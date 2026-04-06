//! Agent inventory, tasking, upload/download, and group-membership REST handlers.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use utoipa::{IntoParams, ToSchema};

use red_cell_common::AgentRecord;
use red_cell_common::demon::{DemonCommand, DemonFilesystemCommand};
use red_cell_common::operator::{AgentTaskInfo, EventCode, Message, MessageHead};

use crate::app::TeamserverState;
use crate::websocket::{AgentCommandError, execute_agent_task};
use crate::{
    AuditResultStatus, AuthorizationError, audit_details, authorize_agent_group_access,
    authorize_listener_access, parameter_object,
};

use super::{
    AdminApiAccess, ApiErrorBody, ReadApiAccess, TaskAgentApiAccess, json_error_response,
    next_task_id, parse_api_agent_id, record_audit_entry,
};

// ── Response / request DTOs ───────────────────────────────────────────────────

/// Sanitized REST representation of an agent/session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub(super) struct ApiAgentInfo {
    /// Numeric agent identifier.
    #[serde(rename = "AgentID")]
    agent_id: u32,
    /// Whether the agent is still marked active.
    #[serde(rename = "Active")]
    active: bool,
    /// Optional inactive reason or registration source.
    #[serde(rename = "Reason")]
    reason: String,
    /// Optional operator-authored note attached to the agent.
    #[serde(rename = "Note")]
    note: String,
    /// Computer hostname.
    #[serde(rename = "Hostname")]
    hostname: String,
    /// Logon username.
    #[serde(rename = "Username")]
    username: String,
    /// Logon domain.
    #[serde(rename = "DomainName")]
    domain_name: String,
    /// External callback IP.
    #[serde(rename = "ExternalIP")]
    external_ip: String,
    /// Internal workstation IP.
    #[serde(rename = "InternalIP")]
    internal_ip: String,
    /// Process executable name.
    #[serde(rename = "ProcessName")]
    process_name: String,
    /// Remote process base address.
    #[serde(rename = "BaseAddress")]
    base_address: u64,
    /// Remote process id.
    #[serde(rename = "ProcessPID")]
    process_pid: u32,
    /// Remote thread id.
    #[serde(rename = "ProcessTID")]
    process_tid: u32,
    /// Remote parent process id.
    #[serde(rename = "ProcessPPID")]
    process_ppid: u32,
    /// Process architecture label.
    #[serde(rename = "ProcessArch")]
    process_arch: String,
    /// Whether the current token is elevated.
    #[serde(rename = "Elevated")]
    elevated: bool,
    /// Operating system version string.
    #[serde(rename = "OSVersion")]
    os_version: String,
    /// Operating system build number (e.g. 22000 for Windows 11 21H2).
    #[serde(rename = "OSBuild")]
    os_build: u32,
    /// Operating system architecture label.
    #[serde(rename = "OSArch")]
    os_arch: String,
    /// Sleep interval in seconds.
    #[serde(rename = "SleepDelay")]
    sleep_delay: u32,
    /// Sleep jitter percentage.
    #[serde(rename = "SleepJitter")]
    sleep_jitter: u32,
    /// Optional kill-date value.
    #[serde(rename = "KillDate")]
    kill_date: Option<i64>,
    /// Optional working-hours bitmask.
    #[serde(rename = "WorkingHours")]
    working_hours: Option<i32>,
    /// Registration timestamp.
    #[serde(rename = "FirstCallIn")]
    first_call_in: String,
    /// Last callback timestamp.
    #[serde(rename = "LastCallIn")]
    last_call_in: String,
}

impl From<AgentRecord> for ApiAgentInfo {
    fn from(agent: AgentRecord) -> Self {
        Self::from(&agent)
    }
}

impl From<&AgentRecord> for ApiAgentInfo {
    fn from(agent: &AgentRecord) -> Self {
        Self {
            agent_id: agent.agent_id,
            active: agent.active,
            reason: agent.reason.clone(),
            note: agent.note.clone(),
            hostname: agent.hostname.clone(),
            username: agent.username.clone(),
            domain_name: agent.domain_name.clone(),
            external_ip: agent.external_ip.clone(),
            internal_ip: agent.internal_ip.clone(),
            process_name: agent.process_name.clone(),
            base_address: agent.base_address,
            process_pid: agent.process_pid,
            process_tid: agent.process_tid,
            process_ppid: agent.process_ppid,
            process_arch: agent.process_arch.clone(),
            elevated: agent.elevated,
            os_version: agent.os_version.clone(),
            os_build: agent.os_build,
            os_arch: agent.os_arch.clone(),
            sleep_delay: agent.sleep_delay,
            sleep_jitter: agent.sleep_jitter,
            kill_date: agent.kill_date,
            working_hours: agent.working_hours,
            first_call_in: agent.first_call_in.clone(),
            last_call_in: agent.last_call_in.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub(super) struct AgentTaskQueuedResponse {
    agent_id: String,
    task_id: String,
    queued_jobs: usize,
}

/// Single output entry returned by `GET /agents/{id}/output`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub(super) struct AgentOutputEntry {
    /// Database row identifier — use as `since` cursor for polling.
    id: i64,
    /// Stable task identifier, when known.
    task_id: Option<String>,
    /// Callback command identifier.
    command_id: u32,
    /// Original request identifier.
    request_id: u32,
    /// Response severity/type label.
    response_type: String,
    /// Human-readable status text.
    message: String,
    /// Raw output string emitted by the agent.
    output: String,
    /// Operator command line associated with the request, when known.
    command_line: Option<String>,
    /// Operator username associated with the request, when known.
    operator: Option<String>,
    /// Response timestamp string.
    received_at: String,
    /// Process exit code, when the agent reported one.
    ///
    /// Present for Red Cell Specter/Phantom shell command responses.
    /// `None` for entries from legacy Havoc demons or non-shell callbacks.
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
}

/// Paginated agent output response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub(super) struct AgentOutputPage {
    /// Total number of entries returned.
    total: usize,
    /// Output entries in insertion order.
    entries: Vec<AgentOutputEntry>,
}

/// Request body for `POST /agents/{id}/upload`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub(super) struct AgentUploadRequest {
    /// Remote path on the target where the file should be written.
    remote_path: String,
    /// File content encoded as base64.
    content: String,
}

/// Request body for `POST /agents/{id}/download`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub(super) struct AgentDownloadRequest {
    /// Remote path on the target to download.
    remote_path: String,
}

/// Query parameters for `GET /agents/{id}/output`.
#[derive(Debug, Deserialize, IntoParams)]
pub(super) struct AgentOutputQuery {
    /// Cursor: only return rows with `id` strictly greater than this value.
    since: Option<i64>,
}

/// Response body for agent group membership endpoints.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AgentGroupsResponse {
    /// Hex-encoded agent id (e.g. `"DEADBEEF"`).
    pub agent_id: String,
    /// Group names the agent currently belongs to.
    pub groups: Vec<String>,
}

/// Request body for setting agent group membership.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SetAgentGroupsRequest {
    /// Replacement group list.  An empty array removes all memberships.
    pub groups: Vec<String>,
}

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub(super) enum AgentApiError {
    #[error("{0}")]
    Teamserver(#[from] crate::TeamserverError),
    #[error("{0}")]
    Task(#[from] AgentCommandError),
    #[error("{0}")]
    Authorization(#[from] AuthorizationError),
}

impl IntoResponse for AgentApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::Teamserver(crate::TeamserverError::AgentNotFound { .. }) => {
                (StatusCode::NOT_FOUND, "agent_not_found")
            }
            Self::Task(
                AgentCommandError::InvalidAgentId { .. }
                | AgentCommandError::MissingAgentId
                | AgentCommandError::MissingNote
                | AgentCommandError::InvalidCommandId { .. }
                | AgentCommandError::MissingField { .. }
                | AgentCommandError::InvalidBooleanField { .. }
                | AgentCommandError::InvalidNumericField { .. }
                | AgentCommandError::InvalidBase64Field { .. }
                | AgentCommandError::UnsupportedProcessSubcommand { .. }
                | AgentCommandError::UnsupportedFilesystemSubcommand { .. }
                | AgentCommandError::UnsupportedTokenSubcommand { .. }
                | AgentCommandError::UnsupportedSocketSubcommand { .. }
                | AgentCommandError::UnsupportedKerberosSubcommand { .. }
                | AgentCommandError::UnsupportedInjectionWay { .. }
                | AgentCommandError::UnsupportedInjectionTechnique { .. }
                | AgentCommandError::UnsupportedArchitecture { .. }
                | AgentCommandError::InvalidProcessCreateArguments
                | AgentCommandError::InvalidRemovePayload
                | AgentCommandError::UnsupportedCommandId { .. },
            ) => (StatusCode::BAD_REQUEST, "invalid_agent_task"),
            Self::Task(AgentCommandError::Teamserver(crate::TeamserverError::AgentNotFound {
                ..
            })) => (StatusCode::NOT_FOUND, "agent_not_found"),
            Self::Teamserver(crate::TeamserverError::QueueFull { .. })
            | Self::Task(AgentCommandError::Teamserver(crate::TeamserverError::QueueFull {
                ..
            })) => (StatusCode::TOO_MANY_REQUESTS, "queue_full"),
            Self::Task(AgentCommandError::Authorization(
                AuthorizationError::AgentGroupDenied { .. }
                | AuthorizationError::ListenerAccessDenied { .. },
            ))
            | Self::Authorization(
                AuthorizationError::AgentGroupDenied { .. }
                | AuthorizationError::ListenerAccessDenied { .. },
            ) => (StatusCode::FORBIDDEN, "agent_access_denied"),
            Self::Teamserver(_) | Self::Task(_) | Self::Authorization(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "agent_api_error")
            }
        };

        json_error_response(status, code, self.to_string())
    }
}

// ── Agent list / show handlers ────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/agents",
    context_path = "/api/v1",
    tag = "agents",
    security(("api_key" = [])),
    responses(
        (status = 200, description = "List all tracked agents", body = [ApiAgentInfo]),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = ApiErrorBody)
    )
)]
pub(super) async fn list_agents(
    State(state): State<TeamserverState>,
    _identity: ReadApiAccess,
) -> Json<Vec<ApiAgentInfo>> {
    Json(state.agent_registry.list().await.into_iter().map(ApiAgentInfo::from).collect())
}

#[utoipa::path(
    get,
    path = "/agents/{id}",
    context_path = "/api/v1",
    tag = "agents",
    security(("api_key" = [])),
    params(("id" = String, Path, description = "Agent id in hex (with optional 0x prefix)")),
    responses(
        (status = 200, description = "Agent details", body = ApiAgentInfo),
        (status = 400, description = "Invalid agent id", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 404, description = "Agent not found", body = ApiErrorBody)
    )
)]
pub(super) async fn get_agent(
    State(state): State<TeamserverState>,
    _identity: ReadApiAccess,
    Path(id): Path<String>,
) -> Result<Json<ApiAgentInfo>, AgentApiError> {
    let agent_id = parse_api_agent_id(&id)?;
    let agent = state
        .agent_registry
        .get(agent_id)
        .await
        .ok_or(crate::TeamserverError::AgentNotFound { agent_id })?;
    Ok(Json(ApiAgentInfo::from(agent)))
}

#[utoipa::path(
    delete,
    path = "/agents/{id}",
    context_path = "/api/v1",
    tag = "agents",
    security(("api_key" = [])),
    params(("id" = String, Path, description = "Agent id in hex (with optional 0x prefix)")),
    responses(
        (status = 202, description = "Agent kill task queued", body = AgentTaskQueuedResponse),
        (status = 400, description = "Invalid agent id", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 404, description = "Agent not found", body = ApiErrorBody)
    )
)]
pub(super) async fn kill_agent(
    State(state): State<TeamserverState>,
    identity: TaskAgentApiAccess,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<AgentTaskQueuedResponse>), AgentApiError> {
    let agent_id = parse_api_agent_id(&id)?;
    authorize_agent_group_access(&state.database, &identity.key_id, agent_id).await?;
    if let Some(listener_name) = state.agent_registry.listener_name(agent_id).await {
        authorize_listener_access(&state.database, &identity.key_id, &listener_name).await?;
    }
    let task_id = next_task_id();
    let message = Message {
        head: MessageHead {
            event: EventCode::Session,
            user: identity.key_id.clone(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: AgentTaskInfo {
            task_id: task_id.clone(),
            command_line: "kill".to_owned(),
            demon_id: format!("{agent_id:08X}"),
            command_id: u32::from(DemonCommand::CommandExit).to_string(),
            command: Some("kill".to_owned()),
            ..AgentTaskInfo::default()
        },
    };
    let queued_jobs = match execute_agent_task(
        &state.agent_registry,
        &state.sockets,
        &state.events,
        &identity.key_id,
        identity.role,
        message,
    )
    .await
    {
        Ok(queued_jobs) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "agent.task",
                "agent",
                Some(format!("{agent_id:08X}")),
                audit_details(
                    AuditResultStatus::Success,
                    Some(agent_id),
                    Some("kill"),
                    Some(parameter_object([
                        ("task_id", Value::String(task_id.clone())),
                        ("command", Value::String("kill".to_owned())),
                    ])),
                ),
            )
            .await;
            queued_jobs
        }
        Err(error) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "agent.task",
                "agent",
                Some(format!("{agent_id:08X}")),
                audit_details(
                    AuditResultStatus::Failure,
                    Some(agent_id),
                    Some("kill"),
                    Some(parameter_object([
                        ("task_id", Value::String(task_id.clone())),
                        ("command", Value::String("kill".to_owned())),
                        ("error", Value::String(error.to_string())),
                    ])),
                ),
            )
            .await;
            return Err(error.into());
        }
    };

    Ok((
        StatusCode::ACCEPTED,
        Json(AgentTaskQueuedResponse { agent_id: format!("{agent_id:08X}"), task_id, queued_jobs }),
    ))
}

#[utoipa::path(
    post,
    path = "/agents/{id}/task",
    context_path = "/api/v1",
    tag = "agents",
    security(("api_key" = [])),
    params(("id" = String, Path, description = "Agent id in hex (with optional 0x prefix)")),
    request_body = AgentTaskInfo,
    responses(
        (status = 202, description = "Agent task queued", body = AgentTaskQueuedResponse),
        (status = 400, description = "Invalid task payload", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 404, description = "Agent not found", body = ApiErrorBody),
        (status = 429, description = "Agent task queue full", body = ApiErrorBody)
    )
)]
pub(super) async fn queue_agent_task(
    State(state): State<TeamserverState>,
    identity: TaskAgentApiAccess,
    Path(id): Path<String>,
    Json(mut task): Json<AgentTaskInfo>,
) -> Result<(StatusCode, Json<AgentTaskQueuedResponse>), AgentApiError> {
    let agent_id = parse_api_agent_id(&id)?;
    authorize_agent_group_access(&state.database, &identity.key_id, agent_id).await?;
    if let Some(listener_name) = state.agent_registry.listener_name(agent_id).await {
        authorize_listener_access(&state.database, &identity.key_id, &listener_name).await?;
    }
    let canonical_id = format!("{agent_id:08X}");

    if !task.demon_id.is_empty() && !task.demon_id.eq_ignore_ascii_case(&canonical_id) {
        return Err(AgentCommandError::InvalidAgentId { agent_id: task.demon_id }.into());
    }
    if task.task_id.trim().is_empty() {
        task.task_id = next_task_id();
    }
    task.demon_id = canonical_id.clone();

    let audit_parameters = serde_json::to_value(&task).ok();
    let command = task.command.clone().unwrap_or_else(|| task.command_line.clone());
    let queued_jobs = match execute_agent_task(
        &state.agent_registry,
        &state.sockets,
        &state.events,
        &identity.key_id,
        identity.role,
        Message {
            head: MessageHead {
                event: EventCode::Session,
                user: identity.key_id.clone(),
                timestamp: String::new(),
                one_time: String::new(),
            },
            info: task.clone(),
        },
    )
    .await
    {
        Ok(queued_jobs) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "agent.task",
                "agent",
                Some(canonical_id.clone()),
                audit_details(
                    AuditResultStatus::Success,
                    Some(agent_id),
                    Some(command.as_str()),
                    audit_parameters.clone(),
                ),
            )
            .await;
            queued_jobs
        }
        Err(error) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "agent.task",
                "agent",
                Some(canonical_id.clone()),
                audit_details(
                    AuditResultStatus::Failure,
                    Some(agent_id),
                    Some(command.as_str()),
                    Some(parameter_object([
                        ("task", audit_parameters.unwrap_or(Value::Null)),
                        ("error", Value::String(error.to_string())),
                    ])),
                ),
            )
            .await;
            return Err(error.into());
        }
    };

    Ok((
        StatusCode::ACCEPTED,
        Json(AgentTaskQueuedResponse {
            agent_id: canonical_id,
            task_id: task.task_id,
            queued_jobs,
        }),
    ))
}

// ── Agent output / upload / download handlers ─────────────────────────────────

#[utoipa::path(
    get,
    path = "/agents/{id}/output",
    context_path = "/api/v1",
    tag = "agents",
    security(("api_key" = [])),
    params(
        ("id" = String, Path, description = "Agent id in hex (with optional 0x prefix)"),
        AgentOutputQuery
    ),
    responses(
        (status = 200, description = "Agent output entries", body = AgentOutputPage),
        (status = 400, description = "Invalid agent id", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 404, description = "Agent not found", body = ApiErrorBody)
    )
)]
pub(super) async fn get_agent_output(
    State(state): State<TeamserverState>,
    _identity: ReadApiAccess,
    Path(id): Path<String>,
    Query(query): Query<AgentOutputQuery>,
) -> Result<Json<AgentOutputPage>, AgentApiError> {
    let agent_id = parse_api_agent_id(&id)?;

    // Verify agent exists.
    state
        .agent_registry
        .get(agent_id)
        .await
        .ok_or(crate::TeamserverError::AgentNotFound { agent_id })?;

    let records = state
        .database
        .agent_responses()
        .list_for_agent_since(agent_id, query.since)
        .await
        .map_err(AgentApiError::Teamserver)?;

    let entries: Vec<AgentOutputEntry> = records
        .into_iter()
        .map(|r| {
            let exit_code = r
                .extra
                .as_ref()
                .and_then(|v| v.get("ExitCode"))
                .and_then(serde_json::Value::as_i64)
                .map(|c| c as i32);
            AgentOutputEntry {
                id: r.id.unwrap_or(0),
                task_id: r.task_id,
                command_id: r.command_id,
                request_id: r.request_id,
                response_type: r.response_type,
                message: r.message,
                output: r.output,
                command_line: r.command_line,
                operator: r.operator,
                received_at: r.received_at,
                exit_code,
            }
        })
        .collect();

    let total = entries.len();
    Ok(Json(AgentOutputPage { total, entries }))
}

#[utoipa::path(
    post,
    path = "/agents/{id}/upload",
    context_path = "/api/v1",
    tag = "agents",
    security(("api_key" = [])),
    params(("id" = String, Path, description = "Agent id in hex (with optional 0x prefix)")),
    request_body = AgentUploadRequest,
    responses(
        (status = 202, description = "Upload task queued", body = AgentTaskQueuedResponse),
        (status = 400, description = "Invalid agent id or payload", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 404, description = "Agent not found", body = ApiErrorBody),
        (status = 429, description = "Agent task queue full", body = ApiErrorBody)
    )
)]
pub(super) async fn agent_upload(
    State(state): State<TeamserverState>,
    identity: TaskAgentApiAccess,
    Path(id): Path<String>,
    Json(body): Json<AgentUploadRequest>,
) -> Result<(StatusCode, Json<AgentTaskQueuedResponse>), AgentApiError> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    let agent_id = parse_api_agent_id(&id)?;
    authorize_agent_group_access(&state.database, &identity.key_id, agent_id).await?;
    if let Some(listener_name) = state.agent_registry.listener_name(agent_id).await {
        authorize_listener_access(&state.database, &identity.key_id, &listener_name).await?;
    }
    let canonical_id = format!("{agent_id:08X}");
    let task_id = next_task_id();

    // Validate the base64 content before queuing.
    let _ = BASE64
        .decode(&body.content)
        .map_err(|_| AgentCommandError::MissingField { field: "content: invalid base64" })?;

    // Encode remote_path and content as the semicolon-delimited base64 pair that
    // the existing `build_upload_jobs` helper expects in `Arguments`.
    let remote_b64 = BASE64.encode(body.remote_path.as_bytes());
    let arguments = format!("{remote_b64};{}", body.content);

    let command_line = format!("upload {} (via REST API)", body.remote_path);
    let task = AgentTaskInfo {
        task_id: task_id.clone(),
        command_line: command_line.clone(),
        demon_id: canonical_id.clone(),
        command_id: u32::from(DemonCommand::CommandFs).to_string(),
        command: Some("upload".to_owned()),
        sub_command: Some(u32::from(DemonFilesystemCommand::Upload).to_string()),
        arguments: Some(arguments),
        ..AgentTaskInfo::default()
    };

    let message = Message {
        head: MessageHead {
            event: EventCode::Session,
            user: identity.key_id.clone(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: task,
    };

    let queued_jobs = match execute_agent_task(
        &state.agent_registry,
        &state.sockets,
        &state.events,
        &identity.key_id,
        identity.role,
        message,
    )
    .await
    {
        Ok(queued_jobs) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "agent.upload",
                "agent",
                Some(canonical_id.clone()),
                audit_details(
                    AuditResultStatus::Success,
                    Some(agent_id),
                    Some("upload"),
                    Some(parameter_object([
                        ("task_id", Value::String(task_id.clone())),
                        ("remote_path", Value::String(body.remote_path)),
                    ])),
                ),
            )
            .await;
            queued_jobs
        }
        Err(error) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "agent.upload",
                "agent",
                Some(canonical_id.clone()),
                audit_details(
                    AuditResultStatus::Failure,
                    Some(agent_id),
                    Some("upload"),
                    Some(parameter_object([
                        ("task_id", Value::String(task_id.clone())),
                        ("error", Value::String(error.to_string())),
                    ])),
                ),
            )
            .await;
            return Err(error.into());
        }
    };

    Ok((
        StatusCode::ACCEPTED,
        Json(AgentTaskQueuedResponse { agent_id: canonical_id, task_id, queued_jobs }),
    ))
}

#[utoipa::path(
    post,
    path = "/agents/{id}/download",
    context_path = "/api/v1",
    tag = "agents",
    security(("api_key" = [])),
    params(("id" = String, Path, description = "Agent id in hex (with optional 0x prefix)")),
    request_body = AgentDownloadRequest,
    responses(
        (status = 202, description = "Download task queued", body = AgentTaskQueuedResponse),
        (status = 400, description = "Invalid agent id or payload", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = ApiErrorBody),
        (status = 404, description = "Agent not found", body = ApiErrorBody),
        (status = 429, description = "Agent task queue full", body = ApiErrorBody)
    )
)]
pub(super) async fn agent_download(
    State(state): State<TeamserverState>,
    identity: TaskAgentApiAccess,
    Path(id): Path<String>,
    Json(body): Json<AgentDownloadRequest>,
) -> Result<(StatusCode, Json<AgentTaskQueuedResponse>), AgentApiError> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    let agent_id = parse_api_agent_id(&id)?;
    authorize_agent_group_access(&state.database, &identity.key_id, agent_id).await?;
    if let Some(listener_name) = state.agent_registry.listener_name(agent_id).await {
        authorize_listener_access(&state.database, &identity.key_id, &listener_name).await?;
    }
    let canonical_id = format!("{agent_id:08X}");
    let task_id = next_task_id();

    // The filesystem download handler expects Arguments to be base64-encoded.
    let arguments_b64 = BASE64.encode(body.remote_path.as_bytes());

    let command_line = format!("download {} (via REST API)", body.remote_path);
    let task = AgentTaskInfo {
        task_id: task_id.clone(),
        command_line: command_line.clone(),
        demon_id: canonical_id.clone(),
        command_id: u32::from(DemonCommand::CommandFs).to_string(),
        command: Some("download".to_owned()),
        sub_command: Some(u32::from(DemonFilesystemCommand::Download).to_string()),
        arguments: Some(arguments_b64),
        ..AgentTaskInfo::default()
    };

    let message = Message {
        head: MessageHead {
            event: EventCode::Session,
            user: identity.key_id.clone(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: task,
    };

    let queued_jobs = match execute_agent_task(
        &state.agent_registry,
        &state.sockets,
        &state.events,
        &identity.key_id,
        identity.role,
        message,
    )
    .await
    {
        Ok(queued_jobs) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "agent.download",
                "agent",
                Some(canonical_id.clone()),
                audit_details(
                    AuditResultStatus::Success,
                    Some(agent_id),
                    Some("download"),
                    Some(parameter_object([
                        ("task_id", Value::String(task_id.clone())),
                        ("remote_path", Value::String(body.remote_path)),
                    ])),
                ),
            )
            .await;
            queued_jobs
        }
        Err(error) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "agent.download",
                "agent",
                Some(canonical_id.clone()),
                audit_details(
                    AuditResultStatus::Failure,
                    Some(agent_id),
                    Some("download"),
                    Some(parameter_object([
                        ("task_id", Value::String(task_id.clone())),
                        ("error", Value::String(error.to_string())),
                    ])),
                ),
            )
            .await;
            return Err(error.into());
        }
    };

    Ok((
        StatusCode::ACCEPTED,
        Json(AgentTaskQueuedResponse { agent_id: canonical_id, task_id, queued_jobs }),
    ))
}

// ── Agent group handlers ──────────────────────────────────────────────────────

pub(super) async fn get_agent_groups(
    State(state): State<TeamserverState>,
    _identity: ReadApiAccess,
    Path(id): Path<String>,
) -> Result<Json<AgentGroupsResponse>, AgentApiError> {
    let agent_id = parse_api_agent_id(&id)?;
    let groups = state.database.agent_groups().groups_for_agent(agent_id).await?;
    Ok(Json(AgentGroupsResponse { agent_id: format!("{agent_id:08X}"), groups }))
}

pub(super) async fn set_agent_groups(
    State(state): State<TeamserverState>,
    identity: AdminApiAccess,
    Path(id): Path<String>,
    Json(request): Json<SetAgentGroupsRequest>,
) -> Result<Json<AgentGroupsResponse>, AgentApiError> {
    let agent_id = parse_api_agent_id(&id)?;
    state.database.agent_groups().set_agent_groups(agent_id, &request.groups).await?;
    record_audit_entry(
        &state.database,
        &state.webhooks,
        &identity.key_id,
        "agent.set_groups",
        "agent",
        Some(format!("{agent_id:08X}")),
        audit_details(
            AuditResultStatus::Success,
            Some(agent_id),
            Some("set_groups"),
            Some(parameter_object([(
                "groups",
                serde_json::to_value(&request.groups).unwrap_or(Value::Null),
            )])),
        ),
    )
    .await;
    Ok(Json(AgentGroupsResponse { agent_id: format!("{agent_id:08X}"), groups: request.groups }))
}
