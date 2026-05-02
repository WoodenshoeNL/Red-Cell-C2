//! List/show agent records and persisted output (`GET /agents`, `/agents/:id`,
//! `/agents/:id/output`).

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::Serialize;
use utoipa::ToSchema;

use red_cell_common::AgentRecord;

use crate::app::TeamserverState;

use super::AgentApiError;
use super::access::{authorize_agent_access, operator_may_access_agent};
use crate::api::{ReadApiAccess, parse_api_agent_id};

/// Sanitized REST representation of an agent/session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub(crate) struct ApiAgentInfo {
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
    /// Name of the listener that accepted this agent's registration.
    #[serde(rename = "Listener")]
    listener: String,
}

impl ApiAgentInfo {
    pub(crate) fn from_record_with_listener(agent: &AgentRecord, listener: String) -> Self {
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
            listener,
        }
    }
}

/// Single output entry returned by `GET /agents/{id}/output`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub(crate) struct AgentOutputEntry {
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
pub(crate) struct AgentOutputPage {
    /// Total number of entries returned.
    total: usize,
    /// Output entries in insertion order.
    entries: Vec<AgentOutputEntry>,
}

/// Query parameters for `GET /agents/{id}/output`.
#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
pub(crate) struct AgentOutputQuery {
    /// Cursor: only return rows with `id` strictly greater than this value.
    since: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/agents",
    context_path = "/api/v1",
    tag = "agents",
    security(("api_key" = [])),
    responses(
        (status = 200, description = "List all tracked agents", body = [ApiAgentInfo]),
        (status = 401, description = "Missing or invalid API key", body = crate::api::ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = crate::api::ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = crate::api::ApiErrorBody)
    )
)]
pub(crate) async fn list_agents(
    State(state): State<TeamserverState>,
    identity: ReadApiAccess,
) -> Json<Vec<ApiAgentInfo>> {
    let agents = state.agent_registry.list_with_listeners().await;
    let mut visible = Vec::with_capacity(agents.len());
    for (agent, listener) in agents {
        if operator_may_access_agent(&state, &identity.key_id, agent.agent_id).await {
            visible.push(ApiAgentInfo::from_record_with_listener(&agent, listener));
        }
    }
    Json(visible)
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
        (status = 400, description = "Invalid agent id", body = crate::api::ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = crate::api::ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = crate::api::ApiErrorBody),
        (status = 404, description = "Agent not found", body = crate::api::ApiErrorBody)
    )
)]
pub(crate) async fn get_agent(
    State(state): State<TeamserverState>,
    identity: ReadApiAccess,
    Path(id): Path<String>,
) -> Result<Json<ApiAgentInfo>, AgentApiError> {
    let agent_id = parse_api_agent_id(&id)?;
    let agent = state
        .agent_registry
        .get(agent_id)
        .await
        .ok_or(crate::TeamserverError::AgentNotFound { agent_id })?;
    authorize_agent_access(&state, &identity.key_id, agent_id).await?;
    let listener = state.agent_registry.listener_name(agent_id).await.unwrap_or_default();
    Ok(Json(ApiAgentInfo::from_record_with_listener(&agent, listener)))
}

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
        (status = 400, description = "Invalid agent id", body = crate::api::ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = crate::api::ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = crate::api::ApiErrorBody),
        (status = 404, description = "Agent not found", body = crate::api::ApiErrorBody)
    )
)]
pub(crate) async fn get_agent_output(
    State(state): State<TeamserverState>,
    identity: ReadApiAccess,
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
    authorize_agent_access(&state, &identity.key_id, agent_id).await?;

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
