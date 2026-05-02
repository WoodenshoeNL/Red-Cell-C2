//! Kill, deregister, and queue agent tasks (`DELETE /agents/:id`,
//! `POST /agents/:id/task`).

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::Value;

use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::{AgentTaskInfo, EventCode, Message, MessageHead};

use crate::app::TeamserverState;
use crate::events::broadcast_teamserver_warning;
use crate::websocket::{AgentCommandError, execute_agent_task};
use crate::{AuditResultStatus, audit_details, parameter_object};

use crate::api::{TaskAgentApiAccess, next_task_id, parse_api_agent_id, record_audit_entry};

use super::access::authorize_agent_access;
use super::{AgentApiError, AgentDeregisteredResponse, AgentTaskQueuedResponse};

/// Query parameters for `DELETE /agents/{id}`.
#[derive(Debug, Default, Deserialize, utoipa::IntoParams)]
pub(crate) struct DeleteAgentQuery {
    /// When `true`, queue the kill task **and** immediately remove the agent
    /// from the registry without waiting for the agent to acknowledge.
    #[serde(default)]
    force: bool,
    /// When `true`, skip the kill task entirely and only remove the agent
    /// from the registry (server-side deregistration).
    #[serde(default)]
    deregister_only: bool,
}

#[utoipa::path(
    delete,
    path = "/agents/{id}",
    context_path = "/api/v1",
    tag = "agents",
    security(("api_key" = [])),
    params(
        ("id" = String, Path, description = "Agent id in hex (with optional 0x prefix)"),
        DeleteAgentQuery,
    ),
    responses(
        (status = 200, description = "Agent deregistered (force / deregister_only)", body = AgentDeregisteredResponse),
        (status = 202, description = "Agent kill task queued", body = AgentTaskQueuedResponse),
        (status = 400, description = "Invalid agent id", body = crate::api::ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = crate::api::ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = crate::api::ApiErrorBody),
        (status = 404, description = "Agent not found", body = crate::api::ApiErrorBody)
    )
)]
pub(crate) async fn kill_agent(
    State(state): State<TeamserverState>,
    identity: TaskAgentApiAccess,
    Path(id): Path<String>,
    Query(params): Query<DeleteAgentQuery>,
) -> Result<Response, AgentApiError> {
    let agent_id = parse_api_agent_id(&id)?;
    authorize_agent_access(&state, &identity.key_id, agent_id).await?;

    if params.deregister_only {
        return deregister_agent(&state, &identity.key_id, agent_id).await;
    }

    let (task_id, queued_jobs) = queue_kill_task(&state, &identity, agent_id).await?;

    if params.force {
        return deregister_agent(&state, &identity.key_id, agent_id).await;
    }

    Ok((
        StatusCode::ACCEPTED,
        Json(AgentTaskQueuedResponse { agent_id: format!("{agent_id:08X}"), task_id, queued_jobs }),
    )
        .into_response())
}

async fn queue_kill_task(
    state: &TeamserverState,
    identity: &TaskAgentApiAccess,
    agent_id: u32,
) -> Result<(String, usize), AgentApiError> {
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
    match execute_agent_task(
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
            Ok((task_id, queued_jobs))
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
            broadcast_teamserver_warning(
                &state.events,
                format!(
                    "[rest agent.task] key={} agent={:08X} kill task queue failed: {}",
                    identity.key_id, agent_id, error
                ),
            );
            Err(error.into())
        }
    }
}

async fn deregister_agent(
    state: &TeamserverState,
    operator: &str,
    agent_id: u32,
) -> Result<Response, AgentApiError> {
    state.agent_registry.remove(agent_id).await?;
    state.sockets.remove_agent(agent_id).await;
    record_audit_entry(
        &state.database,
        &state.webhooks,
        operator,
        "agent.deregister",
        "agent",
        Some(format!("{agent_id:08X}")),
        audit_details(AuditResultStatus::Success, Some(agent_id), Some("deregister"), None),
    )
    .await;
    Ok((
        StatusCode::OK,
        Json(AgentDeregisteredResponse { agent_id: format!("{agent_id:08X}"), deregistered: true }),
    )
        .into_response())
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
        (status = 400, description = "Invalid task payload", body = crate::api::ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = crate::api::ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = crate::api::ApiErrorBody),
        (status = 404, description = "Agent not found", body = crate::api::ApiErrorBody),
        (status = 429, description = "Agent task queue full", body = crate::api::ApiErrorBody)
    )
)]
pub(crate) async fn queue_agent_task(
    State(state): State<TeamserverState>,
    identity: TaskAgentApiAccess,
    Path(id): Path<String>,
    Json(mut task): Json<AgentTaskInfo>,
) -> Result<(StatusCode, Json<AgentTaskQueuedResponse>), AgentApiError> {
    let agent_id = parse_api_agent_id(&id)?;
    authorize_agent_access(&state, &identity.key_id, agent_id).await?;
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
            broadcast_teamserver_warning(
                &state.events,
                format!(
                    "[rest agent.task] key={} agent={} agent.task failed: {}",
                    identity.key_id, canonical_id, error
                ),
            );
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
