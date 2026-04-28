//! Task introspection — correlate queue state, retained dispatch metadata, and persisted callbacks.

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use thiserror::Error;
use utoipa::{IntoParams, ToSchema};

use crate::app::TeamserverState;

use super::{AgentApiError, ReadApiAccess, authorize_agent_access, parse_api_agent_id};

/// Query string for [`get_agent_task_status`].
#[derive(Debug, serde::Deserialize, IntoParams)]
pub struct AgentTaskStatusQuery {
    /// Stable task identifier (`TaskID`) returned when the job was submitted.
    pub task_id: String,
}

/// High-level lifecycle classification for automated triage after timeouts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentTaskLifecycle {
    /// The job is still in the teamserver FIFO queue for this agent.
    Queued,
    /// The job was dispatched; no persisted callback rows yet, but dispatch metadata is retained.
    DispatchedPending,
    /// At least one persisted callback/output row exists for this correlation.
    ResponsesPresent,
    /// No queue entry, no retained dispatch context, and no matching persisted rows (or correlation was evicted).
    Unknown,
}

/// Snapshot of a queued job matching the task id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct AgentTaskQueuedSnapshot {
    /// Zero-based index in the FIFO queue (0 = next to dispatch).
    pub queue_position: usize,
    pub command_id: u32,
    pub request_id: u32,
    pub command_line: String,
    pub created_at: String,
    pub operator: String,
}

/// Retained metadata after the job left the queue (bounded in-memory map).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct AgentTaskDispatchSnapshot {
    pub request_id: u32,
    pub command_line: String,
    pub created_at: String,
    pub operator: String,
}

/// One persisted callback row (subset for correlation / debugging).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct AgentTaskResponseSnapshot {
    pub response_row_id: i64,
    pub command_id: u32,
    pub request_id: u32,
    pub response_type: String,
    pub received_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
}

/// Combined task status for `GET /agents/{id}/task-status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct AgentTaskStatusBody {
    pub agent_id: String,
    pub task_id: String,
    pub lifecycle: AgentTaskLifecycle,
    /// Resolved request id when known from the queue, dispatch context, responses, or a hex-parsed task id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queued: Option<AgentTaskQueuedSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dispatch_context: Option<AgentTaskDispatchSnapshot>,
    pub response_rows: Vec<AgentTaskResponseSnapshot>,
}

#[derive(Debug, Error)]
pub enum TaskStatusError {
    #[error("{0}")]
    Agent(AgentApiError),
    #[error("task_id must not be empty")]
    EmptyTaskId,
}

impl From<AgentApiError> for TaskStatusError {
    fn from(value: AgentApiError) -> Self {
        Self::Agent(value)
    }
}

impl IntoResponse for TaskStatusError {
    fn into_response(self) -> Response {
        match self {
            Self::Agent(e) => e.into_response(),
            Self::EmptyTaskId => super::super::json_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_task_id",
                self.to_string(),
            ),
        }
    }
}

/// `GET /agents/{id}/task-status?task_id=` — correlate queue, dispatch memory, and persisted responses.
#[utoipa::path(
    get,
    path = "/agents/{id}/task-status",
    context_path = "/api/v1",
    tag = "agents",
    security(("api_key" = [])),
    params(
        ("id" = String, Path, description = "Agent id in hex (with optional 0x prefix)"),
        AgentTaskStatusQuery
    ),
    responses(
        (status = 200, description = "Task correlation snapshot", body = AgentTaskStatusBody),
        (status = 400, description = "Missing or invalid task_id", body = super::super::ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = super::super::ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = super::super::ApiErrorBody),
        (status = 404, description = "Agent not found", body = super::super::ApiErrorBody)
    )
)]
pub async fn get_agent_task_status(
    State(state): State<TeamserverState>,
    identity: ReadApiAccess,
    Path(agent_path): Path<String>,
    Query(query): Query<AgentTaskStatusQuery>,
) -> Result<Json<AgentTaskStatusBody>, TaskStatusError> {
    let task_id = query.task_id.trim();
    if task_id.is_empty() {
        return Err(TaskStatusError::EmptyTaskId);
    }
    let task_id = task_id.to_owned();

    let agent_id = parse_api_agent_id(&agent_path)
        .map_err(|e| TaskStatusError::Agent(AgentApiError::Task(e)))?;

    state
        .agent_registry
        .get(agent_id)
        .await
        .ok_or(crate::TeamserverError::AgentNotFound { agent_id })
        .map_err(|e| TaskStatusError::Agent(AgentApiError::Teamserver(e)))?;
    authorize_agent_access(&state, &identity.key_id, agent_id)
        .await
        .map_err(|e| TaskStatusError::Agent(AgentApiError::Authorization(e)))?;

    let rid_from_hex = parse_task_id_as_request_id(&task_id);

    let queued = state
        .agent_registry
        .queued_job_lookup_by_task_id(agent_id, &task_id)
        .await
        .map_err(|e| TaskStatusError::Agent(AgentApiError::Teamserver(e)))?;
    let ctx = state.agent_registry.request_context_lookup_by_task_id(agent_id, &task_id).await;

    let request_id_for_db = rid_from_hex
        .or_else(|| queued.as_ref().map(|(_, j)| j.request_id))
        .or_else(|| ctx.as_ref().map(|(r, _)| *r));

    let responses = state
        .database
        .agent_responses()
        .list_correlated_for_task(agent_id, &task_id, request_id_for_db)
        .await
        .map_err(|e| TaskStatusError::Agent(AgentApiError::Teamserver(e)))?;

    let response_rows: Vec<AgentTaskResponseSnapshot> = responses
        .iter()
        .map(|r| AgentTaskResponseSnapshot {
            response_row_id: r.id.unwrap_or(0),
            command_id: r.command_id,
            request_id: r.request_id,
            response_type: r.response_type.clone(),
            received_at: r.received_at.clone(),
            exit_code: r
                .extra
                .as_ref()
                .and_then(|v| v.get("ExitCode"))
                .and_then(|v| v.as_i64())
                .map(|c| c as i32),
        })
        .collect();

    let request_id_resolved = queued
        .as_ref()
        .map(|(_, j)| j.request_id)
        .or_else(|| ctx.as_ref().map(|(r, _)| *r))
        .or_else(|| response_rows.first().map(|s| s.request_id))
        .or(rid_from_hex);

    let dispatched_by_rid = match rid_from_hex {
        Some(rid) => state.agent_registry.request_context(agent_id, rid).await.is_some(),
        None => false,
    };

    let lifecycle = if queued.is_some() {
        AgentTaskLifecycle::Queued
    } else if !response_rows.is_empty() {
        AgentTaskLifecycle::ResponsesPresent
    } else if ctx.is_some() || dispatched_by_rid {
        AgentTaskLifecycle::DispatchedPending
    } else {
        AgentTaskLifecycle::Unknown
    };

    let queued_snap = queued.map(|(pos, job)| AgentTaskQueuedSnapshot {
        queue_position: pos,
        command_id: job.command,
        request_id: job.request_id,
        command_line: job.command_line,
        created_at: job.created_at,
        operator: job.operator,
    });

    let dispatch_snap = ctx.map(|(rid, c)| AgentTaskDispatchSnapshot {
        request_id: rid,
        command_line: c.command_line,
        created_at: c.created_at,
        operator: c.operator,
    });

    Ok(Json(AgentTaskStatusBody {
        agent_id: format!("{agent_id:08X}"),
        task_id,
        lifecycle,
        request_id: request_id_resolved,
        queued: queued_snap,
        dispatch_context: dispatch_snap,
        response_rows,
    }))
}

/// Parse `task_id` as an unsigned hex request id (same heuristic as session exec wait).
fn parse_task_id_as_request_id(task_id: &str) -> Option<u32> {
    let trimmed = task_id.trim();
    if trimmed.is_empty() {
        return None;
    }
    let hex_digits =
        trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    if hex_digits.len() > 8 {
        return None;
    }
    u32::from_str_radix(hex_digits, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::parse_task_id_as_request_id;

    #[test]
    fn parse_hex_task_id_as_request_id() {
        assert_eq!(parse_task_id_as_request_id("2A"), Some(42));
        assert_eq!(parse_task_id_as_request_id("0xDEAD"), Some(0xDEAD));
        assert!(parse_task_id_as_request_id("").is_none());
        assert!(parse_task_id_as_request_id("not-hex").is_none());
    }
}
