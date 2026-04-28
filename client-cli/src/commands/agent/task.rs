//! Task introspection — correlate queue position, dispatch metadata, and persisted callbacks.

use serde::Deserialize;

use crate::AgentId;
use crate::client::ApiClient;
use crate::error::CliError;
use crate::output::TextRender;

/// Mirror of [`GET /agents/{id}/task-status`] JSON body (machine consumption).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
pub(crate) struct AgentTaskStatusBody {
    pub(crate) agent_id: String,
    pub(crate) task_id: String,
    pub(crate) lifecycle: String,
    pub(crate) request_id: Option<u32>,
    pub(crate) queued: Option<AgentTaskQueuedSnapshot>,
    pub(crate) dispatch_context: Option<AgentTaskDispatchSnapshot>,
    pub(crate) response_rows: Vec<AgentTaskResponseSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
pub(crate) struct AgentTaskQueuedSnapshot {
    pub(crate) queue_position: usize,
    pub(crate) command_id: u32,
    pub(crate) request_id: u32,
    pub(crate) command_line: String,
    pub(crate) created_at: String,
    pub(crate) operator: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
pub(crate) struct AgentTaskDispatchSnapshot {
    pub(crate) request_id: u32,
    pub(crate) command_line: String,
    pub(crate) created_at: String,
    pub(crate) operator: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, Deserialize)]
pub(crate) struct AgentTaskResponseSnapshot {
    pub(crate) response_row_id: i64,
    pub(crate) command_id: u32,
    pub(crate) request_id: u32,
    pub(crate) response_type: String,
    pub(crate) received_at: String,
    pub(crate) exit_code: Option<i32>,
}

/// Fetch aggregated task status for debugging timeouts and orphan correlations.
pub(crate) async fn fetch_task_status(
    client: &ApiClient,
    id: AgentId,
    task_id: &str,
) -> Result<AgentTaskStatusBody, CliError> {
    let qs = serde_urlencoded::to_string([("task_id", task_id)])
        .map_err(|e| CliError::General(format!("encode query string: {e}")))?;
    let path = format!("/agents/{id}/task-status?{qs}");
    client.get(&path).await
}

impl TextRender for AgentTaskStatusBody {
    fn render_text(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "(invalid task status)".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_task_status_body_round_trips() {
        let json = serde_json::json!({
            "agent_id": "DEADBEEF",
            "task_id": "A1B2C3D4",
            "lifecycle": "queued",
            "request_id": 42,
            "queued": {
                "queue_position": 0,
                "command_id": 256,
                "request_id": 42,
                "command_line": "whoami",
                "created_at": "2026-01-01T00:00:00Z",
                "operator": "alice"
            },
            "dispatch_context": null,
            "response_rows": []
        });
        let body: AgentTaskStatusBody = serde_json::from_value(json).expect("deserialize");
        assert_eq!(body.lifecycle, "queued");
        assert!(body.queued.is_some());
    }
}
