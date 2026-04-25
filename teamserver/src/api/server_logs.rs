//! `GET /api/v1/debug/server-logs` — return recent teamserver log messages.

use axum::Json;
use axum::extract::{Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use red_cell_common::operator::OperatorMessage;

use crate::app::TeamserverState;
use crate::{AuditDetails, AuditResultStatus};

use super::auth::AdminApiAccess;

const DEFAULT_LINES: u32 = 200;
const MAX_LINES: u32 = 10_000;

/// Query parameters for `GET /debug/server-logs`.
#[derive(Debug, Default, Deserialize, IntoParams)]
pub(super) struct ServerLogsQuery {
    /// Maximum number of log lines to return (most-recent last). Capped at 10 000.
    lines: Option<u32>,
}

/// A single teamserver log entry returned by the endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub(super) struct ServerLogEntry {
    /// Timestamp from the original `MessageHead`.
    pub timestamp: String,
    /// Log message text.
    pub text: String,
}

/// Response body for `GET /debug/server-logs`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub(super) struct ServerLogsResponse {
    /// Log entries in chronological order (oldest first).
    pub logs: Vec<ServerLogEntry>,
    /// Number of entries returned.
    pub count: usize,
}

#[utoipa::path(
    get,
    path = "/debug/server-logs",
    context_path = "/api/v1",
    tag = "rest",
    params(ServerLogsQuery),
    security(("api_key" = [])),
    responses(
        (status = 200, description = "Recent teamserver log entries", body = ServerLogsResponse),
        (status = 401, description = "Missing or invalid API key", body = super::errors::ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = super::errors::ApiErrorBody),
        (status = 429, description = "Rate limit exceeded", body = super::errors::ApiErrorBody)
    )
)]
pub(super) async fn get_server_logs(
    State(state): State<TeamserverState>,
    identity: AdminApiAccess,
    Query(query): Query<ServerLogsQuery>,
) -> Json<ServerLogsResponse> {
    let limit = query.lines.unwrap_or(DEFAULT_LINES).min(MAX_LINES) as usize;

    super::record_audit_entry(
        &state.database,
        &state.webhooks,
        &identity.key_id,
        "server.logs.show",
        "debug",
        None,
        AuditDetails {
            agent_id: None,
            command: None,
            parameters: Some(serde_json::json!({ "lines": limit })),
            result_status: AuditResultStatus::Success,
        },
    )
    .await;

    let all_logs = state.events.recent_teamserver_logs();

    let entries: Vec<ServerLogEntry> = all_logs
        .into_iter()
        .filter_map(|msg| {
            if let OperatorMessage::TeamserverLog(m) = msg {
                Some(ServerLogEntry { timestamp: m.head.timestamp, text: m.info.text })
            } else {
                None
            }
        })
        .collect();

    let start = entries.len().saturating_sub(limit);
    let tail = entries[start..].to_vec();
    let count = tail.len();

    Json(ServerLogsResponse { logs: tail, count })
}

#[cfg(test)]
mod tests {
    use super::*;
    use red_cell_common::operator::{EventCode, Message, MessageHead, TeamserverLogInfo};

    fn log_msg(ts: &str, text: &str) -> OperatorMessage {
        OperatorMessage::TeamserverLog(Message {
            head: MessageHead {
                event: EventCode::Teamserver,
                user: String::new(),
                timestamp: ts.to_owned(),
                one_time: String::new(),
            },
            info: TeamserverLogInfo { text: text.to_owned() },
        })
    }

    #[test]
    fn extract_entries_from_operator_messages() {
        let msgs = vec![log_msg("12:00:01", "started"), log_msg("12:00:02", "listening")];

        let entries: Vec<ServerLogEntry> = msgs
            .into_iter()
            .filter_map(|msg| {
                if let OperatorMessage::TeamserverLog(m) = msg {
                    Some(ServerLogEntry { timestamp: m.head.timestamp, text: m.info.text })
                } else {
                    None
                }
            })
            .collect();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].text, "started");
        assert_eq!(entries[1].text, "listening");
    }

    #[test]
    fn lines_cap_limits_output() {
        let msgs: Vec<OperatorMessage> =
            (0..10).map(|i| log_msg(&format!("12:00:{i:02}"), &format!("line-{i}"))).collect();

        let entries: Vec<ServerLogEntry> = msgs
            .into_iter()
            .filter_map(|msg| {
                if let OperatorMessage::TeamserverLog(m) = msg {
                    Some(ServerLogEntry { timestamp: m.head.timestamp, text: m.info.text })
                } else {
                    None
                }
            })
            .collect();

        let limit: usize = 3;
        let start = entries.len().saturating_sub(limit);
        let tail = &entries[start..];

        assert_eq!(tail.len(), 3);
        assert_eq!(tail[0].text, "line-7");
        assert_eq!(tail[2].text, "line-9");
    }

    #[test]
    fn default_lines_constant_is_200() {
        assert_eq!(DEFAULT_LINES, 200);
    }

    #[test]
    fn max_lines_constant_is_10000() {
        assert_eq!(MAX_LINES, 10_000);
    }

    #[test]
    fn server_logs_response_serializes_correctly() {
        let resp = ServerLogsResponse {
            logs: vec![ServerLogEntry {
                timestamp: "12:00:01".to_owned(),
                text: "hello".to_owned(),
            }],
            count: 1,
        };

        let json = serde_json::to_value(&resp).expect("serialize");
        assert_eq!(json["count"], 1);
        assert_eq!(json["logs"][0]["text"], "hello");
        assert_eq!(json["logs"][0]["timestamp"], "12:00:01");
    }

    #[test]
    fn empty_logs_returns_empty_response() {
        let entries: Vec<ServerLogEntry> = vec![];
        let resp = ServerLogsResponse { logs: entries, count: 0 };

        let json = serde_json::to_value(&resp).expect("serialize");
        assert_eq!(json["count"], 0);
        assert!(json["logs"].as_array().expect("array").is_empty());
    }
}
