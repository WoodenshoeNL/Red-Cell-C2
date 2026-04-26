//! Type definitions for `red-cell-cli log` subcommands.

use serde::{Deserialize, Serialize};

use crate::AgentId;
use crate::output::{TextRender, TextRow};

// ── raw API response shapes ───────────────────────────────────────────────────

/// Mirrors the fields of `teamserver::audit::AuditRecord` that are consumed
/// by the CLI.  The server also sends `id`, `parameters` which are silently
/// ignored by serde — no `deny_unknown_fields` is set.
#[derive(Debug, Deserialize)]
pub(super) struct RawAuditRecord {
    pub(super) actor: String,
    pub(super) action: String,
    pub(super) target_kind: String,
    pub(super) target_id: Option<String>,
    pub(super) agent_id: Option<AgentId>,
    pub(super) command: Option<String>,
    pub(super) result_status: String,
    pub(super) occurred_at: String,
}

/// Mirrors `AuditPurgeResponse` from the teamserver.
#[derive(Debug, Deserialize)]
pub(super) struct RawPurgeResponse {
    pub(super) deleted: u64,
    pub(super) cutoff: String,
}

/// Mirrors `teamserver::audit::AuditPage`.  Pagination metadata (`total`,
/// `limit`, `offset`) is silently ignored by serde — no `deny_unknown_fields`
/// is set.
#[derive(Debug, Deserialize)]
pub(super) struct RawAuditPage {
    pub(super) items: Vec<RawAuditRecord>,
}

/// Mirrors `ServerLogsResponse` from the teamserver debug endpoint.
#[derive(Debug, Deserialize)]
pub(super) struct RawServerLogsResponse {
    pub(super) logs: Vec<ServerLogEntry>,
}

// ── public output types ───────────────────────────────────────────────────────

/// A single audit log entry returned by `log list` / `log tail`.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    /// ISO 8601 UTC timestamp of the event.
    pub ts: String,
    /// Operator / API-key actor who performed the action.
    pub operator: String,
    /// Action type (e.g. `"agent.task"`, `"operator.login"`).
    pub action: String,
    /// Agent ID the action was performed on, if applicable.
    pub agent_id: Option<AgentId>,
    /// Sub-action label or target reference for this event.
    pub detail: Option<String>,
    /// Outcome: `"success"` or `"failure"`.
    pub result_status: String,
}

impl TextRow for AuditEntry {
    fn headers() -> Vec<&'static str> {
        vec!["Timestamp", "Operator", "Action", "Agent ID", "Detail", "Result"]
    }

    fn row(&self) -> Vec<String> {
        vec![
            self.ts.clone(),
            self.operator.clone(),
            self.action.clone(),
            self.agent_id.map_or_else(String::new, |id| id.to_string()),
            self.detail.clone().unwrap_or_default(),
            self.result_status.clone(),
        ]
    }
}

/// Result returned by `log purge`.
#[derive(Debug, Clone, Serialize)]
pub struct PurgeResult {
    /// Number of audit log rows deleted.
    pub deleted: u64,
    /// RFC 3339 timestamp used as the deletion cutoff.
    pub cutoff: String,
}

impl TextRender for PurgeResult {
    fn render_text(&self) -> String {
        format!("Purged {} audit log entries (cutoff: {}).", self.deleted, self.cutoff)
    }
}

/// A single teamserver log entry returned by `log server-tail`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerLogEntry {
    /// Timestamp from the teamserver log message header.
    pub timestamp: String,
    /// Log message text.
    pub text: String,
}

impl TextRow for ServerLogEntry {
    fn headers() -> Vec<&'static str> {
        vec!["Timestamp", "Message"]
    }

    fn row(&self) -> Vec<String> {
        vec![self.timestamp.clone(), self.text.clone()]
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Map a raw `AuditRecord` from the server into a display-friendly
/// [`AuditEntry`].
///
/// Field mapping:
/// - `ts`           ← `occurred_at`
/// - `operator`     ← `actor`
/// - `action`       ← `action`
/// - `agent_id`     ← `agent_id`
/// - `detail`       ← `command` if present, otherwise `target_kind`:`target_id`
/// - `result_status`← `result_status`
pub(super) fn audit_entry_from_raw(raw: RawAuditRecord) -> AuditEntry {
    let detail = raw.command.clone().or_else(|| {
        raw.target_id.as_deref().map(|tid| format!("{}:{}", raw.target_kind, tid)).or_else(|| {
            if raw.target_kind.is_empty() { None } else { Some(raw.target_kind.clone()) }
        })
    });

    AuditEntry {
        ts: raw.occurred_at,
        operator: raw.actor,
        action: raw.action,
        agent_id: raw.agent_id,
        detail,
        result_status: raw.result_status,
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn agent_id(value: u32) -> AgentId {
        AgentId::new(value)
    }

    fn sample_raw_record(
        actor: &str,
        action: &str,
        target_kind: &str,
        target_id: Option<&str>,
        agent_id: Option<AgentId>,
        command: Option<&str>,
        result_status: &str,
        occurred_at: &str,
    ) -> RawAuditRecord {
        RawAuditRecord {
            actor: actor.to_owned(),
            action: action.to_owned(),
            target_kind: target_kind.to_owned(),
            target_id: target_id.map(ToOwned::to_owned),
            agent_id,
            command: command.map(ToOwned::to_owned),
            result_status: result_status.to_owned(),
            occurred_at: occurred_at.to_owned(),
        }
    }

    // ── audit_entry_from_raw ──────────────────────────────────────────────────

    #[test]
    fn audit_entry_from_raw_maps_all_fields() {
        let raw = sample_raw_record(
            "alice",
            "agent.task",
            "agent",
            Some("CAFE0001"),
            Some(agent_id(0xABC123)),
            Some("whoami"),
            "success",
            "2026-03-21T12:00:00Z",
        );
        let entry = audit_entry_from_raw(raw);
        assert_eq!(entry.ts, "2026-03-21T12:00:00Z");
        assert_eq!(entry.operator, "alice");
        assert_eq!(entry.action, "agent.task");
        assert_eq!(entry.agent_id, Some(agent_id(0xABC123)));
        assert_eq!(entry.detail.as_deref(), Some("whoami"));
        assert_eq!(entry.result_status, "success");
    }

    #[test]
    fn audit_entry_from_raw_detail_falls_back_to_target_kind_and_id() {
        let raw = sample_raw_record(
            "bob",
            "operator.create",
            "operator",
            Some("charlie"),
            None,
            None,
            "success",
            "2026-03-21T00:00:00Z",
        );
        let entry = audit_entry_from_raw(raw);
        assert_eq!(entry.detail.as_deref(), Some("operator:charlie"));
    }

    #[test]
    fn audit_entry_from_raw_detail_falls_back_to_target_kind_only() {
        let raw = sample_raw_record(
            "admin",
            "config.reload",
            "config",
            None,
            None,
            None,
            "success",
            "2026-03-21T00:00:00Z",
        );
        let entry = audit_entry_from_raw(raw);
        assert_eq!(entry.detail.as_deref(), Some("config"));
    }

    #[test]
    fn audit_entry_from_raw_detail_none_when_target_kind_empty_and_no_command() {
        let raw = sample_raw_record(
            "admin",
            "system.ping",
            "",
            None,
            None,
            None,
            "success",
            "2026-03-21T00:00:00Z",
        );
        let entry = audit_entry_from_raw(raw);
        assert!(entry.detail.is_none());
    }

    #[test]
    fn audit_entry_from_raw_handles_none_agent_id() {
        let raw = sample_raw_record(
            "bob",
            "operator.login",
            "session",
            None,
            None,
            None,
            "success",
            "2026-03-21T00:00:00Z",
        );
        let entry = audit_entry_from_raw(raw);
        assert!(entry.agent_id.is_none());
    }

    #[test]
    fn audit_entry_from_raw_failure_result_status() {
        let raw = sample_raw_record(
            "eve",
            "operator.login",
            "session",
            None,
            None,
            None,
            "failure",
            "2026-03-21T09:00:00Z",
        );
        let entry = audit_entry_from_raw(raw);
        assert_eq!(entry.result_status, "failure");
    }

    // ── AuditEntry / TextRow ──────────────────────────────────────────────────

    #[test]
    fn audit_entry_headers_match_row_length() {
        let entry = AuditEntry {
            ts: "2026-03-21T12:00:00Z".to_owned(),
            operator: "alice".to_owned(),
            action: "agent.task".to_owned(),
            agent_id: Some(agent_id(0xABC123)),
            detail: Some("whoami".to_owned()),
            result_status: "success".to_owned(),
        };
        assert_eq!(AuditEntry::headers().len(), entry.row().len());
    }

    #[test]
    fn audit_entry_row_uses_empty_string_for_none_fields() {
        let entry = AuditEntry {
            ts: "2026-03-21T12:00:00Z".to_owned(),
            operator: "alice".to_owned(),
            action: "operator.login".to_owned(),
            agent_id: None,
            detail: None,
            result_status: "success".to_owned(),
        };
        let row = entry.row();
        assert_eq!(row[3], ""); // agent_id column
        assert_eq!(row[4], ""); // detail column
    }

    #[test]
    fn audit_entry_serialises_all_fields() {
        let entry = AuditEntry {
            ts: "2026-03-21T12:00:00Z".to_owned(),
            operator: "carol".to_owned(),
            action: "agent.kill".to_owned(),
            agent_id: Some(agent_id(0xFED789)),
            detail: Some("SIGTERM".to_owned()),
            result_status: "success".to_owned(),
        };
        let v = serde_json::to_value(&entry).expect("serialise");
        assert_eq!(v["ts"], "2026-03-21T12:00:00Z");
        assert_eq!(v["operator"], "carol");
        assert_eq!(v["action"], "agent.kill");
        assert_eq!(v["agent_id"], "00FED789");
        assert_eq!(v["detail"], "SIGTERM");
        assert_eq!(v["result_status"], "success");
    }

    #[test]
    fn vec_audit_entry_renders_table_with_data() {
        let entries = vec![AuditEntry {
            ts: "2026-03-21T12:00:00Z".to_owned(),
            operator: "dave".to_owned(),
            action: "agent.task".to_owned(),
            agent_id: Some(agent_id(0xABC)),
            detail: Some("id".to_owned()),
            result_status: "success".to_owned(),
        }];
        let rendered = entries.render_text();
        assert!(rendered.contains("dave"));
        assert!(rendered.contains("agent.task"));
        assert!(rendered.contains("00000ABC"));
    }

    #[test]
    fn vec_audit_entry_empty_renders_none() {
        let entries: Vec<AuditEntry> = vec![];
        assert_eq!(entries.render_text(), "(none)");
    }

    // ── ServerLogEntry ───────────────────────────────────────────────────────

    #[test]
    fn server_log_entry_serializes_correctly() {
        let entry = ServerLogEntry {
            timestamp: "12:00:01".to_owned(),
            text: "listener started".to_owned(),
        };
        let v = serde_json::to_value(&entry).expect("serialise");
        assert_eq!(v["timestamp"], "12:00:01");
        assert_eq!(v["text"], "listener started");
    }

    #[test]
    fn server_log_entry_text_row_headers() {
        let hdrs = ServerLogEntry::headers();
        assert_eq!(hdrs, vec!["Timestamp", "Message"]);
    }

    #[test]
    fn server_log_entry_text_row_values() {
        let entry = ServerLogEntry { timestamp: "12:34:56".to_owned(), text: "hello".to_owned() };
        let row = entry.row();
        assert_eq!(row, vec!["12:34:56", "hello"]);
    }

    #[test]
    fn vec_server_log_entry_renders_table() {
        let entries = vec![
            ServerLogEntry { timestamp: "12:00:01".to_owned(), text: "started".to_owned() },
            ServerLogEntry { timestamp: "12:00:02".to_owned(), text: "listening".to_owned() },
        ];
        let rendered = entries.render_text();
        assert!(rendered.contains("started"));
        assert!(rendered.contains("listening"));
        assert!(rendered.contains("12:00:01"));
    }

    #[test]
    fn vec_server_log_entry_empty_renders_none() {
        let entries: Vec<ServerLogEntry> = vec![];
        assert_eq!(entries.render_text(), "(none)");
    }

    // ── PurgeResult ──────────────────────────────────────────────────────────

    #[test]
    fn purge_result_render_text() {
        let result = PurgeResult { deleted: 42, cutoff: "2026-01-01T00:00:00Z".to_owned() };
        let rendered = result.render_text();
        assert!(rendered.contains("42"));
        assert!(rendered.contains("2026-01-01T00:00:00Z"));
    }
}
