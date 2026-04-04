//! Shared types used across multiple command modules.

use serde::Deserialize;

/// Wire format returned by `GET /agents/{id}/output`.
///
/// The server also sends `total` (pagination metadata) which is silently
/// ignored by serde.
#[derive(Debug, Deserialize)]
pub(crate) struct OutputPage {
    pub(crate) entries: Vec<OutputWireEntry>,
}

/// Single entry in the `OutputPage.entries` array.
///
/// The server also sends `command_id`, `request_id`, `response_type`, and
/// `operator` which are silently ignored by serde.
#[derive(Debug, Deserialize)]
pub(crate) struct OutputWireEntry {
    pub(crate) id: i64,
    pub(crate) task_id: Option<String>,
    pub(crate) message: String,
    pub(crate) output: String,
    pub(crate) command_line: Option<String>,
    pub(crate) received_at: String,
    /// Process exit code surfaced by the teamserver when the agent reported one.
    #[serde(default)]
    pub(crate) exit_code: Option<i32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `OutputWireEntry` deserialises `exit_code` when the server sends it.
    #[test]
    fn output_wire_entry_deserialises_exit_code() {
        let json = serde_json::json!({
            "id": 42,
            "task_id": "t1",
            "message": "Received Output [3 bytes]:",
            "output": "err",
            "command_line": "exit 1",
            "received_at": "2026-04-04T00:00:00Z",
            "exit_code": 1
        });
        let entry: OutputWireEntry = serde_json::from_value(json).expect("deserialise");
        assert_eq!(entry.exit_code, Some(1));
    }

    /// `OutputWireEntry` sets `exit_code` to `None` when the field is absent
    /// (legacy Havoc demon responses do not include it).
    #[test]
    fn output_wire_entry_defaults_exit_code_to_none_when_absent() {
        let json = serde_json::json!({
            "id": 7,
            "task_id": null,
            "message": "Received Output [2 bytes]:",
            "output": "ok",
            "command_line": null,
            "received_at": "2026-04-04T00:00:00Z"
        });
        let entry: OutputWireEntry = serde_json::from_value(json).expect("deserialise");
        assert_eq!(entry.exit_code, None);
    }
}

/// Build the output polling URL with an optional numeric cursor.
///
/// The `since` parameter is the numeric database row id of the last seen
/// entry.  The server returns only rows with `id > since`, matching the
/// `AgentOutputQuery::since: Option<i64>` parameter on the teamserver side.
pub(crate) fn output_url(agent_id: &str, since: Option<i64>) -> String {
    match since {
        Some(cursor) => format!("/agents/{agent_id}/output?since={cursor}"),
        None => format!("/agents/{agent_id}/output"),
    }
}
