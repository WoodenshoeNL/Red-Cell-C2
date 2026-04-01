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
