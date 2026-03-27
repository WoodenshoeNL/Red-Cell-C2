//! Shared types used across multiple command modules.

use serde::Deserialize;

/// Wire format returned by `GET /agents/{id}/output`.
#[derive(Debug, Deserialize)]
pub(crate) struct OutputPage {
    #[allow(dead_code)]
    pub(crate) total: usize,
    pub(crate) entries: Vec<OutputWireEntry>,
}

/// Single entry in the `OutputPage.entries` array.
#[derive(Debug, Deserialize)]
pub(crate) struct OutputWireEntry {
    pub(crate) id: i64,
    pub(crate) task_id: Option<String>,
    #[allow(dead_code)]
    pub(crate) command_id: u32,
    #[allow(dead_code)]
    pub(crate) request_id: u32,
    #[allow(dead_code)]
    pub(crate) response_type: String,
    pub(crate) message: String,
    pub(crate) output: String,
    pub(crate) command_line: Option<String>,
    #[allow(dead_code)]
    pub(crate) operator: Option<String>,
    pub(crate) received_at: String,
}

/// Build the output polling URL with an optional cursor.
pub(crate) fn output_url(agent_id: &str, since: Option<&str>) -> String {
    match since {
        Some(cursor) => format!("/agents/{agent_id}/output?since={cursor}"),
        None => format!("/agents/{agent_id}/output"),
    }
}
