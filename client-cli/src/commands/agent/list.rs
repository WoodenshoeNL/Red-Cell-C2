//! `agent list` — fetch all registered agents.

use tracing::instrument;

use crate::client::ApiClient;
use crate::error::CliError;

use super::types::AgentSummary;
use super::wire::RawAgent;

/// Map a [`RawAgent`] to a table row for `agent list`.
pub(crate) fn agent_summary_from_raw(r: RawAgent) -> AgentSummary {
    AgentSummary {
        id: r.id,
        hostname: r.hostname,
        os: r.os,
        last_seen: r.last_seen,
        status: r.status,
    }
}

/// `agent list` — fetch all registered agents.
///
/// # Examples
/// ```text
/// red-cell-cli agent list
/// ```
#[instrument(skip(client))]
pub async fn list(client: &ApiClient) -> Result<Vec<AgentSummary>, CliError> {
    let raw: Vec<RawAgent> = client.get("/agents").await?;
    Ok(raw.into_iter().map(agent_summary_from_raw).collect())
}
