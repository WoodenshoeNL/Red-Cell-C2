//! `agent show` — full details for one agent.

use tracing::instrument;

use crate::AgentId;
use crate::client::ApiClient;
use crate::error::CliError;

use super::types::AgentDetail;
use super::wire::RawAgent;

/// Map a [`RawAgent`] to the verbose `agent show` record.
pub(crate) fn agent_detail_from_raw(r: RawAgent) -> AgentDetail {
    AgentDetail {
        id: r.id,
        hostname: r.hostname,
        os: r.os,
        arch: r.arch,
        username: r.username,
        domain: r.domain,
        external_ip: r.external_ip,
        internal_ip: r.internal_ip,
        process_name: r.process_name,
        pid: r.pid,
        elevated: r.elevated,
        first_seen: r.first_seen,
        last_seen: r.last_seen,
        status: r.status,
        sleep_interval: r.sleep_interval,
        jitter: r.jitter,
        listener: r.listener,
    }
}

/// `agent show <id>` — fetch full details of a single agent.
///
/// # Examples
/// ```text
/// red-cell-cli agent show abc123
/// ```
#[instrument(skip(client))]
pub async fn show(client: &ApiClient, id: AgentId) -> Result<AgentDetail, CliError> {
    let raw: RawAgent = client.get(&format!("/agents/{id}")).await?;
    Ok(agent_detail_from_raw(raw))
}
