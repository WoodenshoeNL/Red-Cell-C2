//! `agent groups` / `agent set-groups` — RBAC tags on an agent.

use tracing::instrument;

use crate::AgentId;
use crate::client::ApiClient;
use crate::error::CliError;

use super::types::{AgentGroupsInfo, RawAgentGroupsResponse};

/// `agent groups <id>` — fetch RBAC group tags for an agent.
///
/// # Examples
/// ```text
/// red-cell-cli agent groups DEADBEEF
/// ```
#[instrument(skip(client))]
pub async fn get_groups(client: &ApiClient, id: AgentId) -> Result<AgentGroupsInfo, CliError> {
    let raw: RawAgentGroupsResponse = client.get(&format!("/agents/{id}/groups")).await?;
    Ok(AgentGroupsInfo { agent_id: raw.agent_id, groups: raw.groups })
}

/// `agent set-groups <id>` — replace RBAC group membership for an agent.
///
/// # Examples
/// ```text
/// red-cell-cli agent set-groups DEADBEEF --group tier1 --group corp
/// red-cell-cli agent set-groups DEADBEEF
/// ```
#[instrument(skip(client, groups))]
pub async fn set_groups(
    client: &ApiClient,
    id: AgentId,
    groups: &[String],
) -> Result<AgentGroupsInfo, CliError> {
    let body = serde_json::json!({ "groups": groups });
    let raw: RawAgentGroupsResponse = client.put(&format!("/agents/{id}/groups"), &body).await?;
    Ok(AgentGroupsInfo { agent_id: raw.agent_id, groups: raw.groups })
}
