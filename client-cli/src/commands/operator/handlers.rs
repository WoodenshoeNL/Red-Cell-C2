//! Individual `operator` command implementations.

use tracing::instrument;

use crate::client::ApiClient;
use crate::error::CliError;

use super::types::{
    ActiveOperatorRow, CreateResult, DeleteResult, LogoutResult, OperatorGroupAccessInfo,
    OperatorRow, RawActiveOperatorEntry, RawCreateResponse, RawLogoutResponse,
    RawOperatorGroupAccessResponse, RawOperatorSummary, SetRoleResult,
};
use super::validate_role;

/// `operator list` — fetch all registered operators.
///
/// # Examples
/// ```text
/// red-cell-cli operator list
/// ```
#[instrument(skip(client))]
pub(super) async fn list(client: &ApiClient) -> Result<Vec<OperatorRow>, CliError> {
    let raw: Vec<RawOperatorSummary> = client.get("/operators").await?;
    Ok(raw.into_iter().map(operator_row_from_raw).collect())
}

/// `operator create <username> --password <password> --role <role>` — create a new operator.
///
/// # Examples
/// ```text
/// red-cell-cli operator create alice --role operator --password s3cr3t!
/// red-cell-cli operator create bob   --role admin    --password hunter2
/// ```
#[instrument(skip(client, password))]
pub(super) async fn create(
    client: &ApiClient,
    username: &str,
    password: &str,
    role: &str,
) -> Result<CreateResult, CliError> {
    validate_role(role)?;

    let body = serde_json::json!({ "username": username, "password": password, "role": role });
    let raw: RawCreateResponse = client.post("/operators", &body).await?;

    Ok(CreateResult { username: raw.username, role: raw.role.to_lowercase() })
}

/// `operator delete <username>` — permanently remove an operator account.
///
/// # Examples
/// ```text
/// red-cell-cli operator delete alice
/// ```
#[instrument(skip(client))]
pub(super) async fn delete(client: &ApiClient, username: &str) -> Result<DeleteResult, CliError> {
    client.delete_no_body(&format!("/operators/{username}")).await?;
    Ok(DeleteResult { username: username.to_owned() })
}

/// `operator set-role <username> <role>` — change an operator's role.
///
/// # Examples
/// ```text
/// red-cell-cli operator set-role alice admin
/// red-cell-cli operator set-role bob   analyst
/// ```
#[instrument(skip(client))]
pub(super) async fn set_role(
    client: &ApiClient,
    username: &str,
    role: &str,
) -> Result<SetRoleResult, CliError> {
    validate_role(role)?;

    let body = serde_json::json!({ "role": role });
    let raw: RawOperatorSummary = client.put(&format!("/operators/{username}/role"), &body).await?;

    Ok(SetRoleResult { username: raw.username, role: raw.role.to_lowercase() })
}

/// `operator show-agent-groups <username>` — fetch RBAC agent-group restrictions.
///
/// # Examples
/// ```text
/// red-cell-cli operator show-agent-groups alice
/// ```
#[instrument(skip(client))]
pub(super) async fn get_operator_agent_groups(
    client: &ApiClient,
    username: &str,
) -> Result<OperatorGroupAccessInfo, CliError> {
    let raw: RawOperatorGroupAccessResponse =
        client.get(&format!("/operators/{username}/agent-groups")).await?;
    Ok(OperatorGroupAccessInfo { username: raw.username, allowed_groups: raw.allowed_groups })
}

/// `operator set-agent-groups <username>` — replace agent-group restrictions.
///
/// # Examples
/// ```text
/// red-cell-cli operator set-agent-groups alice --group tier1
/// red-cell-cli operator set-agent-groups alice
/// ```
#[instrument(skip(client, groups))]
pub(super) async fn set_operator_agent_groups(
    client: &ApiClient,
    username: &str,
    groups: &[String],
) -> Result<OperatorGroupAccessInfo, CliError> {
    let body = serde_json::json!({ "allowed_groups": groups });
    let raw: RawOperatorGroupAccessResponse =
        client.put(&format!("/operators/{username}/agent-groups"), &body).await?;
    Ok(OperatorGroupAccessInfo { username: raw.username, allowed_groups: raw.allowed_groups })
}

/// `operator active` — list operators with live WebSocket connections.
///
/// # Examples
/// ```text
/// red-cell-cli operator active
/// ```
#[instrument(skip(client))]
pub(super) async fn active(client: &ApiClient) -> Result<Vec<ActiveOperatorRow>, CliError> {
    let raw: Vec<RawActiveOperatorEntry> = client.get("/operators/active").await?;
    Ok(raw
        .into_iter()
        .map(|r| ActiveOperatorRow {
            username: r.username,
            connect_time: r.connect_time,
            remote_addr: r.remote_addr,
        })
        .collect())
}

/// `operator logout <username>` — revoke all active sessions for an operator.
///
/// # Examples
/// ```text
/// red-cell-cli operator logout alice
/// ```
#[instrument(skip(client))]
pub(super) async fn logout(client: &ApiClient, username: &str) -> Result<LogoutResult, CliError> {
    let raw: RawLogoutResponse =
        client.post_empty(&format!("/operators/{username}/logout")).await?;
    Ok(LogoutResult { username: raw.username, revoked_sessions: raw.revoked_sessions })
}

pub(super) fn operator_row_from_raw(raw: RawOperatorSummary) -> OperatorRow {
    OperatorRow {
        username: raw.username,
        role: raw.role.to_lowercase(),
        online: raw.online,
        last_seen: raw.last_seen,
    }
}
