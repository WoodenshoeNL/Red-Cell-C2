//! `listener start`, `stop`, `delete`, `access`, and `set-access` implementations.

use tracing::instrument;

use crate::client::ApiClient;
use crate::error::CliError;

use super::{
    ListenerAccessInfo, ListenerActionResult, ListenerDeleted, RawListenerAccessResponse,
    RawListenerSummary,
};

/// `listener start <name>` — start a stopped listener.
///
/// Idempotent: if the listener is already running the current state is
/// returned with `already_in_state: true`.
///
/// # Examples
/// ```text
/// red-cell-cli listener start http1
/// ```
#[instrument(skip(client))]
pub(super) async fn start(
    client: &ApiClient,
    name: &str,
) -> Result<ListenerActionResult, CliError> {
    match client.put_empty::<RawListenerSummary>(&format!("/listeners/{name}/start")).await {
        Ok(raw) => Ok(ListenerActionResult {
            name: name.to_owned(),
            status: raw.state.status,
            already_in_state: false,
        }),
        Err(CliError::General(msg)) if msg.contains("listener_already_running") => {
            let raw: RawListenerSummary = client.get(&format!("/listeners/{name}")).await?;
            Ok(ListenerActionResult {
                name: name.to_owned(),
                status: raw.state.status,
                already_in_state: true,
            })
        }
        Err(e) => Err(e),
    }
}

/// `listener stop <name>` — stop a running listener.
///
/// Idempotent: if the listener is already stopped the current state is
/// returned with `already_in_state: true`.
///
/// # Examples
/// ```text
/// red-cell-cli listener stop http1
/// ```
#[instrument(skip(client))]
pub(super) async fn stop(client: &ApiClient, name: &str) -> Result<ListenerActionResult, CliError> {
    match client.put_empty::<RawListenerSummary>(&format!("/listeners/{name}/stop")).await {
        Ok(raw) => Ok(ListenerActionResult {
            name: name.to_owned(),
            status: raw.state.status,
            already_in_state: false,
        }),
        Err(CliError::General(msg)) if msg.contains("listener_not_running") => {
            let raw: RawListenerSummary = client.get(&format!("/listeners/{name}")).await?;
            Ok(ListenerActionResult {
                name: name.to_owned(),
                status: raw.state.status,
                already_in_state: true,
            })
        }
        Err(e) => Err(e),
    }
}

/// `listener delete <name>` — permanently delete a listener.
///
/// # Examples
/// ```text
/// red-cell-cli listener delete http1
/// ```
#[instrument(skip(client))]
pub(super) async fn delete(client: &ApiClient, name: &str) -> Result<ListenerDeleted, CliError> {
    client.delete_no_body(&format!("/listeners/{name}")).await?;
    Ok(ListenerDeleted { name: name.to_owned(), deleted: true })
}

/// `listener access <name>` — fetch the operator allow-list for a listener.
///
/// # Examples
/// ```text
/// red-cell-cli listener access http1
/// ```
#[instrument(skip(client))]
pub(super) async fn get_access(
    client: &ApiClient,
    name: &str,
) -> Result<ListenerAccessInfo, CliError> {
    let raw: RawListenerAccessResponse = client.get(&format!("/listeners/{name}/access")).await?;
    Ok(ListenerAccessInfo {
        listener_name: raw.listener_name,
        allowed_operators: raw.allowed_operators,
    })
}

/// `listener set-access <name>` — replace the operator allow-list.
///
/// # Examples
/// ```text
/// red-cell-cli listener set-access http1 --allow-operator alice
/// red-cell-cli listener set-access http1
/// ```
#[instrument(skip(client, operators))]
pub(super) async fn set_access(
    client: &ApiClient,
    name: &str,
    operators: &[String],
) -> Result<ListenerAccessInfo, CliError> {
    let body = serde_json::json!({ "allowed_operators": operators });
    let raw: RawListenerAccessResponse =
        client.put(&format!("/listeners/{name}/access"), &body).await?;
    Ok(ListenerAccessInfo {
        listener_name: raw.listener_name,
        allowed_operators: raw.allowed_operators,
    })
}
