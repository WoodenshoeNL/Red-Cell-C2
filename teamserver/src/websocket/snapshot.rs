use axum::extract::ws::WebSocket;
use thiserror::Error;

use super::connection::{SendMessageError, WsSession, send_hmac_message};
use super::events::{agent_snapshot_event, operator_snapshot_event};
use crate::{
    AgentRegistry, AuthError, AuthService, AuthorizationError, Database, EventBus,
    ListenerEventAction, ListenerManager, authorize_agent_group_access, authorize_listener_access,
    listener_event_for_action,
};

#[derive(Debug, Error)]
pub(super) enum SnapshotSyncError {
    #[error(transparent)]
    Send(#[from] SendMessageError),
    #[error(transparent)]
    Serialize(#[from] serde_json::Error),
    #[error(transparent)]
    Listener(#[from] crate::ListenerManagerError),
    #[error(transparent)]
    Teamserver(#[from] crate::TeamserverError),
    #[error(transparent)]
    Auth(#[from] AuthError),
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn send_session_snapshot(
    socket: &mut WebSocket,
    auth: &AuthService,
    events: &EventBus,
    listeners: &ListenerManager,
    registry: &AgentRegistry,
    database: &Database,
    username: &str,
    ws_session: &mut WsSession,
) -> Result<(), SnapshotSyncError> {
    let operators = auth
        .operator_inventory()
        .await?
        .into_iter()
        .map(|entry| entry.as_operator_info())
        .collect();
    send_hmac_message(socket, &operator_snapshot_event(operators)?, ws_session).await?;

    for summary in listeners.list().await?.into_iter() {
        if !listener_visible_to(database, username, &summary.name).await {
            continue;
        }
        send_hmac_message(
            socket,
            &listener_event_for_action("teamserver", &summary, ListenerEventAction::Created),
            ws_session,
        )
        .await?;
    }

    for message in events.recent_teamserver_logs() {
        send_hmac_message(socket, &message, ws_session).await?;
    }

    for agent in registry.list_active().await {
        let listener_name = registry.listener_name(agent.agent_id).await;
        if !agent_visible_to(database, username, agent.agent_id, listener_name.as_deref()).await {
            continue;
        }
        let pivots = registry.pivots(agent.agent_id).await;
        let display_listener = listener_name.unwrap_or_else(|| "null".to_owned());
        send_hmac_message(
            socket,
            &agent_snapshot_event(&display_listener, &agent, &pivots),
            ws_session,
        )
        .await?;
    }

    Ok(())
}

/// Apply the per-operator listener allow-list to the snapshot feed.
///
/// Mirrors the REST list-endpoint filter so a restricted operator does not
/// learn of listeners outside their scope via the WebSocket snapshot.
async fn listener_visible_to(database: &Database, username: &str, listener_name: &str) -> bool {
    match authorize_listener_access(database, username, listener_name).await {
        Ok(()) => true,
        Err(AuthorizationError::ListenerAccessDenied { .. }) => false,
        Err(err) => {
            tracing::warn!(
                %username,
                %listener_name,
                %err,
                "listener ACL check failed; hiding listener from snapshot"
            );
            false
        }
    }
}

/// Apply the composite agent-group + listener allow-list to the snapshot feed.
///
/// Mirrors `api::agents::operator_may_access_agent` so a restricted operator
/// does not learn of agents outside their scope via the WebSocket snapshot.
async fn agent_visible_to(
    database: &Database,
    username: &str,
    agent_id: u32,
    listener_name: Option<&str>,
) -> bool {
    if let Err(err) = authorize_agent_group_access(database, username, agent_id).await {
        return match err {
            AuthorizationError::AgentGroupDenied { .. } => false,
            other => {
                tracing::warn!(
                    %username,
                    agent_id,
                    err = %other,
                    "agent-group ACL check failed; hiding agent from snapshot"
                );
                false
            }
        };
    }

    if let Some(listener_name) = listener_name {
        return listener_visible_to(database, username, listener_name).await;
    }

    true
}
