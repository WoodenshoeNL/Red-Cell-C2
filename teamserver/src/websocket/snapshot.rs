use axum::extract::ws::WebSocket;
use thiserror::Error;

use super::acl::{agent_visible_to, listener_visible_to};
use super::connection::{SendMessageError, WsSession, send_hmac_message};
use super::events::{agent_snapshot_event, operator_snapshot_event};
use crate::{
    AgentRegistry, AuthError, AuthService, Database, EventBus, ListenerEventAction,
    ListenerManager, listener_event_for_action,
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
