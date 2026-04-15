use std::collections::BTreeMap;

use axum::extract::ws::WebSocket;
use red_cell_common::operator::{EventCode, FlatInfo, Message, MessageHead, OperatorMessage};
use red_cell_common::{AgentRecord, OperatorInfo};
use thiserror::Error;

use super::connection::{SendMessageError, WsSession, send_hmac_message};
use crate::{
    AgentRegistry, AuthError, AuthService, EventBus, ListenerEventAction, ListenerManager,
    agent_events::agent_new_event, listener_event_for_action,
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

pub(super) async fn send_session_snapshot(
    socket: &mut WebSocket,
    auth: &AuthService,
    events: &EventBus,
    listeners: &ListenerManager,
    registry: &AgentRegistry,
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
        let pivots = registry.pivots(agent.agent_id).await;
        let listener_name =
            registry.listener_name(agent.agent_id).await.unwrap_or_else(|| "null".to_owned());
        send_hmac_message(
            socket,
            &agent_snapshot_event(&listener_name, &agent, &pivots),
            ws_session,
        )
        .await?;
    }

    Ok(())
}

pub(super) fn agent_snapshot_event(
    listener_name: &str,
    agent: &AgentRecord,
    pivots: &crate::PivotInfo,
) -> OperatorMessage {
    agent_new_event(listener_name, red_cell_common::demon::DEMON_MAGIC_VALUE, agent, pivots)
}

fn operator_snapshot_event(
    operators: Vec<OperatorInfo>,
) -> Result<OperatorMessage, serde_json::Error> {
    Ok(OperatorMessage::InitConnectionInfo(Message {
        head: MessageHead {
            event: EventCode::InitConnection,
            user: String::new(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: FlatInfo {
            fields: BTreeMap::from([("Operators".to_owned(), serde_json::to_value(operators)?)]),
        },
    }))
}
