use serde_json::Value;
use tracing::warn;
use uuid::Uuid;

use super::connection::{DisconnectKind, OperatorConnectionManager};
use super::events::chat_presence_event;
use crate::{
    AuditResultStatus, AuditWebhookNotifier, AuthService, Database, EventBus, audit_details,
    parameter_object, record_operator_action_with_notifications,
};

pub(super) async fn cleanup_connection(
    auth: &AuthService,
    connections: &OperatorConnectionManager,
    events: &EventBus,
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    connection_id: Uuid,
    disconnect_kind: DisconnectKind,
) {
    if let Some(session) = auth.remove_connection(connection_id).await {
        log_operator_action(
            database,
            webhooks,
            &session.username,
            "operator.disconnect",
            "operator",
            Some(session.username.clone()),
            audit_details(
                AuditResultStatus::Success,
                None,
                Some("disconnect"),
                Some(parameter_object([
                    ("connection_id", Value::String(connection_id.to_string())),
                    ("kind", Value::String(disconnect_kind.as_str().to_owned())),
                ])),
            ),
        )
        .await;

        if last_online_session(auth, &session.username).await {
            events.broadcast(chat_presence_event(&session.username, false));
        }
    }
    connections.unregister(connection_id).await;
}

pub(super) async fn first_online_session(auth: &AuthService, username: &str) -> bool {
    auth.active_sessions().await.into_iter().filter(|session| session.username == username).count()
        == 1
}

pub(super) async fn last_online_session(auth: &AuthService, username: &str) -> bool {
    auth.active_sessions().await.into_iter().all(|session| session.username != username)
}

pub(super) async fn log_operator_action(
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    actor: &str,
    action: &str,
    target_kind: &str,
    target_id: Option<String>,
    details: crate::AuditDetails,
) {
    if let Err(error) = record_operator_action_with_notifications(
        database,
        webhooks,
        actor,
        action,
        target_kind,
        target_id,
        details,
    )
    .await
    {
        warn!(actor, action, %error, "failed to persist audit log entry");
    }
}
