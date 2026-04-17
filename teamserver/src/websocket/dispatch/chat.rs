//! Operator WebSocket handler for `ChatMessage`.

use red_cell_common::operator::{FlatInfo, Message};
use serde_json::Value;

use crate::websocket::command_enc::flat_info_string;
use crate::websocket::events::chat_message_event;
use crate::websocket::lifecycle::log_operator_action;
use crate::{
    AuditResultStatus, AuditWebhookNotifier, Database, EventBus, audit_details, parameter_object,
};

pub(super) async fn handle_chat_message(
    events: &EventBus,
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    session: &crate::OperatorSession,
    message: Message<FlatInfo>,
) {
    let text = flat_info_string(&message.info, &["Message", "Text"]).unwrap_or_default();
    if !text.trim().is_empty() {
        let trimmed = text.trim();
        events.broadcast(chat_message_event(&session.username, trimmed));
        log_operator_action(
            database,
            webhooks,
            &session.username,
            "operator.chat",
            "operator",
            Some(session.username.clone()),
            audit_details(
                AuditResultStatus::Success,
                None,
                Some("chat"),
                Some(parameter_object([("message", Value::String(trimmed.to_owned()))])),
            ),
        )
        .await;
    }
}
