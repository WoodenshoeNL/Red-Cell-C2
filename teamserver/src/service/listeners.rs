use red_cell_common::operator::{
    EventCode, ListenerErrorInfo, ListenerMarkInfo, Message, MessageHead, OperatorMessage,
    ServiceListenerRegistrationInfo,
};
use serde_json::Value;
use time::OffsetDateTime;
use tracing::{debug, info, warn};

use crate::audit::{AuditResultStatus, audit_details};
use crate::{AuditWebhookNotifier, Database, EventBus};

use super::logging::log_service_action;
use super::{BODY_LISTENER_ADD, BODY_LISTENER_START, ServiceBridge, ServiceBridgeError};

/// Handle a `Listener` message — register or start service-provided listeners.
pub(super) async fn handle_listener_message(
    message: &Value,
    bridge: &ServiceBridge,
    events: &EventBus,
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    client_listeners: &mut Vec<String>,
) -> Result<(), ServiceBridgeError> {
    let body_type =
        message.get("Body").and_then(|b| b.get("Type")).and_then(Value::as_str).unwrap_or_default();

    match body_type {
        BODY_LISTENER_ADD => {
            handle_listener_add(message, bridge, events, database, webhooks, client_listeners).await
        }
        BODY_LISTENER_START => handle_listener_start(message, events, database, webhooks).await,
        other => {
            debug!(body_type = %other, "unknown service listener sub-message type");
            Ok(())
        }
    }
}

/// Handle a `ListenerAdd` message — register a custom listener provided by a
/// service client.
pub(super) async fn handle_listener_add(
    message: &Value,
    bridge: &ServiceBridge,
    events: &EventBus,
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    client_listeners: &mut Vec<String>,
) -> Result<(), ServiceBridgeError> {
    let listener = message
        .get("Body")
        .and_then(|b| b.get("Listener"))
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Listener".to_owned()))?;

    let name = listener
        .get("Name")
        .and_then(Value::as_str)
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Listener.Name".to_owned()))?;

    bridge.register_listener(name.to_owned()).await;
    client_listeners.push(name.to_owned());

    info!(name = %name, "service listener registered");

    log_service_action(
        database,
        webhooks,
        "service.listener_add",
        "listener",
        Some(name.to_owned()),
        audit_details(AuditResultStatus::Success, None, None, None),
    )
    .await;

    let listener_json = serde_json::to_string(listener)?;
    let event = OperatorMessage::ServiceListenerRegister(Message {
        head: MessageHead {
            event: EventCode::Service,
            user: String::new(),
            timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
            one_time: String::new(),
        },
        info: ServiceListenerRegistrationInfo { listener: listener_json },
    });
    events.broadcast(event);

    Ok(())
}

/// Handle a `ListenerStart` notification — validate the listener metadata
/// and broadcast the start status to connected operators.
///
/// The Havoc service protocol sends start notifications with the following
/// fields inside `Body.Listener`:
/// - `Name` — listener name (required)
/// - `Protocol` — listener protocol, e.g. "HTTPS" (required)
/// - `Host` — bind host (required)
/// - `PortBind` — bind port (required)
/// - `Status` — start status string, e.g. "online" or "error" (required)
/// - `Error` — error description if the start failed (required, may be empty)
/// - `Info` — additional listener metadata (optional)
pub(super) async fn handle_listener_start(
    message: &Value,
    events: &EventBus,
    database: &Database,
    webhooks: &AuditWebhookNotifier,
) -> Result<(), ServiceBridgeError> {
    let body =
        message.get("Body").ok_or_else(|| ServiceBridgeError::MissingField("Body".to_owned()))?;

    let listener = body
        .get("Listener")
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Listener".to_owned()))?;

    let name = listener
        .get("Name")
        .and_then(Value::as_str)
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Listener.Name".to_owned()))?;

    let protocol = listener
        .get("Protocol")
        .and_then(Value::as_str)
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Listener.Protocol".to_owned()))?;

    let host = listener
        .get("Host")
        .and_then(Value::as_str)
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Listener.Host".to_owned()))?;

    let port_bind = listener
        .get("PortBind")
        .and_then(Value::as_str)
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Listener.PortBind".to_owned()))?;

    let status = listener
        .get("Status")
        .and_then(Value::as_str)
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Listener.Status".to_owned()))?;

    let error_text = listener
        .get("Error")
        .and_then(Value::as_str)
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Listener.Error".to_owned()))?;

    let head = MessageHead {
        event: EventCode::Listener,
        user: "service".to_owned(),
        timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
        one_time: String::new(),
    };

    let is_error = status.eq_ignore_ascii_case("error") || !error_text.is_empty();

    if is_error {
        warn!(
            %name, %protocol, %host, %port_bind, %error_text,
            "service listener start failed"
        );
        log_service_action(
            database,
            webhooks,
            "service.listener_start",
            "listener",
            Some(name.to_owned()),
            audit_details(AuditResultStatus::Failure, None, None, None),
        )
        .await;
        let event = OperatorMessage::ListenerError(Message {
            head,
            info: ListenerErrorInfo { error: error_text.to_owned(), name: name.to_owned() },
        });
        events.broadcast(event);
    } else {
        info!(
            %name, %protocol, %host, %port_bind, %status,
            "service listener started"
        );
        log_service_action(
            database,
            webhooks,
            "service.listener_start",
            "listener",
            Some(name.to_owned()),
            audit_details(AuditResultStatus::Success, None, None, None),
        )
        .await;
        let event = OperatorMessage::ListenerMark(Message {
            head,
            info: ListenerMarkInfo { name: name.to_owned(), mark: "Online".to_owned() },
        });
        events.broadcast(event);
    }

    Ok(())
}
