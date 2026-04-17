//! Operator WebSocket handlers for listener lifecycle commands
//! (`ListenerNew`, `ListenerEdit`, `ListenerRemove`, `ListenerMark`).

use red_cell_common::operator::{ListenerInfo, ListenerMarkInfo, Message, NameInfo};
use serde_json::Value;

use super::serialize_for_audit;
use crate::websocket::events::teamserver_log_event;
use crate::websocket::lifecycle::log_operator_action;
use crate::{
    AuditResultStatus, AuditWebhookNotifier, Database, EventBus, ListenerEventAction,
    ListenerManager, action_from_mark, audit_details, authorize_listener_access,
    listener_config_from_operator, listener_error_event, listener_event_for_action,
    listener_removed_event, operator_requests_start, parameter_object,
};

pub(super) async fn handle_listener_new(
    listeners: &ListenerManager,
    events: &EventBus,
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    session: &crate::OperatorSession,
    message: Message<ListenerInfo>,
) {
    let name = message.info.name.clone().unwrap_or_default();
    let parameters = serialize_for_audit(&message.info, "listener.create");
    match listener_config_from_operator(&message.info) {
        Ok(config) => match listeners.create(config).await {
            Ok(summary) => {
                log_operator_action(
                    database,
                    webhooks,
                    &session.username,
                    "listener.create",
                    "listener",
                    Some(summary.name.clone()),
                    audit_details(
                        AuditResultStatus::Success,
                        None,
                        Some("create"),
                        parameters.clone(),
                    ),
                )
                .await;
                events.broadcast(listener_event_for_action(
                    &session.username,
                    &summary,
                    ListenerEventAction::Created,
                ));

                if operator_requests_start(&message.info) {
                    match listeners.start(&summary.name).await {
                        Ok(started) => {
                            log_operator_action(
                                database,
                                webhooks,
                                &session.username,
                                "listener.start",
                                "listener",
                                Some(started.name.clone()),
                                audit_details(
                                    AuditResultStatus::Success,
                                    None,
                                    Some("start"),
                                    Some(parameter_object([(
                                        "listener",
                                        Value::String(started.name.clone()),
                                    )])),
                                ),
                            )
                            .await;
                            events.broadcast(listener_event_for_action(
                                &session.username,
                                &started,
                                ListenerEventAction::Started,
                            ));
                        }
                        Err(error) => {
                            log_operator_action(
                                database,
                                webhooks,
                                &session.username,
                                "listener.start",
                                "listener",
                                Some(summary.name.clone()),
                                audit_details(
                                    AuditResultStatus::Failure,
                                    None,
                                    Some("start"),
                                    Some(parameter_object([
                                        ("listener", Value::String(summary.name.clone())),
                                        ("error", Value::String(error.to_string())),
                                    ])),
                                ),
                            )
                            .await;
                            events.broadcast(listener_error_event(
                                &session.username,
                                &summary.name,
                                &error,
                            ));
                        }
                    }
                }
            }
            Err(error) => {
                log_operator_action(
                    database,
                    webhooks,
                    &session.username,
                    "listener.create",
                    "listener",
                    (!name.is_empty()).then_some(name.clone()),
                    audit_details(
                        AuditResultStatus::Failure,
                        None,
                        Some("create"),
                        Some(parameter_object([
                            ("name", Value::String(name.clone())),
                            ("error", Value::String(error.to_string())),
                        ])),
                    ),
                )
                .await;
                events.broadcast(listener_error_event(&session.username, &name, &error));
            }
        },
        Err(error) => {
            log_operator_action(
                database,
                webhooks,
                &session.username,
                "listener.create",
                "listener",
                (!name.is_empty()).then_some(name.clone()),
                audit_details(
                    AuditResultStatus::Failure,
                    None,
                    Some("create"),
                    Some(parameter_object([
                        ("name", Value::String(name.clone())),
                        ("error", Value::String(error.to_string())),
                    ])),
                ),
            )
            .await;
            events.broadcast(listener_error_event(&session.username, &name, &error));
        }
    }
}

pub(super) async fn handle_listener_edit(
    listeners: &ListenerManager,
    events: &EventBus,
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    session: &crate::OperatorSession,
    message: Message<ListenerInfo>,
) {
    let name = message.info.name.clone().unwrap_or_default();
    let parameters = serialize_for_audit(&message.info, "listener.update");
    if !name.is_empty() {
        if let Err(error) = authorize_listener_access(database, &session.username, &name).await {
            log_operator_action(
                database,
                webhooks,
                &session.username,
                "listener.update",
                "listener",
                Some(name.clone()),
                audit_details(
                    AuditResultStatus::Failure,
                    None,
                    Some("update"),
                    Some(parameter_object([
                        ("config", parameters.clone().unwrap_or(Value::Null)),
                        ("error", Value::String(error.to_string())),
                    ])),
                ),
            )
            .await;
            events.broadcast(teamserver_log_event(&session.username, &error.to_string()));
            return;
        }
    }
    match listener_config_from_operator(&message.info) {
        Ok(config) => match listeners.update(config).await {
            Ok(summary) => {
                log_operator_action(
                    database,
                    webhooks,
                    &session.username,
                    "listener.update",
                    "listener",
                    Some(summary.name.clone()),
                    audit_details(
                        AuditResultStatus::Success,
                        None,
                        Some("update"),
                        serialize_for_audit(&summary.config, "listener.update.config"),
                    ),
                )
                .await;
                events.broadcast(listener_event_for_action(
                    &session.username,
                    &summary,
                    ListenerEventAction::Updated,
                ));
            }
            Err(error) => {
                log_operator_action(
                    database,
                    webhooks,
                    &session.username,
                    "listener.update",
                    "listener",
                    (!name.is_empty()).then_some(name.clone()),
                    audit_details(
                        AuditResultStatus::Failure,
                        None,
                        Some("update"),
                        Some(parameter_object([
                            ("config", parameters.clone().unwrap_or(Value::Null)),
                            ("error", Value::String(error.to_string())),
                        ])),
                    ),
                )
                .await;
                events.broadcast(listener_error_event(&session.username, &name, &error));
            }
        },
        Err(error) => {
            log_operator_action(
                database,
                webhooks,
                &session.username,
                "listener.update",
                "listener",
                (!name.is_empty()).then_some(name.clone()),
                audit_details(
                    AuditResultStatus::Failure,
                    None,
                    Some("update"),
                    Some(parameter_object([
                        ("config", parameters.unwrap_or(Value::Null)),
                        ("error", Value::String(error.to_string())),
                    ])),
                ),
            )
            .await;
            events.broadcast(listener_error_event(&session.username, &name, &error));
        }
    }
}

pub(super) async fn handle_listener_remove(
    listeners: &ListenerManager,
    events: &EventBus,
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    session: &crate::OperatorSession,
    message: Message<NameInfo>,
) {
    let name = message.info.name;
    if !name.is_empty() {
        if let Err(error) = authorize_listener_access(database, &session.username, &name).await {
            log_operator_action(
                database,
                webhooks,
                &session.username,
                "listener.delete",
                "listener",
                Some(name.clone()),
                audit_details(
                    AuditResultStatus::Failure,
                    None,
                    Some("delete"),
                    Some(parameter_object([
                        ("name", Value::String(name.clone())),
                        ("error", Value::String(error.to_string())),
                    ])),
                ),
            )
            .await;
            events.broadcast(teamserver_log_event(&session.username, &error.to_string()));
            return;
        }
    }
    match listeners.delete(&name).await {
        Ok(()) => {
            log_operator_action(
                database,
                webhooks,
                &session.username,
                "listener.delete",
                "listener",
                (!name.is_empty()).then_some(name.clone()),
                audit_details(
                    AuditResultStatus::Success,
                    None,
                    Some("delete"),
                    Some(parameter_object([("name", Value::String(name.clone()))])),
                ),
            )
            .await;
            events.broadcast(listener_removed_event(&session.username, &name));
        }
        Err(error) => {
            log_operator_action(
                database,
                webhooks,
                &session.username,
                "listener.delete",
                "listener",
                (!name.is_empty()).then_some(name.clone()),
                audit_details(
                    AuditResultStatus::Failure,
                    None,
                    Some("delete"),
                    Some(parameter_object([
                        ("name", Value::String(name.clone())),
                        ("error", Value::String(error.to_string())),
                    ])),
                ),
            )
            .await;
            events.broadcast(listener_error_event(&session.username, &name, &error));
        }
    }
}

pub(super) async fn handle_listener_mark(
    listeners: &ListenerManager,
    events: &EventBus,
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    session: &crate::OperatorSession,
    message: Message<ListenerMarkInfo>,
) {
    let name = message.info.name.clone();
    let mark = message.info.mark.clone();
    if !name.is_empty() {
        if let Err(error) = authorize_listener_access(database, &session.username, &name).await {
            let audit_action =
                if mark.eq_ignore_ascii_case("start") || mark.eq_ignore_ascii_case("online") {
                    "listener.start"
                } else {
                    "listener.stop"
                };
            log_operator_action(
                database,
                webhooks,
                &session.username,
                audit_action,
                "listener",
                Some(name.clone()),
                audit_details(
                    AuditResultStatus::Failure,
                    None,
                    Some(mark.as_str()),
                    Some(parameter_object([
                        ("mark", Value::String(mark.clone())),
                        ("error", Value::String(error.to_string())),
                    ])),
                ),
            )
            .await;
            events.broadcast(teamserver_log_event(&session.username, &error.to_string()));
            return;
        }
    }
    let result = match action_from_mark(&message.info.mark) {
        Ok(ListenerEventAction::Started) => listeners.start(&message.info.name).await,
        Ok(ListenerEventAction::Stopped) => listeners.stop(&message.info.name).await,
        Ok(ListenerEventAction::Created | ListenerEventAction::Updated) => unreachable!(),
        Err(error) => Err(error),
    };

    match result {
        Ok(summary) => {
            let action = if summary.state.status == crate::ListenerStatus::Running {
                ListenerEventAction::Started
            } else {
                ListenerEventAction::Stopped
            };
            let audit_action = if summary.state.status == crate::ListenerStatus::Running {
                "listener.start"
            } else {
                "listener.stop"
            };
            log_operator_action(
                database,
                webhooks,
                &session.username,
                audit_action,
                "listener",
                Some(summary.name.clone()),
                audit_details(
                    AuditResultStatus::Success,
                    None,
                    Some(mark.as_str()),
                    Some(parameter_object([("mark", Value::String(mark.clone()))])),
                ),
            )
            .await;
            events.broadcast(listener_event_for_action(&session.username, &summary, action));
        }
        Err(error) => {
            let audit_action =
                if mark.eq_ignore_ascii_case("start") || mark.eq_ignore_ascii_case("online") {
                    "listener.start"
                } else {
                    "listener.stop"
                };
            log_operator_action(
                database,
                webhooks,
                &session.username,
                audit_action,
                "listener",
                Some(name.clone()),
                audit_details(
                    AuditResultStatus::Failure,
                    None,
                    Some(mark.as_str()),
                    Some(parameter_object([
                        ("mark", Value::String(mark.clone())),
                        ("error", Value::String(error.to_string())),
                    ])),
                ),
            )
            .await;
            events.broadcast(listener_error_event(&session.username, &name, &error));
        }
    }
}
