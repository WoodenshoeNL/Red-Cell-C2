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

#[cfg(test)]
mod tests {
    //! Verify that the WebSocket listener handlers refuse to act on listeners
    //! outside the operator's per-listener allow-list.  These mirror the REST
    //! `rbac_scope` tests but exercise the operator-WebSocket dispatch path.

    use std::time::{Duration, Instant};

    use red_cell_common::config::{OperatorRole, Profile};
    use red_cell_common::operator::{
        EventCode, ListenerInfo, ListenerMarkInfo, Message, MessageHead, NameInfo, OperatorMessage,
    };
    use red_cell_common::{HttpListenerConfig, ListenerConfig};
    use tokio::time::timeout;
    use uuid::Uuid;

    use crate::auth::OperatorSession;
    use crate::{
        AgentRegistry, AuditWebhookNotifier, Database, EventBus, ListenerManager,
        SocketRelayManager,
    };

    use super::{handle_listener_edit, handle_listener_mark, handle_listener_remove};

    struct Harness {
        listeners: ListenerManager,
        events: EventBus,
        database: Database,
        webhooks: AuditWebhookNotifier,
    }

    async fn build_harness() -> Harness {
        let database = Database::connect_in_memory().await.expect("database");
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let listeners =
            ListenerManager::new(database.clone(), registry, events.clone(), sockets, None)
                .with_demon_allow_legacy_ctr(true);
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40090
            }
            Operators {
              user "Neo" {
                Password = "password1234"
              }
            }
            Demon {}
            "#,
        )
        .expect("profile");
        let webhooks = AuditWebhookNotifier::from_profile(&profile);
        Harness { listeners, events, database, webhooks }
    }

    fn session(username: &str) -> OperatorSession {
        let now = Instant::now();
        OperatorSession {
            token: format!("{username}-token"),
            username: username.to_owned(),
            role: OperatorRole::Admin,
            connection_id: Uuid::new_v4(),
            created_at: now,
            last_activity_at: now,
        }
    }

    fn http_listener(name: &str, port: u16) -> ListenerConfig {
        ListenerConfig::from(HttpListenerConfig {
            name: name.to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["127.0.0.1".to_owned()],
            host_bind: "127.0.0.1".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: port,
            port_conn: None,
            method: None,
            behind_redirector: false,
            trusted_proxy_peers: Vec::new(),
            user_agent: None,
            headers: Vec::new(),
            uris: vec!["/".to_owned()],
            host_header: None,
            secure: false,
            cert: None,
            response: None,
            proxy: None,
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
        })
    }

    fn edit_message(name: &str, port: u16) -> Message<ListenerInfo> {
        Message {
            head: MessageHead {
                event: EventCode::Listener,
                user: "test".to_owned(),
                timestamp: String::new(),
                one_time: String::new(),
            },
            info: ListenerInfo {
                name: Some(name.to_owned()),
                protocol: Some("http".to_owned()),
                hosts: Some("127.0.0.1".to_owned()),
                host_bind: Some("127.0.0.1".to_owned()),
                host_rotation: Some("round-robin".to_owned()),
                port_bind: Some(port.to_string()),
                uris: Some("/".to_owned()),
                secure: Some("false".to_owned()),
                ..ListenerInfo::default()
            },
        }
    }

    async fn next_event(rx: &mut crate::events::EventReceiver) -> OperatorMessage {
        timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("event arrived in time")
            .expect("subscription open")
    }

    fn assert_log_event_for_user(message: &OperatorMessage, expected_user: &str) {
        let body = serde_json::to_value(message).expect("message to json");
        let head = body.get("Head").expect("Head field");
        assert_eq!(head.get("User").and_then(|v| v.as_str()), Some(expected_user));
    }

    #[tokio::test]
    async fn handle_listener_edit_denies_operator_outside_allow_list() {
        let h = build_harness().await;
        let summary = h.listeners.create(http_listener("alice-only", 40130)).await.expect("create");
        h.database
            .listener_access()
            .set_allowed_operators(&summary.name, &["alice".to_owned()])
            .await
            .expect("seed");

        let mut rx = h.events.subscribe();

        handle_listener_edit(
            &h.listeners,
            &h.events,
            &h.database,
            &h.webhooks,
            &session("bob"),
            edit_message("alice-only", 40131),
        )
        .await;

        let envelope = next_event(&mut rx).await;
        assert_log_event_for_user(&envelope, "bob");

        let after = h.listeners.summary("alice-only").await.expect("summary");
        let ListenerConfig::Http(http) = &after.config else {
            panic!("expected http listener");
        };
        assert_eq!(http.port_bind, 40130, "edit must not have applied");
    }

    #[tokio::test]
    async fn handle_listener_remove_denies_operator_outside_allow_list() {
        let h = build_harness().await;
        let summary = h.listeners.create(http_listener("alice-only", 40132)).await.expect("create");
        h.database
            .listener_access()
            .set_allowed_operators(&summary.name, &["alice".to_owned()])
            .await
            .expect("seed");

        let mut rx = h.events.subscribe();

        handle_listener_remove(
            &h.listeners,
            &h.events,
            &h.database,
            &h.webhooks,
            &session("bob"),
            Message {
                head: MessageHead {
                    event: EventCode::Listener,
                    user: "test".to_owned(),
                    timestamp: String::new(),
                    one_time: String::new(),
                },
                info: NameInfo { name: "alice-only".to_owned() },
            },
        )
        .await;

        let envelope = next_event(&mut rx).await;
        assert_log_event_for_user(&envelope, "bob");

        h.listeners.summary("alice-only").await.expect("listener still exists");
    }

    #[tokio::test]
    async fn handle_listener_mark_denies_operator_outside_allow_list() {
        let h = build_harness().await;
        let summary = h.listeners.create(http_listener("alice-only", 40133)).await.expect("create");
        h.database
            .listener_access()
            .set_allowed_operators(&summary.name, &["alice".to_owned()])
            .await
            .expect("seed");

        let mut rx = h.events.subscribe();

        handle_listener_mark(
            &h.listeners,
            &h.events,
            &h.database,
            &h.webhooks,
            &session("bob"),
            Message {
                head: MessageHead {
                    event: EventCode::Listener,
                    user: "test".to_owned(),
                    timestamp: String::new(),
                    one_time: String::new(),
                },
                info: ListenerMarkInfo { name: "alice-only".to_owned(), mark: "start".to_owned() },
            },
        )
        .await;

        let envelope = next_event(&mut rx).await;
        assert_log_event_for_user(&envelope, "bob");

        let after = h.listeners.summary("alice-only").await.expect("summary");
        assert_ne!(after.state.status, crate::ListenerStatus::Running);
    }
}
