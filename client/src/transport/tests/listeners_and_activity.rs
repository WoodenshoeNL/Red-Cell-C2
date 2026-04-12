use super::super::*;
use std::collections::BTreeMap;
use std::sync::Arc;

use super::helpers::head;
use red_cell_common::operator::{
    BuildPayloadMessageInfo, ChatCode, EventCode, FlatInfo, InitConnectionCode, ListenerCode,
    ListenerErrorInfo, LoginInfo, Message, MessageHead, MessageInfo, SessionCode,
};
#[test]
fn listener_error_updates_existing_listener_status_and_pushes_chat() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
    // Pre-populate a listener so we can verify it is updated in-place.
    Arc::make_mut(&mut state.listeners).push(ListenerSummary {
        name: "http".to_owned(),
        protocol: "Https".to_owned(),
        host: "0.0.0.0".to_owned(),
        port_bind: "443".to_owned(),
        port_conn: "443".to_owned(),
        status: "Online".to_owned(),
    });
    let log_before = state.event_log.len();

    state.apply_operator_message(OperatorMessage::ListenerError(Message {
        head: head(EventCode::Listener),
        info: ListenerErrorInfo { name: "http".to_owned(), error: "port in use".to_owned() },
    }));

    assert_eq!(state.listeners.len(), 1, "upsert should not create a duplicate");
    let listener = &state.listeners[0];
    assert!(
        listener.status.starts_with("Error:"),
        "status should start with 'Error:' but was: {:?}",
        listener.status
    );
    assert!(
        listener.status.contains("port in use"),
        "status should contain the error text but was: {:?}",
        listener.status
    );
    assert_eq!(
        state.event_log.len(),
        log_before + 1,
        "an event notification should have been appended"
    );
    let entry = state.event_log.entries.back().expect("entry should exist");
    assert!(
        entry.message.contains("port in use"),
        "event message should echo the error text but was: {:?}",
        entry.message
    );
}

#[test]
fn listener_error_creates_new_listener_entry_when_none_exists() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
    assert!(state.listeners.is_empty());

    state.apply_operator_message(OperatorMessage::ListenerError(Message {
        head: head(EventCode::Listener),
        info: ListenerErrorInfo { name: "smb".to_owned(), error: "bind failed".to_owned() },
    }));

    assert_eq!(state.listeners.len(), 1, "upsert should create a new entry");
    let listener = &state.listeners[0];
    assert_eq!(listener.name, "smb");
    assert!(
        listener.status.starts_with("Error:"),
        "status should start with 'Error:' but was: {:?}",
        listener.status
    );
    assert_eq!(state.event_log.len(), 1, "event notification should be appended");
}

#[test]
fn message_variants_used_by_transport_state_reducer_are_constructible() {
    let _ =
        (InitConnectionCode::Success, ListenerCode::New, SessionCode::AgentNew, ChatCode::Message);
    let _ =
        BuildPayloadMessageInfo { message_type: "info".to_owned(), message: "built".to_owned() };
    let _ = MessageInfo { message: "ok".to_owned() };
    let _ = ListenerErrorInfo { error: "failed".to_owned(), name: "http".to_owned() };
}

#[test]
fn queue_message_forwards_commands_to_sender_task() {
    let (outgoing_tx, mut outgoing_rx) = mpsc::unbounded_channel();
    let (shutdown_tx, _) = watch::channel(false);
    let transport = ClientTransport { runtime: None, shutdown_tx, outgoing_tx };

    let message = OperatorMessage::Login(Message {
        head: head(EventCode::InitConnection),
        info: LoginInfo { user: "operator".to_owned(), password: "hash".to_owned() },
    });

    transport
        .queue_message(message.clone())
        .unwrap_or_else(|error| panic!("queue_message should succeed: {error}"));

    let queued_message = outgoing_rx
        .try_recv()
        .unwrap_or_else(|error| panic!("queued message should be available: {error}"));
    assert_eq!(queued_message, message);
}

#[test]
fn queue_message_returns_error_when_sender_is_closed() {
    let (outgoing_tx, outgoing_rx) = mpsc::unbounded_channel();
    drop(outgoing_rx);
    let (shutdown_tx, _) = watch::channel(false);
    let transport = ClientTransport { runtime: None, shutdown_tx, outgoing_tx };

    let result = transport.queue_message(OperatorMessage::Login(Message {
        head: head(EventCode::InitConnection),
        info: LoginInfo { user: "operator".to_owned(), password: "hash".to_owned() },
    }));

    assert!(matches!(result, Err(TransportError::OutgoingQueueClosed)));
}

#[test]
fn agent_task_records_activity_in_connected_operators() {
    use red_cell_common::operator::AgentTaskInfo;

    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::AgentTask(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "alice".to_owned(),
            timestamp: "10/03/2026 12:00:00".to_owned(),
            one_time: String::new(),
        },
        info: AgentTaskInfo {
            task_id: "1".to_owned(),
            command_line: "shell whoami".to_owned(),
            demon_id: "abcd1234".to_owned(),
            command_id: "9".to_owned(),
            ..AgentTaskInfo::default()
        },
    }));
    state.apply_operator_message(OperatorMessage::AgentTask(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "alice".to_owned(),
            timestamp: "10/03/2026 12:01:00".to_owned(),
            one_time: String::new(),
        },
        info: AgentTaskInfo {
            task_id: "2".to_owned(),
            command_line: "ps".to_owned(),
            demon_id: "beef5678".to_owned(),
            command_id: "35".to_owned(),
            ..AgentTaskInfo::default()
        },
    }));

    let alice = state
        .connected_operators
        .get("alice")
        .unwrap_or_else(|| panic!("alice should be in connected_operators"));
    assert_eq!(alice.recent_commands.len(), 2, "both commands should be recorded");
    // Newest first.
    assert_eq!(alice.recent_commands[0].command_line, "ps");
    assert_eq!(alice.recent_commands[0].agent_id, "BEEF5678");
    assert_eq!(alice.recent_commands[1].command_line, "shell whoami");
    assert_eq!(alice.recent_commands[1].agent_id, "ABCD1234");
    assert_eq!(
        alice.last_seen.as_deref(),
        Some("10/03/2026 12:01:00"),
        "last_seen should reflect most recent command timestamp"
    );
}

#[test]
fn agent_task_with_empty_user_is_ignored() {
    use red_cell_common::operator::AgentTaskInfo;

    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::AgentTask(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: String::new(),
            timestamp: "10/03/2026 12:00:00".to_owned(),
            one_time: String::new(),
        },
        info: AgentTaskInfo {
            task_id: "1".to_owned(),
            command_line: "shell whoami".to_owned(),
            demon_id: "abcd1234".to_owned(),
            command_id: "9".to_owned(),
            ..AgentTaskInfo::default()
        },
    }));

    assert!(
        state.connected_operators.is_empty(),
        "empty-username task should not create an operator entry"
    );
}

#[test]
fn activity_feed_capped_at_max_operator_activity() {
    use red_cell_common::operator::AgentTaskInfo;

    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    for i in 0..=(MAX_OPERATOR_ACTIVITY + 5) {
        state.apply_operator_message(OperatorMessage::AgentTask(Message {
            head: MessageHead {
                event: EventCode::Session,
                user: "bob".to_owned(),
                timestamp: format!("ts-{i}"),
                one_time: String::new(),
            },
            info: AgentTaskInfo {
                task_id: i.to_string(),
                command_line: format!("cmd-{i}"),
                demon_id: "abcd1234".to_owned(),
                command_id: "9".to_owned(),
                ..AgentTaskInfo::default()
            },
        }));
    }

    let bob = state
        .connected_operators
        .get("bob")
        .unwrap_or_else(|| panic!("bob should be in connected_operators"));
    assert_eq!(
        bob.recent_commands.len(),
        MAX_OPERATOR_ACTIVITY,
        "activity feed must not exceed MAX_OPERATOR_ACTIVITY entries"
    );
}

#[test]
fn operator_snapshot_populates_connected_operators_with_role_and_presence() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::InitConnectionInfo(Message {
        head: head(EventCode::InitConnection),
        info: FlatInfo {
            fields: BTreeMap::from([(
                "Operators".to_owned(),
                serde_json::json!([
                    {
                        "Username": "operator",
                        "Role": "Operator",
                        "Online": true,
                        "LastSeen": "2026-03-10T12:00:00Z"
                    },
                    {
                        "Username": "admin",
                        "Role": "Admin",
                        "Online": false,
                        "LastSeen": null
                    }
                ]),
            )]),
        },
    }));

    let op = state
        .connected_operators
        .get("operator")
        .unwrap_or_else(|| panic!("operator should be in connected_operators"));
    assert_eq!(op.role.as_deref(), Some("Operator"));
    assert!(op.online);
    assert_eq!(op.last_seen.as_deref(), Some("2026-03-10T12:00:00Z"));

    let admin = state
        .connected_operators
        .get("admin")
        .unwrap_or_else(|| panic!("admin should be in connected_operators"));
    assert_eq!(admin.role.as_deref(), Some("Admin"));
    assert!(!admin.online);
}

#[test]
fn chat_user_presence_updates_connected_operators() {
    use red_cell_common::operator::ChatUserInfo;

    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    // Connect alice.
    state.apply_operator_message(OperatorMessage::ChatUserConnected(Message {
        head: MessageHead {
            event: EventCode::Chat,
            user: String::new(),
            timestamp: "10/03/2026 12:00:00".to_owned(),
            one_time: String::new(),
        },
        info: ChatUserInfo { user: "alice".to_owned() },
    }));
    let alice = state
        .connected_operators
        .get("alice")
        .unwrap_or_else(|| panic!("alice should appear on connect"));
    assert!(alice.online);
    assert_eq!(alice.last_seen.as_deref(), Some("10/03/2026 12:00:00"));

    // Disconnect alice.
    state.apply_operator_message(OperatorMessage::ChatUserDisconnected(Message {
        head: MessageHead {
            event: EventCode::Chat,
            user: String::new(),
            timestamp: "10/03/2026 12:05:00".to_owned(),
            one_time: String::new(),
        },
        info: ChatUserInfo { user: "alice".to_owned() },
    }));
    let alice = state
        .connected_operators
        .get("alice")
        .unwrap_or_else(|| panic!("alice should still be present after disconnect"));
    assert!(!alice.online);
    assert_eq!(alice.last_seen.as_deref(), Some("10/03/2026 12:05:00"));
}
