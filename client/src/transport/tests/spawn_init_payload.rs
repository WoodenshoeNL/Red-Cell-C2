use super::super::*;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use super::helpers::head;
use base64::Engine as _;
use red_cell_common::operator::{
    BuildPayloadMessageInfo, BuildPayloadResponseInfo, EventCode, FlatInfo, ListenerInfo,
    ListenerMarkInfo, LoginInfo, Message, MessageHead, MessageInfo, NameInfo, TeamserverLogInfo,
};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio_tungstenite::accept_async;

#[test]
fn next_reconnect_delay_already_at_max_stays_at_max() {
    let delay = next_reconnect_delay(MAX_RECONNECT_DELAY);
    assert_eq!(delay, MAX_RECONNECT_DELAY);
}

#[test]
fn reconnect_delay_resets_after_success() {
    // Simulate several backoff steps then a successful connection reset.
    let mut delay = INITIAL_RECONNECT_DELAY;
    for _ in 0..5 {
        delay = next_reconnect_delay(delay);
    }
    assert!(delay > INITIAL_RECONNECT_DELAY);

    // On success the connection manager resets to INITIAL_RECONNECT_DELAY.
    delay = INITIAL_RECONNECT_DELAY;
    assert_eq!(delay, Duration::from_secs(1));

    // Next failure should start doubling from the initial value again.
    let after_reset = next_reconnect_delay(delay);
    assert_eq!(after_reset, Duration::from_secs(2));
}

#[test]
fn spawn_connects_to_mock_websocket_server() {
    // Bind a TCP listener on a random port using std (so we can get the port
    // synchronously before spawning any async runtime).
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to random port");
    let port = std_listener.local_addr().expect("local addr").port();
    std_listener.set_nonblocking(true).expect("set nonblocking");

    // Run a mock WebSocket server on a background thread with its own runtime.
    let server_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("server runtime");
        rt.block_on(async {
            let listener = TcpListener::from_std(std_listener).expect("convert to tokio listener");
            if let Ok((stream, _)) = listener.accept().await {
                let _ws = accept_async(stream).await.ok();
                // Keep the connection alive long enough for the client to observe
                // Connected status.
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
    });

    let app_state: SharedAppState = Arc::new(Mutex::new(AppState::new(String::new())));
    let ctx = egui::Context::default();

    let transport = ClientTransport::spawn(
        format!("ws://127.0.0.1:{port}"),
        app_state.clone(),
        ctx,
        None,
        TlsVerification::DangerousSkipVerify,
    )
    .expect("spawn should succeed");

    // Poll until the connection manager reaches Connected status.
    let mut connected = false;
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        let state = lock_app_state(&app_state);
        if matches!(state.connection_status, ConnectionStatus::Connected) {
            connected = true;
            break;
        }
    }

    assert!(connected, "transport should reach Connected status");

    drop(transport);
    server_handle.join().ok();
}

#[test]
fn spawn_reports_error_for_refused_connection() {
    // Bind then immediately drop to obtain a port with nothing listening.
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to random port");
        listener.local_addr().expect("local addr").port()
    };

    let app_state: SharedAppState = Arc::new(Mutex::new(AppState::new(String::new())));
    let ctx = egui::Context::default();

    // spawn() itself must not panic even when the target is unreachable.
    let transport = ClientTransport::spawn(
        format!("ws://127.0.0.1:{port}"),
        app_state.clone(),
        ctx,
        None,
        TlsVerification::DangerousSkipVerify,
    )
    .expect("spawn should not panic for unreachable target");

    // The connection manager should eventually transition to Retrying or Error.
    let mut saw_failure_status = false;
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        let state = lock_app_state(&app_state);
        match &state.connection_status {
            ConnectionStatus::Retrying(_) | ConnectionStatus::Error(_) => {
                saw_failure_status = true;
                break;
            }
            _ => {}
        }
    }

    assert!(
        saw_failure_status,
        "transport should report Retrying or Error for a refused connection"
    );

    drop(transport);
}

#[test]
fn outgoing_sender_delivers_messages_to_channel() {
    // Build a ClientTransport by hand so we retain a handle to the receiver.
    let (shutdown_tx, _shutdown_rx) = watch::channel(false);
    let (outgoing_tx, mut outgoing_rx) = mpsc::unbounded_channel();
    let transport = ClientTransport { runtime: None, shutdown_tx, outgoing_tx };

    let sender = transport.outgoing_sender();

    // Send a message via the cloned sender.
    let msg = OperatorMessage::Login(Message {
        head: head(EventCode::InitConnection),
        info: LoginInfo { user: "test-user".to_owned(), password: "hunter2".to_owned() },
    });
    sender.send(msg).expect("send via cloned sender should succeed");

    // The message must arrive on the receiver.
    assert!(
        outgoing_rx.try_recv().is_ok(),
        "message sent via outgoing_sender should appear on the receiver"
    );

    // The original transport sender should still work after cloning.
    let msg2 = OperatorMessage::Login(Message {
        head: head(EventCode::InitConnection),
        info: LoginInfo { user: "another-user".to_owned(), password: "pass".to_owned() },
    });
    transport.queue_message(msg2).expect("queue_message via original sender should succeed");
    assert!(outgoing_rx.try_recv().is_ok(), "message sent via queue_message should also arrive");
}

#[test]
fn init_connection_success_sets_connected_and_populates_operator() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
    assert!(matches!(state.connection_status, ConnectionStatus::Disconnected));
    assert!(state.operator_info.is_none());
    assert!(state.online_operators.is_empty());

    let events = state.apply_operator_message(OperatorMessage::InitConnectionSuccess(Message {
        head: MessageHead {
            event: EventCode::InitConnection,
            user: "alice".to_owned(),
            timestamp: "18/03/2026 09:30:00".to_owned(),
            one_time: String::new(),
        },
        info: MessageInfo { message: "Authentication successful".to_owned() },
    }));

    assert!(
        matches!(state.connection_status, ConnectionStatus::Connected),
        "connection_status should be Connected after success"
    );

    let info = state.operator_info.as_ref().expect("operator_info should be populated");
    assert_eq!(info.username, "alice");
    assert!(info.online);
    assert_eq!(info.last_seen.as_deref(), Some("18/03/2026 09:30:00"));

    assert!(state.online_operators.contains("alice"), "alice should be in online_operators");

    // A system event should have been logged.
    assert_eq!(state.event_log.len(), 1);

    // apply_operator_message returns no AppEvent variants for this message type.
    assert!(events.is_empty());
}

#[test]
fn init_connection_success_with_empty_user_skips_operator_info() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::InitConnectionSuccess(Message {
        head: MessageHead {
            event: EventCode::InitConnection,
            user: String::new(),
            timestamp: "18/03/2026 09:30:00".to_owned(),
            one_time: String::new(),
        },
        info: MessageInfo { message: "Connected".to_owned() },
    }));

    assert!(matches!(state.connection_status, ConnectionStatus::Connected));
    assert!(state.operator_info.is_none(), "operator_info should remain None when user is empty");
    assert!(state.online_operators.is_empty());
    assert_eq!(state.event_log.len(), 1);
}

#[test]
fn init_connection_error_sets_error_status_and_logs_event() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    let events = state.apply_operator_message(OperatorMessage::InitConnectionError(Message {
        head: MessageHead {
            event: EventCode::InitConnection,
            user: String::new(),
            timestamp: "18/03/2026 09:31:00".to_owned(),
            one_time: String::new(),
        },
        info: MessageInfo { message: "Invalid credentials".to_owned() },
    }));

    assert!(
        matches!(&state.connection_status, ConnectionStatus::Error(msg) if msg == "Invalid credentials"),
        "connection_status should be Error with the message"
    );

    assert_eq!(
        state.last_auth_error.as_deref(),
        Some("Invalid credentials"),
        "last_auth_error should capture the error message"
    );

    // operator_info should remain None after an error.
    assert!(state.operator_info.is_none());

    // A system event should be logged.
    assert_eq!(state.event_log.len(), 1);
    let entry = state.event_log.entries.front().expect("should have one event entry");
    assert_eq!(entry.message, "Invalid credentials");

    assert!(events.is_empty());
}

#[test]
fn listener_edit_upserts_and_emits_edit_event() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    // Add an initial listener via ListenerNew.
    state.apply_operator_message(OperatorMessage::ListenerNew(Message {
        head: head(EventCode::Listener),
        info: ListenerInfo {
            name: Some("http".to_owned()),
            protocol: Some("Https".to_owned()),
            status: Some("Online".to_owned()),
            ..ListenerInfo::default()
        },
    }));
    assert_eq!(state.listeners.len(), 1);
    assert_eq!(state.listeners[0].protocol, "Https");

    // Edit the listener — should update in place, not add a duplicate.
    let events = state.apply_operator_message(OperatorMessage::ListenerEdit(Message {
        head: head(EventCode::Listener),
        info: ListenerInfo {
            name: Some("http".to_owned()),
            protocol: Some("Http".to_owned()),
            status: Some("Offline".to_owned()),
            ..ListenerInfo::default()
        },
    }));

    assert_eq!(state.listeners.len(), 1, "should upsert, not duplicate");
    assert_eq!(state.listeners[0].protocol, "Http");
    assert_eq!(state.listeners[0].status, "Offline");

    assert_eq!(events.len(), 1);
    assert!(
        matches!(&events[0], AppEvent::ListenerChanged { name, action } if name == "http" && action == "edit"),
        "expected ListenerChanged edit event, got {events:?}",
    );
}

#[test]
fn listener_edit_creates_new_entry_when_absent() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    let events = state.apply_operator_message(OperatorMessage::ListenerEdit(Message {
        head: head(EventCode::Listener),
        info: ListenerInfo {
            name: Some("smb".to_owned()),
            protocol: Some("SMB".to_owned()),
            status: Some("Online".to_owned()),
            ..ListenerInfo::default()
        },
    }));

    assert_eq!(state.listeners.len(), 1);
    assert_eq!(state.listeners[0].name, "smb");
    assert_eq!(events.len(), 1);
    assert!(matches!(&events[0], AppEvent::ListenerChanged { action, .. } if action == "edit"),);
}

#[test]
fn listener_remove_deletes_listener_and_emits_stop_event() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    // Add two listeners.
    state.apply_operator_message(OperatorMessage::ListenerNew(Message {
        head: head(EventCode::Listener),
        info: ListenerInfo {
            name: Some("http".to_owned()),
            protocol: Some("Https".to_owned()),
            status: Some("Online".to_owned()),
            ..ListenerInfo::default()
        },
    }));
    state.apply_operator_message(OperatorMessage::ListenerNew(Message {
        head: head(EventCode::Listener),
        info: ListenerInfo {
            name: Some("smb".to_owned()),
            protocol: Some("SMB".to_owned()),
            status: Some("Online".to_owned()),
            ..ListenerInfo::default()
        },
    }));
    assert_eq!(state.listeners.len(), 2);

    // Remove the first one.
    let events = state.apply_operator_message(OperatorMessage::ListenerRemove(Message {
        head: head(EventCode::Listener),
        info: NameInfo { name: "http".to_owned() },
    }));

    assert_eq!(state.listeners.len(), 1);
    assert_eq!(state.listeners[0].name, "smb", "only 'smb' should remain");

    assert_eq!(events.len(), 1);
    assert!(
        matches!(&events[0], AppEvent::ListenerChanged { name, action } if name == "http" && action == "stop"),
        "expected ListenerChanged stop event, got {events:?}",
    );
}

#[test]
fn listener_remove_is_noop_for_unknown_listener() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    let events = state.apply_operator_message(OperatorMessage::ListenerRemove(Message {
        head: head(EventCode::Listener),
        info: NameInfo { name: "nonexistent".to_owned() },
    }));

    assert!(state.listeners.is_empty());
    // Event is still emitted even if no listener was present.
    assert_eq!(events.len(), 1);
    assert!(matches!(&events[0], AppEvent::ListenerChanged { action, .. } if action == "stop"),);
}

#[test]
fn listener_mark_updates_status_of_existing_listener() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    // Add a listener.
    state.apply_operator_message(OperatorMessage::ListenerNew(Message {
        head: head(EventCode::Listener),
        info: ListenerInfo {
            name: Some("http".to_owned()),
            protocol: Some("Https".to_owned()),
            status: Some("Online".to_owned()),
            ..ListenerInfo::default()
        },
    }));
    assert_eq!(state.listeners[0].status, "Online");

    // Mark it as offline.
    let events = state.apply_operator_message(OperatorMessage::ListenerMark(Message {
        head: head(EventCode::Listener),
        info: ListenerMarkInfo { name: "http".to_owned(), mark: "Offline".to_owned() },
    }));

    assert_eq!(state.listeners.len(), 1);
    assert_eq!(state.listeners[0].status, "Offline");
    assert_eq!(state.listeners[0].protocol, "Https", "protocol should be unchanged");

    // ListenerMark does not emit events.
    assert!(events.is_empty());
}

#[test]
fn listener_mark_creates_placeholder_when_listener_absent() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::ListenerMark(Message {
        head: head(EventCode::Listener),
        info: ListenerMarkInfo { name: "unknown-listener".to_owned(), mark: "Offline".to_owned() },
    }));

    assert_eq!(state.listeners.len(), 1);
    assert_eq!(state.listeners[0].name, "unknown-listener");
    assert_eq!(state.listeners[0].status, "Offline");
    assert_eq!(state.listeners[0].protocol, "unknown");
}

#[test]
fn chat_message_pushes_operator_event_with_user_and_message() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    let mut fields = BTreeMap::new();
    fields.insert("User".to_owned(), Value::String("alice".to_owned()));
    fields.insert("Message".to_owned(), Value::String("hello team".to_owned()));

    state.apply_operator_message(OperatorMessage::ChatMessage(Message {
        head: head(EventCode::Chat),
        info: FlatInfo { fields },
    }));

    assert_eq!(state.event_log.len(), 1);
    let entry = state.event_log.entries.back().unwrap();
    assert_eq!(entry.kind, EventKind::Operator);
    assert_eq!(entry.author, "alice");
    assert_eq!(entry.message, "hello team");
}

#[test]
fn chat_message_uses_fallback_when_fields_missing() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::ChatMessage(Message {
        head: head(EventCode::Chat),
        info: FlatInfo { fields: BTreeMap::new() },
    }));

    assert_eq!(state.event_log.len(), 1);
    let entry = state.event_log.entries.back().unwrap();
    assert_eq!(entry.kind, EventKind::Operator);
    assert_eq!(entry.author, "system");
    assert_eq!(entry.message, "Received event");
}

#[test]
fn chat_message_extracts_alternate_keys_name_and_text() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    let mut fields = BTreeMap::new();
    fields.insert("Name".to_owned(), Value::String("bob".to_owned()));
    fields.insert("Text".to_owned(), Value::String("hi there".to_owned()));

    state.apply_operator_message(OperatorMessage::ChatMessage(Message {
        head: head(EventCode::Chat),
        info: FlatInfo { fields },
    }));

    let entry = state.event_log.entries.back().unwrap();
    assert_eq!(entry.author, "bob");
    assert_eq!(entry.message, "hi there");
}

#[test]
fn chat_listener_pushes_agent_event() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    let mut fields = BTreeMap::new();
    fields.insert("User".to_owned(), Value::String("listener1".to_owned()));
    fields.insert("Message".to_owned(), Value::String("listener event".to_owned()));

    state.apply_operator_message(OperatorMessage::ChatListener(Message {
        head: head(EventCode::Chat),
        info: FlatInfo { fields },
    }));

    assert_eq!(state.event_log.len(), 1);
    let entry = state.event_log.entries.back().unwrap();
    assert_eq!(entry.kind, EventKind::Agent);
    assert_eq!(entry.author, "listener1");
    assert_eq!(entry.message, "listener event");
}

#[test]
fn chat_agent_pushes_agent_event() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    let mut fields = BTreeMap::new();
    fields.insert("DemonID".to_owned(), Value::String("deadbeef".to_owned()));
    fields.insert("Output".to_owned(), Value::String("agent output".to_owned()));

    state.apply_operator_message(OperatorMessage::ChatAgent(Message {
        head: head(EventCode::Chat),
        info: FlatInfo { fields },
    }));

    assert_eq!(state.event_log.len(), 1);
    let entry = state.event_log.entries.back().unwrap();
    assert_eq!(entry.kind, EventKind::Agent);
    assert_eq!(entry.author, "deadbeef");
    assert_eq!(entry.message, "agent output");
}

#[test]
fn teamserver_log_pushes_system_event() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::TeamserverLog(Message {
        head: head(EventCode::Teamserver),
        info: TeamserverLogInfo { text: "server started".to_owned() },
    }));

    assert_eq!(state.event_log.len(), 1);
    let entry = state.event_log.entries.back().unwrap();
    assert_eq!(entry.kind, EventKind::System);
    assert_eq!(entry.author, "teamserver");
    assert_eq!(entry.message, "server started");
}

#[test]
fn build_payload_message_pushes_formatted_system_event() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::BuildPayloadMessage(Message {
        head: head(EventCode::Teamserver),
        info: BuildPayloadMessageInfo {
            message_type: "Info".to_owned(),
            message: "compiling agent".to_owned(),
        },
    }));

    assert_eq!(state.event_log.len(), 1);
    let entry = state.event_log.entries.back().unwrap();
    assert_eq!(entry.kind, EventKind::System);
    assert_eq!(entry.author, "builder");
    assert_eq!(entry.message, "Info: compiling agent");
}

#[test]
fn build_payload_response_pushes_built_filename_event() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::BuildPayloadResponse(Message {
        head: head(EventCode::Teamserver),
        info: BuildPayloadResponseInfo {
            payload_array: String::new(),
            format: "exe".to_owned(),
            file_name: "demon.exe".to_owned(),
            export_name: None,
        },
    }));

    assert_eq!(state.event_log.len(), 1);
    let entry = state.event_log.entries.back().unwrap();
    assert_eq!(entry.kind, EventKind::System);
    assert_eq!(entry.author, "builder");
    assert_eq!(entry.message, "Built demon.exe");
}

#[test]
fn build_payload_message_stores_console_entry() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::BuildPayloadMessage(Message {
        head: head(EventCode::Teamserver),
        info: BuildPayloadMessageInfo {
            message_type: "Info".to_owned(),
            message: "compiling core dll".to_owned(),
        },
    }));

    assert_eq!(state.build_console_messages.len(), 1);
    assert_eq!(state.build_console_messages[0].message_type, "Info");
    assert_eq!(state.build_console_messages[0].message, "compiling core dll");
}

#[test]
fn build_payload_response_stores_decoded_payload() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());
    let payload_bytes = b"binary payload data";
    let encoded = base64::engine::general_purpose::STANDARD.encode(payload_bytes);

    state.apply_operator_message(OperatorMessage::BuildPayloadResponse(Message {
        head: head(EventCode::Teamserver),
        info: BuildPayloadResponseInfo {
            payload_array: encoded,
            format: "Windows Exe".to_owned(),
            file_name: "demon.exe".to_owned(),
            export_name: None,
        },
    }));

    let result = state.last_payload_response.as_ref().unwrap();
    assert_eq!(result.payload_bytes, payload_bytes);
    assert_eq!(result.format, "Windows Exe");
    assert_eq!(result.file_name, "demon.exe");
}

#[test]
fn build_payload_response_invalid_base64_does_not_store() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    state.apply_operator_message(OperatorMessage::BuildPayloadResponse(Message {
        head: head(EventCode::Teamserver),
        info: BuildPayloadResponseInfo {
            payload_array: "!!!not-valid-base64!!!".to_owned(),
            format: "exe".to_owned(),
            file_name: "demon.exe".to_owned(),
            export_name: None,
        },
    }));

    // Invalid base64 should not produce a stored result.
    assert!(state.last_payload_response.is_none());
    // But the event log entry should still be pushed.
    assert_eq!(state.event_log.len(), 1);
}

#[test]
fn build_console_messages_accumulate() {
    let mut state = AppState::new("wss://127.0.0.1:40056/havoc/".to_owned());

    for msg in &["Starting build", "Compiling source", "Finished compiling"] {
        state.apply_operator_message(OperatorMessage::BuildPayloadMessage(Message {
            head: head(EventCode::Teamserver),
            info: BuildPayloadMessageInfo {
                message_type: "Info".to_owned(),
                message: (*msg).to_owned(),
            },
        }));
    }

    assert_eq!(state.build_console_messages.len(), 3);
    assert_eq!(state.build_console_messages[2].message, "Finished compiling");
}
