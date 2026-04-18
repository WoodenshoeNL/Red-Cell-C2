use super::agent::{
    handle_agent_instance_register, handle_agent_output, handle_agent_response, handle_agent_task,
    handle_register_agent,
};
use super::listeners::{handle_listener_add, handle_listener_start};
use super::*;
use red_cell_common::operator::{
    AgentResponseInfo, EventCode, ListenerErrorInfo, ListenerMarkInfo, Message, MessageHead,
    OperatorMessage, ServiceAgentRegistrationInfo, ServiceListenerRegistrationInfo,
};
use std::time::Duration;

/// Create a test database and webhook notifier pair for audit logging tests.
async fn test_audit_deps() -> (Database, AuditWebhookNotifier) {
    let database = crate::database::Database::connect_in_memory().await.expect("in-memory db");
    let webhooks = AuditWebhookNotifier::default();
    (database, webhooks)
}

/// Create an Argon2id verifier from a plaintext password (for test use).
fn test_verifier(password: &str) -> String {
    password_verifier_for_sha3(&hash_password_sha3(password))
        .expect("test verifier should be generated")
}

#[test]
fn service_bridge_creates_with_config() {
    let config =
        ServiceConfig { endpoint: "svc-endpoint".to_owned(), password: "secret".to_owned() };
    let bridge = ServiceBridge::new(config).expect("service bridge");
    assert_eq!(bridge.endpoint(), "svc-endpoint");
}

#[tokio::test]
async fn service_bridge_tracks_clients() {
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");

    let id = Uuid::new_v4();
    bridge.add_client(id).await;
    assert_eq!(bridge.connected_client_count().await, 1);

    bridge.remove_client(id, &[], &[]).await;
    assert_eq!(bridge.connected_client_count().await, 0);
}

#[tokio::test]
async fn service_bridge_registers_agent() {
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");

    bridge
        .register_agent("custom-agent".to_owned())
        .await
        .expect("first registration should succeed");

    assert!(bridge.agent_exists("custom-agent").await);

    let err = bridge.register_agent("custom-agent".to_owned()).await;
    assert!(err.is_err(), "duplicate registration should fail");
}

#[tokio::test]
async fn service_bridge_registers_listener() {
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");

    bridge.register_listener("my-listener".to_owned()).await;
    // Registering same name again is idempotent.
    bridge.register_listener("my-listener".to_owned()).await;

    let inner = bridge.inner.read().await;
    assert_eq!(inner.registered_listeners.len(), 1);
}

#[tokio::test]
async fn client_cleanup_removes_agents_and_listeners() {
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");

    let client_id = Uuid::new_v4();
    bridge.add_client(client_id).await;
    bridge.register_agent("agent-a".to_owned()).await.ok();
    bridge.register_listener("listener-b".to_owned()).await;

    bridge.remove_client(client_id, &["agent-a".to_owned()], &["listener-b".to_owned()]).await;

    assert_eq!(bridge.connected_client_count().await, 0);
    assert!(!bridge.agent_exists("agent-a").await);
    let inner = bridge.inner.read().await;
    assert!(inner.registered_listeners.is_empty());
}

#[test]
fn authenticate_response_format_matches_havoc() {
    let response = serde_json::json!({
        "Head": { "Type": HEAD_REGISTER },
        "Body": { "Success": true },
    });
    let head_type = response["Head"]["Type"].as_str().expect("unwrap");
    assert_eq!(head_type, "Register");
    assert!(response["Body"]["Success"].as_bool().expect("unwrap"));
}

#[tokio::test]
async fn dispatch_returns_ok_for_unknown_listener_subtype() {
    // `dispatch_message` requires a `WebSocket` (not constructable in unit
    // tests), so we test the equivalent "unknown type → Ok" path via
    // `handle_listener_message`, which `dispatch_message` delegates to for
    // HEAD_LISTENER messages and which has the same unknown-type branch.
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");
    let events = EventBus::default();
    let (db, wh) = test_audit_deps().await;
    let mut client_listeners = Vec::new();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_LISTENER },
        "Body": { "Type": "CompletelyUnknownBodyType" },
    });

    let result =
        handle_listener_message(&message, &bridge, &events, &db, &wh, &mut client_listeners).await;
    assert!(result.is_ok(), "unknown listener sub-type should be silently ignored");
    assert!(client_listeners.is_empty(), "no listener should be registered");
}

#[tokio::test]
async fn handle_register_agent_broadcasts_event() {
    let (db, wh) = test_audit_deps().await;
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let mut client_agents = Vec::new();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_REGISTER_AGENT },
        "Body": {
            "Agent": {
                "Name": "TestAgent",
                "Author": "test",
                "Description": "A test agent",
            }
        },
    });

    handle_register_agent(&message, &bridge, &events, &db, &wh, &mut client_agents)
        .await
        .expect("registration should succeed");

    assert!(bridge.agent_exists("TestAgent").await);
    assert_eq!(client_agents, vec!["TestAgent".to_owned()]);

    let event = rx.recv().await.expect("event should be broadcast");
    match event {
        OperatorMessage::ServiceAgentRegister(msg) => {
            assert!(msg.info.agent.contains("TestAgent"));
        }
        _ => panic!("expected ServiceAgentRegister event"),
    }
}

#[tokio::test]
async fn handle_listener_add_broadcasts_event() {
    let (db, wh) = test_audit_deps().await;
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let mut client_listeners = Vec::new();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_LISTENER },
        "Body": {
            "Type": BODY_LISTENER_ADD,
            "Listener": {
                "Name": "custom-listener",
                "Agent": "TestAgent",
            },
        },
    });

    handle_listener_add(&message, &bridge, &events, &db, &wh, &mut client_listeners)
        .await
        .expect("listener add should succeed");

    assert_eq!(client_listeners, vec!["custom-listener".to_owned()]);

    let event = rx.recv().await.expect("event should be broadcast");
    match event {
        OperatorMessage::ServiceListenerRegister(msg) => {
            assert!(msg.info.listener.contains("custom-listener"));
        }
        _ => panic!("expected ServiceListenerRegister event"),
    }
}

#[tokio::test]
async fn handle_register_agent_rejects_duplicate() {
    let (db, wh) = test_audit_deps().await;
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");
    let events = EventBus::default();
    let mut client_agents = Vec::new();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_REGISTER_AGENT },
        "Body": {
            "Agent": { "Name": "DupAgent" }
        },
    });

    handle_register_agent(&message, &bridge, &events, &db, &wh, &mut client_agents)
        .await
        .expect("first registration should succeed");

    let mut client_agents2 = Vec::new();
    let err = handle_register_agent(&message, &bridge, &events, &db, &wh, &mut client_agents2)
        .await
        .expect_err("duplicate should fail");

    assert!(
        matches!(err, ServiceBridgeError::DuplicateAgent { .. }),
        "expected DuplicateAgent error"
    );
}

#[tokio::test]
async fn missing_agent_name_returns_error() {
    let (db, wh) = test_audit_deps().await;
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");
    let events = EventBus::default();
    let mut client_agents = Vec::new();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_REGISTER_AGENT },
        "Body": {
            "Agent": {}
        },
    });

    let err = handle_register_agent(&message, &bridge, &events, &db, &wh, &mut client_agents)
        .await
        .expect_err("missing Name should fail");

    assert!(
        matches!(err, ServiceBridgeError::MissingField(ref f) if f.contains("Name")),
        "expected MissingField error mentioning Name, got: {err:?}"
    );
}

// ── AgentTask handler tests ─────────────────────────────────────

async fn test_registry() -> AgentRegistry {
    let database = crate::database::Database::connect_in_memory().await.expect("in-memory db");
    AgentRegistry::new(database)
}

fn test_agent_record(agent_id: u32) -> red_cell_common::AgentRecord {
    red_cell_common::AgentRecord {
        agent_id,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: red_cell_common::AgentEncryptionInfo::default(),
        hostname: "WORKSTATION".to_owned(),
        username: "admin".to_owned(),
        domain_name: "DOMAIN".to_owned(),
        external_ip: "10.0.0.1".to_owned(),
        internal_ip: "192.168.1.100".to_owned(),
        process_name: "svc.exe".to_owned(),
        process_path: "C:\\svc.exe".to_owned(),
        base_address: 0,
        process_pid: 1234,
        process_tid: 0,
        process_ppid: 0,
        process_arch: "x64".to_owned(),
        elevated: false,
        os_version: "Windows 10".to_owned(),
        os_build: 0,
        os_arch: "x64".to_owned(),
        sleep_delay: 5,
        sleep_jitter: 0,
        kill_date: None,
        working_hours: None,
        first_call_in: "0".to_owned(),
        last_call_in: "0".to_owned(),
    }
}

/// Create a WebSocket pair using a real TCP connection and axum upgrade.
async fn ws_pair() -> (
    WebSocket,
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
) {
    use tokio::net::TcpListener;

    let (tx, rx) = tokio::sync::mpsc::channel::<WebSocket>(1);

    let app = axum::Router::new().route(
        "/ws",
        axum::routing::get(move |ws: WebSocketUpgrade| {
            let tx = tx.clone();
            async move {
                ws.on_upgrade(move |socket| async move {
                    let _ = tx.send(socket).await;
                })
            }
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");

    let server_handle =
        tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });

    let url = format!("ws://127.0.0.1:{}/ws", addr.port());
    let (client, _) = tokio_tungstenite::connect_async(&url).await.expect("ws connect");

    let mut rx = rx;
    let server_socket = rx.recv().await.expect("server socket");

    server_handle.abort();
    (server_socket, client)
}

#[tokio::test]
async fn handle_agent_task_add_enqueues_job() {
    use base64::Engine as _;
    let (db, wh) = test_audit_deps().await;

    let registry = test_registry().await;
    let agent_id: u32 = 0xAABB_CCDD;
    registry.insert(test_agent_record(agent_id)).await.expect("insert agent");

    let events = EventBus::default();
    let mut rx = events.subscribe();

    let payload = vec![0x41, 0x42, 0x43];
    let encoded = base64::engine::general_purpose::STANDARD.encode(&payload);

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_TASK,
            "Agent": { "NameID": "AABBCCDD" },
            "Task": "Add",
            "Command": encoded,
        },
    });

    let (mut server_ws, _client_ws) = ws_pair().await;

    handle_agent_task(&message, &events, &registry, &db, &wh, &mut server_ws)
        .await
        .expect("task add should succeed");

    let jobs = registry.queued_jobs(agent_id).await.expect("queued jobs");
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].payload, payload);
    assert_eq!(jobs[0].operator, "service");

    let event = rx.recv().await.expect("event should be broadcast");
    assert!(matches!(event, OperatorMessage::TeamserverLog(_)), "expected teamserver log event");
}

#[tokio::test]
async fn handle_agent_task_get_returns_queued_payloads() {
    use base64::Engine as _;
    use futures_util::StreamExt as _;
    let (db, wh) = test_audit_deps().await;

    let registry = test_registry().await;
    let agent_id: u32 = 0x1122_3344;
    registry.insert(test_agent_record(agent_id)).await.expect("insert agent");

    let job1 = crate::agents::Job {
        payload: vec![0x01, 0x02],
        task_id: "t1".to_owned(),
        created_at: "0".to_owned(),
        operator: "op".to_owned(),
        ..Default::default()
    };
    let job2 = crate::agents::Job {
        payload: vec![0x03, 0x04],
        task_id: "t2".to_owned(),
        created_at: "0".to_owned(),
        operator: "op".to_owned(),
        ..Default::default()
    };
    registry.enqueue_job(agent_id, job1).await.expect("enqueue job1");
    registry.enqueue_job(agent_id, job2).await.expect("enqueue job2");

    let events = EventBus::default();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_TASK,
            "Agent": { "NameID": "11223344" },
            "Task": "Get",
        },
    });

    let (mut server_ws, mut client_ws) = ws_pair().await;

    handle_agent_task(&message, &events, &registry, &db, &wh, &mut server_ws)
        .await
        .expect("task get should succeed");

    // Read the response from the client side
    let resp = client_ws.next().await.expect("should receive").expect("not error");
    let text = resp.into_text().expect("text message");
    let parsed: Value = serde_json::from_str(&text).expect("valid json");
    let tasks_queue = parsed["Body"]["TasksQueue"].as_str().expect("TasksQueue");
    let decoded =
        base64::engine::general_purpose::STANDARD.decode(tasks_queue).expect("valid base64");
    assert_eq!(decoded, vec![0x01, 0x02, 0x03, 0x04]);

    // Queue should be drained
    let remaining = registry.queued_jobs(agent_id).await.expect("queued");
    assert!(remaining.is_empty());
}

#[tokio::test]
async fn handle_agent_task_missing_body_returns_error() {
    let (db, wh) = test_audit_deps().await;
    let registry = test_registry().await;
    let events = EventBus::default();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
    });

    let (mut server_ws, _client_ws) = ws_pair().await;

    let err = handle_agent_task(&message, &events, &registry, &db, &wh, &mut server_ws)
        .await
        .expect_err("should fail");
    assert!(matches!(err, ServiceBridgeError::MissingField(_)));
}

#[tokio::test]
async fn handle_agent_task_add_invalid_base64_returns_error() {
    let (db, wh) = test_audit_deps().await;
    let registry = test_registry().await;
    let agent_id: u32 = 0xDEAD_BEEF;
    registry.insert(test_agent_record(agent_id)).await.expect("insert agent");
    let events = EventBus::default();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_TASK,
            "Agent": { "NameID": "DEADBEEF" },
            "Task": "Add",
            "Command": "!!!not-base64!!!",
        },
    });

    let (mut server_ws, _client_ws) = ws_pair().await;

    let err = handle_agent_task(&message, &events, &registry, &db, &wh, &mut server_ws)
        .await
        .expect_err("should fail");
    assert!(matches!(err, ServiceBridgeError::Base64Decode(_)));
}

#[tokio::test]
async fn handle_agent_task_add_unknown_agent_returns_error() {
    let (db, wh) = test_audit_deps().await;
    let registry = test_registry().await;
    let events = EventBus::default();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_TASK,
            "Agent": { "NameID": "99999999" },
            "Task": "Add",
            "Command": "AAAA",
        },
    });

    let (mut server_ws, _client_ws) = ws_pair().await;

    let err = handle_agent_task(&message, &events, &registry, &db, &wh, &mut server_ws)
        .await
        .expect_err("should fail for unknown agent");
    assert!(matches!(err, ServiceBridgeError::AgentRegistry(_)));
}

// ── AgentRegister handler tests ─────────────────────────────────

#[tokio::test]
async fn handle_agent_instance_register_inserts_and_broadcasts() {
    let (db, wh) = test_audit_deps().await;
    let registry = test_registry().await;
    let events = EventBus::default();
    let mut rx = events.subscribe();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_REGISTER,
            "AgentHeader": {
                "Size": "256",
                "MagicValue": "deadbeef",
                "AgentID": "AABB0011",
            },
            "RegisterInfo": {
                "Hostname": "SRV01",
                "Username": "admin",
                "DomainName": "CORP",
                "ExternalIP": "10.0.0.5",
                "InternalIP": "192.168.1.5",
                "ProcessName": "agent.exe",
                "ProcessArch": "x64",
                "OSVersion": "Windows 11",
                "OSArch": "x64",
                "SleepDelay": 10,
                "SleepJitter": 20,
            },
        },
    });

    handle_agent_instance_register(&message, &events, &registry, &db, &wh)
        .await
        .expect("registration should succeed");

    let agent = registry.get(0xAABB_0011).await.expect("agent should exist");
    assert_eq!(agent.hostname, "SRV01");
    assert_eq!(agent.username, "admin");
    assert_eq!(agent.domain_name, "CORP");
    assert_eq!(agent.sleep_delay, 10);
    assert!(agent.active);

    let event = rx.recv().await.expect("event should be broadcast");
    assert!(matches!(event, OperatorMessage::AgentNew(_)), "expected AgentNew event");
}

#[tokio::test]
async fn handle_agent_instance_register_duplicate_returns_error() {
    let (db, wh) = test_audit_deps().await;
    let registry = test_registry().await;
    let events = EventBus::default();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_REGISTER,
            "AgentHeader": {
                "Size": "0",
                "MagicValue": "DEADBEEF",
                "AgentID": "11223344",
            },
            "RegisterInfo": {
                "Hostname": "H1",
                "Username": "u1",
            },
        },
    });

    handle_agent_instance_register(&message, &events, &registry, &db, &wh)
        .await
        .expect("first registration should succeed");

    let err = handle_agent_instance_register(&message, &events, &registry, &db, &wh)
        .await
        .expect_err("duplicate should fail");
    assert!(matches!(err, ServiceBridgeError::AgentRegistry(_)));
}

#[tokio::test]
async fn handle_agent_instance_register_missing_header_returns_error() {
    let (db, wh) = test_audit_deps().await;
    let registry = test_registry().await;
    let events = EventBus::default();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_REGISTER,
            "RegisterInfo": { "Hostname": "H1" },
        },
    });

    let err = handle_agent_instance_register(&message, &events, &registry, &db, &wh)
        .await
        .expect_err("should fail without AgentHeader");
    assert!(matches!(err, ServiceBridgeError::MissingField(_)));
}

// ── AgentResponse handler tests ─────────────────────────────────

#[tokio::test]
async fn handle_agent_response_broadcasts_event() {
    let events = EventBus::default();
    let mut rx = events.subscribe();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_RESPONSE,
            "Agent": { "NameID": "DEAD0001" },
            "Response": "SGVsbG8gV29ybGQ=",
            "RandID": "abc123",
        },
    });

    handle_agent_response(&message, &events).await.expect("response handling should succeed");

    let event = rx.recv().await.expect("event should be broadcast");
    match event {
        OperatorMessage::AgentResponse(msg) => {
            assert_eq!(msg.info.demon_id, "DEAD0001");
            assert_eq!(msg.info.command_id, "abc123");
            assert_eq!(msg.info.output, "SGVsbG8gV29ybGQ=");
            assert!(msg.info.command_line.is_none());
            assert_eq!(msg.head.event, EventCode::Session);
            assert_eq!(msg.head.user, "service");
        }
        _ => panic!("expected AgentResponse event"),
    }
}

#[tokio::test]
async fn handle_agent_response_missing_body_returns_error() {
    let events = EventBus::default();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
    });

    let err = handle_agent_response(&message, &events).await.expect_err("should fail without Body");
    assert!(matches!(err, ServiceBridgeError::MissingField(_)));
}

#[tokio::test]
async fn handle_agent_response_missing_optional_fields_uses_defaults() {
    let events = EventBus::default();
    let mut rx = events.subscribe();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_RESPONSE,
        },
    });

    handle_agent_response(&message, &events).await.expect("should succeed with defaults");

    let event = rx.recv().await.expect("event should be broadcast");
    match event {
        OperatorMessage::AgentResponse(msg) => {
            assert_eq!(msg.info.demon_id, "unknown");
            assert_eq!(msg.info.command_id, "");
            assert_eq!(msg.info.output, "");
        }
        _ => panic!("expected AgentResponse event"),
    }
}

#[tokio::test]
async fn handle_agent_instance_register_invalid_hex_id_returns_error() {
    let (db, wh) = test_audit_deps().await;
    let registry = test_registry().await;
    let events = EventBus::default();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_REGISTER,
            "AgentHeader": {
                "AgentID": "ZZZZZZ",
                "MagicValue": "0",
            },
            "RegisterInfo": { "Hostname": "H1" },
        },
    });

    let err = handle_agent_instance_register(&message, &events, &registry, &db, &wh)
        .await
        .expect_err("should fail with invalid hex");
    assert!(matches!(err, ServiceBridgeError::MissingField(_)));
}

#[tokio::test]
async fn handle_agent_instance_register_rejects_wrong_magic_value() {
    let (db, wh) = test_audit_deps().await;
    let registry = test_registry().await;
    let events = EventBus::default();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_REGISTER,
            "AgentHeader": {
                "AgentID": "AABB0011",
                "MagicValue": "CAFEBABE",
            },
            "RegisterInfo": { "Hostname": "H1" },
        },
    });

    let err = handle_agent_instance_register(&message, &events, &registry, &db, &wh)
        .await
        .expect_err("should fail with wrong magic value");
    assert!(
        matches!(
            err,
            ServiceBridgeError::InvalidMagicValue { expected: 0xDEAD_BEEF, actual: 0xCAFE_BABE }
        ),
        "expected InvalidMagicValue, got {err:?}"
    );
}

#[tokio::test]
async fn handle_agent_instance_register_rejects_missing_magic_value() {
    let (db, wh) = test_audit_deps().await;
    let registry = test_registry().await;
    let events = EventBus::default();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_REGISTER,
            "AgentHeader": {
                "AgentID": "AABB0011",
            },
            "RegisterInfo": { "Hostname": "H1" },
        },
    });

    let err = handle_agent_instance_register(&message, &events, &registry, &db, &wh)
        .await
        .expect_err("should fail with missing magic value");
    assert!(
        matches!(err, ServiceBridgeError::MissingField(ref f) if f.contains("MagicValue")),
        "expected MissingField for MagicValue, got {err:?}"
    );
}

#[tokio::test]
async fn handle_agent_instance_register_clamps_overflowing_u32_fields_to_zero() {
    let (db, wh) = test_audit_deps().await;
    let registry = test_registry().await;
    let events = EventBus::default();

    let over_u32_max: u64 = u32::MAX as u64 + 1;
    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_REGISTER,
            "AgentHeader": {
                "Size": "0",
                "MagicValue": "DEADBEEF",
                "AgentID": "DEAD0001",
            },
            "RegisterInfo": {
                "Hostname": "H1",
                "Username": "u1",
                "ProcessPID": over_u32_max,
                "SleepDelay": over_u32_max,
                "SleepJitter": over_u32_max,
            },
        },
    });

    handle_agent_instance_register(&message, &events, &registry, &db, &wh)
        .await
        .expect("registration should succeed");

    let agent = registry.get(0xDEAD_0001).await.expect("agent should exist");
    assert_eq!(agent.process_pid, 0, "ProcessPID should clamp to 0 on overflow");
    assert_eq!(agent.sleep_delay, 0, "SleepDelay should clamp to 0 on overflow");
    assert_eq!(agent.sleep_jitter, 0, "SleepJitter should clamp to 0 on overflow");
}

#[tokio::test]
async fn handle_agent_instance_register_accepts_u32_max_values() {
    let (db, wh) = test_audit_deps().await;
    let registry = test_registry().await;
    let events = EventBus::default();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_REGISTER,
            "AgentHeader": {
                "Size": "0",
                "MagicValue": "DEADBEEF",
                "AgentID": "DEAD0002",
            },
            "RegisterInfo": {
                "Hostname": "H2",
                "Username": "u2",
                "ProcessPID": u32::MAX as u64,
                "SleepDelay": u32::MAX as u64,
                "SleepJitter": u32::MAX as u64,
            },
        },
    });

    handle_agent_instance_register(&message, &events, &registry, &db, &wh)
        .await
        .expect("registration should succeed");

    let agent = registry.get(0xDEAD_0002).await.expect("agent should exist");
    assert_eq!(agent.process_pid, u32::MAX, "ProcessPID at u32::MAX should be accepted");
    assert_eq!(agent.sleep_delay, u32::MAX, "SleepDelay at u32::MAX should be accepted");
    assert_eq!(agent.sleep_jitter, u32::MAX, "SleepJitter at u32::MAX should be accepted");
}

// ── ListenerStart handler tests ─────────────────────────────────

fn listener_start_message(status: &str, error: &str) -> Value {
    serde_json::json!({
        "Head": { "Type": HEAD_LISTENER },
        "Body": {
            "Type": BODY_LISTENER_START,
            "Listener": {
                "Name": "https-listener",
                "Protocol": "HTTPS",
                "Host": "0.0.0.0",
                "PortBind": "443",
                "Status": status,
                "Error": error,
                "Info": { "CertPath": "/tmp/cert.pem" },
            },
        },
    })
}

#[tokio::test]
async fn listener_start_broadcasts_online_mark() {
    let (db, wh) = test_audit_deps().await;
    let events = EventBus::default();
    let mut rx = events.subscribe();

    let message = listener_start_message("online", "");

    handle_listener_start(&message, &events, &db, &wh)
        .await
        .expect("listener start should succeed");

    let event = rx.recv().await.expect("event should be broadcast");
    match event {
        OperatorMessage::ListenerMark(msg) => {
            assert_eq!(msg.info.name, "https-listener");
            assert_eq!(msg.info.mark, "Online");
        }
        other => panic!("expected ListenerMark, got: {other:?}"),
    }
}

#[tokio::test]
async fn listener_start_broadcasts_error_on_failure() {
    let (db, wh) = test_audit_deps().await;
    let events = EventBus::default();
    let mut rx = events.subscribe();

    let message = listener_start_message("error", "bind: address already in use");

    handle_listener_start(&message, &events, &db, &wh)
        .await
        .expect("listener start should succeed even on error status");

    let event = rx.recv().await.expect("event should be broadcast");
    match event {
        OperatorMessage::ListenerError(msg) => {
            assert_eq!(msg.info.name, "https-listener");
            assert_eq!(msg.info.error, "bind: address already in use");
        }
        other => panic!("expected ListenerError, got: {other:?}"),
    }
}

#[tokio::test]
async fn listener_start_error_text_nonempty_overrides_status() {
    let (db, wh) = test_audit_deps().await;
    let events = EventBus::default();
    let mut rx = events.subscribe();

    // Status is "online" but error text is non-empty — should still treat as error.
    let message = listener_start_message("online", "partial failure");

    handle_listener_start(&message, &events, &db, &wh)
        .await
        .expect("listener start should succeed");

    let event = rx.recv().await.expect("event should be broadcast");
    assert!(
        matches!(event, OperatorMessage::ListenerError(_)),
        "non-empty error text should produce ListenerError"
    );
}

#[tokio::test]
async fn listener_start_rejects_missing_name() {
    let (db, wh) = test_audit_deps().await;
    let events = EventBus::default();

    let message = serde_json::json!({
        "Body": {
            "Type": BODY_LISTENER_START,
            "Listener": {
                "Protocol": "HTTPS",
                "Host": "0.0.0.0",
                "PortBind": "443",
                "Status": "online",
                "Error": "",
            },
        },
    });

    let err = handle_listener_start(&message, &events, &db, &wh)
        .await
        .expect_err("missing Name should fail");
    assert!(
        matches!(err, ServiceBridgeError::MissingField(ref f) if f.contains("Name")),
        "expected MissingField mentioning Name, got: {err:?}"
    );
}

#[tokio::test]
async fn listener_start_rejects_missing_body() {
    let (db, wh) = test_audit_deps().await;
    let events = EventBus::default();
    let message = serde_json::json!({ "Head": { "Type": HEAD_LISTENER } });

    let err = handle_listener_start(&message, &events, &db, &wh)
        .await
        .expect_err("missing Body should fail");
    assert!(matches!(err, ServiceBridgeError::MissingField(ref f) if f.contains("Body")));
}

#[tokio::test]
async fn listener_start_rejects_missing_status() {
    let (db, wh) = test_audit_deps().await;
    let events = EventBus::default();

    let message = serde_json::json!({
        "Body": {
            "Type": BODY_LISTENER_START,
            "Listener": {
                "Name": "test",
                "Protocol": "HTTPS",
                "Host": "0.0.0.0",
                "PortBind": "443",
                "Error": "",
            },
        },
    });

    let err = handle_listener_start(&message, &events, &db, &wh)
        .await
        .expect_err("missing Status should fail");
    assert!(
        matches!(err, ServiceBridgeError::MissingField(ref f) if f.contains("Status")),
        "expected MissingField mentioning Status, got: {err:?}"
    );
}

#[tokio::test]
async fn listener_message_dispatches_start() {
    let (db, wh) = test_audit_deps().await;
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let mut client_listeners = Vec::new();

    let message = listener_start_message("online", "");

    handle_listener_message(&message, &bridge, &events, &db, &wh, &mut client_listeners)
        .await
        .expect("dispatch to listener start should succeed");

    let event = rx.recv().await.expect("event should be broadcast");
    assert!(
        matches!(event, OperatorMessage::ListenerMark(_)),
        "expected ListenerMark from dispatched handler"
    );
}

// ── Audit logging tests ───────────────────────────────────────────

#[tokio::test]
async fn register_agent_creates_audit_entry() {
    let (db, wh) = test_audit_deps().await;
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");
    let events = EventBus::default();
    let mut client_agents = Vec::new();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_REGISTER_AGENT },
        "Body": { "Agent": { "Name": "AuditTestAgent" } },
    });

    handle_register_agent(&message, &bridge, &events, &db, &wh, &mut client_agents)
        .await
        .expect("registration should succeed");

    let query = crate::audit::AuditQuery {
        action: Some("service.register_agent".to_owned()),
        ..Default::default()
    };
    let page = crate::audit::query_audit_log(&db, &query).await.expect("query should succeed");
    assert_eq!(page.total, 1, "expected one audit entry for agent registration");
    assert_eq!(page.items[0].actor, "service");
    assert_eq!(page.items[0].target_kind, "agent_type");
    assert_eq!(page.items[0].target_id.as_deref(), Some("AuditTestAgent"));
}

#[tokio::test]
async fn listener_add_creates_audit_entry() {
    let (db, wh) = test_audit_deps().await;
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");
    let events = EventBus::default();
    let mut client_listeners = Vec::new();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_LISTENER },
        "Body": {
            "Type": BODY_LISTENER_ADD,
            "Listener": { "Name": "audit-listener" },
        },
    });

    handle_listener_add(&message, &bridge, &events, &db, &wh, &mut client_listeners)
        .await
        .expect("listener add should succeed");

    let query = crate::audit::AuditQuery {
        action: Some("service.listener_add".to_owned()),
        ..Default::default()
    };
    let page = crate::audit::query_audit_log(&db, &query).await.expect("query should succeed");
    assert_eq!(page.total, 1, "expected one audit entry for listener add");
    assert_eq!(page.items[0].actor, "service");
    assert_eq!(page.items[0].target_id.as_deref(), Some("audit-listener"));
}

#[tokio::test]
async fn listener_start_creates_audit_entry() {
    let (db, wh) = test_audit_deps().await;
    let events = EventBus::default();

    let message = listener_start_message("online", "");
    handle_listener_start(&message, &events, &db, &wh)
        .await
        .expect("listener start should succeed");

    let query = crate::audit::AuditQuery {
        action: Some("service.listener_start".to_owned()),
        ..Default::default()
    };
    let page = crate::audit::query_audit_log(&db, &query).await.expect("query should succeed");
    assert_eq!(page.total, 1, "expected one audit entry for listener start");
    assert_eq!(page.items[0].actor, "service");
    assert_eq!(page.items[0].result_status, AuditResultStatus::Success,);
}

#[tokio::test]
async fn listener_start_failure_creates_audit_entry_with_failure_status() {
    let (db, wh) = test_audit_deps().await;
    let events = EventBus::default();

    let message = listener_start_message("error", "bind failed");
    handle_listener_start(&message, &events, &db, &wh)
        .await
        .expect("listener start (error) should succeed");

    let query = crate::audit::AuditQuery {
        action: Some("service.listener_start".to_owned()),
        ..Default::default()
    };
    let page = crate::audit::query_audit_log(&db, &query).await.expect("query should succeed");
    assert_eq!(page.total, 1);
    assert_eq!(page.items[0].result_status, AuditResultStatus::Failure,);
}

#[tokio::test]
async fn agent_instance_register_creates_audit_entry() {
    let (db, wh) = test_audit_deps().await;
    let registry = test_registry().await;
    let events = EventBus::default();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_REGISTER,
            "AgentHeader": { "AgentID": "ABCD1234", "MagicValue": "DEADBEEF" },
            "RegisterInfo": {
                "Hostname": "HOST",
                "Username": "user",
                "DomainName": "DOMAIN",
                "ExternalIP": "10.0.0.1",
                "InternalIP": "192.168.1.1",
                "ProcessName": "svc.exe",
                "ProcessPID": 100,
                "ProcessArch": "x64",
                "OSVersion": "Windows 10",
                "OSArch": "x64",
            },
        },
    });

    handle_agent_instance_register(&message, &events, &registry, &db, &wh)
        .await
        .expect("agent registration should succeed");

    let query = crate::audit::AuditQuery {
        action: Some("service.agent_register".to_owned()),
        ..Default::default()
    };
    let page = crate::audit::query_audit_log(&db, &query).await.expect("query should succeed");
    assert_eq!(page.total, 1, "expected one audit entry for agent instance register");
    assert_eq!(page.items[0].actor, "service");
    assert_eq!(page.items[0].target_kind, "agent");
    assert_eq!(page.items[0].agent_id.as_deref(), Some("ABCD1234"));
}

// ── authenticate() tests ─────────────────────────────────────────

/// Helper: send a text message from the tungstenite client side of a ws_pair.
async fn client_send(
    client: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    text: &str,
) {
    use futures_util::SinkExt as _;
    use tokio_tungstenite::tungstenite::Message as TungMsg;
    client.send(TungMsg::Text(text.into())).await.expect("client send");
}

/// Helper: read a text message from the tungstenite client side.
async fn client_recv(
    client: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> String {
    use futures_util::StreamExt as _;
    let msg = client.next().await.expect("should receive").expect("not error");
    msg.into_text().expect("text message").to_string()
}

#[tokio::test]
async fn authenticate_correct_password_succeeds() {
    let server_verifier = test_verifier("correct-pw");

    let (mut server_ws, mut client_ws) = ws_pair().await;

    let auth_handle = tokio::spawn(async move {
        let rl = LoginRateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");
        authenticate(&mut server_ws, &server_verifier, &rl, ip).await
    });

    let register_msg = serde_json::json!({
        "Head": { "Type": "Register" },
        "Body": { "Password": "correct-pw" },
    });
    client_send(&mut client_ws, &register_msg.to_string()).await;

    let response_text = client_recv(&mut client_ws).await;
    let response: Value = serde_json::from_str(&response_text).expect("valid json");
    assert!(response["Body"]["Success"].as_bool().expect("bool"), "auth should succeed");

    let result = auth_handle.await.expect("join");
    assert!(result.is_ok(), "authenticate should return Ok");
}

#[tokio::test]
async fn authenticate_wrong_password_fails() {
    let server_verifier = test_verifier("correct-pw");

    let (mut server_ws, mut client_ws) = ws_pair().await;

    let auth_handle = tokio::spawn(async move {
        let rl = LoginRateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");
        authenticate(&mut server_ws, &server_verifier, &rl, ip).await
    });

    let register_msg = serde_json::json!({
        "Head": { "Type": "Register" },
        "Body": { "Password": "wrong-pw" },
    });
    client_send(&mut client_ws, &register_msg.to_string()).await;

    let response_text = client_recv(&mut client_ws).await;
    let response: Value = serde_json::from_str(&response_text).expect("valid json");
    assert!(!response["Body"]["Success"].as_bool().expect("bool"), "auth should report failure");

    let result = auth_handle.await.expect("join");
    assert!(result.is_err(), "authenticate should return Err");
    assert!(
        matches!(result.expect_err("expected Err"), ServiceBridgeError::AuthenticationFailed),
        "expected AuthenticationFailed error"
    );
}

#[tokio::test]
async fn authenticate_malformed_json_fails() {
    let server_verifier = test_verifier("pw");

    let (mut server_ws, mut client_ws) = ws_pair().await;

    let auth_handle = tokio::spawn(async move {
        let rl = LoginRateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");
        authenticate(&mut server_ws, &server_verifier, &rl, ip).await
    });

    client_send(&mut client_ws, "this is not json!!!").await;

    let result = auth_handle.await.expect("join");
    assert!(result.is_err(), "malformed JSON should fail");
    assert!(
        matches!(result.expect_err("expected Err"), ServiceBridgeError::Json(_)),
        "expected Json parse error"
    );
}

#[tokio::test]
async fn authenticate_non_register_head_type_fails() {
    let server_verifier = test_verifier("pw");

    let (mut server_ws, mut client_ws) = ws_pair().await;

    let auth_handle = tokio::spawn(async move {
        let rl = LoginRateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");
        authenticate(&mut server_ws, &server_verifier, &rl, ip).await
    });

    let message = serde_json::json!({
        "Head": { "Type": "Agent" },
        "Body": { "Password": "pw" },
    });
    client_send(&mut client_ws, &message.to_string()).await;

    let result = auth_handle.await.expect("join");
    assert!(result.is_err(), "non-Register type should fail");
    assert!(
        matches!(result.expect_err("expected Err"), ServiceBridgeError::AuthenticationFailed),
        "expected AuthenticationFailed error"
    );
}

#[tokio::test]
async fn authenticate_missing_password_field_fails() {
    let server_verifier = test_verifier("secret");

    let (mut server_ws, mut client_ws) = ws_pair().await;

    let auth_handle = tokio::spawn(async move {
        let rl = LoginRateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");
        authenticate(&mut server_ws, &server_verifier, &rl, ip).await
    });

    let message = serde_json::json!({
        "Head": { "Type": "Register" },
        "Body": {},
    });
    client_send(&mut client_ws, &message.to_string()).await;

    // Missing Password defaults to empty string, which won't match "secret"
    let response_text = client_recv(&mut client_ws).await;
    let response: Value = serde_json::from_str(&response_text).expect("valid json");
    assert!(
        !response["Body"]["Success"].as_bool().expect("bool"),
        "missing password should fail auth"
    );

    let result = auth_handle.await.expect("join");
    assert!(result.is_err());
}

#[tokio::test]
async fn authenticate_empty_password_matches_empty_config() {
    let server_verifier = test_verifier("");

    let (mut server_ws, mut client_ws) = ws_pair().await;

    let auth_handle = tokio::spawn(async move {
        let rl = LoginRateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");
        authenticate(&mut server_ws, &server_verifier, &rl, ip).await
    });

    let message = serde_json::json!({
        "Head": { "Type": "Register" },
        "Body": { "Password": "" },
    });
    client_send(&mut client_ws, &message.to_string()).await;

    let response_text = client_recv(&mut client_ws).await;
    let response: Value = serde_json::from_str(&response_text).expect("valid json");
    assert!(response["Body"]["Success"].as_bool().expect("bool"));

    let result = auth_handle.await.expect("join");
    assert!(result.is_ok());
}

// ── handle_agent_output tests ────────────────────────────────────

#[tokio::test]
async fn handle_agent_output_broadcasts_callback_as_agent_response() {
    let events = EventBus::default();
    let mut rx = events.subscribe();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_OUTPUT,
            "AgentID": "CAFE0001",
            "Callback": { "Output": "command output here" },
        },
    });

    handle_agent_output(&message, &events).await.expect("agent output should succeed");

    let event = rx.recv().await.expect("event should be broadcast");
    match event {
        OperatorMessage::AgentResponse(msg) => {
            assert_eq!(msg.info.demon_id, "CAFE0001");
            assert_eq!(msg.head.user, "service");
            assert_eq!(msg.head.event, EventCode::Session);
            // Callback was a JSON object — it should be serialized into output.
            assert!(
                msg.info.output.contains("command output here"),
                "callback content should be forwarded, got: {}",
                msg.info.output
            );
        }
        other => panic!("expected AgentResponse, got: {other:?}"),
    }
}

#[tokio::test]
async fn handle_agent_output_string_callback_forwarded_verbatim() {
    let events = EventBus::default();
    let mut rx = events.subscribe();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_OUTPUT,
            "AgentID": "BEEF0002",
            "Callback": "raw text output",
        },
    });

    handle_agent_output(&message, &events).await.expect("agent output should succeed");

    let event = rx.recv().await.expect("event should be broadcast");
    match event {
        OperatorMessage::AgentResponse(msg) => {
            assert_eq!(msg.info.demon_id, "BEEF0002");
            assert_eq!(msg.info.output, "raw text output");
        }
        other => panic!("expected AgentResponse, got: {other:?}"),
    }
}

#[tokio::test]
async fn handle_agent_output_missing_body_returns_error() {
    let events = EventBus::default();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
    });

    let err = handle_agent_output(&message, &events).await.expect_err("should fail without Body");
    assert!(matches!(err, ServiceBridgeError::MissingField(ref f) if f.contains("Body")));
}

#[tokio::test]
async fn handle_agent_output_missing_agent_id_uses_unknown() {
    let events = EventBus::default();
    let mut rx = events.subscribe();

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_OUTPUT,
        },
    });

    handle_agent_output(&message, &events).await.expect("should succeed with defaults");

    let event = rx.recv().await.expect("event should be broadcast");
    match event {
        OperatorMessage::AgentResponse(msg) => {
            assert_eq!(msg.info.demon_id, "unknown");
            assert!(msg.info.output.is_empty(), "no callback means empty output");
        }
        other => panic!("expected AgentResponse, got: {other:?}"),
    }
}

// ── handle_agent_message dispatch tests ──────────────────────────

#[tokio::test]
async fn handle_agent_message_dispatches_agent_register() {
    let (db, wh) = test_audit_deps().await;
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let registry = test_registry().await;

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_REGISTER,
            "AgentHeader": {
                "AgentID": "FF001122",
                "MagicValue": "DEADBEEF",
            },
            "RegisterInfo": {
                "Hostname": "DISPATCH-TEST",
                "Username": "user1",
            },
        },
    });

    let (mut server_ws, _client_ws) = ws_pair().await;

    handle_agent_message(&message, &bridge, &events, &registry, &db, &wh, &mut server_ws)
        .await
        .expect("dispatch to AgentRegister should succeed");

    let agent = registry.get(0xFF00_1122).await.expect("agent should be registered");
    assert_eq!(agent.hostname, "DISPATCH-TEST");

    let event = rx.recv().await.expect("event should be broadcast");
    assert!(matches!(event, OperatorMessage::AgentNew(_)));
}

#[tokio::test]
async fn handle_agent_message_dispatches_agent_response() {
    let (db, wh) = test_audit_deps().await;
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let registry = test_registry().await;

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_RESPONSE,
            "Agent": { "NameID": "DISPATCH01" },
            "Response": "dGVzdA==",
            "RandID": "dispatch-rand",
        },
    });

    let (mut server_ws, _client_ws) = ws_pair().await;

    handle_agent_message(&message, &bridge, &events, &registry, &db, &wh, &mut server_ws)
        .await
        .expect("dispatch to AgentResponse should succeed");

    let event = rx.recv().await.expect("event should be broadcast");
    match event {
        OperatorMessage::AgentResponse(msg) => {
            assert_eq!(msg.info.demon_id, "DISPATCH01");
            assert_eq!(msg.info.command_id, "dispatch-rand");
        }
        other => panic!("expected AgentResponse, got: {other:?}"),
    }
}

#[tokio::test]
async fn handle_agent_message_dispatches_agent_output() {
    let (db, wh) = test_audit_deps().await;
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let registry = test_registry().await;

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": BODY_AGENT_OUTPUT,
            "AgentID": "OUTPUT01",
            "Callback": { "Output": "hello" },
        },
    });

    let (mut server_ws, _client_ws) = ws_pair().await;

    handle_agent_message(&message, &bridge, &events, &registry, &db, &wh, &mut server_ws)
        .await
        .expect("dispatch to AgentOutput should succeed");

    let event = rx.recv().await.expect("event should be broadcast");
    match event {
        OperatorMessage::AgentResponse(msg) => {
            assert_eq!(msg.info.demon_id, "OUTPUT01");
            assert!(msg.info.output.contains("hello"));
        }
        other => panic!("expected AgentResponse, got: {other:?}"),
    }
}

#[tokio::test]
async fn handle_agent_message_unknown_body_type_returns_ok() {
    let (db, wh) = test_audit_deps().await;
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "test".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");
    let events = EventBus::default();
    let registry = test_registry().await;

    let message = serde_json::json!({
        "Head": { "Type": HEAD_AGENT },
        "Body": {
            "Type": "SomethingCompletelyUnknown",
        },
    });

    let (mut server_ws, _client_ws) = ws_pair().await;

    let result =
        handle_agent_message(&message, &bridge, &events, &registry, &db, &wh, &mut server_ws).await;
    assert!(result.is_ok(), "unknown agent body type should be silently ignored");
}

#[tokio::test]
async fn authenticate_rate_limits_after_max_failures() {
    let server_verifier = test_verifier("correct-pw");
    let rate_limiter = LoginRateLimiter::new();
    let ip: IpAddr = "10.0.0.99".parse().expect("valid IP");

    // Exhaust the rate limiter for this IP (5 failures).
    for _ in 0..5 {
        rate_limiter.record_failure(ip).await;
    }

    // The next attempt should be rate-limited without even reading a message.
    let (mut server_ws, _client_ws) = ws_pair().await;
    let result = authenticate(&mut server_ws, &server_verifier, &rate_limiter, ip).await;
    assert!(result.is_err(), "should be rate limited");
    assert!(
        matches!(result.expect_err("expected Err"), ServiceBridgeError::RateLimited),
        "expected RateLimited error"
    );
}

#[tokio::test]
async fn authenticate_allows_different_ip_when_one_is_limited() {
    let server_verifier = test_verifier("correct-pw");
    let rate_limiter = LoginRateLimiter::new();
    let blocked_ip: IpAddr = "10.0.0.100".parse().expect("valid IP");
    let allowed_ip: IpAddr = "10.0.0.101".parse().expect("valid IP");

    // Exhaust the rate limiter for blocked_ip.
    for _ in 0..5 {
        rate_limiter.record_failure(blocked_ip).await;
    }

    // blocked_ip should be rejected.
    let (mut server_ws, _client_ws) = ws_pair().await;
    let result = authenticate(&mut server_ws, &server_verifier, &rate_limiter, blocked_ip).await;
    assert!(matches!(result.expect_err("expected Err"), ServiceBridgeError::RateLimited));

    // allowed_ip should still work (correct password).
    let (mut server_ws2, mut client_ws2) = ws_pair().await;
    let rl = rate_limiter.clone();
    let hash = server_verifier.clone();
    let auth_handle =
        tokio::spawn(async move { authenticate(&mut server_ws2, &hash, &rl, allowed_ip).await });

    let msg = serde_json::json!({
        "Head": { "Type": "Register" },
        "Body": { "Password": "correct-pw" },
    });
    client_send(&mut client_ws2, &msg.to_string()).await;
    let _ = client_recv(&mut client_ws2).await;

    let result = auth_handle.await.expect("join");
    assert!(result.is_ok(), "unblocked IP should authenticate successfully");
}

#[tokio::test]
async fn authenticate_times_out_when_no_frame_sent() {
    let server_verifier = test_verifier("correct-pw");
    let rate_limiter = LoginRateLimiter::new();
    let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");

    let (mut server_ws, _client_ws) = ws_pair().await;

    // Hold `_client_ws` open but never send anything — the server side
    // should time out after SERVICE_AUTH_FRAME_TIMEOUT.
    let start = tokio::time::Instant::now();
    let result = authenticate(&mut server_ws, &server_verifier, &rate_limiter, ip).await;
    let elapsed = start.elapsed();

    assert!(
        matches!(result, Err(ServiceBridgeError::AuthenticationTimeout)),
        "expected AuthenticationTimeout, got {result:?}"
    );
    // Should complete within a reasonable margin of the timeout.
    assert!(
        elapsed < auth::SERVICE_AUTH_FRAME_TIMEOUT + Duration::from_secs(2),
        "took too long: {elapsed:?}"
    );
}

#[tokio::test]
async fn authenticate_binary_frame_returns_auth_failed() {
    let server_verifier = test_verifier("pw");

    let (mut server_ws, mut client_ws) = ws_pair().await;

    let auth_handle = tokio::spawn(async move {
        let rl = LoginRateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");
        authenticate(&mut server_ws, &server_verifier, &rl, ip).await
    });

    // Send a binary frame instead of a text frame.
    {
        use futures_util::SinkExt as _;
        use tokio_tungstenite::tungstenite::Message as TungMsg;
        client_ws
            .send(TungMsg::Binary(vec![0xDE, 0xAD, 0xBE, 0xEF].into()))
            .await
            .expect("client send binary");
    }

    let result = auth_handle.await.expect("join");
    assert!(result.is_err(), "binary frame should fail auth");
    assert!(
        matches!(result.expect_err("expected Err"), ServiceBridgeError::AuthenticationFailed),
        "expected AuthenticationFailed for binary frame"
    );
}

#[tokio::test]
async fn authenticate_close_frame_returns_auth_failed() {
    let server_verifier = test_verifier("pw");

    let (mut server_ws, mut client_ws) = ws_pair().await;

    let auth_handle = tokio::spawn(async move {
        let rl = LoginRateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");
        authenticate(&mut server_ws, &server_verifier, &rl, ip).await
    });

    // Send a close frame instead of a text frame.
    {
        use futures_util::SinkExt as _;
        use tokio_tungstenite::tungstenite::Message as TungMsg;
        client_ws.send(TungMsg::Close(None)).await.expect("client send close");
    }

    let result = auth_handle.await.expect("join");
    assert!(result.is_err(), "close frame should fail auth");
    assert!(
        matches!(result.expect_err("expected Err"), ServiceBridgeError::AuthenticationFailed),
        "expected AuthenticationFailed for close frame"
    );
}

// ── service_routes wiring tests ─────────────────────────────────

/// Build a minimal `TeamserverState` with the given `ServiceBridge` attached.
async fn test_state_with_bridge(bridge: ServiceBridge) -> crate::TeamserverState {
    use red_cell_common::config::Profile;

    let profile = Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 0
        }

        Operators {
          user "op" {
            Password = "pw1234"
            Role = "Operator"
          }
        }

        Demon {}
        "#,
    )
    .expect("test profile should parse");
    let database = crate::database::Database::connect_in_memory()
        .await
        .expect("in-memory database should initialize");
    let agent_registry = crate::AgentRegistry::new(database.clone());
    let events = crate::EventBus::new(8);
    let sockets = crate::SocketRelayManager::new(agent_registry.clone(), events.clone());
    crate::TeamserverState {
        profile: profile.clone(),
        database: database.clone(),
        auth: crate::AuthService::from_profile(&profile).expect("auth service should initialize"),
        api: crate::ApiRuntime::from_profile(&profile).expect("rng should work in tests"),
        events: events.clone(),
        connections: crate::OperatorConnectionManager::new(),
        agent_registry: agent_registry.clone(),
        listeners: crate::ListenerManager::new(
            database,
            agent_registry,
            events,
            sockets.clone(),
            None,
        )
        .with_demon_allow_legacy_ctr(true),
        payload_builder: crate::PayloadBuilderService::disabled_for_tests(),
        sockets,
        webhooks: crate::AuditWebhookNotifier::from_profile(&profile),
        login_rate_limiter: LoginRateLimiter::new(),
        shutdown: crate::ShutdownController::new(),
        service_bridge: Some(bridge),
        started_at: std::time::Instant::now(),
        plugins_loaded: 0,
        plugins_failed: 0,
        metrics: crate::metrics::standalone_metrics_handle(),
    }
}

#[tokio::test]
async fn service_routes_registers_get_endpoint() {
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;

    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "svc-bridge".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");

    let state = test_state_with_bridge(bridge.clone()).await;
    let app = service_routes(&bridge).with_state(state);

    let response = app
        .oneshot(Request::get("/svc-bridge").body(String::new()).expect("request"))
        .await
        .expect("router should respond");

    // The route is registered; without WebSocket upgrade headers the extractor
    // rejects the request, but the status must NOT be 404 (unmounted) or
    // 405 (wrong method).
    assert_ne!(response.status(), StatusCode::NOT_FOUND, "GET /svc-bridge should be mounted");
    assert_ne!(
        response.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "GET should be the accepted method"
    );
}

#[tokio::test]
async fn service_routes_rejects_post_with_method_not_allowed() {
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;

    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "svc-bridge".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");

    let state = test_state_with_bridge(bridge.clone()).await;
    let app = service_routes(&bridge).with_state(state);

    let response = app
        .oneshot(Request::post("/svc-bridge").body(String::new()).expect("request"))
        .await
        .expect("router should respond");

    assert_eq!(
        response.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "POST to the service endpoint should be rejected"
    );
}

#[tokio::test]
async fn service_routes_returns_404_for_unregistered_path() {
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;

    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "svc-bridge".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");

    let state = test_state_with_bridge(bridge.clone()).await;
    let app = service_routes(&bridge).with_state(state);

    let response = app
        .oneshot(Request::get("/other-path").body(String::new()).expect("request"))
        .await
        .expect("router should respond");

    assert_eq!(response.status(), StatusCode::NOT_FOUND, "unregistered path should return 404");
}

#[tokio::test]
async fn service_routes_normalizes_leading_slash() {
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt as _;

    // Endpoint configured without a leading slash — service_routes should
    // still mount it at exactly "/<endpoint>" (one slash, no double-slash).
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: "no-leading-slash".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");

    let state = test_state_with_bridge(bridge.clone()).await;
    let app = service_routes(&bridge).with_state(state);

    let response = app
        .oneshot(Request::get("/no-leading-slash").body(String::new()).expect("request"))
        .await
        .expect("router should respond");

    assert_ne!(
        response.status(),
        StatusCode::NOT_FOUND,
        "endpoint should be reachable at /no-leading-slash"
    );

    // Double-slash variant should NOT match.
    let bridge2 = ServiceBridge::new(ServiceConfig {
        endpoint: "no-leading-slash".to_owned(),
        password: "pw".to_owned(),
    })
    .expect("service bridge");
    let state2 = test_state_with_bridge(bridge2.clone()).await;
    let app2 = service_routes(&bridge2).with_state(state2);

    let response2 = app2
        .oneshot(Request::get("//no-leading-slash").body(String::new()).expect("request"))
        .await
        .expect("router should respond");

    assert_eq!(
        response2.status(),
        StatusCode::NOT_FOUND,
        "double-slash path should not match the endpoint"
    );
}
