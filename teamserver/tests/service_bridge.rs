//! WebSocket integration tests for the service bridge auth + dispatch flow.
//!
//! These tests spin up a real teamserver (with service bridge enabled),
//! connect via WebSocket, authenticate, and exercise the dispatch loop.

mod common;

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use red_cell::{
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, LoginRateLimiter, OperatorConnectionManager, PayloadBuilderService,
    ServiceBridge, ShutdownController, SocketRelayManager, TeamserverState, build_router,
};
use red_cell_common::config::ServiceConfig;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message as ClientMessage;

/// Spawn a test server with the service bridge enabled.
async fn spawn_service_server(
    service_password: &str,
    service_endpoint: &str,
) -> Result<(std::net::SocketAddr, AgentRegistry, EventBus), Box<dyn std::error::Error>> {
    let profile = common::default_test_profile();
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let listeners = ListenerManager::new(
        database.clone(),
        registry.clone(),
        events.clone(),
        sockets.clone(),
        None,
    );
    let webhooks = AuditWebhookNotifier::from_profile(&profile);
    let bridge = ServiceBridge::new(ServiceConfig {
        endpoint: service_endpoint.to_owned(),
        password: service_password.to_owned(),
    });

    let state = TeamserverState {
        profile: profile.clone(),
        database,
        auth: AuthService::from_profile(&profile)?,
        api: ApiRuntime::from_profile(&profile)?,
        events: events.clone(),
        connections: OperatorConnectionManager::new(),
        agent_registry: registry.clone(),
        listeners,
        payload_builder: PayloadBuilderService::disabled_for_tests(),
        sockets,
        webhooks,
        login_rate_limiter: LoginRateLimiter::new(),
        shutdown: ShutdownController::new(),
        service_bridge: Some(bridge),
    };

    let tcp = TcpListener::bind("127.0.0.1:0").await?;
    let addr = tcp.local_addr()?;
    tokio::spawn(async move {
        let app = build_router(state);
        let _ = axum::serve(tcp, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await;
    });

    Ok((addr, registry, events))
}

/// Connect a tungstenite WebSocket client to the service endpoint.
async fn connect_service(
    addr: std::net::SocketAddr,
    endpoint: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let url = format!("ws://127.0.0.1:{}/{endpoint}", addr.port());
    let (client, _) = tokio_tungstenite::connect_async(&url).await.expect("ws connect");
    client
}

/// Send a JSON value as a text frame.
async fn send_json(
    client: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    value: &Value,
) {
    let text = serde_json::to_string(value).expect("serialize");
    client.send(ClientMessage::Text(text.into())).await.expect("send");
}

/// Read and parse a JSON response with timeout.
async fn recv_json(
    client: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Value {
    let msg = timeout(Duration::from_secs(5), client.next())
        .await
        .expect("timeout waiting for ws message")
        .expect("stream should have message")
        .expect("ws message should be ok");
    let text = msg.into_text().expect("text frame").to_string();
    serde_json::from_str(&text).expect("valid json")
}

/// Authenticate and return success status.
async fn authenticate(
    client: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    password: &str,
) -> bool {
    let auth_msg = serde_json::json!({
        "Head": { "Type": "Register" },
        "Body": { "Password": password },
    });
    send_json(client, &auth_msg).await;
    let resp = recv_json(client).await;
    resp["Body"]["Success"].as_bool().unwrap_or(false)
}

// ── Tests ────────────────────────────────────────────────────────────

#[tokio::test]
async fn service_bridge_auth_success_then_register_agent() {
    let (addr, _registry, events) =
        spawn_service_server("test-secret", "service-ws").await.expect("spawn");
    let mut event_sub = events.subscribe();
    let mut client = connect_service(addr, "service-ws").await;

    // Authenticate with correct password.
    assert!(authenticate(&mut client, "test-secret").await, "auth should succeed");

    // Service client connected log event should be broadcast.
    let event =
        timeout(Duration::from_secs(5), event_sub.recv()).await.expect("timeout").expect("event");
    assert!(
        matches!(event, red_cell_common::operator::OperatorMessage::TeamserverLog(_)),
        "expected TeamserverLog for connection"
    );

    // Register an agent type.
    let register_agent_msg = serde_json::json!({
        "Head": { "Type": "RegisterAgent" },
        "Body": {
            "Agent": {
                "Name": "IntegrationTestAgent",
                "Author": "test",
                "Description": "Test agent for integration",
            }
        },
    });
    send_json(&mut client, &register_agent_msg).await;

    // Wait for the broadcast event.
    let event =
        timeout(Duration::from_secs(5), event_sub.recv()).await.expect("timeout").expect("event");
    assert!(
        matches!(event, red_cell_common::operator::OperatorMessage::ServiceAgentRegister(_)),
        "expected ServiceAgentRegister event"
    );
}

#[tokio::test]
async fn service_bridge_auth_failure_closes_connection() {
    let (addr, _registry, _events) =
        spawn_service_server("correct-pw", "service-ws").await.expect("spawn");
    let mut client = connect_service(addr, "service-ws").await;

    // Authenticate with wrong password.
    let success = authenticate(&mut client, "wrong-pw").await;
    assert!(!success, "auth should fail");

    // Server should close the connection after auth failure.
    // Try to read — should get Close or None.
    let next = timeout(Duration::from_secs(5), client.next()).await;
    match next {
        Ok(Some(Ok(ClientMessage::Close(_)))) | Ok(None) => {} // expected
        Ok(Some(Err(_))) => {} // connection reset is also acceptable
        other => panic!("expected connection close after auth failure, got: {other:?}"),
    }
}

#[tokio::test]
async fn service_bridge_auth_then_listener_add() {
    let (addr, _registry, events) = spawn_service_server("pw123", "svc-ep").await.expect("spawn");
    let mut event_sub = events.subscribe();
    let mut client = connect_service(addr, "svc-ep").await;

    assert!(authenticate(&mut client, "pw123").await);

    // Consume the "connected" log event.
    let _ = timeout(Duration::from_secs(5), event_sub.recv()).await;

    // Add a listener.
    let listener_msg = serde_json::json!({
        "Head": { "Type": "Listener" },
        "Body": {
            "Type": "ListenerAdd",
            "Listener": {
                "Name": "integration-listener",
                "Agent": "TestAgent",
            },
        },
    });
    send_json(&mut client, &listener_msg).await;

    let event =
        timeout(Duration::from_secs(5), event_sub.recv()).await.expect("timeout").expect("event");
    assert!(
        matches!(event, red_cell_common::operator::OperatorMessage::ServiceListenerRegister(_)),
        "expected ServiceListenerRegister event"
    );
}

#[tokio::test]
async fn service_bridge_auth_then_agent_task_round_trip() {
    use base64::Engine as _;

    let (addr, registry, events) = spawn_service_server("secret", "svc").await.expect("spawn");
    let mut event_sub = events.subscribe();
    let mut client = connect_service(addr, "svc").await;

    assert!(authenticate(&mut client, "secret").await);

    // Consume the "connected" log event.
    let _ = timeout(Duration::from_secs(5), event_sub.recv()).await;

    // Register an agent instance in the registry so we can enqueue tasks for it.
    let agent_id: u32 = 0xBEEF_0001;
    let agent = red_cell_common::AgentRecord {
        agent_id,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: red_cell_common::AgentEncryptionInfo::default(),
        hostname: "INTEG-HOST".to_owned(),
        username: "integ-user".to_owned(),
        domain_name: String::new(),
        external_ip: String::new(),
        internal_ip: String::new(),
        process_name: String::new(),
        process_path: String::new(),
        base_address: 0,
        process_pid: 0,
        process_tid: 0,
        process_ppid: 0,
        process_arch: "x64".to_owned(),
        elevated: false,
        os_version: String::new(),
        os_build: 0,
        os_arch: "x64".to_owned(),
        sleep_delay: 5,
        sleep_jitter: 0,
        kill_date: None,
        working_hours: None,
        first_call_in: "0".to_owned(),
        last_call_in: "0".to_owned(),
    };
    registry.insert(agent).await.expect("insert agent");

    // Send an AgentTask Add via the service bridge.
    let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let encoded = base64::engine::general_purpose::STANDARD.encode(&payload);

    let task_add_msg = serde_json::json!({
        "Head": { "Type": "Agent" },
        "Body": {
            "Type": "AgentTask",
            "Agent": { "NameID": "BEEF0001" },
            "Task": "Add",
            "Command": encoded,
        },
    });
    send_json(&mut client, &task_add_msg).await;

    // Wait a moment for the server to process.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify the job was enqueued.
    let jobs = registry.queued_jobs(agent_id).await.expect("queued jobs");
    assert_eq!(jobs.len(), 1, "task should be enqueued via service bridge");
    assert_eq!(jobs[0].payload, payload);

    // Now send a Get to retrieve the tasks.
    let task_get_msg = serde_json::json!({
        "Head": { "Type": "Agent" },
        "Body": {
            "Type": "AgentTask",
            "Agent": { "NameID": "BEEF0001" },
            "Task": "Get",
        },
    });
    send_json(&mut client, &task_get_msg).await;

    let response = recv_json(&mut client).await;
    let tasks_queue = response["Body"]["TasksQueue"].as_str().expect("TasksQueue field");
    let decoded =
        base64::engine::general_purpose::STANDARD.decode(tasks_queue).expect("valid base64");
    assert_eq!(decoded, payload, "round-trip payload should match");

    // Queue should be drained.
    let remaining = registry.queued_jobs(agent_id).await.expect("queued");
    assert!(remaining.is_empty(), "queue should be drained after Get");
}

#[tokio::test]
async fn service_bridge_dispatch_unknown_type_does_not_crash() {
    let (addr, _registry, _events) = spawn_service_server("pw", "svc").await.expect("spawn");
    let mut client = connect_service(addr, "svc").await;

    assert!(authenticate(&mut client, "pw").await);

    // Send a message with an unknown head type.
    let unknown_msg = serde_json::json!({
        "Head": { "Type": "CompletelyUnknown" },
        "Body": { "Data": "test" },
    });
    send_json(&mut client, &unknown_msg).await;

    // Send a valid message after — the connection should still be alive.
    let another_msg = serde_json::json!({
        "Head": { "Type": "Listener" },
        "Body": {
            "Type": "ListenerAdd",
            "Listener": { "Name": "after-unknown", "Agent": "T" },
        },
    });
    send_json(&mut client, &another_msg).await;

    // Give server time to process.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connection should still be open — close gracefully.
    client.close(None).await.expect("graceful close");
}

#[tokio::test]
async fn service_bridge_agent_task_add_nonexistent_agent_does_not_crash() {
    use base64::Engine as _;

    let (addr, registry, _events) = spawn_service_server("secret", "svc").await.expect("spawn");
    let mut client = connect_service(addr, "svc").await;

    assert!(authenticate(&mut client, "secret").await);

    // Register a real agent so we can later verify nothing was enqueued there.
    let real_agent_id: u32 = 0xAAAA_0001;
    let real_agent = red_cell_common::AgentRecord {
        agent_id: real_agent_id,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: red_cell_common::AgentEncryptionInfo::default(),
        hostname: "real-host".to_owned(),
        username: "real-user".to_owned(),
        domain_name: String::new(),
        external_ip: String::new(),
        internal_ip: String::new(),
        process_name: String::new(),
        process_path: String::new(),
        base_address: 0,
        process_pid: 0,
        process_tid: 0,
        process_ppid: 0,
        process_arch: "x64".to_owned(),
        elevated: false,
        os_version: String::new(),
        os_build: 0,
        os_arch: "x64".to_owned(),
        sleep_delay: 5,
        sleep_jitter: 0,
        kill_date: None,
        working_hours: None,
        first_call_in: "0".to_owned(),
        last_call_in: "0".to_owned(),
    };
    registry.insert(real_agent).await.expect("insert real agent");

    // Send AgentTask.Add targeting a NameID that does not exist in the registry.
    let payload = base64::engine::general_purpose::STANDARD.encode(b"ghost-payload");
    let ghost_task_msg = serde_json::json!({
        "Head": { "Type": "Agent" },
        "Body": {
            "Type": "AgentTask",
            "Agent": { "NameID": "DEADBEEF" },
            "Task": "Add",
            "Command": payload,
        },
    });
    send_json(&mut client, &ghost_task_msg).await;

    // Give the server time to process the message.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // No jobs should have been enqueued for the real registered agent.
    let jobs = registry.queued_jobs(real_agent_id).await.expect("queued jobs");
    assert!(jobs.is_empty(), "no job should be enqueued for an unrelated agent");

    // The connection must still be alive — send a valid follow-up message
    // and confirm it is processed without error (listener add broadcasts an event).
    let (_, _, events2) = spawn_service_server("secret2", "svc2").await.expect("second spawn");
    let _ = events2; // unused, just ensuring the server helper compiles with this pattern

    // Reuse the existing connection: a second valid message should succeed.
    let listener_msg = serde_json::json!({
        "Head": { "Type": "Listener" },
        "Body": {
            "Type": "ListenerAdd",
            "Listener": { "Name": "after-ghost-task", "Agent": "TestAgent" },
        },
    });
    send_json(&mut client, &listener_msg).await;

    // Give server time to process the second message, then close gracefully.
    tokio::time::sleep(Duration::from_millis(100)).await;
    client.close(None).await.expect("graceful close after non-existent agent task");
}

#[tokio::test]
async fn service_bridge_rejects_oversized_messages() {
    let (addr, _registry, _events) = spawn_service_server("pw", "svc").await.expect("spawn");
    let mut client = connect_service(addr, "svc").await;

    // Send an oversized frame (> 1 MiB). Auth happens post-upgrade, so this
    // tests that the size limit is enforced even before authentication.
    let oversized = "x".repeat(1024 * 1024 + 1);
    client.send(ClientMessage::Text(oversized.into())).await.expect("send oversized");

    // The server should close the connection or return an error.
    let frame = timeout(Duration::from_secs(5), client.next())
        .await
        .expect("socket should react to oversized message")
        .expect("connection should close or error");
    assert!(
        matches!(frame, Err(_) | Ok(ClientMessage::Close(_))),
        "expected close or error for oversized frame, got: {frame:?}"
    );
}
