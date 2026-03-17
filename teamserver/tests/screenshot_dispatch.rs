//! Integration tests for `dispatch/screenshot.rs` — `handle_screenshot_callback`.
//!
//! All tests go through the full HTTP → listener → dispatch pipeline so that
//! the database write and event-bus broadcast paths are exercised end-to-end.

mod common;

use red_cell::{
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, LoginRateLimiter, OperatorConnectionManager, PayloadBuilderService,
    SocketRelayManager, TeamserverState, websocket_routes,
};
use red_cell_common::HttpListenerConfig;
use red_cell_common::config::Profile;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::OperatorMessage;
use tokio::net::TcpListener;
use tokio_tungstenite::connect_async;

// ---------------------------------------------------------------------------
// Shared profile
// ---------------------------------------------------------------------------

const PROFILE: &str = r#"
    Teamserver {
      Host = "127.0.0.1"
      Port = 0
    }

    Operators {
      user "operator" {
        Password = "password1234"
        Role = "Operator"
      }
    }

    Demon {}
"#;

// ---------------------------------------------------------------------------
// Test server helpers
// ---------------------------------------------------------------------------

/// Boot a full teamserver and return its local address, the listener manager,
/// and a clone of the in-memory database so tests can verify persisted state.
async fn start_server()
-> Result<(std::net::SocketAddr, ListenerManager, Database), Box<dyn std::error::Error>> {
    let profile = Profile::parse(PROFILE)?;
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
    let state = TeamserverState {
        profile: profile.clone(),
        database: database.clone(),
        auth: AuthService::from_profile(&profile).expect("auth service should init"),
        api: ApiRuntime::from_profile(&profile).expect("rng should work in tests"),
        events,
        connections: OperatorConnectionManager::new(),
        agent_registry: registry,
        listeners: listeners.clone(),
        payload_builder: PayloadBuilderService::disabled_for_tests(),
        sockets,
        webhooks: AuditWebhookNotifier::from_profile(&profile),
        login_rate_limiter: LoginRateLimiter::new(),
        shutdown: red_cell::ShutdownController::new(),
    };

    let tcp = TcpListener::bind("127.0.0.1:0").await?;
    let addr = tcp.local_addr()?;
    tokio::spawn(async move {
        let app = websocket_routes().with_state(state);
        let _ = axum::serve(tcp, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await;
    });

    Ok((addr, listeners, database))
}

/// Register a fresh agent via `DEMON_INIT` and return the AES-CTR offset after init.
async fn register_agent(
    client: &reqwest::Client,
    listener_port: u16,
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> Result<u64, Box<dyn std::error::Error>> {
    let resp = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let bytes = resp.bytes().await?;
    Ok(ctr_blocks_for_len(bytes.len()))
}

/// Build an HTTP listener config with the given `name` and `port`.
fn http_listener(name: &str, port: u16) -> red_cell_common::ListenerConfig {
    red_cell_common::ListenerConfig::from(HttpListenerConfig {
        name: name.to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["127.0.0.1".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: port,
        port_conn: Some(port),
        method: Some("POST".to_owned()),
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
    })
}

// ---------------------------------------------------------------------------
// Payload builders
// ---------------------------------------------------------------------------

/// Build a `CommandScreenshot` callback payload with `success=1` and the given image bytes.
fn screenshot_success_payload(image_bytes: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&1_u32.to_le_bytes()); // success = 1
    p.extend_from_slice(&(image_bytes.len() as u32).to_le_bytes());
    p.extend_from_slice(image_bytes);
    p
}

/// Build a `CommandScreenshot` callback payload with `success=0`.
fn screenshot_failure_payload() -> Vec<u8> {
    0_u32.to_le_bytes().to_vec()
}

/// Build a `CommandScreenshot` callback payload with `success=1` but zero-length bytes.
fn screenshot_empty_bytes_payload() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&1_u32.to_le_bytes()); // success = 1
    p.extend_from_slice(&0_u32.to_le_bytes()); // length = 0
    p
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A screenshot callback carrying valid PNG bytes must:
///   1. Store a loot record in the database with `kind = "screenshot"` and
///      the raw image bytes as `data`.
///   2. Broadcast a loot-new `AgentResponse` event with `MiscType = "loot-new"`.
///   3. Broadcast a screenshot download-complete `AgentResponse` with
///      `MiscType = "screenshot"` and `Type = "Good"`.
#[tokio::test]
async fn screenshot_callback_stores_loot_and_broadcasts_events()
-> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners, database) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(http_listener("screenshot-success-test", listener_port)).await?;
    drop(listener_guard);
    listeners.start("screenshot-success-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xFB01_0001_u32;
    let key = [0xAA; AGENT_KEY_LENGTH];
    let iv = [0xBB; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    // Consume the AgentNew broadcast from registration.
    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(
        matches!(agent_new, OperatorMessage::AgentNew(_)),
        "expected AgentNew, got {agent_new:?}"
    );

    // Minimal valid PNG header as test image data.
    let png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    let payload = screenshot_success_payload(&png);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandScreenshot),
            0x01,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // First broadcast: loot-new event.
    let loot_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(loot_msg) = loot_event else {
        panic!("expected AgentResponse (loot-new), got {loot_event:?}");
    };
    assert_eq!(
        loot_msg.info.extra.get("MiscType").and_then(|v| v.as_str()),
        Some("loot-new"),
        "loot event must have MiscType=loot-new"
    );

    // Second broadcast: screenshot download-complete response.
    let resp_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(resp_msg) = resp_event else {
        panic!("expected AgentResponse (screenshot), got {resp_event:?}");
    };
    assert_eq!(resp_msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(resp_msg.info.command_id, u32::from(DemonCommand::CommandScreenshot).to_string());
    assert_eq!(
        resp_msg.info.extra.get("MiscType").and_then(|v| v.as_str()),
        Some("screenshot"),
        "screenshot response must have MiscType=screenshot"
    );
    assert_eq!(
        resp_msg.info.extra.get("Type").and_then(|v| v.as_str()),
        Some("Good"),
        "screenshot response must have Type=Good"
    );

    // Verify loot record is persisted in the database.
    let loot_records = database.loot().list_for_agent(agent_id).await?;
    assert_eq!(loot_records.len(), 1, "exactly one loot record must be stored");
    assert_eq!(loot_records[0].kind, "screenshot", "loot kind must be 'screenshot'");
    assert_eq!(loot_records[0].agent_id, agent_id);
    assert_eq!(
        loot_records[0].data.as_deref(),
        Some(png.as_slice()),
        "loot data must contain the raw image bytes"
    );

    socket.close(None).await?;
    listeners.stop("screenshot-success-test").await?;
    Ok(())
}

/// A screenshot callback with `success=0` must broadcast an error `AgentResponse`
/// and must NOT create any loot record in the database.
#[tokio::test]
async fn screenshot_callback_failure_broadcasts_error_no_loot()
-> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners, database) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(http_listener("screenshot-fail-test", listener_port)).await?;
    drop(listener_guard);
    listeners.start("screenshot-fail-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xFB01_0002_u32;
    let key = [0xCC; AGENT_KEY_LENGTH];
    let iv = [0xDD; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandScreenshot),
            0x02,
            &screenshot_failure_payload(),
        ))
        .send()
        .await?
        .error_for_status()?;

    // Must receive an error broadcast.
    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(
        msg.info.extra.get("Type").and_then(|v| v.as_str()),
        Some("Error"),
        "failed screenshot must broadcast Type=Error"
    );

    // No loot record should be stored.
    let loot_records = database.loot().list_for_agent(agent_id).await?;
    assert!(loot_records.is_empty(), "no loot must be stored for a failed screenshot");

    socket.close(None).await?;
    listeners.stop("screenshot-fail-test").await?;
    Ok(())
}

/// A screenshot callback with `success=1` but zero-length image data must broadcast
/// an error `AgentResponse` without panicking and must NOT create any loot record.
#[tokio::test]
async fn screenshot_callback_empty_bytes_broadcasts_error_no_loot()
-> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners, database) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(http_listener("screenshot-empty-test", listener_port)).await?;
    drop(listener_guard);
    listeners.start("screenshot-empty-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xFB01_0003_u32;
    let key = [0xEE; AGENT_KEY_LENGTH];
    let iv = [0xFF; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandScreenshot),
            0x03,
            &screenshot_empty_bytes_payload(),
        ))
        .send()
        .await?
        .error_for_status()?;

    // Must receive an error broadcast — no panic.
    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(
        msg.info.extra.get("Type").and_then(|v| v.as_str()),
        Some("Error"),
        "empty-bytes screenshot must broadcast Type=Error"
    );

    // No loot record should be stored.
    let loot_records = database.loot().list_for_agent(agent_id).await?;
    assert!(loot_records.is_empty(), "no loot must be stored for empty screenshot bytes");

    socket.close(None).await?;
    listeners.stop("screenshot-empty-test").await?;
    Ok(())
}
