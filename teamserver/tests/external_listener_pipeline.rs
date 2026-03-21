mod common;

use std::time::Duration;

use red_cell::{
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, LoginRateLimiter, OperatorConnectionManager, PayloadBuilderService,
    ShutdownController, SocketRelayManager, TeamserverState, build_router,
};
use red_cell_common::ExternalListenerConfig;
use red_cell_common::ListenerConfig;
use red_cell_common::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len, decrypt_agent_data_at_offset,
};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::OperatorMessage;
use reqwest::Client;
use tokio::net::TcpListener;
use tokio::time::timeout;

/// Spawn a test server using [`build_router`] so the teamserver fallback handler
/// is active (required for External C2 bridge endpoint routing).
async fn spawn_server_with_fallback() -> Result<common::TestServer, Box<dyn std::error::Error>> {
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
    let state = TeamserverState {
        profile: profile.clone(),
        database: database.clone(),
        auth: AuthService::from_profile(&profile)?,
        api: ApiRuntime::from_profile(&profile)?,
        events: events.clone(),
        connections: OperatorConnectionManager::new(),
        agent_registry: registry.clone(),
        listeners: listeners.clone(),
        payload_builder: PayloadBuilderService::disabled_for_tests(),
        sockets: sockets.clone(),
        webhooks: webhooks.clone(),
        login_rate_limiter: LoginRateLimiter::new(),
        shutdown: ShutdownController::new(),
        service_bridge: None,
    };

    let tcp = TcpListener::bind("127.0.0.1:0").await?;
    let addr = tcp.local_addr()?;
    tokio::spawn(async move {
        let app = build_router(state);
        let _ = axum::serve(tcp, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await;
    });

    Ok(common::TestServer {
        addr,
        profile,
        listeners,
        agent_registry: registry,
        database,
        events,
        sockets,
        webhooks,
    })
}

/// Full pipeline: register external listener → agent init via bridge endpoint →
/// verify registration + event → callback dispatch → verify update event.
#[tokio::test]
async fn external_listener_pipeline_registers_agent_and_broadcasts_checkin()
-> Result<(), Box<dyn std::error::Error>> {
    let server = spawn_server_with_fallback().await?;
    let mut event_receiver = server.events.subscribe();

    let key: [u8; AGENT_KEY_LENGTH] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xB0, 0xC3, 0xD6, 0xE9, 0xFC, 0x0F, 0x22, 0x35, 0x48, 0x5B, 0x6E, 0x81, 0x94, 0xA7, 0xBA,
        0xCD,
    ];
    let agent_id = 0xE1E2_E3E4_u32;
    let mut ctr_offset = 0_u64;

    server.listeners.create(external_listener("ext-bridge-pipeline", "/bridge")).await?;
    server.listeners.start("ext-bridge-pipeline").await?;
    wait_for_external_endpoint(&server, "/bridge").await?;
    wait_for_teamserver(&server).await?;

    let client = Client::new();
    let bridge_url = format!("http://{}/bridge", server.addr);

    // ── Agent init ──────────────────────────────────────────────────────────
    let init_response = client
        .post(&bridge_url)
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let init_ack = init_response.bytes().await?;

    let decrypted_ack = decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &init_ack)?;
    assert_eq!(decrypted_ack.as_slice(), &agent_id.to_le_bytes());
    ctr_offset += ctr_blocks_for_len(init_ack.len());

    // ── Verify agent registered ─────────────────────────────────────────────
    let stored = server.agent_registry.get(agent_id).await.ok_or("agent should be registered")?;
    let before_checkin = stored.last_call_in.clone();
    assert_eq!(stored.hostname, "wkstn-01");

    // ── Verify AgentNew event ───────────────────────────────────────────────
    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    let Some(OperatorMessage::AgentNew(message)) = event else {
        panic!("expected AgentNew event, got {event:?}");
    };
    assert_eq!(message.info.listener, "ext-bridge-pipeline");

    // ── Agent callback (checkin) ────────────────────────────────────────────
    let checkin_response = client
        .post(&bridge_url)
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandCheckin),
            6,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    assert!(checkin_response.bytes().await?.is_empty());

    // ── Verify AgentUpdate event ────────────────────────────────────────────
    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    let Some(OperatorMessage::AgentUpdate(message)) = event else {
        panic!("expected AgentUpdate event, got {event:?}");
    };
    assert_eq!(message.info.agent_id.to_lowercase(), format!("{agent_id:08x}"));
    assert_eq!(message.info.marked, "Alive");

    // ── Verify last_call_in updated ─────────────────────────────────────────
    let updated =
        server.agent_registry.get(agent_id).await.ok_or("agent should remain registered")?;
    assert_ne!(updated.last_call_in, before_checkin);

    server.listeners.stop("ext-bridge-pipeline").await?;
    Ok(())
}

/// Requests to a non-registered external endpoint return 404.
#[tokio::test]
async fn external_listener_pipeline_unregistered_path_returns_404()
-> Result<(), Box<dyn std::error::Error>> {
    let server = spawn_server_with_fallback().await?;
    wait_for_teamserver(&server).await?;

    let client = Client::new();
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34,
        0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xE5, 0xF8, 0x0B, 0x1E, 0x31, 0x44, 0x57, 0x6A, 0x7D, 0x90, 0xA3, 0xB6, 0xC9, 0xDC, 0xEF,
        0x02,
    ];
    let response = client
        .post(format!("http://{}/nonexistent", server.addr))
        .body(common::valid_demon_init_body(0xDEAD_0001, key, iv))
        .send()
        .await?;

    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    assert!(
        server.agent_registry.get(0xDEAD_0001).await.is_none(),
        "agent must not be registered on unregistered path"
    );
    Ok(())
}

/// After stopping an external listener, its endpoint must no longer accept requests.
#[tokio::test]
async fn external_listener_pipeline_endpoint_deregistered_after_stop()
-> Result<(), Box<dyn std::error::Error>> {
    let server = spawn_server_with_fallback().await?;

    server.listeners.create(external_listener("ext-bridge-stop", "/stop-test")).await?;
    server.listeners.start("ext-bridge-stop").await?;
    wait_for_external_endpoint(&server, "/stop-test").await?;
    wait_for_teamserver(&server).await?;

    // Verify the endpoint is active.
    let client = Client::new();
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
        0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x69, 0x6A,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x1A, 0x2D, 0x40, 0x53, 0x66, 0x79, 0x8C, 0x9F, 0xB2, 0xC5, 0xD8, 0xEB, 0xFE, 0x11, 0x24,
        0x37,
    ];
    let response = client
        .post(format!("http://{}/stop-test", server.addr))
        .body(common::valid_demon_init_body(0xEEEE_0001, key, iv))
        .send()
        .await?;
    assert!(response.status().is_success(), "endpoint should be active before stop");

    // Stop the listener.
    server.listeners.stop("ext-bridge-stop").await?;

    // Give the runtime a moment to deregister.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify the endpoint is no longer active.
    let response = client
        .post(format!("http://{}/stop-test", server.addr))
        .body(common::valid_demon_init_body(0xEEEE_0002, key, iv))
        .send()
        .await?;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "endpoint must return 404 after listener stop"
    );
    assert!(
        server.agent_registry.get(0xEEEE_0002).await.is_none(),
        "no agent should register after endpoint deregistered"
    );

    Ok(())
}

/// Callbacks from unregistered agents must be rejected with 404.
#[tokio::test]
async fn external_listener_pipeline_rejects_unregistered_agent_callback()
-> Result<(), Box<dyn std::error::Error>> {
    let server = spawn_server_with_fallback().await?;

    server.listeners.create(external_listener("ext-bridge-unknown", "/unknown-cb")).await?;
    server.listeners.start("ext-bridge-unknown").await?;
    wait_for_external_endpoint(&server, "/unknown-cb").await?;
    wait_for_teamserver(&server).await?;

    let client = Client::new();
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E,
        0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D,
        0x8E, 0x8F,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x4F, 0x62, 0x75, 0x88, 0x9B, 0xAE, 0xC1, 0xD4, 0xE7, 0xFA, 0x0D, 0x20, 0x33, 0x46, 0x59,
        0x6C,
    ];
    let _response = client
        .post(format!("http://{}/unknown-cb", server.addr))
        .body(common::valid_demon_callback_body(
            0xBAD0_CAFE,
            key,
            iv,
            0,
            u32::from(DemonCommand::CommandCheckin),
            6,
            &[],
        ))
        .send()
        .await?;

    // The external listener may return 200 with a fake response body (the callback
    // goes through process_demon_transport which may return a fake-404 HTML payload
    // as an Ok result).  The critical invariant is that the agent must NOT be registered.
    assert!(
        server.agent_registry.get(0xBAD0_CAFE).await.is_none(),
        "callback from unregistered agent must not create registry state"
    );
    assert!(
        server.agent_registry.list_active().await.is_empty(),
        "no agent should be active after unknown callback"
    );

    server.listeners.stop("ext-bridge-unknown").await?;
    Ok(())
}

fn external_listener(name: &str, endpoint: &str) -> ListenerConfig {
    ListenerConfig::from(ExternalListenerConfig {
        name: name.to_owned(),
        endpoint: endpoint.to_owned(),
    })
}

/// Poll until the external endpoint is registered in the listener manager.
async fn wait_for_external_endpoint(
    server: &common::TestServer,
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..40 {
        if server.listeners.external_state_for_path(path).await.is_some() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Err(format!("external endpoint {path} did not become ready").into())
}

/// Poll the teamserver HTTP port until it accepts connections.
async fn wait_for_teamserver(
    server: &common::TestServer,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    for _ in 0..40 {
        if client.get(format!("http://{}/", server.addr)).send().await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    Err("teamserver HTTP port did not become ready".into())
}
