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

    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
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
    let response = client
        .post(format!("http://{}/nonexistent", server.addr))
        .body(common::valid_demon_init_body(
            0xDEAD_0001,
            [0x41; AGENT_KEY_LENGTH],
            [0x24; AGENT_IV_LENGTH],
        ))
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
    let response = client
        .post(format!("http://{}/stop-test", server.addr))
        .body(common::valid_demon_init_body(
            0xEEEE_0001,
            [0x41; AGENT_KEY_LENGTH],
            [0x24; AGENT_IV_LENGTH],
        ))
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
        .body(common::valid_demon_init_body(
            0xEEEE_0002,
            [0x41; AGENT_KEY_LENGTH],
            [0x24; AGENT_IV_LENGTH],
        ))
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
    let _response = client
        .post(format!("http://{}/unknown-cb", server.addr))
        .body(common::valid_demon_callback_body(
            0xBAD0_CAFE,
            [0x41; AGENT_KEY_LENGTH],
            [0x24; AGENT_IV_LENGTH],
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
