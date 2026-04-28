mod common;

use std::time::Duration;

use red_cell::{
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, LoginRateLimiter, MAX_AGENT_MESSAGE_LEN, MAX_DEMON_INIT_ATTEMPTS_PER_IP,
    OperatorConnectionManager, PayloadBuilderService, ShutdownController, SocketRelayManager,
    TeamserverState, build_router,
};
use red_cell_common::ExternalListenerConfig;
use red_cell_common::ListenerConfig;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, decrypt_agent_data_at_offset};
use red_cell_common::demon::{DemonCommand, DemonMessage};
use red_cell_common::operator::{AgentTaskInfo, EventCode, Message, MessageHead, OperatorMessage};
use reqwest::Client;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::connect_async;

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
    )
    .with_demon_allow_legacy_ctr(true);
    let webhooks = AuditWebhookNotifier::from_profile(&profile);
    let state = TeamserverState {
        profile: profile.clone(),
        profile_path: "test.yaotl".to_owned(),
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
        started_at: std::time::Instant::now(),
        plugins_loaded: 0,
        plugins_failed: 0,
        metrics: red_cell::metrics::standalone_metrics_handle(),
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
        rate_limiter: LoginRateLimiter::new(),
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
    let ctr_offset = 0_u64;

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
    // Legacy CTR mode: offset stays at 0.

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
    let response = client
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

    assert_eq!(
        response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "unknown agent callback probe must return 404, not 200"
    );
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

/// Happy-path task dispatch: operator queues a task via WebSocket `AgentTask` →
/// agent POSTs a `CommandGetJob` checkin → server returns encrypted-over-wire task
/// bytes → agent parses and verifies task identity matches what was queued.
#[tokio::test]
async fn external_listener_task_delivery_happy_path() -> Result<(), Box<dyn std::error::Error>> {
    let server = spawn_server_with_fallback().await?;

    let key: [u8; AGENT_KEY_LENGTH] = [
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE,
        0xBF, 0xC0,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xD1, 0xE4, 0xF7, 0x0A, 0x1D, 0x30, 0x43, 0x56, 0x69, 0x7C, 0x8F, 0xA2, 0xB5, 0xC8, 0xDB,
        0xEE,
    ];
    let agent_id = 0xC1C2_C3C4_u32;
    // The teamserver normalises agent IDs to uppercase hex in its registry, but
    // the operator protocol uses lowercase; use uppercase for WebSocket messages
    // (DemonID field) and lowercase for registry lookups.
    let agent_id_hex = format!("{agent_id:08X}");
    let ctr_offset = 0_u64;

    server.listeners.create(external_listener("ext-task-happy", "/task-happy")).await?;
    server.listeners.start("ext-task-happy").await?;
    wait_for_external_endpoint(&server, "/task-happy").await?;
    wait_for_teamserver(&server).await?;

    let client = Client::new();
    let bridge_url = format!("http://{}/task-happy", server.addr);

    // ── Agent init ───────────────────────────────────────────────────────────
    let init_resp = client
        .post(&bridge_url)
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let init_bytes = init_resp.bytes().await?;
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    // Legacy CTR mode: offset stays at 0.

    // ── Connect operator via WebSocket and login ─────────────────────────────
    let (raw_socket_, _) = connect_async(format!("ws://{}/havoc", server.addr)).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    // Consume the AgentNew event broadcast by the init above.
    let agent_new = timeout(Duration::from_secs(5), async {
        loop {
            let msg = common::read_operator_message(&mut socket).await?;
            if matches!(msg, OperatorMessage::AgentNew(_)) {
                return Ok::<_, Box<dyn std::error::Error>>(msg);
            }
        }
    })
    .await??;
    let OperatorMessage::AgentNew(new_msg) = agent_new else {
        panic!("expected AgentNew");
    };
    assert_eq!(new_msg.info.name_id, agent_id_hex);

    // ── Operator queues a checkin task via WebSocket ──────────────────────────
    let task_msg = serde_json::to_string(&OperatorMessage::AgentTask(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "operator".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: AgentTaskInfo {
            task_id: "3A".to_owned(),
            command_line: "checkin".to_owned(),
            demon_id: agent_id_hex.clone(),
            command_id: u32::from(DemonCommand::CommandCheckin).to_string(),
            ..AgentTaskInfo::default()
        },
    }))?;
    socket.send_text(task_msg).await?;

    // ── Consume the task-echo broadcast ──────────────────────────────────────
    let task_echo = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentTask(echo) = task_echo else {
        panic!("expected AgentTask echo, got {task_echo:?}");
    };
    assert_eq!(echo.info.demon_id, agent_id_hex);
    assert_eq!(echo.info.task_id, "3A");
    assert_eq!(echo.info.command_line, "checkin");

    // ── Agent polls for jobs via CommandGetJob ───────────────────────────────
    let get_job_resp = client
        .post(&bridge_url)
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            5,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    // Legacy CTR mode: offset stays at 0.
    let job_bytes = get_job_resp.bytes().await?;

    // ── Agent decrypts and verifies the task ─────────────────────────────────
    assert!(!job_bytes.is_empty(), "task response must not be empty");
    let job_msg = DemonMessage::from_bytes(job_bytes.as_ref())?;
    assert_eq!(job_msg.packages.len(), 1, "exactly one task package expected");
    assert_eq!(
        job_msg.packages[0].command_id,
        u32::from(DemonCommand::CommandCheckin),
        "task command must match queued CommandCheckin"
    );
    assert_eq!(
        job_msg.packages[0].request_id, 0x3A,
        "request_id must match task_id '3A' parsed as hex"
    );

    let _ = ctr_offset; // suppress unused warning
    socket.close(None).await?;
    server.listeners.stop("ext-task-happy").await?;
    Ok(())
}

/// No-task poll: registered agent polls when task queue is empty →
/// server returns 200 OK with empty body.
#[tokio::test]
async fn external_listener_no_task_poll_returns_empty_body()
-> Result<(), Box<dyn std::error::Error>> {
    let server = spawn_server_with_fallback().await?;

    let key: [u8; AGENT_KEY_LENGTH] = [
        0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE,
        0xDF, 0xE0,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x11, 0x24, 0x37, 0x4A, 0x5D, 0x70, 0x83, 0x96, 0xA9, 0xBC, 0xCF, 0xE2, 0xF5, 0x08, 0x1B,
        0x2E,
    ];
    let agent_id = 0xD1D2_D3D4_u32;
    let ctr_offset = 0_u64;

    server.listeners.create(external_listener("ext-empty-poll", "/empty-poll")).await?;
    server.listeners.start("ext-empty-poll").await?;
    wait_for_external_endpoint(&server, "/empty-poll").await?;
    wait_for_teamserver(&server).await?;

    let client = Client::new();
    let bridge_url = format!("http://{}/empty-poll", server.addr);

    // ── Agent init ───────────────────────────────────────────────────────────
    let init_resp = client
        .post(&bridge_url)
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let init_bytes = init_resp.bytes().await?;
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    // Legacy CTR mode: offset stays at 0.

    // ── Poll for jobs immediately — queue is empty ────────────────────────────
    let get_job_resp = client
        .post(&bridge_url)
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            1,
            &[],
        ))
        .send()
        .await?;
    let status = get_job_resp.status();
    let body = get_job_resp.bytes().await?;

    assert_eq!(status, reqwest::StatusCode::OK, "empty queue poll must return 200 OK");
    assert!(body.is_empty(), "empty queue poll must return empty body, got {} bytes", body.len());

    server.listeners.stop("ext-empty-poll").await?;
    Ok(())
}

/// Task consumption: once a task is downloaded via `CommandGetJob`, a subsequent
/// poll must not re-deliver the same task (the task must be consumed).
#[tokio::test]
async fn external_listener_task_consumed_after_download() -> Result<(), Box<dyn std::error::Error>>
{
    let server = spawn_server_with_fallback().await?;

    let key: [u8; AGENT_KEY_LENGTH] = [
        0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE,
        0xFF, 0x00,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x41, 0x54, 0x67, 0x7A, 0x8D, 0xA0, 0xB3, 0xC6, 0xD9, 0xEC, 0xFF, 0x12, 0x25, 0x38, 0x4B,
        0x5E,
    ];
    let agent_id = 0xE1E2_E3E4_u32;
    let agent_id_hex = format!("{agent_id:08x}");
    let ctr_offset = 0_u64;

    server.listeners.create(external_listener("ext-consume", "/consume")).await?;
    server.listeners.start("ext-consume").await?;
    wait_for_external_endpoint(&server, "/consume").await?;
    wait_for_teamserver(&server).await?;

    let client = Client::new();
    let bridge_url = format!("http://{}/consume", server.addr);

    // ── Agent init ───────────────────────────────────────────────────────────
    let init_resp = client
        .post(&bridge_url)
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let init_bytes = init_resp.bytes().await?;
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    // Legacy CTR mode: offset stays at 0.

    // ── Connect operator and queue a task ─────────────────────────────────────
    let (raw_socket_, _) = connect_async(format!("ws://{}/havoc", server.addr)).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    // Consume the AgentNew event (may arrive after login snapshot).
    timeout(Duration::from_secs(5), async {
        loop {
            let msg = common::read_operator_message(&mut socket).await?;
            if matches!(msg, OperatorMessage::AgentNew(_)) {
                return Ok::<_, Box<dyn std::error::Error>>(());
            }
        }
    })
    .await??;

    let task_msg = serde_json::to_string(&OperatorMessage::AgentTask(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "operator".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: AgentTaskInfo {
            task_id: "5B".to_owned(),
            command_line: "checkin".to_owned(),
            demon_id: agent_id_hex.clone(),
            command_id: u32::from(DemonCommand::CommandCheckin).to_string(),
            ..AgentTaskInfo::default()
        },
    }))?;
    socket.send_text(task_msg).await?;

    // Consume the task echo.
    let task_echo = common::read_operator_message(&mut socket).await?;
    assert!(matches!(task_echo, OperatorMessage::AgentTask(_)), "expected AgentTask echo");

    // ── First poll — must deliver the task ───────────────────────────────────
    let first_resp = client
        .post(&bridge_url)
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            5,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    // Legacy CTR mode: offset stays at 0.
    let first_bytes = first_resp.bytes().await?;
    assert!(!first_bytes.is_empty(), "first poll must deliver the queued task");
    let first_msg = DemonMessage::from_bytes(first_bytes.as_ref())?;
    assert_eq!(first_msg.packages.len(), 1, "first poll must contain exactly one task");

    // ── Second poll — task must NOT be re-delivered ──────────────────────────
    let second_resp = client
        .post(&bridge_url)
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            6,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    let second_bytes = second_resp.bytes().await?;
    assert!(
        second_bytes.is_empty(),
        "second poll must not re-deliver the consumed task; got {} bytes",
        second_bytes.len()
    );

    socket.close(None).await?;
    server.listeners.stop("ext-consume").await?;
    Ok(())
}

/// Sending a body that exceeds `MAX_AGENT_MESSAGE_LEN` to an external listener
/// bridge endpoint must be rejected — no agent should be registered.
#[tokio::test]
async fn external_listener_rejects_oversized_body() -> Result<(), Box<dyn std::error::Error>> {
    let server = spawn_server_with_fallback().await?;

    server.listeners.create(external_listener("ext-bridge-oversized", "/oversized")).await?;
    server.listeners.start("ext-bridge-oversized").await?;
    wait_for_external_endpoint(&server, "/oversized").await?;
    wait_for_teamserver(&server).await?;

    let client = Client::new();
    let bridge_url = format!("http://{}/oversized", server.addr);

    // Build a body that exceeds MAX_AGENT_MESSAGE_LEN.
    // Include valid Demon magic at bytes 4–7 so the rejection is due to size, not magic.
    let oversized_len = MAX_AGENT_MESSAGE_LEN + 1;
    let mut oversized_body = vec![0_u8; oversized_len];
    // bytes 0–3: size field (BE) — claim the rest of the packet
    let rest_len = u32::try_from(oversized_len - 4).unwrap_or(u32::MAX);
    oversized_body[0..4].copy_from_slice(&rest_len.to_be_bytes());
    // bytes 4–7: valid Demon magic (0xDEADBEEF BE)
    oversized_body[4..8].copy_from_slice(&0xDEAD_BEEF_u32.to_be_bytes());
    // bytes 8–11: fake agent_id
    oversized_body[8..12].copy_from_slice(&0xBAAD_F00D_u32.to_be_bytes());

    let response = client.post(&bridge_url).body(oversized_body).send().await?;

    // The fallback handler enforces a body size limit via `axum::body::to_bytes`;
    // exceeding it returns 400 Bad Request.
    assert!(
        response.status().is_client_error() || response.status().is_server_error(),
        "oversized body must be rejected with a 4xx/5xx status, got {}",
        response.status()
    );

    // The oversized request must not register an agent.
    assert!(
        server.agent_registry.get(0xBAAD_F00D).await.is_none(),
        "oversized body must not register an agent"
    );
    assert!(
        server.agent_registry.list_active().await.is_empty(),
        "no agent should be active after oversized body"
    );

    // Verify the listener remains responsive after the oversized request.
    let key: [u8; red_cell_common::crypto::AGENT_KEY_LENGTH] = [
        0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10,
    ];
    let iv: [u8; red_cell_common::crypto::AGENT_IV_LENGTH] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
        0x2F,
    ];
    let valid_agent_id = 0xAAAA_BBBB_u32;
    let valid_response = client
        .post(&bridge_url)
        .body(common::valid_demon_init_body(valid_agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    assert!(
        !valid_response.bytes().await?.is_empty(),
        "valid init must succeed after oversized body rejection"
    );
    assert!(
        server.agent_registry.get(valid_agent_id).await.is_some(),
        "agent must be registered — listener survived oversized body"
    );

    server.listeners.stop("ext-bridge-oversized").await?;
    Ok(())
}

/// A duplicate DEMON_INIT for an already-registered agent must not overwrite
/// the original AES key/IV — prevents MITM re-keying attacks.
#[tokio::test]
async fn external_listener_pipeline_rejects_duplicate_init_preserves_original_key()
-> Result<(), Box<dyn std::error::Error>> {
    let server = spawn_server_with_fallback().await?;
    let mut event_receiver = server.events.subscribe();

    let agent_id = 0xDEAD_0001_u32;
    let original_key: [u8; AGENT_KEY_LENGTH] = [
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E,
        0x5F, 0x60,
    ];
    let original_iv: [u8; AGENT_IV_LENGTH] = [
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
        0x33,
    ];
    let hijack_key: [u8; AGENT_KEY_LENGTH] = [
        0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9,
        0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8,
        0xD9, 0xDA,
    ];
    let hijack_iv: [u8; AGENT_IV_LENGTH] = [
        0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA,
        0xDB,
    ];

    server.listeners.create(external_listener("ext-bridge-dup-init", "/dup-init")).await?;
    server.listeners.start("ext-bridge-dup-init").await?;
    wait_for_external_endpoint(&server, "/dup-init").await?;
    wait_for_teamserver(&server).await?;

    let client = Client::new();
    let bridge_url = format!("http://{}/dup-init", server.addr);

    // ── First DEMON_INIT — must succeed ──────────────────────────────────────
    let first_resp = client
        .post(&bridge_url)
        .body(common::valid_demon_init_body(agent_id, original_key, original_iv))
        .send()
        .await?
        .error_for_status()?;
    let first_ack = first_resp.bytes().await?;
    assert!(!first_ack.is_empty(), "first init must return an ACK");

    let stored_after_first = server
        .agent_registry
        .get(agent_id)
        .await
        .ok_or("agent should be registered after first init")?;
    assert_eq!(stored_after_first.encryption.aes_key.as_slice(), &original_key);
    assert_eq!(stored_after_first.encryption.aes_iv.as_slice(), &original_iv);

    // Consume the AgentNew event from the first init.
    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    assert!(
        matches!(event, Some(OperatorMessage::AgentNew(_))),
        "expected AgentNew event for first init, got {event:?}"
    );

    // ── Second DEMON_INIT — same agent_id, different key material ────────────
    let replay_response = client
        .post(&bridge_url)
        .body(common::valid_demon_init_body(agent_id, hijack_key, hijack_iv))
        .send()
        .await?;

    assert_eq!(
        replay_response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "duplicate DEMON_INIT must be rejected with 404"
    );

    // ── Verify original key/IV are preserved ─────────────────────────────────
    let stored_after_replay = server
        .agent_registry
        .get(agent_id)
        .await
        .ok_or("agent should still be registered after rejected replay")?;
    assert_eq!(
        stored_after_replay.encryption.aes_key.as_slice(),
        &original_key,
        "original AES key must not be overwritten by duplicate init"
    );
    assert_eq!(
        stored_after_replay.encryption.aes_iv.as_slice(),
        &original_iv,
        "original AES IV must not be overwritten by duplicate init"
    );

    // ── No duplicate registration ────────────────────────────────────────────
    let active = server.agent_registry.list_active().await;
    assert_eq!(active.len(), 1, "duplicate DEMON_INIT must not create a second registry entry");
    assert_eq!(active[0].agent_id, agent_id);

    // ── No second AgentNew event ─────────────────────────────────────────────
    // Give a brief window for any spurious event to arrive, then assert none did.
    let spurious = timeout(Duration::from_millis(250), event_receiver.recv()).await;
    assert!(spurious.is_err(), "duplicate DEMON_INIT must not broadcast a second AgentNew event");

    server.listeners.stop("ext-bridge-dup-init").await?;
    Ok(())
}

/// Registering two external listeners on the same endpoint path must fail —
/// the second `create()` call should return a `DuplicateEndpoint` error.
#[tokio::test]
async fn external_listener_pipeline_rejects_duplicate_endpoint_path()
-> Result<(), Box<dyn std::error::Error>> {
    let server = spawn_server_with_fallback().await?;

    // Register and start listener A on `/shared`.
    server.listeners.create(external_listener("ext-shared-a", "/shared")).await?;
    server.listeners.start("ext-shared-a").await?;
    wait_for_external_endpoint(&server, "/shared").await?;
    wait_for_teamserver(&server).await?;

    // Attempt to register listener B on the same `/shared` path — must fail.
    let result = server.listeners.create(external_listener("ext-shared-b", "/shared")).await;
    assert!(result.is_err(), "duplicate endpoint path must be rejected");
    let err_msg = result.expect_err("expected Err").to_string();
    assert!(
        err_msg.contains("/shared"),
        "error must mention the conflicting endpoint path, got: {err_msg}"
    );
    assert!(
        err_msg.contains("ext-shared-a"),
        "error must mention the existing listener name, got: {err_msg}"
    );

    // Verify the original listener still works: send an init and confirm registration.
    let client = Client::new();
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E,
        0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
        0xAE, 0xAF,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x84, 0x97, 0xAA, 0xBD, 0xD0, 0xE3, 0xF6, 0x09, 0x1C, 0x2F, 0x42, 0x55, 0x68, 0x7B, 0x8E,
        0xA1,
    ];
    let agent_id = 0xF1F2_F3F4_u32;
    let bridge_url = format!("http://{}/shared", server.addr);
    let init_resp = client
        .post(&bridge_url)
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    assert!(!init_resp.bytes().await?.is_empty(), "init must succeed on original listener");

    assert!(
        server.agent_registry.get(agent_id).await.is_some(),
        "agent must be registered — original listener still owns the endpoint"
    );

    server.listeners.stop("ext-shared-a").await?;
    Ok(())
}

/// A `DEMON_INIT` that exceeds the per-IP cap must be rejected (rate limited),
/// matching the behaviour enforced by HTTP, SMB, and DNS listeners.
#[tokio::test]
async fn external_listener_pipeline_rejects_demon_init_after_per_ip_cap()
-> Result<(), Box<dyn std::error::Error>> {
    let server = spawn_server_with_fallback().await?;

    server.listeners.create(external_listener("ext-rate-limit", "/rate-limit")).await?;
    server.listeners.start("ext-rate-limit").await?;
    wait_for_external_endpoint(&server, "/rate-limit").await?;
    wait_for_teamserver(&server).await?;

    let client = Client::new();
    let bridge_url = format!("http://{}/rate-limit", server.addr);

    let key: [u8; AGENT_KEY_LENGTH] = [
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE,
        0xBF, 0xC0,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
        0xE0,
    ];

    // Send up to the cap of successful DEMON_INIT requests (each with a unique agent_id).
    for attempt in 0..MAX_DEMON_INIT_ATTEMPTS_PER_IP {
        let agent_id = 0xAA00_0000 + attempt;
        let response = client
            .post(&bridge_url)
            .body(common::valid_demon_init_body(agent_id, key, iv))
            .send()
            .await?;
        assert!(
            response.status().is_success(),
            "init attempt {attempt} should succeed, got {}",
            response.status()
        );
        assert!(
            server.agent_registry.get(agent_id).await.is_some(),
            "agent {agent_id:#010X} must be registered after init"
        );
    }

    // The next DEMON_INIT from the same IP must be rejected.
    let blocked_agent_id = 0xAA00_00FF_u32;
    let blocked = client
        .post(&bridge_url)
        .body(common::valid_demon_init_body(blocked_agent_id, key, iv))
        .send()
        .await?;
    assert_eq!(
        blocked.status(),
        reqwest::StatusCode::NOT_FOUND,
        "DEMON_INIT from same IP after per-IP cap must be rate-limited"
    );
    assert!(
        server.agent_registry.get(blocked_agent_id).await.is_none(),
        "blocked agent must not be registered"
    );

    server.listeners.stop("ext-rate-limit").await?;
    Ok(())
}

/// Unknown reconnect probes (DEMON_INIT with empty payload from an agent-ID that is not
/// registered) must receive a camouflage 404, not a 200.
///
/// This regression test guards against the bug where `handle_external_request` discarded
/// `ProcessedDemonResponse::http_disposition` and blindly returned `Ok(payload)`, causing
/// the Axum fallback to emit HTTP 200 for every `Fake404`-tagged response.
#[tokio::test]
async fn external_listener_unknown_reconnect_probe_returns_404()
-> Result<(), Box<dyn std::error::Error>> {
    let server = spawn_server_with_fallback().await?;

    server.listeners.create(external_listener("ext-reconnect-probe", "/reconnect-probe")).await?;
    server.listeners.start("ext-reconnect-probe").await?;
    wait_for_external_endpoint(&server, "/reconnect-probe").await?;
    wait_for_teamserver(&server).await?;

    let client = Client::new();

    // Send a reconnect probe for an agent that was never registered.
    let response = client
        .post(format!("http://{}/reconnect-probe", server.addr))
        .body(common::valid_demon_reconnect_body(0xDEAD_1234))
        .send()
        .await?;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "unknown reconnect probe must return 404 (Fake404 disposition), not 200"
    );
    assert!(
        server.agent_registry.get(0xDEAD_1234).await.is_none(),
        "reconnect probe from unknown agent must not create registry state"
    );

    server.listeners.stop("ext-reconnect-probe").await?;
    Ok(())
}

/// Unknown callback probes (callback from an agent-ID that is not registered) must receive
/// a camouflage 404, not a 200.
///
/// This is the callback-probe counterpart to `external_listener_unknown_reconnect_probe_returns_404`.
#[tokio::test]
async fn external_listener_unknown_callback_probe_returns_404()
-> Result<(), Box<dyn std::error::Error>> {
    let server = spawn_server_with_fallback().await?;

    server.listeners.create(external_listener("ext-callback-probe", "/callback-probe")).await?;
    server.listeners.start("ext-callback-probe").await?;
    wait_for_external_endpoint(&server, "/callback-probe").await?;
    wait_for_teamserver(&server).await?;

    let client = Client::new();
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D,
        0x2E, 0x2F,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x30, 0x43, 0x56, 0x69, 0x7C, 0x8F, 0xA2, 0xB5, 0xC8, 0xDB, 0xEE, 0x01, 0x14, 0x27, 0x3A,
        0x4D,
    ];

    // Send a callback for an agent that was never registered.
    let response = client
        .post(format!("http://{}/callback-probe", server.addr))
        .body(common::valid_demon_callback_body(
            0xDEAD_5678,
            key,
            iv,
            0,
            u32::from(DemonCommand::CommandCheckin),
            6,
            &[],
        ))
        .send()
        .await?;

    assert_eq!(
        response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "unknown callback probe must return 404 (Fake404 disposition), not 200"
    );
    assert!(
        server.agent_registry.get(0xDEAD_5678).await.is_none(),
        "callback probe from unknown agent must not create registry state"
    );

    server.listeners.stop("ext-callback-probe").await?;
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
