mod common;

use red_cell::{
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, LoginRateLimiter, OperatorConnectionManager, PayloadBuilderService,
    SocketRelayManager, TeamserverState, websocket_routes,
};
use red_cell_common::HttpListenerConfig;
use red_cell_common::config::Profile;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len};
use red_cell_common::demon::{DemonCommand, DemonInfoClass};
use red_cell_common::operator::OperatorMessage;
use tokio::net::TcpListener;
use tokio_tungstenite::connect_async;

// ── shared profile ───────────────────────────────────────────────────────────

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

async fn start_server()
-> Result<(std::net::SocketAddr, ListenerManager), Box<dyn std::error::Error>> {
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
        agent_registry: registry.clone(),
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

    Ok((addr, listeners))
}

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

// ── payload builders ─────────────────────────────────────────────────────────

/// Build a `CommandExit` payload: exit_method as LE u32.
fn exit_payload(exit_method: u32) -> Vec<u8> {
    exit_method.to_le_bytes().to_vec()
}

/// Build a `DemonInfo/MemAlloc` payload: info_class(10) + pointer(u64) + size(u32) + prot(u32).
fn demon_info_mem_alloc_payload(pointer: u64, size: u32, protection: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonInfoClass::MemAlloc).to_le_bytes());
    p.extend_from_slice(&pointer.to_le_bytes());
    p.extend_from_slice(&size.to_le_bytes());
    p.extend_from_slice(&protection.to_le_bytes());
    p
}

/// Build a truncated `DemonInfo/MemAlloc` payload: only the info_class, no pointer/size/prot.
fn demon_info_truncated_payload() -> Vec<u8> {
    u32::from(DemonInfoClass::MemAlloc).to_le_bytes().to_vec()
}

/// Build a `CommandJob/List` payload with the given jobs (id, type, state).
fn job_list_payload(jobs: &[(u32, u32, u32)]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&1u32.to_le_bytes()); // DemonJobCommand::List = 1
    for &(job_id, job_type, state) in jobs {
        p.extend_from_slice(&job_id.to_le_bytes());
        p.extend_from_slice(&job_type.to_le_bytes());
        p.extend_from_slice(&state.to_le_bytes());
    }
    p
}

// ── tests ────────────────────────────────────────────────────────────────────

/// `mark_agent_dead_and_broadcast` (called via CommandExit callback) must mark the agent
/// dead in the registry, broadcast an `AgentUpdate` with `Marked="Dead"`, and broadcast
/// an `AgentResponse` carrying the exit message — in that order.
#[tokio::test]
async fn exit_callback_marks_agent_dead_and_broadcasts_update()
-> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners
        .create(red_cell_common::ListenerConfig::from(HttpListenerConfig {
            name: "out-exit-test".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["127.0.0.1".to_owned()],
            host_bind: "127.0.0.1".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: listener_port,
            port_conn: Some(listener_port),
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
        }))
        .await?;
    drop(listener_guard);
    listeners.start("out-exit-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0001_u32;
    let key = [0x01; AGENT_KEY_LENGTH];
    let iv = [0x02; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    // Consume the AgentNew broadcast from registration.
    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(
        matches!(agent_new, OperatorMessage::AgentNew(_)),
        "expected AgentNew, got {agent_new:?}"
    );

    // Send a CommandExit callback (exit_method=1 → thread exit).
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandExit),
            0x01,
            &exit_payload(1),
        ))
        .send()
        .await?
        .error_for_status()?;

    // First broadcast: AgentUpdate with Marked="Dead".
    let update_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentUpdate(update_msg) = update_event else {
        panic!("expected AgentUpdate after exit callback, got {update_event:?}");
    };
    assert_eq!(
        update_msg.info.agent_id,
        format!("{agent_id:08X}"),
        "AgentUpdate agent_id mismatch"
    );
    assert_eq!(update_msg.info.marked, "Dead", "agent should be marked Dead after exit callback");

    // Second broadcast: AgentResponse carrying the exit message.
    let response_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(response_msg) = response_event else {
        panic!("expected AgentResponse after exit callback, got {response_event:?}");
    };
    assert_eq!(response_msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(response_msg.info.command_id, u32::from(DemonCommand::CommandExit).to_string());
    assert_eq!(response_msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    assert!(
        response_msg
            .info
            .extra
            .get("Message")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .contains("exit"),
        "exit message should mention 'exit': {:?}",
        response_msg.info.extra.get("Message")
    );

    socket.close(None).await?;
    listeners.stop("out-exit-test").await?;
    Ok(())
}

/// `handle_demon_info_callback` with a `MemAlloc` payload must broadcast an `AgentResponse`
/// containing the pointer, size, and memory protection to the operator.
#[tokio::test]
async fn demon_info_mem_alloc_broadcasts_response() -> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners
        .create(red_cell_common::ListenerConfig::from(HttpListenerConfig {
            name: "out-info-test".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["127.0.0.1".to_owned()],
            host_bind: "127.0.0.1".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: listener_port,
            port_conn: Some(listener_port),
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
        }))
        .await?;
    drop(listener_guard);
    listeners.start("out-info-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0002_u32;
    let key = [0x03; AGENT_KEY_LENGTH];
    let iv = [0x04; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let pointer: u64 = 0x1122_3344_5566_7788;
    let size: u32 = 4096;
    let protection: u32 = 0x20; // PAGE_EXECUTE_READ
    let payload = demon_info_mem_alloc_payload(pointer, size, protection);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::DemonInfo),
            0x10,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for DemonInfo, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::DemonInfo).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Info"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains(&format!("{pointer:x}")),
        "response message should contain pointer {pointer:#x}: {message:?}"
    );
    assert!(
        message.contains(&size.to_string()),
        "response message should contain size {size}: {message:?}"
    );

    socket.close(None).await?;
    listeners.stop("out-info-test").await?;
    Ok(())
}

/// `handle_job_callback` with a `List` subcommand and two jobs must broadcast an
/// `AgentResponse` to the operator whose output contains formatted rows for both jobs.
#[tokio::test]
async fn job_list_callback_broadcasts_formatted_table() -> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners
        .create(red_cell_common::ListenerConfig::from(HttpListenerConfig {
            name: "out-job-test".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["127.0.0.1".to_owned()],
            host_bind: "127.0.0.1".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: listener_port,
            port_conn: Some(listener_port),
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
        }))
        .await?;
    drop(listener_guard);
    listeners.start("out-job-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0003_u32;
    let key = [0x05; AGENT_KEY_LENGTH];
    let iv = [0x06; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Two jobs: (id=1, type=0, state=0) and (id=2, type=1, state=1)
    let jobs = [(1u32, 0u32, 0u32), (2u32, 1u32, 1u32)];
    let payload = job_list_payload(&jobs);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandJob),
            0x20,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for CommandJob, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandJob).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Info"));

    // Output should contain a row for each job ID.
    let output = &msg.info.output;
    assert!(output.contains('1'), "output should contain job id 1: {output:?}");
    assert!(output.contains('2'), "output should contain job id 2: {output:?}");
    assert!(output.contains("Job ID"), "output should contain header row: {output:?}");

    socket.close(None).await?;
    listeners.stop("out-job-test").await?;
    Ok(())
}

/// `handle_demon_info_callback` with a truncated payload (info_class only, no class data)
/// must return an error to the HTTP caller and must NOT broadcast any `AgentResponse`.
#[tokio::test]
async fn demon_info_truncated_payload_returns_error_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners
        .create(red_cell_common::ListenerConfig::from(HttpListenerConfig {
            name: "out-trunc-test".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["127.0.0.1".to_owned()],
            host_bind: "127.0.0.1".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: listener_port,
            port_conn: Some(listener_port),
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
        }))
        .await?;
    drop(listener_guard);
    listeners.start("out-trunc-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0004_u32;
    let key = [0x07; AGENT_KEY_LENGTH];
    let iv = [0x08; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Send a DemonInfo payload that contains only the info_class (truncated — no pointer/size/prot).
    let truncated = demon_info_truncated_payload();
    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::DemonInfo),
            0x30,
            &truncated,
        ))
        .send()
        .await?;

    // The dispatch error must propagate back as a non-2xx HTTP response.
    assert!(
        !response.status().is_success(),
        "expected error HTTP status for truncated payload, got {}",
        response.status()
    );

    // No AgentResponse must have been broadcast.
    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    listeners.stop("out-trunc-test").await?;
    Ok(())
}

/// A `CommandExit` callback with an empty payload (zero bytes) must return a
/// non-2xx HTTP status and must NOT broadcast `AgentUpdate` or `AgentResponse`.
#[tokio::test]
async fn exit_callback_empty_payload_returns_error_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners
        .create(red_cell_common::ListenerConfig::from(HttpListenerConfig {
            name: "out-exit-empty-test".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["127.0.0.1".to_owned()],
            host_bind: "127.0.0.1".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: listener_port,
            port_conn: Some(listener_port),
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
        }))
        .await?;
    drop(listener_guard);
    listeners.start("out-exit-empty-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0005_u32;
    let key = [0x09; AGENT_KEY_LENGTH];
    let iv = [0x0A; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Send a CommandExit callback with zero bytes — no exit_method u32 at all.
    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandExit),
            0x40,
            &[], // empty payload
        ))
        .send()
        .await?;

    assert!(
        !response.status().is_success(),
        "empty CommandExit payload must not return 2xx, got {}",
        response.status()
    );

    // Neither AgentUpdate nor AgentResponse should be broadcast.
    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    listeners.stop("out-exit-empty-test").await?;
    Ok(())
}

/// A `CommandExit` callback with fewer than four bytes (truncated exit_method)
/// must return a non-2xx HTTP status and must NOT broadcast any events.
#[tokio::test]
async fn exit_callback_truncated_exit_method_returns_error_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners
        .create(red_cell_common::ListenerConfig::from(HttpListenerConfig {
            name: "out-exit-short-test".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["127.0.0.1".to_owned()],
            host_bind: "127.0.0.1".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: listener_port,
            port_conn: Some(listener_port),
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
        }))
        .await?;
    drop(listener_guard);
    listeners.start("out-exit-short-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0006_u32;
    let key = [0x0B; AGENT_KEY_LENGTH];
    let iv = [0x0C; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Send a CommandExit callback with only 2 bytes — too short for a u32 exit_method.
    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandExit),
            0x41,
            &[0x01, 0x00], // only 2 bytes, need 4
        ))
        .send()
        .await?;

    assert!(
        !response.status().is_success(),
        "truncated CommandExit payload must not return 2xx, got {}",
        response.status()
    );

    // Neither AgentUpdate nor AgentResponse should be broadcast.
    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    listeners.stop("out-exit-short-test").await?;
    Ok(())
}
