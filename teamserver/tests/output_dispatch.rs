mod common;

use red_cell::{
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, LoginRateLimiter, OperatorConnectionManager, PayloadBuilderService,
    SocketRelayManager, TeamserverState, websocket_routes,
};
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

/// Build a `DemonInfo/MemExec` payload: info_class(11) + function(u64) + thread_id(u32).
fn demon_info_mem_exec_payload(function: u64, thread_id: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonInfoClass::MemExec).to_le_bytes());
    p.extend_from_slice(&function.to_le_bytes());
    p.extend_from_slice(&thread_id.to_le_bytes());
    p
}

/// Build a `DemonInfo/MemProtect` payload: info_class(12) + memory(u64) + size(u32) + old(u32) + new(u32).
fn demon_info_mem_protect_payload(memory: u64, size: u32, old: u32, new: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonInfoClass::MemProtect).to_le_bytes());
    p.extend_from_slice(&memory.to_le_bytes());
    p.extend_from_slice(&size.to_le_bytes());
    p.extend_from_slice(&old.to_le_bytes());
    p.extend_from_slice(&new.to_le_bytes());
    p
}

/// Build a `DemonInfo/ProcCreate` payload: info_class(21) + utf16_path + pid(u32) + success(u32) + piped(u32) + verbose(u32).
fn demon_info_proc_create_payload(
    path: &str,
    pid: u32,
    success: bool,
    piped: bool,
    verbose: bool,
) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonInfoClass::ProcCreate).to_le_bytes());
    // UTF-16LE path, length-prefixed with u32 byte count
    let utf16: Vec<u16> = path.encode_utf16().collect();
    let byte_len = (utf16.len() * 2) as u32;
    p.extend_from_slice(&byte_len.to_le_bytes());
    for word in &utf16 {
        p.extend_from_slice(&word.to_le_bytes());
    }
    p.extend_from_slice(&pid.to_le_bytes());
    p.extend_from_slice(&u32::from(success).to_le_bytes());
    p.extend_from_slice(&u32::from(piped).to_le_bytes());
    p.extend_from_slice(&u32::from(verbose).to_le_bytes());
    p
}

/// Build a `DemonInfo` payload with an unknown info class value.
fn demon_info_unknown_class_payload(class: u32) -> Vec<u8> {
    class.to_le_bytes().to_vec()
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

/// Build a `CommandJob` action payload (Suspend/Resume/KillRemove).
/// `subcommand` is the `DemonJobCommand` discriminant (2, 3, or 4).
fn job_action_payload(subcommand: u32, job_id: u32, success: bool) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&subcommand.to_le_bytes());
    p.extend_from_slice(&job_id.to_le_bytes());
    p.extend_from_slice(&u32::from(success).to_le_bytes());
    p
}

/// Build a `CommandJob/Died` payload — subcommand only, no additional fields.
fn job_died_payload() -> Vec<u8> {
    5u32.to_le_bytes().to_vec() // DemonJobCommand::Died = 5
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

    listeners.create(common::http_listener_config("out-exit-test", listener_port)).await?;
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

    listeners.create(common::http_listener_config("out-info-test", listener_port)).await?;
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

    listeners.create(common::http_listener_config("out-job-test", listener_port)).await?;
    drop(listener_guard);
    listeners.start("out-job-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0003_u32;
    let key = [0x05; AGENT_KEY_LENGTH];
    let iv = [0x06; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Two jobs with distinct type/state combos so labels are unambiguous:
    //   id=10, type=2 (Process),       state=3 (Dead)
    //   id=42, type=3 (Track Process), state=2 (Suspended)
    let jobs = [(10u32, 2u32, 3u32), (42u32, 3u32, 2u32)];
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

    let output = &msg.info.output;

    // Verify the header and separator are present.
    assert!(output.contains("Job ID"), "output should contain header row: {output:?}");
    assert!(output.contains("Type"), "output should contain Type column header: {output:?}");
    assert!(output.contains("State"), "output should contain State column header: {output:?}");
    assert!(output.contains("------"), "output should contain separator row: {output:?}");

    // Normalize output lines for row-level assertions.
    let lines: Vec<String> =
        output.lines().map(|l| l.split_whitespace().collect::<Vec<_>>().join(" ")).collect();

    // Row for job 10: type=2 → "Process", state=3 → "Dead"
    assert!(
        lines.iter().any(|l| l.contains("10") && l.contains("Process") && l.contains("Dead")),
        "expected row with job 10, type Process, state Dead in output:\n{output}"
    );

    // Row for job 42: type=3 → "Track Process", state=2 → "Suspended"
    assert!(
        lines
            .iter()
            .any(|l| l.contains("42") && l.contains("Track Process") && l.contains("Suspended")),
        "expected row with job 42, type Track Process, state Suspended in output:\n{output}"
    );

    // Verify exactly two data rows (not counting header/separator).
    let data_rows: Vec<_> = lines
        .iter()
        .filter(|l| !l.is_empty() && !l.contains("Job ID") && !l.contains("------"))
        .collect();
    assert_eq!(
        data_rows.len(),
        2,
        "expected exactly 2 data rows, got {}: {data_rows:?}",
        data_rows.len()
    );

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

    listeners.create(common::http_listener_config("out-trunc-test", listener_port)).await?;
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

    listeners.create(common::http_listener_config("out-exit-empty-test", listener_port)).await?;
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

    listeners.create(common::http_listener_config("out-exit-short-test", listener_port)).await?;
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

/// `handle_demon_info_callback` with a `MemExec` payload must broadcast an `AgentResponse`
/// containing the function pointer and thread ID.
#[tokio::test]
async fn demon_info_mem_exec_broadcasts_response() -> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("out-mexec-test", listener_port)).await?;
    drop(listener_guard);
    listeners.start("out-mexec-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0010_u32;
    let key = [0x11; AGENT_KEY_LENGTH];
    let iv = [0x12; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let function: u64 = 0xAABB_CCDD_EEFF_0011;
    let thread_id: u32 = 42;
    let payload = demon_info_mem_exec_payload(function, thread_id);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::DemonInfo),
            0x50,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for DemonInfo/MemExec, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::DemonInfo).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Info"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains(&format!("{function:x}")),
        "response should contain function pointer {function:#x}: {message:?}"
    );
    assert!(
        message.contains(&thread_id.to_string()),
        "response should contain thread id {thread_id}: {message:?}"
    );
    assert!(
        message.contains("Memory Executed"),
        "response should contain 'Memory Executed': {message:?}"
    );

    socket.close(None).await?;
    listeners.stop("out-mexec-test").await?;
    Ok(())
}

/// `handle_demon_info_callback` with a `MemProtect` payload must broadcast an `AgentResponse`
/// containing the memory address, size, and old/new protection values.
#[tokio::test]
async fn demon_info_mem_protect_broadcasts_response() -> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("out-mprot-test", listener_port)).await?;
    drop(listener_guard);
    listeners.start("out-mprot-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0011_u32;
    let key = [0x13; AGENT_KEY_LENGTH];
    let iv = [0x14; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let memory: u64 = 0x7FFE_0000_1000;
    let size: u32 = 8192;
    let old_prot: u32 = 0x04; // PAGE_READWRITE
    let new_prot: u32 = 0x20; // PAGE_EXECUTE_READ
    let payload = demon_info_mem_protect_payload(memory, size, old_prot, new_prot);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::DemonInfo),
            0x51,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for DemonInfo/MemProtect, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::DemonInfo).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Info"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains(&format!("{memory:x}")),
        "response should contain memory address {memory:#x}: {message:?}"
    );
    assert!(
        message.contains(&size.to_string()),
        "response should contain size {size}: {message:?}"
    );
    assert!(
        message.contains("PAGE_READWRITE"),
        "response should contain old protection PAGE_READWRITE: {message:?}"
    );
    assert!(
        message.contains("PAGE_EXECUTE_READ"),
        "response should contain new protection PAGE_EXECUTE_READ: {message:?}"
    );
    assert!(
        message.contains("Memory Protection"),
        "response should contain 'Memory Protection': {message:?}"
    );

    socket.close(None).await?;
    listeners.stop("out-mprot-test").await?;
    Ok(())
}

/// `handle_demon_info_callback` with `ProcCreate` and `verbose=false` must return `Ok(None)`
/// without broadcasting any `AgentResponse`.
#[tokio::test]
async fn demon_info_proc_create_non_verbose_no_broadcast() -> Result<(), Box<dyn std::error::Error>>
{
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("out-proc-nv-test", listener_port)).await?;
    drop(listener_guard);
    listeners.start("out-proc-nv-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0012_u32;
    let key = [0x15; AGENT_KEY_LENGTH];
    let iv = [0x16; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // ProcCreate with verbose=false — should silently return Ok(None).
    let payload =
        demon_info_proc_create_payload("C:\\Windows\\System32\\cmd.exe", 1234, true, true, false);

    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::DemonInfo),
            0x52,
            &payload,
        ))
        .send()
        .await?;

    // The callback should succeed (2xx) but produce no broadcast.
    assert!(
        response.status().is_success(),
        "ProcCreate non-verbose should succeed, got {}",
        response.status()
    );

    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    listeners.stop("out-proc-nv-test").await?;
    Ok(())
}

/// `handle_demon_info_callback` with an unrecognized info class value must return `Ok(None)`
/// without broadcasting any `AgentResponse`.
#[tokio::test]
async fn demon_info_unknown_class_no_broadcast() -> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("out-info-unk-test", listener_port)).await?;
    drop(listener_guard);
    listeners.start("out-info-unk-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0013_u32;
    let key = [0x17; AGENT_KEY_LENGTH];
    let iv = [0x18; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Use an info class value (0xFF) that doesn't map to any DemonInfoClass variant.
    let payload = demon_info_unknown_class_payload(0xFF);

    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::DemonInfo),
            0x53,
            &payload,
        ))
        .send()
        .await?;

    // The callback should succeed (2xx) but produce no broadcast.
    assert!(
        response.status().is_success(),
        "unknown info class should succeed silently, got {}",
        response.status()
    );

    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    listeners.stop("out-info-unk-test").await?;
    Ok(())
}

/// `handle_job_callback` with `Suspend` subcommand and `success=true` must broadcast
/// an `AgentResponse` with Type="Good" and a message mentioning "suspended".
#[tokio::test]
async fn job_suspend_success_broadcasts_good_response() -> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("out-job-susp-ok", listener_port)).await?;
    drop(listener_guard);
    listeners.start("out-job-susp-ok").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0020_u32;
    let key = [0x20; AGENT_KEY_LENGTH];
    let iv = [0x21; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = job_action_payload(2, 77, true); // Suspend=2, job_id=77, success

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandJob),
            0x60,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for job Suspend success, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandJob).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("suspended") || message.contains("Suspended"),
        "message should mention suspended: {message:?}"
    );
    assert!(message.contains("77"), "message should contain job id 77: {message:?}");

    socket.close(None).await?;
    listeners.stop("out-job-susp-ok").await?;
    Ok(())
}

/// `handle_job_callback` with `Suspend` subcommand and `success=false` must broadcast
/// an `AgentResponse` with Type="Error".
#[tokio::test]
async fn job_suspend_failure_broadcasts_error_response() -> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("out-job-susp-fail", listener_port)).await?;
    drop(listener_guard);
    listeners.start("out-job-susp-fail").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0021_u32;
    let key = [0x22; AGENT_KEY_LENGTH];
    let iv = [0x23; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = job_action_payload(2, 88, false); // Suspend=2, job_id=88, failure

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandJob),
            0x61,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for job Suspend failure, got {event:?}");
    };
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.to_lowercase().contains("suspend"),
        "message should mention suspend: {message:?}"
    );
    assert!(message.contains("88"), "message should contain job id 88: {message:?}");

    socket.close(None).await?;
    listeners.stop("out-job-susp-fail").await?;
    Ok(())
}

/// `handle_job_callback` with `Resume` subcommand and `success=true` must broadcast
/// an `AgentResponse` with Type="Good" and a message mentioning "resumed".
#[tokio::test]
async fn job_resume_success_broadcasts_good_response() -> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("out-job-res-ok", listener_port)).await?;
    drop(listener_guard);
    listeners.start("out-job-res-ok").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0022_u32;
    let key = [0x24; AGENT_KEY_LENGTH];
    let iv = [0x25; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = job_action_payload(3, 55, true); // Resume=3, job_id=55, success

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandJob),
            0x62,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for job Resume success, got {event:?}");
    };
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.to_lowercase().contains("resum"),
        "message should mention resumed: {message:?}"
    );
    assert!(message.contains("55"), "message should contain job id 55: {message:?}");

    socket.close(None).await?;
    listeners.stop("out-job-res-ok").await?;
    Ok(())
}

/// `handle_job_callback` with `Resume` subcommand and `success=false` must broadcast
/// an `AgentResponse` with Type="Error".
#[tokio::test]
async fn job_resume_failure_broadcasts_error_response() -> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("out-job-res-fail", listener_port)).await?;
    drop(listener_guard);
    listeners.start("out-job-res-fail").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0023_u32;
    let key = [0x26; AGENT_KEY_LENGTH];
    let iv = [0x27; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = job_action_payload(3, 66, false); // Resume=3, job_id=66, failure

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandJob),
            0x63,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for job Resume failure, got {event:?}");
    };
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.to_lowercase().contains("resum"), "message should mention resume: {message:?}");
    assert!(message.contains("66"), "message should contain job id 66: {message:?}");

    socket.close(None).await?;
    listeners.stop("out-job-res-fail").await?;
    Ok(())
}

/// `handle_job_callback` with `KillRemove` subcommand and `success=true` must broadcast
/// an `AgentResponse` with Type="Good" and a message mentioning "killed".
#[tokio::test]
async fn job_kill_remove_success_broadcasts_good_response() -> Result<(), Box<dyn std::error::Error>>
{
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("out-job-kill-ok", listener_port)).await?;
    drop(listener_guard);
    listeners.start("out-job-kill-ok").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0024_u32;
    let key = [0x28; AGENT_KEY_LENGTH];
    let iv = [0x29; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = job_action_payload(4, 99, true); // KillRemove=4, job_id=99, success

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandJob),
            0x64,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for job KillRemove success, got {event:?}");
    };
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.to_lowercase().contains("kill"), "message should mention killed: {message:?}");
    assert!(message.contains("99"), "message should contain job id 99: {message:?}");

    socket.close(None).await?;
    listeners.stop("out-job-kill-ok").await?;
    Ok(())
}

/// `handle_job_callback` with `KillRemove` subcommand and `success=false` must broadcast
/// an `AgentResponse` with Type="Error".
#[tokio::test]
async fn job_kill_remove_failure_broadcasts_error_response()
-> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("out-job-kill-fail", listener_port)).await?;
    drop(listener_guard);
    listeners.start("out-job-kill-fail").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0025_u32;
    let key = [0x2A; AGENT_KEY_LENGTH];
    let iv = [0x2B; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = job_action_payload(4, 100, false); // KillRemove=4, job_id=100, failure

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandJob),
            0x65,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for job KillRemove failure, got {event:?}");
    };
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.to_lowercase().contains("kill"), "message should mention kill: {message:?}");
    assert!(message.contains("100"), "message should contain job id 100: {message:?}");

    socket.close(None).await?;
    listeners.stop("out-job-kill-fail").await?;
    Ok(())
}

/// `handle_job_callback` with `Died` subcommand must succeed (2xx) but must NOT
/// broadcast any `AgentResponse` to operators.
#[tokio::test]
async fn job_died_no_broadcast() -> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("out-job-died", listener_port)).await?;
    drop(listener_guard);
    listeners.start("out-job-died").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0026_u32;
    let key = [0x2C; AGENT_KEY_LENGTH];
    let iv = [0x2D; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = job_died_payload();

    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandJob),
            0x66,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        response.status().is_success(),
        "Died subcommand should succeed, got {}",
        response.status()
    );

    // Died intentionally emits nothing — verify no broadcast.
    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    listeners.stop("out-job-died").await?;
    Ok(())
}
