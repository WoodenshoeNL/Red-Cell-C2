mod common;

use red_cell::{
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, LoginRateLimiter, OperatorConnectionManager, PayloadBuilderService,
    SocketRelayManager, TeamserverState, websocket_routes,
};
use red_cell_common::config::Profile;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::OperatorMessage;
use tokio::net::TcpListener;
use tokio_tungstenite::connect_async;

// ── payload builders ────────────────────────────────────────────────────────

/// Build a BOF_CALLBACK_OUTPUT (0x00) payload: u32 LE type + length-prefixed UTF-8 string.
fn bof_output_payload(text: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&0u32.to_le_bytes()); // BOF_CALLBACK_OUTPUT
    p.extend_from_slice(&(text.len() as u32).to_le_bytes());
    p.extend_from_slice(text.as_bytes());
    p
}

/// Build a BOF_RAN_OK (3) payload: just the u32 LE sub-type, no extra data.
fn bof_ran_ok_payload() -> Vec<u8> {
    3u32.to_le_bytes().to_vec()
}

/// Build a BOF_EXCEPTION (1) payload: u32 LE sub-type + u32 LE exception code + u64 LE address.
fn bof_exception_payload(exception_code: u32, address: u64) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&1u32.to_le_bytes()); // BOF_EXCEPTION
    p.extend_from_slice(&exception_code.to_le_bytes());
    p.extend_from_slice(&address.to_le_bytes());
    p
}

/// Build a BOF_SYMBOL_NOT_FOUND (2) payload: u32 LE sub-type + length-prefixed UTF-8 symbol name.
fn bof_symbol_not_found_payload(symbol: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&2u32.to_le_bytes()); // BOF_SYMBOL_NOT_FOUND
    p.extend_from_slice(&(symbol.len() as u32).to_le_bytes());
    p.extend_from_slice(symbol.as_bytes());
    p
}

/// Build a BOF_COULD_NOT_RUN (4) payload: just the u32 LE sub-type, no extra data.
fn bof_could_not_run_payload() -> Vec<u8> {
    4u32.to_le_bytes().to_vec()
}

/// Build a BOF_CALLBACK_ERROR (0x0d) payload: u32 LE type + length-prefixed UTF-8 string.
fn bof_callback_error_payload(text: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&0x0du32.to_le_bytes()); // BOF_CALLBACK_ERROR
    p.extend_from_slice(&(text.len() as u32).to_le_bytes());
    p.extend_from_slice(text.as_bytes());
    p
}

/// Build an unknown BOF sub-type payload: u32 LE with a value that doesn't match any known variant.
fn bof_unknown_subtype_payload(subtype: u32) -> Vec<u8> {
    subtype.to_le_bytes().to_vec()
}

/// Build a DOTNET_INFO_NET_VERSION (0x2) payload for `CommandAssemblyInlineExecute`.
/// The CLR version string is encoded as a LE-length-prefixed UTF-16 LE string.
fn assembly_clr_version_payload(version: &str) -> Vec<u8> {
    let utf16_bytes: Vec<u8> = version.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let mut p = Vec::new();
    p.extend_from_slice(&2u32.to_le_bytes()); // DOTNET_INFO_NET_VERSION
    p.extend_from_slice(&(utf16_bytes.len() as u32).to_le_bytes());
    p.extend_from_slice(&utf16_bytes);
    p
}

/// Build a DOTNET_INFO_PATCHED (0x1) payload for `CommandAssemblyInlineExecute`.
/// No extra data beyond the u32 LE info-id.
fn assembly_patched_payload() -> Vec<u8> {
    1u32.to_le_bytes().to_vec()
}

/// Build a DOTNET_INFO_ENTRYPOINT_EXECUTED (0x3) payload for `CommandAssemblyInlineExecute`.
/// Contains the info-id followed by a u32 LE thread ID.
fn assembly_entrypoint_executed_payload(thread_id: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&3u32.to_le_bytes()); // DOTNET_INFO_ENTRYPOINT_EXECUTED
    p.extend_from_slice(&thread_id.to_le_bytes());
    p
}

/// Build a DOTNET_INFO_FINISHED (0x4) payload for `CommandAssemblyInlineExecute`.
/// No extra data beyond the u32 LE info-id.
fn assembly_finished_payload() -> Vec<u8> {
    4u32.to_le_bytes().to_vec()
}

/// Build a DOTNET_INFO_FAILED (0x5) payload for `CommandAssemblyInlineExecute`.
/// No extra data beyond the u32 LE info-id.
fn assembly_failed_payload() -> Vec<u8> {
    5u32.to_le_bytes().to_vec()
}

/// Build an unknown info-id payload for `CommandAssemblyInlineExecute`.
fn assembly_unknown_info_id_payload(info_id: u32) -> Vec<u8> {
    info_id.to_le_bytes().to_vec()
}

/// Build a `CommandAssemblyListVersions` payload: a sequence of LE-length-prefixed
/// UTF-16 LE strings, one per version.
fn assembly_list_versions_payload(versions: &[&str]) -> Vec<u8> {
    let mut p = Vec::new();
    for v in versions {
        let utf16_bytes: Vec<u8> = v.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        p.extend_from_slice(&(utf16_bytes.len() as u32).to_le_bytes());
        p.extend_from_slice(&utf16_bytes);
    }
    p
}

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

/// Boot a teamserver and return its local address together with a cloned
/// `ListenerManager` so callers can start HTTP listeners.
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
        service_bridge: None,
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

// ── helpers ──────────────────────────────────────────────────────────────────

/// Register a fresh agent via DEMON_INIT and return the ctr_offset after init.
async fn register_agent(
    client: &reqwest::Client,
    listener_port: u16,
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> Result<u64, Box<dyn std::error::Error>> {
    let init_response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let init_bytes = init_response.bytes().await?;
    let ctr_offset = ctr_blocks_for_len(init_bytes.len());
    Ok(ctr_offset)
}

// ── tests ────────────────────────────────────────────────────────────────────

/// A BOF inline-execute callback with output text must broadcast an `AgentResponse`
/// event to the operator with the correct message and kind fields.
#[tokio::test]
async fn bof_output_callback_broadcasts_output_to_operator()
-> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("asm-test-bof-out", listener_port)).await?;
    drop(listener_guard);
    listeners.start("asm-test-bof-out").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xAB01_0001_u32;
    let key = [0x11; AGENT_KEY_LENGTH];
    let iv = [0x22; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    // Consume the AgentNew broadcast.
    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(
        matches!(agent_new, OperatorMessage::AgentNew(_)),
        "expected AgentNew, got {agent_new:?}"
    );

    let output_text = "BOF found 3 processes";
    let payload = bof_output_payload(output_text);
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandInlineExecute),
            0x10,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandInlineExecute).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Output"));
    assert_eq!(msg.info.extra.get("Message").and_then(|v| v.as_str()), Some(output_text));

    socket.close(None).await?;
    listeners.stop("asm-test-bof-out").await?;
    Ok(())
}

/// A BOF inline-execute callback with an empty payload (BOF_RAN_OK) must not
/// return an error and must broadcast a completion event to the operator.
#[tokio::test]
async fn bof_ran_ok_callback_broadcasts_completion() -> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("asm-test-bof-ok", listener_port)).await?;
    drop(listener_guard);
    listeners.start("asm-test-bof-ok").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xAB01_0002_u32;
    let key = [0x33; AGENT_KEY_LENGTH];
    let iv = [0x44; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // BOF_RAN_OK has no extra data — just the 4-byte sub-type code.
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandInlineExecute),
            0x20,
            &bof_ran_ok_payload(),
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    assert_eq!(
        msg.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("BOF execution completed")
    );

    socket.close(None).await?;
    listeners.stop("asm-test-bof-ok").await?;
    Ok(())
}

/// `handle_assembly_list_versions_callback` must broadcast a formatted list of
/// available CLR version strings to the operator, one per line.
#[tokio::test]
async fn assembly_list_versions_broadcasts_formatted_list() -> Result<(), Box<dyn std::error::Error>>
{
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("asm-test-list-ver", listener_port)).await?;
    drop(listener_guard);
    listeners.start("asm-test-list-ver").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xAB01_0003_u32;
    let key = [0x55; AGENT_KEY_LENGTH];
    let iv = [0x66; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let versions = ["v4.0.30319", "v2.0.50727"];
    let payload = assembly_list_versions_payload(&versions);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandAssemblyListVersions),
            0x30,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(
        msg.info.command_id,
        u32::from(DemonCommand::CommandAssemblyListVersions).to_string()
    );
    // The output must contain each version prefixed with "   - ".
    for v in &versions {
        assert!(
            msg.info.output.contains(&format!("   - {v}")),
            "output missing version {v}: {:?}",
            msg.info.output
        );
    }

    socket.close(None).await?;
    listeners.stop("asm-test-list-ver").await?;
    Ok(())
}

/// `handle_assembly_inline_execute_callback` with DOTNET_INFO_NET_VERSION must
/// broadcast the parsed CLR version string to the operator.
#[tokio::test]
async fn assembly_inline_execute_clr_version_broadcast() -> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("asm-test-clr-ver", listener_port)).await?;
    drop(listener_guard);
    listeners.start("asm-test-clr-ver").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xAB01_0004_u32;
    let key = [0x77; AGENT_KEY_LENGTH];
    let iv = [0x88; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let clr_version = "v4.0.30319";
    let payload = assembly_clr_version_payload(clr_version);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandAssemblyInlineExecute),
            0x40,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(
        msg.info.command_id,
        u32::from(DemonCommand::CommandAssemblyInlineExecute).to_string()
    );
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Info"));
    assert!(
        msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("").contains(clr_version),
        "message should contain CLR version string: {:?}",
        msg.info.extra.get("Message")
    );

    socket.close(None).await?;
    listeners.stop("asm-test-clr-ver").await?;
    Ok(())
}

/// A BOF inline-execute callback with BOF_EXCEPTION must broadcast an `AgentResponse`
/// with kind "Error" and a message containing the exception code and address.
#[tokio::test]
async fn bof_exception_callback_broadcasts_error_with_details()
-> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("asm-test-bof-exc", listener_port)).await?;
    drop(listener_guard);
    listeners.start("asm-test-bof-exc").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xAB01_0005_u32;
    let key = [0x99; AGENT_KEY_LENGTH];
    let iv = [0xAA; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let exception_code = 0xC000_0005_u32;
    let exception_addr = 0x00007FFE_1234_5678_u64;
    let payload = bof_exception_payload(exception_code, exception_addr);
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandInlineExecute),
            0x50,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandInlineExecute).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).expect("Message field");
    assert!(message.contains("C0000005"), "expected exception code in message, got {message:?}");
    assert!(
        message.contains("00007FFE12345678"),
        "expected exception address in message, got {message:?}"
    );

    socket.close(None).await?;
    listeners.stop("asm-test-bof-exc").await?;
    Ok(())
}

/// A BOF inline-execute callback with BOF_SYMBOL_NOT_FOUND must broadcast an
/// `AgentResponse` with kind "Error" and the missing symbol name in the message.
#[tokio::test]
async fn bof_symbol_not_found_callback_broadcasts_error_with_symbol()
-> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("asm-test-bof-sym", listener_port)).await?;
    drop(listener_guard);
    listeners.start("asm-test-bof-sym").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xAB01_0006_u32;
    let key = [0xBB; AGENT_KEY_LENGTH];
    let iv = [0xCC; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let missing_symbol = "KERNEL32$VirtualAllocEx";
    let payload = bof_symbol_not_found_payload(missing_symbol);
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandInlineExecute),
            0x60,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandInlineExecute).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).expect("Message field");
    assert!(
        message.contains(missing_symbol),
        "expected missing symbol name in message, got {message:?}"
    );

    socket.close(None).await?;
    listeners.stop("asm-test-bof-sym").await?;
    Ok(())
}

/// A BOF inline-execute callback with BOF_COULD_NOT_RUN must broadcast an
/// `AgentResponse` with kind "Error" and the expected failure message.
#[tokio::test]
async fn bof_could_not_run_callback_broadcasts_error() -> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("asm-test-bof-cnr", listener_port)).await?;
    drop(listener_guard);
    listeners.start("asm-test-bof-cnr").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xAB01_0007_u32;
    let key = [0xDD; AGENT_KEY_LENGTH];
    let iv = [0xEE; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = bof_could_not_run_payload();
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandInlineExecute),
            0x70,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandInlineExecute).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    assert_eq!(
        msg.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Failed to execute object file")
    );

    socket.close(None).await?;
    listeners.stop("asm-test-bof-cnr").await?;
    Ok(())
}

/// A BOF inline-execute callback with BOF_CALLBACK_ERROR (0x0d) must broadcast an
/// `AgentResponse` with kind "Error" and the error text in the message.
#[tokio::test]
async fn bof_callback_error_broadcasts_error_with_text() -> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("asm-test-bof-err", listener_port)).await?;
    drop(listener_guard);
    listeners.start("asm-test-bof-err").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xAB01_0008_u32;
    let key = [0xA1; AGENT_KEY_LENGTH];
    let iv = [0xA2; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let error_text = "BOF stderr: access violation reading 0x0";
    let payload = bof_callback_error_payload(error_text);
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandInlineExecute),
            0x80,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandInlineExecute).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    assert_eq!(msg.info.extra.get("Message").and_then(|v| v.as_str()), Some(error_text));

    socket.close(None).await?;
    listeners.stop("asm-test-bof-err").await?;
    Ok(())
}

/// An unknown BOF inline-execute sub-type must succeed at the HTTP layer (200 OK)
/// but must NOT broadcast any operator message.
#[tokio::test]
async fn bof_unknown_subtype_succeeds_without_operator_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("asm-test-bof-unk", listener_port)).await?;
    drop(listener_guard);
    listeners.start("asm-test-bof-unk").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xAB01_0009_u32;
    let key = [0xB1; AGENT_KEY_LENGTH];
    let iv = [0xB2; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = bof_unknown_subtype_payload(0xDEAD);
    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandInlineExecute),
            0x90,
            &payload,
        ))
        .send()
        .await?;
    assert!(response.status().is_success(), "HTTP callback should succeed for unknown sub-type");

    // No operator message should be broadcast for an unknown sub-type.
    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(250)).await;

    socket.close(None).await?;
    listeners.stop("asm-test-bof-unk").await?;
    Ok(())
}

/// `handle_assembly_inline_execute_callback` with DOTNET_INFO_PATCHED must
/// broadcast an `AgentResponse` with kind "Info" and a message mentioning Amsi/Etw patching.
#[tokio::test]
async fn assembly_inline_execute_patched_broadcasts_info() -> Result<(), Box<dyn std::error::Error>>
{
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("asm-test-patched", listener_port)).await?;
    drop(listener_guard);
    listeners.start("asm-test-patched").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xAB01_000A_u32;
    let key = [0xC1; AGENT_KEY_LENGTH];
    let iv = [0xC2; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = assembly_patched_payload();
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandAssemblyInlineExecute),
            0xA0,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(
        msg.info.command_id,
        u32::from(DemonCommand::CommandAssemblyInlineExecute).to_string()
    );
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Info"));
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).expect("Message field");
    assert!(
        message.contains("Amsi/Etw"),
        "expected patched message to mention Amsi/Etw, got {message:?}"
    );

    socket.close(None).await?;
    listeners.stop("asm-test-patched").await?;
    Ok(())
}

/// `handle_assembly_inline_execute_callback` with DOTNET_INFO_ENTRYPOINT_EXECUTED must
/// broadcast an `AgentResponse` with kind "Good" and a message containing the thread ID.
#[tokio::test]
async fn assembly_inline_execute_entrypoint_executed_broadcasts_thread_id()
-> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("asm-test-entry", listener_port)).await?;
    drop(listener_guard);
    listeners.start("asm-test-entry").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xAB01_000B_u32;
    let key = [0xD1; AGENT_KEY_LENGTH];
    let iv = [0xD2; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let thread_id = 4242_u32;
    let payload = assembly_entrypoint_executed_payload(thread_id);
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandAssemblyInlineExecute),
            0xB0,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(
        msg.info.command_id,
        u32::from(DemonCommand::CommandAssemblyInlineExecute).to_string()
    );
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).expect("Message field");
    assert!(message.contains("4242"), "expected thread id in message, got {message:?}");
    assert!(message.contains("Thread"), "expected 'Thread' label in message, got {message:?}");

    socket.close(None).await?;
    listeners.stop("asm-test-entry").await?;
    Ok(())
}

/// `handle_assembly_inline_execute_callback` with DOTNET_INFO_FINISHED must
/// broadcast an `AgentResponse` with kind "Good" and a completion message.
#[tokio::test]
async fn assembly_inline_execute_finished_broadcasts_good() -> Result<(), Box<dyn std::error::Error>>
{
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("asm-test-finished", listener_port)).await?;
    drop(listener_guard);
    listeners.start("asm-test-finished").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xAB01_000C_u32;
    let key = [0xE1; AGENT_KEY_LENGTH];
    let iv = [0xE2; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = assembly_finished_payload();
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandAssemblyInlineExecute),
            0xC0,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(
        msg.info.command_id,
        u32::from(DemonCommand::CommandAssemblyInlineExecute).to_string()
    );
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).expect("Message field");
    assert!(message.contains("Finished"), "expected 'Finished' in message, got {message:?}");

    socket.close(None).await?;
    listeners.stop("asm-test-finished").await?;
    Ok(())
}

/// `handle_assembly_inline_execute_callback` with DOTNET_INFO_FAILED must
/// broadcast an `AgentResponse` with kind "Error" and a failure message.
#[tokio::test]
async fn assembly_inline_execute_failed_broadcasts_error() -> Result<(), Box<dyn std::error::Error>>
{
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("asm-test-failed", listener_port)).await?;
    drop(listener_guard);
    listeners.start("asm-test-failed").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xAB01_000D_u32;
    let key = [0xF1; AGENT_KEY_LENGTH];
    let iv = [0xF2; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = assembly_failed_payload();
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandAssemblyInlineExecute),
            0xD0,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(
        msg.info.command_id,
        u32::from(DemonCommand::CommandAssemblyInlineExecute).to_string()
    );
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).expect("Message field");
    assert!(message.contains("Failed"), "expected 'Failed' in message, got {message:?}");

    socket.close(None).await?;
    listeners.stop("asm-test-failed").await?;
    Ok(())
}

/// An unknown info-id for `CommandAssemblyInlineExecute` must succeed at the HTTP layer
/// but must NOT broadcast any operator message — unknown IDs are silently ignored.
#[tokio::test]
async fn assembly_inline_execute_unknown_info_id_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("asm-test-unk-id", listener_port)).await?;
    drop(listener_guard);
    listeners.start("asm-test-unk-id").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xAB01_000E_u32;
    let key = [0xA3; AGENT_KEY_LENGTH];
    let iv = [0xA4; AGENT_IV_LENGTH];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = assembly_unknown_info_id_payload(0xBEEF);
    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandAssemblyInlineExecute),
            0xE0,
            &payload,
        ))
        .send()
        .await?;
    assert!(
        response.status().is_success(),
        "HTTP callback should succeed for unknown assembly info-id"
    );

    // No operator message should be broadcast for an unknown info-id.
    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(250)).await;

    socket.close(None).await?;
    listeners.stop("asm-test-unk-id").await?;
    Ok(())
}
