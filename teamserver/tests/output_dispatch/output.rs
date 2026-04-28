//! CommandOutput callback happy-path tests.
use super::*;
use crate::common;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::OperatorMessage;
use tokio_tungstenite::connect_async;

// ── tests ────────────────────────────────────────────────────────────────────

/// `mark_agent_dead_and_broadcast` (called via CommandExit callback) must mark the agent
/// dead in the registry, broadcast an `AgentUpdate` with `Marked="Dead"`, and broadcast
/// an `AgentResponse` carrying the exit message — in that order.
#[tokio::test]
async fn exit_callback_marks_agent_dead_and_broadcasts_update()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-exit-test", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-exit-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0001_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xB0, 0xC3, 0xD6, 0xE9, 0xFC, 0x0F, 0x22, 0x35, 0x48, 0x5B, 0x6E, 0x81, 0x94, 0xA7, 0xBA,
        0xCD,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

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
    server.listeners.stop("out-exit-test").await?;
    Ok(())
}

/// `handle_exit_callback` with `exit_method=2` must mark the agent dead and broadcast a
/// response containing "exit process" to distinguish it from thread exit.
#[tokio::test]
async fn exit_callback_process_exit_broadcasts_correct_message()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-exit-proc", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-exit-proc").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0002_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E,
        0x3F, 0x40,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xA0, 0xB3, 0xC6, 0xD9, 0xEC, 0xFF, 0x12, 0x25, 0x38, 0x4B, 0x5E, 0x71, 0x84, 0x97, 0xAA,
        0xBD,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    // Consume the AgentNew broadcast from registration.
    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(
        matches!(agent_new, OperatorMessage::AgentNew(_)),
        "expected AgentNew, got {agent_new:?}"
    );

    // Send a CommandExit callback (exit_method=2 → process exit).
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandExit),
            0x01,
            &exit_payload(2),
        ))
        .send()
        .await?
        .error_for_status()?;

    // First broadcast: AgentUpdate with Marked="Dead".
    let update_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentUpdate(update_msg) = update_event else {
        panic!("expected AgentUpdate after exit callback, got {update_event:?}");
    };
    assert_eq!(update_msg.info.marked, "Dead", "agent should be marked Dead after process exit");

    // Second broadcast: AgentResponse carrying the process exit message.
    let response_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(response_msg) = response_event else {
        panic!("expected AgentResponse after exit callback, got {response_event:?}");
    };
    assert_eq!(response_msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    let message = response_msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("exit process"),
        "exit_method=2 message should mention 'exit process', got: {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-exit-proc").await?;
    Ok(())
}

/// `handle_exit_callback` with an unknown `exit_method` value must mark the agent dead
/// and broadcast a generic "Agent exited" fallback message.
#[tokio::test]
async fn exit_callback_unknown_method_broadcasts_fallback_message()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-exit-unk", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-exit-unk").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0003_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E,
        0x5F, 0x60,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x90, 0xA3, 0xB6, 0xC9, 0xDC, 0xEF, 0x02, 0x15, 0x28, 0x3B, 0x4E, 0x61, 0x74, 0x87, 0x9A,
        0xAD,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    // Consume the AgentNew broadcast from registration.
    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(
        matches!(agent_new, OperatorMessage::AgentNew(_)),
        "expected AgentNew, got {agent_new:?}"
    );

    // Send a CommandExit callback (exit_method=99 → unknown/default).
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandExit),
            0x01,
            &exit_payload(99),
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
        update_msg.info.marked, "Dead",
        "agent should be marked Dead for unknown exit method"
    );

    // Second broadcast: AgentResponse with the generic fallback.
    let response_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(response_msg) = response_event else {
        panic!("expected AgentResponse after exit callback, got {response_event:?}");
    };
    assert_eq!(response_msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    let message = response_msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(
        message, "Agent exited",
        "unknown exit_method should produce fallback 'Agent exited', got: {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-exit-unk").await?;
    Ok(())
}

/// `handle_demon_info_callback` with a `MemAlloc` payload must broadcast an `AgentResponse`
/// containing the pointer, size, and memory protection to the operator.
#[tokio::test]
async fn demon_info_mem_alloc_broadcasts_response() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-info-test", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-info-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0002_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34,
        0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xE5, 0xF8, 0x0B, 0x1E, 0x31, 0x44, 0x57, 0x6A, 0x7D, 0x90, 0xA3, 0xB6, 0xC9, 0xDC, 0xEF,
        0x02,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

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
    server.listeners.stop("out-info-test").await?;
    Ok(())
}

/// `handle_job_callback` with a `List` subcommand and two jobs must broadcast an
/// `AgentResponse` to the operator whose output contains formatted rows for both jobs.
#[tokio::test]
async fn job_list_callback_broadcasts_formatted_table() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-job-test", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-job-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0003_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
        0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x69, 0x6A,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x1A, 0x2D, 0x40, 0x53, 0x66, 0x79, 0x8C, 0x9F, 0xB2, 0xC5, 0xD8, 0xEB, 0xFE, 0x11, 0x24,
        0x37,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

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
    server.listeners.stop("out-job-test").await?;
    Ok(())
}

/// `handle_job_callback` with a `List` subcommand and zero jobs must broadcast an
/// `AgentResponse` with Type=Info whose output contains the header/separator rows
/// but no data rows.
#[tokio::test]
async fn job_list_callback_empty_broadcasts_header_only() -> Result<(), Box<dyn std::error::Error>>
{
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-job-empty-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-job-empty-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0004_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E,
        0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D,
        0x8E, 0x8F,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x4F, 0x62, 0x75, 0x88, 0x9B, 0xAE, 0xC1, 0xD4, 0xE7, 0xFA, 0x0D, 0x20, 0x33, 0x46, 0x59,
        0x6C,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Empty job list — only the List subcommand u32, no job entries.
    let payload = job_list_payload(&[]);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandJob),
            0x30,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for empty CommandJob/List, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandJob).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Info"));

    let output = &msg.info.output;

    // Header and separator must still be present.
    assert!(output.contains("Job ID"), "output should contain header row: {output:?}");
    assert!(output.contains("Type"), "output should contain Type column header: {output:?}");
    assert!(output.contains("State"), "output should contain State column header: {output:?}");
    assert!(output.contains("------"), "output should contain separator row: {output:?}");

    // There must be zero data rows (only header + separator lines).
    let lines: Vec<String> =
        output.lines().map(|l| l.split_whitespace().collect::<Vec<_>>().join(" ")).collect();
    let data_rows: Vec<_> = lines
        .iter()
        .filter(|l| !l.is_empty() && !l.contains("Job ID") && !l.contains("------"))
        .collect();
    assert_eq!(
        data_rows.len(),
        0,
        "expected zero data rows for empty job list, got {}: {data_rows:?}",
        data_rows.len()
    );

    socket.close(None).await?;
    server.listeners.stop("out-job-empty-test").await?;
    Ok(())
}

/// `handle_demon_info_callback` with a `MemExec` payload must broadcast an `AgentResponse`
/// containing the function pointer and thread ID.
#[tokio::test]
async fn demon_info_mem_exec_broadcasts_response() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-mexec-test", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-mexec-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0010_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
        0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21,
        0x22, 0x23,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x23, 0x36, 0x49, 0x5C, 0x6F, 0x82, 0x95, 0xA8, 0xBB, 0xCE, 0xE1, 0xF4, 0x07, 0x1A, 0x2D,
        0x40,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

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
    server.listeners.stop("out-mexec-test").await?;
    Ok(())
}

/// `handle_demon_info_callback` with a `MemProtect` payload must broadcast an `AgentResponse`
/// containing the memory address, size, and old/new protection values.
#[tokio::test]
async fn demon_info_mem_protect_broadcasts_response() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-mprot-test", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-mprot-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0011_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
        0x47, 0x48,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x58, 0x6B, 0x7E, 0x91, 0xA4, 0xB7, 0xCA, 0xDD, 0xF0, 0x03, 0x16, 0x29, 0x3C, 0x4F, 0x62,
        0x75,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

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

    socket.close(None).await?;
    server.listeners.stop("out-mprot-test").await?;
    Ok(())
}

/// `handle_demon_info_callback` with `ProcCreate` and `verbose=false` must return `Ok(None)`
/// without broadcasting any `AgentResponse`.
#[tokio::test]
async fn demon_info_proc_create_non_verbose_no_broadcast() -> Result<(), Box<dyn std::error::Error>>
{
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-proc-nv-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-proc-nv-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0012_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C,
        0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B,
        0x6C, 0x6D,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x8D, 0xA0, 0xB3, 0xC6, 0xD9, 0xEC, 0xFF, 0x12, 0x25, 0x38, 0x4B, 0x5E, 0x71, 0x84, 0x97,
        0xAA,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

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
    server.listeners.stop("out-proc-nv-test").await?;
    Ok(())
}

/// `handle_demon_info_callback` with an unrecognized info class value must return `Ok(None)`
/// without broadcasting any `AgentResponse`.
#[tokio::test]
async fn demon_info_unknown_class_no_broadcast() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-info-unk-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-info-unk-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0013_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81,
        0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90,
        0x91, 0x92,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xC2, 0xD5, 0xE8, 0xFB, 0x0E, 0x21, 0x34, 0x47, 0x5A, 0x6D, 0x80, 0x93, 0xA6, 0xB9, 0xCC,
        0xDF,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

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

    common::skip_optional_teamserver_log(&mut socket, std::time::Duration::from_millis(200)).await;
    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-info-unk-test").await?;
    Ok(())
}

/// `handle_demon_info_callback` with `ProcCreate`, `verbose=true`, and `success=true`
/// must broadcast an `AgentResponse` containing the path and PID.
#[tokio::test]
async fn demon_info_proc_create_verbose_success_broadcasts_response()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-proc-vs-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-proc-vs-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0014_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6,
        0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
        0xB6, 0xB7,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xF7, 0x0A, 0x1D, 0x30, 0x43, 0x56, 0x69, 0x7C, 0x8F, 0xA2, 0xB5, 0xC8, 0xDB, 0xEE, 0x01,
        0x14,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload =
        demon_info_proc_create_payload("C:\\Windows\\System32\\cmd.exe", 5678, true, true, true);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::DemonInfo),
            0x54,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for DemonInfo/ProcCreate verbose success, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::DemonInfo).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Info"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("Process started"),
        "response should contain 'Process started': {message:?}"
    );
    assert!(message.contains("cmd.exe"), "response should contain path: {message:?}");
    assert!(message.contains("5678"), "response should contain PID 5678: {message:?}");

    socket.close(None).await?;
    server.listeners.stop("out-proc-vs-test").await?;
    Ok(())
}

/// `handle_demon_info_callback` with `ProcCreate`, `verbose=true`, `success=false`, and
/// `piped=false` must broadcast an `AgentResponse` indicating the process could not be started.
#[tokio::test]
async fn demon_info_proc_create_verbose_failure_broadcasts_response()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-proc-vf-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-proc-vf-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0015_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB,
        0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA,
        0xDB, 0xDC,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x2C, 0x3F, 0x52, 0x65, 0x78, 0x8B, 0x9E, 0xB1, 0xC4, 0xD7, 0xEA, 0xFD, 0x10, 0x23, 0x36,
        0x49,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // success=false, piped=false → "Process could not be started"
    let payload =
        demon_info_proc_create_payload("C:\\Windows\\System32\\bad.exe", 0, false, false, true);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::DemonInfo),
            0x55,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for DemonInfo/ProcCreate verbose failure, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::DemonInfo).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Info"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("could not be started"),
        "response should contain 'could not be started': {message:?}"
    );
    assert!(message.contains("bad.exe"), "response should contain path: {message:?}");

    socket.close(None).await?;
    server.listeners.stop("out-proc-vf-test").await?;
    Ok(())
}

/// `handle_demon_info_callback` with `ProcCreate`, `verbose=true`, `success=false`, and
/// `piped=true` must broadcast an `AgentResponse` indicating the process started without
/// an output pipe.
#[tokio::test]
async fn demon_info_proc_create_verbose_no_pipe_broadcasts_response()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-proc-np-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-proc-np-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0016_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0,
        0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        0x00, 0x01,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x61, 0x74, 0x87, 0x9A, 0xAD, 0xC0, 0xD3, 0xE6, 0xF9, 0x0C, 0x1F, 0x32, 0x45, 0x58, 0x6B,
        0x7E,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // success=false, piped=true → "Process started without output pipe"
    let payload = demon_info_proc_create_payload(
        "C:\\Windows\\System32\\notepad.exe",
        9999,
        false,
        true,
        true,
    );

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::DemonInfo),
            0x56,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for DemonInfo/ProcCreate verbose no-pipe, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::DemonInfo).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Info"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("without output pipe"),
        "response should contain 'without output pipe': {message:?}"
    );
    assert!(message.contains("notepad.exe"), "response should contain path: {message:?}");
    assert!(message.contains("9999"), "response should contain PID 9999: {message:?}");

    socket.close(None).await?;
    server.listeners.stop("out-proc-np-test").await?;
    Ok(())
}

/// `handle_job_callback` with a `List` subcommand and exactly one job must broadcast an
/// `AgentResponse` whose output contains the header rows and a single data row.
#[tokio::test]
async fn job_list_callback_single_job_broadcasts_one_row() -> Result<(), Box<dyn std::error::Error>>
{
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-job-single", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-job-single").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0077_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D,
        0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C,
        0x9D, 0x9E,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x8E, 0xA1, 0xB4, 0xC7, 0xDA, 0xED, 0x00, 0x13, 0x26, 0x39, 0x4C, 0x5F, 0x72, 0x85, 0x98,
        0xAB,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Single job: id=7, type=1 (Thread), state=1 (Running)
    let jobs = [(7u32, 1u32, 1u32)];
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
        panic!("expected AgentResponse for CommandJob/List single, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandJob).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Info"));

    let output = &msg.info.output;

    // Header/separator present.
    assert!(output.contains("Job ID"), "output should contain header: {output:?}");
    assert!(output.contains("------"), "output should contain separator: {output:?}");

    let lines: Vec<String> =
        output.lines().map(|l| l.split_whitespace().collect::<Vec<_>>().join(" ")).collect();

    // Single row: job 7, type Thread, state Running.
    assert!(
        lines.iter().any(|l| l.contains("7") && l.contains("Thread") && l.contains("Running")),
        "expected row with job 7, type Thread, state Running in output:\n{output}"
    );

    // Exactly one data row.
    let data_rows: Vec<_> = lines
        .iter()
        .filter(|l| !l.is_empty() && !l.contains("Job ID") && !l.contains("------"))
        .collect();
    assert_eq!(
        data_rows.len(),
        1,
        "expected exactly 1 data row, got {}: {data_rows:?}",
        data_rows.len()
    );

    socket.close(None).await?;
    server.listeners.stop("out-job-single").await?;
    Ok(())
}

/// `handle_job_callback` with a `List` subcommand and three jobs must broadcast an
/// `AgentResponse` whose output contains formatted rows for all three jobs.
#[tokio::test]
async fn job_list_callback_three_jobs_broadcasts_all_rows() -> Result<(), Box<dyn std::error::Error>>
{
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-job-three", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-job-three").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0078_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2,
        0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1,
        0xC2, 0xC3,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xC3, 0xD6, 0xE9, 0xFC, 0x0F, 0x22, 0x35, 0x48, 0x5B, 0x6E, 0x81, 0x94, 0xA7, 0xBA, 0xCD,
        0xE0,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Three jobs covering all known type/state combos:
    //   id=1, type=1 (Thread),        state=1 (Running)
    //   id=2, type=2 (Process),       state=2 (Suspended)
    //   id=3, type=3 (Track Process), state=3 (Dead)
    let jobs = [(1u32, 1u32, 1u32), (2u32, 2u32, 2u32), (3u32, 3u32, 3u32)];
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
        panic!("expected AgentResponse for CommandJob/List three, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandJob).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Info"));

    let output = &msg.info.output;

    let lines: Vec<String> =
        output.lines().map(|l| l.split_whitespace().collect::<Vec<_>>().join(" ")).collect();

    // Row for job 1: Thread, Running
    assert!(
        lines.iter().any(|l| l.contains("1") && l.contains("Thread") && l.contains("Running")),
        "expected row with job 1, type Thread, state Running in output:\n{output}"
    );
    // Row for job 2: Process, Suspended
    assert!(
        lines.iter().any(|l| l.contains("2") && l.contains("Process") && l.contains("Suspended")),
        "expected row with job 2, type Process, state Suspended in output:\n{output}"
    );
    // Row for job 3: Track Process, Dead
    assert!(
        lines.iter().any(|l| l.contains("3") && l.contains("Track Process") && l.contains("Dead")),
        "expected row with job 3, type Track Process, state Dead in output:\n{output}"
    );

    // Exactly three data rows.
    let data_rows: Vec<_> = lines
        .iter()
        .filter(|l| !l.is_empty() && !l.contains("Job ID") && !l.contains("------"))
        .collect();
    assert_eq!(
        data_rows.len(),
        3,
        "expected exactly 3 data rows, got {}: {data_rows:?}",
        data_rows.len()
    );

    socket.close(None).await?;
    server.listeners.stop("out-job-three").await?;
    Ok(())
}
