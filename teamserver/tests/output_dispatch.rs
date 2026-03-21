mod common;

use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use red_cell_common::demon::{DemonCallbackError, DemonCommand, DemonConfigKey, DemonInfoClass};
use red_cell_common::operator::OperatorMessage;
use tokio_tungstenite::connect_async;

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
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
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

/// `handle_demon_info_callback` with a `MemAlloc` payload must broadcast an `AgentResponse`
/// containing the pointer, size, and memory protection to the operator.
#[tokio::test]
async fn demon_info_mem_alloc_broadcasts_response() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
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

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
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

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
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

/// `handle_demon_info_callback` with a truncated payload (info_class only, no class data)
/// must return an error to the HTTP caller and must NOT broadcast any `AgentResponse`.
#[tokio::test]
async fn demon_info_truncated_payload_returns_error_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-trunc-test", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-trunc-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0004_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3,
        0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2,
        0xB3, 0xB4,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x84, 0x97, 0xAA, 0xBD, 0xD0, 0xE3, 0xF6, 0x09, 0x1C, 0x2F, 0x42, 0x55, 0x68, 0x7B, 0x8E,
        0xA1,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

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
    server.listeners.stop("out-trunc-test").await?;
    Ok(())
}

/// A `CommandExit` callback with an empty payload (zero bytes) must return a
/// non-2xx HTTP status and must NOT broadcast `AgentUpdate` or `AgentResponse`.
#[tokio::test]
async fn exit_callback_empty_payload_returns_error_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-exit-empty-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-exit-empty-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0005_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8,
        0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
        0xD8, 0xD9,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xB9, 0xCC, 0xDF, 0xF2, 0x05, 0x18, 0x2B, 0x3E, 0x51, 0x64, 0x77, 0x8A, 0x9D, 0xB0, 0xC3,
        0xD6,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

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
    server.listeners.stop("out-exit-empty-test").await?;
    Ok(())
}

/// A `CommandExit` callback with fewer than four bytes (truncated exit_method)
/// must return a non-2xx HTTP status and must NOT broadcast any events.
#[tokio::test]
async fn exit_callback_truncated_exit_method_returns_error_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-exit-short-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-exit-short-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0006_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED,
        0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC,
        0xFD, 0xFE,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xEE, 0x01, 0x14, 0x27, 0x3A, 0x4D, 0x60, 0x73, 0x86, 0x99, 0xAC, 0xBF, 0xD2, 0xE5, 0xF8,
        0x0B,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

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
    server.listeners.stop("out-exit-short-test").await?;
    Ok(())
}

/// `handle_demon_info_callback` with a `MemExec` payload must broadcast an `AgentResponse`
/// containing the function pointer and thread ID.
#[tokio::test]
async fn demon_info_mem_exec_broadcasts_response() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
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

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
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

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
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

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
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

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
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

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
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

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
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

/// `handle_job_callback` with `Suspend` subcommand and `success=true` must broadcast
/// an `AgentResponse` with Type="Good" and a message mentioning "suspended".
#[tokio::test]
async fn job_suspend_success_broadcasts_good_response() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-job-susp-ok", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-job-susp-ok").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0020_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
        0x25, 0x26,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x96, 0xA9, 0xBC, 0xCF, 0xE2, 0xF5, 0x08, 0x1B, 0x2E, 0x41, 0x54, 0x67, 0x7A, 0x8D, 0xA0,
        0xB3,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

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
    server.listeners.stop("out-job-susp-ok").await?;
    Ok(())
}

/// `handle_job_callback` with `Suspend` subcommand and `success=false` must broadcast
/// an `AgentResponse` with Type="Error".
#[tokio::test]
async fn job_suspend_failure_broadcasts_error_response() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-job-susp-fail", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-job-susp-fail").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0021_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A,
        0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
        0x4A, 0x4B,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xCB, 0xDE, 0xF1, 0x04, 0x17, 0x2A, 0x3D, 0x50, 0x63, 0x76, 0x89, 0x9C, 0xAF, 0xC2, 0xD5,
        0xE8,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

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
    server.listeners.stop("out-job-susp-fail").await?;
    Ok(())
}

/// `handle_job_callback` with `Resume` subcommand and `success=true` must broadcast
/// an `AgentResponse` with Type="Good" and a message mentioning "resumed".
#[tokio::test]
async fn job_resume_success_broadcasts_good_response() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-job-res-ok", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-job-res-ok").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0022_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
        0x6F, 0x70,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x00, 0x13, 0x26, 0x39, 0x4C, 0x5F, 0x72, 0x85, 0x98, 0xAB, 0xBE, 0xD1, 0xE4, 0xF7, 0x0A,
        0x1D,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

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
    server.listeners.stop("out-job-res-ok").await?;
    Ok(())
}

/// `handle_job_callback` with `Resume` subcommand and `success=false` must broadcast
/// an `AgentResponse` with Type="Error".
#[tokio::test]
async fn job_resume_failure_broadcasts_error_response() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-job-res-fail", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-job-res-fail").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0023_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84,
        0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93,
        0x94, 0x95,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x35, 0x48, 0x5B, 0x6E, 0x81, 0x94, 0xA7, 0xBA, 0xCD, 0xE0, 0xF3, 0x06, 0x19, 0x2C, 0x3F,
        0x52,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

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
    server.listeners.stop("out-job-res-fail").await?;
    Ok(())
}

/// `handle_job_callback` with `KillRemove` subcommand and `success=true` must broadcast
/// an `AgentResponse` with Type="Good" and a message mentioning "killed".
#[tokio::test]
async fn job_kill_remove_success_broadcasts_good_response() -> Result<(), Box<dyn std::error::Error>>
{
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-job-kill-ok", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-job-kill-ok").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0024_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9,
        0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8,
        0xB9, 0xBA,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x6A, 0x7D, 0x90, 0xA3, 0xB6, 0xC9, 0xDC, 0xEF, 0x02, 0x15, 0x28, 0x3B, 0x4E, 0x61, 0x74,
        0x87,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

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
    server.listeners.stop("out-job-kill-ok").await?;
    Ok(())
}

/// `handle_job_callback` with `KillRemove` subcommand and `success=false` must broadcast
/// an `AgentResponse` with Type="Error".
#[tokio::test]
async fn job_kill_remove_failure_broadcasts_error_response()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-job-kill-fail", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-job-kill-fail").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0025_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE,
        0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD,
        0xDE, 0xDF,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x9F, 0xB2, 0xC5, 0xD8, 0xEB, 0xFE, 0x11, 0x24, 0x37, 0x4A, 0x5D, 0x70, 0x83, 0x96, 0xA9,
        0xBC,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

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
    server.listeners.stop("out-job-kill-fail").await?;
    Ok(())
}

// ── additional payload builders ──────────────────────────────────────────────

/// Build a `CommandError/Win32` payload: error_class(1) + win32_code(u32).
fn command_error_win32_payload(win32_code: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonCallbackError::Win32).to_le_bytes());
    p.extend_from_slice(&win32_code.to_le_bytes());
    p
}

/// Build a `CommandError/Token` payload: error_class(3) + status(u32).
fn command_error_token_payload(status: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonCallbackError::Token).to_le_bytes());
    p.extend_from_slice(&status.to_le_bytes());
    p
}

/// Build a `CommandError/Coffee` payload: error_class(2) only.
fn command_error_coffee_payload() -> Vec<u8> {
    u32::from(DemonCallbackError::Coffee).to_le_bytes().to_vec()
}

/// Build a `CommandError` payload with an unknown error class.
fn command_error_unknown_payload(class: u32) -> Vec<u8> {
    class.to_le_bytes().to_vec()
}

/// Build a `CommandSleep` payload: delay(u32) + jitter(u32).
fn sleep_payload(delay: u32, jitter: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&delay.to_le_bytes());
    p.extend_from_slice(&jitter.to_le_bytes());
    p
}

/// Build a `CommandConfig/KillDate` payload: key(u32=154) + raw_date(u64).
fn config_kill_date_payload(raw_date: u64) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonConfigKey::KillDate).to_le_bytes());
    p.extend_from_slice(&raw_date.to_le_bytes());
    p
}

/// Build a `CommandConfig/WorkingHours` payload: key(u32=155) + raw(u32).
fn config_working_hours_payload(raw: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonConfigKey::WorkingHours).to_le_bytes());
    p.extend_from_slice(&raw.to_le_bytes());
    p
}

/// Build a `CommandConfig/MemoryAlloc` payload: key(u32=101) + value(u32).
fn config_memory_alloc_payload(value: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonConfigKey::MemoryAlloc).to_le_bytes());
    p.extend_from_slice(&value.to_le_bytes());
    p
}

/// Build a `CommandConfig` payload with an invalid key discriminant.
fn config_invalid_key_payload(key: u32) -> Vec<u8> {
    key.to_le_bytes().to_vec()
}

/// `handle_job_callback` with `Died` subcommand must succeed (2xx) but must NOT
/// broadcast any `AgentResponse` to operators.
#[tokio::test]
async fn job_died_no_broadcast() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-job-died", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-job-died").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0026_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3,
        0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF, 0x00, 0x01, 0x02,
        0x03, 0x04,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xD4, 0xE7, 0xFA, 0x0D, 0x20, 0x33, 0x46, 0x59, 0x6C, 0x7F, 0x92, 0xA5, 0xB8, 0xCB, 0xDE,
        0xF1,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

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
    server.listeners.stop("out-job-died").await?;
    Ok(())
}

// ── handle_command_output_callback ──────────────────────────────────────────

/// `handle_command_output_callback` with non-empty output must broadcast an
/// `AgentResponse` containing the output text and a "Received Output" message.
#[tokio::test]
async fn command_output_happy_path_broadcasts_response() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-output-ok", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-output-ok").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0030_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x09, 0x1C, 0x2F, 0x42, 0x55, 0x68, 0x7B, 0x8E, 0xA1, 0xB4, 0xC7, 0xDA, 0xED, 0x00, 0x13,
        0x26,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let output_text = "whoami output: REDCELL\\operator";
    let payload = common::command_output_payload(output_text);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandOutput),
            0x70,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for CommandOutput, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandOutput).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("Received Output"),
        "message should contain 'Received Output': {message:?}"
    );
    assert!(
        message.contains(&output_text.len().to_string()),
        "message should contain byte count {}: {message:?}",
        output_text.len()
    );

    // The output field should contain the actual command output text.
    assert!(
        msg.info.output.contains(output_text),
        "output should contain the command text: {:?}",
        msg.info.output
    );

    socket.close(None).await?;
    server.listeners.stop("out-output-ok").await?;
    Ok(())
}

/// `handle_command_output_callback` with empty output must return `Ok(None)`
/// without broadcasting any `AgentResponse`.
#[tokio::test]
async fn command_output_empty_does_not_broadcast() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-output-empty", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-output-empty").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0031_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
        0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
        0x4D, 0x4E,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x3E, 0x51, 0x64, 0x77, 0x8A, 0x9D, 0xB0, 0xC3, 0xD6, 0xE9, 0xFC, 0x0F, 0x22, 0x35, 0x48,
        0x5B,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = common::command_output_payload("");

    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandOutput),
            0x71,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        response.status().is_success(),
        "empty output should succeed silently, got {}",
        response.status()
    );

    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-output-empty").await?;
    Ok(())
}

// ── handle_command_error_callback ───────────────────────────────────────────

/// `handle_command_error_callback` with Win32 error class and a known error code
/// must broadcast an `AgentResponse` with Type="Error" containing the symbolic name.
#[tokio::test]
async fn command_error_win32_known_code_broadcasts_error() -> Result<(), Box<dyn std::error::Error>>
{
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-err-win32-known", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-err-win32-known").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0040_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62,
        0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71,
        0x72, 0x73,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x73, 0x86, 0x99, 0xAC, 0xBF, 0xD2, 0xE5, 0xF8, 0x0B, 0x1E, 0x31, 0x44, 0x57, 0x6A, 0x7D,
        0x90,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Win32 error code 5 = ERROR_ACCESS_DENIED
    let payload = command_error_win32_payload(5);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandError),
            0x80,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for CommandError/Win32, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandError).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("ERROR_ACCESS_DENIED"),
        "message should contain symbolic name: {message:?}"
    );
    assert!(message.contains("[5]"), "message should contain error code [5]: {message:?}");

    socket.close(None).await?;
    server.listeners.stop("out-err-win32-known").await?;
    Ok(())
}

/// `handle_command_error_callback` with Win32 error class and an unknown code
/// must broadcast an `AgentResponse` with just the numeric code.
#[tokio::test]
async fn command_error_win32_unknown_code_broadcasts_numeric()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-err-win32-unk", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-err-win32-unk").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0041_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
        0x97, 0x98,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xA8, 0xBB, 0xCE, 0xE1, 0xF4, 0x07, 0x1A, 0x2D, 0x40, 0x53, 0x66, 0x79, 0x8C, 0x9F, 0xB2,
        0xC5,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Unknown Win32 code 9999
    let payload = command_error_win32_payload(9999);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandError),
            0x81,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for CommandError/Win32 unknown, got {event:?}");
    };
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("Win32 Error"), "message should contain 'Win32 Error': {message:?}");
    assert!(message.contains("[9999]"), "message should contain code [9999]: {message:?}");

    socket.close(None).await?;
    server.listeners.stop("out-err-win32-unk").await?;
    Ok(())
}

/// `handle_command_error_callback` with Token error class and status 0x1
/// must broadcast "No tokens inside the token vault".
#[tokio::test]
async fn command_error_token_empty_vault_broadcasts_message()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-err-token-empty", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-err-token-empty").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0042_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC,
        0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB,
        0xBC, 0xBD,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xDD, 0xF0, 0x03, 0x16, 0x29, 0x3C, 0x4F, 0x62, 0x75, 0x88, 0x9B, 0xAE, 0xC1, 0xD4, 0xE7,
        0xFA,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = command_error_token_payload(0x1);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandError),
            0x82,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for CommandError/Token, got {event:?}");
    };
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("No tokens inside the token vault"),
        "message should mention empty vault: {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-err-token-empty").await?;
    Ok(())
}

/// `handle_command_error_callback` with Token error class and a non-0x1 status
/// must broadcast a generic "Token operation failed" message with the hex status.
#[tokio::test]
async fn command_error_token_other_status_broadcasts_hex() -> Result<(), Box<dyn std::error::Error>>
{
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-err-token-hex", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-err-token-hex").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0043_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1,
        0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0,
        0xE1, 0xE2,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x12, 0x25, 0x38, 0x4B, 0x5E, 0x71, 0x84, 0x97, 0xAA, 0xBD, 0xD0, 0xE3, 0xF6, 0x09, 0x1C,
        0x2F,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = command_error_token_payload(0xBEEF);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandError),
            0x83,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for CommandError/Token other, got {event:?}");
    };
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("Token operation failed"),
        "message should mention token failure: {message:?}"
    );
    assert!(message.contains("BEEF"), "message should contain hex status BEEF: {message:?}");

    socket.close(None).await?;
    server.listeners.stop("out-err-token-hex").await?;
    Ok(())
}

/// `handle_command_error_callback` with Coffee error class must succeed (2xx)
/// without broadcasting any `AgentResponse`.
#[tokio::test]
async fn command_error_coffee_no_broadcast() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-err-coffee", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-err-coffee").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0044_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6,
        0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x47, 0x5A, 0x6D, 0x80, 0x93, 0xA6, 0xB9, 0xCC, 0xDF, 0xF2, 0x05, 0x18, 0x2B, 0x3E, 0x51,
        0x64,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = command_error_coffee_payload();

    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandError),
            0x84,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        response.status().is_success(),
        "Coffee error class should succeed silently, got {}",
        response.status()
    );

    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-err-coffee").await?;
    Ok(())
}

/// `handle_command_error_callback` with an unknown error class must succeed (2xx)
/// without broadcasting any `AgentResponse`.
#[tokio::test]
async fn command_error_unknown_class_no_broadcast() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-err-unk-class", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-err-unk-class").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0045_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
        0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
        0x2B, 0x2C,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x7C, 0x8F, 0xA2, 0xB5, 0xC8, 0xDB, 0xEE, 0x01, 0x14, 0x27, 0x3A, 0x4D, 0x60, 0x73, 0x86,
        0x99,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = command_error_unknown_payload(0xFF);

    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandError),
            0x85,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        response.status().is_success(),
        "unknown error class should succeed silently, got {}",
        response.status()
    );

    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-err-unk-class").await?;
    Ok(())
}

// ── handle_kill_date_callback ───────────────────────────────────────────────

/// `handle_kill_date_callback` must mark the agent dead, broadcast `AgentUpdate`
/// with Marked="Dead", and broadcast an `AgentResponse` with the kill date message.
#[tokio::test]
async fn kill_date_callback_marks_agent_dead_and_broadcasts()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-killdate-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-killdate-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0050_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xB1, 0xC4, 0xD7, 0xEA, 0xFD, 0x10, 0x23, 0x36, 0x49, 0x5C, 0x6F, 0x82, 0x95, 0xA8, 0xBB,
        0xCE,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Kill date callback takes _payload — content is ignored.
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandKillDate),
            0x90,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;

    // First broadcast: AgentUpdate with Marked="Dead".
    let update_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentUpdate(update_msg) = update_event else {
        panic!("expected AgentUpdate after kill date callback, got {update_event:?}");
    };
    assert_eq!(update_msg.info.agent_id, format!("{agent_id:08X}"));
    assert_eq!(
        update_msg.info.marked, "Dead",
        "agent should be marked Dead after kill date callback"
    );

    // Second broadcast: AgentResponse with kill date message.
    let response_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(response_msg) = response_event else {
        panic!("expected AgentResponse after kill date callback, got {response_event:?}");
    };
    assert_eq!(response_msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(response_msg.info.command_id, u32::from(DemonCommand::CommandKillDate).to_string());
    assert_eq!(response_msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = response_msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("kill date"), "message should mention kill date: {message:?}");

    socket.close(None).await?;
    server.listeners.stop("out-killdate-test").await?;
    Ok(())
}

// ── handle_sleep_callback ───────────────────────────────────────────────────

/// `handle_sleep_callback` must update the agent's sleep delay/jitter in the registry,
/// broadcast an `AgentUpdate`, and broadcast an `AgentResponse` with the new values.
#[tokio::test]
async fn sleep_callback_updates_agent_and_broadcasts() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-sleep-test", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-sleep-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0060_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65,
        0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74,
        0x75, 0x76,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xE6, 0xF9, 0x0C, 0x1F, 0x32, 0x45, 0x58, 0x6B, 0x7E, 0x91, 0xA4, 0xB7, 0xCA, 0xDD, 0xF0,
        0x03,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let delay = 30_u32;
    let jitter = 25_u32;
    let payload = sleep_payload(delay, jitter);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandSleep),
            0xA0,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // First broadcast: AgentUpdate (agent_mark_event with updated sleep values).
    let update_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentUpdate(update_msg) = update_event else {
        panic!("expected AgentUpdate after sleep callback, got {update_event:?}");
    };
    assert_eq!(update_msg.info.agent_id, format!("{agent_id:08X}"));
    assert_eq!(update_msg.info.marked, "Alive", "agent should remain Alive after sleep callback");

    // Second broadcast: AgentResponse with sleep interval message.
    let response_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(response_msg) = response_event else {
        panic!("expected AgentResponse after sleep callback, got {response_event:?}");
    };
    assert_eq!(response_msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(response_msg.info.command_id, u32::from(DemonCommand::CommandSleep).to_string());
    assert_eq!(response_msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = response_msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains(&delay.to_string()),
        "message should contain delay {delay}: {message:?}"
    );
    assert!(
        message.contains(&jitter.to_string()),
        "message should contain jitter {jitter}: {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-sleep-test").await?;
    Ok(())
}

// ── handle_config_callback ──────────────────────────────────────────────────

/// `handle_config_callback` with `KillDate` key and a non-zero value must broadcast
/// "KillDate has been set" and update the agent's kill_date in the registry.
#[tokio::test]
async fn config_kill_date_set_broadcasts_and_updates_agent()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-cfg-kd-set", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-kd-set").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0070_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A,
        0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99,
        0x9A, 0x9B,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x1B, 0x2E, 0x41, 0x54, 0x67, 0x7A, 0x8D, 0xA0, 0xB3, 0xC6, 0xD9, 0xEC, 0xFF, 0x12, 0x25,
        0x38,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Non-zero kill date value (epoch timestamp).
    let payload = config_kill_date_payload(1_893_456_000);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xB0,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // First: AgentUpdate from the registry update.
    let update_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentUpdate(update_msg) = update_event else {
        panic!("expected AgentUpdate for config KillDate set, got {update_event:?}");
    };
    assert_eq!(update_msg.info.agent_id, format!("{agent_id:08X}"));

    // Second: AgentResponse with "KillDate has been set".
    let response_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(response_msg) = response_event else {
        panic!("expected AgentResponse for config KillDate set, got {response_event:?}");
    };
    assert_eq!(response_msg.info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
    assert_eq!(response_msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = response_msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("KillDate has been set"),
        "message should contain 'KillDate has been set': {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cfg-kd-set").await?;
    Ok(())
}

/// `handle_config_callback` with `KillDate` key and raw=0 must broadcast
/// "KillDate was disabled" and clear the agent's kill_date.
#[tokio::test]
async fn config_kill_date_zero_disables_and_broadcasts() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-cfg-kd-zero", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-kd-zero").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0071_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE,
        0xBF, 0xC0,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x50, 0x63, 0x76, 0x89, 0x9C, 0xAF, 0xC2, 0xD5, 0xE8, 0xFB, 0x0E, 0x21, 0x34, 0x47, 0x5A,
        0x6D,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = config_kill_date_payload(0);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xB1,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // First: AgentUpdate from the registry update.
    let update_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentUpdate(update_msg) = update_event else {
        panic!("expected AgentUpdate for config KillDate disable, got {update_event:?}");
    };
    assert_eq!(update_msg.info.agent_id, format!("{agent_id:08X}"));

    // Second: AgentResponse with "KillDate was disabled".
    let response_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(response_msg) = response_event else {
        panic!("expected AgentResponse for config KillDate disable, got {response_event:?}");
    };
    let message = response_msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("KillDate was disabled"),
        "message should contain 'KillDate was disabled': {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cfg-kd-zero").await?;
    Ok(())
}

/// `handle_config_callback` with `WorkingHours` key and a non-zero value must
/// broadcast "WorkingHours has been set" and update agent state.
#[tokio::test]
async fn config_working_hours_set_broadcasts_and_updates() -> Result<(), Box<dyn std::error::Error>>
{
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-cfg-wh-set", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-wh-set").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0072_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4,
        0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3,
        0xE4, 0xE5,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x85, 0x98, 0xAB, 0xBE, 0xD1, 0xE4, 0xF7, 0x0A, 0x1D, 0x30, 0x43, 0x56, 0x69, 0x7C, 0x8F,
        0xA2,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Non-zero working hours value.
    let payload = config_working_hours_payload(0b101010);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xB2,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // First: AgentUpdate.
    let update_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentUpdate(update_msg) = update_event else {
        panic!("expected AgentUpdate for config WorkingHours set, got {update_event:?}");
    };
    assert_eq!(update_msg.info.agent_id, format!("{agent_id:08X}"));

    // Second: AgentResponse.
    let response_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(response_msg) = response_event else {
        panic!("expected AgentResponse for config WorkingHours set, got {response_event:?}");
    };
    let message = response_msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("WorkingHours has been set"),
        "message should contain 'WorkingHours has been set': {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cfg-wh-set").await?;
    Ok(())
}

/// `handle_config_callback` with `WorkingHours` key and raw=0 must broadcast
/// "WorkingHours was disabled".
#[tokio::test]
async fn config_working_hours_zero_disables() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-cfg-wh-zero", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-wh-zero").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0073_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9,
        0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xBA, 0xCD, 0xE0, 0xF3, 0x06, 0x19, 0x2C, 0x3F, 0x52, 0x65, 0x78, 0x8B, 0x9E, 0xB1, 0xC4,
        0xD7,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = config_working_hours_payload(0);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xB3,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // First: AgentUpdate.
    let update_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentUpdate(update_msg) = update_event else {
        panic!("expected AgentUpdate for config WorkingHours disable, got {update_event:?}");
    };
    assert_eq!(update_msg.info.agent_id, format!("{agent_id:08X}"));

    // Second: AgentResponse.
    let response_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(response_msg) = response_event else {
        panic!("expected AgentResponse for config WorkingHours disable, got {response_event:?}");
    };
    let message = response_msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("WorkingHours was disabled"),
        "message should contain 'WorkingHours was disabled': {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cfg-wh-zero").await?;
    Ok(())
}

/// `handle_config_callback` with `MemoryAlloc` key must broadcast an `AgentResponse`
/// with the allocation value in the message.
#[tokio::test]
async fn config_memory_alloc_broadcasts_value() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cfg-memalloc", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-memalloc").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0074_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D,
        0x2E, 0x2F,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xEF, 0x02, 0x15, 0x28, 0x3B, 0x4E, 0x61, 0x74, 0x87, 0x9A, 0xAD, 0xC0, 0xD3, 0xE6, 0xF9,
        0x0C,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let alloc_value = 64_u32; // PAGE_EXECUTE_READWRITE
    let payload = config_memory_alloc_payload(alloc_value);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xB4,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for config MemoryAlloc, got {event:?}");
    };
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("memory allocation")
            || message.contains("Memory Alloc")
            || message.contains("memory alloc"),
        "message should mention memory allocation: {message:?}"
    );
    assert!(
        message.contains(&alloc_value.to_string()),
        "message should contain alloc value {alloc_value}: {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cfg-memalloc").await?;
    Ok(())
}

/// `handle_config_callback` with an invalid config key must return a non-2xx
/// HTTP status (`InvalidCallbackPayload`) and must NOT broadcast.
#[tokio::test]
async fn config_invalid_key_returns_error() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-cfg-bad-key", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-bad-key").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0075_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52,
        0x53, 0x54,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x24, 0x37, 0x4A, 0x5D, 0x70, 0x83, 0x96, 0xA9, 0xBC, 0xCF, 0xE2, 0xF5, 0x08, 0x1B, 0x2E,
        0x41,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // 0xFFFF is not a valid DemonConfigKey.
    let payload = config_invalid_key_payload(0xFFFF);

    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xB5,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        !response.status().is_success(),
        "invalid config key should return error, got {}",
        response.status()
    );

    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-cfg-bad-key").await?;
    Ok(())
}

/// A `CommandJob/List` callback with an incomplete trailing row (only job_id, missing
/// type and state) must return a non-2xx HTTP status and must NOT broadcast any
/// `AgentResponse` to the operator socket.
#[tokio::test]
async fn job_list_malformed_incomplete_row_returns_error_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-job-malformed", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-job-malformed").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0076_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x59, 0x6C, 0x7F, 0x92, 0xA5, 0xB8, 0xCB, 0xDE, 0xF1, 0x04, 0x17, 0x2A, 0x3D, 0x50, 0x63,
        0x76,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Build a malformed CommandJob/List payload: one complete row followed by a
    // truncated row that only contains job_id (missing job_type and state).
    let mut malformed = Vec::new();
    malformed.extend_from_slice(&1u32.to_le_bytes()); // DemonJobCommand::List = 1
    // Complete row: id=10, type=2, state=1
    malformed.extend_from_slice(&10u32.to_le_bytes());
    malformed.extend_from_slice(&2u32.to_le_bytes());
    malformed.extend_from_slice(&1u32.to_le_bytes());
    // Incomplete trailing row: only job_id, no type or state
    malformed.extend_from_slice(&99u32.to_le_bytes());

    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandJob),
            0x20,
            &malformed,
        ))
        .send()
        .await?;

    assert!(
        !response.status().is_success(),
        "expected error HTTP status for malformed job list payload, got {}",
        response.status()
    );

    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-job-malformed").await?;
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

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
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

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
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

/// `handle_job_callback` with an unknown subcommand value (not 1–5) must return a
/// non-2xx HTTP status and must NOT broadcast any `AgentResponse`.
#[tokio::test]
async fn job_unknown_subcommand_returns_error() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-job-unknown", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-job-unknown").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0079_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
        0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6,
        0xE7, 0xE8,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xF8, 0x0B, 0x1E, 0x31, 0x44, 0x57, 0x6A, 0x7D, 0x90, 0xA3, 0xB6, 0xC9, 0xDC, 0xEF, 0x02,
        0x15,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Build a payload with subcommand value 99 — not a valid DemonJobCommand.
    let payload = 99u32.to_le_bytes().to_vec();

    let response = client
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
        .await?;

    assert!(
        !response.status().is_success(),
        "expected error HTTP status for unknown job subcommand, got {}",
        response.status()
    );

    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-job-unknown").await?;
    Ok(())
}

// ── handle_config_callback — remaining branches ─────────────────────────────

/// Build a `CommandConfig/MemoryExecute` payload: key(u32=102) + value(u32).
fn config_memory_execute_payload(value: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonConfigKey::MemoryExecute).to_le_bytes());
    p.extend_from_slice(&value.to_le_bytes());
    p
}

/// Encode a UTF-16LE length-prefixed field (u32 byte-length + UTF-16LE data).
fn encode_utf16_field(s: &str) -> Vec<u8> {
    let utf16: Vec<u16> = s.encode_utf16().collect();
    let byte_len = (utf16.len() * 2) as u32;
    let mut p = Vec::new();
    p.extend_from_slice(&byte_len.to_le_bytes());
    for word in &utf16 {
        p.extend_from_slice(&word.to_le_bytes());
    }
    p
}

/// Encode a UTF-8 length-prefixed field (u32 byte-length + UTF-8 data).
fn encode_string_field(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut p = Vec::new();
    p.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    p.extend_from_slice(bytes);
    p
}

/// Build a `CommandConfig/InjectSpawn64` payload: key(u32=152) + utf16 path.
fn config_inject_spawn64_payload(path: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonConfigKey::InjectSpawn64).to_le_bytes());
    p.extend(encode_utf16_field(path));
    p
}

/// Build a `CommandConfig/InjectSpawn32` payload: key(u32=153) + utf16 path.
fn config_inject_spawn32_payload(path: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonConfigKey::InjectSpawn32).to_le_bytes());
    p.extend(encode_utf16_field(path));
    p
}

/// Build a `CommandConfig/ImplantSpfThreadStart` payload: key(u32=3) + string module + string symbol.
fn config_spf_thread_start_payload(module: &str, symbol: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonConfigKey::ImplantSpfThreadStart).to_le_bytes());
    p.extend(encode_string_field(module));
    p.extend(encode_string_field(symbol));
    p
}

/// Build a `CommandConfig/ImplantSleepTechnique` payload: key(u32=5) + value(u32).
fn config_sleep_technique_payload(value: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonConfigKey::ImplantSleepTechnique).to_le_bytes());
    p.extend_from_slice(&value.to_le_bytes());
    p
}

/// Build a `CommandConfig/ImplantCoffeeVeh` payload: key(u32=7) + bool(u32).
fn config_coffee_veh_payload(enabled: bool) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonConfigKey::ImplantCoffeeVeh).to_le_bytes());
    p.extend_from_slice(&u32::from(enabled).to_le_bytes());
    p
}

/// Build a `CommandConfig/ImplantCoffeeThreaded` payload: key(u32=6) + bool(u32).
fn config_coffee_threaded_payload(enabled: bool) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonConfigKey::ImplantCoffeeThreaded).to_le_bytes());
    p.extend_from_slice(&u32::from(enabled).to_le_bytes());
    p
}

/// Build a `CommandConfig/InjectTechnique` payload: key(u32=150) + value(u32).
fn config_inject_technique_payload(value: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonConfigKey::InjectTechnique).to_le_bytes());
    p.extend_from_slice(&value.to_le_bytes());
    p
}

/// Build a `CommandConfig/InjectSpoofAddr` payload: key(u32=151) + string module + string symbol.
fn config_inject_spoof_addr_payload(module: &str, symbol: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonConfigKey::InjectSpoofAddr).to_le_bytes());
    p.extend(encode_string_field(module));
    p.extend(encode_string_field(symbol));
    p
}

/// Build a `CommandConfig/ImplantVerbose` payload: key(u32=4) + bool(u32).
fn config_implant_verbose_payload(enabled: bool) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonConfigKey::ImplantVerbose).to_le_bytes());
    p.extend_from_slice(&u32::from(enabled).to_le_bytes());
    p
}

/// `handle_config_callback` with `MemoryExecute` broadcasts a message containing
/// the execute protection value.
#[tokio::test]
async fn config_memory_execute_broadcasts_value() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-cfg-memexec", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-memexec").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0080_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC,
        0xFD, 0xFE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x2D, 0x40, 0x53, 0x66, 0x79, 0x8C, 0x9F, 0xB2, 0xC5, 0xD8, 0xEB, 0xFE, 0x11, 0x24, 0x37,
        0x4A,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let exec_value = 32_u32;
    let payload = config_memory_execute_payload(exec_value);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xC0,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for config MemoryExecute, got {event:?}");
    };
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("memory executing") || message.contains("Memory Execute"),
        "message should mention memory executing: {message:?}"
    );
    assert!(
        message.contains(&exec_value.to_string()),
        "message should contain execute value {exec_value}: {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cfg-memexec").await?;
    Ok(())
}

/// `handle_config_callback` with `InjectSpawn64` broadcasts the x64 target process path.
#[tokio::test]
async fn config_inject_spawn64_broadcasts_path() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-cfg-spawn64", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-spawn64").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0081_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21,
        0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
        0x31, 0x32,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x62, 0x75, 0x88, 0x9B, 0xAE, 0xC1, 0xD4, 0xE7, 0xFA, 0x0D, 0x20, 0x33, 0x46, 0x59, 0x6C,
        0x7F,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let target_path = r"C:\Windows\System32\notepad.exe";
    let payload = config_inject_spawn64_payload(target_path);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xC1,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for config InjectSpawn64, got {event:?}");
    };
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("x64") || message.contains("64"),
        "message should mention x64: {message:?}"
    );
    assert!(
        message.contains("notepad.exe"),
        "message should contain the target process path: {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cfg-spawn64").await?;
    Ok(())
}

/// `handle_config_callback` with `InjectSpawn32` broadcasts the x86 target process path.
#[tokio::test]
async fn config_inject_spawn32_broadcasts_path() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-cfg-spawn32", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-spawn32").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0082_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
        0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
        0x56, 0x57,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x97, 0xAA, 0xBD, 0xD0, 0xE3, 0xF6, 0x09, 0x1C, 0x2F, 0x42, 0x55, 0x68, 0x7B, 0x8E, 0xA1,
        0xB4,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let target_path = r"C:\Windows\SysWOW64\cmd.exe";
    let payload = config_inject_spawn32_payload(target_path);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xC2,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for config InjectSpawn32, got {event:?}");
    };
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("x86") || message.contains("32"),
        "message should mention x86: {message:?}"
    );
    assert!(
        message.contains("cmd.exe"),
        "message should contain the target process path: {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cfg-spawn32").await?;
    Ok(())
}

/// `handle_config_callback` with `ImplantSpfThreadStart` broadcasts module!symbol.
#[tokio::test]
async fn config_spf_thread_start_broadcasts_module_symbol() -> Result<(), Box<dyn std::error::Error>>
{
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cfg-spfthread", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-spfthread").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0083_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B,
        0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A,
        0x7B, 0x7C,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xCC, 0xDF, 0xF2, 0x05, 0x18, 0x2B, 0x3E, 0x51, 0x64, 0x77, 0x8A, 0x9D, 0xB0, 0xC3, 0xD6,
        0xE9,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = config_spf_thread_start_payload("ntdll.dll", "RtlUserThreadStart");

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xC3,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for config ImplantSpfThreadStart, got {event:?}");
    };
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("ntdll.dll") && message.contains("RtlUserThreadStart"),
        "message should contain module!symbol: {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cfg-spfthread").await?;
    Ok(())
}

/// `handle_config_callback` with `ImplantSleepTechnique` broadcasts the technique value.
#[tokio::test]
async fn config_sleep_technique_broadcasts_value() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cfg-sleeptech", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-sleeptech").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0084_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90,
        0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
        0xA0, 0xA1,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x01, 0x14, 0x27, 0x3A, 0x4D, 0x60, 0x73, 0x86, 0x99, 0xAC, 0xBF, 0xD2, 0xE5, 0xF8, 0x0B,
        0x1E,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let technique = 2_u32;
    let payload = config_sleep_technique_payload(technique);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xC4,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for config ImplantSleepTechnique, got {event:?}");
    };
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("obfuscation") || message.contains("Sleep"),
        "message should mention sleep obfuscation: {message:?}"
    );
    assert!(
        message.contains(&technique.to_string()),
        "message should contain technique value {technique}: {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cfg-sleeptech").await?;
    Ok(())
}

/// `handle_config_callback` with `ImplantCoffeeVeh` (true) broadcasts enabled status.
#[tokio::test]
async fn config_coffee_veh_true_broadcasts_enabled() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cfg-coffeeveh", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-coffeeveh").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0085_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
        0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4,
        0xC5, 0xC6,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x36, 0x49, 0x5C, 0x6F, 0x82, 0x95, 0xA8, 0xBB, 0xCE, 0xE1, 0xF4, 0x07, 0x1A, 0x2D, 0x40,
        0x53,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = config_coffee_veh_payload(true);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xC5,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for config ImplantCoffeeVeh, got {event:?}");
    };
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("VEH") || message.contains("veh"),
        "message should mention Coffee VEH: {message:?}"
    );
    assert!(message.contains("true"), "message should contain 'true': {message:?}");

    socket.close(None).await?;
    server.listeners.stop("out-cfg-coffeeveh").await?;
    Ok(())
}

/// `handle_config_callback` with `ImplantCoffeeThreaded` (false) broadcasts disabled status.
#[tokio::test]
async fn config_coffee_threaded_false_broadcasts_disabled() -> Result<(), Box<dyn std::error::Error>>
{
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cfg-coffeethread", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-coffeethread").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0086_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA,
        0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9,
        0xEA, 0xEB,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x6B, 0x7E, 0x91, 0xA4, 0xB7, 0xCA, 0xDD, 0xF0, 0x03, 0x16, 0x29, 0x3C, 0x4F, 0x62, 0x75,
        0x88,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = config_coffee_threaded_payload(false);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xC6,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for config ImplantCoffeeThreaded, got {event:?}");
    };
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("threading") || message.contains("Coffee"),
        "message should mention coffee threading: {message:?}"
    );
    assert!(message.contains("false"), "message should contain 'false': {message:?}");

    socket.close(None).await?;
    server.listeners.stop("out-cfg-coffeethread").await?;
    Ok(())
}

/// `handle_config_callback` with `InjectTechnique` broadcasts the injection technique value.
#[tokio::test]
async fn config_inject_technique_broadcasts_value() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cfg-injecttech", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-injecttech").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0087_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xA0, 0xB3, 0xC6, 0xD9, 0xEC, 0xFF, 0x12, 0x25, 0x38, 0x4B, 0x5E, 0x71, 0x84, 0x97, 0xAA,
        0xBD,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let technique = 3_u32;
    let payload = config_inject_technique_payload(technique);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xC7,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for config InjectTechnique, got {event:?}");
    };
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("injection technique") || message.contains("inject"),
        "message should mention injection technique: {message:?}"
    );
    assert!(
        message.contains(&technique.to_string()),
        "message should contain technique value {technique}: {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cfg-injecttech").await?;
    Ok(())
}

/// `handle_config_callback` with `InjectSpoofAddr` broadcasts module!symbol for spoofing.
#[tokio::test]
async fn config_inject_spoof_addr_broadcasts_module_symbol()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cfg-injectspoof", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-injectspoof").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0088_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
        0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33,
        0x34, 0x35,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xD5, 0xE8, 0xFB, 0x0E, 0x21, 0x34, 0x47, 0x5A, 0x6D, 0x80, 0x93, 0xA6, 0xB9, 0xCC, 0xDF,
        0xF2,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = config_inject_spoof_addr_payload("kernel32.dll", "CreateThread");

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xC8,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for config InjectSpoofAddr, got {event:?}");
    };
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("kernel32.dll") && message.contains("CreateThread"),
        "message should contain module!symbol: {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cfg-injectspoof").await?;
    Ok(())
}

/// `handle_config_callback` with `ImplantVerbose` (true) broadcasts verbose enabled.
#[tokio::test]
async fn config_implant_verbose_broadcasts_value() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-cfg-verbose", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-verbose").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0089_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
        0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        0x59, 0x5A,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x0A, 0x1D, 0x30, 0x43, 0x56, 0x69, 0x7C, 0x8F, 0xA2, 0xB5, 0xC8, 0xDB, 0xEE, 0x01, 0x14,
        0x27,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = config_implant_verbose_payload(true);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xC9,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for config ImplantVerbose, got {event:?}");
    };
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("verbose") || message.contains("Verbose"),
        "message should mention verbose: {message:?}"
    );
    assert!(message.contains("true"), "message should contain 'true': {message:?}");

    socket.close(None).await?;
    server.listeners.stop("out-cfg-verbose").await?;
    Ok(())
}

// ── handle_command_output_callback truncated payload tests ──────────────────

/// `handle_command_output_callback` with an empty payload (zero bytes) must fail
/// because `read_string` needs at least a u32 length prefix. No event must be broadcast.
#[tokio::test]
async fn command_output_empty_payload_returns_error_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cmdout-empty", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cmdout-empty").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_00A0_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
        0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D,
        0x7E, 0x7F,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x3F, 0x52, 0x65, 0x78, 0x8B, 0x9E, 0xB1, 0xC4, 0xD7, 0xEA, 0xFD, 0x10, 0x23, 0x36, 0x49,
        0x5C,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Send CommandOutput with zero bytes — no length prefix at all.
    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandOutput),
            0xD0,
            &[], // empty payload
        ))
        .send()
        .await?;

    assert!(
        !response.status().is_success(),
        "empty CommandOutput payload must not return 2xx, got {}",
        response.status()
    );

    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-cmdout-empty").await?;
    Ok(())
}

/// `handle_command_output_callback` with a truncated payload (only 2 bytes, less than
/// the 4-byte u32 length prefix) must return a non-2xx HTTP status and no event.
#[tokio::test]
async fn command_output_truncated_length_prefix_returns_error_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cmdout-short", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cmdout-short").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_00A1_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93,
        0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2,
        0xA3, 0xA4,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x74, 0x87, 0x9A, 0xAD, 0xC0, 0xD3, 0xE6, 0xF9, 0x0C, 0x1F, 0x32, 0x45, 0x58, 0x6B, 0x7E,
        0x91,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Send CommandOutput with only 2 bytes — too short for a u32 length prefix.
    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandOutput),
            0xD1,
            &[0x05, 0x00], // only 2 bytes, need at least 4 for length prefix
        ))
        .send()
        .await?;

    assert!(
        !response.status().is_success(),
        "truncated CommandOutput payload must not return 2xx, got {}",
        response.status()
    );

    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-cmdout-short").await?;
    Ok(())
}

/// `handle_command_output_callback` with a length prefix that exceeds the actual payload
/// must return a non-2xx HTTP status. The length says 100 bytes but only 3 bytes follow.
#[tokio::test]
async fn command_output_length_exceeds_payload_returns_error_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cmdout-overlen", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cmdout-overlen").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_00A2_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8,
        0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
        0xC8, 0xC9,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xA9, 0xBC, 0xCF, 0xE2, 0xF5, 0x08, 0x1B, 0x2E, 0x41, 0x54, 0x67, 0x7A, 0x8D, 0xA0, 0xB3,
        0xC6,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Length prefix says 100 bytes, but only 3 bytes of data follow.
    let mut payload = Vec::new();
    payload.extend_from_slice(&100_u32.to_le_bytes()); // length = 100
    payload.extend_from_slice(&[0x41, 0x42, 0x43]); // only 3 bytes of data

    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandOutput),
            0xD2,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        !response.status().is_success(),
        "CommandOutput with oversized length prefix must not return 2xx, got {}",
        response.status()
    );

    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-cmdout-overlen").await?;
    Ok(())
}

// ── handle_command_error_callback truncated body tests ──────────────────────

/// `handle_command_error_callback` with a valid Win32 error class but no error code
/// (truncated body) must return a non-2xx HTTP status and no event.
#[tokio::test]
async fn command_error_win32_truncated_body_returns_error_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cmderr-win32-trunc", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cmderr-win32-trunc").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_00B0_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD,
        0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC,
        0xED, 0xEE,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xDE, 0xF1, 0x04, 0x17, 0x2A, 0x3D, 0x50, 0x63, 0x76, 0x89, 0x9C, 0xAF, 0xC2, 0xD5, 0xE8,
        0xFB,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Win32 error class (0x01) but no error code after it.
    let payload = u32::from(DemonCallbackError::Win32).to_le_bytes().to_vec();

    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandError),
            0xE0,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        !response.status().is_success(),
        "Win32 error with truncated body must not return 2xx, got {}",
        response.status()
    );

    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-cmderr-win32-trunc").await?;
    Ok(())
}

/// `handle_command_error_callback` with a valid Token error class but no status u32
/// (truncated body) must return a non-2xx HTTP status and no event.
#[tokio::test]
async fn command_error_token_truncated_body_returns_error_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cmderr-token-trunc", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cmderr-token-trunc").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_00B1_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF, 0x00, 0x01, 0x02,
        0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
        0x12, 0x13,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x13, 0x26, 0x39, 0x4C, 0x5F, 0x72, 0x85, 0x98, 0xAB, 0xBE, 0xD1, 0xE4, 0xF7, 0x0A, 0x1D,
        0x30,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Token error class (0x03) but no status u32 after it.
    let payload = u32::from(DemonCallbackError::Token).to_le_bytes().to_vec();

    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandError),
            0xE1,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        !response.status().is_success(),
        "Token error with truncated body must not return 2xx, got {}",
        response.status()
    );

    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-cmderr-token-trunc").await?;
    Ok(())
}

// ── handle_sleep_callback truncated payload tests ───────────────────────────

/// `handle_sleep_callback` with an empty payload (zero bytes) must return a
/// non-2xx HTTP status and must NOT broadcast any events.
#[tokio::test]
async fn sleep_callback_empty_payload_returns_error_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-sleep-empty", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-sleep-empty").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_00C0_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x48, 0x5B, 0x6E, 0x81, 0x94, 0xA7, 0xBA, 0xCD, 0xE0, 0xF3, 0x06, 0x19, 0x2C, 0x3F, 0x52,
        0x65,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Send CommandSleep with zero bytes — no sleep_delay or sleep_jitter.
    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandSleep),
            0xF0,
            &[], // empty payload
        ))
        .send()
        .await?;

    assert!(
        !response.status().is_success(),
        "empty CommandSleep payload must not return 2xx, got {}",
        response.status()
    );

    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-sleep-empty").await?;
    Ok(())
}

/// `handle_sleep_callback` with only the sleep_delay u32 but missing the sleep_jitter u32
/// must return a non-2xx HTTP status and must NOT broadcast any events.
#[tokio::test]
async fn sleep_callback_truncated_missing_jitter_returns_error_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-sleep-trunc", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-sleep-trunc").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_00C1_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
        0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B,
        0x5C, 0x5D,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x7D, 0x90, 0xA3, 0xB6, 0xC9, 0xDC, 0xEF, 0x02, 0x15, 0x28, 0x3B, 0x4E, 0x61, 0x74, 0x87,
        0x9A,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Only sleep_delay (4 bytes), missing sleep_jitter.
    let payload = 10_u32.to_le_bytes().to_vec(); // delay=10, no jitter

    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandSleep),
            0xF1,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        !response.status().is_success(),
        "truncated CommandSleep (missing jitter) must not return 2xx, got {}",
        response.status()
    );

    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-sleep-trunc").await?;
    Ok(())
}

// ── persist_credentials_from_output — credential extraction tests ───────────

/// Sending command output containing a credential pattern (keyword-block style)
/// must create a loot record with kind="credential" in the database and broadcast
/// both a loot-new event and a CredentialsAdd event to the operator WebSocket.
#[tokio::test]
async fn command_output_credential_pattern_creates_loot_record()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cred-extract", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cred-extract").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_00D0_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71,
        0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80,
        0x81, 0x82,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xB2, 0xC5, 0xD8, 0xEB, 0xFE, 0x11, 0x24, 0x37, 0x4A, 0x5D, 0x70, 0x83, 0x96, 0xA9, 0xBC,
        0xCF,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Mimikatz-style credential output with keyword-block lines.
    let output_text = "Username : admin\nPassword : P@ssw0rd!";
    let payload = common::command_output_payload(output_text);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandOutput),
            0xD0,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // First event: AgentResponse with the output text.
    let event1 = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(resp_msg) = event1 else {
        panic!("expected AgentResponse for CommandOutput, got {event1:?}");
    };
    assert_eq!(resp_msg.info.demon_id, format!("{agent_id:08X}"));
    assert!(resp_msg.info.output.contains(output_text));

    // Second event: loot-new for the credential record.
    let event2 = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(loot_msg) = event2 else {
        panic!("expected AgentResponse (loot-new), got {event2:?}");
    };
    assert_eq!(
        loot_msg.info.extra.get("MiscType").and_then(|v| v.as_str()),
        Some("loot-new"),
        "loot event must have MiscType=loot-new"
    );

    // Third event: CredentialsAdd with the extracted credential details.
    let event3 = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::CredentialsAdd(cred_msg) = event3 else {
        panic!("expected CredentialsAdd event, got {event3:?}");
    };
    assert_eq!(
        cred_msg.info.fields.get("DemonID").and_then(|v| v.as_str()),
        Some(&format!("{agent_id:08X}") as &str),
    );
    let credential_content = cred_msg
        .info
        .fields
        .get("Credential")
        .and_then(|v| v.as_str())
        .expect("CredentialsAdd must contain a Credential field");
    assert!(
        credential_content.contains("Username") && credential_content.contains("Password"),
        "credential content should contain the keyword block: {credential_content:?}"
    );

    // Database must contain a loot record with kind="credential".
    let loot_records = server.database.loot().list_for_agent(agent_id).await?;
    assert!(!loot_records.is_empty(), "at least one loot record must be persisted");
    assert!(
        loot_records.iter().any(|r| r.kind == "credential"),
        "expected a 'credential' loot record; got kinds: {:?}",
        loot_records.iter().map(|r| &r.kind).collect::<Vec<_>>()
    );
    let cred_record = loot_records.iter().find(|r| r.kind == "credential").unwrap();
    assert_eq!(cred_record.agent_id, agent_id);
    let data_str = std::str::from_utf8(cred_record.data.as_deref().unwrap_or_default())
        .unwrap_or("<invalid utf8>");
    assert!(
        data_str.contains("Username") && data_str.contains("Password"),
        "loot data should contain the credential block: {data_str:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cred-extract").await?;
    Ok(())
}

/// Sending command output containing a pwdump-format hash must create a loot
/// record with pattern="pwdump-hash".
#[tokio::test]
async fn command_output_pwdump_hash_creates_loot_record() -> Result<(), Box<dyn std::error::Error>>
{
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-cred-pwdump", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-cred-pwdump").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_00D1_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
        0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
        0xA6, 0xA7,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xE7, 0xFA, 0x0D, 0x20, 0x33, 0x46, 0x59, 0x6C, 0x7F, 0x92, 0xA5, 0xB8, 0xCB, 0xDE, 0xF1,
        0x04,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // pwdump-format NTLM hash line.
    let hash_line =
        "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::";
    let payload = common::command_output_payload(hash_line);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandOutput),
            0xD1,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // First event: AgentResponse with the output.
    let event1 = common::read_operator_message(&mut socket).await?;
    assert!(
        matches!(event1, OperatorMessage::AgentResponse(_)),
        "expected AgentResponse, got {event1:?}"
    );

    // Second event: loot-new.
    let event2 = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(loot_msg) = event2 else {
        panic!("expected AgentResponse (loot-new), got {event2:?}");
    };
    assert_eq!(loot_msg.info.extra.get("MiscType").and_then(|v| v.as_str()), Some("loot-new"),);

    // Third event: CredentialsAdd.
    let event3 = common::read_operator_message(&mut socket).await?;
    assert!(
        matches!(event3, OperatorMessage::CredentialsAdd(_)),
        "expected CredentialsAdd, got {event3:?}"
    );

    // Database loot record must exist with the hash data.
    let loot_records = server.database.loot().list_for_agent(agent_id).await?;
    assert!(
        loot_records.iter().any(|r| r.kind == "credential"),
        "expected a 'credential' loot record; got: {loot_records:?}"
    );
    let cred_record = loot_records.iter().find(|r| r.kind == "credential").unwrap();
    let data_str = std::str::from_utf8(cred_record.data.as_deref().unwrap_or_default())
        .unwrap_or("<invalid utf8>");
    assert!(
        data_str.contains("Administrator") && data_str.contains("aad3b435b51404ee"),
        "loot data should contain the pwdump hash: {data_str:?}"
    );
    // Verify metadata contains pattern=pwdump-hash.
    let metadata = cred_record.metadata.as_ref().expect("loot metadata must be present");
    assert_eq!(
        metadata.get("pattern").and_then(|v| v.as_str()),
        Some("pwdump-hash"),
        "loot metadata pattern should be 'pwdump-hash'"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cred-pwdump").await?;
    Ok(())
}

/// Non-credential command output (plain text with no credential patterns) must
/// NOT create any loot records — verifies no false-positive extraction.
#[tokio::test]
async fn command_output_no_credentials_creates_no_loot() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-cred-none", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-cred-none").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_00D2_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB,
        0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
        0xCB, 0xCC,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x1C, 0x2F, 0x42, 0x55, 0x68, 0x7B, 0x8E, 0xA1, 0xB4, 0xC7, 0xDA, 0xED, 0x00, 0x13, 0x26,
        0x39,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Plain text output with no credential patterns.
    let output_text = "Directory of C:\\Users\\operator\\Desktop\n\n2026-03-19  10:30    <DIR>          .\n2026-03-19  10:30    <DIR>          ..\n               0 File(s)              0 bytes";
    let payload = common::command_output_payload(output_text);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandOutput),
            0xD2,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // Must receive the AgentResponse for the output text.
    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(resp_msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert!(resp_msg.info.output.contains("Directory of"));

    // No further events should arrive (no loot-new, no CredentialsAdd).
    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(300)).await;

    // Database must have zero loot records for this agent.
    let loot_records = server.database.loot().list_for_agent(agent_id).await?;
    assert!(
        loot_records.is_empty(),
        "non-credential output must not create loot records; got: {loot_records:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cred-none").await?;
    Ok(())
}
