//! Integration tests for `dispatch/process.rs` — process-related callback handlers.
//!
//! All tests go through the full HTTP → listener → dispatch pipeline so that
//! the event-bus broadcast paths are exercised end-to-end.

mod common;

use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use red_cell_common::demon::{DemonCommand, DemonInjectError, DemonProcessCommand};
use red_cell_common::operator::OperatorMessage;
use tokio_tungstenite::connect_async;

// ── Payload builders ─────────────────────────────────────────────────────────

/// Encode a string as LE-length-prefixed UTF-16 LE bytes (the wire format used
/// by `CallbackParser::read_utf16`).
fn le_utf16(s: &str) -> Vec<u8> {
    let utf16_bytes: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    let mut out = (utf16_bytes.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(&utf16_bytes);
    out
}

/// Encode a byte slice as LE-length-prefixed bytes (the wire format used by
/// `CallbackParser::read_bytes` and `read_string`).
fn le_bytes(b: &[u8]) -> Vec<u8> {
    let mut out = (b.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(b);
    out
}

/// Build a `CommandProcPpidSpoof` callback payload: just a LE u32 PID.
fn ppid_spoof_payload(pid: u32) -> Vec<u8> {
    pid.to_le_bytes().to_vec()
}

/// Build a `CommandProcList` callback payload with one process entry.
///
/// Wire layout (all values LE unless stated):
///   u32 from_process_manager, then for each process:
///     UTF16LE name, u32 pid, u32 wow64, u32 ppid, u32 session, u32 threads, UTF16LE user
fn process_list_payload(
    from_pm: u32,
    entries: &[(&str, u32, u32, u32, u32, u32, &str)],
) -> Vec<u8> {
    let mut p = from_pm.to_le_bytes().to_vec();
    for &(name, pid, wow64, ppid, session, threads, user) in entries {
        p.extend_from_slice(&le_utf16(name));
        p.extend_from_slice(&pid.to_le_bytes());
        p.extend_from_slice(&wow64.to_le_bytes());
        p.extend_from_slice(&ppid.to_le_bytes());
        p.extend_from_slice(&session.to_le_bytes());
        p.extend_from_slice(&threads.to_le_bytes());
        p.extend_from_slice(&le_utf16(user));
    }
    p
}

/// Build a `CommandProc` / `DemonProcessCommand::Create` callback payload.
fn proc_create_payload(path: &str, pid: u32, success: u32, piped: u32, verbose: u32) -> Vec<u8> {
    let mut p = (u32::from(DemonProcessCommand::Create)).to_le_bytes().to_vec();
    p.extend_from_slice(&le_utf16(path));
    p.extend_from_slice(&pid.to_le_bytes());
    p.extend_from_slice(&success.to_le_bytes());
    p.extend_from_slice(&piped.to_le_bytes());
    p.extend_from_slice(&verbose.to_le_bytes());
    p
}

/// Build a `CommandProc` / `DemonProcessCommand::Kill` callback payload.
fn proc_kill_payload(success: u32, pid: u32) -> Vec<u8> {
    let mut p = (u32::from(DemonProcessCommand::Kill)).to_le_bytes().to_vec();
    p.extend_from_slice(&success.to_le_bytes());
    p.extend_from_slice(&pid.to_le_bytes());
    p
}

/// Build a `CommandProc` / `DemonProcessCommand::Modules` callback payload.
fn proc_modules_payload(pid: u32, modules: &[(&str, u64)]) -> Vec<u8> {
    let mut p = (u32::from(DemonProcessCommand::Modules)).to_le_bytes().to_vec();
    p.extend_from_slice(&pid.to_le_bytes());
    for &(name, base) in modules {
        p.extend_from_slice(&le_bytes(name.as_bytes()));
        p.extend_from_slice(&base.to_le_bytes());
    }
    p
}

/// Build a `CommandProc` / `DemonProcessCommand::Grep` callback payload.
fn proc_grep_payload(entries: &[(&str, u32, u32, &str, u32)]) -> Vec<u8> {
    let mut p = (u32::from(DemonProcessCommand::Grep)).to_le_bytes().to_vec();
    for &(name, pid, ppid, user, arch_val) in entries {
        p.extend_from_slice(&le_utf16(name));
        p.extend_from_slice(&pid.to_le_bytes());
        p.extend_from_slice(&ppid.to_le_bytes());
        // user is read_bytes (LE-length-prefixed raw bytes, null-terminated)
        let user_bytes = {
            let mut b = user.as_bytes().to_vec();
            b.push(0); // null terminator
            b
        };
        p.extend_from_slice(&le_bytes(&user_bytes));
        p.extend_from_slice(&arch_val.to_le_bytes());
    }
    p
}

/// Build a `CommandProc` / `DemonProcessCommand::Memory` callback payload.
fn proc_memory_payload(
    pid: u32,
    query_protect: u32,
    regions: &[(u64, u32, u32, u32, u32)],
) -> Vec<u8> {
    let mut p = (u32::from(DemonProcessCommand::Memory)).to_le_bytes().to_vec();
    p.extend_from_slice(&pid.to_le_bytes());
    p.extend_from_slice(&query_protect.to_le_bytes());
    for &(base, size, protect, state, mem_type) in regions {
        p.extend_from_slice(&base.to_le_bytes());
        p.extend_from_slice(&size.to_le_bytes());
        p.extend_from_slice(&protect.to_le_bytes());
        p.extend_from_slice(&state.to_le_bytes());
        p.extend_from_slice(&mem_type.to_le_bytes());
    }
    p
}

/// Build a `CommandInjectShellcode` callback payload: LE u32 status code.
fn inject_shellcode_payload(status: u32) -> Vec<u8> {
    status.to_le_bytes().to_vec()
}

/// Build a `CommandInjectDll` callback payload: LE u32 status code.
fn inject_dll_payload(status: u32) -> Vec<u8> {
    status.to_le_bytes().to_vec()
}

/// Build a `CommandSpawnDll` callback payload: LE u32 status code.
fn spawn_dll_payload(status: u32) -> Vec<u8> {
    status.to_le_bytes().to_vec()
}

// ── Shared keys / IVs ────────────────────────────────────────────────────────
//
// Each test uses a unique (agent_id, key, iv) triple so tests can run in
// parallel without sharing any agent state.

const KEY_A: [u8; AGENT_KEY_LENGTH] = [
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
    0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0,
];
const IV_A: [u8; AGENT_IV_LENGTH] = [
    0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0,
];

const KEY_B: [u8; AGENT_KEY_LENGTH] = [
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
];
const IV_B: [u8; AGENT_IV_LENGTH] = [
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
];

const KEY_C: [u8; AGENT_KEY_LENGTH] = [
    0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60,
    0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
];
const IV_C: [u8; AGENT_IV_LENGTH] = [
    0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80,
];

const KEY_D: [u8; AGENT_KEY_LENGTH] = [
    0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90,
    0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0,
];
const IV_D: [u8; AGENT_IV_LENGTH] = [
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
];

const KEY_E: [u8; AGENT_KEY_LENGTH] = [
    0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0,
    0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0,
];
const IV_E: [u8; AGENT_IV_LENGTH] = [
    0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0,
];

const KEY_F: [u8; AGENT_KEY_LENGTH] = [
    0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF, 0x00,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
];
const IV_F: [u8; AGENT_IV_LENGTH] = [
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
];

const KEY_G: [u8; AGENT_KEY_LENGTH] = [
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
];
const IV_G: [u8; AGENT_IV_LENGTH] = [
    0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
];

const KEY_H: [u8; AGENT_KEY_LENGTH] = [
    0x51, 0x62, 0x73, 0x84, 0x95, 0xA6, 0xB7, 0xC8, 0xD9, 0xEA, 0xFB, 0x0C, 0x1D, 0x2E, 0x3F, 0x40,
    0x51, 0x62, 0x73, 0x84, 0x95, 0xA6, 0xB7, 0xC8, 0xD9, 0xEA, 0xFB, 0x0C, 0x1D, 0x2E, 0x3F, 0x50,
];
const IV_H: [u8; AGENT_IV_LENGTH] = [
    0x61, 0x72, 0x83, 0x94, 0xA5, 0xB6, 0xC7, 0xD8, 0xE9, 0xFA, 0x0B, 0x1C, 0x2D, 0x3E, 0x4F, 0x60,
];

// ── Tests ────────────────────────────────────────────────────────────────────

/// A `CommandProcPpidSpoof` callback must broadcast an `AgentResponse` with
/// `Type = "Good"` and update the agent's `process_ppid` field.
#[tokio::test]
async fn ppid_spoof_callback_broadcasts_good_and_updates_agent()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("proc-ppid-spoof-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("proc-ppid-spoof-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xCC01_0001_u32;
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, KEY_A, IV_A).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)), "expected AgentNew");

    let new_ppid = 4444_u32;
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            KEY_A,
            IV_A,
            ctr_offset,
            u32::from(DemonCommand::CommandProcPpidSpoof),
            0x01,
            &ppid_spoof_payload(new_ppid),
        ))
        .send()
        .await?
        .error_for_status()?;

    // Should receive an AgentUpdate (agent mark) followed by an AgentResponse.
    let mark_event = common::read_operator_message(&mut socket).await?;
    assert!(
        matches!(mark_event, OperatorMessage::AgentUpdate(_)),
        "expected AgentUpdate after ppid spoof, got {mark_event:?}"
    );

    let resp_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = resp_event else {
        panic!("expected AgentResponse, got {resp_event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(
        msg.info.extra.get("Type").and_then(|v| v.as_str()),
        Some("Good"),
        "ppid spoof response must have Type=Good"
    );
    assert!(
        msg.info
            .extra
            .get("Message")
            .and_then(|v| v.as_str())
            .map(|m| m.contains(&new_ppid.to_string()))
            .unwrap_or(false),
        "message must mention the new ppid"
    );

    socket.close(None).await?;
    server.listeners.stop("proc-ppid-spoof-test").await?;
    Ok(())
}

/// A `CommandProcList` callback with one process entry must broadcast an
/// `AgentResponse` that contains the process list in `ProcessListRows`.
#[tokio::test]
async fn process_list_callback_broadcasts_process_table() -> Result<(), Box<dyn std::error::Error>>
{
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("proc-list-test", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("proc-list-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xCC01_0002_u32;
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, KEY_B, IV_B).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)), "expected AgentNew");

    // from_pm=1, one entry: explorer.exe pid=1234, wow64=0 (x64), ppid=4, session=1, threads=10, user="SYSTEM"
    let payload = process_list_payload(1, &[("explorer.exe", 1234, 0, 4, 1, 10, "SYSTEM")]);
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            KEY_B,
            IV_B,
            ctr_offset,
            u32::from(DemonCommand::CommandProcList),
            0x02,
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
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandProcList).to_string());

    // ProcessListRows should contain the single process entry.
    let rows = msg
        .info
        .extra
        .get("ProcessListRows")
        .and_then(|v| v.as_array())
        .expect("response must contain ProcessListRows array");
    assert_eq!(rows.len(), 1, "exactly one process row");
    assert_eq!(rows[0].get("Name").and_then(|v| v.as_str()), Some("explorer.exe"));
    assert_eq!(rows[0].get("PID").and_then(|v| v.as_u64()), Some(1234));
    assert_eq!(rows[0].get("Arch").and_then(|v| v.as_str()), Some("x64"));

    socket.close(None).await?;
    server.listeners.stop("proc-list-test").await?;
    Ok(())
}

/// A `CommandProc` / Create callback with verbose=1 and success=1 must broadcast
/// an `AgentResponse` with `Type = "Info"` containing the process path and PID.
#[tokio::test]
async fn proc_create_verbose_success_broadcasts_info() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("proc-create-verbose-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("proc-create-verbose-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xCC01_0003_u32;
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, KEY_C, IV_C).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)), "expected AgentNew");

    let path = "C:\\Windows\\notepad.exe";
    let pid = 5678_u32;
    // success=1, piped=1, verbose=1
    let payload = proc_create_payload(path, pid, 1, 1, 1);
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            KEY_C,
            IV_C,
            ctr_offset,
            u32::from(DemonCommand::CommandProc),
            0x03,
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
        msg.info.extra.get("Type").and_then(|v| v.as_str()),
        Some("Info"),
        "verbose create success must broadcast Type=Info"
    );
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains(path), "message must contain the process path");
    assert!(message.contains(&pid.to_string()), "message must contain the PID");

    socket.close(None).await?;
    server.listeners.stop("proc-create-verbose-test").await?;
    Ok(())
}

/// A `CommandProc` / Kill callback with success=1 must broadcast an `AgentResponse`
/// with `Type = "Good"` mentioning the killed PID.
#[tokio::test]
async fn proc_kill_success_broadcasts_good() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("proc-kill-test", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("proc-kill-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xCC01_0004_u32;
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, KEY_D, IV_D).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)), "expected AgentNew");

    let target_pid = 9999_u32;
    let payload = proc_kill_payload(1, target_pid);
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            KEY_D,
            IV_D,
            ctr_offset,
            u32::from(DemonCommand::CommandProc),
            0x04,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(
        msg.info.extra.get("Type").and_then(|v| v.as_str()),
        Some("Good"),
        "kill success must broadcast Type=Good"
    );
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains(&target_pid.to_string()), "message must mention the killed pid");

    socket.close(None).await?;
    server.listeners.stop("proc-kill-test").await?;
    Ok(())
}

/// A `CommandProc` / Kill callback with success=0 must broadcast an `AgentResponse`
/// with `Type = "Error"`.
#[tokio::test]
async fn proc_kill_failure_broadcasts_error() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("proc-kill-fail-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("proc-kill-fail-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xCC01_0005_u32;
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, KEY_E, IV_E).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)), "expected AgentNew");

    let payload = proc_kill_payload(0, 1234);
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            KEY_E,
            IV_E,
            ctr_offset,
            u32::from(DemonCommand::CommandProc),
            0x05,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(
        msg.info.extra.get("Type").and_then(|v| v.as_str()),
        Some("Error"),
        "kill failure must broadcast Type=Error"
    );

    socket.close(None).await?;
    server.listeners.stop("proc-kill-fail-test").await?;
    Ok(())
}

/// A `CommandProc` / Modules callback must broadcast an `AgentResponse` containing
/// `ModuleRows` with the correct module names and base addresses.
#[tokio::test]
async fn proc_modules_callback_broadcasts_module_rows() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("proc-modules-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("proc-modules-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xCC01_0006_u32;
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, KEY_F, IV_F).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)), "expected AgentNew");

    let pid = 1337_u32;
    let payload = proc_modules_payload(
        pid,
        &[("ntdll.dll", 0x7FFF_0000_0000_u64), ("kernel32.dll", 0x7FFE_0000_0000_u64)],
    );
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            KEY_F,
            IV_F,
            ctr_offset,
            u32::from(DemonCommand::CommandProc),
            0x06,
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

    let rows = msg
        .info
        .extra
        .get("ModuleRows")
        .and_then(|v| v.as_array())
        .expect("response must contain ModuleRows");
    assert_eq!(rows.len(), 2, "two module rows expected");
    assert_eq!(rows[0].get("Name").and_then(|v| v.as_str()), Some("ntdll.dll"));
    assert_eq!(rows[1].get("Name").and_then(|v| v.as_str()), Some("kernel32.dll"));

    socket.close(None).await?;
    server.listeners.stop("proc-modules-test").await?;
    Ok(())
}

/// A `CommandProc` / Grep callback must broadcast an `AgentResponse` with
/// `GrepRows` containing the matched process entries.
#[tokio::test]
async fn proc_grep_callback_broadcasts_grep_rows() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("proc-grep-test", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("proc-grep-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xCC01_0007_u32;
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, KEY_G, IV_G).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)), "expected AgentNew");

    // name, pid, ppid, user, arch_val (64 = x64, 86 = x86)
    let payload = proc_grep_payload(&[("svchost.exe", 2222, 688, "SYSTEM", 64)]);
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            KEY_G,
            IV_G,
            ctr_offset,
            u32::from(DemonCommand::CommandProc),
            0x07,
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

    let rows = msg
        .info
        .extra
        .get("GrepRows")
        .and_then(|v| v.as_array())
        .expect("response must contain GrepRows");
    assert_eq!(rows.len(), 1, "one grep row expected");
    assert_eq!(rows[0].get("Name").and_then(|v| v.as_str()), Some("svchost.exe"));
    assert_eq!(rows[0].get("PID").and_then(|v| v.as_u64()), Some(2222));
    assert_eq!(rows[0].get("User").and_then(|v| v.as_str()), Some("SYSTEM"));
    assert_eq!(rows[0].get("Arch").and_then(|v| v.as_str()), Some("x64"));

    socket.close(None).await?;
    server.listeners.stop("proc-grep-test").await?;
    Ok(())
}

/// A `CommandInjectShellcode` callback with `Success` status must broadcast an
/// `AgentResponse` with `Type = "Good"`.
#[tokio::test]
async fn inject_shellcode_success_broadcasts_good() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("inject-sc-ok-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("inject-sc-ok-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xCC01_0008_u32;
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, KEY_H, IV_H).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)), "expected AgentNew");

    let payload = inject_shellcode_payload(u32::from(DemonInjectError::Success));
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            KEY_H,
            IV_H,
            ctr_offset,
            u32::from(DemonCommand::CommandInjectShellcode),
            0x08,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(
        msg.info.extra.get("Type").and_then(|v| v.as_str()),
        Some("Good"),
        "shellcode inject success must broadcast Type=Good"
    );

    socket.close(None).await?;
    server.listeners.stop("inject-sc-ok-test").await?;
    Ok(())
}

/// A `CommandInjectShellcode` callback with `Failed` status must broadcast an
/// `AgentResponse` with `Type = "Error"`.
#[tokio::test]
async fn inject_shellcode_failure_broadcasts_error() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("inject-sc-fail-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("inject-sc-fail-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xCC01_0009_u32;
    // Reuse KEY_A/IV_A since agent_id differs.
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, KEY_A, IV_A).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)), "expected AgentNew");

    let payload = inject_shellcode_payload(u32::from(DemonInjectError::Failed));
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            KEY_A,
            IV_A,
            ctr_offset,
            u32::from(DemonCommand::CommandInjectShellcode),
            0x09,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(
        msg.info.extra.get("Type").and_then(|v| v.as_str()),
        Some("Error"),
        "shellcode inject failure must broadcast Type=Error"
    );

    socket.close(None).await?;
    server.listeners.stop("inject-sc-fail-test").await?;
    Ok(())
}

/// A `CommandInjectDll` callback with `Success` status must broadcast an
/// `AgentResponse` with `Type = "Good"`.
#[tokio::test]
async fn inject_dll_success_broadcasts_good() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("inject-dll-ok-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("inject-dll-ok-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xCC01_000A_u32;
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, KEY_B, IV_B).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)), "expected AgentNew");

    let payload = inject_dll_payload(u32::from(DemonInjectError::Success));
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            KEY_B,
            IV_B,
            ctr_offset,
            u32::from(DemonCommand::CommandInjectDll),
            0x0A,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(
        msg.info.extra.get("Type").and_then(|v| v.as_str()),
        Some("Good"),
        "dll inject success must broadcast Type=Good"
    );

    socket.close(None).await?;
    server.listeners.stop("inject-dll-ok-test").await?;
    Ok(())
}

/// A `CommandInjectDll` callback with `ProcessArchMismatch` status must broadcast
/// an `AgentResponse` with `Type = "Error"`.
#[tokio::test]
async fn inject_dll_arch_mismatch_broadcasts_error() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("inject-dll-arch-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("inject-dll-arch-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xCC01_000B_u32;
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, KEY_C, IV_C).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)), "expected AgentNew");

    let payload = inject_dll_payload(u32::from(DemonInjectError::ProcessArchMismatch));
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            KEY_C,
            IV_C,
            ctr_offset,
            u32::from(DemonCommand::CommandInjectDll),
            0x0B,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(
        msg.info.extra.get("Type").and_then(|v| v.as_str()),
        Some("Error"),
        "dll inject arch mismatch must broadcast Type=Error"
    );

    socket.close(None).await?;
    server.listeners.stop("inject-dll-arch-test").await?;
    Ok(())
}

/// A `CommandSpawnDll` callback with `Success` status must broadcast an
/// `AgentResponse` with `Type = "Good"`.
#[tokio::test]
async fn spawn_dll_success_broadcasts_good() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("spawn-dll-ok-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("spawn-dll-ok-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xCC01_000C_u32;
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, KEY_D, IV_D).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)), "expected AgentNew");

    let payload = spawn_dll_payload(u32::from(DemonInjectError::Success));
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            KEY_D,
            IV_D,
            ctr_offset,
            u32::from(DemonCommand::CommandSpawnDll),
            0x0C,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(
        msg.info.extra.get("Type").and_then(|v| v.as_str()),
        Some("Good"),
        "spawn dll success must broadcast Type=Good"
    );

    socket.close(None).await?;
    server.listeners.stop("spawn-dll-ok-test").await?;
    Ok(())
}

/// A `CommandSpawnDll` callback with `Failed` status must broadcast an
/// `AgentResponse` with `Type = "Error"`.
#[tokio::test]
async fn spawn_dll_failure_broadcasts_error() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("spawn-dll-fail-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("spawn-dll-fail-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xCC01_000D_u32;
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, KEY_E, IV_E).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)), "expected AgentNew");

    let payload = spawn_dll_payload(u32::from(DemonInjectError::Failed));
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            KEY_E,
            IV_E,
            ctr_offset,
            u32::from(DemonCommand::CommandSpawnDll),
            0x0D,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(
        msg.info.extra.get("Type").and_then(|v| v.as_str()),
        Some("Error"),
        "spawn dll failure must broadcast Type=Error"
    );

    socket.close(None).await?;
    server.listeners.stop("spawn-dll-fail-test").await?;
    Ok(())
}

/// A `CommandProc` / Memory callback must broadcast an `AgentResponse` containing
/// `MemoryRows` with the correct region data.
#[tokio::test]
async fn proc_memory_callback_broadcasts_memory_rows() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("proc-memory-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("proc-memory-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xCC01_000E_u32;
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, KEY_F, IV_F).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)), "expected AgentNew");

    let pid = 4321_u32;
    // query_protect=0 means "All", one region: base=0x1000_0000, size=0x1000, protect=0x20(PAGE_EXECUTE_READ),
    // state=0x1000(MEM_COMMIT), type=0x20000(MEM_PRIVATE)
    let payload = proc_memory_payload(pid, 0, &[(0x1000_0000_u64, 0x1000, 0x20, 0x1000, 0x20000)]);
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            KEY_F,
            IV_F,
            ctr_offset,
            u32::from(DemonCommand::CommandProc),
            0x0E,
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

    let rows = msg
        .info
        .extra
        .get("MemoryRows")
        .and_then(|v| v.as_array())
        .expect("response must contain MemoryRows");
    assert_eq!(rows.len(), 1, "one memory region row expected");
    // Base address should be formatted as hex
    let base_str = rows[0].get("Base").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        base_str.to_uppercase().contains("1000000"),
        "Base must contain the address, got: {base_str}"
    );

    socket.close(None).await?;
    server.listeners.stop("proc-memory-test").await?;
    Ok(())
}
