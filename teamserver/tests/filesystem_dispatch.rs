//! Integration tests for `dispatch/filesystem.rs` — filesystem callback handlers.
//!
//! All tests go through the full HTTP → listener → dispatch pipeline so that
//! the event-bus broadcast paths are exercised end-to-end.

mod common;

use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use red_cell_common::demon::{DemonCommand, DemonFilesystemCommand};
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

/// Build a `CommandFs` / `DemonFilesystemCommand::Dir` callback payload.
///
/// Wire layout (all LE):
///   u32 subcommand | u32 explorer | u32 list_only | utf16 root_path | u32 success
///   then per directory block:
///     utf16 path | u32 file_count | u32 dir_count | u64 total_size (if !list_only)
///     then per item (file_count + dir_count entries):
///       utf16 name | u32 is_dir | u64 size | u32 day | u32 month | u32 year | u32 minute | u32 hour
#[allow(clippy::type_complexity)]
fn dir_payload(
    root_path: &str,
    entries: &[(&str, &[(&str, bool, u64, (u32, u32, u32, u32, u32))])],
) -> Vec<u8> {
    let mut p = (u32::from(DemonFilesystemCommand::Dir)).to_le_bytes().to_vec();
    // explorer = false, list_only = false
    p.extend_from_slice(&0_u32.to_le_bytes());
    p.extend_from_slice(&0_u32.to_le_bytes());
    p.extend_from_slice(&le_utf16(root_path));
    // success = true
    p.extend_from_slice(&1_u32.to_le_bytes());
    for &(dir_path, items) in entries {
        p.extend_from_slice(&le_utf16(dir_path));
        let file_count = items.iter().filter(|&&(_, is_dir, _, _)| !is_dir).count() as u32;
        let dir_count = items.iter().filter(|&&(_, is_dir, _, _)| is_dir).count() as u32;
        p.extend_from_slice(&file_count.to_le_bytes());
        p.extend_from_slice(&dir_count.to_le_bytes());
        // total_size (list_only=false so always present)
        let total_size: u64 = items.iter().map(|&(_, _, size, _)| size).sum();
        p.extend_from_slice(&total_size.to_le_bytes());
        for &(name, is_dir, size, (day, month, year, minute, hour)) in items {
            p.extend_from_slice(&le_utf16(name));
            p.extend_from_slice(&(u32::from(is_dir)).to_le_bytes());
            p.extend_from_slice(&size.to_le_bytes());
            p.extend_from_slice(&day.to_le_bytes());
            p.extend_from_slice(&month.to_le_bytes());
            p.extend_from_slice(&year.to_le_bytes());
            p.extend_from_slice(&minute.to_le_bytes());
            p.extend_from_slice(&hour.to_le_bytes());
        }
    }
    p
}

/// Build a `CommandFs` / `DemonFilesystemCommand::Upload` callback payload.
///
/// Wire layout (all LE):
///   u32 subcommand | u32 size | utf16 path
fn upload_payload(size: u32, path: &str) -> Vec<u8> {
    let mut p = (u32::from(DemonFilesystemCommand::Upload)).to_le_bytes().to_vec();
    p.extend_from_slice(&size.to_le_bytes());
    p.extend_from_slice(&le_utf16(path));
    p
}

/// Build a `CommandFs` / `DemonFilesystemCommand::Cat` callback payload.
///
/// Wire layout (all LE):
///   u32 subcommand | utf16 path | u32 success | bytes output
fn cat_payload(path: &str, success: bool, output: &str) -> Vec<u8> {
    let mut p = (u32::from(DemonFilesystemCommand::Cat)).to_le_bytes().to_vec();
    p.extend_from_slice(&le_utf16(path));
    p.extend_from_slice(&(u32::from(success)).to_le_bytes());
    p.extend_from_slice(&le_bytes(output.as_bytes()));
    p
}

/// Build a `CommandFs` / `DemonFilesystemCommand::GetPwd` callback payload.
///
/// Wire layout (all LE):
///   u32 subcommand | utf16 path
fn getpwd_payload(path: &str) -> Vec<u8> {
    let mut p = (u32::from(DemonFilesystemCommand::GetPwd)).to_le_bytes().to_vec();
    p.extend_from_slice(&le_utf16(path));
    p
}

/// Build a `CommandFs` / `DemonFilesystemCommand::Download` mode=0 (start) payload.
///
/// Wire layout (all LE):
///   u32 subcommand | u32 mode=0 | u32 file_id | u64 expected_size | utf16 remote_path
fn download_start_payload(file_id: u32, expected_size: u64, remote_path: &str) -> Vec<u8> {
    let mut p = (u32::from(DemonFilesystemCommand::Download)).to_le_bytes().to_vec();
    p.extend_from_slice(&0_u32.to_le_bytes()); // mode = 0 (start)
    p.extend_from_slice(&file_id.to_le_bytes());
    p.extend_from_slice(&expected_size.to_le_bytes());
    p.extend_from_slice(&le_utf16(remote_path));
    p
}

/// Build a `CommandFs` / `DemonFilesystemCommand::Download` mode=1 (chunk) payload.
///
/// Wire layout (all LE):
///   u32 subcommand | u32 mode=1 | u32 file_id | bytes chunk
fn download_chunk_payload(file_id: u32, chunk: &[u8]) -> Vec<u8> {
    let mut p = (u32::from(DemonFilesystemCommand::Download)).to_le_bytes().to_vec();
    p.extend_from_slice(&1_u32.to_le_bytes()); // mode = 1 (chunk)
    p.extend_from_slice(&file_id.to_le_bytes());
    p.extend_from_slice(&le_bytes(chunk));
    p
}

/// Build a `CommandFs` / `DemonFilesystemCommand::Download` mode=2 (close) payload.
///
/// Wire layout (all LE):
///   u32 subcommand | u32 mode=2 | u32 file_id | u32 reason (0=success)
fn download_close_payload(file_id: u32, reason: u32) -> Vec<u8> {
    let mut p = (u32::from(DemonFilesystemCommand::Download)).to_le_bytes().to_vec();
    p.extend_from_slice(&2_u32.to_le_bytes()); // mode = 2 (close)
    p.extend_from_slice(&file_id.to_le_bytes());
    p.extend_from_slice(&reason.to_le_bytes());
    p
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

// ── Tests ────────────────────────────────────────────────────────────────────

/// A `CommandFs` / `Dir` callback with one file entry must broadcast an
/// `AgentResponse` with `Type = "Info"`, `Message = "Directory listing completed"`,
/// and an `output` that contains the filename.
#[tokio::test]
async fn dir_callback_broadcasts_directory_listing() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("fs-dir-test", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("fs-dir-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDD01_0001_u32;
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, KEY_A, IV_A).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)), "expected AgentNew");

    let root = "C:\\Users\\operator\\Documents\\*";
    let payload =
        dir_payload(root, &[(root, &[("secret.txt", false, 4096, (15, 3, 2024, 30, 10))])]);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            KEY_A,
            IV_A,
            ctr_offset,
            u32::from(DemonCommand::CommandFs),
            0x01,
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
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandFs).to_string());
    assert_eq!(
        msg.info.extra.get("Type").and_then(|v| v.as_str()),
        Some("Info"),
        "Dir response must have Type=Info"
    );
    assert_eq!(
        msg.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Directory listing completed"),
        "Dir response must say 'Directory listing completed'"
    );
    assert!(
        msg.info.output.contains("secret.txt"),
        "Dir output must contain the filename, got: {:?}",
        msg.info.output
    );

    socket.close(None).await?;
    server.listeners.stop("fs-dir-test").await?;
    Ok(())
}

/// A `CommandFs` / `Upload` callback must broadcast an `AgentResponse` with
/// `Type = "Info"` and a message containing the uploaded path and byte count.
#[tokio::test]
async fn upload_callback_broadcasts_upload_message() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("fs-upload-test", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("fs-upload-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDD01_0002_u32;
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, KEY_B, IV_B).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)), "expected AgentNew");

    let upload_path = "C:\\Windows\\Temp\\payload.exe";
    let upload_size = 8192_u32;
    let payload = upload_payload(upload_size, upload_path);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            KEY_B,
            IV_B,
            ctr_offset,
            u32::from(DemonCommand::CommandFs),
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
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandFs).to_string());
    assert_eq!(
        msg.info.extra.get("Type").and_then(|v| v.as_str()),
        Some("Info"),
        "Upload response must have Type=Info"
    );
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains(upload_path),
        "Upload message must contain the path, got: {message:?}"
    );
    assert!(
        message.contains(&upload_size.to_string()),
        "Upload message must contain the byte count, got: {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("fs-upload-test").await?;
    Ok(())
}

/// A successful `CommandFs` / `Cat` callback must broadcast an `AgentResponse`
/// with `Type = "Info"`, a message containing the path, and `output` with the
/// file content.
#[tokio::test]
async fn cat_callback_success_broadcasts_file_content() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("fs-cat-test", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("fs-cat-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDD01_0003_u32;
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, KEY_C, IV_C).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)), "expected AgentNew");

    let cat_path = "C:\\Users\\operator\\secrets.txt";
    let file_content = "supersecret_password=hunter2\n";
    let payload = cat_payload(cat_path, true, file_content);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            KEY_C,
            IV_C,
            ctr_offset,
            u32::from(DemonCommand::CommandFs),
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
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandFs).to_string());
    assert_eq!(
        msg.info.extra.get("Type").and_then(|v| v.as_str()),
        Some("Info"),
        "Cat success response must have Type=Info"
    );
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains(cat_path), "Cat message must reference the path, got: {message:?}");
    assert_eq!(msg.info.output, file_content, "Cat output must contain the file content");

    socket.close(None).await?;
    server.listeners.stop("fs-cat-test").await?;
    Ok(())
}

/// A `CommandFs` / `GetPwd` callback must broadcast an `AgentResponse` with
/// `Type = "Info"` and a message containing the current directory path.
#[tokio::test]
async fn getpwd_callback_broadcasts_current_directory() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("fs-pwd-test", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("fs-pwd-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDD01_0004_u32;
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, KEY_D, IV_D).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)), "expected AgentNew");

    let cwd = "C:\\Users\\operator\\Desktop";
    let payload = getpwd_payload(cwd);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            KEY_D,
            IV_D,
            ctr_offset,
            u32::from(DemonCommand::CommandFs),
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

    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandFs).to_string());
    assert_eq!(
        msg.info.extra.get("Type").and_then(|v| v.as_str()),
        Some("Info"),
        "GetPwd response must have Type=Info"
    );
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains(cwd),
        "GetPwd message must contain the current directory path, got: {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("fs-pwd-test").await?;
    Ok(())
}

/// E2E integration test: full file-download flow via `CommandFs` / `Download` callbacks.
///
/// Sequence:
/// 1. Register agent, subscribe operator WebSocket.
/// 2. Agent sends mode=0 (start): server emits `download-progress / Started`.
/// 3. Agent sends mode=1 (chunk): server emits `download-progress / InProgress`.
/// 4. Agent sends mode=2 (close, reason=0): server emits `loot-new` then `download`.
/// 5. Loot record is verified in the database.
///
/// This exercises the full reassembly → persistence → event-broadcast path that
/// the per-function unit tests in `dispatch/filesystem.rs` do not cover.
#[tokio::test]
async fn download_flow_emits_progress_loot_and_complete_events()
-> Result<(), Box<dyn std::error::Error>> {
    // This test sends 3 sequential callbacks (start/chunk/close) for the same agent.
    // Use the legacy CTR profile to avoid tracking monotonic offsets across multiple
    // callback-response cycles, which is orthogonal to the download-flow logic under test.
    let server = common::spawn_test_server(common::legacy_ctr_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("fs-download-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("fs-download-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDD01_0005_u32;
    let ctr_offset =
        common::register_legacy_agent(&client, listener_port, agent_id, KEY_E, IV_E).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)), "expected AgentNew");

    let file_id: u32 = 0x0000_0042;
    let remote_path = "C:\\Users\\operator\\Documents\\secrets.zip";
    let file_data: &[u8] = b"PK\x03\x04fake-zip-content-for-test";
    let expected_size = file_data.len() as u64;
    let request_id = 0x10_u32;

    // ── Step 1: mode=0 (start) ───────────────────────────────────────────────
    let start_payload = download_start_payload(file_id, expected_size, remote_path);
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            KEY_E,
            IV_E,
            ctr_offset,
            u32::from(DemonCommand::CommandFs),
            request_id,
            &start_payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let started_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(started_msg) = started_event else {
        panic!("expected AgentResponse for download-start, got {started_event:?}");
    };
    assert_eq!(started_msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(
        started_msg.info.extra.get("MiscType").and_then(|v| v.as_str()),
        Some("download-progress"),
        "start event must have MiscType=download-progress"
    );
    assert_eq!(
        started_msg.info.extra.get("State").and_then(|v| v.as_str()),
        Some("Started"),
        "start event must have State=Started"
    );
    assert_eq!(
        started_msg.info.extra.get("FileName").and_then(|v| v.as_str()),
        Some(remote_path),
        "start event must carry the remote path"
    );
    assert_eq!(
        started_msg.info.extra.get("FileID").and_then(|v| v.as_str()),
        Some(format!("{file_id:08X}").as_str()),
        "start event must carry the file ID"
    );

    // ── Step 2: mode=1 (chunk) ───────────────────────────────────────────────
    let chunk_payload = download_chunk_payload(file_id, file_data);
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            KEY_E,
            IV_E,
            ctr_offset,
            u32::from(DemonCommand::CommandFs),
            request_id,
            &chunk_payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let inprogress_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(inprogress_msg) = inprogress_event else {
        panic!("expected AgentResponse for download-chunk, got {inprogress_event:?}");
    };
    assert_eq!(
        inprogress_msg.info.extra.get("MiscType").and_then(|v| v.as_str()),
        Some("download-progress"),
        "chunk event must have MiscType=download-progress"
    );
    assert_eq!(
        inprogress_msg.info.extra.get("State").and_then(|v| v.as_str()),
        Some("InProgress"),
        "chunk event must have State=InProgress"
    );
    assert_eq!(
        inprogress_msg.info.extra.get("CurrentSize").and_then(|v| v.as_str()),
        Some(expected_size.to_string().as_str()),
        "chunk event CurrentSize must equal the chunk length"
    );

    // ── Step 3: mode=2 (close, reason=0 = success) ───────────────────────────
    let close_payload = download_close_payload(file_id, 0);
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            KEY_E,
            IV_E,
            ctr_offset,
            u32::from(DemonCommand::CommandFs),
            request_id,
            &close_payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // Server broadcasts loot-new then download-complete in that order.
    let loot_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(loot_msg) = loot_event else {
        panic!("expected AgentResponse for loot-new, got {loot_event:?}");
    };
    assert_eq!(
        loot_msg.info.extra.get("MiscType").and_then(|v| v.as_str()),
        Some("loot-new"),
        "first close event must have MiscType=loot-new"
    );
    assert_eq!(
        loot_msg.info.extra.get("LootKind").and_then(|v| v.as_str()),
        Some("download"),
        "loot-new event must have LootKind=download"
    );
    assert!(
        loot_msg
            .info
            .extra
            .get("LootName")
            .and_then(|v| v.as_str())
            .map(|n| n.ends_with("secrets.zip"))
            .unwrap_or(false),
        "loot-new LootName must include the filename"
    );

    let complete_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(complete_msg) = complete_event else {
        panic!("expected AgentResponse for download-complete, got {complete_event:?}");
    };
    assert_eq!(
        complete_msg.info.extra.get("MiscType").and_then(|v| v.as_str()),
        Some("download"),
        "second close event must have MiscType=download"
    );
    assert_eq!(
        complete_msg.info.extra.get("Type").and_then(|v| v.as_str()),
        Some("Good"),
        "download-complete event must have Type=Good"
    );
    assert_eq!(
        complete_msg.info.extra.get("FileName").and_then(|v| v.as_str()),
        Some(remote_path),
        "download-complete event must carry the remote path"
    );
    // MiscData carries the base64-encoded file content.
    let misc_data = complete_msg
        .info
        .extra
        .get("MiscData")
        .and_then(|v| v.as_str())
        .expect("download-complete must include MiscData");
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD.decode(misc_data)?;
    assert_eq!(decoded, file_data, "MiscData must round-trip the file bytes");

    // ── Step 4: verify persistence ───────────────────────────────────────────
    let loot_records = server.database.loot().list_for_agent(agent_id).await?;
    assert_eq!(loot_records.len(), 1, "exactly one loot record must be persisted");
    let record = &loot_records[0];
    assert_eq!(record.agent_id, agent_id);
    assert_eq!(record.kind, "download");
    assert!(
        record.name.ends_with("secrets.zip"),
        "loot record name must include the filename, got {:?}",
        record.name
    );
    assert_eq!(
        record.size_bytes,
        Some(i64::try_from(expected_size).expect("file size fits in i64")),
        "loot record size_bytes must match the transferred data length"
    );

    socket.close(None).await?;
    server.listeners.stop("fs-download-test").await?;
    Ok(())
}
