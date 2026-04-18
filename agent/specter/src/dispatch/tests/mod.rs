use super::*;
use crate::download::{DOWNLOAD_MODE_OPEN, DOWNLOAD_REASON_REMOVED, DownloadState};
use red_cell_common::demon::{
    DemonConfigKey, DemonInjectError, DemonInjectWay, DemonNetCommand, PhantomPersistOp,
};

use std::path::PathBuf;

use crate::coffeeldr;
use crate::dotnet;
use red_cell_common::demon::{
    DemonFilesystemCommand, DemonPackage, DemonProcessCommand, DemonTokenCommand,
};

use super::harvest::{
    HarvestEntry, HarvestRoots, collect_credentials_for_roots, harvest_dispatch_result,
};
use super::persist::{
    SPECTER_PERSIST_MARKER, SPECTER_RUN_VALUE_NAME, SPECTER_STARTUP_FILE_NAME, TestPersistGuard,
    write_text_file,
};

mod assembly;
mod config;
mod filesystem;
mod harvest;
mod inject;
mod kerberos;
mod persist;
mod process;
mod screenshot;
mod sleep;
mod token;
mod transfer;

// Re-export dispatch-internal items for submodules.
pub(super) use super::decode_utf16le_null;
pub(super) use super::filesystem::unix_secs_to_ymd_hm;
pub(super) use super::parse_bytes_le;
pub(super) use super::parse_u32_le;
pub(super) use super::parse_u64_le;
pub(super) use super::process::{arch_from_wow64, translate_to_shell_cmd};
pub(super) use super::write_ptr_be;
pub(super) use super::write_ptr_le;

// ── Helpers ──────────────────────────────────────────────────────────────

/// Build a LE-encoded u32 + u32 payload (used for CommandSleep tests).
pub(super) fn le_u32_pair(a: u32, b: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&a.to_le_bytes());
    v.extend_from_slice(&b.to_le_bytes());
    v
}

/// Build a LE-encoded payload with a single u32 subcommand (for CommandFs/Proc).
pub(super) fn le_subcmd(subcmd: u32) -> Vec<u8> {
    subcmd.to_le_bytes().to_vec()
}

/// Build a LE length-prefixed UTF-16LE byte payload for a string.
pub(super) fn le_utf16le_payload(s: &str) -> Vec<u8> {
    let utf16: Vec<u8> =
        s.encode_utf16().chain(std::iter::once(0u16)).flat_map(|c| c.to_le_bytes()).collect();
    let mut v = Vec::new();
    v.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
    v.extend_from_slice(&utf16);
    v
}

/// Build a full Dir request payload (LE-encoded, matching the teamserver write order).
#[allow(clippy::too_many_arguments)]
pub(super) fn dir_request_payload(
    path: &str,
    subdirs: bool,
    files_only: bool,
    dirs_only: bool,
    list_only: bool,
    starts: &str,
    contains: &str,
    ends: &str,
) -> Vec<u8> {
    let mut v = le_subcmd(1); // Dir = 1
    v.extend_from_slice(&0u32.to_le_bytes()); // file_explorer = false
    v.extend_from_slice(&le_utf16le_payload(path));
    v.extend_from_slice(&(subdirs as u32).to_le_bytes());
    v.extend_from_slice(&(files_only as u32).to_le_bytes());
    v.extend_from_slice(&(dirs_only as u32).to_le_bytes());
    v.extend_from_slice(&(list_only as u32).to_le_bytes());
    v.extend_from_slice(&le_utf16le_payload(starts));
    v.extend_from_slice(&le_utf16le_payload(contains));
    v.extend_from_slice(&le_utf16le_payload(ends));
    v
}

pub(super) fn persist_payload(method: u32, op: u32, command: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&method.to_le_bytes());
    payload.extend_from_slice(&op.to_le_bytes());
    if op == u32::from(PhantomPersistOp::Install) {
        payload.extend_from_slice(&(command.len() as u32).to_le_bytes());
        payload.extend_from_slice(command.as_bytes());
    }
    payload
}

pub(super) fn decode_command_output_text(payload: &[u8]) -> String {
    let len = u32::from_le_bytes(payload[0..4].try_into().expect("u32 length")) as usize;
    String::from_utf8(payload[4..4 + len].to_vec()).expect("utf8 payload")
}

pub(super) fn decode_error_text(payload: &[u8]) -> String {
    let callback_type = u32::from_le_bytes(payload[0..4].try_into().expect("callback type"));
    assert_eq!(callback_type, u32::from(DemonCallback::ErrorMessage));
    let len = u32::from_le_bytes(payload[4..8].try_into().expect("u32 length")) as usize;
    String::from_utf8(payload[8..8 + len].to_vec()).expect("utf8 payload")
}

pub(super) fn harvest_expected_payload(entries: &[(&str, &str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (kind, path, data) in entries {
        buf.extend_from_slice(&(kind.len() as u32).to_le_bytes());
        buf.extend_from_slice(kind.as_bytes());
        buf.extend_from_slice(&(path.len() as u32).to_le_bytes());
        buf.extend_from_slice(path.as_bytes());
        buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
        buf.extend_from_slice(data);
    }
    buf
}

pub(super) fn make_test_persist_dir(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("{prefix}_{}", rand::random::<u32>()));
    std::fs::create_dir_all(&dir).expect("create temp persist dir");
    dir
}

// ── parse_u32_le ─────────────────────────────────────────────────────────

#[test]
fn parse_u32_le_reads_correct_value() {
    let buf = [0x01, 0x00, 0x00, 0x00]; // 1 in LE
    let mut offset = 0;
    assert_eq!(parse_u32_le(&buf, &mut offset).expect("parse"), 1);
    assert_eq!(offset, 4);
}

#[test]
fn parse_u32_le_advances_offset() {
    let buf = [0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00];
    let mut offset = 0;
    assert_eq!(parse_u32_le(&buf, &mut offset).expect("first"), 1);
    assert_eq!(parse_u32_le(&buf, &mut offset).expect("second"), 2);
}

#[test]
fn parse_u32_le_short_buffer_returns_err() {
    let buf = [0x01, 0x00, 0x00]; // only 3 bytes
    let mut offset = 0;
    assert!(parse_u32_le(&buf, &mut offset).is_err());
}

// ── parse_bytes_le ───────────────────────────────────────────────────────

#[test]
fn parse_bytes_le_reads_length_prefixed_slice() {
    let data: &[u8] = &[0xAA, 0xBB];
    let mut buf = (data.len() as u32).to_le_bytes().to_vec();
    buf.extend_from_slice(data);
    let mut offset = 0;
    let result = parse_bytes_le(&buf, &mut offset).expect("parse");
    assert_eq!(result, data);
    assert_eq!(offset, 6);
}

#[test]
fn parse_bytes_le_empty_payload_is_ok() {
    let buf = 0u32.to_le_bytes();
    let mut offset = 0;
    let result = parse_bytes_le(&buf, &mut offset).expect("parse");
    assert!(result.is_empty());
}

// ── decode_utf16le_null ──────────────────────────────────────────────────

#[test]
fn decode_utf16le_null_strips_null_terminator() {
    // "Hi\0" encoded as UTF-16LE
    let encoded: Vec<u8> = "Hi\0".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    assert_eq!(decode_utf16le_null(&encoded), "Hi");
}

#[test]
fn decode_utf16le_null_handles_empty_slice() {
    assert_eq!(decode_utf16le_null(&[]), "");
}

// ── write_utf16le_be ─────────────────────────────────────────────────────

#[test]
fn write_utf16le_be_roundtrips_ascii_string() {
    let s = "hello";
    let mut buf = Vec::new();
    write_utf16le_be(&mut buf, s);

    // First 4 bytes: BE length of UTF-16LE bytes (including null terminator)
    // "hello\0" → 6 UTF-16 code units × 2 bytes = 12 bytes
    let len = u32::from_be_bytes(buf[0..4].try_into().expect("len"));
    assert_eq!(len, 12); // 5 chars + NUL = 6 × 2

    let decoded = decode_utf16le_null(&buf[4..]);
    assert_eq!(decoded, s);
}

// ── write_utf16le ────────────────────────────────────────────────────────

#[test]
fn write_utf16le_roundtrips_ascii_string() {
    let s = "hello";
    let mut buf = Vec::new();
    write_utf16le(&mut buf, s);

    // First 4 bytes: LE length of UTF-16LE bytes (including null terminator)
    // "hello\0" → 6 UTF-16 code units × 2 bytes = 12 bytes
    let len = u32::from_le_bytes(buf[0..4].try_into().expect("len"));
    assert_eq!(len, 12); // 5 chars + NUL = 6 × 2

    let decoded = decode_utf16le_null(&buf[4..]);
    assert_eq!(decoded, s);
}

// ── Dispatch routing completeness ────────────────────────────────────────

#[test]
fn dispatch_routes_command_output_returns_ignore() {
    let mut config = SpecterConfig::default();
    let package = DemonPackage::new(DemonCommand::CommandOutput, 1, vec![0xAA]);
    let result = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    assert!(matches!(result, DispatchResult::Ignore), "CommandOutput from server must be ignored");
}

#[test]
fn dispatch_routes_beacon_output_returns_ignore() {
    let mut config = SpecterConfig::default();
    let package = DemonPackage::new(DemonCommand::BeaconOutput, 1, vec![0xBB]);
    let result = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    assert!(matches!(result, DispatchResult::Ignore), "BeaconOutput from server must be ignored");
}

#[test]
fn dispatch_routes_command_get_job_returns_ignore() {
    let mut config = SpecterConfig::default();
    let package = DemonPackage::new(DemonCommand::CommandGetJob, 1, vec![]);
    let result = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    assert!(matches!(result, DispatchResult::Ignore), "CommandGetJob from server must be ignored");
}

// ── CommandPivot is handled outside dispatch() ─────────────────────────────

#[test]
fn dispatch_command_pivot_returns_ignore() {
    // CommandPivot is intercepted by the agent run-loop (agent.rs) before
    // dispatch() is called and routed to PivotState::handle_command().
    // If it somehow reaches dispatch(), it should be safely ignored.
    let mut config = SpecterConfig::default();
    let package = DemonPackage::new(DemonCommand::CommandPivot, 42, vec![]);
    let result = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    assert!(
        matches!(result, DispatchResult::Ignore),
        "CommandPivot must be Ignore in dispatch — it is handled in agent.rs"
    );
}

// ── unimplemented command error response ─────────────────────────────────

#[test]
fn dispatch_unhandled_command_returns_beacon_output_error_message() {
    // DemonInfo is a server-side-only identifier — it falls into the `_` arm.
    let mut config = SpecterConfig::default();
    let package = DemonPackage::new(DemonCommand::DemonInfo, 42, vec![]);
    let result = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond, got something else — operator task would hang forever");
    };
    assert_eq!(
        resp.command_id,
        u32::from(DemonCommand::BeaconOutput),
        "unimplemented command response must use BeaconOutput"
    );
    // First u32 LE in payload must be DemonCallback::ErrorMessage (0x0d).
    let callback_type =
        u32::from_le_bytes(resp.payload[0..4].try_into().expect("callback type u32"));
    assert_eq!(
        callback_type,
        u32::from(DemonCallback::ErrorMessage),
        "callback type must be ErrorMessage (0x0d)"
    );
    // The text payload must mention the command name.
    let text_len =
        u32::from_le_bytes(resp.payload[4..8].try_into().expect("text len u32")) as usize;
    let text = std::str::from_utf8(&resp.payload[8..8 + text_len]).expect("utf8 text");
    assert!(
        text.contains("specter does not implement"),
        "error text must mention 'specter does not implement', got: {text:?}"
    );
    assert!(text.contains("DemonInfo"), "error text must include the command name, got: {text:?}");
}
