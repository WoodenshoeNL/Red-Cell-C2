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

use super::assembly::{
    handle_assembly_inline_execute, handle_assembly_list_versions, handle_inline_execute,
    handle_job, handle_ps_import,
};
use super::config::handle_config;
use super::filesystem::{handle_fs_download, handle_fs_upload, handle_memfile, handle_transfer};
use super::harvest::{
    HarvestEntry, HarvestRoots, collect_credentials_for_roots, harvest_dispatch_result,
};
use super::inject::{
    handle_inject_dll, handle_inject_shellcode, handle_proc_ppid_spoof, handle_spawn_dll,
    inject_status_response,
};
use super::kerberos::{
    handle_kerberos, handle_kerberos_klist, handle_kerberos_luid, handle_kerberos_ptt,
    handle_kerberos_purge,
};
use super::persist::{
    SPECTER_PERSIST_MARKER, SPECTER_RUN_VALUE_NAME, SPECTER_STARTUP_FILE_NAME, TestPersistGuard,
    write_text_file,
};
use super::screenshot::handle_screenshot;

mod filesystem;
mod harvest;
mod persist;
mod process;
mod sleep;
mod token;

// Re-export dispatch-internal items for submodules.
pub(super) use super::decode_utf16le_null;
pub(super) use super::filesystem::unix_secs_to_ymd_hm;
pub(super) use super::parse_bytes_le;
pub(super) use super::parse_u32_le;
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

// ── CommandTransfer tests ───────────────────────────────────────────────

/// Build a CommandTransfer payload: `[subcmd: u32 LE][args…]`
fn transfer_payload(subcmd: u32, args: &[u8]) -> Vec<u8> {
    let mut v = subcmd.to_le_bytes().to_vec();
    v.extend_from_slice(args);
    v
}

#[test]
fn transfer_list_empty_returns_subcmd_only() {
    let payload = transfer_payload(0, &[]); // List = 0
    let downloads = DownloadTracker::new();
    let result = handle_transfer(&payload, &mut { downloads });
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandTransfer));
    // Payload: just the subcommand echo (4 bytes).
    assert_eq!(resp.payload.len(), 4);
    let subcmd_echo = u32::from_le_bytes(resp.payload[0..4].try_into().expect("u32"));
    assert_eq!(subcmd_echo, 0); // List
}

#[test]
fn transfer_list_with_active_download() {
    let mut downloads = DownloadTracker::new();
    let dir = std::env::temp_dir();
    let path = dir.join(format!("specter_test_tl_{}", rand::random::<u32>()));
    std::fs::write(&path, b"data").expect("write");
    let file = std::fs::File::open(&path).expect("open");
    let file_id = downloads.add(file, 1, 4);

    let payload = transfer_payload(0, &[]);
    let result = handle_transfer(&payload, &mut downloads);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    // Payload: subcmd(4) + file_id(4) + read_size(4) + state(4) = 16 bytes
    assert_eq!(resp.payload.len(), 16);
    let listed_id = u32::from_le_bytes(resp.payload[4..8].try_into().expect("u32"));
    assert_eq!(listed_id, file_id);
    let state = u32::from_le_bytes(resp.payload[12..16].try_into().expect("u32"));
    assert_eq!(state, 1); // Running
    let _ = std::fs::remove_file(path);
}

#[test]
fn transfer_stop_found() {
    let mut downloads = DownloadTracker::new();
    let dir = std::env::temp_dir();
    let path = dir.join(format!("specter_test_ts_{}", rand::random::<u32>()));
    std::fs::write(&path, b"data").expect("write");
    let file = std::fs::File::open(&path).expect("open");
    let file_id = downloads.add(file, 1, 4);

    let payload = transfer_payload(1, &file_id.to_le_bytes());
    let result = handle_transfer(&payload, &mut downloads);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    // [subcmd(4)][found(4)][file_id(4)]
    assert_eq!(resp.payload.len(), 12);
    let found = u32::from_le_bytes(resp.payload[4..8].try_into().expect("u32"));
    assert_eq!(found, 1);
    assert_eq!(downloads.get(file_id).expect("entry").state, DownloadState::Stopped);
    let _ = std::fs::remove_file(path);
}

#[test]
fn transfer_stop_not_found() {
    let mut downloads = DownloadTracker::new();
    let payload = transfer_payload(1, &0xDEADu32.to_le_bytes());
    let result = handle_transfer(&payload, &mut downloads);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    let found = u32::from_le_bytes(resp.payload[4..8].try_into().expect("u32"));
    assert_eq!(found, 0);
}

#[test]
fn transfer_resume_found() {
    let mut downloads = DownloadTracker::new();
    let dir = std::env::temp_dir();
    let path = dir.join(format!("specter_test_tr_{}", rand::random::<u32>()));
    std::fs::write(&path, b"data").expect("write");
    let file = std::fs::File::open(&path).expect("open");
    let file_id = downloads.add(file, 1, 4);
    downloads.get_mut(file_id).expect("entry").state = DownloadState::Stopped;

    let payload = transfer_payload(2, &file_id.to_le_bytes());
    let result = handle_transfer(&payload, &mut downloads);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    let found = u32::from_le_bytes(resp.payload[4..8].try_into().expect("u32"));
    assert_eq!(found, 1);
    assert_eq!(downloads.get(file_id).expect("entry").state, DownloadState::Running);
    let _ = std::fs::remove_file(path);
}

#[test]
fn transfer_remove_found_returns_multi_respond() {
    let mut downloads = DownloadTracker::new();
    let dir = std::env::temp_dir();
    let path = dir.join(format!("specter_test_trm_{}", rand::random::<u32>()));
    std::fs::write(&path, b"data").expect("write");
    let file = std::fs::File::open(&path).expect("open");
    let file_id = downloads.add(file, 1, 4);

    let payload = transfer_payload(3, &file_id.to_le_bytes());
    let result = handle_transfer(&payload, &mut downloads);
    let DispatchResult::MultiRespond(resps) = result else {
        panic!("expected MultiRespond, got {result:?}");
    };
    assert_eq!(resps.len(), 2);
    // First: [subcmd][found=1][file_id]
    let found = u32::from_le_bytes(resps[0].payload[4..8].try_into().expect("u32"));
    assert_eq!(found, 1);
    // Second: [subcmd][file_id][reason=REMOVED(1)]
    let reason = u32::from_le_bytes(resps[1].payload[8..12].try_into().expect("u32"));
    assert_eq!(reason, DOWNLOAD_REASON_REMOVED);
    let _ = std::fs::remove_file(path);
}

#[test]
fn transfer_remove_not_found_returns_single() {
    let mut downloads = DownloadTracker::new();
    let payload = transfer_payload(3, &0xBEEFu32.to_le_bytes());
    let result = handle_transfer(&payload, &mut downloads);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    let found = u32::from_le_bytes(resp.payload[4..8].try_into().expect("u32"));
    assert_eq!(found, 0);
}

#[test]
fn transfer_unknown_subcommand_returns_ignore() {
    let mut downloads = DownloadTracker::new();
    let payload = transfer_payload(255, &[]);
    let result = handle_transfer(&payload, &mut downloads);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn transfer_empty_payload_returns_ignore() {
    let mut downloads = DownloadTracker::new();
    let result = handle_transfer(&[], &mut downloads);
    assert!(matches!(result, DispatchResult::Ignore));
}

// ── FS Download tests ───────────────────────────────────────────────────

#[test]
fn fs_download_opens_file_and_returns_open_header() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("specter_test_fsd_{}", rand::random::<u32>()));
    std::fs::write(&path, b"hello world").expect("write");

    let path_str = path.display().to_string();
    let rest = le_utf16le_payload(&path_str);
    let mut downloads = DownloadTracker::new();
    let result = handle_fs_download(2, &rest, 42, &mut downloads);

    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond, got {result:?}");
    };

    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandFs));

    // Parse the BE header: [subcmd(4)][mode(4)][file_id(4)][file_size(8)][path…]
    let payload = &resp.payload;
    let subcmd = u32::from_be_bytes(payload[0..4].try_into().expect("u32"));
    assert_eq!(subcmd, 2); // Download
    let mode = u32::from_be_bytes(payload[4..8].try_into().expect("u32"));
    assert_eq!(mode, DOWNLOAD_MODE_OPEN);
    let file_size = u64::from_be_bytes(payload[12..20].try_into().expect("u64"));
    assert_eq!(file_size, 11); // "hello world".len()

    // Download should be registered.
    assert_eq!(downloads.len(), 1);

    let _ = std::fs::remove_file(path);
}

#[test]
fn fs_download_nonexistent_file_returns_ignore() {
    let rest = le_utf16le_payload("/tmp/specter_nonexistent_file_test_12345");
    let mut downloads = DownloadTracker::new();
    let result = handle_fs_download(2, &rest, 1, &mut downloads);
    assert!(matches!(result, DispatchResult::Ignore));
    assert!(downloads.is_empty());
}

// ── FS Upload tests ─────────────────────────────────────────────────────

#[test]
fn fs_upload_writes_file_from_memfile() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("specter_test_fsu_{}", rand::random::<u32>()));
    let path_str = path.display().to_string();
    let content = b"uploaded data";
    let mem_file_id: u32 = 42;

    // Pre-stage the MemFile.
    let mut mem_files: MemFileStore = HashMap::new();
    mem_files.insert(mem_file_id, MemFile { expected_size: content.len(), data: content.to_vec() });

    // Build payload: [path: bytes LE (UTF-16LE)][mem_file_id: u32 LE]
    let mut rest = le_utf16le_payload(&path_str);
    rest.extend_from_slice(&mem_file_id.to_le_bytes());

    let result = handle_fs_upload(3, &rest, &mut mem_files);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond, got {result:?}");
    };

    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandFs));

    // Verify file was written.
    let written = std::fs::read(&path).expect("read back");
    assert_eq!(written, content);

    // Parse BE response: [subcmd(4)][file_size(4)][path…]
    let file_size = u32::from_be_bytes(resp.payload[4..8].try_into().expect("u32"));
    assert_eq!(file_size, content.len() as u32);

    // MemFile should be consumed.
    assert!(!mem_files.contains_key(&mem_file_id));

    let _ = std::fs::remove_file(path);
}

#[test]
fn fs_upload_missing_memfile_returns_ignore() {
    let mut mem_files: MemFileStore = HashMap::new();
    // Build payload: [path: bytes LE][mem_file_id: u32 LE]
    let mut rest = le_utf16le_payload("/tmp/specter_test_no_memfile");
    rest.extend_from_slice(&99u32.to_le_bytes()); // non-existent memfile ID
    let result = handle_fs_upload(3, &rest, &mut mem_files);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn fs_upload_incomplete_memfile_returns_ignore() {
    let mut mem_files: MemFileStore = HashMap::new();
    mem_files.insert(
        7,
        MemFile {
            expected_size: 100,
            data: vec![0u8; 50], // only half staged
        },
    );
    let mut rest = le_utf16le_payload("/tmp/specter_test_incomplete");
    rest.extend_from_slice(&7u32.to_le_bytes());
    let result = handle_fs_upload(3, &rest, &mut mem_files);
    assert!(matches!(result, DispatchResult::Ignore));
}

// ── MemFile tests ────────────────────────────────────────────────────────

/// Build a MemFile payload: [mem_file_id: u32 LE][total_size: u64 LE][chunk: bytes LE]
fn memfile_payload(mem_file_id: u32, total_size: u64, chunk: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&mem_file_id.to_le_bytes());
    v.extend_from_slice(&total_size.to_le_bytes());
    v.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
    v.extend_from_slice(chunk);
    v
}

#[test]
fn parse_u64_le_reads_correct_value() {
    let buf = 0x0102_0304_0506_0708u64.to_le_bytes();
    let mut offset = 0;
    assert_eq!(parse_u64_le(&buf, &mut offset).expect("parse"), 0x0102_0304_0506_0708);
    assert_eq!(offset, 8);
}

#[test]
fn parse_u64_le_too_short_returns_error() {
    let buf = [0u8; 7];
    let mut offset = 0;
    assert!(parse_u64_le(&buf, &mut offset).is_err());
}

#[test]
fn memfile_single_chunk_complete() {
    let data = b"hello world";
    let payload = memfile_payload(1, data.len() as u64, data);
    let mut store: MemFileStore = HashMap::new();

    let result = handle_memfile(&payload, 10, &mut store);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond, got {result:?}");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandMemFile));
    assert_eq!(resp.request_id, 10);
    // success = true (1)
    assert_eq!(u32::from_be_bytes(resp.payload[4..8].try_into().unwrap()), 1);

    let entry = store.get(&1).expect("memfile should exist");
    assert!(entry.is_complete());
    assert_eq!(entry.data, data);
}

#[test]
fn memfile_multi_chunk_accumulates() {
    let mut store: MemFileStore = HashMap::new();
    let total: u64 = 10;

    // First chunk: 6 bytes.
    let payload1 = memfile_payload(5, total, &[1, 2, 3, 4, 5, 6]);
    let result1 = handle_memfile(&payload1, 1, &mut store);
    assert!(matches!(result1, DispatchResult::Respond(_)));
    assert!(!store.get(&5).unwrap().is_complete());

    // Second chunk: 4 bytes — completes the file.
    let payload2 = memfile_payload(5, total, &[7, 8, 9, 10]);
    let result2 = handle_memfile(&payload2, 2, &mut store);
    assert!(matches!(result2, DispatchResult::Respond(_)));
    assert!(store.get(&5).unwrap().is_complete());
    assert_eq!(store.get(&5).unwrap().data, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
}

#[test]
fn memfile_size_mismatch_returns_failure() {
    let mut store: MemFileStore = HashMap::new();

    // First chunk declares total_size = 10.
    let payload1 = memfile_payload(3, 10, &[1, 2, 3]);
    let _ = handle_memfile(&payload1, 1, &mut store);

    // Second chunk declares total_size = 20 (mismatch).
    let payload2 = memfile_payload(3, 20, &[4, 5, 6]);
    let result = handle_memfile(&payload2, 2, &mut store);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond, got {result:?}");
    };
    // success = false (0)
    assert_eq!(u32::from_be_bytes(resp.payload[4..8].try_into().unwrap()), 0);
}

#[test]
fn memfile_truncates_overflow() {
    let mut store: MemFileStore = HashMap::new();
    // Declare total_size = 4 but send 6 bytes.
    let payload = memfile_payload(8, 4, &[1, 2, 3, 4, 5, 6]);
    let _ = handle_memfile(&payload, 1, &mut store);
    let entry = store.get(&8).unwrap();
    assert_eq!(entry.data, &[1, 2, 3, 4]);
    assert!(entry.is_complete());
}

#[test]
fn memfile_then_upload_end_to_end() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("specter_test_mfu_{}", rand::random::<u32>()));
    let path_str = path.display().to_string();
    let content = b"memfile-upload";
    let mem_id: u32 = 77;

    let mut store: MemFileStore = HashMap::new();

    // Stage the MemFile.
    let mf_payload = memfile_payload(mem_id, content.len() as u64, content);
    let _ = handle_memfile(&mf_payload, 1, &mut store);
    assert!(store.get(&mem_id).unwrap().is_complete());

    // Now issue the Upload command referencing the MemFile.
    let mut rest = le_utf16le_payload(&path_str);
    rest.extend_from_slice(&mem_id.to_le_bytes());
    let result = handle_fs_upload(3, &rest, &mut store);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond, got {result:?}");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandFs));

    // File written correctly.
    let written = std::fs::read(&path).expect("read back");
    assert_eq!(written, content);

    // MemFile consumed.
    assert!(!store.contains_key(&mem_id));

    let _ = std::fs::remove_file(path);
}

#[test]
fn dispatch_routes_command_memfile() {
    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::new();
    let mut mem_files: MemFileStore = HashMap::new();

    let payload = memfile_payload(1, 5, &[1, 2, 3, 4, 5]);
    let package = DemonPackage::new(DemonCommand::CommandMemFile, 1, payload);
    let result = dispatch(
        &package,
        &mut config,
        &mut vault,
        &mut downloads,
        &mut mem_files,
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    assert!(matches!(result, DispatchResult::Respond(_)));
    assert!(mem_files.contains_key(&1));
}

// ── dispatch routing tests for new commands ─────────────────────────────

#[test]
fn dispatch_routes_command_transfer() {
    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::new();
    let payload = transfer_payload(0, &[]); // Transfer::List
    let package = DemonPackage::new(DemonCommand::CommandTransfer, 1, payload);
    let result = dispatch(
        &package,
        &mut config,
        &mut vault,
        &mut downloads,
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    assert!(matches!(result, DispatchResult::Respond(_)));
}

// ── Process injection tests ─────────────────────────────────────────────

/// Build a `CommandProcPpidSpoof` payload: LE u32 PID.
fn ppid_spoof_payload(ppid: u32) -> Vec<u8> {
    ppid.to_le_bytes().to_vec()
}

/// Build a `CommandInjectShellcode` payload for the Inject way.
fn inject_shellcode_inject_payload(
    method: u32,
    x64: u32,
    shellcode: &[u8],
    args: &[u8],
    pid: u32,
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&u32::from(DemonInjectWay::Inject).to_le_bytes());
    v.extend_from_slice(&method.to_le_bytes());
    v.extend_from_slice(&x64.to_le_bytes());
    // shellcode (length-prefixed)
    v.extend_from_slice(&(shellcode.len() as u32).to_le_bytes());
    v.extend_from_slice(shellcode);
    // args (length-prefixed)
    v.extend_from_slice(&(args.len() as u32).to_le_bytes());
    v.extend_from_slice(args);
    // target PID
    v.extend_from_slice(&pid.to_le_bytes());
    v
}

/// Build a `CommandInjectShellcode` payload for the Spawn way (no PID).
fn inject_shellcode_spawn_payload(method: u32, x64: u32, shellcode: &[u8], args: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&u32::from(DemonInjectWay::Spawn).to_le_bytes());
    v.extend_from_slice(&method.to_le_bytes());
    v.extend_from_slice(&x64.to_le_bytes());
    v.extend_from_slice(&(shellcode.len() as u32).to_le_bytes());
    v.extend_from_slice(shellcode);
    v.extend_from_slice(&(args.len() as u32).to_le_bytes());
    v.extend_from_slice(args);
    v
}

/// Build a `CommandInjectDll` payload.
fn inject_dll_payload(
    technique: u32,
    pid: u32,
    loader: &[u8],
    dll: &[u8],
    params: &[u8],
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&technique.to_le_bytes());
    v.extend_from_slice(&pid.to_le_bytes());
    v.extend_from_slice(&(loader.len() as u32).to_le_bytes());
    v.extend_from_slice(loader);
    v.extend_from_slice(&(dll.len() as u32).to_le_bytes());
    v.extend_from_slice(dll);
    v.extend_from_slice(&(params.len() as u32).to_le_bytes());
    v.extend_from_slice(params);
    v
}

/// Build a `CommandSpawnDll` payload.
fn spawn_dll_payload(loader: &[u8], dll: &[u8], args: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&(loader.len() as u32).to_le_bytes());
    v.extend_from_slice(loader);
    v.extend_from_slice(&(dll.len() as u32).to_le_bytes());
    v.extend_from_slice(dll);
    v.extend_from_slice(&(args.len() as u32).to_le_bytes());
    v.extend_from_slice(args);
    v
}

// ── CommandProcPpidSpoof ─────────────────────────────────────────────────

#[test]
fn handle_proc_ppid_spoof_updates_config() {
    let mut config = SpecterConfig::default();
    assert!(config.ppid_spoof.is_none());

    let payload = ppid_spoof_payload(1234);
    let result = handle_proc_ppid_spoof(&payload, &mut config);

    assert_eq!(config.ppid_spoof, Some(1234));

    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond, got {result:?}");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandProcPpidSpoof));

    // Response payload: LE u32 PPID.
    assert_eq!(resp.payload.len(), 4);
    let ppid = u32::from_le_bytes(resp.payload[..4].try_into().unwrap());
    assert_eq!(ppid, 1234);
}

#[test]
fn handle_proc_ppid_spoof_empty_payload_ignores() {
    let mut config = SpecterConfig::default();
    let result = handle_proc_ppid_spoof(&[], &mut config);
    assert!(matches!(result, DispatchResult::Ignore));
    assert!(config.ppid_spoof.is_none());
}

#[test]
fn dispatch_routes_proc_ppid_spoof() {
    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::new();
    let payload = ppid_spoof_payload(5678);
    let package = DemonPackage::new(DemonCommand::CommandProcPpidSpoof, 1, payload);
    let result = dispatch(
        &package,
        &mut config,
        &mut vault,
        &mut downloads,
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    assert!(matches!(result, DispatchResult::Respond(_)));
    assert_eq!(config.ppid_spoof, Some(5678));
}

// ── CommandInjectShellcode ───────────────────────────────────────────────

#[test]
fn handle_inject_shellcode_inject_returns_response() {
    let shellcode = &[0x90, 0x90, 0xCC];
    let args = &[0x41, 0x42];
    let payload = inject_shellcode_inject_payload(0, 1, shellcode, args, 4444);
    let result = handle_inject_shellcode(&payload);

    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond, got {result:?}");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandInjectShellcode));
    assert_eq!(resp.payload.len(), 4);

    // On non-Windows: status should be Failed (1).
    if !cfg!(windows) {
        let status = u32::from_le_bytes(resp.payload[..4].try_into().unwrap());
        assert_eq!(status, u32::from(DemonInjectError::Failed));
    }
}

#[test]
fn handle_inject_shellcode_spawn_returns_response() {
    let shellcode = &[0xCC];
    let payload = inject_shellcode_spawn_payload(0, 1, shellcode, &[]);
    let result = handle_inject_shellcode(&payload);

    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond, got {result:?}");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandInjectShellcode));
    assert_eq!(resp.payload.len(), 4);
}

#[test]
fn handle_inject_shellcode_empty_payload_returns_invalid_param() {
    let result = handle_inject_shellcode(&[]);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond, got {result:?}");
    };
    let status = u32::from_le_bytes(resp.payload[..4].try_into().unwrap());
    assert_eq!(status, u32::from(DemonInjectError::InvalidParam));
}

#[test]
fn dispatch_routes_inject_shellcode() {
    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::new();
    let payload = inject_shellcode_inject_payload(0, 1, &[0x90], &[], 1234);
    let package = DemonPackage::new(DemonCommand::CommandInjectShellcode, 1, payload);
    let result = dispatch(
        &package,
        &mut config,
        &mut vault,
        &mut downloads,
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    assert!(matches!(result, DispatchResult::Respond(_)));
}

// ── CommandInjectDll ─────────────────────────────────────────────────────

#[test]
fn handle_inject_dll_returns_response() {
    let loader = &[0xCC, 0xDD, 0xEE];
    let dll = &[0x4D, 0x5A, 0x90, 0x00];
    let params = b"test-param";
    let payload = inject_dll_payload(0, 1234, loader, dll, params);
    let result = handle_inject_dll(&payload);

    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond, got {result:?}");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandInjectDll));
    assert_eq!(resp.payload.len(), 4);

    if !cfg!(windows) {
        let status = u32::from_le_bytes(resp.payload[..4].try_into().unwrap());
        assert_eq!(status, u32::from(DemonInjectError::Failed));
    }
}

#[test]
fn handle_inject_dll_empty_payload_returns_invalid_param() {
    let result = handle_inject_dll(&[]);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond, got {result:?}");
    };
    let status = u32::from_le_bytes(resp.payload[..4].try_into().unwrap());
    assert_eq!(status, u32::from(DemonInjectError::InvalidParam));
}

#[test]
fn dispatch_routes_inject_dll() {
    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::new();
    let payload = inject_dll_payload(0, 999, &[0xCC], &[0x4D, 0x5A], b"arg");
    let package = DemonPackage::new(DemonCommand::CommandInjectDll, 1, payload);
    let result = dispatch(
        &package,
        &mut config,
        &mut vault,
        &mut downloads,
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    assert!(matches!(result, DispatchResult::Respond(_)));
}

// ── CommandSpawnDll ──────────────────────────────────────────────────────

#[test]
fn handle_spawn_dll_returns_response() {
    let loader = &[0x11, 0x22, 0x33];
    let dll = &[0x4D, 0x5A];
    let args = b"spawn-args";
    let payload = spawn_dll_payload(loader, dll, args);
    let result = handle_spawn_dll(&payload);

    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond, got {result:?}");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandSpawnDll));
    assert_eq!(resp.payload.len(), 4);

    if !cfg!(windows) {
        let status = u32::from_le_bytes(resp.payload[..4].try_into().unwrap());
        assert_eq!(status, u32::from(DemonInjectError::Failed));
    }
}

#[test]
fn handle_spawn_dll_empty_payload_returns_invalid_param() {
    let result = handle_spawn_dll(&[]);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond, got {result:?}");
    };
    let status = u32::from_le_bytes(resp.payload[..4].try_into().unwrap());
    assert_eq!(status, u32::from(DemonInjectError::InvalidParam));
}

#[test]
fn dispatch_routes_spawn_dll() {
    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::new();
    let payload = spawn_dll_payload(&[0xAA], &[0xBB], b"args");
    let package = DemonPackage::new(DemonCommand::CommandSpawnDll, 1, payload);
    let result = dispatch(
        &package,
        &mut config,
        &mut vault,
        &mut downloads,
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    assert!(matches!(result, DispatchResult::Respond(_)));
}

// ── inject_status_response helper ────────────────────────────────────────

#[test]
fn inject_status_response_encodes_le() {
    let result =
        inject_status_response(DemonCommand::CommandInjectShellcode, DemonInjectError::Success);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.payload, 0u32.to_le_bytes());
}

#[test]
fn inject_status_response_failed() {
    let result = inject_status_response(DemonCommand::CommandInjectDll, DemonInjectError::Failed);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.payload, 1u32.to_le_bytes());
}

#[test]
fn inject_status_response_arch_mismatch() {
    let result = inject_status_response(
        DemonCommand::CommandSpawnDll,
        DemonInjectError::ProcessArchMismatch,
    );
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.payload, 3u32.to_le_bytes());
}

// ── Kerberos tests ─────────────────────────────────────────────────────

/// Build a Kerberos task payload with the given subcommand and extra args.
fn kerberos_payload(subcmd: u32, extra: &[u8]) -> Vec<u8> {
    let mut v = subcmd.to_le_bytes().to_vec();
    v.extend_from_slice(extra);
    v
}

#[test]
fn kerberos_dispatch_routes_to_handler() {
    let payload = kerberos_payload(0, &[]); // Luid subcommand
    let pkg = DemonPackage {
        command_id: u32::from(DemonCommand::CommandKerberos),
        request_id: 1,
        payload,
    };
    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::default();
    let mut mem_files = MemFileStore::new();
    let result = dispatch(
        &pkg,
        &mut config,
        &mut vault,
        &mut downloads,
        &mut mem_files,
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    // On non-Windows, get_luid returns error → success=FALSE.
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandKerberos));
    // Parse: [subcmd=0][success=0]
    assert!(resp.payload.len() >= 8);
    assert_eq!(u32::from_le_bytes(resp.payload[0..4].try_into().unwrap()), 0); // subcmd
    // On non-Windows, success is 0 (FALSE)
    #[cfg(not(windows))]
    assert_eq!(u32::from_le_bytes(resp.payload[4..8].try_into().unwrap()), 0);
}

#[test]
fn kerberos_luid_response_format() {
    let result = handle_kerberos_luid(0);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandKerberos));
    // Subcmd should be 0.
    assert_eq!(u32::from_le_bytes(resp.payload[0..4].try_into().unwrap()), 0);
    // On non-Windows: [subcmd=0][success=0] → 8 bytes
    #[cfg(not(windows))]
    assert_eq!(resp.payload.len(), 8);
}

#[test]
fn kerberos_klist_all_response_format() {
    // type=0 means /all
    let mut rest = Vec::new();
    rest.extend_from_slice(&0u32.to_le_bytes()); // type = 0 (/all)
    let result = handle_kerberos_klist(1, &rest);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandKerberos));
    // [subcmd=1][success=0] on non-Windows → 8 bytes
    #[cfg(not(windows))]
    assert_eq!(resp.payload.len(), 8);
    assert_eq!(u32::from_le_bytes(resp.payload[0..4].try_into().unwrap()), 1); // subcmd
}

#[test]
fn kerberos_klist_by_luid_response_format() {
    // type=1 means /luid, then a LUID value
    let mut rest = Vec::new();
    rest.extend_from_slice(&1u32.to_le_bytes()); // type = 1 (/luid)
    rest.extend_from_slice(&0x1234u32.to_le_bytes()); // target LUID
    let result = handle_kerberos_klist(1, &rest);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(u32::from_le_bytes(resp.payload[0..4].try_into().unwrap()), 1);
}

#[test]
fn kerberos_klist_missing_luid_ignored() {
    // type=1 but no LUID value → parse error → Ignore
    let rest = 1u32.to_le_bytes().to_vec(); // type = 1 (/luid), no LUID
    let result = handle_kerberos_klist(1, &rest);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn kerberos_purge_response_format() {
    let rest = 0xABCDu32.to_le_bytes().to_vec();
    let result = handle_kerberos_purge(2, &rest);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(u32::from_le_bytes(resp.payload[0..4].try_into().unwrap()), 2); // subcmd
    // On non-Windows: success = 0
    #[cfg(not(windows))]
    assert_eq!(u32::from_le_bytes(resp.payload[4..8].try_into().unwrap()), 0);
}

#[test]
fn kerberos_purge_missing_luid_ignored() {
    let result = handle_kerberos_purge(2, &[]);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn kerberos_ptt_response_format() {
    let ticket = vec![0x61, 0x82, 0x03, 0x00];
    let luid: u32 = 0x5678;
    let mut rest = Vec::new();
    // Length-prefixed ticket bytes.
    rest.extend_from_slice(&(ticket.len() as u32).to_le_bytes());
    rest.extend_from_slice(&ticket);
    rest.extend_from_slice(&luid.to_le_bytes());
    let result = handle_kerberos_ptt(3, &rest);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(u32::from_le_bytes(resp.payload[0..4].try_into().unwrap()), 3); // subcmd
    // On non-Windows: success = 0
    #[cfg(not(windows))]
    assert_eq!(u32::from_le_bytes(resp.payload[4..8].try_into().unwrap()), 0);
}

#[test]
fn kerberos_ptt_missing_ticket_ignored() {
    let result = handle_kerberos_ptt(3, &[]);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn kerberos_ptt_missing_luid_after_ticket_ignored() {
    // Valid ticket but no LUID after it.
    let mut rest = Vec::new();
    rest.extend_from_slice(&2u32.to_le_bytes()); // ticket length = 2
    rest.extend_from_slice(&[0xAA, 0xBB]); // ticket data
    // No LUID following → parse error.
    let result = handle_kerberos_ptt(3, &rest);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn kerberos_unknown_subcommand_ignored() {
    let payload = kerberos_payload(99, &[]); // invalid subcmd
    let result = handle_kerberos(&payload);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn kerberos_empty_payload_ignored() {
    let result = handle_kerberos(&[]);
    assert!(matches!(result, DispatchResult::Ignore));
}

// ── CommandConfig tests ───────────────────────────────────────────────────

/// Build a config payload: `[key: u32 LE][extra…]`
fn config_payload(key: u32, extra: &[u8]) -> Vec<u8> {
    let mut v = key.to_le_bytes().to_vec();
    v.extend_from_slice(extra);
    v
}

/// Parse a LE u32 from a response payload at the given byte offset.
fn resp_u32(payload: &[u8], byte_offset: usize) -> u32 {
    u32::from_le_bytes(payload[byte_offset..byte_offset + 4].try_into().unwrap())
}

/// Parse a LE u64 from a response payload at the given byte offset.
fn resp_u64(payload: &[u8], byte_offset: usize) -> u64 {
    u64::from_le_bytes(payload[byte_offset..byte_offset + 8].try_into().unwrap())
}

#[test]
fn config_empty_payload_ignored() {
    let mut config = SpecterConfig::default();
    let result = handle_config(&[], &mut config);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn config_unknown_key_ignored() {
    let mut config = SpecterConfig::default();
    let payload = config_payload(9999, &[]);
    let result = handle_config(&payload, &mut config);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn config_implant_verbose_sets_flag() {
    let mut config = SpecterConfig::default();
    assert!(!config.verbose);

    let extra = 1u32.to_le_bytes();
    let payload = config_payload(u32::from(DemonConfigKey::ImplantVerbose), &extra);
    let result = handle_config(&payload, &mut config);

    assert!(config.verbose);
    let DispatchResult::Respond(resp) = result else { panic!("expected Respond") };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandConfig));
    assert_eq!(resp_u32(&resp.payload, 0), u32::from(DemonConfigKey::ImplantVerbose));
    assert_eq!(resp_u32(&resp.payload, 4), 1);
}

#[test]
fn config_implant_verbose_zero_clears_flag() {
    let mut config = SpecterConfig { verbose: true, ..Default::default() };

    let extra = 0u32.to_le_bytes();
    let payload = config_payload(u32::from(DemonConfigKey::ImplantVerbose), &extra);
    handle_config(&payload, &mut config);
    assert!(!config.verbose);
}

#[test]
fn config_sleep_technique_updates() {
    let mut config = SpecterConfig::default();
    let extra = 3u32.to_le_bytes();
    let payload = config_payload(u32::from(DemonConfigKey::ImplantSleepTechnique), &extra);
    let result = handle_config(&payload, &mut config);

    assert_eq!(config.sleep_technique, 3);
    let DispatchResult::Respond(resp) = result else { panic!("expected Respond") };
    assert_eq!(resp_u32(&resp.payload, 0), u32::from(DemonConfigKey::ImplantSleepTechnique));
    assert_eq!(resp_u32(&resp.payload, 4), 3);
}

#[test]
fn config_coffee_threaded_updates() {
    let mut config = SpecterConfig::default();
    let extra = 1u32.to_le_bytes();
    let payload = config_payload(u32::from(DemonConfigKey::ImplantCoffeeThreaded), &extra);
    handle_config(&payload, &mut config);
    assert!(config.coffee_threaded);
}

#[test]
fn config_coffee_veh_updates() {
    let mut config = SpecterConfig::default();
    let extra = 1u32.to_le_bytes();
    let payload = config_payload(u32::from(DemonConfigKey::ImplantCoffeeVeh), &extra);
    handle_config(&payload, &mut config);
    assert!(config.coffee_veh);
}

#[test]
fn config_memory_alloc_updates() {
    let mut config = SpecterConfig::default();
    let extra = 42u32.to_le_bytes();
    let payload = config_payload(u32::from(DemonConfigKey::MemoryAlloc), &extra);
    let result = handle_config(&payload, &mut config);

    assert_eq!(config.memory_alloc, 42);
    let DispatchResult::Respond(resp) = result else { panic!("expected Respond") };
    assert_eq!(resp_u32(&resp.payload, 4), 42);
}

#[test]
fn config_memory_execute_updates() {
    let mut config = SpecterConfig::default();
    let extra = 7u32.to_le_bytes();
    let payload = config_payload(u32::from(DemonConfigKey::MemoryExecute), &extra);
    handle_config(&payload, &mut config);
    assert_eq!(config.memory_execute, 7);
}

#[test]
fn config_inject_technique_updates() {
    let mut config = SpecterConfig::default();
    let extra = 5u32.to_le_bytes();
    let payload = config_payload(u32::from(DemonConfigKey::InjectTechnique), &extra);
    handle_config(&payload, &mut config);
    assert_eq!(config.inject_technique, 5);
}

#[test]
fn config_killdate_sets_timestamp() {
    let mut config = SpecterConfig::default();
    let ts: u64 = 1_700_000_000;
    let extra = ts.to_le_bytes();
    let payload = config_payload(u32::from(DemonConfigKey::KillDate), &extra);
    let result = handle_config(&payload, &mut config);

    assert_eq!(config.kill_date, Some(ts as i64));
    let DispatchResult::Respond(resp) = result else { panic!("expected Respond") };
    assert_eq!(resp_u32(&resp.payload, 0), u32::from(DemonConfigKey::KillDate));
    assert_eq!(resp_u64(&resp.payload, 4), ts);
}

#[test]
fn config_killdate_zero_clears() {
    let mut config = SpecterConfig { kill_date: Some(123), ..Default::default() };
    let extra = 0u64.to_le_bytes();
    let payload = config_payload(u32::from(DemonConfigKey::KillDate), &extra);
    handle_config(&payload, &mut config);
    assert_eq!(config.kill_date, None);
}

#[test]
fn config_killdate_missing_value_ignored() {
    let mut config = SpecterConfig::default();
    let payload = config_payload(u32::from(DemonConfigKey::KillDate), &[]);
    let result = handle_config(&payload, &mut config);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn config_working_hours_updates() {
    let mut config = SpecterConfig::default();
    let extra = 0x00FF_FF00u32.to_le_bytes();
    let payload = config_payload(u32::from(DemonConfigKey::WorkingHours), &extra);
    handle_config(&payload, &mut config);
    assert_eq!(config.working_hours, Some(0x00FF_FF00u32 as i32));
}

#[test]
fn config_spf_thread_addr_updates() {
    let mut config = SpecterConfig::default();
    // Build: [key][lib_len][lib_bytes\0][func_len][func_bytes\0][offset]
    let lib = b"ntdll.dll\0";
    let func = b"RtlUserThreadStart\0";
    let mut extra = Vec::new();
    extra.extend_from_slice(&(lib.len() as u32).to_le_bytes());
    extra.extend_from_slice(lib);
    extra.extend_from_slice(&(func.len() as u32).to_le_bytes());
    extra.extend_from_slice(func);
    extra.extend_from_slice(&0x10u32.to_le_bytes());
    let payload = config_payload(u32::from(DemonConfigKey::ImplantSpfThreadStart), &extra);
    let result = handle_config(&payload, &mut config);

    assert_eq!(
        config.spf_thread_addr,
        Some(("ntdll.dll".to_string(), "RtlUserThreadStart".to_string(), 0x10))
    );
    let DispatchResult::Respond(resp) = result else { panic!("expected Respond") };
    assert_eq!(resp_u32(&resp.payload, 0), u32::from(DemonConfigKey::ImplantSpfThreadStart));
}

#[test]
fn config_inject_spoof_addr_updates() {
    let mut config = SpecterConfig::default();
    let lib = b"kernel32.dll\0";
    let func = b"CreateThread\0";
    let mut extra = Vec::new();
    extra.extend_from_slice(&(lib.len() as u32).to_le_bytes());
    extra.extend_from_slice(lib);
    extra.extend_from_slice(&(func.len() as u32).to_le_bytes());
    extra.extend_from_slice(func);
    extra.extend_from_slice(&0x20u32.to_le_bytes());
    let payload = config_payload(u32::from(DemonConfigKey::InjectSpoofAddr), &extra);
    handle_config(&payload, &mut config);

    assert_eq!(
        config.inject_spoof_addr,
        Some(("kernel32.dll".to_string(), "CreateThread".to_string(), 0x20))
    );
}

#[test]
fn config_addr_missing_function_ignored() {
    let mut config = SpecterConfig::default();
    let lib = b"ntdll.dll\0";
    let mut extra = Vec::new();
    extra.extend_from_slice(&(lib.len() as u32).to_le_bytes());
    extra.extend_from_slice(lib);
    // No function or offset follows.
    let payload = config_payload(u32::from(DemonConfigKey::ImplantSpfThreadStart), &extra);
    let result = handle_config(&payload, &mut config);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn config_spawn64_updates() {
    let mut config = SpecterConfig::default();
    // The server sends the path as length-prefixed UTF-16LE bytes.
    let path_str = "C:\\Windows\\System32\\notepad.exe";
    let utf16: Vec<u8> = path_str
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let mut extra = Vec::new();
    extra.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
    extra.extend_from_slice(&utf16);
    let payload = config_payload(u32::from(DemonConfigKey::InjectSpawn64), &extra);
    let result = handle_config(&payload, &mut config);

    assert_eq!(config.spawn64.as_deref(), Some(path_str));
    let DispatchResult::Respond(resp) = result else { panic!("expected Respond") };
    assert_eq!(resp_u32(&resp.payload, 0), u32::from(DemonConfigKey::InjectSpawn64));
}

#[test]
fn config_spawn32_updates() {
    let mut config = SpecterConfig::default();
    let path_str = "C:\\Windows\\SysWOW64\\cmd.exe";
    let utf16: Vec<u8> = path_str
        .encode_utf16()
        .chain(std::iter::once(0u16))
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let mut extra = Vec::new();
    extra.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
    extra.extend_from_slice(&utf16);
    let payload = config_payload(u32::from(DemonConfigKey::InjectSpawn32), &extra);
    handle_config(&payload, &mut config);

    assert_eq!(config.spawn32.as_deref(), Some(path_str));
}

#[test]
fn config_spawn_missing_bytes_ignored() {
    let mut config = SpecterConfig::default();
    let payload = config_payload(u32::from(DemonConfigKey::InjectSpawn64), &[]);
    let result = handle_config(&payload, &mut config);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn config_u32_missing_value_ignored() {
    let mut config = SpecterConfig::default();
    // Key with no value bytes.
    let payload = config_payload(u32::from(DemonConfigKey::MemoryAlloc), &[]);
    let result = handle_config(&payload, &mut config);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn config_dispatch_routes_correctly() {
    let extra = 1u32.to_le_bytes();
    let inner = config_payload(u32::from(DemonConfigKey::ImplantVerbose), &extra);
    let pkg = DemonPackage {
        command_id: u32::from(DemonCommand::CommandConfig),
        request_id: 42,
        payload: inner,
    };
    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::default();
    let mut mem_files = MemFileStore::new();
    let result = dispatch(
        &pkg,
        &mut config,
        &mut vault,
        &mut downloads,
        &mut mem_files,
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );

    assert!(config.verbose);
    let DispatchResult::Respond(resp) = result else { panic!("expected Respond") };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandConfig));
}

// ── CommandScreenshot (2510) ────────────────────────────────────────────

#[test]
fn screenshot_returns_respond_with_correct_command_id() {
    let result = handle_screenshot();
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandScreenshot));
}

#[test]
fn screenshot_response_starts_with_success_flag() {
    let result = handle_screenshot();
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    // On non-Windows (CI) the stub returns None → success=0.
    // On Windows the GDI call should succeed → success=1.
    assert!(resp.payload.len() >= 4, "payload must contain at least the success flag");
    let success = u32::from_le_bytes(resp.payload[..4].try_into().unwrap());
    if cfg!(windows) {
        assert_eq!(success, 1, "screenshot must succeed on Windows");
        // Verify the image bytes are present after the success flag.
        assert!(resp.payload.len() > 8, "payload must contain image data");
        let img_len = u32::from_le_bytes(resp.payload[4..8].try_into().unwrap());
        assert!(img_len > 0, "image length must be non-zero");
        assert_eq!(
            resp.payload.len(),
            8 + img_len as usize,
            "payload length must match header + image bytes"
        );
        // BMP magic: first two bytes of image data should be 'BM'.
        assert_eq!(resp.payload[8], b'B', "BMP magic byte 0");
        assert_eq!(resp.payload[9], b'M', "BMP magic byte 1");
    } else {
        assert_eq!(success, 0, "screenshot must fail on non-Windows stub");
        assert_eq!(resp.payload.len(), 4, "failure payload is just the flag");
    }
}

#[test]
fn screenshot_dispatch_routes_correctly() {
    let pkg = DemonPackage {
        command_id: u32::from(DemonCommand::CommandScreenshot),
        request_id: 99,
        payload: Vec::new(),
    };
    let mut config = SpecterConfig::default();
    let mut vault = TokenVault::new();
    let mut downloads = DownloadTracker::default();
    let mut mem_files = MemFileStore::new();
    let result = dispatch(
        &pkg,
        &mut config,
        &mut vault,
        &mut downloads,
        &mut mem_files,
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandScreenshot));
}

// ── CommandInlineExecute (20) ───────────────────────────────────────────

#[test]
fn inline_execute_short_payload_returns_could_not_run() {
    let result = handle_inline_execute(
        &[],
        1,
        &SpecterConfig::default(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandInlineExecute));
    // Payload should start with BOF_COULD_NOT_RUN (4)
    let cb_type = u32::from_le_bytes(resp.payload[0..4].try_into().expect("u32"));
    assert_eq!(cb_type, coffeeldr::BOF_COULD_NOT_RUN);
}

#[test]
fn inline_execute_missing_memfile_returns_could_not_run() {
    // Valid payload structure but memfile IDs don't exist
    let mut payload = Vec::new();
    // function_name: "go"
    let func = b"go\0";
    payload.extend_from_slice(&(func.len() as u32).to_le_bytes());
    payload.extend_from_slice(func);
    // bof_file_id
    payload.extend_from_slice(&99u32.to_le_bytes());
    // params_file_id
    payload.extend_from_slice(&100u32.to_le_bytes());
    // flags
    payload.extend_from_slice(&0u32.to_le_bytes());

    let result = handle_inline_execute(
        &payload,
        1,
        &SpecterConfig::default(),
        &mut HashMap::new(),
        &mut JobStore::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandInlineExecute));
    let cb_type = u32::from_le_bytes(resp.payload[0..4].try_into().expect("u32"));
    assert_eq!(cb_type, coffeeldr::BOF_COULD_NOT_RUN);
}

#[test]
fn inline_execute_incomplete_memfile_returns_could_not_run() {
    let mut mem_files = MemFileStore::new();
    // Insert an incomplete memfile
    mem_files.insert(1, MemFile { expected_size: 100, data: vec![0u8; 50] });

    let mut payload = Vec::new();
    let func = b"go\0";
    payload.extend_from_slice(&(func.len() as u32).to_le_bytes());
    payload.extend_from_slice(func);
    payload.extend_from_slice(&1u32.to_le_bytes()); // bof_file_id
    payload.extend_from_slice(&2u32.to_le_bytes()); // params_file_id
    payload.extend_from_slice(&0u32.to_le_bytes()); // flags

    let result = handle_inline_execute(
        &payload,
        1,
        &SpecterConfig::default(),
        &mut mem_files,
        &mut JobStore::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    let cb_type = u32::from_le_bytes(resp.payload[0..4].try_into().expect("u32"));
    assert_eq!(cb_type, coffeeldr::BOF_COULD_NOT_RUN);
    // Memfiles should be cleaned up
    assert!(!mem_files.contains_key(&1));
}

#[test]
fn inline_execute_with_valid_memfiles_attempts_execution() {
    let mut mem_files = MemFileStore::new();
    // Insert complete memfiles (garbage COFF data — execution will fail)
    mem_files.insert(1, MemFile { expected_size: 4, data: vec![0xDE, 0xAD, 0xBE, 0xEF] });
    mem_files.insert(2, MemFile { expected_size: 0, data: Vec::new() });

    let mut payload = Vec::new();
    let func = b"go\0";
    payload.extend_from_slice(&(func.len() as u32).to_le_bytes());
    payload.extend_from_slice(func);
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.extend_from_slice(&2u32.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());

    let result = handle_inline_execute(
        &payload,
        1,
        &SpecterConfig::default(),
        &mut mem_files,
        &mut JobStore::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    // Should get some kind of response (BOF_COULD_NOT_RUN on invalid COFF)
    match result {
        DispatchResult::Respond(resp) => {
            assert_eq!(resp.command_id, u32::from(DemonCommand::CommandInlineExecute));
        }
        DispatchResult::MultiRespond(resps) => {
            assert!(!resps.is_empty());
            assert_eq!(resps[0].command_id, u32::from(DemonCommand::CommandInlineExecute));
        }
        _ => panic!("expected Respond or MultiRespond"),
    }
    // Memfiles should be cleaned up
    assert!(!mem_files.contains_key(&1));
    assert!(!mem_files.contains_key(&2));
}

// ── CommandJob (21) ─────────────────────────────────────────────────────

#[test]
fn job_list_empty_store_returns_header_only() {
    let mut store = JobStore::new();
    let payload = 1u32.to_le_bytes().to_vec(); // List = 1
    let result = handle_job(&payload, &mut store);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandJob));
    // Payload: [1: u32 LE] — just the subcommand, no jobs
    assert_eq!(resp.payload.len(), 4);
    let subcmd = u32::from_le_bytes(resp.payload[0..4].try_into().expect("u32"));
    assert_eq!(subcmd, 1);
}

#[test]
fn job_list_with_jobs_includes_all_entries() {
    let mut store = JobStore::new();
    store.add(crate::job::JOB_TYPE_THREAD, 0, 0);
    store.add(crate::job::JOB_TYPE_PROCESS, 0, 0);

    let payload = 1u32.to_le_bytes().to_vec();
    let result = handle_job(&payload, &mut store);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    // Payload: [1: u32] + 2 * [job_id: u32, type: u32, state: u32] = 4 + 24 = 28
    assert_eq!(resp.payload.len(), 28);
}

#[test]
fn job_suspend_nonexistent_returns_failure() {
    let mut store = JobStore::new();
    let mut payload = Vec::new();
    payload.extend_from_slice(&2u32.to_le_bytes()); // Suspend = 2
    payload.extend_from_slice(&999u32.to_le_bytes()); // nonexistent job
    let result = handle_job(&payload, &mut store);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    // [2: u32][999: u32][0: u32 (false)]
    assert_eq!(resp.payload.len(), 12);
    let success = u32::from_le_bytes(resp.payload[8..12].try_into().expect("u32"));
    assert_eq!(success, 0);
}

#[test]
fn job_kill_existing_returns_success() {
    let mut store = JobStore::new();
    let id = store.add(crate::job::JOB_TYPE_THREAD, 0, 0);
    let mut payload = Vec::new();
    payload.extend_from_slice(&4u32.to_le_bytes()); // KillRemove = 4
    payload.extend_from_slice(&id.to_le_bytes());
    let result = handle_job(&payload, &mut store);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    let success = u32::from_le_bytes(resp.payload[8..12].try_into().expect("u32"));
    assert_eq!(success, 1);
}

#[test]
fn job_unknown_subcommand_returns_ignore() {
    let mut store = JobStore::new();
    let payload = 99u32.to_le_bytes().to_vec();
    let result = handle_job(&payload, &mut store);
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn job_short_payload_returns_ignore() {
    let mut store = JobStore::new();
    let result = handle_job(&[0x01], &mut store);
    assert!(matches!(result, DispatchResult::Ignore));
}

// ── CommandPsImport (0x1011) ────────────────────────────────────────────

#[test]
fn ps_import_stores_script_and_responds_success() {
    let mut ps_scripts = PsScriptStore::new();
    let mut mem_files = MemFileStore::new();

    // Stage script in memfile
    let script = b"Write-Host 'Hello'";
    mem_files.insert(42, MemFile { expected_size: script.len(), data: script.to_vec() });

    let payload = 42u32.to_le_bytes().to_vec(); // memfile ID
    let result = handle_ps_import(&payload, &mut ps_scripts, &mut mem_files);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandPsImport));
    assert_eq!(ps_scripts, script.to_vec());
    // Response should contain empty string (success)
    let out_len = u32::from_le_bytes(resp.payload[0..4].try_into().expect("u32"));
    assert_eq!(out_len, 0);
}

#[test]
fn ps_import_missing_memfile_uses_raw_payload() {
    let mut ps_scripts = PsScriptStore::new();
    let mut mem_files = MemFileStore::new();

    // Payload: [memfile_id: u32][raw script bytes]
    let mut payload = Vec::new();
    payload.extend_from_slice(&99u32.to_le_bytes()); // nonexistent memfile
    payload.extend_from_slice(b"Get-Process");

    let result = handle_ps_import(&payload, &mut ps_scripts, &mut mem_files);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandPsImport));
    assert_eq!(ps_scripts, b"Get-Process".to_vec());
}

#[test]
fn ps_import_empty_script_returns_error() {
    let mut ps_scripts = PsScriptStore::new();
    let mut mem_files = MemFileStore::new();
    mem_files.insert(1, MemFile { expected_size: 0, data: Vec::new() });

    let payload = 1u32.to_le_bytes().to_vec();
    let result = handle_ps_import(&payload, &mut ps_scripts, &mut mem_files);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    // Should contain non-empty error message
    let out_len = u32::from_le_bytes(resp.payload[0..4].try_into().expect("u32"));
    assert!(out_len > 0);
}

// ── CommandAssemblyInlineExecute (0x2001) ───────────────────────────────

#[test]
fn assembly_inline_execute_short_payload_returns_failed() {
    let result = handle_assembly_inline_execute(&[], &mut HashMap::new());
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandAssemblyInlineExecute));
    let info_id = u32::from_le_bytes(resp.payload[0..4].try_into().expect("u32"));
    assert_eq!(info_id, dotnet::DOTNET_INFO_FAILED);
}

#[test]
fn assembly_inline_execute_missing_memfile_returns_failed() {
    let mut mem_files = MemFileStore::new();

    // Build payload with valid wstrings but nonexistent memfile
    let mut payload = Vec::new();
    // pipe_name
    let pipe_utf16: Vec<u8> =
        "pipe".encode_utf16().chain(std::iter::once(0u16)).flat_map(|c| c.to_le_bytes()).collect();
    payload.extend_from_slice(&(pipe_utf16.len() as u32).to_le_bytes());
    payload.extend_from_slice(&pipe_utf16);
    // app_domain
    let domain_utf16: Vec<u8> =
        "dom".encode_utf16().chain(std::iter::once(0u16)).flat_map(|c| c.to_le_bytes()).collect();
    payload.extend_from_slice(&(domain_utf16.len() as u32).to_le_bytes());
    payload.extend_from_slice(&domain_utf16);
    // net_version
    let ver_utf16: Vec<u8> =
        "v4.0".encode_utf16().chain(std::iter::once(0u16)).flat_map(|c| c.to_le_bytes()).collect();
    payload.extend_from_slice(&(ver_utf16.len() as u32).to_le_bytes());
    payload.extend_from_slice(&ver_utf16);
    // memfile_id (nonexistent)
    payload.extend_from_slice(&999u32.to_le_bytes());

    let result = handle_assembly_inline_execute(&payload, &mut mem_files);
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    let info_id = u32::from_le_bytes(resp.payload[0..4].try_into().expect("u32"));
    assert_eq!(info_id, dotnet::DOTNET_INFO_FAILED);
}

// ── CommandAssemblyListVersions (0x2003) ────────────────────────────────

#[test]
fn assembly_list_versions_returns_respond() {
    let result = handle_assembly_list_versions();
    let DispatchResult::Respond(resp) = result else {
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandAssemblyListVersions));
    // On non-Windows, payload will be empty (no CLR versions)
    #[cfg(not(windows))]
    assert_eq!(resp.payload.len(), 0);
}

// ── Full dispatch routing tests for new commands ────────────────────────

#[test]
fn dispatch_routes_command_job() {
    let mut config = SpecterConfig::default();
    let payload = 1u32.to_le_bytes().to_vec(); // List
    let package = DemonPackage::new(DemonCommand::CommandJob, 1, payload);
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
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandJob));
}

#[test]
fn dispatch_routes_command_assembly_list_versions() {
    let mut config = SpecterConfig::default();
    let package = DemonPackage::new(DemonCommand::CommandAssemblyListVersions, 1, Vec::new());
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
        panic!("expected Respond");
    };
    assert_eq!(resp.command_id, u32::from(DemonCommand::CommandAssemblyListVersions));
}

// ── CommandPackageDropped ────────────────────────────────────────────────

#[test]
fn dispatch_routes_package_dropped_returns_ignore() {
    let mut config = SpecterConfig::default();
    let payload = le_u32_pair(0x20000, 0x10000); // dropped=128KB, max=64KB
    let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 42, payload);
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
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn package_dropped_marks_matching_downloads_for_removal() {
    let mut config = SpecterConfig::default();
    let mut downloads = DownloadTracker::new();

    // Create a temp file to register as a download.
    let dir = std::env::temp_dir();
    let path = dir.join(format!("specter_pkg_drop_{}", rand::random::<u32>()));
    std::fs::write(&path, b"data").expect("write temp");
    let file = std::fs::File::open(&path).expect("open temp");
    let file_id = downloads.add(file, 99, 4); // request_id=99

    let payload = le_u32_pair(0x20000, 0x10000);
    let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 99, payload);
    let result = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut downloads,
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    assert!(matches!(result, DispatchResult::Ignore));

    // The download should now be marked for removal.
    let entry = downloads.get(file_id).expect("entry should still exist before push");
    assert_eq!(entry.state, DownloadState::Remove);
    let _ = std::fs::remove_file(path);
}

#[test]
fn package_dropped_removes_matching_memfile() {
    let mut config = SpecterConfig::default();
    let mut mem_files: MemFileStore = HashMap::new();
    mem_files.insert(55, MemFile { expected_size: 1024, data: vec![0u8; 512] });

    let payload = le_u32_pair(0x20000, 0x10000);
    let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 55, payload);
    let result = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut mem_files,
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    assert!(matches!(result, DispatchResult::Ignore));
    assert!(mem_files.get(&55).is_none(), "mem-file should have been removed");
}

#[test]
fn package_dropped_ignores_short_payload() {
    let mut config = SpecterConfig::default();
    let payload = vec![0x00, 0x01, 0x00]; // only 3 bytes, not enough for two u32s
    let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 1, payload);
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
    assert!(matches!(result, DispatchResult::Ignore));
}

#[test]
fn package_dropped_does_not_affect_unrelated_downloads() {
    let mut config = SpecterConfig::default();
    let mut downloads = DownloadTracker::new();

    let dir = std::env::temp_dir();
    let path = dir.join(format!("specter_pkg_drop_unrel_{}", rand::random::<u32>()));
    std::fs::write(&path, b"data").expect("write temp");
    let file = std::fs::File::open(&path).expect("open temp");
    let file_id = downloads.add(file, 100, 4); // request_id=100

    // Package dropped for request_id=99 — should NOT affect download with request_id=100.
    let payload = le_u32_pair(0x20000, 0x10000);
    let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 99, payload);
    dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut downloads,
        &mut HashMap::new(),
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );

    let entry = downloads.get(file_id).expect("entry should exist");
    assert_eq!(entry.state, DownloadState::Running);
    let _ = std::fs::remove_file(path);
}

// ── Dispatch routing completeness ────────────────────────────────────────

#[test]
fn dispatch_routes_command_config() {
    let mut config = SpecterConfig::default();
    // Config key 0 (Sleep) + u32 value
    let mut payload = Vec::new();
    payload.extend_from_slice(&0u32.to_le_bytes()); // key = Sleep
    payload.extend_from_slice(&42u32.to_le_bytes()); // value
    let package = DemonPackage::new(DemonCommand::CommandConfig, 1, payload);
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
    // Config handler returns Ignore for most valid updates (no response ack).
    // Just verify it doesn't panic.
    let _ = result;
}

#[test]
fn dispatch_routes_command_screenshot() {
    let mut config = SpecterConfig::default();
    let package = DemonPackage::new(DemonCommand::CommandScreenshot, 1, vec![]);
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
    assert!(matches!(result, DispatchResult::Respond(_)));
}

#[test]
fn dispatch_routes_command_kerberos() {
    let mut config = SpecterConfig::default();
    // Kerberos subcommand 0 = Luid
    let payload = le_subcmd(0);
    let package = DemonPackage::new(DemonCommand::CommandKerberos, 1, payload);
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
    assert!(matches!(result, DispatchResult::Respond(_)));
}

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

// ── handle_ps_import edge cases ──────────────────────────────────────────

#[test]
fn ps_import_accumulates_across_multiple_imports() {
    let mut config = SpecterConfig::default();
    let mut ps_scripts = Vec::new();
    let mut mem_files: MemFileStore = HashMap::new();

    // First import
    let script1 = b"function Get-Foo { 'foo' }\n";
    let mut payload1 = (script1.len() as u32).to_le_bytes().to_vec();
    payload1.extend_from_slice(script1);
    let package1 = DemonPackage::new(DemonCommand::CommandPsImport, 1, payload1);
    let _ = dispatch(
        &package1,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut mem_files,
        &mut JobStore::new(),
        &mut ps_scripts,
        &crate::coffeeldr::new_bof_output_queue(),
    );
    assert_eq!(ps_scripts.len(), script1.len());

    // Second import — should replace (not accumulate).
    let script2 = b"function Get-Bar { 'bar' }\n";
    let mut payload2 = (script2.len() as u32).to_le_bytes().to_vec();
    payload2.extend_from_slice(script2);
    let package2 = DemonPackage::new(DemonCommand::CommandPsImport, 2, payload2);
    let _ = dispatch(
        &package2,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut mem_files,
        &mut JobStore::new(),
        &mut ps_scripts,
        &crate::coffeeldr::new_bof_output_queue(),
    );
    // After second import, the stored script should be the second one.
    assert_eq!(ps_scripts.len(), script2.len());
}

// ── handle_memfile edge cases ────────────────────────────────────────────

#[test]
fn memfile_zero_size_completes_immediately() {
    let mut config = SpecterConfig::default();
    let mut mem_files: MemFileStore = HashMap::new();

    // Send a memfile with expected_size=0 and empty data.
    let mut payload = Vec::new();
    payload.extend_from_slice(&1u32.to_le_bytes()); // file_id = 1
    payload.extend_from_slice(&0u64.to_le_bytes()); // expected_size = 0 (u64)
    payload.extend_from_slice(&0u32.to_le_bytes()); // chunk_len = 0
    let package = DemonPackage::new(DemonCommand::CommandMemFile, 1, payload);
    let result = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut mem_files,
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    // Zero-size memfile should return an ack response and be stored.
    assert!(matches!(result, DispatchResult::Respond(_)));
    assert!(mem_files.contains_key(&1));
}

#[test]
fn memfile_oversized_total_size_is_rejected() {
    let mut config = SpecterConfig::default();
    let mut mem_files: MemFileStore = HashMap::new();

    // total_size just above the 100 MiB cap → must be rejected without allocation.
    let oversized: u64 = 100 * 1024 * 1024 + 1;
    let mut payload = Vec::new();
    payload.extend_from_slice(&42u32.to_le_bytes()); // file_id = 42
    payload.extend_from_slice(&oversized.to_le_bytes()); // total_size > MAX
    payload.extend_from_slice(&0u32.to_le_bytes()); // chunk_len = 0 (irrelevant)
    let package = DemonPackage::new(DemonCommand::CommandMemFile, 1, payload);
    let result = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut mem_files,
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    // Oversized → failure ack, entry must NOT be inserted.
    assert!(matches!(result, DispatchResult::Respond(_)));
    assert!(!mem_files.contains_key(&42), "oversized memfile must not be stored");
}

#[test]
fn memfile_at_exact_size_limit_is_accepted() {
    let mut config = SpecterConfig::default();
    let mut mem_files: MemFileStore = HashMap::new();

    // total_size exactly at the 100 MiB cap → must be accepted.
    let max: u64 = 100 * 1024 * 1024;
    let mut payload = Vec::new();
    payload.extend_from_slice(&7u32.to_le_bytes()); // file_id = 7
    payload.extend_from_slice(&max.to_le_bytes()); // total_size == MAX
    payload.extend_from_slice(&0u32.to_le_bytes()); // chunk_len = 0
    let package = DemonPackage::new(DemonCommand::CommandMemFile, 1, payload);
    let result = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut mem_files,
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    assert!(matches!(result, DispatchResult::Respond(_)));
    assert!(mem_files.contains_key(&7), "memfile at exact limit must be accepted");
}

// ── handle_inline_execute edge cases ─────────────────────────────────────

#[test]
fn dispatch_routes_command_inline_execute() {
    let mut config = SpecterConfig::default();
    // Minimal payload that will fail parsing (too short).
    let package = DemonPackage::new(DemonCommand::CommandInlineExecute, 1, vec![0x00]);
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
    // Short payload → returns CouldNotRun response.
    assert!(matches!(result, DispatchResult::Respond(_)));
}

/// Build a minimal InlineExecute payload with the given `flags` value.
///
/// Does NOT insert a BOF memfile — the handler will return CouldNotRun
/// when the memfile is missing.  Used to test error-path behaviour.
fn inline_execute_payload_no_memfile(flags: i32) -> Vec<u8> {
    let mut payload = Vec::new();
    let func = b"go\0";
    payload.extend_from_slice(&(func.len() as u32).to_le_bytes());
    payload.extend_from_slice(func);
    payload.extend_from_slice(&1u32.to_le_bytes()); // bof_file_id = 1 (absent)
    payload.extend_from_slice(&2u32.to_le_bytes()); // params_file_id = 2
    payload.extend_from_slice(&flags.to_le_bytes());
    payload
}

/// Insert a complete BOF memfile into `mem_files` by dispatching a
/// `CommandMemFile` packet.
fn insert_complete_memfile(mem_files: &mut MemFileStore, file_id: u32, data: Vec<u8>) {
    let mut config = SpecterConfig::default();
    let mut payload = Vec::new();
    payload.extend_from_slice(&file_id.to_le_bytes());
    payload.extend_from_slice(&(data.len() as u64).to_le_bytes());
    payload.extend_from_slice(&(data.len() as u32).to_le_bytes());
    payload.extend_from_slice(&data);
    let pkg = DemonPackage::new(DemonCommand::CommandMemFile, 1, payload);
    let _ = dispatch(
        &pkg,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        mem_files,
        &mut JobStore::new(),
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
}

#[test]
fn inline_execute_threaded_missing_bof_returns_could_not_run() {
    // When the BOF memfile is absent, threaded mode still returns an error
    // and registers no job in the store.
    let mut config = SpecterConfig::default();
    let mut mem_files: MemFileStore = HashMap::new();
    let mut job_store = JobStore::new();

    let package = DemonPackage::new(
        DemonCommand::CommandInlineExecute,
        1,
        inline_execute_payload_no_memfile(1), // flags=1 → threaded
    );
    let result = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut mem_files,
        &mut job_store,
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    assert!(matches!(result, DispatchResult::Respond(_)));
    assert_eq!(job_store.list().count(), 0, "no job should be registered on error");
}

#[test]
fn inline_execute_nonthreaded_does_not_register_job() {
    // flags=0 (sync) with a garbage BOF: runs sync, returns BOF_COULD_NOT_RUN,
    // and leaves the job store empty.
    let mut config = SpecterConfig::default();
    let mut mem_files: MemFileStore = HashMap::new();
    let mut job_store = JobStore::new();

    insert_complete_memfile(&mut mem_files, 10, vec![0xDE, 0xAD]); // garbage COFF

    let mut payload = Vec::new();
    let func = b"go\0";
    payload.extend_from_slice(&(func.len() as u32).to_le_bytes());
    payload.extend_from_slice(func);
    payload.extend_from_slice(&10u32.to_le_bytes()); // bof_file_id = 10
    payload.extend_from_slice(&11u32.to_le_bytes()); // params_file_id = 11 (absent → empty)
    payload.extend_from_slice(&0i32.to_le_bytes()); // flags = 0 → non-threaded

    let package = DemonPackage::new(DemonCommand::CommandInlineExecute, 1, payload);
    let result = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut mem_files,
        &mut job_store,
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    assert!(matches!(result, DispatchResult::Respond(_)));
    assert_eq!(job_store.list().count(), 0, "sync BOF must not register a job");
}

#[cfg(not(windows))]
#[test]
fn inline_execute_threaded_non_windows_falls_back_to_sync() {
    // On non-Windows the threaded path is a no-op stub; execution falls
    // back to sync, returns BOF_COULD_NOT_RUN, and no job is registered.
    let mut config = SpecterConfig::default();
    let mut mem_files: MemFileStore = HashMap::new();
    let mut job_store = JobStore::new();

    insert_complete_memfile(&mut mem_files, 20, vec![0xDE, 0xAD]); // garbage COFF

    let mut payload = Vec::new();
    let func = b"go\0";
    payload.extend_from_slice(&(func.len() as u32).to_le_bytes());
    payload.extend_from_slice(func);
    payload.extend_from_slice(&20u32.to_le_bytes()); // bof_file_id = 20
    payload.extend_from_slice(&21u32.to_le_bytes()); // params_file_id = 21 (absent → empty)
    payload.extend_from_slice(&1i32.to_le_bytes()); // flags = 1 → threaded

    let package = DemonPackage::new(DemonCommand::CommandInlineExecute, 1, payload);
    let result = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut mem_files,
        &mut job_store,
        &mut Vec::new(),
        &crate::coffeeldr::new_bof_output_queue(),
    );
    // Non-Windows sync fallback → returns BOF_COULD_NOT_RUN response
    assert!(matches!(result, DispatchResult::Respond(_)));
    // No job registered — threaded BOF unsupported on non-Windows
    assert_eq!(job_store.list().count(), 0);
}

#[cfg(not(windows))]
#[test]
fn inline_execute_threaded_non_windows_output_queue_stays_empty() {
    // On non-Windows the threaded stub returns None, so no callbacks should
    // appear in the output queue — the sync fallback produces an immediate
    // response instead.
    let mut config = SpecterConfig::default();
    let mut mem_files: MemFileStore = HashMap::new();
    let mut job_store = JobStore::new();
    let queue = crate::coffeeldr::new_bof_output_queue();

    insert_complete_memfile(&mut mem_files, 30, vec![0xDE, 0xAD]);

    let mut payload = Vec::new();
    let func = b"go\0";
    payload.extend_from_slice(&(func.len() as u32).to_le_bytes());
    payload.extend_from_slice(func);
    payload.extend_from_slice(&30u32.to_le_bytes());
    payload.extend_from_slice(&31u32.to_le_bytes());
    payload.extend_from_slice(&1i32.to_le_bytes()); // flags = 1 → threaded

    let package = DemonPackage::new(DemonCommand::CommandInlineExecute, 1, payload);
    let result = dispatch(
        &package,
        &mut config,
        &mut TokenVault::new(),
        &mut DownloadTracker::new(),
        &mut mem_files,
        &mut job_store,
        &mut Vec::new(),
        &queue,
    );
    // Sync fallback returns a response
    assert!(matches!(result, DispatchResult::Respond(_)));
    // Queue must remain empty — no threaded execution occurred
    assert!(queue.lock().expect("lock").is_empty());
}

#[test]
fn dispatch_routes_command_ps_import() {
    let mut config = SpecterConfig::default();
    // Empty script (0-length).
    let payload = 0u32.to_le_bytes().to_vec();
    let package = DemonPackage::new(DemonCommand::CommandPsImport, 1, payload);
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
    // Empty script returns error response.
    assert!(matches!(result, DispatchResult::Respond(_)));
}

#[test]
fn dispatch_routes_command_assembly_inline_execute() {
    let mut config = SpecterConfig::default();
    let package = DemonPackage::new(DemonCommand::CommandAssemblyInlineExecute, 1, vec![0x00]);
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
    // Short payload → returns error response.
    assert!(matches!(result, DispatchResult::Respond(_)));
}
