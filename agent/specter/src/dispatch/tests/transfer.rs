use std::collections::HashMap;

use red_cell_common::demon::{DemonCommand, DemonPackage};

use super::super::filesystem::{
    handle_fs_download, handle_fs_upload, handle_memfile, handle_transfer,
};
use super::super::{DispatchResult, MemFile, MemFileStore, dispatch};
use super::{le_utf16le_payload, parse_u64_le};
use crate::config::SpecterConfig;
use crate::download::{
    DOWNLOAD_MODE_OPEN, DOWNLOAD_REASON_REMOVED, DownloadState, DownloadTracker,
};
use crate::job::JobStore;
use crate::token::TokenVault;

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
