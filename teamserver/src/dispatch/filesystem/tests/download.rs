//! Download-specific tests for `handle_filesystem_callback`.
//!
//! Covers payload parsers (`parse_file_*`), the `DownloadTracker` state machine
//! via the Download subcommand, operator event shape, and loot persistence.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell_common::demon::{DemonCommand, DemonFilesystemCommand};
use red_cell_common::operator::OperatorMessage;
use tokio::time::{Duration, timeout};

use crate::AgentRegistry;
use crate::Database;
use crate::dispatch::{DownloadState, DownloadTracker, LootContext};

use super::super::CommandDispatchError;
use super::super::download::{
    download_complete_event, download_progress_event, parse_file_chunk, parse_file_close,
    parse_file_open_header, persist_download,
};
use super::super::handle_filesystem_callback;

use super::{add_u32_le, add_u64_le, add_utf16_le, dir_test_deps, stub_agent};

const CMD_ID: u32 = 0x1234;

#[test]
fn parse_file_open_header_happy_path() {
    // file_id = 7 (BE), size = 1024 (BE), path = "C:\flag.txt"
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&7u32.to_be_bytes());
    bytes.extend_from_slice(&1024u32.to_be_bytes());
    bytes.extend_from_slice(b"C:\\flag.txt");

    let (file_id, size, path) = parse_file_open_header(CMD_ID, &bytes).expect("unwrap");
    assert_eq!(file_id, 7);
    assert_eq!(size, 1024);
    assert_eq!(path, "C:\\flag.txt");
}

#[test]
fn parse_file_open_header_strips_null_terminator() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(b"path\0");

    let (_, _, path) = parse_file_open_header(CMD_ID, &bytes).expect("unwrap");
    assert_eq!(path, "path");
}

#[test]
fn parse_file_open_header_empty_path() {
    // Exactly 8 bytes — no path bytes at all
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&42u32.to_be_bytes());
    bytes.extend_from_slice(&99u32.to_be_bytes());

    let (file_id, size, path) = parse_file_open_header(CMD_ID, &bytes).expect("unwrap");
    assert_eq!(file_id, 42);
    assert_eq!(size, 99);
    assert_eq!(path, "");
}

#[test]
fn parse_file_open_header_too_short_returns_error() {
    let bytes = [0u8; 7];
    let err = parse_file_open_header(CMD_ID, &bytes).expect_err("expected Err");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[test]
fn parse_file_open_header_empty_slice_returns_error() {
    let err = parse_file_open_header(CMD_ID, &[]).expect_err("expected Err");
    assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }));
}

// parse_file_chunk tests

#[test]
fn parse_file_chunk_happy_path() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&5u32.to_be_bytes());
    bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    let (file_id, chunk) = parse_file_chunk(CMD_ID, &bytes).expect("unwrap");
    assert_eq!(file_id, 5);
    assert_eq!(chunk, &[0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn parse_file_chunk_empty_chunk_data() {
    // Exactly 4 bytes — file_id only, empty chunk
    let bytes = 3u32.to_be_bytes();
    let (file_id, chunk) = parse_file_chunk(CMD_ID, &bytes).expect("unwrap");
    assert_eq!(file_id, 3);
    assert!(chunk.is_empty());
}

#[test]
fn parse_file_chunk_too_short_returns_error() {
    let bytes = [0u8; 3];
    let err = parse_file_chunk(CMD_ID, &bytes).expect_err("expected Err");
    assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }));
}

#[test]
fn parse_file_chunk_empty_slice_returns_error() {
    let err = parse_file_chunk(CMD_ID, &[]).expect_err("expected Err");
    assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }));
}

// parse_file_close tests

#[test]
fn parse_file_close_happy_path() {
    let bytes = 0xDEAD_u32.to_be_bytes();
    let file_id = parse_file_close(CMD_ID, &bytes).expect("unwrap");
    assert_eq!(file_id, 0xDEAD);
}

#[test]
fn parse_file_close_extra_bytes_ignored() {
    // More than 4 bytes is fine — only first 4 matter
    let mut bytes = 0x0000_0001u32.to_be_bytes().to_vec();
    bytes.extend_from_slice(&[0xFF, 0xFF]);
    let file_id = parse_file_close(CMD_ID, &bytes).expect("unwrap");
    assert_eq!(file_id, 1);
}

#[test]
fn parse_file_close_too_short_returns_error() {
    let bytes = [0u8; 3];
    let err = parse_file_close(CMD_ID, &bytes).expect_err("expected Err");
    assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }));
}

#[test]
fn parse_file_close_empty_slice_returns_error() {
    let err = parse_file_close(CMD_ID, &[]).expect_err("expected Err");
    assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }));
}

// DownloadTracker out-of-order state machine tests

fn sample_download_state() -> DownloadState {
    DownloadState {
        request_id: 1,
        remote_path: "C:\\loot\\flag.txt".to_owned(),
        expected_size: 1024,
        data: Vec::new(),
        started_at: "2026-03-17T00:00:00Z".to_owned(),
    }
}

#[tokio::test]
async fn append_without_start_returns_error() {
    let tracker = DownloadTracker::new(1024 * 1024);
    let agent_id = 0xAAAA_BBBB;
    let file_id = 42;

    let err = tracker.append(agent_id, file_id, b"chunk data").await.expect_err("expected Err");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload for append without start, got {err:?}"
    );
}

#[tokio::test]
async fn finish_without_start_returns_none() {
    let tracker = DownloadTracker::new(1024 * 1024);
    let agent_id = 0xAAAA_BBBB;
    let file_id = 42;

    let result = tracker.finish(agent_id, file_id).await;
    assert!(result.is_none(), "finish without start should return None");
}

#[tokio::test]
async fn finish_after_start_returns_state() {
    let tracker = DownloadTracker::new(1024 * 1024);
    let agent_id = 0x1234_5678;
    let file_id = 7;
    let state = sample_download_state();

    tracker.start(agent_id, file_id, state.clone()).await.expect("start should succeed");
    let finished = tracker.finish(agent_id, file_id).await;
    assert_eq!(finished, Some(state));
}

#[tokio::test]
async fn double_finish_returns_none_on_second_call() {
    let tracker = DownloadTracker::new(1024 * 1024);
    let agent_id = 0x1234_5678;
    let file_id = 7;

    tracker.start(agent_id, file_id, sample_download_state()).await.expect("start should succeed");
    let first = tracker.finish(agent_id, file_id).await;
    assert!(first.is_some());

    let second = tracker.finish(agent_id, file_id).await;
    assert!(second.is_none(), "second finish should return None after state was consumed");
}

#[tokio::test]
async fn append_after_finish_returns_error() {
    let tracker = DownloadTracker::new(1024 * 1024);
    let agent_id = 0x1234_5678;
    let file_id = 7;

    tracker.start(agent_id, file_id, sample_download_state()).await.expect("start should succeed");
    let _ = tracker.finish(agent_id, file_id).await;

    let err = tracker.append(agent_id, file_id, b"late chunk").await.expect_err("expected Err");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "append after finish should fail, got {err:?}"
    );
}

#[tokio::test]
async fn finish_wrong_agent_returns_none() {
    let tracker = DownloadTracker::new(1024 * 1024);
    let agent_id = 0x1111_1111;
    let wrong_agent = 0x2222_2222;
    let file_id = 1;

    tracker.start(agent_id, file_id, sample_download_state()).await.expect("start should succeed");
    let result = tracker.finish(wrong_agent, file_id).await;
    assert!(result.is_none(), "finish with wrong agent_id should return None");
}

#[tokio::test]
async fn finish_wrong_file_id_returns_none() {
    let tracker = DownloadTracker::new(1024 * 1024);
    let agent_id = 0x1111_1111;
    let file_id = 1;
    let wrong_file_id = 99;

    tracker.start(agent_id, file_id, sample_download_state()).await.expect("start should succeed");
    let result = tracker.finish(agent_id, wrong_file_id).await;
    assert!(result.is_none(), "finish with wrong file_id should return None");
}

#[tokio::test]
async fn buffered_bytes_cleared_after_finish_without_start() {
    let tracker = DownloadTracker::new(1024 * 1024);
    // Calling finish on non-existent download should not affect buffered bytes.
    let _ = tracker.finish(0xDEAD, 0xBEEF).await;
    assert_eq!(tracker.buffered_bytes().await, 0);
}

// --- Download payload helpers (match CallbackParser LE encoding) ---

fn add_bytes_le(buf: &mut Vec<u8>, value: &[u8]) {
    add_u32_le(buf, u32::try_from(value.len()).expect("test data fits in u32"));
    buf.extend_from_slice(value);
}

pub(super) fn build_download_open_payload(
    file_id: u32,
    expected_size: u64,
    remote_path: &str,
) -> Vec<u8> {
    let mut buf = Vec::new();
    add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Download));
    add_u32_le(&mut buf, 0); // mode = open
    add_u32_le(&mut buf, file_id);
    add_u64_le(&mut buf, expected_size);
    add_utf16_le(&mut buf, remote_path);
    buf
}

pub(super) fn build_download_write_payload(file_id: u32, chunk: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Download));
    add_u32_le(&mut buf, 1); // mode = write
    add_u32_le(&mut buf, file_id);
    add_bytes_le(&mut buf, chunk);
    buf
}

pub(super) fn build_download_close_payload(file_id: u32, reason: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Download));
    add_u32_le(&mut buf, 2); // mode = close
    add_u32_le(&mut buf, file_id);
    add_u32_le(&mut buf, reason);
    buf
}

fn build_download_invalid_mode_payload(file_id: u32, mode: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Download));
    add_u32_le(&mut buf, mode);
    add_u32_le(&mut buf, file_id);
    buf
}

// --- Download close-failure and invalid-mode tests ---

#[tokio::test]
async fn download_close_nonzero_reason_emits_removed_and_discards_loot() {
    let (registry, db, events, downloads) = dir_test_deps().await;
    let mut rx = events.subscribe();
    let agent_id = 0xFA01;
    let file_id = 0x77;
    let request_id = 0xBB;
    let remote_path = "C:\\Temp\\partial.bin";

    // Open the download.
    handle_filesystem_callback(
        &registry,
        &db,
        &events,
        &downloads,
        None,
        agent_id,
        request_id,
        &build_download_open_payload(file_id, 1024, remote_path),
    )
    .await
    .expect("open should succeed");

    // Drain the "Started" event.
    let _ = timeout(Duration::from_millis(50), rx.recv()).await.expect("should receive open event");

    // Append one chunk.
    handle_filesystem_callback(
        &registry,
        &db,
        &events,
        &downloads,
        None,
        agent_id,
        request_id,
        &build_download_write_payload(file_id, b"partial-data"),
    )
    .await
    .expect("write should succeed");

    // Drain the "InProgress" event.
    let _ =
        timeout(Duration::from_millis(50), rx.recv()).await.expect("should receive progress event");

    // Close with non-zero reason (failure).
    handle_filesystem_callback(
        &registry,
        &db,
        &events,
        &downloads,
        None,
        agent_id,
        request_id,
        &build_download_close_payload(file_id, 1),
    )
    .await
    .expect("close should succeed even with non-zero reason");

    // The close should emit a "Removed" progress event.
    let event = timeout(Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive close event")
        .expect("should have broadcast event");

    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(
        msg.info.extra.get("State").and_then(|v| v.as_str()),
        Some("Removed"),
        "failed download close should report State=Removed"
    );

    // No loot should have been persisted.
    let loot = db.loot().list_for_agent(agent_id).await.expect("loot query should work");
    assert!(loot.is_empty(), "failed download should not persist loot");

    // Tracker should be drained — no active downloads for this agent.
    let active = downloads.active_for_agent(agent_id).await;
    assert!(active.is_empty(), "tracker should be drained after failed close");

    // No further events expected.
    assert!(
        timeout(Duration::from_millis(50), rx.recv()).await.is_err(),
        "no extra events should be emitted after failed close"
    );
}

#[tokio::test]
async fn download_unsupported_mode_returns_invalid_callback_payload() {
    let (registry, db, events, downloads) = dir_test_deps().await;
    let mut rx = events.subscribe();
    let agent_id = 0xFA02;
    let request_id = 0xCC;

    let err = handle_filesystem_callback(
        &registry,
        &db,
        &events,
        &downloads,
        None,
        agent_id,
        request_id,
        &build_download_invalid_mode_payload(0x99, 42),
    )
    .await
    .expect_err("unsupported mode should return error");

    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );

    // No events should have been emitted.
    assert!(
        timeout(Duration::from_millis(50), rx.recv()).await.is_err(),
        "no events should be emitted for unsupported download mode"
    );

    // No active downloads left behind.
    let active = downloads.active_for_agent(agent_id).await;
    assert!(active.is_empty(), "no partial state should remain after invalid mode");

    // No loot persisted.
    let loot = db.loot().list_for_agent(agent_id).await.expect("loot query should work");
    assert!(loot.is_empty(), "no loot should be stored for invalid mode");
}

// --- Happy-path download: open → chunk → close(reason=0) ---

#[tokio::test]
async fn download_happy_path_persists_loot_and_emits_all_events() {
    let (registry, db, events, downloads) = dir_test_deps().await;
    registry.insert(stub_agent(0xFA03)).await.expect("insert agent");
    let mut rx = events.subscribe();
    let agent_id = 0xFA03;
    let file_id = 0x42;
    let request_id = 0xDD;
    let remote_path = "C:\\Users\\admin\\secret.docx";
    let chunk_data = b"hello-world-download-data";
    let expected_size = chunk_data.len() as u64;

    // 1) Open
    handle_filesystem_callback(
        &registry,
        &db,
        &events,
        &downloads,
        None,
        agent_id,
        request_id,
        &build_download_open_payload(file_id, expected_size, remote_path),
    )
    .await
    .expect("open should succeed");

    let event = timeout(Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive Started event")
        .expect("broadcast");
    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(msg.info.extra.get("State").and_then(|v| v.as_str()), Some("Started"),);
    assert_eq!(msg.info.extra.get("MiscType").and_then(|v| v.as_str()), Some("download-progress"),);
    assert_eq!(msg.info.extra.get("FileName").and_then(|v| v.as_str()), Some(remote_path),);
    assert_eq!(msg.info.extra.get("CurrentSize").and_then(|v| v.as_str()), Some("0"),);

    // 2) Write chunk
    handle_filesystem_callback(
        &registry,
        &db,
        &events,
        &downloads,
        None,
        agent_id,
        request_id,
        &build_download_write_payload(file_id, chunk_data),
    )
    .await
    .expect("write should succeed");

    let event = timeout(Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive InProgress event")
        .expect("broadcast");
    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(msg.info.extra.get("State").and_then(|v| v.as_str()), Some("InProgress"),);
    let current_size_str = chunk_data.len().to_string();
    assert_eq!(
        msg.info.extra.get("CurrentSize").and_then(|v| v.as_str()),
        Some(current_size_str.as_str()),
    );

    // 3) Close with reason=0 (success)
    handle_filesystem_callback(
        &registry,
        &db,
        &events,
        &downloads,
        None,
        agent_id,
        request_id,
        &build_download_close_payload(file_id, 0),
    )
    .await
    .expect("close should succeed");

    // Close emits two events: loot_new_event then download_complete_event
    let loot_event = timeout(Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive loot-new event")
        .expect("broadcast");
    let OperatorMessage::AgentResponse(loot_msg) = &loot_event else {
        panic!("expected AgentResponse for loot, got {loot_event:?}");
    };
    assert_eq!(loot_msg.info.extra.get("MiscType").and_then(|v| v.as_str()), Some("loot-new"),);
    assert_eq!(loot_msg.info.extra.get("LootKind").and_then(|v| v.as_str()), Some("download"),);
    assert_eq!(loot_msg.info.extra.get("LootName").and_then(|v| v.as_str()), Some("secret.docx"),);

    let complete_event = timeout(Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive download-complete event")
        .expect("broadcast");
    let OperatorMessage::AgentResponse(complete_msg) = &complete_event else {
        panic!("expected AgentResponse for completion, got {complete_event:?}");
    };
    assert_eq!(complete_msg.info.extra.get("MiscType").and_then(|v| v.as_str()), Some("download"),);
    // MiscData should be base64 of the file content
    let misc_data_b64 =
        complete_msg.info.extra.get("MiscData").and_then(|v| v.as_str()).expect("MiscData present");
    let decoded = BASE64_STANDARD.decode(misc_data_b64).expect("valid base64");
    assert_eq!(decoded, chunk_data, "MiscData should contain the downloaded file bytes");

    // MiscData2 = base64(remote_path) + ";" + byte_count(size)
    let misc_data2 = complete_msg
        .info
        .extra
        .get("MiscData2")
        .and_then(|v| v.as_str())
        .expect("MiscData2 present");
    let expected_b64_path = BASE64_STANDARD.encode(remote_path.as_bytes());
    assert!(
        misc_data2.starts_with(&expected_b64_path),
        "MiscData2 should start with base64-encoded path"
    );
    assert!(misc_data2.contains(';'), "MiscData2 should contain separator");

    // Verify loot persisted in database
    let loot = db.loot().list_for_agent(agent_id).await.expect("loot query");
    assert_eq!(loot.len(), 1, "exactly one loot record should be persisted");
    let record = &loot[0];
    assert_eq!(record.kind, "download");
    assert_eq!(record.name, "secret.docx");
    assert_eq!(record.file_path.as_deref(), Some(remote_path));
    assert_eq!(record.size_bytes, Some(chunk_data.len() as i64));
    assert_eq!(record.data.as_deref(), Some(chunk_data.as_slice()));
    assert!(record.id.is_some(), "record should have a database ID");

    // Verify metadata fields
    let meta = record.metadata.as_ref().expect("metadata should be present");
    let file_id_hex = format!("{file_id:08X}");
    let request_id_hex = format!("{request_id:X}");
    let expected_size_str = expected_size.to_string();
    assert_eq!(meta.get("file_id").and_then(|v| v.as_str()), Some(file_id_hex.as_str()),);
    assert_eq!(meta.get("request_id").and_then(|v| v.as_str()), Some(request_id_hex.as_str()),);
    assert_eq!(
        meta.get("expected_size").and_then(|v| v.as_str()),
        Some(expected_size_str.as_str()),
    );
    assert!(
        meta.get("started_at").and_then(|v| v.as_str()).is_some(),
        "started_at should be present"
    );

    // Tracker should be drained
    let active = downloads.active_for_agent(agent_id).await;
    assert!(active.is_empty(), "tracker should be drained after successful close");
}

// --- Direct unit tests for download_progress_event ---

#[test]
fn download_progress_event_produces_correct_structure() {
    let event = download_progress_event(
        0xABCD,
        u32::from(DemonCommand::CommandFs),
        0x10,
        0x77,
        "C:\\data\\report.pdf",
        512,
        2048,
        "InProgress",
    )
    .expect("should build event");

    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };

    assert_eq!(msg.info.extra.get("MiscType").and_then(|v| v.as_str()), Some("download-progress"),);
    assert_eq!(msg.info.extra.get("FileID").and_then(|v| v.as_str()), Some("00000077"),);
    assert_eq!(
        msg.info.extra.get("FileName").and_then(|v| v.as_str()),
        Some("C:\\data\\report.pdf"),
    );
    assert_eq!(msg.info.extra.get("CurrentSize").and_then(|v| v.as_str()), Some("512"),);
    assert_eq!(msg.info.extra.get("ExpectedSize").and_then(|v| v.as_str()), Some("2048"),);
    assert_eq!(msg.info.extra.get("State").and_then(|v| v.as_str()), Some("InProgress"),);

    // Message should contain the path and state
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("report.pdf"), "message should mention file: {message}");
    assert!(message.contains("InProgress"), "message should contain state: {message}");
}

#[test]
fn download_progress_event_started_shows_zero_current() {
    let event = download_progress_event(
        0x01,
        u32::from(DemonCommand::CommandFs),
        0x02,
        0x03,
        "C:\\flag.txt",
        0,
        1024,
        "Started",
    )
    .expect("should build event");

    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse");
    };
    assert_eq!(msg.info.extra.get("State").and_then(|v| v.as_str()), Some("Started"),);
    assert_eq!(msg.info.extra.get("CurrentSize").and_then(|v| v.as_str()), Some("0"),);
}

#[test]
fn download_progress_event_removed_state() {
    let event = download_progress_event(
        0x01,
        u32::from(DemonCommand::CommandFs),
        0x02,
        0x03,
        "C:\\fail.bin",
        100,
        500,
        "Removed",
    )
    .expect("should build event");

    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse");
    };
    assert_eq!(msg.info.extra.get("State").and_then(|v| v.as_str()), Some("Removed"),);
}

// --- Direct unit tests for download_complete_event ---

#[test]
fn download_complete_event_encodes_data_and_path() {
    let state = DownloadState {
        request_id: 0x10,
        remote_path: "C:\\loot\\secrets.zip".to_owned(),
        expected_size: 4,
        data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        started_at: "2026-03-17T12:00:00Z".to_owned(),
    };

    let event =
        download_complete_event(0xBBBB, u32::from(DemonCommand::CommandFs), 0x10, 0x55, &state)
            .expect("should build event");

    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };

    assert_eq!(msg.info.extra.get("MiscType").and_then(|v| v.as_str()), Some("download"),);
    assert_eq!(msg.info.extra.get("FileID").and_then(|v| v.as_str()), Some("00000055"),);
    assert_eq!(
        msg.info.extra.get("FileName").and_then(|v| v.as_str()),
        Some("C:\\loot\\secrets.zip"),
    );

    // MiscData = base64(data)
    let misc_data = msg.info.extra.get("MiscData").and_then(|v| v.as_str()).expect("MiscData");
    let decoded = BASE64_STANDARD.decode(misc_data).expect("valid base64");
    assert_eq!(decoded, &[0xDE, 0xAD, 0xBE, 0xEF]);

    // MiscData2 = base64(path) + ";" + byte_count(size)
    let misc_data2 = msg.info.extra.get("MiscData2").and_then(|v| v.as_str()).expect("MiscData2");
    let parts: Vec<&str> = misc_data2.splitn(2, ';').collect();
    assert_eq!(parts.len(), 2, "MiscData2 should have two semicolon-separated parts");
    let decoded_path = BASE64_STANDARD.decode(parts[0]).expect("base64 path");
    assert_eq!(String::from_utf8_lossy(&decoded_path), "C:\\loot\\secrets.zip");
    assert_eq!(parts[1], "4 B", "byte_count(4) should be '4 B'");

    // Kind should be "Good"
    let kind = msg.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(kind, "Good");
}

#[test]
fn download_complete_event_empty_data() {
    let state = DownloadState {
        request_id: 0x01,
        remote_path: "C:\\empty.bin".to_owned(),
        expected_size: 0,
        data: Vec::new(),
        started_at: "2026-03-17T00:00:00Z".to_owned(),
    };

    let event =
        download_complete_event(0x01, u32::from(DemonCommand::CommandFs), 0x01, 0x01, &state)
            .expect("should build event");

    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse");
    };

    let misc_data = msg.info.extra.get("MiscData").and_then(|v| v.as_str()).expect("MiscData");
    let decoded = BASE64_STANDARD.decode(misc_data).expect("valid base64");
    assert!(decoded.is_empty(), "empty download data should decode to empty");
}

// --- Direct unit tests for persist_download ---

#[tokio::test]
async fn persist_download_extracts_filename_from_windows_path() {
    let db = Database::connect_in_memory().await.expect("in-memory db");
    let registry = AgentRegistry::new(db.clone());
    registry.insert(stub_agent(0xAA)).await.expect("insert agent");
    let state = DownloadState {
        request_id: 0x10,
        remote_path: "C:\\Users\\admin\\Desktop\\flag.txt".to_owned(),
        expected_size: 5,
        data: b"hello".to_vec(),
        started_at: "2026-03-17T12:00:00Z".to_owned(),
    };
    let context = LootContext::default();

    let record =
        persist_download(&db, 0xAA, 0x42, &state, &context).await.expect("persist should succeed");

    assert_eq!(record.name, "flag.txt");
    assert_eq!(record.kind, "download");
    assert_eq!(record.file_path.as_deref(), Some("C:\\Users\\admin\\Desktop\\flag.txt"),);
    assert_eq!(record.size_bytes, Some(5));
    assert_eq!(record.data.as_deref(), Some(b"hello".as_slice()));
    assert!(record.id.is_some(), "should have a database-assigned ID");
}

#[tokio::test]
async fn persist_download_extracts_filename_from_unix_path() {
    let db = Database::connect_in_memory().await.expect("in-memory db");
    let registry = AgentRegistry::new(db.clone());
    registry.insert(stub_agent(0xBB)).await.expect("insert agent");
    let state = DownloadState {
        request_id: 0x20,
        remote_path: "/home/user/docs/report.pdf".to_owned(),
        expected_size: 3,
        data: b"pdf".to_vec(),
        started_at: "2026-03-17T12:00:00Z".to_owned(),
    };
    let context = LootContext::default();

    let record =
        persist_download(&db, 0xBB, 0x01, &state, &context).await.expect("persist should succeed");

    assert_eq!(record.name, "report.pdf");
}

#[tokio::test]
async fn persist_download_bare_filename_no_separators() {
    let db = Database::connect_in_memory().await.expect("in-memory db");
    let registry = AgentRegistry::new(db.clone());
    registry.insert(stub_agent(0xCC)).await.expect("insert agent");
    let state = DownloadState {
        request_id: 0x30,
        remote_path: "standalone.exe".to_owned(),
        expected_size: 2,
        data: b"MZ".to_vec(),
        started_at: "2026-03-17T12:00:00Z".to_owned(),
    };
    let context = LootContext::default();

    let record =
        persist_download(&db, 0xCC, 0x02, &state, &context).await.expect("persist should succeed");

    assert_eq!(record.name, "standalone.exe");
}

#[tokio::test]
async fn persist_download_metadata_includes_file_id_and_timestamps() {
    let db = Database::connect_in_memory().await.expect("in-memory db");
    let registry = AgentRegistry::new(db.clone());
    registry.insert(stub_agent(0xDD)).await.expect("insert agent");
    let state = DownloadState {
        request_id: 0xFF,
        remote_path: "C:\\meta.bin".to_owned(),
        expected_size: 999,
        data: vec![0; 10],
        started_at: "2026-03-17T08:30:00Z".to_owned(),
    };
    let context = LootContext::default();

    let record =
        persist_download(&db, 0xDD, 0x88, &state, &context).await.expect("persist should succeed");

    let meta = record.metadata.as_ref().expect("metadata should be present");
    assert_eq!(meta.get("file_id").and_then(|v| v.as_str()), Some("00000088"),);
    assert_eq!(meta.get("request_id").and_then(|v| v.as_str()), Some("FF"),);
    assert_eq!(meta.get("expected_size").and_then(|v| v.as_str()), Some("999"),);
    assert_eq!(meta.get("started_at").and_then(|v| v.as_str()), Some("2026-03-17T08:30:00Z"),);
}
