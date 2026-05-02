//! Shared test helpers for `handle_filesystem_callback` test modules.
//!
//! Payload builders for primitive fields, a stub `AgentRecord` for
//! foreign-key satisfaction, and small dispatch-and-assert wrappers used by
//! both the download and directory test files.

use red_cell_common::operator::OperatorMessage;
use red_cell_common::{AgentEncryptionInfo, AgentRecord};
use tokio::time::{Duration, timeout};
use zeroize::Zeroizing;

use crate::dispatch::DownloadTracker;
use crate::{AgentRegistry, Database, EventBus};

use super::super::CommandDispatchError;
use super::super::handle_filesystem_callback;

/// Build a minimal agent record for database foreign-key satisfaction.
pub(in crate::dispatch::filesystem) fn stub_agent(agent_id: u32) -> AgentRecord {
    AgentRecord {
        agent_id,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: AgentEncryptionInfo {
            aes_key: Zeroizing::new(vec![0; 32]),
            aes_iv: Zeroizing::new(vec![0; 16]),
            monotonic_ctr: false,
        },
        hostname: "test".to_owned(),
        username: "user".to_owned(),
        domain_name: "DOMAIN".to_owned(),
        external_ip: "127.0.0.1".to_owned(),
        internal_ip: "127.0.0.1".to_owned(),
        process_name: "test.exe".to_owned(),
        process_path: "C:\\test.exe".to_owned(),
        base_address: 0,
        process_pid: 1,
        process_tid: 1,
        process_ppid: 0,
        process_arch: "x64".to_owned(),
        elevated: false,
        os_version: "Windows 10".to_owned(),
        os_build: 0,
        os_arch: "x64".to_owned(),
        sleep_delay: 5,
        sleep_jitter: 0,
        kill_date: None,
        working_hours: None,
        first_call_in: "2026-01-01T00:00:00Z".to_owned(),
        last_call_in: "2026-01-01T00:00:00Z".to_owned(),
        archon_magic: None,
    }
}

/// Encode a UTF-16 LE string with a LE u32 length prefix (matching CallbackParser::read_utf16).
pub(in crate::dispatch::filesystem) fn add_utf16_le(buf: &mut Vec<u8>, value: &str) {
    let mut encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
    encoded.extend_from_slice(&[0, 0]); // null terminator
    buf.extend_from_slice(&u32::try_from(encoded.len()).expect("unwrap").to_le_bytes());
    buf.extend_from_slice(&encoded);
}

pub(in crate::dispatch::filesystem) fn add_u32_le(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

pub(in crate::dispatch::filesystem) fn add_u64_le(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

pub(in crate::dispatch::filesystem) fn add_bool_le(buf: &mut Vec<u8>, value: bool) {
    add_u32_le(buf, u32::from(value));
}

/// Build a fresh set of test dependencies with a 1 MiB download tracker limit.
pub(in crate::dispatch::filesystem) async fn dir_test_deps()
-> (AgentRegistry, Database, EventBus, DownloadTracker) {
    let db = Database::connect_in_memory().await.expect("in-memory db");
    let registry = AgentRegistry::new(db.clone());
    let events = EventBus::default();
    let downloads = DownloadTracker::new(1024 * 1024);
    (registry, db, events, downloads)
}

/// Invoke `handle_filesystem_callback` and return the first broadcast event.
pub(in crate::dispatch::filesystem) async fn call_and_recv(
    payload: &[u8],
    agent_id: u32,
    request_id: u32,
) -> OperatorMessage {
    let (registry, db, events, downloads) = dir_test_deps().await;
    let mut rx = events.subscribe();
    handle_filesystem_callback(
        &registry, &db, &events, &downloads, None, agent_id, request_id, payload,
    )
    .await
    .expect("handler should succeed");
    timeout(Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive event")
        .expect("broadcast")
}

/// Invoke `handle_filesystem_callback` and expect an error.
pub(in crate::dispatch::filesystem) async fn call_and_expect_error(
    payload: &[u8],
    agent_id: u32,
    request_id: u32,
) -> CommandDispatchError {
    let (registry, db, events, downloads) = dir_test_deps().await;
    handle_filesystem_callback(
        &registry, &db, &events, &downloads, None, agent_id, request_id, payload,
    )
    .await
    .expect_err("handler should return error for truncated payload")
}
