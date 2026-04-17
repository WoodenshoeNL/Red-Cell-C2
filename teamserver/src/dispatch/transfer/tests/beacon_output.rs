//! Tests for the `BeaconOutput` callback handler, covering the
//! Output/OutputUtf8/OutputOem/ErrorMessage text branches and the
//! File/FileWrite/FileClose transfer state machine.

use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use red_cell_common::demon::DemonCallback;
use red_cell_common::operator::OperatorMessage;
use zeroize::Zeroizing;

use super::super::super::{CommandDispatchError, DownloadTracker};
use super::super::handle_beacon_output_callback;
use super::{le32, length_prefixed};
use crate::{AgentRegistry, Database, EventBus};

// ------------------------------------------------------------------
// Helper: register a minimal agent in the database so FK constraints pass
// ------------------------------------------------------------------

async fn register_test_agent(
    registry: &AgentRegistry,
    agent_id: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let key = [0x11_u8; AGENT_KEY_LENGTH];
    let iv = [0x22_u8; AGENT_IV_LENGTH];
    registry
        .insert(red_cell_common::AgentRecord {
            agent_id,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: red_cell_common::AgentEncryptionInfo {
                aes_key: Zeroizing::new(key.to_vec()),
                aes_iv: Zeroizing::new(iv.to_vec()),
            },
            hostname: "test-host".to_owned(),
            username: "test-user".to_owned(),
            domain_name: "test".to_owned(),
            external_ip: "1.2.3.4".to_owned(),
            internal_ip: "10.0.0.1".to_owned(),
            process_name: "cmd.exe".to_owned(),
            process_path: "C:\\cmd.exe".to_owned(),
            base_address: 0x1000,
            process_pid: 100,
            process_tid: 101,
            process_ppid: 4,
            process_arch: "x64".to_owned(),
            elevated: false,
            os_version: "Windows 10".to_owned(),
            os_build: 19045,
            os_arch: "x64".to_owned(),
            sleep_delay: 5,
            sleep_jitter: 0,
            kill_date: None,
            working_hours: None,
            first_call_in: "2026-03-17T00:00:00Z".to_owned(),
            last_call_in: "2026-03-17T00:00:00Z".to_owned(),
        })
        .await?;
    Ok(())
}

/// Encode a Rust string as UTF-16LE bytes.
fn utf16le_bytes(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

/// Build a File-open (DemonCallback::File) payload with the given file_id,
/// expected_size, and remote_path.  The inner bytes use big-endian for
/// file_id and expected_size (as expected by `parse_file_open_header`).
fn file_open_payload(file_id: u32, expected_size: u32, remote_path: &str) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend_from_slice(&file_id.to_be_bytes());
    inner.extend_from_slice(&expected_size.to_be_bytes());
    inner.extend_from_slice(remote_path.as_bytes());

    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(u32::from(DemonCallback::File)));
    payload.extend_from_slice(&length_prefixed(&inner));
    payload
}

/// Build a FileWrite (DemonCallback::FileWrite) payload with the given
/// file_id and chunk data.  file_id is big-endian.
fn file_write_payload(file_id: u32, chunk: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend_from_slice(&file_id.to_be_bytes());
    inner.extend_from_slice(chunk);

    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(u32::from(DemonCallback::FileWrite)));
    payload.extend_from_slice(&length_prefixed(&inner));
    payload
}

/// Build a FileClose (DemonCallback::FileClose) payload.  file_id is big-endian.
fn file_close_payload(file_id: u32) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend_from_slice(&file_id.to_be_bytes());

    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(u32::from(DemonCallback::FileClose)));
    payload.extend_from_slice(&length_prefixed(&inner));
    payload
}

// ------------------------------------------------------------------
// handle_beacon_output_callback — credential line triggers persistence
// ------------------------------------------------------------------

#[tokio::test]
async fn beacon_output_callback_persists_credential_loot() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let downloads = DownloadTracker::new(1024 * 1024);
    let agent_id: u32 = 0xCAFE_BABE;
    let request_id: u32 = 99;

    // Register the agent so agent_responses FK constraint is satisfied.
    let key = [0x11_u8; AGENT_KEY_LENGTH];
    let iv = [0x22_u8; AGENT_IV_LENGTH];
    registry
        .insert(red_cell_common::AgentRecord {
            agent_id,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: red_cell_common::AgentEncryptionInfo {
                aes_key: Zeroizing::new(key.to_vec()),
                aes_iv: Zeroizing::new(iv.to_vec()),
            },
            hostname: "test-host".to_owned(),
            username: "test-user".to_owned(),
            domain_name: "test".to_owned(),
            external_ip: "1.2.3.4".to_owned(),
            internal_ip: "10.0.0.1".to_owned(),
            process_name: "cmd.exe".to_owned(),
            process_path: "C:\\cmd.exe".to_owned(),
            base_address: 0x1000,
            process_pid: 100,
            process_tid: 101,
            process_ppid: 4,
            process_arch: "x64".to_owned(),
            elevated: false,
            os_version: "Windows 10".to_owned(),
            os_build: 19045,
            os_arch: "x64".to_owned(),
            sleep_delay: 5,
            sleep_jitter: 0,
            kill_date: None,
            working_hours: None,
            first_call_in: "2026-03-17T00:00:00Z".to_owned(),
            last_call_in: "2026-03-17T00:00:00Z".to_owned(),
        })
        .await?;

    // Output text containing a recognisable credential line.
    let output_text = "password: secret123";
    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(u32::from(DemonCallback::Output)));
    payload.extend_from_slice(&length_prefixed(output_text.as_bytes()));

    let result = handle_beacon_output_callback(
        &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
    )
    .await?;

    assert_eq!(result, None, "beacon-output handler must not produce a reply packet");

    // First event: AgentResponse carrying the captured output.
    let first_event = receiver.recv().await.ok_or("expected AgentResponse event for output")?;
    assert!(
        matches!(first_event, OperatorMessage::AgentResponse(_)),
        "first event should be AgentResponse; got: {first_event:?}"
    );

    // The credential line must have been persisted as a loot record.
    let loot_records = database.loot().list_for_agent(agent_id).await?;
    assert!(
        loot_records.iter().any(|r| r.kind == "credential"),
        "expected at least one 'credential' loot record; got: {loot_records:?}"
    );
    Ok(())
}

// ------------------------------------------------------------------
// handle_beacon_output_callback — OutputUtf8 variant
// ------------------------------------------------------------------

#[tokio::test]
async fn beacon_output_utf8_broadcasts_and_persists() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let downloads = DownloadTracker::new(1024 * 1024);
    let agent_id: u32 = 0xDA01_0001;
    let request_id: u32 = 200;

    register_test_agent(&registry, agent_id).await?;

    let output_text = "hello from utf-16";
    let utf16_data = utf16le_bytes(output_text);
    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(u32::from(DemonCallback::OutputUtf8)));
    payload.extend_from_slice(&length_prefixed(&utf16_data));

    let result = handle_beacon_output_callback(
        &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
    )
    .await?;

    assert_eq!(result, None);

    let event = receiver.recv().await.ok_or("expected AgentResponse event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        return Err("expected AgentResponse".into());
    };
    assert!(
        msg.info.output.contains("hello from utf-16"),
        "output should contain decoded UTF-16 text; got: {}",
        msg.info.output
    );

    // Verify agent_response was persisted.
    let responses = database.agent_responses().list_for_agent(agent_id).await?;
    assert!(!responses.is_empty(), "OutputUtf8 must persist an agent_response record");
    Ok(())
}

// ------------------------------------------------------------------
// handle_beacon_output_callback — OutputOem variant
// ------------------------------------------------------------------

#[tokio::test]
async fn beacon_output_oem_broadcasts_and_persists() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let downloads = DownloadTracker::new(1024 * 1024);
    let agent_id: u32 = 0xDA02_0001;
    let request_id: u32 = 201;

    register_test_agent(&registry, agent_id).await?;

    let output_text = "OEM encoded text";
    let utf16_data = utf16le_bytes(output_text);
    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(u32::from(DemonCallback::OutputOem)));
    payload.extend_from_slice(&length_prefixed(&utf16_data));

    let result = handle_beacon_output_callback(
        &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
    )
    .await?;

    assert_eq!(result, None);

    let event = receiver.recv().await.ok_or("expected AgentResponse event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        return Err("expected AgentResponse".into());
    };
    assert!(
        msg.info.output.contains("OEM encoded text"),
        "output should contain decoded OEM/UTF-16 text; got: {}",
        msg.info.output
    );
    Ok(())
}

// ------------------------------------------------------------------
// handle_beacon_output_callback — OutputUtf8 credential extraction
// ------------------------------------------------------------------

#[tokio::test]
async fn beacon_output_utf8_persists_credential_loot() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let downloads = DownloadTracker::new(1024 * 1024);
    let agent_id: u32 = 0xDA01_0002;
    let request_id: u32 = 210;

    register_test_agent(&registry, agent_id).await?;

    // UTF-16LE payload that decodes to a string with a credential pattern.
    let output_text = "Password : s3cr3t!";
    let utf16_data = utf16le_bytes(output_text);
    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(u32::from(DemonCallback::OutputUtf8)));
    payload.extend_from_slice(&length_prefixed(&utf16_data));

    let result = handle_beacon_output_callback(
        &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
    )
    .await?;

    assert_eq!(result, None, "beacon-output handler must not produce a reply packet");

    // First event: AgentResponse carrying the captured output.
    let first_event = receiver.recv().await.ok_or("expected AgentResponse event for output")?;
    assert!(
        matches!(first_event, OperatorMessage::AgentResponse(_)),
        "first event should be AgentResponse; got: {first_event:?}"
    );

    // The credential line must have been persisted as a loot record.
    let loot_records = database.loot().list_for_agent(agent_id).await?;
    assert!(
        loot_records.iter().any(|r| r.kind == "credential"),
        "expected at least one 'credential' loot record from OutputUtf8 path; got: {loot_records:?}"
    );
    Ok(())
}

// ------------------------------------------------------------------
// handle_beacon_output_callback — OutputOem credential extraction
// ------------------------------------------------------------------

#[tokio::test]
async fn beacon_output_oem_persists_credential_loot() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let downloads = DownloadTracker::new(1024 * 1024);
    let agent_id: u32 = 0xDA02_0002;
    let request_id: u32 = 211;

    register_test_agent(&registry, agent_id).await?;

    // UTF-16LE payload that decodes to a string with a credential pattern.
    let output_text = "Password : s3cr3t!";
    let utf16_data = utf16le_bytes(output_text);
    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(u32::from(DemonCallback::OutputOem)));
    payload.extend_from_slice(&length_prefixed(&utf16_data));

    let result = handle_beacon_output_callback(
        &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
    )
    .await?;

    assert_eq!(result, None, "beacon-output handler must not produce a reply packet");

    // First event: AgentResponse carrying the captured output.
    let first_event = receiver.recv().await.ok_or("expected AgentResponse event for output")?;
    assert!(
        matches!(first_event, OperatorMessage::AgentResponse(_)),
        "first event should be AgentResponse; got: {first_event:?}"
    );

    // The credential line must have been persisted as a loot record.
    let loot_records = database.loot().list_for_agent(agent_id).await?;
    assert!(
        loot_records.iter().any(|r| r.kind == "credential"),
        "expected at least one 'credential' loot record from OutputOem path; got: {loot_records:?}"
    );
    Ok(())
}

// ------------------------------------------------------------------
// handle_beacon_output_callback — ErrorMessage variant
// ------------------------------------------------------------------

#[tokio::test]
async fn beacon_error_message_broadcasts_error_kind() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let downloads = DownloadTracker::new(1024 * 1024);
    let agent_id: u32 = 0xDA03_0001;
    let request_id: u32 = 202;

    register_test_agent(&registry, agent_id).await?;

    let error_text = "access denied";
    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(u32::from(DemonCallback::ErrorMessage)));
    payload.extend_from_slice(&length_prefixed(error_text.as_bytes()));

    let result = handle_beacon_output_callback(
        &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
    )
    .await?;

    assert_eq!(result, None);

    let event = receiver.recv().await.ok_or("expected AgentResponse event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        return Err("expected AgentResponse".into());
    };
    // ErrorMessage branch sets kind = "Error"
    let kind = msg.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(kind, "Error", "ErrorMessage callback must emit Error kind; got: {kind}");
    assert!(
        msg.info.output.contains("access denied"),
        "output should contain the error text; got: {}",
        msg.info.output
    );

    // Should still persist an agent_response record.
    let responses = database.agent_responses().list_for_agent(agent_id).await?;
    assert!(!responses.is_empty(), "ErrorMessage must persist an agent_response record");
    Ok(())
}

// ------------------------------------------------------------------
// handle_beacon_output_callback — File→FileWrite→FileClose sequence
// ------------------------------------------------------------------

#[tokio::test]
async fn beacon_file_transfer_full_sequence() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let downloads = DownloadTracker::new(1024 * 1024);
    let agent_id: u32 = 0xDA04_0001;
    let request_id: u32 = 300;
    let file_id: u32 = 0x0000_FF01;
    let chunk_a = b"Hello, ";
    let chunk_b = b"World!";
    let expected_size: u32 = (chunk_a.len() + chunk_b.len()) as u32;

    register_test_agent(&registry, agent_id).await?;

    // --- Step 1: File open ---
    let payload = file_open_payload(file_id, expected_size, r"C:\exfil\data.txt");
    handle_beacon_output_callback(
        &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
    )
    .await?;

    // Should emit a download-progress "Started" event.
    let event = receiver.recv().await.ok_or("expected progress event after File open")?;
    let OperatorMessage::AgentResponse(msg) = &event else {
        return Err("expected AgentResponse for File open".into());
    };
    let misc_type = msg.info.extra.get("MiscType").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(
        misc_type, "download-progress",
        "File open should emit download-progress; got: {misc_type}"
    );
    let state_field = msg.info.extra.get("State").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(state_field, "Started");

    // Download should now be tracked.
    assert!(
        !downloads.active_for_agent(agent_id).await.is_empty(),
        "download should be tracked after File open"
    );

    // --- Step 2: FileWrite (chunk A) ---
    let payload = file_write_payload(file_id, chunk_a);
    handle_beacon_output_callback(
        &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
    )
    .await?;

    let event = receiver.recv().await.ok_or("expected progress event after FileWrite A")?;
    let OperatorMessage::AgentResponse(msg) = &event else {
        return Err("expected AgentResponse for FileWrite A".into());
    };
    let misc_type = msg.info.extra.get("MiscType").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(misc_type, "download-progress");
    let state_field = msg.info.extra.get("State").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(state_field, "InProgress");

    // --- Step 3: FileWrite (chunk B) ---
    let payload = file_write_payload(file_id, chunk_b);
    handle_beacon_output_callback(
        &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
    )
    .await?;

    let event = receiver.recv().await.ok_or("expected progress event after FileWrite B")?;
    let OperatorMessage::AgentResponse(msg) = &event else {
        return Err("expected AgentResponse for FileWrite B".into());
    };
    let misc_type = msg.info.extra.get("MiscType").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(misc_type, "download-progress");

    // --- Step 4: FileClose ---
    let payload = file_close_payload(file_id);
    handle_beacon_output_callback(
        &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
    )
    .await?;

    // FileClose emits loot_new_event first, then download_complete_event.
    let event = receiver.recv().await.ok_or("expected loot-new event after FileClose")?;
    let OperatorMessage::AgentResponse(msg) = &event else {
        return Err("expected AgentResponse for loot-new".into());
    };
    let misc_type = msg.info.extra.get("MiscType").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(misc_type, "loot-new", "first FileClose event should be loot-new; got: {misc_type}");

    let event = receiver.recv().await.ok_or("expected download-complete event after FileClose")?;
    let OperatorMessage::AgentResponse(msg) = &event else {
        return Err("expected AgentResponse for download-complete".into());
    };
    let misc_type = msg.info.extra.get("MiscType").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(
        misc_type, "download",
        "second FileClose event should be download; got: {misc_type}"
    );

    // Download should be cleaned up.
    assert!(
        downloads.active_for_agent(agent_id).await.is_empty(),
        "download should be removed after FileClose"
    );

    // Loot record must be persisted with the correct data.
    let loot_records = database.loot().list_for_agent(agent_id).await?;
    let download_loot = loot_records.iter().find(|r| r.kind == "download");
    assert!(download_loot.is_some(), "expected a 'download' loot record; got: {loot_records:?}");
    let loot = download_loot.expect("unwrap");
    assert_eq!(loot.name, "data.txt", "loot name should be the filename");
    assert_eq!(
        loot.data.as_deref(),
        Some(b"Hello, World!".as_slice()),
        "loot data should be the concatenated chunks"
    );
    Ok(())
}

// ------------------------------------------------------------------
// handle_beacon_output_callback — truncated FileWrite payload
// ------------------------------------------------------------------

#[tokio::test]
async fn beacon_file_write_without_open_returns_error() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let downloads = DownloadTracker::new(1024 * 1024);
    let agent_id: u32 = 0xDA05_0001;
    let request_id: u32 = 400;
    let file_id: u32 = 0x0000_FF02;

    register_test_agent(&registry, agent_id).await?;

    // FileWrite without a preceding File open — download was not started.
    let payload = file_write_payload(file_id, b"orphan chunk");
    let result = handle_beacon_output_callback(
        &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
    )
    .await;

    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "FileWrite for unopened download must yield InvalidCallbackPayload; got: {result:?}"
    );

    // No loot should have been persisted.
    let loot_records = database.loot().list_for_agent(agent_id).await?;
    assert!(loot_records.is_empty(), "no loot should be persisted on error; got: {loot_records:?}");
    Ok(())
}

// ------------------------------------------------------------------
// handle_beacon_output_callback — truncated file open header
// ------------------------------------------------------------------

#[tokio::test]
async fn beacon_file_open_truncated_header_returns_error() {
    let database = Database::connect_in_memory().await.expect("unwrap");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let downloads = DownloadTracker::new(1024 * 1024);
    let agent_id: u32 = 0xDA06_0001;
    let request_id: u32 = 401;

    // File open with inner data too short (only 4 bytes instead of 8+).
    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(u32::from(DemonCallback::File)));
    payload.extend_from_slice(&length_prefixed(&[0x00, 0x00, 0x00, 0x01]));

    let result = handle_beacon_output_callback(
        &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
    )
    .await;

    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "truncated file open header must yield InvalidCallbackPayload; got: {result:?}"
    );
}

// ------------------------------------------------------------------
// handle_beacon_output_callback — empty output no-op paths
// ------------------------------------------------------------------

#[tokio::test]
async fn beacon_output_empty_string_skips_broadcast_and_persist()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let downloads = DownloadTracker::new(1024 * 1024);
    let agent_id: u32 = 0xE000_0001;
    let request_id: u32 = 500;

    register_test_agent(&registry, agent_id).await?;

    // Build payload: Output callback with a length-prefixed empty string (len=0).
    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(u32::from(DemonCallback::Output)));
    payload.extend_from_slice(&length_prefixed(b""));

    let result = handle_beacon_output_callback(
        &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
    )
    .await?;

    assert_eq!(result, None, "empty Output must not produce a reply packet");

    // No event should have been broadcast.
    let no_event =
        tokio::time::timeout(std::time::Duration::from_millis(50), receiver.recv()).await;
    assert!(no_event.is_err(), "empty Output must not broadcast an event; got: {no_event:?}");

    // No agent_response should have been persisted.
    let responses = database.agent_responses().list_for_agent(agent_id).await?;
    assert!(
        responses.is_empty(),
        "empty Output must not persist an agent_response record; got: {responses:?}"
    );
    Ok(())
}

#[tokio::test]
async fn beacon_output_utf8_empty_skips_broadcast_and_persist()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let downloads = DownloadTracker::new(1024 * 1024);
    let agent_id: u32 = 0xE000_0002;
    let request_id: u32 = 501;

    register_test_agent(&registry, agent_id).await?;

    // Build payload: OutputUtf8 callback with a length-prefixed empty UTF-16 buffer.
    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(u32::from(DemonCallback::OutputUtf8)));
    payload.extend_from_slice(&length_prefixed(b""));

    let result = handle_beacon_output_callback(
        &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
    )
    .await?;

    assert_eq!(result, None, "empty OutputUtf8 must not produce a reply packet");

    let no_event =
        tokio::time::timeout(std::time::Duration::from_millis(50), receiver.recv()).await;
    assert!(no_event.is_err(), "empty OutputUtf8 must not broadcast an event; got: {no_event:?}");

    let responses = database.agent_responses().list_for_agent(agent_id).await?;
    assert!(
        responses.is_empty(),
        "empty OutputUtf8 must not persist an agent_response record; got: {responses:?}"
    );
    Ok(())
}

#[tokio::test]
async fn beacon_output_oem_empty_skips_broadcast_and_persist()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let downloads = DownloadTracker::new(1024 * 1024);
    let agent_id: u32 = 0xE000_0003;
    let request_id: u32 = 502;

    register_test_agent(&registry, agent_id).await?;

    // Build payload: OutputOem callback with a length-prefixed empty UTF-16 buffer.
    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(u32::from(DemonCallback::OutputOem)));
    payload.extend_from_slice(&length_prefixed(b""));

    let result = handle_beacon_output_callback(
        &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
    )
    .await?;

    assert_eq!(result, None, "empty OutputOem must not produce a reply packet");

    let no_event =
        tokio::time::timeout(std::time::Duration::from_millis(50), receiver.recv()).await;
    assert!(no_event.is_err(), "empty OutputOem must not broadcast an event; got: {no_event:?}");

    let responses = database.agent_responses().list_for_agent(agent_id).await?;
    assert!(
        responses.is_empty(),
        "empty OutputOem must not persist an agent_response record; got: {responses:?}"
    );
    Ok(())
}

#[tokio::test]
async fn beacon_error_message_empty_skips_broadcast_and_persist()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let downloads = DownloadTracker::new(1024 * 1024);
    let agent_id: u32 = 0xE000_0004;
    let request_id: u32 = 503;

    register_test_agent(&registry, agent_id).await?;

    // Build payload: ErrorMessage callback with a length-prefixed empty string.
    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(u32::from(DemonCallback::ErrorMessage)));
    payload.extend_from_slice(&length_prefixed(b""));

    let result = handle_beacon_output_callback(
        &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
    )
    .await?;

    assert_eq!(result, None, "empty ErrorMessage must not produce a reply packet");

    let no_event =
        tokio::time::timeout(std::time::Duration::from_millis(50), receiver.recv()).await;
    assert!(no_event.is_err(), "empty ErrorMessage must not broadcast an event; got: {no_event:?}");

    let responses = database.agent_responses().list_for_agent(agent_id).await?;
    assert!(
        responses.is_empty(),
        "empty ErrorMessage must not persist an agent_response record; got: {responses:?}"
    );
    Ok(())
}

// ------------------------------------------------------------------
// handle_beacon_output_callback — invalid DemonCallback type returns error
// ------------------------------------------------------------------

#[tokio::test]
async fn beacon_output_callback_invalid_callback_type_returns_error()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let downloads = DownloadTracker::new(1024 * 1024);
    let agent_id: u32 = 0xBAAD_F00D;
    let request_id: u32 = 7;

    // Build a payload whose callback type (0xFF) is not a valid DemonCallback variant.
    let invalid_callback: u32 = 0xFF;
    let payload = le32(invalid_callback).to_vec();

    let result = handle_beacon_output_callback(
        &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
    )
    .await;

    let err = result.expect_err("invalid callback type must return an error");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );

    // Verify the error carries the correct command_id.
    if let CommandDispatchError::InvalidCallbackPayload { command_id, .. } = &err {
        assert_eq!(
            *command_id,
            u32::from(red_cell_common::demon::DemonCommand::BeaconOutput),
            "command_id in error must match BeaconOutput"
        );
    }

    Ok(())
}
