use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use zeroize::Zeroizing;

use super::parse::parse_checkin_metadata;
use super::validate::validate_checkin_transport_material;
use super::*;
use crate::{AgentRegistry, AuditQuery, Database, EventBus, query_audit_log};

/// Generate a non-degenerate test key from a seed byte.
fn test_key(seed: u8) -> [u8; AGENT_KEY_LENGTH] {
    core::array::from_fn(|i| seed.wrapping_add(i as u8))
}

/// Generate a non-degenerate test IV from a seed byte.
fn test_iv(seed: u8) -> [u8; AGENT_IV_LENGTH] {
    core::array::from_fn(|i| seed.wrapping_add(i as u8))
}

#[test]
fn decode_working_hours_zero_returns_none() {
    assert_eq!(decode_working_hours(0u32), None);
}

#[test]
fn decode_working_hours_nonzero_returns_some() {
    assert_eq!(decode_working_hours(0b101010u32), Some(42i32));
}

#[test]
fn decode_working_hours_high_bit_set_preserves_sign() {
    // 0x8000_0000 as u32 → i32::MIN when reinterpreted via big-endian bytes.
    assert_eq!(decode_working_hours(0x8000_0000u32), Some(i32::MIN));
}

// -- helpers for building checkin payloads --

fn push_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn push_bytes(buf: &mut Vec<u8>, value: &[u8]) {
    push_u32(buf, u32::try_from(value.len()).expect("test data fits in u32"));
    buf.extend_from_slice(value);
}

fn push_checkin_string(buf: &mut Vec<u8>, value: &str) {
    push_bytes(buf, value.as_bytes());
}

fn push_checkin_utf16(buf: &mut Vec<u8>, value: &str) {
    let mut encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
    encoded.extend_from_slice(&[0, 0]);
    push_bytes(buf, &encoded);
}

fn make_checkin_payload(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&key);
    buf.extend_from_slice(&iv);
    push_u32(&mut buf, agent_id);
    push_checkin_string(&mut buf, "wkstn-02");
    push_checkin_string(&mut buf, "svc-op");
    push_checkin_string(&mut buf, "research");
    push_checkin_string(&mut buf, "10.10.10.50");
    push_checkin_utf16(&mut buf, "C:\\Windows\\System32\\cmd.exe");
    push_u32(&mut buf, 4040); // pid
    push_u32(&mut buf, 5050); // tid
    push_u32(&mut buf, 3030); // ppid
    push_u32(&mut buf, 1); // arch
    push_u32(&mut buf, 0); // elevated
    push_u64(&mut buf, 0x401000); // base_address
    push_u32(&mut buf, 10); // os_major
    push_u32(&mut buf, 0); // os_minor
    push_u32(&mut buf, 1); // os_product_type
    push_u32(&mut buf, 0); // os_service_pack
    push_u32(&mut buf, 22_621); // os_build
    push_u32(&mut buf, 9); // os_arch
    push_u32(&mut buf, 45); // sleep_delay
    push_u32(&mut buf, 5); // sleep_jitter
    push_u64(&mut buf, 1_725_000_000); // kill_date
    push_u32(&mut buf, 0x00FF_00FF); // working_hours
    buf
}

fn sample_agent(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> red_cell_common::AgentRecord {
    red_cell_common::AgentRecord {
        agent_id,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: red_cell_common::AgentEncryptionInfo {
            aes_key: Zeroizing::new(key.to_vec()),
            aes_iv: Zeroizing::new(iv.to_vec()),
        },
        hostname: "wkstn-01".to_owned(),
        username: "operator".to_owned(),
        domain_name: "lab".to_owned(),
        external_ip: "127.0.0.1".to_owned(),
        internal_ip: "10.0.0.25".to_owned(),
        process_name: "explorer.exe".to_owned(),
        process_path: "C:\\Windows\\explorer.exe".to_owned(),
        base_address: 0x1000,
        process_pid: 1337,
        process_tid: 7331,
        process_ppid: 512,
        process_arch: "x64".to_owned(),
        elevated: true,
        os_version: "Windows 11".to_owned(),
        os_build: 0,
        os_arch: "x64".to_owned(),
        sleep_delay: 10,
        sleep_jitter: 25,
        kill_date: None,
        working_hours: None,
        first_call_in: "2026-03-09T20:00:00Z".to_owned(),
        last_call_in: "2026-03-09T20:00:00Z".to_owned(),
        archon_magic: None,
    }
}

/// Verify that `handle_checkin` preserves the original AES session key when
/// the CHECKIN payload carries different key/IV material (replay-attack
/// defence).  This is the security property guarded by lines 29–51.
#[tokio::test]
async fn handle_checkin_rejects_key_rotation_and_preserves_original_session_key()
-> Result<(), Box<dyn std::error::Error>> {
    let original_key = test_key(0xAA);
    let original_iv = test_iv(0xBB);
    let attacker_key = test_key(0xCC);
    let attacker_iv = test_iv(0xDD);
    let agent_id = 0xDEAD_0001;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();

    registry.insert(sample_agent(agent_id, original_key, original_iv)).await?;

    // Build a CHECKIN payload with attacker-controlled key material.
    let payload = make_checkin_payload(agent_id, attacker_key, attacker_iv);

    handle_checkin(&registry, &events, &database, None, agent_id, &payload).await?;

    // The agent's stored encryption must be the original, not the attacker's.
    let agent = registry.get(agent_id).await.ok_or("agent should still be registered")?;

    assert_eq!(
        agent.encryption.aes_key.as_slice(),
        original_key.as_slice(),
        "AES key must not be overwritten by CHECKIN payload"
    );
    assert_eq!(
        agent.encryption.aes_iv.as_slice(),
        original_iv.as_slice(),
        "AES IV must not be overwritten by CHECKIN payload"
    );

    Ok(())
}

/// When the CHECKIN payload carries the *same* key/IV as already registered,
/// no rotation is detected and the metadata update proceeds normally.
#[tokio::test]
async fn handle_checkin_accepts_same_key_without_triggering_rotation_guard()
-> Result<(), Box<dyn std::error::Error>> {
    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0002;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();

    registry.insert(sample_agent(agent_id, key, iv)).await?;

    // CHECKIN with the same key — should update metadata without warnings.
    let payload = make_checkin_payload(agent_id, key, iv);
    handle_checkin(&registry, &events, &database, None, agent_id, &payload).await?;

    let agent = registry.get(agent_id).await.ok_or("agent should still be registered")?;

    assert_eq!(agent.encryption.aes_key.as_slice(), key.as_slice());
    assert_eq!(agent.encryption.aes_iv.as_slice(), iv.as_slice());
    // Metadata should have been updated from the payload.
    assert_eq!(agent.hostname, "wkstn-02");
    assert_eq!(agent.username, "svc-op");

    Ok(())
}

/// A payload shorter than the 48-byte metadata prefix must be rejected
/// with `InvalidCallbackPayload`.  This guards against truncated or
/// malformed CHECKIN frames reaching the parser.
#[test]
fn parse_checkin_metadata_rejects_truncated_payload() {
    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0003;
    let existing = sample_agent(agent_id, key, iv);

    // 47 bytes — one byte short of the 48-byte minimum.
    let truncated = vec![0x42u8; 47];
    let result = parse_checkin_metadata(existing, agent_id, &truncated, "2026-03-17T00:00:00Z");

    let err = result.expect_err("truncated payload must be rejected");
    match &err {
        CommandDispatchError::InvalidCallbackPayload { command_id, message } => {
            assert_eq!(
                *command_id,
                u32::from(red_cell_common::demon::DemonCommand::CommandCheckin),
                "error must reference CommandCheckin"
            );
            assert!(
                message.contains("truncated"),
                "error message should mention truncation, got: {message}"
            );
            assert!(
                message.contains("47"),
                "error message should include actual payload length, got: {message}"
            );
        }
        other => panic!("expected InvalidCallbackPayload, got: {other:?}"),
    }
}

// -- validate_checkin_transport_material unit tests --

#[test]
fn validate_checkin_transport_material_rejects_all_zero_key() {
    let key = [0u8; AGENT_KEY_LENGTH];
    let iv = test_iv(0xAA);
    let err = validate_checkin_transport_material(0x1234, &key, &iv)
        .expect_err("all-zero key must be rejected");
    match err {
        CommandDispatchError::InvalidCallbackPayload { message, .. } => {
            assert!(message.contains("key"), "message should mention key: {message}");
        }
        other => panic!("expected InvalidCallbackPayload, got: {other:?}"),
    }
}

#[test]
fn validate_checkin_transport_material_rejects_all_zero_iv() {
    let key = test_key(0xBB);
    let iv = [0u8; AGENT_IV_LENGTH];
    let err = validate_checkin_transport_material(0x1234, &key, &iv)
        .expect_err("all-zero IV must be rejected");
    match err {
        CommandDispatchError::InvalidCallbackPayload { message, .. } => {
            assert!(message.contains("IV"), "message should mention IV: {message}");
        }
        other => panic!("expected InvalidCallbackPayload, got: {other:?}"),
    }
}

#[test]
fn validate_checkin_transport_material_rejects_both_zero() {
    let key = [0u8; AGENT_KEY_LENGTH];
    let iv = [0u8; AGENT_IV_LENGTH];
    // When both are zero, key check fires first.
    let err = validate_checkin_transport_material(0x1234, &key, &iv)
        .expect_err("all-zero key+IV must be rejected");
    match err {
        CommandDispatchError::InvalidCallbackPayload { message, .. } => {
            assert!(message.contains("key"), "key should be checked first: {message}");
        }
        other => panic!("expected InvalidCallbackPayload, got: {other:?}"),
    }
}

#[test]
fn validate_checkin_transport_material_rejects_repeating_byte_key() {
    let key = [0xAA; AGENT_KEY_LENGTH];
    let iv = test_iv(0xBB);
    let err = validate_checkin_transport_material(0x1234, &key, &iv)
        .expect_err("repeating-byte key must be rejected");
    match err {
        CommandDispatchError::InvalidCallbackPayload { message, .. } => {
            assert!(message.contains("key"), "message should mention key: {message}");
        }
        other => panic!("expected InvalidCallbackPayload, got: {other:?}"),
    }
}

#[test]
fn validate_checkin_transport_material_rejects_repeating_byte_iv() {
    let key = test_key(0xBB);
    let iv = [0xCC; AGENT_IV_LENGTH];
    let err = validate_checkin_transport_material(0x1234, &key, &iv)
        .expect_err("repeating-byte IV must be rejected");
    match err {
        CommandDispatchError::InvalidCallbackPayload { message, .. } => {
            assert!(message.contains("IV"), "message should mention IV: {message}");
        }
        other => panic!("expected InvalidCallbackPayload, got: {other:?}"),
    }
}

#[test]
fn validate_checkin_transport_material_accepts_valid_material() {
    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    validate_checkin_transport_material(0x1234, &key, &iv)
        .expect("valid key and IV must be accepted");
}

/// A key with only the last byte non-zero is NOT considered weak by
/// `is_weak_aes_key` (not a repeating pattern).  Verify that
/// `validate_checkin_transport_material` passes this boundary case.
#[test]
fn validate_checkin_transport_material_accepts_partially_zeroed_key() {
    let mut key = [0u8; AGENT_KEY_LENGTH];
    key[AGENT_KEY_LENGTH - 1] = 1;
    let iv = test_iv(0xCC);
    validate_checkin_transport_material(0x1234, &key, &iv)
        .expect("partially-zeroed key (last byte non-zero) must be accepted");
}

/// Same boundary test for IV: only the first byte is non-zero.
#[test]
fn validate_checkin_transport_material_accepts_partially_zeroed_iv() {
    let key = test_key(0xAA);
    let mut iv = [0u8; AGENT_IV_LENGTH];
    iv[0] = 1;
    validate_checkin_transport_material(0x1234, &key, &iv)
        .expect("partially-zeroed IV (first byte non-zero) must be accepted");
}

/// An empty CHECKIN payload (heartbeat-only, no metadata) must leave the
/// existing agent record unchanged except for `last_call_in`.
#[tokio::test]
async fn handle_checkin_empty_payload_updates_last_call_in_only()
-> Result<(), Box<dyn std::error::Error>> {
    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0010;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();

    let original = sample_agent(agent_id, key, iv);
    registry.insert(original.clone()).await?;

    handle_checkin(&registry, &events, &database, None, agent_id, &[]).await?;

    let agent = registry.get(agent_id).await.ok_or("agent should still exist")?;
    assert_eq!(agent.hostname, original.hostname, "hostname must not change on empty checkin");
    assert_eq!(agent.username, original.username, "username must not change on empty checkin");
    assert_ne!(agent.last_call_in, original.last_call_in, "last_call_in must be updated");

    Ok(())
}

/// A rejected checkin (truncated payload) must not modify the stored agent
/// record — the original metadata must be preserved unchanged.
#[tokio::test]
async fn handle_checkin_truncated_payload_does_not_mutate_agent()
-> Result<(), Box<dyn std::error::Error>> {
    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0011;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();

    let original = sample_agent(agent_id, key, iv);
    registry.insert(original.clone()).await?;

    // 10 bytes — too short for the 48-byte metadata prefix.
    let result = handle_checkin(&registry, &events, &database, None, agent_id, &[0x42; 10]).await;
    assert!(result.is_err(), "truncated payload must be rejected");

    let agent = registry.get(agent_id).await.ok_or("agent should still exist")?;
    assert_eq!(agent.hostname, original.hostname, "hostname must not change after rejection");
    assert_eq!(agent.username, original.username, "username must not change after rejection");
    assert_eq!(
        agent.last_call_in, original.last_call_in,
        "last_call_in must not change after rejection"
    );

    Ok(())
}

/// When the agent ID inside the payload differs from the outer envelope's
/// agent ID, `parse_checkin_metadata` must return `InvalidCallbackPayload`.
/// This prevents silent state corruption from misrouted or tampered frames.
#[test]
fn parse_checkin_metadata_rejects_agent_id_mismatch() {
    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    let envelope_agent_id = 0xDEAD_0004;
    let payload_agent_id = 0xDEAD_FFFF; // different from envelope
    let existing = sample_agent(envelope_agent_id, key, iv);

    let payload = make_checkin_payload(payload_agent_id, key, iv);
    let result =
        parse_checkin_metadata(existing, envelope_agent_id, &payload, "2026-03-17T00:00:00Z");

    let err = result.expect_err("agent ID mismatch must be rejected");
    match &err {
        CommandDispatchError::InvalidCallbackPayload { command_id, message } => {
            assert_eq!(
                *command_id,
                u32::from(red_cell_common::demon::DemonCommand::CommandCheckin),
                "error must reference CommandCheckin"
            );
            assert!(
                message.contains("mismatch"),
                "error message should mention mismatch, got: {message}"
            );
            assert!(
                message.contains(&format!("0x{envelope_agent_id:08X}")),
                "error message should include expected agent ID, got: {message}"
            );
            assert!(
                message.contains(&format!("0x{payload_agent_id:08X}")),
                "error message should include actual agent ID, got: {message}"
            );
        }
        other => panic!("expected InvalidCallbackPayload, got: {other:?}"),
    }
}

/// Happy-path: a valid checkin payload updates *all* metadata fields on the
/// agent record (hostname, username, domain, IPs, process info, OS, sleep,
/// working hours, etc.) and broadcasts an `AgentUpdate` "Alive" event.
#[tokio::test]
async fn handle_checkin_valid_payload_updates_all_metadata_and_broadcasts_alive()
-> Result<(), Box<dyn std::error::Error>> {
    use red_cell_common::operator::OperatorMessage;

    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0020;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut rx = events.subscribe();

    let original = sample_agent(agent_id, key, iv);
    registry.insert(original.clone()).await?;

    let payload = make_checkin_payload(agent_id, key, iv);
    handle_checkin(&registry, &events, &database, None, agent_id, &payload).await?;

    let agent = registry.get(agent_id).await.ok_or("agent should exist")?;

    // Metadata fields from the payload.
    assert_eq!(agent.hostname, "wkstn-02");
    assert_eq!(agent.username, "svc-op");
    assert_eq!(agent.domain_name, "research");
    assert_eq!(agent.internal_ip, "10.10.10.50");
    assert_eq!(agent.process_name, "cmd.exe");
    assert_eq!(agent.process_path, "C:\\Windows\\System32\\cmd.exe");
    assert_eq!(agent.process_pid, 4040);
    assert_eq!(agent.process_tid, 5050);
    assert_eq!(agent.process_ppid, 3030);
    assert_eq!(agent.base_address, 0x401000);
    assert!(!agent.elevated, "elevated should be false from payload");
    assert_eq!(agent.sleep_delay, 45);
    assert_eq!(agent.sleep_jitter, 5);
    assert_eq!(agent.os_build, 22_621);
    assert!(agent.active, "agent must be marked active after checkin");
    assert_ne!(agent.last_call_in, original.last_call_in, "last_call_in must be refreshed");

    // working_hours from payload: 0x00FF_00FF
    assert_eq!(
        agent.working_hours,
        decode_working_hours(0x00FF_00FF),
        "working_hours must match decoded payload value"
    );

    // Verify the broadcast event is an AgentUpdate with "Alive".
    let event = rx.recv().await.ok_or("should have received a broadcast event")?;
    match event {
        OperatorMessage::AgentUpdate(msg) => {
            assert_eq!(msg.info.agent_id, format!("{agent_id:08X}"));
            assert_eq!(msg.info.marked, "Alive");
        }
        other => panic!("expected AgentUpdate, got: {other:?}"),
    }

    Ok(())
}

/// When the CHECKIN payload contains an all-zero AES key, `handle_checkin`
/// must return `InvalidCallbackPayload` and leave the stored agent record
/// completely untouched.
#[tokio::test]
async fn handle_checkin_weak_aes_key_rejects_and_does_not_mutate()
-> Result<(), Box<dyn std::error::Error>> {
    let good_key = test_key(0xAA);
    let good_iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0030;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();

    let original = sample_agent(agent_id, good_key, good_iv);
    registry.insert(original.clone()).await?;

    // Build payload with all-zero key (weak).
    let weak_key = [0u8; AGENT_KEY_LENGTH];
    let payload = make_checkin_payload(agent_id, weak_key, good_iv);
    let result = handle_checkin(&registry, &events, &database, None, agent_id, &payload).await;

    assert!(result.is_err(), "weak AES key must be rejected");
    match result.expect_err("expected Err") {
        CommandDispatchError::InvalidCallbackPayload { message, .. } => {
            assert!(message.contains("key"), "error should mention key: {message}");
        }
        other => panic!("expected InvalidCallbackPayload, got: {other:?}"),
    }

    // Agent state must be unchanged.
    let agent = registry.get(agent_id).await.ok_or("agent should still exist")?;
    assert_eq!(agent.hostname, original.hostname);
    assert_eq!(agent.username, original.username);
    assert_eq!(agent.last_call_in, original.last_call_in);

    Ok(())
}

/// When the CHECKIN payload contains an all-zero AES IV, `handle_checkin`
/// must return `InvalidCallbackPayload` and leave the stored agent record
/// completely untouched.
#[tokio::test]
async fn handle_checkin_weak_aes_iv_rejects_and_does_not_mutate()
-> Result<(), Box<dyn std::error::Error>> {
    let good_key = test_key(0xAA);
    let good_iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0031;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();

    let original = sample_agent(agent_id, good_key, good_iv);
    registry.insert(original.clone()).await?;

    // Build payload with all-zero IV (weak).
    let weak_iv = [0u8; AGENT_IV_LENGTH];
    let payload = make_checkin_payload(agent_id, good_key, weak_iv);
    let result = handle_checkin(&registry, &events, &database, None, agent_id, &payload).await;

    assert!(result.is_err(), "weak AES IV must be rejected");
    match result.expect_err("expected Err") {
        CommandDispatchError::InvalidCallbackPayload { message, .. } => {
            assert!(message.contains("IV"), "error should mention IV: {message}");
        }
        other => panic!("expected InvalidCallbackPayload, got: {other:?}"),
    }

    // Agent state must be unchanged.
    let agent = registry.get(agent_id).await.ok_or("agent should still exist")?;
    assert_eq!(agent.hostname, original.hostname);
    assert_eq!(agent.last_call_in, original.last_call_in);

    Ok(())
}

/// Verify `parse_checkin_metadata` correctly populates all fields from a
/// well-formed payload — the pure-function counterpart to the
/// `handle_checkin` happy-path integration test above.
#[test]
fn parse_checkin_metadata_populates_all_fields() {
    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0040;
    let existing = sample_agent(agent_id, key, iv);

    let payload = make_checkin_payload(agent_id, key, iv);
    let ts = "2026-03-18T12:00:00Z";
    let result = parse_checkin_metadata(existing, agent_id, &payload, ts);

    let updated =
        result.expect("valid payload must succeed").expect("non-empty payload must return Some");

    assert_eq!(updated.hostname, "wkstn-02");
    assert_eq!(updated.username, "svc-op");
    assert_eq!(updated.domain_name, "research");
    assert_eq!(updated.internal_ip, "10.10.10.50");
    assert_eq!(updated.process_name, "cmd.exe");
    assert_eq!(updated.process_path, "C:\\Windows\\System32\\cmd.exe");
    assert_eq!(updated.process_pid, 4040);
    assert_eq!(updated.process_tid, 5050);
    assert_eq!(updated.process_ppid, 3030);
    assert_eq!(updated.base_address, 0x401000);
    assert!(!updated.elevated);
    assert_eq!(updated.sleep_delay, 45);
    assert_eq!(updated.sleep_jitter, 5);
    assert_eq!(updated.os_build, 22_621);
    assert!(updated.active);
    assert!(updated.reason.is_empty());
    assert_eq!(updated.last_call_in, ts);
    assert_eq!(updated.working_hours, decode_working_hours(0x00FF_00FF));
    // kill_date should be parsed from the payload value 1_725_000_000
    assert!(updated.kill_date.is_some(), "kill_date should be set from non-zero payload value");
    // Encryption should carry the payload key/iv (before handle_checkin's rotation guard).
    assert_eq!(updated.encryption.aes_key.as_slice(), key.as_slice());
    assert_eq!(updated.encryption.aes_iv.as_slice(), iv.as_slice());
}

/// Empty payload returns `None` from `parse_checkin_metadata`, indicating
/// heartbeat-only (no metadata update).
#[test]
fn parse_checkin_metadata_empty_payload_returns_none() {
    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0041;
    let existing = sample_agent(agent_id, key, iv);

    let result = parse_checkin_metadata(existing, agent_id, &[], "2026-03-18T12:00:00Z");
    let opt = result.expect("empty payload must not error");
    assert!(opt.is_none(), "empty payload must return None");
}

/// Verify that the empty-payload path through `handle_checkin` broadcasts
/// an `AgentUpdate` "Alive" event even when no metadata is updated.
#[tokio::test]
async fn handle_checkin_empty_payload_still_broadcasts_alive()
-> Result<(), Box<dyn std::error::Error>> {
    use red_cell_common::operator::OperatorMessage;

    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0050;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut rx = events.subscribe();

    registry.insert(sample_agent(agent_id, key, iv)).await?;

    handle_checkin(&registry, &events, &database, None, agent_id, &[]).await?;

    let event = rx.recv().await.ok_or("should have received a broadcast")?;
    match event {
        OperatorMessage::AgentUpdate(msg) => {
            assert_eq!(msg.info.agent_id, format!("{agent_id:08X}"));
            assert_eq!(msg.info.marked, "Alive");
        }
        other => panic!("expected AgentUpdate, got: {other:?}"),
    }

    Ok(())
}

// -- plugin branch (emit_agent_checkin) tests --

/// Happy path: `handle_checkin` with `plugins = Some(stub_succeeding)` still
/// returns `Ok(None)` and completes without error.
#[tokio::test]
async fn handle_checkin_with_succeeding_plugin_runtime_returns_ok()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::{PluginRuntime, SocketRelayManager};

    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0020;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());

    registry.insert(sample_agent(agent_id, key, iv)).await?;

    let runtime =
        PluginRuntime::stub_succeeding(database.clone(), registry.clone(), events.clone(), sockets);

    let result =
        handle_checkin(&registry, &events, &database, Some(&runtime), agent_id, &[]).await?;
    assert_eq!(result, None, "handle_checkin must return Ok(None) with succeeding plugins");

    Ok(())
}

/// Error path: `handle_checkin` with `plugins = Some(stub_failing)` still
/// returns `Ok(None)` — plugin errors are non-fatal.
#[tokio::test]
async fn handle_checkin_with_failing_plugin_runtime_returns_ok()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::{PluginRuntime, SocketRelayManager};

    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0021;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());

    registry.insert(sample_agent(agent_id, key, iv)).await?;

    let runtime =
        PluginRuntime::stub_failing(database.clone(), registry.clone(), events.clone(), sockets);

    let result =
        handle_checkin(&registry, &events, &database, Some(&runtime), agent_id, &[]).await?;
    assert_eq!(result, None, "handle_checkin must return Ok(None) even when plugin emit fails");

    Ok(())
}

/// The audit entry for `agent.checkin` must still be written when the plugin
/// emit fails — the spawned audit task is independent of the plugin branch.
#[tokio::test]
async fn handle_checkin_audit_entry_written_despite_plugin_failure()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::{PluginRuntime, SocketRelayManager};

    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0022;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());

    registry.insert(sample_agent(agent_id, key, iv)).await?;

    let runtime =
        PluginRuntime::stub_failing(database.clone(), registry.clone(), events.clone(), sockets);

    handle_checkin(&registry, &events, &database, Some(&runtime), agent_id, &[]).await?;

    // The audit write is spawned as a background task — yield to let it complete.
    tokio::task::yield_now().await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let page = query_audit_log(
        &database,
        &AuditQuery {
            action: Some("agent.checkin".to_owned()),
            target_id: Some(format!("{agent_id:08X}")),
            ..Default::default()
        },
    )
    .await?;

    assert!(
        !page.items.is_empty(),
        "agent.checkin audit entry must be written even when plugin emit fails"
    );
    assert_eq!(page.items[0].action, "agent.checkin");

    Ok(())
}

// -- replay-warning path (seq protection) tests --

/// For a non-seq-protected (Demon/Archon) agent, a valid CHECKIN with metadata
/// must succeed — the replay warning is advisory only and must not block the update.
#[tokio::test]
async fn handle_checkin_non_seq_protected_agent_metadata_updated_with_warning()
-> Result<(), Box<dyn std::error::Error>> {
    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0060;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();

    registry.insert(sample_agent(agent_id, key, iv)).await?;
    // Newly inserted agents default to seq_protected = false (Demon/Archon compatibility).
    assert!(
        !registry.is_seq_protected(agent_id).await,
        "test precondition: agent must not be seq-protected"
    );

    let payload = make_checkin_payload(agent_id, key, iv);
    // Must succeed (warning is emitted but does not block the update).
    handle_checkin(&registry, &events, &database, None, agent_id, &payload).await?;

    let agent = registry.get(agent_id).await.ok_or("agent should still exist")?;
    // Metadata must have been updated despite the replay-warning path.
    assert_eq!(agent.hostname, "wkstn-02", "hostname must be updated for non-seq-protected agent");
    assert_eq!(agent.username, "svc-op", "username must be updated for non-seq-protected agent");

    Ok(())
}

/// For a seq-protected (Specter/Phantom) agent, a valid CHECKIN with metadata
/// must succeed and the replay-warning code path must not fire.
#[tokio::test]
async fn handle_checkin_seq_protected_agent_metadata_updated_without_replay_warning()
-> Result<(), Box<dyn std::error::Error>> {
    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0061;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();

    registry.insert(sample_agent(agent_id, key, iv)).await?;
    // Mark agent as seq-protected (Specter/Phantom path).
    registry.set_seq_protected(agent_id, true).await?;
    assert!(
        registry.is_seq_protected(agent_id).await,
        "test precondition: agent must be seq-protected"
    );

    let payload = make_checkin_payload(agent_id, key, iv);
    // Must succeed without emitting the replay warning.
    handle_checkin(&registry, &events, &database, None, agent_id, &payload).await?;

    let agent = registry.get(agent_id).await.ok_or("agent should still exist")?;
    assert_eq!(agent.hostname, "wkstn-02", "hostname must be updated for seq-protected agent");
    assert_eq!(agent.username, "svc-op", "username must be updated for seq-protected agent");

    Ok(())
}
