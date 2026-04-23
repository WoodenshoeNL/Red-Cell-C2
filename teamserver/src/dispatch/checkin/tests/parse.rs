use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};

use super::super::CommandDispatchError;
use super::super::parse::parse_checkin_metadata;
use super::super::validate::validate_checkin_transport_material;
use super::{make_checkin_payload, sample_agent, test_iv, test_key};

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

/// Verify `parse_checkin_metadata` correctly populates all fields from a
/// well-formed payload — the pure-function counterpart to the
/// `handle_checkin` happy-path integration test above.
#[test]
fn parse_checkin_metadata_populates_all_fields() {
    use super::super::decode_working_hours;

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
