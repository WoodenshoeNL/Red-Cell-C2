//! Shared test helpers, builders, and fixtures for dispatch tests.

use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use red_cell_common::demon::{
    DemonCallback, DemonCommand, DemonFilesystemCommand, DemonPivotCommand,
};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Primitive payload helpers
// ---------------------------------------------------------------------------

pub(super) fn add_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

pub(super) fn add_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

pub(super) fn add_bytes(buf: &mut Vec<u8>, value: &[u8]) {
    add_u32(buf, u32::try_from(value.len()).expect("test data fits in u32"));
    buf.extend_from_slice(value);
}

pub(super) fn add_utf16(buf: &mut Vec<u8>, value: &str) {
    let mut encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
    encoded.extend_from_slice(&[0, 0]);
    add_bytes(buf, &encoded);
}

pub(super) fn add_length_prefixed_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(
        &u32::try_from(bytes.len()).expect("test data fits in u32").to_be_bytes(),
    );
    buf.extend_from_slice(bytes);
}

pub(super) fn add_length_prefixed_utf16(buf: &mut Vec<u8>, value: &str) {
    let mut encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
    encoded.extend_from_slice(&[0, 0]);
    add_length_prefixed_bytes(buf, &encoded);
}

pub(super) fn add_checkin_string(buf: &mut Vec<u8>, value: &str) {
    add_bytes(buf, value.as_bytes());
}

pub(super) fn add_checkin_utf16(buf: &mut Vec<u8>, value: &str) {
    let mut encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
    encoded.extend_from_slice(&[0, 0]);
    add_bytes(buf, &encoded);
}

// ---------------------------------------------------------------------------
// Key / IV generators
// ---------------------------------------------------------------------------

/// Generate a non-degenerate test key from a seed byte.
pub(super) fn test_key(seed: u8) -> [u8; AGENT_KEY_LENGTH] {
    core::array::from_fn(|i| seed.wrapping_add(i as u8))
}

/// Generate a non-degenerate test IV from a seed byte.
pub(super) fn test_iv(seed: u8) -> [u8; AGENT_IV_LENGTH] {
    core::array::from_fn(|i| seed.wrapping_add(i as u8))
}

// ---------------------------------------------------------------------------
// Agent record builder
// ---------------------------------------------------------------------------

pub(super) fn sample_agent_info(
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
            // registry.insert() uses legacy_ctr=false; row_to_agent_record derives monotonic_ctr=true.
            monotonic_ctr: true,
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

// ---------------------------------------------------------------------------
// Checkin metadata payload builders
// ---------------------------------------------------------------------------

pub(super) fn sample_checkin_metadata_payload(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> Vec<u8> {
    sample_checkin_metadata_payload_with_kill_date_and_working_hours(
        agent_id,
        key,
        iv,
        1_725_000_000,
        0x00FF_00FF,
    )
}

pub(super) fn sample_checkin_metadata_payload_with_working_hours(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    working_hours: u32,
) -> Vec<u8> {
    sample_checkin_metadata_payload_with_kill_date_and_working_hours(
        agent_id,
        key,
        iv,
        1_725_000_000,
        working_hours,
    )
}

pub(super) fn sample_checkin_metadata_payload_with_kill_date_and_working_hours(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    kill_date: u64,
    working_hours: u32,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&key);
    payload.extend_from_slice(&iv);
    add_u32(&mut payload, agent_id);
    add_checkin_string(&mut payload, "wkstn-02");
    add_checkin_string(&mut payload, "svc-op");
    add_checkin_string(&mut payload, "research");
    add_checkin_string(&mut payload, "10.10.10.50");
    add_checkin_utf16(&mut payload, "C:\\Windows\\System32\\cmd.exe");
    add_u32(&mut payload, 4040);
    add_u32(&mut payload, 5050);
    add_u32(&mut payload, 3030);
    add_u32(&mut payload, 1);
    add_u32(&mut payload, 0);
    add_u64(&mut payload, 0x401000);
    add_u32(&mut payload, 10);
    add_u32(&mut payload, 0);
    add_u32(&mut payload, 1);
    add_u32(&mut payload, 0);
    add_u32(&mut payload, 22_621);
    add_u32(&mut payload, 9);
    add_u32(&mut payload, 45);
    add_u32(&mut payload, 5);
    add_u64(&mut payload, kill_date);
    add_u32(&mut payload, working_hours);
    payload
}

// ---------------------------------------------------------------------------
// Demon init envelope builder
// ---------------------------------------------------------------------------

/// Build a DEMON_INIT envelope with the `INIT_EXT_MONOTONIC_CTR` extension flag set.
///
/// Use this variant in tests that exercise pivot paths (or any code path that runs
/// the production default `allow_legacy_ctr = false` dispatcher), so the CTR-mode
/// gate is satisfied and the test exercises its intended code path rather than
/// hitting the legacy-CTR rejection early.
pub(super) fn valid_demon_init_body_monotonic(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> Vec<u8> {
    let mut metadata = Vec::new();
    metadata.extend_from_slice(&agent_id.to_be_bytes());
    add_length_prefixed_bytes(&mut metadata, b"wkstn-01");
    add_length_prefixed_bytes(&mut metadata, b"operator");
    add_length_prefixed_bytes(&mut metadata, b"lab");
    add_length_prefixed_bytes(&mut metadata, b"10.0.0.25");
    add_length_prefixed_utf16(&mut metadata, "C:\\Windows\\explorer.exe");
    metadata.extend_from_slice(&1337_u32.to_be_bytes());
    metadata.extend_from_slice(&7331_u32.to_be_bytes());
    metadata.extend_from_slice(&512_u32.to_be_bytes());
    metadata.extend_from_slice(&2_u32.to_be_bytes());
    metadata.extend_from_slice(&1_u32.to_be_bytes());
    metadata.extend_from_slice(&0x1000_u64.to_be_bytes());
    metadata.extend_from_slice(&10_u32.to_be_bytes());
    metadata.extend_from_slice(&0_u32.to_be_bytes());
    metadata.extend_from_slice(&1_u32.to_be_bytes());
    metadata.extend_from_slice(&0_u32.to_be_bytes());
    metadata.extend_from_slice(&22000_u32.to_be_bytes());
    metadata.extend_from_slice(&9_u32.to_be_bytes());
    metadata.extend_from_slice(&10_u32.to_be_bytes());
    metadata.extend_from_slice(&25_u32.to_be_bytes());
    metadata.extend_from_slice(&0_u64.to_be_bytes());
    metadata.extend_from_slice(&0_u32.to_be_bytes());
    // Extension flags: request monotonic (non-legacy) AES-CTR mode.
    metadata.extend_from_slice(&crate::demon::INIT_EXT_MONOTONIC_CTR.to_be_bytes());

    let encrypted = red_cell_common::crypto::encrypt_agent_data(&key, &iv, &metadata)
        .expect("metadata encryption should succeed");
    let payload = [
        u32::from(DemonCommand::DemonInit).to_be_bytes().as_slice(),
        7_u32.to_be_bytes().as_slice(),
        key.as_slice(),
        iv.as_slice(),
        encrypted.as_slice(),
    ]
    .concat();

    red_cell_common::demon::DemonEnvelope::new(agent_id, payload)
        .unwrap_or_else(|error| panic!("failed to build demon init body (monotonic): {error}"))
        .to_bytes()
}

// ---------------------------------------------------------------------------
// Pivot payload builders
// ---------------------------------------------------------------------------

pub(super) fn pivot_connect_payload(inner: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(DemonPivotCommand::SmbConnect).to_le_bytes());
    payload.extend_from_slice(&1_u32.to_le_bytes());
    payload.extend_from_slice(
        &u32::try_from(inner.len()).expect("test data fits in u32").to_le_bytes(),
    );
    payload.extend_from_slice(inner);
    payload
}

pub(super) fn decode_pivot_payload(payload: &[u8]) -> Result<(u32, Vec<u8>), String> {
    if payload.len() < 12 {
        return Err("pivot payload too short".to_owned());
    }

    let subcommand = u32::from_le_bytes(
        payload[0..4].try_into().map_err(|_| "invalid pivot subcommand".to_owned())?,
    );
    if subcommand != u32::from(DemonPivotCommand::SmbCommand) {
        return Err(format!("unexpected pivot subcommand {subcommand}"));
    }

    let target_agent_id = u32::from_le_bytes(
        payload[4..8].try_into().map_err(|_| "invalid pivot target".to_owned())?,
    );
    let outer_len = usize::try_from(u32::from_le_bytes(
        payload[8..12].try_into().map_err(|_| "invalid pivot outer length".to_owned())?,
    ))
    .map_err(|_| "pivot outer length overflow".to_owned())?;
    let outer =
        payload.get(12..12 + outer_len).ok_or_else(|| "pivot outer buffer truncated".to_owned())?;
    if outer.len() < 8 {
        return Err("pivot outer buffer too short".to_owned());
    }

    let inner_target = u32::from_le_bytes(
        outer[0..4].try_into().map_err(|_| "invalid pivot inner target".to_owned())?,
    );
    if inner_target != target_agent_id {
        return Err("pivot target mismatch".to_owned());
    }

    let inner_len = usize::try_from(u32::from_le_bytes(
        outer[4..8].try_into().map_err(|_| "invalid pivot inner length".to_owned())?,
    ))
    .map_err(|_| "pivot inner length overflow".to_owned())?;
    let inner =
        outer.get(8..8 + inner_len).ok_or_else(|| "pivot inner buffer truncated".to_owned())?;
    Ok((target_agent_id, inner.to_vec()))
}

pub(super) fn pivot_command_payload(inner_envelope: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(DemonPivotCommand::SmbCommand).to_le_bytes());
    add_bytes(&mut payload, inner_envelope);
    payload
}

// ---------------------------------------------------------------------------
// Beacon file payload builders
// ---------------------------------------------------------------------------

pub(super) fn beacon_file_open(file_id: u32, expected_size: u32, remote_path: &str) -> Vec<u8> {
    let mut header = Vec::new();
    header.extend_from_slice(&file_id.to_be_bytes());
    header.extend_from_slice(&expected_size.to_be_bytes());
    header.extend_from_slice(remote_path.as_bytes());
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonCallback::File));
    add_bytes(&mut payload, &header);
    payload
}

pub(super) fn beacon_file_write(file_id: u32, chunk: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&file_id.to_be_bytes());
    bytes.extend_from_slice(chunk);
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonCallback::FileWrite));
    add_bytes(&mut payload, &bytes);
    payload
}

pub(super) fn beacon_file_close(file_id: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonCallback::FileClose));
    add_bytes(&mut payload, &file_id.to_be_bytes());
    payload
}

// ---------------------------------------------------------------------------
// Filesystem download payload builders
// ---------------------------------------------------------------------------

pub(super) fn filesystem_download_open(
    file_id: u32,
    expected_size: u64,
    remote_path: &str,
) -> Vec<u8> {
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut payload, 0);
    add_u32(&mut payload, file_id);
    add_u64(&mut payload, expected_size);
    add_utf16(&mut payload, remote_path);
    payload
}

pub(super) fn filesystem_download_write(file_id: u32, chunk: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut payload, 1);
    add_u32(&mut payload, file_id);
    add_bytes(&mut payload, chunk);
    payload
}

pub(super) fn filesystem_download_close(file_id: u32, reason: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut payload, 2);
    add_u32(&mut payload, file_id);
    add_u32(&mut payload, reason);
    payload
}

// ---------------------------------------------------------------------------
// Callback envelope builder
// ---------------------------------------------------------------------------

/// Build a valid Demon callback envelope for `agent_id` containing a single callback
/// package with the given `command_id`, `request_id`, and inner payload bytes.
pub(super) fn valid_callback_envelope(
    agent_id: u32,
    key: &[u8; AGENT_KEY_LENGTH],
    iv: &[u8; AGENT_IV_LENGTH],
    command_id: u32,
    request_id: u32,
    inner_payload: &[u8],
) -> Vec<u8> {
    // The callback plaintext is: length-prefixed payload (BE) for the first package.
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(
        &u32::try_from(inner_payload.len()).expect("test data fits in u32").to_be_bytes(),
    );
    plaintext.extend_from_slice(inner_payload);

    let encrypted = red_cell_common::crypto::encrypt_agent_data(key, iv, &plaintext)
        .expect("callback payload encryption should succeed");

    let mut envelope_payload = Vec::new();
    envelope_payload.extend_from_slice(&command_id.to_be_bytes());
    envelope_payload.extend_from_slice(&request_id.to_be_bytes());
    envelope_payload.extend_from_slice(&encrypted);

    red_cell_common::demon::DemonEnvelope::new(agent_id, envelope_payload)
        .unwrap_or_else(|error| panic!("failed to build callback envelope: {error}"))
        .to_bytes()
}
