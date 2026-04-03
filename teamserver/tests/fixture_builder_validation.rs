//! Tests that validate the shared fixture builders in `common/mod.rs`.
//!
//! A bug in a fixture builder can silently invalidate many integration tests,
//! so these tests decode the produced [`DemonEnvelope`]s and verify command IDs,
//! metadata fields, encrypted body layout, and reconnect shape independently.

mod common;

use red_cell_common::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len, decrypt_agent_data,
    decrypt_agent_data_at_offset,
};
use red_cell_common::demon::{DEMON_MAGIC_VALUE, DemonCommand, DemonEnvelope};

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

#[test]
fn add_length_prefixed_bytes_be_encodes_correctly() {
    let mut buf = Vec::new();
    common::add_length_prefixed_bytes_be(&mut buf, b"hello");
    // 4-byte BE length prefix + payload
    assert_eq!(buf.len(), 4 + 5);
    let len = u32::from_be_bytes(buf[..4].try_into().expect("fixed-size slice for try_into"));
    assert_eq!(len, 5);
    assert_eq!(&buf[4..], b"hello");
}

#[test]
fn add_length_prefixed_bytes_be_handles_empty() {
    let mut buf = Vec::new();
    common::add_length_prefixed_bytes_be(&mut buf, b"");
    assert_eq!(buf.len(), 4);
    let len = u32::from_be_bytes(buf[..4].try_into().expect("fixed-size slice for try_into"));
    assert_eq!(len, 0);
}

#[test]
fn add_length_prefixed_utf16_le_encodes_correctly() {
    let mut buf = Vec::new();
    common::add_length_prefixed_utf16_le(&mut buf, "AB");
    // "AB" = 2 code units × 2 bytes + 2 null terminator = 6 bytes payload
    // Total = 4 length prefix + 6 payload = 10
    let len = u32::from_be_bytes(buf[..4].try_into().expect("fixed-size slice for try_into"));
    assert_eq!(len, 6);
    // 'A' = 0x0041 LE, 'B' = 0x0042 LE, null = 0x0000
    assert_eq!(&buf[4..], &[0x41, 0x00, 0x42, 0x00, 0x00, 0x00]);
}

#[test]
fn command_output_payload_encodes_le_length_prefix() {
    let output = "test output";
    let payload = common::command_output_payload(output);
    assert_eq!(payload.len(), 4 + output.len());
    let len = u32::from_le_bytes(payload[..4].try_into().expect("fixed-size slice for try_into"));
    assert_eq!(len as usize, output.len());
    assert_eq!(&payload[4..], output.as_bytes());
}

// ---------------------------------------------------------------------------
// valid_demon_init_body
// ---------------------------------------------------------------------------

#[test]
fn init_body_round_trips_through_envelope() {
    let agent_id: u32 = 0xCAFE_0001;
    let key = [0x11_u8; AGENT_KEY_LENGTH];
    let iv = [0x22_u8; AGENT_IV_LENGTH];

    let bytes = common::valid_demon_init_body(agent_id, key, iv);
    let envelope =
        DemonEnvelope::from_bytes(&bytes).expect("init body must parse as valid envelope");

    assert_eq!(envelope.header.magic, DEMON_MAGIC_VALUE);
    assert_eq!(envelope.header.agent_id, agent_id);
}

#[test]
fn init_body_payload_starts_with_demon_init_command() {
    let agent_id: u32 = 0xBEEF_0001;
    let key = [0x33_u8; AGENT_KEY_LENGTH];
    let iv = [0x44_u8; AGENT_IV_LENGTH];

    let bytes = common::valid_demon_init_body(agent_id, key, iv);
    let envelope = DemonEnvelope::from_bytes(&bytes).expect("envelope parse");

    // First 4 bytes of payload = command ID (DemonInit = 99)
    let command_id = u32::from_be_bytes(envelope.payload[..4].try_into().expect("fixed-size slice for try_into"));
    assert_eq!(command_id, u32::from(DemonCommand::DemonInit));
}

#[test]
fn init_body_payload_contains_request_id_seven() {
    let agent_id: u32 = 0xBEEF_0002;
    let key = [0x55_u8; AGENT_KEY_LENGTH];
    let iv = [0x66_u8; AGENT_IV_LENGTH];

    let bytes = common::valid_demon_init_body(agent_id, key, iv);
    let envelope = DemonEnvelope::from_bytes(&bytes).expect("envelope parse");

    // Bytes 4..8 = request ID, hardcoded to 7
    let request_id = u32::from_be_bytes(envelope.payload[4..8].try_into().expect("fixed-size slice for try_into"));
    assert_eq!(request_id, 7);
}

#[test]
fn init_body_payload_embeds_key_and_iv_in_cleartext() {
    let agent_id: u32 = 0xBEEF_0003;
    let key = [0x77_u8; AGENT_KEY_LENGTH];
    let iv = [0x88_u8; AGENT_IV_LENGTH];

    let bytes = common::valid_demon_init_body(agent_id, key, iv);
    let envelope = DemonEnvelope::from_bytes(&bytes).expect("envelope parse");

    // After command_id (4) + request_id (4) comes key (32) then IV (16)
    let embedded_key = &envelope.payload[8..8 + AGENT_KEY_LENGTH];
    let embedded_iv =
        &envelope.payload[8 + AGENT_KEY_LENGTH..8 + AGENT_KEY_LENGTH + AGENT_IV_LENGTH];

    assert_eq!(embedded_key, &key);
    assert_eq!(embedded_iv, &iv);
}

#[test]
fn init_body_encrypted_metadata_decrypts_to_expected_fields() {
    let agent_id: u32 = 0xDEAD_0001;
    let key = [0xAA_u8; AGENT_KEY_LENGTH];
    let iv = [0xBB_u8; AGENT_IV_LENGTH];

    let bytes = common::valid_demon_init_body(agent_id, key, iv);
    let envelope = DemonEnvelope::from_bytes(&bytes).expect("envelope parse");

    // Encrypted metadata starts after command_id(4) + request_id(4) + key(32) + iv(16) = 56
    let ciphertext = &envelope.payload[8 + AGENT_KEY_LENGTH + AGENT_IV_LENGTH..];
    let plaintext =
        decrypt_agent_data(&key, &iv, ciphertext).expect("metadata decryption must succeed");

    let mut cursor = 0;

    // agent_id (4 bytes BE)
    let decoded_agent_id = u32::from_be_bytes(plaintext[cursor..cursor + 4].try_into().expect("fixed-size slice for try_into"));
    assert_eq!(decoded_agent_id, agent_id);
    cursor += 4;

    // hostname: length-prefixed "wkstn-01"
    let hostname = read_lp_bytes(&plaintext, &mut cursor);
    assert_eq!(hostname, b"wkstn-01");

    // username: "operator"
    let username = read_lp_bytes(&plaintext, &mut cursor);
    assert_eq!(username, b"operator");

    // domain: "REDCELL"
    let domain = read_lp_bytes(&plaintext, &mut cursor);
    assert_eq!(domain, b"REDCELL");

    // internal IP: "10.0.0.25"
    let ip = read_lp_bytes(&plaintext, &mut cursor);
    assert_eq!(ip, b"10.0.0.25");

    // process path: UTF-16 LE null-terminated "C:\Windows\explorer.exe"
    let process_raw = read_lp_bytes(&plaintext, &mut cursor);
    let decoded = decode_utf16_le_null_terminated(&process_raw);
    assert_eq!(decoded, r"C:\Windows\explorer.exe");

    // PID = 1337
    let pid = read_u32_be(&plaintext, &mut cursor);
    assert_eq!(pid, 1337);

    // PPID = 1338
    let ppid = read_u32_be(&plaintext, &mut cursor);
    assert_eq!(ppid, 1338);

    // architecture = 512
    let arch = read_u32_be(&plaintext, &mut cursor);
    assert_eq!(arch, 512);

    // elevated = 2
    let elevated = read_u32_be(&plaintext, &mut cursor);
    assert_eq!(elevated, 2);

    // base address high bits (1) + low bits as u64 = 0x401000
    let base_addr_flag = read_u32_be(&plaintext, &mut cursor);
    assert_eq!(base_addr_flag, 1);
    let base_addr = read_u64_be(&plaintext, &mut cursor);
    assert_eq!(base_addr, 0x401000);
}

// ---------------------------------------------------------------------------
// valid_demon_callback_body
// ---------------------------------------------------------------------------

#[test]
fn callback_body_round_trips_through_envelope() {
    let agent_id: u32 = 0xCAFE_0010;
    let key = [0xCC_u8; AGENT_KEY_LENGTH];
    let iv = [0xDD_u8; AGENT_IV_LENGTH];
    let payload = b"hello callback";

    let bytes = common::valid_demon_callback_body(
        agent_id,
        key,
        iv,
        0,
        u32::from(DemonCommand::CommandOutput),
        42,
        payload,
    );
    let envelope =
        DemonEnvelope::from_bytes(&bytes).expect("callback body must parse as valid envelope");

    assert_eq!(envelope.header.magic, DEMON_MAGIC_VALUE);
    assert_eq!(envelope.header.agent_id, agent_id);
}

#[test]
fn callback_body_carries_correct_command_and_request_ids() {
    let agent_id: u32 = 0xCAFE_0011;
    let key = [0xEE_u8; AGENT_KEY_LENGTH];
    let iv = [0xFF_u8; AGENT_IV_LENGTH];
    let command_id = u32::from(DemonCommand::CommandOutput);
    let request_id: u32 = 99;

    let bytes =
        common::valid_demon_callback_body(agent_id, key, iv, 0, command_id, request_id, b"data");
    let envelope = DemonEnvelope::from_bytes(&bytes).expect("envelope parse");

    let decoded_cmd = u32::from_be_bytes(envelope.payload[..4].try_into().expect("fixed-size slice for try_into"));
    let decoded_req = u32::from_be_bytes(envelope.payload[4..8].try_into().expect("fixed-size slice for try_into"));
    assert_eq!(decoded_cmd, command_id);
    assert_eq!(decoded_req, request_id);
}

#[test]
fn callback_body_encrypted_payload_decrypts_to_original() {
    let agent_id: u32 = 0xCAFE_0012;
    let key = [0x12_u8; AGENT_KEY_LENGTH];
    let iv = [0x34_u8; AGENT_IV_LENGTH];
    let original_payload = b"round-trip test data";
    let ctr_offset: u64 = 0;

    let bytes = common::valid_demon_callback_body(
        agent_id,
        key,
        iv,
        ctr_offset,
        u32::from(DemonCommand::CommandOutput),
        1,
        original_payload,
    );
    let envelope = DemonEnvelope::from_bytes(&bytes).expect("envelope parse");

    // Encrypted data starts after command_id(4) + request_id(4) = 8
    let ciphertext = &envelope.payload[8..];
    let plaintext = decrypt_agent_data_at_offset(&key, &iv, ctr_offset, ciphertext)
        .expect("callback decryption must succeed");

    // Decrypted layout: 4-byte BE length prefix + payload
    let len = u32::from_be_bytes(plaintext[..4].try_into().expect("fixed-size slice for try_into")) as usize;
    assert_eq!(len, original_payload.len());
    assert_eq!(&plaintext[4..4 + len], original_payload);
}

#[test]
fn callback_body_respects_nonzero_ctr_offset() {
    let agent_id: u32 = 0xCAFE_0013;
    let key = [0x56_u8; AGENT_KEY_LENGTH];
    let iv = [0x78_u8; AGENT_IV_LENGTH];
    let payload = b"offset test";

    // Simulate that some data was already encrypted (consuming blocks).
    let prior_plaintext_len = 48;
    let ctr_offset = ctr_blocks_for_len(prior_plaintext_len);
    assert!(ctr_offset > 0, "test requires nonzero CTR offset");

    let bytes = common::valid_demon_callback_body(
        agent_id,
        key,
        iv,
        ctr_offset,
        u32::from(DemonCommand::CommandCheckin),
        7,
        payload,
    );
    let envelope = DemonEnvelope::from_bytes(&bytes).expect("envelope parse");

    let ciphertext = &envelope.payload[8..];

    // Decrypting at offset 0 should NOT recover the plaintext
    let wrong_plaintext =
        decrypt_agent_data_at_offset(&key, &iv, 0, ciphertext).expect("decryption at wrong offset");
    let correct_plaintext = decrypt_agent_data_at_offset(&key, &iv, ctr_offset, ciphertext)
        .expect("decryption at correct offset");

    let len = u32::from_be_bytes(correct_plaintext[..4].try_into().expect("fixed-size slice for try_into")) as usize;
    assert_eq!(len, payload.len());
    assert_eq!(&correct_plaintext[4..4 + len], payload);

    // Verify wrong offset produces different output
    assert_ne!(wrong_plaintext, correct_plaintext);
}

// ---------------------------------------------------------------------------
// valid_demon_reconnect_body
// ---------------------------------------------------------------------------

#[test]
fn reconnect_body_round_trips_through_envelope() {
    let agent_id: u32 = 0xCAFE_0020;

    let bytes = common::valid_demon_reconnect_body(agent_id);
    let envelope =
        DemonEnvelope::from_bytes(&bytes).expect("reconnect body must parse as valid envelope");

    assert_eq!(envelope.header.magic, DEMON_MAGIC_VALUE);
    assert_eq!(envelope.header.agent_id, agent_id);
}

#[test]
fn reconnect_body_carries_demon_init_command_with_empty_metadata() {
    let agent_id: u32 = 0xCAFE_0021;

    let bytes = common::valid_demon_reconnect_body(agent_id);
    let envelope = DemonEnvelope::from_bytes(&bytes).expect("envelope parse");

    let command_id = u32::from_be_bytes(envelope.payload[..4].try_into().expect("fixed-size slice for try_into"));
    assert_eq!(command_id, u32::from(DemonCommand::DemonInit));

    let request_id = u32::from_be_bytes(envelope.payload[4..8].try_into().expect("fixed-size slice for try_into"));
    assert_eq!(request_id, 7);

    // Reconnect body has NO encrypted metadata — payload is exactly command_id + request_id
    assert_eq!(
        envelope.payload.len(),
        8,
        "reconnect payload must contain only command_id and request_id (no encrypted metadata)"
    );
}

#[test]
fn reconnect_body_differs_from_init_body() {
    let agent_id: u32 = 0xCAFE_0022;
    let key = [0x99_u8; AGENT_KEY_LENGTH];
    let iv = [0xAA_u8; AGENT_IV_LENGTH];

    let init_bytes = common::valid_demon_init_body(agent_id, key, iv);
    let reconnect_bytes = common::valid_demon_reconnect_body(agent_id);

    // Reconnect should be strictly smaller (no key, IV, or encrypted metadata)
    assert!(
        reconnect_bytes.len() < init_bytes.len(),
        "reconnect ({}) should be smaller than init ({})",
        reconnect_bytes.len(),
        init_bytes.len()
    );
}

// ---------------------------------------------------------------------------
// Helpers for decoding metadata fields
// ---------------------------------------------------------------------------

/// Read a BE-length-prefixed byte slice from `data` at `cursor`, advancing cursor.
fn read_lp_bytes<'a>(data: &'a [u8], cursor: &mut usize) -> &'a [u8] {
    let len = u32::from_be_bytes(data[*cursor..*cursor + 4].try_into().expect("fixed-size slice for try_into")) as usize;
    *cursor += 4;
    let value = &data[*cursor..*cursor + len];
    *cursor += len;
    value
}

/// Read a BE u32 from `data` at `cursor`, advancing cursor.
fn read_u32_be(data: &[u8], cursor: &mut usize) -> u32 {
    let value = u32::from_be_bytes(data[*cursor..*cursor + 4].try_into().expect("fixed-size slice for try_into"));
    *cursor += 4;
    value
}

/// Read a BE u64 from `data` at `cursor`, advancing cursor.
fn read_u64_be(data: &[u8], cursor: &mut usize) -> u64 {
    let value = u64::from_be_bytes(data[*cursor..*cursor + 8].try_into().expect("fixed-size slice for try_into"));
    *cursor += 8;
    value
}

/// Decode a null-terminated UTF-16LE byte sequence into a String.
fn decode_utf16_le_null_terminated(raw: &[u8]) -> String {
    let code_units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .take_while(|&cu| cu != 0)
        .collect();
    String::from_utf16(&code_units).expect("valid UTF-16")
}
