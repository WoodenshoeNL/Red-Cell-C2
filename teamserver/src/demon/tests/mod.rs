mod ack;
mod callback;
mod init;
mod parser;

use std::path::PathBuf;

use red_cell_common::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, encrypt_agent_data, encrypt_agent_data_at_offset,
};
use red_cell_common::demon::{DemonCommand, DemonEnvelope};
use red_cell_common::{AgentEncryptionInfo, AgentRecord};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::DemonPacketParser;
use crate::{AgentRegistry, Database};

/// Create a packet parser that accepts legacy-CTR registrations.
///
/// Use this in tests that send `build_init_packet` (no `INIT_EXT_MONOTONIC_CTR`
/// flag) and expect the registration to succeed.  The production default is
/// `allow_legacy_ctr = false`; tests that exercise the rejection path should use
/// `DemonPacketParser::new(registry)` directly.
fn legacy_parser(registry: AgentRegistry) -> DemonPacketParser {
    DemonPacketParser::new(registry).with_allow_legacy_ctr(true)
}

/// Generate a non-degenerate test key from a seed byte.
/// Each byte differs, so no repeating-pattern check will flag it.
fn test_key(seed: u8) -> [u8; AGENT_KEY_LENGTH] {
    core::array::from_fn(|i| seed.wrapping_add(i as u8))
}

/// Generate a non-degenerate test IV from a seed byte.
fn test_iv(seed: u8) -> [u8; AGENT_IV_LENGTH] {
    core::array::from_fn(|i| seed.wrapping_add(i as u8))
}

fn u32_be(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

fn u64_be(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

fn add_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&u32_be(u32::try_from(bytes.len()).expect("test data fits in u32")));
    buf.extend_from_slice(bytes);
}

fn add_str(buf: &mut Vec<u8>, value: &str) {
    add_bytes(buf, value.as_bytes());
}

fn add_utf16(buf: &mut Vec<u8>, value: &str) {
    let utf16: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
    add_bytes(buf, &utf16);
}

async fn test_registry() -> AgentRegistry {
    let database = Database::connect_in_memory().await.expect("in-memory db should work");
    AgentRegistry::new(database)
}

fn temp_db_path() -> PathBuf {
    std::env::temp_dir().join(format!("red-cell-demon-parser-{}.sqlite", Uuid::new_v4()))
}

fn build_init_metadata(agent_id: u32) -> Vec<u8> {
    build_init_metadata_with_kill_date_and_working_hours(agent_id, 1_893_456_000, 0b101010)
}

/// Build init metadata with trailing extension flags (Specter-style).
fn build_init_metadata_with_ext_flags(agent_id: u32, ext_flags: u32) -> Vec<u8> {
    let mut metadata = build_init_metadata(agent_id);
    metadata.extend_from_slice(&u32_be(ext_flags));
    metadata
}

fn build_init_metadata_with_working_hours(agent_id: u32, working_hours: i32) -> Vec<u8> {
    build_init_metadata_with_kill_date_and_working_hours(agent_id, 1_893_456_000, working_hours)
}

fn build_init_metadata_with_kill_date_and_working_hours(
    agent_id: u32,
    kill_date: u64,
    working_hours: i32,
) -> Vec<u8> {
    let mut metadata = Vec::new();
    metadata.extend_from_slice(&u32_be(agent_id));
    add_str(&mut metadata, "wkstn-01");
    add_str(&mut metadata, "operator");
    add_str(&mut metadata, "REDCELL");
    add_str(&mut metadata, "10.0.0.25");
    add_utf16(&mut metadata, "C:\\Windows\\explorer.exe");
    metadata.extend_from_slice(&u32_be(1337));
    metadata.extend_from_slice(&u32_be(1338));
    metadata.extend_from_slice(&u32_be(512));
    metadata.extend_from_slice(&u32_be(2));
    metadata.extend_from_slice(&u32_be(1));
    metadata.extend_from_slice(&u64_be(0x401000));
    metadata.extend_from_slice(&u32_be(10));
    metadata.extend_from_slice(&u32_be(0));
    metadata.extend_from_slice(&u32_be(1));
    metadata.extend_from_slice(&u32_be(0));
    metadata.extend_from_slice(&u32_be(22000));
    metadata.extend_from_slice(&u32_be(9));
    metadata.extend_from_slice(&u32_be(15));
    metadata.extend_from_slice(&u32_be(20));
    metadata.extend_from_slice(&u64_be(kill_date));
    metadata.extend_from_slice(&working_hours.to_be_bytes());
    metadata
}

fn build_init_packet(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> Vec<u8> {
    build_init_packet_with_working_hours(agent_id, key, iv, 0b101010)
}

/// Build an init packet with trailing extension flags (Specter-style).
fn build_init_packet_with_ext_flags(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    ext_flags: u32,
) -> Vec<u8> {
    let metadata = build_init_metadata_with_ext_flags(agent_id, ext_flags);
    let encrypted =
        encrypt_agent_data(&key, &iv, &metadata).expect("metadata encryption should succeed");
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32_be(u32::from(DemonCommand::DemonInit)));
    payload.extend_from_slice(&u32_be(7));
    payload.extend_from_slice(&key);
    payload.extend_from_slice(&iv);
    payload.extend_from_slice(&encrypted);

    DemonEnvelope::new(agent_id, payload).expect("init envelope should be valid").to_bytes()
}

fn build_init_packet_with_working_hours(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    working_hours: i32,
) -> Vec<u8> {
    let metadata = build_init_metadata_with_working_hours(agent_id, working_hours);
    let encrypted =
        encrypt_agent_data(&key, &iv, &metadata).expect("metadata encryption should succeed");
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32_be(u32::from(DemonCommand::DemonInit)));
    payload.extend_from_slice(&u32_be(7));
    payload.extend_from_slice(&key);
    payload.extend_from_slice(&iv);
    payload.extend_from_slice(&encrypted);

    DemonEnvelope::new(agent_id, payload).expect("init envelope should be valid").to_bytes()
}

fn build_init_packet_with_kill_date_and_working_hours(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    kill_date: u64,
    working_hours: i32,
) -> Vec<u8> {
    let metadata =
        build_init_metadata_with_kill_date_and_working_hours(agent_id, kill_date, working_hours);
    let encrypted =
        encrypt_agent_data(&key, &iv, &metadata).expect("metadata encryption should succeed");
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32_be(u32::from(DemonCommand::DemonInit)));
    payload.extend_from_slice(&u32_be(7));
    payload.extend_from_slice(&key);
    payload.extend_from_slice(&iv);
    payload.extend_from_slice(&encrypted);

    DemonEnvelope::new(agent_id, payload).expect("init envelope should be valid").to_bytes()
}

fn build_plaintext_zero_key_init_packet(agent_id: u32) -> Vec<u8> {
    let metadata = build_init_metadata(agent_id);
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32_be(u32::from(DemonCommand::DemonInit)));
    payload.extend_from_slice(&u32_be(7));
    payload.extend_from_slice(&[0; AGENT_KEY_LENGTH]);
    payload.extend_from_slice(&[0; AGENT_IV_LENGTH]);
    payload.extend_from_slice(&metadata);

    DemonEnvelope::new(agent_id, payload).expect("init envelope should be valid").to_bytes()
}

fn build_plaintext_zero_iv_init_packet(agent_id: u32) -> Vec<u8> {
    let metadata = build_init_metadata(agent_id);
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32_be(u32::from(DemonCommand::DemonInit)));
    payload.extend_from_slice(&u32_be(7));
    payload.extend_from_slice(&test_key(0xAB));
    payload.extend_from_slice(&[0; AGENT_IV_LENGTH]);
    payload.extend_from_slice(&metadata);

    DemonEnvelope::new(agent_id, payload).expect("init envelope should be valid").to_bytes()
}

/// Build a callback packet encrypted at the given CTR block offset,
/// simulating the Demon agent's counter-advancing AES context.
fn build_callback_packet(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    ctr_offset: u64,
) -> Vec<u8> {
    let mut decrypted = Vec::new();
    decrypted.extend_from_slice(&u32_be(3));
    decrypted.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
    decrypted.extend_from_slice(&u32_be(u32::from(DemonCommand::CommandOutput)));
    decrypted.extend_from_slice(&u32_be(99));
    decrypted.extend_from_slice(&u32_be(5));
    decrypted.extend_from_slice(b"hello");

    let encrypted = encrypt_agent_data_at_offset(&key, &iv, ctr_offset, &decrypted)
        .expect("callback encryption should succeed");
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32_be(u32::from(DemonCommand::CommandCheckin)));
    payload.extend_from_slice(&u32_be(42));
    payload.extend_from_slice(&encrypted);

    DemonEnvelope::new(agent_id, payload).expect("callback envelope should be valid").to_bytes()
}

/// Build an [`AgentRecord`] whose encryption material has arbitrary raw bytes.
/// Passing wrong-length vectors simulates what happens when persisted base64
/// decodes to an unexpected number of bytes (i.e. database corruption).
fn agent_with_raw_crypto(agent_id: u32, aes_key: Vec<u8>, aes_iv: Vec<u8>) -> AgentRecord {
    AgentRecord {
        agent_id,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: AgentEncryptionInfo {
            aes_key: Zeroizing::new(aes_key),
            aes_iv: Zeroizing::new(aes_iv),
        },
        hostname: "wkstn-corrupt".to_owned(),
        username: "operator".to_owned(),
        domain_name: "REDCELL".to_owned(),
        external_ip: "198.51.100.1".to_owned(),
        internal_ip: "10.0.0.50".to_owned(),
        process_name: "svchost.exe".to_owned(),
        process_path: "C:\\Windows\\svchost.exe".to_owned(),
        base_address: 0x401000,
        process_pid: 2000,
        process_tid: 2001,
        process_ppid: 800,
        process_arch: "x64".to_owned(),
        elevated: false,
        os_version: "Windows 11".to_owned(),
        os_build: 22000,
        os_arch: "x64/AMD64".to_owned(),
        sleep_delay: 10,
        sleep_jitter: 5,
        kill_date: None,
        working_hours: None,
        first_call_in: "2026-03-10T12:00:00Z".to_owned(),
        last_call_in: "2026-03-10T12:00:00Z".to_owned(),
        archon_magic: None,
    }
}
