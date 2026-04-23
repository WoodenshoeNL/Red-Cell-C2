mod decode;
mod handle;
mod parse;

use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use zeroize::Zeroizing;

/// Generate a non-degenerate test key from a seed byte.
fn test_key(seed: u8) -> [u8; AGENT_KEY_LENGTH] {
    core::array::from_fn(|i| seed.wrapping_add(i as u8))
}

/// Generate a non-degenerate test IV from a seed byte.
fn test_iv(seed: u8) -> [u8; AGENT_IV_LENGTH] {
    core::array::from_fn(|i| seed.wrapping_add(i as u8))
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
