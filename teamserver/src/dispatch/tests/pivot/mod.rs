//! Tests for pivot and transfer command families.

mod basic;
mod chain;
mod error;

use super::common::*;

use super::super::{CommandDispatchError, CommandDispatcher};
use crate::dispatch::util::CallbackParser;
use crate::dispatch::{BuiltinDispatchContext, DownloadTracker};
use crate::{AgentRegistry, Database, DemonCallbackPackage, EventBus, Job, SocketRelayManager};
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, encrypt_agent_data};
use red_cell_common::demon::{
    DEMON_MAGIC_VALUE, DemonCommand, DemonEnvelope, DemonPivotCommand, DemonProtocolError,
    MIN_ENVELOPE_SIZE,
};
use red_cell_common::operator::OperatorMessage;
use serde_json::Value;
use tokio::time::{Duration, timeout};
use zeroize::Zeroizing;

use super::super::pivot::{
    dispatch_builtin_packages, handle_pivot_callback, handle_pivot_command_callback,
    handle_pivot_connect_callback, handle_pivot_disconnect_callback, handle_pivot_list_callback,
    inner_demon_agent_id, inner_demon_command_id,
};

pub(super) fn pivot_connect_failure_payload(error_code: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(DemonPivotCommand::SmbConnect).to_le_bytes());
    payload.extend_from_slice(&0_u32.to_le_bytes()); // success == 0
    payload.extend_from_slice(&error_code.to_le_bytes());
    payload
}

pub(super) fn pivot_disconnect_failure_payload(child_agent_id: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(DemonPivotCommand::SmbDisconnect).to_le_bytes());
    payload.extend_from_slice(&0_u32.to_le_bytes()); // success == 0
    payload.extend_from_slice(&child_agent_id.to_le_bytes());
    payload
}

pub(super) fn pivot_list_payload(entries: &[(u32, &str)]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(DemonPivotCommand::List).to_le_bytes());
    for (demon_id, pipe_name) in entries {
        payload.extend_from_slice(&demon_id.to_le_bytes());
        let utf16: Vec<u16> = pipe_name.encode_utf16().collect();
        let utf16_bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
        let len = u32::try_from(utf16_bytes.len()).expect("test data fits in u32");
        payload.extend_from_slice(&len.to_le_bytes());
        payload.extend_from_slice(&utf16_bytes);
    }
    payload
}

pub(super) fn pivot_disconnect_success_payload(child_agent_id: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(DemonPivotCommand::SmbDisconnect).to_le_bytes());
    payload.extend_from_slice(&1_u32.to_le_bytes()); // success == 1
    payload.extend_from_slice(&child_agent_id.to_le_bytes());
    payload
}

pub(super) const AGENT_ID: u32 = 0xBEEF_0001;
pub(super) const REQUEST_ID: u32 = 42;

/// Build a minimal valid Demon envelope wire encoding for `agent_id` with no payload.
pub(super) fn valid_envelope_bytes(agent_id: u32) -> Vec<u8> {
    DemonEnvelope::new(agent_id, Vec::new()).expect("envelope construction must succeed").to_bytes()
}

/// Build a Demon envelope whose payload starts with the DEMON_INIT command ID,
/// followed by a dummy request_id. Used for pivot connect tests where the
/// inner envelope must look like an init packet.
pub(super) fn valid_init_envelope_bytes(agent_id: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(DemonCommand::DemonInit).to_be_bytes());
    payload.extend_from_slice(&0_u32.to_be_bytes()); // request_id
    DemonEnvelope::new(agent_id, payload)
        .expect("init envelope construction must succeed")
        .to_bytes()
}

pub(super) fn push_u32(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_le_bytes());
}

/// Append a length-prefixed UTF-16LE string (as `CallbackParser::read_utf16` expects).
pub(super) fn push_utf16(buf: &mut Vec<u8>, s: &str) {
    let words: Vec<u16> = s.encode_utf16().collect();
    let byte_len = (words.len() * 2) as u32;
    push_u32(buf, byte_len);
    for w in &words {
        buf.extend_from_slice(&w.to_le_bytes());
    }
}

/// Build a `CallbackParser` payload with a LE-length-prefixed byte blob.
pub(super) fn length_prefixed_bytes(data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u32(&mut buf, u32::try_from(data.len()).expect("test data fits in u32"));
    buf.extend_from_slice(data);
    buf
}

/// Build a CommandOutput inner payload (LE length-prefixed UTF-8 string).
pub(super) fn command_output_payload(output: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(
        &u32::try_from(output.len()).expect("test data fits in u32").to_le_bytes(),
    );
    payload.extend_from_slice(output.as_bytes());
    payload
}

pub(super) async fn setup_dispatch_context()
-> (Database, AgentRegistry, EventBus, SocketRelayManager, DownloadTracker) {
    let database = Database::connect_in_memory().await.expect("in-memory DB must succeed");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let downloads = DownloadTracker::new(64 * 1024 * 1024);
    (database, registry, events, sockets, downloads)
}

/// Build a disconnect callback payload: success (u32 LE) + child_agent_id (u32 LE).
pub(super) fn disconnect_payload(success: u32, child_agent_id: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u32(&mut buf, success);
    push_u32(&mut buf, child_agent_id);
    buf
}

/// Build a connect callback payload: success (u32 LE) + LE-length-prefixed inner bytes.
pub(super) fn connect_payload(success: u32, inner_envelope: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u32(&mut buf, success);
    push_u32(&mut buf, u32::try_from(inner_envelope.len()).expect("test data fits in u32"));
    buf.extend_from_slice(inner_envelope);
    buf
}

/// Build init metadata in the format expected by `parse_init_agent`.
pub(super) fn build_init_metadata(agent_id: u32) -> Vec<u8> {
    fn add_str_be(buf: &mut Vec<u8>, value: &str) {
        buf.extend_from_slice(&(value.len() as u32).to_be_bytes());
        buf.extend_from_slice(value.as_bytes());
    }
    fn add_utf16_be(buf: &mut Vec<u8>, value: &str) {
        let utf16: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
        buf.extend_from_slice(&(utf16.len() as u32).to_be_bytes());
        buf.extend_from_slice(&utf16);
    }

    let mut m = Vec::new();
    m.extend_from_slice(&agent_id.to_be_bytes()); // agent_id
    add_str_be(&mut m, "pivot-host"); // hostname
    add_str_be(&mut m, "operator"); // username
    add_str_be(&mut m, "PIVOTLAB"); // domain
    add_str_be(&mut m, "10.0.0.99"); // internal_ip
    add_utf16_be(&mut m, "C:\\Windows\\svchost.exe"); // process_path
    m.extend_from_slice(&1234_u32.to_be_bytes()); // pid
    m.extend_from_slice(&5678_u32.to_be_bytes()); // tid
    m.extend_from_slice(&512_u32.to_be_bytes()); // ppid
    m.extend_from_slice(&2_u32.to_be_bytes()); // arch (x64)
    m.extend_from_slice(&1_u32.to_be_bytes()); // elevated
    m.extend_from_slice(&0x401000_u64.to_be_bytes()); // base_address
    m.extend_from_slice(&10_u32.to_be_bytes()); // os_major
    m.extend_from_slice(&0_u32.to_be_bytes()); // os_minor
    m.extend_from_slice(&1_u32.to_be_bytes()); // os_product_type
    m.extend_from_slice(&0_u32.to_be_bytes()); // os_service_pack
    m.extend_from_slice(&22000_u32.to_be_bytes()); // os_build
    m.extend_from_slice(&9_u32.to_be_bytes()); // os_arch
    m.extend_from_slice(&15_u32.to_be_bytes()); // sleep_delay
    m.extend_from_slice(&20_u32.to_be_bytes()); // sleep_jitter
    m.extend_from_slice(&1_893_456_000_u64.to_be_bytes()); // kill_date
    m.extend_from_slice(&0b101010_i32.to_be_bytes()); // working_hours
    m
}

/// Build a complete DEMON_INIT wire packet for a brand-new agent (full metadata).
pub(super) fn build_full_init_packet(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> Vec<u8> {
    let metadata = build_init_metadata(agent_id);
    let encrypted =
        encrypt_agent_data(&key, &iv, &metadata).expect("metadata encryption should succeed");

    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(DemonCommand::DemonInit).to_be_bytes());
    payload.extend_from_slice(&7_u32.to_be_bytes()); // request_id
    payload.extend_from_slice(&key);
    payload.extend_from_slice(&iv);
    payload.extend_from_slice(&encrypted);

    DemonEnvelope::new(agent_id, payload)
        .expect("init envelope construction must succeed")
        .to_bytes()
}

/// Build a Demon envelope whose payload starts with an arbitrary command ID (not `DemonInit`).
pub(super) fn non_init_envelope_bytes(agent_id: u32, command: DemonCommand) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(command).to_be_bytes());
    payload.extend_from_slice(&0_u32.to_be_bytes()); // request_id
    DemonEnvelope::new(agent_id, payload)
        .expect("non-init envelope construction must succeed")
        .to_bytes()
}
