//! Tests for the token command family: steal, list, privs, make, getuid, revert,
//! remove, clear, find_tokens, and impersonate — covering dispatcher callbacks
//! and handler payload formatting.

mod find_tokens;
mod make_getuid;
mod misc;
mod privs;
mod revert_remove_clear;
mod steal_impersonate;
mod vault;

pub(super) use super::super::token::{
    format_found_tokens, format_token_list, format_token_privs_list, handle_token_callback,
};
pub(super) use super::super::{CallbackParser, CommandDispatchError, CommandDispatcher};
pub(super) use super::common::*;
pub(super) use crate::{AgentRegistry, Database, EventBus, SocketRelayManager};
pub(super) use red_cell_common::demon::{DemonCommand, DemonTokenCommand};
pub(super) use red_cell_common::operator::OperatorMessage;
pub(super) use serde_json::Value;
pub(super) use tokio::time::{Duration, timeout};

// ── constants shared by unit-handle tests ────────────────────────────────────

pub(super) const UNIT_AGENT_ID: u32 = 0xDEAD_BEEF;
pub(super) const UNIT_REQUEST_ID: u32 = 42;
pub(super) const UNIT_TOKEN_CMD: u32 = 40;

// ── binary-payload helpers ────────────────────────────────────────────────────

pub(super) fn push_u32(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_le_bytes());
}

pub(super) fn push_utf16(buf: &mut Vec<u8>, s: &str) {
    let words: Vec<u16> = s.encode_utf16().collect();
    let byte_len = (words.len() * 2) as u32;
    push_u32(buf, byte_len);
    for w in &words {
        buf.extend_from_slice(&w.to_le_bytes());
    }
}

pub(super) fn push_string(buf: &mut Vec<u8>, s: &str) {
    push_u32(buf, s.len() as u32);
    buf.extend_from_slice(s.as_bytes());
}

// ── unit-handle test helpers ──────────────────────────────────────────────────

pub(super) fn unit_token_payload(subcmd: DemonTokenCommand, rest: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u32(&mut buf, subcmd as u32);
    buf.extend_from_slice(rest);
    buf
}

pub(super) async fn unit_call_and_recv(
    payload: &[u8],
) -> (Result<Option<Vec<u8>>, CommandDispatchError>, Option<OperatorMessage>) {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let result = handle_token_callback(&events, UNIT_AGENT_ID, UNIT_REQUEST_ID, payload).await;
    drop(events);
    let msg = rx.recv().await;
    (result, msg)
}

pub(super) fn assert_unit_response(
    msg: &OperatorMessage,
    expected_kind: &str,
    expected_message: &str,
) -> String {
    let OperatorMessage::AgentResponse(m) = msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    assert_eq!(m.info.demon_id, format!("{UNIT_AGENT_ID:08X}"));
    assert_eq!(m.info.command_id, UNIT_TOKEN_CMD.to_string());
    assert_eq!(
        m.info.extra.get("Type").and_then(Value::as_str),
        Some(expected_kind),
        "expected kind={expected_kind}, extra={:?}",
        m.info.extra
    );
    assert_eq!(
        m.info.extra.get("Message").and_then(Value::as_str),
        Some(expected_message),
        "expected message={expected_message}, extra={:?}",
        m.info.extra
    );
    m.info.output.clone()
}

// ── find_tokens formatter helpers ────────────────────────────────────────────

pub(super) fn build_found_token_payload(integrity_level: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u32(&mut buf, 1);
    push_utf16(&mut buf, "DOMAIN\\user");
    push_u32(&mut buf, 1000);
    push_u32(&mut buf, 0x100);
    push_u32(&mut buf, integrity_level);
    push_u32(&mut buf, 2);
    push_u32(&mut buf, 2);
    buf
}

pub(super) fn get_integrity_from_output(output: &str) -> String {
    for line in output.lines().skip(3) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            return parts[1].to_string();
        }
    }
    panic!("Could not find integrity value in output:\n{output}");
}
