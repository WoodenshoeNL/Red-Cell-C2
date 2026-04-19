//! Shared test helpers for `handle_net_callback` test modules.

use red_cell_common::demon::{DemonCommand, DemonNetCommand};
use red_cell_common::operator::OperatorMessage;
use serde_json::Value;

use super::super::super::CommandDispatchError;
use super::super::handle_net_callback;
use crate::EventBus;

pub(super) const AGENT_ID: u32 = 0xDEAD_BEEF;
pub(super) const REQUEST_ID: u32 = 42;

pub(super) fn encode_u32(v: u32) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

pub(super) fn encode_string(s: &str) -> Vec<u8> {
    let mut buf = encode_u32(s.len() as u32);
    buf.extend_from_slice(s.as_bytes());
    buf
}

pub(super) fn encode_utf16(s: &str) -> Vec<u8> {
    let words: Vec<u16> = s.encode_utf16().collect();
    let byte_len = (words.len() * 2) as u32;
    let mut buf = encode_u32(byte_len);
    for w in &words {
        buf.extend_from_slice(&w.to_le_bytes());
    }
    buf
}

pub(super) fn encode_bool(v: bool) -> Vec<u8> {
    encode_u32(u32::from(v))
}

pub(super) fn net_payload(subcommand: DemonNetCommand, rest: &[u8]) -> Vec<u8> {
    let mut payload = encode_u32(subcommand as u32);
    payload.extend_from_slice(rest);
    payload
}

pub(super) async fn call_and_recv(
    payload: &[u8],
) -> (Result<Option<Vec<u8>>, CommandDispatchError>, Option<OperatorMessage>) {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let result = handle_net_callback(&events, AGENT_ID, REQUEST_ID, payload).await;
    drop(events);
    let msg = rx.recv().await;
    (result, msg)
}

pub(super) fn assert_agent_response<'a>(
    msg: &'a OperatorMessage,
    expected_kind: &str,
    expected_message: &str,
) -> &'a str {
    let OperatorMessage::AgentResponse(m) = msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    assert_eq!(m.info.demon_id, format!("{AGENT_ID:08X}"));
    assert_eq!(m.info.command_id, u32::from(DemonCommand::CommandNet).to_string());
    assert_eq!(m.info.extra.get("Type").and_then(Value::as_str), Some(expected_kind));
    assert_eq!(m.info.extra.get("Message").and_then(Value::as_str), Some(expected_message));
    &m.info.output
}
