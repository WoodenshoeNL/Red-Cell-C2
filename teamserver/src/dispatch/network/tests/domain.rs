//! Tests for Domain, Computer, and DcList `CommandNet` subcommands.

use red_cell_common::demon::DemonNetCommand;

use super::super::super::CommandDispatchError;
use super::super::handle_net_callback;
use super::common::{
    AGENT_ID, REQUEST_ID, assert_agent_response, call_and_recv, encode_string, encode_utf16,
    net_payload,
};
use crate::EventBus;

// ── Domain ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn domain_non_empty_broadcasts_domain_name() {
    let payload = net_payload(DemonNetCommand::Domain, &encode_string("CORP.LOCAL"));
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    assert_eq!(result.expect("unwrap"), None);
    let msg = msg.expect("should broadcast");
    let output = assert_agent_response(&msg, "Good", "Domain for this Host: CORP.LOCAL");
    assert!(output.is_empty());
}

#[tokio::test]
async fn domain_empty_broadcasts_not_joined_message() {
    let payload = net_payload(DemonNetCommand::Domain, &encode_string(""));
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    assert_eq!(result.expect("unwrap"), None);
    let msg = msg.expect("should broadcast");
    assert_agent_response(&msg, "Good", "The machine does not seem to be joined to a domain");
}

// ── Computer ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn computer_broadcasts_computer_list() {
    let mut rest = encode_utf16("CORP.LOCAL");
    rest.extend(encode_utf16("WS01"));
    rest.extend(encode_utf16("WS02"));
    rest.extend(encode_utf16("SRV-DB"));
    let payload = net_payload(DemonNetCommand::Computer, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    assert_eq!(result.expect("unwrap"), None);
    let msg = msg.expect("should broadcast");
    let output = assert_agent_response(&msg, "Info", "Computers for CORP.LOCAL [3]: ");
    assert!(output.contains("Computer"));
    assert!(output.contains("WS01"));
    assert!(output.contains("WS02"));
    assert!(output.contains("SRV-DB"));
}

#[tokio::test]
async fn computer_empty_list_broadcasts_zero_count() {
    let rest = encode_utf16("CORP.LOCAL");
    let payload = net_payload(DemonNetCommand::Computer, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    assert_agent_response(&msg, "Info", "Computers for CORP.LOCAL [0]: ");
}

#[tokio::test]
async fn truncated_computer_name_returns_invalid_callback_payload() {
    let mut rest = encode_utf16("CORP.LOCAL");
    let mut name = encode_utf16("WS01");
    name.pop();
    rest.extend(name);
    let payload = net_payload(DemonNetCommand::Computer, &rest);
    let events = EventBus::default();
    let result = handle_net_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated Computer name, got {result:?}"
    );
}

// ── DcList ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn dclist_broadcasts_dc_list() {
    let mut rest = encode_utf16("CORP.LOCAL");
    rest.extend(encode_utf16("DC01.corp.local"));
    rest.extend(encode_utf16("DC02.corp.local"));
    let payload = net_payload(DemonNetCommand::DcList, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    assert_eq!(result.expect("unwrap"), None);
    let msg = msg.expect("should broadcast");
    let output = assert_agent_response(&msg, "Info", "Domain controllers for CORP.LOCAL [2]: ");
    assert!(output.contains("Domain Controller"));
    assert!(output.contains("DC01.corp.local"));
    assert!(output.contains("DC02.corp.local"));
}

#[tokio::test]
async fn dclist_empty_list_broadcasts_zero_count() {
    let rest = encode_utf16("CORP.LOCAL");
    let payload = net_payload(DemonNetCommand::DcList, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    assert_agent_response(&msg, "Info", "Domain controllers for CORP.LOCAL [0]: ");
}

#[tokio::test]
async fn truncated_dclist_name_returns_invalid_callback_payload() {
    let mut rest = encode_utf16("CORP.LOCAL");
    let mut dc_name = encode_utf16("DC01.corp.local");
    dc_name.pop();
    rest.extend(dc_name);
    let payload = net_payload(DemonNetCommand::DcList, &rest);
    let events = EventBus::default();
    let result = handle_net_callback(&events, AGENT_ID, REQUEST_ID, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated DcList name, got {result:?}"
    );
}
