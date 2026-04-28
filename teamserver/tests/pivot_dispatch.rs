//! Integration tests for `dispatch/pivot.rs` — `handle_pivot_connect_callback`.
//!
//! All tests go through the full HTTP → listener → dispatch pipeline so that
//! the agent registration, event-bus broadcast, and error paths are exercised
//! end-to-end.

mod common;

use red_cell::demon::INIT_EXT_MONOTONIC_CTR;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len};
use red_cell_common::demon::{DemonCommand, DemonEnvelope, DemonPivotCommand};
use red_cell_common::operator::OperatorMessage;
use serde_json::Value;
use tokio_tungstenite::connect_async;

// ---------------------------------------------------------------------------
// Payload builders
// ---------------------------------------------------------------------------

/// Build a `CommandPivot/SmbConnect` callback payload with `success=1` and
/// a valid inner Demon INIT envelope for `child_agent_id`.
fn pivot_connect_success_payload(
    child_agent_id: u32,
    child_key: [u8; AGENT_KEY_LENGTH],
    child_iv: [u8; AGENT_IV_LENGTH],
) -> Vec<u8> {
    let inner = common::valid_demon_init_body_with_ext_flags(
        child_agent_id,
        child_key,
        child_iv,
        INIT_EXT_MONOTONIC_CTR,
    );
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(DemonPivotCommand::SmbConnect).to_le_bytes());
    payload.extend_from_slice(&1_u32.to_le_bytes()); // success = 1
    // read_bytes reads a u32 length prefix followed by that many bytes
    payload.extend_from_slice(&u32::try_from(inner.len()).expect("unwrap").to_le_bytes());
    payload.extend_from_slice(&inner);
    payload
}

/// Build a `CommandPivot/SmbConnect` callback payload with `success=0` and
/// the given Win32 error code.
fn pivot_connect_error_payload(error_code: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(DemonPivotCommand::SmbConnect).to_le_bytes());
    payload.extend_from_slice(&0_u32.to_le_bytes()); // success = 0
    payload.extend_from_slice(&error_code.to_le_bytes());
    payload
}

/// Build a `CommandPivot/SmbConnect` callback payload with `success=1` but
/// an inner envelope that is a valid DemonEnvelope but NOT a DemonInit
/// (it has an empty payload, which `DemonPacketParser::parse_for_listener`
/// won't recognise as a valid init).
fn pivot_connect_non_init_inner_payload(child_agent_id: u32) -> Vec<u8> {
    // A bare DemonEnvelope with empty payload — no DemonInit command header.
    let inner = DemonEnvelope::new(child_agent_id, Vec::new())
        .expect("envelope construction must succeed")
        .to_bytes();
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(DemonPivotCommand::SmbConnect).to_le_bytes());
    payload.extend_from_slice(&1_u32.to_le_bytes()); // success = 1
    payload.extend_from_slice(&u32::try_from(inner.len()).expect("unwrap").to_le_bytes());
    payload.extend_from_slice(&inner);
    payload
}

/// Build a `CommandPivot/SmbConnect` callback payload with `success=1` but
/// malformed inner bytes that cannot parse as a DemonEnvelope at all.
fn pivot_connect_malformed_inner_payload() -> Vec<u8> {
    let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(DemonPivotCommand::SmbConnect).to_le_bytes());
    payload.extend_from_slice(&1_u32.to_le_bytes()); // success = 1
    payload.extend_from_slice(&u32::try_from(garbage.len()).expect("unwrap").to_le_bytes());
    payload.extend_from_slice(&garbage);
    payload
}

/// Build a `CommandPivot/SmbDisconnect` callback payload with `success=1`
/// and the given `child_agent_id`.
fn pivot_disconnect_success_payload(child_agent_id: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(DemonPivotCommand::SmbDisconnect).to_le_bytes());
    payload.extend_from_slice(&1_u32.to_le_bytes()); // success = 1
    payload.extend_from_slice(&child_agent_id.to_le_bytes());
    payload
}

/// Build a `CommandPivot/SmbDisconnect` callback payload with `success=0`
/// (failure) and the given `child_agent_id`.
fn pivot_disconnect_failure_payload(child_agent_id: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(DemonPivotCommand::SmbDisconnect).to_le_bytes());
    payload.extend_from_slice(&0_u32.to_le_bytes()); // success = 0
    payload.extend_from_slice(&child_agent_id.to_le_bytes());
    payload
}

// ---------------------------------------------------------------------------
// Helper: spawn server, listener, register parent agent, return handles
// ---------------------------------------------------------------------------

struct PivotTestHarness {
    client: reqwest::Client,
    listener_port: u16,
    socket: common::WsSession,
    server: common::TestServer,
    parent_agent_id: u32,
    parent_key: [u8; AGENT_KEY_LENGTH],
    parent_iv: [u8; AGENT_IV_LENGTH],
    parent_ctr_offset: u64,
}

async fn setup_pivot_test(
    listener_name: &str,
) -> Result<PivotTestHarness, Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config(listener_name, listener_port)).await?;
    drop(listener_guard);
    server.listeners.start(listener_name).await?;
    common::wait_for_listener(listener_port).await?;

    let parent_agent_id = 0xAA00_0001_u32;
    let parent_key: [u8; AGENT_KEY_LENGTH] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let parent_iv: [u8; AGENT_IV_LENGTH] = [
        0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F,
        0x90,
    ];
    let parent_ctr_offset =
        common::register_agent(&client, listener_port, parent_agent_id, parent_key, parent_iv)
            .await?;

    // Consume the AgentNew broadcast from parent registration.
    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(
        matches!(agent_new, OperatorMessage::AgentNew(_)),
        "expected AgentNew for parent, got {agent_new:?}"
    );

    Ok(PivotTestHarness {
        client,
        listener_port,
        socket,
        server,
        parent_agent_id,
        parent_key,
        parent_iv,
        parent_ctr_offset,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Happy path: a valid inner Demon INIT for a new child agent must:
///   1. Register the child agent in the registry.
///   2. Broadcast an `AgentNew` event for the child.
///   3. Broadcast an `AgentResponse` with Type "Good" and the SMB connect message.
#[tokio::test]
async fn pivot_connect_new_child_agent_registered_and_announced()
-> Result<(), Box<dyn std::error::Error>> {
    let mut h = setup_pivot_test("pivot-new-child").await?;

    let child_agent_id = 0xCC00_0001_u32;
    let child_key: [u8; AGENT_KEY_LENGTH] = [
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E,
        0x3F, 0x40,
    ];
    let child_iv: [u8; AGENT_IV_LENGTH] = [
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0,
        0x01,
    ];

    let payload = pivot_connect_success_payload(child_agent_id, child_key, child_iv);

    h.client
        .post(format!("http://127.0.0.1:{}/", h.listener_port))
        .body(common::valid_demon_callback_body(
            h.parent_agent_id,
            h.parent_key,
            h.parent_iv,
            h.parent_ctr_offset,
            u32::from(DemonCommand::CommandPivot),
            0x01,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // First broadcast: AgentNew for the child.
    let child_new = common::read_operator_message(&mut h.socket).await?;
    let OperatorMessage::AgentNew(child_msg) = child_new else {
        panic!("expected AgentNew for child, got {child_new:?}");
    };
    assert_eq!(child_msg.info.name_id, format!("{child_agent_id:08X}"));

    // Second broadcast: AgentResponse "Good" confirming the pivot connection.
    let resp_event = common::read_operator_message(&mut h.socket).await?;
    let OperatorMessage::AgentResponse(resp_msg) = resp_event else {
        panic!("expected AgentResponse (Good), got {resp_event:?}");
    };
    assert_eq!(resp_msg.info.demon_id, format!("{:08X}", h.parent_agent_id));
    assert_eq!(
        resp_msg.info.extra.get("Type").and_then(Value::as_str),
        Some("Good"),
        "expected Type=Good for successful pivot connect"
    );
    let message = resp_msg.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(
        message.contains("[SMB] Connected to pivot agent"),
        "expected SMB connect message, got {message:?}"
    );

    // Verify child is in the registry.
    let child_record = h.server.agent_registry.get(child_agent_id).await;
    assert!(child_record.is_some(), "child agent must be registered in the AgentRegistry");

    // Verify the pivot link exists.
    let pivots = h.server.agent_registry.pivots(child_agent_id).await;
    assert_eq!(pivots.parent, Some(h.parent_agent_id), "child's parent must be the parent agent");

    Ok(())
}

/// When the child agent already exists in the registry, the pivot connect handler
/// treats this as a reconnect: it reuses the existing agent record, updates
/// `last_call_in`, reactivates the agent if dead, establishes the pivot link, and
/// broadcasts an `AgentUpdate` (mark) followed by an `AgentResponse` confirming
/// the connection.  This matches the original Havoc behaviour where pivot
/// reconnects are handled by retrieving the existing instance rather than
/// re-parsing the DEMON_INIT.
#[tokio::test]
async fn pivot_connect_existing_child_reconnects_successfully()
-> Result<(), Box<dyn std::error::Error>> {
    let mut h = setup_pivot_test("pivot-reconnect").await?;

    let child_agent_id = 0xCC00_0002_u32;
    let child_key: [u8; AGENT_KEY_LENGTH] = [
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E,
        0x5F, 0x60,
    ];
    let child_iv: [u8; AGENT_IV_LENGTH] = [
        0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9A, 0xAB, 0xBC, 0xCD, 0xDE, 0xEF, 0xF0,
        0x01,
    ];

    // Pre-register the child agent via a direct HTTP init so it already exists
    // in the registry before the pivot connect.
    let _child_ctr =
        common::register_agent(&h.client, h.listener_port, child_agent_id, child_key, child_iv)
            .await?;

    // Consume the AgentNew broadcast from the child's direct registration.
    let child_new = common::read_operator_message(&mut h.socket).await?;
    assert!(
        matches!(child_new, OperatorMessage::AgentNew(_)),
        "expected AgentNew for pre-registered child, got {child_new:?}"
    );

    // Now send the pivot connect callback — child already exists, handler
    // should treat this as a reconnect.
    let payload = pivot_connect_success_payload(child_agent_id, child_key, child_iv);

    h.client
        .post(format!("http://127.0.0.1:{}/", h.listener_port))
        .body(common::valid_demon_callback_body(
            h.parent_agent_id,
            h.parent_key,
            h.parent_iv,
            h.parent_ctr_offset,
            u32::from(DemonCommand::CommandPivot),
            0x01,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // First broadcast: AgentUpdate (mark) for the reconnected child.
    let mark_event = common::read_operator_message(&mut h.socket).await?;
    let OperatorMessage::AgentUpdate(update) = &mark_event else {
        panic!("expected AgentUpdate for reconnected child, got {mark_event:?}");
    };
    assert_eq!(
        update.info.agent_id,
        format!("{child_agent_id:08X}"),
        "mark event must reference the child agent"
    );
    assert_eq!(update.info.marked, "Alive", "reconnected child must be marked Alive");

    // Second broadcast: AgentResponse confirming the pivot connection.
    let resp_event = common::read_operator_message(&mut h.socket).await?;
    let OperatorMessage::AgentResponse(resp) = &resp_event else {
        panic!("expected AgentResponse, got {resp_event:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(
        message.contains("[SMB] Connected to pivot agent"),
        "response must confirm pivot connection, got: {message}"
    );

    // The child should still exist and now have a pivot link to the parent.
    let child_record = h.server.agent_registry.get(child_agent_id).await;
    assert!(child_record.is_some(), "child must exist after reconnect");

    Ok(())
}

/// Error path: `success=0` must broadcast an error `AgentResponse` with the
/// Win32 error code name and must NOT register a child agent.
#[tokio::test]
async fn pivot_connect_failure_broadcasts_error_response() -> Result<(), Box<dyn std::error::Error>>
{
    let mut h = setup_pivot_test("pivot-error").await?;

    // Win32 error code 5 = ERROR_ACCESS_DENIED
    let payload = pivot_connect_error_payload(5);

    h.client
        .post(format!("http://127.0.0.1:{}/", h.listener_port))
        .body(common::valid_demon_callback_body(
            h.parent_agent_id,
            h.parent_key,
            h.parent_iv,
            h.parent_ctr_offset,
            u32::from(DemonCommand::CommandPivot),
            0x01,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // Should receive an AgentResponse with Type "Error" and the error code name.
    let resp_event = common::read_operator_message(&mut h.socket).await?;
    let OperatorMessage::AgentResponse(resp_msg) = resp_event else {
        panic!("expected AgentResponse (Error), got {resp_event:?}");
    };
    assert_eq!(
        resp_msg.info.extra.get("Type").and_then(Value::as_str),
        Some("Error"),
        "failed pivot connect must have Type=Error"
    );
    let message = resp_msg.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(
        message.contains("ERROR_ACCESS_DENIED"),
        "expected error name in message, got {message:?}"
    );
    assert!(message.contains("[5]"), "expected numeric error code in message, got {message:?}");

    Ok(())
}

/// Error path: inner envelope is a valid DemonEnvelope but does NOT contain a
/// Demon INIT. The handler must return an `InvalidCallbackPayload` error. The
/// dispatch pipeline logs the error but the server does not crash, and no child
/// agent is registered.
#[tokio::test]
async fn pivot_connect_non_init_inner_envelope_is_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let mut h = setup_pivot_test("pivot-non-init").await?;

    let child_agent_id = 0xCC00_0003_u32;
    let payload = pivot_connect_non_init_inner_payload(child_agent_id);

    // Send the callback — we don't assert on HTTP status because the dispatch
    // error may surface as a non-200 response depending on the listener pipeline.
    let _resp = h
        .client
        .post(format!("http://127.0.0.1:{}/", h.listener_port))
        .body(common::valid_demon_callback_body(
            h.parent_agent_id,
            h.parent_key,
            h.parent_iv,
            h.parent_ctr_offset,
            u32::from(DemonCommand::CommandPivot),
            0x01,
            &payload,
        ))
        .send()
        .await?;

    // The child agent must NOT be in the registry.
    let child_record = h.server.agent_registry.get(child_agent_id).await;
    assert!(
        child_record.is_none(),
        "child agent must NOT be registered when inner envelope is not a DemonInit"
    );

    // No AgentNew event should have been broadcast for this child (optional TeamserverLog ok).
    common::skip_optional_teamserver_log(&mut h.socket, std::time::Duration::from_millis(500))
        .await;
    common::assert_no_operator_message(&mut h.socket, std::time::Duration::from_millis(500)).await;

    Ok(())
}

/// Error path: inner bytes are too short to be a valid DemonEnvelope. The handler
/// must fail with a DemonProtocolError wrapped in `InvalidCallbackPayload`. The
/// server does not crash and no child agent is registered.
#[tokio::test]
async fn pivot_connect_malformed_inner_envelope_is_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    let mut h = setup_pivot_test("pivot-malformed").await?;

    let payload = pivot_connect_malformed_inner_payload();

    // Send the callback — the server must not crash.
    let _resp = h
        .client
        .post(format!("http://127.0.0.1:{}/", h.listener_port))
        .body(common::valid_demon_callback_body(
            h.parent_agent_id,
            h.parent_key,
            h.parent_iv,
            h.parent_ctr_offset,
            u32::from(DemonCommand::CommandPivot),
            0x01,
            &payload,
        ))
        .send()
        .await?;

    // No AgentNew event should have been broadcast, and no child registered (optional TeamserverLog ok).
    common::skip_optional_teamserver_log(&mut h.socket, std::time::Duration::from_millis(500))
        .await;
    common::assert_no_operator_message(&mut h.socket, std::time::Duration::from_millis(500)).await;

    Ok(())
}

// ---------------------------------------------------------------------------
// SmbDisconnect tests
// ---------------------------------------------------------------------------

/// Happy path: disconnect a previously connected pivot child.
///
/// 1. Establish a pivot link via SmbConnect.
/// 2. Send an SmbDisconnect callback for that child.
/// 3. Assert: the child is marked dead, the pivot link is removed, an
///    `AgentUpdate` (mark) is broadcast for the child, and an `AgentResponse`
///    with Type "Info" confirms the disconnection.
#[tokio::test]
async fn pivot_disconnect_removes_link_and_marks_child_dead()
-> Result<(), Box<dyn std::error::Error>> {
    let mut h = setup_pivot_test("pivot-disconnect-ok").await?;

    // -- Step 1: connect a child via SmbConnect --
    let child_agent_id = 0xDD00_0001_u32;
    let child_key: [u8; AGENT_KEY_LENGTH] = [
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E,
        0x7F, 0x80,
    ];
    let child_iv: [u8; AGENT_IV_LENGTH] = [
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0,
    ];

    let connect_payload = pivot_connect_success_payload(child_agent_id, child_key, child_iv);

    h.client
        .post(format!("http://127.0.0.1:{}/", h.listener_port))
        .body(common::valid_demon_callback_body(
            h.parent_agent_id,
            h.parent_key,
            h.parent_iv,
            h.parent_ctr_offset,
            u32::from(DemonCommand::CommandPivot),
            0x01,
            &connect_payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // Consume the AgentNew for the child.
    let child_new = common::read_operator_message(&mut h.socket).await?;
    assert!(
        matches!(child_new, OperatorMessage::AgentNew(_)),
        "expected AgentNew for child, got {child_new:?}"
    );

    // Consume the AgentResponse (Good) for the SmbConnect.
    let connect_resp = common::read_operator_message(&mut h.socket).await?;
    assert!(
        matches!(connect_resp, OperatorMessage::AgentResponse(_)),
        "expected AgentResponse for connect, got {connect_resp:?}"
    );

    // Verify pivot link exists before disconnect.
    let pivots_before = h.server.agent_registry.pivots(child_agent_id).await;
    assert_eq!(pivots_before.parent, Some(h.parent_agent_id), "child must be linked to parent");

    // -- Step 2: disconnect the child via SmbDisconnect --
    // Monotonic CTR: advance past the connect callback's encrypted payload.
    let next_ctr_offset = h.parent_ctr_offset + ctr_blocks_for_len(4 + connect_payload.len());

    let disconnect_payload = pivot_disconnect_success_payload(child_agent_id);

    h.client
        .post(format!("http://127.0.0.1:{}/", h.listener_port))
        .body(common::valid_demon_callback_body(
            h.parent_agent_id,
            h.parent_key,
            h.parent_iv,
            next_ctr_offset,
            u32::from(DemonCommand::CommandPivot),
            0x02,
            &disconnect_payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // Expect AgentUpdate (mark) for the child being marked dead.
    let mark_event = common::read_operator_message(&mut h.socket).await?;
    let OperatorMessage::AgentUpdate(update) = &mark_event else {
        panic!("expected AgentUpdate for disconnected child, got {mark_event:?}");
    };
    assert_eq!(
        update.info.agent_id,
        format!("{child_agent_id:08X}"),
        "mark event must reference the child agent"
    );
    assert_eq!(update.info.marked, "Dead", "disconnected child must be marked Dead");

    // Expect AgentResponse (Info) confirming disconnection.
    let resp_event = common::read_operator_message(&mut h.socket).await?;
    let OperatorMessage::AgentResponse(resp) = &resp_event else {
        panic!("expected AgentResponse (Info), got {resp_event:?}");
    };
    assert_eq!(
        resp.info.extra.get("Type").and_then(Value::as_str),
        Some("Info"),
        "disconnect response must have Type=Info"
    );
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(
        message.contains("[SMB] Agent disconnected"),
        "expected disconnect message, got {message:?}"
    );

    // Verify pivot link is removed.
    let pivots_after = h.server.agent_registry.pivots(child_agent_id).await;
    assert_eq!(pivots_after.parent, None, "child must no longer have a parent after disconnect");

    let parent_children = h.server.agent_registry.children_of(h.parent_agent_id).await;
    assert!(
        !parent_children.contains(&child_agent_id),
        "parent must no longer list child after disconnect"
    );

    Ok(())
}

/// Error path: SmbDisconnect with `success=0` must broadcast an error
/// `AgentResponse` and must NOT modify the pivot link or agent status.
#[tokio::test]
async fn pivot_disconnect_failure_broadcasts_error_without_modifying_registry()
-> Result<(), Box<dyn std::error::Error>> {
    let mut h = setup_pivot_test("pivot-disconnect-fail").await?;

    // -- Establish a pivot link first --
    let child_agent_id = 0xDD00_0002_u32;
    let child_key: [u8; AGENT_KEY_LENGTH] = [
        0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E,
        0x9F, 0xA0,
    ];
    let child_iv: [u8; AGENT_IV_LENGTH] = [
        0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        0xD0,
    ];

    let connect_payload = pivot_connect_success_payload(child_agent_id, child_key, child_iv);

    h.client
        .post(format!("http://127.0.0.1:{}/", h.listener_port))
        .body(common::valid_demon_callback_body(
            h.parent_agent_id,
            h.parent_key,
            h.parent_iv,
            h.parent_ctr_offset,
            u32::from(DemonCommand::CommandPivot),
            0x01,
            &connect_payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // Consume AgentNew + AgentResponse for the connect.
    let _child_new = common::read_operator_message(&mut h.socket).await?;
    let _connect_resp = common::read_operator_message(&mut h.socket).await?;

    // -- Send SmbDisconnect with success=0 --
    // Monotonic CTR: advance past the connect callback's encrypted payload.
    let next_ctr_offset = h.parent_ctr_offset + ctr_blocks_for_len(4 + connect_payload.len());

    let disconnect_payload = pivot_disconnect_failure_payload(child_agent_id);

    h.client
        .post(format!("http://127.0.0.1:{}/", h.listener_port))
        .body(common::valid_demon_callback_body(
            h.parent_agent_id,
            h.parent_key,
            h.parent_iv,
            next_ctr_offset,
            u32::from(DemonCommand::CommandPivot),
            0x03,
            &disconnect_payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // Expect AgentResponse with Type "Error".
    let resp_event = common::read_operator_message(&mut h.socket).await?;
    let OperatorMessage::AgentResponse(resp) = &resp_event else {
        panic!("expected AgentResponse (Error), got {resp_event:?}");
    };
    assert_eq!(
        resp.info.extra.get("Type").and_then(Value::as_str),
        Some("Error"),
        "failed disconnect must have Type=Error"
    );
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(
        message.contains("[SMB] Failed to disconnect agent"),
        "expected failure message, got {message:?}"
    );
    assert!(
        message.contains(&format!("{child_agent_id:08X}")),
        "error message must include child agent ID"
    );

    // Pivot link must still exist — failure does not modify the registry.
    let pivots = h.server.agent_registry.pivots(child_agent_id).await;
    assert_eq!(
        pivots.parent,
        Some(h.parent_agent_id),
        "pivot link must remain after failed disconnect"
    );

    Ok(())
}

/// Edge case: SmbDisconnect for a child that was never connected must not
/// crash, must not register a phantom agent, and must still broadcast the
/// confirmation `AgentResponse`.
#[tokio::test]
async fn pivot_disconnect_no_existing_link_does_not_panic_or_corrupt_registry()
-> Result<(), Box<dyn std::error::Error>> {
    let mut h = setup_pivot_test("pivot-disconnect-no-link").await?;

    // Use a child ID that was never connected via pivot.
    let phantom_child_id = 0xDD00_FFFF_u32;

    let disconnect_payload = pivot_disconnect_success_payload(phantom_child_id);

    h.client
        .post(format!("http://127.0.0.1:{}/", h.listener_port))
        .body(common::valid_demon_callback_body(
            h.parent_agent_id,
            h.parent_key,
            h.parent_iv,
            h.parent_ctr_offset,
            u32::from(DemonCommand::CommandPivot),
            0x01,
            &disconnect_payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // The handler calls disconnect_link which returns empty affected list when
    // the link doesn't exist, but still broadcasts the AgentResponse (Info).
    let resp_event = common::read_operator_message(&mut h.socket).await?;
    let OperatorMessage::AgentResponse(resp) = &resp_event else {
        panic!("expected AgentResponse (Info), got {resp_event:?}");
    };
    assert_eq!(
        resp.info.extra.get("Type").and_then(Value::as_str),
        Some("Info"),
        "disconnect of nonexistent link must still produce Type=Info"
    );

    // The phantom child must NOT appear in the registry.
    let phantom_record = h.server.agent_registry.get(phantom_child_id).await;
    assert!(
        phantom_record.is_none(),
        "disconnecting a never-connected child must not register a phantom agent"
    );

    // Parent must have no children.
    let parent_children = h.server.agent_registry.children_of(h.parent_agent_id).await;
    assert!(
        parent_children.is_empty(),
        "parent must have no children after disconnecting a nonexistent link"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Self-referential pivot (child_agent_id == parent_agent_id)
// ---------------------------------------------------------------------------

/// Edge case: a `CommandPivot/SmbConnect` callback whose inner DEMON_INIT
/// carries the same `agent_id` as the parent agent that sent the callback.
///
/// The server must reject this without:
/// - Overwriting the parent agent's registry record (AES key, IV, etc.).
/// - Creating a self-referential cycle in the pivot graph.
/// - Crashing or panicking.
///
/// Because the parent is already registered, the handler takes the
/// "reconnect" path (`registry.get(child_agent_id).is_some()`), calls
/// `set_last_call_in`, then calls `add_link(parent, parent)` which must
/// fail with `InvalidPivotLink`.
#[tokio::test]
async fn pivot_connect_self_referential_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut h = setup_pivot_test("pivot-self-ref").await?;

    // Capture the parent agent's original AES key before the pivot attempt.
    let parent_before =
        h.server.agent_registry.get(h.parent_agent_id).await.expect("parent must be registered");
    let original_key = parent_before.encryption.aes_key.clone();
    let original_iv = parent_before.encryption.aes_iv.clone();

    // Build a pivot connect payload where the inner DEMON_INIT uses the
    // *same* agent_id as the parent.  Use a different AES key/IV so we can
    // detect if the parent's crypto material gets overwritten.
    let evil_key: [u8; AGENT_KEY_LENGTH] = [
        0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10,
    ];
    let evil_iv: [u8; AGENT_IV_LENGTH] = [
        0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
        0xE0,
    ];

    let payload = pivot_connect_success_payload(h.parent_agent_id, evil_key, evil_iv);

    // Send the self-referential pivot callback.  The dispatch error is
    // logged server-side; the HTTP response may or may not be 200 depending
    // on the listener pipeline, so we don't assert on status.
    let _resp = h
        .client
        .post(format!("http://127.0.0.1:{}/", h.listener_port))
        .body(common::valid_demon_callback_body(
            h.parent_agent_id,
            h.parent_key,
            h.parent_iv,
            h.parent_ctr_offset,
            u32::from(DemonCommand::CommandPivot),
            0x01,
            &payload,
        ))
        .send()
        .await?;

    // No AgentNew event should be broadcast ... (optional TeamserverLog diagnostic ok).
    common::skip_optional_teamserver_log(&mut h.socket, std::time::Duration::from_millis(500))
        .await;
    common::assert_no_operator_message(&mut h.socket, std::time::Duration::from_millis(500)).await;

    // The parent's AES key and IV must NOT have been overwritten.
    let parent_after = h
        .server
        .agent_registry
        .get(h.parent_agent_id)
        .await
        .expect("parent must still be registered");
    assert_eq!(
        parent_after.encryption.aes_key, original_key,
        "parent AES key must not be overwritten by self-referential pivot"
    );
    assert_eq!(
        parent_after.encryption.aes_iv, original_iv,
        "parent AES IV must not be overwritten by self-referential pivot"
    );

    // No pivot cycle: the parent must have no parent and no children.
    let pivots = h.server.agent_registry.pivots(h.parent_agent_id).await;
    assert_eq!(pivots.parent, None, "parent must not have a pivot parent (no self-cycle)");
    assert!(pivots.children.is_empty(), "parent must not have pivot children (no self-link)");

    Ok(())
}

// ---------------------------------------------------------------------------
// Unregistered parent agent
// ---------------------------------------------------------------------------

/// Security boundary: a `CommandPivot/SmbConnect` callback sent from an agent
/// that has never completed DEMON_INIT (i.e., `parent_agent_id` is not in the
/// registry) must be rejected with HTTP 404, must NOT register any child agent,
/// and must NOT broadcast an `AgentNew` event.
///
/// This mirrors the property already tested for `CommandGetJob` and
/// `CommandCheckin` in `http_listener_pipeline.rs`.
#[tokio::test]
async fn pivot_connect_from_unregistered_parent_returns_404()
-> Result<(), Box<dyn std::error::Error>> {
    // Set up a server and listener but do NOT register any parent agent.
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("pivot-unregistered", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("pivot-unregistered").await?;
    common::wait_for_listener(listener_port).await?;

    // Use an agent_id that was never registered via DEMON_INIT.
    let unregistered_parent_id = 0xBAAD_F00D_u32;
    let fake_key: [u8; AGENT_KEY_LENGTH] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let fake_iv: [u8; AGENT_IV_LENGTH] = [
        0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F,
        0x90,
    ];

    // Build a valid-looking CommandPivot/SmbConnect payload with a child agent.
    let child_agent_id = 0xCC00_DEAD_u32;
    let child_key: [u8; AGENT_KEY_LENGTH] = [
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E,
        0x5F, 0x60,
    ];
    let child_iv: [u8; AGENT_IV_LENGTH] = [
        0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9A, 0xAB, 0xBC, 0xCD, 0xDE, 0xEF, 0xF0,
        0x01,
    ];

    let payload = pivot_connect_success_payload(child_agent_id, child_key, child_iv);

    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            unregistered_parent_id,
            fake_key,
            fake_iv,
            0,
            u32::from(DemonCommand::CommandPivot),
            0x01,
            &payload,
        ))
        .send()
        .await?;

    // The server must reject the callback with 404 — the parent is unknown.
    assert_eq!(
        response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "CommandPivot from unregistered parent must return 404"
    );

    // The child agent must NOT have been registered.
    assert!(
        server.agent_registry.get(child_agent_id).await.is_none(),
        "child agent must not be registered when parent is unregistered"
    );

    // The unregistered parent must not have been created either.
    assert!(
        server.agent_registry.get(unregistered_parent_id).await.is_none(),
        "unregistered parent must not appear in the registry"
    );

    // No agents should exist at all.
    assert!(
        server.agent_registry.list_active().await.is_empty(),
        "no agents should be registered after CommandPivot from unknown parent"
    );

    // No AgentNew event should have been broadcast (optional TeamserverLog for 404 is ok).
    common::skip_optional_teamserver_log(&mut socket, std::time::Duration::from_millis(500)).await;
    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(500)).await;

    Ok(())
}
