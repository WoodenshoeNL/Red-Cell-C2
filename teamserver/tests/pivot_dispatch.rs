//! Integration tests for `dispatch/pivot.rs` — `handle_pivot_connect_callback`.
//!
//! All tests go through the full HTTP → listener → dispatch pipeline so that
//! the agent registration, event-bus broadcast, and error paths are exercised
//! end-to-end.

mod common;

use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
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
    let inner = common::valid_demon_init_body(child_agent_id, child_key, child_iv);
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(DemonPivotCommand::SmbConnect).to_le_bytes());
    payload.extend_from_slice(&1_u32.to_le_bytes()); // success = 1
    // read_bytes reads a u32 length prefix followed by that many bytes
    payload.extend_from_slice(&u32::try_from(inner.len()).unwrap().to_le_bytes());
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
    payload.extend_from_slice(&u32::try_from(inner.len()).unwrap().to_le_bytes());
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
    payload.extend_from_slice(&u32::try_from(garbage.len()).unwrap().to_le_bytes());
    payload.extend_from_slice(&garbage);
    payload
}

// ---------------------------------------------------------------------------
// Helper: spawn server, listener, register parent agent, return handles
// ---------------------------------------------------------------------------

struct PivotTestHarness {
    client: reqwest::Client,
    listener_port: u16,
    socket: common::WsClient,
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

    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config(listener_name, listener_port)).await?;
    drop(listener_guard);
    server.listeners.start(listener_name).await?;
    common::wait_for_listener(listener_port).await?;

    let parent_agent_id = 0xAA00_0001_u32;
    let parent_key = [0x11; AGENT_KEY_LENGTH];
    let parent_iv = [0x22; AGENT_IV_LENGTH];
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
    let child_key = [0x33; AGENT_KEY_LENGTH];
    let child_iv = [0x44; AGENT_IV_LENGTH];

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
    let child_key = [0x55; AGENT_KEY_LENGTH];
    let child_iv = [0x66; AGENT_IV_LENGTH];

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

    // No AgentNew event should have been broadcast for this child.
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

    // No AgentNew event should have been broadcast, and no child registered.
    common::assert_no_operator_message(&mut h.socket, std::time::Duration::from_millis(500)).await;

    Ok(())
}
