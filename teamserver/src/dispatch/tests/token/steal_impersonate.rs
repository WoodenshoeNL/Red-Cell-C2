//! Tests for token steal and impersonate subcommands.

use super::*;

// ── integration tests ─────────────────────────────────────────────────────────

#[tokio::test]
async fn token_steal_callback_broadcasts_success_event() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Steal));
    add_utf16(&mut payload, "LAB\\admin");
    add_u32(&mut payload, 3);
    add_u32(&mut payload, 1234);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 10, &payload).await?;

    let event = receiver.recv().await.ok_or("token steal response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(
        msg,
        "Successfully stole and impersonated token from 1234 User:[LAB\\admin] TokenID:[3]"
    );
    assert!(msg.contains("LAB\\admin"));
    assert!(msg.contains("TokenID:[3]"));
    Ok(())
}

#[tokio::test]
async fn token_impersonate_success_emits_good_response() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Impersonate));
    add_u32(&mut payload, 1); // success
    add_bytes(&mut payload, b"CORP\\jdoe\0");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 40, &payload).await?;

    let event = receiver.recv().await.ok_or("impersonate success response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Successfully impersonated CORP\\jdoe")
    );
    Ok(())
}

#[tokio::test]
async fn token_impersonate_failure_emits_error_response() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Impersonate));
    add_u32(&mut payload, 0); // failure
    add_bytes(&mut payload, b"CORP\\jdoe\0");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 41, &payload).await?;

    let event = receiver.recv().await.ok_or("impersonate failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Failed to impersonate CORP\\jdoe")
    );
    Ok(())
}

// ── unit-handle tests ─────────────────────────────────────────────────────────

#[tokio::test]
async fn unit_handle_impersonate_success() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 1);
    push_string(&mut rest, "CORP\\admin");
    let payload = unit_token_payload(DemonTokenCommand::Impersonate, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    assert_eq!(result.expect("ok"), None);
    let msg = msg.expect("broadcast");
    assert_unit_response(&msg, "Good", "Successfully impersonated CORP\\admin");
}

#[tokio::test]
async fn unit_handle_impersonate_failure() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 0);
    push_string(&mut rest, "CORP\\user");
    let payload = unit_token_payload(DemonTokenCommand::Impersonate, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    assert_unit_response(&msg, "Error", "Failed to impersonate CORP\\user");
}

#[tokio::test]
async fn unit_handle_steal() {
    let mut rest = Vec::new();
    push_utf16(&mut rest, "LAB\\admin");
    push_u32(&mut rest, 7);
    push_u32(&mut rest, 9999);
    let payload = unit_token_payload(DemonTokenCommand::Steal, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    let output = assert_unit_response(
        &msg,
        "Good",
        "Successfully stole and impersonated token from 9999 User:[LAB\\admin] TokenID:[7]",
    );
    assert!(output.is_empty() || !output.contains("Error"));
}

// ── truncated-payload error tests ─────────────────────────────────────────────

#[tokio::test]
async fn unit_handle_truncated_impersonate_payload() {
    let payload = unit_token_payload(DemonTokenCommand::Impersonate, &[]);
    let events = EventBus::default();
    let result = handle_token_callback(&events, UNIT_AGENT_ID, UNIT_REQUEST_ID, &payload).await;
    assert!(result.is_err(), "truncated Impersonate should fail");
}

#[tokio::test]
async fn unit_handle_truncated_steal_payload() {
    let payload = unit_token_payload(DemonTokenCommand::Steal, &[]);
    let events = EventBus::default();
    let result = handle_token_callback(&events, UNIT_AGENT_ID, UNIT_REQUEST_ID, &payload).await;
    assert!(result.is_err(), "truncated Steal should fail");
}
