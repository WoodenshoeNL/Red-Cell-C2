//! Tests for token revert, remove, and clear subcommands.

use super::*;

// ── integration tests ─────────────────────────────────────────────────────────

#[tokio::test]
async fn token_revert_callback_success_and_failure() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Revert));
    add_u32(&mut payload, 1);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 20, &payload).await?;

    let event = receiver.recv().await.ok_or("token revert response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("reverted token to itself"));

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Revert));
    add_u32(&mut payload, 0);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 21, &payload).await?;

    let event = receiver.recv().await.ok_or("token revert failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("Failed to revert"));
    Ok(())
}

#[tokio::test]
async fn token_remove_callback_success_and_failure() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Remove));
    add_u32(&mut payload, 1);
    add_u32(&mut payload, 5);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 22, &payload).await?;

    let event = receiver.recv().await.ok_or("token remove response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("removed token [5]"));

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Remove));
    add_u32(&mut payload, 0);
    add_u32(&mut payload, 5);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 23, &payload).await?;

    let event = receiver.recv().await.ok_or("token remove failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("Failed to remove token [5]"));
    Ok(())
}

#[tokio::test]
async fn token_clear_callback_broadcasts_success() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Clear));
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 24, &payload).await?;

    let event = receiver.recv().await.ok_or("token clear response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("Token vault has been cleared"));
    Ok(())
}

#[tokio::test]
async fn token_revert_success_emits_good_failure_emits_error()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Revert));
    add_u32(&mut payload, 1); // success
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 49, &payload).await?;

    let event = receiver.recv().await.ok_or("revert success response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Successful reverted token to itself")
    );

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Revert));
    add_u32(&mut payload, 0); // failure
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 50, &payload).await?;

    let event = receiver.recv().await.ok_or("revert failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Failed to revert token to itself")
    );
    Ok(())
}

#[tokio::test]
async fn token_remove_success_emits_good_failure_emits_error()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Remove));
    add_u32(&mut payload, 1); // success
    add_u32(&mut payload, 42); // token_id
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 51, &payload).await?;

    let event = receiver.recv().await.ok_or("remove success response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Successful removed token [42] from vault")
    );

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Remove));
    add_u32(&mut payload, 0); // failure
    add_u32(&mut payload, 42); // token_id
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 52, &payload).await?;

    let event = receiver.recv().await.ok_or("remove failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Failed to remove token [42] from vault")
    );
    Ok(())
}

// ── unit-handle tests ─────────────────────────────────────────────────────────

#[tokio::test]
async fn unit_handle_clear() {
    let payload = unit_token_payload(DemonTokenCommand::Clear, &[]);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    assert_unit_response(&msg, "Good", "Token vault has been cleared");
}

#[tokio::test]
async fn unit_handle_remove_success() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 1);
    push_u32(&mut rest, 5);
    let payload = unit_token_payload(DemonTokenCommand::Remove, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    assert_unit_response(&msg, "Good", "Successful removed token [5] from vault");
}

#[tokio::test]
async fn unit_handle_remove_failure() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 0);
    push_u32(&mut rest, 3);
    let payload = unit_token_payload(DemonTokenCommand::Remove, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    assert_unit_response(&msg, "Error", "Failed to remove token [3] from vault");
}

// ── truncated-payload error tests ─────────────────────────────────────────────

#[tokio::test]
async fn unit_handle_truncated_revert_payload() {
    let payload = unit_token_payload(DemonTokenCommand::Revert, &[]);
    let events = EventBus::default();
    let result = handle_token_callback(&events, UNIT_AGENT_ID, UNIT_REQUEST_ID, &payload).await;
    assert!(result.is_err(), "truncated Revert should fail");
}

#[tokio::test]
async fn unit_handle_truncated_remove_payload() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 1);
    let payload = unit_token_payload(DemonTokenCommand::Remove, &rest);
    let events = EventBus::default();
    let result = handle_token_callback(&events, UNIT_AGENT_ID, UNIT_REQUEST_ID, &payload).await;
    assert!(result.is_err(), "truncated Remove should fail");
}
