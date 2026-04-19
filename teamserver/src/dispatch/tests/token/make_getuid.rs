//! Tests for token make and getuid subcommands.

use super::*;

// ── integration tests ─────────────────────────────────────────────────────────

#[tokio::test]
async fn token_make_callback_success_and_empty() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Make));
    add_utf16(&mut payload, "LAB\\admin");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 16, &payload).await?;

    let event = receiver.recv().await.ok_or("token make response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("Successfully created and impersonated token"));
    assert!(msg.contains("LAB\\admin"));

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Make));
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 17, &payload).await?;

    let event = receiver.recv().await.ok_or("token make failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("Failed to create token"));
    Ok(())
}

#[tokio::test]
async fn token_getuid_callback_elevated_and_normal() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::GetUid));
    add_u32(&mut payload, 1);
    add_utf16(&mut payload, "LAB\\admin");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 18, &payload).await?;

    let event = receiver.recv().await.ok_or("token getuid response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("LAB\\admin"));
    assert!(msg.contains("(Admin)"));

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::GetUid));
    add_u32(&mut payload, 0);
    add_utf16(&mut payload, "LAB\\user");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 19, &payload).await?;

    let event = receiver.recv().await.ok_or("token getuid normal response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("LAB\\user"));
    assert!(!msg.contains("(Admin)"));
    Ok(())
}

#[tokio::test]
async fn token_make_success_emits_good_type() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Make));
    add_utf16(&mut payload, "CORP\\svcacct");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 42, &payload).await?;

    let event = receiver.recv().await.ok_or("make success response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(msg, "Successfully created and impersonated token: CORP\\svcacct");
    Ok(())
}

#[tokio::test]
async fn token_make_empty_payload_emits_error_type() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Make));
    // No user_domain — triggers failure path
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 43, &payload).await?;

    let event = receiver.recv().await.ok_or("make failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Failed to create token")
    );
    Ok(())
}

#[tokio::test]
async fn token_getuid_elevated_emits_admin_suffix() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    // Elevated user
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::GetUid));
    add_u32(&mut payload, 1); // elevated
    add_utf16(&mut payload, "CORP\\admin");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 44, &payload).await?;

    let event = receiver.recv().await.ok_or("getuid elevated response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Token User: CORP\\admin (Admin)")
    );

    // Non-elevated user
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::GetUid));
    add_u32(&mut payload, 0); // not elevated
    add_utf16(&mut payload, "CORP\\user");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 45, &payload).await?;

    let event = receiver.recv().await.ok_or("getuid normal response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Token User: CORP\\user")
    );
    Ok(())
}

// ── unit-handle tests ─────────────────────────────────────────────────────────

#[tokio::test]
async fn unit_handle_make_success() {
    let mut rest = Vec::new();
    push_utf16(&mut rest, "CORP\\admin");
    let payload = unit_token_payload(DemonTokenCommand::Make, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    assert_unit_response(&msg, "Good", "Successfully created and impersonated token: CORP\\admin");
}

#[tokio::test]
async fn unit_handle_make_empty_payload_is_error() {
    let payload = unit_token_payload(DemonTokenCommand::Make, &[]);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    assert_unit_response(&msg, "Error", "Failed to create token");
}

#[tokio::test]
async fn unit_handle_getuid_elevated() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 1);
    push_utf16(&mut rest, "CORP\\admin");
    let payload = unit_token_payload(DemonTokenCommand::GetUid, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    assert_unit_response(&msg, "Good", "Token User: CORP\\admin (Admin)");
}

#[tokio::test]
async fn unit_handle_getuid_not_elevated() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 0);
    push_utf16(&mut rest, "CORP\\user");
    let payload = unit_token_payload(DemonTokenCommand::GetUid, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    assert_unit_response(&msg, "Good", "Token User: CORP\\user");
}

// ── truncated-payload error tests ─────────────────────────────────────────────

#[tokio::test]
async fn unit_handle_truncated_getuid_payload() {
    let payload = unit_token_payload(DemonTokenCommand::GetUid, &[]);
    let events = EventBus::default();
    let result = handle_token_callback(&events, UNIT_AGENT_ID, UNIT_REQUEST_ID, &payload).await;
    assert!(result.is_err(), "truncated GetUid should fail");
}
