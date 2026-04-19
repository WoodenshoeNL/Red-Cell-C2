//! Tests for token privs_get and privs_list subcommands, including formatter unit tests.

use super::*;

// ── integration tests ─────────────────────────────────────────────────────────

#[tokio::test]
async fn token_privs_list_callback_formats_privilege_table()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::PrivsGetOrList));
    add_u32(&mut payload, 1);
    add_bytes(&mut payload, b"SeDebugPrivilege\0");
    add_u32(&mut payload, 3);
    add_bytes(&mut payload, b"SeShutdownPrivilege\0");
    add_u32(&mut payload, 0);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 13, &payload).await?;

    let event = receiver.recv().await.ok_or("token privs list response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert!(message.info.output.contains("SeDebugPrivilege"));
    assert!(message.info.output.contains("Enabled"));
    assert!(message.info.output.contains("SeShutdownPrivilege"));
    assert!(message.info.output.contains("Disabled"));
    Ok(())
}

#[tokio::test]
async fn token_privs_get_callback_success_and_failure() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::PrivsGetOrList));
    add_u32(&mut payload, 0);
    add_u32(&mut payload, 1);
    add_bytes(&mut payload, b"SeDebugPrivilege\0");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 14, &payload).await?;

    let event = receiver.recv().await.ok_or("token privs get response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("successfully enabled"));
    assert!(msg.contains("SeDebugPrivilege"));

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::PrivsGetOrList));
    add_u32(&mut payload, 0);
    add_u32(&mut payload, 0);
    add_bytes(&mut payload, b"SeDebugPrivilege\0");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 15, &payload).await?;

    let event = receiver.recv().await.ok_or("token privs get failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("Failed to enable"));
    Ok(())
}

#[tokio::test]
async fn token_privs_get_success_emits_good_type() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    // Enable privilege — success
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::PrivsGetOrList));
    add_u32(&mut payload, 0); // get mode
    add_u32(&mut payload, 1); // success
    add_bytes(&mut payload, b"SeImpersonatePrivilege\0");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 46, &payload).await?;

    let event = receiver.recv().await.ok_or("privs get success response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("The privilege SeImpersonatePrivilege was successfully enabled")
    );

    // Enable privilege — failure
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::PrivsGetOrList));
    add_u32(&mut payload, 0); // get mode
    add_u32(&mut payload, 0); // failure
    add_bytes(&mut payload, b"SeImpersonatePrivilege\0");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 47, &payload).await?;

    let event = receiver.recv().await.ok_or("privs get failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Failed to enable the SeImpersonatePrivilege privilege")
    );
    Ok(())
}

#[tokio::test]
async fn token_privs_list_emits_good_type_with_all_states() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::PrivsGetOrList));
    add_u32(&mut payload, 1); // list mode
    add_bytes(&mut payload, b"SeDebugPrivilege\0");
    add_u32(&mut payload, 3); // Enabled
    add_bytes(&mut payload, b"SeBackupPrivilege\0");
    add_u32(&mut payload, 2); // Adjusted
    add_bytes(&mut payload, b"SeRestorePrivilege\0");
    add_u32(&mut payload, 0); // Disabled
    add_bytes(&mut payload, b"SeCustomPrivilege\0");
    add_u32(&mut payload, 99); // Unknown
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 48, &payload).await?;

    let event = receiver.recv().await.ok_or("privs list response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    let output = &message.info.output;
    assert!(output.contains("SeDebugPrivilege :: Enabled"));
    assert!(output.contains("SeBackupPrivilege :: Adjusted"));
    assert!(output.contains("SeRestorePrivilege :: Disabled"));
    assert!(output.contains("SeCustomPrivilege :: Unknown"));
    Ok(())
}

#[tokio::test]
async fn token_privs_list_callback_rejects_truncated_row() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    // PrivsGetOrList with priv_list=1 (list mode), one complete priv followed by truncation.
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::PrivsGetOrList));
    add_u32(&mut payload, 1); // priv_list flag
    // First complete privilege entry
    add_bytes(&mut payload, b"SeDebugPrivilege\0");
    add_u32(&mut payload, 3); // state = Enabled
    // Second row: privilege name present but state truncated
    add_bytes(&mut payload, b"SeShutdownPrivilege\0");
    // Missing: state u32

    let err = dispatcher
        .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 31, &payload)
        .await
        .expect_err("truncated privilege list row must be rejected");
    assert!(
        matches!(
            err,
            CommandDispatchError::InvalidCallbackPayload { command_id, .. }
            if command_id == u32::from(DemonCommand::CommandToken)
        ),
        "expected InvalidCallbackPayload, got {err:?}"
    );
    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "no event should be broadcast on parse failure"
    );
    Ok(())
}

// ── format_token_privs_list unit tests ───────────────────────────────────────

#[test]
fn format_token_privs_list_all_states() {
    let mut buf = Vec::new();
    push_string(&mut buf, "SeDebugPrivilege");
    push_u32(&mut buf, 3);
    push_string(&mut buf, "SeBackupPrivilege");
    push_u32(&mut buf, 2);
    push_string(&mut buf, "SeShutdownPrivilege");
    push_u32(&mut buf, 0);
    push_string(&mut buf, "SeRestorePrivilege");
    push_u32(&mut buf, 99);

    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_privs_list(&mut parser).expect("unwrap");
    assert!(output.contains("SeDebugPrivilege :: Enabled"));
    assert!(output.contains("SeBackupPrivilege :: Adjusted"));
    assert!(output.contains("SeShutdownPrivilege :: Disabled"));
    assert!(output.contains("SeRestorePrivilege :: Unknown"));
}

#[test]
fn format_token_privs_list_empty() {
    let buf = Vec::new();
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_privs_list(&mut parser).expect("unwrap");
    assert_eq!(output, "\n");
}

#[test]
fn format_token_privs_list_single_enabled() {
    let mut buf = Vec::new();
    push_string(&mut buf, "SeDebugPrivilege");
    push_u32(&mut buf, 3);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_privs_list(&mut parser).expect("unwrap");
    assert_eq!(output, "\n SeDebugPrivilege :: Enabled\n");
}

#[test]
fn format_token_privs_list_single_adjusted() {
    let mut buf = Vec::new();
    push_string(&mut buf, "SeBackupPrivilege");
    push_u32(&mut buf, 2);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_privs_list(&mut parser).expect("unwrap");
    assert_eq!(output, "\n SeBackupPrivilege :: Adjusted\n");
}

#[test]
fn format_token_privs_list_single_disabled() {
    let mut buf = Vec::new();
    push_string(&mut buf, "SeShutdownPrivilege");
    push_u32(&mut buf, 0);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_privs_list(&mut parser).expect("unwrap");
    assert_eq!(output, "\n SeShutdownPrivilege :: Disabled\n");
}

#[test]
fn format_token_privs_list_state_1_is_unknown() {
    let mut buf = Vec::new();
    push_string(&mut buf, "SeImpersonatePrivilege");
    push_u32(&mut buf, 1);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_privs_list(&mut parser).expect("unwrap");
    assert_eq!(output, "\n SeImpersonatePrivilege :: Unknown\n");
}

#[test]
fn format_token_privs_list_large_unknown_state() {
    let mut buf = Vec::new();
    push_string(&mut buf, "SeLoadDriverPrivilege");
    push_u32(&mut buf, 255);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_privs_list(&mut parser).expect("unwrap");
    assert_eq!(output, "\n SeLoadDriverPrivilege :: Unknown\n");
}

#[test]
fn format_token_privs_list_multiple_preserves_order() {
    let mut buf = Vec::new();
    push_string(&mut buf, "SeDebugPrivilege");
    push_u32(&mut buf, 3);
    push_string(&mut buf, "SeShutdownPrivilege");
    push_u32(&mut buf, 0);
    push_string(&mut buf, "SeBackupPrivilege");
    push_u32(&mut buf, 2);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_privs_list(&mut parser).expect("unwrap");
    assert_eq!(
        output,
        "\n SeDebugPrivilege :: Enabled\n SeShutdownPrivilege :: Disabled\n SeBackupPrivilege :: Adjusted\n"
    );
}

// ── unit-handle tests ─────────────────────────────────────────────────────────

#[tokio::test]
async fn unit_handle_privs_list() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 1);
    push_string(&mut rest, "SeDebugPrivilege");
    push_u32(&mut rest, 3);
    let payload = unit_token_payload(DemonTokenCommand::PrivsGetOrList, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    let output = assert_unit_response(&msg, "Good", "List Privileges for current Token:");
    assert!(output.contains("SeDebugPrivilege :: Enabled"));
}

#[tokio::test]
async fn unit_handle_privs_get_success() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 0);
    push_u32(&mut rest, 1);
    push_string(&mut rest, "SeDebugPrivilege");
    let payload = unit_token_payload(DemonTokenCommand::PrivsGetOrList, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    assert_unit_response(&msg, "Good", "The privilege SeDebugPrivilege was successfully enabled");
}

#[tokio::test]
async fn unit_handle_privs_get_failure() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 0);
    push_u32(&mut rest, 0);
    push_string(&mut rest, "SeDebugPrivilege");
    let payload = unit_token_payload(DemonTokenCommand::PrivsGetOrList, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    assert_unit_response(&msg, "Error", "Failed to enable the SeDebugPrivilege privilege");
}

// ── truncated-payload error tests ─────────────────────────────────────────────

#[tokio::test]
async fn unit_handle_truncated_privs_get_or_list_payload() {
    let payload = unit_token_payload(DemonTokenCommand::PrivsGetOrList, &[]);
    let events = EventBus::default();
    let result = handle_token_callback(&events, UNIT_AGENT_ID, UNIT_REQUEST_ID, &payload).await;
    assert!(result.is_err(), "truncated PrivsGetOrList should fail");
}
