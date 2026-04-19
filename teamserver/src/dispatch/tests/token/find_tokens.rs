//! Tests for token find_tokens subcommand, including format_found_tokens unit tests.

use super::*;

// ── integration tests ─────────────────────────────────────────────────────────

#[tokio::test]
async fn token_find_tokens_callback_formats_table() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::FindTokens));
    add_u32(&mut payload, 1);
    add_u32(&mut payload, 1);
    add_utf16(&mut payload, "LAB\\admin");
    add_u32(&mut payload, 5678);
    add_u32(&mut payload, 0x10);
    add_u32(&mut payload, 0x3000);
    add_u32(&mut payload, 2);
    add_u32(&mut payload, 1);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 25, &payload).await?;

    let event = receiver.recv().await.ok_or("token find response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert!(message.info.output.contains("LAB\\admin"));
    assert!(message.info.output.contains("High"));
    assert!(message.info.output.contains("Primary"));
    assert!(message.info.output.contains("token steal"));
    Ok(())
}

#[tokio::test]
async fn token_find_tokens_callback_failure() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::FindTokens));
    add_u32(&mut payload, 0);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 26, &payload).await?;

    let event = receiver.recv().await.ok_or("token find failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("Failed to list existing tokens"));
    Ok(())
}

#[tokio::test]
async fn token_find_tokens_zero_count_returns_no_tokens() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::FindTokens));
    add_u32(&mut payload, 1); // success
    add_u32(&mut payload, 0); // num_tokens = 0
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 53, &payload).await?;

    let event = receiver.recv().await.ok_or("find tokens zero count response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Info"));
    assert!(message.info.output.contains("No tokens found"));
    Ok(())
}

#[tokio::test]
async fn token_find_tokens_impersonation_type_with_delegation()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::FindTokens));
    add_u32(&mut payload, 1); // success
    add_u32(&mut payload, 1); // num_tokens
    add_utf16(&mut payload, "CORP\\delegator");
    add_u32(&mut payload, 9999); // pid
    add_u32(&mut payload, 0x20); // handle
    add_u32(&mut payload, 0x2000); // integrity = Medium
    add_u32(&mut payload, 3); // impersonation = Delegation
    add_u32(&mut payload, 2); // token_type = Impersonation
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 54, &payload).await?;

    let event = receiver.recv().await.ok_or("find tokens impersonation response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Info"));
    let output = &message.info.output;
    assert!(output.contains("CORP\\delegator"));
    assert!(output.contains("Medium"));
    assert!(output.contains("Impersonation"));
    assert!(output.contains("Delegation"));
    // Delegation impersonation level means remote auth = Yes
    assert!(output.contains("Yes"));
    assert!(output.contains("token steal"));
    Ok(())
}

#[tokio::test]
async fn token_find_tokens_failure_emits_error_type() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::FindTokens));
    add_u32(&mut payload, 0); // failure
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 55, &payload).await?;

    let event = receiver.recv().await.ok_or("find tokens failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Failed to list existing tokens")
    );
    Ok(())
}

#[tokio::test]
async fn token_find_tokens_integrity_levels_formatted_correctly()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::FindTokens));
    add_u32(&mut payload, 1); // success
    add_u32(&mut payload, 4); // num_tokens
    // Token 1: Low integrity (0x0800 < LOW_RID 0x1000)
    add_utf16(&mut payload, "LOW\\user");
    add_u32(&mut payload, 100); // pid
    add_u32(&mut payload, 0x01); // handle
    add_u32(&mut payload, 0x0800); // integrity = Low
    add_u32(&mut payload, 0); // impersonation
    add_u32(&mut payload, 2); // Impersonation token
    // Token 2: Medium integrity (0x2000)
    add_utf16(&mut payload, "MED\\user");
    add_u32(&mut payload, 200); // pid
    add_u32(&mut payload, 0x02); // handle
    add_u32(&mut payload, 0x2000); // integrity = Medium
    add_u32(&mut payload, 1); // impersonation = Identification
    add_u32(&mut payload, 2); // Impersonation token
    // Token 3: High integrity (0x3000)
    add_utf16(&mut payload, "HIGH\\user");
    add_u32(&mut payload, 300); // pid
    add_u32(&mut payload, 0x03); // handle
    add_u32(&mut payload, 0x3000); // integrity = High
    add_u32(&mut payload, 2); // impersonation = Impersonation
    add_u32(&mut payload, 2); // Impersonation token
    // Token 4: System integrity (0x4000)
    add_utf16(&mut payload, "SYS\\user");
    add_u32(&mut payload, 400); // pid
    add_u32(&mut payload, 0x04); // handle
    add_u32(&mut payload, 0x4000); // integrity = System
    add_u32(&mut payload, 0); // impersonation = Anonymous
    add_u32(&mut payload, 2); // Impersonation token
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 57, &payload).await?;

    let event = receiver.recv().await.ok_or("find tokens integrity response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let output = &message.info.output;
    // Verify each integrity level is correctly mapped
    assert!(output.contains("Low"));
    assert!(output.contains("Medium"));
    assert!(output.contains("High"));
    assert!(output.contains("System"));
    // Verify impersonation level labels
    assert!(output.contains("Anonymous"));
    assert!(output.contains("Identification"));
    // "Impersonation" appears as both token type and impersonation level
    assert!(output.contains("Impersonation"));
    Ok(())
}

#[tokio::test]
async fn token_find_tokens_callback_rejects_truncated_row() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    // FindTokens with success=1, num_tokens=2 but only one complete token row,
    // the second row truncated after domain_user.
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::FindTokens));
    add_u32(&mut payload, 1); // success
    add_u32(&mut payload, 2); // num_tokens
    // First complete token entry
    add_utf16(&mut payload, "LAB\\admin"); // domain_user
    add_u32(&mut payload, 5678); // pid
    add_u32(&mut payload, 0x10); // handle
    add_u32(&mut payload, 0x3000); // integrity
    add_u32(&mut payload, 2); // impersonation level
    add_u32(&mut payload, 1); // token type
    // Second token: only domain_user, missing remaining fields
    add_utf16(&mut payload, "LAB\\guest");

    let err = dispatcher
        .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 32, &payload)
        .await
        .expect_err("truncated found-token row must be rejected");
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

// ── format_found_tokens unit tests — integrity level boundaries ───────────────

#[test]
fn format_found_tokens_integrity_0x0000_is_low() {
    let buf = build_found_token_payload(0x0000);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert_eq!(get_integrity_from_output(&output), "Low");
}

#[test]
fn format_found_tokens_integrity_0x1000_is_low() {
    let buf = build_found_token_payload(0x1000);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert_eq!(get_integrity_from_output(&output), "Low");
}

#[test]
fn format_found_tokens_integrity_0x1001_falls_through_to_low() {
    let buf = build_found_token_payload(0x1001);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert_eq!(get_integrity_from_output(&output), "Low");
}

#[test]
fn format_found_tokens_integrity_0x1fff_falls_through_to_low() {
    let buf = build_found_token_payload(0x1FFF);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert_eq!(get_integrity_from_output(&output), "Low");
}

#[test]
fn format_found_tokens_integrity_0x2000_is_medium() {
    let buf = build_found_token_payload(0x2000);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert_eq!(get_integrity_from_output(&output), "Medium");
}

#[test]
fn format_found_tokens_integrity_0x2fff_is_medium() {
    let buf = build_found_token_payload(0x2FFF);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert_eq!(get_integrity_from_output(&output), "Medium");
}

#[test]
fn format_found_tokens_integrity_0x3000_is_high() {
    let buf = build_found_token_payload(0x3000);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert_eq!(get_integrity_from_output(&output), "High");
}

#[test]
fn format_found_tokens_integrity_0x3fff_is_high() {
    let buf = build_found_token_payload(0x3FFF);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert_eq!(get_integrity_from_output(&output), "High");
}

#[test]
fn format_found_tokens_integrity_0x4000_is_system() {
    let buf = build_found_token_payload(0x4000);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert_eq!(get_integrity_from_output(&output), "System");
}

#[test]
fn format_found_tokens_zero_count() {
    let mut buf = Vec::new();
    push_u32(&mut buf, 0);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert_eq!(output, "\nNo tokens found");
}

#[test]
fn format_found_tokens_primary_token_type() {
    let mut buf = Vec::new();
    push_u32(&mut buf, 1);
    push_utf16(&mut buf, "NT AUTHORITY\\SYSTEM");
    push_u32(&mut buf, 4);
    push_u32(&mut buf, 0x200);
    push_u32(&mut buf, 0x4000);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 1);

    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert!(output.contains("Primary"), "expected 'Primary' in output: {output}");
    assert!(output.contains("N/A"), "expected 'N/A' impersonation for Primary");
}

#[test]
fn format_found_tokens_impersonation_levels() {
    let levels = [
        (0u32, "Anonymous"),
        (1, "Identification"),
        (2, "Impersonation"),
        (3, "Delegation"),
        (99, "Unknown"),
    ];
    for (imp_level, expected_label) in &levels {
        let mut buf = Vec::new();
        push_u32(&mut buf, 1);
        push_utf16(&mut buf, "CORP\\user");
        push_u32(&mut buf, 100);
        push_u32(&mut buf, 0x50);
        push_u32(&mut buf, 0x2000);
        push_u32(&mut buf, *imp_level);
        push_u32(&mut buf, 2);

        let mut parser = CallbackParser::new(&buf, 0);
        let output = format_found_tokens(&mut parser).expect("unwrap");
        assert!(
            output.contains(expected_label),
            "imp_level={imp_level}: expected '{expected_label}' in output: {output}"
        );
    }
}

#[test]
fn format_found_tokens_column_expansion_with_long_domain_user() {
    let mut buf = Vec::new();
    push_u32(&mut buf, 2);
    push_utf16(&mut buf, "X\\Y");
    push_u32(&mut buf, 10);
    push_u32(&mut buf, 0x50);
    push_u32(&mut buf, 0x2000);
    push_u32(&mut buf, 2);
    push_u32(&mut buf, 2);
    push_utf16(&mut buf, "LONGCORP\\very_long_username_here");
    push_u32(&mut buf, 20);
    push_u32(&mut buf, 0x60);
    push_u32(&mut buf, 0x3000);
    push_u32(&mut buf, 1);
    push_u32(&mut buf, 2);

    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");

    assert!(output.contains("LONGCORP\\very_long_username_here"));
    assert!(output.contains("X\\Y"));

    let table_lines: Vec<&str> =
        output.lines().filter(|l| !l.is_empty() && !l.starts_with("To impersonate")).collect();
    assert!(table_lines.len() >= 3);
    let expected_len = table_lines[0].len();
    for line in &table_lines {
        assert_eq!(
            line.len(),
            expected_len,
            "column misalignment in found_tokens:\n  expected len {expected_len}\n  got len {} for: '{line}'",
            line.len()
        );
    }
}

#[test]
fn format_found_tokens_integrity_0x0fff_is_low() {
    let buf = build_found_token_payload(0x0FFF);
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert_eq!(get_integrity_from_output(&output), "Low");
}

#[test]
fn format_found_tokens_unknown_token_type() {
    let mut buf = Vec::new();
    push_u32(&mut buf, 1);
    push_utf16(&mut buf, "DOM\\user");
    push_u32(&mut buf, 42);
    push_u32(&mut buf, 0x10);
    push_u32(&mut buf, 0x2000);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 99);

    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert!(output.contains("?"), "expected '?' for unknown token type: {output}");
    assert!(output.contains("Unknown"), "expected 'Unknown' impersonation for unknown type");
}

#[test]
fn format_found_tokens_truncates_when_num_tokens_exceeds_payload() {
    let mut buf = Vec::new();
    push_u32(&mut buf, 3);
    push_utf16(&mut buf, "CORP\\admin");
    push_u32(&mut buf, 1234);
    push_u32(&mut buf, 0x10);
    push_u32(&mut buf, 0x2000);
    push_u32(&mut buf, 2);
    push_u32(&mut buf, 2);

    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");

    assert!(output.contains("CORP\\admin"), "expected the single token in output: {output}");
    let data_rows: Vec<&str> = output.lines().filter(|l| l.contains("CORP\\admin")).collect();
    assert_eq!(
        data_rows.len(),
        1,
        "expected exactly 1 data row, got {}: {output}",
        data_rows.len()
    );
    assert!(!output.contains("No tokens found"));
}

#[test]
fn format_found_tokens_num_tokens_exceeds_payload_completely_empty() {
    let mut buf = Vec::new();
    push_u32(&mut buf, 5);

    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    assert_eq!(output, "\nNo tokens found");
}

#[test]
fn format_found_tokens_delegation_has_remote_auth_yes() {
    let mut buf = Vec::new();
    push_u32(&mut buf, 1);
    push_utf16(&mut buf, "CORP\\admin");
    push_u32(&mut buf, 500);
    push_u32(&mut buf, 0x60);
    push_u32(&mut buf, 0x3000);
    push_u32(&mut buf, 3);
    push_u32(&mut buf, 2);

    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_found_tokens(&mut parser).expect("unwrap");
    let yes_count = output.matches("Yes").count();
    assert!(yes_count >= 2, "expected at least 2 'Yes' (Local+Remote) for delegation: {output}");
}

// ── unit-handle tests ─────────────────────────────────────────────────────────

#[tokio::test]
async fn unit_handle_find_tokens_success() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 1);
    push_u32(&mut rest, 1);
    push_utf16(&mut rest, "CORP\\admin");
    push_u32(&mut rest, 500);
    push_u32(&mut rest, 0x60);
    push_u32(&mut rest, 0x3000);
    push_u32(&mut rest, 2);
    push_u32(&mut rest, 2);
    let payload = unit_token_payload(DemonTokenCommand::FindTokens, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    let output = assert_unit_response(&msg, "Info", "Tokens available:");
    assert!(output.contains("CORP\\admin"));
    assert!(output.contains("High"));
}

#[tokio::test]
async fn unit_handle_find_tokens_failure() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 0);
    let payload = unit_token_payload(DemonTokenCommand::FindTokens, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    assert_unit_response(&msg, "Error", "Failed to list existing tokens");
}

// ── truncated-payload error tests ─────────────────────────────────────────────

#[tokio::test]
async fn unit_handle_truncated_find_tokens_payload() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 1);
    let payload = unit_token_payload(DemonTokenCommand::FindTokens, &rest);
    let events = EventBus::default();
    let result = handle_token_callback(&events, UNIT_AGENT_ID, UNIT_REQUEST_ID, &payload).await;
    assert!(result.is_err(), "truncated FindTokens should fail");
}
