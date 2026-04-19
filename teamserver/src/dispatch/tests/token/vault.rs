//! Tests for token list (vault) subcommand, including format_token_list unit tests.

use super::*;

// ── integration tests ─────────────────────────────────────────────────────────

#[tokio::test]
async fn token_list_callback_formats_vault_table() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::List));
    add_u32(&mut payload, 0);
    add_u32(&mut payload, 0xAB);
    add_utf16(&mut payload, "LAB\\svc");
    add_u32(&mut payload, 4444);
    add_u32(&mut payload, 1);
    add_u32(&mut payload, 1);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 11, &payload).await?;

    let event = receiver.recv().await.ok_or("token list response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert!(message.info.output.contains("LAB\\svc"));
    assert!(message.info.output.contains("stolen"));
    assert!(message.info.output.contains("Yes"));
    Ok(())
}

#[tokio::test]
async fn token_list_callback_empty_vault() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::List));
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 12, &payload).await?;

    let event = receiver.recv().await.ok_or("token list empty response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert!(message.info.output.contains("token vault is empty"));
    Ok(())
}

#[tokio::test]
async fn token_list_multiple_types_formats_correctly() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::List));
    // Entry 0: stolen (type=1), impersonating
    add_u32(&mut payload, 0); // index
    add_u32(&mut payload, 0xAA); // handle
    add_utf16(&mut payload, "LAB\\stolen_user");
    add_u32(&mut payload, 1000); // pid
    add_u32(&mut payload, 1); // type = stolen
    add_u32(&mut payload, 1); // impersonating = Yes
    // Entry 1: make (local) (type=2), not impersonating
    add_u32(&mut payload, 1); // index
    add_u32(&mut payload, 0xBB); // handle
    add_utf16(&mut payload, "LAB\\local_user");
    add_u32(&mut payload, 2000); // pid
    add_u32(&mut payload, 2); // type = make (local)
    add_u32(&mut payload, 0); // impersonating = No
    // Entry 2: make (network) (type=3)
    add_u32(&mut payload, 2); // index
    add_u32(&mut payload, 0xCC); // handle
    add_utf16(&mut payload, "LAB\\net_user");
    add_u32(&mut payload, 3000); // pid
    add_u32(&mut payload, 3); // type = make (network)
    add_u32(&mut payload, 0); // impersonating = No
    // Entry 3: unknown type (type=99)
    add_u32(&mut payload, 3); // index
    add_u32(&mut payload, 0xDD); // handle
    add_utf16(&mut payload, "LAB\\unknown_user");
    add_u32(&mut payload, 4000); // pid
    add_u32(&mut payload, 99); // type = unknown
    add_u32(&mut payload, 0); // impersonating = No
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 56, &payload).await?;

    let event = receiver.recv().await.ok_or("token list multi response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Info"));
    let output = &message.info.output;
    assert!(output.contains("stolen"));
    assert!(output.contains("make (local)"));
    assert!(output.contains("make (network)"));
    assert!(output.contains("unknown"));
    assert!(output.contains("LAB\\stolen_user"));
    assert!(output.contains("LAB\\local_user"));
    assert!(output.contains("LAB\\net_user"));
    assert!(output.contains("LAB\\unknown_user"));
    Ok(())
}

#[tokio::test]
async fn token_list_callback_rejects_truncated_row() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    // Build a List payload with one complete row followed by a truncated second row.
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::List));
    // First complete row
    add_u32(&mut payload, 0); // index
    add_u32(&mut payload, 0xAB); // handle
    add_utf16(&mut payload, "LAB\\svc"); // domain_user
    add_u32(&mut payload, 4444); // pid
    add_u32(&mut payload, 1); // type
    add_u32(&mut payload, 1); // impersonating
    // Second row: truncated — only index, missing the rest
    add_u32(&mut payload, 1); // index only

    let err = dispatcher
        .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 30, &payload)
        .await
        .expect_err("truncated token list row must be rejected");
    assert!(
        matches!(
            err,
            CommandDispatchError::InvalidCallbackPayload { command_id, .. }
            if command_id == u32::from(DemonCommand::CommandToken)
        ),
        "expected InvalidCallbackPayload, got {err:?}"
    );
    // Verify no event was broadcast by checking recv times out.
    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "no event should be broadcast on parse failure"
    );
    Ok(())
}

// ── format_token_list unit tests ──────────────────────────────────────────────

#[test]
fn format_token_list_empty() {
    let buf = Vec::new();
    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_list(&mut parser).expect("unwrap");
    assert_eq!(output, "\nThe token vault is empty");
}

#[test]
fn format_token_list_stolen_impersonating() {
    let mut buf = Vec::new();
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 0x10);
    push_utf16(&mut buf, "CORP\\admin");
    push_u32(&mut buf, 1234);
    push_u32(&mut buf, 1);
    push_u32(&mut buf, 1);

    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_list(&mut parser).expect("unwrap");
    assert!(output.contains("stolen"), "expected 'stolen' in output: {output}");
    assert!(output.contains("Yes"), "expected 'Yes' for impersonating");
    assert!(output.contains("CORP\\admin"));
}

#[test]
fn format_token_list_make_local_not_impersonating() {
    let mut buf = Vec::new();
    push_u32(&mut buf, 1);
    push_u32(&mut buf, 0x20);
    push_utf16(&mut buf, "LOCAL\\user");
    push_u32(&mut buf, 5678);
    push_u32(&mut buf, 2);
    push_u32(&mut buf, 0);

    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_list(&mut parser).expect("unwrap");
    assert!(output.contains("make (local)"));
    assert!(output.contains("No"));
}

#[test]
fn format_token_list_make_network() {
    let mut buf = Vec::new();
    push_u32(&mut buf, 2);
    push_u32(&mut buf, 0x30);
    push_utf16(&mut buf, "NET\\svc");
    push_u32(&mut buf, 9999);
    push_u32(&mut buf, 3);
    push_u32(&mut buf, 0);

    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_list(&mut parser).expect("unwrap");
    assert!(output.contains("make (network)"));
}

#[test]
fn format_token_list_unknown_type() {
    let mut buf = Vec::new();
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 0x40);
    push_utf16(&mut buf, "X\\Y");
    push_u32(&mut buf, 42);
    push_u32(&mut buf, 99);
    push_u32(&mut buf, 0);

    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_list(&mut parser).expect("unwrap");
    assert!(output.contains("unknown"));
}

#[test]
fn format_token_list_column_expansion_with_long_domain_user() {
    let mut buf = Vec::new();
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 0x10);
    push_utf16(&mut buf, "A\\B");
    push_u32(&mut buf, 100);
    push_u32(&mut buf, 1);
    push_u32(&mut buf, 0);
    push_u32(&mut buf, 1);
    push_u32(&mut buf, 0x20);
    push_utf16(&mut buf, "VERYLONGDOMAIN\\administratoraccount");
    push_u32(&mut buf, 200);
    push_u32(&mut buf, 2);
    push_u32(&mut buf, 1);

    let mut parser = CallbackParser::new(&buf, 0);
    let output = format_token_list(&mut parser).expect("unwrap");

    assert!(output.contains("VERYLONGDOMAIN\\administratoraccount"));
    assert!(output.contains("A\\B"));

    let data_lines: Vec<&str> = output.lines().filter(|l| !l.is_empty()).skip(2).collect();
    assert_eq!(data_lines.len(), 2, "expected 2 data rows");
    assert_eq!(
        data_lines[0].len(),
        data_lines[1].len(),
        "data rows should have same width:\n  row0: '{}'\n  row1: '{}'",
        data_lines[0],
        data_lines[1]
    );
}

// ── unit-handle tests ─────────────────────────────────────────────────────────

#[tokio::test]
async fn unit_handle_list_empty_vault() {
    let payload = unit_token_payload(DemonTokenCommand::List, &[]);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    let output = assert_unit_response(&msg, "Info", "Token Vault:");
    assert!(output.contains("token vault is empty"), "output={output}");
}

#[tokio::test]
async fn unit_handle_list_with_entries() {
    let mut rest = Vec::new();
    push_u32(&mut rest, 0);
    push_u32(&mut rest, 0x10);
    push_utf16(&mut rest, "CORP\\admin");
    push_u32(&mut rest, 1234);
    push_u32(&mut rest, 1);
    push_u32(&mut rest, 1);
    let payload = unit_token_payload(DemonTokenCommand::List, &rest);

    let (result, msg) = unit_call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("broadcast");
    let output = assert_unit_response(&msg, "Info", "Token Vault:");
    assert!(output.contains("CORP\\admin"));
    assert!(output.contains("stolen"));
}
