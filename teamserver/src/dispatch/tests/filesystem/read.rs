//! Tests for filesystem read operations: getpwd and cat.

use super::*;

#[tokio::test]
async fn builtin_filesystem_getpwd_broadcasts_current_directory()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_000A, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::GetPwd));
    add_utf16(&mut payload, "C:\\Windows\\System32");
    dispatcher.dispatch(0xF500_000A, u32::from(DemonCommand::CommandFs), 0xAA, &payload).await?;

    let event = receiver.recv().await.ok_or("missing getpwd event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for getpwd");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String("Current directory: C:\\Windows\\System32".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_cat_success_broadcasts_content()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_000B, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let file_content = "Hello, world!\nLine two.";
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Cat));
    add_utf16(&mut payload, "C:\\flag.txt");
    add_u32(&mut payload, 1); // success = true
    add_bytes(&mut payload, file_content.as_bytes()); // read_string uses read_bytes
    dispatcher.dispatch(0xF500_000B, u32::from(DemonCommand::CommandFs), 0xAB, &payload).await?;

    let event = receiver.recv().await.ok_or("missing cat event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for cat");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String(format!("File content of C:\\flag.txt ({}):", file_content.len())))
    );
    assert_eq!(msg.info.extra.get("Type"), Some(&Value::String("Info".to_owned())));
    assert_eq!(msg.info.output, file_content);
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_cat_failure_broadcasts_error() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_000C, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Cat));
    add_utf16(&mut payload, "C:\\nonexistent.txt");
    add_u32(&mut payload, 0); // success = false
    add_bytes(&mut payload, b"error details");
    dispatcher.dispatch(0xF500_000C, u32::from(DemonCommand::CommandFs), 0xAC, &payload).await?;

    let event = receiver.recv().await.ok_or("missing cat failure event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for cat failure");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String("Failed to read file: C:\\nonexistent.txt".to_owned()))
    );
    assert_eq!(msg.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    // On failure, output should be empty (None maps to empty string)
    assert_eq!(msg.info.output, "");
    Ok(())
}
