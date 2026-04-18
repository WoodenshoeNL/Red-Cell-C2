//! Tests for filesystem write operations: upload, cd, remove, mkdir, copy, move.

use super::*;

#[tokio::test]
async fn builtin_filesystem_upload_broadcasts_info() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_0001, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Upload));
    add_u32(&mut payload, 4096); // size
    add_utf16(&mut payload, "C:\\Temp\\payload.bin");
    dispatcher.dispatch(0xF500_0001, u32::from(DemonCommand::CommandFs), 0xA1, &payload).await?;

    let event = receiver.recv().await.ok_or("missing upload event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for upload");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String("Uploaded file: C:\\Temp\\payload.bin (4096 bytes)".to_owned()))
    );
    assert_eq!(msg.info.extra.get("Type"), Some(&Value::String("Info".to_owned())));
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_cd_broadcasts_changed_directory()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_0002, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Cd));
    add_utf16(&mut payload, "C:\\Users\\Admin\\Desktop");
    dispatcher.dispatch(0xF500_0002, u32::from(DemonCommand::CommandFs), 0xA2, &payload).await?;

    let event = receiver.recv().await.ok_or("missing cd event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for cd");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String("Changed directory: C:\\Users\\Admin\\Desktop".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_remove_file_broadcasts_info() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_0003, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    // Remove a file (is_dir = false = 0)
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Remove));
    add_u32(&mut payload, 0); // is_dir = false
    add_utf16(&mut payload, "C:\\Temp\\old.txt");
    dispatcher.dispatch(0xF500_0003, u32::from(DemonCommand::CommandFs), 0xA3, &payload).await?;

    let event = receiver.recv().await.ok_or("missing remove event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for remove");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String("Removed file: C:\\Temp\\old.txt".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_remove_directory_broadcasts_info()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_0004, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    // Remove a directory (is_dir = true = 1)
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Remove));
    add_u32(&mut payload, 1); // is_dir = true
    add_utf16(&mut payload, "C:\\Temp\\subdir");
    dispatcher.dispatch(0xF500_0004, u32::from(DemonCommand::CommandFs), 0xA4, &payload).await?;

    let event = receiver.recv().await.ok_or("missing remove dir event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for remove dir");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String("Removed directory: C:\\Temp\\subdir".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_mkdir_broadcasts_info() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_0005, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Mkdir));
    add_utf16(&mut payload, "C:\\Temp\\newdir");
    dispatcher.dispatch(0xF500_0005, u32::from(DemonCommand::CommandFs), 0xA5, &payload).await?;

    let event = receiver.recv().await.ok_or("missing mkdir event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for mkdir");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String("Created directory: C:\\Temp\\newdir".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_copy_success_broadcasts_good() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_0006, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Copy));
    add_u32(&mut payload, 1); // success = true
    add_utf16(&mut payload, "C:\\src\\file.txt");
    add_utf16(&mut payload, "C:\\dst\\file.txt");
    dispatcher.dispatch(0xF500_0006, u32::from(DemonCommand::CommandFs), 0xA6, &payload).await?;

    let event = receiver.recv().await.ok_or("missing copy event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for copy");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String(
            "Successfully copied file C:\\src\\file.txt to C:\\dst\\file.txt".to_owned()
        ))
    );
    assert_eq!(msg.info.extra.get("Type"), Some(&Value::String("Good".to_owned())));
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_copy_failure_broadcasts_error() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_0007, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Copy));
    add_u32(&mut payload, 0); // success = false
    add_utf16(&mut payload, "C:\\nope\\a.txt");
    add_utf16(&mut payload, "C:\\nope\\b.txt");
    dispatcher.dispatch(0xF500_0007, u32::from(DemonCommand::CommandFs), 0xA7, &payload).await?;

    let event = receiver.recv().await.ok_or("missing copy failure event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for copy failure");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String("Failed to copy file C:\\nope\\a.txt to C:\\nope\\b.txt".to_owned()))
    );
    assert_eq!(msg.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_move_success_broadcasts_good() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_0008, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Move));
    add_u32(&mut payload, 1); // success = true
    add_utf16(&mut payload, "C:\\old\\data.bin");
    add_utf16(&mut payload, "C:\\new\\data.bin");
    dispatcher.dispatch(0xF500_0008, u32::from(DemonCommand::CommandFs), 0xA8, &payload).await?;

    let event = receiver.recv().await.ok_or("missing move event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for move");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String(
            "Successfully moved file C:\\old\\data.bin to C:\\new\\data.bin".to_owned()
        ))
    );
    assert_eq!(msg.info.extra.get("Type"), Some(&Value::String("Good".to_owned())));
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_move_failure_broadcasts_error() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_0009, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Move));
    add_u32(&mut payload, 0); // success = false
    add_utf16(&mut payload, "C:\\locked\\x.dll");
    add_utf16(&mut payload, "C:\\dest\\x.dll");
    dispatcher.dispatch(0xF500_0009, u32::from(DemonCommand::CommandFs), 0xA9, &payload).await?;

    let event = receiver.recv().await.ok_or("missing move failure event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for move failure");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String("Failed to move file C:\\locked\\x.dll to C:\\dest\\x.dll".to_owned()))
    );
    assert_eq!(msg.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    Ok(())
}
