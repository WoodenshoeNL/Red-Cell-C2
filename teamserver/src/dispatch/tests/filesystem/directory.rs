//! Tests for filesystem directory listing (dir command).

use super::*;

#[tokio::test]
async fn builtin_filesystem_dir_list_only_broadcasts_paths()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_0010, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Dir));
    add_u32(&mut payload, 0); // explorer = false
    add_u32(&mut payload, 1); // list_only = true
    add_utf16(&mut payload, "C:\\Temp\\*");
    add_u32(&mut payload, 1); // success = true
    // One directory entry with 2 files, 0 dirs
    add_utf16(&mut payload, "C:\\Temp\\");
    add_u32(&mut payload, 2); // file_count
    add_u32(&mut payload, 0); // dir_count
    // No total_size for list_only mode
    // Item 1
    add_utf16(&mut payload, "a.txt");
    // Item 2
    add_utf16(&mut payload, "b.log");

    dispatcher.dispatch(0xF500_0010, u32::from(DemonCommand::CommandFs), 0xB0, &payload).await?;

    let event = receiver.recv().await.ok_or("missing dir list event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for dir list_only");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String("Directory listing completed".to_owned()))
    );
    // In list_only mode, output is just path+name lines
    assert!(msg.info.output.contains("C:\\Temp\\a.txt"), "output should contain a.txt");
    assert!(msg.info.output.contains("C:\\Temp\\b.log"), "output should contain b.log");
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_dir_normal_mode_broadcasts_formatted_listing()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_0011, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Dir));
    add_u32(&mut payload, 0); // explorer = false
    add_u32(&mut payload, 0); // list_only = false
    add_utf16(&mut payload, "C:\\Data\\*");
    add_u32(&mut payload, 1); // success = true
    // Directory entry
    add_utf16(&mut payload, "C:\\Data\\");
    add_u32(&mut payload, 1); // file_count
    add_u32(&mut payload, 1); // dir_count
    add_u64(&mut payload, 2048); // total_size (present when not list_only)
    // Item 1: a directory
    add_utf16(&mut payload, "subdir");
    add_u32(&mut payload, 1); // is_dir = true
    add_u64(&mut payload, 0); // size (ignored for dirs)
    add_u32(&mut payload, 15); // day
    add_u32(&mut payload, 3); // month
    add_u32(&mut payload, 2026); // year
    add_u32(&mut payload, 30); // minute
    add_u32(&mut payload, 14); // hour
    // Item 2: a file
    add_utf16(&mut payload, "readme.md");
    add_u32(&mut payload, 0); // is_dir = false
    add_u64(&mut payload, 2048); // size
    add_u32(&mut payload, 15); // day
    add_u32(&mut payload, 3); // month
    add_u32(&mut payload, 2026); // year
    add_u32(&mut payload, 0); // minute
    add_u32(&mut payload, 9); // hour

    dispatcher.dispatch(0xF500_0011, u32::from(DemonCommand::CommandFs), 0xB1, &payload).await?;

    let event = receiver.recv().await.ok_or("missing dir normal event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for dir normal mode");
    };
    let output = &msg.info.output;
    assert!(output.contains("Directory of C:\\Data\\"), "should contain directory header");
    assert!(output.contains("<DIR>"), "should contain <DIR> marker for subdirectory");
    assert!(output.contains("subdir"), "should list subdir name");
    assert!(output.contains("readme.md"), "should list file name");
    assert!(output.contains("1 File(s)"), "should show file count");
    assert!(output.contains("1 Folder(s)"), "should show folder count");
    // Check date formatting: "15/03/2026  14:30"
    assert!(output.contains("15/03/2026"), "should contain formatted date");
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_dir_explorer_mode_broadcasts_base64_json()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_0012, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Dir));
    add_u32(&mut payload, 1); // explorer = true
    add_u32(&mut payload, 0); // list_only = false
    add_utf16(&mut payload, "C:\\Loot\\");
    add_u32(&mut payload, 1); // success = true
    // Directory entry
    add_utf16(&mut payload, "C:\\Loot\\");
    add_u32(&mut payload, 1); // file_count
    add_u32(&mut payload, 0); // dir_count
    add_u64(&mut payload, 512); // total_size
    // Item 1: a file
    add_utf16(&mut payload, "secret.key");
    add_u32(&mut payload, 0); // is_dir = false
    add_u64(&mut payload, 512); // size
    add_u32(&mut payload, 1); // day
    add_u32(&mut payload, 1); // month
    add_u32(&mut payload, 2026); // year
    add_u32(&mut payload, 0); // minute
    add_u32(&mut payload, 12); // hour

    dispatcher.dispatch(0xF500_0012, u32::from(DemonCommand::CommandFs), 0xB2, &payload).await?;

    let event = receiver.recv().await.ok_or("missing dir explorer event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for dir explorer");
    };
    assert_eq!(msg.info.extra.get("MiscType"), Some(&Value::String("FileExplorer".to_owned())));
    // MiscData should be base64-encoded JSON with Path and Files
    let misc_data = msg.info.extra.get("MiscData").expect("MiscData should exist");
    let Value::String(b64) = misc_data else {
        panic!("MiscData should be a string");
    };
    let decoded = BASE64_STANDARD.decode(b64)?;
    let json: Value = serde_json::from_slice(&decoded)?;
    assert_eq!(json["Path"], Value::String("C:\\Loot\\".to_owned()));
    let files = json["Files"].as_array().expect("Files should be an array");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["Name"], Value::String("secret.key".to_owned()));
    assert_eq!(files[0]["Type"], Value::String("".to_owned())); // file, not dir
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_dir_failure_broadcasts_not_found()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_0013, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    // Dir with success=false — no items follow
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Dir));
    add_u32(&mut payload, 0); // explorer = false
    add_u32(&mut payload, 0); // list_only = false
    add_utf16(&mut payload, "C:\\NoSuchDir\\*");
    add_u32(&mut payload, 0); // success = false

    dispatcher.dispatch(0xF500_0013, u32::from(DemonCommand::CommandFs), 0xB3, &payload).await?;

    let event = receiver.recv().await.ok_or("missing dir failure event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for dir failure");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String("No file or folder was found".to_owned()))
    );
    assert_eq!(msg.info.output, "No file or folder was found");
    Ok(())
}
