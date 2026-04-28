//! Builtin handler integration tests: process list/kill/modules/grep/memory,
//! inject DLL/shellcode/spawn DLL, exit, kill-date, demon-info, command-error.

use super::*;

#[tokio::test]
async fn builtin_process_list_handler_broadcasts_formatted_agent_response()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    registry.insert(sample_agent_info(0xDEAD_BEEF, test_key(0x10), test_iv(0x20))).await?;
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, 0);
    add_utf16(&mut payload, "explorer.exe");
    add_u32(&mut payload, 1337);
    add_u32(&mut payload, 0);
    add_u32(&mut payload, 512);
    add_u32(&mut payload, 1);
    add_u32(&mut payload, 17);
    add_utf16(&mut payload, "LAB\\operator");

    let response = dispatcher
        .dispatch(0xDEAD_BEEF, u32::from(DemonCommand::CommandProcList), 0x2A, &payload)
        .await?;
    assert_eq!(response, None);

    let event = receiver.recv().await.ok_or_else(|| "agent response event missing".to_owned())?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.demon_id, "DEADBEEF");
    assert_eq!(message.info.command_id, u32::from(DemonCommand::CommandProcList).to_string());
    assert!(message.info.output.contains("explorer.exe"));
    assert_eq!(message.info.extra.get("Message"), Some(&Value::String("Process List:".to_owned())));
    let rows = message
        .info
        .extra
        .get("ProcessListRows")
        .and_then(Value::as_array)
        .ok_or_else(|| "structured process rows missing".to_owned())?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("PID"), Some(&Value::from(1337)));
    assert_eq!(rows[0].get("Name"), Some(&Value::String("explorer.exe".to_owned())));
    Ok(())
}

#[tokio::test]
async fn builtin_process_kill_and_token_handlers_broadcast_agent_responses()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    registry.insert(sample_agent_info(0xAABB_CCDD, test_key(0x21), test_iv(0x31))).await?;
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let kill_payload = [
        u32::from(DemonProcessCommand::Kill).to_le_bytes(),
        1_u32.to_le_bytes(),
        4040_u32.to_le_bytes(),
    ]
    .concat();
    dispatcher
        .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandProc), 7, &kill_payload)
        .await?;

    let event = receiver.recv().await.ok_or_else(|| "kill response missing".to_owned())?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Successfully killed process: 4040".to_owned()))
    );

    let token_payload =
        [u32::from(DemonTokenCommand::Impersonate).to_le_bytes(), 1_u32.to_le_bytes()].concat();
    let mut token_payload = token_payload;
    add_bytes(&mut token_payload, b"LAB\\svc");
    dispatcher
        .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 8, &token_payload)
        .await?;

    let event = receiver.recv().await.ok_or_else(|| "token response missing".to_owned())?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Successfully impersonated LAB\\svc".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn builtin_shellcode_handler_broadcasts_agent_response()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    registry.insert(sample_agent_info(0x0102_0304, test_key(0x55), test_iv(0x66))).await?;
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    dispatcher
        .dispatch(
            0x0102_0304,
            u32::from(DemonCommand::CommandInjectShellcode),
            9,
            &u32::from(DemonInjectError::ProcessArchMismatch).to_le_bytes(),
        )
        .await?;

    let event = receiver.recv().await.ok_or_else(|| "shellcode response missing".to_owned())?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Process architecture mismatch".to_owned()))
    );
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    Ok(())
}

#[tokio::test]
async fn builtin_process_modules_handler_broadcasts_module_list()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    registry.insert(sample_agent_info(0xAABB_CCDD, test_key(0x21), test_iv(0x31))).await?;
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonProcessCommand::Modules));
    add_u32(&mut payload, 1234);
    add_bytes(&mut payload, b"ntdll.dll");
    add_u64(&mut payload, 0x7FFA_0000_0000);
    add_bytes(&mut payload, b"kernel32.dll");
    add_u64(&mut payload, 0x7FFA_1000_0000);

    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandProc), 10, &payload).await?;

    let event = receiver.recv().await.ok_or_else(|| "modules response missing".to_owned())?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Process Modules (PID: 1234):".to_owned()))
    );
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Info".to_owned())));
    let rows = message
        .info
        .extra
        .get("ModuleRows")
        .and_then(Value::as_array)
        .ok_or_else(|| "structured module rows missing".to_owned())?;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get("Name"), Some(&Value::String("ntdll.dll".to_owned())));
    assert_eq!(rows[0].get("Base"), Some(&Value::String("0x00007FFA00000000".to_owned())));
    assert_eq!(rows[1].get("Name"), Some(&Value::String("kernel32.dll".to_owned())));
    assert!(message.info.output.contains("ntdll.dll"));
    assert!(message.info.output.contains("kernel32.dll"));
    Ok(())
}

#[tokio::test]
async fn builtin_process_grep_handler_broadcasts_matching_processes()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    registry.insert(sample_agent_info(0x1122_3344, test_key(0x22), test_iv(0x32))).await?;
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonProcessCommand::Grep));
    add_utf16(&mut payload, "svchost.exe");
    add_u32(&mut payload, 800);
    add_u32(&mut payload, 4);
    add_bytes(&mut payload, b"NT AUTHORITY\\SYSTEM");
    add_u32(&mut payload, 64);

    dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandProc), 11, &payload).await?;

    let event = receiver.recv().await.ok_or_else(|| "grep response missing".to_owned())?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Message"), Some(&Value::String("Process Grep:".to_owned())));
    let rows = message
        .info
        .extra
        .get("GrepRows")
        .and_then(Value::as_array)
        .ok_or_else(|| "structured grep rows missing".to_owned())?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("Name"), Some(&Value::String("svchost.exe".to_owned())));
    assert_eq!(rows[0].get("PID"), Some(&Value::from(800)));
    assert_eq!(rows[0].get("PPID"), Some(&Value::from(4)));
    assert_eq!(rows[0].get("Arch"), Some(&Value::String("x64".to_owned())));
    assert!(message.info.output.contains("svchost.exe"));
    Ok(())
}

#[tokio::test]
async fn builtin_process_memory_handler_broadcasts_memory_regions()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    registry.insert(sample_agent_info(0xDEAD_BEEF, test_key(0x10), test_iv(0x20))).await?;
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonProcessCommand::Memory));
    add_u32(&mut payload, 5678);
    add_u32(&mut payload, 0x40); // PAGE_EXECUTE_READWRITE
    add_u64(&mut payload, 0x0000_0140_0000_0000);
    add_u32(&mut payload, 0x1000);
    add_u32(&mut payload, 0x40); // PAGE_EXECUTE_READWRITE
    add_u32(&mut payload, 0x1000); // MEM_COMMIT
    add_u32(&mut payload, 0x1000000); // MEM_IMAGE

    dispatcher.dispatch(0xDEAD_BEEF, u32::from(DemonCommand::CommandProc), 12, &payload).await?;

    let event = receiver.recv().await.ok_or_else(|| "memory response missing".to_owned())?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert!(
        message
            .info
            .extra
            .get("Message")
            .and_then(Value::as_str)
            .is_some_and(|m| m.contains("PID: 5678"))
    );
    let rows = message
        .info
        .extra
        .get("MemoryRows")
        .and_then(Value::as_array)
        .ok_or_else(|| "structured memory rows missing".to_owned())?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("Base"), Some(&Value::String("0x0000014000000000".to_owned())));
    assert_eq!(rows[0].get("Size"), Some(&Value::String("0x1000".to_owned())));
    assert_eq!(rows[0].get("Protect"), Some(&Value::String("PAGE_EXECUTE_READWRITE".to_owned())));
    assert_eq!(rows[0].get("State"), Some(&Value::String("MEM_COMMIT".to_owned())));
    assert_eq!(rows[0].get("Type"), Some(&Value::String("MEM_IMAGE".to_owned())));
    assert!(message.info.output.contains("PAGE_EXECUTE_READWRITE"));
    Ok(())
}

#[tokio::test]
async fn builtin_process_modules_handler_handles_empty_module_list()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    registry.insert(sample_agent_info(0xCAFE_BABE, test_key(0x23), test_iv(0x33))).await?;
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonProcessCommand::Modules));
    add_u32(&mut payload, 9999);

    dispatcher.dispatch(0xCAFE_BABE, u32::from(DemonCommand::CommandProc), 13, &payload).await?;

    let event = receiver.recv().await.ok_or_else(|| "empty modules response missing".to_owned())?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let rows = message
        .info
        .extra
        .get("ModuleRows")
        .and_then(Value::as_array)
        .ok_or_else(|| "module rows should be present even if empty".to_owned())?;
    assert!(rows.is_empty());
    Ok(())
}

#[tokio::test]
async fn builtin_inject_dll_handler_broadcasts_success() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    registry.insert(sample_agent_info(0xBEEF_0001, test_key(0x71), test_iv(0x81))).await?;
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    dispatcher
        .dispatch(
            0xBEEF_0001,
            u32::from(DemonCommand::CommandInjectDll),
            20,
            &u32::from(DemonInjectError::Success).to_le_bytes(),
        )
        .await?;

    let event = receiver.recv().await.ok_or("inject dll response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Successfully injected DLL into remote process".to_owned()))
    );
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Good".to_owned())));
    Ok(())
}

#[tokio::test]
async fn builtin_inject_dll_handler_broadcasts_error() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    registry.insert(sample_agent_info(0xBEEF_0002, test_key(0x72), test_iv(0x82))).await?;
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    dispatcher
        .dispatch(
            0xBEEF_0002,
            u32::from(DemonCommand::CommandInjectDll),
            21,
            &u32::from(DemonInjectError::Failed).to_le_bytes(),
        )
        .await?;

    let event = receiver.recv().await.ok_or("inject dll error missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Failed to inject DLL into remote process".to_owned()))
    );
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    Ok(())
}

#[tokio::test]
async fn builtin_inject_dll_handler_broadcasts_arch_mismatch()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    registry.insert(sample_agent_info(0xBEEF_0003, test_key(0x73), test_iv(0x83))).await?;
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    dispatcher
        .dispatch(
            0xBEEF_0003,
            u32::from(DemonCommand::CommandInjectDll),
            22,
            &u32::from(DemonInjectError::ProcessArchMismatch).to_le_bytes(),
        )
        .await?;

    let event = receiver.recv().await.ok_or("inject dll arch mismatch missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("DLL injection failed: process architecture mismatch".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn builtin_spawn_dll_handler_broadcasts_success() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    registry.insert(sample_agent_info(0xBEEF_0010, test_key(0x74), test_iv(0x84))).await?;
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    dispatcher
        .dispatch(
            0xBEEF_0010,
            u32::from(DemonCommand::CommandSpawnDll),
            30,
            &u32::from(DemonInjectError::Success).to_le_bytes(),
        )
        .await?;

    let event = receiver.recv().await.ok_or("spawn dll response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Successfully spawned DLL in new process".to_owned()))
    );
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Good".to_owned())));
    Ok(())
}

#[tokio::test]
async fn builtin_spawn_dll_handler_broadcasts_error() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    registry.insert(sample_agent_info(0xBEEF_0011, test_key(0x75), test_iv(0x85))).await?;
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    dispatcher
        .dispatch(
            0xBEEF_0011,
            u32::from(DemonCommand::CommandSpawnDll),
            31,
            &u32::from(DemonInjectError::Failed).to_le_bytes(),
        )
        .await?;

    let event = receiver.recv().await.ok_or("spawn dll error missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Failed to spawn DLL in new process".to_owned()))
    );
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    Ok(())
}

#[tokio::test]
async fn builtin_exit_handler_marks_agent_dead_and_broadcasts_events()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    registry.insert(sample_agent_info(0xAABB_CCDD, test_key(0x41), test_iv(0x24))).await?;
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events,
        database,
        sockets.clone(),
        None,
    );
    sockets.add_socks_server(0xAABB_CCDD, "0").await?;

    dispatcher
        .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandExit), 40, &1_u32.to_le_bytes())
        .await?;

    let event = receiver.recv().await.ok_or("agent update missing")?;
    let OperatorMessage::AgentUpdate(message) = event else {
        panic!("expected agent update event");
    };
    assert_eq!(message.info.agent_id, "AABBCCDD");
    assert_eq!(message.info.marked, "Dead");

    let event = receiver.recv().await.ok_or("agent response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(
            &Value::String("Agent has been tasked to cleanup and exit thread. cya...".to_owned(),)
        )
    );

    let agent = registry.get(0xAABB_CCDD).await.ok_or("agent should remain tracked")?;
    assert!(!agent.active);
    assert_eq!(sockets.list_socks_servers(0xAABB_CCDD).await, "No active SOCKS5 servers");
    Ok(())
}

#[tokio::test]
async fn builtin_exit_handler_process_exit_broadcasts_process_message()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    registry.insert(sample_agent_info(0xBBCC_DD01, test_key(0x51), test_iv(0x34))).await?;
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets, None);

    dispatcher
        .dispatch(0xBBCC_DD01, u32::from(DemonCommand::CommandExit), 42, &2_u32.to_le_bytes())
        .await?;

    // First event: AgentUpdate marking dead.
    let event = receiver.recv().await.ok_or("agent update missing")?;
    let OperatorMessage::AgentUpdate(message) = event else {
        panic!("expected agent update event");
    };
    assert_eq!(message.info.agent_id, "BBCCDD01");
    assert_eq!(message.info.marked, "Dead");

    // Second event: AgentResponse with the process-exit message.
    let event = receiver.recv().await.ok_or("agent response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String(
            "Agent has been tasked to cleanup and exit process. cya...".to_owned(),
        ))
    );

    let agent = registry.get(0xBBCC_DD01).await.ok_or("agent should remain tracked")?;
    assert!(!agent.active);
    Ok(())
}

#[tokio::test]
async fn builtin_exit_handler_unknown_method_broadcasts_generic_message()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    registry.insert(sample_agent_info(0xBBCC_DD02, test_key(0x52), test_iv(0x35))).await?;
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets, None);

    dispatcher
        .dispatch(0xBBCC_DD02, u32::from(DemonCommand::CommandExit), 43, &0x99_u32.to_le_bytes())
        .await?;

    // First event: AgentUpdate marking dead.
    let event = receiver.recv().await.ok_or("agent update missing")?;
    let OperatorMessage::AgentUpdate(message) = event else {
        panic!("expected agent update event");
    };
    assert_eq!(message.info.agent_id, "BBCCDD02");
    assert_eq!(message.info.marked, "Dead");

    // Second event: AgentResponse with the generic fallback message.
    let event = receiver.recv().await.ok_or("agent response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Message"), Some(&Value::String("Agent exited".to_owned())));

    let agent = registry.get(0xBBCC_DD02).await.ok_or("agent should remain tracked")?;
    assert!(!agent.active);
    Ok(())
}

#[tokio::test]
async fn builtin_kill_date_handler_marks_agent_dead_and_broadcasts_response()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    registry.insert(sample_agent_info(0x1020_3040, test_key(0x42), test_iv(0x25))).await?;
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events,
        database,
        sockets.clone(),
        None,
    );
    sockets.add_socks_server(0x1020_3040, "0").await?;

    dispatcher.dispatch(0x1020_3040, u32::from(DemonCommand::CommandKillDate), 41, &[]).await?;

    let _ = receiver.recv().await.ok_or("agent update missing")?;
    let event = receiver.recv().await.ok_or("agent response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String(
            "Agent has reached its kill date, tasked to cleanup and exit thread. cya...".to_owned(),
        ))
    );
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Good".to_owned())));
    assert_eq!(sockets.list_socks_servers(0x1020_3040).await, "No active SOCKS5 servers");
    Ok(())
}

#[tokio::test]
async fn builtin_demon_info_handler_formats_memory_and_process_messages()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonInfoClass::MemAlloc));
    add_u64(&mut payload, 0x1234_5000);
    add_u32(&mut payload, 4096);
    add_u32(&mut payload, 0x40);
    dispatcher.dispatch(0xDEAD_BEEF, u32::from(DemonCommand::DemonInfo), 42, &payload).await?;

    let event = receiver.recv().await.ok_or("mem alloc response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Info".to_owned())));
    assert!(
        message
            .info
            .extra
            .get("Message")
            .and_then(Value::as_str)
            .is_some_and(|value| value.contains("Memory Allocated"))
    );
    assert!(
        message
            .info
            .extra
            .get("Message")
            .and_then(Value::as_str)
            .is_some_and(|value| value.contains("PAGE_EXECUTE_READWRITE"))
    );

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonInfoClass::ProcCreate));
    add_utf16(&mut payload, "C:\\Windows\\System32\\cmd.exe");
    add_u32(&mut payload, 777);
    add_u32(&mut payload, 1);
    add_u32(&mut payload, 1);
    add_u32(&mut payload, 1);
    dispatcher.dispatch(0xDEAD_BEEF, u32::from(DemonCommand::DemonInfo), 43, &payload).await?;

    let event = receiver.recv().await.ok_or("proc create response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert!(message.info.extra.get("Message").and_then(Value::as_str).is_some_and(|value| {
        value.contains("Process started: Path:[C:\\Windows\\System32\\cmd.exe]")
    }));
    Ok(())
}

#[tokio::test]
async fn builtin_command_error_handler_broadcasts_win32_and_token_messages()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonCallbackError::Win32));
    add_u32(&mut payload, 2);
    dispatcher.dispatch(0xCAFE_BABE, u32::from(DemonCommand::CommandError), 44, &payload).await?;

    let event = receiver.recv().await.ok_or("win32 error response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Win32 Error: ERROR_FILE_NOT_FOUND [2]".to_owned()))
    );
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonCallbackError::Token));
    add_u32(&mut payload, 1);
    dispatcher.dispatch(0xCAFE_BABE, u32::from(DemonCommand::CommandError), 45, &payload).await?;

    let event = receiver.recv().await.ok_or("token error response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("No tokens inside the token vault".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn command_error_handler_win32_unknown_code_and_token_non_0x1_status()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    // Case 1: Win32 with an unknown error code (no name lookup hit)
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonCallbackError::Win32));
    add_u32(&mut payload, 9999);
    dispatcher.dispatch(0xCAFE_BABE, u32::from(DemonCommand::CommandError), 50, &payload).await?;

    let event = receiver.recv().await.ok_or("win32 unknown code response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Win32 Error: [9999]".to_owned()))
    );
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));

    // Case 2: Token with status != 0x1
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonCallbackError::Token));
    add_u32(&mut payload, 0x5);
    dispatcher.dispatch(0xCAFE_BABE, u32::from(DemonCommand::CommandError), 51, &payload).await?;

    let event = receiver.recv().await.ok_or("token non-0x1 response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Token operation failed with status 0x5".to_owned()))
    );
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));

    Ok(())
}

#[tokio::test]
async fn command_error_handler_coffee_and_unknown_class_broadcast_nothing()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    registry.insert(sample_agent_info(0xCAFE_BABE, test_key(0x77), test_iv(0x88))).await?;
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    // Case 3: Coffee — should return Ok(None) with no broadcast
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonCallbackError::Coffee));
    dispatcher.dispatch(0xCAFE_BABE, u32::from(DemonCommand::CommandError), 52, &payload).await?;

    let result = timeout(Duration::from_millis(50), receiver.recv()).await;
    assert!(result.is_err(), "Coffee error class should not broadcast any event");

    // Case 4: Unknown error class (0xFF) — `Ok(None)` for gameplay; retained TeamserverLog for server-tail.
    let mut payload = Vec::new();
    add_u32(&mut payload, 0xFF_u32);
    dispatcher.dispatch(0xCAFE_BABE, u32::from(DemonCommand::CommandError), 53, &payload).await?;

    let first = timeout(Duration::from_millis(50), receiver.recv()).await;
    match first {
        Ok(Some(OperatorMessage::TeamserverLog(_))) => {}
        Ok(None) => panic!("event subscription closed before unknown-class TeamserverLog"),
        Err(_) => panic!("unknown CommandError class should retain a TeamserverLog line"),
        Ok(Some(other)) => panic!("expected TeamserverLog for unknown error class, got {other:?}"),
    }

    let result = timeout(Duration::from_millis(50), receiver.recv()).await;
    assert!(result.is_err(), "unknown error class must not broadcast a second gameplay event");

    Ok(())
}
