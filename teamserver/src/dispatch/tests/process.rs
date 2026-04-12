//! Tests for process, job, inject, exit, and related dispatch command handlers.

use super::common::*;

use super::super::{CommandDispatchError, CommandDispatcher};
use crate::{AgentRegistry, Database, EventBus, SocketRelayManager, TeamserverError};
use red_cell_common::demon::{
    DemonCallbackError, DemonCommand, DemonInfoClass, DemonInjectError, DemonJobCommand,
    DemonProcessCommand, DemonTokenCommand,
};
use red_cell_common::operator::OperatorMessage;
use serde_json::Value;
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn builtin_process_list_handler_broadcasts_formatted_agent_response()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
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

    // Case 4: Unknown error class (0xFF) — should also return Ok(None) with no broadcast
    let mut payload = Vec::new();
    add_u32(&mut payload, 0xFF_u32);
    dispatcher.dispatch(0xCAFE_BABE, u32::from(DemonCommand::CommandError), 53, &payload).await?;

    let result = timeout(Duration::from_millis(50), receiver.recv()).await;
    assert!(result.is_err(), "Unknown error class should not broadcast any event");

    Ok(())
}

#[tokio::test]
async fn builtin_job_and_package_dropped_handlers_broadcast_agent_responses()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xAABB_CCDD, test_key(0x21), test_iv(0x43));
    registry.insert(agent).await?;

    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events.clone(), database, sockets, None);
    let mut receiver = events.subscribe();

    let mut job_payload = Vec::new();
    add_u32(&mut job_payload, u32::from(DemonJobCommand::Resume));
    add_u32(&mut job_payload, 7);
    add_u32(&mut job_payload, 1);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandJob), 30, &job_payload).await?;

    let event = receiver.recv().await.ok_or("job response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Successfully resumed job 7".to_owned()))
    );

    let mut dropped_payload = Vec::new();
    add_u32(&mut dropped_payload, 8192);
    add_u32(&mut dropped_payload, 4096);
    dispatcher
        .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandPackageDropped), 31, &dropped_payload)
        .await?;

    let event = receiver.recv().await.ok_or("package dropped response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String(
            "A package was discarded by demon for being larger than PIPE_BUFFER_MAX (8192 > 4096)"
                .to_owned(),
        ))
    );
    Ok(())
}

#[tokio::test]
async fn handle_job_list_with_entries_broadcasts_formatted_table()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xAABB_CCDD, test_key(0x21), test_iv(0x43));
    registry.insert(agent).await?;

    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events.clone(), database, sockets, None);
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonJobCommand::List));
    // Entry 1: job_id=10, type=Thread(1), state=Running(1)
    add_u32(&mut payload, 10);
    add_u32(&mut payload, 1);
    add_u32(&mut payload, 1);
    // Entry 2: job_id=42, type=Process(2), state=Suspended(2)
    add_u32(&mut payload, 42);
    add_u32(&mut payload, 2);
    add_u32(&mut payload, 2);
    // Entry 3: job_id=99, type=Track Process(3), state=Dead(3)
    add_u32(&mut payload, 99);
    add_u32(&mut payload, 3);
    add_u32(&mut payload, 3);

    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandJob), 40, &payload).await?;

    let event = receiver.recv().await.ok_or("job list response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Message"), Some(&Value::String("Job list:".to_owned())));
    let output = &message.info.output;
    assert!(output.contains("Job ID"), "table header should contain Job ID column");
    assert!(output.contains("Type"), "table header should contain Type column");
    assert!(output.contains("State"), "table header should contain State column");
    assert!(output.contains("10"), "output should contain job_id 10");
    assert!(output.contains("Thread"), "output should contain Thread type");
    assert!(output.contains("Running"), "output should contain Running state");
    assert!(output.contains("42"), "output should contain job_id 42");
    assert!(output.contains("Process"), "output should contain Process type");
    assert!(output.contains("Suspended"), "output should contain Suspended state");
    assert!(output.contains("99"), "output should contain job_id 99");
    assert!(output.contains("Track Process"), "output should contain Track Process type");
    assert!(output.contains("Dead"), "output should contain Dead state");
    Ok(())
}

#[tokio::test]
async fn handle_job_list_with_zero_rows_still_broadcasts_header()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xAABB_CCDD, test_key(0x21), test_iv(0x43));
    registry.insert(agent).await?;

    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events.clone(), database, sockets, None);
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonJobCommand::List));
    // No job entries follow

    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandJob), 41, &payload).await?;

    let event = receiver.recv().await.ok_or("job list empty response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let output = &message.info.output;
    assert!(output.contains("Job ID"), "header should be present even with zero rows");
    assert!(output.contains("Type"), "header should contain Type column");
    assert!(output.contains("State"), "header should contain State column");
    Ok(())
}

#[tokio::test]
async fn handle_job_list_unknown_type_and_state_shows_unknown_label()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xAABB_CCDD, test_key(0x21), test_iv(0x43));
    registry.insert(agent).await?;

    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events.clone(), database, sockets, None);
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonJobCommand::List));
    // Entry with out-of-range type=99 and state=0 → both should render as "Unknown"
    add_u32(&mut payload, 7);
    add_u32(&mut payload, 99);
    add_u32(&mut payload, 0);

    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandJob), 42, &payload).await?;

    let event = receiver.recv().await.ok_or("job list response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let output = &message.info.output;
    assert!(output.contains("7"), "output should contain job_id 7");
    // "Unknown" must appear at least twice: once for type, once for state
    let unknown_count = output.matches("Unknown").count();
    assert!(
        unknown_count >= 2,
        "expected at least 2 occurrences of 'Unknown' (type and state), found {unknown_count} in: {output}"
    );
    Ok(())
}

#[tokio::test]
async fn handle_job_list_truncated_mid_row_returns_invalid_payload()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xAABB_CCDD, test_key(0x21), test_iv(0x43));
    registry.insert(agent).await?;

    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events.clone(), database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonJobCommand::List));
    // One complete row: job_id=10, type=1, state=1
    add_u32(&mut payload, 10);
    add_u32(&mut payload, 1);
    add_u32(&mut payload, 1);
    // Partial row: only job_id present, missing type and state
    add_u32(&mut payload, 20);

    let result =
        dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandJob), 42, &payload).await;

    assert!(result.is_err(), "truncated mid-row payload should be rejected");
    let err = result.expect_err("truncated mid-row payload must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got: {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn handle_job_suspend_success_and_failure_broadcasts_correct_messages()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xAABB_CCDD, test_key(0x21), test_iv(0x43));
    registry.insert(agent).await?;

    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events.clone(), database, sockets, None);
    let mut receiver = events.subscribe();

    // Suspend success
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonJobCommand::Suspend));
    add_u32(&mut payload, 5);
    add_u32(&mut payload, 1); // success=true
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandJob), 42, &payload).await?;

    let event = receiver.recv().await.ok_or("suspend success response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Successfully suspended job 5".to_owned()))
    );
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Good".to_owned())));

    // Suspend failure
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonJobCommand::Suspend));
    add_u32(&mut payload, 9);
    add_u32(&mut payload, 0); // success=false
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandJob), 43, &payload).await?;

    let event = receiver.recv().await.ok_or("suspend failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Failed to suspend job 9".to_owned()))
    );
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    Ok(())
}

#[tokio::test]
async fn handle_job_killremove_success_and_failure_broadcasts_correct_messages()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xAABB_CCDD, test_key(0x21), test_iv(0x43));
    registry.insert(agent).await?;

    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events.clone(), database, sockets, None);
    let mut receiver = events.subscribe();

    // KillRemove success
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonJobCommand::KillRemove));
    add_u32(&mut payload, 3);
    add_u32(&mut payload, 1); // success=true
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandJob), 44, &payload).await?;

    let event = receiver.recv().await.ok_or("killremove success response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Successfully killed and removed job 3".to_owned()))
    );
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Good".to_owned())));

    // KillRemove failure
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonJobCommand::KillRemove));
    add_u32(&mut payload, 11);
    add_u32(&mut payload, 0); // success=false
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandJob), 45, &payload).await?;

    let event = receiver.recv().await.ok_or("killremove failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Failed to kill job 11".to_owned()))
    );
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    Ok(())
}

#[tokio::test]
async fn handle_job_died_broadcasts_nothing() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonJobCommand::Died));
    dispatcher.dispatch(0xCAFE_BABE, u32::from(DemonCommand::CommandJob), 46, &payload).await?;

    let result = timeout(Duration::from_millis(50), receiver.recv()).await;
    assert!(result.is_err(), "Died subcommand should not broadcast any event");
    Ok(())
}

#[tokio::test]
async fn handle_job_unknown_subcommand_returns_invalid_callback_payload()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, 0xFF_u32); // invalid subcommand
    let result =
        dispatcher.dispatch(0xCAFE_BABE, u32::from(DemonCommand::CommandJob), 47, &payload).await;

    match result {
        Err(CommandDispatchError::InvalidCallbackPayload { command_id, .. }) => {
            assert_eq!(command_id, u32::from(DemonCommand::CommandJob));
        }
        other => panic!("expected InvalidCallbackPayload, got {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn builtin_sleep_ppid_and_assembly_handlers_update_state_and_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xCAFEBABE, test_key(0x66), test_iv(0x77));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    let mut sleep_payload = Vec::new();
    add_u32(&mut sleep_payload, 60);
    add_u32(&mut sleep_payload, 15);
    dispatcher
        .dispatch(0xCAFEBABE, u32::from(DemonCommand::CommandSleep), 37, &sleep_payload)
        .await?;

    let event = receiver.recv().await.ok_or("sleep agent update missing")?;
    let OperatorMessage::AgentUpdate(_) = event else {
        panic!("expected agent update event");
    };
    let event = receiver.recv().await.ok_or("sleep response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Set sleep interval to 60 seconds with 15% jitter".to_owned()))
    );
    let updated = registry.get(0xCAFEBABE).await.ok_or("missing updated agent")?;
    assert_eq!(updated.sleep_delay, 60);
    assert_eq!(updated.sleep_jitter, 15);

    let mut ppid_payload = Vec::new();
    add_u32(&mut ppid_payload, 4242);
    dispatcher
        .dispatch(0xCAFEBABE, u32::from(DemonCommand::CommandProcPpidSpoof), 38, &ppid_payload)
        .await?;

    let event = receiver.recv().await.ok_or("ppid agent update missing")?;
    let OperatorMessage::AgentUpdate(_) = event else {
        panic!("expected agent update event");
    };
    let event = receiver.recv().await.ok_or("ppid response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Changed parent pid to spoof: 4242".to_owned()))
    );
    assert_eq!(registry.get(0xCAFEBABE).await.ok_or("missing updated agent")?.process_ppid, 4242);

    let mut assembly_payload = Vec::new();
    add_u32(&mut assembly_payload, 0x2);
    add_utf16(&mut assembly_payload, "v4.0.30319");
    dispatcher
        .dispatch(
            0xCAFEBABE,
            u32::from(DemonCommand::CommandAssemblyInlineExecute),
            39,
            &assembly_payload,
        )
        .await?;

    let event = receiver.recv().await.ok_or("assembly response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Using CLR Version: v4.0.30319".to_owned()))
    );

    let mut versions_payload = Vec::new();
    add_utf16(&mut versions_payload, "v2.0.50727");
    add_utf16(&mut versions_payload, "v4.0.30319");
    dispatcher
        .dispatch(
            0xCAFEBABE,
            u32::from(DemonCommand::CommandAssemblyListVersions),
            40,
            &versions_payload,
        )
        .await?;

    let event = receiver.recv().await.ok_or("assembly versions response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("List available assembly versions:".to_owned()))
    );
    assert!(message.info.output.contains("v2.0.50727"));
    assert!(message.info.output.contains("v4.0.30319"));
    Ok(())
}

#[tokio::test]
async fn inline_execute_bof_output_broadcasts_agent_response()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xB0B1B2B3, test_key(0x11), test_iv(0x22));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    // BOF_CALLBACK_OUTPUT (0x00): standard output from the BOF
    let mut payload = Vec::new();
    add_u32(&mut payload, 0x00);
    add_bytes(&mut payload, b"hello from BOF");
    dispatcher
        .dispatch(0xB0B1B2B3, u32::from(DemonCommand::CommandInlineExecute), 1, &payload)
        .await?;
    let event = receiver.recv().await.ok_or("bof output response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Output".to_owned())));
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("hello from BOF".to_owned()))
    );

    // BOF_RAN_OK (3): completion confirmation
    let mut ran_ok = Vec::new();
    add_u32(&mut ran_ok, 3);
    dispatcher
        .dispatch(0xB0B1B2B3, u32::from(DemonCommand::CommandInlineExecute), 2, &ran_ok)
        .await?;
    let event = receiver.recv().await.ok_or("bof ran-ok response missing")?;
    let OperatorMessage::AgentResponse(ok_message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        ok_message.info.extra.get("Message"),
        Some(&Value::String("BOF execution completed".to_owned()))
    );

    // BOF_EXCEPTION (1): exception code + address
    let mut exc = Vec::new();
    add_u32(&mut exc, 1);
    add_u32(&mut exc, 0xC000_0005_u32); // STATUS_ACCESS_VIOLATION
    add_u64(&mut exc, 0x0000_7FF7_DEAD_BEEF_u64);
    dispatcher.dispatch(0xB0B1B2B3, u32::from(DemonCommand::CommandInlineExecute), 3, &exc).await?;
    let event = receiver.recv().await.ok_or("bof exception response missing")?;
    let OperatorMessage::AgentResponse(exc_message) = event else {
        panic!("expected agent response event");
    };
    assert!(
        exc_message
            .info
            .extra
            .get("Message")
            .and_then(|v| v.as_str())
            .map(|s| s.contains("0xC0000005") && s.contains("0x00007FF7DEADBEEF"))
            .unwrap_or(false),
        "exception message must include code and address"
    );

    // BOF_SYMBOL_NOT_FOUND (2): missing symbol name
    let mut sym = Vec::new();
    add_u32(&mut sym, 2);
    add_bytes(&mut sym, b"kernel32.VirtualAllocEx");
    dispatcher.dispatch(0xB0B1B2B3, u32::from(DemonCommand::CommandInlineExecute), 4, &sym).await?;
    let event = receiver.recv().await.ok_or("bof symbol-not-found response missing")?;
    let OperatorMessage::AgentResponse(sym_message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        sym_message.info.extra.get("Message"),
        Some(&Value::String("Symbol not found: kernel32.VirtualAllocEx".to_owned()))
    );

    // BOF_COULD_NOT_RUN (4): loader failed to start
    let mut no_run = Vec::new();
    add_u32(&mut no_run, 4);
    dispatcher
        .dispatch(0xB0B1B2B3, u32::from(DemonCommand::CommandInlineExecute), 5, &no_run)
        .await?;
    let event = receiver.recv().await.ok_or("bof could-not-run response missing")?;
    let OperatorMessage::AgentResponse(no_run_message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        no_run_message.info.extra.get("Message"),
        Some(&Value::String("Failed to execute object file".to_owned()))
    );

    // BOF_CALLBACK_ERROR (0x0d): error output text from the BOF
    let mut err_output = Vec::new();
    add_u32(&mut err_output, 0x0d);
    add_bytes(&mut err_output, b"access denied to target process");
    dispatcher
        .dispatch(0xB0B1B2B3, u32::from(DemonCommand::CommandInlineExecute), 6, &err_output)
        .await?;
    let event = receiver.recv().await.ok_or("bof error-output response missing")?;
    let OperatorMessage::AgentResponse(err_message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(err_message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    assert_eq!(
        err_message.info.extra.get("Message"),
        Some(&Value::String("access denied to target process".to_owned()))
    );

    Ok(())
}

#[tokio::test]
async fn sleep_callback_returns_agent_not_found_for_unregistered_agent()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    // Build a valid CommandSleep payload: delay=60, jitter=15
    let mut payload = Vec::new();
    add_u32(&mut payload, 60);
    add_u32(&mut payload, 15);

    // Dispatch to a non-existent agent
    let nonexistent_agent_id: u32 = 0xDEAD_BEEF;
    let result = dispatcher
        .dispatch(nonexistent_agent_id, u32::from(DemonCommand::CommandSleep), 99, &payload)
        .await;

    // Assert that the error is AgentNotFound
    let error = result.expect_err("dispatch to unregistered agent must fail");
    assert!(
        matches!(
            &error,
            CommandDispatchError::Registry(TeamserverError::AgentNotFound { agent_id })
                if *agent_id == nonexistent_agent_id
        ),
        "expected AgentNotFound for 0x{nonexistent_agent_id:08X}, got: {error}"
    );

    // Confirm no events were broadcast (short timeout to verify nothing arrives)
    let no_event = timeout(Duration::from_millis(50), receiver.recv()).await;
    assert!(no_event.is_err(), "no events should be broadcast when agent is not found");

    Ok(())
}
