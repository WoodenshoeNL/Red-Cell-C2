//! Tests for process, job, inject, exit, and related dispatch command handlers.

use super::common::*;

use super::super::process::{
    GrepRow, MemoryRow, ModuleRow, ProcessRow, format_grep_table, format_memory_protect,
    format_memory_state, format_memory_table, format_memory_type, format_module_table,
    format_process_table, handle_inject_dll_callback, handle_inject_shellcode_callback,
    handle_proc_ppid_spoof_callback, handle_process_command_callback, handle_process_list_callback,
    handle_spawn_dll_callback, process_rows_json, win32_error_code_name,
};
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

// ── Tests migrated from dispatch/process.rs inline mod tests ──────────────

// ── helpers ──────────────────────────────────────────────────────────────

fn make_process_row(name: &str, pid: u32, ppid: u32) -> ProcessRow {
    ProcessRow {
        name: name.to_owned(),
        pid,
        ppid,
        session: 1,
        arch: "x64".to_owned(),
        threads: 4,
        user: "SYSTEM".to_owned(),
    }
}

// ── format_process_table ─────────────────────────────────────────────────

#[test]
fn format_process_table_empty_returns_empty_string() {
    assert_eq!(format_process_table(&[]), "");
}

#[test]
fn format_process_table_single_row_contains_header_separator_and_data() {
    let rows = vec![make_process_row("svchost.exe", 1234, 456)];
    let table = format_process_table(&rows);

    // Header line must be present
    assert!(table.contains("Name"), "missing Name header: {table}");
    assert!(table.contains("PID"), "missing PID header: {table}");
    assert!(table.contains("PPID"), "missing PPID header: {table}");
    assert!(table.contains("Session"), "missing Session header: {table}");
    assert!(table.contains("Arch"), "missing Arch header: {table}");
    assert!(table.contains("Threads"), "missing Threads header: {table}");
    assert!(table.contains("User"), "missing User header: {table}");

    // Separator dashes must be present
    assert!(table.contains("----"), "missing separator: {table}");

    // Data row must be present
    assert!(table.contains("svchost.exe"), "missing process name: {table}");
    assert!(table.contains("1234"), "missing PID: {table}");
    assert!(table.contains("456"), "missing PPID: {table}");

    // Three lines: header, separator, data row (each ends with '\n')
    assert_eq!(table.lines().count(), 3, "expected 3 lines:\n{table}");
}

#[test]
fn format_process_table_name_width_is_dynamic() {
    // A long process name should widen the Name column for all rows.
    let rows =
        vec![make_process_row("a", 1, 0), make_process_row("very_long_process_name.exe", 2, 0)];
    let table = format_process_table(&rows);
    // Both rows must have the same leading-space alignment — i.e. "a" must
    // be left-padded to the same width as "very_long_process_name.exe".
    let lines: Vec<&str> = table.lines().collect();
    // data rows start at index 2
    let short_row = lines[2];
    let long_row = lines[3];
    // The PID column starts at the same offset in both rows when names
    // are padded correctly; verify by checking equal lengths up to PID.
    assert_eq!(
        short_row.find("1   "),
        long_row.find("2   "),
        "PID column offsets differ — name width not applied uniformly"
    );
}

// ── process_rows_json ────────────────────────────────────────────────────

#[test]
fn process_rows_json_two_rows_produce_correct_array() {
    let rows = vec![
        ProcessRow {
            name: "explorer.exe".to_owned(),
            pid: 100,
            ppid: 4,
            session: 1,
            arch: "x64".to_owned(),
            threads: 32,
            user: "user1".to_owned(),
        },
        ProcessRow {
            name: "cmd.exe".to_owned(),
            pid: 200,
            ppid: 100,
            session: 1,
            arch: "x86".to_owned(),
            threads: 2,
            user: "user2".to_owned(),
        },
    ];

    let Value::Array(arr) = process_rows_json(&rows) else {
        panic!("expected JSON array");
    };

    assert_eq!(arr.len(), 2);

    assert_eq!(arr[0]["Name"], "explorer.exe");
    assert_eq!(arr[0]["PID"], 100u32);
    assert_eq!(arr[0]["PPID"], 4u32);
    assert_eq!(arr[0]["Session"], 1u32);
    assert_eq!(arr[0]["Arch"], "x64");
    assert_eq!(arr[0]["Threads"], 32u32);
    assert_eq!(arr[0]["User"], "user1");

    assert_eq!(arr[1]["Name"], "cmd.exe");
    assert_eq!(arr[1]["PID"], 200u32);
    assert_eq!(arr[1]["PPID"], 100u32);
    assert_eq!(arr[1]["Arch"], "x86");
    assert_eq!(arr[1]["User"], "user2");
}

#[test]
fn process_rows_json_empty_produces_empty_array() {
    let Value::Array(arr) = process_rows_json(&[]) else {
        panic!("expected JSON array");
    };
    assert!(arr.is_empty());
}

// ── format_module_table ──────────────────────────────────────────────────

#[test]
fn format_module_table_empty_returns_empty_string() {
    assert_eq!(format_module_table(&[]), "");
}

#[test]
fn format_module_table_formats_hex_base_address() {
    let rows = vec![ModuleRow { name: "ntdll.dll".to_owned(), base: 0x7FFE_0000_1234_ABCD }];
    let table = format_module_table(&rows);
    assert!(table.contains("7FFE00001234ABCD"), "expected hex base address in table:\n{table}");
    assert!(table.contains("ntdll.dll"), "missing module name:\n{table}");
}

// ── format_grep_table ────────────────────────────────────────────────────

#[test]
fn format_grep_table_empty_returns_empty_string() {
    assert_eq!(format_grep_table(&[]), "");
}

#[test]
fn format_grep_table_contains_expected_row_data() {
    let rows = vec![GrepRow {
        name: "lsass.exe".to_owned(),
        pid: 700,
        ppid: 4,
        user: "SYSTEM".to_owned(),
        arch: "x64".to_owned(),
    }];
    let table = format_grep_table(&rows);
    assert!(table.contains("lsass.exe"), "missing name:\n{table}");
    assert!(table.contains("700"), "missing PID:\n{table}");
    assert!(table.contains("SYSTEM"), "missing user:\n{table}");
}

// ── format_memory_table ──────────────────────────────────────────────────

#[test]
fn format_memory_table_empty_returns_empty_string() {
    assert_eq!(format_memory_table(&[]), "");
}

#[test]
fn format_memory_table_formats_row_correctly() {
    let rows = vec![MemoryRow {
        base: 0x0000_7FF0_0000_0000,
        size: 0x1000,
        protect: 0x20,     // PAGE_EXECUTE_READ
        state: 0x1000,     // MEM_COMMIT
        mem_type: 0x20000, // MEM_PRIVATE
    }];
    let table = format_memory_table(&rows);
    assert!(table.contains("PAGE_EXECUTE_READ"), "missing protect:\n{table}");
    assert!(table.contains("MEM_COMMIT"), "missing state:\n{table}");
    assert!(table.contains("MEM_PRIVATE"), "missing type:\n{table}");
    assert!(table.contains("7FF000000000"), "missing base address:\n{table}");
}

// ── format_memory_protect ────────────────────────────────────────────────

#[test]
fn format_memory_protect_known_constants_return_names() {
    assert_eq!(format_memory_protect(0x01), "PAGE_NOACCESS");
    assert_eq!(format_memory_protect(0x02), "PAGE_READONLY");
    assert_eq!(format_memory_protect(0x04), "PAGE_READWRITE");
    assert_eq!(format_memory_protect(0x08), "PAGE_WRITECOPY");
    assert_eq!(format_memory_protect(0x10), "PAGE_EXECUTE");
    assert_eq!(format_memory_protect(0x20), "PAGE_EXECUTE_READ");
    assert_eq!(format_memory_protect(0x40), "PAGE_EXECUTE_READWRITE");
    assert_eq!(format_memory_protect(0x80), "PAGE_EXECUTE_WRITECOPY");
    assert_eq!(format_memory_protect(0x100), "PAGE_GUARD");
}

#[test]
fn format_memory_protect_unknown_constant_returns_hex_fallback() {
    assert_eq!(format_memory_protect(0x99), "0x99");
    assert_eq!(format_memory_protect(0), "0x0");
    // Combined flags (e.g. PAGE_GUARD | PAGE_READWRITE) fall through to hex
    assert_eq!(format_memory_protect(0x104), "0x104");
    // Uppercase hex must be preserved for consistency
    assert_eq!(format_memory_protect(0xAB), "0xAB");
}

// ── format_memory_state ──────────────────────────────────────────────────

#[test]
fn format_memory_state_known_constants_return_names() {
    assert_eq!(format_memory_state(0x1000), "MEM_COMMIT");
    assert_eq!(format_memory_state(0x2000), "MEM_RESERVE");
    assert_eq!(format_memory_state(0x10000), "MEM_FREE");
}

#[test]
fn format_memory_state_unknown_constant_returns_hex_fallback() {
    assert_eq!(format_memory_state(0xABCD), "0xABCD");
    // Combined flags (e.g. MEM_COMMIT | MEM_RESERVE) fall through to hex
    assert_eq!(format_memory_state(0x3000), "0x3000");
    assert_eq!(format_memory_state(0), "0x0");
}

// ── format_memory_type ───────────────────────────────────────────────────

#[test]
fn format_memory_type_known_constants_return_names() {
    assert_eq!(format_memory_type(0x20000), "MEM_PRIVATE");
    assert_eq!(format_memory_type(0x40000), "MEM_MAPPED");
    assert_eq!(format_memory_type(0x1000000), "MEM_IMAGE");
}

#[test]
fn format_memory_type_unknown_constant_returns_hex_fallback() {
    assert_eq!(format_memory_type(0x99999), "0x99999");
    assert_eq!(format_memory_type(0x9999), "0x9999");
    assert_eq!(format_memory_type(0), "0x0");
}

// ── win32_error_code_name ────────────────────────────────────────────────

#[test]
fn win32_error_code_name_known_codes_return_symbolic_names() {
    assert_eq!(win32_error_code_name(2), Some("ERROR_FILE_NOT_FOUND"));
    assert_eq!(win32_error_code_name(5), Some("ERROR_ACCESS_DENIED"));
    assert_eq!(win32_error_code_name(87), Some("ERROR_INVALID_PARAMETER"));
    assert_eq!(win32_error_code_name(183), Some("ERROR_ALREADY_EXISTS"));
    assert_eq!(win32_error_code_name(997), Some("ERROR_IO_PENDING"));
}

#[test]
fn win32_error_code_name_unknown_codes_return_none() {
    assert_eq!(win32_error_code_name(0), None);
    assert_eq!(win32_error_code_name(1), None);
    assert_eq!(win32_error_code_name(9999), None);
}

// ── handle_process_command_callback — Create branch ─────────────────────

/// Build a binary payload for the `Create` subcommand of `CommandProc`.
fn build_process_create_payload(
    path: &str,
    pid: u32,
    success: u32,
    piped: u32,
    verbose: u32,
) -> Vec<u8> {
    let mut buf = Vec::new();
    // subcommand
    buf.extend_from_slice(&u32::from(DemonProcessCommand::Create).to_le_bytes());
    // path (UTF-16 LE, null-terminated, length-prefixed)
    let mut encoded: Vec<u8> = path.encode_utf16().flat_map(u16::to_le_bytes).collect();
    encoded.extend_from_slice(&[0, 0]); // null terminator
    buf.extend_from_slice(&u32::try_from(encoded.len()).expect("unwrap").to_le_bytes());
    buf.extend_from_slice(&encoded);
    // pid, success, piped, verbose
    buf.extend_from_slice(&pid.to_le_bytes());
    buf.extend_from_slice(&success.to_le_bytes());
    buf.extend_from_slice(&piped.to_le_bytes());
    buf.extend_from_slice(&verbose.to_le_bytes());
    buf
}

/// Helper: extract the `Type` and `Message` extra fields from an `AgentResponse`.
fn extract_response_kind_and_message(msg: &OperatorMessage) -> (String, String) {
    let OperatorMessage::AgentResponse(m) = msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    let kind = m.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("").to_owned();
    let message = m.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("").to_owned();
    (kind, message)
}

#[tokio::test]
async fn process_create_verbose_success_broadcasts_info_with_path_and_pid() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let payload = build_process_create_payload("C:\\cmd.exe", 1234, 1, 0, 1);

    handle_process_command_callback(&events, 0xAA, 1, &payload)
        .await
        .expect("handler should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive event within timeout")
        .expect("should have a broadcast event");

    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Info");
    assert!(
        message.contains("C:\\cmd.exe") && message.contains("1234"),
        "expected path and pid in message, got: {message}"
    );
}

#[tokio::test]
async fn process_create_verbose_failure_broadcasts_error() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let payload = build_process_create_payload("C:\\bad.exe", 0, 0, 0, 1);

    handle_process_command_callback(&events, 0xBB, 2, &payload)
        .await
        .expect("handler should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive event within timeout")
        .expect("should have a broadcast event");

    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Error");
    assert!(message.contains("C:\\bad.exe"), "expected path in error message, got: {message}");
}

#[tokio::test]
async fn process_create_non_verbose_failure_unpiped_broadcasts_fallback() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    // verbose=0, success=0, piped=0
    let payload = build_process_create_payload("C:\\app.exe", 0, 0, 0, 0);

    handle_process_command_callback(&events, 0xCC, 3, &payload)
        .await
        .expect("handler should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive event within timeout")
        .expect("should have a broadcast event");

    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Info");
    assert_eq!(message, "Process create completed");
}

#[tokio::test]
async fn process_create_non_verbose_failure_piped_broadcasts_fallback() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    // verbose=0, success=0, piped=1
    let payload = build_process_create_payload("C:\\app.exe", 0, 0, 1, 0);

    handle_process_command_callback(&events, 0xDD, 4, &payload)
        .await
        .expect("handler should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive event within timeout")
        .expect("should have a broadcast event");

    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Info");
    assert_eq!(message, "Process create completed");
}

#[tokio::test]
async fn process_create_non_verbose_success_unpiped_broadcasts_fallback() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    // verbose=0, success=1, piped=0
    let payload = build_process_create_payload("C:\\app.exe", 999, 1, 0, 0);

    handle_process_command_callback(&events, 0xEE, 5, &payload)
        .await
        .expect("handler should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive event within timeout")
        .expect("should have a broadcast event");

    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Info");
    assert_eq!(message, "Process create completed");
}

#[tokio::test]
async fn process_create_non_verbose_success_piped_does_not_broadcast() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    // verbose=0, success=1, piped=1 → no broadcast
    let payload = build_process_create_payload("C:\\app.exe", 999, 1, 1, 0);

    handle_process_command_callback(&events, 0xFF, 6, &payload)
        .await
        .expect("handler should succeed");

    let result = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;

    assert!(result.is_err(), "expected no broadcast when verbose=0, success=1, piped=1");
}

// ── payload builder helpers ─────────────────────────────────────────────

/// Build a binary payload for `handle_proc_ppid_spoof_callback`.
fn build_ppid_spoof_payload(ppid: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    add_u32(&mut buf, ppid);
    buf
}

/// Build a binary payload for `handle_process_list_callback`.
fn build_process_list_payload(
    from_process_manager: u32,
    rows: &[(&str, u32, u32, u32, u32, u32, &str)], // name, pid, is_wow, ppid, session, threads, user
) -> Vec<u8> {
    let mut buf = Vec::new();
    add_u32(&mut buf, from_process_manager);
    for &(name, pid, is_wow, ppid, session, threads, user) in rows {
        add_utf16(&mut buf, name);
        add_u32(&mut buf, pid);
        add_u32(&mut buf, is_wow);
        add_u32(&mut buf, ppid);
        add_u32(&mut buf, session);
        add_u32(&mut buf, threads);
        add_utf16(&mut buf, user);
    }
    buf
}

/// Build a payload containing a single u32 status code (for inject/spawn handlers).
fn build_status_payload(status: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    add_u32(&mut buf, status);
    buf
}

// ── handle_proc_ppid_spoof_callback ─────────────────────────────────────

fn temp_db_path() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("red-cell-dispatch-process-{}.sqlite", uuid::Uuid::new_v4()))
}

async fn test_registry() -> AgentRegistry {
    let db = crate::Database::connect(temp_db_path()).await.expect("unwrap");
    AgentRegistry::new(db)
}

fn sample_agent(agent_id: u32) -> red_cell_common::AgentRecord {
    use red_cell_common::AgentEncryptionInfo;
    use zeroize::Zeroizing;
    red_cell_common::AgentRecord {
        agent_id,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: AgentEncryptionInfo {
            aes_key: Zeroizing::new(b"0123456789abcdef0123456789abcdef".to_vec()),
            aes_iv: Zeroizing::new(b"0123456789abcdef".to_vec()),
        },
        hostname: "wkstn-01".to_owned(),
        username: "operator".to_owned(),
        domain_name: "LAB".to_owned(),
        external_ip: "127.0.0.1".to_owned(),
        internal_ip: "10.0.0.25".to_owned(),
        process_name: "explorer.exe".to_owned(),
        process_path: "C:\\Windows\\explorer.exe".to_owned(),
        base_address: 0x1000,
        process_pid: 1337,
        process_tid: 7331,
        process_ppid: 512,
        process_arch: "x64".to_owned(),
        elevated: true,
        os_version: "Windows 11".to_owned(),
        os_build: 0,
        os_arch: "x64".to_owned(),
        sleep_delay: 10,
        sleep_jitter: 25,
        kill_date: None,
        working_hours: None,
        first_call_in: "2026-03-09T20:00:00Z".to_owned(),
        last_call_in: "2026-03-09T20:00:00Z".to_owned(),
    }
}

#[tokio::test]
async fn ppid_spoof_updates_registry_and_broadcasts() {
    let registry = test_registry().await;
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let agent_id = 0xABCD_0001;
    let agent = sample_agent(agent_id);
    registry.insert(agent).await.expect("unwrap");

    let payload = build_ppid_spoof_payload(9999);
    handle_proc_ppid_spoof_callback(&registry, &events, agent_id, 1, &payload)
        .await
        .expect("handler should succeed");

    // Agent's process_ppid should be updated in the registry.
    let updated = registry.get(agent_id).await.expect("agent should exist");
    assert_eq!(updated.process_ppid, 9999);

    // Two events: agent_mark_event + agent_response_event
    let _mark_event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive mark event")
        .expect("mark event");

    let response_event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive response event")
        .expect("response event");

    let (kind, message) = extract_response_kind_and_message(&response_event);
    assert_eq!(kind, "Good");
    assert!(message.contains("9999"), "expected ppid in message, got: {message}");
}

#[tokio::test]
async fn ppid_spoof_missing_agent_still_broadcasts_response() {
    let registry = test_registry().await;
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let agent_id = 0xDEAD_BEEF;

    let payload = build_ppid_spoof_payload(42);
    let result = handle_proc_ppid_spoof_callback(&registry, &events, agent_id, 5, &payload).await;

    assert!(result.is_ok(), "handler should not panic for missing agent");

    // Only the response event should be broadcast (no mark event).
    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive response event")
        .expect("response event");

    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Good");
    assert!(message.contains("42"), "expected ppid in message, got: {message}");
}

#[tokio::test]
async fn ppid_spoof_truncated_payload_returns_error() {
    let registry = test_registry().await;
    let events = EventBus::default();
    // Payload too short — only 2 bytes instead of 4.
    let result = handle_proc_ppid_spoof_callback(&registry, &events, 1, 1, &[0x01, 0x02]).await;

    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload, got: {result:?}"
    );
}

// ── handle_process_list_callback ────────────────────────────────────────

#[tokio::test]
async fn process_list_happy_path_broadcasts_table_and_json() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let payload = build_process_list_payload(
        0, // from_process_manager
        &[
            ("svchost.exe", 800, 0, 4, 0, 12, "SYSTEM"),
            ("explorer.exe", 1200, 1, 800, 1, 32, "user1"),
        ],
    );

    let result = handle_process_list_callback(&events, 0xAA, 1, &payload).await;
    assert!(result.is_ok());
    assert!(result.expect("unwrap").is_none());

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive event")
        .expect("broadcast event");

    let OperatorMessage::AgentResponse(ref msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };

    // Check structured JSON extra
    let rows_json = msg.info.extra.get("ProcessListRows").expect("missing ProcessListRows");
    let arr = rows_json.as_array().expect("ProcessListRows should be array");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["Name"], "svchost.exe");
    assert_eq!(arr[0]["PID"], 800);
    assert_eq!(arr[0]["Arch"], "x64"); // is_wow=0 → x64
    assert_eq!(arr[1]["Name"], "explorer.exe");
    assert_eq!(arr[1]["Arch"], "x86"); // is_wow=1 → x86
    assert_eq!(arr[1]["User"], "user1");

    // Check the message type
    let kind = msg.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(kind, "Info");
}

#[tokio::test]
async fn process_list_empty_returns_none_without_broadcasting() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    // No rows, just the from_process_manager flag.
    let payload = build_process_list_payload(0, &[]);

    let result = handle_process_list_callback(&events, 0xBB, 2, &payload).await;
    assert!(result.is_ok());
    assert!(result.expect("unwrap").is_none());

    let timeout_result =
        tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
    assert!(timeout_result.is_err(), "expected no broadcast for empty process list");
}

#[tokio::test]
async fn process_list_truncated_row_returns_error() {
    let events = EventBus::default();
    // Payload with the flag but a truncated row (just 2 bytes of garbage).
    let mut payload = Vec::new();
    add_u32(&mut payload, 0); // from_process_manager
    payload.extend_from_slice(&[0x01, 0x02]); // truncated — not enough for a utf16 length

    let result = handle_process_list_callback(&events, 0xCC, 3, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated row, got: {result:?}"
    );
}

// ── handle_inject_shellcode_callback ────────────────────────────────────

#[tokio::test]
async fn inject_shellcode_success_broadcasts_good() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let payload = build_status_payload(u32::from(DemonInjectError::Success));

    handle_inject_shellcode_callback(&events, 0xAA, 1, &payload).await.expect("should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Good");
    assert!(message.contains("Successfully"), "got: {message}");
}

#[tokio::test]
async fn inject_shellcode_failed_broadcasts_error() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let payload = build_status_payload(u32::from(DemonInjectError::Failed));

    handle_inject_shellcode_callback(&events, 0xAA, 1, &payload).await.expect("should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, _) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Error");
}

#[tokio::test]
async fn inject_shellcode_invalid_param_broadcasts_error() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let payload = build_status_payload(u32::from(DemonInjectError::InvalidParam));

    handle_inject_shellcode_callback(&events, 0xAA, 1, &payload).await.expect("should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Error");
    assert!(message.contains("Invalid parameter"), "got: {message}");
}

#[tokio::test]
async fn inject_shellcode_arch_mismatch_broadcasts_error() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let payload = build_status_payload(u32::from(DemonInjectError::ProcessArchMismatch));

    handle_inject_shellcode_callback(&events, 0xAA, 1, &payload).await.expect("should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Error");
    assert!(message.contains("architecture mismatch"), "got: {message}");
}

#[tokio::test]
async fn inject_shellcode_unknown_status_returns_error() {
    let events = EventBus::default();
    let payload = build_status_payload(0xFFFF);

    let result = handle_inject_shellcode_callback(&events, 0xAA, 1, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for unknown status, got: {result:?}"
    );
}

// ── handle_inject_dll_callback ──────────────────────────────────────────

#[tokio::test]
async fn inject_dll_success_broadcasts_good() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let payload = build_status_payload(u32::from(DemonInjectError::Success));

    handle_inject_dll_callback(&events, 0xBB, 1, &payload).await.expect("should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Good");
    assert!(message.contains("Successfully"), "got: {message}");
}

#[tokio::test]
async fn inject_dll_failed_broadcasts_error() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let payload = build_status_payload(u32::from(DemonInjectError::Failed));

    handle_inject_dll_callback(&events, 0xBB, 1, &payload).await.expect("should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, _) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Error");
}

#[tokio::test]
async fn inject_dll_invalid_param_broadcasts_error() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let payload = build_status_payload(u32::from(DemonInjectError::InvalidParam));

    handle_inject_dll_callback(&events, 0xBB, 1, &payload).await.expect("should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Error");
    assert!(message.contains("invalid parameter"), "got: {message}");
}

#[tokio::test]
async fn inject_dll_arch_mismatch_broadcasts_error() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let payload = build_status_payload(u32::from(DemonInjectError::ProcessArchMismatch));

    handle_inject_dll_callback(&events, 0xBB, 1, &payload).await.expect("should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Error");
    assert!(message.contains("architecture mismatch"), "got: {message}");
}

#[tokio::test]
async fn inject_dll_unknown_status_returns_error() {
    let events = EventBus::default();
    let payload = build_status_payload(0xFFFF);

    let result = handle_inject_dll_callback(&events, 0xBB, 1, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload, got: {result:?}"
    );
}

// ── handle_spawn_dll_callback ───────────────────────────────────────────

#[tokio::test]
async fn spawn_dll_success_broadcasts_good() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let payload = build_status_payload(u32::from(DemonInjectError::Success));

    handle_spawn_dll_callback(&events, 0xCC, 1, &payload).await.expect("should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Good");
    assert!(message.contains("Successfully"), "got: {message}");
}

#[tokio::test]
async fn spawn_dll_failed_broadcasts_error() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let payload = build_status_payload(u32::from(DemonInjectError::Failed));

    handle_spawn_dll_callback(&events, 0xCC, 1, &payload).await.expect("should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, _) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Error");
}

#[tokio::test]
async fn spawn_dll_invalid_param_broadcasts_error() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let payload = build_status_payload(u32::from(DemonInjectError::InvalidParam));

    handle_spawn_dll_callback(&events, 0xCC, 1, &payload).await.expect("should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Error");
    assert!(message.contains("invalid parameter"), "got: {message}");
}

#[tokio::test]
async fn spawn_dll_arch_mismatch_broadcasts_error() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let payload = build_status_payload(u32::from(DemonInjectError::ProcessArchMismatch));

    handle_spawn_dll_callback(&events, 0xCC, 1, &payload).await.expect("should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Error");
    assert!(message.contains("architecture mismatch"), "got: {message}");
}

#[tokio::test]
async fn spawn_dll_unknown_status_returns_error() {
    let events = EventBus::default();
    let payload = build_status_payload(0xFFFF);

    let result = handle_spawn_dll_callback(&events, 0xCC, 1, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload, got: {result:?}"
    );
}

// ── handle_process_command_callback — Kill branch ──────────────────────

fn build_process_kill_payload(success: u32, pid: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    add_u32(&mut buf, u32::from(DemonProcessCommand::Kill));
    add_u32(&mut buf, success);
    add_u32(&mut buf, pid);
    buf
}

#[tokio::test]
async fn process_kill_success_broadcasts_good_with_pid() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let payload = build_process_kill_payload(1, 4200);

    handle_process_command_callback(&events, 0xA1, 10, &payload)
        .await
        .expect("handler should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Good");
    assert!(message.contains("4200"), "expected pid in message, got: {message}");
}

#[tokio::test]
async fn process_kill_failure_broadcasts_error() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let payload = build_process_kill_payload(0, 4200);

    handle_process_command_callback(&events, 0xA2, 11, &payload)
        .await
        .expect("handler should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");
    let (kind, message) = extract_response_kind_and_message(&event);
    assert_eq!(kind, "Error");
    assert!(message.contains("Failed"), "expected failure message, got: {message}");
}

// ── handle_process_command_callback — Kill branch (truncated payloads) ─

#[tokio::test]
async fn process_kill_empty_payload_returns_error() {
    let events = EventBus::default();
    // Payload: only the subcommand u32 (Kill), no success or pid fields.
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonProcessCommand::Kill));

    let result = handle_process_command_callback(&events, 0xA3, 12, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for empty kill body, got: {result:?}"
    );
}

#[tokio::test]
async fn process_kill_truncated_pid_returns_error() {
    let events = EventBus::default();
    // Payload: subcommand u32 (Kill) + success u32, but NO pid field.
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonProcessCommand::Kill));
    add_u32(&mut payload, 1); // success field only

    let result = handle_process_command_callback(&events, 0xA4, 13, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated kill pid, got: {result:?}"
    );
}

#[tokio::test]
async fn process_kill_full_payload_success_returns_ok() {
    // Regression guard: a well-formed 8-byte body (success=1, pid) must still succeed.
    let events = EventBus::default();
    let payload = build_process_kill_payload(1, 9999);

    let result = handle_process_command_callback(&events, 0xA5, 14, &payload).await;
    assert!(result.is_ok(), "expected Ok for full kill payload, got: {result:?}");
}

// ── handle_process_command_callback — Modules branch ────────────────────

fn add_string(buf: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    add_u32(buf, u32::try_from(bytes.len()).expect("unwrap"));
    buf.extend_from_slice(bytes);
}

fn build_process_modules_payload(pid: u32, modules: &[(&str, u64)]) -> Vec<u8> {
    let mut buf = Vec::new();
    add_u32(&mut buf, u32::from(DemonProcessCommand::Modules));
    add_u32(&mut buf, pid);
    for &(name, base) in modules {
        add_string(&mut buf, name);
        add_u64(&mut buf, base);
    }
    buf
}

#[tokio::test]
async fn process_modules_broadcasts_info_with_table_and_json() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let payload = build_process_modules_payload(
        1234,
        &[("ntdll.dll", 0x7FFE_0000_0000), ("kernel32.dll", 0x7FFE_0001_0000)],
    );

    handle_process_command_callback(&events, 0xB1, 20, &payload)
        .await
        .expect("handler should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");

    let OperatorMessage::AgentResponse(ref msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };

    let kind = msg.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(kind, "Info");

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("1234"), "expected PID in message, got: {message}");

    let rows_json = msg.info.extra.get("ModuleRows").expect("missing ModuleRows");
    let arr = rows_json.as_array().expect("ModuleRows should be array");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["Name"], "ntdll.dll");
    assert_eq!(arr[1]["Name"], "kernel32.dll");
}

#[tokio::test]
async fn process_modules_empty_list_still_broadcasts() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let payload = build_process_modules_payload(999, &[]);

    handle_process_command_callback(&events, 0xB2, 21, &payload)
        .await
        .expect("handler should succeed");

    // Empty module table → format_module_table returns "" but handler still broadcasts
    // because the Modules branch always broadcasts (unlike process list which checks is_empty)
    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");

    let OperatorMessage::AgentResponse(ref msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    let rows_json = msg.info.extra.get("ModuleRows").expect("missing ModuleRows");
    let arr = rows_json.as_array().expect("ModuleRows should be array");
    assert!(arr.is_empty());
}

// ── handle_process_command_callback — Grep branch ───────────────────────

fn add_bytes_raw(buf: &mut Vec<u8>, data: &[u8]) {
    add_u32(buf, u32::try_from(data.len()).expect("unwrap"));
    buf.extend_from_slice(data);
}

fn build_process_grep_payload(rows: &[(&str, u32, u32, &[u8], u32)]) -> Vec<u8> {
    let mut buf = Vec::new();
    add_u32(&mut buf, u32::from(DemonProcessCommand::Grep));
    for &(name, pid, ppid, user_bytes, arch) in rows {
        add_utf16(&mut buf, name);
        add_u32(&mut buf, pid);
        add_u32(&mut buf, ppid);
        add_bytes_raw(&mut buf, user_bytes);
        add_u32(&mut buf, arch);
    }
    buf
}

#[tokio::test]
async fn process_grep_broadcasts_info_with_table_and_json() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let payload = build_process_grep_payload(&[
        ("lsass.exe", 700, 4, b"SYSTEM\0", 64),
        ("cmd.exe", 1200, 700, b"user1\0", 86),
    ]);

    handle_process_command_callback(&events, 0xC1, 30, &payload)
        .await
        .expect("handler should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");

    let OperatorMessage::AgentResponse(ref msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };

    let kind = msg.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(kind, "Info");

    let rows_json = msg.info.extra.get("GrepRows").expect("missing GrepRows");
    let arr = rows_json.as_array().expect("GrepRows should be array");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["Name"], "lsass.exe");
    assert_eq!(arr[0]["PID"], 700);
    assert_eq!(arr[0]["User"], "SYSTEM");
    assert_eq!(arr[0]["Arch"], "x64"); // arch != 86 → x64
    assert_eq!(arr[1]["Name"], "cmd.exe");
    assert_eq!(arr[1]["Arch"], "x86"); // arch == 86 → x86
}

#[tokio::test]
async fn process_grep_user_bytes_null_terminator_edge_cases() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let payload = build_process_grep_payload(&[
        // No null terminator — raw string should be preserved as-is
        ("notepad.exe", 100, 4, b"admin", 64),
        // Multiple trailing null bytes — all should be stripped
        ("svchost.exe", 200, 4, b"user\0\0\0", 64),
        // Entirely null bytes — should produce an empty string
        ("idle.exe", 300, 4, b"\0", 86),
    ]);

    handle_process_command_callback(&events, 0xC2, 31, &payload)
        .await
        .expect("handler should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");

    let OperatorMessage::AgentResponse(ref msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };

    let rows_json = msg.info.extra.get("GrepRows").expect("missing GrepRows");
    let arr = rows_json.as_array().expect("GrepRows should be array");
    assert_eq!(arr.len(), 3);

    // No null terminator — user string preserved
    assert_eq!(arr[0]["Name"], "notepad.exe");
    assert_eq!(arr[0]["User"], "admin");

    // Multiple trailing nulls — all stripped
    assert_eq!(arr[1]["Name"], "svchost.exe");
    assert_eq!(arr[1]["User"], "user");

    // Entirely null — empty string
    assert_eq!(arr[2]["Name"], "idle.exe");
    assert_eq!(arr[2]["User"], "");
}

// ── handle_process_command_callback — Memory branch ─────────────────────

fn build_process_memory_payload(
    pid: u32,
    query_protect: u32,
    regions: &[(u64, u32, u32, u32, u32)],
) -> Vec<u8> {
    let mut buf = Vec::new();
    add_u32(&mut buf, u32::from(DemonProcessCommand::Memory));
    add_u32(&mut buf, pid);
    add_u32(&mut buf, query_protect);
    for &(base, size, protect, state, mem_type) in regions {
        add_u64(&mut buf, base);
        add_u32(&mut buf, size);
        add_u32(&mut buf, protect);
        add_u32(&mut buf, state);
        add_u32(&mut buf, mem_type);
    }
    buf
}

#[tokio::test]
async fn process_memory_broadcasts_info_with_table_and_json() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let payload = build_process_memory_payload(
        500,
        0, // query_protect=0 → "All"
        &[(0x7FF0_0000_0000, 0x1000, 0x20, 0x1000, 0x20000)],
    );

    handle_process_command_callback(&events, 0xD1, 40, &payload)
        .await
        .expect("handler should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");

    let OperatorMessage::AgentResponse(ref msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };

    let kind = msg.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(kind, "Info");

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("500"), "expected PID in message, got: {message}");
    assert!(message.contains("All"), "expected 'All' filter, got: {message}");

    let rows_json = msg.info.extra.get("MemoryRows").expect("missing MemoryRows");
    let arr = rows_json.as_array().expect("MemoryRows should be array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["Protect"], "PAGE_EXECUTE_READ");
    assert_eq!(arr[0]["State"], "MEM_COMMIT");
    assert_eq!(arr[0]["Type"], "MEM_PRIVATE");
}

#[tokio::test]
async fn process_memory_with_protect_filter_shows_protect_name() {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let payload = build_process_memory_payload(
        600,
        0x40, // PAGE_EXECUTE_READWRITE
        &[(0x1000, 0x100, 0x40, 0x1000, 0x1000000)],
    );

    handle_process_command_callback(&events, 0xD2, 41, &payload)
        .await
        .expect("handler should succeed");

    let event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .expect("timeout")
        .expect("event");

    let OperatorMessage::AgentResponse(ref msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("PAGE_EXECUTE_READWRITE"),
        "expected protect name in filter, got: {message}"
    );
}

// ── handle_process_command_callback — invalid subcommand ────────────────

#[tokio::test]
async fn process_command_invalid_subcommand_returns_error() {
    let events = EventBus::default();
    let mut buf = Vec::new();
    add_u32(&mut buf, 0xFF); // invalid subcommand

    let result = handle_process_command_callback(&events, 0xE1, 50, &buf).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for invalid subcommand, got: {result:?}"
    );
}

// ── handle_process_command_callback — truncated multi-row payload ───────

#[tokio::test]
async fn process_modules_truncated_second_row_returns_error() {
    let events = EventBus::default();
    // Build a valid first module row, then a truncated second row
    let mut buf = Vec::new();
    add_u32(&mut buf, u32::from(DemonProcessCommand::Modules));
    add_u32(&mut buf, 1234); // pid
    // First complete module row
    add_string(&mut buf, "ntdll.dll");
    add_u64(&mut buf, 0x7FFE_0000_0000);
    // Second row: name length says 10 bytes, but only provide 3
    buf.extend_from_slice(&10u32.to_le_bytes());
    buf.extend_from_slice(&[0x41, 0x42, 0x43]); // only 3 of the promised 10 bytes

    let result = handle_process_command_callback(&events, 0xF1, 60, &buf).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated module row, got: {result:?}"
    );
}

#[tokio::test]
async fn inject_shellcode_truncated_payload_returns_error() {
    let events = EventBus::default();
    let result = handle_inject_shellcode_callback(&events, 0xAA, 1, &[0x01]).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated payload, got: {result:?}"
    );
}

#[tokio::test]
async fn inject_dll_truncated_payload_returns_error() {
    let events = EventBus::default();
    let result = handle_inject_dll_callback(&events, 0xBB, 1, &[]).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated payload, got: {result:?}"
    );
}

#[tokio::test]
async fn spawn_dll_truncated_payload_returns_error() {
    let events = EventBus::default();
    let result = handle_spawn_dll_callback(&events, 0xCC, 1, &[0xFF, 0xFF]).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated payload, got: {result:?}"
    );
}

// ── Unicode / non-ASCII process name formatting ─────────────────────────
//
// Note on alignment: `format_process_table` and `format_grep_table` compute
// column widths via `.len()` (byte length) and pad via `format!("{:<w$}", …)`
// (which counts Unicode scalar values, not display width).  For multi-byte
// UTF-8 characters this means:
//
//  - CJK characters: 3 bytes each, 1 char, 2 display columns
//    → `.len()` over-counts vs char count → extra padding spaces
//    → display columns = display_width + padding > expected column width
//
//  - Accented Latin (e.g. "é"): 2 bytes, 1 char, 1 display column
//    → `.len()` over-counts vs char count → extra padding spaces
//
// The result is that rows with multi-byte names get more visual padding than
// pure-ASCII rows, causing slight column misalignment.  This is a known
// cosmetic limitation.  Fixing it properly requires a Unicode display-width
// library (e.g. `unicode-width`).  The tests below document the current
// behavior so any future fix can be validated.

#[test]
fn format_process_table_cjk_name_output_is_well_formed() {
    let rows =
        vec![make_process_row("测试进程.exe", 1000, 4), make_process_row("svchost.exe", 800, 4)];
    let table = format_process_table(&rows);

    // All data must appear in the output
    assert!(table.contains("测试进程.exe"), "missing CJK process name:\n{table}");
    assert!(table.contains("svchost.exe"), "missing ASCII process name:\n{table}");
    assert!(table.contains("1000"), "missing PID 1000:\n{table}");
    assert!(table.contains("800"), "missing PID 800:\n{table}");

    // Must still have 4 lines: header, separator, 2 data rows
    assert_eq!(table.lines().count(), 4, "expected 4 lines:\n{table}");

    // Header and separator must still be present
    assert!(table.contains("Name"), "missing Name header:\n{table}");
    assert!(table.contains("----"), "missing separator:\n{table}");
}

#[test]
fn format_process_table_cjk_name_byte_len_exceeds_char_count() {
    // "测试进程.exe" = 4 CJK chars (3 bytes each) + ".exe" (4 bytes) = 16 bytes, 8 chars
    // This documents the known divergence between .len() and char count.
    let name = "测试进程.exe";
    assert_eq!(name.len(), 16, "byte length");
    assert_eq!(name.chars().count(), 8, "char count");

    let rows = vec![make_process_row(name, 1, 0)];
    let table = format_process_table(&rows);
    let data_line = table.lines().nth(2).expect("data row");

    // The Name column is padded to byte-length (16) by format!("{:<16}", …),
    // but since the string is only 8 chars, format! adds 8 spaces of padding.
    // Verify the name appears and is followed by spaces (over-padded).
    assert!(data_line.contains("测试进程.exe"), "data line must contain CJK name:\n{data_line}");
}

#[test]
fn format_process_table_accented_latin_name_is_present() {
    // "Ünïcödé.exe" contains multi-byte Latin chars
    let rows = vec![make_process_row("Ünïcödé.exe", 42, 1)];
    let table = format_process_table(&rows);

    assert!(table.contains("Ünïcödé.exe"), "missing accented name:\n{table}");
    assert_eq!(table.lines().count(), 3, "expected 3 lines:\n{table}");
}

#[test]
fn format_process_table_mixed_script_rows_all_present() {
    // Mix of ASCII, CJK, Cyrillic, and accented names
    let rows = vec![
        make_process_row("explorer.exe", 100, 4),
        make_process_row("测试.exe", 200, 4),
        make_process_row("процесс.exe", 300, 4),
        make_process_row("café.exe", 400, 4),
    ];
    let table = format_process_table(&rows);

    assert!(table.contains("explorer.exe"), "missing ASCII name:\n{table}");
    assert!(table.contains("测试.exe"), "missing CJK name:\n{table}");
    assert!(table.contains("процесс.exe"), "missing Cyrillic name:\n{table}");
    assert!(table.contains("café.exe"), "missing accented name:\n{table}");
    assert_eq!(table.lines().count(), 6, "expected 6 lines (header+sep+4 data):\n{table}");
}

#[test]
fn format_process_table_unicode_user_field_is_present() {
    // Non-ASCII user name (e.g. domain with CJK characters)
    let row = ProcessRow {
        name: "cmd.exe".to_owned(),
        pid: 10,
        ppid: 1,
        session: 0,
        arch: "x64".to_owned(),
        threads: 1,
        user: "域\\管理员".to_owned(),
    };
    let table = format_process_table(&[row]);
    assert!(table.contains("域\\管理员"), "missing Unicode user:\n{table}");
}

#[test]
fn format_grep_table_cjk_name_output_is_well_formed() {
    let rows = vec![GrepRow {
        name: "恶意软件.exe".to_owned(),
        pid: 999,
        ppid: 4,
        user: "SYSTEM".to_owned(),
        arch: "x64".to_owned(),
    }];
    let table = format_grep_table(&rows);

    assert!(table.contains("恶意软件.exe"), "missing CJK name:\n{table}");
    assert!(table.contains("999"), "missing PID:\n{table}");
    assert!(table.contains("SYSTEM"), "missing user:\n{table}");
    // header + separator + 1 data row
    assert_eq!(
        table.lines().filter(|l| !l.is_empty()).count(),
        3,
        "expected 3 non-empty lines:\n{table}"
    );
}

#[test]
fn format_grep_table_unicode_user_is_present() {
    let rows = vec![GrepRow {
        name: "notepad.exe".to_owned(),
        pid: 50,
        ppid: 1,
        user: "用户".to_owned(),
        arch: "x86".to_owned(),
    }];
    let table = format_grep_table(&rows);
    assert!(table.contains("用户"), "missing Unicode user:\n{table}");
}

#[test]
fn format_module_table_cjk_module_name_is_present() {
    let rows = vec![ModuleRow { name: "テスト.dll".to_owned(), base: 0x7FFE_0000_0000_0000 }];
    let table = format_module_table(&rows);
    assert!(table.contains("テスト.dll"), "missing CJK module name:\n{table}");
}

#[test]
fn format_process_table_empty_name_does_not_panic() {
    // Edge case: empty process name (could happen with malformed agent data)
    let rows = vec![make_process_row("", 1, 0)];
    let table = format_process_table(&rows);
    // Name column minimum width is 4 ("Name" header), so this should still work
    assert_eq!(table.lines().count(), 3, "expected 3 lines:\n{table}");
}
