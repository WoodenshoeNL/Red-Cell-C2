//! Tests for the builtin CONFIG and MEM_FILE command handlers.

use super::common::*;

use super::super::{CommandDispatchError, CommandDispatcher};
use crate::{AgentRegistry, Database, EventBus, SocketRelayManager};
use red_cell_common::demon::{DemonCommand, DemonConfigKey};
use red_cell_common::operator::OperatorMessage;
use serde_json::Value;
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn builtin_config_and_mem_file_handlers_update_agent_state_and_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0x5566_7788, test_key(0x56), test_iv(0x78));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    let mut config_payload = Vec::new();
    add_u32(&mut config_payload, u32::from(DemonConfigKey::WorkingHours));
    add_u32(&mut config_payload, 0b101010);
    dispatcher
        .dispatch(0x5566_7788, u32::from(DemonCommand::CommandConfig), 35, &config_payload)
        .await?;

    let event = receiver.recv().await.ok_or("agent update missing")?;
    let OperatorMessage::AgentUpdate(_) = event else {
        panic!("expected agent update event");
    };
    let event = receiver.recv().await.ok_or("config response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("WorkingHours has been set".to_owned()))
    );
    assert_eq!(
        registry.get(0x5566_7788).await.and_then(|agent| agent.working_hours),
        Some(0b101010)
    );

    let mut mem_file_payload = Vec::new();
    add_u32(&mut mem_file_payload, 0xAB);
    add_u32(&mut mem_file_payload, 1);
    dispatcher
        .dispatch(0x5566_7788, u32::from(DemonCommand::CommandMemFile), 36, &mem_file_payload)
        .await?;

    let event = receiver.recv().await.ok_or("mem file response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Memory file ab registered successfully".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn builtin_config_handler_preserves_high_bit_working_hours()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0x5566_7799, test_key(0x56), test_iv(0x78));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database.clone(),
        sockets,
        None,
    );
    let mut receiver = events.subscribe();
    let working_hours = 0x8000_002A;

    let mut config_payload = Vec::new();
    add_u32(&mut config_payload, u32::from(DemonConfigKey::WorkingHours));
    add_u32(&mut config_payload, working_hours);
    dispatcher
        .dispatch(0x5566_7799, u32::from(DemonCommand::CommandConfig), 37, &config_payload)
        .await?;

    let event = receiver.recv().await.ok_or("agent update missing")?;
    let OperatorMessage::AgentUpdate(_) = event else {
        panic!("expected agent update event");
    };
    let event = receiver.recv().await.ok_or("config response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("WorkingHours has been set".to_owned()))
    );
    let expected = Some(i32::from_be_bytes(working_hours.to_be_bytes()));
    assert_eq!(registry.get(0x5566_7799).await.and_then(|agent| agent.working_hours), expected);

    let persisted = database
        .agents()
        .get(0x5566_7799)
        .await?
        .ok_or_else(|| "agent should be persisted after config update".to_owned())?;
    assert_eq!(persisted.working_hours, expected);
    Ok(())
}

#[tokio::test]
async fn builtin_config_handler_rejects_kill_date_exceeding_i64_range()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0x5566_7800, test_key(0x56), test_iv(0x78));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database.clone(),
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    let mut config_payload = Vec::new();
    add_u32(&mut config_payload, u32::from(DemonConfigKey::KillDate));
    add_u64(&mut config_payload, i64::MAX as u64 + 1);
    let error = dispatcher
        .dispatch(0x5566_7800, u32::from(DemonCommand::CommandConfig), 38, &config_payload)
        .await
        .expect_err("overflowing kill date config must be rejected");

    assert!(matches!(
        error,
        CommandDispatchError::InvalidCallbackPayload { command_id, ref message }
            if command_id == u32::from(DemonCommand::CommandConfig)
                && message == "config kill date exceeds i64 range"
    ));
    assert_eq!(registry.get(0x5566_7800).await.and_then(|agent| agent.kill_date), None);
    let persisted = database
        .agents()
        .get(0x5566_7800)
        .await?
        .ok_or_else(|| "agent should still exist after rejected config update".to_owned())?;
    assert_eq!(persisted.kill_date, None);
    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "rejected config update should not broadcast events"
    );
    Ok(())
}

#[tokio::test]
async fn builtin_config_handler_kill_date_set_then_clear_and_sleep_update()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0x5566_7801, test_key(0x56), test_iv(0x78));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database.clone(),
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    // --- Step 1: Set kill_date to a future timestamp ---
    let future_timestamp: u64 = 1_893_456_000; // 2030-01-01 approx
    let mut config_payload = Vec::new();
    add_u32(&mut config_payload, u32::from(DemonConfigKey::KillDate));
    add_u64(&mut config_payload, future_timestamp);
    dispatcher
        .dispatch(0x5566_7801, u32::from(DemonCommand::CommandConfig), 40, &config_payload)
        .await?;

    // Drain agent-update + response events
    let event = receiver.recv().await.ok_or("agent update missing after kill_date set")?;
    let OperatorMessage::AgentUpdate(_) = event else {
        panic!("expected agent update event after kill_date set");
    };
    let event = receiver.recv().await.ok_or("config response missing after kill_date set")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event after kill_date set");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("KillDate has been set".to_owned()))
    );

    // Verify registry and database reflect the new kill_date
    assert_eq!(
        registry.get(0x5566_7801).await.and_then(|a| a.kill_date),
        Some(future_timestamp as i64)
    );
    let persisted = database.agents().get(0x5566_7801).await?.ok_or("agent missing")?;
    assert_eq!(persisted.kill_date, Some(future_timestamp as i64));

    // --- Step 2: Clear kill_date with kill_date = 0 ---
    let mut clear_payload = Vec::new();
    add_u32(&mut clear_payload, u32::from(DemonConfigKey::KillDate));
    add_u64(&mut clear_payload, 0);
    dispatcher
        .dispatch(0x5566_7801, u32::from(DemonCommand::CommandConfig), 41, &clear_payload)
        .await?;

    // Drain agent-update + response events
    let event = receiver.recv().await.ok_or("agent update missing after kill_date clear")?;
    let OperatorMessage::AgentUpdate(_) = event else {
        panic!("expected agent update event after kill_date clear");
    };
    let event = receiver.recv().await.ok_or("config response missing after kill_date clear")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event after kill_date clear");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("KillDate was disabled".to_owned()))
    );

    // Verify registry and database kill_date is cleared
    assert_eq!(registry.get(0x5566_7801).await.and_then(|a| a.kill_date), None);
    let persisted = database.agents().get(0x5566_7801).await?.ok_or("agent missing")?;
    assert_eq!(persisted.kill_date, None);

    // --- Step 3: Update sleep via sleep callback and verify ---
    let mut sleep_payload = Vec::new();
    add_u32(&mut sleep_payload, 30); // sleep_delay
    add_u32(&mut sleep_payload, 50); // sleep_jitter
    dispatcher
        .dispatch(0x5566_7801, u32::from(DemonCommand::CommandSleep), 42, &sleep_payload)
        .await?;

    // Drain agent-update + response events
    let event = receiver.recv().await.ok_or("agent update missing after sleep")?;
    let OperatorMessage::AgentUpdate(_) = event else {
        panic!("expected agent update event after sleep");
    };
    let event = receiver.recv().await.ok_or("sleep response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event after sleep");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Set sleep interval to 30 seconds with 50% jitter".to_owned()))
    );

    // Verify sleep values updated and kill_date still cleared
    let agent = registry.get(0x5566_7801).await.ok_or("agent missing")?;
    assert_eq!(agent.sleep_delay, 30);
    assert_eq!(agent.sleep_jitter, 50);
    assert_eq!(agent.kill_date, None);

    Ok(())
}

#[tokio::test]
async fn builtin_config_handler_memory_alloc() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xCF01_0001, test_key(0x56), test_iv(0x78));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonConfigKey::MemoryAlloc));
    add_u32(&mut payload, 0x40); // PAGE_EXECUTE_READWRITE
    dispatcher.dispatch(0xCF01_0001, u32::from(DemonCommand::CommandConfig), 100, &payload).await?;

    let event = receiver.recv().await.ok_or("config response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Default memory allocation set to 64".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn builtin_config_handler_memory_execute() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xCF01_0002, test_key(0x56), test_iv(0x78));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonConfigKey::MemoryExecute));
    add_u32(&mut payload, 0x20); // PAGE_EXECUTE_READ
    dispatcher.dispatch(0xCF01_0002, u32::from(DemonCommand::CommandConfig), 101, &payload).await?;

    let event = receiver.recv().await.ok_or("config response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Default memory executing set to 32".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn builtin_config_handler_inject_spawn64() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xCF01_0003, test_key(0x56), test_iv(0x78));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonConfigKey::InjectSpawn64));
    add_utf16(&mut payload, "C:\\Windows\\System32\\notepad.exe");
    dispatcher.dispatch(0xCF01_0003, u32::from(DemonCommand::CommandConfig), 102, &payload).await?;

    let event = receiver.recv().await.ok_or("config response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String(
            "Default x64 target process set to C:\\Windows\\System32\\notepad.exe".to_owned()
        ))
    );
    Ok(())
}

#[tokio::test]
async fn builtin_config_handler_inject_spawn32() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xCF01_0004, test_key(0x56), test_iv(0x78));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonConfigKey::InjectSpawn32));
    add_utf16(&mut payload, "C:\\Windows\\SysWOW64\\rundll32.exe");
    dispatcher.dispatch(0xCF01_0004, u32::from(DemonCommand::CommandConfig), 103, &payload).await?;

    let event = receiver.recv().await.ok_or("config response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String(
            "Default x86 target process set to C:\\Windows\\SysWOW64\\rundll32.exe".to_owned()
        ))
    );
    Ok(())
}

#[tokio::test]
async fn builtin_config_handler_implant_spf_thread_start() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xCF01_0005, test_key(0x56), test_iv(0x78));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonConfigKey::ImplantSpfThreadStart));
    add_bytes(&mut payload, b"ntdll.dll");
    add_bytes(&mut payload, b"RtlUserThreadStart");
    dispatcher.dispatch(0xCF01_0005, u32::from(DemonCommand::CommandConfig), 104, &payload).await?;

    let event = receiver.recv().await.ok_or("config response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String(
            "Sleep obfuscation spoof thread start addr to ntdll.dll!RtlUserThreadStart".to_owned()
        ))
    );
    Ok(())
}

#[tokio::test]
async fn builtin_config_handler_implant_sleep_technique() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xCF01_0006, test_key(0x56), test_iv(0x78));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonConfigKey::ImplantSleepTechnique));
    add_u32(&mut payload, 2);
    dispatcher.dispatch(0xCF01_0006, u32::from(DemonCommand::CommandConfig), 105, &payload).await?;

    let event = receiver.recv().await.ok_or("config response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Sleep obfuscation technique set to 2".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn builtin_config_handler_implant_coffee_veh() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xCF01_0007, test_key(0x56), test_iv(0x78));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    // Test with true
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonConfigKey::ImplantCoffeeVeh));
    add_u32(&mut payload, 1); // true
    dispatcher.dispatch(0xCF01_0007, u32::from(DemonCommand::CommandConfig), 106, &payload).await?;

    let event = receiver.recv().await.ok_or("config response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Coffee VEH set to true".to_owned()))
    );

    // Test with false
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonConfigKey::ImplantCoffeeVeh));
    add_u32(&mut payload, 0); // false
    dispatcher.dispatch(0xCF01_0007, u32::from(DemonCommand::CommandConfig), 107, &payload).await?;

    let event = receiver.recv().await.ok_or("config response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Coffee VEH set to false".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn builtin_config_handler_implant_coffee_threaded() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xCF01_0008, test_key(0x56), test_iv(0x78));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonConfigKey::ImplantCoffeeThreaded));
    add_u32(&mut payload, 1); // true
    dispatcher.dispatch(0xCF01_0008, u32::from(DemonCommand::CommandConfig), 108, &payload).await?;

    let event = receiver.recv().await.ok_or("config response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Coffee threading set to true".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn builtin_config_handler_inject_technique() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xCF01_0009, test_key(0x56), test_iv(0x78));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonConfigKey::InjectTechnique));
    add_u32(&mut payload, 3);
    dispatcher.dispatch(0xCF01_0009, u32::from(DemonCommand::CommandConfig), 109, &payload).await?;

    let event = receiver.recv().await.ok_or("config response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Set default injection technique to 3".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn builtin_config_handler_inject_spoof_addr() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xCF01_000A, test_key(0x56), test_iv(0x78));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonConfigKey::InjectSpoofAddr));
    add_bytes(&mut payload, b"kernel32.dll");
    add_bytes(&mut payload, b"CreateThread");
    dispatcher.dispatch(0xCF01_000A, u32::from(DemonCommand::CommandConfig), 110, &payload).await?;

    let event = receiver.recv().await.ok_or("config response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String(
            "Injection thread spoofing value set to kernel32.dll!CreateThread".to_owned()
        ))
    );
    Ok(())
}

#[tokio::test]
async fn builtin_config_handler_implant_verbose() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xCF01_000B, test_key(0x56), test_iv(0x78));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    // Test enabled
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonConfigKey::ImplantVerbose));
    add_u32(&mut payload, 1); // true
    dispatcher.dispatch(0xCF01_000B, u32::from(DemonCommand::CommandConfig), 111, &payload).await?;

    let event = receiver.recv().await.ok_or("config response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Implant verbose messaging: true".to_owned()))
    );

    // Test disabled
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonConfigKey::ImplantVerbose));
    add_u32(&mut payload, 0); // false
    dispatcher.dispatch(0xCF01_000B, u32::from(DemonCommand::CommandConfig), 112, &payload).await?;

    let event = receiver.recv().await.ok_or("config response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Implant verbose messaging: false".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn builtin_config_handler_working_hours_disabled() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xCF01_000C, test_key(0x56), test_iv(0x78));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonConfigKey::WorkingHours));
    add_u32(&mut payload, 0); // disable
    dispatcher.dispatch(0xCF01_000C, u32::from(DemonCommand::CommandConfig), 113, &payload).await?;

    let event = receiver.recv().await.ok_or("agent update missing")?;
    let OperatorMessage::AgentUpdate(_) = event else {
        panic!("expected agent update event");
    };
    let event = receiver.recv().await.ok_or("config response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("WorkingHours was disabled".to_owned()))
    );
    assert_eq!(registry.get(0xCF01_000C).await.and_then(|a| a.working_hours), None);
    Ok(())
}

#[tokio::test]
async fn builtin_config_handler_unknown_key_returns_error() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0xCF01_000D, test_key(0x56), test_iv(0x78));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );

    let mut payload = Vec::new();
    add_u32(&mut payload, 9999); // unknown config key
    let error = dispatcher
        .dispatch(0xCF01_000D, u32::from(DemonCommand::CommandConfig), 114, &payload)
        .await
        .expect_err("unknown config key must be rejected");

    assert!(matches!(
        error,
        CommandDispatchError::InvalidCallbackPayload { command_id, .. }
            if command_id == u32::from(DemonCommand::CommandConfig)
    ));
    Ok(())
}
