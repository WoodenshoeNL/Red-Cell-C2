//! Integration and unit tests for the command dispatch module.

mod checkin;
mod common;
mod filesystem;
mod network_token_kerberos;
mod output;
mod pivot_socket_transfer;
mod process;
use common::*;

use super::util::{
    windows_arch_label as checkin_windows_arch_label,
    windows_version_label as checkin_windows_version_label,
};
use super::{
    CommandDispatchError, CommandDispatcher, DownloadState, DownloadTracker, LootContext,
    loot_context, non_empty_option,
};
use crate::{AgentRegistry, Database, EventBus, Job, SocketRelayManager};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell_common::crypto::decrypt_agent_data;
use red_cell_common::demon::{
    DemonCallback, DemonCallbackError, DemonCommand, DemonConfigKey, DemonFilesystemCommand,
    DemonInfoClass, DemonInjectError, DemonJobCommand, DemonKerberosCommand, DemonMessage,
    DemonNetCommand, DemonPivotCommand, DemonProcessCommand, DemonSocketCommand, DemonSocketType,
    DemonTokenCommand, DemonTransferCommand,
};
use red_cell_common::operator::OperatorMessage;
use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Duration, timeout},
};

#[tokio::test]
async fn dispatch_errors_for_unregistered_commands() {
    let dispatcher = CommandDispatcher::new();
    let agent_id = 0x4141_4141_u32;
    let command_id = 0x9999_u32;
    let request_id = 7_u32;

    let err = dispatcher
        .dispatch(agent_id, command_id, request_id, b"payload")
        .await
        .expect_err("dispatch to unregistered command_id must return Err");

    assert!(
        matches!(
            err,
            CommandDispatchError::UnknownCommand {
                agent_id: a,
                command_id: c,
                request_id: r,
            } if a == agent_id && c == command_id && r == request_id
        ),
        "unexpected error variant: {err:?}"
    );
    assert!(!dispatcher.handles_command(command_id));
}

#[tokio::test]
async fn custom_handlers_receive_agent_request_and_payload()
-> Result<(), Box<dyn std::error::Error>> {
    let mut dispatcher = CommandDispatcher::default();
    dispatcher.register_handler(0x1234, |agent_id, request_id, payload| {
        Box::pin(async move {
            let mut response = agent_id.to_le_bytes().to_vec();
            response.extend_from_slice(&request_id.to_le_bytes());
            response.extend_from_slice(&payload);
            Ok(Some(response))
        })
    });

    let response = dispatcher.dispatch(0xAABB_CCDD, 0x1234, 0x0102_0304, b"abc").await?;

    assert_eq!(
        response,
        Some([0xDD, 0xCC, 0xBB, 0xAA, 0x04, 0x03, 0x02, 0x01, b'a', b'b', b'c',].to_vec())
    );
    assert!(dispatcher.handles_command(0x1234));
    Ok(())
}

#[tokio::test]
async fn dispatch_packages_concatenates_handler_responses() -> Result<(), Box<dyn std::error::Error>>
{
    let mut dispatcher = CommandDispatcher::new();
    dispatcher.register_handler(0x1111, |_, _, _| Box::pin(async move { Ok(Some(vec![1, 2])) }));
    dispatcher.register_handler(0x2222, |_, _, _| Box::pin(async move { Ok(Some(vec![3, 4])) }));

    let packages = vec![
        crate::DemonCallbackPackage { command_id: 0x1111, request_id: 1, payload: Vec::new() },
        crate::DemonCallbackPackage { command_id: 0x2222, request_id: 2, payload: Vec::new() },
    ];

    assert_eq!(dispatcher.dispatch_packages(0x1234_5678, &packages).await?, vec![1, 2, 3, 4]);
    Ok(())
}

#[tokio::test]
async fn collect_response_bytes_concatenates_all_child_package_responses()
-> Result<(), Box<dyn std::error::Error>> {
    let mut dispatcher = CommandDispatcher::new();
    dispatcher
        .register_handler(0x1111, |_, _, _| Box::pin(async move { Ok(Some(vec![0xAA, 0xBB])) }));
    dispatcher
        .register_handler(0x2222, |_, _, _| Box::pin(async move { Ok(Some(vec![0xCC, 0xDD])) }));

    let child_packages = vec![
        crate::DemonCallbackPackage { command_id: 0x1111, request_id: 17, payload: Vec::new() },
        crate::DemonCallbackPackage { command_id: 0x2222, request_id: 18, payload: Vec::new() },
    ];

    assert_eq!(
        dispatcher.collect_response_bytes(0x8765_4321, &child_packages).await?,
        vec![0xAA, 0xBB, 0xCC, 0xDD]
    );
    Ok(())
}

#[tokio::test]
async fn builtin_get_job_handler_serializes_and_drains_jobs()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets, None);
    let key = test_key(0x55);
    let iv = test_iv(0x22);
    let agent_id = 0x5566_7788;

    registry.insert(sample_agent_info(agent_id, key, iv)).await?;
    registry
        .enqueue_job(
            agent_id,
            Job {
                command: u32::from(DemonCommand::CommandSleep),
                request_id: 41,
                payload: vec![1, 2, 3, 4],
                command_line: "sleep 10".to_owned(),
                task_id: "task-41".to_owned(),
                created_at: "2026-03-09T20:10:00Z".to_owned(),
                operator: "operator".to_owned(),
            },
        )
        .await?;

    let response = dispatcher
        .dispatch(agent_id, u32::from(DemonCommand::CommandGetJob), 9, &[])
        .await?
        .ok_or_else(|| "get job should return serialized packages".to_owned())?;
    let message = red_cell_common::demon::DemonMessage::from_bytes(&response)?;

    assert_eq!(message.packages.len(), 1);
    assert_eq!(message.packages[0].command_id, u32::from(DemonCommand::CommandSleep));
    assert_eq!(message.packages[0].request_id, 41);
    assert_eq!(decrypt_agent_data(&key, &iv, &message.packages[0].payload)?, vec![1, 2, 3, 4]);
    assert!(registry.queued_jobs(agent_id).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn builtin_get_job_wraps_linked_child_jobs_through_pivot_chain()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets, None);
    let root_id = 0x0102_0304;
    let pivot_id = 0x1112_1314;
    let child_id = 0x2122_2324;
    let root_key = test_key(0x10);
    let root_iv = test_iv(0x20);
    let pivot_key = test_key(0x30);
    let pivot_iv = test_iv(0x40);
    let child_key = test_key(0x50);
    let child_iv = test_iv(0x60);

    registry.insert(sample_agent_info(root_id, root_key, root_iv)).await?;
    registry.insert(sample_agent_info(pivot_id, pivot_key, pivot_iv)).await?;
    registry.insert(sample_agent_info(child_id, child_key, child_iv)).await?;
    registry.add_link(root_id, pivot_id).await?;
    registry.add_link(pivot_id, child_id).await?;
    registry
        .enqueue_job(
            child_id,
            Job {
                command: u32::from(DemonCommand::CommandSleep),
                request_id: 77,
                payload: vec![9, 8, 7, 6],
                command_line: "sleep 5".to_owned(),
                task_id: "task-77".to_owned(),
                created_at: "2026-03-09T20:12:00Z".to_owned(),
                operator: "operator".to_owned(),
            },
        )
        .await?;

    let response = dispatcher
        .dispatch(root_id, u32::from(DemonCommand::CommandGetJob), 9, &[])
        .await?
        .ok_or_else(|| "get job should return serialized packages".to_owned())?;
    let message = DemonMessage::from_bytes(&response)?;
    assert_eq!(message.packages.len(), 1);
    assert_eq!(message.packages[0].command_id, u32::from(DemonCommand::CommandPivot));

    let first_layer = decrypt_agent_data(&root_key, &root_iv, &message.packages[0].payload)?;
    let (first_target, first_inner) = decode_pivot_payload(&first_layer)?;
    assert_eq!(first_target, pivot_id);

    let second_layer = DemonMessage::from_bytes(&first_inner)?;
    assert_eq!(second_layer.packages.len(), 1);
    let second_payload =
        decrypt_agent_data(&pivot_key, &pivot_iv, &second_layer.packages[0].payload)?;
    let (second_target, second_inner) = decode_pivot_payload(&second_payload)?;
    assert_eq!(second_target, child_id);

    let child_message = DemonMessage::from_bytes(&second_inner)?;
    assert_eq!(child_message.packages.len(), 1);
    assert_eq!(child_message.packages[0].command_id, u32::from(DemonCommand::CommandSleep));
    assert_eq!(child_message.packages[0].request_id, 77);
    assert_eq!(
        decrypt_agent_data(&child_key, &child_iv, &child_message.packages[0].payload)?,
        vec![9, 8, 7, 6]
    );
    Ok(())
}

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

// -----------------------------------------------------------------
// checkin_windows_arch_label
// -----------------------------------------------------------------

#[test]
fn windows_arch_label_known_values() {
    let cases: &[(u32, &str)] =
        &[(0, "x86"), (9, "x64/AMD64"), (5, "ARM"), (12, "ARM64"), (6, "Itanium-based")];
    for &(value, expected) in cases {
        assert_eq!(
            checkin_windows_arch_label(value),
            expected,
            "arch value {value} should map to \"{expected}\""
        );
    }
}

#[test]
fn windows_arch_label_unknown_falls_back() {
    for value in [2_u32, 3, 7, 8, 10, 11, 99, u32::MAX] {
        assert_eq!(
            checkin_windows_arch_label(value),
            "Unknown",
            "arch value {value} should map to \"Unknown\""
        );
    }
}

// -----------------------------------------------------------------
// checkin_windows_version_label
// -----------------------------------------------------------------

#[test]
fn windows_version_label_known_versions() {
    const WORKSTATION: u32 = 1;
    const SERVER: u32 = 3; // any value != VER_NT_WORKSTATION (1)

    let cases: &[((u32, u32, u32, u32, u32), &str)] = &[
        // (major, minor, product_type, service_pack, build) → expected prefix
        ((10, 0, SERVER, 0, 20_348), "Windows 2022 Server 22H2"),
        ((10, 0, SERVER, 0, 17_763), "Windows 2019 Server"),
        ((10, 0, WORKSTATION, 0, 22_000), "Windows 11"),
        ((10, 0, WORKSTATION, 0, 22_621), "Windows 11"),
        ((10, 0, SERVER, 0, 99_999), "Windows 2016 Server"),
        ((10, 0, WORKSTATION, 0, 19_045), "Windows 10"),
        ((6, 3, SERVER, 0, 0), "Windows Server 2012 R2"),
        ((6, 3, WORKSTATION, 0, 0), "Windows 8.1"),
        ((6, 2, SERVER, 0, 0), "Windows Server 2012"),
        ((6, 2, WORKSTATION, 0, 0), "Windows 8"),
        ((6, 1, SERVER, 0, 0), "Windows Server 2008 R2"),
        ((6, 1, WORKSTATION, 0, 0), "Windows 7"),
    ];
    for &((major, minor, product_type, sp, build), expected) in cases {
        let label = checkin_windows_version_label(major, minor, product_type, sp, build);
        assert_eq!(
            label, expected,
            "({major}, {minor}, {product_type}, {sp}, {build}) should produce \"{expected}\""
        );
    }
}

#[test]
fn windows_version_label_appends_service_pack() {
    // Windows 7 workstation with SP1
    let label = checkin_windows_version_label(6, 1, 1, 1, 0);
    assert_eq!(label, "Windows 7 Service Pack 1");

    // Windows Server 2008 R2 with SP2
    let label = checkin_windows_version_label(6, 1, 3, 2, 0);
    assert_eq!(label, "Windows Server 2008 R2 Service Pack 2");
}

#[test]
fn windows_version_label_no_service_pack_suffix_when_zero() {
    let label = checkin_windows_version_label(6, 1, 1, 0, 0);
    assert!(!label.contains("Service Pack"), "label should not contain service pack suffix");
}

#[test]
fn windows_version_label_unknown_falls_back() {
    let label = checkin_windows_version_label(5, 1, 1, 0, 0);
    assert_eq!(label, "Unknown");

    // Build in Windows 11 range but wrong product type for 2022 or 2019
    let label = checkin_windows_version_label(99, 0, 1, 0, 0);
    assert_eq!(label, "Unknown");
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

#[tokio::test]
async fn with_builtin_handlers_and_downloads_registers_all_builtin_commands()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());

    let custom_cap: usize = 2048;
    let tracker = DownloadTracker::new(custom_cap);
    let dispatcher = CommandDispatcher::with_builtin_handlers_and_downloads(
        registry,
        events,
        database,
        sockets,
        None,
        tracker,
        super::DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        true,
    );

    // Every built-in command must be registered.
    let expected_commands = [
        DemonCommand::CommandGetJob,
        DemonCommand::CommandCheckin,
        DemonCommand::CommandProcList,
        DemonCommand::CommandSleep,
        DemonCommand::CommandFs,
        DemonCommand::CommandProc,
        DemonCommand::CommandProcPpidSpoof,
        DemonCommand::CommandInjectShellcode,
        DemonCommand::CommandInjectDll,
        DemonCommand::CommandSpawnDll,
        DemonCommand::CommandOutput,
        DemonCommand::CommandError,
        DemonCommand::CommandExit,
        DemonCommand::CommandKillDate,
        DemonCommand::DemonInfo,
        DemonCommand::BeaconOutput,
        DemonCommand::CommandToken,
        DemonCommand::CommandInlineExecute,
        DemonCommand::CommandAssemblyInlineExecute,
        DemonCommand::CommandAssemblyListVersions,
        DemonCommand::CommandJob,
        DemonCommand::CommandNet,
        DemonCommand::CommandConfig,
        DemonCommand::CommandScreenshot,
        DemonCommand::CommandTransfer,
        DemonCommand::CommandKerberos,
        DemonCommand::CommandMemFile,
        DemonCommand::CommandPackageDropped,
        DemonCommand::CommandSocket,
        DemonCommand::CommandPivot,
    ];
    for cmd in &expected_commands {
        assert!(
            dispatcher.handles_command(u32::from(*cmd)),
            "built-in handler missing for {cmd:?} (0x{:08X})",
            u32::from(*cmd),
        );
    }

    // The custom tracker limits must be preserved.
    assert_eq!(dispatcher.downloads.max_download_bytes, custom_cap);
    assert_eq!(
        dispatcher.downloads.max_total_download_bytes,
        custom_cap.saturating_mul(super::DOWNLOAD_TRACKER_AGGREGATE_CAP_MULTIPLIER).max(custom_cap),
    );

    Ok(())
}

#[tokio::test]
async fn with_builtin_handlers_and_downloads_dispatches_known_builtin_command()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());

    let tracker = DownloadTracker::new(4096);
    let dispatcher = CommandDispatcher::with_builtin_handlers_and_downloads(
        registry.clone(),
        events,
        database,
        sockets,
        None,
        tracker,
        super::DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        true,
    );

    // Dispatching CommandGetJob for an agent with no queued jobs should return None
    // (no jobs to serialize), proving the handler ran rather than returning None because
    // no handler was found. We verify by first confirming the handler exists.
    assert!(dispatcher.handles_command(u32::from(DemonCommand::CommandGetJob)));

    let agent_id = 0xCAFE_0001;
    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    registry.insert(sample_agent_info(agent_id, key, iv)).await?;

    // With no queued jobs, CommandGetJob handler returns None (empty queue path).
    let result =
        dispatcher.dispatch(agent_id, u32::from(DemonCommand::CommandGetJob), 1, &[]).await?;
    assert!(result.is_none(), "empty job queue should return None");

    // Now enqueue a job and confirm the handler produces a response.
    registry
        .enqueue_job(
            agent_id,
            Job {
                command: u32::from(DemonCommand::CommandSleep),
                request_id: 42,
                payload: vec![0xDE, 0xAD],
                command_line: "sleep 5".to_owned(),
                task_id: "task-42".to_owned(),
                created_at: "2026-03-18T00:00:00Z".to_owned(),
                operator: "tester".to_owned(),
            },
        )
        .await?;

    let response =
        dispatcher.dispatch(agent_id, u32::from(DemonCommand::CommandGetJob), 2, &[]).await?;
    assert!(response.is_some(), "handler must return serialized job packages");

    Ok(())
}

#[test]
fn download_tracker_from_max_download_bytes_normal_value() {
    let tracker = DownloadTracker::from_max_download_bytes(1024);
    assert_eq!(tracker.max_download_bytes, 1024);
    assert_eq!(
        tracker.max_total_download_bytes,
        1024 * super::DOWNLOAD_TRACKER_AGGREGATE_CAP_MULTIPLIER,
    );
}

#[test]
fn download_tracker_from_max_download_bytes_saturates_large_u64() {
    // A value larger than usize::MAX (on any platform) must saturate to usize::MAX.
    let huge: u64 = u64::MAX;
    let tracker = DownloadTracker::from_max_download_bytes(huge);

    // The per-file cap saturates to usize::MAX.
    assert_eq!(tracker.max_download_bytes, usize::MAX);
    // The aggregate cap is at least the per-file cap (saturating_mul overflows to
    // usize::MAX, and .max() ensures it is >= max_download_bytes).
    assert!(tracker.max_total_download_bytes >= tracker.max_download_bytes);
}

#[test]
fn download_tracker_from_max_download_bytes_zero() {
    let tracker = DownloadTracker::from_max_download_bytes(0);
    assert_eq!(tracker.max_download_bytes, 0);
    // 0 * multiplier = 0, .max(0) = 0
    assert_eq!(tracker.max_total_download_bytes, 0);
}

#[test]
fn download_tracker_from_max_download_bytes_one() {
    let tracker = DownloadTracker::from_max_download_bytes(1);
    assert_eq!(tracker.max_download_bytes, 1);
    assert_eq!(tracker.max_total_download_bytes, super::DOWNLOAD_TRACKER_AGGREGATE_CAP_MULTIPLIER,);
}

// ---- non_empty_option tests ----

#[test]
fn non_empty_option_empty_string_returns_none() {
    assert_eq!(non_empty_option(""), None);
}

#[test]
fn non_empty_option_non_empty_returns_some() {
    assert_eq!(non_empty_option("value"), Some("value".to_owned()));
}

#[test]
fn non_empty_option_whitespace_only_returns_some() {
    // Whitespace-only is not empty — the function checks `.is_empty()`, not `.trim()`.
    assert_eq!(non_empty_option("  "), Some("  ".to_owned()));
}

#[test]
fn non_empty_option_single_char_returns_some() {
    assert_eq!(non_empty_option("x"), Some("x".to_owned()));
}

// ---- loot_context tests ----

#[tokio::test]
async fn loot_context_unknown_agent_returns_default() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    let registry = AgentRegistry::new(database);
    let unknown_agent_id = 0xDEAD_0001;
    let request_id = 42;

    let ctx = loot_context(&registry, unknown_agent_id, request_id).await;

    assert_eq!(ctx, LootContext::default());
    assert!(ctx.operator.is_empty());
    assert!(ctx.command_line.is_empty());
    assert!(ctx.task_id.is_empty());
    assert!(ctx.queued_at.is_empty());
}

#[tokio::test]
async fn loot_context_known_agent_unknown_request_id_returns_default() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    let registry = AgentRegistry::new(database);

    // Register an agent so the agent_id is known.
    let agent_id = 0x1234_5678;
    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    let info = sample_agent_info(agent_id, key, iv);
    registry.insert(info).await.expect("agent should register");

    // Use a request_id that was never enqueued.
    let unknown_request_id = 0xFFFF;
    let ctx = loot_context(&registry, agent_id, unknown_request_id).await;

    assert_eq!(ctx, LootContext::default());
    assert!(ctx.operator.is_empty());
    assert!(ctx.command_line.is_empty());
    assert!(ctx.task_id.is_empty());
    assert!(ctx.queued_at.is_empty());
}
