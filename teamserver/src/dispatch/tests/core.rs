//! Core dispatch tests: registration, routing, packages, and built-in handler integration.

use super::common::*;
use crate::dispatch::{CommandDispatchError, CommandDispatcher, DownloadTracker};
use crate::{AgentRegistry, Database, DemonInitSecretConfig, EventBus, Job, SocketRelayManager};
use red_cell_common::crypto::decrypt_agent_data;
use red_cell_common::demon::{DemonCommand, DemonMessage};

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

    assert_eq!(
        dispatcher
            .dispatch_packages(0x1234_5678, &packages, crate::dispatch::PayloadEndian::Le)
            .await?,
        vec![1, 2, 3, 4]
    );
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
        crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        true,
        DemonInitSecretConfig::None,
    );

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

    assert_eq!(dispatcher.downloads.max_download_bytes, custom_cap);
    assert_eq!(
        dispatcher.downloads.max_total_download_bytes,
        custom_cap
            .saturating_mul(crate::dispatch::DOWNLOAD_TRACKER_AGGREGATE_CAP_MULTIPLIER)
            .max(custom_cap),
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
        crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        true,
        DemonInitSecretConfig::None,
    );

    assert!(dispatcher.handles_command(u32::from(DemonCommand::CommandGetJob)));

    let agent_id = 0xCAFE_0001;
    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    registry.insert(sample_agent_info(agent_id, key, iv)).await?;

    let result =
        dispatcher.dispatch(agent_id, u32::from(DemonCommand::CommandGetJob), 1, &[]).await?;
    assert!(result.is_none(), "empty job queue should return None");

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
