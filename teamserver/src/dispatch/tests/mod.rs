//! Integration and unit tests for the command dispatch module.

mod checkin;
mod common;
mod output;
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
async fn pivot_connect_callback_registers_child_and_link() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets, None);
    let parent_id = 0x4546_4748;
    let parent_key = test_key(0x21);
    let parent_iv = test_iv(0x31);
    let child_id = 0x5152_5354;
    let child_key = test_key(0x41);
    let child_iv = test_iv(0x51);

    registry
        .insert_with_listener(sample_agent_info(parent_id, parent_key, parent_iv), "http-main")
        .await?;

    let response = dispatcher
        .dispatch(
            parent_id,
            u32::from(DemonCommand::CommandPivot),
            17,
            &pivot_connect_payload(&valid_demon_init_body_monotonic(child_id, child_key, child_iv)),
        )
        .await?;

    assert_eq!(response, None);
    assert_eq!(registry.parent_of(child_id).await, Some(parent_id));
    assert_eq!(registry.children_of(parent_id).await, vec![child_id]);
    assert!(registry.get(child_id).await.is_some());
    let event = receiver
        .recv()
        .await
        .ok_or_else(|| "expected AgentNew event after pivot connect".to_owned())?;
    let red_cell_common::operator::OperatorMessage::AgentNew(message) = event else {
        return Err("expected AgentNew event after pivot connect".into());
    };
    assert_eq!(message.info.name_id, "51525354");
    assert_eq!(message.info.listener, "http-main");
    assert_eq!(message.info.pivots.parent.as_deref(), Some("45464748"));
    assert_eq!(message.info.pivots.links, Vec::<String>::new());
    assert_eq!(message.info.pivot_parent, "45464748");
    Ok(())
}

#[tokio::test]
async fn pivot_connect_callback_child_snapshot_preserves_listener_provenance()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets, None);
    let parent_id = 0xAABB_CCDD;
    let parent_key = test_key(0x11);
    let parent_iv = test_iv(0x22);
    let child_id = 0x1122_3344;
    let child_key = test_key(0x33);
    let child_iv = test_iv(0x44);

    registry
        .insert_with_listener(sample_agent_info(parent_id, parent_key, parent_iv), "http-external")
        .await?;

    dispatcher
        .dispatch(
            parent_id,
            u32::from(DemonCommand::CommandPivot),
            42,
            &pivot_connect_payload(&valid_demon_init_body_monotonic(child_id, child_key, child_iv)),
        )
        .await?;

    // The child's persisted listener_name must match the parent's — not "null".
    assert_eq!(
        registry.listener_name(child_id).await.as_deref(),
        Some("http-external"),
        "child pivot listener_name must inherit the parent's listener, not be 'null'"
    );
    Ok(())
}

fn pivot_connect_failure_payload(error_code: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(DemonPivotCommand::SmbConnect).to_le_bytes());
    payload.extend_from_slice(&0_u32.to_le_bytes()); // success == 0
    payload.extend_from_slice(&error_code.to_le_bytes());
    payload
}

#[tokio::test]
async fn pivot_connect_callback_failure_broadcasts_error_event()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets, None);
    let parent_id = 0x1234_5678;
    let parent_key = test_key(0xAA);
    let parent_iv = test_iv(0xBB);
    registry
        .insert_with_listener(sample_agent_info(parent_id, parent_key, parent_iv), "http-main")
        .await?;

    // ERROR_ACCESS_DENIED = 5
    let response = dispatcher
        .dispatch(
            parent_id,
            u32::from(DemonCommand::CommandPivot),
            99,
            &pivot_connect_failure_payload(5),
        )
        .await?;

    assert_eq!(response, None, "failure path should return no agent response bytes");

    // No new agent should have been registered.
    assert_eq!(registry.children_of(parent_id).await, Vec::<u32>::new());

    let event =
        receiver.recv().await.ok_or("expected an operator event after pivot connect failure")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        return Err(format!("expected AgentResponse, got {event:?}").into());
    };
    assert_eq!(msg.info.demon_id, format!("{parent_id:08X}"), "event must be for the parent agent");
    let msg_text = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg_text.contains("Failed to connect"), "message must mention failure: {:?}", msg_text);
    assert!(msg_text.contains("[5]"), "message must include numeric error code: {:?}", msg_text);
    let kind = msg.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(kind, "Error", "message type must be Error");
    let request_id_str = msg.info.extra.get("RequestID").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(request_id_str, "63", "request id must be 99 in hex");
    Ok(())
}

fn pivot_disconnect_failure_payload(child_agent_id: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(DemonPivotCommand::SmbDisconnect).to_le_bytes());
    payload.extend_from_slice(&0_u32.to_le_bytes()); // success == 0
    payload.extend_from_slice(&child_agent_id.to_le_bytes());
    payload
}

#[tokio::test]
async fn pivot_disconnect_callback_failure_broadcasts_error_event()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets, None);
    let parent_id = 0xABCD_1234_u32;
    let child_id = 0x5678_EF01_u32;
    let parent_key = test_key(0xCC);
    let parent_iv = test_iv(0xDD);
    registry
        .insert_with_listener(sample_agent_info(parent_id, parent_key, parent_iv), "smb-test")
        .await?;

    let response = dispatcher
        .dispatch(
            parent_id,
            u32::from(DemonCommand::CommandPivot),
            42,
            &pivot_disconnect_failure_payload(child_id),
        )
        .await?;

    assert_eq!(response, None, "failure path should return no agent response bytes");

    let event =
        receiver.recv().await.ok_or("expected an operator event after pivot disconnect failure")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        return Err(format!("expected AgentResponse, got {event:?}").into());
    };
    assert_eq!(msg.info.demon_id, format!("{parent_id:08X}"), "event must be for the parent agent");
    let msg_text = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        msg_text.contains("Failed to disconnect"),
        "message must mention disconnect failure: {:?}",
        msg_text
    );
    assert!(
        msg_text.contains(&format!("{child_id:08X}")),
        "message must include child agent id: {:?}",
        msg_text
    );
    let kind = msg.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(kind, "Error", "message type must be Error");
    Ok(())
}

fn pivot_list_payload(entries: &[(u32, &str)]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(DemonPivotCommand::List).to_le_bytes());
    for (demon_id, pipe_name) in entries {
        payload.extend_from_slice(&demon_id.to_le_bytes());
        let utf16: Vec<u16> = pipe_name.encode_utf16().collect();
        let utf16_bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
        let len = u32::try_from(utf16_bytes.len()).expect("test data fits in u32");
        payload.extend_from_slice(&len.to_le_bytes());
        payload.extend_from_slice(&utf16_bytes);
    }
    payload
}

#[tokio::test]
async fn pivot_list_callback_demon_id_is_zero_padded_on_left()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets, None);
    let agent_id = 0xAAAA_BBBB;
    let key = test_key(0x11);
    let iv = test_iv(0x22);
    registry.insert(sample_agent_info(agent_id, key, iv)).await?;

    // demon_id = 0x1 is only 1 hex digit — must be padded to "00000001", not "10000000"
    let response = dispatcher
        .dispatch(
            agent_id,
            u32::from(DemonCommand::CommandPivot),
            100,
            &pivot_list_payload(&[(0x1, "\\\\.\\pipe\\test")]),
        )
        .await?;

    assert_eq!(response, None);
    let event = receiver
        .recv()
        .await
        .ok_or_else(|| "expected AgentResponse event after pivot list".to_owned())?;
    let OperatorMessage::AgentResponse(msg) = event else {
        return Err("expected AgentResponse".into());
    };
    let output = &msg.info.output;
    assert!(
        output.contains("00000001"),
        "demon id 0x1 must be right-aligned zero-padded to '00000001', got: {output}"
    );
    assert!(
        !output.contains("10000000"),
        "demon id 0x1 must NOT be left-aligned to '10000000', got: {output}"
    );
    Ok(())
}

#[tokio::test]
async fn pivot_list_callback_with_entries_broadcasts_formatted_table()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets, None);
    let agent_id = 0xAAAA_BBBB;
    let key = test_key(0x11);
    let iv = test_iv(0x22);
    registry.insert(sample_agent_info(agent_id, key, iv)).await?;

    let response = dispatcher
        .dispatch(
            agent_id,
            u32::from(DemonCommand::CommandPivot),
            99,
            &pivot_list_payload(&[
                (0x1234_5678, "\\\\.\\pipe\\foo"),
                (0xDEAD_BEEF, "\\\\.\\pipe\\bar"),
            ]),
        )
        .await?;

    assert_eq!(response, None);
    let event = receiver
        .recv()
        .await
        .ok_or_else(|| "expected AgentResponse event after pivot list".to_owned())?;
    let OperatorMessage::AgentResponse(msg) = event else {
        return Err("expected AgentResponse".into());
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.extra.get("Type"), Some(&Value::String("Info".to_owned())));
    let message = msg.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(message.contains("Pivot List [2]"), "message: {message}");
    let output = &msg.info.output;
    assert!(output.contains("12345678"), "output: {output}");
    assert!(output.contains("pipe\\foo"), "output: {output}");
    assert!(output.contains("deadbeef"), "output: {output}");
    assert!(output.contains("pipe\\bar"), "output: {output}");
    Ok(())
}

#[tokio::test]
async fn pivot_list_callback_empty_broadcasts_no_pivots_message()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets, None);
    let agent_id = 0xCCCC_DDDD;
    let key = test_key(0x33);
    let iv = test_iv(0x44);
    registry.insert(sample_agent_info(agent_id, key, iv)).await?;

    let response = dispatcher
        .dispatch(agent_id, u32::from(DemonCommand::CommandPivot), 77, &pivot_list_payload(&[]))
        .await?;

    assert_eq!(response, None);
    let event = receiver
        .recv()
        .await
        .ok_or_else(|| "expected AgentResponse event after empty pivot list".to_owned())?;
    let OperatorMessage::AgentResponse(msg) = event else {
        return Err("expected AgentResponse".into());
    };
    assert_eq!(msg.info.extra.get("Type"), Some(&Value::String("Info".to_owned())));
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String("No pivots connected".to_owned()))
    );
    assert!(
        msg.info.output.is_empty(),
        "output should be empty for no pivots: {}",
        msg.info.output
    );
    Ok(())
}

#[tokio::test]
async fn pivot_connect_failure_unknown_error_code_omits_name()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets, None);
    let parent_id = 0x8182_8384;
    let parent_key = test_key(0x81);
    let parent_iv = test_iv(0x82);
    registry
        .insert_with_listener(sample_agent_info(parent_id, parent_key, parent_iv), "http-main")
        .await?;

    // Error code 9999 is not in win32_error_code_name — should produce "[9999]" without a name.
    let response = dispatcher
        .dispatch(
            parent_id,
            u32::from(DemonCommand::CommandPivot),
            33,
            &pivot_connect_failure_payload(9999),
        )
        .await?;

    assert_eq!(response, None);
    let event = receiver.recv().await.ok_or("expected error event for unknown error code")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        return Err(format!("expected AgentResponse, got {event:?}").into());
    };
    let msg_text = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg_text.contains("[9999]"), "message must include numeric error code: {msg_text:?}");
    // The message should NOT contain a named error — just the bracketed code.
    assert_eq!(
        msg_text, "[SMB] Failed to connect: [9999]",
        "unknown error code should produce message without error name"
    );
    Ok(())
}

fn pivot_disconnect_success_payload(child_agent_id: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(DemonPivotCommand::SmbDisconnect).to_le_bytes());
    payload.extend_from_slice(&1_u32.to_le_bytes()); // success == 1
    payload.extend_from_slice(&child_agent_id.to_le_bytes());
    payload
}

#[tokio::test]
async fn pivot_disconnect_callback_success_marks_affected_and_broadcasts_info()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets, None);
    let parent_id = 0x9192_9394;
    let child_id = 0xA1A2_A3A4;
    let parent_key = test_key(0x91);
    let parent_iv = test_iv(0x92);
    let child_key = test_key(0xA1);
    let child_iv = test_iv(0xA2);

    // Register parent and child, then link them.
    registry
        .insert_with_listener(sample_agent_info(parent_id, parent_key, parent_iv), "smb-test")
        .await?;
    registry
        .insert_with_listener(sample_agent_info(child_id, child_key, child_iv), "smb-test")
        .await?;
    registry.add_link(parent_id, child_id).await?;
    assert_eq!(registry.parent_of(child_id).await, Some(parent_id));

    let response = dispatcher
        .dispatch(
            parent_id,
            u32::from(DemonCommand::CommandPivot),
            88,
            &pivot_disconnect_success_payload(child_id),
        )
        .await?;

    assert_eq!(response, None);

    // First event: AgentUpdate (mark) for the disconnected child.
    let event = receiver.recv().await.ok_or("expected AgentUpdate event for disconnected child")?;
    let OperatorMessage::AgentUpdate(mark_msg) = event else {
        return Err(format!("expected AgentUpdate (mark), got {event:?}").into());
    };
    assert_eq!(mark_msg.info.agent_id, format!("{child_id:08X}"));
    assert_eq!(mark_msg.info.marked, "Dead", "disconnected agent must be marked Dead");

    // Second event: AgentResponse with Info about successful disconnect.
    let event = receiver.recv().await.ok_or("expected AgentResponse event after disconnect")?;
    let OperatorMessage::AgentResponse(resp_msg) = event else {
        return Err(format!("expected AgentResponse, got {event:?}").into());
    };
    assert_eq!(resp_msg.info.demon_id, format!("{parent_id:08X}"));
    let kind = resp_msg.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(kind, "Info", "successful disconnect must emit Info type");
    let msg_text = resp_msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        msg_text.contains(&format!("{child_id:08X}")),
        "message must include child agent id: {msg_text:?}"
    );
    assert!(msg_text.contains("disconnected"), "message must mention disconnection: {msg_text:?}");

    // Link should be removed.
    assert_eq!(
        registry.parent_of(child_id).await,
        None,
        "child should no longer have parent after disconnect"
    );
    assert_eq!(
        registry.children_of(parent_id).await,
        Vec::<u32>::new(),
        "parent should have no children after disconnect"
    );
    Ok(())
}

#[tokio::test]
async fn pivot_disconnect_callback_success_no_link_emits_response_without_marks()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets, None);
    let parent_id = 0xB1B2_B3B4;
    let child_id = 0xC1C2_C3C4;
    let parent_key = test_key(0xB1);
    let parent_iv = test_iv(0xB2);

    // Only register parent — no link exists to child.
    registry
        .insert_with_listener(sample_agent_info(parent_id, parent_key, parent_iv), "smb-test")
        .await?;

    let response = dispatcher
        .dispatch(
            parent_id,
            u32::from(DemonCommand::CommandPivot),
            44,
            &pivot_disconnect_success_payload(child_id),
        )
        .await?;

    assert_eq!(response, None);

    // With no link, disconnect_link returns empty affected list, so the only event
    // should be the AgentResponse Info — no AgentUpdate marks.
    let event = receiver.recv().await.ok_or("expected AgentResponse event")?;
    let OperatorMessage::AgentResponse(resp_msg) = event else {
        return Err(format!("expected AgentResponse, got {event:?}").into());
    };
    let kind = resp_msg.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(kind, "Info");
    let msg_text = resp_msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg_text.contains(&format!("{child_id:08X}")));
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_download_handler_persists_loot_and_progress()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF11, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database.clone(), sockets, None);

    let file_id = 0x33_u32;
    let remote_path = "C:\\Temp\\sam.dump";
    let content = b"secret-bytes";

    let mut open = Vec::new();
    add_u32(&mut open, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut open, 0);
    add_u32(&mut open, file_id);
    add_u64(&mut open, u64::try_from(content.len())?);
    add_utf16(&mut open, remote_path);
    dispatcher.dispatch(0xABCD_EF11, u32::from(DemonCommand::CommandFs), 0x99, &open).await?;

    let mut write = Vec::new();
    add_u32(&mut write, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut write, 1);
    add_u32(&mut write, file_id);
    add_bytes(&mut write, content);
    dispatcher.dispatch(0xABCD_EF11, u32::from(DemonCommand::CommandFs), 0x99, &write).await?;

    let mut close = Vec::new();
    add_u32(&mut close, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut close, 2);
    add_u32(&mut close, file_id);
    add_u32(&mut close, 0);
    dispatcher.dispatch(0xABCD_EF11, u32::from(DemonCommand::CommandFs), 0x99, &close).await?;

    let first = receiver.recv().await.ok_or("missing open event")?;
    let second = receiver.recv().await.ok_or("missing progress event")?;
    let third = receiver.recv().await.ok_or("missing loot event")?;
    let fourth = receiver.recv().await.ok_or("missing completion event")?;

    let OperatorMessage::AgentResponse(open_message) = first else {
        panic!("expected download open response");
    };
    assert_eq!(
        open_message.info.extra.get("MiscType"),
        Some(&Value::String("download-progress".to_owned()))
    );

    let OperatorMessage::AgentResponse(progress_message) = second else {
        panic!("expected download progress response");
    };
    assert_eq!(
        progress_message.info.extra.get("CurrentSize"),
        Some(&Value::String(content.len().to_string()))
    );

    let OperatorMessage::AgentResponse(loot_message) = third else {
        panic!("expected loot event");
    };
    assert_eq!(
        loot_message.info.extra.get("MiscType"),
        Some(&Value::String("loot-new".to_owned()))
    );

    let OperatorMessage::AgentResponse(done_message) = fourth else {
        panic!("expected download completion response");
    };
    assert_eq!(
        done_message.info.extra.get("MiscType"),
        Some(&Value::String("download".to_owned()))
    );
    assert_eq!(
        done_message.info.extra.get("MiscData"),
        Some(&Value::String(BASE64_STANDARD.encode(content)))
    );

    let loot = database.loot().list_for_agent(0xABCD_EF11).await?;
    assert_eq!(loot.len(), 1);
    assert_eq!(loot[0].kind, "download");
    assert_eq!(loot[0].file_path.as_deref(), Some(remote_path));
    assert_eq!(loot[0].data.as_deref(), Some(content.as_slice()));
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_download_handler_accumulates_multi_chunk_downloads_until_close()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF12, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database.clone(), sockets, None);

    let file_id = 0x34_u32;
    let remote_path = "C:\\Temp\\partial.dump";

    dispatcher
        .dispatch(
            0xABCD_EF12,
            u32::from(DemonCommand::CommandFs),
            0x9A,
            &filesystem_download_open(file_id, 64, remote_path),
        )
        .await?;
    dispatcher
        .dispatch(
            0xABCD_EF12,
            u32::from(DemonCommand::CommandFs),
            0x9A,
            &filesystem_download_write(file_id, b"secret-"),
        )
        .await?;
    dispatcher
        .dispatch(
            0xABCD_EF12,
            u32::from(DemonCommand::CommandFs),
            0x9A,
            &filesystem_download_write(file_id, b"bytes"),
        )
        .await?;

    assert!(database.loot().list_for_agent(0xABCD_EF12).await?.is_empty());

    let _ = receiver.recv().await.ok_or("missing filesystem open event")?;
    let progress_one = receiver.recv().await.ok_or("missing first filesystem progress event")?;
    let progress_two = receiver.recv().await.ok_or("missing second filesystem progress event")?;

    let OperatorMessage::AgentResponse(progress_one) = progress_one else {
        panic!("expected first filesystem progress response");
    };
    assert_eq!(progress_one.info.extra.get("CurrentSize"), Some(&Value::String("7".to_owned())));
    assert_eq!(progress_one.info.extra.get("ExpectedSize"), Some(&Value::String("64".to_owned())));

    let OperatorMessage::AgentResponse(progress_two) = progress_two else {
        panic!("expected second filesystem progress response");
    };
    assert_eq!(progress_two.info.extra.get("CurrentSize"), Some(&Value::String("12".to_owned())));
    assert_eq!(progress_two.info.extra.get("ExpectedSize"), Some(&Value::String("64".to_owned())));
    let active = dispatcher.downloads.active_for_agent(0xABCD_EF12).await;
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].0, file_id);
    assert_eq!(active[0].1.request_id, 0x9A);
    assert_eq!(active[0].1.remote_path, remote_path);
    assert_eq!(active[0].1.expected_size, 64);
    assert_eq!(active[0].1.data, b"secret-bytes");
    assert!(
        !active[0].1.started_at.is_empty(),
        "active filesystem download should preserve its start timestamp"
    );
    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "filesystem download should remain incomplete until close"
    );

    dispatcher
        .dispatch(
            0xABCD_EF12,
            u32::from(DemonCommand::CommandFs),
            0x9A,
            &filesystem_download_close(file_id, 0),
        )
        .await?;

    let _ = receiver.recv().await.ok_or("missing filesystem loot event")?;
    let completion = receiver.recv().await.ok_or("missing filesystem completion event")?;
    let OperatorMessage::AgentResponse(completion) = completion else {
        panic!("expected filesystem completion response");
    };
    assert_eq!(
        completion.info.extra.get("MiscData"),
        Some(&Value::String(BASE64_STANDARD.encode(b"secret-bytes")))
    );

    let loot = database.loot().list_for_agent(0xABCD_EF12).await?;
    assert_eq!(loot.len(), 1);
    assert_eq!(loot[0].data.as_deref(), Some(b"secret-bytes".as_slice()));
    assert_eq!(loot[0].file_path.as_deref(), Some(remote_path));
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_download_handler_rejects_writes_without_open()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF13, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database.clone(), sockets, None);

    let error = dispatcher
        .dispatch(
            0xABCD_EF13,
            u32::from(DemonCommand::CommandFs),
            0x9B,
            &filesystem_download_write(0x35, b"orphan"),
        )
        .await
        .expect_err("filesystem download write without open should fail");
    assert!(matches!(
        error,
        CommandDispatchError::InvalidCallbackPayload {
            command_id,
            message,
        } if command_id == 0
            && message.contains("0x00000035")
            && message.contains("was not opened")
    ));
    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "unexpected events for rejected filesystem download write"
    );
    assert!(database.loot().list_for_agent(0xABCD_EF13).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn download_tracker_accumulates_multi_chunk_data_until_finish() {
    let tracker = DownloadTracker::new(64);
    tracker
        .start(
            0xABCD_EF51,
            0x41,
            DownloadState {
                request_id: 0x71,
                remote_path: "C:\\Temp\\multi.bin".to_owned(),
                expected_size: 32,
                data: Vec::new(),
                started_at: "2026-03-11T09:00:00Z".to_owned(),
            },
        )
        .await
        .expect("start should succeed");

    let first = tracker.append(0xABCD_EF51, 0x41, b"abc").await.expect("first chunk should append");
    assert_eq!(first.data, b"abc");
    assert_eq!(first.expected_size, 32);

    let second =
        tracker.append(0xABCD_EF51, 0x41, b"def").await.expect("second chunk should append");
    assert_eq!(second.data, b"abcdef");
    assert_eq!(second.expected_size, 32);

    let finished = tracker.finish(0xABCD_EF51, 0x41).await;
    assert_eq!(
        finished,
        Some(DownloadState {
            request_id: 0x71,
            remote_path: "C:\\Temp\\multi.bin".to_owned(),
            expected_size: 32,
            data: b"abcdef".to_vec(),
            started_at: "2026-03-11T09:00:00Z".to_owned(),
        })
    );
    assert_eq!(tracker.finish(0xABCD_EF51, 0x41).await, None);
}

#[tokio::test]
async fn download_tracker_keeps_partial_downloads_active_until_finish() {
    let tracker = DownloadTracker::new(64);
    tracker
        .start(
            0xABCD_EF54,
            0x44,
            DownloadState {
                request_id: 0x73,
                remote_path: "C:\\Temp\\pending.bin".to_owned(),
                expected_size: 32,
                data: Vec::new(),
                started_at: "2026-03-11T09:10:00Z".to_owned(),
            },
        )
        .await
        .expect("start should succeed");

    let partial =
        tracker.append(0xABCD_EF54, 0x44, b"partial").await.expect("partial chunk should append");
    assert_eq!(partial.data, b"partial");
    assert_eq!(partial.expected_size, 32);

    let active = tracker.active_for_agent(0xABCD_EF54).await;
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].0, 0x44);
    assert_eq!(active[0].1, partial);

    assert_eq!(tracker.active_for_agent(0xABCD_EF99).await, Vec::new());
    assert_eq!(tracker.finish(0xABCD_EF54, 0x44).await, Some(partial));
}

#[tokio::test]
async fn download_tracker_drain_agent_discards_all_partial_downloads_for_agent() {
    let tracker = DownloadTracker::with_limits(64, 128);

    for (agent_id, file_id, data) in [
        (0xABCD_EF57, 0x70_u32, b"first".as_slice()),
        (0xABCD_EF57, 0x71_u32, b"second".as_slice()),
        (0xABCD_EF58, 0x72_u32, b"third".as_slice()),
    ] {
        tracker
            .start(
                agent_id,
                file_id,
                DownloadState {
                    request_id: file_id,
                    remote_path: format!("C:\\Temp\\{file_id:08x}.bin"),
                    expected_size: 32,
                    data: Vec::new(),
                    started_at: "2026-03-11T09:25:00Z".to_owned(),
                },
            )
            .await
            .expect("start should succeed");
        let state = tracker.append(agent_id, file_id, data).await.expect("chunk should append");
        assert_eq!(state.data, data);
    }

    assert_eq!(tracker.buffered_bytes().await, 16);
    assert_eq!(tracker.drain_agent(0xABCD_EF57).await, 2);
    assert!(tracker.active_for_agent(0xABCD_EF57).await.is_empty());
    assert_eq!(tracker.buffered_bytes().await, 5);
    assert_eq!(tracker.active_for_agent(0xABCD_EF58).await.len(), 1);
    assert_eq!(tracker.drain_agent(0xABCD_EF57).await, 0);
}

#[tokio::test]
async fn download_tracker_rejects_chunks_for_unknown_downloads() {
    let tracker = DownloadTracker::new(64);

    let error = tracker
        .append(0xABCD_EF52, 0x42, b"orphan")
        .await
        .expect_err("append without start should fail");
    assert!(matches!(
        error,
        CommandDispatchError::InvalidCallbackPayload {
            command_id,
            message,
        } if command_id == 0
            && message.contains("0x00000042")
            && message.contains("was not opened")
    ));
}

#[tokio::test]
async fn download_tracker_drops_downloads_that_exceed_the_size_cap() {
    let tracker = DownloadTracker::new(4);
    tracker
        .start(
            0xABCD_EF53,
            0x43,
            DownloadState {
                request_id: 0x72,
                remote_path: "C:\\Temp\\oversized.bin".to_owned(),
                expected_size: 16,
                data: Vec::new(),
                started_at: "2026-03-11T09:05:00Z".to_owned(),
            },
        )
        .await
        .expect("start should succeed");

    let partial =
        tracker.append(0xABCD_EF53, 0x43, b"12").await.expect("first partial chunk should append");
    assert_eq!(partial.data, b"12");

    let error = tracker
        .append(0xABCD_EF53, 0x43, b"345")
        .await
        .expect_err("downloads above the cap should be dropped");
    assert!(matches!(
        error,
        CommandDispatchError::DownloadTooLarge {
            agent_id: 0xABCD_EF53,
            file_id: 0x43,
            max_download_bytes: 4,
        }
    ));
    assert_eq!(tracker.finish(0xABCD_EF53, 0x43).await, None);
}

#[tokio::test]
async fn download_tracker_limits_total_buffered_bytes_across_partial_downloads() {
    let tracker = DownloadTracker::with_limits(8, 10);

    for file_id in [0x50_u32, 0x51, 0x52] {
        tracker
            .start(
                0xABCD_EF55,
                file_id,
                DownloadState {
                    request_id: 0x80 + file_id,
                    remote_path: format!("C:\\Temp\\{file_id:08x}.bin"),
                    expected_size: 16,
                    data: Vec::new(),
                    started_at: "2026-03-11T09:15:00Z".to_owned(),
                },
            )
            .await
            .expect("start should succeed");
    }

    assert_eq!(
        tracker.append(0xABCD_EF55, 0x50, b"abcd").await.expect("first chunk").data,
        b"abcd"
    );
    assert_eq!(
        tracker.append(0xABCD_EF55, 0x51, b"efgh").await.expect("second chunk").data,
        b"efgh"
    );
    assert_eq!(tracker.buffered_bytes().await, 8);

    let error = tracker
        .append(0xABCD_EF55, 0x52, b"ijk")
        .await
        .expect_err("aggregate cap should reject additional concurrent partial data");
    assert!(matches!(
        error,
        CommandDispatchError::DownloadAggregateTooLarge {
            agent_id: 0xABCD_EF55,
            file_id: 0x52,
            max_total_download_bytes: 10,
        }
    ));
    assert_eq!(tracker.buffered_bytes().await, 8);

    let active = tracker.active_for_agent(0xABCD_EF55).await;
    assert_eq!(active.len(), 2);
    assert_eq!(active[0].0, 0x50);
    assert_eq!(active[0].1.data, b"abcd");
    assert_eq!(active[1].0, 0x51);
    assert_eq!(active[1].1.data, b"efgh");
    assert_eq!(tracker.finish(0xABCD_EF55, 0x52).await, None);
}

#[tokio::test]
async fn download_tracker_keeps_idle_partial_downloads_until_finish() {
    let tracker = DownloadTracker::with_limits(16, 12);

    for file_id in [0x60_u32, 0x61] {
        tracker
            .start(
                0xABCD_EF56,
                file_id,
                DownloadState {
                    request_id: 0x90 + file_id,
                    remote_path: format!("C:\\Temp\\idle-{file_id:08x}.bin"),
                    expected_size: 32,
                    data: Vec::new(),
                    started_at: "2026-03-11T09:20:00Z".to_owned(),
                },
            )
            .await
            .expect("start should succeed");
    }

    tracker.append(0xABCD_EF56, 0x60, b"12").await.expect("first partial should append");
    tracker.append(0xABCD_EF56, 0x61, b"34").await.expect("second partial should append");
    assert_eq!(tracker.buffered_bytes().await, 4);

    tokio::time::sleep(std::time::Duration::from_millis(5)).await;

    let continued = tracker
        .append(0xABCD_EF56, 0x60, b"56")
        .await
        .expect("idle transfer should still accept more data");
    assert_eq!(continued.data, b"1256");
    assert_eq!(tracker.buffered_bytes().await, 6);

    let active = tracker.active_for_agent(0xABCD_EF56).await;
    assert_eq!(active.len(), 2);
    assert_eq!(active[0].0, 0x60);
    assert_eq!(active[0].1.data, b"1256");
    assert_eq!(active[1].0, 0x61);
    assert_eq!(active[1].1.data, b"34");

    assert_eq!(
        tracker.finish(0xABCD_EF56, 0x60).await,
        Some(DownloadState {
            request_id: 0xF0,
            remote_path: "C:\\Temp\\idle-00000060.bin".to_owned(),
            expected_size: 32,
            data: b"1256".to_vec(),
            started_at: "2026-03-11T09:20:00Z".to_owned(),
        })
    );
    assert_eq!(tracker.buffered_bytes().await, 2);
    assert_eq!(
        tracker.finish(0xABCD_EF56, 0x61).await,
        Some(DownloadState {
            request_id: 0xF1,
            remote_path: "C:\\Temp\\idle-00000061.bin".to_owned(),
            expected_size: 32,
            data: b"34".to_vec(),
            started_at: "2026-03-11T09:20:00Z".to_owned(),
        })
    );
}

#[tokio::test]
async fn download_tracker_rejects_start_when_per_agent_cap_is_reached() {
    // Use a tracker with a tiny per-agent cap so we don't need to create 32 entries.
    let mut tracker = DownloadTracker::with_limits(1024, 1024 * 64);
    tracker.max_concurrent_downloads_per_agent = 2;
    let agent_id = 0xDEAD_BEEF;

    let make_state = |file_id: u32| DownloadState {
        request_id: file_id,
        remote_path: format!("C:\\Temp\\file_{file_id:08x}.bin"),
        expected_size: 64,
        data: Vec::new(),
        started_at: "2026-03-28T00:00:00Z".to_owned(),
    };

    tracker.start(agent_id, 0x01, make_state(0x01)).await.expect("first start should succeed");
    tracker
        .start(agent_id, 0x02, make_state(0x02))
        .await
        .expect("second start should succeed (at cap)");

    let err = tracker
        .start(agent_id, 0x03, make_state(0x03))
        .await
        .expect_err("third start should be rejected (over cap)");
    assert!(
        matches!(
            err,
            CommandDispatchError::DownloadConcurrentLimitExceeded {
                agent_id: 0xDEAD_BEEF,
                file_id: 0x03,
                max_concurrent: 2,
            }
        ),
        "unexpected error variant: {err:?}"
    );
    // The rejected entry must not have been inserted.
    assert_eq!(tracker.active_for_agent(agent_id).await.len(), 2);
}

#[tokio::test]
async fn download_tracker_per_agent_cap_does_not_affect_other_agents() {
    let mut tracker = DownloadTracker::with_limits(1024, 1024 * 64);
    tracker.max_concurrent_downloads_per_agent = 1;

    let make_state = |file_id: u32| DownloadState {
        request_id: file_id,
        remote_path: format!("C:\\Temp\\file_{file_id:08x}.bin"),
        expected_size: 64,
        data: Vec::new(),
        started_at: "2026-03-28T00:00:00Z".to_owned(),
    };

    tracker.start(0xAAAA_0001, 0x10, make_state(0x10)).await.expect("agent A start ok");
    tracker.start(0xBBBB_0002, 0x20, make_state(0x20)).await.expect("agent B start ok");

    // Agent A is now at its cap — agent B should still be unaffected.
    let err = tracker
        .start(0xAAAA_0001, 0x11, make_state(0x11))
        .await
        .expect_err("agent A second start should be rejected");
    assert!(matches!(
        err,
        CommandDispatchError::DownloadConcurrentLimitExceeded { agent_id: 0xAAAA_0001, .. }
    ));

    // Agent B can still open another download.
    tracker
        .start(0xBBBB_0002, 0x21, make_state(0x21))
        .await
        .expect_err("agent B second start should also be rejected (cap=1)");
}

#[tokio::test]
async fn download_tracker_restart_same_file_id_does_not_count_as_new_slot() {
    let mut tracker = DownloadTracker::with_limits(1024, 1024 * 64);
    tracker.max_concurrent_downloads_per_agent = 1;
    let agent_id = 0xCAFE_BABE;

    let make_state = |file_id: u32| DownloadState {
        request_id: file_id,
        remote_path: format!("C:\\Temp\\file_{file_id:08x}.bin"),
        expected_size: 64,
        data: Vec::new(),
        started_at: "2026-03-28T00:00:00Z".to_owned(),
    };

    tracker.start(agent_id, 0x01, make_state(0x01)).await.expect("initial start");
    // Re-starting the same (agent, file) pair must replace the old entry, not consume an extra slot.
    tracker
        .start(agent_id, 0x01, make_state(0x01))
        .await
        .expect("restart of same file_id should succeed");
    assert_eq!(tracker.active_for_agent(agent_id).await.len(), 1);
}

#[tokio::test]
async fn builtin_beacon_file_callbacks_reassemble_downloads()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF21, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database.clone(), sockets, None);

    let file_id = 0x55_u32;
    let remote_path = "C:\\Windows\\Temp\\note.txt";
    let content = b"beacon-chunk";

    let mut open_header = Vec::new();
    open_header.extend_from_slice(&file_id.to_be_bytes());
    open_header.extend_from_slice(&(u32::try_from(content.len())?).to_be_bytes());
    open_header.extend_from_slice(remote_path.as_bytes());
    let mut open = Vec::new();
    add_u32(&mut open, u32::from(DemonCallback::File));
    add_bytes(&mut open, &open_header);
    dispatcher.dispatch(0xABCD_EF21, u32::from(DemonCommand::BeaconOutput), 0x77, &open).await?;

    let mut chunk = Vec::new();
    chunk.extend_from_slice(&file_id.to_be_bytes());
    chunk.extend_from_slice(content);
    let mut write = Vec::new();
    add_u32(&mut write, u32::from(DemonCallback::FileWrite));
    add_bytes(&mut write, &chunk);
    dispatcher.dispatch(0xABCD_EF21, u32::from(DemonCommand::BeaconOutput), 0x77, &write).await?;

    let mut close = Vec::new();
    add_u32(&mut close, u32::from(DemonCallback::FileClose));
    add_bytes(&mut close, &file_id.to_be_bytes());
    dispatcher.dispatch(0xABCD_EF21, u32::from(DemonCommand::BeaconOutput), 0x77, &close).await?;

    let _ = receiver.recv().await.ok_or("missing beacon open event")?;
    let _ = receiver.recv().await.ok_or("missing beacon progress event")?;
    let loot_event = receiver.recv().await.ok_or("missing beacon loot event")?;
    let final_event = receiver.recv().await.ok_or("missing beacon completion event")?;
    let OperatorMessage::AgentResponse(loot_message) = loot_event else {
        panic!("expected beacon file loot event");
    };
    assert_eq!(
        loot_message.info.extra.get("MiscType"),
        Some(&Value::String("loot-new".to_owned()))
    );
    let OperatorMessage::AgentResponse(message) = final_event else {
        panic!("expected beacon file completion response");
    };
    assert_eq!(message.info.extra.get("MiscType"), Some(&Value::String("download".to_owned())));

    let loot = database.loot().list_for_agent(0xABCD_EF21).await?;
    assert_eq!(loot.len(), 1);
    assert_eq!(loot[0].data.as_deref(), Some(content.as_slice()));
    assert_eq!(loot[0].file_path.as_deref(), Some(remote_path));
    Ok(())
}

#[tokio::test]
async fn builtin_beacon_file_callbacks_accumulate_partial_downloads_until_close()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF22, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database.clone(), sockets, None);

    let file_id = 0x56_u32;
    let remote_path = "C:\\Windows\\Temp\\partial.txt";

    dispatcher
        .dispatch(
            0xABCD_EF22,
            u32::from(DemonCommand::BeaconOutput),
            0x78,
            &beacon_file_open(file_id, 32, remote_path),
        )
        .await?;
    dispatcher
        .dispatch(
            0xABCD_EF22,
            u32::from(DemonCommand::BeaconOutput),
            0x78,
            &beacon_file_write(file_id, b"beacon-"),
        )
        .await?;
    dispatcher
        .dispatch(
            0xABCD_EF22,
            u32::from(DemonCommand::BeaconOutput),
            0x78,
            &beacon_file_write(file_id, b"chunk"),
        )
        .await?;

    assert!(database.loot().list_for_agent(0xABCD_EF22).await?.is_empty());

    let _ = receiver.recv().await.ok_or("missing beacon open event")?;
    let progress_one = receiver.recv().await.ok_or("missing first beacon progress event")?;
    let progress_two = receiver.recv().await.ok_or("missing second beacon progress event")?;

    let OperatorMessage::AgentResponse(progress_one) = progress_one else {
        panic!("expected first beacon progress response");
    };
    assert_eq!(progress_one.info.extra.get("CurrentSize"), Some(&Value::String("7".to_owned())));
    assert_eq!(progress_one.info.extra.get("ExpectedSize"), Some(&Value::String("32".to_owned())));

    let OperatorMessage::AgentResponse(progress_two) = progress_two else {
        panic!("expected second beacon progress response");
    };
    assert_eq!(progress_two.info.extra.get("CurrentSize"), Some(&Value::String("12".to_owned())));
    assert_eq!(progress_two.info.extra.get("ExpectedSize"), Some(&Value::String("32".to_owned())));
    let active = dispatcher.downloads.active_for_agent(0xABCD_EF22).await;
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].0, file_id);
    assert_eq!(active[0].1.request_id, 0x78);
    assert_eq!(active[0].1.remote_path, remote_path);
    assert_eq!(active[0].1.expected_size, 32);
    assert_eq!(active[0].1.data, b"beacon-chunk");
    assert!(
        !active[0].1.started_at.is_empty(),
        "active beacon download should preserve its start timestamp"
    );
    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "beacon download should remain incomplete until close"
    );

    dispatcher
        .dispatch(
            0xABCD_EF22,
            u32::from(DemonCommand::BeaconOutput),
            0x78,
            &beacon_file_close(file_id),
        )
        .await?;

    let _ = receiver.recv().await.ok_or("missing beacon loot event")?;
    let completion = receiver.recv().await.ok_or("missing beacon completion event")?;
    let OperatorMessage::AgentResponse(completion) = completion else {
        panic!("expected beacon completion response");
    };
    assert_eq!(
        completion.info.extra.get("MiscData"),
        Some(&Value::String(BASE64_STANDARD.encode(b"beacon-chunk")))
    );

    let loot = database.loot().list_for_agent(0xABCD_EF22).await?;
    assert_eq!(loot.len(), 1);
    assert_eq!(loot[0].data.as_deref(), Some(b"beacon-chunk".as_slice()));
    assert_eq!(loot[0].file_path.as_deref(), Some(remote_path));
    Ok(())
}

#[tokio::test]
async fn builtin_beacon_file_callbacks_reject_writes_without_open()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF23, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database.clone(), sockets, None);

    let error = dispatcher
        .dispatch(
            0xABCD_EF23,
            u32::from(DemonCommand::BeaconOutput),
            0x79,
            &beacon_file_write(0x57, b"orphan"),
        )
        .await
        .expect_err("beacon file write without open should fail");
    assert!(matches!(
        error,
        CommandDispatchError::InvalidCallbackPayload {
            command_id,
            message,
        } if command_id == 0
            && message.contains("0x00000057")
            && message.contains("was not opened")
    ));
    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "unexpected events for rejected beacon download write"
    );
    assert!(database.loot().list_for_agent(0xABCD_EF23).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_download_handler_surfaces_over_limit_as_error_event()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF31, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher = CommandDispatcher::with_builtin_handlers_and_max_download_bytes(
        registry,
        events,
        database.clone(),
        sockets,
        None,
        4,
    );

    let file_id = 0x91_u32;
    let mut open = Vec::new();
    add_u32(&mut open, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut open, 0);
    add_u32(&mut open, file_id);
    add_u64(&mut open, 8);
    add_utf16(&mut open, "C:\\Temp\\oversized.bin");
    dispatcher.dispatch(0xABCD_EF31, u32::from(DemonCommand::CommandFs), 0x99, &open).await?;

    // Chunk that exceeds the 4-byte cap — must succeed (not propagate error).
    let mut write = Vec::new();
    add_u32(&mut write, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut write, 1);
    add_u32(&mut write, file_id);
    add_bytes(&mut write, b"12345");
    dispatcher
        .dispatch(0xABCD_EF31, u32::from(DemonCommand::CommandFs), 0x99, &write)
        .await
        .expect("oversized chunk should not propagate as dispatch error");

    // Open event (download-progress "Started").
    let open_event = receiver.recv().await.ok_or("missing open event")?;
    let OperatorMessage::AgentResponse(open_message) = open_event else {
        panic!("expected download open response");
    };
    assert_eq!(
        open_message.info.extra.get("MiscType"),
        Some(&Value::String("download-progress".to_owned()))
    );

    // Error event surfaced to operator.
    let error_event = receiver.recv().await.ok_or("missing error event")?;
    let OperatorMessage::AgentResponse(error_message) = error_event else {
        panic!("expected AgentResponse error event");
    };
    assert_eq!(error_message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    let msg = error_message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("limit exceeded"), "error message should mention limit exceeded: {msg}");

    // Audit log must have a download.rejected entry.
    let audit_rows = database.audit_log().list().await?;
    assert!(
        audit_rows.iter().any(|r| r.action == "download.rejected"),
        "audit log must contain a download.rejected entry"
    );

    // No loot must have been persisted.
    assert!(database.loot().list_for_agent(0xABCD_EF31).await?.is_empty());

    // Close packet is harmless (download already removed from tracker).
    let mut close = Vec::new();
    add_u32(&mut close, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut close, 2);
    add_u32(&mut close, file_id);
    add_u32(&mut close, 0);
    assert_eq!(
        dispatcher.dispatch(0xABCD_EF31, u32::from(DemonCommand::CommandFs), 0x99, &close).await?,
        None
    );
    Ok(())
}

// ── Filesystem subcommand tests (non-Download) ──────────────────────────

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

#[tokio::test]
async fn builtin_beacon_file_callbacks_surface_over_limit_as_error_event()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF41, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher = CommandDispatcher::with_builtin_handlers_and_max_download_bytes(
        registry,
        events,
        database.clone(),
        sockets,
        None,
        4,
    );

    let file_id = 0x92_u32;
    let mut open_header = Vec::new();
    open_header.extend_from_slice(&file_id.to_be_bytes());
    open_header.extend_from_slice(&8_u32.to_be_bytes());
    open_header.extend_from_slice(b"C:\\Windows\\Temp\\oversized.txt");
    let mut open = Vec::new();
    add_u32(&mut open, u32::from(DemonCallback::File));
    add_bytes(&mut open, &open_header);
    dispatcher.dispatch(0xABCD_EF41, u32::from(DemonCommand::BeaconOutput), 0x77, &open).await?;

    // Chunk that exceeds the 4-byte cap — must succeed (not propagate error).
    let mut chunk = Vec::new();
    chunk.extend_from_slice(&file_id.to_be_bytes());
    chunk.extend_from_slice(b"12345");
    let mut write = Vec::new();
    add_u32(&mut write, u32::from(DemonCallback::FileWrite));
    add_bytes(&mut write, &chunk);
    dispatcher
        .dispatch(0xABCD_EF41, u32::from(DemonCommand::BeaconOutput), 0x77, &write)
        .await
        .expect("oversized beacon chunk should not propagate as dispatch error");

    // Open event (download-progress "Started").
    let open_event = receiver.recv().await.ok_or("missing beacon open event")?;
    let OperatorMessage::AgentResponse(open_message) = open_event else {
        panic!("expected beacon open response");
    };
    assert_eq!(
        open_message.info.extra.get("MiscType"),
        Some(&Value::String("download-progress".to_owned()))
    );

    // Error event surfaced to operator.
    let error_event = receiver.recv().await.ok_or("missing error event")?;
    let OperatorMessage::AgentResponse(error_message) = error_event else {
        panic!("expected AgentResponse error event");
    };
    assert_eq!(error_message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    let msg = error_message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("limit exceeded"), "error message should mention limit exceeded: {msg}");

    // Audit log must have a download.rejected entry.
    let audit_rows = database.audit_log().list().await?;
    assert!(
        audit_rows.iter().any(|r| r.action == "download.rejected"),
        "audit log must contain a download.rejected entry"
    );

    // No loot must have been persisted.
    assert!(database.loot().list_for_agent(0xABCD_EF41).await?.is_empty());

    // Close packet is harmless (download already removed from tracker).
    let mut close = Vec::new();
    add_u32(&mut close, u32::from(DemonCallback::FileClose));
    add_bytes(&mut close, &file_id.to_be_bytes());
    assert_eq!(
        dispatcher
            .dispatch(0xABCD_EF41, u32::from(DemonCommand::BeaconOutput), 0x77, &close)
            .await?,
        None
    );
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_download_handler_surfaces_concurrent_limit_as_error_event()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF70, test_key(0x11), test_iv(0x22))).await?;
    let tracker = DownloadTracker::new(1024 * 1024).with_max_concurrent_per_agent(1);
    let dispatcher = CommandDispatcher::with_builtin_handlers_and_downloads(
        registry,
        events,
        database.clone(),
        sockets,
        None,
        tracker,
        super::DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        false,
    );

    let file_id_1 = 0xB1_u32;
    let file_id_2 = 0xB2_u32;

    // Open first download — must succeed.
    let mut open1 = Vec::new();
    add_u32(&mut open1, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut open1, 0);
    add_u32(&mut open1, file_id_1);
    add_u64(&mut open1, 16);
    add_utf16(&mut open1, "C:\\Temp\\first.bin");
    dispatcher.dispatch(0xABCD_EF70, u32::from(DemonCommand::CommandFs), 0x99, &open1).await?;

    // Open second download while first is still active — concurrent limit exceeded.
    // Must return Ok(()) (error is surfaced as event, not propagated).
    let mut open2 = Vec::new();
    add_u32(&mut open2, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut open2, 0);
    add_u32(&mut open2, file_id_2);
    add_u64(&mut open2, 16);
    add_utf16(&mut open2, "C:\\Temp\\second.bin");
    dispatcher
        .dispatch(0xABCD_EF70, u32::from(DemonCommand::CommandFs), 0x99, &open2)
        .await
        .expect("concurrent-limit rejection must not propagate as dispatch error");

    // First event: download-progress "Started" for the first file.
    let open_event = receiver.recv().await.ok_or("missing open event")?;
    let OperatorMessage::AgentResponse(open_message) = open_event else {
        panic!("expected AgentResponse for first download open");
    };
    assert_eq!(
        open_message.info.extra.get("MiscType"),
        Some(&Value::String("download-progress".to_owned()))
    );

    // Second event: error event for the concurrent-limit rejection.
    let error_event = receiver.recv().await.ok_or("missing error event")?;
    let OperatorMessage::AgentResponse(error_message) = error_event else {
        panic!("expected AgentResponse error event for concurrent-limit rejection");
    };
    assert_eq!(error_message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    let msg = error_message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("limit exceeded"), "error message should mention limit exceeded: {msg}");

    // Audit log must contain a download.rejected entry.
    let audit_rows = database.audit_log().list().await?;
    assert!(
        audit_rows.iter().any(|r| r.action == "download.rejected"),
        "audit log must contain a download.rejected entry"
    );

    // No loot persisted (neither download completed).
    assert!(database.loot().list_for_agent(0xABCD_EF70).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn builtin_beacon_file_callbacks_surface_concurrent_limit_as_error_event()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF71, test_key(0x11), test_iv(0x22))).await?;
    let tracker = DownloadTracker::new(1024 * 1024).with_max_concurrent_per_agent(1);
    let dispatcher = CommandDispatcher::with_builtin_handlers_and_downloads(
        registry,
        events,
        database.clone(),
        sockets,
        None,
        tracker,
        super::DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        false,
    );

    let file_id_1 = 0xC1_u32;
    let file_id_2 = 0xC2_u32;

    // Open first beacon file download — must succeed.
    let mut open_header1 = Vec::new();
    open_header1.extend_from_slice(&file_id_1.to_be_bytes());
    open_header1.extend_from_slice(&16_u32.to_be_bytes());
    open_header1.extend_from_slice(b"C:\\Windows\\Temp\\first.txt");
    let mut open1 = Vec::new();
    add_u32(&mut open1, u32::from(DemonCallback::File));
    add_bytes(&mut open1, &open_header1);
    dispatcher.dispatch(0xABCD_EF71, u32::from(DemonCommand::BeaconOutput), 0x77, &open1).await?;

    // Open second beacon file download while first is active — concurrent limit exceeded.
    // Must return Ok(()) (error is surfaced as event, not propagated).
    let mut open_header2 = Vec::new();
    open_header2.extend_from_slice(&file_id_2.to_be_bytes());
    open_header2.extend_from_slice(&16_u32.to_be_bytes());
    open_header2.extend_from_slice(b"C:\\Windows\\Temp\\second.txt");
    let mut open2 = Vec::new();
    add_u32(&mut open2, u32::from(DemonCallback::File));
    add_bytes(&mut open2, &open_header2);
    dispatcher
        .dispatch(0xABCD_EF71, u32::from(DemonCommand::BeaconOutput), 0x77, &open2)
        .await
        .expect("concurrent-limit rejection must not propagate as dispatch error");

    // First event: download-progress "Started" for the first file.
    let open_event = receiver.recv().await.ok_or("missing beacon open event")?;
    let OperatorMessage::AgentResponse(open_message) = open_event else {
        panic!("expected AgentResponse for first beacon file open");
    };
    assert_eq!(
        open_message.info.extra.get("MiscType"),
        Some(&Value::String("download-progress".to_owned()))
    );

    // Second event: error event for the concurrent-limit rejection.
    let error_event = receiver.recv().await.ok_or("missing error event")?;
    let OperatorMessage::AgentResponse(error_message) = error_event else {
        panic!("expected AgentResponse error event for concurrent-limit rejection");
    };
    assert_eq!(error_message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    let msg = error_message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("limit exceeded"), "error message should mention limit exceeded: {msg}");

    // Audit log must contain a download.rejected entry.
    let audit_rows = database.audit_log().list().await?;
    assert!(
        audit_rows.iter().any(|r| r.action == "download.rejected"),
        "audit log must contain a download.rejected entry"
    );

    // No loot persisted (neither download completed).
    assert!(database.loot().list_for_agent(0xABCD_EF71).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn with_builtin_handlers_and_max_download_bytes_happy_path()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF60, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher = CommandDispatcher::with_builtin_handlers_and_max_download_bytes(
        registry,
        events,
        database.clone(),
        sockets,
        None,
        512,
    );

    let file_id = 0xA1_u32;
    let content = b"small-payload";

    // Open
    let mut open = Vec::new();
    add_u32(&mut open, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut open, 0);
    add_u32(&mut open, file_id);
    add_u64(&mut open, u64::try_from(content.len())?);
    add_utf16(&mut open, "C:\\Temp\\small.bin");
    dispatcher.dispatch(0xABCD_EF60, u32::from(DemonCommand::CommandFs), 0x99, &open).await?;

    // Write (13 bytes < 512 ceiling)
    let mut write = Vec::new();
    add_u32(&mut write, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut write, 1);
    add_u32(&mut write, file_id);
    add_bytes(&mut write, content);
    dispatcher.dispatch(0xABCD_EF60, u32::from(DemonCommand::CommandFs), 0x99, &write).await?;

    // Close
    let mut close = Vec::new();
    add_u32(&mut close, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut close, 2);
    add_u32(&mut close, file_id);
    add_u32(&mut close, 0);
    dispatcher.dispatch(0xABCD_EF60, u32::from(DemonCommand::CommandFs), 0x99, &close).await?;

    // Drain events: open, progress, loot, completion
    let _open_event = receiver.recv().await.ok_or("missing open event")?;
    let _progress_event = receiver.recv().await.ok_or("missing progress event")?;
    let loot_event = receiver.recv().await.ok_or("missing loot event")?;
    let _done_event = receiver.recv().await.ok_or("missing completion event")?;

    let OperatorMessage::AgentResponse(loot_message) = loot_event else {
        panic!("expected loot event");
    };
    assert_eq!(
        loot_message.info.extra.get("MiscType"),
        Some(&Value::String("loot-new".to_owned()))
    );

    let loot = database.loot().list_for_agent(0xABCD_EF60).await?;
    assert_eq!(loot.len(), 1);
    assert_eq!(loot[0].kind, "download");
    assert_eq!(loot[0].file_path.as_deref(), Some("C:\\Temp\\small.bin"));
    assert_eq!(loot[0].data.as_deref(), Some(content.as_slice()));
    Ok(())
}

#[tokio::test]
async fn with_builtin_handlers_and_max_download_bytes_ceiling_exceeded()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF61, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher = CommandDispatcher::with_builtin_handlers_and_max_download_bytes(
        registry,
        events,
        database.clone(),
        sockets,
        None,
        8,
    );

    let file_id = 0xA2_u32;

    // Open
    let mut open = Vec::new();
    add_u32(&mut open, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut open, 0);
    add_u32(&mut open, file_id);
    add_u64(&mut open, 32);
    add_utf16(&mut open, "C:\\Temp\\big.bin");
    dispatcher.dispatch(0xABCD_EF61, u32::from(DemonCommand::CommandFs), 0x99, &open).await?;

    // Write chunk that exceeds ceiling (9 bytes > 8) — must succeed, error surfaced as event.
    let mut write = Vec::new();
    add_u32(&mut write, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut write, 1);
    add_u32(&mut write, file_id);
    add_bytes(&mut write, b"123456789");
    dispatcher
        .dispatch(0xABCD_EF61, u32::from(DemonCommand::CommandFs), 0x99, &write)
        .await
        .expect("oversized chunk should not propagate as dispatch error");

    // Subsequent write for the same file_id hits InvalidCallbackPayload (download dropped).
    let mut write2 = Vec::new();
    add_u32(&mut write2, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut write2, 1);
    add_u32(&mut write2, file_id);
    add_bytes(&mut write2, b"ab");
    let error2 =
        dispatcher.dispatch(0xABCD_EF61, u32::from(DemonCommand::CommandFs), 0x99, &write2).await;
    assert!(error2.is_err(), "writes after drop should be rejected with protocol error");

    // Drain: open event, then error event for the oversized chunk.
    let _open_event = receiver.recv().await.ok_or("missing open event")?;
    let error_event = receiver.recv().await.ok_or("missing error event")?;
    let OperatorMessage::AgentResponse(error_msg) = error_event else {
        panic!("expected AgentResponse error event");
    };
    assert_eq!(error_msg.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    // No further events (write2 errors without events).
    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "no further events after drop"
    );

    // Audit log must contain a download.rejected entry.
    let audit_rows = database.audit_log().list().await?;
    assert!(
        audit_rows.iter().any(|r| r.action == "download.rejected"),
        "audit log must contain a download.rejected entry"
    );
    assert!(database.loot().list_for_agent(0xABCD_EF61).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn with_builtin_handlers_and_max_download_bytes_zero_ceiling()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF62, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher = CommandDispatcher::with_builtin_handlers_and_max_download_bytes(
        registry,
        events,
        database.clone(),
        sockets,
        None,
        0,
    );

    let file_id = 0xA3_u32;

    // Open succeeds (start does not enforce the cap)
    let mut open = Vec::new();
    add_u32(&mut open, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut open, 0);
    add_u32(&mut open, file_id);
    add_u64(&mut open, 1);
    add_utf16(&mut open, "C:\\Temp\\zero.bin");
    dispatcher.dispatch(0xABCD_EF62, u32::from(DemonCommand::CommandFs), 0x99, &open).await?;

    // Even a single byte write should be surfaced as error event with ceiling=0.
    let mut write = Vec::new();
    add_u32(&mut write, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut write, 1);
    add_u32(&mut write, file_id);
    add_bytes(&mut write, b"x");
    dispatcher
        .dispatch(0xABCD_EF62, u32::from(DemonCommand::CommandFs), 0x99, &write)
        .await
        .expect("zero-ceiling write should not propagate as dispatch error");

    // Drain: open event, then error event.
    let _open_event = receiver.recv().await.ok_or("missing open event")?;
    let error_event = receiver.recv().await.ok_or("missing error event")?;
    let OperatorMessage::AgentResponse(error_msg) = error_event else {
        panic!("expected AgentResponse error event");
    };
    assert_eq!(error_msg.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));

    // Audit log must contain a download.rejected entry.
    let audit_rows = database.audit_log().list().await?;
    assert!(
        audit_rows.iter().any(|r| r.action == "download.rejected"),
        "audit log must contain a download.rejected entry"
    );
    assert!(database.loot().list_for_agent(0xABCD_EF62).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn builtin_kerberos_klist_handler_formats_ticket_output()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonKerberosCommand::Klist));
    add_u32(&mut payload, 1);
    add_u32(&mut payload, 1);
    add_utf16(&mut payload, "alice");
    add_utf16(&mut payload, "LAB");
    add_u32(&mut payload, 0x1234);
    add_u32(&mut payload, 0x5678);
    add_u32(&mut payload, 1);
    add_utf16(&mut payload, "S-1-5-21");
    add_u32(&mut payload, 0xD53E_8000);
    add_u32(&mut payload, 0x019D_B1DE);
    add_u32(&mut payload, 2);
    add_utf16(&mut payload, "Kerberos");
    add_utf16(&mut payload, "DC01");
    add_utf16(&mut payload, "lab.local");
    add_utf16(&mut payload, "alice@lab.local");
    add_u32(&mut payload, 1);
    add_utf16(&mut payload, "alice");
    add_utf16(&mut payload, "LAB.LOCAL");
    add_utf16(&mut payload, "krbtgt");
    add_utf16(&mut payload, "LAB.LOCAL");
    add_u32(&mut payload, 0xD53E_8000);
    add_u32(&mut payload, 0x019D_B1DE);
    add_u32(&mut payload, 0xD53E_8000);
    add_u32(&mut payload, 0x019D_B1DE);
    add_u32(&mut payload, 0xD53E_8000);
    add_u32(&mut payload, 0x019D_B1DE);
    add_u32(&mut payload, 18);
    add_u32(&mut payload, 0x4081_0000);
    add_bytes(&mut payload, b"ticket");

    dispatcher.dispatch(0x0102_0304, u32::from(DemonCommand::CommandKerberos), 9, &payload).await?;

    let event = receiver.recv().await.ok_or_else(|| "kerberos response missing".to_owned())?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected kerberos agent response event");
    };
    assert!(message.info.output.contains("UserName                : alice"));
    assert!(message.info.output.contains("Encryption type : AES256_CTS_HMAC_SHA1"));
    assert!(message.info.output.contains("Ticket          : dGlja2V0"));
    Ok(())
}

#[tokio::test]
async fn token_steal_callback_broadcasts_success_event() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Steal));
    add_utf16(&mut payload, "LAB\\admin");
    add_u32(&mut payload, 3);
    add_u32(&mut payload, 1234);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 10, &payload).await?;

    let event = receiver.recv().await.ok_or("token steal response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(
        msg,
        "Successfully stole and impersonated token from 1234 User:[LAB\\admin] TokenID:[3]"
    );
    assert!(msg.contains("LAB\\admin"));
    assert!(msg.contains("TokenID:[3]"));
    Ok(())
}

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
async fn token_privs_list_callback_formats_privilege_table()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::PrivsGetOrList));
    add_u32(&mut payload, 1);
    add_bytes(&mut payload, b"SeDebugPrivilege\0");
    add_u32(&mut payload, 3);
    add_bytes(&mut payload, b"SeShutdownPrivilege\0");
    add_u32(&mut payload, 0);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 13, &payload).await?;

    let event = receiver.recv().await.ok_or("token privs list response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert!(message.info.output.contains("SeDebugPrivilege"));
    assert!(message.info.output.contains("Enabled"));
    assert!(message.info.output.contains("SeShutdownPrivilege"));
    assert!(message.info.output.contains("Disabled"));
    Ok(())
}

#[tokio::test]
async fn token_privs_get_callback_success_and_failure() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::PrivsGetOrList));
    add_u32(&mut payload, 0);
    add_u32(&mut payload, 1);
    add_bytes(&mut payload, b"SeDebugPrivilege\0");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 14, &payload).await?;

    let event = receiver.recv().await.ok_or("token privs get response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("successfully enabled"));
    assert!(msg.contains("SeDebugPrivilege"));

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::PrivsGetOrList));
    add_u32(&mut payload, 0);
    add_u32(&mut payload, 0);
    add_bytes(&mut payload, b"SeDebugPrivilege\0");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 15, &payload).await?;

    let event = receiver.recv().await.ok_or("token privs get failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("Failed to enable"));
    Ok(())
}

#[tokio::test]
async fn token_make_callback_success_and_empty() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Make));
    add_utf16(&mut payload, "LAB\\admin");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 16, &payload).await?;

    let event = receiver.recv().await.ok_or("token make response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("Successfully created and impersonated token"));
    assert!(msg.contains("LAB\\admin"));

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Make));
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 17, &payload).await?;

    let event = receiver.recv().await.ok_or("token make failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("Failed to create token"));
    Ok(())
}

#[tokio::test]
async fn token_getuid_callback_elevated_and_normal() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::GetUid));
    add_u32(&mut payload, 1);
    add_utf16(&mut payload, "LAB\\admin");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 18, &payload).await?;

    let event = receiver.recv().await.ok_or("token getuid response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("LAB\\admin"));
    assert!(msg.contains("(Admin)"));

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::GetUid));
    add_u32(&mut payload, 0);
    add_utf16(&mut payload, "LAB\\user");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 19, &payload).await?;

    let event = receiver.recv().await.ok_or("token getuid normal response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("LAB\\user"));
    assert!(!msg.contains("(Admin)"));
    Ok(())
}

#[tokio::test]
async fn token_revert_callback_success_and_failure() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Revert));
    add_u32(&mut payload, 1);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 20, &payload).await?;

    let event = receiver.recv().await.ok_or("token revert response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("reverted token to itself"));

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Revert));
    add_u32(&mut payload, 0);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 21, &payload).await?;

    let event = receiver.recv().await.ok_or("token revert failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("Failed to revert"));
    Ok(())
}

#[tokio::test]
async fn token_remove_callback_success_and_failure() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Remove));
    add_u32(&mut payload, 1);
    add_u32(&mut payload, 5);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 22, &payload).await?;

    let event = receiver.recv().await.ok_or("token remove response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("removed token [5]"));

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Remove));
    add_u32(&mut payload, 0);
    add_u32(&mut payload, 5);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 23, &payload).await?;

    let event = receiver.recv().await.ok_or("token remove failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("Failed to remove token [5]"));
    Ok(())
}

#[tokio::test]
async fn token_clear_callback_broadcasts_success() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Clear));
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 24, &payload).await?;

    let event = receiver.recv().await.ok_or("token clear response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("Token vault has been cleared"));
    Ok(())
}

#[tokio::test]
async fn token_find_tokens_callback_formats_table() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::FindTokens));
    add_u32(&mut payload, 1);
    add_u32(&mut payload, 1);
    add_utf16(&mut payload, "LAB\\admin");
    add_u32(&mut payload, 5678);
    add_u32(&mut payload, 0x10);
    add_u32(&mut payload, 0x3000);
    add_u32(&mut payload, 2);
    add_u32(&mut payload, 1);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 25, &payload).await?;

    let event = receiver.recv().await.ok_or("token find response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert!(message.info.output.contains("LAB\\admin"));
    assert!(message.info.output.contains("High"));
    assert!(message.info.output.contains("Primary"));
    assert!(message.info.output.contains("token steal"));
    Ok(())
}

#[tokio::test]
async fn token_find_tokens_callback_failure() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::FindTokens));
    add_u32(&mut payload, 0);
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 26, &payload).await?;

    let event = receiver.recv().await.ok_or("token find failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("Failed to list existing tokens"));
    Ok(())
}

#[tokio::test]
async fn token_impersonate_success_emits_good_response() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Impersonate));
    add_u32(&mut payload, 1); // success
    add_bytes(&mut payload, b"CORP\\jdoe\0");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 40, &payload).await?;

    let event = receiver.recv().await.ok_or("impersonate success response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Successfully impersonated CORP\\jdoe")
    );
    Ok(())
}

#[tokio::test]
async fn token_impersonate_failure_emits_error_response() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Impersonate));
    add_u32(&mut payload, 0); // failure
    add_bytes(&mut payload, b"CORP\\jdoe\0");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 41, &payload).await?;

    let event = receiver.recv().await.ok_or("impersonate failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Failed to impersonate CORP\\jdoe")
    );
    Ok(())
}

#[tokio::test]
async fn token_make_success_emits_good_type() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Make));
    add_utf16(&mut payload, "CORP\\svcacct");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 42, &payload).await?;

    let event = receiver.recv().await.ok_or("make success response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(msg, "Successfully created and impersonated token: CORP\\svcacct");
    Ok(())
}

#[tokio::test]
async fn token_make_empty_payload_emits_error_type() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Make));
    // No user_domain — triggers failure path
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 43, &payload).await?;

    let event = receiver.recv().await.ok_or("make failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Failed to create token")
    );
    Ok(())
}

#[tokio::test]
async fn token_getuid_elevated_emits_admin_suffix() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    // Elevated user
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::GetUid));
    add_u32(&mut payload, 1); // elevated
    add_utf16(&mut payload, "CORP\\admin");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 44, &payload).await?;

    let event = receiver.recv().await.ok_or("getuid elevated response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Token User: CORP\\admin (Admin)")
    );

    // Non-elevated user
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::GetUid));
    add_u32(&mut payload, 0); // not elevated
    add_utf16(&mut payload, "CORP\\user");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 45, &payload).await?;

    let event = receiver.recv().await.ok_or("getuid normal response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Token User: CORP\\user")
    );
    Ok(())
}

#[tokio::test]
async fn token_privs_get_success_emits_good_type() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    // Enable privilege — success
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::PrivsGetOrList));
    add_u32(&mut payload, 0); // get mode
    add_u32(&mut payload, 1); // success
    add_bytes(&mut payload, b"SeImpersonatePrivilege\0");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 46, &payload).await?;

    let event = receiver.recv().await.ok_or("privs get success response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("The privilege SeImpersonatePrivilege was successfully enabled")
    );

    // Enable privilege — failure
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::PrivsGetOrList));
    add_u32(&mut payload, 0); // get mode
    add_u32(&mut payload, 0); // failure
    add_bytes(&mut payload, b"SeImpersonatePrivilege\0");
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 47, &payload).await?;

    let event = receiver.recv().await.ok_or("privs get failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Failed to enable the SeImpersonatePrivilege privilege")
    );
    Ok(())
}

#[tokio::test]
async fn token_privs_list_emits_good_type_with_all_states() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::PrivsGetOrList));
    add_u32(&mut payload, 1); // list mode
    add_bytes(&mut payload, b"SeDebugPrivilege\0");
    add_u32(&mut payload, 3); // Enabled
    add_bytes(&mut payload, b"SeBackupPrivilege\0");
    add_u32(&mut payload, 2); // Adjusted
    add_bytes(&mut payload, b"SeRestorePrivilege\0");
    add_u32(&mut payload, 0); // Disabled
    add_bytes(&mut payload, b"SeCustomPrivilege\0");
    add_u32(&mut payload, 99); // Unknown
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 48, &payload).await?;

    let event = receiver.recv().await.ok_or("privs list response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    let output = &message.info.output;
    assert!(output.contains("SeDebugPrivilege :: Enabled"));
    assert!(output.contains("SeBackupPrivilege :: Adjusted"));
    assert!(output.contains("SeRestorePrivilege :: Disabled"));
    assert!(output.contains("SeCustomPrivilege :: Unknown"));
    Ok(())
}

#[tokio::test]
async fn token_revert_success_emits_good_failure_emits_error()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Revert));
    add_u32(&mut payload, 1); // success
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 49, &payload).await?;

    let event = receiver.recv().await.ok_or("revert success response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Successful reverted token to itself")
    );

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Revert));
    add_u32(&mut payload, 0); // failure
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 50, &payload).await?;

    let event = receiver.recv().await.ok_or("revert failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Failed to revert token to itself")
    );
    Ok(())
}

#[tokio::test]
async fn token_remove_success_emits_good_failure_emits_error()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Remove));
    add_u32(&mut payload, 1); // success
    add_u32(&mut payload, 42); // token_id
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 51, &payload).await?;

    let event = receiver.recv().await.ok_or("remove success response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Successful removed token [42] from vault")
    );

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::Remove));
    add_u32(&mut payload, 0); // failure
    add_u32(&mut payload, 42); // token_id
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 52, &payload).await?;

    let event = receiver.recv().await.ok_or("remove failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Failed to remove token [42] from vault")
    );
    Ok(())
}

#[tokio::test]
async fn token_find_tokens_zero_count_returns_no_tokens() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::FindTokens));
    add_u32(&mut payload, 1); // success
    add_u32(&mut payload, 0); // num_tokens = 0
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 53, &payload).await?;

    let event = receiver.recv().await.ok_or("find tokens zero count response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Info"));
    assert!(message.info.output.contains("No tokens found"));
    Ok(())
}

#[tokio::test]
async fn token_find_tokens_impersonation_type_with_delegation()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::FindTokens));
    add_u32(&mut payload, 1); // success
    add_u32(&mut payload, 1); // num_tokens
    add_utf16(&mut payload, "CORP\\delegator");
    add_u32(&mut payload, 9999); // pid
    add_u32(&mut payload, 0x20); // handle
    add_u32(&mut payload, 0x2000); // integrity = Medium
    add_u32(&mut payload, 3); // impersonation = Delegation
    add_u32(&mut payload, 2); // token_type = Impersonation
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 54, &payload).await?;

    let event = receiver.recv().await.ok_or("find tokens impersonation response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Info"));
    let output = &message.info.output;
    assert!(output.contains("CORP\\delegator"));
    assert!(output.contains("Medium"));
    assert!(output.contains("Impersonation"));
    assert!(output.contains("Delegation"));
    // Delegation impersonation level means remote auth = Yes
    assert!(output.contains("Yes"));
    assert!(output.contains("token steal"));
    Ok(())
}

#[tokio::test]
async fn token_find_tokens_failure_emits_error_type() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::FindTokens));
    add_u32(&mut payload, 0); // failure
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 55, &payload).await?;

    let event = receiver.recv().await.ok_or("find tokens failure response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    assert_eq!(
        message.info.extra.get("Message").and_then(|v| v.as_str()),
        Some("Failed to list existing tokens")
    );
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
async fn token_find_tokens_integrity_levels_formatted_correctly()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::FindTokens));
    add_u32(&mut payload, 1); // success
    add_u32(&mut payload, 4); // num_tokens
    // Token 1: Low integrity (0x0800 < LOW_RID 0x1000)
    add_utf16(&mut payload, "LOW\\user");
    add_u32(&mut payload, 100); // pid
    add_u32(&mut payload, 0x01); // handle
    add_u32(&mut payload, 0x0800); // integrity = Low
    add_u32(&mut payload, 0); // impersonation
    add_u32(&mut payload, 2); // Impersonation token
    // Token 2: Medium integrity (0x2000)
    add_utf16(&mut payload, "MED\\user");
    add_u32(&mut payload, 200); // pid
    add_u32(&mut payload, 0x02); // handle
    add_u32(&mut payload, 0x2000); // integrity = Medium
    add_u32(&mut payload, 1); // impersonation = Identification
    add_u32(&mut payload, 2); // Impersonation token
    // Token 3: High integrity (0x3000)
    add_utf16(&mut payload, "HIGH\\user");
    add_u32(&mut payload, 300); // pid
    add_u32(&mut payload, 0x03); // handle
    add_u32(&mut payload, 0x3000); // integrity = High
    add_u32(&mut payload, 2); // impersonation = Impersonation
    add_u32(&mut payload, 2); // Impersonation token
    // Token 4: System integrity (0x4000)
    add_utf16(&mut payload, "SYS\\user");
    add_u32(&mut payload, 400); // pid
    add_u32(&mut payload, 0x04); // handle
    add_u32(&mut payload, 0x4000); // integrity = System
    add_u32(&mut payload, 0); // impersonation = Anonymous
    add_u32(&mut payload, 2); // Impersonation token
    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 57, &payload).await?;

    let event = receiver.recv().await.ok_or("find tokens integrity response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let output = &message.info.output;
    // Verify each integrity level is correctly mapped
    assert!(output.contains("Low"));
    assert!(output.contains("Medium"));
    assert!(output.contains("High"));
    assert!(output.contains("System"));
    // Verify impersonation level labels
    assert!(output.contains("Anonymous"));
    assert!(output.contains("Identification"));
    // "Impersonation" appears as both token type and impersonation level
    assert!(output.contains("Impersonation"));
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

#[tokio::test]
async fn token_privs_list_callback_rejects_truncated_row() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    // PrivsGetOrList with priv_list=1 (list mode), one complete priv followed by truncation.
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::PrivsGetOrList));
    add_u32(&mut payload, 1); // priv_list flag
    // First complete privilege entry
    add_bytes(&mut payload, b"SeDebugPrivilege\0");
    add_u32(&mut payload, 3); // state = Enabled
    // Second row: privilege name present but state truncated
    add_bytes(&mut payload, b"SeShutdownPrivilege\0");
    // Missing: state u32

    let err = dispatcher
        .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 31, &payload)
        .await
        .expect_err("truncated privilege list row must be rejected");
    assert!(
        matches!(
            err,
            CommandDispatchError::InvalidCallbackPayload { command_id, .. }
            if command_id == u32::from(DemonCommand::CommandToken)
        ),
        "expected InvalidCallbackPayload, got {err:?}"
    );
    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "no event should be broadcast on parse failure"
    );
    Ok(())
}

#[tokio::test]
async fn token_find_tokens_callback_rejects_truncated_row() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    // FindTokens with success=1, num_tokens=2 but only one complete token row,
    // the second row truncated after domain_user.
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonTokenCommand::FindTokens));
    add_u32(&mut payload, 1); // success
    add_u32(&mut payload, 2); // num_tokens
    // First complete token entry
    add_utf16(&mut payload, "LAB\\admin"); // domain_user
    add_u32(&mut payload, 5678); // pid
    add_u32(&mut payload, 0x10); // handle
    add_u32(&mut payload, 0x3000); // integrity
    add_u32(&mut payload, 2); // impersonation level
    add_u32(&mut payload, 1); // token type
    // Second token: only domain_user, missing remaining fields
    add_utf16(&mut payload, "LAB\\guest");

    let err = dispatcher
        .dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandToken), 32, &payload)
        .await
        .expect_err("truncated found-token row must be rejected");
    assert!(
        matches!(
            err,
            CommandDispatchError::InvalidCallbackPayload { command_id, .. }
            if command_id == u32::from(DemonCommand::CommandToken)
        ),
        "expected InvalidCallbackPayload, got {err:?}"
    );
    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "no event should be broadcast on parse failure"
    );
    Ok(())
}

#[tokio::test]
async fn socket_read_callback_broadcasts_error_when_relay_delivery_fails()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonSocketCommand::Read));
    add_u32(&mut payload, 0x55);
    add_u32(&mut payload, u32::from(DemonSocketType::ReverseProxy));
    add_u32(&mut payload, 1);
    add_bytes(&mut payload, b"hello");

    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandSocket), 27, &payload).await?;

    let event = receiver.recv().await.ok_or("socket relay delivery error missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("Failed to deliver socks data for 85"));
    assert!(msg.contains("SOCKS5 client 0x00000055 not found"));
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    Ok(())
}

#[tokio::test]
async fn socket_rportfwd_add_callback_broadcasts_success_and_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut success = Vec::new();
    add_u32(&mut success, u32::from(DemonSocketCommand::ReversePortForwardAdd));
    add_u32(&mut success, 1);
    add_u32(&mut success, 0x55);
    add_u32(&mut success, u32::from_le_bytes([127, 0, 0, 1]));
    add_u32(&mut success, 4444);
    add_u32(&mut success, u32::from_le_bytes([10, 0, 0, 5]));
    add_u32(&mut success, 8080);

    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandSocket), 28, &success).await?;

    let success_event = receiver.recv().await.ok_or("missing rportfwd add success event")?;
    let OperatorMessage::AgentResponse(success_message) = success_event else {
        panic!("expected agent response event");
    };
    assert_eq!(success_message.info.extra.get("Type"), Some(&Value::String("Info".to_owned())));
    assert_eq!(
        success_message.info.extra.get("Message"),
        Some(&Value::String(
            "Started reverse port forward on 127.0.0.1:4444 to 10.0.0.5:8080 [Id: 55]".to_owned(),
        ))
    );

    let mut failure = Vec::new();
    add_u32(&mut failure, u32::from(DemonSocketCommand::ReversePortForwardAdd));
    add_u32(&mut failure, 0);
    add_u32(&mut failure, 0x66);
    add_u32(&mut failure, u32::from_le_bytes([192, 168, 1, 10]));
    add_u32(&mut failure, 9001);
    add_u32(&mut failure, u32::from_le_bytes([172, 16, 1, 20]));
    add_u32(&mut failure, 22);

    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandSocket), 29, &failure).await?;

    let failure_event = receiver.recv().await.ok_or("missing rportfwd add failure event")?;
    let OperatorMessage::AgentResponse(failure_message) = failure_event else {
        panic!("expected agent response event");
    };
    assert_eq!(failure_message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    assert_eq!(
        failure_message.info.extra.get("Message"),
        Some(&Value::String(
            "Failed to start reverse port forward on 192.168.1.10:9001 to 172.16.1.20:22"
                .to_owned(),
        ))
    );
    Ok(())
}

#[tokio::test]
async fn socket_rportfwd_list_callback_formats_output_rows()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonSocketCommand::ReversePortForwardList));
    add_u32(&mut payload, 0x21);
    add_u32(&mut payload, u32::from_le_bytes([127, 0, 0, 1]));
    add_u32(&mut payload, 8080);
    add_u32(&mut payload, u32::from_le_bytes([10, 0, 0, 8]));
    add_u32(&mut payload, 80);
    add_u32(&mut payload, 0x22);
    add_u32(&mut payload, u32::from_le_bytes([0, 0, 0, 0]));
    add_u32(&mut payload, 8443);
    add_u32(&mut payload, u32::from_le_bytes([192, 168, 56, 10]));
    add_u32(&mut payload, 443);

    dispatcher.dispatch(0xCAFE_BABE, u32::from(DemonCommand::CommandSocket), 30, &payload).await?;

    let event = receiver.recv().await.ok_or("missing rportfwd list event")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Info".to_owned())));
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("reverse port forwards:".to_owned()))
    );
    assert!(message.info.output.contains("Socket ID"));
    assert!(message.info.output.contains("21           127.0.0.1:8080 -> 10.0.0.8:80"));
    assert!(message.info.output.contains("22           0.0.0.0:8443 -> 192.168.56.10:443"));
    Ok(())
}

#[tokio::test]
async fn socket_rportfwd_remove_callback_only_broadcasts_for_rportfwd_type()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonSocketCommand::ReversePortForwardRemove));
    add_u32(&mut payload, 0x88);
    add_u32(&mut payload, u32::from(DemonSocketType::ReversePortForward));
    add_u32(&mut payload, u32::from_le_bytes([127, 0, 0, 1]));
    add_u32(&mut payload, 7000);
    add_u32(&mut payload, u32::from_le_bytes([10, 10, 10, 10]));
    add_u32(&mut payload, 3389);

    dispatcher.dispatch(0xBEEF_CAFE, u32::from(DemonCommand::CommandSocket), 31, &payload).await?;

    let event = receiver.recv().await.ok_or("missing rportfwd remove event")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Info".to_owned())));
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String(
            "Successful closed and removed rportfwd [SocketID: 88] [Forward: 127.0.0.1:7000 -> 10.10.10.10:3389]"
                .to_owned(),
        ))
    );

    let mut other_type = Vec::new();
    add_u32(&mut other_type, u32::from(DemonSocketCommand::ReversePortForwardRemove));
    add_u32(&mut other_type, 0x99);
    add_u32(&mut other_type, u32::from(DemonSocketType::ReverseProxy));
    add_u32(&mut other_type, u32::from_le_bytes([127, 0, 0, 1]));
    add_u32(&mut other_type, 7001);
    add_u32(&mut other_type, u32::from_le_bytes([10, 10, 10, 11]));
    add_u32(&mut other_type, 3390);

    dispatcher
        .dispatch(0xBEEF_CAFE, u32::from(DemonCommand::CommandSocket), 32, &other_type)
        .await?;

    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "non-rportfwd remove should not broadcast an event"
    );
    Ok(())
}

#[tokio::test]
async fn socket_rportfwd_clear_callback_broadcasts_success_and_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut success = Vec::new();
    add_u32(&mut success, u32::from(DemonSocketCommand::ReversePortForwardClear));
    add_u32(&mut success, 1);
    dispatcher.dispatch(0xDEAD_BEEF, u32::from(DemonCommand::CommandSocket), 33, &success).await?;

    let success_event = receiver.recv().await.ok_or("missing rportfwd clear success event")?;
    let OperatorMessage::AgentResponse(success_message) = success_event else {
        panic!("expected agent response event");
    };
    assert_eq!(success_message.info.extra.get("Type"), Some(&Value::String("Good".to_owned())));
    assert_eq!(
        success_message.info.extra.get("Message"),
        Some(&Value::String("Successful closed and removed all rportfwds".to_owned()))
    );

    let mut failure = Vec::new();
    add_u32(&mut failure, u32::from(DemonSocketCommand::ReversePortForwardClear));
    add_u32(&mut failure, 0);
    dispatcher.dispatch(0xDEAD_BEEF, u32::from(DemonCommand::CommandSocket), 34, &failure).await?;

    let failure_event = receiver.recv().await.ok_or("missing rportfwd clear failure event")?;
    let OperatorMessage::AgentResponse(failure_message) = failure_event else {
        panic!("expected agent response event");
    };
    assert_eq!(failure_message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    assert_eq!(
        failure_message.info.extra.get("Message"),
        Some(&Value::String("Failed to closed and remove all rportfwds".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn socket_write_callback_broadcasts_error_on_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonSocketCommand::Write));
    add_u32(&mut payload, 0x44);
    add_u32(&mut payload, u32::from(DemonSocketType::ReverseProxy));
    add_u32(&mut payload, 0);
    add_u32(&mut payload, 10061);

    dispatcher.dispatch(0xFACE_FEED, u32::from(DemonCommand::CommandSocket), 35, &payload).await?;

    let event = receiver.recv().await.ok_or("missing socket write failure event")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Failed to write to socks target 68: 10061".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn socket_connect_and_close_callbacks_drive_socks_client_lifecycle()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    registry.insert(sample_agent_info(0x1234_5678, test_key(0x11), test_iv(0x22))).await?;
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events,
        database,
        sockets.clone(),
        None,
    );

    let started = sockets.add_socks_server(0x1234_5678, "0").await?;
    let addr = started
        .split_whitespace()
        .last()
        .ok_or("SOCKS server address missing from start message")?;
    let mut client = TcpStream::connect(addr).await?;

    client.write_all(&[5, 1, 0]).await?;
    let mut negotiation = [0_u8; 2];
    client.read_exact(&mut negotiation).await?;
    assert_eq!(negotiation, [5, 0]);

    client.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0x1F, 0x90]).await?;

    let socket_id = timeout(Duration::from_secs(5), async {
        loop {
            let queued = registry.queued_jobs(0x1234_5678).await?;
            if let Some(job) = queued.iter().find(|job| job.command_line == "socket connect") {
                let socket_id =
                    u32::from_le_bytes(job.payload[4..8].try_into().map_err(|_| "socket id")?);
                return Ok::<u32, Box<dyn std::error::Error>>(socket_id);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out waiting for socket connect job to be queued",
        )
    })??;

    let mut connect = Vec::new();
    add_u32(&mut connect, u32::from(DemonSocketCommand::Connect));
    add_u32(&mut connect, 1);
    add_u32(&mut connect, socket_id);
    add_u32(&mut connect, 0);
    dispatcher.dispatch(0x1234_5678, u32::from(DemonCommand::CommandSocket), 36, &connect).await?;

    let mut connect_reply = [0_u8; 10];
    client.read_exact(&mut connect_reply).await?;
    assert_eq!(connect_reply, [5, 0, 0, 1, 127, 0, 0, 1, 0x1F, 0x90]);

    let mut close = Vec::new();
    add_u32(&mut close, u32::from(DemonSocketCommand::Close));
    add_u32(&mut close, socket_id);
    add_u32(&mut close, u32::from(DemonSocketType::ReverseProxy));
    dispatcher.dispatch(0x1234_5678, u32::from(DemonCommand::CommandSocket), 37, &close).await?;

    let mut eof = [0_u8; 1];
    let closed = timeout(Duration::from_secs(1), client.read(&mut eof)).await?;
    assert_eq!(closed?, 0);
    Ok(())
}

#[tokio::test]
async fn socket_callback_rejects_unknown_subcommands() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let error = dispatcher
        .dispatch(
            0xDEAD_BEEF,
            u32::from(DemonCommand::CommandSocket),
            38,
            &0xFFFF_FFFF_u32.to_le_bytes(),
        )
        .await
        .expect_err("unknown socket subcommand should fail");
    assert!(matches!(
        error,
        CommandDispatchError::InvalidCallbackPayload { command_id, .. }
            if command_id == u32::from(DemonCommand::CommandSocket)
    ));
    Ok(())
}

#[tokio::test]
async fn socket_read_callback_broadcasts_error_on_agent_read_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonSocketCommand::Read));
    add_u32(&mut payload, 0x77); // socket_id
    add_u32(&mut payload, u32::from(DemonSocketType::ReverseProxy));
    add_u32(&mut payload, 0); // success = 0 (failure)
    add_u32(&mut payload, 10054); // error_code (WSAECONNRESET)

    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandSocket), 40, &payload).await?;

    let event = receiver.recv().await.ok_or("missing socket read failure event")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Failed to read from socks target 119: 10054".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn socket_read_callback_success_non_reverse_proxy_is_silent()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonSocketCommand::Read));
    add_u32(&mut payload, 0x33); // socket_id
    add_u32(&mut payload, u32::from(DemonSocketType::ReversePortForward)); // not ReverseProxy
    add_u32(&mut payload, 1); // success
    add_bytes(&mut payload, b"some data");

    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandSocket), 41, &payload).await?;

    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "read success with non-ReverseProxy type should not broadcast"
    );
    Ok(())
}

#[tokio::test]
async fn socket_write_callback_no_broadcast_on_success() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonSocketCommand::Write));
    add_u32(&mut payload, 0x44); // socket_id
    add_u32(&mut payload, u32::from(DemonSocketType::ReverseProxy));
    add_u32(&mut payload, 1); // success

    dispatcher.dispatch(0xFACE_FEED, u32::from(DemonCommand::CommandSocket), 42, &payload).await?;

    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "write success should not broadcast any event"
    );
    Ok(())
}

#[tokio::test]
async fn socket_rportfwd_list_callback_rejects_truncated_payload()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    // Build a payload with the list subcommand plus an incomplete row (only 3 of 5 fields).
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonSocketCommand::ReversePortForwardList));
    add_u32(&mut payload, 0x21); // socket_id
    add_u32(&mut payload, u32::from_le_bytes([127, 0, 0, 1])); // local_addr
    add_u32(&mut payload, 8080); // local_port
    // Missing: forward_addr and forward_port — should trigger InvalidCallbackPayload

    let error = dispatcher
        .dispatch(0xCAFE_BABE, u32::from(DemonCommand::CommandSocket), 43, &payload)
        .await
        .expect_err("truncated rportfwd list payload should fail");
    assert!(matches!(
        error,
        CommandDispatchError::InvalidCallbackPayload { command_id, .. }
            if command_id == u32::from(DemonCommand::CommandSocket)
    ));
    Ok(())
}

#[tokio::test]
async fn builtin_net_and_transfer_handlers_format_operator_output()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0x1122_3344, test_key(0x12), test_iv(0x34));
    registry.insert(agent).await?;

    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events.clone(),
        database,
        sockets,
        None,
    );
    let mut receiver = events.subscribe();

    let mut open = Vec::new();
    add_u32(&mut open, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut open, 0);
    add_u32(&mut open, 0x44);
    add_u64(&mut open, 20);
    add_utf16(&mut open, "C:\\loot.bin");
    dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandFs), 32, &open).await?;
    let _ = receiver.recv().await.ok_or("download progress event missing")?;

    let mut transfer_payload = Vec::new();
    add_u32(&mut transfer_payload, u32::from(DemonTransferCommand::List));
    add_u32(&mut transfer_payload, 0x44);
    add_u32(&mut transfer_payload, 10);
    add_u32(&mut transfer_payload, 1);
    dispatcher
        .dispatch(0x1122_3344, u32::from(DemonCommand::CommandTransfer), 33, &transfer_payload)
        .await?;

    let event = receiver.recv().await.ok_or("transfer response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("List downloads [1 current downloads]:".to_owned()))
    );
    assert!(message.info.output.contains("loot.bin"));
    assert!(message.info.output.contains("50.00%"));

    let mut net_payload = Vec::new();
    add_u32(&mut net_payload, u32::from(DemonNetCommand::Users));
    add_utf16(&mut net_payload, "WKSTN-01");
    add_utf16(&mut net_payload, "alice");
    add_u32(&mut net_payload, 1);
    add_utf16(&mut net_payload, "bob");
    add_u32(&mut net_payload, 0);
    dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 34, &net_payload).await?;

    let event = receiver.recv().await.ok_or("net response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Users on WKSTN-01: ".to_owned()))
    );
    assert!(message.info.output.contains("alice (Admin)"));
    assert!(message.info.output.contains("bob"));
    Ok(())
}

#[tokio::test]
async fn net_sessions_two_rows_produces_formatted_table() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0x1122_3344, test_key(0x12), test_iv(0x34));
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
    add_u32(&mut payload, u32::from(DemonNetCommand::Sessions));
    add_utf16(&mut payload, "SRV-01");
    // Row 1
    add_utf16(&mut payload, "10.0.0.1");
    add_utf16(&mut payload, "alice");
    add_u32(&mut payload, 120);
    add_u32(&mut payload, 5);
    // Row 2
    add_utf16(&mut payload, "10.0.0.2");
    add_utf16(&mut payload, "bob");
    add_u32(&mut payload, 300);
    add_u32(&mut payload, 0);

    dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 50, &payload).await?;

    let event = receiver.recv().await.ok_or("net sessions response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Sessions for SRV-01 [2]: ".to_owned()))
    );
    let output = &message.info.output;
    assert!(output.contains("10.0.0.1"), "output should contain first client");
    assert!(output.contains("alice"), "output should contain first user");
    assert!(output.contains("10.0.0.2"), "output should contain second client");
    assert!(output.contains("bob"), "output should contain second user");
    assert!(output.contains("Computer"), "output should contain header");
    Ok(())
}

#[tokio::test]
async fn net_share_one_row_contains_name_and_path() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0x1122_3344, test_key(0x12), test_iv(0x34));
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
    add_u32(&mut payload, u32::from(DemonNetCommand::Share));
    add_utf16(&mut payload, "FILE-SRV");
    // One share row
    add_utf16(&mut payload, "ADMIN$");
    add_utf16(&mut payload, "C:\\Windows");
    add_utf16(&mut payload, "Remote Admin");
    add_u32(&mut payload, 0);

    dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 51, &payload).await?;

    let event = receiver.recv().await.ok_or("net share response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Shares for FILE-SRV [1]: ".to_owned()))
    );
    let output = &message.info.output;
    assert!(output.contains("ADMIN$"), "output should contain share name");
    assert!(output.contains("C:\\Windows"), "output should contain share path");
    assert!(output.contains("Remote Admin"), "output should contain remark");
    Ok(())
}

#[tokio::test]
async fn net_logons_lists_each_username() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0x1122_3344, test_key(0x12), test_iv(0x34));
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
    add_u32(&mut payload, u32::from(DemonNetCommand::Logons));
    add_utf16(&mut payload, "DC-01");
    add_utf16(&mut payload, "administrator");
    add_utf16(&mut payload, "svc_backup");
    add_utf16(&mut payload, "jdoe");

    dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 52, &payload).await?;

    let event = receiver.recv().await.ok_or("net logons response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Logged on users at DC-01 [3]: ".to_owned()))
    );
    let output = &message.info.output;
    assert!(output.contains("administrator"), "output should list first user");
    assert!(output.contains("svc_backup"), "output should list second user");
    assert!(output.contains("jdoe"), "output should list third user");
    assert!(output.contains("Usernames"), "output should contain header");
    Ok(())
}

#[tokio::test]
async fn net_group_two_rows_contains_both_names() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0x1122_3344, test_key(0x12), test_iv(0x34));
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
    add_u32(&mut payload, u32::from(DemonNetCommand::Group));
    add_utf16(&mut payload, "CORP-DC");
    add_utf16(&mut payload, "Domain Admins");
    add_utf16(&mut payload, "Designated administrators of the domain");
    add_utf16(&mut payload, "Domain Users");
    add_utf16(&mut payload, "All domain users");

    dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 53, &payload).await?;

    let event = receiver.recv().await.ok_or("net group response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("List groups on CORP-DC: ".to_owned()))
    );
    let output = &message.info.output;
    assert!(output.contains("Domain Admins"), "output should contain first group");
    assert!(output.contains("Domain Users"), "output should contain second group");
    Ok(())
}

#[tokio::test]
async fn net_localgroup_two_rows_contains_both_names() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0x1122_3344, test_key(0x12), test_iv(0x34));
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
    add_u32(&mut payload, u32::from(DemonNetCommand::LocalGroup));
    add_utf16(&mut payload, "WKSTN-05");
    add_utf16(&mut payload, "Administrators");
    add_utf16(&mut payload, "Full system access");
    add_utf16(&mut payload, "Remote Desktop Users");
    add_utf16(&mut payload, "Can log on remotely");

    dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 54, &payload).await?;

    let event = receiver.recv().await.ok_or("net localgroup response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Local Groups for WKSTN-05: ".to_owned()))
    );
    let output = &message.info.output;
    assert!(output.contains("Administrators"), "output should contain first group");
    assert!(output.contains("Remote Desktop Users"), "output should contain second group");
    Ok(())
}

#[tokio::test]
async fn net_domain_nonempty_reports_domain_name() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0x1122_3344, test_key(0x12), test_iv(0x34));
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
    add_u32(&mut payload, u32::from(DemonNetCommand::Domain));
    // read_string uses read_bytes (length-prefixed UTF-8)
    add_bytes(&mut payload, b"CORP.LOCAL\0");

    dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 55, &payload).await?;

    let event = receiver.recv().await.ok_or("net domain response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Domain for this Host: CORP.LOCAL".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn net_domain_empty_reports_not_joined() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0x1122_3344, test_key(0x12), test_iv(0x34));
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
    add_u32(&mut payload, u32::from(DemonNetCommand::Domain));
    // Empty string: just a null terminator (read_string trims trailing \0)
    add_bytes(&mut payload, b"\0");

    dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 56, &payload).await?;

    let event = receiver.recv().await.ok_or("net domain empty response missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("The machine does not seem to be joined to a domain".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn net_computer_broadcasts_computer_list() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0x1122_3344, test_key(0x12), test_iv(0x34));
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
    add_u32(&mut payload, u32::from(DemonNetCommand::Computer));
    add_utf16(&mut payload, "CORP.LOCAL");
    add_utf16(&mut payload, "WS01");
    add_utf16(&mut payload, "WS02");

    let result =
        dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 57, &payload).await?;
    assert!(result.is_none(), "Computer subcommand should return None");

    let msg = timeout(Duration::from_millis(200), receiver.recv())
        .await
        .expect("should receive event")
        .expect("should have message");
    let OperatorMessage::AgentResponse(resp) = msg else {
        panic!("expected AgentResponse");
    };
    assert!(
        resp.info
            .extra
            .get("Message")
            .and_then(Value::as_str)
            .unwrap_or("")
            .contains("Computers for CORP.LOCAL [2]"),
        "message should contain target and count"
    );
    assert!(resp.info.output.contains("WS01"));
    assert!(resp.info.output.contains("WS02"));
    Ok(())
}

#[tokio::test]
async fn net_dclist_broadcasts_dc_list() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let agent = sample_agent_info(0x1122_3344, test_key(0x12), test_iv(0x34));
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
    add_u32(&mut payload, u32::from(DemonNetCommand::DcList));
    add_utf16(&mut payload, "CORP.LOCAL");
    add_utf16(&mut payload, "DC01.corp.local");

    let result =
        dispatcher.dispatch(0x1122_3344, u32::from(DemonCommand::CommandNet), 58, &payload).await?;
    assert!(result.is_none(), "DcList subcommand should return None");

    let msg = timeout(Duration::from_millis(200), receiver.recv())
        .await
        .expect("should receive event")
        .expect("should have message");
    let OperatorMessage::AgentResponse(resp) = msg else {
        panic!("expected AgentResponse");
    };
    assert!(
        resp.info
            .extra
            .get("Message")
            .and_then(Value::as_str)
            .unwrap_or("")
            .contains("Domain controllers for CORP.LOCAL [1]"),
        "message should contain target and count"
    );
    assert!(resp.info.output.contains("DC01.corp.local"));
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

/// Build a pivot SmbCommand payload wrapping the given inner callback envelope bytes.
#[tokio::test]
async fn pivot_command_callback_dispatches_inner_package_and_emits_mark_event()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets, None);

    let parent_id = 0x1111_2222;
    let parent_key = test_key(0xAA);
    let parent_iv = test_iv(0xBB);
    let child_id = 0x3333_4444;
    let child_key = test_key(0xCC);
    let child_iv = test_iv(0xDD);

    // Register both parent and child agents.
    registry.insert(sample_agent_info(parent_id, parent_key, parent_iv)).await?;
    registry.insert(sample_agent_info(child_id, child_key, child_iv)).await?;
    registry.add_link(parent_id, child_id).await?;

    // Enqueue a job on the child so we can verify the command handler sees the right
    // agent_id.  We use CommandOutput as a simple builtin that broadcasts an event.
    registry
        .enqueue_job(
            child_id,
            Job {
                command: u32::from(DemonCommand::CommandOutput),
                request_id: 0x42,
                payload: Vec::new(),
                command_line: "test-cmd".to_owned(),
                task_id: "task-42".to_owned(),
                created_at: "2026-03-17T12:00:00Z".to_owned(),
                operator: "operator".to_owned(),
            },
        )
        .await?;

    // Build a callback from the child agent containing a CommandOutput response.
    let mut inner_output = Vec::new();
    add_bytes(&mut inner_output, b"hello from pivot child");

    let inner_envelope = valid_callback_envelope(
        child_id,
        &child_key,
        &child_iv,
        u32::from(DemonCommand::CommandOutput),
        0x42,
        &inner_output,
    );
    let payload = pivot_command_payload(&inner_envelope);

    let response =
        dispatcher.dispatch(parent_id, u32::from(DemonCommand::CommandPivot), 1, &payload).await?;
    assert_eq!(response, None);

    // First event should be the agent update (mark) event from last_call_in update.
    let mark_event =
        receiver.recv().await.ok_or("expected AgentUpdate event after pivot command")?;
    let OperatorMessage::AgentUpdate(update) = mark_event else {
        return Err(format!("expected AgentUpdate, got {mark_event:?}").into());
    };
    assert_eq!(
        update.info.agent_id,
        format!("{child_id:08x}"),
        "update event must be for the child agent"
    );

    // Second event should be the output response from the inner CommandOutput handler.
    let output_event =
        receiver.recv().await.ok_or("expected AgentResponse from inner command handler")?;
    let OperatorMessage::AgentResponse(msg) = output_event else {
        return Err(format!("expected AgentResponse, got {output_event:?}").into());
    };
    assert_eq!(
        msg.info.demon_id,
        format!("{child_id:08X}"),
        "output event must reference the child agent"
    );
    Ok(())
}

#[tokio::test]
async fn pivot_command_callback_unknown_inner_agent_returns_error()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets, None);

    let parent_id = 0xAAAA_BBBB;
    let parent_key = test_key(0x11);
    let parent_iv = test_iv(0x22);
    registry.insert(sample_agent_info(parent_id, parent_key, parent_iv)).await?;

    // Build an envelope for a non-existent inner agent.
    let unknown_child_id = 0xDEAD_FACE;
    let fake_key = test_key(0x99);
    let fake_iv = test_iv(0x88);
    let inner_envelope = valid_callback_envelope(
        unknown_child_id,
        &fake_key,
        &fake_iv,
        u32::from(DemonCommand::CommandOutput),
        1,
        &[],
    );
    let payload = pivot_command_payload(&inner_envelope);

    let result =
        dispatcher.dispatch(parent_id, u32::from(DemonCommand::CommandPivot), 1, &payload).await;

    assert!(result.is_err(), "unknown inner agent must produce an error, not panic");
    Ok(())
}

#[tokio::test]
async fn pivot_command_callback_truncated_inner_payload_returns_error()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets, None);

    let parent_id = 0xBBCC_DDEE;
    let parent_key = test_key(0x33);
    let parent_iv = test_iv(0x44);
    registry.insert(sample_agent_info(parent_id, parent_key, parent_iv)).await?;

    // Build a pivot SmbCommand payload with truncated inner data (too short for an
    // envelope header).
    let truncated_inner = vec![0xDE, 0xAD];
    let payload = pivot_command_payload(&truncated_inner);

    let result =
        dispatcher.dispatch(parent_id, u32::from(DemonCommand::CommandPivot), 1, &payload).await;

    assert!(result.is_err(), "truncated inner payload must produce a parse error, not panic");
    Ok(())
}

#[tokio::test]
async fn pivot_connect_callback_non_init_inner_returns_invalid_callback()
-> Result<(), Box<dyn std::error::Error>> {
    // When the inner envelope in a pivot connect payload decodes successfully but
    // is a Callback (not Init), the handler must reject it with InvalidCallbackPayload
    // and must NOT create a link or broadcast any events.
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets, None);

    let parent_id = 0xD1D2_D3D4;
    let parent_key = test_key(0xD1);
    let parent_iv = test_iv(0xD2);
    let child_id = 0xE1E2_E3E4;
    let child_key = test_key(0xE1);
    let child_iv = test_iv(0xE2);

    // Register both agents so the parser can look up the child's key to decrypt.
    registry
        .insert_with_listener(sample_agent_info(parent_id, parent_key, parent_iv), "smb-test")
        .await?;
    registry.insert(sample_agent_info(child_id, child_key, child_iv)).await?;

    // Build a callback envelope (not init) for the child — this is the wrong message
    // type for a pivot connect inner payload.
    let mut inner_output = Vec::new();
    add_bytes(&mut inner_output, b"fake callback data");
    let callback_envelope = valid_callback_envelope(
        child_id,
        &child_key,
        &child_iv,
        u32::from(DemonCommand::CommandOutput),
        0x99,
        &inner_output,
    );

    let payload = pivot_connect_payload(&callback_envelope);
    let result =
        dispatcher.dispatch(parent_id, u32::from(DemonCommand::CommandPivot), 77, &payload).await;

    let err = result.expect_err("non-init inner envelope must be rejected");
    assert!(
        matches!(
            err,
            CommandDispatchError::InvalidCallbackPayload { command_id, ref message }
                if command_id == u32::from(DemonCommand::CommandPivot)
                    && message.contains("init")
        ),
        "expected InvalidCallbackPayload mentioning init, got {err:?}"
    );

    // No link should have been created.
    assert_eq!(
        registry.parent_of(child_id).await,
        None,
        "child must not have a parent link after malformed connect"
    );
    assert_eq!(
        registry.children_of(parent_id).await,
        Vec::<u32>::new(),
        "parent must not have children after malformed connect"
    );

    // No events should have been broadcast.
    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "no event should be broadcast when inner envelope is not an init"
    );
    Ok(())
}

#[tokio::test]
async fn pivot_command_callback_non_callback_inner_returns_invalid_callback()
-> Result<(), Box<dyn std::error::Error>> {
    // When the inner envelope in a pivot command payload decodes successfully but
    // is an Init (not Callback), the handler must reject it with InvalidCallbackPayload
    // and must NOT update liveness or broadcast any events.
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets, None);

    let parent_id = 0xF1F2_F3F4;
    let parent_key = test_key(0xF1);
    let parent_iv = test_iv(0xF2);
    let child_id = 0xA5A6_A7A8;
    let child_key = test_key(0xA5);
    let child_iv = test_iv(0xA6);

    registry.insert(sample_agent_info(parent_id, parent_key, parent_iv)).await?;

    // Capture the initial state of the parent's last_call_in so we can verify
    // no liveness update occurs on the (unregistered) child.
    let parent_before =
        registry.get(parent_id).await.ok_or("parent should exist")?.last_call_in.clone();

    // Build an init body (not callback) for an unregistered child agent —
    // this is the wrong message type for a pivot command inner payload.
    // Use the monotonic-CTR variant so the CTR-mode gate passes and the
    // parser reaches the "expected callback, got init" rejection.
    let init_envelope = valid_demon_init_body_monotonic(child_id, child_key, child_iv);
    let payload = pivot_command_payload(&init_envelope);

    let result =
        dispatcher.dispatch(parent_id, u32::from(DemonCommand::CommandPivot), 88, &payload).await;

    let err = result.expect_err("non-callback inner envelope must be rejected");
    assert!(
        matches!(
            err,
            CommandDispatchError::InvalidCallbackPayload { command_id, ref message }
                if command_id == u32::from(DemonCommand::CommandPivot)
                    && message.contains("callback")
        ),
        "expected InvalidCallbackPayload mentioning callback, got {err:?}"
    );

    // Parent's state must be unchanged.
    let parent_after = registry.get(parent_id).await.ok_or("parent should still exist")?;
    assert_eq!(
        parent_after.last_call_in, parent_before,
        "parent's last_call_in must be unchanged after malformed pivot command"
    );

    // No events should have been broadcast.
    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "no event should be broadcast when inner envelope is not a callback"
    );
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
