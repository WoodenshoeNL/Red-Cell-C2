//! Integration and unit tests for the command dispatch module.

mod checkin;
mod common;
mod filesystem;
mod network_token_kerberos;
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
