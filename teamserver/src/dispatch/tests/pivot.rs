//! Tests for pivot and transfer command families.

use super::common::*;

use super::super::{CommandDispatchError, CommandDispatcher};
use crate::dispatch::util::CallbackParser;
use crate::dispatch::{BuiltinDispatchContext, DownloadTracker};
use crate::{AgentRegistry, Database, DemonCallbackPackage, EventBus, Job, SocketRelayManager};
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, encrypt_agent_data};
use red_cell_common::demon::{
    DEMON_MAGIC_VALUE, DemonCommand, DemonEnvelope, DemonPivotCommand, DemonProtocolError,
    MIN_ENVELOPE_SIZE,
};
use red_cell_common::operator::OperatorMessage;
use serde_json::Value;
use tokio::time::{Duration, timeout};
use zeroize::Zeroizing;

use super::super::pivot::{
    dispatch_builtin_packages, handle_pivot_callback, handle_pivot_command_callback,
    handle_pivot_connect_callback, handle_pivot_disconnect_callback, handle_pivot_list_callback,
    inner_demon_agent_id, inner_demon_command_id,
};

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

// ---------------------------------------------------------------------------
// Tests moved from dispatch/pivot.rs inline test block
// ---------------------------------------------------------------------------

const AGENT_ID: u32 = 0xBEEF_0001;
const REQUEST_ID: u32 = 42;

/// Build a minimal valid Demon envelope wire encoding for `agent_id` with no payload.
fn valid_envelope_bytes(agent_id: u32) -> Vec<u8> {
    DemonEnvelope::new(agent_id, Vec::new()).expect("envelope construction must succeed").to_bytes()
}

/// Build a Demon envelope whose payload starts with the DEMON_INIT command ID,
/// followed by a dummy request_id. Used for pivot connect tests where the
/// inner envelope must look like an init packet.
fn valid_init_envelope_bytes(agent_id: u32) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(DemonCommand::DemonInit).to_be_bytes());
    payload.extend_from_slice(&0_u32.to_be_bytes()); // request_id
    DemonEnvelope::new(agent_id, payload)
        .expect("init envelope construction must succeed")
        .to_bytes()
}

fn push_u32(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_le_bytes());
}

/// Append a length-prefixed UTF-16LE string (as `CallbackParser::read_utf16` expects).
fn push_utf16(buf: &mut Vec<u8>, s: &str) {
    let words: Vec<u16> = s.encode_utf16().collect();
    let byte_len = (words.len() * 2) as u32;
    push_u32(buf, byte_len);
    for w in &words {
        buf.extend_from_slice(&w.to_le_bytes());
    }
}

/// Build a `CallbackParser` payload with a LE-length-prefixed byte blob.
fn length_prefixed_bytes(data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u32(&mut buf, u32::try_from(data.len()).expect("test data fits in u32"));
    buf.extend_from_slice(data);
    buf
}

/// Build a CommandOutput inner payload (LE length-prefixed UTF-8 string).
fn command_output_payload(output: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(
        &u32::try_from(output.len()).expect("test data fits in u32").to_le_bytes(),
    );
    payload.extend_from_slice(output.as_bytes());
    payload
}

async fn setup_dispatch_context()
-> (Database, AgentRegistry, EventBus, SocketRelayManager, DownloadTracker) {
    let database = Database::connect_in_memory().await.expect("in-memory DB must succeed");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(16);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let downloads = DownloadTracker::new(64 * 1024 * 1024);
    (database, registry, events, sockets, downloads)
}

#[test]
fn happy_path_returns_correct_agent_id() {
    let expected_agent_id: u32 = 0xCAFE_BABE;
    let bytes = valid_envelope_bytes(expected_agent_id);

    let result = inner_demon_agent_id(&bytes).expect("valid envelope must parse successfully");

    assert_eq!(result, expected_agent_id);
}

#[test]
fn empty_slice_returns_protocol_error_not_panic() {
    let error = inner_demon_agent_id(&[]).expect_err("empty slice must return an error, not panic");

    assert_eq!(
        error,
        DemonProtocolError::BufferTooShort {
            context: "DemonEnvelope",
            expected: MIN_ENVELOPE_SIZE,
            actual: 0,
        }
    );
}

#[test]
fn wrong_magic_returns_invalid_magic_error() {
    // Build a valid envelope then flip the magic bytes.
    let mut bytes = valid_envelope_bytes(0x1234_5678);
    // Magic occupies bytes [4..8] in big-endian order.
    bytes[4] = 0xDE;
    bytes[5] = 0xAD;
    bytes[6] = 0xBE;
    bytes[7] = 0xEE; // last byte differs from 0xEF

    let error =
        inner_demon_agent_id(&bytes).expect_err("wrong magic must return an error, not panic");

    assert_eq!(
        error,
        DemonProtocolError::InvalidMagic { expected: DEMON_MAGIC_VALUE, actual: 0xDEAD_BEEE }
    );
}

#[test]
fn command_id_happy_path_returns_correct_id() {
    let command_id: u32 = 0x0000_0063;
    let mut payload = Vec::new();
    payload.extend_from_slice(&command_id.to_be_bytes());
    let bytes = DemonEnvelope::new(0xCAFE_BABE, payload)
        .expect("envelope construction must succeed")
        .to_bytes();

    let result = inner_demon_command_id(&bytes).expect("valid envelope must parse successfully");

    assert_eq!(result, command_id);
}

#[test]
fn command_id_short_payload_returns_buffer_too_short() {
    // Payload of 3 bytes — one byte short of the required 4.
    let bytes = DemonEnvelope::new(0xCAFE_BABE, vec![0xAA, 0xBB, 0xCC])
        .expect("envelope construction must succeed")
        .to_bytes();

    let error =
        inner_demon_command_id(&bytes).expect_err("short payload must return an error, not panic");

    assert_eq!(
        error,
        DemonProtocolError::BufferTooShort { context: "inner command id", expected: 4, actual: 3 }
    );
}

#[test]
fn command_id_empty_payload_returns_buffer_too_short() {
    let bytes = DemonEnvelope::new(0xCAFE_BABE, Vec::new())
        .expect("envelope construction must succeed")
        .to_bytes();

    let error =
        inner_demon_command_id(&bytes).expect_err("empty payload must return an error, not panic");

    assert_eq!(
        error,
        DemonProtocolError::BufferTooShort { context: "inner command id", expected: 4, actual: 0 }
    );
}

#[tokio::test]
async fn pivot_list_empty_payload_returns_no_pivots_message() {
    let events = EventBus::new(16);
    let mut rx = events.subscribe();
    let payload: Vec<u8> = Vec::new();
    let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandPivot));

    let result = handle_pivot_list_callback(&events, AGENT_ID, REQUEST_ID, &mut parser).await;

    assert!(result.is_ok());
    assert!(matches!(result.as_ref(), Ok(None)));

    let msg = rx.recv().await.expect("should receive agent response");
    let OperatorMessage::AgentResponse(resp) = &msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert_eq!(message, "No pivots connected");
    assert!(resp.info.output.is_empty(), "empty list should have no output table");
}

#[tokio::test]
async fn pivot_list_two_entries_returns_table_with_both() {
    let events = EventBus::new(16);
    let mut rx = events.subscribe();

    let mut payload = Vec::new();
    let demon_id_1: u32 = 0xAAAA_BBBB;
    let demon_id_2: u32 = 0xCCCC_DDDD;
    let pipe_1 = r"\\.\pipe\pivot_one";
    let pipe_2 = r"\\.\pipe\pivot_two";
    push_u32(&mut payload, demon_id_1);
    push_utf16(&mut payload, pipe_1);
    push_u32(&mut payload, demon_id_2);
    push_utf16(&mut payload, pipe_2);

    let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandPivot));

    let result = handle_pivot_list_callback(&events, AGENT_ID, REQUEST_ID, &mut parser).await;

    assert!(result.is_ok());
    assert!(matches!(result.as_ref(), Ok(None)));

    let msg = rx.recv().await.expect("should receive agent response");
    let OperatorMessage::AgentResponse(resp) = &msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(message.contains("[2]"), "expected count [2] in message, got {message:?}");

    let output = &resp.info.output;
    assert!(output.contains("aaaabbbb"), "expected demon_id_1 hex in output, got {output:?}");
    assert!(output.contains("ccccdddd"), "expected demon_id_2 hex in output, got {output:?}");
    assert!(output.contains(pipe_1), "expected pipe_1 in output, got {output:?}");
    assert!(output.contains(pipe_2), "expected pipe_2 in output, got {output:?}");
}

#[tokio::test]
async fn pivot_list_single_entry_returns_table_with_one() {
    let events = EventBus::new(16);
    let mut rx = events.subscribe();

    let mut payload = Vec::new();
    let demon_id: u32 = 0x1234_ABCD;
    let pipe = r"\\.\pipe\single_pivot";
    push_u32(&mut payload, demon_id);
    push_utf16(&mut payload, pipe);

    let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandPivot));

    let result = handle_pivot_list_callback(&events, AGENT_ID, REQUEST_ID, &mut parser).await;

    assert!(result.is_ok());
    assert!(matches!(result.as_ref(), Ok(None)));

    let msg = rx.recv().await.expect("should receive agent response");
    let OperatorMessage::AgentResponse(resp) = &msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(message.contains("[1]"), "expected count [1] in message, got {message:?}");

    let output = &resp.info.output;
    assert!(output.contains("1234abcd"), "expected demon_id hex in output, got {output:?}");
    assert!(output.contains(pipe), "expected pipe path in output, got {output:?}");
    assert!(
        output.contains("DemonID") && output.contains("Named Pipe"),
        "expected table header in output, got {output:?}"
    );
}

#[tokio::test]
async fn pivot_list_truncated_payload_returns_error() {
    let events = EventBus::new(16);

    let mut payload = Vec::new();
    push_u32(&mut payload, 0x1111_2222);
    // No pipe name follows — parser should fail on read_utf16.

    let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandPivot));

    let result = handle_pivot_list_callback(&events, AGENT_ID, REQUEST_ID, &mut parser).await;

    assert!(result.is_err(), "truncated payload must return an error");
}

#[tokio::test]
async fn pivot_command_callback_happy_path_updates_last_call_in_and_dispatches()
-> Result<(), Box<dyn std::error::Error>> {
    let (database, registry, events, sockets, downloads) = setup_dispatch_context().await;
    let mut rx = events.subscribe();

    let child_id: u32 = 0x3333_4444;
    let child_key = test_key(0xCC);
    let child_iv = test_iv(0xDD);
    registry.insert(sample_agent_info(child_id, child_key, child_iv)).await?;

    let output_payload = command_output_payload("pivot child says hello");
    let inner_envelope = valid_callback_envelope(
        child_id,
        &child_key,
        &child_iv,
        u32::from(DemonCommand::CommandOutput),
        0x42,
        &output_payload,
    );

    let parser_payload = length_prefixed_bytes(&inner_envelope);
    let mut parser = CallbackParser::new(&parser_payload, u32::from(DemonCommand::CommandPivot));

    let context = BuiltinDispatchContext {
        registry: &registry,
        events: &events,
        database: &database,
        sockets: &sockets,
        downloads: &downloads,
        plugins: None,
        pivot_dispatch_depth: 0,
        max_pivot_chain_depth: crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        allow_legacy_ctr: true,
        init_secret_config: crate::DemonInitSecretConfig::None,
    };

    let result = handle_pivot_command_callback(context, AGENT_ID, &mut parser).await;
    assert!(result.is_ok(), "happy path must not return an error: {result:?}");

    // First event: AgentUpdate (mark) from last_call_in update.
    let mark_event = rx.recv().await.expect("should receive AgentUpdate event");
    let OperatorMessage::AgentUpdate(update) = &mark_event else {
        panic!("expected AgentUpdate, got {mark_event:?}");
    };
    assert_eq!(
        update.info.agent_id,
        format!("{child_id:08x}"),
        "update event must be for the child agent"
    );

    let agent = registry.get(child_id).await.expect("child agent must exist");
    assert_ne!(
        agent.last_call_in, "2026-03-09T20:00:00Z",
        "last_call_in must have been updated from its initial value"
    );

    let output_event = rx.recv().await.expect("should receive AgentResponse event");
    let OperatorMessage::AgentResponse(msg) = &output_event else {
        panic!("expected AgentResponse, got {output_event:?}");
    };
    assert_eq!(
        msg.info.demon_id,
        format!("{child_id:08X}"),
        "output event must reference the child agent"
    );
    assert!(
        msg.info.output.contains("pivot child says hello"),
        "output must contain the dispatched text"
    );
    Ok(())
}

#[tokio::test]
async fn pivot_command_callback_non_callback_envelope_returns_invalid_callback()
-> Result<(), Box<dyn std::error::Error>> {
    let (database, registry, events, sockets, downloads) = setup_dispatch_context().await;

    let child_id: u32 = 0x5555_6666;
    let child_key = test_key(0xEE);
    let child_iv = test_iv(0xFF);
    registry.insert(sample_agent_info(child_id, child_key, child_iv)).await?;

    // Build a DemonInit envelope (not a callback), which the handler must reject.
    let init_payload = {
        let mut metadata = Vec::new();
        metadata.extend_from_slice(&child_id.to_be_bytes());
        for field in &[b"host" as &[u8], b"user", b"domain", b"10.0.0.1"] {
            metadata.extend_from_slice(
                &u32::try_from(field.len()).expect("test data fits in u32").to_be_bytes(),
            );
            metadata.extend_from_slice(field);
        }
        let path_utf16: Vec<u8> =
            "C:\\a.exe".encode_utf16().flat_map(u16::to_be_bytes).chain([0, 0]).collect();
        metadata.extend_from_slice(
            &u32::try_from(path_utf16.len()).expect("test data fits in u32").to_be_bytes(),
        );
        metadata.extend_from_slice(&path_utf16);
        for _ in 0..14 {
            metadata.extend_from_slice(&0_u32.to_be_bytes());
        }
        metadata.extend_from_slice(&0_u64.to_be_bytes()); // base_address
        metadata.extend_from_slice(&0_u64.to_be_bytes()); // timestamp

        let encrypted =
            red_cell_common::crypto::encrypt_agent_data(&child_key, &child_iv, &metadata)
                .expect("init metadata encryption should succeed");

        let mut envelope_body = Vec::new();
        envelope_body.extend_from_slice(&u32::from(DemonCommand::DemonInit).to_be_bytes());
        envelope_body.extend_from_slice(&7_u32.to_be_bytes()); // request_id
        envelope_body.extend_from_slice(&child_key);
        envelope_body.extend_from_slice(&child_iv);
        envelope_body.extend_from_slice(&encrypted);

        DemonEnvelope::new(child_id, envelope_body)
            .expect("init envelope construction must succeed")
            .to_bytes()
    };

    let parser_payload = length_prefixed_bytes(&init_payload);
    let mut parser = CallbackParser::new(&parser_payload, u32::from(DemonCommand::CommandPivot));

    let context = BuiltinDispatchContext {
        registry: &registry,
        events: &events,
        database: &database,
        sockets: &sockets,
        downloads: &downloads,
        plugins: None,
        pivot_dispatch_depth: 0,
        max_pivot_chain_depth: crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        allow_legacy_ctr: true,
        init_secret_config: crate::DemonInitSecretConfig::None,
    };

    let result = handle_pivot_command_callback(context, AGENT_ID, &mut parser).await;
    assert!(result.is_err(), "non-callback envelope must return an error");

    let error = result.expect_err("expected Err");
    assert!(
        matches!(error, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {error:?}"
    );
    let error_msg = error.to_string();
    assert!(error_msg.contains("callback"), "error message should mention 'callback': {error_msg}");
    Ok(())
}

#[tokio::test]
async fn pivot_command_callback_truncated_inner_returns_protocol_error()
-> Result<(), Box<dyn std::error::Error>> {
    let (database, registry, events, sockets, downloads) = setup_dispatch_context().await;

    // Provide a truncated inner blob (too short to be a valid DemonEnvelope).
    let truncated_inner = vec![0xDE, 0xAD];
    let parser_payload = length_prefixed_bytes(&truncated_inner);
    let mut parser = CallbackParser::new(&parser_payload, u32::from(DemonCommand::CommandPivot));

    let context = BuiltinDispatchContext {
        registry: &registry,
        events: &events,
        database: &database,
        sockets: &sockets,
        downloads: &downloads,
        plugins: None,
        pivot_dispatch_depth: 0,
        max_pivot_chain_depth: crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        allow_legacy_ctr: true,
        init_secret_config: crate::DemonInitSecretConfig::None,
    };

    let result = handle_pivot_command_callback(context, AGENT_ID, &mut parser).await;
    assert!(result.is_err(), "truncated inner data must return an error");

    let error = result.expect_err("expected Err");
    assert!(
        matches!(error, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {error:?}"
    );
    Ok(())
}

#[tokio::test]
async fn dispatch_builtin_packages_with_command_output_emits_event()
-> Result<(), Box<dyn std::error::Error>> {
    let (database, registry, events, sockets, downloads) = setup_dispatch_context().await;
    let mut rx = events.subscribe();

    let child_id: u32 = 0x7777_8888;
    let child_key = test_key(0x11);
    let child_iv = test_iv(0x22);
    registry.insert(sample_agent_info(child_id, child_key, child_iv)).await?;

    let context = BuiltinDispatchContext {
        registry: &registry,
        events: &events,
        database: &database,
        sockets: &sockets,
        downloads: &downloads,
        plugins: None,
        pivot_dispatch_depth: 0,
        max_pivot_chain_depth: crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        allow_legacy_ctr: true,
        init_secret_config: crate::DemonInitSecretConfig::None,
    };

    let packages = vec![DemonCallbackPackage {
        command_id: u32::from(DemonCommand::CommandOutput),
        request_id: 0x99,
        payload: command_output_payload("dispatched output text"),
    }];

    let result = dispatch_builtin_packages(context, child_id, &packages).await;
    assert!(result.is_ok(), "dispatch_builtin_packages must not fail: {result:?}");

    assert_eq!(result.expect("unwrap"), None, "CommandOutput should not produce response bytes");

    let event = rx.recv().await.expect("should receive AgentResponse event");
    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(
        msg.info.demon_id,
        format!("{child_id:08X}"),
        "event must reference the correct agent"
    );
    assert!(
        msg.info.output.contains("dispatched output text"),
        "event output must contain the dispatched text"
    );
    Ok(())
}

#[tokio::test]
async fn dispatch_builtin_packages_at_max_depth_logs_audit_and_returns_ok_none()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH;

    let (database, registry, events, sockets, downloads) = setup_dispatch_context().await;
    let mut rx = events.subscribe();

    let child_id: u32 = 0xDEAD_C0DE;
    let child_key = test_key(0xAA);
    let child_iv = test_iv(0xBB);
    registry.insert(sample_agent_info(child_id, child_key, child_iv)).await?;

    let context = BuiltinDispatchContext {
        registry: &registry,
        events: &events,
        database: &database,
        sockets: &sockets,
        downloads: &downloads,
        plugins: None,
        pivot_dispatch_depth: DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        max_pivot_chain_depth: DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        allow_legacy_ctr: true,
        init_secret_config: crate::DemonInitSecretConfig::None,
    };

    let packages = vec![DemonCallbackPackage {
        command_id: u32::from(DemonCommand::CommandOutput),
        request_id: 0x01,
        payload: command_output_payload("should not reach handler"),
    }];

    let result = dispatch_builtin_packages(context, child_id, &packages).await;
    assert!(result.is_ok(), "dispatch at max depth must return Ok, not Err: {result:?}");
    assert_eq!(result.expect("must be Ok"), None, "dispatch at max depth must return Ok(None)");

    let event = rx.recv().await.expect("must receive an error event");
    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{child_id:08X}"), "event must name triggering agent");
    let error_text =
        msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or(&msg.info.output);
    assert!(
        error_text.contains("Pivot") || error_text.to_lowercase().contains("depth"),
        "error message must mention pivot depth: {:?}",
        msg.info
    );

    let page = crate::audit::query_audit_log(&database, &crate::audit::AuditQuery::default())
        .await
        .expect("audit query must succeed");
    assert!(
        page.items.iter().any(|r| r.action == "pivot_depth_exceeded"),
        "an audit record with action=pivot_depth_exceeded must exist"
    );

    Ok(())
}

#[tokio::test]
async fn dispatch_builtin_packages_just_below_max_depth_succeeds()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH;

    let (database, registry, events, sockets, downloads) = setup_dispatch_context().await;

    let child_id: u32 = 0xC0DE_CAFE;
    let child_key = test_key(0x33);
    let child_iv = test_iv(0x44);
    registry.insert(sample_agent_info(child_id, child_key, child_iv)).await?;

    let context = BuiltinDispatchContext {
        registry: &registry,
        events: &events,
        database: &database,
        sockets: &sockets,
        downloads: &downloads,
        plugins: None,
        pivot_dispatch_depth: DEFAULT_MAX_PIVOT_CHAIN_DEPTH - 1,
        max_pivot_chain_depth: DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        allow_legacy_ctr: true,
        init_secret_config: crate::DemonInitSecretConfig::None,
    };

    let packages = vec![DemonCallbackPackage {
        command_id: u32::from(DemonCommand::CommandOutput),
        request_id: 0x02,
        payload: command_output_payload("near limit"),
    }];

    let result = dispatch_builtin_packages(context, child_id, &packages).await;
    assert!(result.is_ok(), "dispatch just below max depth must succeed: {result:?}");
    Ok(())
}

#[tokio::test]
async fn dispatch_builtin_packages_uses_configurable_depth_limit()
-> Result<(), Box<dyn std::error::Error>> {
    let (database, registry, events, sockets, downloads) = setup_dispatch_context().await;
    let mut rx = events.subscribe();

    let child_id: u32 = 0xCAFE_BABE;
    let child_key = test_key(0x55);
    let child_iv = test_iv(0x66);
    registry.insert(sample_agent_info(child_id, child_key, child_iv)).await?;

    let context = BuiltinDispatchContext {
        registry: &registry,
        events: &events,
        database: &database,
        sockets: &sockets,
        downloads: &downloads,
        plugins: None,
        pivot_dispatch_depth: 3,
        max_pivot_chain_depth: 3,
        allow_legacy_ctr: true,
        init_secret_config: crate::DemonInitSecretConfig::None,
    };

    let packages = vec![DemonCallbackPackage {
        command_id: u32::from(DemonCommand::CommandOutput),
        request_id: 0x03,
        payload: command_output_payload("must not dispatch"),
    }];

    let result = dispatch_builtin_packages(context, child_id, &packages).await;
    assert_eq!(result.expect("must be Ok"), None, "at custom depth limit must return Ok(None)");

    let event = rx.recv().await.expect("must receive error event for custom limit");
    assert!(
        matches!(event, OperatorMessage::AgentResponse(_)),
        "must emit AgentResponse error event"
    );

    Ok(())
}

/// Build a disconnect callback payload: success (u32 LE) + child_agent_id (u32 LE).
fn disconnect_payload(success: u32, child_agent_id: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u32(&mut buf, success);
    push_u32(&mut buf, child_agent_id);
    buf
}

#[tokio::test]
async fn pivot_disconnect_success_marks_child_dead_and_broadcasts_events()
-> Result<(), Box<dyn std::error::Error>> {
    let (_database, registry, events, _sockets, _downloads) = setup_dispatch_context().await;
    let mut rx = events.subscribe();

    let parent_id: u32 = 0xAAAA_0001;
    let child_id: u32 = 0xAAAA_0002;
    let parent_key = test_key(0x10);
    let parent_iv = test_iv(0x11);
    let child_key = test_key(0x20);
    let child_iv = test_iv(0x21);

    registry.insert(sample_agent_info(parent_id, parent_key, parent_iv)).await?;
    registry.insert(sample_agent_info(child_id, child_key, child_iv)).await?;
    registry.add_link(parent_id, child_id).await?;

    let child_before = registry.get(child_id).await.expect("child must exist");
    assert!(child_before.active, "child must be active before disconnect");

    let payload = disconnect_payload(1, child_id);
    let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandPivot));

    let result =
        handle_pivot_disconnect_callback(&registry, &events, parent_id, REQUEST_ID, &mut parser)
            .await;
    assert!(result.is_ok(), "success path must not error: {result:?}");
    assert!(matches!(result, Ok(None)), "handler should return Ok(None)");

    let mark_event = rx.recv().await.expect("should receive AgentUpdate mark event");
    let OperatorMessage::AgentUpdate(update) = &mark_event else {
        panic!("expected AgentUpdate, got {mark_event:?}");
    };
    assert_eq!(
        update.info.agent_id,
        format!("{child_id:08X}"),
        "mark event must be for the child agent"
    );
    assert_eq!(update.info.marked, "Dead", "child agent must be marked Dead");

    let resp_event = rx.recv().await.expect("should receive AgentResponse event");
    let OperatorMessage::AgentResponse(resp) = &resp_event else {
        panic!("expected AgentResponse, got {resp_event:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(
        message.contains(&format!("{child_id:08X}")),
        "response must contain child agent ID hex, got: {message}"
    );
    assert!(
        message.contains("disconnected"),
        "response should mention disconnection, got: {message}"
    );

    let child_after = registry.get(child_id).await.expect("child must still exist");
    assert!(!child_after.active, "child must be inactive after disconnect");

    Ok(())
}

#[tokio::test]
async fn pivot_disconnect_success_cascades_to_grandchild() -> Result<(), Box<dyn std::error::Error>>
{
    let (_database, registry, events, _sockets, _downloads) = setup_dispatch_context().await;
    let mut rx = events.subscribe();

    let parent_id: u32 = 0xBBBB_0001;
    let child_id: u32 = 0xBBBB_0002;
    let grandchild_id: u32 = 0xBBBB_0003;

    registry.insert(sample_agent_info(parent_id, test_key(0x30), test_iv(0x31))).await?;
    registry.insert(sample_agent_info(child_id, test_key(0x40), test_iv(0x41))).await?;
    registry.insert(sample_agent_info(grandchild_id, test_key(0x50), test_iv(0x51))).await?;

    // parent -> child -> grandchild
    registry.add_link(parent_id, child_id).await?;
    registry.add_link(child_id, grandchild_id).await?;

    let payload = disconnect_payload(1, child_id);
    let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandPivot));

    let result =
        handle_pivot_disconnect_callback(&registry, &events, parent_id, REQUEST_ID, &mut parser)
            .await;
    assert!(result.is_ok(), "cascading disconnect must succeed: {result:?}");

    let mut marked_agents = Vec::new();
    for _ in 0..2 {
        let event = rx.recv().await.expect("should receive mark event");
        let OperatorMessage::AgentUpdate(update) = &event else {
            panic!("expected AgentUpdate, got {event:?}");
        };
        assert_eq!(update.info.marked, "Dead");
        marked_agents.push(update.info.agent_id.clone());
    }
    assert!(
        marked_agents.contains(&format!("{child_id:08X}")),
        "child must be in marked agents: {marked_agents:?}"
    );
    assert!(
        marked_agents.contains(&format!("{grandchild_id:08X}")),
        "grandchild must be in marked agents: {marked_agents:?}"
    );

    let child = registry.get(child_id).await.expect("child must exist");
    assert!(!child.active, "child must be dead after cascading disconnect");
    let grandchild = registry.get(grandchild_id).await.expect("grandchild must exist");
    assert!(!grandchild.active, "grandchild must be dead after cascading disconnect");

    let parent = registry.get(parent_id).await.expect("parent must exist");
    assert!(parent.active, "parent must remain alive after disconnecting a child");

    Ok(())
}

#[tokio::test]
async fn pivot_disconnect_failure_broadcasts_error_and_leaves_child_alive()
-> Result<(), Box<dyn std::error::Error>> {
    let (_database, registry, events, _sockets, _downloads) = setup_dispatch_context().await;
    let mut rx = events.subscribe();

    let parent_id: u32 = 0xCCCC_0001;
    let child_id: u32 = 0xCCCC_0002;

    registry.insert(sample_agent_info(parent_id, test_key(0x60), test_iv(0x61))).await?;
    registry.insert(sample_agent_info(child_id, test_key(0x70), test_iv(0x71))).await?;
    registry.add_link(parent_id, child_id).await?;

    // success == 0 means failure
    let payload = disconnect_payload(0, child_id);
    let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandPivot));

    let result =
        handle_pivot_disconnect_callback(&registry, &events, parent_id, REQUEST_ID, &mut parser)
            .await;
    assert!(result.is_ok(), "failure path must not error: {result:?}");
    assert!(matches!(result, Ok(None)), "handler should return Ok(None)");

    let resp_event = rx.recv().await.expect("should receive AgentResponse event");
    let OperatorMessage::AgentResponse(resp) = &resp_event else {
        panic!("expected AgentResponse, got {resp_event:?}");
    };
    let kind = resp.info.extra.get("Type").and_then(Value::as_str).unwrap_or("");
    assert_eq!(kind, "Error", "failure path must produce an Error response");
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(
        message.contains("Failed to disconnect"),
        "error message must mention failure, got: {message}"
    );
    assert!(
        message.contains(&format!("{child_id:08X}")),
        "error message must contain child agent ID, got: {message}"
    );

    let child = registry.get(child_id).await.expect("child must exist");
    assert!(child.active, "child must remain active when disconnect fails");

    let no_extra = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
    assert!(no_extra.is_err(), "no additional events should be broadcast on failure path");

    Ok(())
}

/// Build a connect callback payload: success (u32 LE) + LE-length-prefixed inner bytes.
fn connect_payload(success: u32, inner_envelope: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u32(&mut buf, success);
    push_u32(&mut buf, u32::try_from(inner_envelope.len()).expect("test data fits in u32"));
    buf.extend_from_slice(inner_envelope);
    buf
}

#[tokio::test]
async fn pivot_connect_reconnect_reuses_existing_agent_and_emits_mark_event()
-> Result<(), Box<dyn std::error::Error>> {
    let (_database, registry, events, _sockets, _downloads) = setup_dispatch_context().await;
    let mut rx = events.subscribe();

    let parent_id: u32 = 0xDD00_0001;
    let child_id: u32 = 0xDD00_0002;

    registry.insert(sample_agent_info(parent_id, test_key(0xA0), test_iv(0xA1))).await?;
    registry.insert(sample_agent_info(child_id, test_key(0xB0), test_iv(0xB1))).await?;
    registry.add_link(parent_id, child_id).await?;

    registry.disconnect_link(parent_id, child_id, "test-disconnect").await?;
    let child_before = registry.get(child_id).await.expect("child must exist");
    assert!(!child_before.active, "child must be dead before reconnect");

    // Drain the disconnect mark event(s).
    let _ = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;

    let inner_envelope = valid_init_envelope_bytes(child_id);
    let payload = connect_payload(1, &inner_envelope);
    let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandPivot));

    let result = handle_pivot_connect_callback(
        &registry,
        &events,
        parent_id,
        REQUEST_ID,
        &mut parser,
        true,
        crate::DemonInitSecretConfig::None,
    )
    .await;
    assert!(result.is_ok(), "reconnect must succeed: {result:?}");

    let mark_event = rx.recv().await.expect("should receive AgentUpdate mark event");
    let OperatorMessage::AgentUpdate(update) = &mark_event else {
        panic!("expected AgentUpdate, got {mark_event:?}");
    };
    assert_eq!(update.info.agent_id, format!("{child_id:08X}"));
    assert_eq!(update.info.marked, "Alive", "reconnected child must be marked Alive");

    let resp_event = rx.recv().await.expect("should receive AgentResponse event");
    let OperatorMessage::AgentResponse(resp) = &resp_event else {
        panic!("expected AgentResponse, got {resp_event:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(
        message.contains("[SMB] Connected to pivot agent"),
        "response must confirm pivot connection, got: {message}"
    );

    let child_after = registry.get(child_id).await.expect("child must exist");
    assert!(child_after.active, "child must be active after reconnect");

    assert_ne!(
        child_after.last_call_in, child_before.last_call_in,
        "last_call_in must be updated on reconnect"
    );

    Ok(())
}

#[tokio::test]
async fn pivot_connect_reconnect_active_agent_emits_mark_event()
-> Result<(), Box<dyn std::error::Error>> {
    let (_database, registry, events, _sockets, _downloads) = setup_dispatch_context().await;
    let mut rx = events.subscribe();

    let parent_id: u32 = 0xEE00_0001;
    let child_id: u32 = 0xEE00_0002;

    registry.insert(sample_agent_info(parent_id, test_key(0xC0), test_iv(0xC1))).await?;
    registry.insert(sample_agent_info(child_id, test_key(0xD0), test_iv(0xD1))).await?;

    // Child is already active — reconnect should still succeed.
    let inner_envelope = valid_init_envelope_bytes(child_id);
    let payload = connect_payload(1, &inner_envelope);
    let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandPivot));

    let result = handle_pivot_connect_callback(
        &registry,
        &events,
        parent_id,
        REQUEST_ID,
        &mut parser,
        true,
        crate::DemonInitSecretConfig::None,
    )
    .await;
    assert!(result.is_ok(), "reconnect of active agent must succeed: {result:?}");

    let event = rx.recv().await.expect("should receive event");
    assert!(
        matches!(&event, OperatorMessage::AgentUpdate(_)),
        "reconnect must emit AgentUpdate, not AgentNew; got {event:?}"
    );

    Ok(())
}

#[tokio::test]
async fn pivot_connect_failure_broadcasts_error_low_level() -> Result<(), Box<dyn std::error::Error>>
{
    let (_database, registry, events, _sockets, _downloads) = setup_dispatch_context().await;
    let mut rx = events.subscribe();

    let parent_id: u32 = 0xFF00_0001;
    registry.insert(sample_agent_info(parent_id, test_key(0xE0), test_iv(0xE1))).await?;

    // success == 0, error_code == 5 (ERROR_ACCESS_DENIED)
    let mut payload = Vec::new();
    push_u32(&mut payload, 0); // success = false
    push_u32(&mut payload, 5); // error code
    let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandPivot));

    let result = handle_pivot_connect_callback(
        &registry,
        &events,
        parent_id,
        REQUEST_ID,
        &mut parser,
        true,
        crate::DemonInitSecretConfig::None,
    )
    .await;
    assert!(result.is_ok(), "failure path must return Ok(None): {result:?}");

    let resp_event = rx.recv().await.expect("should receive AgentResponse event");
    let OperatorMessage::AgentResponse(resp) = &resp_event else {
        panic!("expected AgentResponse, got {resp_event:?}");
    };
    let kind = resp.info.extra.get("Type").and_then(Value::as_str).unwrap_or("");
    assert_eq!(kind, "Error", "failure path must produce an Error response");
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(
        message.contains("Failed to connect"),
        "error message must mention failure, got: {message}"
    );

    Ok(())
}

/// Build init metadata in the format expected by `parse_init_agent`.
fn build_init_metadata(agent_id: u32) -> Vec<u8> {
    fn add_str_be(buf: &mut Vec<u8>, value: &str) {
        buf.extend_from_slice(&(value.len() as u32).to_be_bytes());
        buf.extend_from_slice(value.as_bytes());
    }
    fn add_utf16_be(buf: &mut Vec<u8>, value: &str) {
        let utf16: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
        buf.extend_from_slice(&(utf16.len() as u32).to_be_bytes());
        buf.extend_from_slice(&utf16);
    }

    let mut m = Vec::new();
    m.extend_from_slice(&agent_id.to_be_bytes()); // agent_id
    add_str_be(&mut m, "pivot-host"); // hostname
    add_str_be(&mut m, "operator"); // username
    add_str_be(&mut m, "PIVOTLAB"); // domain
    add_str_be(&mut m, "10.0.0.99"); // internal_ip
    add_utf16_be(&mut m, "C:\\Windows\\svchost.exe"); // process_path
    m.extend_from_slice(&1234_u32.to_be_bytes()); // pid
    m.extend_from_slice(&5678_u32.to_be_bytes()); // tid
    m.extend_from_slice(&512_u32.to_be_bytes()); // ppid
    m.extend_from_slice(&2_u32.to_be_bytes()); // arch (x64)
    m.extend_from_slice(&1_u32.to_be_bytes()); // elevated
    m.extend_from_slice(&0x401000_u64.to_be_bytes()); // base_address
    m.extend_from_slice(&10_u32.to_be_bytes()); // os_major
    m.extend_from_slice(&0_u32.to_be_bytes()); // os_minor
    m.extend_from_slice(&1_u32.to_be_bytes()); // os_product_type
    m.extend_from_slice(&0_u32.to_be_bytes()); // os_service_pack
    m.extend_from_slice(&22000_u32.to_be_bytes()); // os_build
    m.extend_from_slice(&9_u32.to_be_bytes()); // os_arch
    m.extend_from_slice(&15_u32.to_be_bytes()); // sleep_delay
    m.extend_from_slice(&20_u32.to_be_bytes()); // sleep_jitter
    m.extend_from_slice(&1_893_456_000_u64.to_be_bytes()); // kill_date
    m.extend_from_slice(&0b101010_i32.to_be_bytes()); // working_hours
    m
}

/// Build a complete DEMON_INIT wire packet for a brand-new agent (full metadata).
fn build_full_init_packet(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> Vec<u8> {
    let metadata = build_init_metadata(agent_id);
    let encrypted =
        encrypt_agent_data(&key, &iv, &metadata).expect("metadata encryption should succeed");

    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(DemonCommand::DemonInit).to_be_bytes());
    payload.extend_from_slice(&7_u32.to_be_bytes()); // request_id
    payload.extend_from_slice(&key);
    payload.extend_from_slice(&iv);
    payload.extend_from_slice(&encrypted);

    DemonEnvelope::new(agent_id, payload)
        .expect("init envelope construction must succeed")
        .to_bytes()
}

#[tokio::test]
async fn pivot_connect_new_agent_registers_child_and_emits_agent_new()
-> Result<(), Box<dyn std::error::Error>> {
    let (_database, registry, events, _sockets, _downloads) = setup_dispatch_context().await;
    let mut rx = events.subscribe();

    let parent_id: u32 = 0xAA00_0001;
    let child_id: u32 = 0xAA00_0002;
    let child_key = test_key(0xF0);
    let child_iv = test_iv(0xF1);

    registry.insert(sample_agent_info(parent_id, test_key(0xE0), test_iv(0xE1))).await?;

    assert!(registry.get(child_id).await.is_none(), "child must not be pre-registered");

    let inner_envelope = build_full_init_packet(child_id, child_key, child_iv);
    let payload = connect_payload(1, &inner_envelope);
    let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandPivot));

    let result = handle_pivot_connect_callback(
        &registry,
        &events,
        parent_id,
        REQUEST_ID,
        &mut parser,
        true,
        crate::DemonInitSecretConfig::None,
    )
    .await;
    assert!(result.is_ok(), "new-agent pivot connect must succeed: {result:?}");
    assert!(matches!(result, Ok(None)), "handler should return Ok(None)");

    let child_agent = registry.get(child_id).await.expect("child must be registered after connect");
    assert!(child_agent.active, "new child agent must be active");
    assert_eq!(child_agent.hostname, "pivot-host", "child hostname must match init metadata");

    let parent = registry.parent_of(child_id).await;
    assert_eq!(parent, Some(parent_id), "pivot link must set parent_id as child's parent");

    let new_event = rx.recv().await.expect("should receive AgentNew event");
    assert!(
        matches!(&new_event, OperatorMessage::AgentNew(_)),
        "new-agent path must emit AgentNew, not AgentUpdate; got {new_event:?}"
    );

    let resp_event = rx.recv().await.expect("should receive AgentResponse event");
    let OperatorMessage::AgentResponse(resp) = &resp_event else {
        panic!("expected AgentResponse, got {resp_event:?}");
    };
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(
        message.contains("[SMB] Connected to pivot agent"),
        "response must confirm pivot connection, got: {message}"
    );

    Ok(())
}

#[tokio::test]
async fn pivot_connect_new_agent_uses_parent_listener_name()
-> Result<(), Box<dyn std::error::Error>> {
    let (_database, registry, events, _sockets, _downloads) = setup_dispatch_context().await;
    let _rx = events.subscribe();

    let parent_id: u32 = 0xBB00_0001;
    let child_id: u32 = 0xBB00_0002;
    let child_key = test_key(0xF2);
    let child_iv = test_iv(0xF3);

    registry.insert(sample_agent_info(parent_id, test_key(0xE2), test_iv(0xE3))).await?;

    let inner_envelope = build_full_init_packet(child_id, child_key, child_iv);
    let payload = connect_payload(1, &inner_envelope);
    let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandPivot));

    let result = handle_pivot_connect_callback(
        &registry,
        &events,
        parent_id,
        REQUEST_ID,
        &mut parser,
        true,
        crate::DemonInitSecretConfig::None,
    )
    .await;
    assert!(result.is_ok(), "new-agent connect must succeed: {result:?}");

    let child_listener = registry.listener_name(child_id).await;
    assert!(child_listener.is_some(), "child must have a listener name after registration");

    Ok(())
}

#[tokio::test]
async fn pivot_connect_new_agent_with_invalid_init_returns_error()
-> Result<(), Box<dyn std::error::Error>> {
    let (_database, registry, events, _sockets, _downloads) = setup_dispatch_context().await;

    let parent_id: u32 = 0xCC00_0001;
    let child_id: u32 = 0xCC00_0002;

    registry.insert(sample_agent_info(parent_id, test_key(0xE4), test_iv(0xE5))).await?;

    // An envelope with DEMON_INIT command ID but truncated metadata that parse_for_listener rejects.
    let inner_envelope = valid_init_envelope_bytes(child_id);
    let payload = connect_payload(1, &inner_envelope);
    let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandPivot));

    let result = handle_pivot_connect_callback(
        &registry,
        &events,
        parent_id,
        REQUEST_ID,
        &mut parser,
        true,
        crate::DemonInitSecretConfig::None,
    )
    .await;
    assert!(result.is_err(), "invalid init metadata must return an error");

    let error = result.expect_err("expected Err");
    assert!(
        matches!(error, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {error:?}"
    );

    assert!(
        registry.get(child_id).await.is_none(),
        "child must not be registered when init parsing fails"
    );

    Ok(())
}

/// Regression test: when a listener is configured with `InitSecret`, pivot-tunnelled
/// DEMON_INIT packets must have their session keys derived via HKDF.
#[tokio::test]
async fn pivot_connect_new_agent_applies_hkdf_when_init_secret_configured()
-> Result<(), Box<dyn std::error::Error>> {
    let (_database, registry, events, _sockets, _downloads) = setup_dispatch_context().await;
    let _rx = events.subscribe();

    let parent_id: u32 = 0xCC00_0001;
    let child_id: u32 = 0xCC00_0002;
    let child_key = test_key(0xC2);
    let child_iv = test_iv(0xC3);

    registry.insert(sample_agent_info(parent_id, test_key(0xC0), test_iv(0xC1))).await?;

    let inner_envelope = build_full_init_packet(child_id, child_key, child_iv);
    let payload = connect_payload(1, &inner_envelope);
    let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandPivot));

    let server_secret = b"test-server-secret".to_vec();
    let result = handle_pivot_connect_callback(
        &registry,
        &events,
        parent_id,
        REQUEST_ID,
        &mut parser,
        true,
        crate::DemonInitSecretConfig::Unversioned(Zeroizing::new(server_secret.clone())),
    )
    .await;
    assert!(result.is_ok(), "pivot connect with init_secret must succeed: {result:?}");

    let child =
        registry.get(child_id).await.expect("child agent must be registered after pivot connect");

    let derived =
        red_cell_common::crypto::derive_session_keys(&child_key, &child_iv, &server_secret)
            .expect("derive_session_keys must succeed");

    assert_eq!(
        child.encryption.aes_key.as_slice(),
        derived.key.as_ref(),
        "stored AES key must be HKDF-derived, not the raw packet key"
    );
    assert_eq!(
        child.encryption.aes_iv.as_slice(),
        derived.iv.as_ref(),
        "stored AES IV must be HKDF-derived, not the raw packet IV"
    );

    assert_ne!(
        child.encryption.aes_key.as_slice(),
        &child_key,
        "raw packet key must not be stored when init_secret is configured"
    );

    Ok(())
}

/// Build a Demon envelope whose payload starts with an arbitrary command ID (not `DemonInit`).
fn non_init_envelope_bytes(agent_id: u32, command: DemonCommand) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(command).to_be_bytes());
    payload.extend_from_slice(&0_u32.to_be_bytes()); // request_id
    DemonEnvelope::new(agent_id, payload)
        .expect("non-init envelope construction must succeed")
        .to_bytes()
}

#[tokio::test]
async fn pivot_connect_non_demon_init_inner_command_returns_error()
-> Result<(), Box<dyn std::error::Error>> {
    let (_database, registry, events, _sockets, _downloads) = setup_dispatch_context().await;
    let mut rx = events.subscribe();

    let parent_id: u32 = 0xAA00_0001;
    let child_id: u32 = 0xAA00_0002;

    registry.insert(sample_agent_info(parent_id, test_key(0xF0), test_iv(0xF1))).await?;

    let inner_envelope = non_init_envelope_bytes(child_id, DemonCommand::CommandOutput);
    let payload = connect_payload(1, &inner_envelope);
    let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandPivot));

    let result = handle_pivot_connect_callback(
        &registry,
        &events,
        parent_id,
        REQUEST_ID,
        &mut parser,
        true,
        crate::DemonInitSecretConfig::None,
    )
    .await;
    assert!(result.is_err(), "non-DemonInit inner command must be rejected");

    let error = result.expect_err("expected Err");
    assert!(
        matches!(error, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {error:?}"
    );

    assert!(
        registry.get(child_id).await.is_none(),
        "child must not be registered when inner command is not DemonInit"
    );

    let no_event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
    assert!(no_event.is_err(), "no event should be broadcast when inner command is rejected");

    Ok(())
}

#[tokio::test]
async fn pivot_callback_unknown_subcommand_returns_invalid_callback_payload() {
    let (database, registry, events, sockets, downloads) = setup_dispatch_context().await;

    let payload = 0xFFFF_FFFFu32.to_le_bytes().to_vec();

    let context = BuiltinDispatchContext {
        registry: &registry,
        events: &events,
        database: &database,
        sockets: &sockets,
        downloads: &downloads,
        plugins: None,
        pivot_dispatch_depth: 0,
        max_pivot_chain_depth: crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        allow_legacy_ctr: true,
        init_secret_config: crate::DemonInitSecretConfig::None,
    };

    let result = handle_pivot_callback(context, AGENT_ID, REQUEST_ID, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for unknown subcommand, got {result:?}"
    );
}

#[tokio::test]
async fn pivot_callback_empty_payload_returns_invalid_callback_payload() {
    let (database, registry, events, sockets, downloads) = setup_dispatch_context().await;

    let context = BuiltinDispatchContext {
        registry: &registry,
        events: &events,
        database: &database,
        sockets: &sockets,
        downloads: &downloads,
        plugins: None,
        pivot_dispatch_depth: 0,
        max_pivot_chain_depth: crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        allow_legacy_ctr: true,
        init_secret_config: crate::DemonInitSecretConfig::None,
    };

    let result = handle_pivot_callback(context, AGENT_ID, REQUEST_ID, &[]).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for empty payload, got {result:?}"
    );
}

#[tokio::test]
async fn pivot_callback_unknown_subcommand_does_not_broadcast_event() {
    let (database, registry, events, sockets, downloads) = setup_dispatch_context().await;
    let mut rx = events.subscribe();

    let payload = 0xFFFF_FFFFu32.to_le_bytes().to_vec();

    let context = BuiltinDispatchContext {
        registry: &registry,
        events: &events,
        database: &database,
        sockets: &sockets,
        downloads: &downloads,
        plugins: None,
        pivot_dispatch_depth: 0,
        max_pivot_chain_depth: crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        allow_legacy_ctr: true,
        init_secret_config: crate::DemonInitSecretConfig::None,
    };

    let _result = handle_pivot_callback(context, AGENT_ID, REQUEST_ID, &payload).await;

    let no_event = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
    assert!(no_event.is_err(), "no event should be broadcast for an unknown pivot subcommand");
}
