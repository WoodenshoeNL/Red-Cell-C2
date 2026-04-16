//! Tests for pivot and transfer command families.

use super::common::*;

use super::super::{CommandDispatchError, CommandDispatcher};
use crate::{AgentRegistry, Database, EventBus, Job, SocketRelayManager};
use red_cell_common::demon::{DemonCommand, DemonPivotCommand};
use red_cell_common::operator::OperatorMessage;
use serde_json::Value;
use tokio::time::{Duration, timeout};

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
