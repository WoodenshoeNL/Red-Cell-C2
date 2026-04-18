//! Single-hop pivot dispatch tests (happy path).

use super::*;

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

#[test]
fn happy_path_returns_correct_agent_id() {
    let expected_agent_id: u32 = 0xCAFE_BABE;
    let bytes = valid_envelope_bytes(expected_agent_id);

    let result = inner_demon_agent_id(&bytes).expect("valid envelope must parse successfully");

    assert_eq!(result, expected_agent_id);
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
