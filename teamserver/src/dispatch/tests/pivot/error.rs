//! Error-path and depth-limit tests.

use super::*;

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
