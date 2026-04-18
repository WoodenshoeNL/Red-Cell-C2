//! Tests for sleep, exit, and kill_date callbacks.

use super::*;

fn sleep_payload(delay: u32, jitter: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u32(&mut buf, delay);
    push_u32(&mut buf, jitter);
    buf
}

#[tokio::test]
async fn sleep_callback_updates_agent_state() {
    let (registry, events) = setup().await;
    let payload = sleep_payload(60, 20);

    let result = handle_sleep_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    assert!(result.is_ok());
    assert_eq!(result.expect("unwrap"), None);

    let agent = registry.get(AGENT_ID).await.expect("agent must exist");
    assert_eq!(agent.sleep_delay, 60);
    assert_eq!(agent.sleep_jitter, 20);
}

#[tokio::test]
async fn sleep_callback_broadcasts_agent_update_and_response() {
    let (registry, events) = setup().await;
    let mut rx = events.subscribe();
    let payload = sleep_payload(30, 10);

    handle_sleep_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload)
        .await
        .expect("handler must succeed");

    // First broadcast: AgentUpdate (mark event)
    let msg1 = rx.recv().await.expect("should receive agent update");
    assert!(matches!(msg1, OperatorMessage::AgentUpdate(_)), "expected AgentUpdate, got {msg1:?}");

    // Second broadcast: AgentResponse
    // Drop the event bus so recv returns None after the last queued message.
    drop(events);
    let msg2 = rx.recv().await.expect("should receive agent response");
    let OperatorMessage::AgentResponse(resp) = &msg2 else {
        panic!("expected AgentResponse, got {msg2:?}");
    };
    assert_eq!(resp.info.demon_id, format!("{AGENT_ID:08X}"));
    let kind = resp.info.extra.get("Type").and_then(Value::as_str);
    assert_eq!(kind, Some("Good"));
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(
        message.contains("30") && message.contains("10"),
        "expected message to contain delay=30 and jitter=10, got {message:?}"
    );
}

#[tokio::test]
async fn sleep_callback_truncated_payload_returns_error() {
    let (registry, events) = setup().await;
    // Only 4 bytes — missing the jitter field.
    let mut payload = Vec::new();
    push_u32(&mut payload, 60);

    let result = handle_sleep_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    let err = result.expect_err("truncated payload must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn sleep_callback_empty_payload_returns_error() {
    let (registry, events) = setup().await;
    let payload = Vec::new();

    let result = handle_sleep_callback(&registry, &events, AGENT_ID, REQUEST_ID, &payload).await;
    let err = result.expect_err("empty payload must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn sleep_callback_agent_not_found_returns_error() {
    let db = Database::connect_in_memory().await.expect("in-memory db must succeed");
    let registry = AgentRegistry::new(db);
    let events = EventBus::new(8);
    let payload = sleep_payload(60, 20);
    let nonexistent_id = 0xDEAD_FFFF;

    let result =
        handle_sleep_callback(&registry, &events, nonexistent_id, REQUEST_ID, &payload).await;
    let err = result.expect_err("nonexistent agent must fail");
    assert!(
        matches!(err, CommandDispatchError::Registry(TeamserverError::AgentNotFound { .. })),
        "expected AgentNotFound, got {err:?}"
    );
}

fn exit_payload(exit_method: u32) -> Vec<u8> {
    let mut buf = Vec::new();
    push_u32(&mut buf, exit_method);
    buf
}

#[tokio::test]
async fn exit_callback_thread_exit_marks_agent_dead() {
    let (registry, events, sockets) = setup_with_sockets().await;
    let payload = exit_payload(1);

    let result =
        handle_exit_callback(&registry, &sockets, &events, None, AGENT_ID, REQUEST_ID, &payload)
            .await;
    assert!(result.is_ok());
    assert_eq!(result.expect("unwrap"), None);

    let agent = registry.get(AGENT_ID).await.expect("agent must exist");
    assert!(!agent.active, "agent should be marked dead");
    assert!(
        agent.reason.contains("exit thread"),
        "reason should mention thread exit, got {:?}",
        agent.reason
    );
}

#[tokio::test]
async fn exit_callback_process_exit_marks_agent_dead() {
    let (registry, events, sockets) = setup_with_sockets().await;
    let payload = exit_payload(2);

    handle_exit_callback(&registry, &sockets, &events, None, AGENT_ID, REQUEST_ID, &payload)
        .await
        .expect("handler must succeed");

    let agent = registry.get(AGENT_ID).await.expect("agent must exist");
    assert!(!agent.active, "agent should be marked dead");
    assert!(
        agent.reason.contains("exit process"),
        "reason should mention process exit, got {:?}",
        agent.reason
    );
}

#[tokio::test]
async fn exit_callback_unknown_method_marks_agent_dead_generic() {
    let (registry, events, sockets) = setup_with_sockets().await;
    let payload = exit_payload(99);

    handle_exit_callback(&registry, &sockets, &events, None, AGENT_ID, REQUEST_ID, &payload)
        .await
        .expect("handler must succeed");

    let agent = registry.get(AGENT_ID).await.expect("agent must exist");
    assert!(!agent.active, "agent should be marked dead");
    assert_eq!(agent.reason, "Agent exited");
}

#[tokio::test]
async fn exit_callback_broadcasts_mark_and_response() {
    let (registry, events, sockets) = setup_with_sockets().await;
    let mut rx = events.subscribe();
    let payload = exit_payload(1);

    handle_exit_callback(&registry, &sockets, &events, None, AGENT_ID, REQUEST_ID, &payload)
        .await
        .expect("handler must succeed");

    // First broadcast: AgentUpdate (mark event)
    let msg1 = rx.recv().await.expect("should receive agent update");
    assert!(matches!(msg1, OperatorMessage::AgentUpdate(_)), "expected AgentUpdate, got {msg1:?}");

    // Second broadcast: AgentResponse
    drop(events);
    let msg2 = rx.recv().await.expect("should receive agent response");
    let OperatorMessage::AgentResponse(resp) = &msg2 else {
        panic!("expected AgentResponse, got {msg2:?}");
    };
    let kind = resp.info.extra.get("Type").and_then(Value::as_str);
    assert_eq!(kind, Some("Good"));
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(message.contains("exit thread"), "expected message about thread exit, got {message:?}");
}

#[tokio::test]
async fn exit_callback_empty_payload_returns_error() {
    let (registry, events, sockets) = setup_with_sockets().await;
    let payload = Vec::new();

    let result =
        handle_exit_callback(&registry, &sockets, &events, None, AGENT_ID, REQUEST_ID, &payload)
            .await;
    let err = result.expect_err("empty payload must fail");
    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

#[tokio::test]
async fn kill_date_callback_marks_agent_dead() {
    let (registry, events, sockets) = setup_with_sockets().await;
    let payload = Vec::new(); // kill date callback ignores payload

    handle_kill_date_callback(&registry, &sockets, &events, None, AGENT_ID, REQUEST_ID, &payload)
        .await
        .expect("handler must succeed");

    let agent = registry.get(AGENT_ID).await.expect("agent must exist");
    assert!(!agent.active, "agent should be marked dead");
    assert!(
        agent.reason.contains("kill date"),
        "reason should mention kill date, got {:?}",
        agent.reason
    );
}

#[tokio::test]
async fn kill_date_callback_broadcasts_mark_and_response() {
    let (registry, events, sockets) = setup_with_sockets().await;
    let mut rx = events.subscribe();
    let payload = Vec::new();

    handle_kill_date_callback(&registry, &sockets, &events, None, AGENT_ID, REQUEST_ID, &payload)
        .await
        .expect("handler must succeed");

    // First broadcast: AgentUpdate (mark event)
    let msg1 = rx.recv().await.expect("should receive agent update");
    assert!(matches!(msg1, OperatorMessage::AgentUpdate(_)), "expected AgentUpdate, got {msg1:?}");

    // Second broadcast: AgentResponse
    drop(events);
    let msg2 = rx.recv().await.expect("should receive agent response");
    let OperatorMessage::AgentResponse(resp) = &msg2 else {
        panic!("expected AgentResponse, got {msg2:?}");
    };
    let kind = resp.info.extra.get("Type").and_then(Value::as_str);
    assert_eq!(kind, Some("Good"));
    let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(message.contains("kill date"), "expected message about kill date, got {message:?}");
}

#[tokio::test]
async fn exit_callback_nonexistent_agent_returns_error() {
    let db = Database::connect_in_memory().await.expect("in-memory db must succeed");
    let registry = AgentRegistry::new(db);
    let events = EventBus::new(8);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let mut rx = events.subscribe();
    let nonexistent_id = 0xDEAD_FFFF;
    let payload = exit_payload(1);

    let result = handle_exit_callback(
        &registry,
        &sockets,
        &events,
        None,
        nonexistent_id,
        REQUEST_ID,
        &payload,
    )
    .await;
    let err = result.expect_err("nonexistent agent must fail");
    assert!(
        matches!(err, CommandDispatchError::Registry(TeamserverError::AgentNotFound { .. })),
        "expected AgentNotFound, got {err:?}"
    );

    // Drop all senders so the receiver closes, then verify no events were queued.
    drop(sockets);
    drop(events);
    assert!(rx.recv().await.is_none(), "no events should be broadcast for a nonexistent agent");
}

#[tokio::test]
async fn kill_date_callback_nonexistent_agent_returns_error() {
    let db = Database::connect_in_memory().await.expect("in-memory db must succeed");
    let registry = AgentRegistry::new(db);
    let events = EventBus::new(8);
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let mut rx = events.subscribe();
    let nonexistent_id = 0xDEAD_FFFF;
    let payload = Vec::new();

    let result = handle_kill_date_callback(
        &registry,
        &sockets,
        &events,
        None,
        nonexistent_id,
        REQUEST_ID,
        &payload,
    )
    .await;
    let err = result.expect_err("nonexistent agent must fail");
    assert!(
        matches!(err, CommandDispatchError::Registry(TeamserverError::AgentNotFound { .. })),
        "expected AgentNotFound, got {err:?}"
    );

    // Drop all senders so the receiver closes, then verify no events were queued.
    drop(sockets);
    drop(events);
    assert!(rx.recv().await.is_none(), "no events should be broadcast for a nonexistent agent");
}
