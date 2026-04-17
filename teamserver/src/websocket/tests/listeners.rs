//! Listener-lifecycle WebSocket tests: create/start/stop/delete broadcast and
//! persistence, plus audit-trail entries for remove/edit on both the success
//! and failure paths.

use red_cell_common::operator::OperatorMessage;

use super::{
    TestState, listener_edit_message, listener_mark_message, listener_new_message,
    listener_remove_message, login, read_operator_message, sample_listener_info, spawn_server,
};
use crate::{AuditQuery, AuditResultStatus, query_audit_log};

#[tokio::test]
async fn websocket_listener_commands_broadcast_and_persist_state() {
    let state = TestState::new().await;
    let listeners = state.listeners.clone();
    // Login each socket immediately after connecting to avoid the 5-second
    // unauthenticated-connection timeout firing while the other login round-trip
    // is in flight under heavy parallel-test load.
    let (mut sender, server) = spawn_server(state.clone()).await;
    login(&mut sender, "operator", "password1234").await;
    let (mut observer, _) = spawn_server(state).await;
    login(&mut observer, "operator", "password1234").await;

    sender
        .send_text(listener_new_message(
            "operator",
            sample_listener_info("alpha", "Online", 0),
            false,
        ))
        .await;

    let created = read_operator_message(&mut observer).await;
    let OperatorMessage::ListenerNew(message) = created else {
        panic!("expected listener create broadcast");
    };
    assert_eq!(message.head.user, "operator");
    assert_eq!(message.info.name.as_deref(), Some("alpha"));

    let started = read_operator_message(&mut observer).await;
    let OperatorMessage::ListenerMark(message) = started else {
        panic!("expected listener start broadcast");
    };
    assert_eq!(message.info.name, "alpha");
    assert_eq!(message.info.mark, "Online");
    assert_eq!(
        listeners.summary("alpha").await.expect("listener should exist").state.status,
        crate::ListenerStatus::Running
    );

    sender.send_text(listener_mark_message("operator", "alpha", "stopped")).await;

    let stopped = read_operator_message(&mut observer).await;
    let OperatorMessage::ListenerMark(message) = stopped else {
        panic!("expected listener stop broadcast");
    };
    assert_eq!(message.info.name, "alpha");
    assert_eq!(message.info.mark, "Offline");
    assert_eq!(
        listeners.summary("alpha").await.expect("listener should exist").state.status,
        crate::ListenerStatus::Stopped
    );

    sender.send_text(listener_remove_message("operator", "alpha")).await;

    let removed = read_operator_message(&mut observer).await;
    let OperatorMessage::ListenerRemove(message) = removed else {
        panic!("expected listener delete broadcast");
    };
    assert_eq!(message.info.name, "alpha");
    assert!(listeners.summary("alpha").await.is_err());

    sender.close().await;
    observer.close().await;
    server.abort();
}

#[tokio::test]
async fn websocket_listener_remove_records_audit_trail() {
    let state = TestState::new().await;
    let database = state.database.clone();
    let (mut socket, server) = spawn_server(state).await;

    login(&mut socket, "operator", "password1234").await;

    socket
        .send_text(listener_new_message(
            "operator",
            sample_listener_info("beta", "Online", 0),
            false,
        ))
        .await;

    let _created = read_operator_message(&mut socket).await;
    let _started = read_operator_message(&mut socket).await;

    socket.send_text(listener_remove_message("operator", "beta")).await;

    let _removed = read_operator_message(&mut socket).await;

    let page = query_audit_log(
        &database,
        &AuditQuery { action: Some("listener.delete".to_owned()), ..AuditQuery::default() },
    )
    .await
    .expect("audit query should succeed");

    assert!(!page.items.is_empty(), "expected at least one listener.delete audit entry");
    let entry = &page.items[0];
    assert_eq!(entry.action, "listener.delete");
    assert_eq!(entry.target_kind, "listener");
    assert_eq!(entry.target_id.as_deref(), Some("beta"));
    assert_eq!(entry.result_status, AuditResultStatus::Success);

    socket.close().await;
    server.abort();
}

#[tokio::test]
async fn websocket_listener_remove_nonexistent_records_failure_audit() {
    let state = TestState::new().await;
    let database = state.database.clone();
    let (mut socket, server) = spawn_server(state).await;

    login(&mut socket, "operator", "password1234").await;

    socket.send_text(listener_remove_message("operator", "ghost")).await;

    let _error_msg = read_operator_message(&mut socket).await;

    let page = query_audit_log(
        &database,
        &AuditQuery { action: Some("listener.delete".to_owned()), ..AuditQuery::default() },
    )
    .await
    .expect("audit query should succeed");

    assert!(!page.items.is_empty(), "expected at least one listener.delete audit entry");
    let entry = &page.items[0];
    assert_eq!(entry.action, "listener.delete");
    assert_eq!(entry.target_kind, "listener");
    assert_eq!(entry.result_status, AuditResultStatus::Failure);

    socket.close().await;
    server.abort();
}

#[tokio::test]
async fn websocket_listener_edit_records_audit_trail() {
    let state = TestState::new().await;
    let database = state.database.clone();
    let (mut socket, server) = spawn_server(state).await;

    login(&mut socket, "operator", "password1234").await;

    socket
        .send_text(listener_new_message(
            "operator",
            sample_listener_info("gamma", "Online", 8443),
            false,
        ))
        .await;

    let _created = read_operator_message(&mut socket).await;
    let _started = read_operator_message(&mut socket).await;

    let mut updated = sample_listener_info("gamma", "Online", 9443);
    updated.headers = Some("X-Test: updated".to_owned());

    socket.send_text(listener_edit_message("operator", updated)).await;

    let _updated = read_operator_message(&mut socket).await;

    let page = query_audit_log(
        &database,
        &AuditQuery { action: Some("listener.update".to_owned()), ..AuditQuery::default() },
    )
    .await
    .expect("audit query should succeed");

    assert!(!page.items.is_empty(), "expected at least one listener.update audit entry");
    let entry = &page.items[0];
    assert_eq!(entry.action, "listener.update");
    assert_eq!(entry.target_kind, "listener");
    assert_eq!(entry.target_id.as_deref(), Some("gamma"));
    assert_eq!(entry.result_status, AuditResultStatus::Success);

    socket.close().await;
    server.abort();
}

#[tokio::test]
async fn websocket_listener_edit_nonexistent_records_failure_audit() {
    let state = TestState::new().await;
    let database = state.database.clone();
    let (mut socket, server) = spawn_server(state).await;

    login(&mut socket, "operator", "password1234").await;

    socket
        .send_text(listener_edit_message("operator", sample_listener_info("ghost", "Online", 9443)))
        .await;

    let _error_msg = read_operator_message(&mut socket).await;

    let page = query_audit_log(
        &database,
        &AuditQuery { action: Some("listener.update".to_owned()), ..AuditQuery::default() },
    )
    .await
    .expect("audit query should succeed");

    assert!(!page.items.is_empty(), "expected at least one listener.update audit entry");
    let entry = &page.items[0];
    assert_eq!(entry.action, "listener.update");
    assert_eq!(entry.target_kind, "listener");
    assert_eq!(entry.target_id.as_deref(), Some("ghost"));
    assert_eq!(entry.result_status, AuditResultStatus::Failure);

    socket.close().await;
    server.abort();
}
