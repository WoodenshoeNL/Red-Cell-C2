//! Authentication-related WebSocket tests: connection manager, login enforcement,
//! pre-auth frame rejection, rate limiting, and permission-denied auditing.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use red_cell_common::operator::{
    AgentTaskInfo, EventCode, Message, MessageHead, OperatorMessage, SessionCode, TeamserverLogInfo,
};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message as ClientMessage;
use uuid::Uuid;

use super::super::{
    LOGIN_WINDOW_DURATION, LoginRateLimiter, MAX_FAILED_LOGIN_ATTEMPTS, MAX_LOGIN_ATTEMPT_WINDOWS,
    OPERATOR_MAX_MESSAGE_SIZE, OperatorConnectionManager,
};
use super::{
    TestState, listener_new_message, login, login_message, read_operator_message,
    read_operator_snapshot, spawn_server, wait_for_connection_count,
};
use crate::{AuditQuery, AuditResultStatus, query_audit_log};

#[tokio::test]
async fn connection_manager_tracks_registered_and_authenticated_clients() {
    let manager = OperatorConnectionManager::new();
    let first = Uuid::new_v4();
    let second = Uuid::new_v4();

    let test_ip: std::net::IpAddr = [127, 0, 0, 1].into();
    manager.register(first, test_ip).await;
    manager.register(second, test_ip).await;
    manager.authenticate(first, "operator".to_owned()).await;

    assert_eq!(manager.connection_count().await, 2);
    assert_eq!(manager.authenticated_count().await, 1);

    manager.unregister(first).await;
    manager.unregister(second).await;

    assert_eq!(manager.connection_count().await, 0);
    assert_eq!(manager.authenticated_count().await, 0);
}

#[tokio::test]
async fn connection_manager_active_operators_returns_authenticated_only() {
    let manager = OperatorConnectionManager::new();

    let authed_id = Uuid::new_v4();
    let unauthed_id = Uuid::new_v4();
    let ip_a: std::net::IpAddr = [10, 0, 0, 1].into();
    let ip_b: std::net::IpAddr = [10, 0, 0, 2].into();

    manager.register(authed_id, ip_a).await;
    manager.register(unauthed_id, ip_b).await;
    manager.authenticate(authed_id, "alice".to_owned()).await;

    let active = manager.active_operators().await;
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].username, "alice");
    assert_eq!(active[0].remote_addr, ip_a);

    manager.unregister(authed_id).await;
    let active = manager.active_operators().await;
    assert!(active.is_empty(), "unregistered connection should be gone");
}

#[tokio::test]
async fn websocket_requires_login_before_other_messages() {
    let state = TestState::new().await;
    let connection_registry = state.connections.clone();
    let (mut socket, server) = spawn_server(state).await;

    let non_login = serde_json::to_string(&OperatorMessage::TeamserverLog(Message {
        head: MessageHead {
            event: EventCode::Teamserver,
            user: "operator".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: TeamserverLogInfo { text: "hello".to_owned() },
    }))
    .expect("message should serialize");

    socket.send_frame(ClientMessage::Text(non_login.into())).await;

    let response = read_operator_message(&mut socket).await;
    assert!(matches!(response, OperatorMessage::InitConnectionError(_)));

    wait_for_connection_count(&connection_registry, 0).await;
    server.abort();
}

/// Error path: a malformed (non-JSON) first frame causes the handler to close
/// the socket without leaving any stale `authenticated_count` state.
#[tokio::test]
async fn websocket_handler_malformed_first_frame_leaves_no_stale_auth_count() {
    let state = TestState::new().await;
    let connections = state.connections.clone();
    let (mut socket, server) = spawn_server(state).await;

    // Send binary garbage as the very first frame — not a valid login message.
    socket
        .send_frame(ClientMessage::Binary(b"not valid json at all \x00\xff".to_vec().into()))
        .await;

    // The server must close the connection.
    wait_for_connection_count(&connections, 0).await;

    // No authenticated session must remain.
    assert_eq!(connections.authenticated_count().await, 0);

    server.abort();
}

/// Edge case: a frame larger than `OPERATOR_MAX_MESSAGE_SIZE` is rejected by the
/// cap set inside `websocket_handler` even when the client has not yet logged in,
/// and the connection closes without leaving stale state.
#[tokio::test]
async fn websocket_handler_rejects_oversized_frame_before_authentication() {
    let state = TestState::new().await;
    let connections = state.connections.clone();
    let (mut socket, server) = spawn_server(state).await;

    // Send an oversized frame as the very first message (no prior login).
    let oversized = "x".repeat(OPERATOR_MAX_MESSAGE_SIZE + 1);
    socket.send_frame(ClientMessage::Text(oversized.into())).await;

    // The server must terminate the connection (close frame or transport error).
    let frame = timeout(Duration::from_secs(5), socket.next_raw_frame())
        .await
        .expect("socket should react to oversized pre-auth frame")
        .expect("connection should close or error");
    assert!(
        matches!(frame, Err(_) | Ok(ClientMessage::Close(_))),
        "expected close or error, got {frame:?}"
    );

    wait_for_connection_count(&connections, 0).await;
    assert_eq!(connections.authenticated_count().await, 0);

    server.abort();
}

#[tokio::test]
async fn websocket_closes_when_authenticated_operator_lacks_permission() {
    let state = TestState::new().await;
    let connection_registry = state.connections.clone();
    let (mut socket, server) = spawn_server(state).await;

    socket.send_frame(ClientMessage::Text(login_message("analyst", "readonly").into())).await;
    let response = read_operator_message(&mut socket).await;
    assert!(matches!(response, OperatorMessage::InitConnectionSuccess(_)));
    let _snapshot = read_operator_snapshot(&mut socket).await;

    let task = serde_json::to_string(&OperatorMessage::AgentTask(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "analyst".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: AgentTaskInfo {
            task_id: "1".to_owned(),
            command_line: "shell whoami".to_owned(),
            demon_id: "deadbeef".to_owned(),
            command_id: SessionCode::AgentTask.as_u32().to_string(),
            agent_type: None,
            task_message: None,
            command: None,
            sub_command: None,
            arguments: None,
            extra: Default::default(),
        },
    }))
    .expect("task should serialize");

    socket.send_text(task).await;

    let close_frame = timeout(Duration::from_secs(2), socket.next_raw_frame())
        .await
        .expect("socket should close")
        .expect("close frame should be present")
        .expect("close frame should be valid");
    assert!(matches!(close_frame, ClientMessage::Close(_)));

    wait_for_connection_count(&connection_registry, 0).await;
    server.abort();
}

#[tokio::test]
async fn login_rate_limiter_allows_attempts_below_threshold() {
    let limiter = LoginRateLimiter::new();
    let ip: IpAddr = "192.168.1.10".parse().expect("valid IP");

    // try_acquire atomically checks and records; after MAX attempts the
    // next call must be rejected.
    for _ in 0..MAX_FAILED_LOGIN_ATTEMPTS {
        assert!(limiter.try_acquire(ip).await);
    }

    assert!(!limiter.try_acquire(ip).await);
}

#[tokio::test]
async fn login_rate_limiter_isolates_different_ips() {
    let limiter = LoginRateLimiter::new();
    let ip_a: IpAddr = "10.0.0.1".parse().expect("valid IP");
    let ip_b: IpAddr = "10.0.0.2".parse().expect("valid IP");

    for _ in 0..MAX_FAILED_LOGIN_ATTEMPTS {
        limiter.record_failure(ip_a).await;
    }

    assert!(!limiter.is_allowed(ip_a).await);
    assert!(limiter.is_allowed(ip_b).await);
}

#[tokio::test]
async fn login_rate_limiter_success_clears_counter() {
    let limiter = LoginRateLimiter::new();
    let ip: IpAddr = "172.16.0.5".parse().expect("valid IP");

    for _ in 0..MAX_FAILED_LOGIN_ATTEMPTS - 1 {
        limiter.record_failure(ip).await;
    }
    assert!(limiter.is_allowed(ip).await);

    limiter.record_success(ip).await;
    assert!(limiter.is_allowed(ip).await);
    assert_eq!(limiter.tracked_ip_count().await, 0);
}

#[tokio::test]
async fn login_rate_limiter_prunes_expired_windows_for_one_shot_ips() {
    let limiter = LoginRateLimiter::new();
    let expired_ip: IpAddr = "192.168.10.10".parse().expect("valid IP");
    let fresh_ip: IpAddr = "192.168.10.11".parse().expect("valid IP");

    limiter
        .with_windows_mut(|windows| {
            windows.insert(
                expired_ip,
                crate::rate_limiter::AttemptWindow {
                    attempts: 3,
                    window_start: Instant::now() - LOGIN_WINDOW_DURATION - Duration::from_secs(1),
                },
            );
        })
        .await;

    limiter.record_failure(fresh_ip).await;

    let has_expired = limiter.window_state(expired_ip).await.is_some();
    let has_fresh = limiter.window_state(fresh_ip).await.is_some();
    assert!(!has_expired);
    assert!(has_fresh);
    assert_eq!(limiter.tracked_ip_count().await, 1);
}

#[tokio::test]
async fn login_rate_limiter_caps_total_tracked_windows() {
    let limiter = LoginRateLimiter::new();
    let now = Instant::now();

    limiter
        .with_windows_mut(|windows| {
            for i in 0..MAX_LOGIN_ATTEMPT_WINDOWS {
                windows.insert(
                    IpAddr::from(std::net::Ipv4Addr::from(i as u32)),
                    crate::rate_limiter::AttemptWindow {
                        attempts: 1,
                        window_start: now
                            - Duration::from_secs((MAX_LOGIN_ATTEMPT_WINDOWS - i) as u64),
                    },
                );
            }
        })
        .await;

    let new_ip = IpAddr::from(std::net::Ipv4Addr::new(10, 0, 0, 1));
    limiter.record_failure(new_ip).await;

    let count = limiter.tracked_ip_count().await;
    assert!(count <= (MAX_LOGIN_ATTEMPT_WINDOWS / 2) + 1);
    assert!(limiter.window_state(new_ip).await.is_some());
    assert!(limiter.window_state(IpAddr::from(std::net::Ipv4Addr::from(0_u32))).await.is_none());
}

#[tokio::test]
async fn login_rate_limiter_window_reset_allows_after_expiry() {
    let limiter = LoginRateLimiter::new();
    let ip: IpAddr = "198.51.100.7".parse().expect("valid IP");

    // Lock the IP out.
    for _ in 0..MAX_FAILED_LOGIN_ATTEMPTS {
        limiter.record_failure(ip).await;
    }
    assert!(!limiter.is_allowed(ip).await, "should be locked out after max failures");

    // Manually expire the window by backdating its start time.
    limiter
        .with_windows_mut(|windows| {
            let window = windows.get_mut(&ip).expect("window should exist");
            window.window_start = Instant::now() - LOGIN_WINDOW_DURATION - Duration::from_secs(1);
        })
        .await;

    // is_allowed must detect the expired window and reset, allowing the IP again.
    assert!(limiter.is_allowed(ip).await, "should be allowed after window expiry");
    assert_eq!(limiter.tracked_ip_count().await, 0, "expired window should be removed");
}

#[tokio::test]
async fn login_rate_limiter_record_failure_resets_expired_window() {
    let limiter = LoginRateLimiter::new();
    let ip: IpAddr = "198.51.100.8".parse().expect("valid IP");

    // Manually insert an expired window with attempts at MAX.
    limiter
        .with_windows_mut(|windows| {
            windows.insert(
                ip,
                crate::rate_limiter::AttemptWindow {
                    attempts: MAX_FAILED_LOGIN_ATTEMPTS,
                    window_start: Instant::now() - LOGIN_WINDOW_DURATION - Duration::from_secs(1),
                },
            );
        })
        .await;

    // Call record_failure on the expired-but-present window.
    limiter.record_failure(ip).await;

    // The window should have been reset: attempts = 1, fresh window_start.
    let (attempts, window_start) =
        limiter.window_state(ip).await.expect("window should still exist after record_failure");
    assert_eq!(attempts, 1, "expired window should reset attempts to 1, not increment stale count");
    assert!(
        window_start.elapsed() < Duration::from_secs(2),
        "window_start should be refreshed to approximately now"
    );

    // The IP should be allowed since attempts = 1 < MAX.
    assert!(
        limiter.is_allowed(ip).await,
        "IP should be allowed after expired window is reset by record_failure"
    );
}

#[tokio::test]
async fn websocket_rejects_login_after_too_many_failures() {
    let state = TestState::new().await;
    let rate_limiter = state.login_rate_limiter.clone();
    let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");

    for _ in 0..MAX_FAILED_LOGIN_ATTEMPTS {
        rate_limiter.record_failure(ip).await;
    }

    let (mut socket, server) = spawn_server(state).await;

    socket.send_frame(ClientMessage::Text(login_message("operator", "password1234").into())).await;

    let frame = timeout(Duration::from_secs(3), socket.next_raw_frame())
        .await
        .expect("should receive a frame")
        .expect("frame should exist")
        .expect("frame should decode");

    if let ClientMessage::Text(payload) = frame {
        let msg: OperatorMessage =
            serde_json::from_str(&payload).expect("should parse operator message");
        assert!(
            matches!(msg, OperatorMessage::InitConnectionError(_)),
            "expected connection error, got {msg:?}"
        );
    } else {
        panic!("expected text frame, got {frame:?}");
    }

    server.abort();
}

#[tokio::test]
async fn permission_denied_audit_recorded_when_analyst_sends_privileged_command() {
    let state = TestState::new().await;
    let database = state.database.clone();
    let connections = state.connections.clone();
    let (mut socket, server) = spawn_server(state).await;

    login(&mut socket, "analyst", "readonly").await;

    // Send a listener-create command — analysts only have Read permission.
    socket
        .send_text(listener_new_message(
            "analyst",
            red_cell_common::operator::ListenerInfo {
                name: Some("test-listener".to_owned()),
                protocol: Some("Http".to_owned()),
                ..Default::default()
            },
            false,
        ))
        .await;

    // Server closes after rejecting the unauthorized command.
    wait_for_connection_count(&connections, 0).await;

    let page = query_audit_log(
        &database,
        &AuditQuery {
            action: Some("operator.permission_denied".to_owned()),
            actor: Some("analyst".to_owned()),
            ..AuditQuery::default()
        },
    )
    .await
    .expect("audit query should succeed");

    assert_eq!(page.total, 1, "one permission_denied record expected");
    let record = &page.items[0];
    assert_eq!(record.action, "operator.permission_denied");
    assert_eq!(record.actor, "analyst");
    assert_eq!(record.result_status, AuditResultStatus::Failure);

    server.abort();
}
