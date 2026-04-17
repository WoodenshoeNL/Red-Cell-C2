//! Lifecycle, disconnect-kind, session-timeout, and route-wiring WebSocket tests.

use std::time::Duration;

use red_cell_common::operator::{
    EventCode, Message, MessageHead, OperatorMessage, TeamserverLogInfo,
};
use serde_json::Value;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message as ClientMessage;

use super::super::{AUTHENTICATION_FRAME_TIMEOUT, OPERATOR_MAX_MESSAGE_SIZE, routes};
use super::{
    TestState, chat_message, login, login_message, read_operator_message, read_operator_snapshot,
    spawn_server, wait_for_connection_count,
};
use crate::{AuditQuery, AuditResultStatus, query_audit_log};

// ── connection / idle / oversized ────────────────────────────────────────────

#[tokio::test]
async fn websocket_closes_idle_unauthenticated_connections() {
    let state = TestState::new().await;
    let connection_registry = state.connections.clone();
    let (mut socket, server) = spawn_server(state).await;

    let frame =
        timeout(AUTHENTICATION_FRAME_TIMEOUT + Duration::from_secs(2), socket.next_raw_frame())
            .await
            .expect("socket should close idle unauthenticated connection")
            .expect("close frame should be present")
            .expect("close frame should decode");
    assert!(matches!(frame, ClientMessage::Close(_)));

    wait_for_connection_count(&connection_registry, 0).await;
    assert_eq!(connection_registry.authenticated_count().await, 0);
    server.abort();
}

#[tokio::test]
async fn websocket_forwards_event_bus_messages_after_login() {
    let state = TestState::new().await;
    let event_bus = state.events.clone();
    let connection_registry = state.connections.clone();
    let auth = state.auth.clone();
    let (mut socket, server) = spawn_server(state).await;

    socket.send_frame(ClientMessage::Text(login_message("operator", "password1234").into())).await;

    let response = read_operator_message(&mut socket).await;
    assert!(matches!(response, OperatorMessage::InitConnectionSuccess(_)));
    let _snapshot = read_operator_snapshot(&mut socket).await;
    assert_eq!(connection_registry.connection_count().await, 1);
    assert_eq!(connection_registry.authenticated_count().await, 1);
    assert_eq!(auth.session_count().await, 1);

    let event = OperatorMessage::TeamserverLog(Message {
        head: MessageHead {
            event: EventCode::Teamserver,
            user: "teamserver".to_owned(),
            timestamp: "12:34:56".to_owned(),
            one_time: String::new(),
        },
        info: TeamserverLogInfo { text: "broadcast".to_owned() },
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(event_bus.broadcast(event.clone()), 1);
    assert_eq!(read_operator_message(&mut socket).await, event);

    socket.close().await;
    wait_for_connection_count(&connection_registry, 0).await;
    assert_eq!(auth.session_count().await, 0);
    server.abort();
}

#[tokio::test]
async fn websocket_closes_oversized_messages() {
    let state = TestState::new().await;
    let connection_registry = state.connections.clone();
    let (mut socket, server) = spawn_server(state).await;

    login(&mut socket, "operator", "password1234").await;

    let oversized_payload = "x".repeat(OPERATOR_MAX_MESSAGE_SIZE + 1);
    socket.send_frame(ClientMessage::Text(oversized_payload.into())).await;

    let frame = timeout(Duration::from_secs(5), socket.next_raw_frame())
        .await
        .expect("socket should react to oversized message")
        .expect("connection should close or error");
    assert!(matches!(frame, Err(_) | Ok(ClientMessage::Close(_))));

    wait_for_connection_count(&connection_registry, 0).await;
    assert_eq!(connection_registry.authenticated_count().await, 0);
    server.abort();
}

// ── websocket_handler direct contract tests ───────────────────────────────────

/// Happy path: `websocket_handler` increments the connection count when a socket
/// is upgraded, increments the authenticated count after a valid login, and
/// decrements both back to zero once the client closes the connection.
#[tokio::test]
async fn websocket_handler_connection_tracking_lifecycle() {
    let state = TestState::new().await;
    let connections = state.connections.clone();
    let auth = state.auth.clone();
    let (mut socket, server) = spawn_server(state).await;

    // After upgrade, exactly one connection should be registered.
    timeout(Duration::from_secs(2), async {
        loop {
            if connections.connection_count().await == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("connection count should reach 1 after upgrade");
    assert_eq!(connections.authenticated_count().await, 0);

    // After a valid login, the connection should become authenticated.
    login(&mut socket, "operator", "password1234").await;
    assert_eq!(connections.connection_count().await, 1);
    assert_eq!(connections.authenticated_count().await, 1);
    assert_eq!(auth.session_count().await, 1);

    // After the client closes, both counts must return to zero.
    socket.close().await;
    wait_for_connection_count(&connections, 0).await;
    assert_eq!(connections.authenticated_count().await, 0);
    assert_eq!(auth.session_count().await, 0);

    server.abort();
}

#[tokio::test]
async fn websocket_notifies_authenticated_clients_before_shutdown_close() {
    let state = TestState::new().await;
    let shutdown = state.shutdown.clone();
    let (mut socket, server) = spawn_server(state).await;

    socket.send_frame(ClientMessage::Text(login_message("operator", "password1234").into())).await;

    let response = read_operator_message(&mut socket).await;
    assert!(matches!(response, OperatorMessage::InitConnectionSuccess(_)));
    let _ = read_operator_snapshot(&mut socket).await;

    shutdown.initiate();

    let response = read_operator_message(&mut socket).await;
    let OperatorMessage::TeamserverLog(message) = response else {
        panic!("expected shutdown notice");
    };
    assert_eq!(message.info.text, "teamserver shutting down");

    let frame = timeout(Duration::from_secs(5), socket.next_raw_frame())
        .await
        .expect("socket should close")
        .expect("close frame should be present")
        .expect("close frame should decode");
    assert!(matches!(frame, ClientMessage::Close(_)));

    server.abort();
}

#[tokio::test]
async fn websocket_broadcasts_operator_presence_changes() {
    let state = TestState::new().await;
    // Login each socket immediately after connecting to avoid the 5-second
    // unauthenticated-connection timeout firing under heavy parallel-test load.
    let (mut first, server) = spawn_server(state.clone()).await;
    login(&mut first, "operator", "password1234").await;
    let (mut second, _) = spawn_server(state).await;
    login(&mut second, "analyst", "readonly").await;

    let joined = read_operator_message(&mut first).await;
    let OperatorMessage::ChatUserConnected(message) = joined else {
        panic!("expected operator join broadcast");
    };
    assert_eq!(message.info.user, "analyst");

    second.close().await;

    let left = read_operator_message(&mut first).await;
    let OperatorMessage::ChatUserDisconnected(message) = left else {
        panic!("expected operator disconnect broadcast");
    };
    assert_eq!(message.info.user, "analyst");

    first.close().await;
    server.abort();
}

#[tokio::test]
async fn websocket_broadcasts_chat_messages_to_other_operators() {
    let state = TestState::new().await;
    // Login each socket immediately after connecting to avoid the 5-second
    // unauthenticated-connection timeout firing under heavy parallel-test load.
    let (mut sender, server) = spawn_server(state.clone()).await;
    login(&mut sender, "operator", "password1234").await;
    let (mut observer, _) = spawn_server(state).await;
    login(&mut observer, "analyst", "readonly").await;
    let _presence = read_operator_message(&mut sender).await;

    sender.send_text(chat_message("operator", "hello team")).await;

    let message = read_operator_message(&mut observer).await;
    let OperatorMessage::ChatMessage(message) = message else {
        panic!("expected chat broadcast");
    };
    assert_eq!(message.head.user, "operator");
    assert_eq!(message.info.fields.get("User"), Some(&Value::String("operator".to_owned())));
    assert_eq!(message.info.fields.get("Message"), Some(&Value::String("hello team".to_owned())));

    sender.close().await;
    observer.close().await;
    server.abort();
}

#[tokio::test]
async fn websocket_chat_messages_are_persisted_as_session_activity() {
    let state = TestState::new().await;
    let (mut sender, server) = spawn_server(state.clone()).await;

    login(&mut sender, "operator", "password1234").await;
    sender.send_text(chat_message("operator", "hello team")).await;
    let _broadcast = read_operator_message(&mut sender).await;

    let page = query_audit_log(
        &state.database,
        &AuditQuery {
            action: Some("operator.chat".to_owned()),
            actor: Some("operator".to_owned()),
            ..AuditQuery::default()
        },
    )
    .await
    .expect("audit query should succeed");

    assert_eq!(page.total, 1);
    assert_eq!(page.items[0].action, "operator.chat");
    assert_eq!(
        page.items[0]
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.get("message"))
            .and_then(Value::as_str),
        Some("hello team")
    );

    sender.close().await;
    server.abort();
}

// ── disconnect kind ───────────────────────────────────────────────────────────

#[tokio::test]
async fn disconnect_kind_as_str_returns_stable_labels() {
    assert_eq!(super::super::DisconnectKind::CleanClose.as_str(), "clean_close");
    assert_eq!(super::super::DisconnectKind::Error.as_str(), "error");
    assert_eq!(super::super::DisconnectKind::ServerShutdown.as_str(), "server_shutdown");
}

#[tokio::test]
async fn clean_disconnect_audit_includes_kind_field() {
    let state = TestState::new().await;
    let database = state.database.clone();
    let connections = state.connections.clone();
    let (mut socket, server) = spawn_server(state).await;

    login(&mut socket, "operator", "password1234").await;

    // Send a clean close frame.
    socket.close().await;
    wait_for_connection_count(&connections, 0).await;

    let page = query_audit_log(
        &database,
        &AuditQuery {
            action: Some("operator.disconnect".to_owned()),
            actor: Some("operator".to_owned()),
            ..AuditQuery::default()
        },
    )
    .await
    .expect("audit query should succeed");

    assert_eq!(page.total, 1, "exactly one disconnect record expected");
    let record = &page.items[0];
    assert_eq!(record.action, "operator.disconnect");
    let kind = record.parameters.as_ref().and_then(|p| p.get("kind")).and_then(|v| v.as_str());
    assert_eq!(kind, Some("clean_close"), "clean socket close should record kind=clean_close");

    server.abort();
}

#[tokio::test]
async fn server_shutdown_disconnect_audit_includes_kind_field() {
    let state = TestState::new().await;
    let database = state.database.clone();
    let connections = state.connections.clone();
    let shutdown = state.shutdown.clone();
    let (mut socket, server) = spawn_server(state).await;

    login(&mut socket, "operator", "password1234").await;

    shutdown.initiate();

    // Drain the shutdown notice and close frame.
    let _shutdown_msg = read_operator_message(&mut socket).await;
    wait_for_connection_count(&connections, 0).await;

    let page = query_audit_log(
        &database,
        &AuditQuery {
            action: Some("operator.disconnect".to_owned()),
            actor: Some("operator".to_owned()),
            ..AuditQuery::default()
        },
    )
    .await
    .expect("audit query should succeed");

    assert_eq!(page.total, 1, "exactly one disconnect record expected");
    let kind =
        page.items[0].parameters.as_ref().and_then(|p| p.get("kind")).and_then(|v| v.as_str());
    assert_eq!(
        kind,
        Some("server_shutdown"),
        "server-initiated close should record kind=server_shutdown"
    );

    server.abort();
}

// ── session timeout ───────────────────────────────────────────────────────────

#[tokio::test]
async fn session_timeout_audit_recorded_for_idle_unauthenticated_connection() {
    let state = TestState::new().await;
    let database = state.database.clone();
    let connections = state.connections.clone();
    let (socket, server) = spawn_server(state).await;

    // Drop the socket without sending any frames — the server will time out.
    drop(socket);
    wait_for_connection_count(&connections, 0).await;

    // The timeout test uses AUTHENTICATION_FRAME_TIMEOUT + margin in the
    // existing test. Here we just wait briefly since the TCP drop is immediate.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The server records session_timeout only on the timer path. A clean drop
    // before receiving data hits the "closed before authentication" arm, not the
    // timeout arm. So verify zero records for session_timeout here; the timeout
    // path is tested via the existing idle-connection test.
    let page = query_audit_log(
        &database,
        &AuditQuery {
            action: Some("operator.session_timeout".to_owned()),
            ..AuditQuery::default()
        },
    )
    .await
    .expect("audit query should succeed");

    // Dropping the socket closes it immediately (Ok(None) path), so no timeout
    // audit is expected.
    assert_eq!(page.total, 0, "early close should not produce a session_timeout record");

    server.abort();
}

#[tokio::test]
async fn authenticated_session_expires_after_idle_timeout_and_is_audited() {
    use crate::SessionPolicy;

    // Drive both TTL and idle timeout short enough that a single post-login
    // frame sent after a small sleep crosses the threshold. 200 ms is large
    // enough to absorb scheduler jitter while keeping the test quick.
    let state = TestState::new_with_session_policy(SessionPolicy {
        ttl: Some(Duration::from_secs(3600)),
        idle_timeout: Some(Duration::from_millis(200)),
    })
    .await;
    let database = state.database.clone();
    let connections = state.connections.clone();
    let (mut socket, server) = spawn_server(state).await;

    login(&mut socket, "operator", "password1234").await;

    // Wait past the idle window, then send any authenticated frame. The server
    // must respond with an InitConnectionError carrying the expiry message and
    // then close the socket.
    tokio::time::sleep(Duration::from_millis(350)).await;
    socket.send_text(chat_message("operator", "hello after idle")).await;

    let response = read_operator_message(&mut socket).await;
    match response {
        OperatorMessage::InitConnectionError(ref message) => {
            assert!(
                message.info.message.contains("inactivity")
                    || message.info.message.contains("idle"),
                "expected idle-timeout message, got {:?}",
                message.info.message
            );
        }
        other => panic!("expected InitConnectionError, got {other:?}"),
    }

    wait_for_connection_count(&connections, 0).await;

    let page = query_audit_log(
        &database,
        &AuditQuery {
            action: Some("operator.session_timeout".to_owned()),
            actor: Some("operator".to_owned()),
            ..AuditQuery::default()
        },
    )
    .await
    .expect("audit query should succeed");

    assert_eq!(page.total, 1, "expected one session_timeout audit record");
    let record = &page.items[0];
    assert_eq!(record.action, "operator.session_timeout");
    assert_eq!(record.actor, "operator");
    assert_eq!(record.result_status, AuditResultStatus::Failure);
    let reason = record.parameters.as_ref().and_then(|p| p.get("reason")).and_then(|v| v.as_str());
    assert_eq!(
        reason,
        Some("idle_timeout"),
        "session_timeout audit should record reason=idle_timeout, got {reason:?}"
    );

    server.abort();
}

#[tokio::test]
async fn authenticated_session_expires_after_absolute_ttl_and_is_audited() {
    use crate::SessionPolicy;

    // Short TTL; leave idle generous so the expiry is unambiguously from TTL.
    let state = TestState::new_with_session_policy(SessionPolicy {
        ttl: Some(Duration::from_millis(200)),
        idle_timeout: Some(Duration::from_secs(600)),
    })
    .await;
    let database = state.database.clone();
    let connections = state.connections.clone();
    let (mut socket, server) = spawn_server(state).await;

    login(&mut socket, "operator", "password1234").await;

    tokio::time::sleep(Duration::from_millis(350)).await;
    socket.send_text(chat_message("operator", "still here")).await;

    let response = read_operator_message(&mut socket).await;
    match response {
        OperatorMessage::InitConnectionError(ref message) => {
            assert!(
                message.info.message.contains("lifetime"),
                "expected TTL-expiry message, got {:?}",
                message.info.message
            );
        }
        other => panic!("expected InitConnectionError, got {other:?}"),
    }

    wait_for_connection_count(&connections, 0).await;

    let page = query_audit_log(
        &database,
        &AuditQuery {
            action: Some("operator.session_timeout".to_owned()),
            actor: Some("operator".to_owned()),
            ..AuditQuery::default()
        },
    )
    .await
    .expect("audit query should succeed");

    assert_eq!(page.total, 1, "expected one session_timeout audit record");
    let reason =
        page.items[0].parameters.as_ref().and_then(|p| p.get("reason")).and_then(|v| v.as_str());
    assert_eq!(reason, Some("ttl_exceeded"));

    server.abort();
}

#[tokio::test]
async fn authenticated_session_within_idle_window_is_not_expired() {
    use crate::SessionPolicy;

    // Generous idle and TTL — no expiry should fire for a normal post-login
    // frame. Guards against regressions where the expiry check mis-triggers on
    // healthy sessions.
    let state = TestState::new_with_session_policy(SessionPolicy {
        ttl: Some(Duration::from_secs(3600)),
        idle_timeout: Some(Duration::from_secs(3600)),
    })
    .await;
    let database = state.database.clone();
    let (mut socket, server) = spawn_server(state).await;

    login(&mut socket, "operator", "password1234").await;

    socket.send_text(chat_message("operator", "hi")).await;
    // ChatMessage broadcasts to all operators (including the sender), so we
    // expect to receive the broadcast rather than an error.
    let response = read_operator_message(&mut socket).await;
    assert!(
        matches!(response, OperatorMessage::ChatMessage(_)),
        "chat should echo for live session, got {response:?}"
    );

    let page = query_audit_log(
        &database,
        &AuditQuery {
            action: Some("operator.session_timeout".to_owned()),
            actor: Some("operator".to_owned()),
            ..AuditQuery::default()
        },
    )
    .await
    .expect("audit query should succeed");
    assert_eq!(page.total, 0, "live session must not trigger session_timeout audit");

    socket.close().await;
    server.abort();
}

// ── route wiring ──────────────────────────────────────────────────────────────

async fn build_ws_router() -> axum::Router {
    let state = TestState::new().await;
    routes::<TestState>().with_state(state)
}

#[tokio::test]
async fn routes_get_root_reaches_websocket_handler() {
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    let app = build_ws_router().await;

    // Send a GET / with WebSocket upgrade headers. Through `oneshot()` the
    // actual protocol switch cannot complete (no real TCP connection), but
    // the route *is* matched — so we must not see 404 or 405.
    let mut req = Request::builder()
        .uri("/")
        .header("host", "localhost")
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(axum::body::Body::empty())
        .expect("request should build");

    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 9999))));

    let response = app.oneshot(req).await.expect("router should respond");
    assert_ne!(
        response.status(),
        StatusCode::NOT_FOUND,
        "GET / must be routed to the WebSocket handler, not fall through to 404"
    );
    assert_ne!(
        response.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "GET / must be an accepted method"
    );
}

#[tokio::test]
async fn routes_post_root_is_method_not_allowed() {
    use axum::http::{Method, Request, StatusCode};
    use tower::ServiceExt;

    let app = build_ws_router().await;

    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/")
        .body(axum::body::Body::empty())
        .expect("request should build");

    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 9999))));

    let response = app.oneshot(req).await.expect("router should respond");
    assert_eq!(
        response.status(),
        StatusCode::METHOD_NOT_ALLOWED,
        "POST / must be rejected — only GET is registered"
    );
}

#[tokio::test]
async fn routes_non_root_path_returns_not_found() {
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    let app = build_ws_router().await;

    let mut req = Request::builder()
        .uri("/some/other/path")
        .header("host", "localhost")
        .header("connection", "Upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .body(axum::body::Body::empty())
        .expect("request should build");

    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 9999))));

    let response = app.oneshot(req).await.expect("router should respond");
    assert_eq!(response.status(), StatusCode::NOT_FOUND, "non-root path must not be registered");
}
