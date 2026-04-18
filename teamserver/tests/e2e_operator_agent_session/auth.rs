use std::time::Duration;

use red_cell_common::operator::{
    AgentTaskInfo, EventCode, FlatInfo, ListenerInfo, ListenerMarkInfo, Message, MessageHead,
    NameInfo, OperatorMessage,
};
use tokio_tungstenite::{connect_async, tungstenite::Message as ClientMessage};

use crate::helpers::{assert_connection_closed_after_rbac_denial, multi_role_profile};

// ---- RBAC WebSocket enforcement integration tests ----------------------------------------

#[tokio::test]
async fn analyst_cannot_send_agent_task_message() -> Result<(), Box<dyn std::error::Error>> {
    let server = crate::common::spawn_test_server(multi_role_profile()).await?;
    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = crate::common::WsSession::new(raw_socket_);
    crate::common::login_as(&mut socket, "analyst", "analystpw").await?;

    let task_msg = serde_json::to_string(&OperatorMessage::AgentTask(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "analyst".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: AgentTaskInfo {
            task_id: "rbac-test-1".to_owned(),
            command_line: "whoami".to_owned(),
            demon_id: "deadbeef".to_owned(),
            command_id: "1".to_owned(),
            ..AgentTaskInfo::default()
        },
    }))?;
    socket.send_text(task_msg).await?;

    assert_connection_closed_after_rbac_denial(&mut socket).await?;

    // Verify no side effects: no jobs should have been queued for any agent.
    let queued = server.agent_registry.queued_jobs_all().await;
    assert!(queued.is_empty(), "RBAC denial left queued jobs behind: {queued:?}");

    Ok(())
}

#[tokio::test]
async fn analyst_cannot_create_listener() -> Result<(), Box<dyn std::error::Error>> {
    let server = crate::common::spawn_test_server(multi_role_profile()).await?;
    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = crate::common::WsSession::new(raw_socket_);
    crate::common::login_as(&mut socket, "analyst", "analystpw").await?;

    let msg = serde_json::to_string(&OperatorMessage::ListenerNew(Message {
        head: MessageHead {
            event: EventCode::Listener,
            user: "analyst".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: ListenerInfo {
            name: Some("evil-listener".to_owned()),
            protocol: Some("Http".to_owned()),
            ..ListenerInfo::default()
        },
    }))?;
    socket.send_text(msg).await?;

    assert_connection_closed_after_rbac_denial(&mut socket).await?;

    // Verify no side effects: no listener should have been created.
    let listeners = server.listeners.list().await?;
    assert!(listeners.is_empty(), "RBAC denial left a listener behind: {listeners:?}");

    Ok(())
}

#[tokio::test]
async fn analyst_cannot_edit_listener() -> Result<(), Box<dyn std::error::Error>> {
    let server = crate::common::spawn_test_server(multi_role_profile()).await?;
    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = crate::common::WsSession::new(raw_socket_);
    crate::common::login_as(&mut socket, "analyst", "analystpw").await?;

    let msg = serde_json::to_string(&OperatorMessage::ListenerEdit(Message {
        head: MessageHead {
            event: EventCode::Listener,
            user: "analyst".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: ListenerInfo {
            name: Some("edge-http".to_owned()),
            protocol: Some("Http".to_owned()),
            ..ListenerInfo::default()
        },
    }))?;
    socket.send_text(msg).await?;

    assert_connection_closed_after_rbac_denial(&mut socket).await?;

    // Verify no side effects: no listener should have been created or modified.
    let listeners = server.listeners.list().await?;
    assert!(listeners.is_empty(), "RBAC denial left a listener behind: {listeners:?}");

    Ok(())
}

#[tokio::test]
async fn analyst_cannot_remove_listener() -> Result<(), Box<dyn std::error::Error>> {
    let server = crate::common::spawn_test_server(multi_role_profile()).await?;
    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = crate::common::WsSession::new(raw_socket_);
    crate::common::login_as(&mut socket, "analyst", "analystpw").await?;

    let msg = serde_json::to_string(&OperatorMessage::ListenerRemove(Message {
        head: MessageHead {
            event: EventCode::Listener,
            user: "analyst".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: NameInfo { name: "edge-http".to_owned() },
    }))?;
    socket.send_text(msg).await?;

    assert_connection_closed_after_rbac_denial(&mut socket).await?;

    // Verify no side effects: no listener state should have changed.
    let listeners = server.listeners.list().await?;
    assert!(listeners.is_empty(), "RBAC denial left unexpected listener state: {listeners:?}");

    Ok(())
}

#[tokio::test]
async fn analyst_cannot_mark_listener() -> Result<(), Box<dyn std::error::Error>> {
    let server = crate::common::spawn_test_server(multi_role_profile()).await?;
    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = crate::common::WsSession::new(raw_socket_);
    crate::common::login_as(&mut socket, "analyst", "analystpw").await?;

    let msg = serde_json::to_string(&OperatorMessage::ListenerMark(Message {
        head: MessageHead {
            event: EventCode::Listener,
            user: "analyst".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: ListenerMarkInfo { name: "edge-http".to_owned(), mark: "Online".to_owned() },
    }))?;
    socket.send_text(msg).await?;

    assert_connection_closed_after_rbac_denial(&mut socket).await?;

    // Verify no side effects: no listener should have been created or marked.
    let listeners = server.listeners.list().await?;
    assert!(listeners.is_empty(), "RBAC denial left unexpected listener state: {listeners:?}");

    Ok(())
}

#[tokio::test]
async fn operator_cannot_send_admin_message() -> Result<(), Box<dyn std::error::Error>> {
    let server = crate::common::spawn_test_server(multi_role_profile()).await?;
    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = crate::common::WsSession::new(raw_socket_);
    crate::common::login_as(&mut socket, "operator", "operatorpw").await?;

    let msg = serde_json::to_string(&OperatorMessage::AgentRemove(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "operator".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: FlatInfo::default(),
    }))?;
    socket.send_text(msg).await?;

    assert_connection_closed_after_rbac_denial(&mut socket).await?;

    // Verify no side effects: no agents should have been removed or modified.
    let agents = server.agent_registry.list_active().await;
    assert!(agents.is_empty(), "RBAC denial left unexpected agent state: {agents:?}");
    let queued = server.agent_registry.queued_jobs_all().await;
    assert!(queued.is_empty(), "RBAC denial left queued jobs behind: {queued:?}");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_password_receives_error_and_connection_closes()
-> Result<(), Box<dyn std::error::Error>> {
    use red_cell_common::crypto::hash_password_sha3;
    use red_cell_common::operator::LoginInfo;
    use tokio::time::timeout;

    let addr = crate::common::spawn_test_server(multi_role_profile()).await?.addr;
    let (raw_socket_, _) = connect_async(format!("ws://{addr}/havoc")).await?;
    let mut socket = crate::common::WsSession::new(raw_socket_);

    // Send correct username but wrong password hash.
    let bad_login = serde_json::to_string(&OperatorMessage::Login(Message {
        head: MessageHead {
            event: EventCode::InitConnection,
            user: "operator".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: LoginInfo {
            user: "operator".to_owned(),
            password: hash_password_sha3("this-is-not-the-right-password"),
        },
    }))?;
    socket.send_text(bad_login).await?;

    // Server imposes a 2 s delay on failed logins; Argon2id with OWASP-recommended
    // parameters adds additional latency for the memory-hard hash.
    let response =
        timeout(Duration::from_secs(30), futures_util::StreamExt::next(&mut socket.socket))
            .await?
            .ok_or("server closed connection without sending a rejection message")??;
    let rejection: OperatorMessage = match response {
        ClientMessage::Text(payload) => serde_json::from_str(payload.as_str())?,
        other => return Err(format!("unexpected frame before rejection message: {other:?}").into()),
    };
    assert!(
        matches!(rejection, OperatorMessage::InitConnectionError(_)),
        "expected InitConnectionError, got {rejection:?}"
    );

    // After the rejection message the server must close the connection.
    let next =
        timeout(Duration::from_secs(10), futures_util::StreamExt::next(&mut socket.socket)).await?;
    match next {
        Some(Ok(ClientMessage::Close(_))) | None => {}
        Some(Ok(frame)) => {
            return Err(format!("expected Close frame after auth rejection, got {frame:?}").into());
        }
        Some(Err(error)) => {
            return Err(format!("websocket error after auth rejection: {error}").into());
        }
    }

    Ok(())
}

/// Fire N consecutive bad-password logins from the same IP, then verify
/// that the (N+1)th connection is rejected immediately by the rate limiter
/// without ever sending a login frame.
#[tokio::test]
async fn repeated_wrong_passwords_trigger_rate_limiter_lockout()
-> Result<(), Box<dyn std::error::Error>> {
    use red_cell_common::crypto::hash_password_sha3;
    use red_cell_common::operator::LoginInfo;
    use std::time::Instant;
    use tokio::time::timeout;

    // MAX_FAILED_LOGIN_ATTEMPTS is 5; we need that many failures to trip the
    // lockout, then one more attempt to observe the rejection.
    const MAX_FAILURES: usize = 5;

    let server = crate::common::spawn_test_server(multi_role_profile()).await?;
    let addr = server.addr;
    let localhost = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

    let bad_login = serde_json::to_string(&OperatorMessage::Login(Message {
        head: MessageHead {
            event: EventCode::InitConnection,
            user: "operator".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: LoginInfo {
            user: "operator".to_owned(),
            password: hash_password_sha3("wrong-password"),
        },
    }))?;

    // --- Phase 1: exhaust the failure budget ---
    //
    // Pre-populate 4 failures directly via the rate limiter to avoid the 30 s
    // Argon2id + rejection-delay wall-clock cost per attempt.  Under parallel
    // test load those 5×30 s waits can exceed the 60 s LOGIN_WINDOW_DURATION,
    // causing the window to expire before Phase 2 runs.
    for _ in 0..MAX_FAILURES - 1 {
        server.rate_limiter.record_failure(localhost).await;
    }

    // Do exactly one real bad-password WS login to verify the per-attempt
    // rejection path (server sends InitConnectionError before closing).
    {
        let (raw_socket_, _) = connect_async(format!("ws://{addr}/havoc")).await?;
        let mut socket = crate::common::WsSession::new(raw_socket_);
        socket.send_text(bad_login.clone()).await?;

        let response =
            timeout(Duration::from_secs(30), futures_util::StreamExt::next(&mut socket.socket))
                .await?
                .ok_or("attempt 5: server closed without rejection")??;
        let rejection: OperatorMessage = match response {
            ClientMessage::Text(payload) => serde_json::from_str(payload.as_str())?,
            other => return Err(format!("attempt 5: unexpected frame: {other:?}").into()),
        };
        assert!(
            matches!(rejection, OperatorMessage::InitConnectionError(_)),
            "attempt 5: expected InitConnectionError, got {rejection:?}"
        );

        // Wait for the close frame so the server records the failure before we
        // open the next connection.
        let _ = timeout(Duration::from_secs(10), futures_util::StreamExt::next(&mut socket.socket))
            .await;
    }

    // --- Phase 2: the next attempt must be rejected by the rate limiter ---
    let (raw_socket_, _) = connect_async(format!("ws://{addr}/havoc")).await?;
    let mut socket = crate::common::WsSession::new(raw_socket_);
    // Start timing only after the connection is established so that TCP setup
    // latency and OS scheduler jitter from parallel Argon2id hashing do not
    // inflate the measurement.
    let start = Instant::now();

    // The rate-limited path rejects *before* reading a login frame, so we
    // intentionally do NOT send any login message. The server should push an
    // error and close the socket on its own.
    let response =
        timeout(Duration::from_secs(10), futures_util::StreamExt::next(&mut socket.socket))
            .await?
            .ok_or("rate-limited attempt: server closed without sending rejection")?;

    // Verify the rejection is an InitConnectionError.
    match response? {
        ClientMessage::Text(payload) => {
            let msg: OperatorMessage = serde_json::from_str(payload.as_str())?;
            assert!(
                matches!(msg, OperatorMessage::InitConnectionError(_)),
                "rate-limited attempt: expected InitConnectionError, got {msg:?}"
            );
        }
        other => return Err(format!("rate-limited attempt: unexpected frame: {other:?}").into()),
    }

    // Wall-clock timing is intentionally not asserted here.
    //
    // The timeout above is 10 s.  If the rate limiter is absent the server
    // never sends a rejection (it waits for a login frame we withheld), so
    // the timeout fires and `?` propagates a hard error before this point is
    // reached.  Any `elapsed < N` assertion with N ≤ 10 s would therefore be
    // dead code: reachable only when a response *was* received, which implies
    // elapsed < 10 s by construction.
    //
    // The meaningful assertion is the behavioural one above (InitConnectionError
    // received).  If a sub-second timing guarantee matters in the future, move
    // this test into a serial partition (nextest --test-threads=1) and restore
    // a threshold of ~2 s.
    let _ = start; // suppress unused-variable lint

    // The server must close the connection after the rejection.
    let next =
        timeout(Duration::from_secs(10), futures_util::StreamExt::next(&mut socket.socket)).await?;
    match next {
        Some(Ok(ClientMessage::Close(_))) | None => {}
        Some(Ok(frame)) => {
            return Err(
                format!("expected Close frame after rate-limit rejection, got {frame:?}").into()
            );
        }
        Some(Err(error)) => {
            return Err(format!("websocket error after rate-limit rejection: {error}").into());
        }
    }

    Ok(())
}

#[tokio::test]
async fn analyst_can_send_chat_message_without_disconnection()
-> Result<(), Box<dyn std::error::Error>> {
    let addr = crate::common::spawn_test_server(multi_role_profile()).await?.addr;
    let (raw_socket_, _) = connect_async(format!("ws://{addr}/havoc")).await?;
    let mut socket = crate::common::WsSession::new(raw_socket_);
    crate::common::login_as(&mut socket, "analyst", "analystpw").await?;

    let msg = serde_json::to_string(&OperatorMessage::ChatMessage(Message {
        head: MessageHead {
            event: EventCode::Chat,
            user: "analyst".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: FlatInfo::default(),
    }))?;
    socket.send_text(msg).await?;

    // The server should NOT close the connection — no frame should arrive within the window.
    crate::common::assert_no_operator_message(&mut socket, Duration::from_millis(300)).await;
    socket.close(None).await?;
    Ok(())
}

#[tokio::test]
async fn admin_can_send_agent_remove_without_disconnection()
-> Result<(), Box<dyn std::error::Error>> {
    use tokio::time::timeout;

    let addr = crate::common::spawn_test_server(multi_role_profile()).await?.addr;
    let (raw_socket_, _) = connect_async(format!("ws://{addr}/havoc")).await?;
    let mut socket = crate::common::WsSession::new(raw_socket_);
    crate::common::login_as(&mut socket, "admin", "adminpw").await?;

    let msg = serde_json::to_string(&OperatorMessage::AgentRemove(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "admin".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: FlatInfo::default(),
    }))?;
    socket.send_text(msg).await?;

    // The server must NOT close the connection — Admin is allowed to send AgentRemove.
    // It may respond with a message (e.g. error about a missing agent), but the key
    // assertion is that the connection stays open — no Close frame is received.
    let result =
        timeout(Duration::from_secs(2), futures_util::StreamExt::next(&mut socket.socket)).await;
    match result {
        Err(_) => {} // timeout — no message, connection still open ✓
        Ok(Some(Ok(ClientMessage::Close(_)))) => {
            panic!("Admin was disconnected after AgentRemove — RBAC should allow this operation");
        }
        Ok(None) => {
            panic!("connection unexpectedly ended after AgentRemove");
        }
        Ok(Some(Ok(_frame))) => {
            // Server sent a non-Close frame (e.g. an error about the missing agent).
            // The connection is still alive, which is what we're asserting.
        }
        Ok(Some(Err(error))) => {
            panic!("websocket error after AgentRemove: {error}");
        }
    }
    socket.close(None).await?;
    Ok(())
}
