mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use futures_util::SinkExt;
#[cfg(unix)]
use interprocess::local_socket::ToNsName as _;
#[cfg(unix)]
use interprocess::local_socket::tokio::Stream as LocalSocketStream;
#[cfg(unix)]
use interprocess::local_socket::traits::tokio::Stream as _;
#[cfg(unix)]
use interprocess::os::unix::local_socket::AbstractNsUdSocket;
use red_cell::{
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, LoginRateLimiter, OperatorConnectionManager, PayloadBuilderService,
    SocketRelayManager, TeamserverState, websocket_routes,
};
use red_cell_common::config::Profile;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len};
use red_cell_common::demon::{DemonCommand, DemonMessage};
use red_cell_common::operator::{
    AgentResponseInfo, AgentTaskInfo, EventCode, FlatInfo, ListenerInfo, ListenerMarkInfo, Message,
    MessageHead, OperatorMessage,
};
use red_cell_common::{HttpListenerConfig, ListenerConfig, SmbListenerConfig};
use serde_json::Value;
#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::{sleep, timeout};
use tokio_tungstenite::{connect_async, tungstenite::Message as ClientMessage};

#[tokio::test]
async fn operator_session_listener_and_mock_demon_round_trip()
-> Result<(), Box<dyn std::error::Error>> {
    let profile = Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40156
        }

        Operators {
          user "operator" {
            Password = "password1234"
            Role = "Operator"
          }
        }

        Demon {}
        "#,
    )?;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let listeners = ListenerManager::new(
        database.clone(),
        registry.clone(),
        events.clone(),
        sockets.clone(),
        None,
    );
    let state = TeamserverState {
        profile: profile.clone(),
        database: database.clone(),
        auth: AuthService::from_profile(&profile).expect("auth service should initialize"),
        api: ApiRuntime::from_profile(&profile).expect("rng should work in tests"),
        events,
        connections: OperatorConnectionManager::new(),
        agent_registry: registry.clone(),
        listeners: listeners.clone(),
        payload_builder: PayloadBuilderService::disabled_for_tests(),
        sockets,
        webhooks: AuditWebhookNotifier::from_profile(&profile),
        login_rate_limiter: LoginRateLimiter::new(),
        shutdown: red_cell::ShutdownController::new(),
    };

    let server_listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = server_listener.local_addr()?;
    let server = tokio::spawn(async move {
        let app = websocket_routes().with_state(state);
        let _ = axum::serve(
            server_listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });

    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    assert_ne!(listener_port, server_addr.port());
    let client = reqwest::Client::new();
    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;

    common::login(&mut socket).await?;
    common::assert_no_operator_message(&mut socket, Duration::from_millis(200)).await;

    // Release the port reservation immediately before the server binds it.
    drop(listener_guard);
    socket
        .send(ClientMessage::Text(listener_new_message("operator", listener_port).into()))
        .await?;

    let listener_created = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::ListenerNew(message) = listener_created else {
        panic!("expected listener create event");
    };
    assert_eq!(message.info.name.as_deref(), Some("edge-http"));
    assert_eq!(message.info.status.as_deref(), Some("Offline"));

    let listener_started = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::ListenerMark(message) = listener_started else {
        panic!("expected listener start event");
    };
    assert_eq!(message.head.event, EventCode::Listener);
    assert_eq!(message.head.user, "operator");
    assert_eq!(
        message.info,
        ListenerMarkInfo { name: "edge-http".to_owned(), mark: "Online".to_owned() }
    );

    listeners.update(http_listener_config(listener_port)).await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0x1234_5678;
    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    let mut ctr_offset = 0_u64;

    let init_response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let init_bytes = init_response.bytes().await?;
    let init_ack =
        red_cell_common::crypto::decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    ctr_offset += ctr_blocks_for_len(init_bytes.len());

    let agent_new = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentNew(message) = agent_new else {
        panic!("expected agent session event");
    };
    assert_eq!(message.info.name_id, "12345678");
    assert_eq!(message.info.listener, "edge-http");
    assert_eq!(message.info.hostname, "wkstn-01");

    socket.send(ClientMessage::Text(agent_task_message("2A").into())).await?;

    let task_echo = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentTask(message) = task_echo else {
        panic!("expected agent task echo");
    };
    assert_eq!(message.info.demon_id, "12345678");
    assert_eq!(message.info.task_id, "2A");
    assert_eq!(message.info.command_line, "checkin");

    let get_job_response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            5,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    ctr_offset += ctr_blocks_for_len(4);
    let job_bytes = get_job_response.bytes().await?;
    let job_message = DemonMessage::from_bytes(job_bytes.as_ref())?;
    assert_eq!(job_message.packages.len(), 1);
    assert_eq!(job_message.packages[0].command_id, u32::from(DemonCommand::CommandCheckin));
    assert_eq!(job_message.packages[0].request_id, 0x2A);
    assert!(job_message.packages[0].payload.is_empty());

    let output_text = "hello from demon";
    let callback_response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandOutput),
            0x2A,
            &common::command_output_payload(output_text),
        ))
        .send()
        .await?
        .error_for_status()?;
    assert!(callback_response.bytes().await?.is_empty());

    let output_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(message) = output_event else {
        panic!("expected agent response event");
    };
    assert_agent_output(&message.info, output_text);

    // --- Audit log assertions ---
    // Verify that the WebSocket handlers persisted the expected audit entries
    // during the session so that a regression (accidentally removing an audit
    // call) would be caught here rather than silently skipped.
    let audit_entries = database.audit_log().list().await?;

    let login_entry = audit_entries
        .iter()
        .find(|e| e.action == "operator.connect" && e.actor == "operator")
        .expect("audit log must contain an operator.connect entry for 'operator'");
    assert_eq!(login_entry.target_kind, "operator");
    assert_eq!(login_entry.target_id.as_deref(), Some("operator"));

    let task_entry = audit_entries
        .iter()
        .find(|e| e.action == "agent.task" && e.actor == "operator")
        .expect("audit log must contain an agent.task entry for 'operator'");
    assert_eq!(task_entry.target_kind, "agent");
    assert_eq!(task_entry.target_id.as_deref(), Some("12345678"));
    // Confirm agent_id is also recorded inside the structured details blob.
    let agent_id_in_details = task_entry
        .details
        .as_ref()
        .and_then(|d| d.get("agent_id"))
        .and_then(serde_json::Value::as_str);
    assert_eq!(
        agent_id_in_details,
        Some("12345678"),
        "audit details must include the agent_id for agent.task entries"
    );

    socket.close(None).await?;
    listeners.stop("edge-http").await?;
    server.abort();
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn operator_session_smb_listener_and_mock_demon_round_trip()
-> Result<(), Box<dyn std::error::Error>> {
    let profile = Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40156
        }

        Operators {
          user "operator" {
            Password = "password1234"
            Role = "Operator"
          }
        }

        Demon {}
        "#,
    )?;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let listeners = ListenerManager::new(
        database.clone(),
        registry.clone(),
        events.clone(),
        sockets.clone(),
        None,
    );
    let state = TeamserverState {
        profile: profile.clone(),
        database: database.clone(),
        auth: AuthService::from_profile(&profile).expect("auth service should initialize"),
        api: ApiRuntime::from_profile(&profile).expect("rng should work in tests"),
        events,
        connections: OperatorConnectionManager::new(),
        agent_registry: registry,
        listeners: listeners.clone(),
        payload_builder: PayloadBuilderService::disabled_for_tests(),
        sockets,
        webhooks: AuditWebhookNotifier::from_profile(&profile),
        login_rate_limiter: LoginRateLimiter::new(),
        shutdown: red_cell::ShutdownController::new(),
    };

    let server_listener = TcpListener::bind("127.0.0.1:0").await?;
    let server_addr = server_listener.local_addr()?;
    let server = tokio::spawn(async move {
        let app = websocket_routes().with_state(state);
        let _ = axum::serve(
            server_listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });

    let pipe_name = unique_pipe_name("operator-round-trip");
    let listener_name = "edge-smb";
    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;

    common::login(&mut socket).await?;
    common::assert_no_operator_message(&mut socket, Duration::from_millis(200)).await;

    socket
        .send(ClientMessage::Text(
            listener_new_smb_message("operator", listener_name, &pipe_name).into(),
        ))
        .await?;

    let listener_created = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::ListenerNew(message) = listener_created else {
        panic!("expected listener create event");
    };
    assert_eq!(message.info.name.as_deref(), Some(listener_name));
    assert_eq!(message.info.protocol.as_deref(), Some("smb"));
    assert_eq!(message.info.status.as_deref(), Some("Offline"));
    assert_eq!(
        message.info.extra.get("PipeName").and_then(serde_json::Value::as_str),
        Some(pipe_name.as_str())
    );

    let listener_started = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::ListenerMark(message) = listener_started else {
        panic!("expected listener start event");
    };
    assert_eq!(message.head.event, EventCode::Listener);
    assert_eq!(message.head.user, "operator");
    assert_eq!(
        message.info,
        ListenerMarkInfo { name: listener_name.to_owned(), mark: "Online".to_owned() }
    );

    listeners.update(smb_listener_config(listener_name, &pipe_name)).await?;
    wait_for_smb_listener(&pipe_name).await?;

    let agent_id = 0x1234_5678;
    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    let mut ctr_offset = 0_u64;

    let mut init_stream = connect_smb(&pipe_name).await?;
    write_smb_frame(&mut init_stream, agent_id, &common::valid_demon_init_body(agent_id, key, iv))
        .await?;

    let (ack_agent_id, ack_payload) =
        timeout(Duration::from_secs(5), read_smb_frame(&mut init_stream)).await??;
    assert_eq!(ack_agent_id, agent_id);
    let init_ack =
        red_cell_common::crypto::decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &ack_payload)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    ctr_offset += ctr_blocks_for_len(ack_payload.len());
    drop(init_stream);

    let agent_new = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentNew(message) = agent_new else {
        panic!("expected agent session event");
    };
    assert_eq!(message.info.name_id, "12345678");
    assert_eq!(message.info.listener, listener_name);
    assert_eq!(message.info.hostname, "wkstn-01");

    let (mut snapshot_socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut snapshot_socket).await?;
    let snapshot_agent = read_until_operator_message(&mut snapshot_socket, |message| {
        matches!(message, OperatorMessage::AgentNew(_))
    })
    .await?;
    let OperatorMessage::AgentNew(message) = snapshot_agent else {
        panic!("expected agent snapshot event");
    };
    assert_eq!(message.info.name_id, "12345678");
    assert_eq!(message.info.listener, listener_name);
    snapshot_socket.close(None).await?;

    socket.send(ClientMessage::Text(agent_task_message("2A").into())).await?;

    let task_echo = read_until_operator_message(&mut socket, |message| {
        matches!(message, OperatorMessage::AgentTask(_))
    })
    .await?;
    let OperatorMessage::AgentTask(message) = task_echo else {
        panic!("expected agent task echo");
    };
    assert_eq!(message.info.demon_id, "12345678");
    assert_eq!(message.info.task_id, "2A");
    assert_eq!(message.info.command_line, "checkin");

    let mut get_job_stream = connect_smb(&pipe_name).await?;
    write_smb_frame(
        &mut get_job_stream,
        agent_id,
        &common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            5,
            &[],
        ),
    )
    .await?;
    ctr_offset += ctr_blocks_for_len(4);

    let (job_agent_id, job_bytes) =
        timeout(Duration::from_secs(5), read_smb_frame(&mut get_job_stream)).await??;
    assert_eq!(job_agent_id, agent_id);
    let job_message = DemonMessage::from_bytes(job_bytes.as_ref())?;
    assert_eq!(job_message.packages.len(), 1);
    assert_eq!(job_message.packages[0].command_id, u32::from(DemonCommand::CommandCheckin));
    assert_eq!(job_message.packages[0].request_id, 0x2A);
    assert!(job_message.packages[0].payload.is_empty());
    drop(get_job_stream);

    let output_text = "hello from smb demon";
    let mut callback_stream = connect_smb(&pipe_name).await?;
    write_smb_frame(
        &mut callback_stream,
        agent_id,
        &common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandOutput),
            0x2A,
            &common::command_output_payload(output_text),
        ),
    )
    .await?;
    assert!(
        timeout(Duration::from_millis(250), read_smb_frame(&mut callback_stream)).await.is_err(),
        "output callback should not produce an SMB response frame"
    );

    let output_event = read_until_operator_message(&mut socket, |message| {
        matches!(message, OperatorMessage::AgentResponse(_))
    })
    .await?;
    let OperatorMessage::AgentResponse(message) = output_event else {
        panic!("expected agent response event");
    };
    assert_agent_output(&message.info, output_text);

    socket.close(None).await?;
    listeners.stop(listener_name).await?;
    server.abort();
    Ok(())
}

/// Spin up a minimal teamserver with Admin, Operator, and Analyst users.
fn multi_role_profile() -> Profile {
    Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 0
        }

        Operators {
          user "admin" {
            Password = "adminpw"
            Role = "Admin"
          }
          user "operator" {
            Password = "operatorpw"
            Role = "Operator"
          }
          user "analyst" {
            Password = "analystpw"
            Role = "Analyst"
          }
        }

        Demon {}
        "#,
    )
    .expect("multi-role profile should parse")
}

/// Read the next frame and assert it is a Close frame, indicating RBAC rejection.
async fn assert_connection_closed_after_rbac_denial(
    socket: &mut common::WsClient,
) -> Result<(), Box<dyn std::error::Error>> {
    let next = timeout(Duration::from_secs(5), futures_util::StreamExt::next(socket)).await?;
    match next {
        Some(Ok(ClientMessage::Close(_))) | None => Ok(()),
        Some(Ok(frame)) => {
            Err(format!("expected Close frame after RBAC denial, got {frame:?}").into())
        }
        Some(Err(error)) => Err(format!("websocket error after RBAC denial: {error}").into()),
    }
}

async fn read_until_operator_message<F>(
    socket: &mut common::WsClient,
    mut predicate: F,
) -> Result<OperatorMessage, Box<dyn std::error::Error>>
where
    F: FnMut(&OperatorMessage) -> bool,
{
    for _ in 0..10 {
        let message = common::read_operator_message(socket).await?;
        if predicate(&message) {
            return Ok(message);
        }
    }

    Err("did not observe expected operator message within 10 frames".into())
}

// ---- RBAC WebSocket enforcement integration tests ----------------------------------------

#[tokio::test]
async fn analyst_cannot_send_agent_task_message() -> Result<(), Box<dyn std::error::Error>> {
    let addr = common::spawn_test_server(multi_role_profile()).await?;
    let (mut socket, _) = connect_async(format!("ws://{addr}/")).await?;
    common::login_as(&mut socket, "analyst", "analystpw").await?;

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
    socket.send(ClientMessage::Text(task_msg.into())).await?;

    assert_connection_closed_after_rbac_denial(&mut socket).await
}

#[tokio::test]
async fn analyst_cannot_create_listener() -> Result<(), Box<dyn std::error::Error>> {
    let addr = common::spawn_test_server(multi_role_profile()).await?;
    let (mut socket, _) = connect_async(format!("ws://{addr}/")).await?;
    common::login_as(&mut socket, "analyst", "analystpw").await?;

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
    socket.send(ClientMessage::Text(msg.into())).await?;

    assert_connection_closed_after_rbac_denial(&mut socket).await
}

#[tokio::test]
async fn operator_cannot_send_admin_message() -> Result<(), Box<dyn std::error::Error>> {
    let addr = common::spawn_test_server(multi_role_profile()).await?;
    let (mut socket, _) = connect_async(format!("ws://{addr}/")).await?;
    common::login_as(&mut socket, "operator", "operatorpw").await?;

    let msg = serde_json::to_string(&OperatorMessage::AgentRemove(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "operator".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: FlatInfo::default(),
    }))?;
    socket.send(ClientMessage::Text(msg.into())).await?;

    assert_connection_closed_after_rbac_denial(&mut socket).await
}

#[tokio::test]
async fn wrong_password_receives_error_and_connection_closes()
-> Result<(), Box<dyn std::error::Error>> {
    use red_cell_common::crypto::hash_password_sha3;
    use red_cell_common::operator::LoginInfo;

    let addr = common::spawn_test_server(multi_role_profile()).await?;
    let (mut socket, _) = connect_async(format!("ws://{addr}/")).await?;

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
    socket.send(ClientMessage::Text(bad_login.into())).await?;

    // Server imposes a 2 s delay on failed logins; use a generous timeout.
    let response = timeout(Duration::from_secs(5), futures_util::StreamExt::next(&mut socket))
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
    let next = timeout(Duration::from_secs(3), futures_util::StreamExt::next(&mut socket)).await?;
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

    // MAX_FAILED_LOGIN_ATTEMPTS is 5; we need that many failures to trip the
    // lockout, then one more attempt to observe the rejection.
    const MAX_FAILURES: usize = 5;

    let addr = common::spawn_test_server(multi_role_profile()).await?;

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
    for i in 0..MAX_FAILURES {
        let (mut socket, _) = connect_async(format!("ws://{addr}/")).await?;
        socket.send(ClientMessage::Text(bad_login.clone().into())).await?;

        // Each failed login incurs a 2 s server-side delay.
        let response = timeout(Duration::from_secs(5), futures_util::StreamExt::next(&mut socket))
            .await?
            .ok_or(format!("attempt {}: server closed without rejection", i + 1))??;
        let rejection: OperatorMessage = match response {
            ClientMessage::Text(payload) => serde_json::from_str(payload.as_str())?,
            other => return Err(format!("attempt {}: unexpected frame: {other:?}", i + 1).into()),
        };
        assert!(
            matches!(rejection, OperatorMessage::InitConnectionError(_)),
            "attempt {}: expected InitConnectionError, got {rejection:?}",
            i + 1
        );

        // Wait for the close frame so the server records the failure before we
        // open the next connection.
        let _ = timeout(Duration::from_secs(3), futures_util::StreamExt::next(&mut socket)).await;
    }

    // --- Phase 2: the next attempt must be rejected by the rate limiter ---
    let start = Instant::now();
    let (mut socket, _) = connect_async(format!("ws://{addr}/")).await?;

    // The rate-limited path rejects *before* reading a login frame, so we
    // intentionally do NOT send any login message. The server should push an
    // error and close the socket on its own.
    let response = timeout(Duration::from_secs(5), futures_util::StreamExt::next(&mut socket))
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

    // The rate-limited rejection must be substantially faster than the normal
    // 2 s FAILED_LOGIN_DELAY, proving the limiter short-circuited the
    // authentication flow.
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(1500),
        "rate-limited rejection took {elapsed:?}, expected < 1.5 s — \
         limiter may not be short-circuiting"
    );

    // The server must close the connection after the rejection.
    let next = timeout(Duration::from_secs(3), futures_util::StreamExt::next(&mut socket)).await?;
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
    let addr = common::spawn_test_server(multi_role_profile()).await?;
    let (mut socket, _) = connect_async(format!("ws://{addr}/")).await?;
    common::login_as(&mut socket, "analyst", "analystpw").await?;

    let msg = serde_json::to_string(&OperatorMessage::ChatMessage(Message {
        head: MessageHead {
            event: EventCode::Chat,
            user: "analyst".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: FlatInfo::default(),
    }))?;
    socket.send(ClientMessage::Text(msg.into())).await?;

    // The server should NOT close the connection — no frame should arrive within the window.
    common::assert_no_operator_message(&mut socket, Duration::from_millis(300)).await;
    socket.close(None).await?;
    Ok(())
}

fn listener_new_message(user: &str, port: u16) -> String {
    serde_json::to_string(&OperatorMessage::ListenerNew(Message {
        head: MessageHead {
            event: EventCode::Listener,
            user: user.to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: ListenerInfo {
            name: Some("edge-http".to_owned()),
            protocol: Some("Http".to_owned()),
            status: Some("Online".to_owned()),
            hosts: Some("127.0.0.1".to_owned()),
            host_bind: Some("127.0.0.1".to_owned()),
            host_rotation: Some("round-robin".to_owned()),
            port_bind: Some(port.to_string()),
            port_conn: Some(port.to_string()),
            uris: Some("/".to_owned()),
            secure: Some("false".to_owned()),
            ..ListenerInfo::default()
        },
    }))
    .expect("listener message should serialize")
}

fn listener_new_smb_message(user: &str, name: &str, pipe_name: &str) -> String {
    serde_json::to_string(&OperatorMessage::ListenerNew(Message {
        head: MessageHead {
            event: EventCode::Listener,
            user: user.to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: ListenerInfo {
            name: Some(name.to_owned()),
            protocol: Some("SMB".to_owned()),
            status: Some("Online".to_owned()),
            extra: BTreeMap::from([("PipeName".to_owned(), Value::String(pipe_name.to_owned()))]),
            ..ListenerInfo::default()
        },
    }))
    .expect("smb listener message should serialize")
}

fn agent_task_message(task_id: &str) -> String {
    serde_json::to_string(&OperatorMessage::AgentTask(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "operator".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: AgentTaskInfo {
            task_id: task_id.to_owned(),
            command_line: "checkin".to_owned(),
            demon_id: "12345678".to_owned(),
            command_id: u32::from(DemonCommand::CommandCheckin).to_string(),
            ..AgentTaskInfo::default()
        },
    }))
    .expect("agent task should serialize")
}

fn assert_agent_output(info: &AgentResponseInfo, output_text: &str) {
    assert_eq!(info.demon_id, "12345678");
    assert_eq!(info.command_id, u32::from(DemonCommand::CommandOutput).to_string());
    assert_eq!(info.output, output_text);
    assert_eq!(info.command_line.as_deref(), Some("checkin"));
    assert_eq!(info.extra.get("RequestID").and_then(serde_json::Value::as_str), Some("2A"));
}

fn http_listener_config(port: u16) -> ListenerConfig {
    ListenerConfig::from(HttpListenerConfig {
        name: "edge-http".to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["127.0.0.1".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: port,
        port_conn: Some(port),
        method: Some("POST".to_owned()),
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: None,
        headers: Vec::new(),
        uris: vec!["/".to_owned()],
        host_header: None,
        secure: false,
        cert: None,
        response: None,
        proxy: None,
    })
}

fn smb_listener_config(name: &str, pipe_name: &str) -> ListenerConfig {
    ListenerConfig::from(SmbListenerConfig {
        name: name.to_owned(),
        pipe_name: pipe_name.to_owned(),
        kill_date: None,
        working_hours: None,
    })
}

#[cfg(unix)]
const SMB_PIPE_PREFIX: &str = r"\\.\pipe\";

#[cfg(unix)]
fn unique_pipe_name(suffix: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or_default();
    format!("red-cell-smb-e2e-{suffix}-{ts}")
}

#[cfg(unix)]
fn resolve_socket_name(
    pipe_name: &str,
) -> Result<interprocess::local_socket::Name<'static>, Box<dyn std::error::Error>> {
    let trimmed = pipe_name.trim();
    let full = if trimmed.starts_with('/') || trimmed.starts_with(r"\\") {
        trimmed.to_owned()
    } else {
        format!("{SMB_PIPE_PREFIX}{trimmed}")
    };
    Ok(full.to_ns_name::<AbstractNsUdSocket>()?.into_owned())
}

#[cfg(unix)]
async fn connect_smb(pipe_name: &str) -> Result<LocalSocketStream, Box<dyn std::error::Error>> {
    let socket_name = resolve_socket_name(pipe_name)?;
    Ok(LocalSocketStream::connect(socket_name).await?)
}

#[cfg(unix)]
async fn wait_for_smb_listener(pipe_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..40 {
        if connect_smb(pipe_name).await.is_ok() {
            return Ok(());
        }
        sleep(Duration::from_millis(25)).await;
    }

    Err(format!("SMB listener on pipe `{pipe_name}` did not become ready within 1 s").into())
}

#[cfg(unix)]
async fn write_smb_frame(
    stream: &mut LocalSocketStream,
    agent_id: u32,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    stream.write_u32_le(agent_id).await?;
    stream.write_u32_le(u32::try_from(payload.len())?).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(unix)]
async fn read_smb_frame(
    stream: &mut LocalSocketStream,
) -> Result<(u32, Vec<u8>), Box<dyn std::error::Error>> {
    let agent_id = stream.read_u32_le().await?;
    let payload_len = usize::try_from(stream.read_u32_le().await?)?;
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await?;
    Ok((agent_id, payload))
}
