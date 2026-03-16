mod common;

use futures_util::SinkExt;
use red_cell::{
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, LoginRateLimiter, OperatorConnectionManager, PayloadBuilderService,
    SocketRelayManager, TeamserverState, websocket_routes,
};
use red_cell_common::HttpListenerConfig;
use red_cell_common::config::Profile;
use red_cell_common::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len, decrypt_agent_data_at_offset,
};
use red_cell_common::demon::{DemonCommand, DemonMessage};
use red_cell_common::operator::{AgentTaskInfo, EventCode, Message, MessageHead, OperatorMessage};
use tokio::net::TcpListener;
use tokio_tungstenite::{connect_async, tungstenite::Message as ClientMessage};

#[tokio::test]
async fn mock_demon_checkin_get_job_and_output_flow() -> Result<(), Box<dyn std::error::Error>> {
    let profile = Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40056
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
        api: ApiRuntime::from_profile(&profile),
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
    let client = reqwest::Client::new();
    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners
        .create(red_cell_common::ListenerConfig::from(HttpListenerConfig {
            name: "edge-http".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["127.0.0.1".to_owned()],
            host_bind: "127.0.0.1".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: listener_port,
            port_conn: Some(listener_port),
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
        }))
        .await?;
    drop(listener_guard);
    listeners.start("edge-http").await?;
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
        panic!("expected agent registration event");
    };
    assert_eq!(message.info.name_id, "12345678");
    assert_eq!(message.info.listener, "edge-http");
    assert_eq!(message.info.hostname, "wkstn-01");

    let task = serde_json::to_string(&OperatorMessage::AgentTask(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "operator".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: AgentTaskInfo {
            task_id: "2A".to_owned(),
            command_line: "checkin".to_owned(),
            demon_id: "12345678".to_owned(),
            command_id: u32::from(DemonCommand::CommandCheckin).to_string(),
            ..AgentTaskInfo::default()
        },
    }))?;
    socket.send(ClientMessage::Text(task.into())).await?;

    let task_echo = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentTask(message) = task_echo else {
        panic!("expected agent task echo");
    };
    assert_eq!(message.info.demon_id, "12345678");
    assert_eq!(message.info.task_id, "2A");

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
    let job_bytes = get_job_response.bytes().await?;
    let message = DemonMessage::from_bytes(job_bytes.as_ref())?;
    assert_eq!(message.packages.len(), 1);
    assert_eq!(message.packages[0].command_id, u32::from(DemonCommand::CommandCheckin));
    assert_eq!(message.packages[0].request_id, 0x2A);
    assert!(message.packages[0].payload.is_empty());
    ctr_offset += ctr_blocks_for_len(4);

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
    assert_eq!(message.info.demon_id, "12345678");
    assert_eq!(message.info.command_id, u32::from(DemonCommand::CommandOutput).to_string());
    assert_eq!(message.info.output, output_text);
    assert_eq!(message.info.command_line.as_deref(), Some("checkin"));
    assert_eq!(message.info.extra.get("RequestID").and_then(serde_json::Value::as_str), Some("2A"));

    socket.close(None).await?;
    listeners.stop("edge-http").await?;
    server.abort();
    Ok(())
}

/// End-to-end test: reconnect then subsequent callback remains synchronised.
///
/// This test exercises the protocol contract documented on [`build_reconnect_ack`]:
/// the reconnect ACK is **not counter-consuming** — neither the server nor the agent should
/// advance their AES-CTR block offset after the reconnect handshake.
///
/// Sequence:
/// 1. Agent does a full init; server responds with init ACK.  Both advance their counters by
///    `ctr_blocks_for_len(4)` (one 4-byte agent_id payload = 1 block).
/// 2. Agent sends a reconnect probe (empty `DEMON_INIT` body, no encrypted payload).
/// 3. Server returns a reconnect ACK encrypted at the current offset (1 block) without
///    advancing.  Agent receives the ACK and also does **not** advance its counter.
/// 4. Agent sends a `COMMAND_GET_JOB` callback encrypted at the same offset (1 block).
///    The server decrypts it successfully, proving both sides remain synchronised.
///
/// If the agent were to mistakenly advance its counter after receiving the reconnect ACK
/// (as it does after the init ACK), step 4 would fail with a decrypt/parse error because
/// the agent would encrypt at offset 2 while the server decrypts at offset 1.
#[tokio::test]
async fn reconnect_then_subsequent_callback_remains_synchronised()
-> Result<(), Box<dyn std::error::Error>> {
    let profile = Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40057
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
        api: ApiRuntime::from_profile(&profile),
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
    let client = reqwest::Client::new();
    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    common::login(&mut socket).await?;

    listeners
        .create(red_cell_common::ListenerConfig::from(HttpListenerConfig {
            name: "edge-http-reconnect-e2e".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["127.0.0.1".to_owned()],
            host_bind: "127.0.0.1".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: listener_port,
            port_conn: Some(listener_port),
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
        }))
        .await?;
    drop(listener_guard);
    listeners.start("edge-http-reconnect-e2e").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_C0DE_u32;
    let key = [0x9A; AGENT_KEY_LENGTH];
    let iv = [0x5B; AGENT_IV_LENGTH];

    // --- Step 1: full init --------------------------------------------------------
    // The agent tracks its own CTR offset mirror to simulate what a real agent does.
    let mut agent_ctr_offset = 0_u64;

    let init_bytes = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    // Verify the init ACK decrypts at offset 0.
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, agent_ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes(), "init ACK must echo agent_id");

    // Agent advances its counter after consuming the init ACK (counter-consuming).
    agent_ctr_offset += ctr_blocks_for_len(init_bytes.len());

    // Consume the AgentNew operator event.
    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(
        matches!(agent_new, OperatorMessage::AgentNew(_)),
        "expected AgentNew event after init"
    );

    // --- Step 2: reconnect probe --------------------------------------------------
    // The reconnect probe carries no encrypted payload — agent counter does NOT change.
    let reconnect_bytes = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_reconnect_body(agent_id))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    // --- Step 3: verify reconnect ACK is encrypted at the current (non-advanced) offset ----
    // The server encrypted at `agent_ctr_offset` without advancing.  The agent decrypts
    // here to confirm the ACK, but critically it does NOT advance its own counter.
    let reconnect_ack =
        decrypt_agent_data_at_offset(&key, &iv, agent_ctr_offset, &reconnect_bytes)?;
    assert_eq!(
        reconnect_ack.as_slice(),
        &agent_id.to_le_bytes(),
        "reconnect ACK must echo agent_id encrypted at the pre-reconnect CTR offset"
    );
    // NOT advancing agent_ctr_offset here — the reconnect ACK is not counter-consuming.

    // Confirm the server's stored offset also did not advance.
    assert_eq!(
        registry.ctr_offset(agent_id).await?,
        agent_ctr_offset,
        "server CTR offset must not advance after sending a reconnect ACK"
    );

    // --- Step 4: subsequent callback at the same (unchanged) offset ---------------
    // If the agent had incorrectly advanced its counter, this would fail because the
    // server would try to decrypt at offset `agent_ctr_offset` while the agent would
    // have encrypted at `agent_ctr_offset + 1`.
    // `error_for_status()` returning Ok proves the server responded with HTTP 200.  A CTR
    // desync would cause the server to fail parsing the decrypted garbage and return HTTP 400,
    // which `error_for_status()` would surface as an error that fails the test.
    // The body itself may be empty (no queued jobs) — that is also a valid 200 response.
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            agent_ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            1,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;

    socket.close(None).await?;
    listeners.stop("edge-http-reconnect-e2e").await?;
    server.abort();
    Ok(())
}
