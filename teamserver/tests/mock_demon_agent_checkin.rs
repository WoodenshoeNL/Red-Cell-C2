use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use red_cell::{
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, LoginRateLimiter, OperatorConnectionManager, PayloadBuilderService,
    SocketRelayManager, TeamserverState, websocket_routes,
};
use red_cell_common::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len, decrypt_agent_data_at_offset,
    encrypt_agent_data, encrypt_agent_data_at_offset, hash_password_sha3,
};
use red_cell_common::demon::{DemonCommand, DemonEnvelope, DemonMessage};
use red_cell_common::operator::{
    AgentTaskInfo, EventCode, LoginInfo, Message, MessageHead, OperatorMessage,
};
use red_cell_common::{HttpListenerConfig, OperatorInfo, config::Profile};
use tokio::net::TcpListener;
use tokio::time::{sleep, timeout};
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

    let listener_port = available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();
    let (mut socket, _) = connect_async(format!("ws://{server_addr}/")).await?;
    login(&mut socket).await?;

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
    listeners.start("edge-http").await?;
    wait_for_listener(listener_port).await?;

    let agent_id = 0x1234_5678;
    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    let mut ctr_offset = 0_u64;

    let init_response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?;
    let init_response = init_response.error_for_status()?;
    let init_bytes = init_response.bytes().await?;
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    ctr_offset += ctr_blocks_for_len(init_bytes.len());

    let agent_new = read_operator_message(&mut socket).await?;
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

    let task_echo = read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentTask(message) = task_echo else {
        panic!("expected agent task echo");
    };
    assert_eq!(message.info.demon_id, "12345678");
    assert_eq!(message.info.task_id, "2A");

    let get_job_response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(valid_demon_callback_body(
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
        .body(valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandOutput),
            0x2A,
            &command_output_payload(output_text),
        ))
        .send()
        .await?
        .error_for_status()?;
    assert!(callback_response.bytes().await?.is_empty());

    let output_event = read_operator_message(&mut socket).await?;
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

async fn login(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = serde_json::to_string(&OperatorMessage::Login(Message {
        head: MessageHead {
            event: EventCode::InitConnection,
            user: "operator".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: LoginInfo {
            user: "operator".to_owned(),
            password: hash_password_sha3("password1234"),
        },
    }))?;

    socket.send(ClientMessage::Text(payload.into())).await?;
    let response = read_operator_message(socket).await?;
    assert!(matches!(response, OperatorMessage::InitConnectionSuccess(_)));
    let _snapshot = read_operator_snapshot(socket).await?;
    Ok(())
}

async fn read_operator_message(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Result<OperatorMessage, Box<dyn std::error::Error>> {
    let next = timeout(Duration::from_secs(5), socket.next()).await?;
    let frame = next.ok_or_else(|| "missing websocket frame".to_owned())??;
    match frame {
        ClientMessage::Text(payload) => Ok(serde_json::from_str(payload.as_str())?),
        other => Err(format!("unexpected websocket frame: {other:?}").into()),
    }
}

async fn read_operator_snapshot(
    socket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> Result<Vec<OperatorInfo>, Box<dyn std::error::Error>> {
    let message = read_operator_message(socket).await?;
    let OperatorMessage::InitConnectionInfo(message) = message else {
        return Err("expected operator snapshot event".into());
    };

    Ok(serde_json::from_value(
        message
            .info
            .fields
            .get("Operators")
            .cloned()
            .ok_or_else(|| "operator snapshot missing operators".to_owned())?,
    )?)
}

fn available_port_excluding(excluded: u16) -> Result<u16, Box<dyn std::error::Error>> {
    for _ in 0..32 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        drop(listener);
        if port != excluded {
            return Ok(port);
        }
    }

    Err(format!("failed to allocate a port different from {excluded}").into())
}

async fn wait_for_listener(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    for _ in 0..40 {
        if let Ok(response) = client.get(format!("http://127.0.0.1:{port}/")).send().await {
            let status = response.status();
            if status != reqwest::StatusCode::NOT_IMPLEMENTED {
                return Ok(());
            }
        }
        sleep(Duration::from_millis(25)).await;
    }

    Err(format!("listener on port {port} did not become ready").into())
}

fn valid_demon_init_body(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> Vec<u8> {
    let mut metadata = Vec::new();
    metadata.extend_from_slice(&agent_id.to_be_bytes());
    add_length_prefixed_bytes_be(&mut metadata, b"wkstn-01");
    add_length_prefixed_bytes_be(&mut metadata, b"operator");
    add_length_prefixed_bytes_be(&mut metadata, b"REDCELL");
    add_length_prefixed_bytes_be(&mut metadata, b"10.0.0.25");
    add_length_prefixed_utf16_be(&mut metadata, "C:\\Windows\\explorer.exe");
    metadata.extend_from_slice(&1337_u32.to_be_bytes());
    metadata.extend_from_slice(&1338_u32.to_be_bytes());
    metadata.extend_from_slice(&512_u32.to_be_bytes());
    metadata.extend_from_slice(&2_u32.to_be_bytes());
    metadata.extend_from_slice(&1_u32.to_be_bytes());
    metadata.extend_from_slice(&0x401000_u64.to_be_bytes());
    metadata.extend_from_slice(&10_u32.to_be_bytes());
    metadata.extend_from_slice(&0_u32.to_be_bytes());
    metadata.extend_from_slice(&1_u32.to_be_bytes());
    metadata.extend_from_slice(&0_u32.to_be_bytes());
    metadata.extend_from_slice(&22000_u32.to_be_bytes());
    metadata.extend_from_slice(&9_u32.to_be_bytes());
    metadata.extend_from_slice(&15_u32.to_be_bytes());
    metadata.extend_from_slice(&20_u32.to_be_bytes());
    metadata.extend_from_slice(&1_893_456_000_u64.to_be_bytes());
    metadata.extend_from_slice(&0b101010_u32.to_be_bytes());

    let encrypted =
        encrypt_agent_data(&key, &iv, &metadata).expect("metadata encryption should succeed");
    let payload = [
        u32::from(DemonCommand::DemonInit).to_be_bytes().as_slice(),
        7_u32.to_be_bytes().as_slice(),
        key.as_slice(),
        iv.as_slice(),
        encrypted.as_slice(),
    ]
    .concat();

    DemonEnvelope::new(agent_id, payload)
        .unwrap_or_else(|error| panic!("failed to build demon init request body: {error}"))
        .to_bytes()
}

fn valid_demon_callback_body(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    ctr_offset: u64,
    command_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut decrypted = Vec::new();
    decrypted.extend_from_slice(&u32::try_from(payload.len()).unwrap_or_default().to_be_bytes());
    decrypted.extend_from_slice(payload);

    let encrypted = encrypt_agent_data_at_offset(&key, &iv, ctr_offset, &decrypted)
        .unwrap_or_else(|error| panic!("callback encrypt failed: {error}"));
    let body = [
        command_id.to_be_bytes().as_slice(),
        request_id.to_be_bytes().as_slice(),
        encrypted.as_slice(),
    ]
    .concat();

    DemonEnvelope::new(agent_id, body)
        .unwrap_or_else(|error| panic!("failed to build demon callback request body: {error}"))
        .to_bytes()
}

fn command_output_payload(output: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::try_from(output.len()).unwrap_or_default().to_le_bytes());
    payload.extend_from_slice(output.as_bytes());
    payload
}

fn add_length_prefixed_bytes_be(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&u32::try_from(bytes.len()).unwrap_or_default().to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn add_length_prefixed_utf16_be(buf: &mut Vec<u8>, value: &str) {
    let mut encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_be_bytes).collect();
    encoded.extend_from_slice(&[0, 0]);
    add_length_prefixed_bytes_be(buf, &encoded);
}
