mod common;

use futures_util::SinkExt;
use red_cell::{
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, LoginRateLimiter, OperatorConnectionManager, PayloadBuilderService,
    SocketRelayManager, TeamserverState, websocket_routes,
};
use red_cell_common::HttpListenerConfig;
use red_cell_common::config::Profile;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len};
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

    let listener_port = common::available_port_excluding(server_addr.port())?;
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
