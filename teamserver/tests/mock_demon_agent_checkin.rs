mod common;

use futures_util::SinkExt;
use red_cell_common::HttpListenerConfig;
use red_cell_common::config::Profile;
use red_cell_common::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len, decrypt_agent_data_at_offset,
};
use red_cell_common::demon::{DemonCommand, DemonMessage};
use red_cell_common::operator::{
    AgentResponseInfo, AgentTaskInfo, EventCode, Message, MessageHead, OperatorMessage,
};
use tokio_tungstenite::{connect_async, tungstenite::Message as ClientMessage};

fn demon_test_profile() -> Profile {
    Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 0
        }

        Operators {
          user "operator" {
            Password = "password1234"
            Role = "Operator"
          }
        }

        Demon {}
        "#,
    )
    .expect("test profile should parse")
}

/// Spawn a test server, create and start an HTTP listener, connect a WebSocket
/// operator, and return the handles needed by the test body.
async fn spawn_server_with_http_listener(
    listener_name: &str,
) -> Result<DemonTestHarness, Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(demon_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();
    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(red_cell_common::ListenerConfig::from(HttpListenerConfig {
            name: listener_name.to_owned(),
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
    server.listeners.start(listener_name).await?;
    common::wait_for_listener(listener_port).await?;

    Ok(DemonTestHarness {
        server,
        listener_port,
        listener_name: listener_name.to_owned(),
        client,
        socket,
    })
}

struct DemonTestHarness {
    server: common::TestServer,
    listener_port: u16,
    listener_name: String,
    client: reqwest::Client,
    socket: common::WsClient,
}

impl DemonTestHarness {
    async fn shutdown(mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.socket.close(None).await?;
        self.server.listeners.stop(&self.listener_name).await?;
        Ok(())
    }
}

fn operator_task_message(
    task_id: &str,
    command_line: &str,
    demon_id: &str,
    command_id: DemonCommand,
) -> Result<String, serde_json::Error> {
    serde_json::to_string(&OperatorMessage::AgentTask(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "operator".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: AgentTaskInfo {
            task_id: task_id.to_owned(),
            command_line: command_line.to_owned(),
            demon_id: demon_id.to_owned(),
            command_id: u32::from(command_id).to_string(),
            ..AgentTaskInfo::default()
        },
    }))
}

fn callback_ctr_advance(payload: &[u8]) -> u64 {
    ctr_blocks_for_len(4 + payload.len())
}

fn assert_agent_output(
    info: &AgentResponseInfo,
    task_id: &str,
    request_id: u32,
    command_line: &str,
    output_text: &str,
) {
    let request_id_hex = format!("{request_id:X}");
    assert_eq!(info.demon_id, "12345678");
    assert_eq!(info.command_id, u32::from(DemonCommand::CommandOutput).to_string());
    assert_eq!(info.output, output_text);
    assert_eq!(info.command_line.as_deref(), Some(command_line));
    assert_eq!(
        info.extra.get("RequestID").and_then(serde_json::Value::as_str),
        Some(request_id_hex.as_str())
    );
    assert_eq!(info.extra.get("TaskID").and_then(serde_json::Value::as_str), Some(task_id));
}

#[tokio::test]
async fn mock_demon_checkin_get_job_and_output_flow() -> Result<(), Box<dyn std::error::Error>> {
    let mut harness = spawn_server_with_http_listener("edge-http").await?;
    let listener_port = harness.listener_port;

    let agent_id = 0x1234_5678;
    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    let mut ctr_offset = 0_u64;

    let init_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let init_bytes = init_response.bytes().await?;
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    ctr_offset += ctr_blocks_for_len(init_bytes.len());

    let agent_new = common::read_operator_message(&mut harness.socket).await?;
    let OperatorMessage::AgentNew(message) = agent_new else {
        panic!("expected agent registration event");
    };
    assert_eq!(message.info.name_id, "12345678");
    assert_eq!(message.info.listener, "edge-http");
    assert_eq!(message.info.hostname, "wkstn-01");

    let task = operator_task_message("2A", "checkin", "12345678", DemonCommand::CommandCheckin)?;
    harness.socket.send(ClientMessage::Text(task.into())).await?;

    let task_echo = common::read_operator_message(&mut harness.socket).await?;
    let OperatorMessage::AgentTask(message) = task_echo else {
        panic!("expected agent task echo");
    };
    assert_eq!(message.info.demon_id, "12345678");
    assert_eq!(message.info.task_id, "2A");

    let get_job_response = harness
        .client
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
    let callback_response = harness
        .client
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

    let output_event = common::read_operator_message(&mut harness.socket).await?;
    let OperatorMessage::AgentResponse(message) = output_event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.demon_id, "12345678");
    assert_eq!(message.info.command_id, u32::from(DemonCommand::CommandOutput).to_string());
    assert_eq!(message.info.output, output_text);
    assert_eq!(message.info.command_line.as_deref(), Some("checkin"));
    assert_eq!(message.info.extra.get("RequestID").and_then(serde_json::Value::as_str), Some("2A"),);

    harness.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn mock_demon_checkin_streams_multiple_output_events_for_one_task()
-> Result<(), Box<dyn std::error::Error>> {
    let mut harness = spawn_server_with_http_listener("edge-http-streaming-single").await?;
    let listener_port = harness.listener_port;

    let agent_id = 0x1234_5678;
    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    let mut ctr_offset = 0_u64;

    let init_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let init_bytes = init_response.bytes().await?;
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    ctr_offset += ctr_blocks_for_len(init_bytes.len());

    let agent_new = common::read_operator_message(&mut harness.socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let task =
        operator_task_message("2A", "shell whoami", "12345678", DemonCommand::CommandCheckin)?;
    harness.socket.send(ClientMessage::Text(task.into())).await?;

    let task_echo = common::read_operator_message(&mut harness.socket).await?;
    let OperatorMessage::AgentTask(message) = task_echo else {
        panic!("expected agent task echo");
    };
    assert_eq!(message.info.task_id, "2A");

    let get_job_response = harness
        .client
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
    assert_eq!(message.packages[0].request_id, 0x2A);
    ctr_offset += ctr_blocks_for_len(4);

    let outputs = ["chunk one\n", "chunk two\n", "chunk three"];
    for output in outputs {
        let payload = common::command_output_payload(output);
        harness
            .client
            .post(format!("http://127.0.0.1:{listener_port}/"))
            .body(common::valid_demon_callback_body(
                agent_id,
                key,
                iv,
                ctr_offset,
                u32::from(DemonCommand::CommandOutput),
                0x2A,
                &payload,
            ))
            .send()
            .await?
            .error_for_status()?;
        ctr_offset += callback_ctr_advance(&payload);
    }

    for output in outputs {
        let event = common::read_operator_message(&mut harness.socket).await?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        assert_agent_output(&message.info, "2A", 0x2A, "shell whoami", output);
    }

    harness.shutdown().await?;
    Ok(())
}

#[tokio::test]
async fn mock_demon_checkin_interleaved_output_keeps_task_attribution()
-> Result<(), Box<dyn std::error::Error>> {
    let mut harness = spawn_server_with_http_listener("edge-http-streaming-interleaved").await?;
    let listener_port = harness.listener_port;

    let agent_id = 0x1234_5678;
    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    let mut ctr_offset = 0_u64;

    let init_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let init_bytes = init_response.bytes().await?;
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    ctr_offset += ctr_blocks_for_len(init_bytes.len());

    let agent_new = common::read_operator_message(&mut harness.socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let first_task =
        operator_task_message("2A", "shell whoami", "12345678", DemonCommand::CommandCheckin)?;
    harness.socket.send(ClientMessage::Text(first_task.into())).await?;
    let first_task_echo = common::read_operator_message(&mut harness.socket).await?;
    assert!(matches!(first_task_echo, OperatorMessage::AgentTask(_)));

    let second_task = operator_task_message(
        "2B",
        "powershell Get-Date",
        "12345678",
        DemonCommand::CommandCheckin,
    )?;
    harness.socket.send(ClientMessage::Text(second_task.into())).await?;
    let second_task_echo = common::read_operator_message(&mut harness.socket).await?;
    assert!(matches!(second_task_echo, OperatorMessage::AgentTask(_)));

    let get_job_response = harness
        .client
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
    assert_eq!(message.packages.len(), 2);
    assert_eq!(message.packages[0].request_id, 0x2A);
    assert_eq!(message.packages[1].request_id, 0x2B);
    ctr_offset += ctr_blocks_for_len(4);

    let callbacks = [
        (0x2A, "shell whoami", "whoami chunk 1"),
        (0x2B, "powershell Get-Date", "date chunk 1"),
        (0x2A, "shell whoami", "whoami chunk 2"),
        (0x2B, "powershell Get-Date", "date chunk 2"),
    ];
    for (request_id, _, output) in callbacks {
        let payload = common::command_output_payload(output);
        harness
            .client
            .post(format!("http://127.0.0.1:{listener_port}/"))
            .body(common::valid_demon_callback_body(
                agent_id,
                key,
                iv,
                ctr_offset,
                u32::from(DemonCommand::CommandOutput),
                request_id,
                &payload,
            ))
            .send()
            .await?
            .error_for_status()?;
        ctr_offset += callback_ctr_advance(&payload);
    }

    for (request_id, command_line, output) in callbacks {
        let event = common::read_operator_message(&mut harness.socket).await?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected agent response event");
        };
        let task_id = format!("{request_id:X}");
        assert_agent_output(&message.info, &task_id, request_id, command_line, output);
    }

    harness.shutdown().await?;
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
    let mut harness = spawn_server_with_http_listener("edge-http-reconnect-e2e").await?;
    let listener_port = harness.listener_port;

    let agent_id = 0xDEAD_C0DE_u32;
    let key = [0x9A; AGENT_KEY_LENGTH];
    let iv = [0x5B; AGENT_IV_LENGTH];

    // --- Step 1: full init --------------------------------------------------------
    // The agent tracks its own CTR offset mirror to simulate what a real agent does.
    let mut agent_ctr_offset = 0_u64;

    let init_bytes = harness
        .client
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
    let agent_new = common::read_operator_message(&mut harness.socket).await?;
    assert!(
        matches!(agent_new, OperatorMessage::AgentNew(_)),
        "expected AgentNew event after init"
    );

    // --- Step 2: reconnect probe --------------------------------------------------
    // The reconnect probe carries no encrypted payload — agent counter does NOT change.
    let reconnect_bytes = harness
        .client
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
        harness.server.agent_registry.ctr_offset(agent_id).await?,
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
    harness
        .client
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

    harness.shutdown().await?;
    Ok(())
}

/// When no operator tasks are queued, a `CommandGetJob` callback must return
/// HTTP 200 with an empty response body.  This is the most common callback
/// pattern in real deployments (idle polling) and a regression here — e.g.
/// returning an error or garbage bytes — would cause agents to malfunction.
#[tokio::test]
async fn get_job_with_empty_task_queue_returns_empty_response()
-> Result<(), Box<dyn std::error::Error>> {
    let mut harness = spawn_server_with_http_listener("edge-http-empty-queue").await?;
    let listener_port = harness.listener_port;

    let agent_id = 0x1234_5678;
    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    let mut ctr_offset = 0_u64;

    // --- DEMON_INIT handshake ----------------------------------------------------
    let init_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let init_bytes = init_response.bytes().await?;
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    ctr_offset += ctr_blocks_for_len(init_bytes.len());

    // Consume the AgentNew operator event so it doesn't block later reads.
    let agent_new = common::read_operator_message(&mut harness.socket).await?;
    assert!(
        matches!(agent_new, OperatorMessage::AgentNew(_)),
        "expected AgentNew event after init"
    );

    // --- Immediately poll for jobs without queuing any tasks --------------------
    let get_job_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            1,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    let status = get_job_response.status();
    let job_bytes = get_job_response.bytes().await?;
    assert_eq!(
        status,
        reqwest::StatusCode::OK,
        "empty task queue must return HTTP 200, got {status}"
    );
    assert!(
        job_bytes.is_empty(),
        "expected empty response body when no tasks are queued, got {} bytes",
        job_bytes.len()
    );
    // The callback itself encrypted 4 bytes (length prefix), advancing the CTR offset.
    ctr_offset += ctr_blocks_for_len(4);

    // --- Verify CTR synchronisation by sending another callback -------------------
    // Queue a task so the next GET_JOB has work to return.  If the empty-poll had
    // desynchronised the CTR state, the server would fail to decrypt this callback.
    let task = operator_task_message("AA", "checkin", "12345678", DemonCommand::CommandCheckin)?;
    harness.socket.send(ClientMessage::Text(task.into())).await?;

    let task_echo = common::read_operator_message(&mut harness.socket).await?;
    assert!(matches!(task_echo, OperatorMessage::AgentTask(_)), "expected AgentTask echo");

    let get_job_response_2 = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            2,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    let job_bytes_2 = get_job_response_2.bytes().await?;
    let message = DemonMessage::from_bytes(job_bytes_2.as_ref())?;
    assert_eq!(message.packages.len(), 1, "second GET_JOB must return the queued task");
    assert_eq!(message.packages[0].request_id, 0xAA);

    harness.shutdown().await?;
    Ok(())
}

/// An unauthenticated WebSocket client must not be able to inject tasks for a
/// live agent.  The server should reject the pre-auth `AgentTask` message and
/// the agent's subsequent `COMMAND_GET_JOB` poll must return no queued jobs.
#[tokio::test]
async fn unauthenticated_operator_cannot_inject_agent_task()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = spawn_server_with_http_listener("edge-http-unauth-inject").await?;
    let listener_port = harness.listener_port;

    // --- Register a live agent via the Demon init handshake -----------------------
    let agent_id = 0x1234_5678;
    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    let mut ctr_offset = 0_u64;

    let init_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let init_bytes = init_response.bytes().await?;
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    ctr_offset += ctr_blocks_for_len(init_bytes.len());

    // --- Open a second (unauthenticated) WebSocket client -------------------------
    let (mut unauth_socket, _) = connect_async(format!("ws://{}/", harness.server.addr)).await?;

    // Send an AgentTask as the very first frame — no login attempt at all.
    let task =
        operator_task_message("FF", "shell whoami", "12345678", DemonCommand::CommandCheckin)?;
    unauth_socket.send(ClientMessage::Text(task.into())).await?;

    // The server must reject the non-login message during the auth phase.
    // It responds with `InitConnectionError` and closes the connection.
    let rejection = common::read_operator_message(&mut unauth_socket).await?;
    assert!(
        matches!(rejection, OperatorMessage::InitConnectionError(_)),
        "expected InitConnectionError for unauthenticated AgentTask, got {rejection:?}"
    );

    // --- Agent polls for jobs — must receive nothing ------------------------------
    let get_job_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            1,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    let job_bytes = get_job_response.bytes().await?;
    assert!(
        job_bytes.is_empty(),
        "agent must receive no jobs after unauthenticated task injection attempt, got {} bytes",
        job_bytes.len()
    );

    // Clean up: close the unauthenticated socket (may already be closed by the
    // server — ignore errors).
    let _ = unauth_socket.close(None).await;

    harness.shutdown().await?;
    Ok(())
}

/// A WebSocket client that fails authentication (wrong password) must not be
/// able to queue agent tasks either.
#[tokio::test]
async fn failed_login_operator_cannot_inject_agent_task() -> Result<(), Box<dyn std::error::Error>>
{
    let harness = spawn_server_with_http_listener("edge-http-badcred-inject").await?;
    let listener_port = harness.listener_port;

    // --- Register a live agent ----------------------------------------------------
    let agent_id = 0x1234_5678;
    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    let mut ctr_offset = 0_u64;

    let init_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let init_bytes = init_response.bytes().await?;
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    ctr_offset += ctr_blocks_for_len(init_bytes.len());

    // --- Attempt login with wrong password ----------------------------------------
    let (mut bad_socket, _) = connect_async(format!("ws://{}/", harness.server.addr)).await?;
    let login_payload =
        serde_json::to_string(&OperatorMessage::Login(red_cell_common::operator::Message {
            head: MessageHead {
                event: EventCode::InitConnection,
                user: "operator".to_owned(),
                timestamp: String::new(),
                one_time: String::new(),
            },
            info: red_cell_common::operator::LoginInfo {
                user: "operator".to_owned(),
                password: red_cell_common::crypto::hash_password_sha3("wrong_password"),
            },
        }))?;
    bad_socket.send(ClientMessage::Text(login_payload.into())).await?;

    // Server responds with InitConnectionError for bad credentials.
    let rejection = common::read_operator_message(&mut bad_socket).await?;
    assert!(
        matches!(rejection, OperatorMessage::InitConnectionError(_)),
        "expected InitConnectionError for wrong password, got {rejection:?}"
    );

    // --- Agent polls — must receive no jobs ---------------------------------------
    let get_job_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            1,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    let job_bytes = get_job_response.bytes().await?;
    assert!(
        job_bytes.is_empty(),
        "agent must receive no jobs after failed-auth task injection attempt, got {} bytes",
        job_bytes.len()
    );

    let _ = bad_socket.close(None).await;
    harness.shutdown().await?;
    Ok(())
}

/// A callback encrypted with the wrong AES key must be rejected with HTTP 404
/// (the server's fake-404 response), and the server's CTR offset must not
/// advance.  A subsequent callback with the *correct* key must still succeed,
/// proving the server did not desync.
#[tokio::test]
async fn wrong_key_callback_returns_404_and_preserves_ctr_offset()
-> Result<(), Box<dyn std::error::Error>> {
    let mut harness = spawn_server_with_http_listener("edge-http-wrong-key").await?;
    let listener_port = harness.listener_port;

    let agent_id = 0x1234_5678;
    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    let mut ctr_offset = 0_u64;

    // --- Register the agent normally ------------------------------------------------
    let init_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let init_bytes = init_response.bytes().await?;
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    ctr_offset += ctr_blocks_for_len(init_bytes.len());

    let agent_new = common::read_operator_message(&mut harness.socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // --- Send a callback encrypted with a WRONG key ---------------------------------
    let wrong_key = [0xBB; AGENT_KEY_LENGTH];
    let wrong_key_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            wrong_key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            1,
            &[],
        ))
        .send()
        .await?;
    assert_eq!(
        wrong_key_response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "wrong-key callback must be rejected with fake 404"
    );

    // --- Verify the server's CTR offset was NOT advanced ----------------------------
    assert_eq!(
        harness.server.agent_registry.ctr_offset(agent_id).await?,
        ctr_offset,
        "CTR offset must not advance after a wrong-key callback"
    );

    // --- A subsequent valid callback must still succeed ------------------------------
    let task = operator_task_message("CC", "checkin", "12345678", DemonCommand::CommandCheckin)?;
    harness.socket.send(ClientMessage::Text(task.into())).await?;
    let _task_echo = common::read_operator_message(&mut harness.socket).await?;

    let valid_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            2,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    let job_bytes = valid_response.bytes().await?;
    let message = DemonMessage::from_bytes(job_bytes.as_ref())?;
    assert_eq!(
        message.packages.len(),
        1,
        "valid callback after wrong-key must still retrieve queued tasks"
    );
    assert_eq!(message.packages[0].request_id, 0xCC);

    harness.shutdown().await?;
    Ok(())
}

/// A duplicate full `DEMON_INIT` for an already-registered agent must be
/// rejected with HTTP 404.  The original agent's crypto state must be
/// preserved — a subsequent callback with the original key must still work.
#[tokio::test]
async fn duplicate_demon_init_rejected_preserves_original_agent()
-> Result<(), Box<dyn std::error::Error>> {
    let mut harness = spawn_server_with_http_listener("edge-http-dup-init").await?;
    let listener_port = harness.listener_port;

    let agent_id = 0x1234_5678;
    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    let mut ctr_offset = 0_u64;

    // --- First (legitimate) init ----------------------------------------------------
    let init_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let init_bytes = init_response.bytes().await?;
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    ctr_offset += ctr_blocks_for_len(init_bytes.len());

    let agent_new = common::read_operator_message(&mut harness.socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let ctr_before_dup = harness.server.agent_registry.ctr_offset(agent_id).await?;

    // --- Second (duplicate) init with different key material ------------------------
    let dup_key = [0xDD; AGENT_KEY_LENGTH];
    let dup_iv = [0xEE; AGENT_IV_LENGTH];
    let dup_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, dup_key, dup_iv))
        .send()
        .await?;
    assert_eq!(
        dup_response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "duplicate DEMON_INIT must be rejected with fake 404"
    );

    // --- Verify CTR offset unchanged ------------------------------------------------
    assert_eq!(
        harness.server.agent_registry.ctr_offset(agent_id).await?,
        ctr_before_dup,
        "CTR offset must not change after duplicate init rejection"
    );

    // --- Verify original key still works --------------------------------------------
    let task = operator_task_message("DD", "checkin", "12345678", DemonCommand::CommandCheckin)?;
    harness.socket.send(ClientMessage::Text(task.into())).await?;
    let _task_echo = common::read_operator_message(&mut harness.socket).await?;

    let valid_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            1,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    let job_bytes = valid_response.bytes().await?;
    let message = DemonMessage::from_bytes(job_bytes.as_ref())?;
    assert_eq!(message.packages.len(), 1);
    assert_eq!(message.packages[0].request_id, 0xDD);

    harness.shutdown().await?;
    Ok(())
}

/// Multiple agents registering and communicating concurrently on the same
/// listener must not interfere with each other.  Each agent has independent
/// key material and CTR state.
#[tokio::test]
async fn multiple_concurrent_agents_on_same_listener() -> Result<(), Box<dyn std::error::Error>> {
    let mut harness = spawn_server_with_http_listener("edge-http-concurrent").await?;
    let listener_port = harness.listener_port;

    struct AgentState {
        agent_id: u32,
        key: [u8; AGENT_KEY_LENGTH],
        iv: [u8; AGENT_IV_LENGTH],
        ctr_offset: u64,
    }

    let mut agents = vec![
        AgentState {
            agent_id: 0xAAAA_0001,
            key: [0x11; AGENT_KEY_LENGTH],
            iv: [0x21; AGENT_IV_LENGTH],
            ctr_offset: 0,
        },
        AgentState {
            agent_id: 0xAAAA_0002,
            key: [0x22; AGENT_KEY_LENGTH],
            iv: [0x32; AGENT_IV_LENGTH],
            ctr_offset: 0,
        },
        AgentState {
            agent_id: 0xAAAA_0003,
            key: [0x33; AGENT_KEY_LENGTH],
            iv: [0x43; AGENT_IV_LENGTH],
            ctr_offset: 0,
        },
    ];

    // --- Register all three agents --------------------------------------------------
    for agent in &mut agents {
        let init_response = harness
            .client
            .post(format!("http://127.0.0.1:{listener_port}/"))
            .body(common::valid_demon_init_body(agent.agent_id, agent.key, agent.iv))
            .send()
            .await?
            .error_for_status()?;
        let init_bytes = init_response.bytes().await?;
        let init_ack =
            decrypt_agent_data_at_offset(&agent.key, &agent.iv, agent.ctr_offset, &init_bytes)?;
        assert_eq!(init_ack.as_slice(), &agent.agent_id.to_le_bytes());
        agent.ctr_offset += ctr_blocks_for_len(init_bytes.len());

        // Consume the AgentNew event.
        let agent_new = common::read_operator_message(&mut harness.socket).await?;
        assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));
    }

    // --- Queue a task for each agent ------------------------------------------------
    for agent in &agents {
        let demon_id = format!("{:X}", agent.agent_id);
        let task_id = format!("{:X}", agent.agent_id & 0xFF);
        let task =
            operator_task_message(&task_id, "checkin", &demon_id, DemonCommand::CommandCheckin)?;
        harness.socket.send(ClientMessage::Text(task.into())).await?;
        let _echo = common::read_operator_message(&mut harness.socket).await?;
    }

    // --- Each agent polls for its job -----------------------------------------------
    for agent in &mut agents {
        let get_job_response = harness
            .client
            .post(format!("http://127.0.0.1:{listener_port}/"))
            .body(common::valid_demon_callback_body(
                agent.agent_id,
                agent.key,
                agent.iv,
                agent.ctr_offset,
                u32::from(DemonCommand::CommandGetJob),
                1,
                &[],
            ))
            .send()
            .await?
            .error_for_status()?;
        let job_bytes = get_job_response.bytes().await?;
        let message = DemonMessage::from_bytes(job_bytes.as_ref())?;
        assert_eq!(
            message.packages.len(),
            1,
            "agent 0x{:08X} must receive exactly one task",
            agent.agent_id
        );
        let expected_request_id = agent.agent_id & 0xFF;
        assert_eq!(
            message.packages[0].request_id, expected_request_id,
            "agent 0x{:08X} received wrong task",
            agent.agent_id
        );
        agent.ctr_offset += ctr_blocks_for_len(4);
    }

    // --- Each agent sends output — verify no cross-contamination --------------------
    for agent in &agents {
        let output_text = format!("output from {:08X}", agent.agent_id);
        let request_id = agent.agent_id & 0xFF;
        let payload = common::command_output_payload(&output_text);
        harness
            .client
            .post(format!("http://127.0.0.1:{listener_port}/"))
            .body(common::valid_demon_callback_body(
                agent.agent_id,
                agent.key,
                agent.iv,
                agent.ctr_offset,
                u32::from(DemonCommand::CommandOutput),
                request_id,
                &payload,
            ))
            .send()
            .await?
            .error_for_status()?;
    }

    for agent in &agents {
        let event = common::read_operator_message(&mut harness.socket).await?;
        let OperatorMessage::AgentResponse(message) = event else {
            panic!("expected AgentResponse event");
        };
        let expected_demon_id = format!("{:X}", agent.agent_id);
        let expected_output = format!("output from {:08X}", agent.agent_id);
        assert_eq!(message.info.demon_id, expected_demon_id);
        assert_eq!(message.info.output, expected_output);
    }

    harness.shutdown().await?;
    Ok(())
}

/// A callback sent with a stale (already-consumed) CTR offset must be
/// rejected with HTTP 404, the server's CTR offset must not change, and
/// a subsequent callback at the correct offset must still succeed.
#[tokio::test]
async fn stale_ctr_offset_callback_returns_404_and_preserves_state()
-> Result<(), Box<dyn std::error::Error>> {
    let mut harness = spawn_server_with_http_listener("edge-http-stale-ctr").await?;
    let listener_port = harness.listener_port;

    let agent_id = 0x1234_5678;
    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    let mut ctr_offset = 0_u64;

    // --- Register the agent ---------------------------------------------------------
    let init_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let init_bytes = init_response.bytes().await?;
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    ctr_offset += ctr_blocks_for_len(init_bytes.len());

    let agent_new = common::read_operator_message(&mut harness.socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // --- First valid callback to advance the server's CTR ---------------------------
    let task = operator_task_message("AA", "checkin", "12345678", DemonCommand::CommandCheckin)?;
    harness.socket.send(ClientMessage::Text(task.into())).await?;
    let _task_echo = common::read_operator_message(&mut harness.socket).await?;

    let valid_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            1,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    let job_bytes = valid_response.bytes().await?;
    let message = DemonMessage::from_bytes(job_bytes.as_ref())?;
    assert_eq!(message.packages.len(), 1);
    assert_eq!(message.packages[0].request_id, 0xAA);

    let stale_offset = ctr_offset;
    ctr_offset += ctr_blocks_for_len(4);
    let ctr_after_valid = harness.server.agent_registry.ctr_offset(agent_id).await?;

    // --- Send a replay with the STALE (pre-advance) CTR offset ----------------------
    let stale_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            stale_offset,
            u32::from(DemonCommand::CommandGetJob),
            2,
            &[],
        ))
        .send()
        .await?;
    assert_eq!(
        stale_response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "stale-CTR callback must be rejected with fake 404"
    );

    // --- Verify server CTR offset was NOT changed -----------------------------------
    assert_eq!(
        harness.server.agent_registry.ctr_offset(agent_id).await?,
        ctr_after_valid,
        "CTR offset must not change after stale-offset callback rejection"
    );

    // --- A subsequent callback at the CORRECT offset must succeed --------------------
    let task2 = operator_task_message("BB", "checkin", "12345678", DemonCommand::CommandCheckin)?;
    harness.socket.send(ClientMessage::Text(task2.into())).await?;
    let _task2_echo = common::read_operator_message(&mut harness.socket).await?;

    let recovery_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            3,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    let recovery_bytes = recovery_response.bytes().await?;
    let recovery_message = DemonMessage::from_bytes(recovery_bytes.as_ref())?;
    assert_eq!(
        recovery_message.packages.len(),
        1,
        "valid callback after stale-CTR must still retrieve queued tasks"
    );
    assert_eq!(recovery_message.packages[0].request_id, 0xBB);

    harness.shutdown().await?;
    Ok(())
}
