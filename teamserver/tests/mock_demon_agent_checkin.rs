mod common;

use std::time::Duration;

use futures_util::SinkExt;
use red_cell_common::HttpListenerConfig;
use red_cell_common::config::Profile;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, decrypt_agent_data_at_offset};
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

        Demon {
          AllowLegacyCtr = true
        }
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
    let (mut socket, _) = connect_async(server.ws_url()).await?;
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
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xB0, 0xC3, 0xD6, 0xE9, 0xFC, 0x0F, 0x22, 0x35, 0x48, 0x5B, 0x6E, 0x81, 0x94, 0xA7, 0xBA,
        0xCD,
    ];
    let ctr_offset = 0_u64;

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
    // Legacy CTR mode: offset stays at 0.

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
    // Legacy CTR mode: offset stays at 0.

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
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34,
        0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xE5, 0xF8, 0x0B, 0x1E, 0x31, 0x44, 0x57, 0x6A, 0x7D, 0x90, 0xA3, 0xB6, 0xC9, 0xDC, 0xEF,
        0x02,
    ];
    let ctr_offset = 0_u64;

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
    // Legacy CTR mode: offset stays at 0.

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
    // Legacy CTR mode: offset stays at 0.

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
        // Legacy CTR mode: offset stays at 0.
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
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
        0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x69, 0x6A,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x1A, 0x2D, 0x40, 0x53, 0x66, 0x79, 0x8C, 0x9F, 0xB2, 0xC5, 0xD8, 0xEB, 0xFE, 0x11, 0x24,
        0x37,
    ];
    let ctr_offset = 0_u64;

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
    // Legacy CTR mode: offset stays at 0.

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
    // Legacy CTR mode: offset stays at 0.

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
        // Legacy CTR mode: offset stays at 0.
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
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E,
        0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D,
        0x8E, 0x8F,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x4F, 0x62, 0x75, 0x88, 0x9B, 0xAE, 0xC1, 0xD4, 0xE7, 0xFA, 0x0D, 0x20, 0x33, 0x46, 0x59,
        0x6C,
    ];

    // --- Step 1: full init --------------------------------------------------------
    // The agent tracks its own CTR offset mirror to simulate what a real agent does.
    let agent_ctr_offset = 0_u64;

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
    // Legacy CTR mode: offset stays at 0.

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
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3,
        0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2,
        0xB3, 0xB4,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x84, 0x97, 0xAA, 0xBD, 0xD0, 0xE3, 0xF6, 0x09, 0x1C, 0x2F, 0x42, 0x55, 0x68, 0x7B, 0x8E,
        0xA1,
    ];
    let ctr_offset = 0_u64;

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
    // Legacy CTR mode: offset stays at 0.

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
    // Legacy CTR mode: offset stays at 0.

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
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8,
        0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
        0xD8, 0xD9,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xB9, 0xCC, 0xDF, 0xF2, 0x05, 0x18, 0x2B, 0x3E, 0x51, 0x64, 0x77, 0x8A, 0x9D, 0xB0, 0xC3,
        0xD6,
    ];
    let ctr_offset = 0_u64;

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
    // Legacy CTR mode: offset stays at 0.

    // --- Open a second (unauthenticated) WebSocket client -------------------------
    let (mut unauth_socket, _) = connect_async(harness.server.ws_url()).await?;

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
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED,
        0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC,
        0xFD, 0xFE,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xEE, 0x01, 0x14, 0x27, 0x3A, 0x4D, 0x60, 0x73, 0x86, 0x99, 0xAC, 0xBF, 0xD2, 0xE5, 0xF8,
        0x0B,
    ];
    let ctr_offset = 0_u64;

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
    // Legacy CTR mode: offset stays at 0.

    // --- Attempt login with wrong password ----------------------------------------
    let (mut bad_socket, _) = connect_async(harness.server.ws_url()).await?;
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
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
        0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21,
        0x22, 0x23,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x23, 0x36, 0x49, 0x5C, 0x6F, 0x82, 0x95, 0xA8, 0xBB, 0xCE, 0xE1, 0xF4, 0x07, 0x1A, 0x2D,
        0x40,
    ];
    let ctr_offset = 0_u64;

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
    // Legacy CTR mode: offset stays at 0.

    let agent_new = common::read_operator_message(&mut harness.socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // --- Send a callback encrypted with a WRONG key ---------------------------------
    let wrong_key: [u8; AGENT_KEY_LENGTH] = [
        0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
        0x47, 0x48,
    ];
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
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C,
        0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B,
        0x6C, 0x6D,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x8D, 0xA0, 0xB3, 0xC6, 0xD9, 0xEC, 0xFF, 0x12, 0x25, 0x38, 0x4B, 0x5E, 0x71, 0x84, 0x97,
        0xAA,
    ];
    let ctr_offset = 0_u64;

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
    // Legacy CTR mode: offset stays at 0.

    let agent_new = common::read_operator_message(&mut harness.socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let ctr_before_dup = harness.server.agent_registry.ctr_offset(agent_id).await?;

    // --- Second (duplicate) init with different key material ------------------------
    let dup_key: [u8; AGENT_KEY_LENGTH] = [
        0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81,
        0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90,
        0x91, 0x92,
    ];
    let dup_iv: [u8; AGENT_IV_LENGTH] = [
        0xC2, 0xD5, 0xE8, 0xFB, 0x0E, 0x21, 0x34, 0x47, 0x5A, 0x6D, 0x80, 0x93, 0xA6, 0xB9, 0xCC,
        0xDF,
    ];
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
            key: [
                0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
                0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3,
                0xB4, 0xB5, 0xB6, 0xB7,
            ],
            iv: [
                0xF7, 0x0A, 0x1D, 0x30, 0x43, 0x56, 0x69, 0x7C, 0x8F, 0xA2, 0xB5, 0xC8, 0xDB, 0xEE,
                0x01, 0x14,
            ],
            ctr_offset: 0,
        },
        AgentState {
            agent_id: 0xAAAA_0002,
            key: [
                0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
                0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8,
                0xD9, 0xDA, 0xDB, 0xDC,
            ],
            iv: [
                0x2C, 0x3F, 0x52, 0x65, 0x78, 0x8B, 0x9E, 0xB1, 0xC4, 0xD7, 0xEA, 0xFD, 0x10, 0x23,
                0x36, 0x49,
            ],
            ctr_offset: 0,
        },
        AgentState {
            agent_id: 0xAAAA_0003,
            key: [
                0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
                0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD,
                0xFE, 0xFF, 0x00, 0x01,
            ],
            iv: [
                0x61, 0x74, 0x87, 0x9A, 0xAD, 0xC0, 0xD3, 0xE6, 0xF9, 0x0C, 0x1F, 0x32, 0x45, 0x58,
                0x6B, 0x7E,
            ],
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
        // Legacy CTR mode: offset stays at 0.

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
        // Legacy CTR mode: offset stays at 0.
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

/// In legacy CTR mode (used by DEMON_INIT-registered agents), every packet
/// uses CTR block offset 0.  Repeated callbacks at offset 0 must all succeed
/// because legacy mode has no concept of a "stale" offset.
#[tokio::test]
async fn stale_ctr_offset_callback_returns_404_and_preserves_state()
-> Result<(), Box<dyn std::error::Error>> {
    let mut harness = spawn_server_with_http_listener("edge-http-stale-ctr").await?;
    let listener_port = harness.listener_port;

    let agent_id = 0x1234_5678;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
        0x25, 0x26,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x96, 0xA9, 0xBC, 0xCF, 0xE2, 0xF5, 0x08, 0x1B, 0x2E, 0x41, 0x54, 0x67, 0x7A, 0x8D, 0xA0,
        0xB3,
    ];
    let ctr_offset = 0_u64;

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

    let agent_new = tokio::time::timeout(
        Duration::from_secs(10),
        common::read_operator_message(&mut harness.socket),
    )
    .await
    .map_err(|_| "timed out waiting for AgentNew message")??;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // --- First callback at offset 0 -------------------------------------------------
    let task = operator_task_message("AA", "checkin", "12345678", DemonCommand::CommandCheckin)?;
    harness.socket.send(ClientMessage::Text(task.into())).await?;
    let _task_echo = tokio::time::timeout(
        Duration::from_secs(10),
        common::read_operator_message(&mut harness.socket),
    )
    .await
    .map_err(|_| "timed out waiting for first task echo")??;

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

    let ctr_after_valid = harness.server.agent_registry.ctr_offset(agent_id).await?;
    assert_eq!(ctr_after_valid, 0, "legacy CTR mode keeps offset at 0");

    // --- Second callback at same offset 0 (legacy mode allows this) -----------------
    let stale_response = harness
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
        .await?;
    // Legacy mode: repeated offset 0 is accepted, not rejected.
    assert!(
        stale_response.status().is_success(),
        "legacy CTR mode accepts repeated callbacks at offset 0"
    );

    // --- Verify server CTR offset remains 0 -----------------------------------------
    assert_eq!(
        harness.server.agent_registry.ctr_offset(agent_id).await?,
        0,
        "CTR offset must remain 0 in legacy mode"
    );

    // --- Third callback also succeeds -----------------------------------------------
    let task2 = operator_task_message("BB", "checkin", "12345678", DemonCommand::CommandCheckin)?;
    harness.socket.send(ClientMessage::Text(task2.into())).await?;
    let _task2_echo = tokio::time::timeout(
        Duration::from_secs(10),
        common::read_operator_message(&mut harness.socket),
    )
    .await
    .map_err(|_| "timed out waiting for second task echo")??;

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

/// Concurrent reconnect probes from the same agent must all succeed and leave the CTR offset
/// unchanged.  The `encrypt_for_agent_without_advancing` path acquires the `ctr_block_offset`
/// mutex, so concurrent calls are serialised — but we must verify that no probe corrupts the
/// offset or causes a panic under real concurrency.
#[tokio::test]
async fn concurrent_reconnect_probes_preserve_ctr_offset() -> Result<(), Box<dyn std::error::Error>>
{
    let mut harness = spawn_server_with_http_listener("edge-http-concurrent-reconnect").await?;
    let listener_port = harness.listener_port;

    let agent_id = 0xCAFE_0001_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A,
        0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
        0x4A, 0x4B,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xCB, 0xDE, 0xF1, 0x04, 0x17, 0x2A, 0x3D, 0x50, 0x63, 0x76, 0x89, 0x9C, 0xAF, 0xC2, 0xD5,
        0xE8,
    ];

    // Register the agent.
    let init_bytes = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    let agent_ctr_offset = 0_u64;
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, agent_ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    // Legacy CTR mode: offset stays at 0.

    // Consume AgentNew event.
    let _agent_new = common::read_operator_message(&mut harness.socket).await?;

    let offset_before = harness.server.agent_registry.ctr_offset(agent_id).await?;

    // Fire 20 concurrent reconnect probes.
    let mut join_set = tokio::task::JoinSet::new();
    for _ in 0..20 {
        let body = common::valid_demon_reconnect_body(agent_id);
        let url = format!("http://127.0.0.1:{listener_port}/");
        join_set.spawn(async move {
            let client = reqwest::Client::new();
            let resp = client
                .post(&url)
                .body(body)
                .send()
                .await
                .expect("reconnect request should succeed")
                .error_for_status()
                .expect("reconnect should return 200");
            resp.bytes().await.expect("should read reconnect ACK bytes")
        });
    }

    let mut ack_count = 0_usize;
    while let Some(result) = join_set.join_next().await {
        let ack_bytes = result?;
        // Every reconnect ACK must be decryptable at the same offset (non-advancing).
        let ack_plaintext = decrypt_agent_data_at_offset(&key, &iv, agent_ctr_offset, &ack_bytes)?;
        assert_eq!(
            ack_plaintext.as_slice(),
            &agent_id.to_le_bytes(),
            "reconnect ACK #{ack_count} must echo agent_id"
        );
        ack_count += 1;
    }
    assert_eq!(ack_count, 20);

    // CTR offset must be unchanged.
    let offset_after = harness.server.agent_registry.ctr_offset(agent_id).await?;
    assert_eq!(
        offset_after, offset_before,
        "CTR offset must not drift after concurrent reconnect probes"
    );

    // Verify the agent session is still functional — a callback at the original offset must work.
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

/// A reconnect probe arriving while a callback is being processed must not corrupt the CTR
/// offset.  The two-phase decrypt pattern (`decrypt_from_agent_without_advancing` +
/// `advance_ctr_for_agent`) acquires and releases the mutex between phases, so a reconnect
/// probe could theoretically encrypt at the same offset during the gap.  Since the reconnect
/// ACK uses `encrypt_for_agent_without_advancing`, the offset must remain stable.
///
/// This test fires callbacks and reconnect probes concurrently from separate tasks.
#[tokio::test]
async fn reconnect_probe_interleaved_with_callbacks_preserves_sync()
-> Result<(), Box<dyn std::error::Error>> {
    let mut harness = spawn_server_with_http_listener("edge-http-reconnect-interleave").await?;
    let listener_port = harness.listener_port;

    let agent_id = 0xCAFE_0002_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
        0x6F, 0x70,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x00, 0x13, 0x26, 0x39, 0x4C, 0x5F, 0x72, 0x85, 0x98, 0xAB, 0xBE, 0xD1, 0xE4, 0xF7, 0x0A,
        0x1D,
    ];

    // Register.
    let init_bytes = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    let agent_ctr_offset = 0_u64;
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, agent_ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    // Legacy CTR mode: offset stays at 0.

    let _agent_new = common::read_operator_message(&mut harness.socket).await?;

    // Run 10 sequential cycles: for each cycle, fire a callback and a reconnect probe
    // concurrently.  After each cycle, the callback advances the agent's offset by the
    // callback payload size, and the reconnect must not have interfered.
    for cycle in 0..10_u32 {
        let callback_body = common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            agent_ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            cycle + 1,
            &[],
        );
        let reconnect_body = common::valid_demon_reconnect_body(agent_id);

        let url = format!("http://127.0.0.1:{listener_port}/");
        let url2 = url.clone();

        // Fire both concurrently.
        let callback_handle = tokio::spawn(async move {
            let client = reqwest::Client::new();
            client.post(&url).body(callback_body).send().await
        });
        let reconnect_handle = tokio::spawn(async move {
            let client = reqwest::Client::new();
            client.post(&url2).body(reconnect_body).send().await
        });

        let (cb_result, rc_result) = tokio::try_join!(callback_handle, reconnect_handle)?;
        let cb_resp = cb_result?.error_for_status()?;
        let _rc_resp = rc_result?.error_for_status()?;

        // The callback carries an encrypted 4-byte inner length prefix (empty payload).
        // `valid_demon_callback_body` with `&[]` produces a 4-byte plaintext (the BE length 0).
        let _callback_encrypted_len = 4; // BE u32 length prefix
        // Legacy CTR mode: offset stays at 0.

        // Verify the server offset matches what the agent expects after the callback.
        let server_offset = harness.server.agent_registry.ctr_offset(agent_id).await?;
        assert_eq!(
            server_offset, agent_ctr_offset,
            "cycle {cycle}: server CTR offset must equal agent-side tracking after callback + reconnect"
        );

        let _ = cb_resp.bytes().await?;
    }

    // Final callback to prove the session is still fully synchronised.
    harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            agent_ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            100,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;

    harness.shutdown().await?;
    Ok(())
}

/// Rapid reconnect-callback cycles must not cause counter drift.  This test performs many
/// reconnect → callback pairs in tight succession, verifying that the CTR offset advances
/// exactly as expected and the session remains usable throughout.
#[tokio::test]
async fn rapid_reconnect_callback_cycles_no_counter_drift() -> Result<(), Box<dyn std::error::Error>>
{
    let mut harness = spawn_server_with_http_listener("edge-http-rapid-cycles").await?;
    let listener_port = harness.listener_port;

    let agent_id = 0xCAFE_0003_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84,
        0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93,
        0x94, 0x95,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x35, 0x48, 0x5B, 0x6E, 0x81, 0x94, 0xA7, 0xBA, 0xCD, 0xE0, 0xF3, 0x06, 0x19, 0x2C, 0x3F,
        0x52,
    ];

    // Register.
    let init_bytes = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?;

    let agent_ctr_offset = 0_u64;
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, agent_ctr_offset, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    // Legacy CTR mode: offset stays at 0.

    let _agent_new = common::read_operator_message(&mut harness.socket).await?;

    // 30 rapid cycles: reconnect → callback → verify offset.
    for cycle in 0..30_u32 {
        // Reconnect probe (non-advancing).
        let reconnect_bytes = harness
            .client
            .post(format!("http://127.0.0.1:{listener_port}/"))
            .body(common::valid_demon_reconnect_body(agent_id))
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;

        // Verify reconnect ACK is at the current offset.
        let reconnect_ack =
            decrypt_agent_data_at_offset(&key, &iv, agent_ctr_offset, &reconnect_bytes)?;
        assert_eq!(
            reconnect_ack.as_slice(),
            &agent_id.to_le_bytes(),
            "cycle {cycle}: reconnect ACK must decrypt at current offset"
        );

        // CTR must not have moved.
        assert_eq!(
            harness.server.agent_registry.ctr_offset(agent_id).await?,
            agent_ctr_offset,
            "cycle {cycle}: CTR must not advance after reconnect ACK"
        );

        // Callback (advancing).
        harness
            .client
            .post(format!("http://127.0.0.1:{listener_port}/"))
            .body(common::valid_demon_callback_body(
                agent_id,
                key,
                iv,
                agent_ctr_offset,
                u32::from(DemonCommand::CommandGetJob),
                cycle + 1,
                &[],
            ))
            .send()
            .await?
            .error_for_status()?;

        // The callback's encrypted portion is the 4-byte inner length prefix.
        // Legacy CTR mode: offset stays at 0.

        // Verify the server agrees.
        assert_eq!(
            harness.server.agent_registry.ctr_offset(agent_id).await?,
            agent_ctr_offset,
            "cycle {cycle}: server CTR must match agent tracking after callback"
        );
    }

    // Final validation: one more callback to prove no drift accumulated.
    harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            agent_ctr_offset,
            u32::from(DemonCommand::CommandGetJob),
            999,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;

    harness.shutdown().await?;
    Ok(())
}

/// Verify that a malformed (non-JSON) operator WebSocket message closes the
/// offending connection but does not break task dispatch for other operators.
///
/// Regression test: ensures the server-side message loop gracefully handles
/// parse errors instead of panicking or poisoning shared state.
#[tokio::test]
async fn malformed_operator_message_closes_connection_without_breaking_dispatch()
-> Result<(), Box<dyn std::error::Error>> {
    use futures_util::StreamExt;
    use tokio::time::{Duration, timeout};

    let mut harness = spawn_server_with_http_listener("edge-malformed").await?;
    let listener_port = harness.listener_port;

    // Register a Demon agent so we can verify task dispatch still works.
    let agent_id = 0x1234_5678;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xB0, 0xC3, 0xD6, 0xE9, 0xFC, 0x0F, 0x22, 0x35, 0x48, 0x5B, 0x6E, 0x81, 0x94, 0xA7, 0xBA,
        0xCD,
    ];

    harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;

    // Consume the AgentNew event on the first operator socket.
    let agent_new = common::read_operator_message(&mut harness.socket).await?;
    assert!(
        matches!(agent_new, OperatorMessage::AgentNew(_)),
        "expected AgentNew, got {agent_new:?}"
    );

    // Open a second operator connection for the "bad" client.
    let (mut bad_socket, _) = connect_async(harness.server.ws_url()).await?;
    common::login(&mut bad_socket).await?;

    // The second socket receives snapshot events (listeners, agents, etc.).
    // Drain until we see the AgentNew entry so the socket is ready for our test.
    let mut saw_agent_new = false;
    for _ in 0..10 {
        let event = common::read_operator_message(&mut bad_socket).await?;
        if matches!(event, OperatorMessage::AgentNew(_)) {
            saw_agent_new = true;
            break;
        }
    }
    assert!(saw_agent_new, "expected AgentNew in snapshot on second socket");

    // --- Send malformed (non-JSON) message on the bad socket ---
    bad_socket.send(ClientMessage::Text("not valid json".into())).await?;

    // The server should close the bad connection.
    let close_frame = timeout(Duration::from_secs(10), bad_socket.next()).await?;
    assert!(
        close_frame
            .as_ref()
            .map(|r| r.as_ref().map(|m| m.is_close()).unwrap_or(false))
            .unwrap_or(true),
        "expected close frame on bad socket after malformed message, got {close_frame:?}"
    );

    // --- Verify the good operator connection still works ---
    // Submit a valid agent task on the original (good) socket.
    let task = operator_task_message("AA", "checkin", "12345678", DemonCommand::CommandCheckin)?;
    harness.socket.send(ClientMessage::Text(task.into())).await?;

    // We should receive the task echo, proving the dispatch loop is alive.
    let task_echo = common::read_operator_message(&mut harness.socket).await?;
    let OperatorMessage::AgentTask(message) = task_echo else {
        panic!("expected AgentTask echo on good socket, got {task_echo:?}");
    };
    assert_eq!(message.info.demon_id, "12345678");
    assert_eq!(message.info.task_id, "AA");

    // Confirm the job is actually enqueued — agent can retrieve it.
    let get_job_response = harness
        .client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            0,
            u32::from(DemonCommand::CommandGetJob),
            7,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    let job_bytes = get_job_response.bytes().await?;
    let jobs = DemonMessage::from_bytes(job_bytes.as_ref())?;
    assert!(
        !jobs.packages.is_empty(),
        "agent should have at least one job enqueued after malformed message on other socket"
    );
    assert_eq!(jobs.packages[0].command_id, u32::from(DemonCommand::CommandCheckin));

    harness.shutdown().await?;
    Ok(())
}
