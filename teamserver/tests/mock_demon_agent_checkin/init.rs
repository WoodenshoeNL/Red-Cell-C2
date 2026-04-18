//! Basic agent init, output delivery, and idle-poll tests.

use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, decrypt_agent_data_at_offset};
use red_cell_common::demon::{DemonCommand, DemonMessage};
use red_cell_common::operator::OperatorMessage;

use super::common;
use super::helpers::{assert_agent_output, operator_task_message, spawn_server_with_http_listener};

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
    harness.socket.send_text(task).await?;

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
    harness.socket.send_text(task).await?;

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
    harness.socket.send_text(first_task).await?;
    let first_task_echo = common::read_operator_message(&mut harness.socket).await?;
    assert!(matches!(first_task_echo, OperatorMessage::AgentTask(_)));

    let second_task = operator_task_message(
        "2B",
        "powershell Get-Date",
        "12345678",
        DemonCommand::CommandCheckin,
    )?;
    harness.socket.send_text(second_task).await?;
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
    harness.socket.send_text(task).await?;

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
        harness.socket.send_text(task).await?;
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
