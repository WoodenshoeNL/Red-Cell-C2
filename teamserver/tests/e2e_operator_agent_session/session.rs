use std::time::Duration;

use red_cell::demon::INIT_EXT_MONOTONIC_CTR;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len};
use red_cell_common::demon::{DemonCommand, DemonMessage};
use red_cell_common::operator::OperatorMessage;
use tokio_tungstenite::connect_async;

use crate::helpers::{
    agent_task_message, agent_task_message_for, assert_agent_output, http_listener_config,
    listener_new_message, read_until_operator_message, two_operator_profile,
};

#[tokio::test]
async fn operator_session_listener_and_mock_demon_round_trip()
-> Result<(), Box<dyn std::error::Error>> {
    let server = crate::common::spawn_test_server(crate::common::default_test_profile()).await?;

    let (listener_port, listener_guard) =
        crate::common::available_port_excluding(server.addr.port())?;
    assert_ne!(listener_port, server.addr.port());
    let client = reqwest::Client::new();
    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = crate::common::WsSession::new(raw_socket_);

    crate::common::login(&mut socket).await?;
    crate::common::assert_no_operator_message(&mut socket, Duration::from_millis(200)).await;

    // Release the port reservation immediately before the server binds it.
    drop(listener_guard);
    socket.send_text(listener_new_message("operator", listener_port)).await?;

    let listener_created = crate::common::read_operator_message(&mut socket).await?;
    let OperatorMessage::ListenerNew(message) = listener_created else {
        panic!("expected listener create event");
    };
    assert_eq!(message.info.name.as_deref(), Some("edge-http"));
    assert_eq!(message.info.status.as_deref(), Some("Offline"));

    let listener_started = crate::common::read_operator_message(&mut socket).await?;
    let OperatorMessage::ListenerMark(message) = listener_started else {
        panic!("expected listener start event");
    };
    use red_cell_common::operator::{EventCode, ListenerMarkInfo};
    assert_eq!(message.head.event, EventCode::Listener);
    assert_eq!(message.head.user, "operator");
    assert_eq!(
        message.info,
        ListenerMarkInfo { name: "edge-http".to_owned(), mark: "Online".to_owned() }
    );

    server.listeners.update(http_listener_config(listener_port)).await?;
    crate::common::wait_for_listener(listener_port).await?;

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
    let init_response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(crate::common::valid_demon_init_body_with_ext_flags(
            agent_id,
            key,
            iv,
            INIT_EXT_MONOTONIC_CTR,
        ))
        .send()
        .await?
        .error_for_status()?;
    let init_bytes = init_response.bytes().await?;
    let init_ack =
        red_cell_common::crypto::decrypt_agent_data_at_offset(&key, &iv, 0, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    let ctr_offset = ctr_blocks_for_len(4);

    let agent_new = crate::common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentNew(message) = agent_new else {
        panic!("expected agent session event");
    };
    assert_eq!(message.info.name_id, "12345678");
    assert_eq!(message.info.listener, "edge-http");
    assert_eq!(message.info.hostname, "wkstn-01");

    // Connect a second operator mid-session and verify the agent appears in the
    // snapshot — mirrors the check already present in the SMB round-trip test.
    let (raw_snapshot_socket_, _) = connect_async(server.ws_url()).await?;
    let mut snapshot_socket = crate::common::WsSession::new(raw_snapshot_socket_);
    crate::common::login(&mut snapshot_socket).await?;
    let snapshot_agent = read_until_operator_message(&mut snapshot_socket, |msg| {
        matches!(msg, OperatorMessage::AgentNew(_))
    })
    .await?;
    let OperatorMessage::AgentNew(snapshot_msg) = snapshot_agent else {
        panic!("expected agent snapshot event for second operator");
    };
    assert_eq!(snapshot_msg.info.name_id, "12345678");
    assert_eq!(snapshot_msg.info.listener, "edge-http");
    assert_eq!(snapshot_msg.info.hostname, "wkstn-01");
    snapshot_socket.close(None).await?;

    socket.send_text(agent_task_message("2A")).await?;

    let task_echo = crate::common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentTask(message) = task_echo else {
        panic!("expected agent task echo");
    };
    assert_eq!(message.info.demon_id, "12345678");
    assert_eq!(message.info.task_id, "2A");
    assert_eq!(message.info.command_line, "checkin");

    let get_job_response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(crate::common::valid_demon_callback_body(
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
    let job_message = DemonMessage::from_bytes(job_bytes.as_ref())?;
    assert_eq!(job_message.packages.len(), 1);
    assert_eq!(job_message.packages[0].command_id, u32::from(DemonCommand::CommandCheckin));
    assert_eq!(job_message.packages[0].request_id, 0x2A);
    assert!(job_message.packages[0].payload.is_empty());

    let output_text = "hello from demon";
    let callback_response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(crate::common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandOutput),
            0x2A,
            &crate::common::command_output_payload(output_text),
        ))
        .send()
        .await?
        .error_for_status()?;
    assert!(callback_response.bytes().await?.is_empty());

    let output_event = crate::common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(message) = output_event else {
        panic!("expected agent response event");
    };
    assert_agent_output(&message.info, output_text);

    // --- Audit log assertions ---
    // Verify that the WebSocket handlers persisted the expected audit entries
    // during the session so that a regression (accidentally removing an audit
    // call) would be caught here rather than silently skipped.
    let audit_entries = server.database.audit_log().list().await?;

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
    server.listeners.stop("edge-http").await?;
    Ok(())
}

/// E2E test: reconnect probe through operator WebSocket.
///
/// Sequence:
/// 1. Agent registers via `DEMON_INIT` — operator sees `AgentNew`.
/// 2. Agent sends a reconnect probe (empty `DEMON_INIT` body, same agent_id).
/// 3. Operator must NOT see a duplicate `AgentNew`.
/// 4. Agent sends a `CommandOutput` callback at the persisted (unchanged) CTR offset.
/// 5. Operator receives the output correctly — proving the session resumed without
///    desync or duplicate registration.
#[tokio::test]
async fn reconnect_probe_does_not_duplicate_agent_new_and_resumes_callbacks()
-> Result<(), Box<dyn std::error::Error>> {
    let server = crate::common::spawn_test_server(crate::common::default_test_profile()).await?;

    let (listener_port, listener_guard) =
        crate::common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();
    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = crate::common::WsSession::new(raw_socket_);

    crate::common::login(&mut socket).await?;
    crate::common::assert_no_operator_message(&mut socket, Duration::from_millis(200)).await;

    // Create and start an HTTP listener.
    drop(listener_guard);
    socket.send_text(listener_new_message("operator", listener_port)).await?;

    let _listener_created = crate::common::read_operator_message(&mut socket).await?;
    let _listener_started = crate::common::read_operator_message(&mut socket).await?;

    server.listeners.update(http_listener_config(listener_port)).await?;
    crate::common::wait_for_listener(listener_port).await?;

    let agent_id = 0xABCD_EF01_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34,
        0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xE5, 0xF8, 0x0B, 0x1E, 0x31, 0x44, 0x57, 0x6A, 0x7D, 0x90, 0xA3, 0xB6, 0xC9, 0xDC, 0xEF,
        0x02,
    ];
    // --- Step 1: full DEMON_INIT registration ---
    let init_response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(crate::common::valid_demon_init_body_with_ext_flags(
            agent_id,
            key,
            iv,
            INIT_EXT_MONOTONIC_CTR,
        ))
        .send()
        .await?
        .error_for_status()?;
    let init_bytes = init_response.bytes().await?;
    let init_ack =
        red_cell_common::crypto::decrypt_agent_data_at_offset(&key, &iv, 0, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    let ctr_offset = ctr_blocks_for_len(4);

    // Operator must see AgentNew.
    let agent_new = crate::common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentNew(new_msg) = agent_new else {
        panic!("expected AgentNew after init");
    };
    assert_eq!(new_msg.info.name_id, "ABCDEF01");

    // --- Step 2: reconnect probe (empty DEMON_INIT body, same agent_id) ---
    let reconnect_response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(crate::common::valid_demon_reconnect_body(agent_id))
        .send()
        .await?
        .error_for_status()?;
    let reconnect_bytes = reconnect_response.bytes().await?;

    // Verify the reconnect ACK decrypts correctly at the current CTR offset.
    // The reconnect ACK is encrypted by the server at its stored offset but is
    // NOT counter-consuming — neither side advances after the reconnect handshake.
    let reconnect_ack = red_cell_common::crypto::decrypt_agent_data_at_offset(
        &key,
        &iv,
        ctr_offset,
        &reconnect_bytes,
    )?;
    assert_eq!(
        reconnect_ack.as_slice(),
        &agent_id.to_le_bytes(),
        "reconnect ACK must echo agent_id at the pre-reconnect CTR offset"
    );

    // --- Step 3: operator must NOT see a duplicate AgentNew ---
    // The reconnect probe should not broadcast any operator event.
    crate::common::assert_no_operator_message(&mut socket, Duration::from_millis(500)).await;

    // --- Step 4: queue a task so we can verify output delivery ---
    socket.send_text(agent_task_message_for("3B", "ABCDEF01")).await?;

    let task_echo = crate::common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentTask(task_msg) = task_echo else {
        panic!("expected AgentTask echo");
    };
    assert_eq!(task_msg.info.demon_id, "ABCDEF01");
    assert_eq!(task_msg.info.task_id, "3B");

    // --- Step 5: agent sends CommandOutput at the current CTR offset ---
    let output_text = "reconnect callback output";
    let callback_response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(crate::common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandOutput),
            0x3B,
            &crate::common::command_output_payload(output_text),
        ))
        .send()
        .await?
        .error_for_status()?;
    assert!(callback_response.bytes().await?.is_empty());

    // Operator must see the resumed callback output.
    let output_event = crate::common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(resp_msg) = output_event else {
        panic!("expected AgentResponse after resumed callback");
    };
    assert_eq!(resp_msg.info.demon_id, "ABCDEF01");
    assert_eq!(resp_msg.info.command_id, u32::from(DemonCommand::CommandOutput).to_string());
    assert_eq!(resp_msg.info.output, output_text);

    socket.close(None).await?;
    server.listeners.stop("edge-http").await?;
    Ok(())
}

/// E2E test: two simultaneous operators both receive agent events.
///
/// Sequence:
/// 1. Spawn server with two operator accounts; connect both via WebSocket.
/// 2. Create an HTTP listener via operator-1.
/// 3. Register a mock agent via `DEMON_INIT`.
/// 4. Assert **both** WebSocket connections independently receive `AgentNew`.
/// 5. Operator-1 sends an `AgentTask` — assert **both** receive the task echo.
#[tokio::test]
async fn two_operators_both_receive_agent_events() -> Result<(), Box<dyn std::error::Error>> {
    let server = crate::common::spawn_test_server(two_operator_profile()).await?;

    let (listener_port, listener_guard) =
        crate::common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    // Connect operator-1.
    let (raw_op1_, _) = connect_async(server.ws_url()).await?;
    let mut op1 = crate::common::WsSession::new(raw_op1_);
    crate::common::login_as(&mut op1, "op_alpha", "alpha_pw").await?;
    crate::common::assert_no_operator_message(&mut op1, Duration::from_millis(200)).await;

    // Connect operator-2.
    let (raw_op2_, _) = connect_async(server.ws_url()).await?;
    let mut op2 = crate::common::WsSession::new(raw_op2_);
    crate::common::login_as(&mut op2, "op_beta", "beta_pw").await?;
    crate::common::assert_no_operator_message(&mut op2, Duration::from_millis(200)).await;

    // Operator-1 creates an HTTP listener.
    drop(listener_guard);
    op1.send_text(listener_new_message("op_alpha", listener_port)).await?;

    // Wait for the listener to be registered by consuming its creation events on op1.
    let _listener_created =
        read_until_operator_message(&mut op1, |m| matches!(m, OperatorMessage::ListenerNew(_)))
            .await?;
    let _listener_started =
        read_until_operator_message(&mut op1, |m| matches!(m, OperatorMessage::ListenerMark(_)))
            .await?;

    server.listeners.update(http_listener_config(listener_port)).await?;
    crate::common::wait_for_listener(listener_port).await?;

    // Register a mock agent.
    let agent_id = 0xCAFE_BABE_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE,
        0xBF, 0xC0,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
        0xE0,
    ];

    let init_response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(crate::common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let init_bytes = init_response.bytes().await?;
    let init_ack =
        red_cell_common::crypto::decrypt_agent_data_at_offset(&key, &iv, 0, &init_bytes)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());

    // Both operators must independently receive AgentNew.
    let agent_new_1 =
        read_until_operator_message(&mut op1, |m| matches!(m, OperatorMessage::AgentNew(_)))
            .await?;
    let OperatorMessage::AgentNew(msg1) = agent_new_1 else {
        unreachable!();
    };
    assert_eq!(msg1.info.name_id, "CAFEBABE");
    assert_eq!(msg1.info.listener, "edge-http");

    let agent_new_2 =
        read_until_operator_message(&mut op2, |m| matches!(m, OperatorMessage::AgentNew(_)))
            .await?;
    let OperatorMessage::AgentNew(msg2) = agent_new_2 else {
        unreachable!();
    };
    assert_eq!(msg2.info.name_id, "CAFEBABE");
    assert_eq!(msg2.info.listener, "edge-http");

    // Operator-1 sends an AgentTask — both must see the echo.
    op1.send_text(agent_task_message_for("5F", "CAFEBABE")).await?;

    let task_echo_1 =
        read_until_operator_message(&mut op1, |m| matches!(m, OperatorMessage::AgentTask(_)))
            .await?;
    let OperatorMessage::AgentTask(t1) = task_echo_1 else {
        unreachable!();
    };
    assert_eq!(t1.info.demon_id, "CAFEBABE");
    assert_eq!(t1.info.task_id, "5F");
    assert_eq!(t1.info.command_line, "checkin");

    let task_echo_2 =
        read_until_operator_message(&mut op2, |m| matches!(m, OperatorMessage::AgentTask(_)))
            .await?;
    let OperatorMessage::AgentTask(t2) = task_echo_2 else {
        unreachable!();
    };
    assert_eq!(t2.info.demon_id, "CAFEBABE");
    assert_eq!(t2.info.task_id, "5F");
    assert_eq!(t2.info.command_line, "checkin");

    op1.close(None).await?;
    op2.close(None).await?;
    server.listeners.stop("edge-http").await?;
    Ok(())
}
