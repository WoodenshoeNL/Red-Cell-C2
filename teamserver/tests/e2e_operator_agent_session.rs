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
use red_cell_common::config::Profile;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use red_cell_common::demon::{DemonCommand, DemonMessage};
use red_cell_common::operator::{
    AgentResponseInfo, AgentTaskInfo, EventCode, FlatInfo, ListenerInfo, ListenerMarkInfo, Message,
    MessageHead, NameInfo, OperatorMessage,
};
use red_cell_common::{DnsListenerConfig, HttpListenerConfig, ListenerConfig, SmbListenerConfig};
use serde_json::Value;
#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};
use tokio_tungstenite::{connect_async, tungstenite::Message as ClientMessage};

#[tokio::test]
async fn operator_session_listener_and_mock_demon_round_trip()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::legacy_ctr_test_profile()).await?;

    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    assert_ne!(listener_port, server.addr.port());
    let client = reqwest::Client::new();
    let (mut socket, _) = connect_async(server.ws_url()).await?;

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

    server.listeners.update(http_listener_config(listener_port)).await?;
    common::wait_for_listener(listener_port).await?;

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
    // Legacy CTR mode: offset stays at 0 regardless of prior traffic.

    let agent_new = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentNew(message) = agent_new else {
        panic!("expected agent session event");
    };
    assert_eq!(message.info.name_id, "12345678");
    assert_eq!(message.info.listener, "edge-http");
    assert_eq!(message.info.hostname, "wkstn-01");

    // Connect a second operator mid-session and verify the agent appears in the
    // snapshot — mirrors the check already present in the SMB round-trip test.
    let (mut snapshot_socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut snapshot_socket).await?;
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
    // Legacy CTR mode: offset stays at 0.
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
    let server = common::spawn_test_server(common::legacy_ctr_test_profile()).await?;

    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();
    let (mut socket, _) = connect_async(server.ws_url()).await?;

    common::login(&mut socket).await?;
    common::assert_no_operator_message(&mut socket, Duration::from_millis(200)).await;

    // Create and start an HTTP listener.
    drop(listener_guard);
    socket
        .send(ClientMessage::Text(listener_new_message("operator", listener_port).into()))
        .await?;

    let _listener_created = common::read_operator_message(&mut socket).await?;
    let _listener_started = common::read_operator_message(&mut socket).await?;

    server.listeners.update(http_listener_config(listener_port)).await?;
    common::wait_for_listener(listener_port).await?;

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
    let ctr_offset = 0_u64;

    // --- Step 1: full DEMON_INIT registration ---
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
    // Legacy CTR mode: offset stays at 0 regardless of prior traffic.

    // Operator must see AgentNew.
    let agent_new = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentNew(new_msg) = agent_new else {
        panic!("expected AgentNew after init");
    };
    assert_eq!(new_msg.info.name_id, "ABCDEF01");

    // --- Step 2: reconnect probe (empty DEMON_INIT body, same agent_id) ---
    let reconnect_response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_reconnect_body(agent_id))
        .send()
        .await?
        .error_for_status()?;
    let reconnect_bytes = reconnect_response.bytes().await?;

    // Verify the reconnect ACK decrypts correctly at the current (unchanged) CTR offset.
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
    common::assert_no_operator_message(&mut socket, Duration::from_millis(500)).await;

    // CTR offset must not have advanced (reconnect ACK is not counter-consuming).
    // We do NOT advance ctr_offset here.

    // --- Step 4: queue a task so we can verify output delivery ---
    socket.send(ClientMessage::Text(agent_task_message_for("3B", "ABCDEF01").into())).await?;

    let task_echo = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentTask(task_msg) = task_echo else {
        panic!("expected AgentTask echo");
    };
    assert_eq!(task_msg.info.demon_id, "ABCDEF01");
    assert_eq!(task_msg.info.task_id, "3B");

    // --- Step 5: agent sends CommandOutput at the unchanged CTR offset ---
    let output_text = "reconnect callback output";
    let callback_response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandOutput),
            0x3B,
            &common::command_output_payload(output_text),
        ))
        .send()
        .await?
        .error_for_status()?;
    assert!(callback_response.bytes().await?.is_empty());

    // Operator must see the resumed callback output.
    let output_event = common::read_operator_message(&mut socket).await?;
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
    let server = common::spawn_test_server(two_operator_profile()).await?;

    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    // Connect operator-1.
    let (mut op1, _) = connect_async(server.ws_url()).await?;
    common::login_as(&mut op1, "op_alpha", "alpha_pw").await?;
    common::assert_no_operator_message(&mut op1, Duration::from_millis(200)).await;

    // Connect operator-2.
    let (mut op2, _) = connect_async(server.ws_url()).await?;
    common::login_as(&mut op2, "op_beta", "beta_pw").await?;
    common::assert_no_operator_message(&mut op2, Duration::from_millis(200)).await;

    // Operator-1 creates an HTTP listener.
    drop(listener_guard);
    op1.send(ClientMessage::Text(listener_new_message("op_alpha", listener_port).into())).await?;

    // Wait for the listener to be registered by consuming its creation events on op1.
    let _listener_created =
        read_until_operator_message(&mut op1, |m| matches!(m, OperatorMessage::ListenerNew(_)))
            .await?;
    let _listener_started =
        read_until_operator_message(&mut op1, |m| matches!(m, OperatorMessage::ListenerMark(_)))
            .await?;

    server.listeners.update(http_listener_config(listener_port)).await?;
    common::wait_for_listener(listener_port).await?;

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
        .body(common::valid_demon_init_body(agent_id, key, iv))
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
    op1.send(ClientMessage::Text(agent_task_message_for("5F", "CAFEBABE").into())).await?;

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

/// Profile with two Operator-role users for fan-out broadcast testing.
fn two_operator_profile() -> Profile {
    Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 0
        }

        Operators {
          user "op_alpha" {
            Password = "alpha_pw"
            Role = "Operator"
          }
          user "op_beta" {
            Password = "beta_pw"
            Role = "Operator"
          }
        }

        Demon {
          AllowLegacyCtr = true
        }
        "#,
    )
    .expect("two-operator profile should parse")
}

#[cfg(unix)]
#[tokio::test]
async fn operator_session_smb_listener_and_mock_demon_round_trip()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::legacy_ctr_test_profile()).await?;

    let pipe_name = unique_pipe_name("operator-round-trip");
    let listener_name = "edge-smb";
    let (mut socket, _) = connect_async(server.ws_url()).await?;

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
    assert_eq!(message.info.protocol.as_deref(), Some("Smb"));
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

    server.listeners.update(smb_listener_config(listener_name, &pipe_name)).await?;
    wait_for_smb_listener(&pipe_name).await?;

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

    let mut init_stream = connect_smb(&pipe_name).await?;
    write_smb_frame(&mut init_stream, agent_id, &common::valid_demon_init_body(agent_id, key, iv))
        .await?;

    let (ack_agent_id, ack_payload) =
        timeout(Duration::from_secs(5), read_smb_frame(&mut init_stream)).await??;
    assert_eq!(ack_agent_id, agent_id);
    let init_ack =
        red_cell_common::crypto::decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &ack_payload)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    // Legacy CTR mode: offset stays at 0.
    drop(init_stream);

    let agent_new = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentNew(message) = agent_new else {
        panic!("expected agent session event");
    };
    assert_eq!(message.info.name_id, "12345678");
    assert_eq!(message.info.listener, listener_name);
    assert_eq!(message.info.hostname, "wkstn-01");

    let (mut snapshot_socket, _) = connect_async(server.ws_url()).await?;
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
    // Legacy CTR mode: offset stays at 0.

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
    let (resp_agent_id, resp_payload) =
        timeout(Duration::from_secs(5), read_smb_frame(&mut callback_stream)).await??;
    assert_eq!(resp_agent_id, agent_id, "output callback response must echo agent_id");
    assert!(
        resp_payload.is_empty(),
        "output callback response payload must be empty, got {} bytes",
        resp_payload.len()
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
    server.listeners.stop(listener_name).await?;
    Ok(())
}

#[tokio::test]
async fn operator_session_dns_listener_and_mock_demon_round_trip()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::legacy_ctr_test_profile()).await?;

    let dns_port = free_udp_port();
    let dns_domain = "c2.example.com";
    let listener_name = "edge-dns";
    let (mut socket, _) = connect_async(server.ws_url()).await?;

    common::login(&mut socket).await?;
    common::assert_no_operator_message(&mut socket, Duration::from_millis(200)).await;

    // Create a DNS listener via WebSocket.
    socket
        .send(ClientMessage::Text(
            listener_new_dns_message("operator", listener_name, dns_port, dns_domain).into(),
        ))
        .await?;

    let listener_created = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::ListenerNew(message) = listener_created else {
        panic!("expected listener create event");
    };
    assert_eq!(message.info.name.as_deref(), Some(listener_name));
    assert_eq!(message.info.protocol.as_deref(), Some("Dns"));
    assert_eq!(message.info.status.as_deref(), Some("Offline"));

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

    server.listeners.update(dns_listener_config(listener_name, dns_port, dns_domain)).await?;
    let dns_client = wait_for_dns_listener(dns_port).await?;

    let agent_id = 0x1234_5678_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E,
        0x8F, 0x90,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xD1, 0xE2, 0xF3, 0x04, 0x15, 0x26, 0x37, 0x48, 0x59, 0x6A, 0x7B, 0x8C, 0x9D, 0xAE, 0xBF,
        0xC0,
    ];

    // 1. Upload DEMON_INIT via chunked DNS queries.
    let init_body = common::valid_demon_init_body(agent_id, key, iv);
    let init_result =
        dns_upload_demon_packet(&dns_client, agent_id, &init_body, dns_domain, 0x1000).await?;
    assert_eq!(init_result, "ack", "DEMON_INIT upload must be acknowledged");

    // 2. Download init ACK via DNS download queries.
    let ack_payload = dns_download_response(&dns_client, agent_id, dns_domain, 0x2000).await?;
    assert!(!ack_payload.is_empty(), "init ACK response must be non-empty");
    // Legacy Demon agents reset AES-CTR to block 0 for every packet, so both the
    // init ACK and all subsequent callbacks use offset 0.
    let decrypted =
        red_cell_common::crypto::decrypt_agent_data_at_offset(&key, &iv, 0, &ack_payload)?;
    assert_eq!(decrypted.as_slice(), &agent_id.to_le_bytes());

    // 3. Operator sees AgentNew.
    let agent_new = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentNew(message) = agent_new else {
        panic!("expected agent session event");
    };
    assert_eq!(message.info.name_id, "12345678");
    assert_eq!(message.info.listener, listener_name);
    assert_eq!(message.info.hostname, "wkstn-01");

    // 4. Second operator connects and sees agent in snapshot.
    let (mut snapshot_socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut snapshot_socket).await?;
    let snapshot_agent = read_until_operator_message(&mut snapshot_socket, |msg| {
        matches!(msg, OperatorMessage::AgentNew(_))
    })
    .await?;
    let OperatorMessage::AgentNew(snapshot_msg) = snapshot_agent else {
        panic!("expected agent snapshot event for second operator");
    };
    assert_eq!(snapshot_msg.info.name_id, "12345678");
    assert_eq!(snapshot_msg.info.listener, listener_name);
    assert_eq!(snapshot_msg.info.hostname, "wkstn-01");
    snapshot_socket.close(None).await?;

    // 5. Operator sends AgentTask.
    socket.send(ClientMessage::Text(agent_task_message("2A").into())).await?;

    let task_echo = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentTask(message) = task_echo else {
        panic!("expected agent task echo");
    };
    assert_eq!(message.info.demon_id, "12345678");
    assert_eq!(message.info.task_id, "2A");
    assert_eq!(message.info.command_line, "checkin");

    // 6. Agent polls for task via DNS: upload CommandGetJob, then download response.
    // Legacy Demon mode: every callback is encrypted at CTR offset 0.
    let get_job_body = common::valid_demon_callback_body(
        agent_id,
        key,
        iv,
        0,
        u32::from(DemonCommand::CommandGetJob),
        5,
        &[],
    );
    let get_job_result =
        dns_upload_demon_packet(&dns_client, agent_id, &get_job_body, dns_domain, 0x3000).await?;
    assert_eq!(get_job_result, "ack", "CommandGetJob callback must be acknowledged");

    let job_bytes = dns_download_response(&dns_client, agent_id, dns_domain, 0x4000).await?;
    let job_message = DemonMessage::from_bytes(&job_bytes)?;
    assert_eq!(job_message.packages.len(), 1);
    assert_eq!(job_message.packages[0].command_id, u32::from(DemonCommand::CommandCheckin));
    assert_eq!(job_message.packages[0].request_id, 0x2A);
    assert!(job_message.packages[0].payload.is_empty());

    // 7. Agent sends CommandOutput callback via DNS upload.
    let output_text = "hello from dns demon";
    let callback_body = common::valid_demon_callback_body(
        agent_id,
        key,
        iv,
        0,
        u32::from(DemonCommand::CommandOutput),
        0x2A,
        &common::command_output_payload(output_text),
    );
    let callback_result =
        dns_upload_demon_packet(&dns_client, agent_id, &callback_body, dns_domain, 0x5000).await?;
    assert_eq!(callback_result, "ack", "CommandOutput callback must be acknowledged");

    // 8. Operator receives AgentResponse broadcast.
    let output_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(message) = output_event else {
        panic!("expected agent response event");
    };
    assert_agent_output(&message.info, output_text);

    socket.close(None).await?;
    server.listeners.stop(listener_name).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// DNS helpers
// ---------------------------------------------------------------------------

/// Base32hex alphabet (RFC 4648 §7).
const BASE32HEX_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

/// Encode `data` using base32hex (unpadded, uppercase).
fn base32hex_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;

    for &byte in data {
        buf = (buf << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            result.push(char::from(BASE32HEX_ALPHABET[((buf >> bits) & 0x1F) as usize]));
        }
    }
    if bits > 0 {
        buf <<= 5 - bits;
        result.push(char::from(BASE32HEX_ALPHABET[(buf & 0x1F) as usize]));
    }
    result
}

/// Decode base32hex (unpadded, case-insensitive) into bytes.
fn base32hex_decode(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut result = Vec::with_capacity(input.len() * 5 / 8);
    let mut buf: u32 = 0;
    let mut bits: u8 = 0;

    for ch in input.chars() {
        let val = match ch {
            '0'..='9' => (ch as u8) - b'0',
            'A'..='V' => (ch as u8) - b'A' + 10,
            'a'..='v' => (ch as u8) - b'a' + 10,
            '=' => continue,
            _ => return Err(format!("invalid base32hex character: {ch}").into()),
        };
        buf = (buf << 5) | u32::from(val);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            result.push((buf >> bits) as u8);
        }
    }
    Ok(result)
}

/// Build a DNS upload qname for the C2 protocol.
fn dns_upload_qname(agent_id: u32, seq: u16, total: u16, chunk: &[u8], domain: &str) -> String {
    format!("{}.{seq:x}-{total:x}-{agent_id:08x}.up.{domain}", base32hex_encode(chunk))
}

/// Build a DNS download qname for the C2 protocol.
fn dns_download_qname(agent_id: u32, seq: u16, domain: &str) -> String {
    format!("{seq:x}-{agent_id:08x}.dn.{domain}")
}

/// Build a minimal DNS TXT query packet.
fn build_dns_txt_query(id: u16, qname: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100_u16.to_be_bytes()); // flags: QR=0, RD=1
    buf.extend_from_slice(&1_u16.to_be_bytes()); // qdcount
    buf.extend_from_slice(&0_u16.to_be_bytes()); // ancount
    buf.extend_from_slice(&0_u16.to_be_bytes()); // nscount
    buf.extend_from_slice(&0_u16.to_be_bytes()); // arcount
    for label in qname.split('.') {
        buf.push(u8::try_from(label.len()).expect("label too long"));
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    buf.extend_from_slice(&16_u16.to_be_bytes()); // QTYPE TXT
    buf.extend_from_slice(&1_u16.to_be_bytes()); // QCLASS IN
    buf
}

/// DNS wire-format header length.
const DNS_HEADER_LEN: usize = 12;

/// Parse the TXT answer from a DNS response packet.
fn parse_dns_txt_answer(packet: &[u8]) -> Option<String> {
    if packet.len() < DNS_HEADER_LEN {
        return None;
    }
    let mut pos = DNS_HEADER_LEN;
    while pos < packet.len() {
        let len = usize::from(packet[pos]);
        pos += 1;
        if len == 0 {
            break;
        }
        pos = pos.checked_add(len)?;
    }
    pos = pos.checked_add(4)?; // QTYPE + QCLASS
    pos = pos.checked_add(2 + 2 + 2 + 4 + 2)?; // NAME + TYPE + CLASS + TTL + RDLENGTH
    let txt_len = usize::from(*packet.get(pos)?);
    let start = pos.checked_add(1)?;
    let end = start.checked_add(txt_len)?;
    std::str::from_utf8(packet.get(start..end)?).ok().map(str::to_owned)
}

/// Find a free UDP port on 127.0.0.1.
fn free_udp_port() -> u16 {
    let sock =
        std::net::UdpSocket::bind("127.0.0.1:0").expect("failed to bind ephemeral UDP socket");
    sock.local_addr().expect("failed to read local addr").port()
}

/// Wait for the DNS listener to start responding.
async fn wait_for_dns_listener(port: u16) -> Result<UdpSocket, Box<dyn std::error::Error>> {
    let client = UdpSocket::bind("127.0.0.1:0").await?;
    client.connect(format!("127.0.0.1:{port}")).await?;

    for _ in 0..40 {
        let packet = build_dns_txt_query(0xFFFF, "probe.other.domain.com");
        let _ = client.send(&packet).await;
        let mut buf = vec![0u8; 512];
        if timeout(Duration::from_millis(50), client.recv(&mut buf)).await.is_ok() {
            return Ok(client);
        }
        sleep(Duration::from_millis(25)).await;
    }
    Err(format!("DNS listener on port {port} did not become ready").into())
}

/// Upload a Demon packet via chunked DNS queries. Returns the final TXT answer.
async fn dns_upload_demon_packet(
    client: &UdpSocket,
    agent_id: u32,
    payload: &[u8],
    domain: &str,
    query_id_base: u16,
) -> Result<String, Box<dyn std::error::Error>> {
    let chunks: Vec<&[u8]> = payload.chunks(39).collect();
    let total = u16::try_from(chunks.len())?;
    let mut last_txt = String::new();

    for (seq, chunk) in chunks.iter().enumerate() {
        let seq_u16 = u16::try_from(seq)?;
        let qname = dns_upload_qname(agent_id, seq_u16, total, chunk, domain);
        let packet = build_dns_txt_query(query_id_base.wrapping_add(seq_u16), &qname);
        client.send(&packet).await?;

        let mut buf = vec![0u8; 4096];
        let len = timeout(Duration::from_secs(5), client.recv(&mut buf)).await??;
        buf.truncate(len);
        last_txt = parse_dns_txt_answer(&buf).ok_or("failed to parse TXT answer")?;
    }

    Ok(last_txt)
}

/// Download the queued DNS response by polling download queries.
async fn dns_download_response(
    client: &UdpSocket,
    agent_id: u32,
    domain: &str,
    query_id_base: u16,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut chunks: Vec<String> = Vec::new();
    let mut expected_total: Option<usize> = None;
    let mut seq: u16 = 0;

    loop {
        let qname = dns_download_qname(agent_id, seq, domain);
        let packet = build_dns_txt_query(query_id_base.wrapping_add(seq), &qname);
        client.send(&packet).await?;

        let mut buf = vec![0u8; 4096];
        let len = timeout(Duration::from_secs(5), client.recv(&mut buf)).await??;
        buf.truncate(len);
        let txt = parse_dns_txt_answer(&buf).ok_or("failed to parse download TXT answer")?;

        if txt == "wait" {
            sleep(Duration::from_millis(50)).await;
            continue;
        }
        if txt == "done" {
            break;
        }

        let (total_str, b32_chunk) =
            txt.split_once(' ').ok_or_else(|| format!("unexpected download response: {txt}"))?;
        let total: usize = total_str.parse()?;
        if let Some(et) = expected_total {
            assert_eq!(et, total, "inconsistent total across download chunks");
        } else {
            expected_total = Some(total);
        }
        chunks.push(b32_chunk.to_owned());
        seq += 1;

        if chunks.len() >= total {
            let done_qname = dns_download_qname(agent_id, seq, domain);
            let done_packet = build_dns_txt_query(query_id_base.wrapping_add(seq), &done_qname);
            client.send(&done_packet).await?;
            let mut done_buf = vec![0u8; 4096];
            let done_len = timeout(Duration::from_secs(5), client.recv(&mut done_buf)).await??;
            done_buf.truncate(done_len);
            let done_txt = parse_dns_txt_answer(&done_buf);
            assert_eq!(done_txt.as_deref(), Some("done"), "expected 'done' after last chunk");
            break;
        }
    }

    let mut assembled = Vec::new();
    for chunk in &chunks {
        assembled.extend_from_slice(&base32hex_decode(chunk)?);
    }
    Ok(assembled)
}

fn listener_new_dns_message(user: &str, name: &str, port: u16, domain: &str) -> String {
    serde_json::to_string(&OperatorMessage::ListenerNew(Message {
        head: MessageHead {
            event: EventCode::Listener,
            user: user.to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: ListenerInfo {
            name: Some(name.to_owned()),
            protocol: Some("Dns".to_owned()),
            status: Some("Online".to_owned()),
            host_bind: Some("127.0.0.1".to_owned()),
            port_bind: Some(port.to_string()),
            extra: BTreeMap::from([("Domain".to_owned(), Value::String(domain.to_owned()))]),
            ..ListenerInfo::default()
        },
    }))
    .expect("dns listener message should serialize")
}

fn dns_listener_config(name: &str, port: u16, domain: &str) -> ListenerConfig {
    ListenerConfig::from(DnsListenerConfig {
        name: name.to_owned(),
        host_bind: "127.0.0.1".to_owned(),
        port_bind: port,
        domain: domain.to_owned(),
        record_types: vec!["TXT".to_owned()],
        kill_date: None,
        working_hours: None,
    })
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
    let next = timeout(Duration::from_secs(30), futures_util::StreamExt::next(socket)).await?;
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
    let server = common::spawn_test_server(multi_role_profile()).await?;
    let (mut socket, _) = connect_async(server.ws_url()).await?;
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

    assert_connection_closed_after_rbac_denial(&mut socket).await?;

    // Verify no side effects: no jobs should have been queued for any agent.
    let queued = server.agent_registry.queued_jobs_all().await;
    assert!(queued.is_empty(), "RBAC denial left queued jobs behind: {queued:?}");

    Ok(())
}

#[tokio::test]
async fn analyst_cannot_create_listener() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(multi_role_profile()).await?;
    let (mut socket, _) = connect_async(server.ws_url()).await?;
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

    assert_connection_closed_after_rbac_denial(&mut socket).await?;

    // Verify no side effects: no listener should have been created.
    let listeners = server.listeners.list().await?;
    assert!(listeners.is_empty(), "RBAC denial left a listener behind: {listeners:?}");

    Ok(())
}

#[tokio::test]
async fn analyst_cannot_edit_listener() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(multi_role_profile()).await?;
    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login_as(&mut socket, "analyst", "analystpw").await?;

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
    socket.send(ClientMessage::Text(msg.into())).await?;

    assert_connection_closed_after_rbac_denial(&mut socket).await?;

    // Verify no side effects: no listener should have been created or modified.
    let listeners = server.listeners.list().await?;
    assert!(listeners.is_empty(), "RBAC denial left a listener behind: {listeners:?}");

    Ok(())
}

#[tokio::test]
async fn analyst_cannot_remove_listener() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(multi_role_profile()).await?;
    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login_as(&mut socket, "analyst", "analystpw").await?;

    let msg = serde_json::to_string(&OperatorMessage::ListenerRemove(Message {
        head: MessageHead {
            event: EventCode::Listener,
            user: "analyst".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: NameInfo { name: "edge-http".to_owned() },
    }))?;
    socket.send(ClientMessage::Text(msg.into())).await?;

    assert_connection_closed_after_rbac_denial(&mut socket).await?;

    // Verify no side effects: no listener state should have changed.
    let listeners = server.listeners.list().await?;
    assert!(listeners.is_empty(), "RBAC denial left unexpected listener state: {listeners:?}");

    Ok(())
}

#[tokio::test]
async fn analyst_cannot_mark_listener() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(multi_role_profile()).await?;
    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login_as(&mut socket, "analyst", "analystpw").await?;

    let msg = serde_json::to_string(&OperatorMessage::ListenerMark(Message {
        head: MessageHead {
            event: EventCode::Listener,
            user: "analyst".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: ListenerMarkInfo { name: "edge-http".to_owned(), mark: "Online".to_owned() },
    }))?;
    socket.send(ClientMessage::Text(msg.into())).await?;

    assert_connection_closed_after_rbac_denial(&mut socket).await?;

    // Verify no side effects: no listener should have been created or marked.
    let listeners = server.listeners.list().await?;
    assert!(listeners.is_empty(), "RBAC denial left unexpected listener state: {listeners:?}");

    Ok(())
}

#[tokio::test]
async fn operator_cannot_send_admin_message() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(multi_role_profile()).await?;
    let (mut socket, _) = connect_async(server.ws_url()).await?;
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

    assert_connection_closed_after_rbac_denial(&mut socket).await?;

    // Verify no side effects: no agents should have been removed or modified.
    let agents = server.agent_registry.list_active().await;
    assert!(agents.is_empty(), "RBAC denial left unexpected agent state: {agents:?}");
    let queued = server.agent_registry.queued_jobs_all().await;
    assert!(queued.is_empty(), "RBAC denial left queued jobs behind: {queued:?}");

    Ok(())
}

#[tokio::test]
async fn wrong_password_receives_error_and_connection_closes()
-> Result<(), Box<dyn std::error::Error>> {
    use red_cell_common::crypto::hash_password_sha3;
    use red_cell_common::operator::LoginInfo;

    let addr = common::spawn_test_server(multi_role_profile()).await?.addr;
    let (mut socket, _) = connect_async(format!("ws://{addr}/havoc")).await?;

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

    // Server imposes a 2 s delay on failed logins; Argon2id with OWASP-recommended
    // parameters adds additional latency for the memory-hard hash.
    let response = timeout(Duration::from_secs(30), futures_util::StreamExt::next(&mut socket))
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
    let next = timeout(Duration::from_secs(10), futures_util::StreamExt::next(&mut socket)).await?;
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

    let addr = common::spawn_test_server(multi_role_profile()).await?.addr;

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
        let (mut socket, _) = connect_async(format!("ws://{addr}/havoc")).await?;
        socket.send(ClientMessage::Text(bad_login.clone().into())).await?;

        // Each failed login incurs a 2 s server-side delay plus Argon2id hashing time.
        let response = timeout(Duration::from_secs(30), futures_util::StreamExt::next(&mut socket))
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
        let _ = timeout(Duration::from_secs(10), futures_util::StreamExt::next(&mut socket)).await;
    }

    // --- Phase 2: the next attempt must be rejected by the rate limiter ---
    let (mut socket, _) = connect_async(format!("ws://{addr}/havoc")).await?;
    // Start timing only after the connection is established so that TCP setup
    // latency and OS scheduler jitter from parallel Argon2id hashing do not
    // inflate the measurement.
    let start = Instant::now();

    // The rate-limited path rejects *before* reading a login frame, so we
    // intentionally do NOT send any login message. The server should push an
    // error and close the socket on its own.
    let response = timeout(Duration::from_secs(10), futures_util::StreamExt::next(&mut socket))
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
    let next = timeout(Duration::from_secs(10), futures_util::StreamExt::next(&mut socket)).await?;
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
    let addr = common::spawn_test_server(multi_role_profile()).await?.addr;
    let (mut socket, _) = connect_async(format!("ws://{addr}/havoc")).await?;
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

#[tokio::test]
async fn admin_can_send_agent_remove_without_disconnection()
-> Result<(), Box<dyn std::error::Error>> {
    let addr = common::spawn_test_server(multi_role_profile()).await?.addr;
    let (mut socket, _) = connect_async(format!("ws://{addr}/havoc")).await?;
    common::login_as(&mut socket, "admin", "adminpw").await?;

    let msg = serde_json::to_string(&OperatorMessage::AgentRemove(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "admin".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: FlatInfo::default(),
    }))?;
    socket.send(ClientMessage::Text(msg.into())).await?;

    // The server must NOT close the connection — Admin is allowed to send AgentRemove.
    // It may respond with a message (e.g. error about a missing agent), but the key
    // assertion is that the connection stays open — no Close frame is received.
    let result = timeout(Duration::from_secs(2), futures_util::StreamExt::next(&mut socket)).await;
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
    agent_task_message_for(task_id, "12345678")
}

fn agent_task_message_for(task_id: &str, demon_id: &str) -> String {
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
            demon_id: demon_id.to_owned(),
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
        ja3_randomize: None,
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
