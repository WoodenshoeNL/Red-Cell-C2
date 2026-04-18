use std::time::Duration;

use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use red_cell_common::demon::{DemonCommand, DemonMessage};
use red_cell_common::operator::{EventCode, ListenerMarkInfo, OperatorMessage};
use tokio_tungstenite::connect_async;

use crate::helpers::{
    agent_task_message, assert_agent_output, dns_download_response, dns_listener_config,
    dns_upload_demon_packet, listener_new_dns_message, read_until_operator_message,
};

#[cfg(unix)]
use crate::helpers::{
    connect_smb, listener_new_smb_message, read_smb_frame, smb_listener_config, unique_pipe_name,
    wait_for_smb_listener, write_smb_frame,
};

#[cfg(unix)]
#[tokio::test]
async fn operator_session_smb_listener_and_mock_demon_round_trip()
-> Result<(), Box<dyn std::error::Error>> {
    use tokio::time::timeout;

    let server = crate::common::spawn_test_server(crate::common::legacy_ctr_test_profile()).await?;

    let pipe_name = unique_pipe_name("operator-round-trip");
    let listener_name = "edge-smb";
    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = crate::common::WsSession::new(raw_socket_);

    crate::common::login(&mut socket).await?;
    crate::common::assert_no_operator_message(&mut socket, Duration::from_millis(200)).await;

    socket.send_text(listener_new_smb_message("operator", listener_name, &pipe_name)).await?;

    let listener_created = crate::common::read_operator_message(&mut socket).await?;
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

    let listener_started = crate::common::read_operator_message(&mut socket).await?;
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
    write_smb_frame(
        &mut init_stream,
        agent_id,
        &crate::common::valid_demon_init_body(agent_id, key, iv),
    )
    .await?;

    let (ack_agent_id, ack_payload) =
        timeout(Duration::from_secs(5), read_smb_frame(&mut init_stream)).await??;
    assert_eq!(ack_agent_id, agent_id);
    let init_ack =
        red_cell_common::crypto::decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &ack_payload)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes());
    // Legacy CTR mode: offset stays at 0.
    drop(init_stream);

    let agent_new = crate::common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentNew(message) = agent_new else {
        panic!("expected agent session event");
    };
    assert_eq!(message.info.name_id, "12345678");
    assert_eq!(message.info.listener, listener_name);
    assert_eq!(message.info.hostname, "wkstn-01");

    let (raw_snapshot_socket_, _) = connect_async(server.ws_url()).await?;
    let mut snapshot_socket = crate::common::WsSession::new(raw_snapshot_socket_);
    crate::common::login(&mut snapshot_socket).await?;
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

    socket.send_text(agent_task_message("2A")).await?;

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
        &crate::common::valid_demon_callback_body(
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
        &crate::common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandOutput),
            0x2A,
            &crate::common::command_output_payload(output_text),
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
    let server = crate::common::spawn_test_server(crate::common::legacy_ctr_test_profile()).await?;

    let dns_port = crate::helpers::free_udp_port();
    let dns_domain = "c2.example.com";
    let listener_name = "edge-dns";
    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = crate::common::WsSession::new(raw_socket_);

    crate::common::login(&mut socket).await?;
    crate::common::assert_no_operator_message(&mut socket, Duration::from_millis(200)).await;

    // Create a DNS listener via WebSocket.
    socket
        .send_text(listener_new_dns_message("operator", listener_name, dns_port, dns_domain))
        .await?;

    let listener_created = crate::common::read_operator_message(&mut socket).await?;
    let OperatorMessage::ListenerNew(message) = listener_created else {
        panic!("expected listener create event");
    };
    assert_eq!(message.info.name.as_deref(), Some(listener_name));
    assert_eq!(message.info.protocol.as_deref(), Some("Dns"));
    assert_eq!(message.info.status.as_deref(), Some("Offline"));

    let listener_started = crate::common::read_operator_message(&mut socket).await?;
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
    let dns_client = crate::helpers::wait_for_dns_listener(dns_port).await?;

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
    let init_body = crate::common::valid_demon_init_body(agent_id, key, iv);
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
    let agent_new = crate::common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentNew(message) = agent_new else {
        panic!("expected agent session event");
    };
    assert_eq!(message.info.name_id, "12345678");
    assert_eq!(message.info.listener, listener_name);
    assert_eq!(message.info.hostname, "wkstn-01");

    // 4. Second operator connects and sees agent in snapshot.
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
    assert_eq!(snapshot_msg.info.listener, listener_name);
    assert_eq!(snapshot_msg.info.hostname, "wkstn-01");
    snapshot_socket.close(None).await?;

    // 5. Operator sends AgentTask.
    socket.send_text(agent_task_message("2A")).await?;

    let task_echo = crate::common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentTask(message) = task_echo else {
        panic!("expected agent task echo");
    };
    assert_eq!(message.info.demon_id, "12345678");
    assert_eq!(message.info.task_id, "2A");
    assert_eq!(message.info.command_line, "checkin");

    // 6. Agent polls for task via DNS: upload CommandGetJob, then download response.
    // Legacy Demon mode: every callback is encrypted at CTR offset 0.
    let get_job_body = crate::common::valid_demon_callback_body(
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
    let callback_body = crate::common::valid_demon_callback_body(
        agent_id,
        key,
        iv,
        0,
        u32::from(DemonCommand::CommandOutput),
        0x2A,
        &crate::common::command_output_payload(output_text),
    );
    let callback_result =
        dns_upload_demon_packet(&dns_client, agent_id, &callback_body, dns_domain, 0x5000).await?;
    assert_eq!(callback_result, "ack", "CommandOutput callback must be acknowledged");

    // 8. Operator receives AgentResponse broadcast.
    let output_event = crate::common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(message) = output_event else {
        panic!("expected agent response event");
    };
    assert_agent_output(&message.info, output_text);

    socket.close(None).await?;
    server.listeners.stop(listener_name).await?;
    Ok(())
}
