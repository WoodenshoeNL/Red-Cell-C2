//! `CommandPsImport` callback dispatch tests.

use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::OperatorMessage;
use tokio_tungstenite::connect_async;

use super::common;
use super::helpers::{
    ps_import_empty_output_payload, ps_import_output_payload, register_agent, start_server,
};

/// A `CommandPsImport` callback with an empty output string must broadcast the
/// default "PowerShell script imported successfully" message to the operator.
#[tokio::test]
async fn ps_import_callback_empty_output_broadcasts_success_message()
-> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(format!("ws://{server_addr}/havoc")).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("asm-psimp-empty", listener_port)).await?;
    drop(listener_guard);
    listeners.start("asm-psimp-empty").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xC501_0001_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
        0x6F, 0x70,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        0xD0,
    ];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    // Consume the AgentNew broadcast.
    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(
        matches!(agent_new, OperatorMessage::AgentNew(_)),
        "expected AgentNew, got {agent_new:?}"
    );

    let payload = ps_import_empty_output_payload();
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandPsImport),
            0x10,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandPsImport).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("PowerShell") && message.contains("imported successfully"),
        "expected default success message, got {message:?}"
    );

    socket.close(None).await?;
    listeners.stop("asm-psimp-empty").await?;
    Ok(())
}

/// A `CommandPsImport` callback with non-empty UTF-8 output must broadcast that
/// output string verbatim to the operator.
#[tokio::test]
async fn ps_import_callback_with_output_broadcasts_the_output()
-> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(format!("ws://{server_addr}/havoc")).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("asm-psimp-out", listener_port)).await?;
    drop(listener_guard);
    listeners.start("asm-psimp-out").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xC501_0002_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E,
        0x8F, 0x90,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
        0xE0,
    ];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    // Consume the AgentNew broadcast.
    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(
        matches!(agent_new, OperatorMessage::AgentNew(_)),
        "expected AgentNew, got {agent_new:?}"
    );

    let output_text = "Script loaded: Invoke-Mimikatz.ps1";
    let payload = ps_import_output_payload(output_text);
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandPsImport),
            0x10,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandPsImport).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    assert_eq!(msg.info.extra.get("Message").and_then(|v| v.as_str()), Some(output_text));

    socket.close(None).await?;
    listeners.stop("asm-psimp-out").await?;
    Ok(())
}

/// A `CommandPsImport` callback with a truncated payload (too short for the
/// length-prefixed string read) must not crash the teamserver.  The HTTP layer
/// should still return a success status (the dispatch error is handled internally).
#[tokio::test]
async fn ps_import_callback_truncated_payload_does_not_crash()
-> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(format!("ws://{server_addr}/havoc")).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("asm-psimp-trunc", listener_port)).await?;
    drop(listener_guard);
    listeners.start("asm-psimp-trunc").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xC501_0003_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE,
        0xAF, 0xB0,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
        0xF0,
    ];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    // Consume the AgentNew broadcast.
    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(
        matches!(agent_new, OperatorMessage::AgentNew(_)),
        "expected AgentNew, got {agent_new:?}"
    );

    // Truncated payload: empty bytes — no length prefix for `read_string` to parse.
    let payload: Vec<u8> = Vec::new();
    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandPsImport),
            0x10,
            &payload,
        ))
        .send()
        .await?;
    // Handler errors are swallowed — response is 200, the server must not crash.
    assert_eq!(
        response.status().as_u16(),
        200,
        "handler errors are now swallowed, response should be 200"
    );

    // The dispatch error is handled internally — no AgentResponse; optional TeamserverLog diag.
    common::skip_optional_teamserver_log(&mut socket, std::time::Duration::from_millis(250)).await;

    socket.close(None).await?;
    listeners.stop("asm-psimp-trunc").await?;
    Ok(())
}
