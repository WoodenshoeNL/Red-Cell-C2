//! Error-path output dispatch tests.
use super::*;
use crate::common;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::OperatorMessage;
use tokio_tungstenite::connect_async;

// ── tests ────────────────────────────────────────────────────────────────────

/// `handle_demon_info_callback` with a truncated payload (info_class only, no class data)
/// must return an error to the HTTP caller and must NOT broadcast any `AgentResponse`.
#[tokio::test]
async fn demon_info_truncated_payload_returns_error_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-trunc-test", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-trunc-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0004_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3,
        0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2,
        0xB3, 0xB4,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x84, 0x97, 0xAA, 0xBD, 0xD0, 0xE3, 0xF6, 0x09, 0x1C, 0x2F, 0x42, 0x55, 0x68, 0x7B, 0x8E,
        0xA1,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Send a truncated DemonInfo payload (info_class only, no class-specific data).
    let payload = demon_info_truncated_payload();
    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::DemonInfo),
            0x20,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        !response.status().is_success(),
        "truncated DemonInfo payload must not return 2xx, got {}",
        response.status()
    );

    // No broadcast should be emitted on error.
    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-trunc-test").await?;
    Ok(())
}

/// A `CommandExit` callback with an empty payload must return a
/// non-2xx HTTP status and must NOT broadcast `AgentUpdate` or `AgentResponse`.
#[tokio::test]
async fn exit_callback_empty_payload_returns_error_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-exit-empty-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-exit-empty-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0005_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8,
        0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
        0xD8, 0xD9,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xB9, 0xCC, 0xDF, 0xF2, 0x05, 0x18, 0x2B, 0x3E, 0x51, 0x64, 0x77, 0x8A, 0x9D, 0xB0, 0xC3,
        0xD6,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Send a CommandExit callback with zero bytes — no exit_method u32 at all.
    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandExit),
            0x40,
            &[], // empty payload
        ))
        .send()
        .await?;

    assert!(
        !response.status().is_success(),
        "empty CommandExit payload must not return 2xx, got {}",
        response.status()
    );

    // Neither AgentUpdate nor AgentResponse should be broadcast.
    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-exit-empty-test").await?;
    Ok(())
}

/// A `CommandExit` callback with fewer than four bytes (truncated exit_method)
/// must return a non-2xx HTTP status and must NOT broadcast any events.
#[tokio::test]
async fn exit_callback_truncated_exit_method_returns_error_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-exit-short-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-exit-short-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0006_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED,
        0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC,
        0xFD, 0xFE,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xEE, 0x01, 0x14, 0x27, 0x3A, 0x4D, 0x60, 0x73, 0x86, 0x99, 0xAC, 0xBF, 0xD2, 0xE5, 0xF8,
        0x0B,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Send a CommandExit callback with only 2 bytes — too short for a u32 exit_method.
    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandExit),
            0x41,
            &[0x01, 0x00], // only 2 bytes, need 4
        ))
        .send()
        .await?;

    assert!(
        !response.status().is_success(),
        "truncated CommandExit payload must not return 2xx, got {}",
        response.status()
    );

    // No events should be broadcast on parse error.
    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-exit-short-test").await?;
    Ok(())
}

/// A `CommandJob/List` callback with an incomplete trailing row (only job_id, missing
/// type and state) must return a non-2xx HTTP status and must NOT broadcast any
/// `AgentResponse` to the operator socket.
#[tokio::test]
async fn job_list_malformed_incomplete_row_returns_error_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-job-malformed", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-job-malformed").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0076_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x59, 0x6C, 0x7F, 0x92, 0xA5, 0xB8, 0xCB, 0xDE, 0xF1, 0x04, 0x17, 0x2A, 0x3D, 0x50, 0x63,
        0x76,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Build a malformed CommandJob/List payload: one complete row followed by a
    // truncated row that only contains job_id (missing job_type and state).
    let mut malformed = Vec::new();
    malformed.extend_from_slice(&1u32.to_le_bytes()); // DemonJobCommand::List = 1
    // Complete row: id=10, type=2, state=1
    malformed.extend_from_slice(&10u32.to_le_bytes());
    malformed.extend_from_slice(&2u32.to_le_bytes());
    malformed.extend_from_slice(&1u32.to_le_bytes());
    // Incomplete trailing row: only job_id, no type or state
    malformed.extend_from_slice(&99u32.to_le_bytes());

    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandJob),
            0x20,
            &malformed,
        ))
        .send()
        .await?;

    assert!(
        !response.status().is_success(),
        "expected error HTTP status for malformed job list payload, got {}",
        response.status()
    );

    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-job-malformed").await?;
    Ok(())
}

/// `handle_job_callback` with an unknown subcommand value (not 1–5) must return a
/// non-2xx HTTP status and must NOT broadcast any `AgentResponse`.
#[tokio::test]
async fn job_unknown_subcommand_returns_error() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-job-unknown", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-job-unknown").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0079_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
        0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6,
        0xE7, 0xE8,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xF8, 0x0B, 0x1E, 0x31, 0x44, 0x57, 0x6A, 0x7D, 0x90, 0xA3, 0xB6, 0xC9, 0xDC, 0xEF, 0x02,
        0x15,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Build a payload with subcommand value 99 — not a valid DemonJobCommand.
    let payload = 99u32.to_le_bytes().to_vec();

    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandJob),
            0x20,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        !response.status().is_success(),
        "expected error HTTP status for unknown job subcommand, got {}",
        response.status()
    );

    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-job-unknown").await?;
    Ok(())
}
