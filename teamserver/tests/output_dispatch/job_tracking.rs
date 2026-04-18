//! Job state and lifecycle callback tests.
use super::*;
use crate::common;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::OperatorMessage;
use tokio_tungstenite::connect_async;

// ── tests ────────────────────────────────────────────────────────────────────

/// `handle_job_callback` with `Suspend` subcommand and `success=true` must broadcast
/// an `AgentResponse` with Type="Good" and a message mentioning "suspended".
#[tokio::test]
async fn job_suspend_success_broadcasts_good_response() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-job-susp-ok", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-job-susp-ok").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0020_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
        0x25, 0x26,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x96, 0xA9, 0xBC, 0xCF, 0xE2, 0xF5, 0x08, 0x1B, 0x2E, 0x41, 0x54, 0x67, 0x7A, 0x8D, 0xA0,
        0xB3,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = job_action_payload(2, 77, true); // Suspend=2, job_id=77, success

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandJob),
            0x60,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for job Suspend success, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandJob).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("suspended") || message.contains("Suspended"),
        "message should mention suspended: {message:?}"
    );
    assert!(message.contains("77"), "message should contain job id 77: {message:?}");

    socket.close(None).await?;
    server.listeners.stop("out-job-susp-ok").await?;
    Ok(())
}

/// `handle_job_callback` with `Suspend` subcommand and `success=false` must broadcast
/// an `AgentResponse` with Type="Error".
#[tokio::test]
async fn job_suspend_failure_broadcasts_error_response() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-job-susp-fail", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-job-susp-fail").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0021_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A,
        0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
        0x4A, 0x4B,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xCB, 0xDE, 0xF1, 0x04, 0x17, 0x2A, 0x3D, 0x50, 0x63, 0x76, 0x89, 0x9C, 0xAF, 0xC2, 0xD5,
        0xE8,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = job_action_payload(2, 88, false); // Suspend=2, job_id=88, failure

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandJob),
            0x61,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for job Suspend failure, got {event:?}");
    };
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.to_lowercase().contains("suspend"),
        "message should mention suspend: {message:?}"
    );
    assert!(message.contains("88"), "message should contain job id 88: {message:?}");

    socket.close(None).await?;
    server.listeners.stop("out-job-susp-fail").await?;
    Ok(())
}

/// `handle_job_callback` with `Resume` subcommand and `success=true` must broadcast
/// an `AgentResponse` with Type="Good" and a message mentioning "resumed".
#[tokio::test]
async fn job_resume_success_broadcasts_good_response() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-job-res-ok", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-job-res-ok").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0022_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
        0x6F, 0x70,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x00, 0x13, 0x26, 0x39, 0x4C, 0x5F, 0x72, 0x85, 0x98, 0xAB, 0xBE, 0xD1, 0xE4, 0xF7, 0x0A,
        0x1D,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = job_action_payload(3, 55, true); // Resume=3, job_id=55, success

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandJob),
            0x62,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for job Resume success, got {event:?}");
    };
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.to_lowercase().contains("resum"),
        "message should mention resumed: {message:?}"
    );
    assert!(message.contains("55"), "message should contain job id 55: {message:?}");

    socket.close(None).await?;
    server.listeners.stop("out-job-res-ok").await?;
    Ok(())
}

/// `handle_job_callback` with `Resume` subcommand and `success=false` must broadcast
/// an `AgentResponse` with Type="Error".
#[tokio::test]
async fn job_resume_failure_broadcasts_error_response() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-job-res-fail", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-job-res-fail").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0023_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84,
        0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93,
        0x94, 0x95,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x35, 0x48, 0x5B, 0x6E, 0x81, 0x94, 0xA7, 0xBA, 0xCD, 0xE0, 0xF3, 0x06, 0x19, 0x2C, 0x3F,
        0x52,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = job_action_payload(3, 66, false); // Resume=3, job_id=66, failure

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandJob),
            0x63,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for job Resume failure, got {event:?}");
    };
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.to_lowercase().contains("resum"), "message should mention resume: {message:?}");
    assert!(message.contains("66"), "message should contain job id 66: {message:?}");

    socket.close(None).await?;
    server.listeners.stop("out-job-res-fail").await?;
    Ok(())
}

/// `handle_job_callback` with `KillRemove` subcommand and `success=true` must broadcast
/// an `AgentResponse` with Type="Good" and a message mentioning "killed".
#[tokio::test]
async fn job_kill_remove_success_broadcasts_good_response() -> Result<(), Box<dyn std::error::Error>>
{
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-job-kill-ok", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-job-kill-ok").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0024_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9,
        0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8,
        0xB9, 0xBA,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x6A, 0x7D, 0x90, 0xA3, 0xB6, 0xC9, 0xDC, 0xEF, 0x02, 0x15, 0x28, 0x3B, 0x4E, 0x61, 0x74,
        0x87,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = job_action_payload(4, 99, true); // KillRemove=4, job_id=99, success

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandJob),
            0x64,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for job KillRemove success, got {event:?}");
    };
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.to_lowercase().contains("kill"), "message should mention killed: {message:?}");
    assert!(message.contains("99"), "message should contain job id 99: {message:?}");

    socket.close(None).await?;
    server.listeners.stop("out-job-kill-ok").await?;
    Ok(())
}

/// `handle_job_callback` with `KillRemove` subcommand and `success=false` must broadcast
/// an `AgentResponse` with Type="Error".
#[tokio::test]
async fn job_kill_remove_failure_broadcasts_error_response()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-job-kill-fail", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-job-kill-fail").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0025_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE,
        0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD,
        0xDE, 0xDF,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x9F, 0xB2, 0xC5, 0xD8, 0xEB, 0xFE, 0x11, 0x24, 0x37, 0x4A, 0x5D, 0x70, 0x83, 0x96, 0xA9,
        0xBC,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = job_action_payload(4, 100, false); // KillRemove=4, job_id=100, failure

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandJob),
            0x65,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for job KillRemove failure, got {event:?}");
    };
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.to_lowercase().contains("kill"), "message should mention kill: {message:?}");
    assert!(message.contains("100"), "message should contain job id 100: {message:?}");

    socket.close(None).await?;
    server.listeners.stop("out-job-kill-fail").await?;
    Ok(())
}

/// `handle_job_callback` with `Died` subcommand must succeed (2xx) but must NOT
/// broadcast any `AgentResponse` to operators.
#[tokio::test]
async fn job_died_no_broadcast() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-job-died", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-job-died").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0026_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3,
        0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF, 0x00, 0x01, 0x02,
        0x03, 0x04,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xD4, 0xE7, 0xFA, 0x0D, 0x20, 0x33, 0x46, 0x59, 0x6C, 0x7F, 0x92, 0xA5, 0xB8, 0xCB, 0xDE,
        0xF1,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = job_died_payload();

    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandJob),
            0x66,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        response.status().is_success(),
        "Died subcommand should succeed, got {}",
        response.status()
    );

    // Died intentionally emits nothing — verify no broadcast.
    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-job-died").await?;
    Ok(())
}
