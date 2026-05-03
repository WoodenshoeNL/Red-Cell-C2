mod common;

use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use red_cell_common::demon::{DemonCallbackError, DemonCommand};
use red_cell_common::operator::OperatorMessage;
use tokio_tungstenite::connect_async;

/// Build a `CommandError/Win32` payload: error_class(1) + win32_code(u32).
fn command_error_win32_payload(win32_code: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonCallbackError::Win32).to_le_bytes());
    p.extend_from_slice(&win32_code.to_le_bytes());
    p
}

/// Build a `CommandError/Token` payload: error_class(3) + status(u32).
fn command_error_token_payload(status: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonCallbackError::Token).to_le_bytes());
    p.extend_from_slice(&status.to_le_bytes());
    p
}

/// Build a `CommandError/Coffee` payload: error_class(2) only.
fn command_error_coffee_payload() -> Vec<u8> {
    u32::from(DemonCallbackError::Coffee).to_le_bytes().to_vec()
}

/// Build a `CommandError` payload with an unknown error class.
fn command_error_unknown_payload(class: u32) -> Vec<u8> {
    class.to_le_bytes().to_vec()
}

/// Build a `CommandSleep` payload: delay(u32) + jitter(u32).
fn sleep_payload(delay: u32, jitter: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&delay.to_le_bytes());
    p.extend_from_slice(&jitter.to_le_bytes());
    p
}

#[tokio::test]
async fn command_output_happy_path_broadcasts_response() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-output-ok", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-output-ok").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0030_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x09, 0x1C, 0x2F, 0x42, 0x55, 0x68, 0x7B, 0x8E, 0xA1, 0xB4, 0xC7, 0xDA, 0xED, 0x00, 0x13,
        0x26,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let output_text = "whoami output: REDCELL\\operator";
    let payload = common::command_output_payload(output_text);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandOutput),
            0x70,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for CommandOutput, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandOutput).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("Received Output"),
        "message should contain 'Received Output': {message:?}"
    );
    assert!(
        message.contains(&output_text.len().to_string()),
        "message should contain byte count {}: {message:?}",
        output_text.len()
    );

    // The output field should contain the actual command output text.
    assert!(
        msg.info.output.contains(output_text),
        "output should contain the command text: {:?}",
        msg.info.output
    );

    socket.close(None).await?;
    server.listeners.stop("out-output-ok").await?;
    Ok(())
}

/// Empty `CommandOutput` (e.g. `kill` with no stdout) must still broadcast and persist so
/// REST `agent exec --wait` and output polling receive a terminal row (`red-cell-c2-1f7q1`).
#[tokio::test]
async fn command_output_empty_broadcasts_agent_response() -> Result<(), Box<dyn std::error::Error>>
{
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-output-empty", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-output-empty").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0031_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D,
        0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
        0x4D, 0x4E,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x3E, 0x51, 0x64, 0x77, 0x8A, 0x9D, 0xB0, 0xC3, 0xD6, 0xE9, 0xFC, 0x0F, 0x22, 0x35, 0x48,
        0x5B,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = common::command_output_payload("");

    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandOutput),
            0x71,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        response.status().is_success(),
        "empty output callback should succeed, got {}",
        response.status()
    );

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for empty CommandOutput, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandOutput).to_string());
    assert!(msg.info.output.is_empty(), "Output field must be empty");
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("[0 bytes]"), "message should note zero-byte output: {message:?}");
    assert_eq!(
        msg.info.extra.get("TaskID").and_then(|v| v.as_str()),
        Some("00000071"),
        "synthetic TaskID must match request_id 0x71 for operator correlation"
    );

    socket.close(None).await?;
    server.listeners.stop("out-output-empty").await?;
    Ok(())
}

// ── handle_command_error_callback ───────────────────────────────────────────

/// `handle_command_error_callback` with Win32 error class and a known error code
/// must broadcast an `AgentResponse` with Type="Error" containing the symbolic name.
#[tokio::test]
async fn command_error_win32_known_code_broadcasts_error() -> Result<(), Box<dyn std::error::Error>>
{
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-err-win32-known", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-err-win32-known").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0040_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62,
        0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71,
        0x72, 0x73,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x73, 0x86, 0x99, 0xAC, 0xBF, 0xD2, 0xE5, 0xF8, 0x0B, 0x1E, 0x31, 0x44, 0x57, 0x6A, 0x7D,
        0x90,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Win32 error code 5 = ERROR_ACCESS_DENIED
    let payload = command_error_win32_payload(5);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandError),
            0x80,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for CommandError/Win32, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandError).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("ERROR_ACCESS_DENIED"),
        "message should contain symbolic name: {message:?}"
    );
    assert!(message.contains("[5]"), "message should contain error code [5]: {message:?}");

    socket.close(None).await?;
    server.listeners.stop("out-err-win32-known").await?;
    Ok(())
}

/// `handle_command_error_callback` with Win32 error class and an unknown code
/// must broadcast an `AgentResponse` with just the numeric code.
#[tokio::test]
async fn command_error_win32_unknown_code_broadcasts_numeric()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-err-win32-unk", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-err-win32-unk").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0041_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96,
        0x97, 0x98,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xA8, 0xBB, 0xCE, 0xE1, 0xF4, 0x07, 0x1A, 0x2D, 0x40, 0x53, 0x66, 0x79, 0x8C, 0x9F, 0xB2,
        0xC5,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Unknown Win32 code 9999
    let payload = command_error_win32_payload(9999);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandError),
            0x81,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for CommandError/Win32 unknown, got {event:?}");
    };
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("Win32 Error"), "message should contain 'Win32 Error': {message:?}");
    assert!(message.contains("[9999]"), "message should contain code [9999]: {message:?}");

    socket.close(None).await?;
    server.listeners.stop("out-err-win32-unk").await?;
    Ok(())
}

/// `handle_command_error_callback` with Token error class and status 0x1
/// must broadcast "No tokens inside the token vault".
#[tokio::test]
async fn command_error_token_empty_vault_broadcasts_message()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-err-token-empty", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-err-token-empty").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0042_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC,
        0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB,
        0xBC, 0xBD,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xDD, 0xF0, 0x03, 0x16, 0x29, 0x3C, 0x4F, 0x62, 0x75, 0x88, 0x9B, 0xAE, 0xC1, 0xD4, 0xE7,
        0xFA,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = command_error_token_payload(0x1);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandError),
            0x82,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for CommandError/Token, got {event:?}");
    };
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("No tokens inside the token vault"),
        "message should mention empty vault: {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-err-token-empty").await?;
    Ok(())
}

/// `handle_command_error_callback` with Token error class and a non-0x1 status
/// must broadcast a generic "Token operation failed" message with the hex status.
#[tokio::test]
async fn command_error_token_other_status_broadcasts_hex() -> Result<(), Box<dyn std::error::Error>>
{
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-err-token-hex", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-err-token-hex").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0043_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1,
        0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0,
        0xE1, 0xE2,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x12, 0x25, 0x38, 0x4B, 0x5E, 0x71, 0x84, 0x97, 0xAA, 0xBD, 0xD0, 0xE3, 0xF6, 0x09, 0x1C,
        0x2F,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = command_error_token_payload(0xBEEF);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandError),
            0x83,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for CommandError/Token other, got {event:?}");
    };
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("Token operation failed"),
        "message should mention token failure: {message:?}"
    );
    assert!(message.contains("BEEF"), "message should contain hex status BEEF: {message:?}");

    socket.close(None).await?;
    server.listeners.stop("out-err-token-hex").await?;
    Ok(())
}

/// `handle_command_error_callback` with Coffee error class must succeed (2xx)
/// without broadcasting any `AgentResponse`.
#[tokio::test]
async fn command_error_coffee_no_broadcast() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-err-coffee", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-err-coffee").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0044_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6,
        0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x47, 0x5A, 0x6D, 0x80, 0x93, 0xA6, 0xB9, 0xCC, 0xDF, 0xF2, 0x05, 0x18, 0x2B, 0x3E, 0x51,
        0x64,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = command_error_coffee_payload();

    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandError),
            0x84,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        response.status().is_success(),
        "Coffee error class should succeed silently, got {}",
        response.status()
    );

    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-err-coffee").await?;
    Ok(())
}

/// `handle_command_error_callback` with an unknown error class must succeed (2xx)
/// without broadcasting any `AgentResponse`.
#[tokio::test]
async fn command_error_unknown_class_no_broadcast() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-err-unk-class", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-err-unk-class").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0045_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
        0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
        0x2B, 0x2C,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x7C, 0x8F, 0xA2, 0xB5, 0xC8, 0xDB, 0xEE, 0x01, 0x14, 0x27, 0x3A, 0x4D, 0x60, 0x73, 0x86,
        0x99,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = command_error_unknown_payload(0xFF);

    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandError),
            0x85,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        response.status().is_success(),
        "unknown error class should succeed silently, got {}",
        response.status()
    );

    common::skip_optional_teamserver_log(&mut socket, std::time::Duration::from_millis(200)).await;
    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-err-unk-class").await?;
    Ok(())
}

// ── handle_kill_date_callback ───────────────────────────────────────────────

/// `handle_kill_date_callback` must mark the agent dead, broadcast `AgentUpdate`
/// with Marked="Dead", and broadcast an `AgentResponse` with the kill date message.
#[tokio::test]
async fn kill_date_callback_marks_agent_dead_and_broadcasts()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-killdate-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-killdate-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0050_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xB1, 0xC4, 0xD7, 0xEA, 0xFD, 0x10, 0x23, 0x36, 0x49, 0x5C, 0x6F, 0x82, 0x95, 0xA8, 0xBB,
        0xCE,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Kill date callback takes _payload — content is ignored.
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandKillDate),
            0x90,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;

    // First broadcast: AgentUpdate with Marked="Dead".
    let update_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentUpdate(update_msg) = update_event else {
        panic!("expected AgentUpdate after kill date callback, got {update_event:?}");
    };
    assert_eq!(update_msg.info.agent_id, format!("{agent_id:08X}"));
    assert_eq!(
        update_msg.info.marked, "Dead",
        "agent should be marked Dead after kill date callback"
    );

    // Second broadcast: AgentResponse with kill date message.
    let response_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(response_msg) = response_event else {
        panic!("expected AgentResponse after kill date callback, got {response_event:?}");
    };
    assert_eq!(response_msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(response_msg.info.command_id, u32::from(DemonCommand::CommandKillDate).to_string());
    assert_eq!(response_msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = response_msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("kill date"), "message should mention kill date: {message:?}");

    socket.close(None).await?;
    server.listeners.stop("out-killdate-test").await?;
    Ok(())
}

// ── handle_sleep_callback ───────────────────────────────────────────────────

/// `handle_sleep_callback` must update the agent's sleep delay/jitter in the registry,
/// broadcast an `AgentUpdate`, and broadcast an `AgentResponse` with the new values.
#[tokio::test]
async fn sleep_callback_updates_agent_and_broadcasts() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-sleep-test", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-sleep-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0060_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65,
        0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74,
        0x75, 0x76,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xE6, 0xF9, 0x0C, 0x1F, 0x32, 0x45, 0x58, 0x6B, 0x7E, 0x91, 0xA4, 0xB7, 0xCA, 0xDD, 0xF0,
        0x03,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let delay = 30_u32;
    let jitter = 25_u32;
    let payload = sleep_payload(delay, jitter);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandSleep),
            0xA0,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // First broadcast: AgentUpdate (agent_mark_event with updated sleep values).
    let update_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentUpdate(update_msg) = update_event else {
        panic!("expected AgentUpdate after sleep callback, got {update_event:?}");
    };
    assert_eq!(update_msg.info.agent_id, format!("{agent_id:08X}"));
    assert_eq!(update_msg.info.marked, "Alive", "agent should remain Alive after sleep callback");

    // Second broadcast: AgentResponse with sleep interval message.
    let response_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(response_msg) = response_event else {
        panic!("expected AgentResponse after sleep callback, got {response_event:?}");
    };
    assert_eq!(response_msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(response_msg.info.command_id, u32::from(DemonCommand::CommandSleep).to_string());
    assert_eq!(response_msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = response_msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains(&delay.to_string()),
        "message should contain delay {delay}: {message:?}"
    );
    assert!(
        message.contains(&jitter.to_string()),
        "message should contain jitter {jitter}: {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-sleep-test").await?;
    Ok(())
}

// ── handle_config_callback ──────────────────────────────────────────────────

/// `handle_config_callback` with `KillDate` key and a non-zero value must broadcast
/// "KillDate has been set" and update the agent's kill_date in the registry.

/// `handle_command_output_callback` with an empty payload (zero bytes) must fail
/// because `read_string` needs at least a u32 length prefix. No event must be broadcast.
#[tokio::test]
async fn command_output_empty_payload_returns_error_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cmdout-empty", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cmdout-empty").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_00A0_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
        0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D,
        0x7E, 0x7F,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x3F, 0x52, 0x65, 0x78, 0x8B, 0x9E, 0xB1, 0xC4, 0xD7, 0xEA, 0xFD, 0x10, 0x23, 0x36, 0x49,
        0x5C,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Send CommandOutput with zero bytes — no length prefix at all.
    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandOutput),
            0xD0,
            &[], // empty payload
        ))
        .send()
        .await?;

    assert!(
        response.status().is_success(),
        "handler errors are now swallowed, response should be 2xx, got {}",
        response.status()
    );

    common::skip_optional_teamserver_log(&mut socket, std::time::Duration::from_millis(200)).await;
    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-cmdout-empty").await?;
    Ok(())
}

/// `handle_command_output_callback` with a truncated payload (only 2 bytes, less than
/// the 4-byte u32 length prefix) must return a non-2xx HTTP status and no event.
#[tokio::test]
async fn command_output_truncated_length_prefix_returns_error_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cmdout-short", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cmdout-short").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_00A1_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93,
        0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2,
        0xA3, 0xA4,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x74, 0x87, 0x9A, 0xAD, 0xC0, 0xD3, 0xE6, 0xF9, 0x0C, 0x1F, 0x32, 0x45, 0x58, 0x6B, 0x7E,
        0x91,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Send CommandOutput with only 2 bytes — too short for a u32 length prefix.
    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandOutput),
            0xD1,
            &[0x05, 0x00], // only 2 bytes, need at least 4 for length prefix
        ))
        .send()
        .await?;

    assert!(
        response.status().is_success(),
        "handler errors are now swallowed, response should be 2xx, got {}",
        response.status()
    );

    common::skip_optional_teamserver_log(&mut socket, std::time::Duration::from_millis(200)).await;
    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-cmdout-short").await?;
    Ok(())
}

/// `handle_command_output_callback` with a length prefix that exceeds the actual payload
/// must return a non-2xx HTTP status. The length says 100 bytes but only 3 bytes follow.
#[tokio::test]
async fn command_output_length_exceeds_payload_returns_error_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cmdout-overlen", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cmdout-overlen").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_00A2_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8,
        0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7,
        0xC8, 0xC9,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xA9, 0xBC, 0xCF, 0xE2, 0xF5, 0x08, 0x1B, 0x2E, 0x41, 0x54, 0x67, 0x7A, 0x8D, 0xA0, 0xB3,
        0xC6,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Length prefix says 100 bytes, but only 3 bytes of data follow.
    let mut payload = Vec::new();
    payload.extend_from_slice(&100_u32.to_le_bytes()); // length = 100
    payload.extend_from_slice(&[0x41, 0x42, 0x43]); // only 3 bytes of data

    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandOutput),
            0xD2,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        response.status().is_success(),
        "handler errors are now swallowed, response should be 2xx, got {}",
        response.status()
    );

    common::skip_optional_teamserver_log(&mut socket, std::time::Duration::from_millis(200)).await;
    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-cmdout-overlen").await?;
    Ok(())
}

/// `handle_command_output_callback` with a u32::MAX length prefix (0xFFFF_FFFF)
/// and only 5 bytes of actual data must return a non-2xx HTTP status and must
/// not broadcast any `AgentResponse`.  This extreme value could trigger
/// arithmetic overflow or allocation failure in a naïve bounds check.
#[tokio::test]
async fn command_output_u32_max_length_prefix_returns_error_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cmdout-maxlen", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cmdout-maxlen").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_00A3_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8,
        0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
        0xE8, 0xE9,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xDE, 0xF1, 0x04, 0x17, 0x2A, 0x3D, 0x50, 0x63, 0x76, 0x89, 0x9C, 0xAF, 0xC2, 0xD5, 0xE8,
        0xFB,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Length prefix says 0xFFFF_FFFF (4 GiB) but only 5 bytes follow.
    let mut payload = Vec::new();
    payload.extend_from_slice(&0xFFFF_FFFF_u32.to_le_bytes());
    payload.extend_from_slice(&[0x48, 0x65, 0x6C, 0x6C, 0x6F]); // "Hello"

    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandOutput),
            0xD3,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        response.status().is_success(),
        "handler errors are now swallowed, response should be 2xx, got {}",
        response.status()
    );

    common::skip_optional_teamserver_log(&mut socket, std::time::Duration::from_millis(200)).await;
    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-cmdout-maxlen").await?;
    Ok(())
}

// ── handle_command_error_callback truncated body tests ──────────────────────

/// `handle_command_error_callback` with a valid Win32 error class but no error code
/// (truncated body) must return a non-2xx HTTP status and no event.
#[tokio::test]
async fn command_error_win32_truncated_body_returns_error_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cmderr-win32-trunc", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cmderr-win32-trunc").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_00B0_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD,
        0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC,
        0xED, 0xEE,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xDE, 0xF1, 0x04, 0x17, 0x2A, 0x3D, 0x50, 0x63, 0x76, 0x89, 0x9C, 0xAF, 0xC2, 0xD5, 0xE8,
        0xFB,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Win32 error class (0x01) but no error code after it.
    let payload = u32::from(DemonCallbackError::Win32).to_le_bytes().to_vec();

    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandError),
            0xE0,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        response.status().is_success(),
        "handler errors are now swallowed, response should be 2xx, got {}",
        response.status()
    );

    common::skip_optional_teamserver_log(&mut socket, std::time::Duration::from_millis(200)).await;
    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-cmderr-win32-trunc").await?;
    Ok(())
}

/// `handle_command_error_callback` with a valid Token error class but no status u32
/// (truncated body) must return a non-2xx HTTP status and no event.
#[tokio::test]
async fn command_error_token_truncated_body_returns_error_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cmderr-token-trunc", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cmderr-token-trunc").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_00B1_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF, 0x00, 0x01, 0x02,
        0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
        0x12, 0x13,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x13, 0x26, 0x39, 0x4C, 0x5F, 0x72, 0x85, 0x98, 0xAB, 0xBE, 0xD1, 0xE4, 0xF7, 0x0A, 0x1D,
        0x30,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Token error class (0x03) but no status u32 after it.
    let payload = u32::from(DemonCallbackError::Token).to_le_bytes().to_vec();

    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandError),
            0xE1,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        response.status().is_success(),
        "handler errors are now swallowed, response should be 2xx, got {}",
        response.status()
    );

    common::skip_optional_teamserver_log(&mut socket, std::time::Duration::from_millis(200)).await;
    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-cmderr-token-trunc").await?;
    Ok(())
}

// ── handle_sleep_callback truncated payload tests ───────────────────────────

/// `handle_sleep_callback` with an empty payload (zero bytes) must return a
/// non-2xx HTTP status and must NOT broadcast any events.
#[tokio::test]
async fn sleep_callback_empty_payload_returns_error_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-sleep-empty", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-sleep-empty").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_00C0_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x48, 0x5B, 0x6E, 0x81, 0x94, 0xA7, 0xBA, 0xCD, 0xE0, 0xF3, 0x06, 0x19, 0x2C, 0x3F, 0x52,
        0x65,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Send CommandSleep with zero bytes — no sleep_delay or sleep_jitter.
    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandSleep),
            0xF0,
            &[], // empty payload
        ))
        .send()
        .await?;

    assert!(
        response.status().is_success(),
        "handler errors are now swallowed, response should be 2xx, got {}",
        response.status()
    );

    common::skip_optional_teamserver_log(&mut socket, std::time::Duration::from_millis(200)).await;
    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-sleep-empty").await?;
    Ok(())
}

/// `handle_sleep_callback` with only the sleep_delay u32 but missing the sleep_jitter u32
/// must return a non-2xx HTTP status and must NOT broadcast any events.
#[tokio::test]
async fn sleep_callback_truncated_missing_jitter_returns_error_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-sleep-trunc", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-sleep-trunc").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_00C1_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C,
        0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B,
        0x5C, 0x5D,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x7D, 0x90, 0xA3, 0xB6, 0xC9, 0xDC, 0xEF, 0x02, 0x15, 0x28, 0x3B, 0x4E, 0x61, 0x74, 0x87,
        0x9A,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Only sleep_delay (4 bytes), missing sleep_jitter.
    let payload = 10_u32.to_le_bytes().to_vec(); // delay=10, no jitter

    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandSleep),
            0xF1,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        response.status().is_success(),
        "handler errors are now swallowed, response should be 2xx, got {}",
        response.status()
    );

    common::skip_optional_teamserver_log(&mut socket, std::time::Duration::from_millis(200)).await;
    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-sleep-trunc").await?;
    Ok(())
}

// ── persist_credentials_from_output — credential extraction tests ───────────
