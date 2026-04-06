//! Integration tests for `dispatch/token.rs` — `handle_token_callback`.
//!
//! All tests go through the full HTTP → listener → dispatch pipeline so that
//! the event-bus broadcast paths are exercised end-to-end.  Each test:
//!   1. Spawns a test teamserver and HTTP listener.
//!   2. Registers a Demon agent via `DEMON_INIT`.
//!   3. Sends a `CommandToken` callback with a specific subcommand payload.
//!   4. Reads the operator WebSocket broadcast and asserts on its contents.

mod common;

use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::OperatorMessage;
use tokio_tungstenite::connect_async;

// ---------------------------------------------------------------------------
// Payload helpers (little-endian, matching CallbackParser expectations)
// ---------------------------------------------------------------------------

fn push_u32(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_le_bytes());
}

fn push_utf16(buf: &mut Vec<u8>, s: &str) {
    let words: Vec<u16> = s.encode_utf16().collect();
    let byte_len = (words.len() * 2) as u32;
    push_u32(buf, byte_len);
    for w in &words {
        buf.extend_from_slice(&w.to_le_bytes());
    }
}

fn push_string(buf: &mut Vec<u8>, s: &str) {
    push_u32(buf, s.len() as u32);
    buf.extend_from_slice(s.as_bytes());
}

// ---------------------------------------------------------------------------
// Token subcommand IDs (must match DemonTokenCommand enum values)
// ---------------------------------------------------------------------------

const TOKEN_IMPERSONATE: u32 = 1;
const TOKEN_STEAL: u32 = 2;
const TOKEN_LIST: u32 = 3;
const TOKEN_PRIVS_GET_OR_LIST: u32 = 4;
const TOKEN_MAKE: u32 = 5;
const TOKEN_GETUID: u32 = 6;
const TOKEN_REVERT: u32 = 7;
const TOKEN_REMOVE: u32 = 8;
const TOKEN_CLEAR: u32 = 9;
const TOKEN_FIND_TOKENS: u32 = 10;

/// Build a CommandToken callback payload with the given subcommand and body.
fn token_callback_payload(subcommand: u32, body: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    push_u32(&mut p, subcommand);
    p.extend_from_slice(body);
    p
}

// ---------------------------------------------------------------------------
// Helper to assert AgentResponse fields
// ---------------------------------------------------------------------------

fn assert_agent_response(
    event: &OperatorMessage,
    agent_id: u32,
    expected_type: &str,
    expected_message: &str,
) -> String {
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandToken).to_string(),);
    assert_eq!(
        msg.info.extra.get("Type").and_then(|v| v.as_str()),
        Some(expected_type),
        "expected Type={expected_type}, got extra={:?}",
        msg.info.extra,
    );
    assert_eq!(
        msg.info.extra.get("Message").and_then(|v| v.as_str()),
        Some(expected_message),
        "expected Message={expected_message}, got extra={:?}",
        msg.info.extra,
    );
    msg.info.output.clone()
}

// ---------------------------------------------------------------------------
// Macro to reduce test boilerplate — sets up server, listener, agent, ws
// ---------------------------------------------------------------------------

macro_rules! setup_test {
    ($name:expr, $agent_id:expr, $key:expr, $iv:expr) => {{
        let server = common::spawn_test_server(common::default_test_profile()).await?;
        let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
        let client = reqwest::Client::new();

        let (raw_socket_, _) = connect_async(server.ws_url()).await?;
        let mut socket = common::WsSession::new(raw_socket_);
        common::login(&mut socket).await?;

        server.listeners.create(common::http_listener_config($name, listener_port)).await?;
        drop(listener_guard);
        server.listeners.start($name).await?;
        common::wait_for_listener(listener_port).await?;

        let ctr_offset =
            common::register_agent(&client, listener_port, $agent_id, $key, $iv).await?;

        let agent_new = common::read_operator_message(&mut socket).await?;
        assert!(
            matches!(agent_new, OperatorMessage::AgentNew(_)),
            "expected AgentNew, got {agent_new:?}"
        );

        (server, client, socket, listener_port, ctr_offset)
    }};
}

// ---------------------------------------------------------------------------
// Impersonate
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_impersonate_success_broadcasts_good() -> Result<(), Box<dyn std::error::Error>> {
    let agent_id = 0xFC01_0001_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE,
        0xBF, 0xC0,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0,
        0x01,
    ];

    let (server, client, mut socket, listener_port, ctr_offset) =
        setup_test!("tok-imp-ok", agent_id, key, iv);

    let mut body = Vec::new();
    push_u32(&mut body, 1); // success
    push_string(&mut body, "CORP\\admin");
    let payload = token_callback_payload(TOKEN_IMPERSONATE, &body);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandToken),
            0x01,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    assert_agent_response(&event, agent_id, "Good", "Successfully impersonated CORP\\admin");

    socket.close(None).await?;
    server.listeners.stop("tok-imp-ok").await?;
    Ok(())
}

#[tokio::test]
async fn token_impersonate_failure_broadcasts_error() -> Result<(), Box<dyn std::error::Error>> {
    let agent_id = 0xFC01_0002_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE,
        0xDF, 0xE0,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x11, 0x21, 0x31, 0x41, 0x51, 0x61, 0x71, 0x81, 0x91, 0xA1, 0xB1, 0xC1, 0xD1, 0xE1, 0xF1,
        0x02,
    ];

    let (server, client, mut socket, listener_port, ctr_offset) =
        setup_test!("tok-imp-err", agent_id, key, iv);

    let mut body = Vec::new();
    push_u32(&mut body, 0); // failure
    push_string(&mut body, "CORP\\user");
    let payload = token_callback_payload(TOKEN_IMPERSONATE, &body);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandToken),
            0x02,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    assert_agent_response(&event, agent_id, "Error", "Failed to impersonate CORP\\user");

    socket.close(None).await?;
    server.listeners.stop("tok-imp-err").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Steal
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_steal_broadcasts_good() -> Result<(), Box<dyn std::error::Error>> {
    let agent_id = 0xFC01_0003_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE,
        0xFF, 0x01,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x12, 0x22, 0x32, 0x42, 0x52, 0x62, 0x72, 0x82, 0x92, 0xA2, 0xB2, 0xC2, 0xD2, 0xE2, 0xF2,
        0x03,
    ];

    let (server, client, mut socket, listener_port, ctr_offset) =
        setup_test!("tok-steal-ok", agent_id, key, iv);

    let mut body = Vec::new();
    push_utf16(&mut body, "CORP\\admin");
    push_u32(&mut body, 7); // token_id
    push_u32(&mut body, 1234); // target_pid
    let payload = token_callback_payload(TOKEN_STEAL, &body);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandToken),
            0x03,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    assert_agent_response(
        &event,
        agent_id,
        "Good",
        "Successfully stole and impersonated token from 1234 User:[CORP\\admin] TokenID:[7]",
    );

    socket.close(None).await?;
    server.listeners.stop("tok-steal-ok").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_list_empty_vault_broadcasts_info() -> Result<(), Box<dyn std::error::Error>> {
    let agent_id = 0xFC01_0004_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x13, 0x23, 0x33, 0x43, 0x53, 0x63, 0x73, 0x83, 0x93, 0xA3, 0xB3, 0xC3, 0xD3, 0xE3, 0xF3,
        0x04,
    ];

    let (server, client, mut socket, listener_port, ctr_offset) =
        setup_test!("tok-list-empty", agent_id, key, iv);

    let payload = token_callback_payload(TOKEN_LIST, &[]);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandToken),
            0x04,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let output = assert_agent_response(&event, agent_id, "Info", "Token Vault:");
    assert!(output.contains("token vault is empty"), "expected empty vault message, got: {output}");

    socket.close(None).await?;
    server.listeners.stop("tok-list-empty").await?;
    Ok(())
}

#[tokio::test]
async fn token_list_with_entries_broadcasts_table() -> Result<(), Box<dyn std::error::Error>> {
    let agent_id = 0xFC01_0005_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x40, 0x41,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x14, 0x24, 0x34, 0x44, 0x54, 0x64, 0x74, 0x84, 0x94, 0xA4, 0xB4, 0xC4, 0xD4, 0xE4, 0xF4,
        0x05,
    ];

    let (server, client, mut socket, listener_port, ctr_offset) =
        setup_test!("tok-list-entries", agent_id, key, iv);

    let mut body = Vec::new();
    // Entry: index=0, handle=0x10, user="CORP\\admin", pid=1234, type=1(stolen), impersonating=1
    push_u32(&mut body, 0);
    push_u32(&mut body, 0x10);
    push_utf16(&mut body, "CORP\\admin");
    push_u32(&mut body, 1234);
    push_u32(&mut body, 1); // stolen
    push_u32(&mut body, 1); // impersonating
    let payload = token_callback_payload(TOKEN_LIST, &body);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandToken),
            0x05,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let output = assert_agent_response(&event, agent_id, "Info", "Token Vault:");
    assert!(output.contains("CORP\\admin"), "output should contain the user: {output}");
    assert!(output.contains("stolen"), "output should contain token type: {output}");
    assert!(output.contains("Yes"), "output should show impersonating=Yes: {output}");

    socket.close(None).await?;
    server.listeners.stop("tok-list-entries").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// PrivsGetOrList
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_privs_list_broadcasts_privilege_table() -> Result<(), Box<dyn std::error::Error>> {
    let agent_id = 0xFC01_0006_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x15, 0x25, 0x35, 0x45, 0x55, 0x65, 0x75, 0x85, 0x95, 0xA5, 0xB5, 0xC5, 0xD5, 0xE5, 0xF5,
        0x06,
    ];

    let (server, client, mut socket, listener_port, ctr_offset) =
        setup_test!("tok-privs-list", agent_id, key, iv);

    let mut body = Vec::new();
    push_u32(&mut body, 1); // priv_list flag = non-zero → list mode
    push_string(&mut body, "SeDebugPrivilege");
    push_u32(&mut body, 3); // Enabled
    push_string(&mut body, "SeShutdownPrivilege");
    push_u32(&mut body, 0); // Disabled
    let payload = token_callback_payload(TOKEN_PRIVS_GET_OR_LIST, &body);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandToken),
            0x06,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let output =
        assert_agent_response(&event, agent_id, "Good", "List Privileges for current Token:");
    assert!(
        output.contains("SeDebugPrivilege :: Enabled"),
        "output should contain enabled priv: {output}"
    );
    assert!(
        output.contains("SeShutdownPrivilege :: Disabled"),
        "output should contain disabled priv: {output}"
    );

    socket.close(None).await?;
    server.listeners.stop("tok-privs-list").await?;
    Ok(())
}

#[tokio::test]
async fn token_privs_get_success_broadcasts_good() -> Result<(), Box<dyn std::error::Error>> {
    let agent_id = 0xFC01_0007_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        0x80, 0x81,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x16, 0x26, 0x36, 0x46, 0x56, 0x66, 0x76, 0x86, 0x96, 0xA6, 0xB6, 0xC6, 0xD6, 0xE6, 0xF6,
        0x07,
    ];

    let (server, client, mut socket, listener_port, ctr_offset) =
        setup_test!("tok-privs-get-ok", agent_id, key, iv);

    let mut body = Vec::new();
    push_u32(&mut body, 0); // priv_list = 0 → get mode
    push_u32(&mut body, 1); // success
    push_string(&mut body, "SeDebugPrivilege");
    let payload = token_callback_payload(TOKEN_PRIVS_GET_OR_LIST, &body);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandToken),
            0x07,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    assert_agent_response(
        &event,
        agent_id,
        "Good",
        "The privilege SeDebugPrivilege was successfully enabled",
    );

    socket.close(None).await?;
    server.listeners.stop("tok-privs-get-ok").await?;
    Ok(())
}

#[tokio::test]
async fn token_privs_get_failure_broadcasts_error() -> Result<(), Box<dyn std::error::Error>> {
    let agent_id = 0xFC01_0008_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90,
        0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
        0xA0, 0xA1,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x17, 0x27, 0x37, 0x47, 0x57, 0x67, 0x77, 0x87, 0x97, 0xA7, 0xB7, 0xC7, 0xD7, 0xE7, 0xF7,
        0x08,
    ];

    let (server, client, mut socket, listener_port, ctr_offset) =
        setup_test!("tok-privs-get-err", agent_id, key, iv);

    let mut body = Vec::new();
    push_u32(&mut body, 0); // priv_list = 0 → get mode
    push_u32(&mut body, 0); // failure
    push_string(&mut body, "SeDebugPrivilege");
    let payload = token_callback_payload(TOKEN_PRIVS_GET_OR_LIST, &body);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandToken),
            0x08,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    assert_agent_response(
        &event,
        agent_id,
        "Error",
        "Failed to enable the SeDebugPrivilege privilege",
    );

    socket.close(None).await?;
    server.listeners.stop("tok-privs-get-err").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Make
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_make_success_broadcasts_good() -> Result<(), Box<dyn std::error::Error>> {
    let agent_id = 0xFC01_0009_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
        0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
        0xC0, 0xC1,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x18, 0x28, 0x38, 0x48, 0x58, 0x68, 0x78, 0x88, 0x98, 0xA8, 0xB8, 0xC8, 0xD8, 0xE8, 0xF8,
        0x09,
    ];

    let (server, client, mut socket, listener_port, ctr_offset) =
        setup_test!("tok-make-ok", agent_id, key, iv);

    let mut body = Vec::new();
    push_utf16(&mut body, "CORP\\newuser");
    let payload = token_callback_payload(TOKEN_MAKE, &body);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandToken),
            0x09,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    assert_agent_response(
        &event,
        agent_id,
        "Good",
        "Successfully created and impersonated token: CORP\\newuser",
    );

    socket.close(None).await?;
    server.listeners.stop("tok-make-ok").await?;
    Ok(())
}

#[tokio::test]
async fn token_make_empty_payload_broadcasts_error() -> Result<(), Box<dyn std::error::Error>> {
    let agent_id = 0xFC01_000A_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0,
        0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
        0xE0, 0xE1,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x19, 0x29, 0x39, 0x49, 0x59, 0x69, 0x79, 0x89, 0x99, 0xA9, 0xB9, 0xC9, 0xD9, 0xE9, 0xF9,
        0x0A,
    ];

    let (server, client, mut socket, listener_port, ctr_offset) =
        setup_test!("tok-make-err", agent_id, key, iv);

    let payload = token_callback_payload(TOKEN_MAKE, &[]);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandToken),
            0x0A,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    assert_agent_response(&event, agent_id, "Error", "Failed to create token");

    socket.close(None).await?;
    server.listeners.stop("tok-make-err").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// GetUid
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_getuid_elevated_broadcasts_admin() -> Result<(), Box<dyn std::error::Error>> {
    let agent_id = 0xFC01_000B_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0,
        0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        0x01, 0x02,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x1A, 0x2A, 0x3A, 0x4A, 0x5A, 0x6A, 0x7A, 0x8A, 0x9A, 0xAA, 0xBA, 0xCA, 0xDA, 0xEA, 0xFA,
        0x0B,
    ];

    let (server, client, mut socket, listener_port, ctr_offset) =
        setup_test!("tok-getuid-admin", agent_id, key, iv);

    let mut body = Vec::new();
    push_u32(&mut body, 1); // elevated
    push_utf16(&mut body, "NT AUTHORITY\\SYSTEM");
    let payload = token_callback_payload(TOKEN_GETUID, &body);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandToken),
            0x0B,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    assert_agent_response(&event, agent_id, "Good", "Token User: NT AUTHORITY\\SYSTEM (Admin)");

    socket.close(None).await?;
    server.listeners.stop("tok-getuid-admin").await?;
    Ok(())
}

#[tokio::test]
async fn token_getuid_not_elevated_broadcasts_user() -> Result<(), Box<dyn std::error::Error>> {
    let agent_id = 0xFC01_000C_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11,
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        0x21, 0x22,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x1B, 0x2B, 0x3B, 0x4B, 0x5B, 0x6B, 0x7B, 0x8B, 0x9B, 0xAB, 0xBB, 0xCB, 0xDB, 0xEB, 0xFB,
        0x0C,
    ];

    let (server, client, mut socket, listener_port, ctr_offset) =
        setup_test!("tok-getuid-user", agent_id, key, iv);

    let mut body = Vec::new();
    push_u32(&mut body, 0); // not elevated
    push_utf16(&mut body, "CORP\\user");
    let payload = token_callback_payload(TOKEN_GETUID, &body);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandToken),
            0x0C,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    assert_agent_response(&event, agent_id, "Good", "Token User: CORP\\user");

    socket.close(None).await?;
    server.listeners.stop("tok-getuid-user").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Revert
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_revert_success_broadcasts_good() -> Result<(), Box<dyn std::error::Error>> {
    let agent_id = 0xFC01_000D_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31,
        0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
        0x41, 0x42,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x1C, 0x2C, 0x3C, 0x4C, 0x5C, 0x6C, 0x7C, 0x8C, 0x9C, 0xAC, 0xBC, 0xCC, 0xDC, 0xEC, 0xFC,
        0x0D,
    ];

    let (server, client, mut socket, listener_port, ctr_offset) =
        setup_test!("tok-revert-ok", agent_id, key, iv);

    let mut body = Vec::new();
    push_u32(&mut body, 1); // success
    let payload = token_callback_payload(TOKEN_REVERT, &body);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandToken),
            0x0D,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    assert_agent_response(&event, agent_id, "Good", "Successful reverted token to itself");

    socket.close(None).await?;
    server.listeners.stop("tok-revert-ok").await?;
    Ok(())
}

#[tokio::test]
async fn token_revert_failure_broadcasts_error() -> Result<(), Box<dyn std::error::Error>> {
    let agent_id = 0xFC01_000E_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51,
        0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60,
        0x61, 0x62,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x1D, 0x2D, 0x3D, 0x4D, 0x5D, 0x6D, 0x7D, 0x8D, 0x9D, 0xAD, 0xBD, 0xCD, 0xDD, 0xED, 0xFD,
        0x0E,
    ];

    let (server, client, mut socket, listener_port, ctr_offset) =
        setup_test!("tok-revert-err", agent_id, key, iv);

    let mut body = Vec::new();
    push_u32(&mut body, 0); // failure
    let payload = token_callback_payload(TOKEN_REVERT, &body);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandToken),
            0x0E,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    assert_agent_response(&event, agent_id, "Error", "Failed to revert token to itself");

    socket.close(None).await?;
    server.listeners.stop("tok-revert-err").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Remove
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_remove_success_broadcasts_good() -> Result<(), Box<dyn std::error::Error>> {
    let agent_id = 0xFC01_000F_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71,
        0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80,
        0x81, 0x82,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x1E, 0x2E, 0x3E, 0x4E, 0x5E, 0x6E, 0x7E, 0x8E, 0x9E, 0xAE, 0xBE, 0xCE, 0xDE, 0xEE, 0xFE,
        0x0F,
    ];

    let (server, client, mut socket, listener_port, ctr_offset) =
        setup_test!("tok-remove-ok", agent_id, key, iv);

    let mut body = Vec::new();
    push_u32(&mut body, 1); // success
    push_u32(&mut body, 5); // token_id
    let payload = token_callback_payload(TOKEN_REMOVE, &body);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandToken),
            0x0F,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    assert_agent_response(&event, agent_id, "Good", "Successful removed token [5] from vault");

    socket.close(None).await?;
    server.listeners.stop("tok-remove-ok").await?;
    Ok(())
}

#[tokio::test]
async fn token_remove_failure_broadcasts_error() -> Result<(), Box<dyn std::error::Error>> {
    let agent_id = 0xFC01_0010_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91,
        0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0,
        0xA1, 0xA2,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x1F, 0x2F, 0x3F, 0x4F, 0x5F, 0x6F, 0x7F, 0x8F, 0x9F, 0xAF, 0xBF, 0xCF, 0xDF, 0xEF, 0xFF,
        0x10,
    ];

    let (server, client, mut socket, listener_port, ctr_offset) =
        setup_test!("tok-remove-err", agent_id, key, iv);

    let mut body = Vec::new();
    push_u32(&mut body, 0); // failure
    push_u32(&mut body, 3); // token_id
    let payload = token_callback_payload(TOKEN_REMOVE, &body);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandToken),
            0x10,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    assert_agent_response(&event, agent_id, "Error", "Failed to remove token [3] from vault");

    socket.close(None).await?;
    server.listeners.stop("tok-remove-err").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Clear
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_clear_broadcasts_good() -> Result<(), Box<dyn std::error::Error>> {
    let agent_id = 0xFC01_0011_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1,
        0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0,
        0xC1, 0xC2,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x01,
        0x11,
    ];

    let (server, client, mut socket, listener_port, ctr_offset) =
        setup_test!("tok-clear", agent_id, key, iv);

    let payload = token_callback_payload(TOKEN_CLEAR, &[]);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandToken),
            0x11,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    assert_agent_response(&event, agent_id, "Good", "Token vault has been cleared");

    socket.close(None).await?;
    server.listeners.stop("tok-clear").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// FindTokens
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_find_tokens_success_broadcasts_info() -> Result<(), Box<dyn std::error::Error>> {
    let agent_id = 0xFC01_0012_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1,
        0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0,
        0xE1, 0xE2,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x21, 0x31, 0x41, 0x51, 0x61, 0x71, 0x81, 0x91, 0xA1, 0xB1, 0xC1, 0xD1, 0xE1, 0xF1, 0x02,
        0x12,
    ];

    let (server, client, mut socket, listener_port, ctr_offset) =
        setup_test!("tok-find-ok", agent_id, key, iv);

    let mut body = Vec::new();
    push_u32(&mut body, 1); // success
    push_u32(&mut body, 1); // num_tokens
    push_utf16(&mut body, "CORP\\admin");
    push_u32(&mut body, 500); // pid
    push_u32(&mut body, 0x60); // handle
    push_u32(&mut body, 0x3000); // High integrity
    push_u32(&mut body, 2); // Impersonation level
    push_u32(&mut body, 2); // Impersonation token type
    let payload = token_callback_payload(TOKEN_FIND_TOKENS, &body);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandToken),
            0x12,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let output = assert_agent_response(&event, agent_id, "Info", "Tokens available:");
    assert!(output.contains("CORP\\admin"), "output should contain user: {output}");
    assert!(output.contains("High"), "output should contain integrity level: {output}");

    socket.close(None).await?;
    server.listeners.stop("tok-find-ok").await?;
    Ok(())
}

#[tokio::test]
async fn token_find_tokens_failure_broadcasts_error() -> Result<(), Box<dyn std::error::Error>> {
    let agent_id = 0xFC01_0013_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1,
        0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF, 0x01,
        0x02, 0x03,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x22, 0x32, 0x42, 0x52, 0x62, 0x72, 0x82, 0x92, 0xA2, 0xB2, 0xC2, 0xD2, 0xE2, 0xF2, 0x03,
        0x13,
    ];

    let (server, client, mut socket, listener_port, ctr_offset) =
        setup_test!("tok-find-err", agent_id, key, iv);

    let mut body = Vec::new();
    push_u32(&mut body, 0); // failure
    let payload = token_callback_payload(TOKEN_FIND_TOKENS, &body);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandToken),
            0x13,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    assert_agent_response(&event, agent_id, "Error", "Failed to list existing tokens");

    socket.close(None).await?;
    server.listeners.stop("tok-find-err").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Error paths — invalid subcommand / truncated payloads
// ---------------------------------------------------------------------------

/// An invalid subcommand ID must cause the server to reject the callback (non-2xx).
#[tokio::test]
async fn token_invalid_subcommand_rejects() -> Result<(), Box<dyn std::error::Error>> {
    let agent_id = 0xFC01_0020_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
        0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21,
        0x22, 0x23,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x23, 0x33, 0x43, 0x53, 0x63, 0x73, 0x83, 0x93, 0xA3, 0xB3, 0xC3, 0xD3, 0xE3, 0xF3, 0x04,
        0x14,
    ];

    let (server, client, mut socket, listener_port, ctr_offset) =
        setup_test!("tok-bad-sub", agent_id, key, iv);

    let payload = token_callback_payload(9999, &[]); // invalid subcommand

    let resp = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandToken),
            0x20,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        !resp.status().is_success(),
        "invalid subcommand must not return 2xx, got {}",
        resp.status()
    );

    socket.close(None).await?;
    server.listeners.stop("tok-bad-sub").await?;
    Ok(())
}

/// A truncated Impersonate payload (subcommand only, no success/user fields) must
/// be rejected by the server.
#[tokio::test]
async fn token_truncated_impersonate_rejects() -> Result<(), Box<dyn std::error::Error>> {
    let agent_id = 0xFC01_0021_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
        0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41,
        0x42, 0x43,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x24, 0x34, 0x44, 0x54, 0x64, 0x74, 0x84, 0x94, 0xA4, 0xB4, 0xC4, 0xD4, 0xE4, 0xF4, 0x05,
        0x15,
    ];

    let (server, client, mut socket, listener_port, ctr_offset) =
        setup_test!("tok-trunc-imp", agent_id, key, iv);

    let payload = token_callback_payload(TOKEN_IMPERSONATE, &[]); // truncated

    let resp = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandToken),
            0x21,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        !resp.status().is_success(),
        "truncated Impersonate payload must not return 2xx, got {}",
        resp.status()
    );

    socket.close(None).await?;
    server.listeners.stop("tok-trunc-imp").await?;
    Ok(())
}

/// A truncated Steal payload (subcommand only) must be rejected.
#[tokio::test]
async fn token_truncated_steal_rejects() -> Result<(), Box<dyn std::error::Error>> {
    let agent_id = 0xFC01_0022_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52,
        0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61,
        0x62, 0x63,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x25, 0x35, 0x45, 0x55, 0x65, 0x75, 0x85, 0x95, 0xA5, 0xB5, 0xC5, 0xD5, 0xE5, 0xF5, 0x06,
        0x16,
    ];

    let (server, client, mut socket, listener_port, ctr_offset) =
        setup_test!("tok-trunc-steal", agent_id, key, iv);

    let payload = token_callback_payload(TOKEN_STEAL, &[]); // truncated

    let resp = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandToken),
            0x22,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        !resp.status().is_success(),
        "truncated Steal payload must not return 2xx, got {}",
        resp.status()
    );

    socket.close(None).await?;
    server.listeners.stop("tok-trunc-steal").await?;
    Ok(())
}

/// A truncated FindTokens payload (success=1 but no num_tokens) must be rejected.
#[tokio::test]
async fn token_truncated_find_tokens_rejects() -> Result<(), Box<dyn std::error::Error>> {
    let agent_id = 0xFC01_0023_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72,
        0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81,
        0x82, 0x83,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x26, 0x36, 0x46, 0x56, 0x66, 0x76, 0x86, 0x96, 0xA6, 0xB6, 0xC6, 0xD6, 0xE6, 0xF6, 0x07,
        0x17,
    ];

    let (server, client, mut socket, listener_port, ctr_offset) =
        setup_test!("tok-trunc-find", agent_id, key, iv);

    let mut body = Vec::new();
    push_u32(&mut body, 1); // success=1 but no num_tokens
    let payload = token_callback_payload(TOKEN_FIND_TOKENS, &body);

    let resp = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandToken),
            0x23,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        !resp.status().is_success(),
        "truncated FindTokens payload must not return 2xx, got {}",
        resp.status()
    );

    socket.close(None).await?;
    server.listeners.stop("tok-trunc-find").await?;
    Ok(())
}

/// An empty payload (no subcommand at all) must be rejected.
#[tokio::test]
async fn token_empty_payload_rejects() -> Result<(), Box<dyn std::error::Error>> {
    let agent_id = 0xFC01_0024_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92,
        0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1,
        0xA2, 0xA3,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x27, 0x37, 0x47, 0x57, 0x67, 0x77, 0x87, 0x97, 0xA7, 0xB7, 0xC7, 0xD7, 0xE7, 0xF7, 0x08,
        0x18,
    ];

    let (server, client, mut socket, listener_port, ctr_offset) =
        setup_test!("tok-empty", agent_id, key, iv);

    let resp = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandToken),
            0x24,
            &[], // completely empty
        ))
        .send()
        .await?;

    assert!(
        !resp.status().is_success(),
        "empty token payload must not return 2xx, got {}",
        resp.status()
    );

    socket.close(None).await?;
    server.listeners.stop("tok-empty").await?;
    Ok(())
}

/// A malformed List payload where the token entry is truncated mid-field
/// (only index and handle provided, no domain_user) must be rejected.
#[tokio::test]
async fn token_malformed_list_truncated_entry_rejects() -> Result<(), Box<dyn std::error::Error>> {
    let agent_id = 0xFC01_0025_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2,
        0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1,
        0xC2, 0xC3,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x28, 0x38, 0x48, 0x58, 0x68, 0x78, 0x88, 0x98, 0xA8, 0xB8, 0xC8, 0xD8, 0xE8, 0xF8, 0x09,
        0x19,
    ];

    let (server, client, mut socket, listener_port, ctr_offset) =
        setup_test!("tok-malform-list", agent_id, key, iv);

    // Build a List payload with a truncated entry: index + handle but no domain_user
    let mut body = Vec::new();
    push_u32(&mut body, 0); // index
    push_u32(&mut body, 0x10); // handle
    // Missing: domain_user (utf16), pid, type, impersonating
    // But the length-prefix for the utf16 will be parsed from the next 4 bytes,
    // which don't exist — should trigger a parse error.
    // Actually, with only 8 bytes after subcommand, parser.is_empty() is false,
    // so it will try to read. Let's add a partial utf16 length that overflows.
    push_u32(&mut body, 1000); // claims 1000 bytes of utf16 data but none follow
    let payload = token_callback_payload(TOKEN_LIST, &body);

    let resp = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandToken),
            0x25,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        !resp.status().is_success(),
        "malformed List entry must not return 2xx, got {}",
        resp.status()
    );

    socket.close(None).await?;
    server.listeners.stop("tok-malform-list").await?;
    Ok(())
}

/// A truncated PrivsGetOrList in get mode (has priv_list=0 and success=1 but no
/// privilege name) must be rejected.
#[tokio::test]
async fn token_truncated_privs_get_rejects() -> Result<(), Box<dyn std::error::Error>> {
    let agent_id = 0xFC01_0026_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2,
        0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1,
        0xE2, 0xE3,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x29, 0x39, 0x49, 0x59, 0x69, 0x79, 0x89, 0x99, 0xA9, 0xB9, 0xC9, 0xD9, 0xE9, 0xF9, 0x0A,
        0x1A,
    ];

    let (server, client, mut socket, listener_port, ctr_offset) =
        setup_test!("tok-trunc-privs", agent_id, key, iv);

    let mut body = Vec::new();
    push_u32(&mut body, 0); // priv_list = 0 (get mode)
    push_u32(&mut body, 1); // success = 1
    // Missing: privilege name string
    let payload = token_callback_payload(TOKEN_PRIVS_GET_OR_LIST, &body);

    let resp = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandToken),
            0x26,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        !resp.status().is_success(),
        "truncated PrivsGetOrList (get mode) must not return 2xx, got {}",
        resp.status()
    );

    socket.close(None).await?;
    server.listeners.stop("tok-trunc-privs").await?;
    Ok(())
}
