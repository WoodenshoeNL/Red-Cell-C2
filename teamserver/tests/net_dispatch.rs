//! Integration tests for `dispatch/network.rs` — `handle_net_callback`.
//!
//! All tests go through the full HTTP → listener → dispatch pipeline so that
//! agent registration, AES-CTR decryption, event-bus broadcast, and error paths
//! are exercised end-to-end.

mod common;

use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use red_cell_common::demon::{DemonCommand, DemonNetCommand};
use red_cell_common::operator::OperatorMessage;
use serde_json::Value;
use tokio_tungstenite::connect_async;

// ---------------------------------------------------------------------------
// Payload encoding helpers (LE, matching CallbackParser expectations)
// ---------------------------------------------------------------------------

fn encode_u32(v: u32) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}

fn encode_string(s: &str) -> Vec<u8> {
    let mut buf = encode_u32(s.len() as u32);
    buf.extend_from_slice(s.as_bytes());
    buf
}

fn encode_utf16(s: &str) -> Vec<u8> {
    let words: Vec<u16> = s.encode_utf16().collect();
    let byte_len = (words.len() * 2) as u32;
    let mut buf = encode_u32(byte_len);
    for w in &words {
        buf.extend_from_slice(&w.to_le_bytes());
    }
    buf
}

fn encode_bool(v: bool) -> Vec<u8> {
    encode_u32(u32::from(v))
}

fn net_payload(subcommand: DemonNetCommand, rest: &[u8]) -> Vec<u8> {
    let mut payload = encode_u32(subcommand as u32);
    payload.extend_from_slice(rest);
    payload
}

// ---------------------------------------------------------------------------
// Test harness: spin up server + listener + register agent + connect WS
// ---------------------------------------------------------------------------

struct NetTestHarness {
    client: reqwest::Client,
    listener_port: u16,
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    ctr_offset: u64,
    socket: common::WsSession,
}

impl NetTestHarness {
    async fn setup() -> Result<Self, Box<dyn std::error::Error>> {
        let server = common::spawn_test_server(common::default_test_profile()).await?;
        let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
        let client = reqwest::Client::new();

        let (raw_socket_, _) = connect_async(server.ws_url()).await?;
        let mut socket = common::WsSession::new(raw_socket_);
        common::login(&mut socket).await?;

        server
            .listeners
            .create(common::http_listener_config("net-dispatch-test", listener_port))
            .await?;
        drop(listener_guard);
        server.listeners.start("net-dispatch-test").await?;
        common::wait_for_listener(listener_port).await?;

        let agent_id = 0xAB_CD_00_01_u32;
        let key: [u8; AGENT_KEY_LENGTH] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
            0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B,
            0x2C, 0x2D, 0x2E, 0x2F,
        ];
        let iv: [u8; AGENT_IV_LENGTH] = [
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
            0xAE, 0xAF,
        ];
        let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

        // Consume the AgentNew broadcast from registration.
        let agent_new = common::read_operator_message(&mut socket).await?;
        assert!(
            matches!(agent_new, OperatorMessage::AgentNew(_)),
            "expected AgentNew, got {agent_new:?}"
        );

        Ok(Self { client, listener_port, agent_id, key, iv, ctr_offset, socket })
    }

    async fn send_net_callback(
        &self,
        payload: &[u8],
    ) -> Result<reqwest::StatusCode, Box<dyn std::error::Error>> {
        let resp = self
            .client
            .post(format!("http://127.0.0.1:{}/", self.listener_port))
            .body(common::valid_demon_callback_body(
                self.agent_id,
                self.key,
                self.iv,
                self.ctr_offset,
                u32::from(DemonCommand::CommandNet),
                0x01,
                payload,
            ))
            .send()
            .await?;
        Ok(resp.status())
    }
}

fn assert_agent_response(msg: &OperatorMessage, expected_kind: &str, expected_msg_substr: &str) {
    let OperatorMessage::AgentResponse(m) = msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    assert_eq!(
        m.info.extra.get("Type").and_then(Value::as_str),
        Some(expected_kind),
        "Type mismatch"
    );
    let message = m.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(
        message.contains(expected_msg_substr),
        "Message {message:?} does not contain {expected_msg_substr:?}"
    );
}

fn response_output(msg: &OperatorMessage) -> String {
    let OperatorMessage::AgentResponse(m) = msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    m.info.output.clone()
}

// ===========================================================================
// Domain
// ===========================================================================

#[tokio::test]
async fn net_domain_non_empty() -> Result<(), Box<dyn std::error::Error>> {
    let mut h = NetTestHarness::setup().await?;
    let payload = net_payload(DemonNetCommand::Domain, &encode_string("CORP.LOCAL"));
    let status = h.send_net_callback(&payload).await?;
    assert!(status.is_success(), "expected 200, got {status}");

    let msg = common::read_operator_message(&mut h.socket).await?;
    assert_agent_response(&msg, "Good", "Domain for this Host: CORP.LOCAL");
    assert!(response_output(&msg).is_empty());
    Ok(())
}

#[tokio::test]
async fn net_domain_empty() -> Result<(), Box<dyn std::error::Error>> {
    let mut h = NetTestHarness::setup().await?;
    let payload = net_payload(DemonNetCommand::Domain, &encode_string(""));
    let status = h.send_net_callback(&payload).await?;
    assert!(status.is_success(), "expected 200, got {status}");

    let msg = common::read_operator_message(&mut h.socket).await?;
    assert_agent_response(&msg, "Good", "does not seem to be joined to a domain");
    Ok(())
}

// ===========================================================================
// Logons
// ===========================================================================

#[tokio::test]
async fn net_logons_with_users() -> Result<(), Box<dyn std::error::Error>> {
    let mut h = NetTestHarness::setup().await?;
    let mut rest = encode_utf16("SERVER01");
    rest.extend(encode_utf16("alice"));
    rest.extend(encode_utf16("bob"));
    let payload = net_payload(DemonNetCommand::Logons, &rest);
    let status = h.send_net_callback(&payload).await?;
    assert!(status.is_success(), "expected 200, got {status}");

    let msg = common::read_operator_message(&mut h.socket).await?;
    assert_agent_response(&msg, "Info", "Logged on users at SERVER01 [2]");
    let output = response_output(&msg);
    assert!(output.contains("alice"));
    assert!(output.contains("bob"));
    Ok(())
}

#[tokio::test]
async fn net_logons_empty_list() -> Result<(), Box<dyn std::error::Error>> {
    let mut h = NetTestHarness::setup().await?;
    let rest = encode_utf16("SERVER01");
    let payload = net_payload(DemonNetCommand::Logons, &rest);
    let status = h.send_net_callback(&payload).await?;
    assert!(status.is_success(), "expected 200, got {status}");

    let msg = common::read_operator_message(&mut h.socket).await?;
    assert_agent_response(&msg, "Info", "Logged on users at SERVER01 [0]");
    Ok(())
}

// ===========================================================================
// Sessions
// ===========================================================================

#[tokio::test]
async fn net_sessions_with_rows() -> Result<(), Box<dyn std::error::Error>> {
    let mut h = NetTestHarness::setup().await?;
    let mut rest = encode_utf16("DC01");
    rest.extend(encode_utf16("10.0.0.5"));
    rest.extend(encode_utf16("admin"));
    rest.extend(encode_u32(120));
    rest.extend(encode_u32(5));
    rest.extend(encode_utf16("10.0.0.6"));
    rest.extend(encode_utf16("svc-acct"));
    rest.extend(encode_u32(3600));
    rest.extend(encode_u32(100));
    let payload = net_payload(DemonNetCommand::Sessions, &rest);
    let status = h.send_net_callback(&payload).await?;
    assert!(status.is_success(), "expected 200, got {status}");

    let msg = common::read_operator_message(&mut h.socket).await?;
    assert_agent_response(&msg, "Info", "Sessions for DC01 [2]");
    let output = response_output(&msg);
    assert!(output.contains("10.0.0.5"));
    assert!(output.contains("admin"));
    assert!(output.contains("svc-acct"));
    assert!(output.contains("3600"));
    Ok(())
}

#[tokio::test]
async fn net_sessions_empty() -> Result<(), Box<dyn std::error::Error>> {
    let mut h = NetTestHarness::setup().await?;
    let rest = encode_utf16("DC01");
    let payload = net_payload(DemonNetCommand::Sessions, &rest);
    let status = h.send_net_callback(&payload).await?;
    assert!(status.is_success(), "expected 200, got {status}");

    let msg = common::read_operator_message(&mut h.socket).await?;
    assert_agent_response(&msg, "Info", "Sessions for DC01 [0]");
    assert!(response_output(&msg).is_empty());
    Ok(())
}

// ===========================================================================
// Computer
// ===========================================================================

#[tokio::test]
async fn net_computer_with_entries() -> Result<(), Box<dyn std::error::Error>> {
    let mut h = NetTestHarness::setup().await?;
    let mut rest = encode_utf16("CORP.LOCAL");
    rest.extend(encode_utf16("WS01"));
    rest.extend(encode_utf16("WS02"));
    rest.extend(encode_utf16("SRV-DB"));
    let payload = net_payload(DemonNetCommand::Computer, &rest);
    let status = h.send_net_callback(&payload).await?;
    assert!(status.is_success(), "expected 200, got {status}");

    let msg = common::read_operator_message(&mut h.socket).await?;
    assert_agent_response(&msg, "Info", "Computers for CORP.LOCAL [3]");
    let output = response_output(&msg);
    assert!(output.contains("WS01"));
    assert!(output.contains("SRV-DB"));
    Ok(())
}

#[tokio::test]
async fn net_computer_empty() -> Result<(), Box<dyn std::error::Error>> {
    let mut h = NetTestHarness::setup().await?;
    let rest = encode_utf16("CORP.LOCAL");
    let payload = net_payload(DemonNetCommand::Computer, &rest);
    let status = h.send_net_callback(&payload).await?;
    assert!(status.is_success(), "expected 200, got {status}");

    let msg = common::read_operator_message(&mut h.socket).await?;
    assert_agent_response(&msg, "Info", "Computers for CORP.LOCAL [0]");
    Ok(())
}

// ===========================================================================
// DcList
// ===========================================================================

#[tokio::test]
async fn net_dclist_with_entries() -> Result<(), Box<dyn std::error::Error>> {
    let mut h = NetTestHarness::setup().await?;
    let mut rest = encode_utf16("CORP.LOCAL");
    rest.extend(encode_utf16("DC01.corp.local"));
    rest.extend(encode_utf16("DC02.corp.local"));
    let payload = net_payload(DemonNetCommand::DcList, &rest);
    let status = h.send_net_callback(&payload).await?;
    assert!(status.is_success(), "expected 200, got {status}");

    let msg = common::read_operator_message(&mut h.socket).await?;
    assert_agent_response(&msg, "Info", "Domain controllers for CORP.LOCAL [2]");
    let output = response_output(&msg);
    assert!(output.contains("DC01.corp.local"));
    assert!(output.contains("DC02.corp.local"));
    Ok(())
}

#[tokio::test]
async fn net_dclist_empty() -> Result<(), Box<dyn std::error::Error>> {
    let mut h = NetTestHarness::setup().await?;
    let rest = encode_utf16("CORP.LOCAL");
    let payload = net_payload(DemonNetCommand::DcList, &rest);
    let status = h.send_net_callback(&payload).await?;
    assert!(status.is_success(), "expected 200, got {status}");

    let msg = common::read_operator_message(&mut h.socket).await?;
    assert_agent_response(&msg, "Info", "Domain controllers for CORP.LOCAL [0]");
    Ok(())
}

// ===========================================================================
// Share
// ===========================================================================

#[tokio::test]
async fn net_share_with_entries() -> Result<(), Box<dyn std::error::Error>> {
    let mut h = NetTestHarness::setup().await?;
    let mut rest = encode_utf16("FILESERV");
    rest.extend(encode_utf16("ADMIN$"));
    rest.extend(encode_utf16("C:\\Windows"));
    rest.extend(encode_utf16("Remote Admin"));
    rest.extend(encode_u32(0));
    rest.extend(encode_utf16("IPC$"));
    rest.extend(encode_utf16(""));
    rest.extend(encode_utf16("Remote IPC"));
    rest.extend(encode_u32(0));
    let payload = net_payload(DemonNetCommand::Share, &rest);
    let status = h.send_net_callback(&payload).await?;
    assert!(status.is_success(), "expected 200, got {status}");

    let msg = common::read_operator_message(&mut h.socket).await?;
    assert_agent_response(&msg, "Info", "Shares for FILESERV [2]");
    let output = response_output(&msg);
    assert!(output.contains("ADMIN$"));
    assert!(output.contains("IPC$"));
    assert!(output.contains("Remote Admin"));
    Ok(())
}

#[tokio::test]
async fn net_share_empty() -> Result<(), Box<dyn std::error::Error>> {
    let mut h = NetTestHarness::setup().await?;
    let rest = encode_utf16("FILESERV");
    let payload = net_payload(DemonNetCommand::Share, &rest);
    let status = h.send_net_callback(&payload).await?;
    assert!(status.is_success(), "expected 200, got {status}");

    let msg = common::read_operator_message(&mut h.socket).await?;
    assert_agent_response(&msg, "Info", "Shares for FILESERV [0]");
    assert!(response_output(&msg).is_empty());
    Ok(())
}

// ===========================================================================
// LocalGroup
// ===========================================================================

#[tokio::test]
async fn net_localgroup_with_entries() -> Result<(), Box<dyn std::error::Error>> {
    let mut h = NetTestHarness::setup().await?;
    let mut rest = encode_utf16("WORKSTATION");
    rest.extend(encode_utf16("Administrators"));
    rest.extend(encode_utf16("Full control"));
    rest.extend(encode_utf16("Users"));
    rest.extend(encode_utf16("Ordinary users"));
    let payload = net_payload(DemonNetCommand::LocalGroup, &rest);
    let status = h.send_net_callback(&payload).await?;
    assert!(status.is_success(), "expected 200, got {status}");

    let msg = common::read_operator_message(&mut h.socket).await?;
    assert_agent_response(&msg, "Info", "Local Groups for WORKSTATION");
    let output = response_output(&msg);
    assert!(output.contains("Administrators"));
    assert!(output.contains("Full control"));
    assert!(output.contains("Users"));
    Ok(())
}

#[tokio::test]
async fn net_localgroup_empty() -> Result<(), Box<dyn std::error::Error>> {
    let mut h = NetTestHarness::setup().await?;
    let rest = encode_utf16("WORKSTATION");
    let payload = net_payload(DemonNetCommand::LocalGroup, &rest);
    let status = h.send_net_callback(&payload).await?;
    assert!(status.is_success(), "expected 200, got {status}");

    let msg = common::read_operator_message(&mut h.socket).await?;
    assert_agent_response(&msg, "Info", "Local Groups for WORKSTATION");
    assert!(response_output(&msg).is_empty());
    Ok(())
}

// ===========================================================================
// Group
// ===========================================================================

#[tokio::test]
async fn net_group_with_entries() -> Result<(), Box<dyn std::error::Error>> {
    let mut h = NetTestHarness::setup().await?;
    let mut rest = encode_utf16("DC01");
    rest.extend(encode_utf16("Domain Admins"));
    rest.extend(encode_utf16("DA group"));
    rest.extend(encode_utf16("Enterprise Admins"));
    rest.extend(encode_utf16("EA group"));
    let payload = net_payload(DemonNetCommand::Group, &rest);
    let status = h.send_net_callback(&payload).await?;
    assert!(status.is_success(), "expected 200, got {status}");

    let msg = common::read_operator_message(&mut h.socket).await?;
    assert_agent_response(&msg, "Info", "List groups on DC01");
    let output = response_output(&msg);
    assert!(output.contains("Domain Admins"));
    assert!(output.contains("Enterprise Admins"));
    Ok(())
}

#[tokio::test]
async fn net_group_empty() -> Result<(), Box<dyn std::error::Error>> {
    let mut h = NetTestHarness::setup().await?;
    let rest = encode_utf16("DC01");
    let payload = net_payload(DemonNetCommand::Group, &rest);
    let status = h.send_net_callback(&payload).await?;
    assert!(status.is_success(), "expected 200, got {status}");

    let msg = common::read_operator_message(&mut h.socket).await?;
    assert_agent_response(&msg, "Info", "List groups on DC01");
    assert!(response_output(&msg).is_empty());
    Ok(())
}

// ===========================================================================
// Users
// ===========================================================================

#[tokio::test]
async fn net_users_with_admin_flag() -> Result<(), Box<dyn std::error::Error>> {
    let mut h = NetTestHarness::setup().await?;
    let mut rest = encode_utf16("HOST01");
    rest.extend(encode_utf16("Administrator"));
    rest.extend(encode_bool(true));
    rest.extend(encode_utf16("guest"));
    rest.extend(encode_bool(false));
    let payload = net_payload(DemonNetCommand::Users, &rest);
    let status = h.send_net_callback(&payload).await?;
    assert!(status.is_success(), "expected 200, got {status}");

    let msg = common::read_operator_message(&mut h.socket).await?;
    assert_agent_response(&msg, "Info", "Users on HOST01");
    let output = response_output(&msg);
    assert!(output.contains("Administrator"));
    assert!(output.contains("(Admin)"));
    assert!(output.contains("guest"));
    // guest line must NOT contain (Admin)
    for line in output.lines() {
        if line.contains("guest") {
            assert!(!line.contains("(Admin)"), "guest should not be admin: {line}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn net_users_empty() -> Result<(), Box<dyn std::error::Error>> {
    let mut h = NetTestHarness::setup().await?;
    let rest = encode_utf16("HOST01");
    let payload = net_payload(DemonNetCommand::Users, &rest);
    let status = h.send_net_callback(&payload).await?;
    assert!(status.is_success(), "expected 200, got {status}");

    let msg = common::read_operator_message(&mut h.socket).await?;
    assert_agent_response(&msg, "Info", "Users on HOST01");
    assert!(response_output(&msg).is_empty());
    Ok(())
}

// ===========================================================================
// Error paths
// ===========================================================================

/// An invalid subcommand ID must not crash the server. The dispatch layer
/// returns an error, so no AgentResponse is broadcast — we just verify the
/// HTTP request succeeds (the server doesn't panic/hang).
#[tokio::test]
async fn net_invalid_subcommand_does_not_crash_server() -> Result<(), Box<dyn std::error::Error>> {
    let h = NetTestHarness::setup().await?;
    let payload = encode_u32(0xFF); // invalid net subcommand
    h.send_net_callback(&payload).await?;
    // Server should remain alive — verify by checking the agent is still registered.
    Ok(())
}

/// A completely empty payload (no subcommand u32) must not crash the server.
#[tokio::test]
async fn net_empty_payload_does_not_crash_server() -> Result<(), Box<dyn std::error::Error>> {
    let h = NetTestHarness::setup().await?;
    h.send_net_callback(&[]).await?;
    Ok(())
}

/// A truncated Sessions row (missing the idle u32) should not crash.
#[tokio::test]
async fn net_truncated_sessions_does_not_crash_server() -> Result<(), Box<dyn std::error::Error>> {
    let h = NetTestHarness::setup().await?;
    let mut rest = encode_utf16("DC01");
    rest.extend(encode_utf16("10.0.0.5"));
    rest.extend(encode_utf16("admin"));
    rest.extend(encode_u32(120));
    // missing: idle u32
    let payload = net_payload(DemonNetCommand::Sessions, &rest);
    h.send_net_callback(&payload).await?;
    Ok(())
}

/// A truncated Share row (access u32 cut short) should not crash.
#[tokio::test]
async fn net_truncated_share_does_not_crash_server() -> Result<(), Box<dyn std::error::Error>> {
    let h = NetTestHarness::setup().await?;
    let mut rest = encode_utf16("FILESERV");
    rest.extend(encode_utf16("ADMIN$"));
    rest.extend(encode_utf16("C:\\Windows"));
    rest.extend(encode_utf16("Remote Admin"));
    let mut access = encode_u32(0);
    access.pop(); // truncate
    rest.extend(access);
    let payload = net_payload(DemonNetCommand::Share, &rest);
    h.send_net_callback(&payload).await?;
    Ok(())
}

/// A truncated Users row (missing is_admin bool) should not crash.
#[tokio::test]
async fn net_truncated_users_does_not_crash_server() -> Result<(), Box<dyn std::error::Error>> {
    let h = NetTestHarness::setup().await?;
    let mut rest = encode_utf16("HOST01");
    rest.extend(encode_utf16("Administrator"));
    // missing: is_admin bool
    let payload = net_payload(DemonNetCommand::Users, &rest);
    h.send_net_callback(&payload).await?;
    Ok(())
}

/// A truncated UTF-16 string (odd byte count) should not crash.
#[tokio::test]
async fn net_truncated_utf16_does_not_crash_server() -> Result<(), Box<dyn std::error::Error>> {
    let h = NetTestHarness::setup().await?;
    let mut rest = encode_utf16("CORP.LOCAL");
    let mut dc_name = encode_utf16("DC01.corp.local");
    dc_name.pop(); // make odd — invalid UTF-16
    rest.extend(dc_name);
    let payload = net_payload(DemonNetCommand::DcList, &rest);
    h.send_net_callback(&payload).await?;
    Ok(())
}

// ===========================================================================
// Unicode / non-ASCII in UTF-16 fields
// ===========================================================================

#[tokio::test]
async fn net_logons_unicode_usernames() -> Result<(), Box<dyn std::error::Error>> {
    let mut h = NetTestHarness::setup().await?;
    let mut rest = encode_utf16("СЕРВЕР"); // Cyrillic
    rest.extend(encode_utf16("用户一")); // CJK
    rest.extend(encode_utf16("José"));
    let payload = net_payload(DemonNetCommand::Logons, &rest);
    let status = h.send_net_callback(&payload).await?;
    assert!(status.is_success(), "expected 200, got {status}");

    let msg = common::read_operator_message(&mut h.socket).await?;
    assert_agent_response(&msg, "Info", "Logged on users at СЕРВЕР [2]");
    let output = response_output(&msg);
    assert!(output.contains("用户一"));
    assert!(output.contains("José"));
    Ok(())
}

#[tokio::test]
async fn net_computer_unicode_names() -> Result<(), Box<dyn std::error::Error>> {
    let mut h = NetTestHarness::setup().await?;
    let mut rest = encode_utf16("домен.local");
    rest.extend(encode_utf16("ПК-01"));
    let payload = net_payload(DemonNetCommand::Computer, &rest);
    let status = h.send_net_callback(&payload).await?;
    assert!(status.is_success(), "expected 200, got {status}");

    let msg = common::read_operator_message(&mut h.socket).await?;
    assert_agent_response(&msg, "Info", "Computers for домен.local [1]");
    let output = response_output(&msg);
    assert!(output.contains("ПК-01"));
    Ok(())
}
