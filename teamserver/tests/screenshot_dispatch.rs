//! Integration tests for `dispatch/screenshot.rs` — `handle_screenshot_callback`.
//!
//! All tests go through the full HTTP → listener → dispatch pipeline so that
//! the database write and event-bus broadcast paths are exercised end-to-end.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::OperatorMessage;
use tokio_tungstenite::connect_async;

// ---------------------------------------------------------------------------
// Payload builders
// ---------------------------------------------------------------------------

/// Build a `CommandScreenshot` callback payload with `success=1` and the given image bytes.
fn screenshot_success_payload(image_bytes: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&1_u32.to_le_bytes()); // success = 1
    p.extend_from_slice(&(image_bytes.len() as u32).to_le_bytes());
    p.extend_from_slice(image_bytes);
    p
}

/// Build a `CommandScreenshot` callback payload with `success=0`.
fn screenshot_failure_payload() -> Vec<u8> {
    0_u32.to_le_bytes().to_vec()
}

/// Build a `CommandScreenshot` callback payload with `success=1` but zero-length bytes.
fn screenshot_empty_bytes_payload() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&1_u32.to_le_bytes()); // success = 1
    p.extend_from_slice(&0_u32.to_le_bytes()); // length = 0
    p
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A screenshot callback carrying valid PNG bytes must:
///   1. Store a loot record in the database with `kind = "screenshot"` and
///      the raw image bytes as `data`.
///   2. Broadcast a loot-new `AgentResponse` event with `MiscType = "loot-new"`.
///   3. Broadcast a screenshot download-complete `AgentResponse` with
///      `MiscType = "screenshot"` and `Type = "Good"`.
#[tokio::test]
async fn screenshot_callback_stores_loot_and_broadcasts_events()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("screenshot-success-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("screenshot-success-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xFB01_0001_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xB0, 0xC3, 0xD6, 0xE9, 0xFC, 0x0F, 0x22, 0x35, 0x48, 0x5B, 0x6E, 0x81, 0x94, 0xA7, 0xBA,
        0xCD,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    // Consume the AgentNew broadcast from registration.
    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(
        matches!(agent_new, OperatorMessage::AgentNew(_)),
        "expected AgentNew, got {agent_new:?}"
    );

    // Minimal valid PNG header as test image data.
    let png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    let payload = screenshot_success_payload(&png);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandScreenshot),
            0x01,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // First broadcast: loot-new event.
    let loot_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(loot_msg) = loot_event else {
        panic!("expected AgentResponse (loot-new), got {loot_event:?}");
    };
    assert_eq!(
        loot_msg.info.extra.get("MiscType").and_then(|v| v.as_str()),
        Some("loot-new"),
        "loot event must have MiscType=loot-new"
    );

    // Second broadcast: screenshot download-complete response.
    let resp_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(resp_msg) = resp_event else {
        panic!("expected AgentResponse (screenshot), got {resp_event:?}");
    };
    assert_eq!(resp_msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(resp_msg.info.command_id, u32::from(DemonCommand::CommandScreenshot).to_string());
    assert_eq!(
        resp_msg.info.extra.get("MiscType").and_then(|v| v.as_str()),
        Some("screenshot"),
        "screenshot response must have MiscType=screenshot"
    );
    assert_eq!(
        resp_msg.info.extra.get("Type").and_then(|v| v.as_str()),
        Some("Good"),
        "screenshot response must have Type=Good"
    );

    // Verify MiscData contains the base64-encoded image bytes.
    let misc_data = resp_msg
        .info
        .extra
        .get("MiscData")
        .and_then(|v| v.as_str())
        .expect("screenshot response must contain MiscData");
    let decoded_bytes = BASE64_STANDARD.decode(misc_data).expect("MiscData must be valid base64");
    assert_eq!(decoded_bytes, png, "MiscData base64 must decode to the original PNG bytes");

    // Verify MiscData2 contains the generated screenshot filename.
    let misc_data2 = resp_msg
        .info
        .extra
        .get("MiscData2")
        .and_then(|v| v.as_str())
        .expect("screenshot response must contain MiscData2");
    assert!(
        misc_data2.starts_with("Desktop_") && misc_data2.ends_with(".png"),
        "MiscData2 should be a Desktop_*.png filename, got: {misc_data2}"
    );

    // Verify loot record is persisted in the database.
    let loot_records = server.database.loot().list_for_agent(agent_id).await?;
    assert_eq!(loot_records.len(), 1, "exactly one loot record must be stored");
    assert_eq!(loot_records[0].kind, "screenshot", "loot kind must be 'screenshot'");
    assert_eq!(loot_records[0].agent_id, agent_id);
    assert_eq!(
        loot_records[0].data.as_deref(),
        Some(png.as_slice()),
        "loot data must contain the raw image bytes"
    );

    // MiscData2 must match the persisted loot record name.
    assert_eq!(
        misc_data2, loot_records[0].name,
        "MiscData2 must match the persisted loot record name"
    );

    socket.close(None).await?;
    server.listeners.stop("screenshot-success-test").await?;
    Ok(())
}

/// A screenshot callback with `success=0` must broadcast an error `AgentResponse`
/// and must NOT create any loot record in the database.
#[tokio::test]
async fn screenshot_callback_failure_broadcasts_error_no_loot()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("screenshot-fail-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("screenshot-fail-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xFB01_0002_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34,
        0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xE5, 0xF8, 0x0B, 0x1E, 0x31, 0x44, 0x57, 0x6A, 0x7D, 0x90, 0xA3, 0xB6, 0xC9, 0xDC, 0xEF,
        0x02,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandScreenshot),
            0x02,
            &screenshot_failure_payload(),
        ))
        .send()
        .await?
        .error_for_status()?;

    // Must receive an error broadcast.
    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(
        msg.info.extra.get("Type").and_then(|v| v.as_str()),
        Some("Error"),
        "failed screenshot must broadcast Type=Error"
    );

    // No loot record should be stored.
    let loot_records = server.database.loot().list_for_agent(agent_id).await?;
    assert!(loot_records.is_empty(), "no loot must be stored for a failed screenshot");

    socket.close(None).await?;
    server.listeners.stop("screenshot-fail-test").await?;
    Ok(())
}

/// A screenshot callback with `success=1` but zero-length image data must broadcast
/// an error `AgentResponse` without panicking and must NOT create any loot record.
#[tokio::test]
async fn screenshot_callback_empty_bytes_broadcasts_error_no_loot()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("screenshot-empty-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("screenshot-empty-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xFB01_0003_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
        0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x69, 0x6A,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x1A, 0x2D, 0x40, 0x53, 0x66, 0x79, 0x8C, 0x9F, 0xB2, 0xC5, 0xD8, 0xEB, 0xFE, 0x11, 0x24,
        0x37,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandScreenshot),
            0x03,
            &screenshot_empty_bytes_payload(),
        ))
        .send()
        .await?
        .error_for_status()?;

    // Must receive an error broadcast — no panic.
    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    assert_eq!(
        msg.info.extra.get("Type").and_then(|v| v.as_str()),
        Some("Error"),
        "empty-bytes screenshot must broadcast Type=Error"
    );

    // No loot record should be stored.
    let loot_records = server.database.loot().list_for_agent(agent_id).await?;
    assert!(loot_records.is_empty(), "no loot must be stored for empty screenshot bytes");

    socket.close(None).await?;
    server.listeners.stop("screenshot-empty-test").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Truncated payload builders
// ---------------------------------------------------------------------------

/// Build a `CommandScreenshot` callback payload that has `success=1` but no
/// subsequent length-prefixed bytes — the payload ends right after the flag.
fn screenshot_truncated_after_success_flag() -> Vec<u8> {
    1_u32.to_le_bytes().to_vec() // success = 1, then EOF
}

/// Build a `CommandScreenshot` callback payload where the declared byte length
/// is larger than the bytes actually present.
fn screenshot_overstated_length_payload() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&1_u32.to_le_bytes()); // success = 1
    p.extend_from_slice(&1024_u32.to_le_bytes()); // claims 1024 bytes
    p.extend_from_slice(b"short"); // only 5 bytes
    p
}

// ---------------------------------------------------------------------------
// Truncated-input tests
// ---------------------------------------------------------------------------

/// A screenshot callback whose payload ends immediately after `success=1` (no
/// length prefix for the image bytes) must be rejected. No loot row should be
/// stored and no success event should be broadcast.
#[tokio::test]
async fn screenshot_callback_truncated_after_success_flag_rejects()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("screenshot-trunc-flag-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("screenshot-trunc-flag-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xFB01_0010_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E,
        0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D,
        0x8E, 0x8F,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x4F, 0x62, 0x75, 0x88, 0x9B, 0xAE, 0xC1, 0xD4, 0xE7, 0xFA, 0x0D, 0x20, 0x33, 0x46, 0x59,
        0x6C,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let resp = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandScreenshot),
            0x10,
            &screenshot_truncated_after_success_flag(),
        ))
        .send()
        .await?;

    assert!(
        !resp.status().is_success(),
        "truncated payload (no bytes after success=1) must not return 2xx, got {}",
        resp.status()
    );

    // No loot record should be stored.
    let loot_records = server.database.loot().list_for_agent(agent_id).await?;
    assert!(loot_records.is_empty(), "no loot must be stored for truncated screenshot payload");

    socket.close(None).await?;
    server.listeners.stop("screenshot-trunc-flag-test").await?;
    Ok(())
}

/// A screenshot callback whose byte-length prefix overstates the available
/// bytes must be rejected. No loot row should be stored and no success event
/// should be broadcast.
#[tokio::test]
async fn screenshot_callback_overstated_length_rejects() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("screenshot-overlen-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("screenshot-overlen-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xFB01_0011_u32;
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

    let resp = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandScreenshot),
            0x11,
            &screenshot_overstated_length_payload(),
        ))
        .send()
        .await?;

    assert!(
        !resp.status().is_success(),
        "overstated-length payload must not return 2xx, got {}",
        resp.status()
    );

    // No loot record should be stored.
    let loot_records = server.database.loot().list_for_agent(agent_id).await?;
    assert!(loot_records.is_empty(), "no loot must be stored for overstated-length screenshot");

    socket.close(None).await?;
    server.listeners.stop("screenshot-overlen-test").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Large-payload test
// ---------------------------------------------------------------------------

/// A screenshot callback carrying a very large image payload (2 MB of repeating
/// bytes) must be handled without panicking, corrupting data, or exceeding
/// memory limits.  The test verifies:
///   1. The loot record is stored with the correct size and data.
///   2. The loot-new and screenshot events are broadcast correctly.
///   3. The base64-encoded `MiscData` round-trips without corruption.
#[tokio::test]
async fn screenshot_callback_large_payload_stores_and_roundtrips()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (mut socket, _) = connect_async(server.ws_url()).await?;
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("screenshot-large-test", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("screenshot-large-test").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xFB01_0020_u32;
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

    // Consume the AgentNew broadcast from registration.
    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(
        matches!(agent_new, OperatorMessage::AgentNew(_)),
        "expected AgentNew, got {agent_new:?}"
    );

    // Build a 2 MB synthetic image payload (repeating byte pattern).
    const LARGE_SIZE: usize = 2 * 1024 * 1024; // 2 MB
    let large_image: Vec<u8> = (0..LARGE_SIZE).map(|i| (i % 251) as u8).collect();
    let payload = screenshot_success_payload(&large_image);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandScreenshot),
            0x20,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // First broadcast: loot-new event.
    let loot_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(loot_msg) = loot_event else {
        panic!("expected AgentResponse (loot-new), got {loot_event:?}");
    };
    assert_eq!(
        loot_msg.info.extra.get("MiscType").and_then(|v| v.as_str()),
        Some("loot-new"),
        "loot event must have MiscType=loot-new"
    );

    // Second broadcast: screenshot download-complete response.
    let resp_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(resp_msg) = resp_event else {
        panic!("expected AgentResponse (screenshot), got {resp_event:?}");
    };
    assert_eq!(resp_msg.info.demon_id, format!("{agent_id:08X}"));
    assert_eq!(
        resp_msg.info.extra.get("MiscType").and_then(|v| v.as_str()),
        Some("screenshot"),
        "screenshot response must have MiscType=screenshot"
    );
    assert_eq!(
        resp_msg.info.extra.get("Type").and_then(|v| v.as_str()),
        Some("Good"),
        "screenshot response must have Type=Good"
    );

    // Verify MiscData contains valid base64 that decodes to the original large payload.
    let misc_data = resp_msg
        .info
        .extra
        .get("MiscData")
        .and_then(|v| v.as_str())
        .expect("screenshot response must contain MiscData");
    let decoded_bytes = BASE64_STANDARD.decode(misc_data).expect("MiscData must be valid base64");
    assert_eq!(
        decoded_bytes.len(),
        LARGE_SIZE,
        "decoded MiscData length must match the original payload size"
    );
    assert_eq!(
        decoded_bytes, large_image,
        "MiscData base64 must decode to the original large image bytes"
    );

    // Verify MiscData2 contains the generated screenshot filename.
    let misc_data2 = resp_msg
        .info
        .extra
        .get("MiscData2")
        .and_then(|v| v.as_str())
        .expect("screenshot response must contain MiscData2");
    assert!(
        misc_data2.starts_with("Desktop_") && misc_data2.ends_with(".png"),
        "MiscData2 should be a Desktop_*.png filename, got: {misc_data2}"
    );

    // Verify loot record is persisted with the correct size and data.
    let loot_records = server.database.loot().list_for_agent(agent_id).await?;
    assert_eq!(loot_records.len(), 1, "exactly one loot record must be stored");
    assert_eq!(loot_records[0].kind, "screenshot", "loot kind must be 'screenshot'");
    assert_eq!(loot_records[0].agent_id, agent_id);
    let stored_data =
        loot_records[0].data.as_deref().expect("loot data must be present for large screenshot");
    assert_eq!(
        stored_data.len(),
        LARGE_SIZE,
        "persisted loot data length must match the original payload size"
    );
    assert_eq!(
        stored_data,
        large_image.as_slice(),
        "persisted loot data must match the original large image bytes"
    );

    // MiscData2 must match the persisted loot record name.
    assert_eq!(
        misc_data2, loot_records[0].name,
        "MiscData2 must match the persisted loot record name"
    );

    socket.close(None).await?;
    server.listeners.stop("screenshot-large-test").await?;
    Ok(())
}
