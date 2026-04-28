mod common;

use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use red_cell_common::demon::{DemonCommand, DemonConfigKey};
use red_cell_common::operator::OperatorMessage;
use tokio_tungstenite::connect_async;

/// Build a `CommandConfig/KillDate` payload: key(u32=154) + raw_date(u64).
fn config_kill_date_payload(raw_date: u64) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonConfigKey::KillDate).to_le_bytes());
    p.extend_from_slice(&raw_date.to_le_bytes());
    p
}

/// Build a `CommandConfig/WorkingHours` payload: key(u32=155) + raw(u32).
fn config_working_hours_payload(raw: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonConfigKey::WorkingHours).to_le_bytes());
    p.extend_from_slice(&raw.to_le_bytes());
    p
}

/// Build a `CommandConfig/MemoryAlloc` payload: key(u32=101) + value(u32).
fn config_memory_alloc_payload(value: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonConfigKey::MemoryAlloc).to_le_bytes());
    p.extend_from_slice(&value.to_le_bytes());
    p
}

/// Build a `CommandConfig` payload with an invalid key discriminant.
fn config_invalid_key_payload(key: u32) -> Vec<u8> {
    key.to_le_bytes().to_vec()
}

#[tokio::test]
async fn config_kill_date_set_broadcasts_and_updates_agent()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-cfg-kd-set", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-kd-set").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0070_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A,
        0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99,
        0x9A, 0x9B,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x1B, 0x2E, 0x41, 0x54, 0x67, 0x7A, 0x8D, 0xA0, 0xB3, 0xC6, 0xD9, 0xEC, 0xFF, 0x12, 0x25,
        0x38,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Non-zero kill date value (epoch timestamp).
    let payload = config_kill_date_payload(1_893_456_000);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xB0,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // First: AgentUpdate from the registry update.
    let update_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentUpdate(update_msg) = update_event else {
        panic!("expected AgentUpdate for config KillDate set, got {update_event:?}");
    };
    assert_eq!(update_msg.info.agent_id, format!("{agent_id:08X}"));

    // Second: AgentResponse with "KillDate has been set".
    let response_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(response_msg) = response_event else {
        panic!("expected AgentResponse for config KillDate set, got {response_event:?}");
    };
    assert_eq!(response_msg.info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
    assert_eq!(response_msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = response_msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("KillDate has been set"),
        "message should contain 'KillDate has been set': {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cfg-kd-set").await?;
    Ok(())
}

/// `handle_config_callback` with `KillDate` key and raw=0 must broadcast
/// "KillDate was disabled" and clear the agent's kill_date.
#[tokio::test]
async fn config_kill_date_zero_disables_and_broadcasts() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-cfg-kd-zero", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-kd-zero").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0071_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE,
        0xBF, 0xC0,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x50, 0x63, 0x76, 0x89, 0x9C, 0xAF, 0xC2, 0xD5, 0xE8, 0xFB, 0x0E, 0x21, 0x34, 0x47, 0x5A,
        0x6D,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = config_kill_date_payload(0);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xB1,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // First: AgentUpdate from the registry update.
    let update_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentUpdate(update_msg) = update_event else {
        panic!("expected AgentUpdate for config KillDate disable, got {update_event:?}");
    };
    assert_eq!(update_msg.info.agent_id, format!("{agent_id:08X}"));

    // Second: AgentResponse with "KillDate was disabled".
    let response_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(response_msg) = response_event else {
        panic!("expected AgentResponse for config KillDate disable, got {response_event:?}");
    };
    let message = response_msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("KillDate was disabled"),
        "message should contain 'KillDate was disabled': {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cfg-kd-zero").await?;
    Ok(())
}

/// `handle_config_callback` with `WorkingHours` key and a non-zero value must
/// broadcast "WorkingHours has been set" and update agent state.
#[tokio::test]
async fn config_working_hours_set_broadcasts_and_updates() -> Result<(), Box<dyn std::error::Error>>
{
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-cfg-wh-set", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-wh-set").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0072_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4,
        0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3,
        0xE4, 0xE5,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x85, 0x98, 0xAB, 0xBE, 0xD1, 0xE4, 0xF7, 0x0A, 0x1D, 0x30, 0x43, 0x56, 0x69, 0x7C, 0x8F,
        0xA2,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Non-zero working hours value.
    let payload = config_working_hours_payload(0b101010);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xB2,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // First: AgentUpdate.
    let update_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentUpdate(update_msg) = update_event else {
        panic!("expected AgentUpdate for config WorkingHours set, got {update_event:?}");
    };
    assert_eq!(update_msg.info.agent_id, format!("{agent_id:08X}"));

    // Second: AgentResponse.
    let response_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(response_msg) = response_event else {
        panic!("expected AgentResponse for config WorkingHours set, got {response_event:?}");
    };
    let message = response_msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("WorkingHours has been set"),
        "message should contain 'WorkingHours has been set': {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cfg-wh-set").await?;
    Ok(())
}

/// `handle_config_callback` with `WorkingHours` key and raw=0 must broadcast
/// "WorkingHours was disabled".
#[tokio::test]
async fn config_working_hours_zero_disables() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-cfg-wh-zero", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-wh-zero").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0073_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9,
        0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xBA, 0xCD, 0xE0, 0xF3, 0x06, 0x19, 0x2C, 0x3F, 0x52, 0x65, 0x78, 0x8B, 0x9E, 0xB1, 0xC4,
        0xD7,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = config_working_hours_payload(0);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xB3,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    // First: AgentUpdate.
    let update_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentUpdate(update_msg) = update_event else {
        panic!("expected AgentUpdate for config WorkingHours disable, got {update_event:?}");
    };
    assert_eq!(update_msg.info.agent_id, format!("{agent_id:08X}"));

    // Second: AgentResponse.
    let response_event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(response_msg) = response_event else {
        panic!("expected AgentResponse for config WorkingHours disable, got {response_event:?}");
    };
    let message = response_msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("WorkingHours was disabled"),
        "message should contain 'WorkingHours was disabled': {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cfg-wh-zero").await?;
    Ok(())
}

/// `handle_config_callback` with `MemoryAlloc` key must broadcast an `AgentResponse`
/// with the allocation value in the message.
#[tokio::test]
async fn config_memory_alloc_broadcasts_value() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cfg-memalloc", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-memalloc").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0074_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D,
        0x2E, 0x2F,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xEF, 0x02, 0x15, 0x28, 0x3B, 0x4E, 0x61, 0x74, 0x87, 0x9A, 0xAD, 0xC0, 0xD3, 0xE6, 0xF9,
        0x0C,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let alloc_value = 64_u32; // PAGE_EXECUTE_READWRITE
    let payload = config_memory_alloc_payload(alloc_value);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xB4,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for config MemoryAlloc, got {event:?}");
    };
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("memory allocation")
            || message.contains("Memory Alloc")
            || message.contains("memory alloc"),
        "message should mention memory allocation: {message:?}"
    );
    assert!(
        message.contains(&alloc_value.to_string()),
        "message should contain alloc value {alloc_value}: {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cfg-memalloc").await?;
    Ok(())
}

/// `handle_config_callback` with an invalid config key must return a non-2xx
/// HTTP status (`InvalidCallbackPayload`) and must NOT broadcast.
#[tokio::test]
async fn config_invalid_key_returns_error() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-cfg-bad-key", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-bad-key").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0075_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43,
        0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52,
        0x53, 0x54,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x24, 0x37, 0x4A, 0x5D, 0x70, 0x83, 0x96, 0xA9, 0xBC, 0xCF, 0xE2, 0xF5, 0x08, 0x1B, 0x2E,
        0x41,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // 0xFFFF is not a valid DemonConfigKey.
    let payload = config_invalid_key_payload(0xFFFF);

    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xB5,
            &payload,
        ))
        .send()
        .await?;

    assert!(
        !response.status().is_success(),
        "invalid config key should return error, got {}",
        response.status()
    );

    common::skip_optional_teamserver_log(&mut socket, std::time::Duration::from_millis(200)).await;
    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(200)).await;

    socket.close(None).await?;
    server.listeners.stop("out-cfg-bad-key").await?;
    Ok(())
}

// ── handle_config_callback — remaining branches ─────────────────────────────

/// Build a `CommandConfig/MemoryExecute` payload: key(u32=102) + value(u32).
fn config_memory_execute_payload(value: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonConfigKey::MemoryExecute).to_le_bytes());
    p.extend_from_slice(&value.to_le_bytes());
    p
}

/// Encode a UTF-16LE length-prefixed field (u32 byte-length + UTF-16LE data).
fn encode_utf16_field(s: &str) -> Vec<u8> {
    let utf16: Vec<u16> = s.encode_utf16().collect();
    let byte_len = (utf16.len() * 2) as u32;
    let mut p = Vec::new();
    p.extend_from_slice(&byte_len.to_le_bytes());
    for word in &utf16 {
        p.extend_from_slice(&word.to_le_bytes());
    }
    p
}

/// Encode a UTF-8 length-prefixed field (u32 byte-length + UTF-8 data).
fn encode_string_field(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut p = Vec::new();
    p.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    p.extend_from_slice(bytes);
    p
}

/// Build a `CommandConfig/InjectSpawn64` payload: key(u32=152) + utf16 path.
fn config_inject_spawn64_payload(path: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonConfigKey::InjectSpawn64).to_le_bytes());
    p.extend(encode_utf16_field(path));
    p
}

/// Build a `CommandConfig/InjectSpawn32` payload: key(u32=153) + utf16 path.
fn config_inject_spawn32_payload(path: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonConfigKey::InjectSpawn32).to_le_bytes());
    p.extend(encode_utf16_field(path));
    p
}

/// Build a `CommandConfig/ImplantSpfThreadStart` payload: key(u32=3) + string module + string symbol.
fn config_spf_thread_start_payload(module: &str, symbol: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonConfigKey::ImplantSpfThreadStart).to_le_bytes());
    p.extend(encode_string_field(module));
    p.extend(encode_string_field(symbol));
    p
}

/// Build a `CommandConfig/ImplantSleepTechnique` payload: key(u32=5) + value(u32).
fn config_sleep_technique_payload(value: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonConfigKey::ImplantSleepTechnique).to_le_bytes());
    p.extend_from_slice(&value.to_le_bytes());
    p
}

/// Build a `CommandConfig/ImplantCoffeeVeh` payload: key(u32=7) + bool(u32).
fn config_coffee_veh_payload(enabled: bool) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonConfigKey::ImplantCoffeeVeh).to_le_bytes());
    p.extend_from_slice(&u32::from(enabled).to_le_bytes());
    p
}

/// Build a `CommandConfig/ImplantCoffeeThreaded` payload: key(u32=6) + bool(u32).
fn config_coffee_threaded_payload(enabled: bool) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonConfigKey::ImplantCoffeeThreaded).to_le_bytes());
    p.extend_from_slice(&u32::from(enabled).to_le_bytes());
    p
}

/// Build a `CommandConfig/InjectTechnique` payload: key(u32=150) + value(u32).
fn config_inject_technique_payload(value: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonConfigKey::InjectTechnique).to_le_bytes());
    p.extend_from_slice(&value.to_le_bytes());
    p
}

/// Build a `CommandConfig/InjectSpoofAddr` payload: key(u32=151) + string module + string symbol.
fn config_inject_spoof_addr_payload(module: &str, symbol: &str) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonConfigKey::InjectSpoofAddr).to_le_bytes());
    p.extend(encode_string_field(module));
    p.extend(encode_string_field(symbol));
    p
}

/// Build a `CommandConfig/ImplantVerbose` payload: key(u32=4) + bool(u32).
fn config_implant_verbose_payload(enabled: bool) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&u32::from(DemonConfigKey::ImplantVerbose).to_le_bytes());
    p.extend_from_slice(&u32::from(enabled).to_le_bytes());
    p
}

/// `handle_config_callback` with `MemoryExecute` broadcasts a message containing
/// the execute protection value.
#[tokio::test]
async fn config_memory_execute_broadcasts_value() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-cfg-memexec", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-memexec").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0080_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC,
        0xFD, 0xFE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        0x0C, 0x0D,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x2D, 0x40, 0x53, 0x66, 0x79, 0x8C, 0x9F, 0xB2, 0xC5, 0xD8, 0xEB, 0xFE, 0x11, 0x24, 0x37,
        0x4A,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let exec_value = 32_u32;
    let payload = config_memory_execute_payload(exec_value);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xC0,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for config MemoryExecute, got {event:?}");
    };
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("memory executing") || message.contains("Memory Execute"),
        "message should mention memory executing: {message:?}"
    );
    assert!(
        message.contains(&exec_value.to_string()),
        "message should contain execute value {exec_value}: {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cfg-memexec").await?;
    Ok(())
}

/// `handle_config_callback` with `InjectSpawn64` broadcasts the x64 target process path.
#[tokio::test]
async fn config_inject_spawn64_broadcasts_path() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-cfg-spawn64", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-spawn64").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0081_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21,
        0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
        0x31, 0x32,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x62, 0x75, 0x88, 0x9B, 0xAE, 0xC1, 0xD4, 0xE7, 0xFA, 0x0D, 0x20, 0x33, 0x46, 0x59, 0x6C,
        0x7F,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let target_path = r"C:\Windows\System32\notepad.exe";
    let payload = config_inject_spawn64_payload(target_path);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xC1,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for config InjectSpawn64, got {event:?}");
    };
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("x64") || message.contains("64"),
        "message should mention x64: {message:?}"
    );
    assert!(
        message.contains("notepad.exe"),
        "message should contain the target process path: {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cfg-spawn64").await?;
    Ok(())
}

/// `handle_config_callback` with `InjectSpawn32` broadcasts the x86 target process path.
#[tokio::test]
async fn config_inject_spawn32_broadcasts_path() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-cfg-spawn32", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-spawn32").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0082_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
        0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
        0x56, 0x57,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x97, 0xAA, 0xBD, 0xD0, 0xE3, 0xF6, 0x09, 0x1C, 0x2F, 0x42, 0x55, 0x68, 0x7B, 0x8E, 0xA1,
        0xB4,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let target_path = r"C:\Windows\SysWOW64\cmd.exe";
    let payload = config_inject_spawn32_payload(target_path);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xC2,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for config InjectSpawn32, got {event:?}");
    };
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("x86") || message.contains("32"),
        "message should mention x86: {message:?}"
    );
    assert!(
        message.contains("cmd.exe"),
        "message should contain the target process path: {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cfg-spawn32").await?;
    Ok(())
}

/// `handle_config_callback` with `ImplantSpfThreadStart` broadcasts module!symbol.
#[tokio::test]
async fn config_spf_thread_start_broadcasts_module_symbol() -> Result<(), Box<dyn std::error::Error>>
{
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cfg-spfthread", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-spfthread").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0083_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B,
        0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A,
        0x7B, 0x7C,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xCC, 0xDF, 0xF2, 0x05, 0x18, 0x2B, 0x3E, 0x51, 0x64, 0x77, 0x8A, 0x9D, 0xB0, 0xC3, 0xD6,
        0xE9,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = config_spf_thread_start_payload("ntdll.dll", "RtlUserThreadStart");

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xC3,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for config ImplantSpfThreadStart, got {event:?}");
    };
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("ntdll.dll") && message.contains("RtlUserThreadStart"),
        "message should contain module!symbol: {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cfg-spfthread").await?;
    Ok(())
}

/// `handle_config_callback` with `ImplantSleepTechnique` broadcasts the technique value.
#[tokio::test]
async fn config_sleep_technique_broadcasts_value() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cfg-sleeptech", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-sleeptech").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0084_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90,
        0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
        0xA0, 0xA1,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x01, 0x14, 0x27, 0x3A, 0x4D, 0x60, 0x73, 0x86, 0x99, 0xAC, 0xBF, 0xD2, 0xE5, 0xF8, 0x0B,
        0x1E,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let technique = 2_u32;
    let payload = config_sleep_technique_payload(technique);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xC4,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for config ImplantSleepTechnique, got {event:?}");
    };
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("obfuscation") || message.contains("Sleep"),
        "message should mention sleep obfuscation: {message:?}"
    );
    assert!(
        message.contains(&technique.to_string()),
        "message should contain technique value {technique}: {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cfg-sleeptech").await?;
    Ok(())
}

/// `handle_config_callback` with `ImplantCoffeeVeh` (true) broadcasts enabled status.
#[tokio::test]
async fn config_coffee_veh_true_broadcasts_enabled() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cfg-coffeeveh", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-coffeeveh").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0085_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
        0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4,
        0xC5, 0xC6,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x36, 0x49, 0x5C, 0x6F, 0x82, 0x95, 0xA8, 0xBB, 0xCE, 0xE1, 0xF4, 0x07, 0x1A, 0x2D, 0x40,
        0x53,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = config_coffee_veh_payload(true);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xC5,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for config ImplantCoffeeVeh, got {event:?}");
    };
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("VEH") || message.contains("veh"),
        "message should mention Coffee VEH: {message:?}"
    );
    assert!(message.contains("true"), "message should contain 'true': {message:?}");

    socket.close(None).await?;
    server.listeners.stop("out-cfg-coffeeveh").await?;
    Ok(())
}

/// `handle_config_callback` with `ImplantCoffeeThreaded` (false) broadcasts disabled status.
#[tokio::test]
async fn config_coffee_threaded_false_broadcasts_disabled() -> Result<(), Box<dyn std::error::Error>>
{
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cfg-coffeethread", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-coffeethread").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0086_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA,
        0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9,
        0xEA, 0xEB,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x6B, 0x7E, 0x91, 0xA4, 0xB7, 0xCA, 0xDD, 0xF0, 0x03, 0x16, 0x29, 0x3C, 0x4F, 0x62, 0x75,
        0x88,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = config_coffee_threaded_payload(false);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xC6,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for config ImplantCoffeeThreaded, got {event:?}");
    };
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("threading") || message.contains("Coffee"),
        "message should mention coffee threading: {message:?}"
    );
    assert!(message.contains("false"), "message should contain 'false': {message:?}");

    socket.close(None).await?;
    server.listeners.stop("out-cfg-coffeethread").await?;
    Ok(())
}

/// `handle_config_callback` with `InjectTechnique` broadcasts the injection technique value.
#[tokio::test]
async fn config_inject_technique_broadcasts_value() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cfg-injecttech", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-injecttech").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0087_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xA0, 0xB3, 0xC6, 0xD9, 0xEC, 0xFF, 0x12, 0x25, 0x38, 0x4B, 0x5E, 0x71, 0x84, 0x97, 0xAA,
        0xBD,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let technique = 3_u32;
    let payload = config_inject_technique_payload(technique);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xC7,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for config InjectTechnique, got {event:?}");
    };
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("injection technique") || message.contains("inject"),
        "message should mention injection technique: {message:?}"
    );
    assert!(
        message.contains(&technique.to_string()),
        "message should contain technique value {technique}: {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cfg-injecttech").await?;
    Ok(())
}

/// `handle_config_callback` with `InjectSpoofAddr` broadcasts module!symbol for spoofing.
#[tokio::test]
async fn config_inject_spoof_addr_broadcasts_module_symbol()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server
        .listeners
        .create(common::http_listener_config("out-cfg-injectspoof", listener_port))
        .await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-injectspoof").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0088_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
        0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33,
        0x34, 0x35,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xD5, 0xE8, 0xFB, 0x0E, 0x21, 0x34, 0x47, 0x5A, 0x6D, 0x80, 0x93, 0xA6, 0xB9, 0xCC, 0xDF,
        0xF2,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = config_inject_spoof_addr_payload("kernel32.dll", "CreateThread");

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xC8,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for config InjectSpoofAddr, got {event:?}");
    };
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("kernel32.dll") && message.contains("CreateThread"),
        "message should contain module!symbol: {message:?}"
    );

    socket.close(None).await?;
    server.listeners.stop("out-cfg-injectspoof").await?;
    Ok(())
}

/// `handle_config_callback` with `ImplantVerbose` (true) broadcasts verbose enabled.
#[tokio::test]
async fn config_implant_verbose_broadcasts_value() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(common::default_test_profile()).await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(server.ws_url()).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    server.listeners.create(common::http_listener_config("out-cfg-verbose", listener_port)).await?;
    drop(listener_guard);
    server.listeners.start("out-cfg-verbose").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xDEAD_0089_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
        0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        0x59, 0x5A,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x0A, 0x1D, 0x30, 0x43, 0x56, 0x69, 0x7C, 0x8F, 0xA2, 0xB5, 0xC8, 0xDB, 0xEE, 0x01, 0x14,
        0x27,
    ];
    let ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = config_implant_verbose_payload(true);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandConfig),
            0xC9,
            &payload,
        ))
        .send()
        .await?
        .error_for_status()?;

    let event = common::read_operator_message(&mut socket).await?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for config ImplantVerbose, got {event:?}");
    };
    assert_eq!(msg.info.command_id, u32::from(DemonCommand::CommandConfig).to_string());
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));

    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        message.contains("verbose") || message.contains("Verbose"),
        "message should mention verbose: {message:?}"
    );
    assert!(message.contains("true"), "message should contain 'true': {message:?}");

    socket.close(None).await?;
    server.listeners.stop("out-cfg-verbose").await?;
    Ok(())
}

// ── handle_command_output_callback truncated payload tests ──────────────────
