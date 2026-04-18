//! `CommandAssemblyInlineExecute` and `CommandAssemblyListVersions` callback dispatch tests.

use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::OperatorMessage;
use tokio_tungstenite::connect_async;

use super::common;
use super::helpers::{
    assembly_clr_version_payload, assembly_entrypoint_executed_payload, assembly_failed_payload,
    assembly_finished_payload, assembly_list_versions_payload, assembly_patched_payload,
    assembly_unknown_info_id_payload, register_agent, start_server,
};

/// `handle_assembly_list_versions_callback` must broadcast a formatted list of
/// available CLR version strings to the operator, one per line.
#[tokio::test]
async fn assembly_list_versions_broadcasts_formatted_list() -> Result<(), Box<dyn std::error::Error>>
{
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(format!("ws://{server_addr}/havoc")).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("asm-test-list-ver", listener_port)).await?;
    drop(listener_guard);
    listeners.start("asm-test-list-ver").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xAB01_0003_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E,
        0x5F, 0x60,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9A, 0xAB, 0xBC, 0xCD, 0xDE, 0xEF, 0xF0,
        0x01,
    ];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let versions = ["v4.0.30319", "v2.0.50727"];
    let payload = assembly_list_versions_payload(&versions);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandAssemblyListVersions),
            0x30,
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
    assert_eq!(
        msg.info.command_id,
        u32::from(DemonCommand::CommandAssemblyListVersions).to_string()
    );
    // The output must contain each version prefixed with "   - ".
    for v in &versions {
        assert!(
            msg.info.output.contains(&format!("   - {v}")),
            "output missing version {v}: {:?}",
            msg.info.output
        );
    }

    socket.close(None).await?;
    listeners.stop("asm-test-list-ver").await?;
    Ok(())
}

/// `handle_assembly_list_versions_callback` with an empty payload (zero versions)
/// must broadcast a valid `AgentResponse` without panicking.
#[tokio::test]
async fn assembly_list_versions_empty_payload_broadcasts_gracefully()
-> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(format!("ws://{server_addr}/havoc")).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    listeners
        .create(common::http_listener_config("asm-test-list-ver-empty", listener_port))
        .await?;
    drop(listener_guard);
    listeners.start("asm-test-list-ver-empty").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xAB01_0004_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E,
        0x7F, 0x80,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A, 0x69,
        0x78,
    ];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    // Send a CommandAssemblyListVersions callback with an empty payload (zero versions).
    let payload = assembly_list_versions_payload(&[]);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandAssemblyListVersions),
            0x30,
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
    assert_eq!(
        msg.info.command_id,
        u32::from(DemonCommand::CommandAssemblyListVersions).to_string()
    );
    // With zero versions the output section should be empty (no version lines).
    assert!(
        msg.info.output.is_empty(),
        "expected empty output for zero versions, got {:?}",
        msg.info.output
    );

    socket.close(None).await?;
    listeners.stop("asm-test-list-ver-empty").await?;
    Ok(())
}

/// `handle_assembly_inline_execute_callback` with DOTNET_INFO_NET_VERSION must
/// broadcast the parsed CLR version string to the operator.
#[tokio::test]
async fn assembly_inline_execute_clr_version_broadcast() -> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(format!("ws://{server_addr}/havoc")).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("asm-test-clr-ver", listener_port)).await?;
    drop(listener_guard);
    listeners.start("asm-test-clr-ver").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xAB01_0004_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E,
        0x9F, 0xA0,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let clr_version = "v4.0.30319";
    let payload = assembly_clr_version_payload(clr_version);

    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandAssemblyInlineExecute),
            0x40,
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
    assert_eq!(
        msg.info.command_id,
        u32::from(DemonCommand::CommandAssemblyInlineExecute).to_string()
    );
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Info"));
    assert!(
        msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("").contains(clr_version),
        "message should contain CLR version string: {:?}",
        msg.info.extra.get("Message")
    );

    socket.close(None).await?;
    listeners.stop("asm-test-clr-ver").await?;
    Ok(())
}

/// `handle_assembly_inline_execute_callback` with DOTNET_INFO_PATCHED must
/// broadcast an `AgentResponse` with kind "Info" and a message mentioning Amsi/Etw patching.
#[tokio::test]
async fn assembly_inline_execute_patched_broadcasts_info() -> Result<(), Box<dyn std::error::Error>>
{
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(format!("ws://{server_addr}/havoc")).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("asm-test-patched", listener_port)).await?;
    drop(listener_guard);
    listeners.start("asm-test-patched").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xAB01_000A_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F,
        0x90, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF, 0x01,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x5E, 0x6F, 0x70, 0x81, 0x92, 0xA3, 0xB4, 0xC5, 0xD6, 0xE7, 0xF8, 0x09, 0x1A, 0x2B, 0x3C,
        0x4D,
    ];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = assembly_patched_payload();
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandAssemblyInlineExecute),
            0xA0,
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
    assert_eq!(
        msg.info.command_id,
        u32::from(DemonCommand::CommandAssemblyInlineExecute).to_string()
    );
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Info"));
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).expect("Message field");
    assert!(
        message.contains("Amsi/Etw"),
        "expected patched message to mention Amsi/Etw, got {message:?}"
    );

    socket.close(None).await?;
    listeners.stop("asm-test-patched").await?;
    Ok(())
}

/// `handle_assembly_inline_execute_callback` with DOTNET_INFO_ENTRYPOINT_EXECUTED must
/// broadcast an `AgentResponse` with kind "Good" and a message containing the thread ID.
#[tokio::test]
async fn assembly_inline_execute_entrypoint_executed_broadcasts_thread_id()
-> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(format!("ws://{server_addr}/havoc")).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("asm-test-entry", listener_port)).await?;
    drop(listener_guard);
    listeners.start("asm-test-entry").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xAB01_000B_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8A, 0x9B, 0xAC, 0xBD, 0xCE, 0xDF, 0xE0, 0xF1,
        0x02, 0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7A, 0x8B, 0x9C, 0xAD, 0xBE, 0xCF, 0xD0, 0xE1,
        0xF2, 0x03,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x6F, 0x70, 0x81, 0x92, 0xA3, 0xB4, 0xC5, 0xD6, 0xE7, 0xF8, 0x09, 0x1A, 0x2B, 0x3C, 0x4D,
        0x5E,
    ];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let thread_id = 4242_u32;
    let payload = assembly_entrypoint_executed_payload(thread_id);
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandAssemblyInlineExecute),
            0xB0,
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
    assert_eq!(
        msg.info.command_id,
        u32::from(DemonCommand::CommandAssemblyInlineExecute).to_string()
    );
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).expect("Message field");
    assert!(message.contains("4242"), "expected thread id in message, got {message:?}");
    assert!(message.contains("Thread"), "expected 'Thread' label in message, got {message:?}");

    socket.close(None).await?;
    listeners.stop("asm-test-entry").await?;
    Ok(())
}

/// `handle_assembly_inline_execute_callback` with DOTNET_INFO_FINISHED must
/// broadcast an `AgentResponse` with kind "Good" and a completion message.
#[tokio::test]
async fn assembly_inline_execute_finished_broadcasts_good() -> Result<(), Box<dyn std::error::Error>>
{
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(format!("ws://{server_addr}/havoc")).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("asm-test-finished", listener_port)).await?;
    drop(listener_guard);
    listeners.start("asm-test-finished").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xAB01_000C_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x25, 0x36, 0x47, 0x58, 0x69, 0x7A, 0x8B, 0x9C, 0xAD, 0xBE, 0xCF, 0xD0, 0xE1, 0xF2, 0x03,
        0x14, 0x26, 0x37, 0x48, 0x59, 0x6A, 0x7B, 0x8C, 0x9D, 0xAE, 0xBF, 0xC0, 0xD1, 0xE2, 0xF3,
        0x04, 0x15,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x70, 0x81, 0x92, 0xA3, 0xB4, 0xC5, 0xD6, 0xE7, 0xF8, 0x09, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E,
        0x6F,
    ];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = assembly_finished_payload();
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandAssemblyInlineExecute),
            0xC0,
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
    assert_eq!(
        msg.info.command_id,
        u32::from(DemonCommand::CommandAssemblyInlineExecute).to_string()
    );
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).expect("Message field");
    assert!(message.contains("Finished"), "expected 'Finished' in message, got {message:?}");

    socket.close(None).await?;
    listeners.stop("asm-test-finished").await?;
    Ok(())
}

/// `handle_assembly_inline_execute_callback` with DOTNET_INFO_FAILED must
/// broadcast an `AgentResponse` with kind "Error" and a failure message.
#[tokio::test]
async fn assembly_inline_execute_failed_broadcasts_error() -> Result<(), Box<dyn std::error::Error>>
{
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(format!("ws://{server_addr}/havoc")).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("asm-test-failed", listener_port)).await?;
    drop(listener_guard);
    listeners.start("asm-test-failed").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xAB01_000D_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x37, 0x48, 0x59, 0x6A, 0x7B, 0x8C, 0x9D, 0xAE, 0xBF, 0xC0, 0xD1, 0xE2, 0xF3, 0x04, 0x15,
        0x26, 0x38, 0x49, 0x5A, 0x6B, 0x7C, 0x8D, 0x9E, 0xAF, 0xB0, 0xC1, 0xD2, 0xE3, 0xF4, 0x05,
        0x16, 0x27,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x81, 0x92, 0xA3, 0xB4, 0xC5, 0xD6, 0xE7, 0xF8, 0x09, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F,
        0x70,
    ];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = assembly_failed_payload();
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandAssemblyInlineExecute),
            0xD0,
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
    assert_eq!(
        msg.info.command_id,
        u32::from(DemonCommand::CommandAssemblyInlineExecute).to_string()
    );
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).expect("Message field");
    assert!(message.contains("Failed"), "expected 'Failed' in message, got {message:?}");

    socket.close(None).await?;
    listeners.stop("asm-test-failed").await?;
    Ok(())
}

/// An unknown info-id for `CommandAssemblyInlineExecute` must succeed at the HTTP layer
/// but must NOT broadcast any operator message — unknown IDs are silently ignored.
#[tokio::test]
async fn assembly_inline_execute_unknown_info_id_no_broadcast()
-> Result<(), Box<dyn std::error::Error>> {
    let (server_addr, listeners) = start_server().await?;
    let (listener_port, listener_guard) = common::available_port_excluding(server_addr.port())?;
    let client = reqwest::Client::new();

    let (raw_socket_, _) = connect_async(format!("ws://{server_addr}/havoc")).await?;
    let mut socket = common::WsSession::new(raw_socket_);
    common::login(&mut socket).await?;

    listeners.create(common::http_listener_config("asm-test-unk-id", listener_port)).await?;
    drop(listener_guard);
    listeners.start("asm-test-unk-id").await?;
    common::wait_for_listener(listener_port).await?;

    let agent_id = 0xAB01_000E_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x49, 0x5A, 0x6B, 0x7C, 0x8D, 0x9E, 0xAF, 0xB0, 0xC1, 0xD2, 0xE3, 0xF4, 0x05, 0x16, 0x27,
        0x38, 0x4A, 0x5B, 0x6C, 0x7D, 0x8E, 0x9F, 0xA0, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5, 0x06, 0x17,
        0x28, 0x39,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x92, 0xA3, 0xB4, 0xC5, 0xD6, 0xE7, 0xF8, 0x09, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70,
        0x81,
    ];
    let ctr_offset = register_agent(&client, listener_port, agent_id, key, iv).await?;

    let agent_new = common::read_operator_message(&mut socket).await?;
    assert!(matches!(agent_new, OperatorMessage::AgentNew(_)));

    let payload = assembly_unknown_info_id_payload(0xBEEF);
    let response = client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandAssemblyInlineExecute),
            0xE0,
            &payload,
        ))
        .send()
        .await?;
    assert!(
        response.status().is_success(),
        "HTTP callback should succeed for unknown assembly info-id"
    );

    // No operator message should be broadcast for an unknown info-id.
    common::assert_no_operator_message(&mut socket, std::time::Duration::from_millis(250)).await;

    socket.close(None).await?;
    listeners.stop("asm-test-unk-id").await?;
    Ok(())
}
