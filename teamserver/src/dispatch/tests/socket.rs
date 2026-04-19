//! Tests for socket command dispatch (SOCKS, rportfwd, socket read/write/connect/close).

use super::common::*;

use super::super::socket::handle_socket_callback;
use super::super::{CommandDispatchError, CommandDispatcher};
use crate::{AgentRegistry, Database, EventBus, SocketRelayManager};
use red_cell_common::demon::{DemonCommand, DemonSocketCommand, DemonSocketType};
use red_cell_common::operator::OperatorMessage;
use serde_json::Value;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Duration, timeout},
};

#[tokio::test]
async fn socket_read_callback_broadcasts_error_when_relay_delivery_fails()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonSocketCommand::Read));
    add_u32(&mut payload, 0x55);
    add_u32(&mut payload, u32::from(DemonSocketType::ReverseProxy));
    add_u32(&mut payload, 1);
    add_bytes(&mut payload, b"hello");

    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandSocket), 27, &payload).await?;

    let event = receiver.recv().await.ok_or("socket relay delivery error missing")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    let msg = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("Failed to deliver socks data for 85"));
    assert!(msg.contains("SOCKS5 client 0x00000055 not found"));
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    Ok(())
}

#[tokio::test]
async fn socket_rportfwd_add_callback_broadcasts_success_and_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut success = Vec::new();
    add_u32(&mut success, u32::from(DemonSocketCommand::ReversePortForwardAdd));
    add_u32(&mut success, 1);
    add_u32(&mut success, 0x55);
    add_u32(&mut success, u32::from_le_bytes([127, 0, 0, 1]));
    add_u32(&mut success, 4444);
    add_u32(&mut success, u32::from_le_bytes([10, 0, 0, 5]));
    add_u32(&mut success, 8080);

    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandSocket), 28, &success).await?;

    let success_event = receiver.recv().await.ok_or("missing rportfwd add success event")?;
    let OperatorMessage::AgentResponse(success_message) = success_event else {
        panic!("expected agent response event");
    };
    assert_eq!(success_message.info.extra.get("Type"), Some(&Value::String("Info".to_owned())));
    assert_eq!(
        success_message.info.extra.get("Message"),
        Some(&Value::String(
            "Started reverse port forward on 127.0.0.1:4444 to 10.0.0.5:8080 [Id: 55]".to_owned(),
        ))
    );

    let mut failure = Vec::new();
    add_u32(&mut failure, u32::from(DemonSocketCommand::ReversePortForwardAdd));
    add_u32(&mut failure, 0);
    add_u32(&mut failure, 0x66);
    add_u32(&mut failure, u32::from_le_bytes([192, 168, 1, 10]));
    add_u32(&mut failure, 9001);
    add_u32(&mut failure, u32::from_le_bytes([172, 16, 1, 20]));
    add_u32(&mut failure, 22);

    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandSocket), 29, &failure).await?;

    let failure_event = receiver.recv().await.ok_or("missing rportfwd add failure event")?;
    let OperatorMessage::AgentResponse(failure_message) = failure_event else {
        panic!("expected agent response event");
    };
    assert_eq!(failure_message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    assert_eq!(
        failure_message.info.extra.get("Message"),
        Some(&Value::String(
            "Failed to start reverse port forward on 192.168.1.10:9001 to 172.16.1.20:22"
                .to_owned(),
        ))
    );
    Ok(())
}

#[tokio::test]
async fn socket_rportfwd_list_callback_formats_output_rows()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonSocketCommand::ReversePortForwardList));
    add_u32(&mut payload, 0x21);
    add_u32(&mut payload, u32::from_le_bytes([127, 0, 0, 1]));
    add_u32(&mut payload, 8080);
    add_u32(&mut payload, u32::from_le_bytes([10, 0, 0, 8]));
    add_u32(&mut payload, 80);
    add_u32(&mut payload, 0x22);
    add_u32(&mut payload, u32::from_le_bytes([0, 0, 0, 0]));
    add_u32(&mut payload, 8443);
    add_u32(&mut payload, u32::from_le_bytes([192, 168, 56, 10]));
    add_u32(&mut payload, 443);

    dispatcher.dispatch(0xCAFE_BABE, u32::from(DemonCommand::CommandSocket), 30, &payload).await?;

    let event = receiver.recv().await.ok_or("missing rportfwd list event")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Info".to_owned())));
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("reverse port forwards:".to_owned()))
    );
    assert!(message.info.output.contains("Socket ID"));
    assert!(message.info.output.contains("21           127.0.0.1:8080 -> 10.0.0.8:80"));
    assert!(message.info.output.contains("22           0.0.0.0:8443 -> 192.168.56.10:443"));
    Ok(())
}

#[tokio::test]
async fn socket_rportfwd_remove_callback_only_broadcasts_for_rportfwd_type()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonSocketCommand::ReversePortForwardRemove));
    add_u32(&mut payload, 0x88);
    add_u32(&mut payload, u32::from(DemonSocketType::ReversePortForward));
    add_u32(&mut payload, u32::from_le_bytes([127, 0, 0, 1]));
    add_u32(&mut payload, 7000);
    add_u32(&mut payload, u32::from_le_bytes([10, 10, 10, 10]));
    add_u32(&mut payload, 3389);

    dispatcher.dispatch(0xBEEF_CAFE, u32::from(DemonCommand::CommandSocket), 31, &payload).await?;

    let event = receiver.recv().await.ok_or("missing rportfwd remove event")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Info".to_owned())));
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String(
            "Successful closed and removed rportfwd [SocketID: 88] [Forward: 127.0.0.1:7000 -> 10.10.10.10:3389]"
                .to_owned(),
        ))
    );

    let mut other_type = Vec::new();
    add_u32(&mut other_type, u32::from(DemonSocketCommand::ReversePortForwardRemove));
    add_u32(&mut other_type, 0x99);
    add_u32(&mut other_type, u32::from(DemonSocketType::ReverseProxy));
    add_u32(&mut other_type, u32::from_le_bytes([127, 0, 0, 1]));
    add_u32(&mut other_type, 7001);
    add_u32(&mut other_type, u32::from_le_bytes([10, 10, 10, 11]));
    add_u32(&mut other_type, 3390);

    dispatcher
        .dispatch(0xBEEF_CAFE, u32::from(DemonCommand::CommandSocket), 32, &other_type)
        .await?;

    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "non-rportfwd remove should not broadcast an event"
    );
    Ok(())
}

#[tokio::test]
async fn socket_rportfwd_clear_callback_broadcasts_success_and_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut success = Vec::new();
    add_u32(&mut success, u32::from(DemonSocketCommand::ReversePortForwardClear));
    add_u32(&mut success, 1);
    dispatcher.dispatch(0xDEAD_BEEF, u32::from(DemonCommand::CommandSocket), 33, &success).await?;

    let success_event = receiver.recv().await.ok_or("missing rportfwd clear success event")?;
    let OperatorMessage::AgentResponse(success_message) = success_event else {
        panic!("expected agent response event");
    };
    assert_eq!(success_message.info.extra.get("Type"), Some(&Value::String("Good".to_owned())));
    assert_eq!(
        success_message.info.extra.get("Message"),
        Some(&Value::String("Successful closed and removed all rportfwds".to_owned()))
    );

    let mut failure = Vec::new();
    add_u32(&mut failure, u32::from(DemonSocketCommand::ReversePortForwardClear));
    add_u32(&mut failure, 0);
    dispatcher.dispatch(0xDEAD_BEEF, u32::from(DemonCommand::CommandSocket), 34, &failure).await?;

    let failure_event = receiver.recv().await.ok_or("missing rportfwd clear failure event")?;
    let OperatorMessage::AgentResponse(failure_message) = failure_event else {
        panic!("expected agent response event");
    };
    assert_eq!(failure_message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    assert_eq!(
        failure_message.info.extra.get("Message"),
        Some(&Value::String("Failed to closed and remove all rportfwds".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn socket_write_callback_broadcasts_error_on_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonSocketCommand::Write));
    add_u32(&mut payload, 0x44);
    add_u32(&mut payload, u32::from(DemonSocketType::ReverseProxy));
    add_u32(&mut payload, 0);
    add_u32(&mut payload, 10061);

    dispatcher.dispatch(0xFACE_FEED, u32::from(DemonCommand::CommandSocket), 35, &payload).await?;

    let event = receiver.recv().await.ok_or("missing socket write failure event")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Failed to write to socks target 68: 10061".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn socket_connect_and_close_callbacks_drive_socks_client_lifecycle()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    registry.insert(sample_agent_info(0x1234_5678, test_key(0x11), test_iv(0x22))).await?;
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events,
        database,
        sockets.clone(),
        None,
    );

    let started = sockets.add_socks_server(0x1234_5678, "0").await?;
    let addr = started
        .split_whitespace()
        .last()
        .ok_or("SOCKS server address missing from start message")?;
    let mut client = TcpStream::connect(addr).await?;

    client.write_all(&[5, 1, 0]).await?;
    let mut negotiation = [0_u8; 2];
    client.read_exact(&mut negotiation).await?;
    assert_eq!(negotiation, [5, 0]);

    client.write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0x1F, 0x90]).await?;

    let socket_id = timeout(Duration::from_secs(5), async {
        loop {
            let queued = registry.queued_jobs(0x1234_5678).await?;
            if let Some(job) = queued.iter().find(|job| job.command_line == "socket connect") {
                let socket_id =
                    u32::from_le_bytes(job.payload[4..8].try_into().map_err(|_| "socket id")?);
                return Ok::<u32, Box<dyn std::error::Error>>(socket_id);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out waiting for socket connect job to be queued",
        )
    })??;

    let mut connect = Vec::new();
    add_u32(&mut connect, u32::from(DemonSocketCommand::Connect));
    add_u32(&mut connect, 1);
    add_u32(&mut connect, socket_id);
    add_u32(&mut connect, 0);
    dispatcher.dispatch(0x1234_5678, u32::from(DemonCommand::CommandSocket), 36, &connect).await?;

    let mut connect_reply = [0_u8; 10];
    client.read_exact(&mut connect_reply).await?;
    assert_eq!(connect_reply, [5, 0, 0, 1, 127, 0, 0, 1, 0x1F, 0x90]);

    let mut close = Vec::new();
    add_u32(&mut close, u32::from(DemonSocketCommand::Close));
    add_u32(&mut close, socket_id);
    add_u32(&mut close, u32::from(DemonSocketType::ReverseProxy));
    dispatcher.dispatch(0x1234_5678, u32::from(DemonCommand::CommandSocket), 37, &close).await?;

    let mut eof = [0_u8; 1];
    let closed = timeout(Duration::from_secs(1), client.read(&mut eof)).await?;
    assert_eq!(closed?, 0);
    Ok(())
}

#[tokio::test]
async fn socket_callback_rejects_unknown_subcommands() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let error = dispatcher
        .dispatch(
            0xDEAD_BEEF,
            u32::from(DemonCommand::CommandSocket),
            38,
            &0xFFFF_FFFF_u32.to_le_bytes(),
        )
        .await
        .expect_err("unknown socket subcommand should fail");
    assert!(matches!(
        error,
        CommandDispatchError::InvalidCallbackPayload { command_id, .. }
            if command_id == u32::from(DemonCommand::CommandSocket)
    ));
    Ok(())
}

#[tokio::test]
async fn socket_read_callback_broadcasts_error_on_agent_read_failure()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonSocketCommand::Read));
    add_u32(&mut payload, 0x77); // socket_id
    add_u32(&mut payload, u32::from(DemonSocketType::ReverseProxy));
    add_u32(&mut payload, 0); // success = 0 (failure)
    add_u32(&mut payload, 10054); // error_code (WSAECONNRESET)

    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandSocket), 40, &payload).await?;

    let event = receiver.recv().await.ok_or("missing socket read failure event")?;
    let OperatorMessage::AgentResponse(message) = event else {
        panic!("expected agent response event");
    };
    assert_eq!(message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    assert_eq!(
        message.info.extra.get("Message"),
        Some(&Value::String("Failed to read from socks target 119: 10054".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn socket_read_callback_success_non_reverse_proxy_is_silent()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonSocketCommand::Read));
    add_u32(&mut payload, 0x33); // socket_id
    add_u32(&mut payload, u32::from(DemonSocketType::ReversePortForward)); // not ReverseProxy
    add_u32(&mut payload, 1); // success
    add_bytes(&mut payload, b"some data");

    dispatcher.dispatch(0xAABB_CCDD, u32::from(DemonCommand::CommandSocket), 41, &payload).await?;

    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "read success with non-ReverseProxy type should not broadcast"
    );
    Ok(())
}

#[tokio::test]
async fn socket_write_callback_no_broadcast_on_success() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonSocketCommand::Write));
    add_u32(&mut payload, 0x44); // socket_id
    add_u32(&mut payload, u32::from(DemonSocketType::ReverseProxy));
    add_u32(&mut payload, 1); // success

    dispatcher.dispatch(0xFACE_FEED, u32::from(DemonCommand::CommandSocket), 42, &payload).await?;

    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "write success should not broadcast any event"
    );
    Ok(())
}

#[tokio::test]
async fn socket_rportfwd_list_callback_rejects_truncated_payload()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonSocketCommand::ReversePortForwardList));
    add_u32(&mut payload, 0x21); // socket_id
    add_u32(&mut payload, u32::from_le_bytes([127, 0, 0, 1])); // local_addr
    add_u32(&mut payload, 8080); // local_port
    // Missing: forward_addr and forward_port — should trigger InvalidCallbackPayload

    let error = dispatcher
        .dispatch(0xCAFE_BABE, u32::from(DemonCommand::CommandSocket), 43, &payload)
        .await
        .expect_err("truncated rportfwd list payload should fail");
    assert!(matches!(
        error,
        CommandDispatchError::InvalidCallbackPayload { command_id, .. }
            if command_id == u32::from(DemonCommand::CommandSocket)
    ));
    Ok(())
}

// ── handle_socket_callback unit tests ────────────────────────────────────────

fn socket_payload(subcommand: DemonSocketCommand, rest: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    add_u32(&mut payload, subcommand as u32);
    payload.extend_from_slice(rest);
    payload
}

const AGENT_ID: u32 = 0xDEAD_BEEF;
const REQUEST_ID: u32 = 42;
const COMMAND_SOCKET: u32 = 2540;

async fn test_deps() -> (EventBus, SocketRelayManager) {
    let db = Database::connect_in_memory().await.expect("in-memory db");
    let registry = AgentRegistry::new(db);
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry, events.clone());
    (events, sockets)
}

async fn call_and_recv(
    payload: &[u8],
) -> (Result<Option<Vec<u8>>, CommandDispatchError>, Option<OperatorMessage>) {
    let (events, sockets) = test_deps().await;
    let mut rx = events.subscribe();
    let result = handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, payload).await;
    // Drop both to close the broadcast channel so rx.recv() returns None
    // when no message was sent (SocketRelayManager holds an EventBus clone).
    drop(events);
    drop(sockets);
    let msg = rx.recv().await;
    (result, msg)
}

fn assert_agent_response(msg: &OperatorMessage, expected_kind: &str, expected_substr: &str) {
    let OperatorMessage::AgentResponse(m) = msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    assert_eq!(m.info.demon_id, format!("{AGENT_ID:08X}"));
    assert_eq!(m.info.command_id, COMMAND_SOCKET.to_string());
    let kind = m.info.extra.get("Type").and_then(Value::as_str);
    assert_eq!(kind, Some(expected_kind), "expected Type={expected_kind}");
    let message = m.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
    assert!(
        message.contains(expected_substr),
        "expected Message to contain {expected_substr:?}, got {message:?}"
    );
}

fn get_output(msg: &OperatorMessage) -> &str {
    let OperatorMessage::AgentResponse(m) = msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    &m.info.output
}

fn get_extra_message(msg: &OperatorMessage) -> String {
    let OperatorMessage::AgentResponse(m) = msg else {
        panic!("expected AgentResponse, got {msg:?}");
    };
    m.info.extra.get("Message").and_then(Value::as_str).unwrap_or("").to_owned()
}

// ── format_rportfwd_list (via ReversePortForwardList subcommand) ────────

#[tokio::test]
async fn rportfwd_list_zero_entries_shows_header_only() {
    let payload = socket_payload(DemonSocketCommand::ReversePortForwardList, &[]);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    assert_agent_response(&msg, "Info", "reverse port forwards:");
    let output = get_output(&msg);
    assert!(output.contains("Socket ID"), "should contain header");
    assert!(output.contains("Forward"), "should contain header");
    let data_lines: Vec<&str> = output
        .lines()
        .filter(|l| !l.is_empty() && !l.contains("Socket ID") && !l.contains("---------"))
        .collect();
    assert!(data_lines.is_empty(), "expected no data rows, got {data_lines:?}");
}

#[tokio::test]
async fn rportfwd_list_single_entry() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 0xABCD_0001); // socket_id
    add_u32(&mut rest, 0x0100_007F); // local_addr = 127.0.0.1
    add_u32(&mut rest, 8080); // local_port
    add_u32(&mut rest, 0x0101_A8C0); // forward_addr = 192.168.1.1
    add_u32(&mut rest, 4443); // forward_port
    let payload = socket_payload(DemonSocketCommand::ReversePortForwardList, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    let output = get_output(&msg);
    assert!(output.contains("abcd0001"), "should contain socket id in hex");
    assert!(output.contains("127.0.0.1:8080"), "should contain local addr:port");
    assert!(output.contains("192.168.1.1:4443"), "should contain forward addr:port");
    assert!(output.contains("->"), "should contain arrow separator");
}

#[tokio::test]
async fn rportfwd_list_multiple_entries() {
    let mut rest = Vec::new();
    // entry 1
    add_u32(&mut rest, 0x0000_0001);
    add_u32(&mut rest, 0x0100_007F); // 127.0.0.1
    add_u32(&mut rest, 9090);
    add_u32(&mut rest, 0x0A01_A8C0); // 192.168.1.10
    add_u32(&mut rest, 80);
    // entry 2
    add_u32(&mut rest, 0x0000_0002);
    add_u32(&mut rest, 0x0100_007F); // 127.0.0.1
    add_u32(&mut rest, 9091);
    add_u32(&mut rest, 0x1401_A8C0); // 192.168.1.20
    add_u32(&mut rest, 443);
    let payload = socket_payload(DemonSocketCommand::ReversePortForwardList, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    let output = get_output(&msg);
    assert!(output.contains("127.0.0.1:9090"));
    assert!(output.contains("127.0.0.1:9091"));
    let data_lines: Vec<&str> = output
        .lines()
        .filter(|l| !l.is_empty() && !l.contains("Socket ID") && !l.contains("---------"))
        .collect();
    assert_eq!(data_lines.len(), 2, "expected 2 data rows, got {data_lines:?}");
}

#[tokio::test]
async fn rportfwd_list_truncated_second_entry_returns_error() {
    let mut rest = Vec::new();
    // complete first entry (5 × u32 = 20 bytes)
    add_u32(&mut rest, 0xABCD_0001); // socket_id
    add_u32(&mut rest, 0x0100_007F); // local_addr = 127.0.0.1
    add_u32(&mut rest, 8080); // local_port
    add_u32(&mut rest, 0x0101_A8C0); // forward_addr = 192.168.1.1
    add_u32(&mut rest, 4443); // forward_port
    // truncated second entry: only socket_id, missing the other 4 fields
    add_u32(&mut rest, 0xABCD_0002); // socket_id only
    let payload = socket_payload(DemonSocketCommand::ReversePortForwardList, &rest);
    let (events, sockets) = test_deps().await;
    let result = handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated list entry, got {result:?}"
    );
}

// ── ReversePortForwardAdd ───────────────────────────────────────────────

#[tokio::test]
async fn rportfwd_add_success_broadcasts_info() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 1); // success
    add_u32(&mut rest, 0x00FF_0001); // socket_id
    add_u32(&mut rest, 0x0100_007F); // local_addr 127.0.0.1
    add_u32(&mut rest, 4444); // local_port
    add_u32(&mut rest, 0x0101_A8C0); // forward_addr 192.168.1.1
    add_u32(&mut rest, 8443); // forward_port
    let payload = socket_payload(DemonSocketCommand::ReversePortForwardAdd, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    assert_agent_response(&msg, "Info", "Started reverse port forward");
    let message = get_extra_message(&msg);
    assert!(message.contains("127.0.0.1:4444"));
    assert!(message.contains("192.168.1.1:8443"));
    assert!(message.contains("ff0001"), "should contain socket id in hex");
}

#[tokio::test]
async fn rportfwd_add_failure_broadcasts_error() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 0); // failure
    add_u32(&mut rest, 0x00FF_0002); // socket_id
    add_u32(&mut rest, 0x0100_007F); // local_addr
    add_u32(&mut rest, 4444); // local_port
    add_u32(&mut rest, 0x0101_A8C0); // forward_addr
    add_u32(&mut rest, 8443); // forward_port
    let payload = socket_payload(DemonSocketCommand::ReversePortForwardAdd, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    assert_agent_response(&msg, "Error", "Failed to start reverse port forward");
}

// ── ReversePortForwardRemove ────────────────────────────────────────────

#[tokio::test]
async fn rportfwd_remove_rportfwd_type_broadcasts_info() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 0x0000_0042); // socket_id
    add_u32(&mut rest, u32::from(DemonSocketType::ReversePortForward)); // type
    add_u32(&mut rest, 0x0100_007F); // local_addr
    add_u32(&mut rest, 5555); // local_port
    add_u32(&mut rest, 0x0101_A8C0); // forward_addr
    add_u32(&mut rest, 6666); // forward_port
    let payload = socket_payload(DemonSocketCommand::ReversePortForwardRemove, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast for ReversePortForward type");
    assert_agent_response(&msg, "Info", "Successful closed and removed rportfwd");
    let message = get_extra_message(&msg);
    assert!(message.contains("42"), "should contain socket id");
}

#[tokio::test]
async fn rportfwd_remove_non_rportfwd_type_no_broadcast() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 0x0000_0042); // socket_id
    add_u32(&mut rest, u32::from(DemonSocketType::ReverseProxy)); // not ReversePortForward
    add_u32(&mut rest, 0x0100_007F);
    add_u32(&mut rest, 5555);
    add_u32(&mut rest, 0x0101_A8C0);
    add_u32(&mut rest, 6666);
    let payload = socket_payload(DemonSocketCommand::ReversePortForwardRemove, &rest);
    let (events, sockets) = test_deps().await;
    let mut rx = events.subscribe();
    let result = handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &payload).await;
    assert!(result.is_ok());
    drop(events);
    drop(sockets);
    let msg = rx.recv().await;
    assert!(msg.is_none(), "should not broadcast for non-ReversePortForward type");
}

#[tokio::test]
async fn rportfwd_remove_truncated_returns_error() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 0x0000_0042); // socket_id only, missing 5 remaining fields
    let payload = socket_payload(DemonSocketCommand::ReversePortForwardRemove, &rest);
    let (events, sockets) = test_deps().await;
    let mut rx = events.subscribe();
    let result = handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated payload, got {result:?}"
    );
    drop(events);
    drop(sockets);
    let msg = rx.recv().await;
    assert!(msg.is_none(), "should not broadcast on truncated payload");
}

// ── ReversePortForwardClear ─────────────────────────────────────────────

#[tokio::test]
async fn rportfwd_clear_success_broadcasts_good() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 1); // success
    let payload = socket_payload(DemonSocketCommand::ReversePortForwardClear, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    assert_agent_response(&msg, "Good", "Successful closed and removed all rportfwds");
}

#[tokio::test]
async fn rportfwd_clear_failure_broadcasts_error() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 0); // failure
    let payload = socket_payload(DemonSocketCommand::ReversePortForwardClear, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    assert_agent_response(&msg, "Error", "Failed to closed and remove all rportfwds");
}

// ── Read subcommand ─────────────────────────────────────────────────────

#[tokio::test]
async fn read_failure_broadcasts_error_with_code() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 0x0000_AAAA); // socket_id
    add_u32(&mut rest, u32::from(DemonSocketType::ReverseProxy)); // type
    add_u32(&mut rest, 0); // success = false
    add_u32(&mut rest, 10054); // error_code (WSAECONNRESET)
    let payload = socket_payload(DemonSocketCommand::Read, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast error");
    assert_agent_response(&msg, "Error", "Failed to read from socks target");
    let message = get_extra_message(&msg);
    assert!(message.contains("10054"), "should contain error code");
}

#[tokio::test]
async fn read_success_reverse_proxy_no_client_broadcasts_delivery_error() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 0x0000_BBBB); // socket_id
    add_u32(&mut rest, u32::from(DemonSocketType::ReverseProxy)); // type
    add_u32(&mut rest, 1); // success = true
    add_bytes(&mut rest, b"hello relay data"); // data
    let payload = socket_payload(DemonSocketCommand::Read, &rest);
    // No client registered, so write_client_data will fail with ClientNotFound
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast delivery error");
    assert_agent_response(&msg, "Error", "Failed to deliver socks data");
}

#[tokio::test]
async fn read_success_non_reverse_proxy_no_broadcast() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 0x0000_CCCC); // socket_id
    add_u32(&mut rest, u32::from(DemonSocketType::ReversePortForward)); // not ReverseProxy
    add_u32(&mut rest, 1); // success = true
    add_bytes(&mut rest, b"some data"); // data
    let payload = socket_payload(DemonSocketCommand::Read, &rest);
    let (events, sockets) = test_deps().await;
    let mut rx = events.subscribe();
    let result = handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &payload).await;
    assert!(result.is_ok());
    drop(events);
    drop(sockets);
    let msg = rx.recv().await;
    assert!(msg.is_none(), "should not broadcast when socket type is not ReverseProxy");
}

// ── Write subcommand ────────────────────────────────────────────────────

#[tokio::test]
async fn write_failure_broadcasts_error_with_code() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 0x0000_DDDD); // socket_id
    add_u32(&mut rest, u32::from(DemonSocketType::ReverseProxy)); // type
    add_u32(&mut rest, 0); // success = false
    add_u32(&mut rest, 10053); // error_code (WSAECONNABORTED)
    let payload = socket_payload(DemonSocketCommand::Write, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast error");
    assert_agent_response(&msg, "Error", "Failed to write to socks target");
    let message = get_extra_message(&msg);
    assert!(message.contains("10053"), "should contain error code");
}

#[tokio::test]
async fn write_success_no_broadcast() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 0x0000_EEEE); // socket_id
    add_u32(&mut rest, u32::from(DemonSocketType::ReverseProxy)); // type
    add_u32(&mut rest, 1); // success = true
    let payload = socket_payload(DemonSocketCommand::Write, &rest);
    let (events, sockets) = test_deps().await;
    let mut rx = events.subscribe();
    let result = handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &payload).await;
    assert!(result.is_ok());
    drop(events);
    drop(sockets);
    let msg = rx.recv().await;
    assert!(msg.is_none(), "write success should not broadcast");
}

// ── Close subcommand ────────────────────────────────────────────────────

#[tokio::test]
async fn close_reverse_proxy_calls_close_client() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 0x0000_1234); // socket_id
    add_u32(&mut rest, u32::from(DemonSocketType::ReverseProxy)); // type
    let payload = socket_payload(DemonSocketCommand::Close, &rest);
    // close_client will return ClientNotFound error (logged as warn, not broadcast)
    let (result, _msg) = call_and_recv(&payload).await;
    // The handler should still return Ok even if close_client errors
    assert!(result.is_ok());
}

#[tokio::test]
async fn close_non_reverse_proxy_skips_close_client() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 0x0000_1234); // socket_id
    add_u32(&mut rest, u32::from(DemonSocketType::ReversePortForward)); // not ReverseProxy
    let payload = socket_payload(DemonSocketCommand::Close, &rest);
    let (events, sockets) = test_deps().await;
    let mut rx = events.subscribe();
    let result = handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &payload).await;
    assert!(result.is_ok());
    drop(events);
    drop(sockets);
    let msg = rx.recv().await;
    assert!(msg.is_none(), "non-ReverseProxy close should not broadcast");
}

// ── Connect subcommand ──────────────────────────────────────────────────

#[tokio::test]
async fn connect_returns_ok_even_when_no_client_exists() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 1); // success
    add_u32(&mut rest, 0x0000_5678); // socket_id
    add_u32(&mut rest, 0); // error_code
    let payload = socket_payload(DemonSocketCommand::Connect, &rest);
    // finish_connect will error with ClientNotFound (logged as warn)
    let (result, _msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn connect_failure_calls_finish_connect_with_false() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 0); // success = 0 (connection refused)
    add_u32(&mut rest, 0x0000_5678); // socket_id
    add_u32(&mut rest, 10061); // error_code (WSAECONNREFUSED)
    let payload = socket_payload(DemonSocketCommand::Connect, &rest);
    // finish_connect will error with ClientNotFound (logged as warn), but
    // the handler must not panic or return Err on a refused-connection payload.
    let (result, _msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    assert!(result.expect("unwrap").is_none());
}

// ── SocksProxyAdd ──────────────────────────────────────────────────────

#[tokio::test]
async fn socks_proxy_add_success_broadcasts_info() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 1); // success
    add_u32(&mut rest, 0x00AA_0001); // socket_id
    add_u32(&mut rest, 0x0100_007F); // bind_addr 127.0.0.1
    add_u32(&mut rest, 1080); // bind_port
    let payload = socket_payload(DemonSocketCommand::SocksProxyAdd, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    assert_agent_response(&msg, "Info", "Started SOCKS proxy");
    let message = get_extra_message(&msg);
    assert!(message.contains("127.0.0.1:1080"));
    assert!(message.contains("aa0001"), "should contain socket id in hex");
}

#[tokio::test]
async fn socks_proxy_add_failure_broadcasts_error() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 0); // failure
    add_u32(&mut rest, 0x00AA_0002); // socket_id
    add_u32(&mut rest, 0x0100_007F); // bind_addr
    add_u32(&mut rest, 1080); // bind_port
    let payload = socket_payload(DemonSocketCommand::SocksProxyAdd, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    assert_agent_response(&msg, "Error", "Failed to start SOCKS proxy");
}

#[tokio::test]
async fn socks_proxy_add_truncated_returns_error() {
    let payload = socket_payload(DemonSocketCommand::SocksProxyAdd, &[]);
    let (events, sockets) = test_deps().await;
    let result = handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated payload, got {result:?}"
    );
}

// ── SocksProxyList ─────────────────────────────────────────────────────

#[tokio::test]
async fn socks_proxy_list_zero_entries_shows_header_only() {
    let payload = socket_payload(DemonSocketCommand::SocksProxyList, &[]);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    assert_agent_response(&msg, "Info", "socks proxies:");
    let output = get_output(&msg);
    assert!(output.contains("Socket ID"), "should contain header");
    assert!(output.contains("Bind Address"), "should contain header");
    let data_lines: Vec<&str> = output
        .lines()
        .filter(|l| !l.is_empty() && !l.contains("Socket ID") && !l.contains("---------"))
        .collect();
    assert!(data_lines.is_empty(), "expected no data rows, got {data_lines:?}");
}

#[tokio::test]
async fn socks_proxy_list_single_entry() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 0xBBCC_0001); // socket_id
    add_u32(&mut rest, 0x0100_007F); // bind_addr = 127.0.0.1
    add_u32(&mut rest, 1080); // bind_port
    let payload = socket_payload(DemonSocketCommand::SocksProxyList, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    let output = get_output(&msg);
    assert!(output.contains("bbcc0001"), "should contain socket id in hex");
    assert!(output.contains("127.0.0.1:1080"), "should contain bind addr:port");
}

#[tokio::test]
async fn socks_proxy_list_multiple_entries() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 0x0000_0001);
    add_u32(&mut rest, 0x0100_007F); // 127.0.0.1
    add_u32(&mut rest, 1080);
    add_u32(&mut rest, 0x0000_0002);
    add_u32(&mut rest, 0x0000_0000); // 0.0.0.0
    add_u32(&mut rest, 9050);
    let payload = socket_payload(DemonSocketCommand::SocksProxyList, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    let output = get_output(&msg);
    assert!(output.contains("127.0.0.1:1080"));
    assert!(output.contains("0.0.0.0:9050"));
    let data_lines: Vec<&str> = output
        .lines()
        .filter(|l| !l.is_empty() && !l.contains("Socket ID") && !l.contains("---------"))
        .collect();
    assert_eq!(data_lines.len(), 2, "expected 2 data rows, got {data_lines:?}");
}

#[tokio::test]
async fn socks_proxy_list_truncated_second_entry_returns_error() {
    let mut rest = Vec::new();
    // complete first entry (3 × u32 = 12 bytes)
    add_u32(&mut rest, 0xBBCC_0001); // socket_id
    add_u32(&mut rest, 0x0100_007F); // bind_addr = 127.0.0.1
    add_u32(&mut rest, 1080); // bind_port
    // truncated second entry: only socket_id, missing bind_addr and bind_port
    add_u32(&mut rest, 0xBBCC_0002); // socket_id only
    let payload = socket_payload(DemonSocketCommand::SocksProxyList, &rest);
    let (events, sockets) = test_deps().await;
    let result = handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated socks proxy list entry, got {result:?}"
    );
}

// ── SocksProxyRemove ───────────────────────────────────────────────────

#[tokio::test]
async fn socks_proxy_remove_broadcasts_info() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 0x0000_00FF); // socket_id
    let payload = socket_payload(DemonSocketCommand::SocksProxyRemove, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    assert_agent_response(&msg, "Info", "Removed SOCKS proxy");
    let message = get_extra_message(&msg);
    assert!(message.contains("ff"), "should contain socket id in hex");
}

#[tokio::test]
async fn socks_proxy_remove_truncated_returns_error() {
    let payload = socket_payload(DemonSocketCommand::SocksProxyRemove, &[]);
    let (events, sockets) = test_deps().await;
    let result = handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated payload, got {result:?}"
    );
}

// ── SocksProxyClear ────────────────────────────────────────────────────

#[tokio::test]
async fn socks_proxy_clear_success_broadcasts_good() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 1); // success
    let payload = socket_payload(DemonSocketCommand::SocksProxyClear, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    assert_agent_response(&msg, "Good", "Successful closed and removed all SOCKS proxies");
}

#[tokio::test]
async fn socks_proxy_clear_failure_broadcasts_error() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 0); // failure
    let payload = socket_payload(DemonSocketCommand::SocksProxyClear, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    assert_agent_response(&msg, "Error", "Failed to close and remove all SOCKS proxies");
}

// ── Open subcommand ────────────────────────────────────────────────────

#[tokio::test]
async fn open_broadcasts_info_with_addresses() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 0x0000_ABCD); // socket_id
    add_u32(&mut rest, 0x0100_007F); // local_addr 127.0.0.1
    add_u32(&mut rest, 8080); // local_port
    add_u32(&mut rest, 0x0101_A8C0); // forward_addr 192.168.1.1
    add_u32(&mut rest, 4443); // forward_port
    let payload = socket_payload(DemonSocketCommand::Open, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    assert_agent_response(&msg, "Info", "Opened socket");
    let message = get_extra_message(&msg);
    assert!(message.contains("127.0.0.1:8080"));
    assert!(message.contains("192.168.1.1:4443"));
    assert!(message.contains("abcd"), "should contain socket id in hex");
    assert!(message.contains("->"), "should contain arrow separator");
}

#[tokio::test]
async fn open_truncated_returns_error() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 0x0000_ABCD); // socket_id only
    let payload = socket_payload(DemonSocketCommand::Open, &rest);
    let (events, sockets) = test_deps().await;
    let result = handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated payload, got {result:?}"
    );
}

// ── ReversePortForwardAddLocal ─────────────────────────────────────────

#[tokio::test]
async fn rportfwd_add_local_success_broadcasts_info() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 1); // success
    add_u32(&mut rest, 0x00CC_0001); // socket_id
    add_u32(&mut rest, 0x0100_007F); // local_addr 127.0.0.1
    add_u32(&mut rest, 3333); // local_port
    add_u32(&mut rest, 0x0101_A8C0); // forward_addr 192.168.1.1
    add_u32(&mut rest, 7777); // forward_port
    let payload = socket_payload(DemonSocketCommand::ReversePortForwardAddLocal, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    assert_agent_response(&msg, "Info", "Started local reverse port forward");
    let message = get_extra_message(&msg);
    assert!(message.contains("127.0.0.1:3333"));
    assert!(message.contains("192.168.1.1:7777"));
    assert!(message.contains("cc0001"), "should contain socket id in hex");
}

#[tokio::test]
async fn rportfwd_add_local_failure_broadcasts_error() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 0); // failure
    add_u32(&mut rest, 0x00CC_0002); // socket_id
    add_u32(&mut rest, 0x0100_007F); // local_addr
    add_u32(&mut rest, 3333); // local_port
    add_u32(&mut rest, 0x0101_A8C0); // forward_addr
    add_u32(&mut rest, 7777); // forward_port
    let payload = socket_payload(DemonSocketCommand::ReversePortForwardAddLocal, &rest);
    let (result, msg) = call_and_recv(&payload).await;
    assert!(result.is_ok());
    let msg = msg.expect("should broadcast");
    assert_agent_response(&msg, "Error", "Failed to start local reverse port forward");
}

#[tokio::test]
async fn rportfwd_add_local_truncated_returns_error() {
    let mut rest = Vec::new();
    add_u32(&mut rest, 1); // success only
    let payload = socket_payload(DemonSocketCommand::ReversePortForwardAddLocal, &rest);
    let (events, sockets) = test_deps().await;
    let result = handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated payload, got {result:?}"
    );
}

// ── Error paths ─────────────────────────────────────────────────────────

#[tokio::test]
async fn empty_payload_returns_invalid_callback_payload() {
    let (events, sockets) = test_deps().await;
    let result = handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &[]).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for empty payload, got {result:?}"
    );
}

#[tokio::test]
async fn invalid_subcommand_returns_invalid_callback_payload() {
    let payload = 0xFFFF_FFFFu32.to_le_bytes().to_vec();
    let (events, sockets) = test_deps().await;
    let result = handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for invalid subcommand, got {result:?}"
    );
}

#[tokio::test]
async fn truncated_rportfwd_add_returns_error() {
    // Only subcommand + success, missing remaining fields
    let mut rest = Vec::new();
    add_u32(&mut rest, 1); // success
    let payload = socket_payload(DemonSocketCommand::ReversePortForwardAdd, &rest);
    let (events, sockets) = test_deps().await;
    let result = handle_socket_callback(&events, &sockets, AGENT_ID, REQUEST_ID, &payload).await;
    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "expected InvalidCallbackPayload for truncated payload, got {result:?}"
    );
}
