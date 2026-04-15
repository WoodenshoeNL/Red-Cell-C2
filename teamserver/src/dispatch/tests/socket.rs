//! Tests for socket command dispatch (SOCKS, rportfwd, socket read/write/connect/close).

use super::common::*;

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
