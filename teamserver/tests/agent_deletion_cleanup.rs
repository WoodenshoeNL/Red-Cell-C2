mod common;

use std::collections::BTreeMap;
use std::time::Duration;

use futures_util::SinkExt;
use red_cell::Job;
use red_cell_common::config::Profile;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use red_cell_common::operator::{EventCode, FlatInfo, Message, MessageHead, OperatorMessage};
use serde_json::Value;
use tokio::time::timeout;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message as ClientMessage;

/// Build a profile with an admin operator (required for AgentRemove).
fn admin_profile() -> Profile {
    Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 0
        }

        Operators {
          user "operator" {
            Password = "password1234"
            Role = "Admin"
          }
        }

        Demon {}
        "#,
    )
    .expect("admin profile should parse")
}

/// Construct the JSON payload an operator sends to request agent deletion.
fn agent_remove_payload(demon_id: &str) -> String {
    let mut fields = BTreeMap::new();
    fields.insert("DemonID".to_owned(), Value::String(demon_id.to_owned()));

    serde_json::to_string(&OperatorMessage::AgentRemove(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "operator".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: FlatInfo { fields },
    }))
    .expect("AgentRemove message should serialize")
}

/// Collect all operator WebSocket messages that arrive within `window`, up to
/// `max_frames`.  Returns without error once the timeout expires.
async fn collect_messages_within(
    socket: &mut common::WsClient,
    window: Duration,
    max_frames: usize,
) -> Vec<OperatorMessage> {
    let mut collected = Vec::new();
    for _ in 0..max_frames {
        let result = tokio::time::timeout(window, common::read_operator_message(socket)).await;
        match result {
            Ok(Ok(msg)) => collected.push(msg),
            // timeout expired or socket error — stop collecting
            _ => break,
        }
    }
    collected
}

/// Read operator WebSocket messages until `predicate` matches, discarding
/// non-matching messages.  Gives up after 20 frames.
async fn read_until<F>(
    socket: &mut common::WsClient,
    mut predicate: F,
) -> Result<OperatorMessage, Box<dyn std::error::Error>>
where
    F: FnMut(&OperatorMessage) -> bool,
{
    for _ in 0..20 {
        let msg = common::read_operator_message(socket).await?;
        if predicate(&msg) {
            return Ok(msg);
        }
    }
    Err("did not observe expected operator message within 20 frames".into())
}

/// End-to-end test: register an agent via HTTP, set up SOCKS relay state,
/// enqueue jobs (creating request contexts), issue AgentRemove over the
/// operator WebSocket, and verify the full cleanup chain:
///
///   1. Agent removed from the in-memory registry.
///   2. Agent deleted from the SQLite database.
///   3. SOCKS relay state cleaned up.
///   4. Request contexts purged.
///   5. Cleanup hooks executed (download tracker drained).
///   6. AgentRemove event broadcast to the operator.
#[tokio::test]
async fn agent_remove_cleans_up_all_state() -> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(admin_profile()).await?;

    // --- Start HTTP listener ---
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let listener_name = "cleanup-http";
    server.listeners.create(common::http_listener_config(listener_name, listener_port)).await?;
    drop(listener_guard);
    server.listeners.start(listener_name).await?;
    common::wait_for_listener(listener_port).await?;

    // --- Connect operator WebSocket ---
    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    // --- Register agent via Demon init ---
    let agent_id: u32 = 0xCAFE_BABE;
    // Key and IV must NOT be single-byte repeating patterns (e.g. [0x55; 32])
    // because the parser rejects degenerate key material via `is_weak_aes_key`.
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F,
        0x90,
    ];
    let client = reqwest::Client::new();
    let _ctr_offset = common::register_agent(&client, listener_port, agent_id, key, iv).await?;

    // Consume the AgentNew event.
    let agent_new =
        read_until(&mut socket, |msg| matches!(msg, OperatorMessage::AgentNew(_))).await?;
    let OperatorMessage::AgentNew(new_msg) = agent_new else {
        unreachable!();
    };
    assert_eq!(new_msg.info.name_id, "CAFEBABE");

    // --- Set up SOCKS relay state ---
    server.sockets.add_socks_server(agent_id, "0").await.map_err(|e| e.to_string())?;
    assert!(
        server.sockets.list_socks_servers(agent_id).await.contains("SOCKS5 servers"),
        "SOCKS server must be active before removal"
    );

    // --- Enqueue a job to create request contexts ---
    let job = Job {
        command: 1,
        request_id: 42,
        payload: vec![0xDE, 0xAD],
        command_line: "shell whoami".to_owned(),
        task_id: "task-001".to_owned(),
        created_at: "2026-03-20T00:00:00Z".to_owned(),
        operator: "operator".to_owned(),
    };
    server.agent_registry.enqueue_job(agent_id, job).await?;
    assert!(
        server.agent_registry.request_context(agent_id, 42).await.is_some(),
        "request context must exist after enqueueing a job"
    );

    // --- Register a spy cleanup hook to confirm hooks fire during remove ---
    let hook_fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hook_signal = hook_fired.clone();
    server.agent_registry.register_cleanup_hook(move |id| {
        let signal = hook_signal.clone();
        async move {
            if id == 0xCAFE_BABE {
                signal.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
    });

    // --- Verify pre-removal DB state ---
    assert!(
        server.database.agents().get(agent_id).await?.is_some(),
        "agent must exist in DB before removal"
    );

    // --- Issue AgentRemove via operator WebSocket ---
    socket.send(ClientMessage::Text(agent_remove_payload("CAFEBABE").into())).await?;

    // --- Wait for AgentRemove broadcast ---
    let remove_event = timeout(Duration::from_secs(5), async {
        loop {
            let msg = common::read_operator_message(&mut socket).await?;
            if matches!(&msg, OperatorMessage::AgentRemove(_)) {
                return Ok::<_, Box<dyn std::error::Error>>(msg);
            }
        }
    })
    .await
    .map_err(|_| "timed out waiting for AgentRemove event on WebSocket")??;

    assert!(
        matches!(remove_event, OperatorMessage::AgentRemove(_)),
        "expected AgentRemove broadcast"
    );

    // --- Verify: agent removed from in-memory registry ---
    assert!(
        server.agent_registry.get(agent_id).await.is_none(),
        "agent must be removed from in-memory registry"
    );

    // --- Verify: agent deleted from SQLite ---
    assert_eq!(
        server.database.agents().get(agent_id).await?,
        None,
        "agent must be deleted from SQLite after removal"
    );

    // --- Verify: SOCKS relay state cleaned up ---
    assert_eq!(
        server.sockets.list_socks_servers(agent_id).await,
        "No active SOCKS5 servers",
        "SOCKS relay state must be cleaned up after agent removal"
    );

    // --- Verify: request contexts purged ---
    assert!(
        server.agent_registry.request_context(agent_id, 42).await.is_none(),
        "request contexts must be purged after agent removal"
    );

    // --- Verify: cleanup hooks ran ---
    assert!(
        hook_fired.load(std::sync::atomic::Ordering::SeqCst),
        "cleanup hooks must fire during agent removal"
    );

    socket.close(None).await?;
    server.listeners.stop(listener_name).await?;
    Ok(())
}

/// Sending `AgentRemove` for an agent ID that was never registered must not
/// broadcast an `AgentRemove` event to operators and must not crash the server.
///
/// The server should return an error internally (logged as a `TeamserverLog`
/// event) and remain available for subsequent requests.
#[tokio::test]
async fn agent_remove_nonexistent_id_does_not_broadcast() -> Result<(), Box<dyn std::error::Error>>
{
    let server = common::spawn_test_server(admin_profile()).await?;

    // --- Connect operator WebSocket ---
    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    // --- Send AgentRemove for an ID that was never registered ---
    let fake_id = "DEAD1234";
    socket.send(ClientMessage::Text(agent_remove_payload(fake_id).into())).await?;

    // --- Collect messages that arrive within a short window ---
    // A TeamserverLog error event may arrive; an AgentRemove must NOT.
    let messages = collect_messages_within(&mut socket, Duration::from_millis(500), 10).await;
    for msg in &messages {
        assert!(
            !matches!(msg, OperatorMessage::AgentRemove(_)),
            "server must not broadcast AgentRemove for a non-existent agent ID, got: {msg:?}"
        );
    }

    // --- Verify the server is still alive: send a second request and confirm
    //     it is handled without panicking (another non-existent remove).     ---
    let fake_id_2 = "DEAD5678";
    socket.send(ClientMessage::Text(agent_remove_payload(fake_id_2).into())).await?;
    let messages2 = collect_messages_within(&mut socket, Duration::from_millis(500), 10).await;
    for msg in &messages2 {
        assert!(
            !matches!(msg, OperatorMessage::AgentRemove(_)),
            "server must not broadcast AgentRemove for a second non-existent agent ID"
        );
    }

    // --- Confirm neither agent was silently inserted into the DB ---
    assert_eq!(
        server.database.agents().get(0xDEAD_1234).await?,
        None,
        "non-existent agent must not appear in DB after failed remove"
    );
    assert_eq!(
        server.database.agents().get(0xDEAD_5678).await?,
        None,
        "non-existent agent must not appear in DB after failed remove"
    );

    socket.close(None).await?;
    Ok(())
}
