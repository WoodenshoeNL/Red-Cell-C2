mod common;

use std::time::Duration;

use red_cell::spawn_agent_liveness_monitor;
use red_cell_common::config::Profile;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::OperatorMessage;
use tokio::time::{sleep, timeout};
use tokio_tungstenite::connect_async;

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

/// Build a profile with an aggressive `AgentTimeoutSecs` so the liveness
/// monitor marks idle agents dead within a couple of seconds.
fn short_timeout_profile() -> Profile {
    Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 0
          AgentTimeoutSecs = 2
        }

        Operators {
          user "operator" {
            Password = "password1234"
            Role = "Operator"
          }
        }

        Demon {
          Sleep = 1
        }
        "#,
    )
    .expect("short timeout profile should parse")
}

/// End-to-end test: register an agent via the HTTP listener, start the
/// liveness monitor, wait for the timeout to expire, and verify:
///   1. The agent is marked dead in the registry.
///   2. An `AgentUpdate` event with `marked = "Dead"` is broadcast to the
///      connected operator over the WebSocket.
///   3. Any SOCKS relay state associated with the agent is cleaned up.
#[tokio::test]
async fn agent_marked_dead_after_liveness_timeout_expires() -> Result<(), Box<dyn std::error::Error>>
{
    let server = common::spawn_test_server(short_timeout_profile()).await?;

    // --- Start HTTP listener ---
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let listener_name = "liveness-http";
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

    // Consume messages until we see the AgentNew event (listener events may arrive first).
    let agent_new =
        read_until(&mut socket, |msg| matches!(msg, OperatorMessage::AgentNew(_))).await?;
    let OperatorMessage::AgentNew(new_msg) = agent_new else {
        unreachable!();
    };
    assert_eq!(new_msg.info.name_id, "CAFEBABE");

    // Verify the agent is alive in the registry before the monitor runs.
    let stored =
        server.agent_registry.get(agent_id).await.ok_or("agent must exist after registration")?;
    assert!(stored.active, "agent must be active immediately after init");

    // Add a SOCKS relay to verify socket cleanup after timeout.
    server.sockets.add_socks_server(agent_id, "0").await.map_err(|e| e.to_string())?;

    // --- Start the liveness monitor ---
    // With AgentTimeoutSecs = 2 the sweep interval is 1 s.  The agent will be
    // marked dead on the first sweep tick that lands >= 2 s after last_call_in.
    let _monitor = spawn_agent_liveness_monitor(
        server.agent_registry.clone(),
        server.sockets.clone(),
        server.events.clone(),
        server.database.clone(),
        &server.profile,
    );

    // --- Wait for the AgentUpdate (dead) event on the operator WebSocket ---
    // Allow up to 10 s to account for timing variance on loaded CI.
    let dead_event = timeout(Duration::from_secs(10), async {
        loop {
            let msg = common::read_operator_message(&mut socket).await?;
            if matches!(&msg, OperatorMessage::AgentUpdate(_)) {
                return Ok::<_, Box<dyn std::error::Error>>(msg);
            }
            // Skip any other events (e.g. AgentMark from SOCKS setup).
        }
    })
    .await
    .map_err(|_| "timed out waiting for AgentUpdate (dead) event on WebSocket")??;

    let OperatorMessage::AgentUpdate(update_msg) = dead_event else {
        return Err(format!("expected AgentUpdate, got {dead_event:?}").into());
    };
    assert_eq!(update_msg.info.agent_id, "CAFEBABE");
    assert_eq!(update_msg.info.marked, "Dead");

    // --- Verify registry state ---
    let stored = server
        .agent_registry
        .get(agent_id)
        .await
        .ok_or("agent must still exist after being marked dead")?;
    assert!(!stored.active, "agent must be inactive after liveness timeout");
    assert!(
        stored.reason.contains("timed out"),
        "reason must mention timeout, got: {}",
        stored.reason
    );

    // --- Verify SOCKS relay cleanup ---
    assert_eq!(
        server.sockets.list_socks_servers(agent_id).await,
        "No active SOCKS5 servers",
        "SOCKS relay state must be pruned after agent death"
    );

    socket.close(None).await?;
    server.listeners.stop(listener_name).await?;
    Ok(())
}

/// End-to-end test: register two agents, let agent A go stale while agent B
/// calls in just before the timeout window, then verify:
///   1. Agent A is marked dead and an `AgentUpdate(Dead)` event is broadcast.
///   2. Agent B remains active — the sweep must NOT mark agents that are still
///      calling in.
///   3. Exactly one `AgentUpdate` event arrives on the WebSocket (i.e. no
///      spurious dead event for agent B within 500 ms of agent A's death).
///
/// This guards against a regression where the liveness sweep marks *all* active
/// agents dead rather than filtering by `last_call_in` age.
#[tokio::test]
async fn active_agent_survives_liveness_sweep_that_kills_stale_peer()
-> Result<(), Box<dyn std::error::Error>> {
    let server = common::spawn_test_server(short_timeout_profile()).await?;

    // --- Start HTTP listener ---
    let (listener_port, listener_guard) = common::available_port_excluding(server.addr.port())?;
    let listener_name = "liveness-multi-http";
    server.listeners.create(common::http_listener_config(listener_name, listener_port)).await?;
    drop(listener_guard);
    server.listeners.start(listener_name).await?;
    common::wait_for_listener(listener_port).await?;

    // --- Connect operator WebSocket ---
    let (mut socket, _) = connect_async(format!("ws://{}/", server.addr)).await?;
    common::login(&mut socket).await?;

    let client = reqwest::Client::new();

    // --- Register agent A (will go stale) ---
    let agent_a_id: u32 = 0xCAFE_BABE;
    let key_a: [u8; AGENT_KEY_LENGTH] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let iv_a: [u8; AGENT_IV_LENGTH] = [
        0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F,
        0x90,
    ];
    let _ctr_a = common::register_agent(&client, listener_port, agent_a_id, key_a, iv_a).await?;
    read_until(&mut socket, |msg| matches!(msg, OperatorMessage::AgentNew(_))).await?;

    // --- Register agent B (will stay alive) ---
    let agent_b_id: u32 = 0xDEAD_BEEF;
    let key_b: [u8; AGENT_KEY_LENGTH] = [
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E,
        0x3F, 0x40,
    ];
    let iv_b: [u8; AGENT_IV_LENGTH] = [
        0xB1, 0xC2, 0xD3, 0xE4, 0xF5, 0x06, 0x17, 0x28, 0x39, 0x4A, 0x5B, 0x6C, 0x7D, 0x8E, 0x9F,
        0xA0,
    ];
    let ctr_b = common::register_agent(&client, listener_port, agent_b_id, key_b, iv_b).await?;
    read_until(&mut socket, |msg| matches!(msg, OperatorMessage::AgentNew(_))).await?;

    // Verify both agents are initially active.
    let stored_a = server.agent_registry.get(agent_a_id).await.ok_or("agent A must exist")?;
    assert!(stored_a.active, "agent A must be active immediately after registration");
    let stored_b = server.agent_registry.get(agent_b_id).await.ok_or("agent B must exist")?;
    assert!(stored_b.active, "agent B must be active immediately after registration");

    // Wait until just inside the timeout window, then refresh agent B's last_call_in.
    // AgentTimeoutSecs = 2: at t=1.5 s, A is already stale relative to a t=2 s sweep,
    // but B's refreshed timestamp will be only ~0.5 s old at the first sweep tick.
    sleep(Duration::from_millis(1500)).await;

    // Refresh B's last_call_in by sending an empty CommandCheckin callback.
    // An empty CHECKIN payload skips metadata parsing and calls set_last_call_in directly,
    // which is the lightest-weight way to prove the agent is still alive.
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(common::valid_demon_callback_body(
            agent_b_id,
            key_b,
            iv_b,
            ctr_b,
            u32::from(DemonCommand::CommandCheckin),
            0,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;

    // --- Start the liveness monitor ---
    // Sweep interval = 1 s (AgentTimeoutSecs / 3, clamped to [1, 30]).
    // First sweep (~1 s after monitor start): A elapsed ~2.5 s → dead; B elapsed ~0.5 s → alive.
    let _monitor = spawn_agent_liveness_monitor(
        server.agent_registry.clone(),
        server.sockets.clone(),
        server.events.clone(),
        server.database.clone(),
        &server.profile,
    );

    // --- Wait for the AgentUpdate(Dead) event for agent A ---
    // Skip any non-Dead AgentUpdate messages (e.g. the liveness mark broadcast
    // that the server emits when agent B's CommandCheckin updates last_call_in).
    let dead_event = timeout(Duration::from_secs(10), async {
        loop {
            let msg = common::read_operator_message(&mut socket).await?;
            if let OperatorMessage::AgentUpdate(ref update) = msg {
                if update.info.marked == "Dead" {
                    return Ok::<_, Box<dyn std::error::Error>>(msg);
                }
            }
            // Skip all non-Dead events (listener notifications, B's checkin mark, etc.).
        }
    })
    .await
    .map_err(|_| "timed out waiting for AgentUpdate (dead) event for agent A")??;

    let OperatorMessage::AgentUpdate(update_msg) = dead_event else {
        return Err(format!("expected AgentUpdate, got {dead_event:?}").into());
    };
    assert_eq!(
        update_msg.info.agent_id, "CAFEBABE",
        "only agent A (CAFEBABE) should be marked dead by the sweep"
    );
    assert_eq!(update_msg.info.marked, "Dead");

    // --- Verify registry state ---
    let stored_a = server
        .agent_registry
        .get(agent_a_id)
        .await
        .ok_or("agent A must still exist after being marked dead")?;
    assert!(!stored_a.active, "agent A must be inactive after liveness timeout");

    let stored_b = server.agent_registry.get(agent_b_id).await.ok_or("agent B must still exist")?;
    assert!(stored_b.active, "agent B must remain active — the sweep must not kill live agents");

    // --- Assert no Dead AgentUpdate for agent B within 500 ms ---
    // A too-aggressive sweep that kills every active agent would emit a Dead
    // AgentUpdate for B here.  The 500 ms window is safely inside agent B's
    // remaining liveness budget (~1.5 s from its last call-in at t=1.5 s).
    let unexpected = timeout(Duration::from_millis(500), async {
        loop {
            let msg = common::read_operator_message(&mut socket).await?;
            if let OperatorMessage::AgentUpdate(ref update) = msg {
                if update.info.marked == "Dead" {
                    return Ok::<_, Box<dyn std::error::Error>>(msg);
                }
            }
            // Skip non-Dead events — they are harmless.
        }
    })
    .await;
    assert!(
        unexpected.is_err(),
        "agent B must not receive a Dead AgentUpdate within 500 ms of agent A's death"
    );

    socket.close(None).await?;
    server.listeners.stop(listener_name).await?;
    Ok(())
}
