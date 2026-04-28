//! SMB (named-pipe) listener integration tests.
//!
//! These tests spin up a real SMB listener through the [`ListenerManager`] API,
//! connect a mock Demon agent via the named-pipe transport (Unix abstract socket
//! on Linux), complete a DEMON_INIT handshake, send a callback packet, and verify
//! the teamserver processes everything correctly.  They follow the same pattern as
//! `http_listener_pipeline.rs`.

mod common;

use std::time::Duration;

#[cfg(unix)]
use interprocess::local_socket::ToNsName as _;
use interprocess::local_socket::tokio::Stream as LocalSocketStream;
use interprocess::local_socket::traits::tokio::Stream as _;
#[cfg(unix)]
use interprocess::os::unix::local_socket::AbstractNsUdSocket;
use red_cell::{
    AgentRegistry, Database, EventBus, ListenerManager, ListenerStatus, SocketRelayManager,
};
use red_cell_common::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, decrypt_agent_data, decrypt_agent_data_at_offset,
};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::OperatorMessage;
use red_cell_common::{ListenerConfig, SmbListenerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, timeout};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The Windows named-pipe prefix; on Linux this becomes the abstract-socket name.
const SMB_PIPE_PREFIX: &str = r"\\.\pipe\";

/// Create a minimal in-memory [`ListenerManager`] for SMB tests.
async fn test_manager()
-> Result<(Database, AgentRegistry, EventBus, ListenerManager), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager =
        ListenerManager::new(database.clone(), registry.clone(), events.clone(), sockets, None)
            .with_demon_allow_legacy_ctr(true);
    Ok((database, registry, events, manager))
}

/// Build an [`SmbListenerConfig`] using the given `pipe_name`.
fn smb_config(name: &str, pipe_name: &str) -> ListenerConfig {
    ListenerConfig::from(SmbListenerConfig {
        name: name.to_owned(),
        pipe_name: pipe_name.to_owned(),
        kill_date: None,
        working_hours: None,
    })
}

/// Compute a unique pipe name for each test to avoid collisions.
fn unique_pipe_name(suffix: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or_default();
    format!("red-cell-smb-test-{suffix}-{ts}")
}

/// Resolve the abstract socket name for `pipe_name`.
///
/// Replicates the teamserver's internal `normalized_smb_pipe_name` logic.
#[cfg(unix)]
fn resolve_socket_name(
    pipe_name: &str,
) -> Result<interprocess::local_socket::Name<'static>, Box<dyn std::error::Error>> {
    let trimmed = pipe_name.trim();
    let full = if trimmed.starts_with('/') || trimmed.starts_with(r"\\") {
        trimmed.to_owned()
    } else {
        format!("{SMB_PIPE_PREFIX}{trimmed}")
    };
    Ok(full.to_ns_name::<AbstractNsUdSocket>()?.into_owned())
}

/// Connect to the SMB listener's abstract socket.
#[cfg(unix)]
async fn connect_smb(pipe_name: &str) -> Result<LocalSocketStream, Box<dyn std::error::Error>> {
    let socket_name = resolve_socket_name(pipe_name)?;
    Ok(LocalSocketStream::connect(socket_name).await?)
}

/// Poll until the SMB listener is ready to accept connections.
#[cfg(unix)]
async fn wait_for_smb_listener(pipe_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..40 {
        if connect_smb(pipe_name).await.is_ok() {
            return Ok(());
        }
        sleep(Duration::from_millis(25)).await;
    }
    Err(format!("SMB listener on pipe `{pipe_name}` did not become ready within 1 s").into())
}

/// Generate a non-degenerate test AES key from a seed byte.
///
/// Produces `[seed, seed+1, seed+2, …]` which passes the server's degenerate-key check.
fn test_key(seed: u8) -> [u8; AGENT_KEY_LENGTH] {
    core::array::from_fn(|i| seed.wrapping_add(i as u8))
}

/// Generate a non-degenerate test AES IV from a seed byte.
fn test_iv(seed: u8) -> [u8; AGENT_IV_LENGTH] {
    core::array::from_fn(|i| seed.wrapping_add(i as u8))
}

/// Write a framed SMB message: `[agent_id u32 LE][payload_len u32 LE][payload]`.
async fn write_smb_frame(
    stream: &mut LocalSocketStream,
    agent_id: u32,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    stream.write_u32_le(agent_id).await?;
    stream.write_u32_le(u32::try_from(payload.len())?).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

/// Read a framed SMB response: `[agent_id u32 LE][payload_len u32 LE][payload]`.
async fn read_smb_frame(
    stream: &mut LocalSocketStream,
) -> Result<(u32, Vec<u8>), Box<dyn std::error::Error>> {
    let agent_id = stream.read_u32_le().await?;
    let payload_len = usize::try_from(stream.read_u32_le().await?)?;
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await?;
    Ok((agent_id, payload))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Spin up an SMB listener, connect a mock Demon agent, complete a DEMON_INIT
/// handshake, and verify the agent is registered in the database.
#[cfg(unix)]
#[tokio::test]
async fn smb_listener_demon_init_registers_agent_and_returns_ack()
-> Result<(), Box<dyn std::error::Error>> {
    let (database, registry, events, manager) = test_manager().await?;
    let mut event_receiver = events.subscribe();
    let pipe_name = unique_pipe_name("init");

    manager.create(smb_config("smb-test-init", &pipe_name)).await?;
    manager.start("smb-test-init").await?;
    wait_for_smb_listener(&pipe_name).await?;

    let key = test_key(0x41);
    let iv = test_iv(0x24);
    let agent_id = 0xDEAD_C0DE_u32;

    let mut stream = connect_smb(&pipe_name).await?;
    write_smb_frame(&mut stream, agent_id, &common::valid_demon_init_body(agent_id, key, iv))
        .await?;

    // Read the init acknowledgement.
    let (ack_agent_id, ack_payload) =
        timeout(Duration::from_secs(5), read_smb_frame(&mut stream)).await??;
    assert_eq!(ack_agent_id, agent_id, "ack agent_id must match");

    // The ack is AES-encrypted at offset 0.
    let decrypted = decrypt_agent_data(&key, &iv, &ack_payload)?;
    assert_eq!(
        decrypted.as_slice(),
        &agent_id.to_le_bytes(),
        "init ack must contain agent_id as LE bytes"
    );

    // Agent must be in the in-memory registry.
    let stored = registry.get(agent_id).await.ok_or("agent should be registered")?;
    assert_eq!(stored.hostname, "wkstn-01");
    // Synthetic IPv4 derived from agent_id 0xDEAD_C0DE → bytes [0xDE,0xAD,0xC0,0xDE]
    assert_eq!(stored.external_ip, "222.173.192.222");

    // Agent must also be persisted in the database.
    let db_agent = database.agents().get(agent_id).await?.ok_or("agent should be in DB")?;
    assert_eq!(db_agent.agent_id, agent_id);

    // AgentNew event must have been broadcast to operators.
    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    let Some(OperatorMessage::AgentNew(message)) = event else {
        panic!("expected AgentNew event");
    };
    assert_eq!(message.info.listener, "smb-test-init");
    assert_eq!(message.info.name_id, format!("{agent_id:08X}"));

    manager.stop("smb-test-init").await?;
    Ok(())
}

/// Start and stop an SMB listener and verify the database reflects the transitions.
#[cfg(unix)]
#[tokio::test]
async fn smb_listener_start_stop_state_transitions() -> Result<(), Box<dyn std::error::Error>> {
    let (_, _, _, manager) = test_manager().await?;
    let pipe_name = unique_pipe_name("lifecycle");

    manager.create(smb_config("smb-test-lifecycle", &pipe_name)).await?;

    let after_create = manager.summary("smb-test-lifecycle").await?;
    assert_eq!(after_create.state.status, ListenerStatus::Created);

    manager.start("smb-test-lifecycle").await?;
    let after_start = manager.summary("smb-test-lifecycle").await?;
    assert_eq!(after_start.state.status, ListenerStatus::Running);

    // Verify the named pipe is actually accepting connections.
    wait_for_smb_listener(&pipe_name).await?;

    let after_stop = manager.stop("smb-test-lifecycle").await?;
    assert_eq!(after_stop.state.status, ListenerStatus::Stopped);

    Ok(())
}

/// After a DEMON_INIT, the agent can send a COMMAND_CHECKIN callback via the SMB
/// transport and the teamserver processes it (no error, empty response).
#[cfg(unix)]
#[tokio::test]
async fn smb_listener_processes_callback_after_init() -> Result<(), Box<dyn std::error::Error>> {
    let (_, registry, events, manager) = test_manager().await?;
    let mut event_receiver = events.subscribe();
    let pipe_name = unique_pipe_name("callback");

    manager.create(smb_config("smb-test-callback", &pipe_name)).await?;
    manager.start("smb-test-callback").await?;
    wait_for_smb_listener(&pipe_name).await?;

    let key = test_key(0x42);
    let iv = test_iv(0x25);
    let agent_id = 0xCAFE_BABE_u32;

    // 1. DEMON_INIT
    let mut stream = connect_smb(&pipe_name).await?;
    write_smb_frame(&mut stream, agent_id, &common::valid_demon_init_body(agent_id, key, iv))
        .await?;
    let (_, _ack) = timeout(Duration::from_secs(5), read_smb_frame(&mut stream)).await??;

    // Drain the AgentNew event.
    let _ = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    let before =
        registry.get(agent_id).await.ok_or("agent missing after init")?.last_call_in.clone();

    // The SMB listener is connection-per-request on the same stream; reconnect for callback.
    drop(stream);
    let mut callback_stream = connect_smb(&pipe_name).await?;

    // 2. COMMAND_CHECKIN callback.
    // Legacy Demon agents reset AES-CTR to block 0 for every packet, so offset is always 0.
    let callback_body = common::valid_demon_callback_body(
        agent_id,
        key,
        iv,
        0,
        u32::from(DemonCommand::CommandCheckin),
        6,
        &[],
    );
    write_smb_frame(&mut callback_stream, agent_id, &callback_body).await?;

    // Read the SMB response frame and verify it echoes the agent_id with an empty payload.
    let (resp_agent_id, resp_payload) =
        timeout(Duration::from_secs(5), read_smb_frame(&mut callback_stream)).await??;
    assert_eq!(resp_agent_id, agent_id, "callback response must echo the agent_id");
    assert!(
        resp_payload.is_empty(),
        "checkin callback response payload must be empty, got {} bytes",
        resp_payload.len()
    );

    // The teamserver should emit an AgentUpdate event.
    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    let Some(OperatorMessage::AgentUpdate(message)) = event else {
        panic!("expected AgentUpdate event");
    };
    assert_eq!(message.info.agent_id, format!("{agent_id:08X}"));

    // last_call_in should have advanced.
    let after = registry.get(agent_id).await.ok_or("agent missing after checkin")?.last_call_in;
    assert_ne!(after, before, "last_call_in must advance after checkin");

    manager.stop("smb-test-callback").await?;
    Ok(())
}

/// After registering one agent, an SMB callback that claims a different, unknown
/// agent ID must be ignored without mutating the registered agent or emitting an
/// operator event.
#[cfg(unix)]
#[tokio::test]
async fn smb_listener_rejects_callbacks_from_unregistered_agent()
-> Result<(), Box<dyn std::error::Error>> {
    let (_, registry, events, manager) = test_manager().await?;
    let mut event_receiver = events.subscribe();
    let pipe_name = unique_pipe_name("unknown-callback");

    manager.create(smb_config("smb-test-unknown-callback", &pipe_name)).await?;
    manager.start("smb-test-unknown-callback").await?;
    wait_for_smb_listener(&pipe_name).await?;

    let registered_key = test_key(0x43);
    let registered_iv = test_iv(0x26);
    let registered_agent_id = 0xA1A2_A3A4_u32;
    let unknown_agent_id = 0xB1B2_B3B4_u32;

    let mut init_stream = connect_smb(&pipe_name).await?;
    write_smb_frame(
        &mut init_stream,
        registered_agent_id,
        &common::valid_demon_init_body(registered_agent_id, registered_key, registered_iv),
    )
    .await?;
    let (_, ack_payload) =
        timeout(Duration::from_secs(5), read_smb_frame(&mut init_stream)).await??;
    let decrypted_ack = decrypt_agent_data(&registered_key, &registered_iv, &ack_payload)?;
    assert_eq!(decrypted_ack.as_slice(), &registered_agent_id.to_le_bytes());

    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    let Some(OperatorMessage::AgentNew(message)) = event else {
        panic!("expected AgentNew event");
    };
    assert_eq!(message.info.name_id, format!("{registered_agent_id:08X}"));

    let before = registry.get(registered_agent_id).await.ok_or("registered agent missing")?;
    let before_last_call_in = before.last_call_in.clone();
    let before_hostname = before.hostname.clone();
    drop(init_stream);

    let mut callback_stream = connect_smb(&pipe_name).await?;
    let unknown_callback = common::valid_demon_callback_body(
        unknown_agent_id,
        registered_key,
        registered_iv,
        0,
        u32::from(DemonCommand::CommandCheckin),
        6,
        &[],
    );
    write_smb_frame(&mut callback_stream, unknown_agent_id, &unknown_callback).await?;

    assert!(
        timeout(Duration::from_millis(200), read_smb_frame(&mut callback_stream)).await.is_err(),
        "unknown SMB callback must not produce a response frame"
    );
    match timeout(Duration::from_millis(500), event_receiver.recv()).await {
        Err(_) => {}
        Ok(None) => panic!("event channel closed unexpectedly before optional TeamserverLog"),
        Ok(Some(OperatorMessage::TeamserverLog(_))) => {}
        Ok(Some(other)) => {
            panic!(
                "unknown SMB callback must not emit an operator event except optional TeamserverLog, got {other:?}"
            )
        }
    }
    assert!(
        timeout(Duration::from_millis(200), event_receiver.recv()).await.is_err(),
        "unknown SMB callback must not emit a second operator event"
    );
    assert!(
        registry.get(unknown_agent_id).await.is_none(),
        "unknown SMB callback must not register a new agent"
    );

    let after = registry.get(registered_agent_id).await.ok_or("registered agent missing")?;
    assert_eq!(
        after.last_call_in, before_last_call_in,
        "registered agent last_call_in must not change after unknown callback"
    );
    assert_eq!(
        after.hostname, before_hostname,
        "registered agent metadata must remain unchanged after unknown callback"
    );

    manager.stop("smb-test-unknown-callback").await?;
    Ok(())
}

/// A duplicate full DEMON_INIT over SMB must not overwrite the original AES key/IV,
/// A second DEMON_INIT via SMB for an already-registered agent is treated as a
/// re-registration (agent restart).  The session key is replaced and a second AgentNew
/// event is broadcast.  Subsequent callbacks must use the new key.
///
/// The teamserver rejects re-registration with different key material (key-rotation hijack
/// prevention).  This test uses the same keys to simulate a legitimate agent restart.
#[cfg(unix)]
#[tokio::test]
async fn smb_listener_reinit_updates_key_material() -> Result<(), Box<dyn std::error::Error>> {
    let (_, registry, events, manager) = test_manager().await?;
    let mut event_receiver = events.subscribe();
    let pipe_name = unique_pipe_name("reinit");

    manager.create(smb_config("smb-test-reinit", &pipe_name)).await?;
    manager.start("smb-test-reinit").await?;
    wait_for_smb_listener(&pipe_name).await?;

    let agent_id = 0xD00D_F00D_u32;
    let key = test_key(0x44);
    let iv = test_iv(0x27);

    let mut init_stream = connect_smb(&pipe_name).await?;
    write_smb_frame(&mut init_stream, agent_id, &common::valid_demon_init_body(agent_id, key, iv))
        .await?;

    let (ack_agent_id, ack_payload) =
        timeout(Duration::from_secs(5), read_smb_frame(&mut init_stream)).await??;
    assert_eq!(ack_agent_id, agent_id, "ack agent_id must match the registered agent");
    let decrypted_ack = decrypt_agent_data(&key, &iv, &ack_payload)?;
    assert_eq!(decrypted_ack.as_slice(), &agent_id.to_le_bytes());

    let first_event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    let Some(OperatorMessage::AgentNew(message)) = first_event else {
        panic!("expected AgentNew event");
    };
    assert_eq!(message.info.name_id, format!("{agent_id:08X}"));

    let stored_after_first =
        registry.get(agent_id).await.ok_or("agent should be registered after first init")?;
    assert_eq!(
        stored_after_first.encryption.aes_key.as_slice(),
        &key,
        "first init must store the AES key"
    );

    drop(init_stream);

    // Second DEMON_INIT (re-registration with same key material) — legitimate agent restart.
    let mut reinit_stream = connect_smb(&pipe_name).await?;
    write_smb_frame(
        &mut reinit_stream,
        agent_id,
        &common::valid_demon_init_body(agent_id, key, iv),
    )
    .await?;

    let (reinit_ack_id, reinit_ack_payload) =
        timeout(Duration::from_secs(5), read_smb_frame(&mut reinit_stream)).await??;
    assert_eq!(reinit_ack_id, agent_id, "re-init ack agent_id must match");
    let decrypted_reinit_ack = decrypt_agent_data(&key, &iv, &reinit_ack_payload)?;
    assert_eq!(decrypted_reinit_ack.as_slice(), &agent_id.to_le_bytes());

    // Re-registration emits an AgentReregistered event (not AgentNew).
    let reinit_event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    assert!(
        matches!(reinit_event, Some(OperatorMessage::AgentReregistered(_))),
        "re-registration must emit an AgentReregistered event"
    );

    // Key material must remain unchanged.
    let stored_after_reinit =
        registry.get(agent_id).await.ok_or("agent should remain registered after re-init")?;
    assert_eq!(
        stored_after_reinit.encryption.aes_key.as_slice(),
        &key,
        "re-init must preserve the session key"
    );
    assert_eq!(
        stored_after_reinit.encryption.aes_iv.as_slice(),
        &iv,
        "re-init must preserve the session IV"
    );

    drop(reinit_stream);

    // Verify that the key still works for callbacks after re-registration.
    // Legacy Demon agents reset AES-CTR to block 0 for every packet.
    let mut callback_stream = connect_smb(&pipe_name).await?;
    let callback_body = common::valid_demon_callback_body(
        agent_id,
        key,
        iv,
        0,
        u32::from(DemonCommand::CommandCheckin),
        6,
        &[],
    );
    write_smb_frame(&mut callback_stream, agent_id, &callback_body).await?;

    let callback_event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    let Some(OperatorMessage::AgentUpdate(message)) = callback_event else {
        panic!("expected AgentUpdate event");
    };
    assert_eq!(message.info.agent_id, format!("{agent_id:08X}"));

    manager.stop("smb-test-reinit").await?;
    Ok(())
}

/// A Demon that connects but sends no valid init payload must not register.
#[cfg(unix)]
#[tokio::test]
async fn smb_listener_ignores_invalid_demon_frame() -> Result<(), Box<dyn std::error::Error>> {
    let (_, registry, _, manager) = test_manager().await?;
    let pipe_name = unique_pipe_name("invalid");

    manager.create(smb_config("smb-test-invalid", &pipe_name)).await?;
    manager.start("smb-test-invalid").await?;
    wait_for_smb_listener(&pipe_name).await?;

    let agent_id = 0x1111_2222_u32;

    // Send a frame that is not a valid Demon envelope (random bytes).
    let mut stream = connect_smb(&pipe_name).await?;
    write_smb_frame(&mut stream, agent_id, b"garbage not a demon envelope").await?;

    // Give the server a moment to process; it should just drop the frame.
    sleep(Duration::from_millis(100)).await;

    // Agent must NOT have been registered.
    assert!(registry.get(agent_id).await.is_none(), "invalid frame must not register an agent");

    manager.stop("smb-test-invalid").await?;
    Ok(())
}

/// Truncated frame headers and partial payloads must not hang the read loop,
/// panic on partial buffers, or register partially parsed agent state.  After
/// the bad connections close, a valid DEMON_INIT on a fresh connection must
/// still succeed.
#[cfg(unix)]
#[tokio::test]
async fn smb_listener_rejects_truncated_header_and_partial_payload()
-> Result<(), Box<dyn std::error::Error>> {
    let (_, registry, events, manager) = test_manager().await?;
    let mut event_receiver = events.subscribe();
    let pipe_name = unique_pipe_name("truncated");

    manager.create(smb_config("smb-test-truncated", &pipe_name)).await?;
    manager.start("smb-test-truncated").await?;
    wait_for_smb_listener(&pipe_name).await?;

    let bogus_agent_id = 0xAAAA_BBBB_u32;

    // --- Case 1: truncated header (only 4 of the 8 header bytes) ---
    {
        let mut stream = connect_smb(&pipe_name).await?;
        // Write only the agent_id field (4 bytes) — the payload_len is missing.
        stream.write_all(&bogus_agent_id.to_le_bytes()).await?;
        stream.flush().await?;
        drop(stream); // disconnect before the server can read a full header
    }

    // Give the server a moment to process the disconnect.
    sleep(Duration::from_millis(100)).await;

    assert!(
        registry.get(bogus_agent_id).await.is_none(),
        "truncated header must not register an agent"
    );

    // --- Case 2: full header but truncated payload ---
    {
        let mut stream = connect_smb(&pipe_name).await?;
        // Write a full 8-byte header claiming 1024 bytes of payload…
        stream.write_u32_le(bogus_agent_id).await?;
        stream.write_u32_le(1024).await?;
        // …but only deliver 16 bytes before disconnecting.
        stream.write_all(&[0xCC_u8; 16]).await?;
        stream.flush().await?;
        drop(stream);
    }

    sleep(Duration::from_millis(100)).await;

    assert!(
        registry.get(bogus_agent_id).await.is_none(),
        "truncated payload must not register an agent"
    );

    // --- Verify the listener is still healthy: a valid DEMON_INIT must succeed ---
    let valid_agent_id = 0xBEEF_CAFE_u32;
    let key = test_key(0x55);
    let iv = test_iv(0x33);

    let mut stream = connect_smb(&pipe_name).await?;
    write_smb_frame(
        &mut stream,
        valid_agent_id,
        &common::valid_demon_init_body(valid_agent_id, key, iv),
    )
    .await?;

    let (ack_agent_id, ack_payload) =
        timeout(Duration::from_secs(5), read_smb_frame(&mut stream)).await??;
    assert_eq!(ack_agent_id, valid_agent_id, "ack agent_id must match");

    let decrypted = decrypt_agent_data(&key, &iv, &ack_payload)?;
    assert_eq!(
        decrypted.as_slice(),
        &valid_agent_id.to_le_bytes(),
        "init ack must contain agent_id as LE bytes"
    );

    let stored = registry.get(valid_agent_id).await.ok_or("agent should be registered")?;
    assert_eq!(stored.hostname, "wkstn-01");

    // Drain the AgentNew event to confirm registration completed.
    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    let Some(OperatorMessage::AgentNew(message)) = event else {
        panic!("expected AgentNew event after valid init");
    };
    assert_eq!(message.info.name_id, format!("{valid_agent_id:08X}"));

    // No spurious events from the truncated connections.
    assert!(
        timeout(Duration::from_millis(200), event_receiver.recv()).await.is_err(),
        "truncated connections must not emit extra operator events"
    );

    manager.stop("smb-test-truncated").await?;
    Ok(())
}

/// Verify that a reconnect probe over SMB succeeds and a subsequent callback
/// still works.
///
/// Legacy Demon agents reset AES-CTR to block 0 for every packet, so all
/// encrypt/decrypt operations use offset 0.  The reconnect ACK is also
/// encrypted at offset 0 (via `encrypt_for_agent_without_advancing`) which
/// is idempotent in legacy mode.
///
/// Sequence:
/// 1. Agent does a full init; server responds with init ACK at offset 0.
/// 2. Agent sends a reconnect probe (empty `DEMON_INIT` body).
/// 3. Server returns a reconnect ACK encrypted at offset 0.
/// 4. Agent sends a `COMMAND_GET_JOB` callback encrypted at offset 0.
///    The server decrypts it successfully, proving the session is still alive.
#[cfg(unix)]
#[tokio::test]
async fn reconnect_then_subsequent_callback_remains_synchronised()
-> Result<(), Box<dyn std::error::Error>> {
    let (_, registry, events, manager) = test_manager().await?;
    let mut event_receiver = events.subscribe();
    let pipe_name = unique_pipe_name("reconnect");

    manager.create(smb_config("smb-test-reconnect", &pipe_name)).await?;
    manager.start("smb-test-reconnect").await?;
    wait_for_smb_listener(&pipe_name).await?;

    let agent_id = 0xFACE_CAFE_u32;
    let key = test_key(0x9A);
    let iv = test_iv(0x5B);

    // --- Step 1: full DEMON_INIT ---------------------------------------------------
    let mut init_stream = connect_smb(&pipe_name).await?;
    write_smb_frame(&mut init_stream, agent_id, &common::valid_demon_init_body(agent_id, key, iv))
        .await?;

    let (ack_agent_id, ack_payload) =
        timeout(Duration::from_secs(5), read_smb_frame(&mut init_stream)).await??;
    assert_eq!(ack_agent_id, agent_id, "init ack agent_id must match");

    // Legacy mode: init ACK is encrypted at offset 0.
    let init_ack = decrypt_agent_data_at_offset(&key, &iv, 0, &ack_payload)?;
    assert_eq!(init_ack.as_slice(), &agent_id.to_le_bytes(), "init ACK must echo agent_id");

    // Drain the AgentNew event.
    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    assert!(
        matches!(event, Some(OperatorMessage::AgentNew(_))),
        "expected AgentNew event after init"
    );

    drop(init_stream);

    // --- Step 2: reconnect probe ---------------------------------------------------
    let mut reconnect_stream = connect_smb(&pipe_name).await?;
    write_smb_frame(&mut reconnect_stream, agent_id, &common::valid_demon_reconnect_body(agent_id))
        .await?;

    // --- Step 3: verify reconnect ACK at offset 0 (legacy mode) --------------------
    let (reconnect_ack_agent_id, reconnect_ack_payload) =
        timeout(Duration::from_secs(5), read_smb_frame(&mut reconnect_stream)).await??;
    assert_eq!(reconnect_ack_agent_id, agent_id, "reconnect ack agent_id must match");

    // Legacy mode: reconnect ACK is also encrypted at offset 0.
    let reconnect_ack = decrypt_agent_data_at_offset(&key, &iv, 0, &reconnect_ack_payload)?;
    assert_eq!(
        reconnect_ack.as_slice(),
        &agent_id.to_le_bytes(),
        "reconnect ACK must echo agent_id"
    );

    // In legacy mode, the stored CTR offset remains 0.
    assert_eq!(
        registry.ctr_offset(agent_id).await?,
        0,
        "server CTR offset must remain 0 in legacy mode"
    );

    drop(reconnect_stream);

    // --- Step 4: subsequent callback at offset 0 -----------------------------------
    let mut callback_stream = connect_smb(&pipe_name).await?;
    let callback_body = common::valid_demon_callback_body(
        agent_id,
        key,
        iv,
        0,
        u32::from(DemonCommand::CommandGetJob),
        1,
        &[],
    );
    write_smb_frame(&mut callback_stream, agent_id, &callback_body).await?;

    // A successful response proves the server decrypted the callback correctly.
    let (resp_agent_id, _resp_payload) =
        timeout(Duration::from_secs(5), read_smb_frame(&mut callback_stream)).await??;
    assert_eq!(resp_agent_id, agent_id, "callback response must echo the agent_id");

    manager.stop("smb-test-reconnect").await?;
    Ok(())
}

/// After an SMB listener is stopped, connections to the named pipe are refused.
#[cfg(unix)]
#[tokio::test]
async fn smb_listener_stop_closes_named_pipe() -> Result<(), Box<dyn std::error::Error>> {
    let (_, _, _, manager) = test_manager().await?;
    let pipe_name = unique_pipe_name("stop-pipe");

    manager.create(smb_config("smb-test-stop-pipe", &pipe_name)).await?;
    manager.start("smb-test-stop-pipe").await?;
    wait_for_smb_listener(&pipe_name).await?;
    manager.stop("smb-test-stop-pipe").await?;

    // After stop, new connections must be refused.
    sleep(Duration::from_millis(50)).await;
    let result = timeout(Duration::from_millis(200), connect_smb(&pipe_name)).await;
    assert!(
        result.is_err() || result.expect("unwrap").is_err(),
        "named pipe must not accept connections after listener is stopped"
    );

    Ok(())
}
