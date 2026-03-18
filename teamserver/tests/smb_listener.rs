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
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len, decrypt_agent_data,
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
        ListenerManager::new(database.clone(), registry.clone(), events.clone(), sockets, None);
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

    let key = [0x41_u8; AGENT_KEY_LENGTH];
    let iv = [0x24_u8; AGENT_IV_LENGTH];
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

    let key = [0x42_u8; AGENT_KEY_LENGTH];
    let iv = [0x25_u8; AGENT_IV_LENGTH];
    let agent_id = 0xCAFE_BABE_u32;
    let mut ctr_offset = 0_u64;

    // 1. DEMON_INIT
    let mut stream = connect_smb(&pipe_name).await?;
    write_smb_frame(&mut stream, agent_id, &common::valid_demon_init_body(agent_id, key, iv))
        .await?;
    let (_, ack) = timeout(Duration::from_secs(5), read_smb_frame(&mut stream)).await??;
    ctr_offset += ctr_blocks_for_len(ack.len());

    // Drain the AgentNew event.
    let _ = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    let before =
        registry.get(agent_id).await.ok_or("agent missing after init")?.last_call_in.clone();

    // The SMB listener is connection-per-request on the same stream; reconnect for callback.
    drop(stream);
    let mut callback_stream = connect_smb(&pipe_name).await?;

    // 2. COMMAND_CHECKIN callback.
    let callback_body = common::valid_demon_callback_body(
        agent_id,
        key,
        iv,
        ctr_offset,
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

    let registered_key = [0x43_u8; AGENT_KEY_LENGTH];
    let registered_iv = [0x26_u8; AGENT_IV_LENGTH];
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
    assert!(
        timeout(Duration::from_millis(200), event_receiver.recv()).await.is_err(),
        "unknown SMB callback must not emit an operator event"
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
/// and must not emit a second registration event.
#[cfg(unix)]
#[tokio::test]
async fn smb_listener_rejects_duplicate_init_preserves_original_key()
-> Result<(), Box<dyn std::error::Error>> {
    let (_, registry, events, manager) = test_manager().await?;
    let mut event_receiver = events.subscribe();
    let pipe_name = unique_pipe_name("duplicate-init");

    manager.create(smb_config("smb-test-duplicate-init", &pipe_name)).await?;
    manager.start("smb-test-duplicate-init").await?;
    wait_for_smb_listener(&pipe_name).await?;

    let agent_id = 0xD00D_F00D_u32;
    let original_key = [0x44_u8; AGENT_KEY_LENGTH];
    let original_iv = [0x27_u8; AGENT_IV_LENGTH];
    let hijack_key = [0xBB_u8; AGENT_KEY_LENGTH];
    let hijack_iv = [0xCC_u8; AGENT_IV_LENGTH];
    let mut ctr_offset = 0_u64;

    let mut init_stream = connect_smb(&pipe_name).await?;
    write_smb_frame(
        &mut init_stream,
        agent_id,
        &common::valid_demon_init_body(agent_id, original_key, original_iv),
    )
    .await?;

    let (ack_agent_id, ack_payload) =
        timeout(Duration::from_secs(5), read_smb_frame(&mut init_stream)).await??;
    assert_eq!(ack_agent_id, agent_id, "ack agent_id must match the registered agent");
    let decrypted_ack = decrypt_agent_data(&original_key, &original_iv, &ack_payload)?;
    assert_eq!(decrypted_ack.as_slice(), &agent_id.to_le_bytes());
    ctr_offset += ctr_blocks_for_len(ack_payload.len());

    let registration_event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    let Some(OperatorMessage::AgentNew(message)) = registration_event else {
        panic!("expected AgentNew event");
    };
    assert_eq!(message.info.name_id, format!("{agent_id:08X}"));

    let stored_after_first =
        registry.get(agent_id).await.ok_or("agent should be registered after first init")?;
    assert_eq!(
        stored_after_first.encryption.aes_key.as_slice(),
        &original_key,
        "first init must store the original AES key"
    );
    assert_eq!(
        stored_after_first.encryption.aes_iv.as_slice(),
        &original_iv,
        "first init must store the original AES IV"
    );

    drop(init_stream);

    let mut duplicate_stream = connect_smb(&pipe_name).await?;
    write_smb_frame(
        &mut duplicate_stream,
        agent_id,
        &common::valid_demon_init_body(agent_id, hijack_key, hijack_iv),
    )
    .await?;

    assert!(
        timeout(Duration::from_millis(250), read_smb_frame(&mut duplicate_stream)).await.is_err(),
        "duplicate SMB init must not return an ACK"
    );
    assert!(
        timeout(Duration::from_millis(250), event_receiver.recv()).await.is_err(),
        "duplicate SMB init must not emit a second AgentNew event"
    );

    let stored_after_duplicate = registry
        .get(agent_id)
        .await
        .ok_or("agent should remain registered after duplicate init")?;
    assert_eq!(
        stored_after_duplicate.encryption.aes_key.as_slice(),
        &original_key,
        "duplicate init must not overwrite the original AES key"
    );
    assert_eq!(
        stored_after_duplicate.encryption.aes_iv.as_slice(),
        &original_iv,
        "duplicate init must not overwrite the original AES IV"
    );

    drop(duplicate_stream);

    let mut callback_stream = connect_smb(&pipe_name).await?;
    let callback_body = common::valid_demon_callback_body(
        agent_id,
        original_key,
        original_iv,
        ctr_offset,
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

    manager.stop("smb-test-duplicate-init").await?;
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
    let key = [0x55_u8; AGENT_KEY_LENGTH];
    let iv = [0x33_u8; AGENT_IV_LENGTH];

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
        result.is_err() || result.unwrap().is_err(),
        "named pipe must not accept connections after listener is stopped"
    );

    Ok(())
}
