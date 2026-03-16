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
    assert_eq!(stored.external_ip, "127.0.0.1");

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
