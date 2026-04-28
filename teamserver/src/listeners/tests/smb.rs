use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use super::super::smb::smb_local_socket_name;
use super::super::{
    MAX_DEMON_INIT_ATTEMPTS_PER_IP, MAX_SMB_FRAME_PAYLOAD_LEN, read_smb_frame,
    spawn_smb_listener_runtime,
};
use super::*;
use crate::Job;
use interprocess::local_socket::ListenerOptions;
use interprocess::local_socket::tokio::Stream as LocalSocketStream;
use interprocess::local_socket::traits::tokio::Listener as _;
use interprocess::local_socket::traits::tokio::Stream as _;
use red_cell_common::crypto::{
    ctr_blocks_for_len, decrypt_agent_data, decrypt_agent_data_at_offset,
};
use red_cell_common::demon::DemonMessage;
use red_cell_common::operator::OperatorMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

#[tokio::test]
async fn smb_listener_registers_demon_init_and_returns_framed_ack()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager =
        ListenerManager::new(database.clone(), registry.clone(), events.clone(), sockets, None)
            .with_demon_allow_legacy_ctr(true);
    let mut event_receiver = events.subscribe();
    let pipe_name = unique_smb_pipe_name("init");

    manager.create(smb_listener("edge-smb-init", &pipe_name)).await?;
    manager.start("edge-smb-init").await?;
    wait_for_smb_listener(&pipe_name).await?;

    let key = test_key(0x41);
    let iv = test_iv(0x24);
    let mut stream = connect_smb_stream(&pipe_name).await?;
    write_test_smb_frame(&mut stream, 0x1234_5678, &valid_demon_init_body(0x1234_5678, key, iv))
        .await?;

    let (agent_id, response) = read_test_smb_frame(&mut stream).await?;
    assert_eq!(agent_id, 0x1234_5678);
    let decrypted = decrypt_agent_data(&key, &iv, &response)?;
    assert_eq!(decrypted.as_slice(), &0x1234_5678_u32.to_le_bytes());

    let stored = registry.get(0x1234_5678).await.expect("agent should be registered");
    assert_eq!(stored.hostname, "wkstn-01");
    // Synthetic IPv4 derived from agent_id 0x1234_5678 → bytes [0x12,0x34,0x56,0x78]
    assert_eq!(stored.external_ip, "18.52.86.120");
    assert_eq!(database.agents().get(0x1234_5678).await?, Some(stored.clone()));

    let event = event_receiver.recv().await.expect("agent registration should broadcast");
    let OperatorMessage::AgentNew(message) = event else {
        panic!("unexpected operator event");
    };
    assert_eq!(message.info.listener, "edge-smb-init");

    manager.stop("edge-smb-init").await?;
    Ok(())
}

#[tokio::test]
async fn smb_listener_rate_limits_demon_init_per_named_pipe_connection()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let pipe_name = unique_smb_pipe_name("init-limit");

    manager.create(smb_listener("edge-smb-init-limit", &pipe_name)).await?;
    manager.start("edge-smb-init-limit").await?;
    wait_for_smb_listener(&pipe_name).await?;

    // On one named-pipe connection, each full DEMON_INIT counts against the same sliding
    // window — rotating `agent_id` must not grant a fresh bucket (regression for
    // synthetic-IPv4 keying).
    let mut stream = connect_smb_stream(&pipe_name).await?;
    for attempt in 0..MAX_DEMON_INIT_ATTEMPTS_PER_IP {
        let agent_id = 0x5000_0000 + attempt;
        write_test_smb_frame(
            &mut stream,
            agent_id,
            &valid_demon_init_body(agent_id, test_key(0x41), test_iv(0x24)),
        )
        .await?;

        let (response_agent_id, response) = read_test_smb_frame(&mut stream).await?;
        assert_eq!(response_agent_id, agent_id);
        assert!(!response.is_empty());
        assert!(registry.get(agent_id).await.is_some());
    }

    let rotated_id = 0x5000_00FF_u32;
    write_test_smb_frame(
        &mut stream,
        rotated_id,
        &valid_demon_init_body(rotated_id, test_key(0x42), test_iv(0x26)),
    )
    .await?;
    let blocked =
        tokio::time::timeout(Duration::from_millis(250), read_test_smb_frame(&mut stream)).await;
    assert!(
        blocked.is_err(),
        "DEMON_INIT on the same SMB connection after the per-IP cap must be rate-limited even with a new agent_id"
    );
    assert!(
        registry.get(rotated_id).await.is_none(),
        "rate-limited init must not register a new agent"
    );

    // A new connection gets its own window — one more full DEMON_INIT must succeed.
    let mut stream2 = connect_smb_stream(&pipe_name).await?;
    let fresh_id = 0x6000_0001_u32;
    write_test_smb_frame(
        &mut stream2,
        fresh_id,
        &valid_demon_init_body(fresh_id, test_key(0x43), test_iv(0x27)),
    )
    .await?;
    let (ack_id, ack) = read_test_smb_frame(&mut stream2).await?;
    assert_eq!(ack_id, fresh_id);
    assert!(!ack.is_empty());
    assert!(registry.get(fresh_id).await.is_some());

    manager.stop("edge-smb-init-limit").await?;
    Ok(())
}

#[tokio::test]
async fn smb_listener_reinit_updates_pivot_agent_registration()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager =
        ListenerManager::new(database.clone(), registry.clone(), events.clone(), sockets, None)
            .with_demon_allow_legacy_ctr(true);
    let mut event_receiver = events.subscribe();
    let pipe_name = unique_smb_pipe_name("pivot-reinit");
    let parent_id = 0x1111_2222;
    let parent_key = test_key(0x31);
    let parent_iv = test_iv(0x41);
    let child_id = 0x3333_4444;
    let child_key = test_key(0x51);
    let child_iv = test_iv(0x61);

    registry.insert(sample_agent_info(parent_id, parent_key, parent_iv)).await?;
    registry.insert(sample_agent_info(child_id, child_key, child_iv)).await?;
    registry.add_link(parent_id, child_id).await?;

    manager.create(smb_listener("edge-smb-pivot-reinit", &pipe_name)).await?;
    manager.start("edge-smb-pivot-reinit").await?;
    wait_for_smb_listener(&pipe_name).await?;

    // Re-register with the same key material (legitimate restart).
    let mut stream = connect_smb_stream(&pipe_name).await?;
    write_test_smb_frame(
        &mut stream,
        child_id,
        &valid_demon_init_body(child_id, child_key, child_iv),
    )
    .await?;

    // Re-registration must return an ACK.
    let (ack_id, ack_payload) =
        tokio::time::timeout(Duration::from_millis(500), read_test_smb_frame(&mut stream))
            .await
            .expect("re-registration ack must arrive within timeout")
            .expect("re-registration ack read must succeed");
    assert_eq!(ack_id, child_id, "ack agent_id must match the child");
    assert!(!ack_payload.is_empty(), "ack payload must not be empty");

    // Re-registration must emit an AgentReregistered event.
    let reinit_event = tokio::time::timeout(Duration::from_millis(500), event_receiver.recv())
        .await
        .expect("AgentReregistered must arrive within timeout");
    assert!(
        matches!(reinit_event, Some(OperatorMessage::AgentReregistered(_))),
        "re-registration must broadcast AgentReregistered"
    );

    // The child's listener_name must now reflect the SMB listener.
    let listener_after = registry.listener_name(child_id).await;
    assert_eq!(
        listener_after.as_deref(),
        Some("edge-smb-pivot-reinit"),
        "listener_name must be updated to the SMB listener after re-registration"
    );

    // Key material must remain unchanged (same keys were used).
    let stored_after = registry.get(child_id).await.expect("child agent must still be registered");
    assert_eq!(
        stored_after.encryption.aes_key.as_slice(),
        &child_key,
        "re-registration must preserve the session key"
    );

    manager.stop("edge-smb-pivot-reinit").await?;
    Ok(())
}

#[tokio::test]
async fn smb_listener_serializes_all_queued_jobs_for_get_job()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let pipe_name = unique_smb_pipe_name("jobs");
    let key = test_key(0x61);
    let iv = test_iv(0x27);
    let agent_id = 0x5566_7788;

    registry.insert(sample_agent_info(agent_id, key, iv)).await?;
    registry
        .enqueue_job(
            agent_id,
            Job {
                command: u32::from(DemonCommand::CommandSleep),
                request_id: 41,
                payload: vec![1, 2, 3, 4],
                command_line: "sleep 10".to_owned(),
                task_id: "task-41".to_owned(),
                created_at: "2026-03-09T20:10:00Z".to_owned(),
                operator: "operator".to_owned(),
            },
        )
        .await?;
    registry
        .enqueue_job(
            agent_id,
            Job {
                command: u32::from(DemonCommand::CommandCheckin),
                request_id: 42,
                payload: vec![5, 6, 7],
                command_line: "checkin".to_owned(),
                task_id: "task-42".to_owned(),
                created_at: "2026-03-09T20:11:00Z".to_owned(),
                operator: "operator".to_owned(),
            },
        )
        .await?;
    manager.create(smb_listener("edge-smb-jobs", &pipe_name)).await?;
    manager.start("edge-smb-jobs").await?;
    wait_for_smb_listener(&pipe_name).await?;

    let mut stream = connect_smb_stream(&pipe_name).await?;
    write_test_smb_frame(
        &mut stream,
        agent_id,
        &valid_demon_callback_body(
            agent_id,
            key,
            iv,
            u32::from(DemonCommand::CommandGetJob),
            9,
            &[],
        ),
    )
    .await?;

    let (response_agent_id, response_bytes) = read_test_smb_frame(&mut stream).await?;
    assert_eq!(response_agent_id, agent_id);
    let message = DemonMessage::from_bytes(response_bytes.as_ref())?;
    let response_ctr_offset = ctr_blocks_for_len(0);
    assert_eq!(message.packages.len(), 2);
    assert_eq!(message.packages[0].command_id, u32::from(DemonCommand::CommandSleep));
    assert_eq!(message.packages[0].request_id, 41);
    let pt0 =
        decrypt_agent_data_at_offset(&key, &iv, response_ctr_offset, &message.packages[0].payload)?;
    assert_eq!(pt0, vec![1, 2, 3, 4]);
    assert_eq!(message.packages[1].command_id, u32::from(DemonCommand::CommandCheckin));
    assert_eq!(message.packages[1].request_id, 42);
    let pt1 = decrypt_agent_data_at_offset(
        &key,
        &iv,
        response_ctr_offset + ctr_blocks_for_len(message.packages[0].payload.len()),
        &message.packages[1].payload,
    )?;
    assert_eq!(pt1, vec![5, 6, 7]);
    assert!(registry.queued_jobs(agent_id).await?.is_empty());

    manager.stop("edge-smb-jobs").await?;
    Ok(())
}

async fn wait_for_smb_listener(pipe_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..40 {
        match connect_smb_stream(pipe_name).await {
            Ok(stream) => {
                drop(stream);
                return Ok(());
            }
            Err(_) => sleep(Duration::from_millis(25)).await,
        }
    }

    Err(format!("smb listener `{pipe_name}` did not become ready").into())
}

async fn connect_smb_stream(
    pipe_name: &str,
) -> Result<LocalSocketStream, Box<dyn std::error::Error>> {
    let socket_name = smb_local_socket_name(pipe_name)?;
    Ok(LocalSocketStream::connect(socket_name).await?)
}

async fn connected_smb_stream_pair(
    pipe_name: &str,
) -> Result<(LocalSocketStream, LocalSocketStream), Box<dyn std::error::Error>> {
    let socket_name = smb_local_socket_name(pipe_name)?;
    let listener = ListenerOptions::new().name(socket_name).create_tokio()?;
    let server = tokio::spawn(async move { listener.accept().await });
    let client = connect_smb_stream(pipe_name).await?;
    let server = server.await??;
    Ok((client, server))
}

async fn write_test_smb_frame(
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

async fn read_test_smb_frame(
    stream: &mut LocalSocketStream,
) -> Result<(u32, Vec<u8>), Box<dyn std::error::Error>> {
    let agent_id = stream.read_u32_le().await?;
    let payload_len = usize::try_from(stream.read_u32_le().await?)?;
    let mut payload = vec![0_u8; payload_len];
    stream.read_exact(&mut payload).await?;
    Ok((agent_id, payload))
}

#[tokio::test]
async fn read_smb_frame_rejects_payloads_over_limit() -> Result<(), Box<dyn std::error::Error>> {
    let pipe_name = unique_smb_pipe_name("oversize");
    let (mut client, mut server) = connected_smb_stream_pair(&pipe_name).await?;
    let oversized_len = u32::try_from(MAX_SMB_FRAME_PAYLOAD_LEN + 1)?;

    client.write_u32_le(0x1234_5678).await?;
    client.write_u32_le(oversized_len).await?;
    client.flush().await?;

    let error = read_smb_frame(&mut server).await.expect_err("oversized frame should be rejected");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(error.to_string().contains("exceeds maximum"), "unexpected error message: {error}");

    Ok(())
}

fn unique_smb_pipe_name(suffix: &str) -> String {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("red-cell-test-{suffix}-{unique}")
}

async fn spawn_test_smb_runtime(
    config: red_cell_common::SmbListenerConfig,
    shutdown: ShutdownController,
) -> Result<super::super::ListenerRuntimeFuture, ListenerManagerError> {
    let database = Database::connect_in_memory().await.expect("database creation failed");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    spawn_smb_listener_runtime(
        &config,
        registry,
        events,
        database,
        sockets,
        None,
        DownloadTracker::from_max_download_bytes(crate::DEFAULT_MAX_DOWNLOAD_BYTES),
        UnknownCallbackProbeAuditLimiter::new(),
        ReconnectProbeRateLimiter::new(),
        DemonInitRateLimiter::default(),
        shutdown,
        DemonInitSecretConfig::None,
        crate::dispatch::DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        true,
    )
    .await
}

#[tokio::test]
async fn smb_listener_runtime_exits_when_shutdown_started_before_first_poll() {
    let shutdown = ShutdownController::new();
    let pipe_name = unique_smb_pipe_name("shutdown-prepoll");
    let config = red_cell_common::SmbListenerConfig {
        name: "smb-shutdown-prepoll".to_owned(),
        pipe_name,
        kill_date: None,
        working_hours: None,
    };
    let runtime =
        spawn_test_smb_runtime(config, shutdown.clone()).await.expect("smb runtime should start");

    shutdown.initiate();

    let result = timeout(Duration::from_millis(200), runtime)
        .await
        .expect("smb runtime should observe pre-existing shutdown");
    assert_eq!(result, Ok(()));
}
