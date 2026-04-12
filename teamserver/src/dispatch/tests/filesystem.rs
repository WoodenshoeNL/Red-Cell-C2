//! Tests for filesystem operations: download, upload, cat, dir, and the download tracker.

use super::common::*;

use super::super::{
    CommandDispatchError, CommandDispatcher, DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
    DOWNLOAD_TRACKER_AGGREGATE_CAP_MULTIPLIER, DownloadState, DownloadTracker,
};
use crate::{AgentRegistry, Database, EventBus, Job, SocketRelayManager};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell_common::demon::{DemonCallback, DemonCommand, DemonFilesystemCommand};
use red_cell_common::operator::OperatorMessage;
use serde_json::Value;
use tokio::time::{Duration, timeout};

#[tokio::test]
async fn builtin_filesystem_download_handler_persists_loot_and_progress()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF11, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database.clone(), sockets, None);

    let file_id = 0x33_u32;
    let remote_path = "C:\\Temp\\sam.dump";
    let content = b"secret-bytes";

    let mut open = Vec::new();
    add_u32(&mut open, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut open, 0);
    add_u32(&mut open, file_id);
    add_u64(&mut open, u64::try_from(content.len())?);
    add_utf16(&mut open, remote_path);
    dispatcher.dispatch(0xABCD_EF11, u32::from(DemonCommand::CommandFs), 0x99, &open).await?;

    let mut write = Vec::new();
    add_u32(&mut write, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut write, 1);
    add_u32(&mut write, file_id);
    add_bytes(&mut write, content);
    dispatcher.dispatch(0xABCD_EF11, u32::from(DemonCommand::CommandFs), 0x99, &write).await?;

    let mut close = Vec::new();
    add_u32(&mut close, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut close, 2);
    add_u32(&mut close, file_id);
    add_u32(&mut close, 0);
    dispatcher.dispatch(0xABCD_EF11, u32::from(DemonCommand::CommandFs), 0x99, &close).await?;

    let first = receiver.recv().await.ok_or("missing open event")?;
    let second = receiver.recv().await.ok_or("missing progress event")?;
    let third = receiver.recv().await.ok_or("missing loot event")?;
    let fourth = receiver.recv().await.ok_or("missing completion event")?;

    let OperatorMessage::AgentResponse(open_message) = first else {
        panic!("expected download open response");
    };
    assert_eq!(
        open_message.info.extra.get("MiscType"),
        Some(&Value::String("download-progress".to_owned()))
    );

    let OperatorMessage::AgentResponse(progress_message) = second else {
        panic!("expected download progress response");
    };
    assert_eq!(
        progress_message.info.extra.get("CurrentSize"),
        Some(&Value::String(content.len().to_string()))
    );

    let OperatorMessage::AgentResponse(loot_message) = third else {
        panic!("expected loot event");
    };
    assert_eq!(
        loot_message.info.extra.get("MiscType"),
        Some(&Value::String("loot-new".to_owned()))
    );

    let OperatorMessage::AgentResponse(done_message) = fourth else {
        panic!("expected download completion response");
    };
    assert_eq!(
        done_message.info.extra.get("MiscType"),
        Some(&Value::String("download".to_owned()))
    );
    assert_eq!(
        done_message.info.extra.get("MiscData"),
        Some(&Value::String(BASE64_STANDARD.encode(content)))
    );

    let loot = database.loot().list_for_agent(0xABCD_EF11).await?;
    assert_eq!(loot.len(), 1);
    assert_eq!(loot[0].kind, "download");
    assert_eq!(loot[0].file_path.as_deref(), Some(remote_path));
    assert_eq!(loot[0].data.as_deref(), Some(content.as_slice()));
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_download_handler_accumulates_multi_chunk_downloads_until_close()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF12, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database.clone(), sockets, None);

    let file_id = 0x34_u32;
    let remote_path = "C:\\Temp\\partial.dump";

    dispatcher
        .dispatch(
            0xABCD_EF12,
            u32::from(DemonCommand::CommandFs),
            0x9A,
            &filesystem_download_open(file_id, 64, remote_path),
        )
        .await?;
    dispatcher
        .dispatch(
            0xABCD_EF12,
            u32::from(DemonCommand::CommandFs),
            0x9A,
            &filesystem_download_write(file_id, b"secret-"),
        )
        .await?;
    dispatcher
        .dispatch(
            0xABCD_EF12,
            u32::from(DemonCommand::CommandFs),
            0x9A,
            &filesystem_download_write(file_id, b"bytes"),
        )
        .await?;

    assert!(database.loot().list_for_agent(0xABCD_EF12).await?.is_empty());

    let _ = receiver.recv().await.ok_or("missing filesystem open event")?;
    let progress_one = receiver.recv().await.ok_or("missing first filesystem progress event")?;
    let progress_two = receiver.recv().await.ok_or("missing second filesystem progress event")?;

    let OperatorMessage::AgentResponse(progress_one) = progress_one else {
        panic!("expected first filesystem progress response");
    };
    assert_eq!(progress_one.info.extra.get("CurrentSize"), Some(&Value::String("7".to_owned())));
    assert_eq!(progress_one.info.extra.get("ExpectedSize"), Some(&Value::String("64".to_owned())));

    let OperatorMessage::AgentResponse(progress_two) = progress_two else {
        panic!("expected second filesystem progress response");
    };
    assert_eq!(progress_two.info.extra.get("CurrentSize"), Some(&Value::String("12".to_owned())));
    assert_eq!(progress_two.info.extra.get("ExpectedSize"), Some(&Value::String("64".to_owned())));
    let active = dispatcher.downloads.active_for_agent(0xABCD_EF12).await;
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].0, file_id);
    assert_eq!(active[0].1.request_id, 0x9A);
    assert_eq!(active[0].1.remote_path, remote_path);
    assert_eq!(active[0].1.expected_size, 64);
    assert_eq!(active[0].1.data, b"secret-bytes");
    assert!(
        !active[0].1.started_at.is_empty(),
        "active filesystem download should preserve its start timestamp"
    );
    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "filesystem download should remain incomplete until close"
    );

    dispatcher
        .dispatch(
            0xABCD_EF12,
            u32::from(DemonCommand::CommandFs),
            0x9A,
            &filesystem_download_close(file_id, 0),
        )
        .await?;

    let _ = receiver.recv().await.ok_or("missing filesystem loot event")?;
    let completion = receiver.recv().await.ok_or("missing filesystem completion event")?;
    let OperatorMessage::AgentResponse(completion) = completion else {
        panic!("expected filesystem completion response");
    };
    assert_eq!(
        completion.info.extra.get("MiscData"),
        Some(&Value::String(BASE64_STANDARD.encode(b"secret-bytes")))
    );

    let loot = database.loot().list_for_agent(0xABCD_EF12).await?;
    assert_eq!(loot.len(), 1);
    assert_eq!(loot[0].data.as_deref(), Some(b"secret-bytes".as_slice()));
    assert_eq!(loot[0].file_path.as_deref(), Some(remote_path));
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_download_handler_rejects_writes_without_open()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF13, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database.clone(), sockets, None);

    let error = dispatcher
        .dispatch(
            0xABCD_EF13,
            u32::from(DemonCommand::CommandFs),
            0x9B,
            &filesystem_download_write(0x35, b"orphan"),
        )
        .await
        .expect_err("filesystem download write without open should fail");
    assert!(matches!(
        error,
        CommandDispatchError::InvalidCallbackPayload {
            command_id,
            message,
        } if command_id == 0
            && message.contains("0x00000035")
            && message.contains("was not opened")
    ));
    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "unexpected events for rejected filesystem download write"
    );
    assert!(database.loot().list_for_agent(0xABCD_EF13).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn download_tracker_accumulates_multi_chunk_data_until_finish() {
    let tracker = DownloadTracker::new(64);
    tracker
        .start(
            0xABCD_EF51,
            0x41,
            DownloadState {
                request_id: 0x71,
                remote_path: "C:\\Temp\\multi.bin".to_owned(),
                expected_size: 32,
                data: Vec::new(),
                started_at: "2026-03-11T09:00:00Z".to_owned(),
            },
        )
        .await
        .expect("start should succeed");

    let first = tracker.append(0xABCD_EF51, 0x41, b"abc").await.expect("first chunk should append");
    assert_eq!(first.data, b"abc");
    assert_eq!(first.expected_size, 32);

    let second =
        tracker.append(0xABCD_EF51, 0x41, b"def").await.expect("second chunk should append");
    assert_eq!(second.data, b"abcdef");
    assert_eq!(second.expected_size, 32);

    let finished = tracker.finish(0xABCD_EF51, 0x41).await;
    assert_eq!(
        finished,
        Some(DownloadState {
            request_id: 0x71,
            remote_path: "C:\\Temp\\multi.bin".to_owned(),
            expected_size: 32,
            data: b"abcdef".to_vec(),
            started_at: "2026-03-11T09:00:00Z".to_owned(),
        })
    );
    assert_eq!(tracker.finish(0xABCD_EF51, 0x41).await, None);
}

#[tokio::test]
async fn download_tracker_keeps_partial_downloads_active_until_finish() {
    let tracker = DownloadTracker::new(64);
    tracker
        .start(
            0xABCD_EF54,
            0x44,
            DownloadState {
                request_id: 0x73,
                remote_path: "C:\\Temp\\pending.bin".to_owned(),
                expected_size: 32,
                data: Vec::new(),
                started_at: "2026-03-11T09:10:00Z".to_owned(),
            },
        )
        .await
        .expect("start should succeed");

    let partial =
        tracker.append(0xABCD_EF54, 0x44, b"partial").await.expect("partial chunk should append");
    assert_eq!(partial.data, b"partial");
    assert_eq!(partial.expected_size, 32);

    let active = tracker.active_for_agent(0xABCD_EF54).await;
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].0, 0x44);
    assert_eq!(active[0].1, partial);

    assert_eq!(tracker.active_for_agent(0xABCD_EF99).await, Vec::new());
    assert_eq!(tracker.finish(0xABCD_EF54, 0x44).await, Some(partial));
}

#[tokio::test]
async fn download_tracker_drain_agent_discards_all_partial_downloads_for_agent() {
    let tracker = DownloadTracker::with_limits(64, 128);

    for (agent_id, file_id, data) in [
        (0xABCD_EF57, 0x70_u32, b"first".as_slice()),
        (0xABCD_EF57, 0x71_u32, b"second".as_slice()),
        (0xABCD_EF58, 0x72_u32, b"third".as_slice()),
    ] {
        tracker
            .start(
                agent_id,
                file_id,
                DownloadState {
                    request_id: file_id,
                    remote_path: format!("C:\\Temp\\{file_id:08x}.bin"),
                    expected_size: 32,
                    data: Vec::new(),
                    started_at: "2026-03-11T09:25:00Z".to_owned(),
                },
            )
            .await
            .expect("start should succeed");
        let state = tracker.append(agent_id, file_id, data).await.expect("chunk should append");
        assert_eq!(state.data, data);
    }

    assert_eq!(tracker.buffered_bytes().await, 16);
    assert_eq!(tracker.drain_agent(0xABCD_EF57).await, 2);
    assert!(tracker.active_for_agent(0xABCD_EF57).await.is_empty());
    assert_eq!(tracker.buffered_bytes().await, 5);
    assert_eq!(tracker.active_for_agent(0xABCD_EF58).await.len(), 1);
    assert_eq!(tracker.drain_agent(0xABCD_EF57).await, 0);
}

#[tokio::test]
async fn download_tracker_rejects_chunks_for_unknown_downloads() {
    let tracker = DownloadTracker::new(64);

    let error = tracker
        .append(0xABCD_EF52, 0x42, b"orphan")
        .await
        .expect_err("append without start should fail");
    assert!(matches!(
        error,
        CommandDispatchError::InvalidCallbackPayload {
            command_id,
            message,
        } if command_id == 0
            && message.contains("0x00000042")
            && message.contains("was not opened")
    ));
}

#[tokio::test]
async fn download_tracker_drops_downloads_that_exceed_the_size_cap() {
    let tracker = DownloadTracker::new(4);
    tracker
        .start(
            0xABCD_EF53,
            0x43,
            DownloadState {
                request_id: 0x72,
                remote_path: "C:\\Temp\\oversized.bin".to_owned(),
                expected_size: 16,
                data: Vec::new(),
                started_at: "2026-03-11T09:05:00Z".to_owned(),
            },
        )
        .await
        .expect("start should succeed");

    let partial =
        tracker.append(0xABCD_EF53, 0x43, b"12").await.expect("first partial chunk should append");
    assert_eq!(partial.data, b"12");

    let error = tracker
        .append(0xABCD_EF53, 0x43, b"345")
        .await
        .expect_err("downloads above the cap should be dropped");
    assert!(matches!(
        error,
        CommandDispatchError::DownloadTooLarge {
            agent_id: 0xABCD_EF53,
            file_id: 0x43,
            max_download_bytes: 4,
        }
    ));
    assert_eq!(tracker.finish(0xABCD_EF53, 0x43).await, None);
}

#[tokio::test]
async fn download_tracker_limits_total_buffered_bytes_across_partial_downloads() {
    let tracker = DownloadTracker::with_limits(8, 10);

    for file_id in [0x50_u32, 0x51, 0x52] {
        tracker
            .start(
                0xABCD_EF55,
                file_id,
                DownloadState {
                    request_id: 0x80 + file_id,
                    remote_path: format!("C:\\Temp\\{file_id:08x}.bin"),
                    expected_size: 16,
                    data: Vec::new(),
                    started_at: "2026-03-11T09:15:00Z".to_owned(),
                },
            )
            .await
            .expect("start should succeed");
    }

    assert_eq!(
        tracker.append(0xABCD_EF55, 0x50, b"abcd").await.expect("first chunk").data,
        b"abcd"
    );
    assert_eq!(
        tracker.append(0xABCD_EF55, 0x51, b"efgh").await.expect("second chunk").data,
        b"efgh"
    );
    assert_eq!(tracker.buffered_bytes().await, 8);

    let error = tracker
        .append(0xABCD_EF55, 0x52, b"ijk")
        .await
        .expect_err("aggregate cap should reject additional concurrent partial data");
    assert!(matches!(
        error,
        CommandDispatchError::DownloadAggregateTooLarge {
            agent_id: 0xABCD_EF55,
            file_id: 0x52,
            max_total_download_bytes: 10,
        }
    ));
    assert_eq!(tracker.buffered_bytes().await, 8);

    let active = tracker.active_for_agent(0xABCD_EF55).await;
    assert_eq!(active.len(), 2);
    assert_eq!(active[0].0, 0x50);
    assert_eq!(active[0].1.data, b"abcd");
    assert_eq!(active[1].0, 0x51);
    assert_eq!(active[1].1.data, b"efgh");
    assert_eq!(tracker.finish(0xABCD_EF55, 0x52).await, None);
}

#[tokio::test]
async fn download_tracker_keeps_idle_partial_downloads_until_finish() {
    let tracker = DownloadTracker::with_limits(16, 12);

    for file_id in [0x60_u32, 0x61] {
        tracker
            .start(
                0xABCD_EF56,
                file_id,
                DownloadState {
                    request_id: 0x90 + file_id,
                    remote_path: format!("C:\\Temp\\idle-{file_id:08x}.bin"),
                    expected_size: 32,
                    data: Vec::new(),
                    started_at: "2026-03-11T09:20:00Z".to_owned(),
                },
            )
            .await
            .expect("start should succeed");
    }

    tracker.append(0xABCD_EF56, 0x60, b"12").await.expect("first partial should append");
    tracker.append(0xABCD_EF56, 0x61, b"34").await.expect("second partial should append");
    assert_eq!(tracker.buffered_bytes().await, 4);

    tokio::time::sleep(std::time::Duration::from_millis(5)).await;

    let continued = tracker
        .append(0xABCD_EF56, 0x60, b"56")
        .await
        .expect("idle transfer should still accept more data");
    assert_eq!(continued.data, b"1256");
    assert_eq!(tracker.buffered_bytes().await, 6);

    let active = tracker.active_for_agent(0xABCD_EF56).await;
    assert_eq!(active.len(), 2);
    assert_eq!(active[0].0, 0x60);
    assert_eq!(active[0].1.data, b"1256");
    assert_eq!(active[1].0, 0x61);
    assert_eq!(active[1].1.data, b"34");

    assert_eq!(
        tracker.finish(0xABCD_EF56, 0x60).await,
        Some(DownloadState {
            request_id: 0xF0,
            remote_path: "C:\\Temp\\idle-00000060.bin".to_owned(),
            expected_size: 32,
            data: b"1256".to_vec(),
            started_at: "2026-03-11T09:20:00Z".to_owned(),
        })
    );
    assert_eq!(tracker.buffered_bytes().await, 2);
    assert_eq!(
        tracker.finish(0xABCD_EF56, 0x61).await,
        Some(DownloadState {
            request_id: 0xF1,
            remote_path: "C:\\Temp\\idle-00000061.bin".to_owned(),
            expected_size: 32,
            data: b"34".to_vec(),
            started_at: "2026-03-11T09:20:00Z".to_owned(),
        })
    );
}

#[tokio::test]
async fn download_tracker_rejects_start_when_per_agent_cap_is_reached() {
    // Use a tracker with a tiny per-agent cap so we don't need to create 32 entries.
    let mut tracker = DownloadTracker::with_limits(1024, 1024 * 64);
    tracker.max_concurrent_downloads_per_agent = 2;
    let agent_id = 0xDEAD_BEEF;

    let make_state = |file_id: u32| DownloadState {
        request_id: file_id,
        remote_path: format!("C:\\Temp\\file_{file_id:08x}.bin"),
        expected_size: 64,
        data: Vec::new(),
        started_at: "2026-03-28T00:00:00Z".to_owned(),
    };

    tracker.start(agent_id, 0x01, make_state(0x01)).await.expect("first start should succeed");
    tracker
        .start(agent_id, 0x02, make_state(0x02))
        .await
        .expect("second start should succeed (at cap)");

    let err = tracker
        .start(agent_id, 0x03, make_state(0x03))
        .await
        .expect_err("third start should be rejected (over cap)");
    assert!(
        matches!(
            err,
            CommandDispatchError::DownloadConcurrentLimitExceeded {
                agent_id: 0xDEAD_BEEF,
                file_id: 0x03,
                max_concurrent: 2,
            }
        ),
        "unexpected error variant: {err:?}"
    );
    // The rejected entry must not have been inserted.
    assert_eq!(tracker.active_for_agent(agent_id).await.len(), 2);
}

#[tokio::test]
async fn download_tracker_per_agent_cap_does_not_affect_other_agents() {
    let mut tracker = DownloadTracker::with_limits(1024, 1024 * 64);
    tracker.max_concurrent_downloads_per_agent = 1;

    let make_state = |file_id: u32| DownloadState {
        request_id: file_id,
        remote_path: format!("C:\\Temp\\file_{file_id:08x}.bin"),
        expected_size: 64,
        data: Vec::new(),
        started_at: "2026-03-28T00:00:00Z".to_owned(),
    };

    tracker.start(0xAAAA_0001, 0x10, make_state(0x10)).await.expect("agent A start ok");
    tracker.start(0xBBBB_0002, 0x20, make_state(0x20)).await.expect("agent B start ok");

    // Agent A is now at its cap — agent B should still be unaffected.
    let err = tracker
        .start(0xAAAA_0001, 0x11, make_state(0x11))
        .await
        .expect_err("agent A second start should be rejected");
    assert!(matches!(
        err,
        CommandDispatchError::DownloadConcurrentLimitExceeded { agent_id: 0xAAAA_0001, .. }
    ));

    // Agent B can still open another download.
    tracker
        .start(0xBBBB_0002, 0x21, make_state(0x21))
        .await
        .expect_err("agent B second start should also be rejected (cap=1)");
}

#[tokio::test]
async fn download_tracker_restart_same_file_id_does_not_count_as_new_slot() {
    let mut tracker = DownloadTracker::with_limits(1024, 1024 * 64);
    tracker.max_concurrent_downloads_per_agent = 1;
    let agent_id = 0xCAFE_BABE;

    let make_state = |file_id: u32| DownloadState {
        request_id: file_id,
        remote_path: format!("C:\\Temp\\file_{file_id:08x}.bin"),
        expected_size: 64,
        data: Vec::new(),
        started_at: "2026-03-28T00:00:00Z".to_owned(),
    };

    tracker.start(agent_id, 0x01, make_state(0x01)).await.expect("initial start");
    // Re-starting the same (agent, file) pair must replace the old entry, not consume an extra slot.
    tracker
        .start(agent_id, 0x01, make_state(0x01))
        .await
        .expect("restart of same file_id should succeed");
    assert_eq!(tracker.active_for_agent(agent_id).await.len(), 1);
}

#[tokio::test]
async fn builtin_beacon_file_callbacks_reassemble_downloads()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF21, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database.clone(), sockets, None);

    let file_id = 0x55_u32;
    let remote_path = "C:\\Windows\\Temp\\note.txt";
    let content = b"beacon-chunk";

    let mut open_header = Vec::new();
    open_header.extend_from_slice(&file_id.to_be_bytes());
    open_header.extend_from_slice(&(u32::try_from(content.len())?).to_be_bytes());
    open_header.extend_from_slice(remote_path.as_bytes());
    let mut open = Vec::new();
    add_u32(&mut open, u32::from(DemonCallback::File));
    add_bytes(&mut open, &open_header);
    dispatcher.dispatch(0xABCD_EF21, u32::from(DemonCommand::BeaconOutput), 0x77, &open).await?;

    let mut chunk = Vec::new();
    chunk.extend_from_slice(&file_id.to_be_bytes());
    chunk.extend_from_slice(content);
    let mut write = Vec::new();
    add_u32(&mut write, u32::from(DemonCallback::FileWrite));
    add_bytes(&mut write, &chunk);
    dispatcher.dispatch(0xABCD_EF21, u32::from(DemonCommand::BeaconOutput), 0x77, &write).await?;

    let mut close = Vec::new();
    add_u32(&mut close, u32::from(DemonCallback::FileClose));
    add_bytes(&mut close, &file_id.to_be_bytes());
    dispatcher.dispatch(0xABCD_EF21, u32::from(DemonCommand::BeaconOutput), 0x77, &close).await?;

    let _ = receiver.recv().await.ok_or("missing beacon open event")?;
    let _ = receiver.recv().await.ok_or("missing beacon progress event")?;
    let loot_event = receiver.recv().await.ok_or("missing beacon loot event")?;
    let final_event = receiver.recv().await.ok_or("missing beacon completion event")?;
    let OperatorMessage::AgentResponse(loot_message) = loot_event else {
        panic!("expected beacon file loot event");
    };
    assert_eq!(
        loot_message.info.extra.get("MiscType"),
        Some(&Value::String("loot-new".to_owned()))
    );
    let OperatorMessage::AgentResponse(message) = final_event else {
        panic!("expected beacon file completion response");
    };
    assert_eq!(message.info.extra.get("MiscType"), Some(&Value::String("download".to_owned())));

    let loot = database.loot().list_for_agent(0xABCD_EF21).await?;
    assert_eq!(loot.len(), 1);
    assert_eq!(loot[0].data.as_deref(), Some(content.as_slice()));
    assert_eq!(loot[0].file_path.as_deref(), Some(remote_path));
    Ok(())
}

#[tokio::test]
async fn builtin_beacon_file_callbacks_accumulate_partial_downloads_until_close()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF22, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database.clone(), sockets, None);

    let file_id = 0x56_u32;
    let remote_path = "C:\\Windows\\Temp\\partial.txt";

    dispatcher
        .dispatch(
            0xABCD_EF22,
            u32::from(DemonCommand::BeaconOutput),
            0x78,
            &beacon_file_open(file_id, 32, remote_path),
        )
        .await?;
    dispatcher
        .dispatch(
            0xABCD_EF22,
            u32::from(DemonCommand::BeaconOutput),
            0x78,
            &beacon_file_write(file_id, b"beacon-"),
        )
        .await?;
    dispatcher
        .dispatch(
            0xABCD_EF22,
            u32::from(DemonCommand::BeaconOutput),
            0x78,
            &beacon_file_write(file_id, b"chunk"),
        )
        .await?;

    assert!(database.loot().list_for_agent(0xABCD_EF22).await?.is_empty());

    let _ = receiver.recv().await.ok_or("missing beacon open event")?;
    let progress_one = receiver.recv().await.ok_or("missing first beacon progress event")?;
    let progress_two = receiver.recv().await.ok_or("missing second beacon progress event")?;

    let OperatorMessage::AgentResponse(progress_one) = progress_one else {
        panic!("expected first beacon progress response");
    };
    assert_eq!(progress_one.info.extra.get("CurrentSize"), Some(&Value::String("7".to_owned())));
    assert_eq!(progress_one.info.extra.get("ExpectedSize"), Some(&Value::String("32".to_owned())));

    let OperatorMessage::AgentResponse(progress_two) = progress_two else {
        panic!("expected second beacon progress response");
    };
    assert_eq!(progress_two.info.extra.get("CurrentSize"), Some(&Value::String("12".to_owned())));
    assert_eq!(progress_two.info.extra.get("ExpectedSize"), Some(&Value::String("32".to_owned())));
    let active = dispatcher.downloads.active_for_agent(0xABCD_EF22).await;
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].0, file_id);
    assert_eq!(active[0].1.request_id, 0x78);
    assert_eq!(active[0].1.remote_path, remote_path);
    assert_eq!(active[0].1.expected_size, 32);
    assert_eq!(active[0].1.data, b"beacon-chunk");
    assert!(
        !active[0].1.started_at.is_empty(),
        "active beacon download should preserve its start timestamp"
    );
    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "beacon download should remain incomplete until close"
    );

    dispatcher
        .dispatch(
            0xABCD_EF22,
            u32::from(DemonCommand::BeaconOutput),
            0x78,
            &beacon_file_close(file_id),
        )
        .await?;

    let _ = receiver.recv().await.ok_or("missing beacon loot event")?;
    let completion = receiver.recv().await.ok_or("missing beacon completion event")?;
    let OperatorMessage::AgentResponse(completion) = completion else {
        panic!("expected beacon completion response");
    };
    assert_eq!(
        completion.info.extra.get("MiscData"),
        Some(&Value::String(BASE64_STANDARD.encode(b"beacon-chunk")))
    );

    let loot = database.loot().list_for_agent(0xABCD_EF22).await?;
    assert_eq!(loot.len(), 1);
    assert_eq!(loot[0].data.as_deref(), Some(b"beacon-chunk".as_slice()));
    assert_eq!(loot[0].file_path.as_deref(), Some(remote_path));
    Ok(())
}

#[tokio::test]
async fn builtin_beacon_file_callbacks_reject_writes_without_open()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF23, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database.clone(), sockets, None);

    let error = dispatcher
        .dispatch(
            0xABCD_EF23,
            u32::from(DemonCommand::BeaconOutput),
            0x79,
            &beacon_file_write(0x57, b"orphan"),
        )
        .await
        .expect_err("beacon file write without open should fail");
    assert!(matches!(
        error,
        CommandDispatchError::InvalidCallbackPayload {
            command_id,
            message,
        } if command_id == 0
            && message.contains("0x00000057")
            && message.contains("was not opened")
    ));
    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "unexpected events for rejected beacon download write"
    );
    assert!(database.loot().list_for_agent(0xABCD_EF23).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_download_handler_surfaces_over_limit_as_error_event()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF31, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher = CommandDispatcher::with_builtin_handlers_and_max_download_bytes(
        registry,
        events,
        database.clone(),
        sockets,
        None,
        4,
    );

    let file_id = 0x91_u32;
    let mut open = Vec::new();
    add_u32(&mut open, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut open, 0);
    add_u32(&mut open, file_id);
    add_u64(&mut open, 8);
    add_utf16(&mut open, "C:\\Temp\\oversized.bin");
    dispatcher.dispatch(0xABCD_EF31, u32::from(DemonCommand::CommandFs), 0x99, &open).await?;

    // Chunk that exceeds the 4-byte cap — must succeed (not propagate error).
    let mut write = Vec::new();
    add_u32(&mut write, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut write, 1);
    add_u32(&mut write, file_id);
    add_bytes(&mut write, b"12345");
    dispatcher
        .dispatch(0xABCD_EF31, u32::from(DemonCommand::CommandFs), 0x99, &write)
        .await
        .expect("oversized chunk should not propagate as dispatch error");

    // Open event (download-progress "Started").
    let open_event = receiver.recv().await.ok_or("missing open event")?;
    let OperatorMessage::AgentResponse(open_message) = open_event else {
        panic!("expected download open response");
    };
    assert_eq!(
        open_message.info.extra.get("MiscType"),
        Some(&Value::String("download-progress".to_owned()))
    );

    // Error event surfaced to operator.
    let error_event = receiver.recv().await.ok_or("missing error event")?;
    let OperatorMessage::AgentResponse(error_message) = error_event else {
        panic!("expected AgentResponse error event");
    };
    assert_eq!(error_message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    let msg = error_message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("limit exceeded"), "error message should mention limit exceeded: {msg}");

    // Audit log must have a download.rejected entry.
    let audit_rows = database.audit_log().list().await?;
    assert!(
        audit_rows.iter().any(|r| r.action == "download.rejected"),
        "audit log must contain a download.rejected entry"
    );

    // No loot must have been persisted.
    assert!(database.loot().list_for_agent(0xABCD_EF31).await?.is_empty());

    // Close packet is harmless (download already removed from tracker).
    let mut close = Vec::new();
    add_u32(&mut close, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut close, 2);
    add_u32(&mut close, file_id);
    add_u32(&mut close, 0);
    assert_eq!(
        dispatcher.dispatch(0xABCD_EF31, u32::from(DemonCommand::CommandFs), 0x99, &close).await?,
        None
    );
    Ok(())
}

// ── Filesystem subcommand tests (non-Download) ──────────────────────────

#[tokio::test]
async fn builtin_filesystem_upload_broadcasts_info() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_0001, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Upload));
    add_u32(&mut payload, 4096); // size
    add_utf16(&mut payload, "C:\\Temp\\payload.bin");
    dispatcher.dispatch(0xF500_0001, u32::from(DemonCommand::CommandFs), 0xA1, &payload).await?;

    let event = receiver.recv().await.ok_or("missing upload event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for upload");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String("Uploaded file: C:\\Temp\\payload.bin (4096 bytes)".to_owned()))
    );
    assert_eq!(msg.info.extra.get("Type"), Some(&Value::String("Info".to_owned())));
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_cd_broadcasts_changed_directory()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_0002, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Cd));
    add_utf16(&mut payload, "C:\\Users\\Admin\\Desktop");
    dispatcher.dispatch(0xF500_0002, u32::from(DemonCommand::CommandFs), 0xA2, &payload).await?;

    let event = receiver.recv().await.ok_or("missing cd event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for cd");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String("Changed directory: C:\\Users\\Admin\\Desktop".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_remove_file_broadcasts_info() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_0003, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    // Remove a file (is_dir = false = 0)
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Remove));
    add_u32(&mut payload, 0); // is_dir = false
    add_utf16(&mut payload, "C:\\Temp\\old.txt");
    dispatcher.dispatch(0xF500_0003, u32::from(DemonCommand::CommandFs), 0xA3, &payload).await?;

    let event = receiver.recv().await.ok_or("missing remove event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for remove");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String("Removed file: C:\\Temp\\old.txt".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_remove_directory_broadcasts_info()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_0004, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    // Remove a directory (is_dir = true = 1)
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Remove));
    add_u32(&mut payload, 1); // is_dir = true
    add_utf16(&mut payload, "C:\\Temp\\subdir");
    dispatcher.dispatch(0xF500_0004, u32::from(DemonCommand::CommandFs), 0xA4, &payload).await?;

    let event = receiver.recv().await.ok_or("missing remove dir event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for remove dir");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String("Removed directory: C:\\Temp\\subdir".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_mkdir_broadcasts_info() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_0005, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Mkdir));
    add_utf16(&mut payload, "C:\\Temp\\newdir");
    dispatcher.dispatch(0xF500_0005, u32::from(DemonCommand::CommandFs), 0xA5, &payload).await?;

    let event = receiver.recv().await.ok_or("missing mkdir event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for mkdir");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String("Created directory: C:\\Temp\\newdir".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_copy_success_broadcasts_good() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_0006, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Copy));
    add_u32(&mut payload, 1); // success = true
    add_utf16(&mut payload, "C:\\src\\file.txt");
    add_utf16(&mut payload, "C:\\dst\\file.txt");
    dispatcher.dispatch(0xF500_0006, u32::from(DemonCommand::CommandFs), 0xA6, &payload).await?;

    let event = receiver.recv().await.ok_or("missing copy event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for copy");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String(
            "Successfully copied file C:\\src\\file.txt to C:\\dst\\file.txt".to_owned()
        ))
    );
    assert_eq!(msg.info.extra.get("Type"), Some(&Value::String("Good".to_owned())));
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_copy_failure_broadcasts_error() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_0007, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Copy));
    add_u32(&mut payload, 0); // success = false
    add_utf16(&mut payload, "C:\\nope\\a.txt");
    add_utf16(&mut payload, "C:\\nope\\b.txt");
    dispatcher.dispatch(0xF500_0007, u32::from(DemonCommand::CommandFs), 0xA7, &payload).await?;

    let event = receiver.recv().await.ok_or("missing copy failure event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for copy failure");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String("Failed to copy file C:\\nope\\a.txt to C:\\nope\\b.txt".to_owned()))
    );
    assert_eq!(msg.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_move_success_broadcasts_good() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_0008, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Move));
    add_u32(&mut payload, 1); // success = true
    add_utf16(&mut payload, "C:\\old\\data.bin");
    add_utf16(&mut payload, "C:\\new\\data.bin");
    dispatcher.dispatch(0xF500_0008, u32::from(DemonCommand::CommandFs), 0xA8, &payload).await?;

    let event = receiver.recv().await.ok_or("missing move event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for move");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String(
            "Successfully moved file C:\\old\\data.bin to C:\\new\\data.bin".to_owned()
        ))
    );
    assert_eq!(msg.info.extra.get("Type"), Some(&Value::String("Good".to_owned())));
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_move_failure_broadcasts_error() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_0009, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Move));
    add_u32(&mut payload, 0); // success = false
    add_utf16(&mut payload, "C:\\locked\\x.dll");
    add_utf16(&mut payload, "C:\\dest\\x.dll");
    dispatcher.dispatch(0xF500_0009, u32::from(DemonCommand::CommandFs), 0xA9, &payload).await?;

    let event = receiver.recv().await.ok_or("missing move failure event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for move failure");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String("Failed to move file C:\\locked\\x.dll to C:\\dest\\x.dll".to_owned()))
    );
    assert_eq!(msg.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_getpwd_broadcasts_current_directory()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_000A, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::GetPwd));
    add_utf16(&mut payload, "C:\\Windows\\System32");
    dispatcher.dispatch(0xF500_000A, u32::from(DemonCommand::CommandFs), 0xAA, &payload).await?;

    let event = receiver.recv().await.ok_or("missing getpwd event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for getpwd");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String("Current directory: C:\\Windows\\System32".to_owned()))
    );
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_cat_success_broadcasts_content()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_000B, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let file_content = "Hello, world!\nLine two.";
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Cat));
    add_utf16(&mut payload, "C:\\flag.txt");
    add_u32(&mut payload, 1); // success = true
    add_bytes(&mut payload, file_content.as_bytes()); // read_string uses read_bytes
    dispatcher.dispatch(0xF500_000B, u32::from(DemonCommand::CommandFs), 0xAB, &payload).await?;

    let event = receiver.recv().await.ok_or("missing cat event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for cat");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String(format!("File content of C:\\flag.txt ({}):", file_content.len())))
    );
    assert_eq!(msg.info.extra.get("Type"), Some(&Value::String("Info".to_owned())));
    assert_eq!(msg.info.output, file_content);
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_cat_failure_broadcasts_error() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_000C, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Cat));
    add_utf16(&mut payload, "C:\\nonexistent.txt");
    add_u32(&mut payload, 0); // success = false
    add_bytes(&mut payload, b"error details");
    dispatcher.dispatch(0xF500_000C, u32::from(DemonCommand::CommandFs), 0xAC, &payload).await?;

    let event = receiver.recv().await.ok_or("missing cat failure event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for cat failure");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String("Failed to read file: C:\\nonexistent.txt".to_owned()))
    );
    assert_eq!(msg.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    // On failure, output should be empty (None maps to empty string)
    assert_eq!(msg.info.output, "");
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_dir_list_only_broadcasts_paths()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_0010, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Dir));
    add_u32(&mut payload, 0); // explorer = false
    add_u32(&mut payload, 1); // list_only = true
    add_utf16(&mut payload, "C:\\Temp\\*");
    add_u32(&mut payload, 1); // success = true
    // One directory entry with 2 files, 0 dirs
    add_utf16(&mut payload, "C:\\Temp\\");
    add_u32(&mut payload, 2); // file_count
    add_u32(&mut payload, 0); // dir_count
    // No total_size for list_only mode
    // Item 1
    add_utf16(&mut payload, "a.txt");
    // Item 2
    add_utf16(&mut payload, "b.log");

    dispatcher.dispatch(0xF500_0010, u32::from(DemonCommand::CommandFs), 0xB0, &payload).await?;

    let event = receiver.recv().await.ok_or("missing dir list event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for dir list_only");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String("Directory listing completed".to_owned()))
    );
    // In list_only mode, output is just path+name lines
    assert!(msg.info.output.contains("C:\\Temp\\a.txt"), "output should contain a.txt");
    assert!(msg.info.output.contains("C:\\Temp\\b.log"), "output should contain b.log");
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_dir_normal_mode_broadcasts_formatted_listing()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_0011, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Dir));
    add_u32(&mut payload, 0); // explorer = false
    add_u32(&mut payload, 0); // list_only = false
    add_utf16(&mut payload, "C:\\Data\\*");
    add_u32(&mut payload, 1); // success = true
    // Directory entry
    add_utf16(&mut payload, "C:\\Data\\");
    add_u32(&mut payload, 1); // file_count
    add_u32(&mut payload, 1); // dir_count
    add_u64(&mut payload, 2048); // total_size (present when not list_only)
    // Item 1: a directory
    add_utf16(&mut payload, "subdir");
    add_u32(&mut payload, 1); // is_dir = true
    add_u64(&mut payload, 0); // size (ignored for dirs)
    add_u32(&mut payload, 15); // day
    add_u32(&mut payload, 3); // month
    add_u32(&mut payload, 2026); // year
    add_u32(&mut payload, 30); // minute
    add_u32(&mut payload, 14); // hour
    // Item 2: a file
    add_utf16(&mut payload, "readme.md");
    add_u32(&mut payload, 0); // is_dir = false
    add_u64(&mut payload, 2048); // size
    add_u32(&mut payload, 15); // day
    add_u32(&mut payload, 3); // month
    add_u32(&mut payload, 2026); // year
    add_u32(&mut payload, 0); // minute
    add_u32(&mut payload, 9); // hour

    dispatcher.dispatch(0xF500_0011, u32::from(DemonCommand::CommandFs), 0xB1, &payload).await?;

    let event = receiver.recv().await.ok_or("missing dir normal event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for dir normal mode");
    };
    let output = &msg.info.output;
    assert!(output.contains("Directory of C:\\Data\\"), "should contain directory header");
    assert!(output.contains("<DIR>"), "should contain <DIR> marker for subdirectory");
    assert!(output.contains("subdir"), "should list subdir name");
    assert!(output.contains("readme.md"), "should list file name");
    assert!(output.contains("1 File(s)"), "should show file count");
    assert!(output.contains("1 Folder(s)"), "should show folder count");
    // Check date formatting: "15/03/2026  14:30"
    assert!(output.contains("15/03/2026"), "should contain formatted date");
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_dir_explorer_mode_broadcasts_base64_json()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_0012, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Dir));
    add_u32(&mut payload, 1); // explorer = true
    add_u32(&mut payload, 0); // list_only = false
    add_utf16(&mut payload, "C:\\Loot\\");
    add_u32(&mut payload, 1); // success = true
    // Directory entry
    add_utf16(&mut payload, "C:\\Loot\\");
    add_u32(&mut payload, 1); // file_count
    add_u32(&mut payload, 0); // dir_count
    add_u64(&mut payload, 512); // total_size
    // Item 1: a file
    add_utf16(&mut payload, "secret.key");
    add_u32(&mut payload, 0); // is_dir = false
    add_u64(&mut payload, 512); // size
    add_u32(&mut payload, 1); // day
    add_u32(&mut payload, 1); // month
    add_u32(&mut payload, 2026); // year
    add_u32(&mut payload, 0); // minute
    add_u32(&mut payload, 12); // hour

    dispatcher.dispatch(0xF500_0012, u32::from(DemonCommand::CommandFs), 0xB2, &payload).await?;

    let event = receiver.recv().await.ok_or("missing dir explorer event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for dir explorer");
    };
    assert_eq!(msg.info.extra.get("MiscType"), Some(&Value::String("FileExplorer".to_owned())));
    // MiscData should be base64-encoded JSON with Path and Files
    let misc_data = msg.info.extra.get("MiscData").expect("MiscData should exist");
    let Value::String(b64) = misc_data else {
        panic!("MiscData should be a string");
    };
    let decoded = BASE64_STANDARD.decode(b64)?;
    let json: Value = serde_json::from_slice(&decoded)?;
    assert_eq!(json["Path"], Value::String("C:\\Loot\\".to_owned()));
    let files = json["Files"].as_array().expect("Files should be an array");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["Name"], Value::String("secret.key".to_owned()));
    assert_eq!(files[0]["Type"], Value::String("".to_owned())); // file, not dir
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_dir_failure_broadcasts_not_found()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xF500_0013, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);

    // Dir with success=false — no items follow
    let mut payload = Vec::new();
    add_u32(&mut payload, u32::from(DemonFilesystemCommand::Dir));
    add_u32(&mut payload, 0); // explorer = false
    add_u32(&mut payload, 0); // list_only = false
    add_utf16(&mut payload, "C:\\NoSuchDir\\*");
    add_u32(&mut payload, 0); // success = false

    dispatcher.dispatch(0xF500_0013, u32::from(DemonCommand::CommandFs), 0xB3, &payload).await?;

    let event = receiver.recv().await.ok_or("missing dir failure event")?;
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse for dir failure");
    };
    assert_eq!(
        msg.info.extra.get("Message"),
        Some(&Value::String("No file or folder was found".to_owned()))
    );
    assert_eq!(msg.info.output, "No file or folder was found");
    Ok(())
}

#[tokio::test]
async fn builtin_beacon_file_callbacks_surface_over_limit_as_error_event()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF41, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher = CommandDispatcher::with_builtin_handlers_and_max_download_bytes(
        registry,
        events,
        database.clone(),
        sockets,
        None,
        4,
    );

    let file_id = 0x92_u32;
    let mut open_header = Vec::new();
    open_header.extend_from_slice(&file_id.to_be_bytes());
    open_header.extend_from_slice(&8_u32.to_be_bytes());
    open_header.extend_from_slice(b"C:\\Windows\\Temp\\oversized.txt");
    let mut open = Vec::new();
    add_u32(&mut open, u32::from(DemonCallback::File));
    add_bytes(&mut open, &open_header);
    dispatcher.dispatch(0xABCD_EF41, u32::from(DemonCommand::BeaconOutput), 0x77, &open).await?;

    // Chunk that exceeds the 4-byte cap — must succeed (not propagate error).
    let mut chunk = Vec::new();
    chunk.extend_from_slice(&file_id.to_be_bytes());
    chunk.extend_from_slice(b"12345");
    let mut write = Vec::new();
    add_u32(&mut write, u32::from(DemonCallback::FileWrite));
    add_bytes(&mut write, &chunk);
    dispatcher
        .dispatch(0xABCD_EF41, u32::from(DemonCommand::BeaconOutput), 0x77, &write)
        .await
        .expect("oversized beacon chunk should not propagate as dispatch error");

    // Open event (download-progress "Started").
    let open_event = receiver.recv().await.ok_or("missing beacon open event")?;
    let OperatorMessage::AgentResponse(open_message) = open_event else {
        panic!("expected beacon open response");
    };
    assert_eq!(
        open_message.info.extra.get("MiscType"),
        Some(&Value::String("download-progress".to_owned()))
    );

    // Error event surfaced to operator.
    let error_event = receiver.recv().await.ok_or("missing error event")?;
    let OperatorMessage::AgentResponse(error_message) = error_event else {
        panic!("expected AgentResponse error event");
    };
    assert_eq!(error_message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    let msg = error_message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("limit exceeded"), "error message should mention limit exceeded: {msg}");

    // Audit log must have a download.rejected entry.
    let audit_rows = database.audit_log().list().await?;
    assert!(
        audit_rows.iter().any(|r| r.action == "download.rejected"),
        "audit log must contain a download.rejected entry"
    );

    // No loot must have been persisted.
    assert!(database.loot().list_for_agent(0xABCD_EF41).await?.is_empty());

    // Close packet is harmless (download already removed from tracker).
    let mut close = Vec::new();
    add_u32(&mut close, u32::from(DemonCallback::FileClose));
    add_bytes(&mut close, &file_id.to_be_bytes());
    assert_eq!(
        dispatcher
            .dispatch(0xABCD_EF41, u32::from(DemonCommand::BeaconOutput), 0x77, &close)
            .await?,
        None
    );
    Ok(())
}

#[tokio::test]
async fn builtin_filesystem_download_handler_surfaces_concurrent_limit_as_error_event()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF70, test_key(0x11), test_iv(0x22))).await?;
    let tracker = DownloadTracker::new(1024 * 1024).with_max_concurrent_per_agent(1);
    let dispatcher = CommandDispatcher::with_builtin_handlers_and_downloads(
        registry,
        events,
        database.clone(),
        sockets,
        None,
        tracker,
        DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        false,
    );

    let file_id_1 = 0xB1_u32;
    let file_id_2 = 0xB2_u32;

    // Open first download — must succeed.
    let mut open1 = Vec::new();
    add_u32(&mut open1, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut open1, 0);
    add_u32(&mut open1, file_id_1);
    add_u64(&mut open1, 16);
    add_utf16(&mut open1, "C:\\Temp\\first.bin");
    dispatcher.dispatch(0xABCD_EF70, u32::from(DemonCommand::CommandFs), 0x99, &open1).await?;

    // Open second download while first is still active — concurrent limit exceeded.
    // Must return Ok(()) (error is surfaced as event, not propagated).
    let mut open2 = Vec::new();
    add_u32(&mut open2, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut open2, 0);
    add_u32(&mut open2, file_id_2);
    add_u64(&mut open2, 16);
    add_utf16(&mut open2, "C:\\Temp\\second.bin");
    dispatcher
        .dispatch(0xABCD_EF70, u32::from(DemonCommand::CommandFs), 0x99, &open2)
        .await
        .expect("concurrent-limit rejection must not propagate as dispatch error");

    // First event: download-progress "Started" for the first file.
    let open_event = receiver.recv().await.ok_or("missing open event")?;
    let OperatorMessage::AgentResponse(open_message) = open_event else {
        panic!("expected AgentResponse for first download open");
    };
    assert_eq!(
        open_message.info.extra.get("MiscType"),
        Some(&Value::String("download-progress".to_owned()))
    );

    // Second event: error event for the concurrent-limit rejection.
    let error_event = receiver.recv().await.ok_or("missing error event")?;
    let OperatorMessage::AgentResponse(error_message) = error_event else {
        panic!("expected AgentResponse error event for concurrent-limit rejection");
    };
    assert_eq!(error_message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    let msg = error_message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("limit exceeded"), "error message should mention limit exceeded: {msg}");

    // Audit log must contain a download.rejected entry.
    let audit_rows = database.audit_log().list().await?;
    assert!(
        audit_rows.iter().any(|r| r.action == "download.rejected"),
        "audit log must contain a download.rejected entry"
    );

    // No loot persisted (neither download completed).
    assert!(database.loot().list_for_agent(0xABCD_EF70).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn builtin_beacon_file_callbacks_surface_concurrent_limit_as_error_event()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF71, test_key(0x11), test_iv(0x22))).await?;
    let tracker = DownloadTracker::new(1024 * 1024).with_max_concurrent_per_agent(1);
    let dispatcher = CommandDispatcher::with_builtin_handlers_and_downloads(
        registry,
        events,
        database.clone(),
        sockets,
        None,
        tracker,
        DEFAULT_MAX_PIVOT_CHAIN_DEPTH,
        false,
    );

    let file_id_1 = 0xC1_u32;
    let file_id_2 = 0xC2_u32;

    // Open first beacon file download — must succeed.
    let mut open_header1 = Vec::new();
    open_header1.extend_from_slice(&file_id_1.to_be_bytes());
    open_header1.extend_from_slice(&16_u32.to_be_bytes());
    open_header1.extend_from_slice(b"C:\\Windows\\Temp\\first.txt");
    let mut open1 = Vec::new();
    add_u32(&mut open1, u32::from(DemonCallback::File));
    add_bytes(&mut open1, &open_header1);
    dispatcher.dispatch(0xABCD_EF71, u32::from(DemonCommand::BeaconOutput), 0x77, &open1).await?;

    // Open second beacon file download while first is active — concurrent limit exceeded.
    // Must return Ok(()) (error is surfaced as event, not propagated).
    let mut open_header2 = Vec::new();
    open_header2.extend_from_slice(&file_id_2.to_be_bytes());
    open_header2.extend_from_slice(&16_u32.to_be_bytes());
    open_header2.extend_from_slice(b"C:\\Windows\\Temp\\second.txt");
    let mut open2 = Vec::new();
    add_u32(&mut open2, u32::from(DemonCallback::File));
    add_bytes(&mut open2, &open_header2);
    dispatcher
        .dispatch(0xABCD_EF71, u32::from(DemonCommand::BeaconOutput), 0x77, &open2)
        .await
        .expect("concurrent-limit rejection must not propagate as dispatch error");

    // First event: download-progress "Started" for the first file.
    let open_event = receiver.recv().await.ok_or("missing beacon open event")?;
    let OperatorMessage::AgentResponse(open_message) = open_event else {
        panic!("expected AgentResponse for first beacon file open");
    };
    assert_eq!(
        open_message.info.extra.get("MiscType"),
        Some(&Value::String("download-progress".to_owned()))
    );

    // Second event: error event for the concurrent-limit rejection.
    let error_event = receiver.recv().await.ok_or("missing error event")?;
    let OperatorMessage::AgentResponse(error_message) = error_event else {
        panic!("expected AgentResponse error event for concurrent-limit rejection");
    };
    assert_eq!(error_message.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    let msg = error_message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg.contains("limit exceeded"), "error message should mention limit exceeded: {msg}");

    // Audit log must contain a download.rejected entry.
    let audit_rows = database.audit_log().list().await?;
    assert!(
        audit_rows.iter().any(|r| r.action == "download.rejected"),
        "audit log must contain a download.rejected entry"
    );

    // No loot persisted (neither download completed).
    assert!(database.loot().list_for_agent(0xABCD_EF71).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn with_builtin_handlers_and_max_download_bytes_happy_path()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF60, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher = CommandDispatcher::with_builtin_handlers_and_max_download_bytes(
        registry,
        events,
        database.clone(),
        sockets,
        None,
        512,
    );

    let file_id = 0xA1_u32;
    let content = b"small-payload";

    // Open
    let mut open = Vec::new();
    add_u32(&mut open, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut open, 0);
    add_u32(&mut open, file_id);
    add_u64(&mut open, u64::try_from(content.len())?);
    add_utf16(&mut open, "C:\\Temp\\small.bin");
    dispatcher.dispatch(0xABCD_EF60, u32::from(DemonCommand::CommandFs), 0x99, &open).await?;

    // Write (13 bytes < 512 ceiling)
    let mut write = Vec::new();
    add_u32(&mut write, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut write, 1);
    add_u32(&mut write, file_id);
    add_bytes(&mut write, content);
    dispatcher.dispatch(0xABCD_EF60, u32::from(DemonCommand::CommandFs), 0x99, &write).await?;

    // Close
    let mut close = Vec::new();
    add_u32(&mut close, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut close, 2);
    add_u32(&mut close, file_id);
    add_u32(&mut close, 0);
    dispatcher.dispatch(0xABCD_EF60, u32::from(DemonCommand::CommandFs), 0x99, &close).await?;

    // Drain events: open, progress, loot, completion
    let _open_event = receiver.recv().await.ok_or("missing open event")?;
    let _progress_event = receiver.recv().await.ok_or("missing progress event")?;
    let loot_event = receiver.recv().await.ok_or("missing loot event")?;
    let _done_event = receiver.recv().await.ok_or("missing completion event")?;

    let OperatorMessage::AgentResponse(loot_message) = loot_event else {
        panic!("expected loot event");
    };
    assert_eq!(
        loot_message.info.extra.get("MiscType"),
        Some(&Value::String("loot-new".to_owned()))
    );

    let loot = database.loot().list_for_agent(0xABCD_EF60).await?;
    assert_eq!(loot.len(), 1);
    assert_eq!(loot[0].kind, "download");
    assert_eq!(loot[0].file_path.as_deref(), Some("C:\\Temp\\small.bin"));
    assert_eq!(loot[0].data.as_deref(), Some(content.as_slice()));
    Ok(())
}

#[tokio::test]
async fn with_builtin_handlers_and_max_download_bytes_ceiling_exceeded()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF61, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher = CommandDispatcher::with_builtin_handlers_and_max_download_bytes(
        registry,
        events,
        database.clone(),
        sockets,
        None,
        8,
    );

    let file_id = 0xA2_u32;

    // Open
    let mut open = Vec::new();
    add_u32(&mut open, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut open, 0);
    add_u32(&mut open, file_id);
    add_u64(&mut open, 32);
    add_utf16(&mut open, "C:\\Temp\\big.bin");
    dispatcher.dispatch(0xABCD_EF61, u32::from(DemonCommand::CommandFs), 0x99, &open).await?;

    // Write chunk that exceeds ceiling (9 bytes > 8) — must succeed, error surfaced as event.
    let mut write = Vec::new();
    add_u32(&mut write, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut write, 1);
    add_u32(&mut write, file_id);
    add_bytes(&mut write, b"123456789");
    dispatcher
        .dispatch(0xABCD_EF61, u32::from(DemonCommand::CommandFs), 0x99, &write)
        .await
        .expect("oversized chunk should not propagate as dispatch error");

    // Subsequent write for the same file_id hits InvalidCallbackPayload (download dropped).
    let mut write2 = Vec::new();
    add_u32(&mut write2, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut write2, 1);
    add_u32(&mut write2, file_id);
    add_bytes(&mut write2, b"ab");
    let error2 =
        dispatcher.dispatch(0xABCD_EF61, u32::from(DemonCommand::CommandFs), 0x99, &write2).await;
    assert!(error2.is_err(), "writes after drop should be rejected with protocol error");

    // Drain: open event, then error event for the oversized chunk.
    let _open_event = receiver.recv().await.ok_or("missing open event")?;
    let error_event = receiver.recv().await.ok_or("missing error event")?;
    let OperatorMessage::AgentResponse(error_msg) = error_event else {
        panic!("expected AgentResponse error event");
    };
    assert_eq!(error_msg.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));
    // No further events (write2 errors without events).
    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "no further events after drop"
    );

    // Audit log must contain a download.rejected entry.
    let audit_rows = database.audit_log().list().await?;
    assert!(
        audit_rows.iter().any(|r| r.action == "download.rejected"),
        "audit log must contain a download.rejected entry"
    );
    assert!(database.loot().list_for_agent(0xABCD_EF61).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn with_builtin_handlers_and_max_download_bytes_zero_ceiling()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    registry.insert(sample_agent_info(0xABCD_EF62, test_key(0x11), test_iv(0x22))).await?;
    let dispatcher = CommandDispatcher::with_builtin_handlers_and_max_download_bytes(
        registry,
        events,
        database.clone(),
        sockets,
        None,
        0,
    );

    let file_id = 0xA3_u32;

    // Open succeeds (start does not enforce the cap)
    let mut open = Vec::new();
    add_u32(&mut open, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut open, 0);
    add_u32(&mut open, file_id);
    add_u64(&mut open, 1);
    add_utf16(&mut open, "C:\\Temp\\zero.bin");
    dispatcher.dispatch(0xABCD_EF62, u32::from(DemonCommand::CommandFs), 0x99, &open).await?;

    // Even a single byte write should be surfaced as error event with ceiling=0.
    let mut write = Vec::new();
    add_u32(&mut write, u32::from(DemonFilesystemCommand::Download));
    add_u32(&mut write, 1);
    add_u32(&mut write, file_id);
    add_bytes(&mut write, b"x");
    dispatcher
        .dispatch(0xABCD_EF62, u32::from(DemonCommand::CommandFs), 0x99, &write)
        .await
        .expect("zero-ceiling write should not propagate as dispatch error");

    // Drain: open event, then error event.
    let _open_event = receiver.recv().await.ok_or("missing open event")?;
    let error_event = receiver.recv().await.ok_or("missing error event")?;
    let OperatorMessage::AgentResponse(error_msg) = error_event else {
        panic!("expected AgentResponse error event");
    };
    assert_eq!(error_msg.info.extra.get("Type"), Some(&Value::String("Error".to_owned())));

    // Audit log must contain a download.rejected entry.
    let audit_rows = database.audit_log().list().await?;
    assert!(
        audit_rows.iter().any(|r| r.action == "download.rejected"),
        "audit log must contain a download.rejected entry"
    );
    assert!(database.loot().list_for_agent(0xABCD_EF62).await?.is_empty());
    Ok(())
}

// -----------------------------------------------------------------
// DownloadTracker::from_max_download_bytes
// -----------------------------------------------------------------

#[test]
fn download_tracker_from_max_download_bytes_normal_value() {
    let tracker = DownloadTracker::from_max_download_bytes(1024);
    assert_eq!(tracker.max_download_bytes, 1024);
    assert_eq!(tracker.max_total_download_bytes, 1024 * DOWNLOAD_TRACKER_AGGREGATE_CAP_MULTIPLIER,);
}

#[test]
fn download_tracker_from_max_download_bytes_saturates_large_u64() {
    // A value larger than usize::MAX (on any platform) must saturate to usize::MAX.
    let huge: u64 = u64::MAX;
    let tracker = DownloadTracker::from_max_download_bytes(huge);

    // The per-file cap saturates to usize::MAX.
    assert_eq!(tracker.max_download_bytes, usize::MAX);
    // The aggregate cap is at least the per-file cap (saturating_mul overflows to
    // usize::MAX, and .max() ensures it is >= max_download_bytes).
    assert!(tracker.max_total_download_bytes >= tracker.max_download_bytes);
}

#[test]
fn download_tracker_from_max_download_bytes_zero() {
    let tracker = DownloadTracker::from_max_download_bytes(0);
    assert_eq!(tracker.max_download_bytes, 0);
    // 0 * multiplier = 0, .max(0) = 0
    assert_eq!(tracker.max_total_download_bytes, 0);
}

#[test]
fn download_tracker_from_max_download_bytes_one() {
    let tracker = DownloadTracker::from_max_download_bytes(1);
    assert_eq!(tracker.max_download_bytes, 1);
    assert_eq!(tracker.max_total_download_bytes, DOWNLOAD_TRACKER_AGGREGATE_CAP_MULTIPLIER,);
}
