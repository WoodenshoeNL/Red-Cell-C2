//! Tests for filesystem download dispatch and the DownloadTracker.

use super::*;

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
