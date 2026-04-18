//! Tests for download size limits, concurrent limits, and DownloadTracker construction.

use super::*;

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
        DemonInitSecretConfig::None,
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
        DemonInitSecretConfig::None,
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
