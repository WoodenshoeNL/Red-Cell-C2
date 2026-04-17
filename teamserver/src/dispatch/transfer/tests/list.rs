//! Tests for `DemonTransferCommand::List` and the shared formatting helpers.

use red_cell_common::demon::DemonTransferCommand;
use red_cell_common::operator::OperatorMessage;

use super::super::super::{CommandDispatchError, DownloadState, DownloadTracker};
use super::super::handle_transfer_callback;
use super::super::helpers::{byte_count, transfer_progress_text, transfer_state_name};
use super::{assert_no_events_broadcast, le32};
use crate::EventBus;

// ------------------------------------------------------------------
// handle_transfer_callback — List subcommand
// ------------------------------------------------------------------

#[tokio::test]
async fn transfer_callback_list_shows_active_download() -> Result<(), Box<dyn std::error::Error>> {
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let downloads = DownloadTracker::new(1024 * 1024);
    let agent_id: u32 = 0x1234_5678;
    let file_id: u32 = 0xABCD_EF01;
    let request_id: u32 = 42;

    downloads
        .start(
            agent_id,
            file_id,
            DownloadState {
                request_id,
                remote_path: r"C:\loot\secrets.txt".to_owned(),
                expected_size: 1000,
                data: Vec::new(),
                started_at: "2026-03-17T00:00:00Z".to_owned(),
            },
        )
        .await
        .expect("start should succeed");

    // Payload: List subcommand + file_id + progress(500 of 1000 = 50%) + state(Running=1)
    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(u32::from(DemonTransferCommand::List)));
    payload.extend_from_slice(&le32(file_id));
    payload.extend_from_slice(&le32(500));
    payload.extend_from_slice(&le32(1));

    let result =
        handle_transfer_callback(&events, &downloads, agent_id, request_id, &payload).await?;

    assert_eq!(result, None, "transfer List handler must not produce a reply packet");

    let event = receiver.recv().await.ok_or("expected AgentResponse event after List")?;
    let OperatorMessage::AgentResponse(message) = event else {
        return Err("expected AgentResponse event".into());
    };
    assert!(
        message.info.output.contains("secrets.txt"),
        "List output should contain the file name; got: {}",
        message.info.output
    );
    assert!(
        message.info.output.contains("50.00%"),
        "List output should show 50.00%% progress; got: {}",
        message.info.output
    );
    Ok(())
}

// ------------------------------------------------------------------
// handle_transfer_callback — truncated payload
// ------------------------------------------------------------------

#[tokio::test]
async fn transfer_callback_truncated_returns_error() {
    let events = EventBus::default();
    let downloads = DownloadTracker::new(1024 * 1024);

    let result = handle_transfer_callback(&events, &downloads, 0x1111_1111, 1, &[]).await;

    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "empty payload must yield InvalidCallbackPayload; got: {result:?}"
    );
}

#[tokio::test]
async fn transfer_list_truncated_mid_entry_returns_error() {
    let events = EventBus::default();
    let downloads = DownloadTracker::new(1024 * 1024);

    // List subcommand + file_id only (missing progress and state).
    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(u32::from(DemonTransferCommand::List)));
    payload.extend_from_slice(&le32(0x0000_0001)); // file_id
    // Missing: progress (u32) and state (u32)

    let result = handle_transfer_callback(&events, &downloads, 0x1111_0002, 1, &payload).await;

    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "truncated List entry must yield InvalidCallbackPayload; got: {result:?}"
    );
    assert_no_events_broadcast(events).await;
}

// ------------------------------------------------------------------
// byte_count / transfer_progress_text / transfer_state_name tests
// ------------------------------------------------------------------

#[test]
fn byte_count_zero() {
    assert_eq!(byte_count(0), "0 B");
}

#[test]
fn byte_count_below_kilo() {
    assert_eq!(byte_count(999), "999 B");
}

#[test]
fn byte_count_kilobytes() {
    assert_eq!(byte_count(1_000), "1.00 kB");
}

#[test]
fn byte_count_megabytes() {
    assert_eq!(byte_count(1_000_000), "1.00 MB");
}

#[test]
fn byte_count_terabytes() {
    assert_eq!(byte_count(1_000_000_000_000), "1.00 TB");
}

#[test]
fn byte_count_near_kb_boundary() {
    // 999_999 bytes is 999.999 kB — should still display as kB, not MB
    assert_eq!(byte_count(999_999), "1000.00 kB");
}

#[test]
fn byte_count_near_tb_boundary() {
    // 999_999_999_999_999 bytes — exercises the GB→TB boundary
    assert_eq!(byte_count(999_999_999_999_999), "1000.00 TB");
}

#[test]
fn byte_count_u64_max() {
    // u64::MAX = 18_446_744_073_709_551_615 — verify no panic from f64 conversion
    // f64 loses precision at this magnitude: ≈ 18446744.07 TB
    let result = byte_count(u64::MAX);
    assert!(result.ends_with(" TB"), "expected TB suffix, got: {result}");
    assert!(result.starts_with("18446744"), "expected ~18446744 TB, got: {result}");
}

#[test]
fn transfer_progress_text_zero_total() {
    assert_eq!(transfer_progress_text(0, 0), "0.00%");
}

#[test]
fn transfer_progress_text_half() {
    assert_eq!(transfer_progress_text(50, 100), "50.00%");
}

#[test]
fn transfer_progress_text_fraction() {
    assert_eq!(transfer_progress_text(1, 3), "33.33%");
}

#[test]
fn transfer_state_name_running() {
    assert_eq!(transfer_state_name(1), "Running");
}

#[test]
fn transfer_state_name_stopped() {
    assert_eq!(transfer_state_name(2), "Stopped");
}

#[test]
fn transfer_state_name_removed() {
    assert_eq!(transfer_state_name(3), "Removed");
}

#[test]
fn transfer_state_name_unknown() {
    assert_eq!(transfer_state_name(99), "Unknown");
}
