//! Tests for the `Stop`, `Resume`, and `Remove` transfer subcommands.

use red_cell_common::demon::DemonTransferCommand;
use red_cell_common::operator::OperatorMessage;

use super::super::super::{CommandDispatchError, DownloadState, DownloadTracker};
use super::super::handle_transfer_callback;
use super::{assert_no_events_broadcast, le32};
use crate::EventBus;

// ------------------------------------------------------------------
// Helper: build Stop/Resume/Remove payload
// ------------------------------------------------------------------

/// Build a transfer callback payload for Stop, Resume, or Remove subcommands.
/// `found` maps to the agent-side "file id was located" bool, while `file_id`
/// identifies the download entry.
fn stop_resume_remove_payload(
    subcommand: DemonTransferCommand,
    found: bool,
    file_id: u32,
) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(u32::from(subcommand)));
    payload.extend_from_slice(&le32(u32::from(found)));
    payload.extend_from_slice(&le32(file_id));
    payload
}

/// Extract (kind, message) from an `AgentResponse` event's extra map.
fn extract_kind_message(event: &OperatorMessage) -> (&str, &str) {
    let OperatorMessage::AgentResponse(msg) = event else {
        panic!("expected AgentResponse; got: {event:?}");
    };
    let kind = msg.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    (kind, message)
}

/// Seed a DownloadTracker with one active download for the given agent/file pair.
async fn seed_download(downloads: &DownloadTracker, agent_id: u32, file_id: u32) {
    downloads
        .start(
            agent_id,
            file_id,
            DownloadState {
                request_id: 1,
                remote_path: r"C:\test\file.bin".to_owned(),
                expected_size: 4096,
                data: Vec::new(),
                started_at: "2026-03-17T00:00:00Z".to_owned(),
            },
        )
        .await
        .expect("start should succeed");
}

// ------------------------------------------------------------------
// handle_transfer_callback — Stop subcommand
// ------------------------------------------------------------------

#[tokio::test]
async fn transfer_stop_found_and_exists() -> Result<(), Box<dyn std::error::Error>> {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let downloads = DownloadTracker::new(1024 * 1024);
    let agent_id: u32 = 0xAA00_0001;
    let file_id: u32 = 0x0000_0010;

    seed_download(&downloads, agent_id, file_id).await;
    let payload = stop_resume_remove_payload(DemonTransferCommand::Stop, true, file_id);

    let result = handle_transfer_callback(&events, &downloads, agent_id, 1, &payload).await?;
    assert_eq!(result, None);

    let event = rx.recv().await.ok_or("no event")?;
    let (kind, message) = extract_kind_message(&event);
    assert_eq!(kind, "Good");
    assert!(message.contains("stopped"), "expected 'stopped'; got: {message}");
    assert!(message.contains(&format!("{file_id:x}")));

    // Stop must NOT clear the tracked download.
    assert!(
        !downloads.active_for_agent(agent_id).await.is_empty(),
        "Stop success path must not clear the tracked download"
    );
    Ok(())
}

#[tokio::test]
async fn transfer_stop_found_but_not_exists() -> Result<(), Box<dyn std::error::Error>> {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let downloads = DownloadTracker::new(1024 * 1024);
    let agent_id: u32 = 0xAA00_0002;
    let file_id: u32 = 0x0000_0020;

    // No download seeded — found=true but exists=false
    let payload = stop_resume_remove_payload(DemonTransferCommand::Stop, true, file_id);

    let result = handle_transfer_callback(&events, &downloads, agent_id, 1, &payload).await?;
    assert_eq!(result, None);

    let event = rx.recv().await.ok_or("no event")?;
    let (kind, message) = extract_kind_message(&event);
    assert_eq!(kind, "Error");
    assert!(message.contains("does not exist"), "expected 'does not exist'; got: {message}");
    Ok(())
}

#[tokio::test]
async fn transfer_stop_not_found() -> Result<(), Box<dyn std::error::Error>> {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let downloads = DownloadTracker::new(1024 * 1024);
    let agent_id: u32 = 0xAA00_0003;
    let file_id: u32 = 0x0000_0030;

    let payload = stop_resume_remove_payload(DemonTransferCommand::Stop, false, file_id);

    let result = handle_transfer_callback(&events, &downloads, agent_id, 1, &payload).await?;
    assert_eq!(result, None);

    let event = rx.recv().await.ok_or("no event")?;
    let (kind, message) = extract_kind_message(&event);
    assert_eq!(kind, "Error");
    assert!(message.contains("not found"), "expected 'not found'; got: {message}");
    Ok(())
}

// ------------------------------------------------------------------
// handle_transfer_callback — Resume subcommand
// ------------------------------------------------------------------

#[tokio::test]
async fn transfer_resume_found_and_exists() -> Result<(), Box<dyn std::error::Error>> {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let downloads = DownloadTracker::new(1024 * 1024);
    let agent_id: u32 = 0xBB00_0001;
    let file_id: u32 = 0x0000_0040;

    seed_download(&downloads, agent_id, file_id).await;
    let payload = stop_resume_remove_payload(DemonTransferCommand::Resume, true, file_id);

    let result = handle_transfer_callback(&events, &downloads, agent_id, 1, &payload).await?;
    assert_eq!(result, None);

    let event = rx.recv().await.ok_or("no event")?;
    let (kind, message) = extract_kind_message(&event);
    assert_eq!(kind, "Good");
    assert!(message.contains("resumed"), "expected 'resumed'; got: {message}");
    assert!(message.contains(&format!("{file_id:x}")));

    // Resume must NOT clear the tracked download.
    assert!(
        !downloads.active_for_agent(agent_id).await.is_empty(),
        "Resume success path must not clear the tracked download"
    );
    Ok(())
}

#[tokio::test]
async fn transfer_resume_found_but_not_exists() -> Result<(), Box<dyn std::error::Error>> {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let downloads = DownloadTracker::new(1024 * 1024);
    let agent_id: u32 = 0xBB00_0002;
    let file_id: u32 = 0x0000_0050;

    let payload = stop_resume_remove_payload(DemonTransferCommand::Resume, true, file_id);

    let result = handle_transfer_callback(&events, &downloads, agent_id, 1, &payload).await?;
    assert_eq!(result, None);

    let event = rx.recv().await.ok_or("no event")?;
    let (kind, message) = extract_kind_message(&event);
    assert_eq!(kind, "Error");
    assert!(message.contains("does not exist"), "expected 'does not exist'; got: {message}");
    Ok(())
}

#[tokio::test]
async fn transfer_resume_not_found() -> Result<(), Box<dyn std::error::Error>> {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let downloads = DownloadTracker::new(1024 * 1024);
    let agent_id: u32 = 0xBB00_0003;
    let file_id: u32 = 0x0000_0060;

    let payload = stop_resume_remove_payload(DemonTransferCommand::Resume, false, file_id);

    let result = handle_transfer_callback(&events, &downloads, agent_id, 1, &payload).await?;
    assert_eq!(result, None);

    let event = rx.recv().await.ok_or("no event")?;
    let (kind, message) = extract_kind_message(&event);
    assert_eq!(kind, "Error");
    assert!(message.contains("not found"), "expected 'not found'; got: {message}");
    Ok(())
}

// ------------------------------------------------------------------
// handle_transfer_callback — Remove subcommand
// ------------------------------------------------------------------

#[tokio::test]
async fn transfer_remove_found_and_exists_clears_download() -> Result<(), Box<dyn std::error::Error>>
{
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let downloads = DownloadTracker::new(1024 * 1024);
    let agent_id: u32 = 0xCC00_0001;
    let file_id: u32 = 0x0000_0070;

    seed_download(&downloads, agent_id, file_id).await;
    assert!(
        !downloads.active_for_agent(agent_id).await.is_empty(),
        "precondition: download should be tracked before Remove"
    );

    let payload = stop_resume_remove_payload(DemonTransferCommand::Remove, true, file_id);

    let result = handle_transfer_callback(&events, &downloads, agent_id, 1, &payload).await?;
    assert_eq!(result, None);

    let event = rx.recv().await.ok_or("no event")?;
    let (kind, message) = extract_kind_message(&event);
    assert_eq!(kind, "Good");
    assert!(message.contains("removed"), "expected 'removed'; got: {message}");
    assert!(message.contains(&format!("{file_id:x}")));

    // The download must have been cleaned up via downloads.finish().
    assert!(
        downloads.active_for_agent(agent_id).await.is_empty(),
        "Remove success path must clear the tracked download"
    );
    Ok(())
}

#[tokio::test]
async fn transfer_remove_found_but_not_exists() -> Result<(), Box<dyn std::error::Error>> {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let downloads = DownloadTracker::new(1024 * 1024);
    let agent_id: u32 = 0xCC00_0002;
    let file_id: u32 = 0x0000_0080;

    let payload = stop_resume_remove_payload(DemonTransferCommand::Remove, true, file_id);

    let result = handle_transfer_callback(&events, &downloads, agent_id, 1, &payload).await?;
    assert_eq!(result, None);

    let event = rx.recv().await.ok_or("no event")?;
    let (kind, message) = extract_kind_message(&event);
    assert_eq!(kind, "Error");
    assert!(message.contains("does not exist"), "expected 'does not exist'; got: {message}");
    Ok(())
}

#[tokio::test]
async fn transfer_remove_not_found() -> Result<(), Box<dyn std::error::Error>> {
    let events = EventBus::default();
    let mut rx = events.subscribe();
    let downloads = DownloadTracker::new(1024 * 1024);
    let agent_id: u32 = 0xCC00_0003;
    let file_id: u32 = 0x0000_0090;

    // Seed a download to verify it is NOT removed on the error path.
    seed_download(&downloads, agent_id, file_id).await;

    let payload = stop_resume_remove_payload(DemonTransferCommand::Remove, false, file_id);

    let result = handle_transfer_callback(&events, &downloads, agent_id, 1, &payload).await?;
    assert_eq!(result, None);

    let event = rx.recv().await.ok_or("no event")?;
    let (kind, message) = extract_kind_message(&event);
    assert_eq!(kind, "Error");
    assert!(message.contains("not found"), "expected 'not found'; got: {message}");

    // Download must still be tracked — error path must not mutate state.
    assert!(
        !downloads.active_for_agent(agent_id).await.is_empty(),
        "Remove error path must not clear the tracked download"
    );
    Ok(())
}

// ------------------------------------------------------------------
// Malformed-payload tests — Stop/Resume/Remove subcommands
// ------------------------------------------------------------------

#[tokio::test]
async fn transfer_stop_truncated_missing_found_returns_error() {
    let events = EventBus::default();
    let downloads = DownloadTracker::new(1024 * 1024);

    // Stop subcommand only — missing found bool and file_id.
    let payload = le32(u32::from(DemonTransferCommand::Stop));

    let result = handle_transfer_callback(&events, &downloads, 0x1111_0003, 1, &payload).await;

    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "Stop with missing found bool must yield InvalidCallbackPayload; got: {result:?}"
    );
    assert_no_events_broadcast(events).await;
}

#[tokio::test]
async fn transfer_stop_truncated_missing_file_id_returns_error() {
    let events = EventBus::default();
    let downloads = DownloadTracker::new(1024 * 1024);

    // Stop subcommand + found bool — missing file_id.
    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(u32::from(DemonTransferCommand::Stop)));
    payload.extend_from_slice(&le32(1)); // found = true

    let result = handle_transfer_callback(&events, &downloads, 0x1111_0004, 1, &payload).await;

    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "Stop with missing file_id must yield InvalidCallbackPayload; got: {result:?}"
    );
    assert_no_events_broadcast(events).await;
}

#[tokio::test]
async fn transfer_resume_truncated_missing_found_returns_error() {
    let events = EventBus::default();
    let downloads = DownloadTracker::new(1024 * 1024);

    let payload = le32(u32::from(DemonTransferCommand::Resume));

    let result = handle_transfer_callback(&events, &downloads, 0x1111_0005, 1, &payload).await;

    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "Resume with missing found bool must yield InvalidCallbackPayload; got: {result:?}"
    );
    assert_no_events_broadcast(events).await;
}

#[tokio::test]
async fn transfer_remove_truncated_missing_file_id_returns_error() {
    let events = EventBus::default();
    let downloads = DownloadTracker::new(1024 * 1024);

    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(u32::from(DemonTransferCommand::Remove)));
    payload.extend_from_slice(&le32(0)); // found = false

    let result = handle_transfer_callback(&events, &downloads, 0x1111_0006, 1, &payload).await;

    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "Remove with missing file_id must yield InvalidCallbackPayload; got: {result:?}"
    );
    assert_no_events_broadcast(events).await;
}
