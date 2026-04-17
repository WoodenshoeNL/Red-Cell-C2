//! Tests for the `CommandMemFile` and `CommandPackageDropped` callbacks.

use red_cell_common::operator::OperatorMessage;

use super::super::super::CommandDispatchError;
use super::super::{handle_mem_file_callback, handle_package_dropped_callback};
use super::le32;
use crate::EventBus;

/// After an error return the event bus must contain zero messages.
pub(in crate::dispatch::transfer) async fn assert_no_events_broadcast(events: EventBus) {
    let mut rx = events.subscribe();
    // Drop the bus so recv() resolves immediately with None if empty.
    drop(events);
    assert_eq!(rx.recv().await, None, "no events should be broadcast on error path");
}

// ------------------------------------------------------------------
// handle_mem_file_callback — valid payload
// ------------------------------------------------------------------

#[tokio::test]
async fn mem_file_callback_broadcasts_response_event() -> Result<(), Box<dyn std::error::Error>> {
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let agent_id: u32 = 0xDEAD_BEEF;
    let request_id: u32 = 7;

    // Payload: mem_file_id(0x99) + success(1 = true)
    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(0x0000_0099));
    payload.extend_from_slice(&le32(1));

    let result = handle_mem_file_callback(&events, agent_id, request_id, &payload).await?;

    assert_eq!(result, None, "mem-file handler must not produce a reply packet");

    let event =
        receiver.recv().await.ok_or("expected AgentResponse event after mem-file callback")?;
    let OperatorMessage::AgentResponse(message) = event else {
        return Err("expected AgentResponse event".into());
    };
    let kind = message.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(kind, "Good", "success=true must produce Type=\"Good\"; got: {kind}");
    let msg_text = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        msg_text.contains("registered successfully"),
        "success=true message must contain \"registered successfully\"; got: {msg_text}"
    );
    Ok(())
}

// ------------------------------------------------------------------
// handle_mem_file_callback — success=false (failure path)
// ------------------------------------------------------------------

#[tokio::test]
async fn mem_file_callback_failure_broadcasts_error_event() -> Result<(), Box<dyn std::error::Error>>
{
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let agent_id: u32 = 0xDEAD_BEEF;
    let request_id: u32 = 8;

    // Payload: mem_file_id(0x42) + success(0 = false)
    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(0x0000_0042));
    payload.extend_from_slice(&le32(0));

    let result = handle_mem_file_callback(&events, agent_id, request_id, &payload).await?;

    assert_eq!(result, None, "mem-file handler must not produce a reply packet");

    let event = receiver
        .recv()
        .await
        .ok_or("expected AgentResponse event after mem-file failure callback")?;
    let OperatorMessage::AgentResponse(message) = event else {
        return Err("expected AgentResponse event".into());
    };
    let kind = message.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(kind, "Error", "success=false must produce Type=\"Error\"; got: {kind}");
    let msg_text = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        msg_text.contains("failed to register"),
        "success=false message must contain \"failed to register\"; got: {msg_text}"
    );
    Ok(())
}

// ------------------------------------------------------------------
// handle_package_dropped_callback — valid payload
// ------------------------------------------------------------------

#[tokio::test]
async fn package_dropped_callback_broadcasts_error_event() -> Result<(), Box<dyn std::error::Error>>
{
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let agent_id: u32 = 0xAAAA_BBBB;
    let request_id: u32 = 3;

    // Payload: package_length(8192) + max_length(4096)
    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(8192));
    payload.extend_from_slice(&le32(4096));

    let result = handle_package_dropped_callback(&events, agent_id, request_id, &payload).await?;

    assert_eq!(result, None, "package-dropped handler must not produce a reply packet");

    let event = receiver
        .recv()
        .await
        .ok_or("expected AgentResponse event after package-dropped callback")?;
    let OperatorMessage::AgentResponse(message) = event else {
        return Err("expected AgentResponse event".into());
    };
    let msg_text = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        msg_text.contains("8192") && msg_text.contains("4096"),
        "error message should reference both sizes; got: {msg_text}"
    );
    Ok(())
}

// ------------------------------------------------------------------
// handle_mem_file_callback — trailing bytes (overflow scenario)
// ------------------------------------------------------------------

#[tokio::test]
async fn mem_file_callback_with_trailing_bytes_still_succeeds()
-> Result<(), Box<dyn std::error::Error>> {
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let agent_id: u32 = 0xDEAD_0001;
    let request_id: u32 = 10;

    // Payload: mem_file_id(0xAA) + success(1) + 128 bytes of trailing junk
    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(0x0000_00AA));
    payload.extend_from_slice(&le32(1));
    payload.extend_from_slice(&[0xFF; 128]);

    let result = handle_mem_file_callback(&events, agent_id, request_id, &payload).await?;
    assert_eq!(result, None, "handler must not produce a reply even with trailing bytes");

    let event = receiver.recv().await.ok_or("expected event")?;
    let OperatorMessage::AgentResponse(message) = event else {
        return Err("expected AgentResponse event".into());
    };
    let kind = message.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(kind, "Good");
    let msg_text = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg_text.contains("aa"), "hex mem_file_id should appear in message; got: {msg_text}");
    Ok(())
}

// ------------------------------------------------------------------
// handle_mem_file_callback — u32::MAX boundary mem_file_id
// ------------------------------------------------------------------

#[tokio::test]
async fn mem_file_callback_u32_max_id_formats_hex_correctly()
-> Result<(), Box<dyn std::error::Error>> {
    let events = EventBus::default();
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(u32::MAX));
    payload.extend_from_slice(&le32(1));

    let result = handle_mem_file_callback(&events, 0xDEAD_0002, 11, &payload).await?;
    assert_eq!(result, None);

    let event = receiver.recv().await.ok_or("expected event")?;
    let OperatorMessage::AgentResponse(message) = event else {
        return Err("expected AgentResponse event".into());
    };
    let msg_text = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        msg_text.contains("ffffffff"),
        "u32::MAX mem_file_id should format as ffffffff; got: {msg_text}"
    );
    Ok(())
}

// ------------------------------------------------------------------
// handle_mem_file_callback — zero mem_file_id
// ------------------------------------------------------------------

#[tokio::test]
async fn mem_file_callback_zero_id_success() -> Result<(), Box<dyn std::error::Error>> {
    let events = EventBus::default();
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(0));
    payload.extend_from_slice(&le32(0)); // success = false

    let result = handle_mem_file_callback(&events, 0xDEAD_0003, 12, &payload).await?;
    assert_eq!(result, None);

    let event = receiver.recv().await.ok_or("expected event")?;
    let OperatorMessage::AgentResponse(message) = event else {
        return Err("expected AgentResponse event".into());
    };
    let kind = message.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(kind, "Error", "success=0 must produce Error; got: {kind}");
    let msg_text = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg_text.contains("failed to register"), "failure message expected; got: {msg_text}");
    Ok(())
}

// ------------------------------------------------------------------
// handle_package_dropped_callback — Type field is always "Error"
// ------------------------------------------------------------------

#[tokio::test]
async fn package_dropped_callback_type_is_error() -> Result<(), Box<dyn std::error::Error>> {
    let events = EventBus::default();
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(65536));
    payload.extend_from_slice(&le32(32768));

    let result = handle_package_dropped_callback(&events, 0xAAAA_0001, 4, &payload).await?;
    assert_eq!(result, None);

    let event = receiver.recv().await.ok_or("expected event")?;
    let OperatorMessage::AgentResponse(message) = event else {
        return Err("expected AgentResponse event".into());
    };
    let kind = message.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(kind, "Error", "PackageDropped must always emit Error type; got: {kind}");
    let msg_text = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        msg_text.contains("PIPE_BUFFER_MAX"),
        "error message should reference PIPE_BUFFER_MAX; got: {msg_text}"
    );
    Ok(())
}

// ------------------------------------------------------------------
// handle_package_dropped_callback — equal lengths (edge case)
// ------------------------------------------------------------------

#[tokio::test]
async fn package_dropped_callback_equal_lengths() -> Result<(), Box<dyn std::error::Error>> {
    let events = EventBus::default();
    let mut receiver = events.subscribe();

    // Edge case: package_length == max_length
    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(4096));
    payload.extend_from_slice(&le32(4096));

    let result = handle_package_dropped_callback(&events, 0xAAAA_0002, 5, &payload).await?;
    assert_eq!(result, None);

    let event = receiver.recv().await.ok_or("expected event")?;
    let OperatorMessage::AgentResponse(message) = event else {
        return Err("expected AgentResponse event".into());
    };
    let msg_text = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(msg_text.contains("4096"), "message should contain the length value; got: {msg_text}");
    Ok(())
}

// ------------------------------------------------------------------
// handle_package_dropped_callback — u32::MAX boundary values
// ------------------------------------------------------------------

#[tokio::test]
async fn package_dropped_callback_u32_max_values() -> Result<(), Box<dyn std::error::Error>> {
    let events = EventBus::default();
    let mut receiver = events.subscribe();

    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(u32::MAX));
    payload.extend_from_slice(&le32(u32::MAX - 1));

    let result = handle_package_dropped_callback(&events, 0xAAAA_0003, 6, &payload).await?;
    assert_eq!(result, None);

    let event = receiver.recv().await.ok_or("expected event")?;
    let OperatorMessage::AgentResponse(message) = event else {
        return Err("expected AgentResponse event".into());
    };
    let msg_text = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        msg_text.contains("4294967295") && msg_text.contains("4294967294"),
        "u32::MAX values should appear in message; got: {msg_text}"
    );
    Ok(())
}

// ------------------------------------------------------------------
// handle_package_dropped_callback — trailing bytes (overflow)
// ------------------------------------------------------------------

#[tokio::test]
async fn package_dropped_callback_with_trailing_bytes_still_succeeds()
-> Result<(), Box<dyn std::error::Error>> {
    let events = EventBus::default();
    let mut receiver = events.subscribe();

    // Payload: package_length + max_length + trailing junk
    let mut payload = Vec::new();
    payload.extend_from_slice(&le32(1024));
    payload.extend_from_slice(&le32(512));
    payload.extend_from_slice(&[0xDE; 256]);

    let result = handle_package_dropped_callback(&events, 0xAAAA_0004, 7, &payload).await?;
    assert_eq!(result, None, "handler must not produce a reply even with trailing bytes");

    let event = receiver.recv().await.ok_or("expected event")?;
    let OperatorMessage::AgentResponse(message) = event else {
        return Err("expected AgentResponse event".into());
    };
    let kind = message.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(kind, "Error");
    let msg_text = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        msg_text.contains("1024") && msg_text.contains("512"),
        "message should contain both sizes; got: {msg_text}"
    );
    Ok(())
}

// ------------------------------------------------------------------
// Malformed-payload tests — CommandMemFile
// ------------------------------------------------------------------

#[tokio::test]
async fn mem_file_callback_empty_payload_returns_error() {
    let events = EventBus::default();

    let result = handle_mem_file_callback(&events, 0x2222_0001, 1, &[]).await;

    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "empty mem-file payload must yield InvalidCallbackPayload; got: {result:?}"
    );
    assert_no_events_broadcast(events).await;
}

#[tokio::test]
async fn mem_file_callback_truncated_missing_success_returns_error() {
    let events = EventBus::default();

    // Has mem_file_id but missing the success bool.
    let payload = le32(0x0000_0099);

    let result = handle_mem_file_callback(&events, 0x2222_0002, 1, &payload).await;

    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "mem-file missing success bool must yield InvalidCallbackPayload; got: {result:?}"
    );
    assert_no_events_broadcast(events).await;
}

// ------------------------------------------------------------------
// Malformed-payload tests — CommandPackageDropped
// ------------------------------------------------------------------

#[tokio::test]
async fn package_dropped_callback_empty_payload_returns_error() {
    let events = EventBus::default();

    let result = handle_package_dropped_callback(&events, 0x3333_0001, 1, &[]).await;

    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "empty package-dropped payload must yield InvalidCallbackPayload; got: {result:?}"
    );
    assert_no_events_broadcast(events).await;
}

#[tokio::test]
async fn package_dropped_callback_truncated_missing_max_length_returns_error() {
    let events = EventBus::default();

    // Has package_length but missing max_length.
    let payload = le32(8192);

    let result = handle_package_dropped_callback(&events, 0x3333_0002, 1, &payload).await;

    assert!(
        matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
        "package-dropped missing max_length must yield InvalidCallbackPayload; got: {result:?}"
    );
    assert_no_events_broadcast(events).await;
}
