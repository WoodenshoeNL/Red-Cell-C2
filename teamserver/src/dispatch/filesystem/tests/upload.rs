//! Upload-subcommand tests for `handle_filesystem_callback`.
//!
//! Covers the Upload happy path, zero-size edge case, and truncated-payload
//! rejection.

use red_cell_common::demon::DemonFilesystemCommand;
use red_cell_common::operator::OperatorMessage;

use super::super::CommandDispatchError;

use super::common::{add_u32_le, add_utf16_le, call_and_expect_error, call_and_recv};

fn build_upload_payload(size: u32, path: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Upload));
    add_u32_le(&mut buf, size);
    add_utf16_le(&mut buf, path);
    buf
}

#[tokio::test]
async fn upload_callback_emits_info_with_size_and_path() {
    let event = call_and_recv(&build_upload_payload(4096, "C:\\Temp\\payload.bin"), 0xA1, 10).await;
    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("Uploaded file"), "message: {message}");
    assert!(message.contains("C:\\Temp\\payload.bin"), "message: {message}");
    assert!(message.contains("4096 bytes"), "message: {message}");
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Info"));
}

#[tokio::test]
async fn upload_truncated_payload_missing_path_returns_error() {
    // Upload needs: subcommand + u32(size) + utf16(path). Omit path.
    let mut buf = Vec::new();
    add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Upload));
    add_u32_le(&mut buf, 100);
    let err = call_and_expect_error(&buf, 0xEA, 11).await;
    assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }), "got {err:?}");
}

#[tokio::test]
async fn upload_truncated_payload_empty_returns_error() {
    let mut buf = Vec::new();
    add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Upload));
    let err = call_and_expect_error(&buf, 0xEB, 12).await;
    assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }), "got {err:?}");
}

#[tokio::test]
async fn upload_zero_size_broadcasts_event() {
    let event = call_and_recv(&build_upload_payload(0, "C:\\empty.bin"), 0xF4, 104).await;
    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("Uploaded file"), "message: {message}");
    assert!(message.contains("0 bytes"), "message: {message}");
}
