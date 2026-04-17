//! Cat-subcommand tests for `handle_filesystem_callback`.
//!
//! Covers success + failure callbacks, the empty-content edge case, and
//! truncated-payload rejection.

use red_cell_common::demon::DemonFilesystemCommand;
use red_cell_common::operator::OperatorMessage;

use super::super::CommandDispatchError;

use super::common::{add_bool_le, add_u32_le, add_utf16_le, call_and_expect_error, call_and_recv};

/// Build a Cat subcommand payload.  `output` is encoded via `read_string`
/// (u32-LE length prefix + raw UTF-8 bytes).
fn build_cat_payload(path: &str, success: bool, output: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Cat));
    add_utf16_le(&mut buf, path);
    add_bool_le(&mut buf, success);
    let raw = output.as_bytes();
    add_u32_le(&mut buf, u32::try_from(raw.len()).expect("unwrap"));
    buf.extend_from_slice(raw);
    buf
}

#[tokio::test]
async fn cat_success_callback_emits_file_content() {
    let content = "Hello, World!\nLine 2\n";
    let event = call_and_recv(&build_cat_payload("C:\\readme.txt", true, content), 0xAB, 80).await;
    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("File content of"), "message: {message}");
    assert!(message.contains("C:\\readme.txt"), "message: {message}");
    assert!(
        message.contains(&format!("{})", content.len())),
        "message should contain size: {message}"
    );
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Info"));
    assert_eq!(msg.info.output, content, "output should contain file content");
}

#[tokio::test]
async fn cat_failure_callback_emits_error_with_no_content() {
    let event =
        call_and_recv(&build_cat_payload("C:\\secret.key", false, "ignored error data"), 0xAC, 81)
            .await;
    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("Failed to read file"), "message: {message}");
    assert!(message.contains("C:\\secret.key"), "message: {message}");
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
    // On failure, output should be empty (no file contents attached)
    assert!(msg.info.output.is_empty(), "failure should not attach file content");
}

#[tokio::test]
async fn cat_truncated_payload_missing_output_returns_error() {
    // Cat needs: subcommand + utf16(path) + bool(success) + string(output). Omit output.
    let mut buf = Vec::new();
    add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Cat));
    add_utf16_le(&mut buf, "C:\\file.txt");
    add_bool_le(&mut buf, true);
    let err = call_and_expect_error(&buf, 0xE8, 9).await;
    assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }), "got {err:?}");
}

#[tokio::test]
async fn cat_truncated_payload_missing_success_returns_error() {
    // Only subcommand + path, no success bool or output.
    let mut buf = Vec::new();
    add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Cat));
    add_utf16_le(&mut buf, "C:\\file.txt");
    let err = call_and_expect_error(&buf, 0xE9, 10).await;
    assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }), "got {err:?}");
}

#[tokio::test]
async fn cat_success_empty_content_broadcasts_event() {
    let event = call_and_recv(&build_cat_payload("C:\\empty.txt", true, ""), 0xF5, 105).await;
    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("File content of"), "message: {message}");
    assert!(message.contains("0)"), "message should show zero length: {message}");
    assert_eq!(msg.info.output, "", "output should be empty");
}
