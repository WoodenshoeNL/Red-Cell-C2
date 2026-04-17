//! Directory-operation tests for `handle_filesystem_callback`.
//!
//! Covers the Dir, Mkdir, Cd, GetPwd, Remove, Copy and Move subcommands —
//! happy paths, empty-path edge cases, and truncated-payload rejection.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell_common::demon::DemonFilesystemCommand;
use red_cell_common::operator::OperatorMessage;
use serde_json::Value;
use tokio::time::{Duration, timeout};

use super::super::CommandDispatchError;
use super::super::handle_filesystem_callback;

use super::common::{
    add_bool_le, add_u32_le, add_u64_le, add_utf16_le, call_and_expect_error, call_and_recv,
    dir_test_deps,
};

// --- Payload builders for directory subcommands ---

struct DirItem {
    name: String,
    is_dir: bool,
    size: u64,
    day: u32,
    month: u32,
    year: u32,
    minute: u32,
    hour: u32,
}

struct DirEntry {
    path: String,
    file_count: u32,
    dir_count: u32,
    total_size: Option<u64>, // None when list_only
    items: Vec<DirItem>,
}

fn build_dir_payload(
    explorer: bool,
    list_only: bool,
    root_path: &str,
    success: bool,
    entries: &[DirEntry],
) -> Vec<u8> {
    let mut buf = Vec::new();
    add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Dir));
    add_bool_le(&mut buf, explorer);
    add_bool_le(&mut buf, list_only);
    add_utf16_le(&mut buf, root_path);
    add_bool_le(&mut buf, success);

    if success {
        for entry in entries {
            add_utf16_le(&mut buf, &entry.path);
            add_u32_le(&mut buf, entry.file_count);
            add_u32_le(&mut buf, entry.dir_count);
            if !list_only {
                add_u64_le(&mut buf, entry.total_size.unwrap_or(0));
            }
            for item in &entry.items {
                add_utf16_le(&mut buf, &item.name);
                if list_only {
                    continue;
                }
                add_bool_le(&mut buf, item.is_dir);
                add_u64_le(&mut buf, item.size);
                add_u32_le(&mut buf, item.day);
                add_u32_le(&mut buf, item.month);
                add_u32_le(&mut buf, item.year);
                add_u32_le(&mut buf, item.minute);
                add_u32_le(&mut buf, item.hour);
            }
        }
    }

    buf
}

fn build_cd_payload(path: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Cd));
    add_utf16_le(&mut buf, path);
    buf
}

fn build_remove_payload(is_dir: bool, path: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Remove));
    add_bool_le(&mut buf, is_dir);
    add_utf16_le(&mut buf, path);
    buf
}

fn build_mkdir_payload(path: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Mkdir));
    add_utf16_le(&mut buf, path);
    buf
}

fn build_copy_move_payload(copy: bool, success: bool, from: &str, to: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    let subcmd = if copy { DemonFilesystemCommand::Copy } else { DemonFilesystemCommand::Move };
    add_u32_le(&mut buf, u32::from(subcmd));
    add_bool_le(&mut buf, success);
    add_utf16_le(&mut buf, from);
    add_utf16_le(&mut buf, to);
    buf
}

fn build_getpwd_payload(path: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::GetPwd));
    add_utf16_le(&mut buf, path);
    buf
}

// ---------------------------------------------------------------
// Dir callback — explorer, list-only, normal, success/failure modes
// ---------------------------------------------------------------

#[tokio::test]
async fn dir_explorer_mode_broadcasts_file_explorer_misc_data() {
    let (registry, db, events, downloads) = dir_test_deps().await;
    let mut rx = events.subscribe();

    let payload = build_dir_payload(
        true,  // explorer
        false, // list_only
        "C:\\Users\\admin",
        true, // success
        &[DirEntry {
            path: "C:\\Users\\admin\\*".to_owned(),
            file_count: 1,
            dir_count: 1,
            total_size: Some(4096),
            items: vec![
                DirItem {
                    name: "Documents".to_owned(),
                    is_dir: true,
                    size: 0,
                    day: 15,
                    month: 3,
                    year: 2026,
                    minute: 30,
                    hour: 14,
                },
                DirItem {
                    name: "notes.txt".to_owned(),
                    is_dir: false,
                    size: 2048,
                    day: 10,
                    month: 1,
                    year: 2026,
                    minute: 0,
                    hour: 9,
                },
            ],
        }],
    );

    handle_filesystem_callback(&registry, &db, &events, &downloads, None, 0xAA, 1, &payload)
        .await
        .expect("handler should succeed");

    let event = timeout(Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive event within timeout")
        .expect("should have a broadcast event");

    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };

    // Should be a FileExplorer misc type
    let misc_type = msg.info.extra.get("MiscType").and_then(|v| v.as_str());
    assert_eq!(misc_type, Some("FileExplorer"), "expected FileExplorer MiscType");

    // Decode MiscData from base64 → JSON
    let misc_data_b64 = msg
        .info
        .extra
        .get("MiscData")
        .and_then(|v| v.as_str())
        .expect("MiscData should be present");
    let misc_data_bytes =
        BASE64_STANDARD.decode(misc_data_b64).expect("MiscData should be valid base64");
    let misc_data: Value =
        serde_json::from_slice(&misc_data_bytes).expect("MiscData should be valid JSON");

    assert_eq!(
        misc_data["Path"].as_str(),
        Some("C:\\Users\\admin"),
        "MiscData.Path should match root_path"
    );
    let files = misc_data["Files"].as_array().expect("MiscData.Files should be array");
    assert_eq!(files.len(), 2, "should have 2 file rows");

    // First row is the directory
    assert_eq!(files[0]["Name"].as_str(), Some("Documents"));
    assert_eq!(files[0]["Type"].as_str(), Some("dir"));
    assert_eq!(files[0]["Size"].as_str(), Some(""));

    // Second row is the file
    assert_eq!(files[1]["Name"].as_str(), Some("notes.txt"));
    assert_eq!(files[1]["Type"].as_str(), Some(""));
    // byte_count(2048) = "2.05 kB" (decimal)
    assert!(!files[1]["Size"].as_str().unwrap_or("").is_empty(), "file size should be present");

    // In explorer mode, lines stay empty so output/message is the "not found" fallback —
    // the real data lives in MiscData.  Verify that the event was still broadcast.
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(message, "No file or folder was found");
}

#[tokio::test]
async fn dir_list_only_mode_outputs_concatenated_paths() {
    let (registry, db, events, downloads) = dir_test_deps().await;
    let mut rx = events.subscribe();

    let payload = build_dir_payload(
        false, // explorer
        true,  // list_only
        "C:\\tmp",
        true,
        &[DirEntry {
            path: "C:\\tmp\\*".to_owned(),
            file_count: 2,
            dir_count: 0,
            total_size: None,
            items: vec![
                DirItem {
                    name: "a.log".to_owned(),
                    is_dir: false,
                    size: 0,
                    day: 0,
                    month: 0,
                    year: 0,
                    minute: 0,
                    hour: 0,
                },
                DirItem {
                    name: "b.log".to_owned(),
                    is_dir: false,
                    size: 0,
                    day: 0,
                    month: 0,
                    year: 0,
                    minute: 0,
                    hour: 0,
                },
            ],
        }],
    );

    handle_filesystem_callback(&registry, &db, &events, &downloads, None, 0xBB, 2, &payload)
        .await
        .expect("handler should succeed");

    let event = timeout(Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive event within timeout")
        .expect("should have a broadcast event");

    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };

    // list_only paths: root "C:\tmp\*" trimmed to "C:\tmp\" + name
    let output = &msg.info.output;
    assert!(
        output.contains("C:\\tmp\\a.log"),
        "output should contain first file path, got: {output}"
    );
    assert!(
        output.contains("C:\\tmp\\b.log"),
        "output should contain second file path, got: {output}"
    );

    // No MiscType for non-explorer mode
    assert!(!msg.info.extra.contains_key("MiscType"), "non-explorer Dir should not set MiscType");
}

#[tokio::test]
async fn dir_success_zero_rows_outputs_no_file_found_message() {
    let (registry, db, events, downloads) = dir_test_deps().await;
    let mut rx = events.subscribe();

    // success=true but no directory entries → empty lines → "No file or folder was found"
    let payload = build_dir_payload(false, false, "C:\\empty", true, &[]);

    handle_filesystem_callback(&registry, &db, &events, &downloads, None, 0xCC, 3, &payload)
        .await
        .expect("handler should succeed");

    let event = timeout(Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive event within timeout")
        .expect("should have a broadcast event");

    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };

    assert_eq!(msg.info.output, "No file or folder was found");
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(message, "No file or folder was found");
}

#[tokio::test]
async fn dir_failure_outputs_no_file_found_message() {
    let (registry, db, events, downloads) = dir_test_deps().await;
    let mut rx = events.subscribe();

    // success=false → loop body skipped → lines empty → "No file or folder was found"
    let payload = build_dir_payload(false, false, "C:\\denied", false, &[]);

    handle_filesystem_callback(&registry, &db, &events, &downloads, None, 0xDD, 4, &payload)
        .await
        .expect("handler should succeed");

    let event = timeout(Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive event within timeout")
        .expect("should have a broadcast event");

    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };

    assert_eq!(msg.info.output, "No file or folder was found");
}

#[tokio::test]
async fn dir_normal_mode_formats_directory_listing() {
    let (registry, db, events, downloads) = dir_test_deps().await;
    let mut rx = events.subscribe();

    let payload = build_dir_payload(
        false, // explorer
        false, // list_only
        "C:\\work",
        true,
        &[DirEntry {
            path: "C:\\work\\*".to_owned(),
            file_count: 1,
            dir_count: 1,
            total_size: Some(8192),
            items: vec![
                DirItem {
                    name: "src".to_owned(),
                    is_dir: true,
                    size: 0,
                    day: 1,
                    month: 6,
                    year: 2025,
                    minute: 0,
                    hour: 12,
                },
                DirItem {
                    name: "Cargo.toml".to_owned(),
                    is_dir: false,
                    size: 512,
                    day: 2,
                    month: 6,
                    year: 2025,
                    minute: 30,
                    hour: 9,
                },
            ],
        }],
    );

    handle_filesystem_callback(&registry, &db, &events, &downloads, None, 0xB0, 90, &payload)
        .await
        .expect("handler should succeed");

    let event = timeout(Duration::from_millis(50), rx.recv())
        .await
        .expect("should receive event")
        .expect("broadcast");

    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };

    let output = &msg.info.output;
    // Should contain directory header
    assert!(output.contains("Directory of C:\\work\\*"), "output: {output}");
    // Should contain <DIR> marker for the directory entry
    assert!(output.contains("<DIR>"), "output should contain <DIR>: {output}");
    assert!(output.contains("src"), "output should contain dir name: {output}");
    assert!(output.contains("Cargo.toml"), "output should contain file name: {output}");
    // Should contain file/folder summary
    assert!(output.contains("1 File(s)"), "output should contain file count: {output}");
    assert!(output.contains("1 Folder(s)"), "output should contain folder count: {output}");

    // Message should indicate completion
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(message, "Directory listing completed");

    // No MiscType in normal mode
    assert!(!msg.info.extra.contains_key("MiscType"));
}

#[tokio::test]
async fn dir_item_count_overflow_returns_error() {
    let (registry, db, events, downloads) = dir_test_deps().await;

    // Build a payload with file_count + dir_count that would overflow u32.
    let mut buf = Vec::new();
    add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Dir));
    add_bool_le(&mut buf, false); // explorer
    add_bool_le(&mut buf, false); // list_only
    add_utf16_le(&mut buf, "C:\\"); // root_path
    add_bool_le(&mut buf, true); // success
    // First directory entry
    add_utf16_le(&mut buf, "C:\\*"); // path
    add_u32_le(&mut buf, 0xFFFF_FFFF); // file_count
    add_u32_le(&mut buf, 1); // dir_count — sum wraps to 0
    add_u64_le(&mut buf, 0); // total_size (not list_only)

    let err = handle_filesystem_callback(&registry, &db, &events, &downloads, None, 0xBB, 1, &buf)
        .await
        .expect_err("should fail on item count overflow");

    assert!(
        matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
        "expected InvalidCallbackPayload, got {err:?}"
    );
}

// ---------------------------------------------------------------
// Cd callback
// ---------------------------------------------------------------

#[tokio::test]
async fn cd_callback_emits_changed_directory() {
    let event = call_and_recv(&build_cd_payload("C:\\Windows\\System32"), 0xA2, 20).await;
    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("Changed directory"), "message: {message}");
    assert!(message.contains("C:\\Windows\\System32"), "message: {message}");
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Info"));
}

// ---------------------------------------------------------------
// Remove callback — file and directory variants
// ---------------------------------------------------------------

#[tokio::test]
async fn remove_file_callback_emits_removed_file() {
    let event = call_and_recv(&build_remove_payload(false, "C:\\Temp\\old.log"), 0xA3, 30).await;
    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("Removed file"), "message: {message}");
    assert!(message.contains("C:\\Temp\\old.log"), "message: {message}");
}

#[tokio::test]
async fn remove_directory_callback_emits_removed_directory() {
    let event = call_and_recv(&build_remove_payload(true, "C:\\Temp\\cache"), 0xA4, 31).await;
    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("Removed directory"), "message: {message}");
    assert!(message.contains("C:\\Temp\\cache"), "message: {message}");
}

// ---------------------------------------------------------------
// Mkdir callback
// ---------------------------------------------------------------

#[tokio::test]
async fn mkdir_callback_emits_created_directory() {
    let event = call_and_recv(&build_mkdir_payload("C:\\Users\\admin\\new_dir"), 0xA5, 40).await;
    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("Created directory"), "message: {message}");
    assert!(message.contains("C:\\Users\\admin\\new_dir"), "message: {message}");
}

// ---------------------------------------------------------------
// Copy callback — success and failure
// ---------------------------------------------------------------

#[tokio::test]
async fn copy_success_callback_emits_good_message() {
    let event =
        call_and_recv(&build_copy_move_payload(true, true, "C:\\src.txt", "C:\\dst.txt"), 0xA6, 50)
            .await;
    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("Successfully copied"), "message: {message}");
    assert!(message.contains("C:\\src.txt"), "message: {message}");
    assert!(message.contains("C:\\dst.txt"), "message: {message}");
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
}

#[tokio::test]
async fn copy_failure_callback_emits_error_message() {
    let event = call_and_recv(
        &build_copy_move_payload(true, false, "C:\\nope.txt", "C:\\dest.txt"),
        0xA7,
        51,
    )
    .await;
    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("Failed to copy"), "message: {message}");
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
}

// ---------------------------------------------------------------
// Move callback — success and failure
// ---------------------------------------------------------------

#[tokio::test]
async fn move_success_callback_emits_good_message() {
    let event = call_and_recv(
        &build_copy_move_payload(false, true, "C:\\old.dat", "C:\\new.dat"),
        0xA8,
        60,
    )
    .await;
    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("Successfully moved"), "message: {message}");
    assert!(message.contains("C:\\old.dat"), "message: {message}");
    assert!(message.contains("C:\\new.dat"), "message: {message}");
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
}

#[tokio::test]
async fn move_failure_callback_emits_error_message() {
    let event = call_and_recv(
        &build_copy_move_payload(false, false, "C:\\locked.sys", "C:\\target.sys"),
        0xA9,
        61,
    )
    .await;
    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("Failed to move"), "message: {message}");
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
}

// ---------------------------------------------------------------
// GetPwd callback
// ---------------------------------------------------------------

#[tokio::test]
async fn getpwd_callback_emits_current_directory() {
    let event = call_and_recv(&build_getpwd_payload("C:\\Users\\admin"), 0xAA, 70).await;
    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("Current directory"), "message: {message}");
    assert!(message.contains("C:\\Users\\admin"), "message: {message}");
}

// ---------------------------------------------------------------
// Truncated payload tests — each directory subcommand with insufficient data
// ---------------------------------------------------------------

#[tokio::test]
async fn cd_truncated_payload_returns_error() {
    // Cd needs: subcommand(u32) + utf16 string. Provide only the subcommand.
    let mut buf = Vec::new();
    add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Cd));
    let err = call_and_expect_error(&buf, 0xE0, 1).await;
    assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }), "got {err:?}");
}

#[tokio::test]
async fn remove_truncated_payload_missing_path_returns_error() {
    // Remove needs: subcommand(u32) + bool(is_dir) + utf16(path). Only provide subcommand + bool.
    let mut buf = Vec::new();
    add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Remove));
    add_bool_le(&mut buf, false);
    let err = call_and_expect_error(&buf, 0xE1, 2).await;
    assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }), "got {err:?}");
}

#[tokio::test]
async fn remove_truncated_payload_missing_bool_returns_error() {
    // Remove needs at least the bool before the path.
    let mut buf = Vec::new();
    add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Remove));
    let err = call_and_expect_error(&buf, 0xE2, 3).await;
    assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }), "got {err:?}");
}

#[tokio::test]
async fn mkdir_truncated_payload_returns_error() {
    let mut buf = Vec::new();
    add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Mkdir));
    let err = call_and_expect_error(&buf, 0xE3, 4).await;
    assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }), "got {err:?}");
}

#[tokio::test]
async fn copy_truncated_payload_missing_to_returns_error() {
    // Copy needs: subcommand + bool(success) + utf16(from) + utf16(to). Omit 'to'.
    let mut buf = Vec::new();
    add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Copy));
    add_bool_le(&mut buf, true);
    add_utf16_le(&mut buf, "C:\\from.txt");
    let err = call_and_expect_error(&buf, 0xE4, 5).await;
    assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }), "got {err:?}");
}

#[tokio::test]
async fn move_truncated_payload_missing_to_returns_error() {
    let mut buf = Vec::new();
    add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Move));
    add_bool_le(&mut buf, true);
    add_utf16_le(&mut buf, "C:\\from.txt");
    let err = call_and_expect_error(&buf, 0xE5, 6).await;
    assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }), "got {err:?}");
}

#[tokio::test]
async fn copy_truncated_payload_empty_returns_error() {
    // Only subcommand, no bool or strings.
    let mut buf = Vec::new();
    add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Copy));
    let err = call_and_expect_error(&buf, 0xE6, 7).await;
    assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }), "got {err:?}");
}

#[tokio::test]
async fn getpwd_truncated_payload_returns_error() {
    let mut buf = Vec::new();
    add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::GetPwd));
    let err = call_and_expect_error(&buf, 0xE7, 8).await;
    assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }), "got {err:?}");
}

// ---------------------------------------------------------------
// Edge case tests — empty strings
// ---------------------------------------------------------------

#[tokio::test]
async fn cd_empty_path_broadcasts_event() {
    let event = call_and_recv(&build_cd_payload(""), 0xF0, 100).await;
    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("Changed directory"), "message: {message}");
}

#[tokio::test]
async fn mkdir_empty_path_broadcasts_event() {
    let event = call_and_recv(&build_mkdir_payload(""), 0xF1, 101).await;
    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("Created directory"), "message: {message}");
}

#[tokio::test]
async fn remove_empty_path_broadcasts_event() {
    let event = call_and_recv(&build_remove_payload(false, ""), 0xF2, 102).await;
    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("Removed file"), "message: {message}");
}

#[tokio::test]
async fn getpwd_empty_path_broadcasts_event() {
    let event = call_and_recv(&build_getpwd_payload(""), 0xF3, 103).await;
    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("Current directory"), "message: {message}");
}

#[tokio::test]
async fn copy_empty_paths_success_broadcasts_event() {
    let event = call_and_recv(&build_copy_move_payload(true, true, "", ""), 0xF6, 106).await;
    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("Successfully copied"), "message: {message}");
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Good"));
}

#[tokio::test]
async fn move_empty_paths_failure_broadcasts_error() {
    let event = call_and_recv(&build_copy_move_payload(false, false, "", ""), 0xF7, 107).await;
    let OperatorMessage::AgentResponse(msg) = &event else {
        panic!("expected AgentResponse, got {event:?}");
    };
    let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
    assert!(message.contains("Failed to move"), "message: {message}");
    assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"));
}
