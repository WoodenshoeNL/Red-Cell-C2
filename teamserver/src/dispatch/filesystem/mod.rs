//! Dispatch handlers for `CommandFs` callbacks.
//!
//! Routes the filesystem subcommand byte to per-operation handlers. Download
//! lives in its own submodule (see `download.rs`); the directory operations
//! (Dir, Mkdir, Cd, GetPwd, Remove, Copy, Move) live in `directory.rs`.
//! Upload and Cat remain inline pending further sub-issues.

use red_cell_common::demon::{DemonCommand, DemonFilesystemCommand};

use crate::{AgentRegistry, Database, EventBus, PluginRuntime};

use super::{CallbackParser, CommandDispatchError, DownloadTracker, agent_response_event};

mod directory;
mod download;

// Re-exports for sibling dispatch submodules (e.g. `transfer`) that already
// reference these helpers as `super::filesystem::X`.
pub(in crate::dispatch) use download::{
    download_complete_event, download_progress_event, parse_file_chunk, parse_file_close,
    parse_file_open_header, persist_download,
};

pub(super) async fn handle_filesystem_callback(
    registry: &AgentRegistry,
    database: &Database,
    events: &EventBus,
    downloads: &DownloadTracker,
    plugins: Option<&PluginRuntime>,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandFs));
    let subcommand = parser.read_u32("filesystem subcommand")?;
    let subcommand = DemonFilesystemCommand::try_from(subcommand).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandFs),
            message: error.to_string(),
        }
    })?;
    match subcommand {
        DemonFilesystemCommand::Dir => {
            directory::handle_dir(events, &mut parser, agent_id, request_id)?;
        }
        DemonFilesystemCommand::Download => {
            download::handle_download(
                registry,
                database,
                events,
                downloads,
                plugins,
                agent_id,
                request_id,
                &mut parser,
            )
            .await?;
        }
        DemonFilesystemCommand::Upload => {
            let size = parser.read_u32("filesystem upload size")?;
            let path = parser.read_utf16("filesystem upload path")?;
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandFs),
                request_id,
                "Info",
                &format!("Uploaded file: {path} ({size} bytes)"),
                None,
            )?);
        }
        DemonFilesystemCommand::Cd => {
            directory::handle_cd(events, &mut parser, agent_id, request_id)?;
        }
        DemonFilesystemCommand::Remove => {
            directory::handle_remove(events, &mut parser, agent_id, request_id)?;
        }
        DemonFilesystemCommand::Mkdir => {
            directory::handle_mkdir(events, &mut parser, agent_id, request_id)?;
        }
        DemonFilesystemCommand::Copy | DemonFilesystemCommand::Move => {
            directory::handle_copy_move(events, &mut parser, subcommand, agent_id, request_id)?;
        }
        DemonFilesystemCommand::GetPwd => {
            directory::handle_getpwd(events, &mut parser, agent_id, request_id)?;
        }
        DemonFilesystemCommand::Cat => {
            let path = parser.read_utf16("filesystem cat path")?;
            let success = parser.read_bool("filesystem cat success")?;
            let output = parser.read_string("filesystem cat output")?;
            let (kind, message) = if success {
                ("Info", format!("File content of {path} ({}):", output.len()))
            } else {
                ("Error", format!("Failed to read file: {path}"))
            };
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandFs),
                request_id,
                kind,
                &message,
                if success { Some(output) } else { None },
            )?);
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use red_cell_common::demon::DemonFilesystemCommand;
    use red_cell_common::operator::OperatorMessage;

    mod common;
    mod directory;
    mod download;

    use common::{
        add_bool_le, add_u32_le, add_utf16_le, call_and_expect_error, call_and_recv,
    };
    use download::{build_download_open_payload, build_download_write_payload};

    // ---------------------------------------------------------------
    // Payload builders for Upload and Cat (remain inline until the
    // Upload/Cat handlers are extracted in a follow-up sub-issue).
    // ---------------------------------------------------------------

    fn build_upload_payload(size: u32, path: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Upload));
        add_u32_le(&mut buf, size);
        add_utf16_le(&mut buf, path);
        buf
    }

    /// Build a Cat subcommand payload.  `output` is encoded via `read_string`
    /// (u32-LE length prefix + raw UTF-8 bytes).
    fn build_cat_payload(path: &str, success: bool, output: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Cat));
        add_utf16_le(&mut buf, path);
        add_bool_le(&mut buf, success);
        // read_string = read_bytes (u32 LE len + raw bytes)
        let raw = output.as_bytes();
        add_u32_le(&mut buf, u32::try_from(raw.len()).expect("unwrap"));
        buf.extend_from_slice(raw);
        buf
    }

    // ---------------------------------------------------------------
    // Upload callback
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn upload_callback_emits_info_with_size_and_path() {
        let event =
            call_and_recv(&build_upload_payload(4096, "C:\\Temp\\payload.bin"), 0xA1, 10).await;
        let OperatorMessage::AgentResponse(msg) = &event else {
            panic!("expected AgentResponse, got {event:?}");
        };
        let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(message.contains("Uploaded file"), "message: {message}");
        assert!(message.contains("C:\\Temp\\payload.bin"), "message: {message}");
        assert!(message.contains("4096 bytes"), "message: {message}");
        assert_eq!(msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Info"));
    }

    // ---------------------------------------------------------------
    // Cat callback — success and failure
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn cat_success_callback_emits_file_content() {
        let content = "Hello, World!\nLine 2\n";
        let event =
            call_and_recv(&build_cat_payload("C:\\readme.txt", true, content), 0xAB, 80).await;
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
        let event = call_and_recv(
            &build_cat_payload("C:\\secret.key", false, "ignored error data"),
            0xAC,
            81,
        )
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

    // ---------------------------------------------------------------
    // Upload/Cat truncated-payload tests
    // ---------------------------------------------------------------

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

    // ---------------------------------------------------------------
    // Edge case tests — Upload/Cat zero-length payloads
    // ---------------------------------------------------------------

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

    // ---------------------------------------------------------------
    // Dispatcher-level errors: invalid subcommand, empty payload.
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn invalid_subcommand_id_returns_error() {
        let mut buf = Vec::new();
        add_u32_le(&mut buf, 0xFFFF); // invalid subcommand
        let err = call_and_expect_error(&buf, 0xFF, 200).await;
        assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }), "got {err:?}");
    }

    #[tokio::test]
    async fn empty_payload_returns_error() {
        let err = call_and_expect_error(&[], 0xFF, 201).await;
        assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }), "got {err:?}");
    }

    // ---------------------------------------------------------------
    // DownloadTracker memory limit enforcement via filesystem dispatch
    // ---------------------------------------------------------------

    /// Helper that creates test dependencies with a small download tracker limit.
    async fn small_limit_test_deps(
        max_bytes: usize,
    ) -> (AgentRegistry, Database, EventBus, DownloadTracker) {
        let db = Database::connect_in_memory().await.expect("in-memory db");
        let registry = AgentRegistry::new(db.clone());
        let events = EventBus::default();
        let downloads = DownloadTracker::new(max_bytes);
        (registry, db, events, downloads)
    }

    #[tokio::test]
    async fn download_exceeding_memory_limit_surfaces_error_event() {
        let (registry, db, events, downloads) = small_limit_test_deps(64).await;
        let mut receiver = events.subscribe();
        let agent_id = 0xFA10;
        let file_id = 0xA1;
        let request_id = 0xC1;
        let remote_path = "C:\\Temp\\big.bin";

        // Open the download.
        handle_filesystem_callback(
            &registry,
            &db,
            &events,
            &downloads,
            None,
            agent_id,
            request_id,
            &build_download_open_payload(file_id, 256, remote_path),
        )
        .await
        .expect("open should succeed");

        // Append a chunk that fits within the limit.
        let small_chunk = vec![0xAA; 32];
        handle_filesystem_callback(
            &registry,
            &db,
            &events,
            &downloads,
            None,
            agent_id,
            request_id,
            &build_download_write_payload(file_id, &small_chunk),
        )
        .await
        .expect("first chunk within limit should succeed");

        // Append a chunk that pushes past the 64-byte limit (32 + 48 = 80 > 64).
        // Must return Ok(None) — limit failure is surfaced as an operator event + audit entry.
        let overflow_chunk = vec![0xBB; 48];
        handle_filesystem_callback(
            &registry,
            &db,
            &events,
            &downloads,
            None,
            agent_id,
            request_id,
            &build_download_write_payload(file_id, &overflow_chunk),
        )
        .await
        .expect("overflow chunk should not propagate as dispatch error");

        // The download should have been removed after exceeding the limit.
        assert!(downloads.finish(agent_id, file_id).await.is_none(), "download should be removed");

        // Drain: open-progress event, write-progress event, then error event.
        let _open_ev = receiver.recv().await.expect("open event");
        let _write_ev = receiver.recv().await.expect("write event");
        let error_ev = receiver.recv().await.expect("error event");
        let OperatorMessage::AgentResponse(error_msg) = error_ev else {
            panic!("expected AgentResponse error event");
        };
        assert_eq!(
            error_msg.info.extra.get("Type").and_then(|v| v.as_str()),
            Some("Error"),
            "limit event must be Error type"
        );

        // Audit log must record the rejection.
        let audit_rows = db.audit_log().list().await.expect("audit list");
        assert!(
            audit_rows.iter().any(|r| r.action == "download.rejected"),
            "audit log must contain a download.rejected entry"
        );
    }

    #[tokio::test]
    async fn download_exactly_at_memory_limit_succeeds() {
        let (registry, db, events, downloads) = small_limit_test_deps(64).await;
        let agent_id = 0xFA11;
        let file_id = 0xA2;
        let request_id = 0xC2;
        let remote_path = "C:\\Temp\\exact.bin";

        // Open the download.
        handle_filesystem_callback(
            &registry,
            &db,
            &events,
            &downloads,
            None,
            agent_id,
            request_id,
            &build_download_open_payload(file_id, 64, remote_path),
        )
        .await
        .expect("open should succeed");

        // Append exactly 64 bytes in two 32-byte chunks.
        let chunk = vec![0xCC; 32];
        handle_filesystem_callback(
            &registry,
            &db,
            &events,
            &downloads,
            None,
            agent_id,
            request_id,
            &build_download_write_payload(file_id, &chunk),
        )
        .await
        .expect("first half should succeed");

        handle_filesystem_callback(
            &registry,
            &db,
            &events,
            &downloads,
            None,
            agent_id,
            request_id,
            &build_download_write_payload(file_id, &chunk),
        )
        .await
        .expect("second half (exactly at limit) should succeed");

        // Verify data is intact.
        let finished = downloads.finish(agent_id, file_id).await;
        let state = finished.expect("download at exact limit should still be tracked");
        assert_eq!(state.data.len(), 64);
        assert!(state.data.iter().all(|&b| b == 0xCC));
    }

    #[tokio::test]
    async fn download_one_byte_over_limit_surfaces_error_event() {
        let (registry, db, events, downloads) = small_limit_test_deps(64).await;
        let mut receiver = events.subscribe();
        let agent_id = 0xFA12;
        let file_id = 0xA3;
        let request_id = 0xC3;
        let remote_path = "C:\\Temp\\one_over.bin";

        // Open the download.
        handle_filesystem_callback(
            &registry,
            &db,
            &events,
            &downloads,
            None,
            agent_id,
            request_id,
            &build_download_open_payload(file_id, 128, remote_path),
        )
        .await
        .expect("open should succeed");

        // Fill exactly to the limit.
        let full_chunk = vec![0xDD; 64];
        handle_filesystem_callback(
            &registry,
            &db,
            &events,
            &downloads,
            None,
            agent_id,
            request_id,
            &build_download_write_payload(file_id, &full_chunk),
        )
        .await
        .expect("filling to exact limit should succeed");

        // One more byte — must return Ok(None) with error surfaced as event.
        handle_filesystem_callback(
            &registry,
            &db,
            &events,
            &downloads,
            None,
            agent_id,
            request_id,
            &build_download_write_payload(file_id, &[0xEE]),
        )
        .await
        .expect("one-byte-over write should not propagate as dispatch error");

        // Drain: open event, write event, error event.
        let _open_ev = receiver.recv().await.expect("open event");
        let _write_ev = receiver.recv().await.expect("write event");
        let error_ev = receiver.recv().await.expect("error event");
        let OperatorMessage::AgentResponse(error_msg) = error_ev else {
            panic!("expected AgentResponse error event");
        };
        assert_eq!(error_msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"),);
        let audit_rows = db.audit_log().list().await.expect("audit list");
        assert!(audit_rows.iter().any(|r| r.action == "download.rejected"));
    }

    #[tokio::test]
    async fn download_single_chunk_exceeding_limit_surfaces_error_event() {
        let (registry, db, events, downloads) = small_limit_test_deps(16).await;
        let mut receiver = events.subscribe();
        let agent_id = 0xFA13;
        let file_id = 0xA4;
        let request_id = 0xC4;
        let remote_path = "C:\\Temp\\single_huge.bin";

        // Open the download.
        handle_filesystem_callback(
            &registry,
            &db,
            &events,
            &downloads,
            None,
            agent_id,
            request_id,
            &build_download_open_payload(file_id, 1024, remote_path),
        )
        .await
        .expect("open should succeed");

        // A single chunk larger than the limit must return Ok(None).
        let huge_chunk = vec![0xFF; 32];
        handle_filesystem_callback(
            &registry,
            &db,
            &events,
            &downloads,
            None,
            agent_id,
            request_id,
            &build_download_write_payload(file_id, &huge_chunk),
        )
        .await
        .expect("oversized single chunk should not propagate as dispatch error");

        // Download should be removed.
        assert!(downloads.finish(agent_id, file_id).await.is_none());

        // Drain: open event, then error event.
        let _open_ev = receiver.recv().await.expect("open event");
        let error_ev = receiver.recv().await.expect("error event");
        let OperatorMessage::AgentResponse(error_msg) = error_ev else {
            panic!("expected AgentResponse error event");
        };
        assert_eq!(error_msg.info.extra.get("Type").and_then(|v| v.as_str()), Some("Error"),);
        let audit_rows = db.audit_log().list().await.expect("audit list");
        assert!(audit_rows.iter().any(|r| r.action == "download.rejected"));
    }

    #[tokio::test]
    async fn buffered_bytes_freed_after_limit_exceeded() {
        let (registry, db, events, downloads) = small_limit_test_deps(32).await;
        let agent_id = 0xFA14;
        let file_id = 0xA5;
        let request_id = 0xC5;
        let remote_path = "C:\\Temp\\freed.bin";

        // Open and fill to 32 bytes.
        handle_filesystem_callback(
            &registry,
            &db,
            &events,
            &downloads,
            None,
            agent_id,
            request_id,
            &build_download_open_payload(file_id, 128, remote_path),
        )
        .await
        .expect("open should succeed");

        let chunk = vec![0x11; 32];
        handle_filesystem_callback(
            &registry,
            &db,
            &events,
            &downloads,
            None,
            agent_id,
            request_id,
            &build_download_write_payload(file_id, &chunk),
        )
        .await
        .expect("fill to limit should succeed");

        assert_eq!(downloads.buffered_bytes().await, 32);

        // Exceed the limit — should remove the download and free buffered bytes.
        let _ = handle_filesystem_callback(
            &registry,
            &db,
            &events,
            &downloads,
            None,
            agent_id,
            request_id,
            &build_download_write_payload(file_id, &[0x22]),
        )
        .await;

        assert_eq!(
            downloads.buffered_bytes().await,
            0,
            "buffered bytes should be freed after download removed due to limit"
        );
    }
}
