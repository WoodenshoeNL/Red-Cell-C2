//! Dispatch handlers for `CommandFs` callbacks.
//!
//! Routes the filesystem subcommand byte to per-operation handlers. Each
//! subcommand lives in its own submodule: Download in `download.rs`, the
//! directory operations (Dir, Mkdir, Cd, GetPwd, Remove, Copy, Move) in
//! `directory.rs`, Upload in `upload.rs`, and Cat in `cat.rs`.

use red_cell_common::demon::{DemonCommand, DemonFilesystemCommand};

use crate::{AgentRegistry, Database, EventBus, PluginRuntime};

use super::{CallbackParser, CommandDispatchError, DownloadTracker};

mod cat;
mod directory;
mod download;
mod upload;

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
            upload::handle_upload(events, &mut parser, agent_id, request_id)?;
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
            cat::handle_cat(events, &mut parser, agent_id, request_id)?;
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use red_cell_common::operator::OperatorMessage;

    mod cat;
    mod common;
    mod directory;
    mod download;
    mod upload;

    use common::{add_u32_le, call_and_expect_error};
    use download::{build_download_open_payload, build_download_write_payload};

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
