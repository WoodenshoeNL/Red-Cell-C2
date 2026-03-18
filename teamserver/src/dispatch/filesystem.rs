use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell_common::demon::{DemonCommand, DemonFilesystemCommand};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::warn;

use crate::{AgentRegistry, Database, EventBus, LootRecord, PluginRuntime};

use super::transfer::byte_count;
use super::{
    CallbackParser, CommandDispatchError, DownloadState, DownloadTracker, LootContext,
    agent_response_event, agent_response_event_with_extra, insert_loot_record, loot_context,
    loot_new_event, metadata_with_context,
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
    let context = loot_context(registry, agent_id, request_id).await;
    let subcommand = DemonFilesystemCommand::try_from(subcommand).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandFs),
            message: error.to_string(),
        }
    })?;
    match subcommand {
        DemonFilesystemCommand::Dir => {
            let explorer = parser.read_bool("filesystem dir explorer")?;
            let list_only = parser.read_bool("filesystem dir list only")?;
            let root_path = parser.read_utf16("filesystem dir root path")?;
            let success = parser.read_bool("filesystem dir success")?;
            let mut lines = Vec::new();
            let mut explorer_rows = Vec::new();

            if success {
                while !parser.is_empty() {
                    let path = parser.read_utf16("filesystem dir path")?;
                    let file_count = parser.read_u32("filesystem dir file count")?;
                    let dir_count = parser.read_u32("filesystem dir dir count")?;
                    let total_size = if list_only {
                        None
                    } else {
                        Some(parser.read_u64("filesystem dir total size")?)
                    };

                    if !explorer {
                        lines.push(format!(" Directory of {path}"));
                        lines.push(String::new());
                    }

                    let item_count = file_count + dir_count;
                    for _ in 0..item_count {
                        let name = parser.read_utf16("filesystem dir item name")?;
                        if list_only {
                            lines.push(format!("{}{}", path.trim_end_matches('*'), name));
                            continue;
                        }
                        let is_dir = parser.read_bool("filesystem dir item is dir")?;
                        let size = parser.read_u64("filesystem dir item size")?;
                        let day = parser.read_u32("filesystem dir item day")?;
                        let month = parser.read_u32("filesystem dir item month")?;
                        let year = parser.read_u32("filesystem dir item year")?;
                        let minute = parser.read_u32("filesystem dir item minute")?;
                        let hour = parser.read_u32("filesystem dir item hour")?;
                        let modified = format!("{day:02}/{month:02}/{year}  {hour:02}:{minute:02}");
                        if explorer {
                            explorer_rows.push(Value::Object(
                                [
                                    (
                                        "Type".to_owned(),
                                        Value::String(if is_dir { "dir" } else { "" }.to_owned()),
                                    ),
                                    (
                                        "Size".to_owned(),
                                        Value::String(if is_dir {
                                            String::new()
                                        } else {
                                            byte_count(size)
                                        }),
                                    ),
                                    ("Modified".to_owned(), Value::String(modified)),
                                    ("Name".to_owned(), Value::String(name)),
                                ]
                                .into_iter()
                                .collect(),
                            ));
                        } else {
                            let dir_text = if is_dir { "<DIR>" } else { "" };
                            let size_text = if is_dir { String::new() } else { byte_count(size) };
                            lines.push(format!(
                                "{modified:<17}    {dir_text:<5}  {size_text:<12}   {name}"
                            ));
                        }
                    }

                    if !explorer && !list_only && (file_count > 0 || dir_count > 0) {
                        lines.push(format!(
                            "               {file_count} File(s)     {}",
                            byte_count(total_size.unwrap_or_default())
                        ));
                        lines.push(format!("               {dir_count} Folder(s)"));
                        lines.push(String::new());
                    }
                }
            }

            let output = if lines.is_empty() {
                "No file or folder was found".to_owned()
            } else {
                lines.join("\n").trim().to_owned()
            };
            let mut extra = BTreeMap::new();
            if explorer {
                extra.insert("MiscType".to_owned(), Value::String("FileExplorer".to_owned()));
                extra.insert(
                    "MiscData".to_owned(),
                    Value::String(
                        BASE64_STANDARD.encode(
                            serde_json::to_vec(&Value::Object(
                                [
                                    ("Path".to_owned(), Value::String(root_path)),
                                    ("Files".to_owned(), Value::Array(explorer_rows)),
                                ]
                                .into_iter()
                                .collect(),
                            ))
                            .map_err(|error| {
                                CommandDispatchError::InvalidCallbackPayload {
                                    command_id: u32::from(DemonCommand::CommandFs),
                                    message: error.to_string(),
                                }
                            })?,
                        ),
                    ),
                );
            }
            events.broadcast(agent_response_event_with_extra(
                agent_id,
                u32::from(DemonCommand::CommandFs),
                request_id,
                "Info",
                if output == "No file or folder was found" {
                    "No file or folder was found"
                } else {
                    "Directory listing completed"
                },
                extra,
                output,
            )?);
        }
        DemonFilesystemCommand::Download => {
            let mode = parser.read_u32("filesystem download mode")?;
            let file_id = parser.read_u32("filesystem download file id")?;
            match mode {
                0 => {
                    let expected_size = parser.read_u64("filesystem download size")?;
                    let remote_path = parser.read_utf16("filesystem download path")?;
                    let started_at = OffsetDateTime::now_utc().format(&Rfc3339)?;
                    downloads
                        .start(
                            agent_id,
                            file_id,
                            DownloadState {
                                request_id,
                                remote_path: remote_path.clone(),
                                expected_size,
                                data: Vec::new(),
                                started_at,
                            },
                        )
                        .await;
                    events.broadcast(download_progress_event(
                        agent_id,
                        u32::from(DemonCommand::CommandFs),
                        request_id,
                        file_id,
                        &remote_path,
                        0,
                        expected_size,
                        "Started",
                    )?);
                }
                1 => {
                    let chunk = parser.read_bytes("filesystem download chunk")?;
                    let state = downloads.append(agent_id, file_id, &chunk).await?;
                    events.broadcast(download_progress_event(
                        agent_id,
                        u32::from(DemonCommand::CommandFs),
                        state.request_id,
                        file_id,
                        &state.remote_path,
                        state.data.len() as u64,
                        state.expected_size,
                        "InProgress",
                    )?);
                }
                2 => {
                    let reason = parser.read_u32("filesystem download close reason")?;
                    if let Some(state) = downloads.finish(agent_id, file_id).await {
                        if reason == 0 {
                            let record =
                                persist_download(database, agent_id, file_id, &state, &context)
                                    .await?;
                            events.broadcast(loot_new_event(
                                &record,
                                u32::from(DemonCommand::CommandFs),
                                state.request_id,
                                &context,
                            )?);
                            events.broadcast(download_complete_event(
                                agent_id,
                                u32::from(DemonCommand::CommandFs),
                                state.request_id,
                                file_id,
                                &state,
                            )?);
                            if let Some(plugins) = plugins
                                && let Err(error) = plugins.emit_loot_captured(&record).await
                            {
                                warn!(agent_id = format_args!("{agent_id:08X}"), %error, "failed to emit python loot_captured event");
                            }
                        } else {
                            events.broadcast(download_progress_event(
                                agent_id,
                                u32::from(DemonCommand::CommandFs),
                                state.request_id,
                                file_id,
                                &state.remote_path,
                                state.data.len() as u64,
                                state.expected_size,
                                "Removed",
                            )?);
                        }
                    }
                }
                other => {
                    return Err(CommandDispatchError::InvalidCallbackPayload {
                        command_id: u32::from(DemonCommand::CommandFs),
                        message: format!("unsupported filesystem download mode {other}"),
                    });
                }
            }
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
            let path = parser.read_utf16("filesystem cd path")?;
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandFs),
                request_id,
                "Info",
                &format!("Changed directory: {path}"),
                None,
            )?);
        }
        DemonFilesystemCommand::Remove => {
            let is_dir = parser.read_bool("filesystem remove is dir")?;
            let path = parser.read_utf16("filesystem remove path")?;
            let noun = if is_dir { "directory" } else { "file" };
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandFs),
                request_id,
                "Info",
                &format!("Removed {noun}: {path}"),
                None,
            )?);
        }
        DemonFilesystemCommand::Mkdir => {
            let path = parser.read_utf16("filesystem mkdir path")?;
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandFs),
                request_id,
                "Info",
                &format!("Created directory: {path}"),
                None,
            )?);
        }
        DemonFilesystemCommand::Copy | DemonFilesystemCommand::Move => {
            let success = parser.read_bool("filesystem copy/move success")?;
            let from = parser.read_utf16("filesystem copy/move from")?;
            let to = parser.read_utf16("filesystem copy/move to")?;
            let verb =
                if matches!(subcommand, DemonFilesystemCommand::Copy) { "copied" } else { "moved" };
            let kind = if success { "Good" } else { "Error" };
            let message = if success {
                format!("Successfully {verb} file {from} to {to}")
            } else {
                format!("Failed to {verb} file {from} to {to}")
            };
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandFs),
                request_id,
                kind,
                &message,
                None,
            )?);
        }
        DemonFilesystemCommand::GetPwd => {
            let path = parser.read_utf16("filesystem pwd path")?;
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandFs),
                request_id,
                "Info",
                &format!("Current directory: {path}"),
                None,
            )?);
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

pub(super) fn parse_file_open_header(
    command_id: u32,
    bytes: &[u8],
) -> Result<(u32, u64, String), CommandDispatchError> {
    if bytes.len() < 8 {
        return Err(CommandDispatchError::InvalidCallbackPayload {
            command_id,
            message: format!("file open payload: expected at least 8 bytes, got {}", bytes.len()),
        });
    }
    let file_id = u32::from_be_bytes(bytes[0..4].try_into().map_err(|_| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id,
            message: "file id parse failure".to_owned(),
        }
    })?);
    let expected_size = u64::from(u32::from_be_bytes(bytes[4..8].try_into().map_err(|_| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id,
            message: "file size parse failure".to_owned(),
        }
    })?));
    let path = String::from_utf8_lossy(&bytes[8..]).trim_end_matches('\0').to_owned();
    Ok((file_id, expected_size, path))
}

pub(super) fn parse_file_chunk(
    command_id: u32,
    bytes: &[u8],
) -> Result<(u32, Vec<u8>), CommandDispatchError> {
    if bytes.len() < 4 {
        return Err(CommandDispatchError::InvalidCallbackPayload {
            command_id,
            message: format!("file chunk payload: expected at least 4 bytes, got {}", bytes.len()),
        });
    }
    let file_id = u32::from_be_bytes(bytes[0..4].try_into().map_err(|_| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id,
            message: "file id parse failure".to_owned(),
        }
    })?);
    Ok((file_id, bytes[4..].to_vec()))
}

pub(super) fn parse_file_close(command_id: u32, bytes: &[u8]) -> Result<u32, CommandDispatchError> {
    if bytes.len() < 4 {
        return Err(CommandDispatchError::InvalidCallbackPayload {
            command_id,
            message: format!("file close payload: expected 4 bytes, got {}", bytes.len()),
        });
    }
    let file_id = u32::from_be_bytes(bytes[0..4].try_into().map_err(|_| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id,
            message: "file close parse failure".to_owned(),
        }
    })?);
    Ok(file_id)
}

pub(super) async fn persist_download(
    database: &Database,
    agent_id: u32,
    file_id: u32,
    state: &DownloadState,
    context: &LootContext,
) -> Result<LootRecord, CommandDispatchError> {
    let name = state
        .remote_path
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or(state.remote_path.as_str())
        .trim_end_matches('\0')
        .to_owned();
    insert_loot_record(
        database,
        LootRecord {
            id: None,
            agent_id,
            kind: "download".to_owned(),
            name,
            file_path: Some(state.remote_path.clone()),
            size_bytes: Some(i64::try_from(state.data.len()).unwrap_or_default()),
            captured_at: OffsetDateTime::now_utc().format(&Rfc3339)?,
            data: Some(state.data.clone()),
            metadata: Some(metadata_with_context(
                [
                    ("file_id".to_owned(), Value::String(format!("{file_id:08X}"))),
                    ("request_id".to_owned(), Value::String(format!("{:X}", state.request_id))),
                    ("expected_size".to_owned(), Value::String(state.expected_size.to_string())),
                    ("started_at".to_owned(), Value::String(state.started_at.clone())),
                ]
                .into_iter(),
                context,
            )),
        },
    )
    .await
}

pub(super) fn download_progress_event(
    agent_id: u32,
    command_id: u32,
    request_id: u32,
    file_id: u32,
    remote_path: &str,
    current_size: u64,
    expected_size: u64,
    state: &str,
) -> Result<red_cell_common::operator::OperatorMessage, CommandDispatchError> {
    let message = format!(
        "{state} download of file: {remote_path} [{}/{}]",
        byte_count(current_size),
        byte_count(expected_size)
    );
    agent_response_event_with_extra(
        agent_id,
        command_id,
        request_id,
        "Info",
        &message,
        BTreeMap::from([
            ("MiscType".to_owned(), Value::String("download-progress".to_owned())),
            ("FileID".to_owned(), Value::String(format!("{file_id:08X}"))),
            ("FileName".to_owned(), Value::String(remote_path.to_owned())),
            ("CurrentSize".to_owned(), Value::String(current_size.to_string())),
            ("ExpectedSize".to_owned(), Value::String(expected_size.to_string())),
            ("State".to_owned(), Value::String(state.to_owned())),
        ]),
        String::new(),
    )
}

pub(super) fn download_complete_event(
    agent_id: u32,
    command_id: u32,
    request_id: u32,
    file_id: u32,
    state: &DownloadState,
) -> Result<red_cell_common::operator::OperatorMessage, CommandDispatchError> {
    agent_response_event_with_extra(
        agent_id,
        command_id,
        request_id,
        "Good",
        &format!("Finished download of file: {}", state.remote_path),
        BTreeMap::from([
            ("MiscType".to_owned(), Value::String("download".to_owned())),
            ("FileID".to_owned(), Value::String(format!("{file_id:08X}"))),
            ("FileName".to_owned(), Value::String(state.remote_path.clone())),
            ("MiscData".to_owned(), Value::String(BASE64_STANDARD.encode(&state.data))),
            (
                "MiscData2".to_owned(),
                Value::String(format!(
                    "{};{}",
                    BASE64_STANDARD.encode(state.remote_path.as_bytes()),
                    byte_count(state.data.len() as u64)
                )),
            ),
        ]),
        String::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentRegistry, Database, EventBus};
    use red_cell_common::demon::{DemonCommand, DemonFilesystemCommand};
    use red_cell_common::operator::OperatorMessage;
    use tokio::time::{Duration, timeout};

    const CMD_ID: u32 = 0x1234;

    // --- Dir callback test helpers ---

    /// Encode a UTF-16 LE string with a LE u32 length prefix (matching CallbackParser::read_utf16).
    fn add_utf16_le(buf: &mut Vec<u8>, value: &str) {
        let mut encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
        encoded.extend_from_slice(&[0, 0]); // null terminator
        buf.extend_from_slice(&u32::try_from(encoded.len()).unwrap().to_le_bytes());
        buf.extend_from_slice(&encoded);
    }

    fn add_u32_le(buf: &mut Vec<u8>, value: u32) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn add_u64_le(buf: &mut Vec<u8>, value: u64) {
        buf.extend_from_slice(&value.to_le_bytes());
    }

    fn add_bool_le(buf: &mut Vec<u8>, value: bool) {
        add_u32_le(buf, u32::from(value));
    }

    /// Build a Dir subcommand payload for `handle_filesystem_callback`.
    ///
    /// Each `DirEntry` contains the directory-level info plus its items.
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

    async fn dir_test_deps() -> (AgentRegistry, Database, EventBus, DownloadTracker) {
        let db = Database::connect_in_memory().await.expect("in-memory db");
        let registry = AgentRegistry::new(db.clone());
        let events = EventBus::default();
        let downloads = DownloadTracker::new(1024 * 1024);
        (registry, db, events, downloads)
    }

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
        assert!(
            msg.info.extra.get("MiscType").is_none(),
            "non-explorer Dir should not set MiscType"
        );
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

    // parse_file_open_header tests

    #[test]
    fn parse_file_open_header_happy_path() {
        // file_id = 7 (BE), size = 1024 (BE), path = "C:\flag.txt"
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&7u32.to_be_bytes());
        bytes.extend_from_slice(&1024u32.to_be_bytes());
        bytes.extend_from_slice(b"C:\\flag.txt");

        let (file_id, size, path) = parse_file_open_header(CMD_ID, &bytes).unwrap();
        assert_eq!(file_id, 7);
        assert_eq!(size, 1024);
        assert_eq!(path, "C:\\flag.txt");
    }

    #[test]
    fn parse_file_open_header_strips_null_terminator() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(b"path\0");

        let (_, _, path) = parse_file_open_header(CMD_ID, &bytes).unwrap();
        assert_eq!(path, "path");
    }

    #[test]
    fn parse_file_open_header_empty_path() {
        // Exactly 8 bytes — no path bytes at all
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&42u32.to_be_bytes());
        bytes.extend_from_slice(&99u32.to_be_bytes());

        let (file_id, size, path) = parse_file_open_header(CMD_ID, &bytes).unwrap();
        assert_eq!(file_id, 42);
        assert_eq!(size, 99);
        assert_eq!(path, "");
    }

    #[test]
    fn parse_file_open_header_too_short_returns_error() {
        let bytes = [0u8; 7];
        let err = parse_file_open_header(CMD_ID, &bytes).unwrap_err();
        assert!(
            matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
            "expected InvalidCallbackPayload, got {err:?}"
        );
    }

    #[test]
    fn parse_file_open_header_empty_slice_returns_error() {
        let err = parse_file_open_header(CMD_ID, &[]).unwrap_err();
        assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }));
    }

    // parse_file_chunk tests

    #[test]
    fn parse_file_chunk_happy_path() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&5u32.to_be_bytes());
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let (file_id, chunk) = parse_file_chunk(CMD_ID, &bytes).unwrap();
        assert_eq!(file_id, 5);
        assert_eq!(chunk, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn parse_file_chunk_empty_chunk_data() {
        // Exactly 4 bytes — file_id only, empty chunk
        let bytes = 3u32.to_be_bytes();
        let (file_id, chunk) = parse_file_chunk(CMD_ID, &bytes).unwrap();
        assert_eq!(file_id, 3);
        assert!(chunk.is_empty());
    }

    #[test]
    fn parse_file_chunk_too_short_returns_error() {
        let bytes = [0u8; 3];
        let err = parse_file_chunk(CMD_ID, &bytes).unwrap_err();
        assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }));
    }

    #[test]
    fn parse_file_chunk_empty_slice_returns_error() {
        let err = parse_file_chunk(CMD_ID, &[]).unwrap_err();
        assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }));
    }

    // parse_file_close tests

    #[test]
    fn parse_file_close_happy_path() {
        let bytes = 0xDEAD_u32.to_be_bytes();
        let file_id = parse_file_close(CMD_ID, &bytes).unwrap();
        assert_eq!(file_id, 0xDEAD);
    }

    #[test]
    fn parse_file_close_extra_bytes_ignored() {
        // More than 4 bytes is fine — only first 4 matter
        let mut bytes = 0x0000_0001u32.to_be_bytes().to_vec();
        bytes.extend_from_slice(&[0xFF, 0xFF]);
        let file_id = parse_file_close(CMD_ID, &bytes).unwrap();
        assert_eq!(file_id, 1);
    }

    #[test]
    fn parse_file_close_too_short_returns_error() {
        let bytes = [0u8; 3];
        let err = parse_file_close(CMD_ID, &bytes).unwrap_err();
        assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }));
    }

    #[test]
    fn parse_file_close_empty_slice_returns_error() {
        let err = parse_file_close(CMD_ID, &[]).unwrap_err();
        assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }));
    }

    // DownloadTracker out-of-order state machine tests

    use super::{DownloadState, DownloadTracker};

    fn sample_download_state() -> DownloadState {
        DownloadState {
            request_id: 1,
            remote_path: "C:\\loot\\flag.txt".to_owned(),
            expected_size: 1024,
            data: Vec::new(),
            started_at: "2026-03-17T00:00:00Z".to_owned(),
        }
    }

    #[tokio::test]
    async fn append_without_start_returns_error() {
        let tracker = DownloadTracker::new(1024 * 1024);
        let agent_id = 0xAAAA_BBBB;
        let file_id = 42;

        let err = tracker.append(agent_id, file_id, b"chunk data").await.unwrap_err();
        assert!(
            matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
            "expected InvalidCallbackPayload for append without start, got {err:?}"
        );
    }

    #[tokio::test]
    async fn finish_without_start_returns_none() {
        let tracker = DownloadTracker::new(1024 * 1024);
        let agent_id = 0xAAAA_BBBB;
        let file_id = 42;

        let result = tracker.finish(agent_id, file_id).await;
        assert!(result.is_none(), "finish without start should return None");
    }

    #[tokio::test]
    async fn finish_after_start_returns_state() {
        let tracker = DownloadTracker::new(1024 * 1024);
        let agent_id = 0x1234_5678;
        let file_id = 7;
        let state = sample_download_state();

        tracker.start(agent_id, file_id, state.clone()).await;
        let finished = tracker.finish(agent_id, file_id).await;
        assert_eq!(finished, Some(state));
    }

    #[tokio::test]
    async fn double_finish_returns_none_on_second_call() {
        let tracker = DownloadTracker::new(1024 * 1024);
        let agent_id = 0x1234_5678;
        let file_id = 7;

        tracker.start(agent_id, file_id, sample_download_state()).await;
        let first = tracker.finish(agent_id, file_id).await;
        assert!(first.is_some());

        let second = tracker.finish(agent_id, file_id).await;
        assert!(second.is_none(), "second finish should return None after state was consumed");
    }

    #[tokio::test]
    async fn append_after_finish_returns_error() {
        let tracker = DownloadTracker::new(1024 * 1024);
        let agent_id = 0x1234_5678;
        let file_id = 7;

        tracker.start(agent_id, file_id, sample_download_state()).await;
        let _ = tracker.finish(agent_id, file_id).await;

        let err = tracker.append(agent_id, file_id, b"late chunk").await.unwrap_err();
        assert!(
            matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
            "append after finish should fail, got {err:?}"
        );
    }

    #[tokio::test]
    async fn finish_wrong_agent_returns_none() {
        let tracker = DownloadTracker::new(1024 * 1024);
        let agent_id = 0x1111_1111;
        let wrong_agent = 0x2222_2222;
        let file_id = 1;

        tracker.start(agent_id, file_id, sample_download_state()).await;
        let result = tracker.finish(wrong_agent, file_id).await;
        assert!(result.is_none(), "finish with wrong agent_id should return None");
    }

    #[tokio::test]
    async fn finish_wrong_file_id_returns_none() {
        let tracker = DownloadTracker::new(1024 * 1024);
        let agent_id = 0x1111_1111;
        let file_id = 1;
        let wrong_file_id = 99;

        tracker.start(agent_id, file_id, sample_download_state()).await;
        let result = tracker.finish(agent_id, wrong_file_id).await;
        assert!(result.is_none(), "finish with wrong file_id should return None");
    }

    #[tokio::test]
    async fn buffered_bytes_cleared_after_finish_without_start() {
        let tracker = DownloadTracker::new(1024 * 1024);
        // Calling finish on non-existent download should not affect buffered bytes.
        let _ = tracker.finish(0xDEAD, 0xBEEF).await;
        assert_eq!(tracker.buffered_bytes().await, 0);
    }
}
