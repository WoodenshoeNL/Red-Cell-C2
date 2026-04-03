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

                    let item_count = file_count.checked_add(dir_count).ok_or(
                        CommandDispatchError::InvalidCallbackPayload {
                            command_id: u32::from(DemonCommand::CommandFs),
                            message: format!(
                                "filesystem dir item count overflow: file_count={file_count}, dir_count={dir_count}"
                            ),
                        },
                    )?;
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
                        .await?;
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
            let is_copy = matches!(subcommand, DemonFilesystemCommand::Copy);
            let kind = if success { "Good" } else { "Error" };
            let message = if success {
                let verb = if is_copy { "copied" } else { "moved" };
                format!("Successfully {verb} file {from} to {to}")
            } else {
                let verb = if is_copy { "copy" } else { "move" };
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
            size_bytes: Some(i64::try_from(state.data.len()).unwrap_or(i64::MAX)),
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
    use red_cell_common::demon::DemonFilesystemCommand;
    use red_cell_common::operator::OperatorMessage;
    use red_cell_common::{AgentEncryptionInfo, AgentRecord};
    use tokio::time::{Duration, timeout};
    use zeroize::Zeroizing;

    const CMD_ID: u32 = 0x1234;

    /// Build a minimal agent record for database foreign-key satisfaction.
    fn stub_agent(agent_id: u32) -> AgentRecord {
        AgentRecord {
            agent_id,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: AgentEncryptionInfo {
                aes_key: Zeroizing::new(vec![0; 32]),
                aes_iv: Zeroizing::new(vec![0; 16]),
            },
            hostname: "test".to_owned(),
            username: "user".to_owned(),
            domain_name: "DOMAIN".to_owned(),
            external_ip: "127.0.0.1".to_owned(),
            internal_ip: "127.0.0.1".to_owned(),
            process_name: "test.exe".to_owned(),
            process_path: "C:\\test.exe".to_owned(),
            base_address: 0,
            process_pid: 1,
            process_tid: 1,
            process_ppid: 0,
            process_arch: "x64".to_owned(),
            elevated: false,
            os_version: "Windows 10".to_owned(),
            os_build: 0,
            os_arch: "x64".to_owned(),
            sleep_delay: 5,
            sleep_jitter: 0,
            kill_date: None,
            working_hours: None,
            first_call_in: "2026-01-01T00:00:00Z".to_owned(),
            last_call_in: "2026-01-01T00:00:00Z".to_owned(),
        }
    }

    // --- Dir callback test helpers ---

    /// Encode a UTF-16 LE string with a LE u32 length prefix (matching CallbackParser::read_utf16).
    fn add_utf16_le(buf: &mut Vec<u8>, value: &str) {
        let mut encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
        encoded.extend_from_slice(&[0, 0]); // null terminator
        buf.extend_from_slice(&u32::try_from(encoded.len()).expect("unwrap").to_le_bytes());
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
            !msg.info.extra.contains_key("MiscType"),
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

        let (file_id, size, path) = parse_file_open_header(CMD_ID, &bytes).expect("unwrap");
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

        let (_, _, path) = parse_file_open_header(CMD_ID, &bytes).expect("unwrap");
        assert_eq!(path, "path");
    }

    #[test]
    fn parse_file_open_header_empty_path() {
        // Exactly 8 bytes — no path bytes at all
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&42u32.to_be_bytes());
        bytes.extend_from_slice(&99u32.to_be_bytes());

        let (file_id, size, path) = parse_file_open_header(CMD_ID, &bytes).expect("unwrap");
        assert_eq!(file_id, 42);
        assert_eq!(size, 99);
        assert_eq!(path, "");
    }

    #[test]
    fn parse_file_open_header_too_short_returns_error() {
        let bytes = [0u8; 7];
        let err = parse_file_open_header(CMD_ID, &bytes).expect_err("expected Err");
        assert!(
            matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
            "expected InvalidCallbackPayload, got {err:?}"
        );
    }

    #[test]
    fn parse_file_open_header_empty_slice_returns_error() {
        let err = parse_file_open_header(CMD_ID, &[]).expect_err("expected Err");
        assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }));
    }

    // parse_file_chunk tests

    #[test]
    fn parse_file_chunk_happy_path() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&5u32.to_be_bytes());
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let (file_id, chunk) = parse_file_chunk(CMD_ID, &bytes).expect("unwrap");
        assert_eq!(file_id, 5);
        assert_eq!(chunk, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn parse_file_chunk_empty_chunk_data() {
        // Exactly 4 bytes — file_id only, empty chunk
        let bytes = 3u32.to_be_bytes();
        let (file_id, chunk) = parse_file_chunk(CMD_ID, &bytes).expect("unwrap");
        assert_eq!(file_id, 3);
        assert!(chunk.is_empty());
    }

    #[test]
    fn parse_file_chunk_too_short_returns_error() {
        let bytes = [0u8; 3];
        let err = parse_file_chunk(CMD_ID, &bytes).expect_err("expected Err");
        assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }));
    }

    #[test]
    fn parse_file_chunk_empty_slice_returns_error() {
        let err = parse_file_chunk(CMD_ID, &[]).expect_err("expected Err");
        assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }));
    }

    // parse_file_close tests

    #[test]
    fn parse_file_close_happy_path() {
        let bytes = 0xDEAD_u32.to_be_bytes();
        let file_id = parse_file_close(CMD_ID, &bytes).expect("unwrap");
        assert_eq!(file_id, 0xDEAD);
    }

    #[test]
    fn parse_file_close_extra_bytes_ignored() {
        // More than 4 bytes is fine — only first 4 matter
        let mut bytes = 0x0000_0001u32.to_be_bytes().to_vec();
        bytes.extend_from_slice(&[0xFF, 0xFF]);
        let file_id = parse_file_close(CMD_ID, &bytes).expect("unwrap");
        assert_eq!(file_id, 1);
    }

    #[test]
    fn parse_file_close_too_short_returns_error() {
        let bytes = [0u8; 3];
        let err = parse_file_close(CMD_ID, &bytes).expect_err("expected Err");
        assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }));
    }

    #[test]
    fn parse_file_close_empty_slice_returns_error() {
        let err = parse_file_close(CMD_ID, &[]).expect_err("expected Err");
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

        let err = tracker.append(agent_id, file_id, b"chunk data").await.expect_err("expected Err");
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

        tracker.start(agent_id, file_id, state.clone()).await.expect("start should succeed");
        let finished = tracker.finish(agent_id, file_id).await;
        assert_eq!(finished, Some(state));
    }

    #[tokio::test]
    async fn double_finish_returns_none_on_second_call() {
        let tracker = DownloadTracker::new(1024 * 1024);
        let agent_id = 0x1234_5678;
        let file_id = 7;

        tracker
            .start(agent_id, file_id, sample_download_state())
            .await
            .expect("start should succeed");
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

        tracker
            .start(agent_id, file_id, sample_download_state())
            .await
            .expect("start should succeed");
        let _ = tracker.finish(agent_id, file_id).await;

        let err = tracker.append(agent_id, file_id, b"late chunk").await.expect_err("expected Err");
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

        tracker
            .start(agent_id, file_id, sample_download_state())
            .await
            .expect("start should succeed");
        let result = tracker.finish(wrong_agent, file_id).await;
        assert!(result.is_none(), "finish with wrong agent_id should return None");
    }

    #[tokio::test]
    async fn finish_wrong_file_id_returns_none() {
        let tracker = DownloadTracker::new(1024 * 1024);
        let agent_id = 0x1111_1111;
        let file_id = 1;
        let wrong_file_id = 99;

        tracker
            .start(agent_id, file_id, sample_download_state())
            .await
            .expect("start should succeed");
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

    // --- Download payload helpers (match CallbackParser LE encoding) ---

    fn add_bytes_le(buf: &mut Vec<u8>, value: &[u8]) {
        add_u32_le(buf, u32::try_from(value.len()).expect("test data fits in u32"));
        buf.extend_from_slice(value);
    }

    fn build_download_open_payload(file_id: u32, expected_size: u64, remote_path: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Download));
        add_u32_le(&mut buf, 0); // mode = open
        add_u32_le(&mut buf, file_id);
        add_u64_le(&mut buf, expected_size);
        add_utf16_le(&mut buf, remote_path);
        buf
    }

    fn build_download_write_payload(file_id: u32, chunk: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Download));
        add_u32_le(&mut buf, 1); // mode = write
        add_u32_le(&mut buf, file_id);
        add_bytes_le(&mut buf, chunk);
        buf
    }

    fn build_download_close_payload(file_id: u32, reason: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Download));
        add_u32_le(&mut buf, 2); // mode = close
        add_u32_le(&mut buf, file_id);
        add_u32_le(&mut buf, reason);
        buf
    }

    fn build_download_invalid_mode_payload(file_id: u32, mode: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Download));
        add_u32_le(&mut buf, mode);
        add_u32_le(&mut buf, file_id);
        buf
    }

    // --- Download close-failure and invalid-mode tests ---

    #[tokio::test]
    async fn download_close_nonzero_reason_emits_removed_and_discards_loot() {
        let (registry, db, events, downloads) = dir_test_deps().await;
        let mut rx = events.subscribe();
        let agent_id = 0xFA01;
        let file_id = 0x77;
        let request_id = 0xBB;
        let remote_path = "C:\\Temp\\partial.bin";

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

        // Drain the "Started" event.
        let _ =
            timeout(Duration::from_millis(50), rx.recv()).await.expect("should receive open event");

        // Append one chunk.
        handle_filesystem_callback(
            &registry,
            &db,
            &events,
            &downloads,
            None,
            agent_id,
            request_id,
            &build_download_write_payload(file_id, b"partial-data"),
        )
        .await
        .expect("write should succeed");

        // Drain the "InProgress" event.
        let _ = timeout(Duration::from_millis(50), rx.recv())
            .await
            .expect("should receive progress event");

        // Close with non-zero reason (failure).
        handle_filesystem_callback(
            &registry,
            &db,
            &events,
            &downloads,
            None,
            agent_id,
            request_id,
            &build_download_close_payload(file_id, 1),
        )
        .await
        .expect("close should succeed even with non-zero reason");

        // The close should emit a "Removed" progress event.
        let event = timeout(Duration::from_millis(50), rx.recv())
            .await
            .expect("should receive close event")
            .expect("should have broadcast event");

        let OperatorMessage::AgentResponse(msg) = &event else {
            panic!("expected AgentResponse, got {event:?}");
        };
        assert_eq!(
            msg.info.extra.get("State").and_then(|v| v.as_str()),
            Some("Removed"),
            "failed download close should report State=Removed"
        );

        // No loot should have been persisted.
        let loot = db.loot().list_for_agent(agent_id).await.expect("loot query should work");
        assert!(loot.is_empty(), "failed download should not persist loot");

        // Tracker should be drained — no active downloads for this agent.
        let active = downloads.active_for_agent(agent_id).await;
        assert!(active.is_empty(), "tracker should be drained after failed close");

        // No further events expected.
        assert!(
            timeout(Duration::from_millis(50), rx.recv()).await.is_err(),
            "no extra events should be emitted after failed close"
        );
    }

    #[tokio::test]
    async fn download_unsupported_mode_returns_invalid_callback_payload() {
        let (registry, db, events, downloads) = dir_test_deps().await;
        let mut rx = events.subscribe();
        let agent_id = 0xFA02;
        let request_id = 0xCC;

        let err = handle_filesystem_callback(
            &registry,
            &db,
            &events,
            &downloads,
            None,
            agent_id,
            request_id,
            &build_download_invalid_mode_payload(0x99, 42),
        )
        .await
        .expect_err("unsupported mode should return error");

        assert!(
            matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
            "expected InvalidCallbackPayload, got {err:?}"
        );

        // No events should have been emitted.
        assert!(
            timeout(Duration::from_millis(50), rx.recv()).await.is_err(),
            "no events should be emitted for unsupported download mode"
        );

        // No active downloads left behind.
        let active = downloads.active_for_agent(agent_id).await;
        assert!(active.is_empty(), "no partial state should remain after invalid mode");

        // No loot persisted.
        let loot = db.loot().list_for_agent(agent_id).await.expect("loot query should work");
        assert!(loot.is_empty(), "no loot should be stored for invalid mode");
    }

    // --- Happy-path download: open → chunk → close(reason=0) ---

    #[tokio::test]
    async fn download_happy_path_persists_loot_and_emits_all_events() {
        let (registry, db, events, downloads) = dir_test_deps().await;
        registry.insert(stub_agent(0xFA03)).await.expect("insert agent");
        let mut rx = events.subscribe();
        let agent_id = 0xFA03;
        let file_id = 0x42;
        let request_id = 0xDD;
        let remote_path = "C:\\Users\\admin\\secret.docx";
        let chunk_data = b"hello-world-download-data";
        let expected_size = chunk_data.len() as u64;

        // 1) Open
        handle_filesystem_callback(
            &registry,
            &db,
            &events,
            &downloads,
            None,
            agent_id,
            request_id,
            &build_download_open_payload(file_id, expected_size, remote_path),
        )
        .await
        .expect("open should succeed");

        let event = timeout(Duration::from_millis(50), rx.recv())
            .await
            .expect("should receive Started event")
            .expect("broadcast");
        let OperatorMessage::AgentResponse(msg) = &event else {
            panic!("expected AgentResponse, got {event:?}");
        };
        assert_eq!(msg.info.extra.get("State").and_then(|v| v.as_str()), Some("Started"),);
        assert_eq!(
            msg.info.extra.get("MiscType").and_then(|v| v.as_str()),
            Some("download-progress"),
        );
        assert_eq!(msg.info.extra.get("FileName").and_then(|v| v.as_str()), Some(remote_path),);
        assert_eq!(msg.info.extra.get("CurrentSize").and_then(|v| v.as_str()), Some("0"),);

        // 2) Write chunk
        handle_filesystem_callback(
            &registry,
            &db,
            &events,
            &downloads,
            None,
            agent_id,
            request_id,
            &build_download_write_payload(file_id, chunk_data),
        )
        .await
        .expect("write should succeed");

        let event = timeout(Duration::from_millis(50), rx.recv())
            .await
            .expect("should receive InProgress event")
            .expect("broadcast");
        let OperatorMessage::AgentResponse(msg) = &event else {
            panic!("expected AgentResponse, got {event:?}");
        };
        assert_eq!(msg.info.extra.get("State").and_then(|v| v.as_str()), Some("InProgress"),);
        let current_size_str = chunk_data.len().to_string();
        assert_eq!(
            msg.info.extra.get("CurrentSize").and_then(|v| v.as_str()),
            Some(current_size_str.as_str()),
        );

        // 3) Close with reason=0 (success)
        handle_filesystem_callback(
            &registry,
            &db,
            &events,
            &downloads,
            None,
            agent_id,
            request_id,
            &build_download_close_payload(file_id, 0),
        )
        .await
        .expect("close should succeed");

        // Close emits two events: loot_new_event then download_complete_event
        let loot_event = timeout(Duration::from_millis(50), rx.recv())
            .await
            .expect("should receive loot-new event")
            .expect("broadcast");
        let OperatorMessage::AgentResponse(loot_msg) = &loot_event else {
            panic!("expected AgentResponse for loot, got {loot_event:?}");
        };
        assert_eq!(loot_msg.info.extra.get("MiscType").and_then(|v| v.as_str()), Some("loot-new"),);
        assert_eq!(loot_msg.info.extra.get("LootKind").and_then(|v| v.as_str()), Some("download"),);
        assert_eq!(
            loot_msg.info.extra.get("LootName").and_then(|v| v.as_str()),
            Some("secret.docx"),
        );

        let complete_event = timeout(Duration::from_millis(50), rx.recv())
            .await
            .expect("should receive download-complete event")
            .expect("broadcast");
        let OperatorMessage::AgentResponse(complete_msg) = &complete_event else {
            panic!("expected AgentResponse for completion, got {complete_event:?}");
        };
        assert_eq!(
            complete_msg.info.extra.get("MiscType").and_then(|v| v.as_str()),
            Some("download"),
        );
        // MiscData should be base64 of the file content
        let misc_data_b64 = complete_msg
            .info
            .extra
            .get("MiscData")
            .and_then(|v| v.as_str())
            .expect("MiscData present");
        let decoded = BASE64_STANDARD.decode(misc_data_b64).expect("valid base64");
        assert_eq!(decoded, chunk_data, "MiscData should contain the downloaded file bytes");

        // MiscData2 = base64(remote_path) + ";" + byte_count(size)
        let misc_data2 = complete_msg
            .info
            .extra
            .get("MiscData2")
            .and_then(|v| v.as_str())
            .expect("MiscData2 present");
        let expected_b64_path = BASE64_STANDARD.encode(remote_path.as_bytes());
        assert!(
            misc_data2.starts_with(&expected_b64_path),
            "MiscData2 should start with base64-encoded path"
        );
        assert!(misc_data2.contains(';'), "MiscData2 should contain separator");

        // Verify loot persisted in database
        let loot = db.loot().list_for_agent(agent_id).await.expect("loot query");
        assert_eq!(loot.len(), 1, "exactly one loot record should be persisted");
        let record = &loot[0];
        assert_eq!(record.kind, "download");
        assert_eq!(record.name, "secret.docx");
        assert_eq!(record.file_path.as_deref(), Some(remote_path));
        assert_eq!(record.size_bytes, Some(chunk_data.len() as i64));
        assert_eq!(record.data.as_deref(), Some(chunk_data.as_slice()));
        assert!(record.id.is_some(), "record should have a database ID");

        // Verify metadata fields
        let meta = record.metadata.as_ref().expect("metadata should be present");
        let file_id_hex = format!("{file_id:08X}");
        let request_id_hex = format!("{request_id:X}");
        let expected_size_str = expected_size.to_string();
        assert_eq!(meta.get("file_id").and_then(|v| v.as_str()), Some(file_id_hex.as_str()),);
        assert_eq!(meta.get("request_id").and_then(|v| v.as_str()), Some(request_id_hex.as_str()),);
        assert_eq!(
            meta.get("expected_size").and_then(|v| v.as_str()),
            Some(expected_size_str.as_str()),
        );
        assert!(
            meta.get("started_at").and_then(|v| v.as_str()).is_some(),
            "started_at should be present"
        );

        // Tracker should be drained
        let active = downloads.active_for_agent(agent_id).await;
        assert!(active.is_empty(), "tracker should be drained after successful close");
    }

    // --- Direct unit tests for download_progress_event ---

    #[test]
    fn download_progress_event_produces_correct_structure() {
        let event = download_progress_event(
            0xABCD,
            u32::from(DemonCommand::CommandFs),
            0x10,
            0x77,
            "C:\\data\\report.pdf",
            512,
            2048,
            "InProgress",
        )
        .expect("should build event");

        let OperatorMessage::AgentResponse(msg) = &event else {
            panic!("expected AgentResponse, got {event:?}");
        };

        assert_eq!(
            msg.info.extra.get("MiscType").and_then(|v| v.as_str()),
            Some("download-progress"),
        );
        assert_eq!(msg.info.extra.get("FileID").and_then(|v| v.as_str()), Some("00000077"),);
        assert_eq!(
            msg.info.extra.get("FileName").and_then(|v| v.as_str()),
            Some("C:\\data\\report.pdf"),
        );
        assert_eq!(msg.info.extra.get("CurrentSize").and_then(|v| v.as_str()), Some("512"),);
        assert_eq!(msg.info.extra.get("ExpectedSize").and_then(|v| v.as_str()), Some("2048"),);
        assert_eq!(msg.info.extra.get("State").and_then(|v| v.as_str()), Some("InProgress"),);

        // Message should contain the path and state
        let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(message.contains("report.pdf"), "message should mention file: {message}");
        assert!(message.contains("InProgress"), "message should contain state: {message}");
    }

    #[test]
    fn download_progress_event_started_shows_zero_current() {
        let event = download_progress_event(
            0x01,
            u32::from(DemonCommand::CommandFs),
            0x02,
            0x03,
            "C:\\flag.txt",
            0,
            1024,
            "Started",
        )
        .expect("should build event");

        let OperatorMessage::AgentResponse(msg) = &event else {
            panic!("expected AgentResponse");
        };
        assert_eq!(msg.info.extra.get("State").and_then(|v| v.as_str()), Some("Started"),);
        assert_eq!(msg.info.extra.get("CurrentSize").and_then(|v| v.as_str()), Some("0"),);
    }

    #[test]
    fn download_progress_event_removed_state() {
        let event = download_progress_event(
            0x01,
            u32::from(DemonCommand::CommandFs),
            0x02,
            0x03,
            "C:\\fail.bin",
            100,
            500,
            "Removed",
        )
        .expect("should build event");

        let OperatorMessage::AgentResponse(msg) = &event else {
            panic!("expected AgentResponse");
        };
        assert_eq!(msg.info.extra.get("State").and_then(|v| v.as_str()), Some("Removed"),);
    }

    // --- Direct unit tests for download_complete_event ---

    #[test]
    fn download_complete_event_encodes_data_and_path() {
        let state = DownloadState {
            request_id: 0x10,
            remote_path: "C:\\loot\\secrets.zip".to_owned(),
            expected_size: 4,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            started_at: "2026-03-17T12:00:00Z".to_owned(),
        };

        let event =
            download_complete_event(0xBBBB, u32::from(DemonCommand::CommandFs), 0x10, 0x55, &state)
                .expect("should build event");

        let OperatorMessage::AgentResponse(msg) = &event else {
            panic!("expected AgentResponse, got {event:?}");
        };

        assert_eq!(msg.info.extra.get("MiscType").and_then(|v| v.as_str()), Some("download"),);
        assert_eq!(msg.info.extra.get("FileID").and_then(|v| v.as_str()), Some("00000055"),);
        assert_eq!(
            msg.info.extra.get("FileName").and_then(|v| v.as_str()),
            Some("C:\\loot\\secrets.zip"),
        );

        // MiscData = base64(data)
        let misc_data = msg.info.extra.get("MiscData").and_then(|v| v.as_str()).expect("MiscData");
        let decoded = BASE64_STANDARD.decode(misc_data).expect("valid base64");
        assert_eq!(decoded, &[0xDE, 0xAD, 0xBE, 0xEF]);

        // MiscData2 = base64(path) + ";" + byte_count(size)
        let misc_data2 =
            msg.info.extra.get("MiscData2").and_then(|v| v.as_str()).expect("MiscData2");
        let parts: Vec<&str> = misc_data2.splitn(2, ';').collect();
        assert_eq!(parts.len(), 2, "MiscData2 should have two semicolon-separated parts");
        let decoded_path = BASE64_STANDARD.decode(parts[0]).expect("base64 path");
        assert_eq!(String::from_utf8_lossy(&decoded_path), "C:\\loot\\secrets.zip");
        assert_eq!(parts[1], "4 B", "byte_count(4) should be '4 B'");

        // Kind should be "Good"
        let kind = msg.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(kind, "Good");
    }

    #[test]
    fn download_complete_event_empty_data() {
        let state = DownloadState {
            request_id: 0x01,
            remote_path: "C:\\empty.bin".to_owned(),
            expected_size: 0,
            data: Vec::new(),
            started_at: "2026-03-17T00:00:00Z".to_owned(),
        };

        let event =
            download_complete_event(0x01, u32::from(DemonCommand::CommandFs), 0x01, 0x01, &state)
                .expect("should build event");

        let OperatorMessage::AgentResponse(msg) = &event else {
            panic!("expected AgentResponse");
        };

        let misc_data = msg.info.extra.get("MiscData").and_then(|v| v.as_str()).expect("MiscData");
        let decoded = BASE64_STANDARD.decode(misc_data).expect("valid base64");
        assert!(decoded.is_empty(), "empty download data should decode to empty");
    }

    // --- Direct unit tests for persist_download ---

    #[tokio::test]
    async fn persist_download_extracts_filename_from_windows_path() {
        let db = Database::connect_in_memory().await.expect("in-memory db");
        let registry = AgentRegistry::new(db.clone());
        registry.insert(stub_agent(0xAA)).await.expect("insert agent");
        let state = DownloadState {
            request_id: 0x10,
            remote_path: "C:\\Users\\admin\\Desktop\\flag.txt".to_owned(),
            expected_size: 5,
            data: b"hello".to_vec(),
            started_at: "2026-03-17T12:00:00Z".to_owned(),
        };
        let context = LootContext::default();

        let record = persist_download(&db, 0xAA, 0x42, &state, &context)
            .await
            .expect("persist should succeed");

        assert_eq!(record.name, "flag.txt");
        assert_eq!(record.kind, "download");
        assert_eq!(record.file_path.as_deref(), Some("C:\\Users\\admin\\Desktop\\flag.txt"),);
        assert_eq!(record.size_bytes, Some(5));
        assert_eq!(record.data.as_deref(), Some(b"hello".as_slice()));
        assert!(record.id.is_some(), "should have a database-assigned ID");
    }

    #[tokio::test]
    async fn persist_download_extracts_filename_from_unix_path() {
        let db = Database::connect_in_memory().await.expect("in-memory db");
        let registry = AgentRegistry::new(db.clone());
        registry.insert(stub_agent(0xBB)).await.expect("insert agent");
        let state = DownloadState {
            request_id: 0x20,
            remote_path: "/home/user/docs/report.pdf".to_owned(),
            expected_size: 3,
            data: b"pdf".to_vec(),
            started_at: "2026-03-17T12:00:00Z".to_owned(),
        };
        let context = LootContext::default();

        let record = persist_download(&db, 0xBB, 0x01, &state, &context)
            .await
            .expect("persist should succeed");

        assert_eq!(record.name, "report.pdf");
    }

    #[tokio::test]
    async fn persist_download_bare_filename_no_separators() {
        let db = Database::connect_in_memory().await.expect("in-memory db");
        let registry = AgentRegistry::new(db.clone());
        registry.insert(stub_agent(0xCC)).await.expect("insert agent");
        let state = DownloadState {
            request_id: 0x30,
            remote_path: "standalone.exe".to_owned(),
            expected_size: 2,
            data: b"MZ".to_vec(),
            started_at: "2026-03-17T12:00:00Z".to_owned(),
        };
        let context = LootContext::default();

        let record = persist_download(&db, 0xCC, 0x02, &state, &context)
            .await
            .expect("persist should succeed");

        assert_eq!(record.name, "standalone.exe");
    }

    #[tokio::test]
    async fn persist_download_metadata_includes_file_id_and_timestamps() {
        let db = Database::connect_in_memory().await.expect("in-memory db");
        let registry = AgentRegistry::new(db.clone());
        registry.insert(stub_agent(0xDD)).await.expect("insert agent");
        let state = DownloadState {
            request_id: 0xFF,
            remote_path: "C:\\meta.bin".to_owned(),
            expected_size: 999,
            data: vec![0; 10],
            started_at: "2026-03-17T08:30:00Z".to_owned(),
        };
        let context = LootContext::default();

        let record = persist_download(&db, 0xDD, 0x88, &state, &context)
            .await
            .expect("persist should succeed");

        let meta = record.metadata.as_ref().expect("metadata should be present");
        assert_eq!(meta.get("file_id").and_then(|v| v.as_str()), Some("00000088"),);
        assert_eq!(meta.get("request_id").and_then(|v| v.as_str()), Some("FF"),);
        assert_eq!(meta.get("expected_size").and_then(|v| v.as_str()), Some("999"),);
        assert_eq!(meta.get("started_at").and_then(|v| v.as_str()), Some("2026-03-17T08:30:00Z"),);
    }

    // ---------------------------------------------------------------
    // Payload builders for non-download filesystem subcommands
    // ---------------------------------------------------------------

    fn build_upload_payload(size: u32, path: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        add_u32_le(&mut buf, u32::from(DemonFilesystemCommand::Upload));
        add_u32_le(&mut buf, size);
        add_utf16_le(&mut buf, path);
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

    /// Helper: invoke handle_filesystem_callback and return the first broadcast event.
    async fn call_and_recv(payload: &[u8], agent_id: u32, request_id: u32) -> OperatorMessage {
        let (registry, db, events, downloads) = dir_test_deps().await;
        let mut rx = events.subscribe();
        handle_filesystem_callback(
            &registry, &db, &events, &downloads, None, agent_id, request_id, payload,
        )
        .await
        .expect("handler should succeed");
        timeout(Duration::from_millis(50), rx.recv())
            .await
            .expect("should receive event")
            .expect("broadcast")
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
        let event =
            call_and_recv(&build_remove_payload(false, "C:\\Temp\\old.log"), 0xA3, 30).await;
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
        let event =
            call_and_recv(&build_mkdir_payload("C:\\Users\\admin\\new_dir"), 0xA5, 40).await;
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
        let event = call_and_recv(
            &build_copy_move_payload(true, true, "C:\\src.txt", "C:\\dst.txt"),
            0xA6,
            50,
        )
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
    // Dir normal mode (non-explorer, non-list-only) with items
    // ---------------------------------------------------------------

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

    // ---------------------------------------------------------------
    // Helper: invoke handle_filesystem_callback and expect an error.
    // ---------------------------------------------------------------

    async fn call_and_expect_error(
        payload: &[u8],
        agent_id: u32,
        request_id: u32,
    ) -> CommandDispatchError {
        let (registry, db, events, downloads) = dir_test_deps().await;
        handle_filesystem_callback(
            &registry, &db, &events, &downloads, None, agent_id, request_id, payload,
        )
        .await
        .expect_err("handler should return error for truncated payload")
    }

    // ---------------------------------------------------------------
    // Truncated payload tests — each subcommand with insufficient data
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
    // Edge case tests — empty strings, zero-size values
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

    // ---------------------------------------------------------------
    // Invalid subcommand ID
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn invalid_subcommand_id_returns_error() {
        let mut buf = Vec::new();
        add_u32_le(&mut buf, 0xFFFF); // invalid subcommand
        let err = call_and_expect_error(&buf, 0xFF, 200).await;
        assert!(matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }), "got {err:?}");
    }

    // ---------------------------------------------------------------
    // Completely empty payload (no subcommand at all)
    // ---------------------------------------------------------------

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
    async fn download_exceeding_memory_limit_returns_error() {
        let (registry, db, events, downloads) = small_limit_test_deps(64).await;
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
        let overflow_chunk = vec![0xBB; 48];
        let err = handle_filesystem_callback(
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
        .expect_err("expected Err");
        assert!(
            matches!(err, CommandDispatchError::DownloadTooLarge { .. }),
            "expected DownloadTooLarge, got {err:?}"
        );

        // The download should have been removed after exceeding the limit.
        let finished = downloads.finish(agent_id, file_id).await;
        assert!(finished.is_none(), "download should be removed after limit exceeded");
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
    async fn download_one_byte_over_limit_returns_error() {
        let (registry, db, events, downloads) = small_limit_test_deps(64).await;
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

        // One more byte should fail.
        let err = handle_filesystem_callback(
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
        .expect_err("expected Err");
        assert!(
            matches!(err, CommandDispatchError::DownloadTooLarge { .. }),
            "expected DownloadTooLarge for 1 byte over limit, got {err:?}"
        );
    }

    #[tokio::test]
    async fn download_single_chunk_exceeding_limit_returns_error() {
        let (registry, db, events, downloads) = small_limit_test_deps(16).await;
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

        // A single chunk larger than the limit should fail immediately.
        let huge_chunk = vec![0xFF; 32];
        let err = handle_filesystem_callback(
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
        .expect_err("expected Err");
        assert!(
            matches!(err, CommandDispatchError::DownloadTooLarge { .. }),
            "expected DownloadTooLarge for oversized single chunk, got {err:?}"
        );

        // Download should be removed.
        assert!(downloads.finish(agent_id, file_id).await.is_none());
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

        let err =
            handle_filesystem_callback(&registry, &db, &events, &downloads, None, 0xBB, 1, &buf)
                .await
                .expect_err("should fail on item count overflow");

        assert!(
            matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
            "expected InvalidCallbackPayload, got {err:?}"
        );
    }
}
