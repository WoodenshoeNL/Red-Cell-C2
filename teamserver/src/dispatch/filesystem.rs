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
                        u64::try_from(state.data.len()).unwrap_or_default(),
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
                                u64::try_from(state.data.len()).unwrap_or_default(),
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
                    byte_count(u64::try_from(state.data.len()).unwrap_or_default())
                )),
            ),
        ]),
        String::new(),
    )
}
