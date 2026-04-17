//! Download subcommand handler for `CommandFs` callbacks.
//!
//! Handles the `open → write → close` state machine for binary downloads
//! streamed from a Demon agent, along with the payload parsers, the loot
//! persistence, and the operator-facing progress/complete events.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell_common::demon::DemonCommand;
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::warn;

use crate::{
    AgentRegistry, AuditResultStatus, Database, EventBus, LootRecord, PluginRuntime, audit_details,
    parameter_object, record_operator_action,
};

use super::super::transfer::byte_count;
use super::super::{
    CallbackParser, CommandDispatchError, DownloadState, DownloadTracker, LootContext,
    agent_response_event, agent_response_event_with_extra, insert_loot_record, loot_context,
    loot_new_event, metadata_with_context,
};

pub(super) async fn handle_download(
    registry: &AgentRegistry,
    database: &Database,
    events: &EventBus,
    downloads: &DownloadTracker,
    plugins: Option<&PluginRuntime>,
    agent_id: u32,
    request_id: u32,
    parser: &mut CallbackParser<'_>,
) -> Result<(), CommandDispatchError> {
    let context = loot_context(registry, agent_id, request_id).await;
    let mode = parser.read_u32("filesystem download mode")?;
    let file_id = parser.read_u32("filesystem download file id")?;
    match mode {
        0 => {
            let expected_size = parser.read_u64("filesystem download size")?;
            let remote_path = parser.read_utf16("filesystem download path")?;
            let started_at = OffsetDateTime::now_utc().format(&Rfc3339)?;
            match downloads
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
                .await
            {
                Ok(()) => {
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
                Err(
                    ref error @ CommandDispatchError::DownloadConcurrentLimitExceeded {
                        max_concurrent,
                        ..
                    },
                ) => {
                    let msg = format!(
                        "download rejected: concurrent limit exceeded \
                         (file=0x{file_id:08x}, path={remote_path}, limit={max_concurrent})"
                    );
                    warn!(
                        agent_id = format_args!("{agent_id:08X}"),
                        file_id = format_args!("{file_id:08X}"),
                        %remote_path,
                        max_concurrent,
                        "download rejected: per-agent concurrent download limit exceeded"
                    );
                    if let Err(audit_error) = record_operator_action(
                        database,
                        "teamserver",
                        "download.rejected",
                        "agent",
                        Some(format!("{agent_id:08X}")),
                        audit_details(
                            AuditResultStatus::Failure,
                            Some(agent_id),
                            Some("download"),
                            Some(parameter_object([
                                ("limit_type", Value::String("concurrent".to_owned())),
                                ("file_id", Value::String(format!("{file_id:08X}"))),
                                ("file_path", Value::String(remote_path.clone())),
                                ("max_concurrent", Value::Number(max_concurrent.into())),
                                ("error", Value::String(error.to_string())),
                            ])),
                        ),
                    )
                    .await
                    {
                        warn!(
                            agent_id = format_args!("{agent_id:08X}"),
                            %audit_error,
                            "failed to persist download.rejected audit entry"
                        );
                    }
                    events.broadcast(agent_response_event(
                        agent_id,
                        u32::from(DemonCommand::CommandFs),
                        request_id,
                        "Error",
                        &msg,
                        None,
                    )?);
                }
                Err(error) => return Err(error),
            }
        }
        1 => {
            let chunk = parser.read_bytes("filesystem download chunk")?;
            match downloads.append(agent_id, file_id, &chunk).await {
                Ok(state) => {
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
                Err(
                    ref error @ (CommandDispatchError::DownloadTooLarge {
                        max_download_bytes, ..
                    }
                    | CommandDispatchError::DownloadAggregateTooLarge {
                        max_total_download_bytes: max_download_bytes,
                        ..
                    }),
                ) => {
                    let limit_type =
                        if matches!(error, CommandDispatchError::DownloadTooLarge { .. }) {
                            "per_download"
                        } else {
                            "aggregate"
                        };
                    let msg = format!(
                        "download rejected: size limit exceeded \
                         (file=0x{file_id:08x}, limit_type={limit_type}, \
                         max_bytes={max_download_bytes})"
                    );
                    warn!(
                        agent_id = format_args!("{agent_id:08X}"),
                        file_id = format_args!("{file_id:08X}"),
                        limit_type,
                        max_download_bytes,
                        "download rejected: download size limit exceeded"
                    );
                    if let Err(audit_error) = record_operator_action(
                        database,
                        "teamserver",
                        "download.rejected",
                        "agent",
                        Some(format!("{agent_id:08X}")),
                        audit_details(
                            AuditResultStatus::Failure,
                            Some(agent_id),
                            Some("download"),
                            Some(parameter_object([
                                ("limit_type", Value::String(limit_type.to_owned())),
                                ("file_id", Value::String(format!("{file_id:08X}"))),
                                ("max_bytes", Value::Number(max_download_bytes.into())),
                                ("error", Value::String(error.to_string())),
                            ])),
                        ),
                    )
                    .await
                    {
                        warn!(
                            agent_id = format_args!("{agent_id:08X}"),
                            %audit_error,
                            "failed to persist download.rejected audit entry"
                        );
                    }
                    events.broadcast(agent_response_event(
                        agent_id,
                        u32::from(DemonCommand::CommandFs),
                        request_id,
                        "Error",
                        &msg,
                        None,
                    )?);
                }
                Err(error) => return Err(error),
            }
        }
        2 => {
            let reason = parser.read_u32("filesystem download close reason")?;
            if let Some(state) = downloads.finish(agent_id, file_id).await {
                if reason == 0 {
                    let record =
                        persist_download(database, agent_id, file_id, &state, &context).await?;
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
    Ok(())
}

pub(in crate::dispatch) fn parse_file_open_header(
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

pub(in crate::dispatch) fn parse_file_chunk(
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

pub(in crate::dispatch) fn parse_file_close(
    command_id: u32,
    bytes: &[u8],
) -> Result<u32, CommandDispatchError> {
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

pub(in crate::dispatch) async fn persist_download(
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

pub(in crate::dispatch) fn download_progress_event(
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

pub(in crate::dispatch) fn download_complete_event(
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
