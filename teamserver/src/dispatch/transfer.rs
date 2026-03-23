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
                state.data.len() as u64,
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

#[cfg(test)]
mod tests {
    use super::super::{CommandDispatchError, DownloadState, DownloadTracker};
    use super::{
        byte_count, handle_beacon_output_callback, handle_mem_file_callback,
        handle_package_dropped_callback, handle_transfer_callback, transfer_progress_text,
        transfer_state_name,
    };
    use crate::{AgentRegistry, Database, EventBus};
    use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
    use red_cell_common::demon::{DemonCallback, DemonTransferCommand};
    use red_cell_common::operator::OperatorMessage;
    use zeroize::Zeroizing;

    fn le32(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    fn length_prefixed(data: &[u8]) -> Vec<u8> {
        let mut out =
            u32::try_from(data.len()).expect("test data fits in u32").to_le_bytes().to_vec();
        out.extend_from_slice(data);
        out
    }

    // ------------------------------------------------------------------
    // handle_transfer_callback — List subcommand
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn transfer_callback_list_shows_active_download() -> Result<(), Box<dyn std::error::Error>>
    {
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let downloads = DownloadTracker::new(1024 * 1024);
        let agent_id: u32 = 0x1234_5678;
        let file_id: u32 = 0xABCD_EF01;
        let request_id: u32 = 42;

        downloads
            .start(
                agent_id,
                file_id,
                DownloadState {
                    request_id,
                    remote_path: r"C:\loot\secrets.txt".to_owned(),
                    expected_size: 1000,
                    data: Vec::new(),
                    started_at: "2026-03-17T00:00:00Z".to_owned(),
                },
            )
            .await;

        // Payload: List subcommand + file_id + progress(500 of 1000 = 50%) + state(Running=1)
        let mut payload = Vec::new();
        payload.extend_from_slice(&le32(u32::from(DemonTransferCommand::List)));
        payload.extend_from_slice(&le32(file_id));
        payload.extend_from_slice(&le32(500));
        payload.extend_from_slice(&le32(1));

        let result =
            handle_transfer_callback(&events, &downloads, agent_id, request_id, &payload).await?;

        assert_eq!(result, None, "transfer List handler must not produce a reply packet");

        let event = receiver.recv().await.ok_or("expected AgentResponse event after List")?;
        let OperatorMessage::AgentResponse(message) = event else {
            return Err("expected AgentResponse event".into());
        };
        assert!(
            message.info.output.contains("secrets.txt"),
            "List output should contain the file name; got: {}",
            message.info.output
        );
        assert!(
            message.info.output.contains("50.00%"),
            "List output should show 50.00%% progress; got: {}",
            message.info.output
        );
        Ok(())
    }

    // ------------------------------------------------------------------
    // handle_transfer_callback — truncated payload
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn transfer_callback_truncated_returns_error() {
        let events = EventBus::default();
        let downloads = DownloadTracker::new(1024 * 1024);

        let result = handle_transfer_callback(&events, &downloads, 0x1111_1111, 1, &[]).await;

        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "empty payload must yield InvalidCallbackPayload; got: {result:?}"
        );
    }

    // ------------------------------------------------------------------
    // Helper: build Stop/Resume/Remove payload
    // ------------------------------------------------------------------

    /// Build a transfer callback payload for Stop, Resume, or Remove subcommands.
    /// `found` maps to the agent-side "file id was located" bool, while `file_id`
    /// identifies the download entry.
    fn stop_resume_remove_payload(
        subcommand: DemonTransferCommand,
        found: bool,
        file_id: u32,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&le32(u32::from(subcommand)));
        payload.extend_from_slice(&le32(u32::from(found)));
        payload.extend_from_slice(&le32(file_id));
        payload
    }

    /// Extract (kind, message) from an `AgentResponse` event's extra map.
    fn extract_kind_message(event: &OperatorMessage) -> (&str, &str) {
        let OperatorMessage::AgentResponse(msg) = event else {
            panic!("expected AgentResponse; got: {event:?}");
        };
        let kind = msg.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
        let message = msg.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
        (kind, message)
    }

    /// Seed a DownloadTracker with one active download for the given agent/file pair.
    async fn seed_download(downloads: &DownloadTracker, agent_id: u32, file_id: u32) {
        downloads
            .start(
                agent_id,
                file_id,
                DownloadState {
                    request_id: 1,
                    remote_path: r"C:\test\file.bin".to_owned(),
                    expected_size: 4096,
                    data: Vec::new(),
                    started_at: "2026-03-17T00:00:00Z".to_owned(),
                },
            )
            .await;
    }

    // ------------------------------------------------------------------
    // handle_transfer_callback — Stop subcommand
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn transfer_stop_found_and_exists() -> Result<(), Box<dyn std::error::Error>> {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let downloads = DownloadTracker::new(1024 * 1024);
        let agent_id: u32 = 0xAA00_0001;
        let file_id: u32 = 0x0000_0010;

        seed_download(&downloads, agent_id, file_id).await;
        let payload = stop_resume_remove_payload(DemonTransferCommand::Stop, true, file_id);

        let result = handle_transfer_callback(&events, &downloads, agent_id, 1, &payload).await?;
        assert_eq!(result, None);

        let event = rx.recv().await.ok_or("no event")?;
        let (kind, message) = extract_kind_message(&event);
        assert_eq!(kind, "Good");
        assert!(message.contains("stopped"), "expected 'stopped'; got: {message}");
        assert!(message.contains(&format!("{file_id:x}")));

        // Stop must NOT clear the tracked download.
        assert!(
            !downloads.active_for_agent(agent_id).await.is_empty(),
            "Stop success path must not clear the tracked download"
        );
        Ok(())
    }

    #[tokio::test]
    async fn transfer_stop_found_but_not_exists() -> Result<(), Box<dyn std::error::Error>> {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let downloads = DownloadTracker::new(1024 * 1024);
        let agent_id: u32 = 0xAA00_0002;
        let file_id: u32 = 0x0000_0020;

        // No download seeded — found=true but exists=false
        let payload = stop_resume_remove_payload(DemonTransferCommand::Stop, true, file_id);

        let result = handle_transfer_callback(&events, &downloads, agent_id, 1, &payload).await?;
        assert_eq!(result, None);

        let event = rx.recv().await.ok_or("no event")?;
        let (kind, message) = extract_kind_message(&event);
        assert_eq!(kind, "Error");
        assert!(message.contains("does not exist"), "expected 'does not exist'; got: {message}");
        Ok(())
    }

    #[tokio::test]
    async fn transfer_stop_not_found() -> Result<(), Box<dyn std::error::Error>> {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let downloads = DownloadTracker::new(1024 * 1024);
        let agent_id: u32 = 0xAA00_0003;
        let file_id: u32 = 0x0000_0030;

        let payload = stop_resume_remove_payload(DemonTransferCommand::Stop, false, file_id);

        let result = handle_transfer_callback(&events, &downloads, agent_id, 1, &payload).await?;
        assert_eq!(result, None);

        let event = rx.recv().await.ok_or("no event")?;
        let (kind, message) = extract_kind_message(&event);
        assert_eq!(kind, "Error");
        assert!(message.contains("not found"), "expected 'not found'; got: {message}");
        Ok(())
    }

    // ------------------------------------------------------------------
    // handle_transfer_callback — Resume subcommand
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn transfer_resume_found_and_exists() -> Result<(), Box<dyn std::error::Error>> {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let downloads = DownloadTracker::new(1024 * 1024);
        let agent_id: u32 = 0xBB00_0001;
        let file_id: u32 = 0x0000_0040;

        seed_download(&downloads, agent_id, file_id).await;
        let payload = stop_resume_remove_payload(DemonTransferCommand::Resume, true, file_id);

        let result = handle_transfer_callback(&events, &downloads, agent_id, 1, &payload).await?;
        assert_eq!(result, None);

        let event = rx.recv().await.ok_or("no event")?;
        let (kind, message) = extract_kind_message(&event);
        assert_eq!(kind, "Good");
        assert!(message.contains("resumed"), "expected 'resumed'; got: {message}");
        assert!(message.contains(&format!("{file_id:x}")));

        // Resume must NOT clear the tracked download.
        assert!(
            !downloads.active_for_agent(agent_id).await.is_empty(),
            "Resume success path must not clear the tracked download"
        );
        Ok(())
    }

    #[tokio::test]
    async fn transfer_resume_found_but_not_exists() -> Result<(), Box<dyn std::error::Error>> {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let downloads = DownloadTracker::new(1024 * 1024);
        let agent_id: u32 = 0xBB00_0002;
        let file_id: u32 = 0x0000_0050;

        let payload = stop_resume_remove_payload(DemonTransferCommand::Resume, true, file_id);

        let result = handle_transfer_callback(&events, &downloads, agent_id, 1, &payload).await?;
        assert_eq!(result, None);

        let event = rx.recv().await.ok_or("no event")?;
        let (kind, message) = extract_kind_message(&event);
        assert_eq!(kind, "Error");
        assert!(message.contains("does not exist"), "expected 'does not exist'; got: {message}");
        Ok(())
    }

    #[tokio::test]
    async fn transfer_resume_not_found() -> Result<(), Box<dyn std::error::Error>> {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let downloads = DownloadTracker::new(1024 * 1024);
        let agent_id: u32 = 0xBB00_0003;
        let file_id: u32 = 0x0000_0060;

        let payload = stop_resume_remove_payload(DemonTransferCommand::Resume, false, file_id);

        let result = handle_transfer_callback(&events, &downloads, agent_id, 1, &payload).await?;
        assert_eq!(result, None);

        let event = rx.recv().await.ok_or("no event")?;
        let (kind, message) = extract_kind_message(&event);
        assert_eq!(kind, "Error");
        assert!(message.contains("not found"), "expected 'not found'; got: {message}");
        Ok(())
    }

    // ------------------------------------------------------------------
    // handle_transfer_callback — Remove subcommand
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn transfer_remove_found_and_exists_clears_download()
    -> Result<(), Box<dyn std::error::Error>> {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let downloads = DownloadTracker::new(1024 * 1024);
        let agent_id: u32 = 0xCC00_0001;
        let file_id: u32 = 0x0000_0070;

        seed_download(&downloads, agent_id, file_id).await;
        assert!(
            !downloads.active_for_agent(agent_id).await.is_empty(),
            "precondition: download should be tracked before Remove"
        );

        let payload = stop_resume_remove_payload(DemonTransferCommand::Remove, true, file_id);

        let result = handle_transfer_callback(&events, &downloads, agent_id, 1, &payload).await?;
        assert_eq!(result, None);

        let event = rx.recv().await.ok_or("no event")?;
        let (kind, message) = extract_kind_message(&event);
        assert_eq!(kind, "Good");
        assert!(message.contains("removed"), "expected 'removed'; got: {message}");
        assert!(message.contains(&format!("{file_id:x}")));

        // The download must have been cleaned up via downloads.finish().
        assert!(
            downloads.active_for_agent(agent_id).await.is_empty(),
            "Remove success path must clear the tracked download"
        );
        Ok(())
    }

    #[tokio::test]
    async fn transfer_remove_found_but_not_exists() -> Result<(), Box<dyn std::error::Error>> {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let downloads = DownloadTracker::new(1024 * 1024);
        let agent_id: u32 = 0xCC00_0002;
        let file_id: u32 = 0x0000_0080;

        let payload = stop_resume_remove_payload(DemonTransferCommand::Remove, true, file_id);

        let result = handle_transfer_callback(&events, &downloads, agent_id, 1, &payload).await?;
        assert_eq!(result, None);

        let event = rx.recv().await.ok_or("no event")?;
        let (kind, message) = extract_kind_message(&event);
        assert_eq!(kind, "Error");
        assert!(message.contains("does not exist"), "expected 'does not exist'; got: {message}");
        Ok(())
    }

    #[tokio::test]
    async fn transfer_remove_not_found() -> Result<(), Box<dyn std::error::Error>> {
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let downloads = DownloadTracker::new(1024 * 1024);
        let agent_id: u32 = 0xCC00_0003;
        let file_id: u32 = 0x0000_0090;

        // Seed a download to verify it is NOT removed on the error path.
        seed_download(&downloads, agent_id, file_id).await;

        let payload = stop_resume_remove_payload(DemonTransferCommand::Remove, false, file_id);

        let result = handle_transfer_callback(&events, &downloads, agent_id, 1, &payload).await?;
        assert_eq!(result, None);

        let event = rx.recv().await.ok_or("no event")?;
        let (kind, message) = extract_kind_message(&event);
        assert_eq!(kind, "Error");
        assert!(message.contains("not found"), "expected 'not found'; got: {message}");

        // Download must still be tracked — error path must not mutate state.
        assert!(
            !downloads.active_for_agent(agent_id).await.is_empty(),
            "Remove error path must not clear the tracked download"
        );
        Ok(())
    }

    // ------------------------------------------------------------------
    // handle_mem_file_callback — valid payload
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn mem_file_callback_broadcasts_response_event() -> Result<(), Box<dyn std::error::Error>>
    {
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let agent_id: u32 = 0xDEAD_BEEF;
        let request_id: u32 = 7;

        // Payload: mem_file_id(0x99) + success(1 = true)
        let mut payload = Vec::new();
        payload.extend_from_slice(&le32(0x0000_0099));
        payload.extend_from_slice(&le32(1));

        let result = handle_mem_file_callback(&events, agent_id, request_id, &payload).await?;

        assert_eq!(result, None, "mem-file handler must not produce a reply packet");

        let event =
            receiver.recv().await.ok_or("expected AgentResponse event after mem-file callback")?;
        let OperatorMessage::AgentResponse(message) = event else {
            return Err("expected AgentResponse event".into());
        };
        let kind = message.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(kind, "Good", "success=true must produce Type=\"Good\"; got: {kind}");
        let msg_text = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            msg_text.contains("registered successfully"),
            "success=true message must contain \"registered successfully\"; got: {msg_text}"
        );
        Ok(())
    }

    // ------------------------------------------------------------------
    // handle_mem_file_callback — success=false (failure path)
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn mem_file_callback_failure_broadcasts_error_event()
    -> Result<(), Box<dyn std::error::Error>> {
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let agent_id: u32 = 0xDEAD_BEEF;
        let request_id: u32 = 8;

        // Payload: mem_file_id(0x42) + success(0 = false)
        let mut payload = Vec::new();
        payload.extend_from_slice(&le32(0x0000_0042));
        payload.extend_from_slice(&le32(0));

        let result = handle_mem_file_callback(&events, agent_id, request_id, &payload).await?;

        assert_eq!(result, None, "mem-file handler must not produce a reply packet");

        let event = receiver
            .recv()
            .await
            .ok_or("expected AgentResponse event after mem-file failure callback")?;
        let OperatorMessage::AgentResponse(message) = event else {
            return Err("expected AgentResponse event".into());
        };
        let kind = message.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(kind, "Error", "success=false must produce Type=\"Error\"; got: {kind}");
        let msg_text = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            msg_text.contains("failed to register"),
            "success=false message must contain \"failed to register\"; got: {msg_text}"
        );
        Ok(())
    }

    // ------------------------------------------------------------------
    // handle_package_dropped_callback — valid payload
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn package_dropped_callback_broadcasts_error_event()
    -> Result<(), Box<dyn std::error::Error>> {
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let agent_id: u32 = 0xAAAA_BBBB;
        let request_id: u32 = 3;

        // Payload: package_length(8192) + max_length(4096)
        let mut payload = Vec::new();
        payload.extend_from_slice(&le32(8192));
        payload.extend_from_slice(&le32(4096));

        let result =
            handle_package_dropped_callback(&events, agent_id, request_id, &payload).await?;

        assert_eq!(result, None, "package-dropped handler must not produce a reply packet");

        let event = receiver
            .recv()
            .await
            .ok_or("expected AgentResponse event after package-dropped callback")?;
        let OperatorMessage::AgentResponse(message) = event else {
            return Err("expected AgentResponse event".into());
        };
        let msg_text = message.info.extra.get("Message").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            msg_text.contains("8192") && msg_text.contains("4096"),
            "error message should reference both sizes; got: {msg_text}"
        );
        Ok(())
    }

    // ------------------------------------------------------------------
    // handle_beacon_output_callback — credential line triggers persistence
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn beacon_output_callback_persists_credential_loot()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let downloads = DownloadTracker::new(1024 * 1024);
        let agent_id: u32 = 0xCAFE_BABE;
        let request_id: u32 = 99;

        // Register the agent so agent_responses FK constraint is satisfied.
        let key = [0x11_u8; AGENT_KEY_LENGTH];
        let iv = [0x22_u8; AGENT_IV_LENGTH];
        registry
            .insert(red_cell_common::AgentRecord {
                agent_id,
                active: true,
                reason: String::new(),
                note: String::new(),
                encryption: red_cell_common::AgentEncryptionInfo {
                    aes_key: Zeroizing::new(key.to_vec()),
                    aes_iv: Zeroizing::new(iv.to_vec()),
                },
                hostname: "test-host".to_owned(),
                username: "test-user".to_owned(),
                domain_name: "test".to_owned(),
                external_ip: "1.2.3.4".to_owned(),
                internal_ip: "10.0.0.1".to_owned(),
                process_name: "cmd.exe".to_owned(),
                process_path: "C:\\cmd.exe".to_owned(),
                base_address: 0x1000,
                process_pid: 100,
                process_tid: 101,
                process_ppid: 4,
                process_arch: "x64".to_owned(),
                elevated: false,
                os_version: "Windows 10".to_owned(),
                os_build: 19045,
                os_arch: "x64".to_owned(),
                sleep_delay: 5,
                sleep_jitter: 0,
                kill_date: None,
                working_hours: None,
                first_call_in: "2026-03-17T00:00:00Z".to_owned(),
                last_call_in: "2026-03-17T00:00:00Z".to_owned(),
            })
            .await?;

        // Output text containing a recognisable credential line.
        let output_text = "password: secret123";
        let mut payload = Vec::new();
        payload.extend_from_slice(&le32(u32::from(DemonCallback::Output)));
        payload.extend_from_slice(&length_prefixed(output_text.as_bytes()));

        let result = handle_beacon_output_callback(
            &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
        )
        .await?;

        assert_eq!(result, None, "beacon-output handler must not produce a reply packet");

        // First event: AgentResponse carrying the captured output.
        let first_event = receiver.recv().await.ok_or("expected AgentResponse event for output")?;
        assert!(
            matches!(first_event, OperatorMessage::AgentResponse(_)),
            "first event should be AgentResponse; got: {first_event:?}"
        );

        // The credential line must have been persisted as a loot record.
        let loot_records = database.loot().list_for_agent(agent_id).await?;
        assert!(
            loot_records.iter().any(|r| r.kind == "credential"),
            "expected at least one 'credential' loot record; got: {loot_records:?}"
        );
        Ok(())
    }

    // ------------------------------------------------------------------
    // Helper: register a minimal agent in the database so FK constraints pass
    // ------------------------------------------------------------------

    async fn register_test_agent(
        registry: &AgentRegistry,
        agent_id: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let key = [0x11_u8; AGENT_KEY_LENGTH];
        let iv = [0x22_u8; AGENT_IV_LENGTH];
        registry
            .insert(red_cell_common::AgentRecord {
                agent_id,
                active: true,
                reason: String::new(),
                note: String::new(),
                encryption: red_cell_common::AgentEncryptionInfo {
                    aes_key: Zeroizing::new(key.to_vec()),
                    aes_iv: Zeroizing::new(iv.to_vec()),
                },
                hostname: "test-host".to_owned(),
                username: "test-user".to_owned(),
                domain_name: "test".to_owned(),
                external_ip: "1.2.3.4".to_owned(),
                internal_ip: "10.0.0.1".to_owned(),
                process_name: "cmd.exe".to_owned(),
                process_path: "C:\\cmd.exe".to_owned(),
                base_address: 0x1000,
                process_pid: 100,
                process_tid: 101,
                process_ppid: 4,
                process_arch: "x64".to_owned(),
                elevated: false,
                os_version: "Windows 10".to_owned(),
                os_build: 19045,
                os_arch: "x64".to_owned(),
                sleep_delay: 5,
                sleep_jitter: 0,
                kill_date: None,
                working_hours: None,
                first_call_in: "2026-03-17T00:00:00Z".to_owned(),
                last_call_in: "2026-03-17T00:00:00Z".to_owned(),
            })
            .await?;
        Ok(())
    }

    /// Encode a Rust string as UTF-16LE bytes.
    fn utf16le_bytes(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
    }

    // ------------------------------------------------------------------
    // handle_beacon_output_callback — OutputUtf8 variant
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn beacon_output_utf8_broadcasts_and_persists() -> Result<(), Box<dyn std::error::Error>>
    {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let downloads = DownloadTracker::new(1024 * 1024);
        let agent_id: u32 = 0xDA01_0001;
        let request_id: u32 = 200;

        register_test_agent(&registry, agent_id).await?;

        let output_text = "hello from utf-16";
        let utf16_data = utf16le_bytes(output_text);
        let mut payload = Vec::new();
        payload.extend_from_slice(&le32(u32::from(DemonCallback::OutputUtf8)));
        payload.extend_from_slice(&length_prefixed(&utf16_data));

        let result = handle_beacon_output_callback(
            &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
        )
        .await?;

        assert_eq!(result, None);

        let event = receiver.recv().await.ok_or("expected AgentResponse event")?;
        let OperatorMessage::AgentResponse(msg) = event else {
            return Err("expected AgentResponse".into());
        };
        assert!(
            msg.info.output.contains("hello from utf-16"),
            "output should contain decoded UTF-16 text; got: {}",
            msg.info.output
        );

        // Verify agent_response was persisted.
        let responses = database.agent_responses().list_for_agent(agent_id).await?;
        assert!(!responses.is_empty(), "OutputUtf8 must persist an agent_response record");
        Ok(())
    }

    // ------------------------------------------------------------------
    // handle_beacon_output_callback — OutputOem variant
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn beacon_output_oem_broadcasts_and_persists() -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let downloads = DownloadTracker::new(1024 * 1024);
        let agent_id: u32 = 0xDA02_0001;
        let request_id: u32 = 201;

        register_test_agent(&registry, agent_id).await?;

        let output_text = "OEM encoded text";
        let utf16_data = utf16le_bytes(output_text);
        let mut payload = Vec::new();
        payload.extend_from_slice(&le32(u32::from(DemonCallback::OutputOem)));
        payload.extend_from_slice(&length_prefixed(&utf16_data));

        let result = handle_beacon_output_callback(
            &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
        )
        .await?;

        assert_eq!(result, None);

        let event = receiver.recv().await.ok_or("expected AgentResponse event")?;
        let OperatorMessage::AgentResponse(msg) = event else {
            return Err("expected AgentResponse".into());
        };
        assert!(
            msg.info.output.contains("OEM encoded text"),
            "output should contain decoded OEM/UTF-16 text; got: {}",
            msg.info.output
        );
        Ok(())
    }

    // ------------------------------------------------------------------
    // handle_beacon_output_callback — OutputUtf8 credential extraction
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn beacon_output_utf8_persists_credential_loot() -> Result<(), Box<dyn std::error::Error>>
    {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let downloads = DownloadTracker::new(1024 * 1024);
        let agent_id: u32 = 0xDA01_0002;
        let request_id: u32 = 210;

        register_test_agent(&registry, agent_id).await?;

        // UTF-16LE payload that decodes to a string with a credential pattern.
        let output_text = "Password : s3cr3t!";
        let utf16_data = utf16le_bytes(output_text);
        let mut payload = Vec::new();
        payload.extend_from_slice(&le32(u32::from(DemonCallback::OutputUtf8)));
        payload.extend_from_slice(&length_prefixed(&utf16_data));

        let result = handle_beacon_output_callback(
            &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
        )
        .await?;

        assert_eq!(result, None, "beacon-output handler must not produce a reply packet");

        // First event: AgentResponse carrying the captured output.
        let first_event = receiver.recv().await.ok_or("expected AgentResponse event for output")?;
        assert!(
            matches!(first_event, OperatorMessage::AgentResponse(_)),
            "first event should be AgentResponse; got: {first_event:?}"
        );

        // The credential line must have been persisted as a loot record.
        let loot_records = database.loot().list_for_agent(agent_id).await?;
        assert!(
            loot_records.iter().any(|r| r.kind == "credential"),
            "expected at least one 'credential' loot record from OutputUtf8 path; got: {loot_records:?}"
        );
        Ok(())
    }

    // ------------------------------------------------------------------
    // handle_beacon_output_callback — OutputOem credential extraction
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn beacon_output_oem_persists_credential_loot() -> Result<(), Box<dyn std::error::Error>>
    {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let downloads = DownloadTracker::new(1024 * 1024);
        let agent_id: u32 = 0xDA02_0002;
        let request_id: u32 = 211;

        register_test_agent(&registry, agent_id).await?;

        // UTF-16LE payload that decodes to a string with a credential pattern.
        let output_text = "Password : s3cr3t!";
        let utf16_data = utf16le_bytes(output_text);
        let mut payload = Vec::new();
        payload.extend_from_slice(&le32(u32::from(DemonCallback::OutputOem)));
        payload.extend_from_slice(&length_prefixed(&utf16_data));

        let result = handle_beacon_output_callback(
            &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
        )
        .await?;

        assert_eq!(result, None, "beacon-output handler must not produce a reply packet");

        // First event: AgentResponse carrying the captured output.
        let first_event = receiver.recv().await.ok_or("expected AgentResponse event for output")?;
        assert!(
            matches!(first_event, OperatorMessage::AgentResponse(_)),
            "first event should be AgentResponse; got: {first_event:?}"
        );

        // The credential line must have been persisted as a loot record.
        let loot_records = database.loot().list_for_agent(agent_id).await?;
        assert!(
            loot_records.iter().any(|r| r.kind == "credential"),
            "expected at least one 'credential' loot record from OutputOem path; got: {loot_records:?}"
        );
        Ok(())
    }

    // ------------------------------------------------------------------
    // handle_beacon_output_callback — ErrorMessage variant
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn beacon_error_message_broadcasts_error_kind() -> Result<(), Box<dyn std::error::Error>>
    {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let downloads = DownloadTracker::new(1024 * 1024);
        let agent_id: u32 = 0xDA03_0001;
        let request_id: u32 = 202;

        register_test_agent(&registry, agent_id).await?;

        let error_text = "access denied";
        let mut payload = Vec::new();
        payload.extend_from_slice(&le32(u32::from(DemonCallback::ErrorMessage)));
        payload.extend_from_slice(&length_prefixed(error_text.as_bytes()));

        let result = handle_beacon_output_callback(
            &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
        )
        .await?;

        assert_eq!(result, None);

        let event = receiver.recv().await.ok_or("expected AgentResponse event")?;
        let OperatorMessage::AgentResponse(msg) = event else {
            return Err("expected AgentResponse".into());
        };
        // ErrorMessage branch sets kind = "Error"
        let kind = msg.info.extra.get("Type").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(kind, "Error", "ErrorMessage callback must emit Error kind; got: {kind}");
        assert!(
            msg.info.output.contains("access denied"),
            "output should contain the error text; got: {}",
            msg.info.output
        );

        // Should still persist an agent_response record.
        let responses = database.agent_responses().list_for_agent(agent_id).await?;
        assert!(!responses.is_empty(), "ErrorMessage must persist an agent_response record");
        Ok(())
    }

    // ------------------------------------------------------------------
    // handle_beacon_output_callback — File→FileWrite→FileClose sequence
    // ------------------------------------------------------------------

    /// Build a File-open (DemonCallback::File) payload with the given file_id,
    /// expected_size, and remote_path.  The inner bytes use big-endian for
    /// file_id and expected_size (as expected by `parse_file_open_header`).
    fn file_open_payload(file_id: u32, expected_size: u32, remote_path: &str) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.extend_from_slice(&file_id.to_be_bytes());
        inner.extend_from_slice(&expected_size.to_be_bytes());
        inner.extend_from_slice(remote_path.as_bytes());

        let mut payload = Vec::new();
        payload.extend_from_slice(&le32(u32::from(DemonCallback::File)));
        payload.extend_from_slice(&length_prefixed(&inner));
        payload
    }

    /// Build a FileWrite (DemonCallback::FileWrite) payload with the given
    /// file_id and chunk data.  file_id is big-endian.
    fn file_write_payload(file_id: u32, chunk: &[u8]) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.extend_from_slice(&file_id.to_be_bytes());
        inner.extend_from_slice(chunk);

        let mut payload = Vec::new();
        payload.extend_from_slice(&le32(u32::from(DemonCallback::FileWrite)));
        payload.extend_from_slice(&length_prefixed(&inner));
        payload
    }

    /// Build a FileClose (DemonCallback::FileClose) payload.  file_id is big-endian.
    fn file_close_payload(file_id: u32) -> Vec<u8> {
        let mut inner = Vec::new();
        inner.extend_from_slice(&file_id.to_be_bytes());

        let mut payload = Vec::new();
        payload.extend_from_slice(&le32(u32::from(DemonCallback::FileClose)));
        payload.extend_from_slice(&length_prefixed(&inner));
        payload
    }

    #[tokio::test]
    async fn beacon_file_transfer_full_sequence() -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let downloads = DownloadTracker::new(1024 * 1024);
        let agent_id: u32 = 0xDA04_0001;
        let request_id: u32 = 300;
        let file_id: u32 = 0x0000_FF01;
        let chunk_a = b"Hello, ";
        let chunk_b = b"World!";
        let expected_size: u32 = (chunk_a.len() + chunk_b.len()) as u32;

        register_test_agent(&registry, agent_id).await?;

        // --- Step 1: File open ---
        let payload = file_open_payload(file_id, expected_size, r"C:\exfil\data.txt");
        handle_beacon_output_callback(
            &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
        )
        .await?;

        // Should emit a download-progress "Started" event.
        let event = receiver.recv().await.ok_or("expected progress event after File open")?;
        let OperatorMessage::AgentResponse(msg) = &event else {
            return Err("expected AgentResponse for File open".into());
        };
        let misc_type = msg.info.extra.get("MiscType").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(
            misc_type, "download-progress",
            "File open should emit download-progress; got: {misc_type}"
        );
        let state_field = msg.info.extra.get("State").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(state_field, "Started");

        // Download should now be tracked.
        assert!(
            !downloads.active_for_agent(agent_id).await.is_empty(),
            "download should be tracked after File open"
        );

        // --- Step 2: FileWrite (chunk A) ---
        let payload = file_write_payload(file_id, chunk_a);
        handle_beacon_output_callback(
            &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
        )
        .await?;

        let event = receiver.recv().await.ok_or("expected progress event after FileWrite A")?;
        let OperatorMessage::AgentResponse(msg) = &event else {
            return Err("expected AgentResponse for FileWrite A".into());
        };
        let misc_type = msg.info.extra.get("MiscType").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(misc_type, "download-progress");
        let state_field = msg.info.extra.get("State").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(state_field, "InProgress");

        // --- Step 3: FileWrite (chunk B) ---
        let payload = file_write_payload(file_id, chunk_b);
        handle_beacon_output_callback(
            &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
        )
        .await?;

        let event = receiver.recv().await.ok_or("expected progress event after FileWrite B")?;
        let OperatorMessage::AgentResponse(msg) = &event else {
            return Err("expected AgentResponse for FileWrite B".into());
        };
        let misc_type = msg.info.extra.get("MiscType").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(misc_type, "download-progress");

        // --- Step 4: FileClose ---
        let payload = file_close_payload(file_id);
        handle_beacon_output_callback(
            &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
        )
        .await?;

        // FileClose emits loot_new_event first, then download_complete_event.
        let event = receiver.recv().await.ok_or("expected loot-new event after FileClose")?;
        let OperatorMessage::AgentResponse(msg) = &event else {
            return Err("expected AgentResponse for loot-new".into());
        };
        let misc_type = msg.info.extra.get("MiscType").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(
            misc_type, "loot-new",
            "first FileClose event should be loot-new; got: {misc_type}"
        );

        let event =
            receiver.recv().await.ok_or("expected download-complete event after FileClose")?;
        let OperatorMessage::AgentResponse(msg) = &event else {
            return Err("expected AgentResponse for download-complete".into());
        };
        let misc_type = msg.info.extra.get("MiscType").and_then(|v| v.as_str()).unwrap_or("");
        assert_eq!(
            misc_type, "download",
            "second FileClose event should be download; got: {misc_type}"
        );

        // Download should be cleaned up.
        assert!(
            downloads.active_for_agent(agent_id).await.is_empty(),
            "download should be removed after FileClose"
        );

        // Loot record must be persisted with the correct data.
        let loot_records = database.loot().list_for_agent(agent_id).await?;
        let download_loot = loot_records.iter().find(|r| r.kind == "download");
        assert!(
            download_loot.is_some(),
            "expected a 'download' loot record; got: {loot_records:?}"
        );
        let loot = download_loot.unwrap();
        assert_eq!(loot.name, "data.txt", "loot name should be the filename");
        assert_eq!(
            loot.data.as_deref(),
            Some(b"Hello, World!".as_slice()),
            "loot data should be the concatenated chunks"
        );
        Ok(())
    }

    // ------------------------------------------------------------------
    // handle_beacon_output_callback — truncated FileWrite payload
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn beacon_file_write_without_open_returns_error() -> Result<(), Box<dyn std::error::Error>>
    {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let downloads = DownloadTracker::new(1024 * 1024);
        let agent_id: u32 = 0xDA05_0001;
        let request_id: u32 = 400;
        let file_id: u32 = 0x0000_FF02;

        register_test_agent(&registry, agent_id).await?;

        // FileWrite without a preceding File open — download was not started.
        let payload = file_write_payload(file_id, b"orphan chunk");
        let result = handle_beacon_output_callback(
            &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
        )
        .await;

        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "FileWrite for unopened download must yield InvalidCallbackPayload; got: {result:?}"
        );

        // No loot should have been persisted.
        let loot_records = database.loot().list_for_agent(agent_id).await?;
        assert!(
            loot_records.is_empty(),
            "no loot should be persisted on error; got: {loot_records:?}"
        );
        Ok(())
    }

    // ------------------------------------------------------------------
    // handle_beacon_output_callback — truncated file open header
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn beacon_file_open_truncated_header_returns_error() {
        let database = Database::connect_in_memory().await.unwrap();
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let downloads = DownloadTracker::new(1024 * 1024);
        let agent_id: u32 = 0xDA06_0001;
        let request_id: u32 = 401;

        // File open with inner data too short (only 4 bytes instead of 8+).
        let mut payload = Vec::new();
        payload.extend_from_slice(&le32(u32::from(DemonCallback::File)));
        payload.extend_from_slice(&length_prefixed(&[0x00, 0x00, 0x00, 0x01]));

        let result = handle_beacon_output_callback(
            &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
        )
        .await;

        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "truncated file open header must yield InvalidCallbackPayload; got: {result:?}"
        );
    }

    // ------------------------------------------------------------------
    // Malformed-payload tests — CommandTransfer
    // ------------------------------------------------------------------

    /// After an error return the event bus must contain zero messages.
    async fn assert_no_events_broadcast(events: EventBus) {
        let mut rx = events.subscribe();
        // Drop the bus so recv() resolves immediately with None if empty.
        drop(events);
        assert_eq!(rx.recv().await, None, "no events should be broadcast on error path");
    }

    #[tokio::test]
    async fn transfer_callback_invalid_subcommand_returns_error() {
        let events = EventBus::default();
        let downloads = DownloadTracker::new(1024 * 1024);

        // Subcommand 0xFF is not a valid DemonTransferCommand.
        let payload = le32(0xFF);

        let result = handle_transfer_callback(&events, &downloads, 0x1111_0001, 1, &payload).await;

        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "invalid subcommand must yield InvalidCallbackPayload; got: {result:?}"
        );
        assert_no_events_broadcast(events).await;
    }

    #[tokio::test]
    async fn transfer_list_truncated_mid_entry_returns_error() {
        let events = EventBus::default();
        let downloads = DownloadTracker::new(1024 * 1024);

        // List subcommand + file_id only (missing progress and state).
        let mut payload = Vec::new();
        payload.extend_from_slice(&le32(u32::from(DemonTransferCommand::List)));
        payload.extend_from_slice(&le32(0x0000_0001)); // file_id
        // Missing: progress (u32) and state (u32)

        let result = handle_transfer_callback(&events, &downloads, 0x1111_0002, 1, &payload).await;

        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "truncated List entry must yield InvalidCallbackPayload; got: {result:?}"
        );
        assert_no_events_broadcast(events).await;
    }

    #[tokio::test]
    async fn transfer_stop_truncated_missing_found_returns_error() {
        let events = EventBus::default();
        let downloads = DownloadTracker::new(1024 * 1024);

        // Stop subcommand only — missing found bool and file_id.
        let payload = le32(u32::from(DemonTransferCommand::Stop));

        let result = handle_transfer_callback(&events, &downloads, 0x1111_0003, 1, &payload).await;

        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "Stop with missing found bool must yield InvalidCallbackPayload; got: {result:?}"
        );
        assert_no_events_broadcast(events).await;
    }

    #[tokio::test]
    async fn transfer_stop_truncated_missing_file_id_returns_error() {
        let events = EventBus::default();
        let downloads = DownloadTracker::new(1024 * 1024);

        // Stop subcommand + found bool — missing file_id.
        let mut payload = Vec::new();
        payload.extend_from_slice(&le32(u32::from(DemonTransferCommand::Stop)));
        payload.extend_from_slice(&le32(1)); // found = true

        let result = handle_transfer_callback(&events, &downloads, 0x1111_0004, 1, &payload).await;

        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "Stop with missing file_id must yield InvalidCallbackPayload; got: {result:?}"
        );
        assert_no_events_broadcast(events).await;
    }

    #[tokio::test]
    async fn transfer_resume_truncated_missing_found_returns_error() {
        let events = EventBus::default();
        let downloads = DownloadTracker::new(1024 * 1024);

        let payload = le32(u32::from(DemonTransferCommand::Resume));

        let result = handle_transfer_callback(&events, &downloads, 0x1111_0005, 1, &payload).await;

        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "Resume with missing found bool must yield InvalidCallbackPayload; got: {result:?}"
        );
        assert_no_events_broadcast(events).await;
    }

    #[tokio::test]
    async fn transfer_remove_truncated_missing_file_id_returns_error() {
        let events = EventBus::default();
        let downloads = DownloadTracker::new(1024 * 1024);

        let mut payload = Vec::new();
        payload.extend_from_slice(&le32(u32::from(DemonTransferCommand::Remove)));
        payload.extend_from_slice(&le32(0)); // found = false

        let result = handle_transfer_callback(&events, &downloads, 0x1111_0006, 1, &payload).await;

        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "Remove with missing file_id must yield InvalidCallbackPayload; got: {result:?}"
        );
        assert_no_events_broadcast(events).await;
    }

    // ------------------------------------------------------------------
    // Malformed-payload tests — CommandMemFile
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn mem_file_callback_empty_payload_returns_error() {
        let events = EventBus::default();

        let result = handle_mem_file_callback(&events, 0x2222_0001, 1, &[]).await;

        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "empty mem-file payload must yield InvalidCallbackPayload; got: {result:?}"
        );
        assert_no_events_broadcast(events).await;
    }

    #[tokio::test]
    async fn mem_file_callback_truncated_missing_success_returns_error() {
        let events = EventBus::default();

        // Has mem_file_id but missing the success bool.
        let payload = le32(0x0000_0099);

        let result = handle_mem_file_callback(&events, 0x2222_0002, 1, &payload).await;

        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "mem-file missing success bool must yield InvalidCallbackPayload; got: {result:?}"
        );
        assert_no_events_broadcast(events).await;
    }

    // ------------------------------------------------------------------
    // Malformed-payload tests — CommandPackageDropped
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn package_dropped_callback_empty_payload_returns_error() {
        let events = EventBus::default();

        let result = handle_package_dropped_callback(&events, 0x3333_0001, 1, &[]).await;

        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "empty package-dropped payload must yield InvalidCallbackPayload; got: {result:?}"
        );
        assert_no_events_broadcast(events).await;
    }

    #[tokio::test]
    async fn package_dropped_callback_truncated_missing_max_length_returns_error() {
        let events = EventBus::default();

        // Has package_length but missing max_length.
        let payload = le32(8192);

        let result = handle_package_dropped_callback(&events, 0x3333_0002, 1, &payload).await;

        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "package-dropped missing max_length must yield InvalidCallbackPayload; got: {result:?}"
        );
        assert_no_events_broadcast(events).await;
    }

    // ------------------------------------------------------------------
    // Existing truncated-transfer test also asserts no events
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn transfer_callback_truncated_returns_error_no_events() {
        let events = EventBus::default();
        let downloads = DownloadTracker::new(1024 * 1024);

        let result = handle_transfer_callback(&events, &downloads, 0x1111_1111, 1, &[]).await;

        assert!(
            matches!(result, Err(CommandDispatchError::InvalidCallbackPayload { .. })),
            "empty payload must yield InvalidCallbackPayload; got: {result:?}"
        );
        assert_no_events_broadcast(events).await;
    }

    // ------------------------------------------------------------------
    // byte_count / transfer_progress_text / transfer_state_name tests
    // ------------------------------------------------------------------

    #[test]
    fn byte_count_zero() {
        assert_eq!(byte_count(0), "0 B");
    }

    #[test]
    fn byte_count_below_kilo() {
        assert_eq!(byte_count(999), "999 B");
    }

    #[test]
    fn byte_count_kilobytes() {
        assert_eq!(byte_count(1_000), "1.00 kB");
    }

    #[test]
    fn byte_count_megabytes() {
        assert_eq!(byte_count(1_000_000), "1.00 MB");
    }

    #[test]
    fn byte_count_terabytes() {
        assert_eq!(byte_count(1_000_000_000_000), "1.00 TB");
    }

    #[test]
    fn byte_count_near_kb_boundary() {
        // 999_999 bytes is 999.999 kB — should still display as kB, not MB
        assert_eq!(byte_count(999_999), "1000.00 kB");
    }

    #[test]
    fn byte_count_near_tb_boundary() {
        // 999_999_999_999_999 bytes — exercises the GB→TB boundary
        assert_eq!(byte_count(999_999_999_999_999), "1000.00 TB");
    }

    #[test]
    fn byte_count_u64_max() {
        // u64::MAX = 18_446_744_073_709_551_615 — verify no panic from f64 conversion
        // f64 loses precision at this magnitude: ≈ 18446744.07 TB
        let result = byte_count(u64::MAX);
        assert!(result.ends_with(" TB"), "expected TB suffix, got: {result}");
        assert!(result.starts_with("18446744"), "expected ~18446744 TB, got: {result}");
    }

    #[test]
    fn transfer_progress_text_zero_total() {
        assert_eq!(transfer_progress_text(0, 0), "0.00%");
    }

    #[test]
    fn transfer_progress_text_half() {
        assert_eq!(transfer_progress_text(50, 100), "50.00%");
    }

    #[test]
    fn transfer_progress_text_fraction() {
        assert_eq!(transfer_progress_text(1, 3), "33.33%");
    }

    #[test]
    fn transfer_state_name_running() {
        assert_eq!(transfer_state_name(1), "Running");
    }

    #[test]
    fn transfer_state_name_stopped() {
        assert_eq!(transfer_state_name(2), "Stopped");
    }

    #[test]
    fn transfer_state_name_removed() {
        assert_eq!(transfer_state_name(3), "Removed");
    }

    #[test]
    fn transfer_state_name_unknown() {
        assert_eq!(transfer_state_name(99), "Unknown");
    }

    // ------------------------------------------------------------------
    // handle_beacon_output_callback — empty output no-op paths
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn beacon_output_empty_string_skips_broadcast_and_persist()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let downloads = DownloadTracker::new(1024 * 1024);
        let agent_id: u32 = 0xE000_0001;
        let request_id: u32 = 500;

        register_test_agent(&registry, agent_id).await?;

        // Build payload: Output callback with a length-prefixed empty string (len=0).
        let mut payload = Vec::new();
        payload.extend_from_slice(&le32(u32::from(DemonCallback::Output)));
        payload.extend_from_slice(&length_prefixed(b""));

        let result = handle_beacon_output_callback(
            &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
        )
        .await?;

        assert_eq!(result, None, "empty Output must not produce a reply packet");

        // No event should have been broadcast.
        let no_event =
            tokio::time::timeout(std::time::Duration::from_millis(50), receiver.recv()).await;
        assert!(no_event.is_err(), "empty Output must not broadcast an event; got: {no_event:?}");

        // No agent_response should have been persisted.
        let responses = database.agent_responses().list_for_agent(agent_id).await?;
        assert!(
            responses.is_empty(),
            "empty Output must not persist an agent_response record; got: {responses:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn beacon_output_utf8_empty_skips_broadcast_and_persist()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let downloads = DownloadTracker::new(1024 * 1024);
        let agent_id: u32 = 0xE000_0002;
        let request_id: u32 = 501;

        register_test_agent(&registry, agent_id).await?;

        // Build payload: OutputUtf8 callback with a length-prefixed empty UTF-16 buffer.
        let mut payload = Vec::new();
        payload.extend_from_slice(&le32(u32::from(DemonCallback::OutputUtf8)));
        payload.extend_from_slice(&length_prefixed(b""));

        let result = handle_beacon_output_callback(
            &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
        )
        .await?;

        assert_eq!(result, None, "empty OutputUtf8 must not produce a reply packet");

        let no_event =
            tokio::time::timeout(std::time::Duration::from_millis(50), receiver.recv()).await;
        assert!(
            no_event.is_err(),
            "empty OutputUtf8 must not broadcast an event; got: {no_event:?}"
        );

        let responses = database.agent_responses().list_for_agent(agent_id).await?;
        assert!(
            responses.is_empty(),
            "empty OutputUtf8 must not persist an agent_response record; got: {responses:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn beacon_output_oem_empty_skips_broadcast_and_persist()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let downloads = DownloadTracker::new(1024 * 1024);
        let agent_id: u32 = 0xE000_0003;
        let request_id: u32 = 502;

        register_test_agent(&registry, agent_id).await?;

        // Build payload: OutputOem callback with a length-prefixed empty UTF-16 buffer.
        let mut payload = Vec::new();
        payload.extend_from_slice(&le32(u32::from(DemonCallback::OutputOem)));
        payload.extend_from_slice(&length_prefixed(b""));

        let result = handle_beacon_output_callback(
            &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
        )
        .await?;

        assert_eq!(result, None, "empty OutputOem must not produce a reply packet");

        let no_event =
            tokio::time::timeout(std::time::Duration::from_millis(50), receiver.recv()).await;
        assert!(
            no_event.is_err(),
            "empty OutputOem must not broadcast an event; got: {no_event:?}"
        );

        let responses = database.agent_responses().list_for_agent(agent_id).await?;
        assert!(
            responses.is_empty(),
            "empty OutputOem must not persist an agent_response record; got: {responses:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn beacon_error_message_empty_skips_broadcast_and_persist()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let mut receiver = events.subscribe();
        let downloads = DownloadTracker::new(1024 * 1024);
        let agent_id: u32 = 0xE000_0004;
        let request_id: u32 = 503;

        register_test_agent(&registry, agent_id).await?;

        // Build payload: ErrorMessage callback with a length-prefixed empty string.
        let mut payload = Vec::new();
        payload.extend_from_slice(&le32(u32::from(DemonCallback::ErrorMessage)));
        payload.extend_from_slice(&length_prefixed(b""));

        let result = handle_beacon_output_callback(
            &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
        )
        .await?;

        assert_eq!(result, None, "empty ErrorMessage must not produce a reply packet");

        let no_event =
            tokio::time::timeout(std::time::Duration::from_millis(50), receiver.recv()).await;
        assert!(
            no_event.is_err(),
            "empty ErrorMessage must not broadcast an event; got: {no_event:?}"
        );

        let responses = database.agent_responses().list_for_agent(agent_id).await?;
        assert!(
            responses.is_empty(),
            "empty ErrorMessage must not persist an agent_response record; got: {responses:?}"
        );
        Ok(())
    }

    // ------------------------------------------------------------------
    // handle_beacon_output_callback — invalid DemonCallback type returns error
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn beacon_output_callback_invalid_callback_type_returns_error()
    -> Result<(), Box<dyn std::error::Error>> {
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let downloads = DownloadTracker::new(1024 * 1024);
        let agent_id: u32 = 0xBAAD_F00D;
        let request_id: u32 = 7;

        // Build a payload whose callback type (0xFF) is not a valid DemonCallback variant.
        let invalid_callback: u32 = 0xFF;
        let payload = le32(invalid_callback).to_vec();

        let result = handle_beacon_output_callback(
            &registry, &database, &events, &downloads, None, agent_id, request_id, &payload,
        )
        .await;

        let err = result.expect_err("invalid callback type must return an error");
        assert!(
            matches!(err, CommandDispatchError::InvalidCallbackPayload { .. }),
            "expected InvalidCallbackPayload, got {err:?}"
        );

        // Verify the error carries the correct command_id.
        if let CommandDispatchError::InvalidCallbackPayload { command_id, .. } = &err {
            assert_eq!(
                *command_id,
                u32::from(red_cell_common::demon::DemonCommand::BeaconOutput),
                "command_id in error must match BeaconOutput"
            );
        }

        Ok(())
    }
}
