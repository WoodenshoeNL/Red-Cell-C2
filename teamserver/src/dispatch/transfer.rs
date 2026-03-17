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
        let mut out = u32::try_from(data.len()).unwrap_or_default().to_le_bytes().to_vec();
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
        assert!(
            matches!(event, OperatorMessage::AgentResponse(_)),
            "event should be AgentResponse; got: {event:?}"
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
}
