use red_cell_common::demon::DemonCommand;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::agent_events::{agent_mark_event, agent_new_event};
use crate::{AgentRegistry, DemonPacketParser, EventBus};

use super::process::win32_error_code_name;
use super::{
    BuiltinDispatchContext, BuiltinHandlerDependencies, CallbackParser, CommandDispatchError,
    CommandDispatcher, DemonCallbackPackage, DemonProtocolError, agent_response_event,
};

pub(super) async fn handle_pivot_callback(
    context: BuiltinDispatchContext<'_>,
    agent_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut parser = CallbackParser::new(payload, u32::from(DemonCommand::CommandPivot));
    let subcommand = parser.read_u32("pivot subcommand")?;

    match subcommand.try_into() {
        Ok(red_cell_common::demon::DemonPivotCommand::SmbConnect) => {
            handle_pivot_connect_callback(
                context.registry,
                context.events,
                agent_id,
                request_id,
                &mut parser,
            )
            .await
        }
        Ok(red_cell_common::demon::DemonPivotCommand::SmbDisconnect) => {
            handle_pivot_disconnect_callback(
                context.registry,
                context.events,
                agent_id,
                request_id,
                &mut parser,
            )
            .await
        }
        Ok(red_cell_common::demon::DemonPivotCommand::SmbCommand) => {
            handle_pivot_command_callback(context, agent_id, &mut parser).await
        }
        Ok(red_cell_common::demon::DemonPivotCommand::List) => {
            handle_pivot_list_callback(context.events, agent_id, request_id, &mut parser).await
        }
        Err(error) => Err(CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandPivot),
            message: error.to_string(),
        }),
    }
}

async fn handle_pivot_list_callback(
    events: &EventBus,
    agent_id: u32,
    request_id: u32,
    parser: &mut CallbackParser<'_>,
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut entries: Vec<(u32, String)> = Vec::new();
    while !parser.is_empty() {
        let demon_id = parser.read_u32("pivot list demon id")?;
        let named_pipe = parser.read_utf16("pivot list named pipe")?;
        entries.push((demon_id, named_pipe));
    }

    let (kind, message, output) = if entries.is_empty() {
        ("Info", "No pivots connected".to_owned(), None)
    } else {
        let count = entries.len();
        let mut data = String::from(" DemonID    Named Pipe\n --------   -----------\n");
        for (demon_id, named_pipe) in entries {
            data.push_str(&format!(" {demon_id:08x}   {named_pipe}\n"));
        }
        ("Info", format!("Pivot List [{count}]:"), Some(data.trim_end().to_owned()))
    };

    events.broadcast(agent_response_event(
        agent_id,
        u32::from(DemonCommand::CommandPivot),
        request_id,
        kind,
        &message,
        output,
    )?);
    Ok(None)
}

async fn handle_pivot_connect_callback(
    registry: &AgentRegistry,
    events: &EventBus,
    parent_agent_id: u32,
    request_id: u32,
    parser: &mut CallbackParser<'_>,
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let success = parser.read_u32("pivot connect success")?;
    if success == 0 {
        let error_code = parser.read_u32("pivot connect error code")?;
        let message = match win32_error_code_name(error_code) {
            Some(name) => format!("[SMB] Failed to connect: {name} [{error_code}]"),
            None => format!("[SMB] Failed to connect: [{error_code}]"),
        };
        events.broadcast(agent_response_event(
            parent_agent_id,
            u32::from(DemonCommand::CommandPivot),
            request_id,
            "Error",
            &message,
            None,
        )?);
        return Ok(None);
    }

    let inner = parser.read_bytes("pivot connect inner demon init")?;
    let child_agent_id = inner_demon_agent_id(&inner).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandPivot),
            message: error.to_string(),
        }
    })?;
    let existed = registry.get(child_agent_id).await.is_some();
    let external_ip =
        registry.get(parent_agent_id).await.map(|agent| agent.external_ip).unwrap_or_default();
    let listener_name =
        registry.listener_name(parent_agent_id).await.unwrap_or_else(|| "smb".to_owned());
    let parsed = DemonPacketParser::new(registry.clone())
        .parse_for_listener(&inner, external_ip, &listener_name)
        .await;
    let child_agent = match parsed {
        Ok(crate::ParsedDemonPacket::Init(init)) => init.agent,
        Ok(_) => {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: u32::from(DemonCommand::CommandPivot),
                message: "pivot connect payload did not contain a demon init envelope".to_owned(),
            });
        }
        Err(error) => {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: u32::from(DemonCommand::CommandPivot),
                message: error.to_string(),
            });
        }
    };

    registry.add_link(parent_agent_id, child_agent.agent_id).await?;
    let pivots = registry.pivots(child_agent.agent_id).await;
    if existed {
        events.broadcast(agent_mark_event(&child_agent));
    } else {
        events.broadcast(agent_new_event(
            &listener_name,
            red_cell_common::demon::DEMON_MAGIC_VALUE,
            &child_agent,
            &pivots,
        ));
    }
    events.broadcast(agent_response_event(
        parent_agent_id,
        u32::from(DemonCommand::CommandPivot),
        request_id,
        "Good",
        &format!(
            "[SMB] Connected to pivot agent [{parent_agent_id:08X}]-<>-<>-[{}]",
            child_agent.name_id()
        ),
        None,
    )?);
    Ok(None)
}

async fn handle_pivot_disconnect_callback(
    registry: &AgentRegistry,
    events: &EventBus,
    parent_agent_id: u32,
    request_id: u32,
    parser: &mut CallbackParser<'_>,
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let success = parser.read_u32("pivot disconnect success")?;
    let child_agent_id = parser.read_u32("pivot disconnect child agent id")?;
    if success == 0 {
        events.broadcast(agent_response_event(
            parent_agent_id,
            u32::from(DemonCommand::CommandPivot),
            request_id,
            "Error",
            &format!("[SMB] Failed to disconnect agent {child_agent_id:08X}"),
            None,
        )?);
        return Ok(None);
    }

    let affected =
        registry.disconnect_link(parent_agent_id, child_agent_id, "Disconnected").await?;
    for agent_id in affected {
        if let Some(agent) = registry.get(agent_id).await {
            events.broadcast(agent_mark_event(&agent));
        }
    }
    events.broadcast(agent_response_event(
        parent_agent_id,
        u32::from(DemonCommand::CommandPivot),
        request_id,
        "Info",
        &format!("[SMB] Agent disconnected {child_agent_id:08X}"),
        None,
    )?);
    Ok(None)
}

async fn handle_pivot_command_callback(
    context: BuiltinDispatchContext<'_>,
    _parent_agent_id: u32,
    parser: &mut CallbackParser<'_>,
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let package = parser.read_bytes("pivot command package")?;
    let parsed =
        DemonPacketParser::new(context.registry.clone()).parse(&package, String::new()).await;
    let (child_agent_id, packages) = match parsed {
        Ok(crate::ParsedDemonPacket::Callback { header, packages }) => (header.agent_id, packages),
        Ok(_) => {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: u32::from(DemonCommand::CommandPivot),
                message: "pivot command payload did not contain a callback envelope".to_owned(),
            });
        }
        Err(error) => {
            return Err(CommandDispatchError::InvalidCallbackPayload {
                command_id: u32::from(DemonCommand::CommandPivot),
                message: error.to_string(),
            });
        }
    };

    let timestamp = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let updated = context.registry.set_last_call_in(child_agent_id, timestamp).await?;
    context.events.broadcast(agent_mark_event(&updated));
    dispatch_builtin_packages(context, child_agent_id, &packages).await
}

pub(super) async fn dispatch_builtin_packages(
    context: BuiltinDispatchContext<'_>,
    agent_id: u32,
    packages: &[DemonCallbackPackage],
) -> Result<Option<Vec<u8>>, CommandDispatchError> {
    let mut dispatcher =
        CommandDispatcher::with_max_download_bytes(context.downloads.max_download_bytes);
    dispatcher.register_builtin_handlers(
        BuiltinHandlerDependencies {
            registry: context.registry.clone(),
            events: context.events.clone(),
            database: context.database.clone(),
            sockets: context.sockets.clone(),
            downloads: context.downloads.clone(),
            plugins: context.plugins.cloned(),
        },
        false,
    );
    let response = dispatcher.collect_response_bytes(agent_id, packages).await?;
    Ok((!response.is_empty()).then_some(response))
}

pub(super) fn inner_demon_agent_id(bytes: &[u8]) -> Result<u32, DemonProtocolError> {
    Ok(red_cell_common::demon::DemonEnvelope::from_bytes(bytes)?.header.agent_id)
}

#[cfg(test)]
mod tests {
    use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
    use red_cell_common::demon::{
        DEMON_MAGIC_VALUE, DemonCommand, DemonEnvelope, DemonProtocolError, MIN_ENVELOPE_SIZE,
    };
    use red_cell_common::operator::OperatorMessage;
    use serde_json::Value;
    use zeroize::Zeroizing;

    use super::{
        CallbackParser, CommandDispatchError, DemonCallbackPackage, handle_pivot_command_callback,
        handle_pivot_list_callback, inner_demon_agent_id,
    };
    use crate::dispatch::pivot::dispatch_builtin_packages;
    use crate::dispatch::{BuiltinDispatchContext, DownloadTracker};
    use crate::{AgentRegistry, Database, EventBus, SocketRelayManager};

    const AGENT_ID: u32 = 0xBEEF_0001;
    const REQUEST_ID: u32 = 42;

    /// Build a minimal valid Demon envelope wire encoding for `agent_id` with no payload.
    fn valid_envelope_bytes(agent_id: u32) -> Vec<u8> {
        DemonEnvelope::new(agent_id, Vec::new())
            .expect("envelope construction must succeed")
            .to_bytes()
    }

    fn push_u32(buf: &mut Vec<u8>, val: u32) {
        buf.extend_from_slice(&val.to_le_bytes());
    }

    /// Append a length-prefixed UTF-16LE string (as `CallbackParser::read_utf16` expects).
    fn push_utf16(buf: &mut Vec<u8>, s: &str) {
        let words: Vec<u16> = s.encode_utf16().collect();
        let byte_len = (words.len() * 2) as u32;
        push_u32(buf, byte_len);
        for w in &words {
            buf.extend_from_slice(&w.to_le_bytes());
        }
    }

    #[test]
    fn happy_path_returns_correct_agent_id() {
        let expected_agent_id: u32 = 0xCAFE_BABE;
        let bytes = valid_envelope_bytes(expected_agent_id);

        let result = inner_demon_agent_id(&bytes).expect("valid envelope must parse successfully");

        assert_eq!(result, expected_agent_id);
    }

    #[test]
    fn empty_slice_returns_protocol_error_not_panic() {
        let error =
            inner_demon_agent_id(&[]).expect_err("empty slice must return an error, not panic");

        assert_eq!(
            error,
            DemonProtocolError::BufferTooShort {
                context: "DemonEnvelope",
                expected: MIN_ENVELOPE_SIZE,
                actual: 0,
            }
        );
    }

    #[test]
    fn wrong_magic_returns_invalid_magic_error() {
        // Build a valid envelope then flip the magic bytes.
        let mut bytes = valid_envelope_bytes(0x1234_5678);
        // Magic occupies bytes [4..8] in big-endian order.
        bytes[4] = 0xDE;
        bytes[5] = 0xAD;
        bytes[6] = 0xBE;
        bytes[7] = 0xEE; // last byte differs from 0xEF

        let error =
            inner_demon_agent_id(&bytes).expect_err("wrong magic must return an error, not panic");

        assert_eq!(
            error,
            DemonProtocolError::InvalidMagic { expected: DEMON_MAGIC_VALUE, actual: 0xDEAD_BEEE }
        );
    }

    #[tokio::test]
    async fn pivot_list_empty_payload_returns_no_pivots_message() {
        let events = EventBus::new(16);
        let mut rx = events.subscribe();
        let payload: Vec<u8> = Vec::new();
        let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandPivot));

        let result = handle_pivot_list_callback(&events, AGENT_ID, REQUEST_ID, &mut parser).await;

        assert!(result.is_ok());
        assert!(matches!(result.as_ref(), Ok(None)));

        let msg = rx.recv().await.expect("should receive agent response");
        let OperatorMessage::AgentResponse(resp) = &msg else {
            panic!("expected AgentResponse, got {msg:?}");
        };
        let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
        assert_eq!(message, "No pivots connected");
        assert!(resp.info.output.is_empty(), "empty list should have no output table");
    }

    #[tokio::test]
    async fn pivot_list_two_entries_returns_table_with_both() {
        let events = EventBus::new(16);
        let mut rx = events.subscribe();

        let mut payload = Vec::new();
        let demon_id_1: u32 = 0xAAAA_BBBB;
        let demon_id_2: u32 = 0xCCCC_DDDD;
        let pipe_1 = r"\\.\pipe\pivot_one";
        let pipe_2 = r"\\.\pipe\pivot_two";
        push_u32(&mut payload, demon_id_1);
        push_utf16(&mut payload, pipe_1);
        push_u32(&mut payload, demon_id_2);
        push_utf16(&mut payload, pipe_2);

        let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandPivot));

        let result = handle_pivot_list_callback(&events, AGENT_ID, REQUEST_ID, &mut parser).await;

        assert!(result.is_ok());
        assert!(matches!(result.as_ref(), Ok(None)));

        let msg = rx.recv().await.expect("should receive agent response");
        let OperatorMessage::AgentResponse(resp) = &msg else {
            panic!("expected AgentResponse, got {msg:?}");
        };
        let message = resp.info.extra.get("Message").and_then(Value::as_str).unwrap_or("");
        assert!(message.contains("[2]"), "expected count [2] in message, got {message:?}");

        let output = &resp.info.output;
        assert!(output.contains("aaaabbbb"), "expected demon_id_1 hex in output, got {output:?}");
        assert!(output.contains("ccccdddd"), "expected demon_id_2 hex in output, got {output:?}");
        assert!(output.contains(pipe_1), "expected pipe_1 in output, got {output:?}");
        assert!(output.contains(pipe_2), "expected pipe_2 in output, got {output:?}");
    }

    #[tokio::test]
    async fn pivot_list_truncated_payload_returns_error() {
        let events = EventBus::new(16);

        // Build a payload with one demon_id but no pipe name bytes.
        let mut payload = Vec::new();
        push_u32(&mut payload, 0x1111_2222);
        // No pipe name follows — parser should fail on read_utf16.

        let mut parser = CallbackParser::new(&payload, u32::from(DemonCommand::CommandPivot));

        let result = handle_pivot_list_callback(&events, AGENT_ID, REQUEST_ID, &mut parser).await;

        assert!(result.is_err(), "truncated payload must return an error");
    }

    // -----------------------------------------------------------------------
    // Helpers for handle_pivot_command_callback / dispatch_builtin_packages
    // -----------------------------------------------------------------------

    fn sample_agent_info(
        agent_id: u32,
        key: [u8; AGENT_KEY_LENGTH],
        iv: [u8; AGENT_IV_LENGTH],
    ) -> red_cell_common::AgentRecord {
        red_cell_common::AgentRecord {
            agent_id,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: red_cell_common::AgentEncryptionInfo {
                aes_key: Zeroizing::new(key.to_vec()),
                aes_iv: Zeroizing::new(iv.to_vec()),
            },
            hostname: "wkstn-01".to_owned(),
            username: "operator".to_owned(),
            domain_name: "lab".to_owned(),
            external_ip: "127.0.0.1".to_owned(),
            internal_ip: "10.0.0.25".to_owned(),
            process_name: "explorer.exe".to_owned(),
            process_path: "C:\\Windows\\explorer.exe".to_owned(),
            base_address: 0x1000,
            process_pid: 1337,
            process_tid: 7331,
            process_ppid: 512,
            process_arch: "x64".to_owned(),
            elevated: true,
            os_version: "Windows 11".to_owned(),
            os_build: 0,
            os_arch: "x64".to_owned(),
            sleep_delay: 10,
            sleep_jitter: 25,
            kill_date: None,
            working_hours: None,
            first_call_in: "2026-03-09T20:00:00Z".to_owned(),
            last_call_in: "2026-03-09T20:00:00Z".to_owned(),
        }
    }

    /// Build a valid Demon callback envelope containing a single package.
    fn valid_callback_envelope(
        agent_id: u32,
        key: &[u8; AGENT_KEY_LENGTH],
        iv: &[u8; AGENT_IV_LENGTH],
        command_id: u32,
        request_id: u32,
        inner_payload: &[u8],
    ) -> Vec<u8> {
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(
            &u32::try_from(inner_payload.len()).unwrap_or_default().to_be_bytes(),
        );
        plaintext.extend_from_slice(inner_payload);

        let encrypted = red_cell_common::crypto::encrypt_agent_data(key, iv, &plaintext)
            .expect("callback payload encryption should succeed");

        let mut envelope_payload = Vec::new();
        envelope_payload.extend_from_slice(&command_id.to_be_bytes());
        envelope_payload.extend_from_slice(&request_id.to_be_bytes());
        envelope_payload.extend_from_slice(&encrypted);

        DemonEnvelope::new(agent_id, envelope_payload)
            .unwrap_or_else(|error| panic!("failed to build callback envelope: {error}"))
            .to_bytes()
    }

    /// Build a `CallbackParser` payload with a LE-length-prefixed byte blob.
    fn length_prefixed_bytes(data: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        push_u32(&mut buf, u32::try_from(data.len()).unwrap_or_default());
        buf.extend_from_slice(data);
        buf
    }

    /// Build a CommandOutput inner payload (LE length-prefixed UTF-8 string).
    fn command_output_payload(output: &str) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&u32::try_from(output.len()).unwrap_or_default().to_le_bytes());
        payload.extend_from_slice(output.as_bytes());
        payload
    }

    async fn setup_dispatch_context()
    -> (Database, AgentRegistry, EventBus, SocketRelayManager, DownloadTracker) {
        let database = Database::connect_in_memory().await.expect("in-memory DB must succeed");
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::new(16);
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let downloads = DownloadTracker::new(64 * 1024 * 1024);
        (database, registry, events, sockets, downloads)
    }

    // -----------------------------------------------------------------------
    // Tests for handle_pivot_command_callback
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn pivot_command_callback_happy_path_updates_last_call_in_and_dispatches()
    -> Result<(), Box<dyn std::error::Error>> {
        let (database, registry, events, sockets, downloads) = setup_dispatch_context().await;
        let mut rx = events.subscribe();

        let child_id: u32 = 0x3333_4444;
        let child_key = [0xCC; AGENT_KEY_LENGTH];
        let child_iv = [0xDD; AGENT_IV_LENGTH];
        registry.insert(sample_agent_info(child_id, child_key, child_iv)).await?;

        // Build a valid callback envelope from the child agent containing a
        // CommandOutput response.
        let output_payload = command_output_payload("pivot child says hello");
        let inner_envelope = valid_callback_envelope(
            child_id,
            &child_key,
            &child_iv,
            u32::from(DemonCommand::CommandOutput),
            0x42,
            &output_payload,
        );

        // Wrap the inner envelope into a CallbackParser payload (LE-length-prefixed bytes).
        let parser_payload = length_prefixed_bytes(&inner_envelope);
        let mut parser =
            CallbackParser::new(&parser_payload, u32::from(DemonCommand::CommandPivot));

        let context = BuiltinDispatchContext {
            registry: &registry,
            events: &events,
            database: &database,
            sockets: &sockets,
            downloads: &downloads,
            plugins: None,
        };

        let result = handle_pivot_command_callback(context, AGENT_ID, &mut parser).await;
        assert!(result.is_ok(), "happy path must not return an error: {result:?}");

        // First event: AgentUpdate (mark) from last_call_in update.
        let mark_event = rx.recv().await.expect("should receive AgentUpdate event");
        let OperatorMessage::AgentUpdate(update) = &mark_event else {
            panic!("expected AgentUpdate, got {mark_event:?}");
        };
        assert_eq!(
            update.info.agent_id,
            format!("{child_id:08x}"),
            "update event must be for the child agent"
        );

        // Verify last_call_in was actually updated in the registry.
        let agent = registry.get(child_id).await.expect("child agent must exist");
        assert_ne!(
            agent.last_call_in, "2026-03-09T20:00:00Z",
            "last_call_in must have been updated from its initial value"
        );

        // Second event: AgentResponse from the inner CommandOutput handler.
        let output_event = rx.recv().await.expect("should receive AgentResponse event");
        let OperatorMessage::AgentResponse(msg) = &output_event else {
            panic!("expected AgentResponse, got {output_event:?}");
        };
        assert_eq!(
            msg.info.demon_id,
            format!("{child_id:08X}"),
            "output event must reference the child agent"
        );
        assert!(
            msg.info.output.contains("pivot child says hello"),
            "output must contain the dispatched text"
        );
        Ok(())
    }

    #[tokio::test]
    async fn pivot_command_callback_non_callback_envelope_returns_invalid_callback()
    -> Result<(), Box<dyn std::error::Error>> {
        let (database, registry, events, sockets, downloads) = setup_dispatch_context().await;

        let child_id: u32 = 0x5555_6666;
        let child_key = [0xEE; AGENT_KEY_LENGTH];
        let child_iv = [0xFF; AGENT_IV_LENGTH];
        registry.insert(sample_agent_info(child_id, child_key, child_iv)).await?;

        // Build a DemonInit envelope (not a callback), which the handler must reject.
        let init_payload = {
            let mut metadata = Vec::new();
            metadata.extend_from_slice(&child_id.to_be_bytes());
            // Minimal init metadata — hostname, username, domain, etc.
            for field in &[b"host" as &[u8], b"user", b"domain", b"10.0.0.1"] {
                metadata.extend_from_slice(
                    &u32::try_from(field.len()).unwrap_or_default().to_be_bytes(),
                );
                metadata.extend_from_slice(field);
            }
            // UTF-16 process path
            let path_utf16: Vec<u8> =
                "C:\\a.exe".encode_utf16().flat_map(u16::to_be_bytes).chain([0, 0]).collect();
            metadata.extend_from_slice(
                &u32::try_from(path_utf16.len()).unwrap_or_default().to_be_bytes(),
            );
            metadata.extend_from_slice(&path_utf16);
            // Remaining numeric fields (pid, tid, ppid, arch, elevated, base, sleep,
            // jitter, killdate, workhours, build, major, minor, product, timestamp, flags).
            for _ in 0..14 {
                metadata.extend_from_slice(&0_u32.to_be_bytes());
            }
            metadata.extend_from_slice(&0_u64.to_be_bytes()); // base_address
            metadata.extend_from_slice(&0_u64.to_be_bytes()); // timestamp

            let encrypted =
                red_cell_common::crypto::encrypt_agent_data(&child_key, &child_iv, &metadata)
                    .expect("init metadata encryption should succeed");

            let mut envelope_body = Vec::new();
            envelope_body.extend_from_slice(&u32::from(DemonCommand::DemonInit).to_be_bytes());
            envelope_body.extend_from_slice(&7_u32.to_be_bytes()); // request_id
            envelope_body.extend_from_slice(&child_key);
            envelope_body.extend_from_slice(&child_iv);
            envelope_body.extend_from_slice(&encrypted);

            DemonEnvelope::new(child_id, envelope_body)
                .expect("init envelope construction must succeed")
                .to_bytes()
        };

        let parser_payload = length_prefixed_bytes(&init_payload);
        let mut parser =
            CallbackParser::new(&parser_payload, u32::from(DemonCommand::CommandPivot));

        let context = BuiltinDispatchContext {
            registry: &registry,
            events: &events,
            database: &database,
            sockets: &sockets,
            downloads: &downloads,
            plugins: None,
        };

        let result = handle_pivot_command_callback(context, AGENT_ID, &mut parser).await;
        assert!(result.is_err(), "non-callback envelope must return an error");

        let error = result.unwrap_err();
        assert!(
            matches!(error, CommandDispatchError::InvalidCallbackPayload { .. }),
            "expected InvalidCallbackPayload, got {error:?}"
        );
        let error_msg = error.to_string();
        assert!(
            error_msg.contains("callback"),
            "error message should mention 'callback': {error_msg}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn pivot_command_callback_truncated_inner_returns_protocol_error()
    -> Result<(), Box<dyn std::error::Error>> {
        let (database, registry, events, sockets, downloads) = setup_dispatch_context().await;

        // Provide a truncated inner blob (too short to be a valid DemonEnvelope).
        let truncated_inner = vec![0xDE, 0xAD];
        let parser_payload = length_prefixed_bytes(&truncated_inner);
        let mut parser =
            CallbackParser::new(&parser_payload, u32::from(DemonCommand::CommandPivot));

        let context = BuiltinDispatchContext {
            registry: &registry,
            events: &events,
            database: &database,
            sockets: &sockets,
            downloads: &downloads,
            plugins: None,
        };

        let result = handle_pivot_command_callback(context, AGENT_ID, &mut parser).await;
        assert!(result.is_err(), "truncated inner data must return an error");

        let error = result.unwrap_err();
        assert!(
            matches!(error, CommandDispatchError::InvalidCallbackPayload { .. }),
            "expected InvalidCallbackPayload, got {error:?}"
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Tests for dispatch_builtin_packages
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn dispatch_builtin_packages_with_command_output_emits_event()
    -> Result<(), Box<dyn std::error::Error>> {
        let (database, registry, events, sockets, downloads) = setup_dispatch_context().await;
        let mut rx = events.subscribe();

        let child_id: u32 = 0x7777_8888;
        let child_key = [0x11; AGENT_KEY_LENGTH];
        let child_iv = [0x22; AGENT_IV_LENGTH];
        registry.insert(sample_agent_info(child_id, child_key, child_iv)).await?;

        let context = BuiltinDispatchContext {
            registry: &registry,
            events: &events,
            database: &database,
            sockets: &sockets,
            downloads: &downloads,
            plugins: None,
        };

        let packages = vec![DemonCallbackPackage {
            command_id: u32::from(DemonCommand::CommandOutput),
            request_id: 0x99,
            payload: command_output_payload("dispatched output text"),
        }];

        let result = dispatch_builtin_packages(context, child_id, &packages).await;
        assert!(result.is_ok(), "dispatch_builtin_packages must not fail: {result:?}");

        // CommandOutput handler returns None (no response bytes to forward).
        assert_eq!(result.unwrap(), None, "CommandOutput should not produce response bytes");

        // Verify an AgentResponse event was emitted by the output handler.
        let event = rx.recv().await.expect("should receive AgentResponse event");
        let OperatorMessage::AgentResponse(msg) = &event else {
            panic!("expected AgentResponse, got {event:?}");
        };
        assert_eq!(
            msg.info.demon_id,
            format!("{child_id:08X}"),
            "event must reference the correct agent"
        );
        assert!(
            msg.info.output.contains("dispatched output text"),
            "event output must contain the dispatched text"
        );
        Ok(())
    }
}
