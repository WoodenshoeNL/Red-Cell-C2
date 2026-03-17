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
    use red_cell_common::demon::{
        DEMON_MAGIC_VALUE, DemonEnvelope, DemonProtocolError, MIN_ENVELOPE_SIZE,
    };

    use super::inner_demon_agent_id;

    /// Build a minimal valid Demon envelope wire encoding for `agent_id` with no payload.
    fn valid_envelope_bytes(agent_id: u32) -> Vec<u8> {
        DemonEnvelope::new(agent_id, Vec::new())
            .expect("envelope construction must succeed")
            .to_bytes()
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
}
