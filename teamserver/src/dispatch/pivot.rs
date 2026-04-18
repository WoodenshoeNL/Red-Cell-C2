use red_cell_common::demon::DemonCommand;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::warn;

use crate::agent_events::{agent_mark_event, agent_new_event};
use crate::{AgentRegistry, DemonInitSecretConfig, DemonPacketParser, EventBus};

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
                context.allow_legacy_ctr,
                context.init_secret_config,
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

pub(super) async fn handle_pivot_list_callback(
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

pub(super) async fn handle_pivot_connect_callback(
    registry: &AgentRegistry,
    events: &EventBus,
    parent_agent_id: u32,
    request_id: u32,
    parser: &mut CallbackParser<'_>,
    allow_legacy_ctr: bool,
    init_secret_config: DemonInitSecretConfig,
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
    let listener_name =
        registry.listener_name(parent_agent_id).await.unwrap_or_else(|| "smb".to_owned());

    // Verify the inner envelope contains a DEMON_INIT command; any other
    // command type is invalid in a pivot connect payload regardless of
    // whether the agent is already registered or not.
    let inner_command = inner_demon_command_id(&inner).map_err(|error| {
        CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandPivot),
            message: error.to_string(),
        }
    })?;
    if inner_command != u32::from(DemonCommand::DemonInit) {
        return Err(CommandDispatchError::InvalidCallbackPayload {
            command_id: u32::from(DemonCommand::CommandPivot),
            message: "pivot connect payload did not contain a demon init envelope".to_owned(),
        });
    }

    // If the child agent is already registered this is a pivot reconnect.
    // Re-use the existing record (matching Havoc behaviour) instead of
    // calling parse_for_listener, which would reject the duplicate init.
    let child_agent = if registry.get(child_agent_id).await.is_some() {
        let timestamp = OffsetDateTime::now_utc().format(&Rfc3339).map_err(|e| {
            CommandDispatchError::InvalidCallbackPayload {
                command_id: u32::from(DemonCommand::CommandPivot),
                message: format!("failed to format reconnect timestamp: {e}"),
            }
        })?;
        // Reactivates the agent if it was marked dead and updates last_call_in.
        let updated = registry.set_last_call_in(child_agent_id, timestamp).await?;
        registry.add_link(parent_agent_id, child_agent_id).await?;
        events.broadcast(agent_mark_event(&updated));
        updated
    } else {
        let external_ip =
            registry.get(parent_agent_id).await.map(|agent| agent.external_ip).unwrap_or_default();
        let parsed =
            DemonPacketParser::with_init_secret_config(registry.clone(), init_secret_config)
                .with_allow_legacy_ctr(allow_legacy_ctr)
                .parse_for_listener(&inner, external_ip, &listener_name)
                .await;
        let agent = match parsed {
            Ok(crate::ParsedDemonPacket::Init(init)) => init.agent,
            Ok(_) => {
                return Err(CommandDispatchError::InvalidCallbackPayload {
                    command_id: u32::from(DemonCommand::CommandPivot),
                    message: "pivot connect payload did not contain a demon init envelope"
                        .to_owned(),
                });
            }
            Err(error) => {
                return Err(CommandDispatchError::InvalidCallbackPayload {
                    command_id: u32::from(DemonCommand::CommandPivot),
                    message: error.to_string(),
                });
            }
        };
        registry.add_link(parent_agent_id, agent.agent_id).await?;
        let pivots = registry.pivots(agent.agent_id).await;
        events.broadcast(agent_new_event(
            &listener_name,
            red_cell_common::demon::DEMON_MAGIC_VALUE,
            &agent,
            &pivots,
        ));
        agent
    };
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

pub(super) async fn handle_pivot_disconnect_callback(
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

pub(super) async fn handle_pivot_command_callback(
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
    if context.pivot_dispatch_depth >= context.max_pivot_chain_depth {
        let depth = context.pivot_dispatch_depth;
        let max_depth = context.max_pivot_chain_depth;

        warn!(
            agent_id = format_args!("0x{:08X}", agent_id),
            depth, max_depth, "pivot dispatch depth limit reached — dropping recursive dispatch"
        );

        // Write an audit log entry so operators have a record of which agent
        // triggered the limit.
        let occurred_at =
            OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_else(|_| String::from("unknown"));
        let details = serde_json::json!({
            "result_status": "failure",
            "parameters": { "depth": depth, "max_depth": max_depth },
        });
        if let Err(err) = context
            .database
            .audit_log()
            .create(&crate::AuditLogEntry {
                id: None,
                actor: format!("agent:{agent_id:08X}"),
                action: "pivot_depth_exceeded".to_owned(),
                target_kind: "agent".to_owned(),
                target_id: Some(format!("{agent_id:08X}")),
                details: Some(details),
                occurred_at,
            })
            .await
        {
            warn!(
                agent_id = format_args!("0x{:08X}", agent_id),
                error = %err,
                "failed to write pivot depth exceeded audit log entry"
            );
        }

        // Broadcast an error event so the operator console surfaces this as a
        // COMMAND_ERROR for the triggering agent.
        let event = agent_response_event(
            agent_id,
            u32::from(DemonCommand::CommandError),
            0,
            "Error",
            &format!(
                "[Pivot] Dispatch depth limit reached ({depth}/{max_depth}) — \
                 recursive pivot chain rejected for agent {agent_id:08X}"
            ),
            None,
        )?;
        context.events.broadcast(event);

        return Ok(None);
    }

    let mut dispatcher =
        CommandDispatcher::with_max_download_bytes(context.downloads.max_download_bytes());
    dispatcher.register_builtin_handlers(
        BuiltinHandlerDependencies {
            registry: context.registry.clone(),
            events: context.events.clone(),
            database: context.database.clone(),
            sockets: context.sockets.clone(),
            downloads: context.downloads.clone(),
            plugins: context.plugins.cloned(),
            pivot_dispatch_depth: context.pivot_dispatch_depth + 1,
            max_pivot_chain_depth: context.max_pivot_chain_depth,
            allow_legacy_ctr: context.allow_legacy_ctr,
            init_secret_config: context.init_secret_config.clone(),
        },
        false,
    );
    let response = dispatcher.collect_response_bytes(agent_id, packages).await?;
    Ok((!response.is_empty()).then_some(response))
}

pub(super) fn inner_demon_agent_id(bytes: &[u8]) -> Result<u32, DemonProtocolError> {
    Ok(red_cell_common::demon::DemonEnvelope::from_bytes(bytes)?.header.agent_id)
}

/// Extract the top-level command ID from a raw Demon envelope payload.
pub(super) fn inner_demon_command_id(bytes: &[u8]) -> Result<u32, DemonProtocolError> {
    let envelope = red_cell_common::demon::DemonEnvelope::from_bytes(bytes)?;
    if envelope.payload.len() < 4 {
        return Err(DemonProtocolError::BufferTooShort {
            context: "inner command id",
            expected: 4,
            actual: envelope.payload.len(),
        });
    }
    Ok(u32::from_be_bytes([
        envelope.payload[0],
        envelope.payload[1],
        envelope.payload[2],
        envelope.payload[3],
    ]))
}
