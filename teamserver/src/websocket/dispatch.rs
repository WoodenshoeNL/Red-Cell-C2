use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::{FlatInfo, Message, OperatorMessage};
use serde_json::Value;
use thiserror::Error;
use tracing::{debug, warn};

use super::command_enc::{
    build_jobs, flat_info_string, note_from_task, parse_agent_id, required_string, socket_command,
};
use super::events::{
    build_payload_message_event, build_payload_response_event, chat_message_event,
    format_diagnostic, teamserver_log_event,
};
use super::lifecycle::log_operator_action;
use crate::{
    AgentRegistry, AuditResultStatus, AuditWebhookNotifier, Database, EventBus,
    ListenerEventAction, ListenerManager, PayloadBuildError, PayloadBuilderService,
    ShutdownController, SocketRelayManager, action_from_mark, audit_details,
    authorize_agent_group_access, authorize_listener_access, listener_config_from_operator,
    listener_error_event, listener_event_for_action, listener_removed_event,
    operator_requests_start, parameter_object,
};

/// Attempt to serialize a value for audit logging, warning on failure instead
/// of silently discarding the error.
pub(super) fn serialize_for_audit<T: serde::Serialize>(value: &T, context: &str) -> Option<Value> {
    match serde_json::to_value(value) {
        Ok(v) => Some(v),
        Err(error) => {
            warn!(%error, context, "failed to serialize audit parameters");
            None
        }
    }
}

pub(super) async fn dispatch_operator_command<S>(
    state: &S,
    session: &crate::OperatorSession,
    message: OperatorMessage,
) where
    S: Clone + Send + Sync + 'static,
    EventBus: axum::extract::FromRef<S>,
    ListenerManager: axum::extract::FromRef<S>,
    AgentRegistry: axum::extract::FromRef<S>,
    SocketRelayManager: axum::extract::FromRef<S>,
    PayloadBuilderService: axum::extract::FromRef<S>,
    AuditWebhookNotifier: axum::extract::FromRef<S>,
    Database: axum::extract::FromRef<S>,
    ShutdownController: axum::extract::FromRef<S>,
{
    use axum::extract::FromRef;

    let events = EventBus::from_ref(state);
    let listeners = ListenerManager::from_ref(state);
    let registry = AgentRegistry::from_ref(state);
    let sockets = SocketRelayManager::from_ref(state);
    let payload_builder = PayloadBuilderService::from_ref(state);
    let webhooks = AuditWebhookNotifier::from_ref(state);
    let database = Database::from_ref(state);

    match message {
        OperatorMessage::ListenerNew(message) => {
            let name = message.info.name.clone().unwrap_or_default();
            let parameters = serialize_for_audit(&message.info, "listener.create");
            match listener_config_from_operator(&message.info) {
                Ok(config) => match listeners.create(config).await {
                    Ok(summary) => {
                        log_operator_action(
                            &database,
                            &webhooks,
                            &session.username,
                            "listener.create",
                            "listener",
                            Some(summary.name.clone()),
                            audit_details(
                                AuditResultStatus::Success,
                                None,
                                Some("create"),
                                parameters.clone(),
                            ),
                        )
                        .await;
                        events.broadcast(listener_event_for_action(
                            &session.username,
                            &summary,
                            ListenerEventAction::Created,
                        ));

                        if operator_requests_start(&message.info) {
                            match listeners.start(&summary.name).await {
                                Ok(started) => {
                                    log_operator_action(
                                        &database,
                                        &webhooks,
                                        &session.username,
                                        "listener.start",
                                        "listener",
                                        Some(started.name.clone()),
                                        audit_details(
                                            AuditResultStatus::Success,
                                            None,
                                            Some("start"),
                                            Some(parameter_object([(
                                                "listener",
                                                Value::String(started.name.clone()),
                                            )])),
                                        ),
                                    )
                                    .await;
                                    events.broadcast(listener_event_for_action(
                                        &session.username,
                                        &started,
                                        ListenerEventAction::Started,
                                    ));
                                }
                                Err(error) => {
                                    log_operator_action(
                                        &database,
                                        &webhooks,
                                        &session.username,
                                        "listener.start",
                                        "listener",
                                        Some(summary.name.clone()),
                                        audit_details(
                                            AuditResultStatus::Failure,
                                            None,
                                            Some("start"),
                                            Some(parameter_object([
                                                ("listener", Value::String(summary.name.clone())),
                                                ("error", Value::String(error.to_string())),
                                            ])),
                                        ),
                                    )
                                    .await;
                                    events.broadcast(listener_error_event(
                                        &session.username,
                                        &summary.name,
                                        &error,
                                    ));
                                }
                            }
                        }
                    }
                    Err(error) => {
                        log_operator_action(
                            &database,
                            &webhooks,
                            &session.username,
                            "listener.create",
                            "listener",
                            (!name.is_empty()).then_some(name.clone()),
                            audit_details(
                                AuditResultStatus::Failure,
                                None,
                                Some("create"),
                                Some(parameter_object([
                                    ("name", Value::String(name.clone())),
                                    ("error", Value::String(error.to_string())),
                                ])),
                            ),
                        )
                        .await;
                        events.broadcast(listener_error_event(&session.username, &name, &error));
                    }
                },
                Err(error) => {
                    log_operator_action(
                        &database,
                        &webhooks,
                        &session.username,
                        "listener.create",
                        "listener",
                        (!name.is_empty()).then_some(name.clone()),
                        audit_details(
                            AuditResultStatus::Failure,
                            None,
                            Some("create"),
                            Some(parameter_object([
                                ("name", Value::String(name.clone())),
                                ("error", Value::String(error.to_string())),
                            ])),
                        ),
                    )
                    .await;
                    events.broadcast(listener_error_event(&session.username, &name, &error));
                }
            }
        }
        OperatorMessage::ListenerEdit(message) => {
            let name = message.info.name.clone().unwrap_or_default();
            let parameters = serialize_for_audit(&message.info, "listener.update");
            match listener_config_from_operator(&message.info) {
                Ok(config) => match listeners.update(config).await {
                    Ok(summary) => {
                        log_operator_action(
                            &database,
                            &webhooks,
                            &session.username,
                            "listener.update",
                            "listener",
                            Some(summary.name.clone()),
                            audit_details(
                                AuditResultStatus::Success,
                                None,
                                Some("update"),
                                serialize_for_audit(&summary.config, "listener.update.config"),
                            ),
                        )
                        .await;
                        events.broadcast(listener_event_for_action(
                            &session.username,
                            &summary,
                            ListenerEventAction::Updated,
                        ));
                    }
                    Err(error) => {
                        log_operator_action(
                            &database,
                            &webhooks,
                            &session.username,
                            "listener.update",
                            "listener",
                            (!name.is_empty()).then_some(name.clone()),
                            audit_details(
                                AuditResultStatus::Failure,
                                None,
                                Some("update"),
                                Some(parameter_object([
                                    ("config", parameters.clone().unwrap_or(Value::Null)),
                                    ("error", Value::String(error.to_string())),
                                ])),
                            ),
                        )
                        .await;
                        events.broadcast(listener_error_event(&session.username, &name, &error));
                    }
                },
                Err(error) => {
                    log_operator_action(
                        &database,
                        &webhooks,
                        &session.username,
                        "listener.update",
                        "listener",
                        (!name.is_empty()).then_some(name.clone()),
                        audit_details(
                            AuditResultStatus::Failure,
                            None,
                            Some("update"),
                            Some(parameter_object([
                                ("config", parameters.unwrap_or(Value::Null)),
                                ("error", Value::String(error.to_string())),
                            ])),
                        ),
                    )
                    .await;
                    events.broadcast(listener_error_event(&session.username, &name, &error));
                }
            }
        }
        OperatorMessage::ListenerRemove(message) => {
            let name = message.info.name;
            match listeners.delete(&name).await {
                Ok(()) => {
                    log_operator_action(
                        &database,
                        &webhooks,
                        &session.username,
                        "listener.delete",
                        "listener",
                        (!name.is_empty()).then_some(name.clone()),
                        audit_details(
                            AuditResultStatus::Success,
                            None,
                            Some("delete"),
                            Some(parameter_object([("name", Value::String(name.clone()))])),
                        ),
                    )
                    .await;
                    events.broadcast(listener_removed_event(&session.username, &name));
                }
                Err(error) => {
                    log_operator_action(
                        &database,
                        &webhooks,
                        &session.username,
                        "listener.delete",
                        "listener",
                        (!name.is_empty()).then_some(name.clone()),
                        audit_details(
                            AuditResultStatus::Failure,
                            None,
                            Some("delete"),
                            Some(parameter_object([
                                ("name", Value::String(name.clone())),
                                ("error", Value::String(error.to_string())),
                            ])),
                        ),
                    )
                    .await;
                    events.broadcast(listener_error_event(&session.username, &name, &error));
                }
            }
        }
        OperatorMessage::ListenerMark(message) => {
            let name = message.info.name.clone();
            let mark = message.info.mark.clone();
            let result = match action_from_mark(&message.info.mark) {
                Ok(ListenerEventAction::Started) => listeners.start(&message.info.name).await,
                Ok(ListenerEventAction::Stopped) => listeners.stop(&message.info.name).await,
                Ok(ListenerEventAction::Created | ListenerEventAction::Updated) => unreachable!(),
                Err(error) => Err(error),
            };

            match result {
                Ok(summary) => {
                    let action = if summary.state.status == crate::ListenerStatus::Running {
                        ListenerEventAction::Started
                    } else {
                        ListenerEventAction::Stopped
                    };
                    let audit_action = if summary.state.status == crate::ListenerStatus::Running {
                        "listener.start"
                    } else {
                        "listener.stop"
                    };
                    log_operator_action(
                        &database,
                        &webhooks,
                        &session.username,
                        audit_action,
                        "listener",
                        Some(summary.name.clone()),
                        audit_details(
                            AuditResultStatus::Success,
                            None,
                            Some(mark.as_str()),
                            Some(parameter_object([("mark", Value::String(mark.clone()))])),
                        ),
                    )
                    .await;
                    events.broadcast(listener_event_for_action(
                        &session.username,
                        &summary,
                        action,
                    ));
                }
                Err(error) => {
                    let audit_action = if mark.eq_ignore_ascii_case("start")
                        || mark.eq_ignore_ascii_case("online")
                    {
                        "listener.start"
                    } else {
                        "listener.stop"
                    };
                    log_operator_action(
                        &database,
                        &webhooks,
                        &session.username,
                        audit_action,
                        "listener",
                        Some(name.clone()),
                        audit_details(
                            AuditResultStatus::Failure,
                            None,
                            Some(mark.as_str()),
                            Some(parameter_object([
                                ("mark", Value::String(mark.clone())),
                                ("error", Value::String(error.to_string())),
                            ])),
                        ),
                    )
                    .await;
                    events.broadcast(listener_error_event(&session.username, &name, &error));
                }
            }
        }
        OperatorMessage::AgentTask(message) => {
            if let Err(error) = handle_agent_task(
                &registry,
                &sockets,
                &events,
                &database,
                &webhooks,
                session,
                sanitize_agent_task(session, message),
            )
            .await
            {
                events.broadcast(teamserver_log_event(&session.username, &error.to_string()));
            }
        }
        OperatorMessage::AgentRemove(message) => {
            if let Err(error) = handle_agent_remove(
                &registry,
                &sockets,
                &events,
                &database,
                &webhooks,
                session,
                sanitize_agent_remove(session, message),
            )
            .await
            {
                events.broadcast(teamserver_log_event(&session.username, &error.to_string()));
            }
        }
        OperatorMessage::BuildPayloadRequest(message) => {
            let actor = session.username.clone();
            let events = events.clone();
            let listeners = listeners.clone();
            let payload_builder = payload_builder.clone();
            let database = database.clone();
            let webhooks = webhooks.clone();
            let listener_name = message.info.listener.clone();
            let arch = message.info.arch.clone();
            let format = message.info.format.clone();

            tokio::spawn(async move {
                let summary = match listeners.summary(&listener_name).await {
                    Ok(summary) => summary,
                    Err(error) => {
                        events.broadcast(build_payload_message_event(
                            &actor,
                            "Error",
                            &error.to_string(),
                        ));
                        return;
                    }
                };

                match payload_builder
                    .build_payload(&summary.config, &message.info, |entry| {
                        events.broadcast(build_payload_message_event(
                            &actor,
                            &entry.level,
                            &entry.message,
                        ));
                    })
                    .await
                {
                    Ok(artifact) => {
                        events.broadcast(build_payload_response_event(
                            &actor,
                            &artifact.file_name,
                            &artifact.format,
                            artifact.bytes.as_slice(),
                        ));
                        log_operator_action(
                            &database,
                            &webhooks,
                            &actor,
                            "payload.build",
                            "payload",
                            Some(listener_name.clone()),
                            audit_details(
                                AuditResultStatus::Success,
                                None,
                                None,
                                Some(parameter_object([
                                    ("listener", Value::String(listener_name)),
                                    ("arch", Value::String(arch)),
                                    ("format", Value::String(format)),
                                ])),
                            ),
                        )
                        .await;
                    }
                    Err(error) => {
                        events.broadcast(build_payload_message_event(
                            &actor,
                            "Error",
                            &error.to_string(),
                        ));

                        let diagnostic_params =
                            if let PayloadBuildError::CommandFailed { ref diagnostics, .. } = error
                            {
                                for diag in diagnostics {
                                    events.broadcast(build_payload_message_event(
                                        &actor,
                                        match diag.severity.as_str() {
                                            "error" | "fatal error" => "Error",
                                            "warning" => "Warning",
                                            _ => "Info",
                                        },
                                        &format_diagnostic(diag),
                                    ));
                                }
                                serialize_for_audit(diagnostics, "payload.build.diagnostics")
                            } else {
                                None
                            };

                        log_operator_action(
                            &database,
                            &webhooks,
                            &actor,
                            "payload.build",
                            "payload",
                            Some(listener_name.clone()),
                            audit_details(
                                AuditResultStatus::Failure,
                                None,
                                None,
                                Some(parameter_object(
                                    [
                                        ("listener", Value::String(listener_name)),
                                        ("arch", Value::String(arch)),
                                        ("format", Value::String(format)),
                                        ("error", Value::String(error.to_string())),
                                    ]
                                    .into_iter()
                                    .chain(
                                        diagnostic_params.into_iter().map(|d| ("diagnostics", d)),
                                    ),
                                )),
                            ),
                        )
                        .await;
                    }
                }
            });
        }
        OperatorMessage::ChatMessage(message) => {
            let text = flat_info_string(&message.info, &["Message", "Text"]).unwrap_or_default();
            if !text.trim().is_empty() {
                let trimmed = text.trim();
                events.broadcast(chat_message_event(&session.username, trimmed));
                log_operator_action(
                    &database,
                    &webhooks,
                    &session.username,
                    "operator.chat",
                    "operator",
                    Some(session.username.clone()),
                    audit_details(
                        AuditResultStatus::Success,
                        None,
                        Some("chat"),
                        Some(parameter_object([("message", Value::String(trimmed.to_owned()))])),
                    ),
                )
                .await;
            }
        }
        other => {
            debug!(
                connection_id = %session.connection_id,
                username = %session.username,
                event = ?other.event_code(),
                "operator websocket command has no registered handler yet"
            );
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum AgentCommandError {
    #[error("invalid agent id `{agent_id}`")]
    InvalidAgentId { agent_id: String },
    #[error("agent id is required")]
    MissingAgentId,
    #[error("agent note is required")]
    MissingNote,
    #[error("unsupported agent remove payload")]
    InvalidRemovePayload,
    #[error("invalid numeric command id `{command_id}`")]
    InvalidCommandId { command_id: String },
    #[error("missing required field `{field}`")]
    MissingField { field: &'static str },
    #[error("invalid boolean field `{field}`: `{value}`")]
    InvalidBooleanField { field: String, value: String },
    #[error("invalid numeric field `{field}`: `{value}`")]
    InvalidNumericField { field: String, value: String },
    #[error("invalid base64 field `{field}`: {message}")]
    InvalidBase64Field { field: String, message: String },
    #[error("unsupported process subcommand `{subcommand}`")]
    UnsupportedProcessSubcommand { subcommand: String },
    #[error("unsupported filesystem subcommand `{subcommand}`")]
    UnsupportedFilesystemSubcommand { subcommand: String },
    #[error("unsupported token subcommand `{subcommand}`")]
    UnsupportedTokenSubcommand { subcommand: String },
    #[error("unsupported socket subcommand `{subcommand}`")]
    UnsupportedSocketSubcommand { subcommand: String },
    #[error("unsupported kerberos subcommand `{subcommand}`")]
    UnsupportedKerberosSubcommand { subcommand: String },
    #[error("invalid hex task id `{task_id}`")]
    InvalidTaskId { task_id: String },
    #[error("unsupported injection way `{way}`")]
    UnsupportedInjectionWay { way: String },
    #[error("unsupported injection technique `{technique}`")]
    UnsupportedInjectionTechnique { technique: String },
    #[error(
        "unsupported command id {command_id}: not a recognized Demon command and no raw payload provided"
    )]
    UnsupportedCommandId { command_id: u32 },
    #[error("unsupported process architecture `{arch}`")]
    UnsupportedArchitecture { arch: String },
    #[error("invalid process create arguments: expected `state;verbose;piped;program;base64_args`")]
    InvalidProcessCreateArguments,
    #[error(transparent)]
    Teamserver(#[from] crate::TeamserverError),
    #[error(transparent)]
    Plugin(#[from] crate::PluginError),
    #[error(transparent)]
    SocketRelay(#[from] crate::SocketRelayError),
    /// Granular RBAC check (group access or listener access) failed.
    #[error(transparent)]
    Authorization(#[from] crate::AuthorizationError),
}

async fn handle_agent_task(
    registry: &AgentRegistry,
    sockets: &SocketRelayManager,
    events: &EventBus,
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    session: &crate::OperatorSession,
    message: Message<red_cell_common::operator::AgentTaskInfo>,
) -> Result<(), AgentCommandError> {
    let agent_id = parse_agent_id(&message.info.demon_id)?;

    authorize_agent_group_access(database, &session.username, agent_id).await?;

    if let Some(listener_name) = registry.listener_name(agent_id).await {
        authorize_listener_access(database, &session.username, &listener_name).await?;
    }

    let command = message.info.command.clone().unwrap_or_else(|| message.info.command_line.clone());
    let parameters = serialize_for_audit(&message.info, "agent.task");
    match execute_agent_task(registry, sockets, events, &session.username, session.role, message)
        .await
    {
        Ok(_) => {
            log_operator_action(
                database,
                webhooks,
                &session.username,
                "agent.task",
                "agent",
                Some(format!("{agent_id:08X}")),
                audit_details(
                    AuditResultStatus::Success,
                    Some(agent_id),
                    Some(command.as_str()),
                    parameters,
                ),
            )
            .await;
        }
        Err(error) => {
            log_operator_action(
                database,
                webhooks,
                &session.username,
                "agent.task",
                "agent",
                Some(format!("{agent_id:08X}")),
                audit_details(
                    AuditResultStatus::Failure,
                    Some(agent_id),
                    Some(command.as_str()),
                    Some(parameter_object([
                        ("task", parameters.unwrap_or(Value::Null)),
                        ("error", Value::String(error.to_string())),
                    ])),
                ),
            )
            .await;
            return Err(error);
        }
    }
    debug!(
        connection_id = %session.connection_id,
        username = %session.username,
        agent_id = format_args!("{agent_id:08X}"),
        "handled operator agent task command"
    );
    Ok(())
}

pub(crate) async fn execute_agent_task(
    registry: &AgentRegistry,
    sockets: &SocketRelayManager,
    events: &EventBus,
    actor: &str,
    caller_role: red_cell_common::config::OperatorRole,
    mut message: Message<red_cell_common::operator::AgentTaskInfo>,
) -> Result<usize, AgentCommandError> {
    message.head.user = actor.to_owned();
    let agent_id = parse_agent_id(&message.info.demon_id)?;
    let _agent =
        registry.get(agent_id).await.ok_or(crate::TeamserverError::AgentNotFound { agent_id })?;

    let queued_jobs = if let Some(note) = note_from_task(&message.info)? {
        registry.set_note(agent_id, note).await?;
        0
    } else if let Some(result) =
        handle_teamserver_socket_task(sockets, agent_id, &message.info).await?
    {
        events.broadcast(teamserver_log_event(actor, &result));
        0
    } else {
        let handled_by_plugin = if let Some(plugins) = crate::PluginRuntime::current()? {
            if let Some((command, args)) = plugins.match_registered_command(&message.info).await {
                plugins
                    .invoke_registered_command(&command, actor, caller_role, agent_id, args)
                    .await?
            } else {
                false
            }
        } else {
            false
        };

        if handled_by_plugin {
            0
        } else {
            let jobs = build_jobs(&message.info, actor)?;
            let queued_jobs = jobs.len();
            for job in jobs {
                if let Ok(Some(plugins)) = crate::PluginRuntime::current() {
                    if let Err(error) = plugins.emit_task_created(agent_id, &job).await {
                        tracing::warn!(
                            agent_id = format_args!("{agent_id:08X}"),
                            %error,
                            "failed to emit python task_created event"
                        );
                    }
                }
                registry.enqueue_job(agent_id, job).await?;
            }
            queued_jobs
        }
    };

    events.broadcast(OperatorMessage::AgentTask(message));
    Ok(queued_jobs)
}

async fn handle_agent_remove(
    registry: &AgentRegistry,
    sockets: &SocketRelayManager,
    events: &EventBus,
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    session: &crate::OperatorSession,
    message: Message<FlatInfo>,
) -> Result<(), AgentCommandError> {
    let Some(agent_id) = flat_info_string(&message.info, &["AgentID", "DemonID"]) else {
        return Err(AgentCommandError::InvalidRemovePayload);
    };
    let agent_id = parse_agent_id(&agent_id)?;
    match registry.remove(agent_id).await {
        Ok(_) => {
            log_operator_action(
                database,
                webhooks,
                &session.username,
                "agent.delete",
                "agent",
                Some(format!("{agent_id:08X}")),
                audit_details(
                    AuditResultStatus::Success,
                    Some(agent_id),
                    Some("delete"),
                    Some(parameter_object([(
                        "agent_id",
                        Value::String(format!("{agent_id:08X}")),
                    )])),
                ),
            )
            .await;
            sockets.remove_agent(agent_id).await;
            events.broadcast(OperatorMessage::AgentRemove(message));
        }
        Err(error) => {
            log_operator_action(
                database,
                webhooks,
                &session.username,
                "agent.delete",
                "agent",
                Some(format!("{agent_id:08X}")),
                audit_details(
                    AuditResultStatus::Failure,
                    Some(agent_id),
                    Some("delete"),
                    Some(parameter_object([
                        ("agent_id", Value::String(format!("{agent_id:08X}"))),
                        ("error", Value::String(error.to_string())),
                    ])),
                ),
            )
            .await;
            return Err(error.into());
        }
    }
    debug!(
        connection_id = %session.connection_id,
        username = %session.username,
        agent_id = format_args!("{agent_id:08X}"),
        "handled operator agent remove command"
    );
    Ok(())
}

pub(super) fn sanitize_agent_task(
    session: &crate::OperatorSession,
    mut message: Message<red_cell_common::operator::AgentTaskInfo>,
) -> Message<red_cell_common::operator::AgentTaskInfo> {
    message.head.user = session.username.clone();
    message
}

pub(super) fn sanitize_agent_remove(
    session: &crate::OperatorSession,
    mut message: Message<FlatInfo>,
) -> Message<FlatInfo> {
    message.head.user = session.username.clone();
    message
}

async fn handle_teamserver_socket_task(
    sockets: &SocketRelayManager,
    agent_id: u32,
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<Option<String>, AgentCommandError> {
    if info.command_id.trim() != u32::from(DemonCommand::CommandSocket).to_string() {
        return Ok(None);
    }

    let (_, command) = socket_command(info)?;
    let result = match command.as_str() {
        "socks add" => Some(
            sockets
                .add_socks_server(
                    agent_id,
                    &required_string(info, &["Params", "Arguments"], "Params")?,
                )
                .await?,
        ),
        "socks list" => Some(sockets.list_socks_servers(agent_id).await),
        "socks kill" => Some(
            sockets
                .remove_socks_server(
                    agent_id,
                    &required_string(info, &["Params", "Arguments"], "Params")?,
                )
                .await?,
        ),
        "socks clear" => Some(sockets.clear_socks_servers(agent_id).await?),
        _ => None,
    };

    Ok(result)
}
