//! Operator WebSocket handlers for agent commands (`AgentTask`, `AgentRemove`).
//!
//! [`execute_agent_task`] is re-exported so the REST API handlers can reuse
//! the same task-queueing pipeline as the WebSocket dispatch loop.

use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::{AgentTaskInfo, FlatInfo, Message, OperatorMessage};
use serde_json::Value;
use tracing::debug;

use super::serialize_for_audit;
use crate::websocket::command_enc::{
    build_jobs, flat_info_string, note_from_task, parse_agent_id, required_string, socket_command,
};
use crate::websocket::events::teamserver_log_event;
use crate::websocket::lifecycle::log_operator_action;
use crate::{
    AgentRegistry, AuditResultStatus, AuditWebhookNotifier, Database, EventBus, SocketRelayManager,
    audit_details, authorize_agent_group_access, authorize_listener_access, parameter_object,
};

use super::AgentCommandError;

pub(super) async fn handle_agent_task_message(
    registry: &AgentRegistry,
    sockets: &SocketRelayManager,
    events: &EventBus,
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    session: &crate::OperatorSession,
    message: Message<AgentTaskInfo>,
) {
    if let Err(error) = handle_agent_task(
        registry,
        sockets,
        events,
        database,
        webhooks,
        session,
        sanitize_agent_task(session, message),
    )
    .await
    {
        events.broadcast(teamserver_log_event(&session.username, &error.to_string()));
    }
}

pub(super) async fn handle_agent_remove_message(
    registry: &AgentRegistry,
    sockets: &SocketRelayManager,
    events: &EventBus,
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    session: &crate::OperatorSession,
    message: Message<FlatInfo>,
) {
    if let Err(error) = handle_agent_remove(
        registry,
        sockets,
        events,
        database,
        webhooks,
        session,
        sanitize_agent_remove(session, message),
    )
    .await
    {
        events.broadcast(teamserver_log_event(&session.username, &error.to_string()));
    }
}

async fn handle_agent_task(
    registry: &AgentRegistry,
    sockets: &SocketRelayManager,
    events: &EventBus,
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    session: &crate::OperatorSession,
    message: Message<AgentTaskInfo>,
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
    mut message: Message<AgentTaskInfo>,
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

fn sanitize_agent_task(
    session: &crate::OperatorSession,
    mut message: Message<AgentTaskInfo>,
) -> Message<AgentTaskInfo> {
    message.head.user = session.username.clone();
    message
}

fn sanitize_agent_remove(
    session: &crate::OperatorSession,
    mut message: Message<FlatInfo>,
) -> Message<FlatInfo> {
    message.head.user = session.username.clone();
    message
}

async fn handle_teamserver_socket_task(
    sockets: &SocketRelayManager,
    agent_id: u32,
    info: &AgentTaskInfo,
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
