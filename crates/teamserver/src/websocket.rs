//! Operator WebSocket endpoint and connection tracking.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::{
    Router,
    extract::{
        FromRef, State,
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
    routing::get,
};
use red_cell_common::AgentInfo;
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::{
    AgentEncryptionInfo as OperatorAgentEncryptionInfo, AgentInfo as OperatorAgentInfo,
    AgentPivotsInfo, EventCode, FlatInfo, Message, MessageHead, OperatorMessage, TeamserverLogInfo,
};
use serde_json::Value;
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::{
    AgentRegistry, AuthError, AuthService, AuthenticationFailure, AuthenticationResult, EventBus,
    Job, ListenerEventAction, ListenerManager, authorize_websocket_command,
    listener_config_from_operator, listener_error_event, listener_event_for_action,
    listener_removed_event, login_failure_message, login_success_message, operator_requests_start,
};

/// Tracks currently connected operator WebSocket clients.
#[derive(Debug, Clone, Default)]
pub struct OperatorConnectionManager {
    connections: Arc<RwLock<BTreeMap<Uuid, OperatorConnection>>>,
}

impl OperatorConnectionManager {
    /// Create an empty connection registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the number of currently open WebSocket connections.
    pub async fn connection_count(&self) -> usize {
        self.connections.read().await.len()
    }

    /// Return the number of authenticated WebSocket connections.
    pub async fn authenticated_count(&self) -> usize {
        self.connections
            .read()
            .await
            .values()
            .filter(|connection| connection.username.is_some())
            .count()
    }

    async fn register(&self, id: Uuid) {
        self.connections.write().await.insert(id, OperatorConnection { username: None });
    }

    async fn authenticate(&self, id: Uuid, username: String) {
        if let Some(connection) = self.connections.write().await.get_mut(&id) {
            connection.username = Some(username);
        }
    }

    async fn unregister(&self, id: Uuid) {
        self.connections.write().await.remove(&id);
    }
}

#[derive(Debug, Clone, Default)]
struct OperatorConnection {
    username: Option<String>,
}

/// Register the Havoc-compatible operator WebSocket endpoint at `/`.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    AuthService: FromRef<S>,
    EventBus: FromRef<S>,
    ListenerManager: FromRef<S>,
    AgentRegistry: FromRef<S>,
    OperatorConnectionManager: FromRef<S>,
{
    Router::new().route("/", get(websocket_handler::<S>))
}

/// Upgrade a `/havoc/` HTTP request to the operator WebSocket protocol.
pub async fn websocket_handler<S>(
    State(state): State<S>,
    websocket: WebSocketUpgrade,
) -> impl IntoResponse
where
    S: Clone + Send + Sync + 'static,
    AuthService: FromRef<S>,
    EventBus: FromRef<S>,
    ListenerManager: FromRef<S>,
    AgentRegistry: FromRef<S>,
    OperatorConnectionManager: FromRef<S>,
{
    websocket.on_upgrade(move |socket| handle_operator_socket(state, socket))
}

async fn handle_operator_socket<S>(state: S, mut socket: WebSocket)
where
    S: Clone + Send + Sync + 'static,
    AuthService: FromRef<S>,
    EventBus: FromRef<S>,
    ListenerManager: FromRef<S>,
    AgentRegistry: FromRef<S>,
    OperatorConnectionManager: FromRef<S>,
{
    let connection_id = Uuid::new_v4();
    let auth = AuthService::from_ref(&state);
    let connections = OperatorConnectionManager::from_ref(&state);

    connections.register(connection_id).await;

    if handle_authentication(&auth, &connections, connection_id, &mut socket).await.is_err() {
        cleanup_connection(&auth, &connections, connection_id).await;
        return;
    }

    let Some(session) = auth.session_for_connection(connection_id).await else {
        let _ = socket.send(WsMessage::Close(None)).await;
        cleanup_connection(&auth, &connections, connection_id).await;
        return;
    };

    info!(
        %connection_id,
        username = %session.username,
        token = %session.token,
        "operator authenticated"
    );

    let event_bus = EventBus::from_ref(&state);
    let mut event_receiver = event_bus.subscribe();
    if let Err(error) = send_session_snapshot(
        &mut socket,
        &event_bus,
        &ListenerManager::from_ref(&state),
        &AgentRegistry::from_ref(&state),
    )
    .await
    {
        warn!(
            connection_id = %session.connection_id,
            username = %session.username,
            %error,
            "failed to synchronize operator session state"
        );
        cleanup_connection(&auth, &connections, connection_id).await;
        return;
    }

    loop {
        tokio::select! {
            incoming = socket.recv() => {
                match handle_incoming_frame(&state, &mut socket, &session, incoming).await {
                    Ok(SocketLoopControl::Continue) => {}
                    Ok(SocketLoopControl::Break) | Err(()) => break,
                }
            }
            event = event_receiver.recv() => {
                let Some(event) = event else {
                    break;
                };

                if send_operator_message(&mut socket, &event).await.is_err() {
                    break;
                }
            }
        }
    }

    cleanup_connection(&auth, &connections, connection_id).await;
}

async fn handle_authentication(
    auth: &AuthService,
    connections: &OperatorConnectionManager,
    connection_id: Uuid,
    socket: &mut WebSocket,
) -> Result<(), ()> {
    let Some(frame) = socket.recv().await else {
        warn!(%connection_id, "operator websocket closed before authentication");
        return Err(());
    };

    let message = match frame {
        Ok(WsMessage::Text(payload)) => payload,
        Ok(WsMessage::Close(_)) => return Err(()),
        Ok(other) => {
            warn!(%connection_id, frame = ?other, "operator websocket requires text login frame");
            let _ = send_operator_message(
                socket,
                &login_failure_message("", &AuthenticationFailure::WrongPassword),
            )
            .await;
            let _ = socket.send(WsMessage::Close(None)).await;
            return Err(());
        }
        Err(error) => {
            warn!(%connection_id, %error, "failed to receive operator authentication frame");
            return Err(());
        }
    };

    let response = match auth.authenticate_message(connection_id, message.as_str()).await {
        Ok(AuthenticationResult::Success(success)) => {
            connections.authenticate(connection_id, success.username.clone()).await;
            login_success_message(&success.username, &success.token)
        }
        Ok(AuthenticationResult::Failure(failure)) => {
            send_login_error(socket, "", failure, connection_id).await;
            return Err(());
        }
        Err(AuthError::InvalidLoginMessage) => {
            send_login_error(socket, "", AuthenticationFailure::WrongPassword, connection_id).await;
            return Err(());
        }
        Err(AuthError::InvalidMessageJson(error)) => {
            warn!(%connection_id, %error, "failed to parse operator login message");
            send_login_error(socket, "", AuthenticationFailure::WrongPassword, connection_id).await;
            return Err(());
        }
    };

    if send_operator_message(socket, &response).await.is_err() {
        return Err(());
    }

    Ok(())
}

async fn handle_incoming_frame<S>(
    state: &S,
    socket: &mut WebSocket,
    session: &crate::OperatorSession,
    incoming: Option<Result<WsMessage, axum::Error>>,
) -> Result<SocketLoopControl, ()>
where
    S: Clone + Send + Sync + 'static,
    EventBus: FromRef<S>,
    ListenerManager: FromRef<S>,
    AgentRegistry: FromRef<S>,
{
    let Some(frame) = incoming else {
        return Ok(SocketLoopControl::Break);
    };

    match frame {
        Ok(WsMessage::Text(payload)) => {
            let message = match serde_json::from_str::<OperatorMessage>(payload.as_str()) {
                Ok(message) => message,
                Err(error) => {
                    warn!(
                        connection_id = %session.connection_id,
                        username = %session.username,
                        %error,
                        "failed to parse operator websocket message"
                    );
                    let _ = socket.send(WsMessage::Close(None)).await;
                    return Err(());
                }
            };

            match authorize_websocket_command(session, &message) {
                Ok(permission) => {
                    debug!(
                        connection_id = %session.connection_id,
                        username = %session.username,
                        role = ?session.role,
                        permission = permission.as_str(),
                        event = ?message.event_code(),
                        "dispatching operator websocket command"
                    );

                    dispatch_operator_command(state, session, message).await;
                    Ok(SocketLoopControl::Continue)
                }
                Err(error) => {
                    warn!(
                        connection_id = %session.connection_id,
                        username = %session.username,
                        role = ?session.role,
                        %error,
                        "rejecting unauthorized operator websocket command"
                    );
                    let _ = socket.send(WsMessage::Close(None)).await;
                    Err(())
                }
            }
        }
        Ok(WsMessage::Close(_)) => Ok(SocketLoopControl::Break),
        Ok(WsMessage::Ping(payload)) => {
            if socket.send(WsMessage::Pong(payload)).await.is_err() {
                return Err(());
            }
            Ok(SocketLoopControl::Continue)
        }
        Ok(WsMessage::Pong(_)) => Ok(SocketLoopControl::Continue),
        Ok(WsMessage::Binary(_)) => Ok(SocketLoopControl::Continue),
        Err(error) => {
            warn!(
                connection_id = %session.connection_id,
                username = %session.username,
                %error,
                "operator websocket receive loop failed"
            );
            Err(())
        }
    }
}

async fn dispatch_operator_command<S>(
    state: &S,
    session: &crate::OperatorSession,
    message: OperatorMessage,
) where
    S: Clone + Send + Sync + 'static,
    EventBus: FromRef<S>,
    ListenerManager: FromRef<S>,
    AgentRegistry: FromRef<S>,
{
    let events = EventBus::from_ref(state);
    let listeners = ListenerManager::from_ref(state);
    let registry = AgentRegistry::from_ref(state);

    match message {
        OperatorMessage::ListenerNew(message) => {
            let name = message.info.name.clone().unwrap_or_default();
            match listener_config_from_operator(&message.info) {
                Ok(config) => match listeners.create(config).await {
                    Ok(summary) => {
                        events.broadcast(listener_event_for_action(
                            &session.username,
                            &summary,
                            ListenerEventAction::Created,
                        ));

                        if operator_requests_start(&message.info) {
                            match listeners.start(&summary.name).await {
                                Ok(started) => {
                                    events.broadcast(listener_event_for_action(
                                        &session.username,
                                        &started,
                                        ListenerEventAction::Started,
                                    ));
                                }
                                Err(error) => {
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
                        events.broadcast(listener_error_event(&session.username, &name, &error));
                    }
                },
                Err(error) => {
                    events.broadcast(listener_error_event(&session.username, &name, &error));
                }
            }
        }
        OperatorMessage::ListenerEdit(message) => {
            let name = message.info.name.clone().unwrap_or_default();
            match listener_config_from_operator(&message.info) {
                Ok(config) => match listeners.update(config).await {
                    Ok(summary) => {
                        events.broadcast(listener_event_for_action(
                            &session.username,
                            &summary,
                            ListenerEventAction::Updated,
                        ));
                    }
                    Err(error) => {
                        events.broadcast(listener_error_event(&session.username, &name, &error));
                    }
                },
                Err(error) => {
                    events.broadcast(listener_error_event(&session.username, &name, &error));
                }
            }
        }
        OperatorMessage::ListenerRemove(message) => {
            let name = message.info.name;
            match listeners.delete(&name).await {
                Ok(()) => {
                    events.broadcast(listener_removed_event(&session.username, &name));
                }
                Err(error) => {
                    events.broadcast(listener_error_event(&session.username, &name, &error));
                }
            }
        }
        OperatorMessage::ListenerMark(message) => {
            let result = if message.info.mark.eq_ignore_ascii_case("online")
                || message.info.mark.eq_ignore_ascii_case("start")
            {
                listeners.start(&message.info.name).await
            } else if message.info.mark.eq_ignore_ascii_case("offline")
                || message.info.mark.eq_ignore_ascii_case("stop")
            {
                listeners.stop(&message.info.name).await
            } else {
                Err(crate::ListenerManagerError::UnsupportedMark {
                    mark: message.info.mark.clone(),
                })
            };

            match result {
                Ok(summary) => {
                    let action = if summary.state.status == crate::ListenerStatus::Running {
                        ListenerEventAction::Started
                    } else {
                        ListenerEventAction::Stopped
                    };
                    events.broadcast(listener_event_for_action(
                        &session.username,
                        &summary,
                        action,
                    ));
                }
                Err(error) => {
                    events.broadcast(listener_error_event(
                        &session.username,
                        &message.info.name,
                        &error,
                    ));
                }
            }
        }
        OperatorMessage::AgentTask(message) => {
            if let Err(error) = handle_agent_task(
                &registry,
                &events,
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
                &events,
                session,
                sanitize_agent_remove(session, message),
            )
            .await
            {
                events.broadcast(teamserver_log_event(&session.username, &error.to_string()));
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
enum AgentCommandError {
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
    #[error(transparent)]
    Teamserver(#[from] crate::TeamserverError),
}

async fn handle_agent_task(
    registry: &AgentRegistry,
    events: &EventBus,
    session: &crate::OperatorSession,
    message: Message<red_cell_common::operator::AgentTaskInfo>,
) -> Result<(), AgentCommandError> {
    let agent_id = parse_agent_id(&message.info.demon_id)?;
    let _agent =
        registry.get(agent_id).await.ok_or(crate::TeamserverError::AgentNotFound { agent_id })?;

    if let Some(note) = note_from_task(&message.info)? {
        registry.set_note(agent_id, note).await?;
    } else {
        registry.enqueue_job(agent_id, build_job(&message.info)?).await?;
    }

    events.broadcast(OperatorMessage::AgentTask(message));
    debug!(
        connection_id = %session.connection_id,
        username = %session.username,
        agent_id = format_args!("{agent_id:08X}"),
        "handled operator agent task command"
    );
    Ok(())
}

async fn handle_agent_remove(
    registry: &AgentRegistry,
    events: &EventBus,
    session: &crate::OperatorSession,
    message: Message<FlatInfo>,
) -> Result<(), AgentCommandError> {
    let Some(agent_id) = flat_info_string(&message.info, &["AgentID", "DemonID"]) else {
        return Err(AgentCommandError::InvalidRemovePayload);
    };
    let agent_id = parse_agent_id(&agent_id)?;
    registry.remove(agent_id).await?;
    events.broadcast(OperatorMessage::AgentRemove(message));
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
    mut message: Message<red_cell_common::operator::AgentTaskInfo>,
) -> Message<red_cell_common::operator::AgentTaskInfo> {
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

fn build_job(info: &red_cell_common::operator::AgentTaskInfo) -> Result<Job, AgentCommandError> {
    let command_id = info.command_id.trim();
    let request_id = u32::from_str_radix(info.task_id.trim(), 16).unwrap_or_default();
    let payload = task_payload(info);

    if is_teamserver_note_command(info) {
        return Err(AgentCommandError::MissingNote);
    }

    let command = if is_exit_command(info) {
        u32::from(DemonCommand::CommandExit)
    } else {
        command_id.parse::<u32>().map_err(|_| AgentCommandError::InvalidCommandId {
            command_id: command_id.to_owned(),
        })?
    };

    Ok(Job {
        command,
        request_id,
        payload,
        command_line: info.command_line.clone(),
        task_id: info.task_id.clone(),
        created_at: OffsetDateTime::now_utc().unix_timestamp().to_string(),
    })
}

fn task_payload(info: &red_cell_common::operator::AgentTaskInfo) -> Vec<u8> {
    if is_exit_command(info) {
        return exit_method(info).to_be_bytes().to_vec();
    }

    flat_info_string_from_extra(&info.extra, &["PayloadBase64", "Payload"])
        .map(|payload| payload.into_bytes())
        .unwrap_or_default()
}

fn note_from_task(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<Option<String>, AgentCommandError> {
    if !is_teamserver_note_command(info) {
        return Ok(None);
    }

    let note = info
        .arguments
        .clone()
        .or_else(|| info.task_message.clone())
        .or_else(|| flat_info_string_from_extra(&info.extra, &["Note", "note"]))
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or(AgentCommandError::MissingNote)?;

    Ok(Some(note))
}

fn is_teamserver_note_command(info: &red_cell_common::operator::AgentTaskInfo) -> bool {
    info.command_id.eq_ignore_ascii_case("Teamserver")
        && info.command.as_deref().is_some_and(|command| {
            command.eq_ignore_ascii_case("note") || command.eq_ignore_ascii_case("agent::note")
        })
}

fn is_exit_command(info: &red_cell_common::operator::AgentTaskInfo) -> bool {
    info.command_id.trim() == u32::from(DemonCommand::CommandExit).to_string()
        || info.command.as_deref().is_some_and(|command| {
            command.eq_ignore_ascii_case("kill") || command.eq_ignore_ascii_case("agent::kill")
        })
}

fn exit_method(info: &red_cell_common::operator::AgentTaskInfo) -> u32 {
    match info.arguments.as_deref() {
        Some(argument) if argument.eq_ignore_ascii_case("process") => 2,
        _ => 1,
    }
}

fn parse_agent_id(agent_id: &str) -> Result<u32, AgentCommandError> {
    let trimmed = agent_id.trim();
    if trimmed.is_empty() {
        return Err(AgentCommandError::MissingAgentId);
    }

    u32::from_str_radix(trimmed.trim_start_matches("0x").trim_start_matches("0X"), 16)
        .map_err(|_| AgentCommandError::InvalidAgentId { agent_id: trimmed.to_owned() })
}

fn flat_info_string(info: &FlatInfo, keys: &[&str]) -> Option<String> {
    flat_info_string_from_extra(&info.fields, keys)
}

fn flat_info_string_from_extra(extra: &BTreeMap<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| extra.get(*key)).and_then(Value::as_str).map(ToOwned::to_owned)
}

fn teamserver_log_event(user: &str, text: &str) -> OperatorMessage {
    OperatorMessage::TeamserverLog(Message {
        head: MessageHead {
            event: EventCode::Teamserver,
            user: user.to_owned(),
            timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
            one_time: String::new(),
        },
        info: TeamserverLogInfo { text: text.to_owned() },
    })
}

#[derive(Debug, Error)]
enum SnapshotSyncError {
    #[error(transparent)]
    Send(#[from] SendMessageError),
    #[error(transparent)]
    Listener(#[from] crate::ListenerManagerError),
}

async fn send_session_snapshot(
    socket: &mut WebSocket,
    events: &EventBus,
    listeners: &ListenerManager,
    registry: &AgentRegistry,
) -> Result<(), SnapshotSyncError> {
    for summary in listeners
        .list()
        .await?
        .into_iter()
        .filter(|summary| summary.state.status == crate::ListenerStatus::Running)
    {
        send_operator_message(
            socket,
            &listener_event_for_action("teamserver", &summary, ListenerEventAction::Created),
        )
        .await?;
    }

    for message in events.recent_teamserver_logs() {
        send_operator_message(socket, &message).await?;
    }

    for agent in registry.list_active().await {
        send_operator_message(socket, &agent_snapshot_event(&agent)).await?;
    }

    Ok(())
}

fn agent_snapshot_event(agent: &AgentInfo) -> OperatorMessage {
    OperatorMessage::AgentNew(Box::new(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "teamserver".to_owned(),
            timestamp: agent.last_call_in.clone(),
            one_time: "true".to_owned(),
        },
        info: OperatorAgentInfo {
            active: agent.active.to_string(),
            background_check: false,
            domain_name: agent.domain_name.clone(),
            elevated: agent.elevated,
            encryption: OperatorAgentEncryptionInfo {
                aes_key: agent.encryption.aes_key.clone(),
                aes_iv: agent.encryption.aes_iv.clone(),
            },
            internal_ip: agent.internal_ip.clone(),
            external_ip: agent.external_ip.clone(),
            first_call_in: agent.first_call_in.clone(),
            last_call_in: agent.last_call_in.clone(),
            hostname: agent.hostname.clone(),
            listener: "null".to_owned(),
            magic_value: "deadbeef".to_owned(),
            name_id: agent.name_id(),
            os_arch: agent.os_arch.clone(),
            os_build: String::new(),
            os_version: agent.os_version.clone(),
            pivots: AgentPivotsInfo::default(),
            port_fwds: Vec::new(),
            process_arch: agent.process_arch.clone(),
            process_name: agent.process_name.clone(),
            process_pid: agent.process_pid.to_string(),
            process_ppid: agent.process_ppid.to_string(),
            process_path: agent.process_name.clone(),
            reason: agent.reason.clone(),
            note: agent.note.clone(),
            sleep_delay: Value::from(agent.sleep_delay),
            sleep_jitter: Value::from(agent.sleep_jitter),
            kill_date: agent.kill_date.map_or(Value::Null, Value::from),
            working_hours: agent.working_hours.map_or(Value::Null, Value::from),
            socks_cli: Vec::new(),
            socks_cli_mtx: None,
            socks_svr: Vec::new(),
            tasked_once: false,
            username: agent.username.clone(),
            pivot_parent: String::new(),
        },
    }))
}

async fn cleanup_connection(
    auth: &AuthService,
    connections: &OperatorConnectionManager,
    connection_id: Uuid,
) {
    let _ = auth.remove_connection(connection_id).await;
    connections.unregister(connection_id).await;
}

async fn send_operator_message(
    socket: &mut WebSocket,
    message: &OperatorMessage,
) -> Result<(), SendMessageError> {
    let payload = serde_json::to_string(message)?;
    socket.send(WsMessage::Text(payload.into())).await?;
    Ok(())
}

async fn send_login_error(
    socket: &mut WebSocket,
    user: &str,
    failure: AuthenticationFailure,
    connection_id: Uuid,
) {
    if let Err(error) = send_operator_message(socket, &login_failure_message(user, &failure)).await
    {
        warn!(%connection_id, %error, "failed to send operator websocket authentication error");
    }

    let _ = socket.send(WsMessage::Close(None)).await;
}

enum SocketLoopControl {
    Continue,
    Break,
}

#[derive(Debug, Error)]
enum SendMessageError {
    #[error("failed to serialize operator message: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("failed to send operator websocket message: {0}")]
    Socket(#[from] axum::Error),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use axum::extract::FromRef;
    use futures_util::{SinkExt, StreamExt};
    use red_cell_common::{
        AgentEncryptionInfo,
        config::Profile,
        demon::DemonCommand,
        operator::{
            AgentTaskInfo, EventCode, FlatInfo, LoginInfo, Message, MessageHead, OperatorMessage,
            SessionCode, TeamserverLogInfo,
        },
    };
    use serde_json::Value;
    use tokio::net::TcpListener;
    use tokio::time::timeout;
    use tokio_tungstenite::{connect_async, tungstenite::Message as ClientMessage};
    use uuid::Uuid;

    use super::{OperatorConnectionManager, routes, teamserver_log_event};
    use crate::{AgentRegistry, AuthService, Database, EventBus, ListenerManager, hash_password};

    #[derive(Clone)]
    struct TestState {
        auth: AuthService,
        events: EventBus,
        connections: OperatorConnectionManager,
        registry: AgentRegistry,
        listeners: ListenerManager,
    }

    impl TestState {
        async fn new() -> Self {
            let profile = Profile::parse(
                r#"
                Teamserver {
                  Host = "127.0.0.1"
                  Port = 40056
                }

                Operators {
                  user "operator" {
                    Password = "password1234"
                    Role = "Operator"
                  }
                  user "analyst" {
                    Password = "readonly"
                    Role = "Analyst"
                  }
                  user "admin" {
                    Password = "adminpass"
                    Role = "Admin"
                  }
                }

                Demon {}
                "#,
            )
            .expect("test profile should parse");

            let database = Database::connect_in_memory().await.expect("database should initialize");
            let registry = AgentRegistry::new(database.clone());
            let events = EventBus::default();

            Self {
                auth: AuthService::from_profile(&profile),
                events: events.clone(),
                connections: OperatorConnectionManager::new(),
                registry: registry.clone(),
                listeners: ListenerManager::new(database, registry, events),
            }
        }
    }

    impl FromRef<TestState> for AuthService {
        fn from_ref(input: &TestState) -> Self {
            input.auth.clone()
        }
    }

    impl FromRef<TestState> for EventBus {
        fn from_ref(input: &TestState) -> Self {
            input.events.clone()
        }
    }

    impl FromRef<TestState> for OperatorConnectionManager {
        fn from_ref(input: &TestState) -> Self {
            input.connections.clone()
        }
    }

    impl FromRef<TestState> for AgentRegistry {
        fn from_ref(input: &TestState) -> Self {
            input.registry.clone()
        }
    }

    impl FromRef<TestState> for ListenerManager {
        fn from_ref(input: &TestState) -> Self {
            input.listeners.clone()
        }
    }

    #[tokio::test]
    async fn connection_manager_tracks_registered_and_authenticated_clients() {
        let manager = OperatorConnectionManager::new();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();

        manager.register(first).await;
        manager.register(second).await;
        manager.authenticate(first, "operator".to_owned()).await;

        assert_eq!(manager.connection_count().await, 2);
        assert_eq!(manager.authenticated_count().await, 1);

        manager.unregister(first).await;
        manager.unregister(second).await;

        assert_eq!(manager.connection_count().await, 0);
        assert_eq!(manager.authenticated_count().await, 0);
    }

    #[tokio::test]
    async fn websocket_requires_login_before_other_messages() {
        let state = TestState::new().await;
        let connection_registry = state.connections.clone();
        let (mut socket, server) = spawn_server(state).await;

        let non_login = serde_json::to_string(&OperatorMessage::TeamserverLog(Message {
            head: MessageHead {
                event: EventCode::Teamserver,
                user: "operator".to_owned(),
                timestamp: String::new(),
                one_time: String::new(),
            },
            info: TeamserverLogInfo { text: "hello".to_owned() },
        }))
        .expect("message should serialize");

        socket.send(ClientMessage::Text(non_login.into())).await.expect("message should send");

        let response = read_operator_message(&mut socket).await;
        assert!(matches!(response, OperatorMessage::InitConnectionError(_)));

        wait_for_connection_count(&connection_registry, 0).await;
        server.abort();
    }

    #[tokio::test]
    async fn websocket_forwards_event_bus_messages_after_login() {
        let state = TestState::new().await;
        let event_bus = state.events.clone();
        let connection_registry = state.connections.clone();
        let auth = state.auth.clone();
        let (mut socket, server) = spawn_server(state).await;

        socket
            .send(ClientMessage::Text(login_message("operator", "password1234").into()))
            .await
            .expect("login should send");

        let response = read_operator_message(&mut socket).await;
        assert!(matches!(response, OperatorMessage::InitConnectionSuccess(_)));
        assert_eq!(connection_registry.connection_count().await, 1);
        assert_eq!(connection_registry.authenticated_count().await, 1);
        assert_eq!(auth.session_count().await, 1);

        let event = OperatorMessage::TeamserverLog(Message {
            head: MessageHead {
                event: EventCode::Teamserver,
                user: "teamserver".to_owned(),
                timestamp: "12:34:56".to_owned(),
                one_time: String::new(),
            },
            info: TeamserverLogInfo { text: "broadcast".to_owned() },
        });

        assert_eq!(event_bus.broadcast(event.clone()), 1);
        assert_eq!(read_operator_message(&mut socket).await, event);

        socket.close(None).await.expect("close should send");
        wait_for_connection_count(&connection_registry, 0).await;
        assert_eq!(auth.session_count().await, 0);
        server.abort();
    }

    #[tokio::test]
    async fn websocket_sends_session_snapshot_after_login() {
        let state = TestState::new().await;
        let registry = state.registry.clone();
        let listeners = state.listeners.clone();
        let events = state.events.clone();
        registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
        listeners.create(sample_http_listener("alpha", 0)).await.expect("listener should persist");
        listeners.start("alpha").await.expect("listener should start");
        let expected_log = teamserver_log_event("teamserver", "snapshot entry");
        assert_eq!(events.broadcast(expected_log.clone()), 0);
        let (mut socket, server) = spawn_server(state).await;

        login(&mut socket, "operator", "password1234").await;

        let listener_event = read_operator_message(&mut socket).await;
        let OperatorMessage::ListenerNew(message) = listener_event else {
            panic!("expected listener snapshot event");
        };
        assert_eq!(message.info.name.as_deref(), Some("alpha"));
        assert_eq!(message.info.status.as_deref(), Some("Online"));

        assert_eq!(read_operator_message(&mut socket).await, expected_log);

        let agent_event = read_operator_message(&mut socket).await;
        let OperatorMessage::AgentNew(message) = agent_event else {
            panic!("expected agent snapshot event");
        };
        assert_eq!(message.info.name_id, "DEADBEEF");
        assert_eq!(message.info.listener, "null");
        assert_eq!(message.info.magic_value, "deadbeef");

        socket.close(None).await.expect("close should send");
        server.abort();
    }

    #[tokio::test]
    async fn websocket_closes_when_authenticated_operator_lacks_permission() {
        let state = TestState::new().await;
        let connection_registry = state.connections.clone();
        let (mut socket, server) = spawn_server(state).await;

        socket
            .send(ClientMessage::Text(login_message("analyst", "readonly").into()))
            .await
            .expect("login should send");
        let response = read_operator_message(&mut socket).await;
        assert!(matches!(response, OperatorMessage::InitConnectionSuccess(_)));

        let task = serde_json::to_string(&OperatorMessage::AgentTask(Message {
            head: MessageHead {
                event: EventCode::Session,
                user: "analyst".to_owned(),
                timestamp: String::new(),
                one_time: String::new(),
            },
            info: AgentTaskInfo {
                task_id: "1".to_owned(),
                command_line: "shell whoami".to_owned(),
                demon_id: "deadbeef".to_owned(),
                command_id: SessionCode::AgentTask.as_u32().to_string(),
                agent_type: None,
                task_message: None,
                command: None,
                sub_command: None,
                arguments: None,
                extra: Default::default(),
            },
        }))
        .expect("task should serialize");

        socket.send(ClientMessage::Text(task.into())).await.expect("task should send");

        let close_frame = timeout(Duration::from_secs(2), socket.next())
            .await
            .expect("socket should close")
            .expect("close frame should be present")
            .expect("close frame should be valid");
        assert!(matches!(close_frame, ClientMessage::Close(_)));

        wait_for_connection_count(&connection_registry, 0).await;
        server.abort();
    }

    #[tokio::test]
    async fn websocket_agent_task_enqueues_job_and_broadcasts_event() {
        let state = TestState::new().await;
        let registry = state.registry.clone();
        registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
        let (mut sender, server) = spawn_server(state.clone()).await;
        let (mut observer, _) = spawn_server(state).await;

        login(&mut sender, "operator", "password1234").await;
        login(&mut observer, "operator", "password1234").await;
        let snapshot = read_operator_message(&mut sender).await;
        assert!(matches!(snapshot, OperatorMessage::AgentNew(_)));
        let snapshot = read_operator_message(&mut observer).await;
        assert!(matches!(snapshot, OperatorMessage::AgentNew(_)));

        sender
            .send(ClientMessage::Text(
                agent_task_message(
                    "operator",
                    AgentTaskInfo {
                        task_id: "2A".to_owned(),
                        command_line: "checkin".to_owned(),
                        demon_id: "DEADBEEF".to_owned(),
                        command_id: u32::from(DemonCommand::CommandCheckin).to_string(),
                        ..AgentTaskInfo::default()
                    },
                )
                .into(),
            ))
            .await
            .expect("task should send");

        let event = read_operator_message(&mut observer).await;
        let OperatorMessage::AgentTask(message) = event else {
            panic!("expected agent task broadcast");
        };
        assert_eq!(message.head.user, "operator");
        assert_eq!(message.info.demon_id, "DEADBEEF");

        let queued = registry.queued_jobs(0xDEAD_BEEF).await.expect("queue should load");
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].command, u32::from(DemonCommand::CommandCheckin));
        assert_eq!(queued[0].request_id, 0x2A);
        assert_eq!(queued[0].command_line, "checkin");

        sender.close(None).await.expect("close should send");
        observer.close(None).await.expect("close should send");
        server.abort();
    }

    #[tokio::test]
    async fn websocket_agent_note_updates_registry() {
        let state = TestState::new().await;
        let registry = state.registry.clone();
        registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
        let (mut socket, server) = spawn_server(state).await;

        login(&mut socket, "operator", "password1234").await;

        socket
            .send(ClientMessage::Text(
                agent_task_message(
                    "operator",
                    AgentTaskInfo {
                        task_id: "2B".to_owned(),
                        command_line: "note tracked through vpn".to_owned(),
                        demon_id: "DEADBEEF".to_owned(),
                        command_id: "Teamserver".to_owned(),
                        command: Some("note".to_owned()),
                        arguments: Some("tracked through vpn".to_owned()),
                        ..AgentTaskInfo::default()
                    },
                )
                .into(),
            ))
            .await
            .expect("note should send");

        timeout(Duration::from_secs(2), async {
            loop {
                let updated = registry.get(0xDEAD_BEEF).await.expect("agent should exist");
                if updated.note == "tracked through vpn" {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("agent note should update");

        let updated = registry.get(0xDEAD_BEEF).await.expect("agent should exist");
        assert_eq!(updated.note, "tracked through vpn");

        socket.close(None).await.expect("close should send");
        server.abort();
    }

    #[tokio::test]
    async fn websocket_agent_remove_deletes_agent_for_admins() {
        let state = TestState::new().await;
        let registry = state.registry.clone();
        registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
        let (mut socket, server) = spawn_server(state).await;

        login(&mut socket, "admin", "adminpass").await;
        let snapshot = read_operator_message(&mut socket).await;
        assert!(matches!(snapshot, OperatorMessage::AgentNew(_)));

        socket
            .send(ClientMessage::Text(agent_remove_message("admin", "DEADBEEF").into()))
            .await
            .expect("remove should send");

        let event = read_operator_message(&mut socket).await;
        assert!(matches!(event, OperatorMessage::AgentRemove(_)));
        assert!(registry.get(0xDEAD_BEEF).await.is_none());

        socket.close(None).await.expect("close should send");
        server.abort();
    }

    #[tokio::test]
    async fn websocket_reports_missing_agents_for_agent_commands() {
        let state = TestState::new().await;
        let (mut socket, server) = spawn_server(state).await;

        login(&mut socket, "operator", "password1234").await;

        socket
            .send(ClientMessage::Text(
                agent_task_message(
                    "operator",
                    AgentTaskInfo {
                        task_id: "2C".to_owned(),
                        command_line: "checkin".to_owned(),
                        demon_id: "DEADBEEF".to_owned(),
                        command_id: u32::from(DemonCommand::CommandCheckin).to_string(),
                        ..AgentTaskInfo::default()
                    },
                )
                .into(),
            ))
            .await
            .expect("task should send");

        let event = read_operator_message(&mut socket).await;
        let OperatorMessage::TeamserverLog(message) = event else {
            panic!("expected teamserver log");
        };
        assert!(message.info.text.contains("not found"));

        socket.close(None).await.expect("close should send");
        server.abort();
    }

    async fn spawn_server(
        state: TestState,
    ) -> (
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        tokio::task::JoinHandle<()>,
    ) {
        let app = routes::<TestState>().with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener should bind");
        let addr = listener.local_addr().expect("listener should expose addr");
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let (socket, _) =
            connect_async(format!("ws://{addr}/")).await.expect("websocket should connect");

        (socket, server)
    }

    async fn read_operator_message(
        socket: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) -> OperatorMessage {
        let frame = timeout(Duration::from_secs(2), socket.next())
            .await
            .expect("socket should yield a frame")
            .expect("frame should be present")
            .expect("frame should decode");

        match frame {
            ClientMessage::Text(payload) => {
                serde_json::from_str(payload.as_str()).expect("message should parse")
            }
            other => panic!("unexpected frame: {other:?}"),
        }
    }

    async fn wait_for_connection_count(manager: &OperatorConnectionManager, expected: usize) {
        timeout(Duration::from_secs(2), async {
            loop {
                if manager.connection_count().await == expected {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("connection registry should reach expected size");
    }

    fn login_message(user: &str, password: &str) -> String {
        serde_json::to_string(&OperatorMessage::Login(Message {
            head: MessageHead {
                event: EventCode::InitConnection,
                user: user.to_owned(),
                timestamp: String::new(),
                one_time: String::new(),
            },
            info: LoginInfo { user: user.to_owned(), password: hash_password(password) },
        }))
        .expect("login should serialize")
    }

    fn agent_task_message(user: &str, info: AgentTaskInfo) -> String {
        serde_json::to_string(&OperatorMessage::AgentTask(Message {
            head: MessageHead {
                event: EventCode::Session,
                user: user.to_owned(),
                timestamp: String::new(),
                one_time: String::new(),
            },
            info,
        }))
        .expect("task should serialize")
    }

    fn agent_remove_message(user: &str, demon_id: &str) -> String {
        let mut fields = BTreeMap::new();
        fields.insert("DemonID".to_owned(), Value::String(demon_id.to_owned()));

        serde_json::to_string(&OperatorMessage::AgentRemove(Message {
            head: MessageHead {
                event: EventCode::Session,
                user: user.to_owned(),
                timestamp: String::new(),
                one_time: String::new(),
            },
            info: FlatInfo { fields },
        }))
        .expect("remove should serialize")
    }

    async fn login(
        socket: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        user: &str,
        password: &str,
    ) {
        socket
            .send(ClientMessage::Text(login_message(user, password).into()))
            .await
            .expect("login should send");
        let response = read_operator_message(socket).await;
        assert!(matches!(response, OperatorMessage::InitConnectionSuccess(_)));
    }

    fn sample_agent(agent_id: u32) -> red_cell_common::AgentInfo {
        red_cell_common::AgentInfo {
            agent_id,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: AgentEncryptionInfo {
                aes_key: "YWVzLWtleQ==".to_owned(),
                aes_iv: "YWVzLWl2".to_owned(),
            },
            hostname: "wkstn-01".to_owned(),
            username: "operator".to_owned(),
            domain_name: "REDCELL".to_owned(),
            external_ip: "203.0.113.10".to_owned(),
            internal_ip: "10.0.0.25".to_owned(),
            process_name: "explorer.exe".to_owned(),
            base_address: 0x401000,
            process_pid: 1337,
            process_tid: 1338,
            process_ppid: 512,
            process_arch: "x64".to_owned(),
            elevated: true,
            os_version: "Windows 11".to_owned(),
            os_arch: "x64".to_owned(),
            sleep_delay: 15,
            sleep_jitter: 20,
            kill_date: Some(1_893_456_000),
            working_hours: Some(0b101010),
            first_call_in: "2026-03-09T18:45:00Z".to_owned(),
            last_call_in: "2026-03-09T18:46:00Z".to_owned(),
        }
    }

    fn sample_http_listener(name: &str, port: u16) -> red_cell_common::ListenerConfig {
        red_cell_common::ListenerConfig::from(red_cell_common::HttpListenerConfig {
            name: name.to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["c2.redcell.test".to_owned()],
            host_bind: "127.0.0.1".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: port,
            port_conn: Some(port),
            method: Some("GET".to_owned()),
            behind_redirector: false,
            user_agent: Some("Mozilla/5.0".to_owned()),
            headers: vec!["X-Test: true".to_owned()],
            uris: vec!["/".to_owned()],
            host_header: None,
            secure: false,
            cert: None,
            response: None,
            proxy: None,
        })
    }
}
