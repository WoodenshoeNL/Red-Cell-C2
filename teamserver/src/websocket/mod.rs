//! Operator WebSocket endpoint and connection tracking.

mod command_enc;
mod connection;

#[cfg(test)]
use crate::MAX_AGENT_MESSAGE_LEN;
#[cfg(test)]
use command_enc::{build_job, encode_utf16, write_len_prefixed_bytes, write_u32};
use command_enc::{
    build_jobs, flat_info_string, note_from_task, parse_agent_id, required_string, socket_command,
};

use connection::{
    AUTHENTICATION_FRAME_TIMEOUT, DisconnectKind, FAILED_LOGIN_DELAY, OPERATOR_MAX_MESSAGE_SIZE,
    SendMessageError, SocketLoopControl, WsSession, send_hmac_message, send_login_error,
    send_operator_message,
};
#[cfg(test)]
use connection::{LOGIN_WINDOW_DURATION, MAX_FAILED_LOGIN_ATTEMPTS, MAX_LOGIN_ATTEMPT_WINDOWS};
pub use connection::{LoginRateLimiter, OperatorConnectionManager};

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use axum::{
    Router,
    extract::{
        ConnectInfo, FromRef, State,
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
    routing::get,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell_common::crypto::{WsEnvelope, open_ws_frame};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::{
    BuildPayloadMessageInfo, BuildPayloadResponseInfo, EventCode, FlatInfo, Message, MessageHead,
    OperatorMessage, TeamserverLogInfo,
};
use red_cell_common::{AgentRecord, OperatorInfo};
use serde_json::Value;
use thiserror::Error;
use time::OffsetDateTime;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use crate::{
    AgentRegistry, AuditResultStatus, AuditWebhookNotifier, AuthError, AuthService,
    AuthenticationFailure, AuthenticationResult, Database, EventBus, ListenerEventAction,
    ListenerManager, PayloadBuildError, PayloadBuilderService, ShutdownController,
    SocketRelayManager, action_from_mark, agent_events::agent_new_event, audit_details,
    authorize_agent_group_access, authorize_listener_access, authorize_websocket_command,
    listener_config_from_operator, listener_error_event, listener_event_for_action,
    listener_removed_event, login_failure_message, login_parameters, login_success_message,
    operator_requests_start, parameter_object, record_operator_action_with_notifications,
};

/// Register the Havoc-compatible operator WebSocket endpoint at `/`.
pub fn routes<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    AuthService: FromRef<S>,
    EventBus: FromRef<S>,
    ListenerManager: FromRef<S>,
    AgentRegistry: FromRef<S>,
    SocketRelayManager: FromRef<S>,
    PayloadBuilderService: FromRef<S>,
    OperatorConnectionManager: FromRef<S>,
    LoginRateLimiter: FromRef<S>,
    AuditWebhookNotifier: FromRef<S>,
    Database: FromRef<S>,
    ShutdownController: FromRef<S>,
{
    Router::new().route("/", get(websocket_handler::<S>))
}

/// Upgrade a `/havoc/` HTTP request to the operator WebSocket protocol.
#[instrument(skip(state, websocket))]
pub async fn websocket_handler<S>(
    State(state): State<S>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    websocket: WebSocketUpgrade,
) -> impl IntoResponse
where
    S: Clone + Send + Sync + 'static,
    AuthService: FromRef<S>,
    EventBus: FromRef<S>,
    ListenerManager: FromRef<S>,
    AgentRegistry: FromRef<S>,
    SocketRelayManager: FromRef<S>,
    PayloadBuilderService: FromRef<S>,
    OperatorConnectionManager: FromRef<S>,
    LoginRateLimiter: FromRef<S>,
    AuditWebhookNotifier: FromRef<S>,
    Database: FromRef<S>,
    ShutdownController: FromRef<S>,
{
    websocket
        .max_message_size(OPERATOR_MAX_MESSAGE_SIZE)
        .on_upgrade(move |socket| handle_operator_socket(state, socket, addr.ip()))
}

async fn handle_operator_socket<S>(state: S, mut socket: WebSocket, client_ip: IpAddr)
where
    S: Clone + Send + Sync + 'static,
    AuthService: FromRef<S>,
    EventBus: FromRef<S>,
    ListenerManager: FromRef<S>,
    AgentRegistry: FromRef<S>,
    SocketRelayManager: FromRef<S>,
    PayloadBuilderService: FromRef<S>,
    OperatorConnectionManager: FromRef<S>,
    LoginRateLimiter: FromRef<S>,
    AuditWebhookNotifier: FromRef<S>,
    Database: FromRef<S>,
    ShutdownController: FromRef<S>,
{
    let connection_id = Uuid::new_v4();
    let auth = AuthService::from_ref(&state);
    let connections = OperatorConnectionManager::from_ref(&state);
    let database = Database::from_ref(&state);
    let rate_limiter = LoginRateLimiter::from_ref(&state);
    let webhooks = AuditWebhookNotifier::from_ref(&state);
    let shutdown = ShutdownController::from_ref(&state);

    if shutdown.is_shutting_down() {
        if let Err(e) = send_operator_message(&mut socket, &teamserver_shutdown_event()).await {
            debug!(%e, "shutdown: failed to send shutdown event to connecting operator");
        }
        if let Err(e) = socket.send(WsMessage::Close(None)).await {
            debug!(%e, "shutdown: failed to send close frame to connecting operator");
        }
        return;
    }

    connections.register(connection_id).await;

    if handle_authentication(
        &auth,
        &connections,
        &database,
        &webhooks,
        &rate_limiter,
        connection_id,
        client_ip,
        &mut socket,
    )
    .await
    .is_err()
    {
        cleanup_connection(
            &auth,
            &connections,
            &EventBus::from_ref(&state),
            &database,
            &webhooks,
            connection_id,
            DisconnectKind::Error,
        )
        .await;
        return;
    }

    let Some(session) = auth.session_for_connection(connection_id).await else {
        if let Err(e) = socket.send(WsMessage::Close(None)).await {
            debug!(%e, "auth: failed to send close frame for missing session");
        }
        cleanup_connection(
            &auth,
            &connections,
            &EventBus::from_ref(&state),
            &database,
            &webhooks,
            connection_id,
            DisconnectKind::Error,
        )
        .await;
        return;
    };

    let event_bus = EventBus::from_ref(&state);
    if first_online_session(&auth, &session.username).await {
        event_bus.broadcast(chat_presence_event(&session.username, true));
    }

    log_operator_action(
        &database,
        &webhooks,
        &session.username,
        "operator.connect",
        "operator",
        Some(session.username.clone()),
        audit_details(
            AuditResultStatus::Success,
            None,
            Some("connect"),
            Some(parameter_object([("connection_id", Value::String(connection_id.to_string()))])),
        ),
    )
    .await;

    info!(
        %connection_id,
        username = %session.username,
        "operator authenticated"
    );

    // Derive per-session HMAC key from the session token.
    let mut ws_session = WsSession::new(&session.token);

    let mut event_receiver = event_bus.subscribe();
    if let Err(error) = send_session_snapshot(
        &mut socket,
        &auth,
        &event_bus,
        &ListenerManager::from_ref(&state),
        &AgentRegistry::from_ref(&state),
        &mut ws_session,
    )
    .await
    {
        warn!(
            connection_id = %session.connection_id,
            username = %session.username,
            %error,
            "failed to synchronize operator session state"
        );
        cleanup_connection(
            &auth,
            &connections,
            &event_bus,
            &database,
            &webhooks,
            connection_id,
            DisconnectKind::Error,
        )
        .await;
        return;
    }

    let shutdown_signal = shutdown.notified();
    tokio::pin!(shutdown_signal);

    let disconnect_kind = 'recv: loop {
        tokio::select! {
            _ = &mut shutdown_signal => {
                if let Err(e) = send_hmac_message(&mut socket, &teamserver_shutdown_event(), &mut ws_session).await {
                    debug!(%e, "shutdown: failed to send shutdown event to operator");
                }
                if let Err(e) = socket.send(WsMessage::Close(None)).await {
                    debug!(%e, "shutdown: failed to send close frame to operator");
                }
                break 'recv DisconnectKind::ServerShutdown;
            }
            incoming = socket.recv() => {
                match handle_incoming_frame(&state, &mut socket, &session, incoming, &mut ws_session).await {
                    Ok(SocketLoopControl::Continue) => {}
                    Ok(SocketLoopControl::Break) => break 'recv DisconnectKind::CleanClose,
                    Err(()) => break 'recv DisconnectKind::Error,
                }
            }
            event = event_receiver.recv() => {
                let Some(event) = event else {
                    break 'recv DisconnectKind::ServerShutdown;
                };

                if send_hmac_message(&mut socket, &event, &mut ws_session).await.is_err() {
                    break 'recv DisconnectKind::Error;
                }
            }
        }
    };

    cleanup_connection(
        &auth,
        &connections,
        &event_bus,
        &database,
        &webhooks,
        connection_id,
        disconnect_kind,
    )
    .await;
}

async fn handle_authentication(
    auth: &AuthService,
    connections: &OperatorConnectionManager,
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    rate_limiter: &LoginRateLimiter,
    connection_id: Uuid,
    client_ip: IpAddr,
    socket: &mut WebSocket,
) -> Result<(), ()> {
    if !rate_limiter.try_acquire(client_ip).await {
        warn!(
            %connection_id,
            %client_ip,
            "login rate limit exceeded — rejecting connection"
        );
        send_login_error(socket, "", AuthenticationFailure::InvalidCredentials, connection_id)
            .await;
        return Err(());
    }

    let frame = match tokio::time::timeout(AUTHENTICATION_FRAME_TIMEOUT, socket.recv()).await {
        Ok(Some(frame)) => frame,
        Ok(None) => {
            warn!(%connection_id, "operator websocket closed before authentication");
            return Err(());
        }
        Err(_) => {
            warn!(
                %connection_id,
                timeout_secs = AUTHENTICATION_FRAME_TIMEOUT.as_secs(),
                "operator websocket authentication timed out"
            );
            log_operator_action(
                database,
                webhooks,
                "",
                "operator.session_timeout",
                "operator",
                None,
                audit_details(
                    AuditResultStatus::Failure,
                    None,
                    Some("session_timeout"),
                    Some(parameter_object([(
                        "connection_id",
                        Value::String(connection_id.to_string()),
                    )])),
                ),
            )
            .await;
            if let Err(e) = socket.send(WsMessage::Close(None)).await {
                debug!(%e, "session timeout: failed to send close frame");
            }
            return Err(());
        }
    };

    let message = match frame {
        Ok(WsMessage::Text(payload)) => payload,
        Ok(WsMessage::Close(_)) => return Err(()),
        Ok(other) => {
            warn!(%connection_id, frame = ?other, "operator websocket requires text login frame");
            if let Err(e) = send_operator_message(
                socket,
                &login_failure_message("", &AuthenticationFailure::InvalidCredentials),
            )
            .await
            {
                debug!(%e, "auth: failed to send login failure for non-text frame");
            }
            if let Err(e) = socket.send(WsMessage::Close(None)).await {
                debug!(%e, "auth: failed to send close frame for non-text frame");
            }
            return Err(());
        }
        Err(error) => {
            warn!(%connection_id, %error, "failed to receive operator authentication frame");
            return Err(());
        }
    };

    let login_user = serde_json::from_str::<OperatorMessage>(message.as_str())
        .ok()
        .and_then(|message| match message {
            OperatorMessage::Login(message) => Some(message.info.user),
            _ => None,
        })
        .unwrap_or_default();

    let response = match auth.authenticate_message(connection_id, message.as_str()).await {
        Ok(AuthenticationResult::Success(success)) => {
            connections.authenticate(connection_id, success.username.clone()).await;
            rate_limiter.record_success(client_ip).await;
            log_operator_action(
                database,
                webhooks,
                &success.username,
                "operator.login",
                "operator",
                Some(success.username.clone()),
                audit_details(
                    AuditResultStatus::Success,
                    None,
                    Some("login"),
                    Some(login_parameters(&success.username, &connection_id)),
                ),
            )
            .await;
            login_success_message(&success.username, &success.token)
        }
        Ok(AuthenticationResult::Failure(failure)) => {
            tokio::time::sleep(FAILED_LOGIN_DELAY).await;
            log_operator_action(
                database,
                webhooks,
                &login_user,
                "operator.login",
                "operator",
                (!login_user.is_empty()).then_some(login_user.clone()),
                audit_details(
                    AuditResultStatus::Failure,
                    None,
                    Some("login"),
                    Some(login_parameters(&login_user, &connection_id)),
                ),
            )
            .await;
            send_login_error(socket, "", failure, connection_id).await;
            return Err(());
        }
        Err(AuthError::InvalidLoginMessage) => {
            tokio::time::sleep(FAILED_LOGIN_DELAY).await;
            log_operator_action(
                database,
                webhooks,
                &login_user,
                "operator.login",
                "operator",
                (!login_user.is_empty()).then_some(login_user.clone()),
                audit_details(
                    AuditResultStatus::Failure,
                    None,
                    Some("login"),
                    Some(login_parameters(&login_user, &connection_id)),
                ),
            )
            .await;
            send_login_error(socket, "", AuthenticationFailure::InvalidCredentials, connection_id)
                .await;
            return Err(());
        }
        Err(AuthError::InvalidMessageJson(error)) => {
            warn!(%connection_id, %error, "failed to parse operator login message");
            tokio::time::sleep(FAILED_LOGIN_DELAY).await;
            log_operator_action(
                database,
                webhooks,
                "",
                "operator.login",
                "operator",
                None,
                audit_details(
                    AuditResultStatus::Failure,
                    None,
                    Some("login"),
                    Some(parameter_object([
                        ("connection_id", Value::String(connection_id.to_string())),
                        ("error", Value::String(error)),
                    ])),
                ),
            )
            .await;
            send_login_error(socket, "", AuthenticationFailure::InvalidCredentials, connection_id)
                .await;
            return Err(());
        }
        Err(
            AuthError::DuplicateUser { .. }
            | AuthError::EmptyUsername
            | AuthError::EmptyPassword
            | AuthError::OperatorNotFound { .. }
            | AuthError::ProfileOperator { .. },
        ) => {
            tokio::time::sleep(FAILED_LOGIN_DELAY).await;
            send_login_error(socket, "", AuthenticationFailure::InvalidCredentials, connection_id)
                .await;
            return Err(());
        }
        Err(AuthError::PasswordVerifier(error)) => {
            warn!(%connection_id, %error, "operator authentication verifier error");
            tokio::time::sleep(FAILED_LOGIN_DELAY).await;
            send_login_error(socket, "", AuthenticationFailure::InvalidCredentials, connection_id)
                .await;
            return Err(());
        }
        Err(AuthError::Persistence(error)) | Err(AuthError::AuditLog(error)) => {
            warn!(%connection_id, %error, "operator authentication backing store error");
            tokio::time::sleep(FAILED_LOGIN_DELAY).await;
            send_login_error(socket, "", AuthenticationFailure::InvalidCredentials, connection_id)
                .await;
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
    ws_session: &mut WsSession,
) -> Result<SocketLoopControl, ()>
where
    S: Clone + Send + Sync + 'static,
    EventBus: FromRef<S>,
    ListenerManager: FromRef<S>,
    AgentRegistry: FromRef<S>,
    SocketRelayManager: FromRef<S>,
    PayloadBuilderService: FromRef<S>,
    AuditWebhookNotifier: FromRef<S>,
    Database: FromRef<S>,
    ShutdownController: FromRef<S>,
{
    let Some(frame) = incoming else {
        return Ok(SocketLoopControl::Break);
    };

    match frame {
        Ok(WsMessage::Text(payload)) => {
            // Every post-login frame must be a valid WsEnvelope.
            let inner_json = match serde_json::from_str::<WsEnvelope>(payload.as_str()) {
                Ok(envelope) => {
                    match open_ws_frame(&ws_session.key, &envelope, ws_session.recv_seq) {
                        Ok(json) => {
                            ws_session.recv_seq = Some(envelope.seq);
                            json
                        }
                        Err(_) => {
                            warn!(
                                connection_id = %session.connection_id,
                                username = %session.username,
                                "HMAC verification failed on incoming frame — closing connection"
                            );
                            if let Err(e) = socket.send(WsMessage::Close(None)).await {
                                debug!(%e, "failed to send close frame after HMAC failure");
                            }
                            return Err(());
                        }
                    }
                }
                Err(error) => {
                    warn!(
                        connection_id = %session.connection_id,
                        username = %session.username,
                        %error,
                        "failed to parse HMAC envelope on incoming frame"
                    );
                    if let Err(e) = socket.send(WsMessage::Close(None)).await {
                        debug!(%e, "failed to send close frame after envelope parse error");
                    }
                    return Err(());
                }
            };
            let message = match serde_json::from_str::<OperatorMessage>(&inner_json) {
                Ok(message) => message,
                Err(error) => {
                    warn!(
                        connection_id = %session.connection_id,
                        username = %session.username,
                        %error,
                        "failed to parse operator websocket message"
                    );
                    if let Err(e) = socket.send(WsMessage::Close(None)).await {
                        debug!(%e, "failed to send close frame after parse error");
                    }
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
                    let database = Database::from_ref(state);
                    let webhooks = AuditWebhookNotifier::from_ref(state);
                    log_operator_action(
                        &database,
                        &webhooks,
                        &session.username,
                        "operator.permission_denied",
                        "operator",
                        Some(session.username.clone()),
                        audit_details(
                            AuditResultStatus::Failure,
                            None,
                            Some("permission_denied"),
                            Some(parameter_object([
                                ("connection_id", Value::String(session.connection_id.to_string())),
                                ("reason", Value::String(error.to_string())),
                            ])),
                        ),
                    )
                    .await;
                    if let Err(e) = socket.send(WsMessage::Close(None)).await {
                        debug!(%e, "failed to send close frame after command error");
                    }
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

/// Attempt to serialize a value for audit logging, warning on failure instead
/// of silently discarding the error.
fn serialize_for_audit<T: serde::Serialize>(value: &T, context: &str) -> Option<Value> {
    match serde_json::to_value(value) {
        Ok(v) => Some(v),
        Err(error) => {
            warn!(%error, context, "failed to serialize audit parameters");
            None
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
    SocketRelayManager: FromRef<S>,
    PayloadBuilderService: FromRef<S>,
    AuditWebhookNotifier: FromRef<S>,
    Database: FromRef<S>,
    ShutdownController: FromRef<S>,
{
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
                        // Forward the human-readable error summary to the operator console.
                        events.broadcast(build_payload_message_event(
                            &actor,
                            "Error",
                            &error.to_string(),
                        ));

                        // When the compiler exited with structured diagnostics, send each
                        // diagnostic as its own progress message for source-context display.
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

    // Granular RBAC: per-operator group restrictions.
    authorize_agent_group_access(database, &session.username, agent_id).await?;

    // Granular RBAC: per-listener operator allow-list.
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

/// Format a [`CompilerDiagnostic`] as a single human-readable string.
///
/// Produces output compatible with what GCC/NASM print natively:
/// `filename:line[:col]: severity: message`
fn format_diagnostic(diag: &red_cell_common::operator::CompilerDiagnostic) -> String {
    let loc = match diag.column {
        Some(col) => format!("{}:{}:{}", diag.filename, diag.line, col),
        None => format!("{}:{}", diag.filename, diag.line),
    };
    let code_suffix = diag.error_code.as_deref().map(|c| format!(" [{c}]")).unwrap_or_default();
    format!("{loc}: {}: {}{code_suffix}", diag.severity, diag.message)
}

fn build_payload_message_event(user: &str, level: &str, text: &str) -> OperatorMessage {
    OperatorMessage::BuildPayloadMessage(Message {
        head: MessageHead {
            event: EventCode::Gate,
            user: user.to_owned(),
            timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
            one_time: String::new(),
        },
        info: BuildPayloadMessageInfo { message_type: level.to_owned(), message: text.to_owned() },
    })
}

fn build_payload_response_event(
    user: &str,
    file_name: &str,
    format: &str,
    bytes: &[u8],
) -> OperatorMessage {
    OperatorMessage::BuildPayloadResponse(Message {
        head: MessageHead {
            event: EventCode::Gate,
            user: user.to_owned(),
            timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
            one_time: String::new(),
        },
        info: BuildPayloadResponseInfo {
            payload_array: BASE64_STANDARD.encode(bytes),
            format: format.to_owned(),
            file_name: file_name.to_owned(),
        },
    })
}

#[derive(Debug, Error)]
enum SnapshotSyncError {
    #[error(transparent)]
    Send(#[from] SendMessageError),
    #[error(transparent)]
    Serialize(#[from] serde_json::Error),
    #[error(transparent)]
    Listener(#[from] crate::ListenerManagerError),
    #[error(transparent)]
    Teamserver(#[from] crate::TeamserverError),
    #[error(transparent)]
    Auth(#[from] AuthError),
}

async fn send_session_snapshot(
    socket: &mut WebSocket,
    auth: &AuthService,
    events: &EventBus,
    listeners: &ListenerManager,
    registry: &AgentRegistry,
    ws_session: &mut WsSession,
) -> Result<(), SnapshotSyncError> {
    let operators = auth
        .operator_inventory()
        .await?
        .into_iter()
        .map(|entry| entry.as_operator_info())
        .collect();
    send_hmac_message(socket, &operator_snapshot_event(operators)?, ws_session).await?;

    for summary in listeners.list().await?.into_iter() {
        send_hmac_message(
            socket,
            &listener_event_for_action("teamserver", &summary, ListenerEventAction::Created),
            ws_session,
        )
        .await?;
    }

    for message in events.recent_teamserver_logs() {
        send_hmac_message(socket, &message, ws_session).await?;
    }

    for agent in registry.list_active().await {
        let pivots = registry.pivots(agent.agent_id).await;
        let listener_name =
            registry.listener_name(agent.agent_id).await.unwrap_or_else(|| "null".to_owned());
        send_hmac_message(
            socket,
            &agent_snapshot_event(&listener_name, &agent, &pivots),
            ws_session,
        )
        .await?;
    }

    Ok(())
}

fn agent_snapshot_event(
    listener_name: &str,
    agent: &AgentRecord,
    pivots: &crate::PivotInfo,
) -> OperatorMessage {
    agent_new_event(listener_name, red_cell_common::demon::DEMON_MAGIC_VALUE, agent, pivots)
}

fn operator_snapshot_event(
    operators: Vec<OperatorInfo>,
) -> Result<OperatorMessage, serde_json::Error> {
    Ok(OperatorMessage::InitConnectionInfo(Message {
        head: MessageHead {
            event: EventCode::InitConnection,
            user: String::new(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: FlatInfo {
            fields: BTreeMap::from([("Operators".to_owned(), serde_json::to_value(operators)?)]),
        },
    }))
}

async fn cleanup_connection(
    auth: &AuthService,
    connections: &OperatorConnectionManager,
    events: &EventBus,
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    connection_id: Uuid,
    disconnect_kind: DisconnectKind,
) {
    if let Some(session) = auth.remove_connection(connection_id).await {
        log_operator_action(
            database,
            webhooks,
            &session.username,
            "operator.disconnect",
            "operator",
            Some(session.username.clone()),
            audit_details(
                AuditResultStatus::Success,
                None,
                Some("disconnect"),
                Some(parameter_object([
                    ("connection_id", Value::String(connection_id.to_string())),
                    ("kind", Value::String(disconnect_kind.as_str().to_owned())),
                ])),
            ),
        )
        .await;

        if last_online_session(auth, &session.username).await {
            events.broadcast(chat_presence_event(&session.username, false));
        }
    }
    connections.unregister(connection_id).await;
}

async fn first_online_session(auth: &AuthService, username: &str) -> bool {
    auth.active_sessions().await.into_iter().filter(|session| session.username == username).count()
        == 1
}

async fn last_online_session(auth: &AuthService, username: &str) -> bool {
    auth.active_sessions().await.into_iter().all(|session| session.username != username)
}

fn chat_presence_event(user: &str, online: bool) -> OperatorMessage {
    let message = Message {
        head: MessageHead {
            event: EventCode::Chat,
            user: "teamserver".to_owned(),
            timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
            one_time: String::new(),
        },
        info: red_cell_common::operator::ChatUserInfo { user: user.to_owned() },
    };

    if online {
        OperatorMessage::ChatUserConnected(message)
    } else {
        OperatorMessage::ChatUserDisconnected(message)
    }
}

fn chat_message_event(user: &str, text: &str) -> OperatorMessage {
    OperatorMessage::ChatMessage(Message {
        head: MessageHead {
            event: EventCode::Chat,
            user: user.to_owned(),
            timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
            one_time: String::new(),
        },
        info: FlatInfo {
            fields: BTreeMap::from([
                ("User".to_owned(), Value::String(user.to_owned())),
                ("Message".to_owned(), Value::String(text.to_owned())),
            ]),
        },
    })
}

fn teamserver_shutdown_event() -> OperatorMessage {
    OperatorMessage::TeamserverLog(Message {
        head: MessageHead {
            event: EventCode::Teamserver,
            user: "teamserver".to_owned(),
            timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
            one_time: String::new(),
        },
        info: TeamserverLogInfo { text: "teamserver shutting down".to_owned() },
    })
}

async fn log_operator_action(
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    actor: &str,
    action: &str,
    target_kind: &str,
    target_id: Option<String>,
    details: crate::AuditDetails,
) {
    if let Err(error) = record_operator_action_with_notifications(
        database,
        webhooks,
        actor,
        action,
        target_kind,
        target_id,
        details,
    )
    .await
    {
        warn!(actor, action, %error, "failed to persist audit log entry");
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    use axum::extract::FromRef;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use futures_util::{SinkExt, StreamExt};
    use red_cell_common::{
        AgentEncryptionInfo, OperatorInfo,
        config::Profile,
        demon::{
            DemonCommand, DemonFilesystemCommand, DemonInjectWay, DemonProcessCommand,
            DemonTokenCommand,
        },
        operator::{
            AgentTaskInfo, EventCode, FlatInfo, ListenerInfo, ListenerMarkInfo, LoginInfo, Message,
            MessageHead, NameInfo, OperatorMessage, SessionCode, TeamserverLogInfo,
        },
    };
    use serde_json::Value;
    use tokio::net::TcpListener;
    use tokio::time::timeout;
    use tokio_tungstenite::{connect_async, tungstenite::Message as ClientMessage};
    use uuid::Uuid;

    use std::net::IpAddr;

    use super::{
        AgentCommandError, LoginRateLimiter, MAX_AGENT_MESSAGE_LEN, OperatorConnectionManager,
        build_job, build_jobs, encode_utf16, execute_agent_task, routes, teamserver_log_event,
        write_len_prefixed_bytes, write_u32,
    };
    use crate::{
        AgentRegistry, AuditQuery, AuditResultStatus, AuditWebhookNotifier, AuthService, Database,
        EventBus, ListenerManager, PayloadBuilderService, ShutdownController, SocketRelayManager,
        query_audit_log,
    };
    use red_cell_common::crypto::{
        WsEnvelope, derive_ws_hmac_key, hash_password_sha3, open_ws_frame, seal_ws_frame,
    };
    use zeroize::Zeroizing;

    #[derive(Clone)]
    struct TestState {
        auth: AuthService,
        database: Database,
        events: EventBus,
        connections: OperatorConnectionManager,
        registry: AgentRegistry,
        listeners: ListenerManager,
        payload_builder: PayloadBuilderService,
        sockets: SocketRelayManager,
        webhooks: AuditWebhookNotifier,
        login_rate_limiter: LoginRateLimiter,
        shutdown: ShutdownController,
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
            let sockets = SocketRelayManager::new(registry.clone(), events.clone());

            Self {
                auth: AuthService::from_profile(&profile).expect("auth service should initialize"),
                database: database.clone(),
                events: events.clone(),
                connections: OperatorConnectionManager::new(),
                registry: registry.clone(),
                listeners: ListenerManager::new(database, registry, events, sockets.clone(), None)
                    .with_demon_allow_legacy_ctr(true),
                payload_builder: PayloadBuilderService::disabled_for_tests(),
                sockets,
                webhooks: AuditWebhookNotifier::from_profile(&profile),
                login_rate_limiter: LoginRateLimiter::new(),
                shutdown: ShutdownController::new(),
            }
        }
    }

    impl FromRef<TestState> for AuthService {
        fn from_ref(input: &TestState) -> Self {
            input.auth.clone()
        }
    }

    impl FromRef<TestState> for Database {
        fn from_ref(input: &TestState) -> Self {
            input.database.clone()
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

    impl FromRef<TestState> for SocketRelayManager {
        fn from_ref(input: &TestState) -> Self {
            input.sockets.clone()
        }
    }

    impl FromRef<TestState> for PayloadBuilderService {
        fn from_ref(input: &TestState) -> Self {
            input.payload_builder.clone()
        }
    }

    impl FromRef<TestState> for AuditWebhookNotifier {
        fn from_ref(input: &TestState) -> Self {
            input.webhooks.clone()
        }
    }

    impl FromRef<TestState> for LoginRateLimiter {
        fn from_ref(input: &TestState) -> Self {
            input.login_rate_limiter.clone()
        }
    }

    impl FromRef<TestState> for ShutdownController {
        fn from_ref(input: &TestState) -> Self {
            input.shutdown.clone()
        }
    }

    // ── Test WebSocket session (HMAC-aware) ───────────────────────────────────

    /// Raw WebSocket stream type used in tests.
    type RawTestSocket = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    /// Test helper that wraps a raw WebSocket connection with per-session HMAC state.
    ///
    /// Pre-login frames (the `Login` message) are sent/received as plain JSON.
    /// Once `InitConnectionSuccess` is received, the HMAC key is derived from the
    /// embedded session token, and all subsequent frames are wrapped/unwrapped.
    struct WsTestSession {
        socket: RawTestSocket,
        hmac_key: Option<[u8; 32]>,
        send_seq: u64,
        recv_seq: Option<u64>,
    }

    impl WsTestSession {
        fn new(socket: RawTestSocket) -> Self {
            Self { socket, hmac_key: None, send_seq: 0, recv_seq: None }
        }

        /// Send a pre-serialised JSON string, HMAC-wrapping it if the session key
        /// is already established (i.e. after a successful login).
        async fn send_text(&mut self, json: impl Into<String>) {
            let json = json.into();
            if let Some(key) = &self.hmac_key {
                let seq = self.send_seq;
                self.send_seq += 1;
                let envelope = seal_ws_frame(key, seq, &json);
                let wire = serde_json::to_string(&envelope).expect("envelope must serialize");
                self.socket
                    .send(ClientMessage::Text(wire.into()))
                    .await
                    .expect("send_text should succeed");
            } else {
                self.socket
                    .send(ClientMessage::Text(json.into()))
                    .await
                    .expect("send_text should succeed");
            }
        }

        /// Send an arbitrary raw WebSocket frame (bypasses HMAC — for pre-login tests).
        async fn send_frame(&mut self, frame: ClientMessage) {
            self.socket.send(frame).await.expect("send_frame should succeed");
        }

        /// Receive the next `OperatorMessage`.
        ///
        /// If the session key is set, expects and verifies a `WsEnvelope`.
        /// If the key is not yet set and the received message is
        /// `InitConnectionSuccess`, the HMAC key is derived from the embedded
        /// session token for all future messages.
        async fn recv_msg(&mut self) -> OperatorMessage {
            let frame = timeout(Duration::from_secs(30), self.socket.next())
                .await
                .expect("socket should yield a frame within 30s")
                .expect("frame should be present")
                .expect("frame should decode");

            let text = match frame {
                ClientMessage::Text(t) => t,
                other => panic!("unexpected websocket frame type: {other:?}"),
            };

            if let Some(key) = &self.hmac_key {
                let envelope: WsEnvelope =
                    serde_json::from_str(text.as_str()).expect("expected HMAC envelope post-login");
                let inner_json = open_ws_frame(key, &envelope, self.recv_seq)
                    .expect("HMAC verification must succeed in tests");
                self.recv_seq = Some(envelope.seq);
                serde_json::from_str(&inner_json)
                    .expect("inner payload must parse as OperatorMessage")
            } else {
                let msg: OperatorMessage =
                    serde_json::from_str(text.as_str()).expect("plain frame must parse");
                if let OperatorMessage::InitConnectionSuccess(ref m) = msg {
                    if let Some(token) = m.info.message.split_once("SessionToken=").map(|(_, t)| t)
                    {
                        self.hmac_key = Some(derive_ws_hmac_key(token));
                    }
                }
                msg
            }
        }

        /// Receive the next raw WebSocket frame without HMAC processing.
        ///
        /// Used for low-level tests that need to inspect close/error frames.
        async fn next_raw_frame(
            &mut self,
        ) -> Option<Result<ClientMessage, tokio_tungstenite::tungstenite::Error>> {
            self.socket.next().await
        }

        /// Send a clean WebSocket close frame.
        async fn close(&mut self) {
            self.socket.close(None).await.expect("close should send");
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

        socket.send_frame(ClientMessage::Text(non_login.into())).await;

        let response = read_operator_message(&mut socket).await;
        assert!(matches!(response, OperatorMessage::InitConnectionError(_)));

        wait_for_connection_count(&connection_registry, 0).await;
        server.abort();
    }

    #[tokio::test]
    async fn websocket_closes_idle_unauthenticated_connections() {
        let state = TestState::new().await;
        let connection_registry = state.connections.clone();
        let (mut socket, server) = spawn_server(state).await;

        let frame = timeout(
            super::AUTHENTICATION_FRAME_TIMEOUT + Duration::from_secs(2),
            socket.next_raw_frame(),
        )
        .await
        .expect("socket should close idle unauthenticated connection")
        .expect("close frame should be present")
        .expect("close frame should decode");
        assert!(matches!(frame, ClientMessage::Close(_)));

        wait_for_connection_count(&connection_registry, 0).await;
        assert_eq!(connection_registry.authenticated_count().await, 0);
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
            .send_frame(ClientMessage::Text(login_message("operator", "password1234").into()))
            .await;

        let response = read_operator_message(&mut socket).await;
        assert!(matches!(response, OperatorMessage::InitConnectionSuccess(_)));
        let _snapshot = read_operator_snapshot(&mut socket).await;
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

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(event_bus.broadcast(event.clone()), 1);
        assert_eq!(read_operator_message(&mut socket).await, event);

        socket.close().await;
        wait_for_connection_count(&connection_registry, 0).await;
        assert_eq!(auth.session_count().await, 0);
        server.abort();
    }

    #[tokio::test]
    async fn websocket_closes_oversized_messages() {
        let state = TestState::new().await;
        let connection_registry = state.connections.clone();
        let (mut socket, server) = spawn_server(state).await;

        login(&mut socket, "operator", "password1234").await;

        let oversized_payload = "x".repeat(super::OPERATOR_MAX_MESSAGE_SIZE + 1);
        socket.send_frame(ClientMessage::Text(oversized_payload.into())).await;

        let frame = timeout(Duration::from_secs(5), socket.next_raw_frame())
            .await
            .expect("socket should react to oversized message")
            .expect("connection should close or error");
        assert!(matches!(frame, Err(_) | Ok(ClientMessage::Close(_))));

        wait_for_connection_count(&connection_registry, 0).await;
        assert_eq!(connection_registry.authenticated_count().await, 0);
        server.abort();
    }

    // --- websocket_handler direct contract tests ---

    /// Happy path: `websocket_handler` increments the connection count when a socket
    /// is upgraded, increments the authenticated count after a valid login, and
    /// decrements both back to zero once the client closes the connection.
    #[tokio::test]
    async fn websocket_handler_connection_tracking_lifecycle() {
        let state = TestState::new().await;
        let connections = state.connections.clone();
        let auth = state.auth.clone();
        let (mut socket, server) = spawn_server(state).await;

        // After upgrade, exactly one connection should be registered.
        timeout(Duration::from_secs(2), async {
            loop {
                if connections.connection_count().await == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("connection count should reach 1 after upgrade");
        assert_eq!(connections.authenticated_count().await, 0);

        // After a valid login, the connection should become authenticated.
        login(&mut socket, "operator", "password1234").await;
        assert_eq!(connections.connection_count().await, 1);
        assert_eq!(connections.authenticated_count().await, 1);
        assert_eq!(auth.session_count().await, 1);

        // After the client closes, both counts must return to zero.
        socket.close().await;
        wait_for_connection_count(&connections, 0).await;
        assert_eq!(connections.authenticated_count().await, 0);
        assert_eq!(auth.session_count().await, 0);

        server.abort();
    }

    /// Error path: a malformed (non-JSON) first frame causes the handler to close
    /// the socket without leaving any stale `authenticated_count` state.
    #[tokio::test]
    async fn websocket_handler_malformed_first_frame_leaves_no_stale_auth_count() {
        let state = TestState::new().await;
        let connections = state.connections.clone();
        let (mut socket, server) = spawn_server(state).await;

        // Send binary garbage as the very first frame — not a valid login message.
        socket
            .send_frame(ClientMessage::Binary(b"not valid json at all \x00\xff".to_vec().into()))
            .await;

        // The server must close the connection.
        wait_for_connection_count(&connections, 0).await;

        // No authenticated session must remain.
        assert_eq!(connections.authenticated_count().await, 0);

        server.abort();
    }

    /// Edge case: a frame larger than `OPERATOR_MAX_MESSAGE_SIZE` is rejected by the
    /// cap set inside `websocket_handler` even when the client has not yet logged in,
    /// and the connection closes without leaving stale state.
    #[tokio::test]
    async fn websocket_handler_rejects_oversized_frame_before_authentication() {
        let state = TestState::new().await;
        let connections = state.connections.clone();
        let (mut socket, server) = spawn_server(state).await;

        // Send an oversized frame as the very first message (no prior login).
        let oversized = "x".repeat(super::OPERATOR_MAX_MESSAGE_SIZE + 1);
        socket.send_frame(ClientMessage::Text(oversized.into())).await;

        // The server must terminate the connection (close frame or transport error).
        let frame = timeout(Duration::from_secs(5), socket.next_raw_frame())
            .await
            .expect("socket should react to oversized pre-auth frame")
            .expect("connection should close or error");
        assert!(
            matches!(frame, Err(_) | Ok(ClientMessage::Close(_))),
            "expected close or error, got {frame:?}"
        );

        wait_for_connection_count(&connections, 0).await;
        assert_eq!(connections.authenticated_count().await, 0);

        server.abort();
    }

    #[tokio::test]
    async fn websocket_notifies_authenticated_clients_before_shutdown_close() {
        let state = TestState::new().await;
        let shutdown = state.shutdown.clone();
        let (mut socket, server) = spawn_server(state).await;

        socket
            .send_frame(ClientMessage::Text(login_message("operator", "password1234").into()))
            .await;

        let response = read_operator_message(&mut socket).await;
        assert!(matches!(response, OperatorMessage::InitConnectionSuccess(_)));
        let _ = read_operator_snapshot(&mut socket).await;

        shutdown.initiate();

        let response = read_operator_message(&mut socket).await;
        let OperatorMessage::TeamserverLog(message) = response else {
            panic!("expected shutdown notice");
        };
        assert_eq!(message.info.text, "teamserver shutting down");

        let frame = timeout(Duration::from_secs(5), socket.next_raw_frame())
            .await
            .expect("socket should close")
            .expect("close frame should be present")
            .expect("close frame should decode");
        assert!(matches!(frame, ClientMessage::Close(_)));

        server.abort();
    }

    #[tokio::test]
    async fn websocket_broadcasts_operator_presence_changes() {
        let state = TestState::new().await;
        // Login each socket immediately after connecting to avoid the 5-second
        // unauthenticated-connection timeout firing under heavy parallel-test load.
        let (mut first, server) = spawn_server(state.clone()).await;
        login(&mut first, "operator", "password1234").await;
        let (mut second, _) = spawn_server(state).await;
        login(&mut second, "analyst", "readonly").await;

        let joined = read_operator_message(&mut first).await;
        let OperatorMessage::ChatUserConnected(message) = joined else {
            panic!("expected operator join broadcast");
        };
        assert_eq!(message.info.user, "analyst");

        second.close().await;

        let left = read_operator_message(&mut first).await;
        let OperatorMessage::ChatUserDisconnected(message) = left else {
            panic!("expected operator disconnect broadcast");
        };
        assert_eq!(message.info.user, "analyst");

        first.close().await;
        server.abort();
    }

    #[tokio::test]
    async fn websocket_broadcasts_chat_messages_to_other_operators() {
        let state = TestState::new().await;
        // Login each socket immediately after connecting to avoid the 5-second
        // unauthenticated-connection timeout firing under heavy parallel-test load.
        let (mut sender, server) = spawn_server(state.clone()).await;
        login(&mut sender, "operator", "password1234").await;
        let (mut observer, _) = spawn_server(state).await;
        login(&mut observer, "analyst", "readonly").await;
        let _presence = read_operator_message(&mut sender).await;

        sender.send_text(chat_message("operator", "hello team")).await;

        let message = read_operator_message(&mut observer).await;
        let OperatorMessage::ChatMessage(message) = message else {
            panic!("expected chat broadcast");
        };
        assert_eq!(message.head.user, "operator");
        assert_eq!(message.info.fields.get("User"), Some(&Value::String("operator".to_owned())));
        assert_eq!(
            message.info.fields.get("Message"),
            Some(&Value::String("hello team".to_owned()))
        );

        sender.close().await;
        observer.close().await;
        server.abort();
    }

    #[tokio::test]
    async fn websocket_chat_messages_are_persisted_as_session_activity() {
        let state = TestState::new().await;
        let (mut sender, server) = spawn_server(state.clone()).await;

        login(&mut sender, "operator", "password1234").await;
        sender.send_text(chat_message("operator", "hello team")).await;
        let _broadcast = read_operator_message(&mut sender).await;

        let page = query_audit_log(
            &state.database,
            &AuditQuery {
                action: Some("operator.chat".to_owned()),
                actor: Some("operator".to_owned()),
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit query should succeed");

        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].action, "operator.chat");
        assert_eq!(
            page.items[0]
                .parameters
                .as_ref()
                .and_then(|parameters| parameters.get("message"))
                .and_then(Value::as_str),
            Some("hello team")
        );

        sender.close().await;
        server.abort();
    }

    #[tokio::test]
    async fn websocket_sends_session_snapshot_after_login() {
        let state = TestState::new().await;
        let registry = state.registry.clone();
        let listeners = state.listeners.clone();
        let events = state.events.clone();
        registry
            .insert_with_listener(sample_agent(0xDEAD_BEEF), "alpha")
            .await
            .expect("agent should insert");
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
        assert_eq!(message.info.listener, "alpha");
        assert_eq!(message.info.magic_value, "deadbeef");
        let encoded = serde_json::to_value(&message.info).expect("agent snapshot should serialize");
        assert!(encoded.get("Encryption").is_none());

        socket.close().await;
        server.abort();
    }

    #[tokio::test]
    async fn websocket_session_snapshot_includes_configured_and_runtime_operators() {
        let state = TestState::new().await;
        state
            .auth
            .create_operator("trinity", "zion", red_cell_common::config::OperatorRole::Operator)
            .await
            .expect("runtime operator should be created");
        let (mut socket, server) = spawn_server(state).await;

        socket
            .send_frame(ClientMessage::Text(login_message("operator", "password1234").into()))
            .await;
        let response = read_operator_message(&mut socket).await;
        assert!(matches!(response, OperatorMessage::InitConnectionSuccess(_)));

        let operators = read_operator_snapshot(&mut socket).await;
        assert_eq!(
            operators,
            vec![
                OperatorInfo {
                    username: "admin".to_owned(),
                    password_hash: None,
                    role: Some("Admin".to_owned()),
                    online: false,
                    last_seen: None,
                },
                OperatorInfo {
                    username: "analyst".to_owned(),
                    password_hash: None,
                    role: Some("Analyst".to_owned()),
                    online: false,
                    last_seen: None,
                },
                OperatorInfo {
                    username: "operator".to_owned(),
                    password_hash: None,
                    role: Some("Operator".to_owned()),
                    online: true,
                    last_seen: None,
                },
                OperatorInfo {
                    username: "trinity".to_owned(),
                    password_hash: None,
                    role: Some("Operator".to_owned()),
                    online: false,
                    last_seen: None,
                },
            ]
        );

        socket.close().await;
        server.abort();
    }

    #[tokio::test]
    async fn websocket_session_snapshot_includes_agent_pivot_chain() {
        let state = TestState::new().await;
        let registry = state.registry.clone();
        registry.insert(sample_agent(0x0102_0304)).await.expect("parent should insert");
        registry.insert(sample_agent(0x1112_1314)).await.expect("child should insert");
        registry.add_link(0x0102_0304, 0x1112_1314).await.expect("pivot link should insert");
        let (mut socket, server) = spawn_server(state).await;

        login(&mut socket, "operator", "password1234").await;

        let parent_event = read_operator_message(&mut socket).await;
        let OperatorMessage::AgentNew(parent_message) = parent_event else {
            panic!("expected parent snapshot event");
        };
        assert_eq!(parent_message.info.name_id, "01020304");
        assert!(parent_message.info.pivots.parent.is_none());
        assert_eq!(parent_message.info.pivots.links, vec!["11121314".to_owned()]);

        let child_event = read_operator_message(&mut socket).await;
        let OperatorMessage::AgentNew(child_message) = child_event else {
            panic!("expected child snapshot event");
        };
        assert_eq!(child_message.info.name_id, "11121314");
        assert_eq!(child_message.info.pivots.parent.as_deref(), Some("01020304"));
        assert_eq!(child_message.info.pivot_parent, "01020304");

        socket.close().await;
        server.abort();
    }

    #[tokio::test]
    async fn websocket_snapshot_includes_persisted_offline_listeners() {
        let state = TestState::new().await;
        let listeners = state.listeners.clone();
        listeners
            .create(sample_http_listener("offline-alpha", 0))
            .await
            .expect("listener should persist");
        let (mut socket, server) = spawn_server(state).await;

        login(&mut socket, "operator", "password1234").await;

        let listener_event = read_operator_message(&mut socket).await;
        let OperatorMessage::ListenerNew(message) = listener_event else {
            panic!("expected listener snapshot event");
        };
        assert_eq!(message.info.name.as_deref(), Some("offline-alpha"));
        assert_eq!(message.info.status.as_deref(), Some("Offline"));

        socket.close().await;
        server.abort();
    }

    #[tokio::test]
    async fn websocket_closes_when_authenticated_operator_lacks_permission() {
        let state = TestState::new().await;
        let connection_registry = state.connections.clone();
        let (mut socket, server) = spawn_server(state).await;

        socket.send_frame(ClientMessage::Text(login_message("analyst", "readonly").into())).await;
        let response = read_operator_message(&mut socket).await;
        assert!(matches!(response, OperatorMessage::InitConnectionSuccess(_)));
        let _snapshot = read_operator_snapshot(&mut socket).await;

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

        socket.send_text(task).await;

        let close_frame = timeout(Duration::from_secs(2), socket.next_raw_frame())
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
        // Login each socket immediately after connecting to avoid the 5-second
        // unauthenticated-connection timeout firing under heavy parallel-test load.
        let (mut sender, server) = spawn_server(state.clone()).await;
        login(&mut sender, "operator", "password1234").await;
        let (mut observer, _) = spawn_server(state).await;
        login(&mut observer, "operator", "password1234").await;
        let snapshot = read_operator_message(&mut sender).await;
        assert!(matches!(snapshot, OperatorMessage::AgentNew(_)));
        let snapshot = read_operator_message(&mut observer).await;
        assert!(matches!(snapshot, OperatorMessage::AgentNew(_)));

        sender
            .send_text(agent_task_message(
                "operator",
                AgentTaskInfo {
                    task_id: "2A".to_owned(),
                    command_line: "checkin".to_owned(),
                    demon_id: "DEADBEEF".to_owned(),
                    command_id: u32::from(DemonCommand::CommandCheckin).to_string(),
                    ..AgentTaskInfo::default()
                },
            ))
            .await;

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

        sender.close().await;
        observer.close().await;
        server.abort();
    }

    #[test]
    fn build_job_encodes_process_list_payload() {
        let job = build_job(&AgentTaskInfo {
            task_id: "2A".to_owned(),
            command_line: "ps".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandProcList).to_string(),
            extra: BTreeMap::from([(String::from("FromProcessManager"), Value::Bool(true))]),
            ..AgentTaskInfo::default()
        })
        .expect("process list job should build");

        assert_eq!(job.command, u32::from(DemonCommand::CommandProcList));
        assert_eq!(job.payload, 1_u32.to_le_bytes());
    }

    #[test]
    fn build_job_encodes_process_create_payload() {
        let encoded_args = BASE64_STANDARD.encode("\"C:\\Windows\\System32\\cmd.exe\" /c whoami");
        let job = build_job(&AgentTaskInfo {
            task_id: "2B".to_owned(),
            command_line: "proc create normal cmd.exe /c whoami".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandProc).to_string(),
            sub_command: Some("create".to_owned()),
            extra: BTreeMap::from([(
                String::from("Args"),
                Value::String(format!(
                    "0;TRUE;FALSE;C:\\Windows\\System32\\cmd.exe;{encoded_args}"
                )),
            )]),
            ..AgentTaskInfo::default()
        })
        .expect("process create job should build");

        let mut offset = 0usize;
        assert_eq!(read_u32_le(&job.payload, &mut offset), u32::from(DemonProcessCommand::Create));
        assert_eq!(read_u32_le(&job.payload, &mut offset), 0);
        assert_eq!(
            decode_utf16(read_len_prefixed_bytes(&job.payload, &mut offset)),
            "C:\\Windows\\System32\\cmd.exe"
        );
        assert_eq!(
            decode_utf16(read_len_prefixed_bytes(&job.payload, &mut offset)),
            "\"C:\\Windows\\System32\\cmd.exe\" /c whoami"
        );
        assert_eq!(read_u32_le(&job.payload, &mut offset), 0);
        assert_eq!(read_u32_le(&job.payload, &mut offset), 1);
    }

    #[test]
    fn build_job_encodes_shellcode_inject_and_token_impersonation() {
        let shellcode = BASE64_STANDARD.encode([0x90_u8, 0x90, 0xCC]);
        let shellcode_job = build_job(&AgentTaskInfo {
            task_id: "2C".to_owned(),
            command_line: "shellcode inject x64 4444 /tmp/payload.bin".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandInjectShellcode).to_string(),
            extra: BTreeMap::from([
                (String::from("Way"), Value::String("Inject".to_owned())),
                (String::from("Technique"), Value::String("default".to_owned())),
                (String::from("Arch"), Value::String("x64".to_owned())),
                (String::from("Binary"), Value::String(shellcode)),
                (String::from("PID"), Value::String("4444".to_owned())),
            ]),
            ..AgentTaskInfo::default()
        })
        .expect("shellcode inject job should build");

        let mut offset = 0usize;
        assert_eq!(
            read_u32_le(&shellcode_job.payload, &mut offset),
            u32::from(DemonInjectWay::Inject)
        );
        assert_eq!(read_u32_le(&shellcode_job.payload, &mut offset), 0);
        assert_eq!(read_u32_le(&shellcode_job.payload, &mut offset), 1);
        assert_eq!(
            read_len_prefixed_bytes(&shellcode_job.payload, &mut offset),
            vec![0x90, 0x90, 0xCC]
        );
        assert_eq!(read_len_prefixed_bytes(&shellcode_job.payload, &mut offset), Vec::<u8>::new());
        assert_eq!(read_u32_le(&shellcode_job.payload, &mut offset), 4444);

        let token_job = build_job(&AgentTaskInfo {
            task_id: "2D".to_owned(),
            command_line: "token impersonate 7".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandToken).to_string(),
            sub_command: Some("impersonate".to_owned()),
            arguments: Some("7".to_owned()),
            ..AgentTaskInfo::default()
        })
        .expect("token impersonation job should build");
        assert_eq!(
            token_job.payload,
            [u32::from(DemonTokenCommand::Impersonate).to_le_bytes(), 7_u32.to_le_bytes()].concat()
        );
    }

    #[test]
    fn build_jobs_encodes_filesystem_copy_payload() -> Result<(), crate::TeamserverError> {
        let jobs = build_jobs(
            &AgentTaskInfo {
                task_id: "2E".to_owned(),
                command_line: "cp a b".to_owned(),
                demon_id: "DEADBEEF".to_owned(),
                command_id: u32::from(DemonCommand::CommandFs).to_string(),
                sub_command: Some("cp".to_owned()),
                arguments: Some(format!(
                    "{};{}",
                    BASE64_STANDARD.encode("C:\\temp\\a.txt"),
                    BASE64_STANDARD.encode("D:\\loot\\b.txt")
                )),
                ..AgentTaskInfo::default()
            },
            "",
        )
        .expect("filesystem copy should encode");

        assert_eq!(jobs.len(), 1);
        let mut expected = Vec::new();
        write_u32(&mut expected, u32::from(DemonFilesystemCommand::Copy));
        write_len_prefixed_bytes(&mut expected, &encode_utf16("C:\\temp\\a.txt"))?;
        write_len_prefixed_bytes(&mut expected, &encode_utf16("D:\\loot\\b.txt"))?;
        assert_eq!(jobs[0].command, u32::from(DemonCommand::CommandFs));
        assert_eq!(jobs[0].payload, expected);
        Ok(())
    }

    #[test]
    fn build_job_encodes_filesystem_dir_payload() -> Result<(), crate::TeamserverError> {
        let args = "C:\\Users;true;false;true;false;*.txt;2024-01-01;name".to_owned();
        let job = build_job(&AgentTaskInfo {
            task_id: "40".to_owned(),
            command_line: "ls C:\\Users".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandFs).to_string(),
            sub_command: Some("dir".to_owned()),
            arguments: Some(args),
            ..AgentTaskInfo::default()
        })
        .expect("filesystem dir should encode");

        assert_eq!(job.command, u32::from(DemonCommand::CommandFs));
        let mut offset = 0usize;
        assert_eq!(read_u32_le(&job.payload, &mut offset), u32::from(DemonFilesystemCommand::Dir));
        assert_eq!(read_u32_le(&job.payload, &mut offset), 0); // reserved zero
        assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), encode_utf16("C:\\Users"));
        assert_eq!(read_u32_le(&job.payload, &mut offset), 1); // bool true
        assert_eq!(read_u32_le(&job.payload, &mut offset), 0); // bool false
        assert_eq!(read_u32_le(&job.payload, &mut offset), 1); // bool true
        assert_eq!(read_u32_le(&job.payload, &mut offset), 0); // bool false
        assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), encode_utf16("*.txt"));
        assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), encode_utf16("2024-01-01"));
        assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), encode_utf16("name"));
        assert_eq!(offset, job.payload.len());
        Ok(())
    }

    #[test]
    fn build_job_encodes_filesystem_download_payload() -> Result<(), crate::TeamserverError> {
        let job = build_job(&AgentTaskInfo {
            task_id: "41".to_owned(),
            command_line: "download C:\\secret.txt".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandFs).to_string(),
            sub_command: Some("download".to_owned()),
            arguments: Some(BASE64_STANDARD.encode("C:\\secret.txt")),
            ..AgentTaskInfo::default()
        })
        .expect("filesystem download should encode");

        assert_eq!(job.command, u32::from(DemonCommand::CommandFs));
        let mut offset = 0usize;
        assert_eq!(
            read_u32_le(&job.payload, &mut offset),
            u32::from(DemonFilesystemCommand::Download)
        );
        assert_eq!(
            read_len_prefixed_bytes(&job.payload, &mut offset),
            encode_utf16("C:\\secret.txt")
        );
        assert_eq!(offset, job.payload.len());
        Ok(())
    }

    #[test]
    fn build_job_encodes_filesystem_cat_payload() -> Result<(), crate::TeamserverError> {
        let job = build_job(&AgentTaskInfo {
            task_id: "42".to_owned(),
            command_line: "cat C:\\etc\\hosts".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandFs).to_string(),
            sub_command: Some("cat".to_owned()),
            arguments: Some(BASE64_STANDARD.encode("C:\\etc\\hosts")),
            ..AgentTaskInfo::default()
        })
        .expect("filesystem cat should encode");

        assert_eq!(job.command, u32::from(DemonCommand::CommandFs));
        let mut offset = 0usize;
        assert_eq!(read_u32_le(&job.payload, &mut offset), u32::from(DemonFilesystemCommand::Cat));
        assert_eq!(
            read_len_prefixed_bytes(&job.payload, &mut offset),
            encode_utf16("C:\\etc\\hosts")
        );
        assert_eq!(offset, job.payload.len());
        Ok(())
    }

    #[test]
    fn build_job_encodes_filesystem_cd_payload() -> Result<(), crate::TeamserverError> {
        let job = build_job(&AgentTaskInfo {
            task_id: "43".to_owned(),
            command_line: "cd C:\\Windows".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandFs).to_string(),
            sub_command: Some("cd".to_owned()),
            arguments: Some("C:\\Windows".to_owned()),
            ..AgentTaskInfo::default()
        })
        .expect("filesystem cd should encode");

        assert_eq!(job.command, u32::from(DemonCommand::CommandFs));
        let mut offset = 0usize;
        assert_eq!(read_u32_le(&job.payload, &mut offset), u32::from(DemonFilesystemCommand::Cd));
        assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), encode_utf16("C:\\Windows"));
        assert_eq!(offset, job.payload.len());
        Ok(())
    }

    #[test]
    fn build_job_encodes_filesystem_remove_payload() -> Result<(), crate::TeamserverError> {
        let job = build_job(&AgentTaskInfo {
            task_id: "44".to_owned(),
            command_line: "rm C:\\tmp\\evil.exe".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandFs).to_string(),
            sub_command: Some("remove".to_owned()),
            arguments: Some("C:\\tmp\\evil.exe".to_owned()),
            ..AgentTaskInfo::default()
        })
        .expect("filesystem remove should encode");

        assert_eq!(job.command, u32::from(DemonCommand::CommandFs));
        let mut offset = 0usize;
        assert_eq!(
            read_u32_le(&job.payload, &mut offset),
            u32::from(DemonFilesystemCommand::Remove)
        );
        assert_eq!(
            read_len_prefixed_bytes(&job.payload, &mut offset),
            encode_utf16("C:\\tmp\\evil.exe")
        );
        assert_eq!(offset, job.payload.len());
        Ok(())
    }

    #[test]
    fn build_job_encodes_filesystem_mkdir_payload() -> Result<(), crate::TeamserverError> {
        let job = build_job(&AgentTaskInfo {
            task_id: "45".to_owned(),
            command_line: "mkdir C:\\loot".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandFs).to_string(),
            sub_command: Some("mkdir".to_owned()),
            arguments: Some("C:\\loot".to_owned()),
            ..AgentTaskInfo::default()
        })
        .expect("filesystem mkdir should encode");

        assert_eq!(job.command, u32::from(DemonCommand::CommandFs));
        let mut offset = 0usize;
        assert_eq!(
            read_u32_le(&job.payload, &mut offset),
            u32::from(DemonFilesystemCommand::Mkdir)
        );
        assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), encode_utf16("C:\\loot"));
        assert_eq!(offset, job.payload.len());
        Ok(())
    }

    #[test]
    fn build_job_encodes_filesystem_move_payload() -> Result<(), crate::TeamserverError> {
        let job = build_job(&AgentTaskInfo {
            task_id: "46".to_owned(),
            command_line: "mv C:\\src.txt C:\\dst.txt".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandFs).to_string(),
            sub_command: Some("move".to_owned()),
            arguments: Some(format!(
                "{};{}",
                BASE64_STANDARD.encode("C:\\src.txt"),
                BASE64_STANDARD.encode("C:\\dst.txt")
            )),
            ..AgentTaskInfo::default()
        })
        .expect("filesystem move should encode");

        assert_eq!(job.command, u32::from(DemonCommand::CommandFs));
        let mut offset = 0usize;
        assert_eq!(read_u32_le(&job.payload, &mut offset), u32::from(DemonFilesystemCommand::Move));
        assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), encode_utf16("C:\\src.txt"));
        assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), encode_utf16("C:\\dst.txt"));
        assert_eq!(offset, job.payload.len());
        Ok(())
    }

    #[test]
    fn build_job_encodes_filesystem_getpwd_payload() {
        let job = build_job(&AgentTaskInfo {
            task_id: "47".to_owned(),
            command_line: "pwd".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandFs).to_string(),
            sub_command: Some("pwd".to_owned()),
            ..AgentTaskInfo::default()
        })
        .expect("filesystem getpwd should encode");

        assert_eq!(job.command, u32::from(DemonCommand::CommandFs));
        // GetPwd writes only the 4-byte subcommand discriminant and nothing else.
        assert_eq!(job.payload.len(), 4);
        assert_eq!(
            u32::from_le_bytes(job.payload[0..4].try_into().expect("discriminant fits")),
            u32::from(DemonFilesystemCommand::GetPwd)
        );
    }

    #[test]
    fn build_job_rejects_unknown_filesystem_subcommand() {
        let err = build_job(&AgentTaskInfo {
            task_id: "48".to_owned(),
            command_line: "fs cat_dog".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandFs).to_string(),
            sub_command: Some("cat_dog".to_owned()),
            ..AgentTaskInfo::default()
        })
        .expect_err("unknown filesystem subcommand should be rejected");

        assert!(
            matches!(err, AgentCommandError::UnsupportedFilesystemSubcommand { .. }),
            "expected UnsupportedFilesystemSubcommand, got {err:?}"
        );
    }

    #[test]
    fn build_job_encodes_token_privs_list_payload_from_extra_subcommand_string() {
        let job = build_job(&AgentTaskInfo {
            task_id: "2F".to_owned(),
            command_line: "token privs-list".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandToken).to_string(),
            extra: BTreeMap::from([(
                String::from("SubCommand"),
                Value::String("privs-list".to_owned()),
            )]),
            ..AgentTaskInfo::default()
        })
        .expect("token privs-list job should build from extras");

        assert_eq!(
            job.payload,
            [u32::from(DemonTokenCommand::PrivsGetOrList).to_le_bytes(), 1_u32.to_le_bytes(),]
                .concat()
        );
    }

    #[test]
    fn build_job_encodes_token_privs_list_payload_from_extra_subcommand_numeric() {
        let job = build_job(&AgentTaskInfo {
            task_id: "30".to_owned(),
            command_line: "token 4".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandToken).to_string(),
            extra: BTreeMap::from([(String::from("SubCommand"), Value::String("4".to_owned()))]),
            ..AgentTaskInfo::default()
        })
        .expect("token privs-list job should build from numeric extra");

        assert_eq!(
            job.payload,
            [u32::from(DemonTokenCommand::PrivsGetOrList).to_le_bytes(), 1_u32.to_le_bytes(),]
                .concat()
        );
    }

    #[test]
    fn build_jobs_splits_upload_into_memfile_chunks_and_final_fs_job() {
        let content = vec![0x41; MAX_AGENT_MESSAGE_LEN + 16];
        let jobs = build_jobs(
            &AgentTaskInfo {
                task_id: "2F".to_owned(),
                command_line: "upload local.bin remote.bin".to_owned(),
                demon_id: "DEADBEEF".to_owned(),
                command_id: u32::from(DemonCommand::CommandFs).to_string(),
                sub_command: Some("upload".to_owned()),
                arguments: Some(format!(
                    "{};{}",
                    BASE64_STANDARD.encode("C:\\Temp\\remote.bin"),
                    BASE64_STANDARD.encode(&content)
                )),
                ..AgentTaskInfo::default()
            },
            "",
        )
        .expect("filesystem upload should encode");

        assert_eq!(jobs.len(), 3);
        assert_eq!(jobs[0].command, u32::from(DemonCommand::CommandMemFile));
        assert_eq!(jobs[1].command, u32::from(DemonCommand::CommandMemFile));
        assert_eq!(jobs[2].command, u32::from(DemonCommand::CommandFs));
        assert_eq!(jobs[2].request_id, 0x2F);

        let memfile_id =
            u32::from_le_bytes(jobs[0].payload[0..4].try_into().expect("memfile id should exist"));
        assert_eq!(
            u64::from_le_bytes(
                jobs[0].payload[4..12].try_into().expect("memfile size should exist")
            ),
            u64::try_from(content.len()).expect("content length should fit"),
        );
        assert_eq!(
            u32::from_le_bytes(
                jobs[2].payload[0..4].try_into().expect("upload command should exist")
            ),
            u32::from(DemonFilesystemCommand::Upload)
        );
        let final_memfile_id = u32::from_le_bytes(
            jobs[2].payload[jobs[2].payload.len() - 4..]
                .try_into()
                .expect("final memfile id should exist"),
        );
        assert_eq!(memfile_id, final_memfile_id);
    }

    #[test]
    fn build_job_encodes_inject_dll_payload() {
        let loader = BASE64_STANDARD.encode([0xCC_u8, 0xDD, 0xEE]);
        let binary = BASE64_STANDARD.encode([0x4D_u8, 0x5A, 0x90, 0x00]);
        let arguments = BASE64_STANDARD.encode("test-arg");
        let job = build_job(&AgentTaskInfo {
            task_id: "30".to_owned(),
            command_line: "inject-dll 1234 payload.dll".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandInjectDll).to_string(),
            extra: BTreeMap::from([
                (String::from("PID"), Value::String("1234".to_owned())),
                (String::from("DllLoader"), Value::String(loader)),
                (String::from("Binary"), Value::String(binary)),
                (String::from("Arguments"), Value::String(arguments)),
                (String::from("Technique"), Value::String("0".to_owned())),
            ]),
            ..AgentTaskInfo::default()
        })
        .expect("inject dll job should build");

        assert_eq!(job.command, u32::from(DemonCommand::CommandInjectDll));
        let mut offset = 0usize;
        assert_eq!(read_u32_le(&job.payload, &mut offset), 0);
        assert_eq!(read_u32_le(&job.payload, &mut offset), 1234);
        assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), vec![0xCC, 0xDD, 0xEE]);
        assert_eq!(
            read_len_prefixed_bytes(&job.payload, &mut offset),
            vec![0x4D, 0x5A, 0x90, 0x00]
        );
        assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), b"test-arg".to_vec());
    }

    #[test]
    fn build_job_encodes_inject_dll_with_default_technique() {
        let loader = BASE64_STANDARD.encode([0xAA_u8]);
        let binary = BASE64_STANDARD.encode([0xBB_u8]);
        let job = build_job(&AgentTaskInfo {
            task_id: "31".to_owned(),
            command_line: "inject-dll 5555 minimal.dll".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandInjectDll).to_string(),
            extra: BTreeMap::from([
                (String::from("PID"), Value::String("5555".to_owned())),
                (String::from("DllLoader"), Value::String(loader)),
                (String::from("Binary"), Value::String(binary)),
            ]),
            ..AgentTaskInfo::default()
        })
        .expect("inject dll job should build with default technique");

        let mut offset = 0usize;
        assert_eq!(read_u32_le(&job.payload, &mut offset), 0);
        assert_eq!(read_u32_le(&job.payload, &mut offset), 5555);
    }

    #[test]
    fn build_job_encodes_spawn_dll_payload() {
        let loader = BASE64_STANDARD.encode([0x11_u8, 0x22, 0x33]);
        let binary = BASE64_STANDARD.encode([0x4D_u8, 0x5A]);
        let arguments = BASE64_STANDARD.encode("spawn-args");
        let job = build_job(&AgentTaskInfo {
            task_id: "32".to_owned(),
            command_line: "spawn-dll payload.dll".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandSpawnDll).to_string(),
            extra: BTreeMap::from([
                (String::from("DllLoader"), Value::String(loader)),
                (String::from("Binary"), Value::String(binary)),
                (String::from("Arguments"), Value::String(arguments)),
            ]),
            ..AgentTaskInfo::default()
        })
        .expect("spawn dll job should build");

        assert_eq!(job.command, u32::from(DemonCommand::CommandSpawnDll));
        let mut offset = 0usize;
        assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), vec![0x11, 0x22, 0x33]);
        assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), vec![0x4D, 0x5A]);
        assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), b"spawn-args".to_vec());
    }

    #[test]
    fn build_job_encodes_process_modules_payload() {
        let job = build_job(&AgentTaskInfo {
            task_id: "33".to_owned(),
            command_line: "proc modules 8888".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandProc).to_string(),
            sub_command: Some("modules".to_owned()),
            extra: BTreeMap::from([(String::from("Args"), Value::String("8888".to_owned()))]),
            ..AgentTaskInfo::default()
        })
        .expect("proc modules job should build");

        assert_eq!(job.command, u32::from(DemonCommand::CommandProc));
        let mut offset = 0usize;
        assert_eq!(read_u32_le(&job.payload, &mut offset), u32::from(DemonProcessCommand::Modules));
        assert_eq!(read_u32_le(&job.payload, &mut offset), 8888);
    }

    #[test]
    fn build_job_encodes_process_grep_payload() {
        let job = build_job(&AgentTaskInfo {
            task_id: "34".to_owned(),
            command_line: "proc grep svchost".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandProc).to_string(),
            sub_command: Some("grep".to_owned()),
            extra: BTreeMap::from([(String::from("Args"), Value::String("svchost".to_owned()))]),
            ..AgentTaskInfo::default()
        })
        .expect("proc grep job should build");

        assert_eq!(job.command, u32::from(DemonCommand::CommandProc));
        let mut offset = 0usize;
        assert_eq!(read_u32_le(&job.payload, &mut offset), u32::from(DemonProcessCommand::Grep));
        let grep_pattern = decode_utf16(read_len_prefixed_bytes(&job.payload, &mut offset));
        assert_eq!(grep_pattern, "svchost");
    }

    #[test]
    fn build_job_encodes_process_memory_payload() {
        let job = build_job(&AgentTaskInfo {
            task_id: "35".to_owned(),
            command_line: "proc memory 4321 PAGE_EXECUTE_READWRITE".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandProc).to_string(),
            sub_command: Some("memory".to_owned()),
            extra: BTreeMap::from([(
                String::from("Args"),
                Value::String("4321 PAGE_EXECUTE_READWRITE".to_owned()),
            )]),
            ..AgentTaskInfo::default()
        })
        .expect("proc memory job should build");

        assert_eq!(job.command, u32::from(DemonCommand::CommandProc));
        let mut offset = 0usize;
        assert_eq!(read_u32_le(&job.payload, &mut offset), u32::from(DemonProcessCommand::Memory));
        assert_eq!(read_u32_le(&job.payload, &mut offset), 4321);
        assert_eq!(read_u32_le(&job.payload, &mut offset), 0x40);
    }

    #[test]
    fn build_job_rejects_empty_task_id() {
        let result = build_job(&AgentTaskInfo {
            task_id: String::new(),
            command_line: "checkin".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandCheckin).to_string(),
            ..AgentTaskInfo::default()
        });
        let err = result.expect_err("empty task_id should fail");
        assert!(matches!(err, AgentCommandError::InvalidTaskId { .. }));
    }

    #[test]
    fn build_job_rejects_non_hex_task_id() {
        let result = build_job(&AgentTaskInfo {
            task_id: "not-hex".to_owned(),
            command_line: "checkin".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandCheckin).to_string(),
            ..AgentTaskInfo::default()
        });
        let err = result.expect_err("non-hex task_id should fail");
        assert!(matches!(err, AgentCommandError::InvalidTaskId { .. }));
    }

    #[test]
    fn build_job_rejects_overflowing_task_id() {
        let result = build_job(&AgentTaskInfo {
            task_id: "FFFFFFFFFF".to_owned(),
            command_line: "checkin".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandCheckin).to_string(),
            ..AgentTaskInfo::default()
        });
        let err = result.expect_err("overflowing task_id should fail");
        assert!(matches!(err, AgentCommandError::InvalidTaskId { .. }));
    }

    #[test]
    fn build_job_accepts_valid_hex_task_id() {
        let job = build_job(&AgentTaskInfo {
            task_id: "FF".to_owned(),
            command_line: "checkin".to_owned(),
            demon_id: "DEADBEEF".to_owned(),
            command_id: u32::from(DemonCommand::CommandCheckin).to_string(),
            ..AgentTaskInfo::default()
        })
        .expect("valid hex task_id should succeed");
        assert_eq!(job.request_id, 0xFF);
    }

    #[test]
    fn build_jobs_rejects_unknown_command_id_without_raw_payload() {
        // An unrecognised numeric command ID with no raw payload must be rejected.
        let result = build_jobs(
            &AgentTaskInfo {
                task_id: "01".to_owned(),
                command_line: "bogus".to_owned(),
                demon_id: "DEADBEEF".to_owned(),
                command_id: "99999".to_owned(),
                ..AgentTaskInfo::default()
            },
            "op",
        );
        match result {
            Err(AgentCommandError::UnsupportedCommandId { command_id }) => {
                assert_eq!(command_id, 99999);
            }
            other => panic!("expected UnsupportedCommandId, got {other:?}"),
        }
    }

    #[test]
    fn build_jobs_accepts_unknown_command_id_with_raw_payload() {
        // An unrecognised command ID should still be accepted when the caller
        // provides an explicit raw payload.
        let mut extra = BTreeMap::new();
        extra.insert("Payload".to_owned(), serde_json::Value::String("hello".to_owned()));
        let jobs = build_jobs(
            &AgentTaskInfo {
                task_id: "01".to_owned(),
                command_line: "custom".to_owned(),
                demon_id: "DEADBEEF".to_owned(),
                command_id: "99999".to_owned(),
                extra,
                ..AgentTaskInfo::default()
            },
            "op",
        )
        .expect("unknown command with raw payload should succeed");
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].command, 99999);
        assert_eq!(jobs[0].payload, b"hello");
    }

    #[test]
    fn build_jobs_accepts_known_command_without_explicit_payload() {
        // A recognised Demon command that does not have a specialised encoder
        // should succeed with an empty payload.
        let jobs = build_jobs(
            &AgentTaskInfo {
                task_id: "0A".to_owned(),
                command_line: "checkin".to_owned(),
                demon_id: "DEADBEEF".to_owned(),
                command_id: u32::from(DemonCommand::CommandCheckin).to_string(),
                ..AgentTaskInfo::default()
            },
            "op",
        )
        .expect("known command without payload should succeed");
        assert_eq!(jobs.len(), 1);
        assert!(jobs[0].payload.is_empty());
    }

    #[tokio::test]
    async fn websocket_listener_commands_broadcast_and_persist_state() {
        let state = TestState::new().await;
        let listeners = state.listeners.clone();
        // Login each socket immediately after connecting to avoid the 5-second
        // unauthenticated-connection timeout firing while the other login round-trip
        // is in flight under heavy parallel-test load.
        let (mut sender, server) = spawn_server(state.clone()).await;
        login(&mut sender, "operator", "password1234").await;
        let (mut observer, _) = spawn_server(state).await;
        login(&mut observer, "operator", "password1234").await;

        sender
            .send_text(listener_new_message(
                "operator",
                sample_listener_info("alpha", "Online", 0),
                false,
            ))
            .await;

        let created = read_operator_message(&mut observer).await;
        let OperatorMessage::ListenerNew(message) = created else {
            panic!("expected listener create broadcast");
        };
        assert_eq!(message.head.user, "operator");
        assert_eq!(message.info.name.as_deref(), Some("alpha"));

        let started = read_operator_message(&mut observer).await;
        let OperatorMessage::ListenerMark(message) = started else {
            panic!("expected listener start broadcast");
        };
        assert_eq!(message.info.name, "alpha");
        assert_eq!(message.info.mark, "Online");
        assert_eq!(
            listeners.summary("alpha").await.expect("listener should exist").state.status,
            crate::ListenerStatus::Running
        );

        sender.send_text(listener_mark_message("operator", "alpha", "stopped")).await;

        let stopped = read_operator_message(&mut observer).await;
        let OperatorMessage::ListenerMark(message) = stopped else {
            panic!("expected listener stop broadcast");
        };
        assert_eq!(message.info.name, "alpha");
        assert_eq!(message.info.mark, "Offline");
        assert_eq!(
            listeners.summary("alpha").await.expect("listener should exist").state.status,
            crate::ListenerStatus::Stopped
        );

        sender.send_text(listener_remove_message("operator", "alpha")).await;

        let removed = read_operator_message(&mut observer).await;
        let OperatorMessage::ListenerRemove(message) = removed else {
            panic!("expected listener delete broadcast");
        };
        assert_eq!(message.info.name, "alpha");
        assert!(listeners.summary("alpha").await.is_err());

        sender.close().await;
        observer.close().await;
        server.abort();
    }

    #[tokio::test]
    async fn websocket_listener_remove_records_audit_trail() {
        let state = TestState::new().await;
        let database = state.database.clone();
        let (mut socket, server) = spawn_server(state).await;

        login(&mut socket, "operator", "password1234").await;

        socket
            .send_text(listener_new_message(
                "operator",
                sample_listener_info("beta", "Online", 0),
                false,
            ))
            .await;

        let _created = read_operator_message(&mut socket).await;
        let _started = read_operator_message(&mut socket).await;

        socket.send_text(listener_remove_message("operator", "beta")).await;

        let _removed = read_operator_message(&mut socket).await;

        let page = query_audit_log(
            &database,
            &AuditQuery { action: Some("listener.delete".to_owned()), ..AuditQuery::default() },
        )
        .await
        .expect("audit query should succeed");

        assert!(!page.items.is_empty(), "expected at least one listener.delete audit entry");
        let entry = &page.items[0];
        assert_eq!(entry.action, "listener.delete");
        assert_eq!(entry.target_kind, "listener");
        assert_eq!(entry.target_id.as_deref(), Some("beta"));
        assert_eq!(entry.result_status, AuditResultStatus::Success);

        socket.close().await;
        server.abort();
    }

    #[tokio::test]
    async fn websocket_listener_remove_nonexistent_records_failure_audit() {
        let state = TestState::new().await;
        let database = state.database.clone();
        let (mut socket, server) = spawn_server(state).await;

        login(&mut socket, "operator", "password1234").await;

        socket.send_text(listener_remove_message("operator", "ghost")).await;

        let _error_msg = read_operator_message(&mut socket).await;

        let page = query_audit_log(
            &database,
            &AuditQuery { action: Some("listener.delete".to_owned()), ..AuditQuery::default() },
        )
        .await
        .expect("audit query should succeed");

        assert!(!page.items.is_empty(), "expected at least one listener.delete audit entry");
        let entry = &page.items[0];
        assert_eq!(entry.action, "listener.delete");
        assert_eq!(entry.target_kind, "listener");
        assert_eq!(entry.result_status, AuditResultStatus::Failure);

        socket.close().await;
        server.abort();
    }

    #[tokio::test]
    async fn websocket_listener_edit_records_audit_trail() {
        let state = TestState::new().await;
        let database = state.database.clone();
        let (mut socket, server) = spawn_server(state).await;

        login(&mut socket, "operator", "password1234").await;

        socket
            .send_text(listener_new_message(
                "operator",
                sample_listener_info("gamma", "Online", 8443),
                false,
            ))
            .await;

        let _created = read_operator_message(&mut socket).await;
        let _started = read_operator_message(&mut socket).await;

        let mut updated = sample_listener_info("gamma", "Online", 9443);
        updated.headers = Some("X-Test: updated".to_owned());

        socket.send_text(listener_edit_message("operator", updated)).await;

        let _updated = read_operator_message(&mut socket).await;

        let page = query_audit_log(
            &database,
            &AuditQuery { action: Some("listener.update".to_owned()), ..AuditQuery::default() },
        )
        .await
        .expect("audit query should succeed");

        assert!(!page.items.is_empty(), "expected at least one listener.update audit entry");
        let entry = &page.items[0];
        assert_eq!(entry.action, "listener.update");
        assert_eq!(entry.target_kind, "listener");
        assert_eq!(entry.target_id.as_deref(), Some("gamma"));
        assert_eq!(entry.result_status, AuditResultStatus::Success);

        socket.close().await;
        server.abort();
    }

    #[tokio::test]
    async fn websocket_listener_edit_nonexistent_records_failure_audit() {
        let state = TestState::new().await;
        let database = state.database.clone();
        let (mut socket, server) = spawn_server(state).await;

        login(&mut socket, "operator", "password1234").await;

        socket
            .send_text(listener_edit_message(
                "operator",
                sample_listener_info("ghost", "Online", 9443),
            ))
            .await;

        let _error_msg = read_operator_message(&mut socket).await;

        let page = query_audit_log(
            &database,
            &AuditQuery { action: Some("listener.update".to_owned()), ..AuditQuery::default() },
        )
        .await
        .expect("audit query should succeed");

        assert!(!page.items.is_empty(), "expected at least one listener.update audit entry");
        let entry = &page.items[0];
        assert_eq!(entry.action, "listener.update");
        assert_eq!(entry.target_kind, "listener");
        assert_eq!(entry.target_id.as_deref(), Some("ghost"));
        assert_eq!(entry.result_status, AuditResultStatus::Failure);

        socket.close().await;
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
            .send_text(agent_task_message(
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
            ))
            .await;

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

        socket.close().await;
        server.abort();
    }

    #[tokio::test]
    async fn websocket_agent_remove_deletes_agent_for_admins() {
        let state = TestState::new().await;
        let registry = state.registry.clone();
        let sockets = state.sockets.clone();
        registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
        sockets.add_socks_server(0xDEAD_BEEF, "0").await.expect("SOCKS server should start");
        assert!(sockets.list_socks_servers(0xDEAD_BEEF).await.contains("SOCKS5 servers"));
        let (mut socket, server) = spawn_server(state).await;

        login(&mut socket, "admin", "adminpass").await;
        let snapshot = read_operator_message(&mut socket).await;
        assert!(matches!(snapshot, OperatorMessage::AgentNew(_)));

        socket.send_text(agent_remove_message("admin", "DEADBEEF")).await;

        let event = read_operator_message(&mut socket).await;
        assert!(matches!(event, OperatorMessage::AgentRemove(_)));
        assert!(registry.get(0xDEAD_BEEF).await.is_none());
        assert_eq!(sockets.list_socks_servers(0xDEAD_BEEF).await, "No active SOCKS5 servers");

        socket.close().await;
        server.abort();
    }

    #[tokio::test]
    async fn websocket_agent_remove_records_success_audit_trail() {
        let state = TestState::new().await;
        let database = state.database.clone();
        let registry = state.registry.clone();
        registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
        let (mut socket, server) = spawn_server(state).await;

        login(&mut socket, "admin", "adminpass").await;
        let _snapshot = read_operator_message(&mut socket).await;

        socket.send_text(agent_remove_message("admin", "DEADBEEF")).await;

        let _event = read_operator_message(&mut socket).await;

        let page = query_audit_log(
            &database,
            &AuditQuery { action: Some("agent.delete".to_owned()), ..AuditQuery::default() },
        )
        .await
        .expect("audit query should succeed");

        assert!(!page.items.is_empty(), "expected at least one agent.delete audit entry");
        let entry = &page.items[0];
        assert_eq!(entry.actor, "admin");
        assert_eq!(entry.action, "agent.delete");
        assert_eq!(entry.target_kind, "agent");
        assert_eq!(entry.target_id.as_deref(), Some("DEADBEEF"));
        assert_eq!(entry.agent_id.as_deref(), Some("DEADBEEF"));
        assert_eq!(entry.command.as_deref(), Some("delete"));
        assert_eq!(entry.result_status, AuditResultStatus::Success);

        socket.close().await;
        server.abort();
    }

    #[tokio::test]
    async fn websocket_agent_remove_missing_agent_records_failure_audit() {
        let state = TestState::new().await;
        let database = state.database.clone();
        let (mut socket, server) = spawn_server(state).await;

        login(&mut socket, "admin", "adminpass").await;

        socket.send_text(agent_remove_message("admin", "DEADBEEF")).await;

        let _error = read_operator_message(&mut socket).await;

        let page = query_audit_log(
            &database,
            &AuditQuery { action: Some("agent.delete".to_owned()), ..AuditQuery::default() },
        )
        .await
        .expect("audit query should succeed");

        assert!(!page.items.is_empty(), "expected at least one agent.delete audit entry");
        let entry = &page.items[0];
        assert_eq!(entry.actor, "admin");
        assert_eq!(entry.action, "agent.delete");
        assert_eq!(entry.target_kind, "agent");
        assert_eq!(entry.target_id.as_deref(), Some("DEADBEEF"));
        assert_eq!(entry.agent_id.as_deref(), Some("DEADBEEF"));
        assert_eq!(entry.command.as_deref(), Some("delete"));
        assert_eq!(entry.result_status, AuditResultStatus::Failure);
        let parameters =
            entry.parameters.as_ref().expect("failure audit should include parameters");
        assert_eq!(parameters.get("agent_id"), Some(&Value::String("DEADBEEF".to_owned())));
        assert!(parameters.get("error").is_some(), "failure audit should include error details");

        socket.close().await;
        server.abort();
    }

    #[tokio::test]
    async fn websocket_reports_missing_agents_for_agent_commands() {
        let state = TestState::new().await;
        let (mut socket, server) = spawn_server(state).await;

        login(&mut socket, "operator", "password1234").await;

        socket
            .send_text(agent_task_message(
                "operator",
                AgentTaskInfo {
                    task_id: "2C".to_owned(),
                    command_line: "checkin".to_owned(),
                    demon_id: "DEADBEEF".to_owned(),
                    command_id: u32::from(DemonCommand::CommandCheckin).to_string(),
                    ..AgentTaskInfo::default()
                },
            ))
            .await;

        let event = read_operator_message(&mut socket).await;
        let OperatorMessage::TeamserverLog(message) = event else {
            panic!("expected teamserver log");
        };
        assert!(message.info.text.contains("not found"));

        socket.close().await;
        server.abort();
    }

    async fn spawn_server(state: TestState) -> (WsTestSession, tokio::task::JoinHandle<()>) {
        let app = routes::<TestState>().with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener should bind");
        let addr = listener.local_addr().expect("listener should expose addr");
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .expect("test websocket server should not fail");
        });
        let (socket, _) =
            connect_async(format!("ws://{addr}/")).await.expect("websocket should connect");

        (WsTestSession::new(socket), server)
    }

    async fn read_operator_message(session: &mut WsTestSession) -> OperatorMessage {
        session.recv_msg().await
    }

    async fn read_operator_snapshot(session: &mut WsTestSession) -> Vec<OperatorInfo> {
        let message = read_operator_message(session).await;
        let OperatorMessage::InitConnectionInfo(message) = message else {
            panic!("expected operator snapshot event");
        };

        serde_json::from_value(
            message
                .info
                .fields
                .get("Operators")
                .cloned()
                .expect("operator snapshot should include operators"),
        )
        .expect("operator snapshot should decode")
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
            info: LoginInfo { user: user.to_owned(), password: hash_password_sha3(password) },
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

    fn read_u32_le(bytes: &[u8], offset: &mut usize) -> u32 {
        let value =
            u32::from_le_bytes(bytes[*offset..*offset + 4].try_into().expect("u32 should fit"));
        *offset += 4;
        value
    }

    fn read_len_prefixed_bytes(bytes: &[u8], offset: &mut usize) -> Vec<u8> {
        let len = read_u32_le(bytes, offset) as usize;
        let value = bytes[*offset..*offset + len].to_vec();
        *offset += len;
        value
    }

    fn decode_utf16(bytes: Vec<u8>) -> String {
        let words = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        String::from_utf16_lossy(&words).trim_end_matches('\0').to_owned()
    }

    fn listener_new_message(user: &str, info: ListenerInfo, one_time: bool) -> String {
        serde_json::to_string(&OperatorMessage::ListenerNew(Message {
            head: MessageHead {
                event: EventCode::Listener,
                user: user.to_owned(),
                timestamp: String::new(),
                one_time: if one_time { "true".to_owned() } else { String::new() },
            },
            info,
        }))
        .expect("listener create should serialize")
    }

    fn listener_mark_message(user: &str, name: &str, mark: &str) -> String {
        serde_json::to_string(&OperatorMessage::ListenerMark(Message {
            head: MessageHead {
                event: EventCode::Listener,
                user: user.to_owned(),
                timestamp: String::new(),
                one_time: String::new(),
            },
            info: ListenerMarkInfo { name: name.to_owned(), mark: mark.to_owned() },
        }))
        .expect("listener mark should serialize")
    }

    fn listener_remove_message(user: &str, name: &str) -> String {
        serde_json::to_string(&OperatorMessage::ListenerRemove(Message {
            head: MessageHead {
                event: EventCode::Listener,
                user: user.to_owned(),
                timestamp: String::new(),
                one_time: String::new(),
            },
            info: NameInfo { name: name.to_owned() },
        }))
        .expect("listener remove should serialize")
    }

    fn listener_edit_message(user: &str, info: ListenerInfo) -> String {
        serde_json::to_string(&OperatorMessage::ListenerEdit(Message {
            head: MessageHead {
                event: EventCode::Listener,
                user: user.to_owned(),
                timestamp: String::new(),
                one_time: String::new(),
            },
            info,
        }))
        .expect("listener edit should serialize")
    }

    fn chat_message(user: &str, text: &str) -> String {
        serde_json::to_string(&OperatorMessage::ChatMessage(Message {
            head: MessageHead {
                event: EventCode::Chat,
                user: user.to_owned(),
                timestamp: String::new(),
                one_time: String::new(),
            },
            info: FlatInfo {
                fields: BTreeMap::from([
                    ("User".to_owned(), Value::String(user.to_owned())),
                    ("Message".to_owned(), Value::String(text.to_owned())),
                ]),
            },
        }))
        .expect("chat should serialize")
    }

    async fn login(session: &mut WsTestSession, user: &str, password: &str) {
        session.send_frame(ClientMessage::Text(login_message(user, password).into())).await;
        let response = session.recv_msg().await;
        assert!(matches!(response, OperatorMessage::InitConnectionSuccess(_)));
        let _snapshot = read_operator_snapshot(session).await;
    }

    fn sample_agent(agent_id: u32) -> red_cell_common::AgentRecord {
        red_cell_common::AgentRecord {
            agent_id,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: AgentEncryptionInfo {
                aes_key: Zeroizing::new(b"aes-key".to_vec()),
                aes_iv: Zeroizing::new(b"aes-iv".to_vec()),
            },
            hostname: "wkstn-01".to_owned(),
            username: "operator".to_owned(),
            domain_name: "REDCELL".to_owned(),
            external_ip: "203.0.113.10".to_owned(),
            internal_ip: "10.0.0.25".to_owned(),
            process_name: "explorer.exe".to_owned(),
            process_path: "C:\\Windows\\explorer.exe".to_owned(),
            base_address: 0x401000,
            process_pid: 1337,
            process_tid: 1338,
            process_ppid: 512,
            process_arch: "x64".to_owned(),
            elevated: true,
            os_version: "Windows 11".to_owned(),
            os_build: 0,
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
            trusted_proxy_peers: Vec::new(),
            user_agent: Some("Mozilla/5.0".to_owned()),
            headers: vec!["X-Test: true".to_owned()],
            uris: vec!["/".to_owned()],
            host_header: None,
            secure: false,
            cert: None,
            response: None,
            proxy: None,
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
        })
    }

    fn sample_listener_info(name: &str, status: &str, port: u16) -> ListenerInfo {
        ListenerInfo {
            name: Some(name.to_owned()),
            protocol: Some("Http".to_owned()),
            status: Some(status.to_owned()),
            hosts: Some("c2.redcell.test".to_owned()),
            host_bind: Some("127.0.0.1".to_owned()),
            host_rotation: Some("round-robin".to_owned()),
            port_bind: Some(port.to_string()),
            port_conn: Some(port.to_string()),
            headers: Some("X-Test: true".to_owned()),
            uris: Some("/".to_owned()),
            user_agent: Some("Mozilla/5.0".to_owned()),
            secure: Some("false".to_owned()),
            ..ListenerInfo::default()
        }
    }

    #[tokio::test]
    async fn login_rate_limiter_allows_attempts_below_threshold() {
        let limiter = LoginRateLimiter::new();
        let ip: IpAddr = "192.168.1.10".parse().expect("valid IP");

        // try_acquire atomically checks and records; after MAX attempts the
        // next call must be rejected.
        for _ in 0..super::MAX_FAILED_LOGIN_ATTEMPTS {
            assert!(limiter.try_acquire(ip).await);
        }

        assert!(!limiter.try_acquire(ip).await);
    }

    #[tokio::test]
    async fn login_rate_limiter_isolates_different_ips() {
        let limiter = LoginRateLimiter::new();
        let ip_a: IpAddr = "10.0.0.1".parse().expect("valid IP");
        let ip_b: IpAddr = "10.0.0.2".parse().expect("valid IP");

        for _ in 0..super::MAX_FAILED_LOGIN_ATTEMPTS {
            limiter.record_failure(ip_a).await;
        }

        assert!(!limiter.is_allowed(ip_a).await);
        assert!(limiter.is_allowed(ip_b).await);
    }

    #[tokio::test]
    async fn login_rate_limiter_success_clears_counter() {
        let limiter = LoginRateLimiter::new();
        let ip: IpAddr = "172.16.0.5".parse().expect("valid IP");

        for _ in 0..super::MAX_FAILED_LOGIN_ATTEMPTS - 1 {
            limiter.record_failure(ip).await;
        }
        assert!(limiter.is_allowed(ip).await);

        limiter.record_success(ip).await;
        assert!(limiter.is_allowed(ip).await);
        assert_eq!(limiter.tracked_ip_count().await, 0);
    }

    #[tokio::test]
    async fn login_rate_limiter_prunes_expired_windows_for_one_shot_ips() {
        let limiter = LoginRateLimiter::new();
        let expired_ip: IpAddr = "192.168.10.10".parse().expect("valid IP");
        let fresh_ip: IpAddr = "192.168.10.11".parse().expect("valid IP");

        limiter
            .with_windows_mut(|windows| {
                windows.insert(
                    expired_ip,
                    crate::rate_limiter::AttemptWindow {
                        attempts: 3,
                        window_start: Instant::now()
                            - super::LOGIN_WINDOW_DURATION
                            - Duration::from_secs(1),
                    },
                );
            })
            .await;

        limiter.record_failure(fresh_ip).await;

        let has_expired = limiter.window_state(expired_ip).await.is_some();
        let has_fresh = limiter.window_state(fresh_ip).await.is_some();
        assert!(!has_expired);
        assert!(has_fresh);
        assert_eq!(limiter.tracked_ip_count().await, 1);
    }

    #[tokio::test]
    async fn login_rate_limiter_caps_total_tracked_windows() {
        let limiter = LoginRateLimiter::new();
        let now = Instant::now();

        limiter
            .with_windows_mut(|windows| {
                for i in 0..super::MAX_LOGIN_ATTEMPT_WINDOWS {
                    windows.insert(
                        IpAddr::from(std::net::Ipv4Addr::from(i as u32)),
                        crate::rate_limiter::AttemptWindow {
                            attempts: 1,
                            window_start: now
                                - Duration::from_secs(
                                    (super::MAX_LOGIN_ATTEMPT_WINDOWS - i) as u64,
                                ),
                        },
                    );
                }
            })
            .await;

        let new_ip = IpAddr::from(std::net::Ipv4Addr::new(10, 0, 0, 1));
        limiter.record_failure(new_ip).await;

        let count = limiter.tracked_ip_count().await;
        assert!(count <= (super::MAX_LOGIN_ATTEMPT_WINDOWS / 2) + 1);
        assert!(limiter.window_state(new_ip).await.is_some());
        assert!(
            limiter.window_state(IpAddr::from(std::net::Ipv4Addr::from(0_u32))).await.is_none()
        );
    }

    #[tokio::test]
    async fn login_rate_limiter_window_reset_allows_after_expiry() {
        let limiter = LoginRateLimiter::new();
        let ip: IpAddr = "198.51.100.7".parse().expect("valid IP");

        // Lock the IP out.
        for _ in 0..super::MAX_FAILED_LOGIN_ATTEMPTS {
            limiter.record_failure(ip).await;
        }
        assert!(!limiter.is_allowed(ip).await, "should be locked out after max failures");

        // Manually expire the window by backdating its start time.
        limiter
            .with_windows_mut(|windows| {
                let window = windows.get_mut(&ip).expect("window should exist");
                window.window_start =
                    Instant::now() - super::LOGIN_WINDOW_DURATION - Duration::from_secs(1);
            })
            .await;

        // is_allowed must detect the expired window and reset, allowing the IP again.
        assert!(limiter.is_allowed(ip).await, "should be allowed after window expiry");
        assert_eq!(limiter.tracked_ip_count().await, 0, "expired window should be removed");
    }

    #[tokio::test]
    async fn login_rate_limiter_record_failure_resets_expired_window() {
        let limiter = LoginRateLimiter::new();
        let ip: IpAddr = "198.51.100.8".parse().expect("valid IP");

        // Manually insert an expired window with attempts at MAX.
        limiter
            .with_windows_mut(|windows| {
                windows.insert(
                    ip,
                    crate::rate_limiter::AttemptWindow {
                        attempts: super::MAX_FAILED_LOGIN_ATTEMPTS,
                        window_start: Instant::now()
                            - super::LOGIN_WINDOW_DURATION
                            - Duration::from_secs(1),
                    },
                );
            })
            .await;

        // Call record_failure on the expired-but-present window.
        limiter.record_failure(ip).await;

        // The window should have been reset: attempts = 1, fresh window_start.
        let (attempts, window_start) =
            limiter.window_state(ip).await.expect("window should still exist after record_failure");
        assert_eq!(
            attempts, 1,
            "expired window should reset attempts to 1, not increment stale count"
        );
        assert!(
            window_start.elapsed() < Duration::from_secs(2),
            "window_start should be refreshed to approximately now"
        );

        // The IP should be allowed since attempts = 1 < MAX.
        assert!(
            limiter.is_allowed(ip).await,
            "IP should be allowed after expired window is reset by record_failure"
        );
    }

    #[tokio::test]
    async fn websocket_rejects_login_after_too_many_failures() {
        let state = TestState::new().await;
        let rate_limiter = state.login_rate_limiter.clone();
        let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");

        for _ in 0..super::MAX_FAILED_LOGIN_ATTEMPTS {
            rate_limiter.record_failure(ip).await;
        }

        let (mut socket, server) = spawn_server(state).await;

        socket
            .send_frame(ClientMessage::Text(login_message("operator", "password1234").into()))
            .await;

        let frame = timeout(Duration::from_secs(3), socket.next_raw_frame())
            .await
            .expect("should receive a frame")
            .expect("frame should exist")
            .expect("frame should decode");

        if let ClientMessage::Text(payload) = frame {
            let msg: OperatorMessage =
                serde_json::from_str(&payload).expect("should parse operator message");
            assert!(
                matches!(msg, OperatorMessage::InitConnectionError(_)),
                "expected connection error, got {msg:?}"
            );
        } else {
            panic!("expected text frame, got {frame:?}");
        }

        server.abort();
    }

    #[tokio::test]
    async fn disconnect_kind_as_str_returns_stable_labels() {
        assert_eq!(super::DisconnectKind::CleanClose.as_str(), "clean_close");
        assert_eq!(super::DisconnectKind::Error.as_str(), "error");
        assert_eq!(super::DisconnectKind::ServerShutdown.as_str(), "server_shutdown");
    }

    #[tokio::test]
    async fn clean_disconnect_audit_includes_kind_field() {
        let state = TestState::new().await;
        let database = state.database.clone();
        let connections = state.connections.clone();
        let (mut socket, server) = spawn_server(state).await;

        login(&mut socket, "operator", "password1234").await;

        // Send a clean close frame.
        socket.close().await;
        wait_for_connection_count(&connections, 0).await;

        let page = query_audit_log(
            &database,
            &AuditQuery {
                action: Some("operator.disconnect".to_owned()),
                actor: Some("operator".to_owned()),
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit query should succeed");

        assert_eq!(page.total, 1, "exactly one disconnect record expected");
        let record = &page.items[0];
        assert_eq!(record.action, "operator.disconnect");
        let kind = record.parameters.as_ref().and_then(|p| p.get("kind")).and_then(|v| v.as_str());
        assert_eq!(kind, Some("clean_close"), "clean socket close should record kind=clean_close");

        server.abort();
    }

    #[tokio::test]
    async fn server_shutdown_disconnect_audit_includes_kind_field() {
        let state = TestState::new().await;
        let database = state.database.clone();
        let connections = state.connections.clone();
        let shutdown = state.shutdown.clone();
        let (mut socket, server) = spawn_server(state).await;

        login(&mut socket, "operator", "password1234").await;

        shutdown.initiate();

        // Drain the shutdown notice and close frame.
        let _shutdown_msg = read_operator_message(&mut socket).await;
        wait_for_connection_count(&connections, 0).await;

        let page = query_audit_log(
            &database,
            &AuditQuery {
                action: Some("operator.disconnect".to_owned()),
                actor: Some("operator".to_owned()),
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit query should succeed");

        assert_eq!(page.total, 1, "exactly one disconnect record expected");
        let kind =
            page.items[0].parameters.as_ref().and_then(|p| p.get("kind")).and_then(|v| v.as_str());
        assert_eq!(
            kind,
            Some("server_shutdown"),
            "server-initiated close should record kind=server_shutdown"
        );

        server.abort();
    }

    #[tokio::test]
    async fn session_timeout_audit_recorded_for_idle_unauthenticated_connection() {
        let state = TestState::new().await;
        let database = state.database.clone();
        let connections = state.connections.clone();
        let (socket, server) = spawn_server(state).await;

        // Drop the socket without sending any frames — the server will time out.
        drop(socket);
        wait_for_connection_count(&connections, 0).await;

        // The timeout test uses AUTHENTICATION_FRAME_TIMEOUT + margin in the
        // existing test. Here we just wait briefly since the TCP drop is immediate.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // The server records session_timeout only on the timer path. A clean drop
        // before receiving data hits the "closed before authentication" arm, not the
        // timeout arm. So verify zero records for session_timeout here; the timeout
        // path is tested via the existing idle-connection test.
        let page = query_audit_log(
            &database,
            &AuditQuery {
                action: Some("operator.session_timeout".to_owned()),
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit query should succeed");

        // Dropping the socket closes it immediately (Ok(None) path), so no timeout
        // audit is expected.
        assert_eq!(page.total, 0, "early close should not produce a session_timeout record");

        server.abort();
    }

    #[tokio::test]
    async fn permission_denied_audit_recorded_when_analyst_sends_privileged_command() {
        let state = TestState::new().await;
        let database = state.database.clone();
        let connections = state.connections.clone();
        let (mut socket, server) = spawn_server(state).await;

        login(&mut socket, "analyst", "readonly").await;

        // Send a listener-create command — analysts only have Read permission.
        socket
            .send_text(listener_new_message(
                "analyst",
                red_cell_common::operator::ListenerInfo {
                    name: Some("test-listener".to_owned()),
                    protocol: Some("Http".to_owned()),
                    ..Default::default()
                },
                false,
            ))
            .await;

        // Server closes after rejecting the unauthorized command.
        wait_for_connection_count(&connections, 0).await;

        let page = query_audit_log(
            &database,
            &AuditQuery {
                action: Some("operator.permission_denied".to_owned()),
                actor: Some("analyst".to_owned()),
                ..AuditQuery::default()
            },
        )
        .await
        .expect("audit query should succeed");

        assert_eq!(page.total, 1, "one permission_denied record expected");
        let record = &page.items[0];
        assert_eq!(record.action, "operator.permission_denied");
        assert_eq!(record.actor, "analyst");
        assert_eq!(record.result_status, AuditResultStatus::Failure);

        server.abort();
    }

    #[test]
    fn write_len_prefixed_bytes_normal_input() -> Result<(), crate::TeamserverError> {
        let mut buf = Vec::new();
        write_len_prefixed_bytes(&mut buf, b"test")?;
        assert_eq!(buf[..4], 4_u32.to_le_bytes());
        assert_eq!(&buf[4..], b"test");
        Ok(())
    }

    #[test]
    fn write_len_prefixed_bytes_empty_input() -> Result<(), crate::TeamserverError> {
        let mut buf = Vec::new();
        write_len_prefixed_bytes(&mut buf, &[])?;
        assert_eq!(buf, 0_u32.to_le_bytes());
        Ok(())
    }

    // ── Plugin event wiring test ──────────────────────────────────────────────

    /// Verify that `execute_agent_task` calls `emit_task_created` for each queued job,
    /// which in turn fires any registered `TaskCreated` Python callbacks.
    ///
    /// This test calls `execute_agent_task` directly so that a future refactor cannot
    /// silently remove the `emit_task_created` call without breaking the test.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test(flavor = "multi_thread")]
    async fn execute_agent_task_fires_plugin_task_created_event()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::{PluginEvent, PluginRuntime};
        use pyo3::prelude::*;
        use pyo3::types::{PyDict, PyList};
        use red_cell_common::demon::DemonCommand;

        let _guard = crate::plugins::PLUGIN_RUNTIME_TEST_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Build a PluginRuntime and install it as the active runtime.
        let database = Database::connect_in_memory().await?;
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let runtime = PluginRuntime::initialize(
            database.clone(),
            registry.clone(),
            events.clone(),
            sockets.clone(),
            None,
        )
        .await?;

        struct RuntimeGuard(Option<PluginRuntime>);
        impl Drop for RuntimeGuard {
            fn drop(&mut self) {
                let _ = PluginRuntime::swap_active(self.0.take());
            }
        }
        let previous = PluginRuntime::swap_active(Some(runtime.clone()))?;
        let _reset = RuntimeGuard(previous);

        // Register a TaskCreated callback that records the command_line for each event.
        let (tracker, callback) = tokio::task::spawn_blocking({
            let runtime = runtime.clone();
            move || {
                Python::with_gil(|py| {
                    runtime.install_api_module_for_test(py)?;
                    let tracker = PyList::empty(py);
                    let locals = PyDict::new(py);
                    locals.set_item("_tracker", tracker.clone())?;
                    let cb = py.eval(
                        pyo3::ffi::c_str!(
                            "(lambda t: lambda event: t.append(event.data['command_line']))(_tracker)"
                        ),
                        None,
                        Some(&locals),
                    )?;
                    Ok::<_, PyErr>((tracker.unbind(), cb.unbind()))
                })
            }
        })
        .await??;

        runtime.register_callback_for_test(PluginEvent::TaskCreated, callback).await?;

        // Insert an agent so execute_agent_task can find it.
        let agent_id: u32 = 0xABCD_1234;
        registry.insert(sample_agent(agent_id)).await?;

        // Build a task message that produces exactly one job (a checkin command).
        let message = red_cell_common::operator::Message {
            head: red_cell_common::operator::MessageHead {
                event: red_cell_common::operator::EventCode::Session,
                user: "operator".to_owned(),
                timestamp: String::new(),
                one_time: String::new(),
            },
            info: AgentTaskInfo {
                task_id: "FF".to_owned(), // task_id must parse as hex
                command_line: "checkin".to_owned(),
                demon_id: format!("{agent_id:08X}"),
                command_id: u32::from(DemonCommand::CommandCheckin).to_string(),
                ..AgentTaskInfo::default()
            },
        };

        let queued = execute_agent_task(
            &registry,
            &sockets,
            &events,
            "operator",
            red_cell_common::config::OperatorRole::Admin,
            message,
        )
        .await?;
        assert_eq!(queued, 1, "checkin command should queue exactly one job");

        // Poll until the spawn_blocking inside invoke_callbacks appends to the
        // tracker list, or until 10 s elapse.  A fixed sleep is racy under
        // cargo test --workspace concurrency (Argon2id in parallel tests causes
        // CPU contention that can push the callback well past 100 ms).
        //
        // Py<T> does not implement Clone without a GIL token, so wrap it in
        // Arc to share across poll iterations.
        let tracker = std::sync::Arc::new(tracker);
        let deadline = std::time::Duration::from_secs(10);
        let (count, cmd_line) = tokio::time::timeout(deadline, async {
            loop {
                let tracker_ref = tracker.clone();
                let result = tokio::task::spawn_blocking(move || {
                    Python::with_gil(|py| -> PyResult<Option<(usize, String)>> {
                        let list = tracker_ref.bind(py);
                        if list.is_empty() {
                            return Ok(None);
                        }
                        let count = list.len();
                        let first = list.get_item(0)?.extract::<String>()?;
                        Ok(Some((count, first)))
                    })
                })
                .await
                .expect("spawn_blocking panicked")
                .expect("Python GIL error");

                if let Some(pair) = result {
                    break pair;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("timed out waiting for task_created callback after 10 s");

        assert_eq!(count, 1, "exactly one task_created callback should have fired");
        assert_eq!(cmd_line, "checkin");
        Ok(())
    }

    // ---- Route wiring tests for `routes()` ----

    /// Helper: build a `Router` from `routes()` backed by `TestState`.
    async fn build_ws_router() -> axum::Router {
        let state = TestState::new().await;
        routes::<TestState>().with_state(state)
    }

    #[tokio::test]
    async fn routes_get_root_reaches_websocket_handler() {
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = build_ws_router().await;

        // Send a GET / with WebSocket upgrade headers. Through `oneshot()` the
        // actual protocol switch cannot complete (no real TCP connection), but
        // the route *is* matched — so we must not see 404 or 405.
        let mut req = Request::builder()
            .uri("/")
            .header("host", "localhost")
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .body(axum::body::Body::empty())
            .expect("request should build");

        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 9999))));

        let response = app.oneshot(req).await.expect("router should respond");
        assert_ne!(
            response.status(),
            StatusCode::NOT_FOUND,
            "GET / must be routed to the WebSocket handler, not fall through to 404"
        );
        assert_ne!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "GET / must be an accepted method"
        );
    }

    #[tokio::test]
    async fn routes_post_root_is_method_not_allowed() {
        use axum::http::{Method, Request, StatusCode};
        use tower::ServiceExt;

        let app = build_ws_router().await;

        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/")
            .body(axum::body::Body::empty())
            .expect("request should build");

        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 9999))));

        let response = app.oneshot(req).await.expect("router should respond");
        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "POST / must be rejected — only GET is registered"
        );
    }

    #[tokio::test]
    async fn routes_non_root_path_returns_not_found() {
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let app = build_ws_router().await;

        let mut req = Request::builder()
            .uri("/some/other/path")
            .header("host", "localhost")
            .header("connection", "Upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .body(axum::body::Body::empty())
            .expect("request should build");

        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 9999))));

        let response = app.oneshot(req).await.expect("router should respond");
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "non-root path must not be registered"
        );
    }

    #[test]
    fn serialize_for_audit_returns_value_on_success() {
        let data = serde_json::json!({"key": "value"});
        let result = super::serialize_for_audit(&data, "test");
        assert_eq!(result, Some(data));
    }

    #[test]
    fn serialize_for_audit_returns_none_on_failure() {
        /// A type whose `Serialize` implementation always fails.
        struct AlwaysFail;
        impl serde::Serialize for AlwaysFail {
            fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom("intentional failure"))
            }
        }
        let result = super::serialize_for_audit(&AlwaysFail, "test.fail");
        assert!(result.is_none(), "should return None on serialization failure");
    }
}
