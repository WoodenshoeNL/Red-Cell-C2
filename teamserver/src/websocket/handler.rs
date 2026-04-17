//! Operator WebSocket route, upgrade handler, and per-connection event loop.
//!
//! This is the entry point that ties together authentication, snapshot
//! synchronization, command dispatch, and lifecycle cleanup for a single
//! operator session.

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
use red_cell_common::crypto::{WsEnvelope, open_ws_frame};
use red_cell_common::operator::OperatorMessage;
use serde_json::Value;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use super::auth::handle_authentication;
use super::connection::{
    DisconnectKind, OPERATOR_MAX_MESSAGE_SIZE, OperatorConnectionManager, SocketLoopControl,
    WsSession, send_hmac_message, send_operator_message,
};
use super::dispatch::dispatch_operator_command;
use super::events::{chat_presence_event, teamserver_shutdown_event};
use super::lifecycle::{cleanup_connection, first_online_session, log_operator_action};
use super::snapshot::send_session_snapshot;
use crate::{
    AgentRegistry, AuditResultStatus, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, LoginRateLimiter, PayloadBuilderService, SessionActivity, SessionExpiryReason,
    ShutdownController, SocketRelayManager, audit_details, authorize_websocket_command,
    parameter_object, session_expired_message,
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

    connections.register(connection_id, client_ip).await;

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
        &database,
        &session.username,
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

async fn handle_incoming_frame<S>(
    state: &S,
    socket: &mut WebSocket,
    session: &crate::OperatorSession,
    incoming: Option<Result<WsMessage, axum::Error>>,
    ws_session: &mut WsSession,
) -> Result<SocketLoopControl, ()>
where
    S: Clone + Send + Sync + 'static,
    AuthService: FromRef<S>,
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

            let auth = AuthService::from_ref(state);
            match auth.touch_session_activity(session.connection_id).await {
                SessionActivity::Ok => {}
                SessionActivity::Expired { reason, username } => {
                    report_session_expired(state, socket, session, ws_session, reason, &username)
                        .await;
                    return Err(());
                }
                SessionActivity::NotFound => {
                    warn!(
                        connection_id = %session.connection_id,
                        username = %session.username,
                        "session no longer registered; closing operator connection"
                    );
                    if let Err(e) = socket.send(WsMessage::Close(None)).await {
                        debug!(%e, "failed to send close frame after session_not_found");
                    }
                    return Err(());
                }
            }

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

/// Notify the operator that their authenticated session has been revoked
/// server-side, record an audit entry, and close the WebSocket.
///
/// Used when [`AuthService::touch_session_activity`] reports that the session's
/// TTL or idle timeout has elapsed between frames.
async fn report_session_expired<S>(
    state: &S,
    socket: &mut WebSocket,
    session: &crate::OperatorSession,
    ws_session: &mut WsSession,
    reason: SessionExpiryReason,
    username: &str,
) where
    S: Clone + Send + Sync + 'static,
    AuditWebhookNotifier: FromRef<S>,
    Database: FromRef<S>,
{
    warn!(
        connection_id = %session.connection_id,
        username,
        reason = reason.as_reason_str(),
        "operator session expired; revoking"
    );

    let database = Database::from_ref(state);
    let webhooks = AuditWebhookNotifier::from_ref(state);
    log_operator_action(
        &database,
        &webhooks,
        username,
        "operator.session_timeout",
        "operator",
        Some(username.to_owned()),
        audit_details(
            AuditResultStatus::Failure,
            None,
            Some(reason.as_reason_str()),
            Some(parameter_object([
                ("connection_id", Value::String(session.connection_id.to_string())),
                ("reason", Value::String(reason.as_reason_str().to_owned())),
            ])),
        ),
    )
    .await;

    if let Err(error) =
        send_hmac_message(socket, &session_expired_message(username, reason), ws_session).await
    {
        debug!(%error, "failed to send session-expired message to operator");
    }
    if let Err(e) = socket.send(WsMessage::Close(None)).await {
        debug!(%e, "failed to send close frame after session expiry");
    }
}
