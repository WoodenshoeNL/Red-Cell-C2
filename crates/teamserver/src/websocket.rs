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
use red_cell_common::operator::OperatorMessage;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::{
    AuthError, AuthService, AuthenticationFailure, AuthenticationResult, EventBus,
    authorize_websocket_command, login_failure_message, login_success_message,
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
    OperatorConnectionManager: FromRef<S>,
{
    websocket.on_upgrade(move |socket| handle_operator_socket(state, socket))
}

async fn handle_operator_socket<S>(state: S, mut socket: WebSocket)
where
    S: Clone + Send + Sync + 'static,
    AuthService: FromRef<S>,
    EventBus: FromRef<S>,
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

    let mut event_receiver = EventBus::from_ref(&state).subscribe();

    loop {
        tokio::select! {
            incoming = socket.recv() => {
                match handle_incoming_frame(&mut socket, &session, incoming).await {
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

async fn handle_incoming_frame(
    socket: &mut WebSocket,
    session: &crate::OperatorSession,
    incoming: Option<Result<WsMessage, axum::Error>>,
) -> Result<SocketLoopControl, ()> {
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

                    dispatch_operator_command(session, message).await;
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

async fn dispatch_operator_command(session: &crate::OperatorSession, message: OperatorMessage) {
    debug!(
        connection_id = %session.connection_id,
        username = %session.username,
        event = ?message.event_code(),
        "operator websocket command has no registered handler yet"
    );
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
    use std::time::Duration;

    use axum::extract::FromRef;
    use futures_util::{SinkExt, StreamExt};
    use red_cell_common::{
        config::Profile,
        operator::{
            AgentTaskInfo, EventCode, LoginInfo, Message, MessageHead, OperatorMessage,
            SessionCode, TeamserverLogInfo,
        },
    };
    use tokio::net::TcpListener;
    use tokio::time::timeout;
    use tokio_tungstenite::{connect_async, tungstenite::Message as ClientMessage};
    use uuid::Uuid;

    use super::{OperatorConnectionManager, routes};
    use crate::{AuthService, EventBus, hash_password};

    #[derive(Clone)]
    struct TestState {
        auth: AuthService,
        events: EventBus,
        connections: OperatorConnectionManager,
    }

    impl TestState {
        fn new() -> Self {
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
                }

                Demon {}
                "#,
            )
            .expect("test profile should parse");

            Self {
                auth: AuthService::from_profile(&profile),
                events: EventBus::default(),
                connections: OperatorConnectionManager::new(),
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
        let state = TestState::new();
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
        let state = TestState::new();
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
    async fn websocket_closes_when_authenticated_operator_lacks_permission() {
        let state = TestState::new();
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
}
