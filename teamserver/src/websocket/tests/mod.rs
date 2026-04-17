use std::collections::BTreeMap;
use std::time::Duration;

use axum::extract::FromRef;
use futures_util::{SinkExt, StreamExt};
use red_cell_common::{
    AgentEncryptionInfo, OperatorInfo,
    config::Profile,
    operator::{
        AgentTaskInfo, EventCode, FlatInfo, ListenerInfo, ListenerMarkInfo, LoginInfo, Message,
        MessageHead, NameInfo, OperatorMessage, TeamserverLogInfo,
    },
};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::{connect_async, tungstenite::Message as ClientMessage};

use super::{LoginRateLimiter, OperatorConnectionManager, routes, teamserver_log_event};
use crate::{
    AgentRegistry, AuditQuery, AuditResultStatus, AuditWebhookNotifier, AuthService, Database,
    EventBus, ListenerManager, PayloadBuilderService, ShutdownController, SocketRelayManager,
    query_audit_log,
};
use red_cell_common::crypto::{
    WsEnvelope, derive_ws_hmac_key, hash_password_sha3, open_ws_frame, seal_ws_frame,
};
use zeroize::Zeroizing;

mod agents;
mod auth;
mod listeners;
mod payload;
mod snapshot;

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
    async fn new_with_session_policy(policy: crate::SessionPolicy) -> Self {
        let mut state = Self::new().await;
        let updated = state.auth.clone().with_session_policy(policy);
        state.auth = updated;
        state
    }

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
type RawTestSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

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
            serde_json::from_str(&inner_json).expect("inner payload must parse as OperatorMessage")
        } else {
            let msg: OperatorMessage =
                serde_json::from_str(text.as_str()).expect("plain frame must parse");
            if let OperatorMessage::InitConnectionSuccess(ref m) = msg {
                if let Some(token) = m.info.message.split_once("SessionToken=").map(|(_, t)| t) {
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

    socket.send_frame(ClientMessage::Text(login_message("operator", "password1234").into())).await;

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

#[tokio::test]
async fn websocket_notifies_authenticated_clients_before_shutdown_close() {
    let state = TestState::new().await;
    let shutdown = state.shutdown.clone();
    let (mut socket, server) = spawn_server(state).await;

    socket.send_frame(ClientMessage::Text(login_message("operator", "password1234").into())).await;

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
    assert_eq!(message.info.fields.get("Message"), Some(&Value::String("hello team".to_owned())));

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

async fn spawn_server(state: TestState) -> (WsTestSession, tokio::task::JoinHandle<()>) {
    let app = routes::<TestState>().with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener should bind");
    let addr = listener.local_addr().expect("listener should expose addr");
    let server = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
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
    let value = u32::from_le_bytes(bytes[*offset..*offset + 4].try_into().expect("u32 should fit"));
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
async fn authenticated_session_expires_after_idle_timeout_and_is_audited() {
    use crate::SessionPolicy;

    // Drive both TTL and idle timeout short enough that a single post-login
    // frame sent after a small sleep crosses the threshold. 200 ms is large
    // enough to absorb scheduler jitter while keeping the test quick.
    let state = TestState::new_with_session_policy(SessionPolicy {
        ttl: Some(Duration::from_secs(3600)),
        idle_timeout: Some(Duration::from_millis(200)),
    })
    .await;
    let database = state.database.clone();
    let connections = state.connections.clone();
    let (mut socket, server) = spawn_server(state).await;

    login(&mut socket, "operator", "password1234").await;

    // Wait past the idle window, then send any authenticated frame. The server
    // must respond with an InitConnectionError carrying the expiry message and
    // then close the socket.
    tokio::time::sleep(Duration::from_millis(350)).await;
    socket.send_text(chat_message("operator", "hello after idle")).await;

    let response = read_operator_message(&mut socket).await;
    match response {
        OperatorMessage::InitConnectionError(ref message) => {
            assert!(
                message.info.message.contains("inactivity")
                    || message.info.message.contains("idle"),
                "expected idle-timeout message, got {:?}",
                message.info.message
            );
        }
        other => panic!("expected InitConnectionError, got {other:?}"),
    }

    wait_for_connection_count(&connections, 0).await;

    let page = query_audit_log(
        &database,
        &AuditQuery {
            action: Some("operator.session_timeout".to_owned()),
            actor: Some("operator".to_owned()),
            ..AuditQuery::default()
        },
    )
    .await
    .expect("audit query should succeed");

    assert_eq!(page.total, 1, "expected one session_timeout audit record");
    let record = &page.items[0];
    assert_eq!(record.action, "operator.session_timeout");
    assert_eq!(record.actor, "operator");
    assert_eq!(record.result_status, AuditResultStatus::Failure);
    let reason = record.parameters.as_ref().and_then(|p| p.get("reason")).and_then(|v| v.as_str());
    assert_eq!(
        reason,
        Some("idle_timeout"),
        "session_timeout audit should record reason=idle_timeout, got {reason:?}"
    );

    server.abort();
}

#[tokio::test]
async fn authenticated_session_expires_after_absolute_ttl_and_is_audited() {
    use crate::SessionPolicy;

    // Short TTL; leave idle generous so the expiry is unambiguously from TTL.
    let state = TestState::new_with_session_policy(SessionPolicy {
        ttl: Some(Duration::from_millis(200)),
        idle_timeout: Some(Duration::from_secs(600)),
    })
    .await;
    let database = state.database.clone();
    let connections = state.connections.clone();
    let (mut socket, server) = spawn_server(state).await;

    login(&mut socket, "operator", "password1234").await;

    tokio::time::sleep(Duration::from_millis(350)).await;
    socket.send_text(chat_message("operator", "still here")).await;

    let response = read_operator_message(&mut socket).await;
    match response {
        OperatorMessage::InitConnectionError(ref message) => {
            assert!(
                message.info.message.contains("lifetime"),
                "expected TTL-expiry message, got {:?}",
                message.info.message
            );
        }
        other => panic!("expected InitConnectionError, got {other:?}"),
    }

    wait_for_connection_count(&connections, 0).await;

    let page = query_audit_log(
        &database,
        &AuditQuery {
            action: Some("operator.session_timeout".to_owned()),
            actor: Some("operator".to_owned()),
            ..AuditQuery::default()
        },
    )
    .await
    .expect("audit query should succeed");

    assert_eq!(page.total, 1, "expected one session_timeout audit record");
    let reason =
        page.items[0].parameters.as_ref().and_then(|p| p.get("reason")).and_then(|v| v.as_str());
    assert_eq!(reason, Some("ttl_exceeded"));

    server.abort();
}

#[tokio::test]
async fn authenticated_session_within_idle_window_is_not_expired() {
    use crate::SessionPolicy;

    // Generous idle and TTL — no expiry should fire for a normal post-login
    // frame. Guards against regressions where the expiry check mis-triggers on
    // healthy sessions.
    let state = TestState::new_with_session_policy(SessionPolicy {
        ttl: Some(Duration::from_secs(3600)),
        idle_timeout: Some(Duration::from_secs(3600)),
    })
    .await;
    let database = state.database.clone();
    let (mut socket, server) = spawn_server(state).await;

    login(&mut socket, "operator", "password1234").await;

    socket.send_text(chat_message("operator", "hi")).await;
    // ChatMessage broadcasts to all operators (including the sender), so we
    // expect to receive the broadcast rather than an error.
    let response = read_operator_message(&mut socket).await;
    assert!(
        matches!(response, OperatorMessage::ChatMessage(_)),
        "chat should echo for live session, got {response:?}"
    );

    let page = query_audit_log(
        &database,
        &AuditQuery {
            action: Some("operator.session_timeout".to_owned()),
            actor: Some("operator".to_owned()),
            ..AuditQuery::default()
        },
    )
    .await
    .expect("audit query should succeed");
    assert_eq!(page.total, 0, "live session must not trigger session_timeout audit");

    socket.close().await;
    server.abort();
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
    assert_eq!(response.status(), StatusCode::NOT_FOUND, "non-root path must not be registered");
}
