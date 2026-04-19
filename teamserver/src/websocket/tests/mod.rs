use std::collections::BTreeMap;
use std::time::Duration;

use axum::extract::FromRef;
use futures_util::{SinkExt, StreamExt};
use red_cell_common::{
    AgentEncryptionInfo, OperatorInfo,
    config::Profile,
    operator::{
        AgentTaskInfo, EventCode, FlatInfo, ListenerInfo, ListenerMarkInfo, LoginInfo, Message,
        MessageHead, NameInfo, OperatorMessage,
    },
};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::{connect_async, tungstenite::Message as ClientMessage};

use super::{LoginRateLimiter, OperatorConnectionManager, routes, teamserver_log_event};
use crate::{
    AgentRegistry, AuditWebhookNotifier, AuthService, Database, EventBus, ListenerManager,
    PayloadBuilderService, ShutdownController, SocketRelayManager,
};
use red_cell_common::crypto::{
    WsEnvelope, derive_ws_hmac_key, hash_password_sha3, open_ws_frame, seal_ws_frame,
};
use zeroize::Zeroizing;

mod agents;
mod auth;
mod lifecycle;
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
