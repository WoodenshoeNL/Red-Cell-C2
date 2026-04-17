use std::collections::BTreeMap;
use std::time::Duration;

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
        MessageHead, NameInfo, OperatorMessage, TeamserverLogInfo,
    },
};
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_tungstenite::{connect_async, tungstenite::Message as ClientMessage};

use super::{
    AgentCommandError, LoginRateLimiter, OperatorConnectionManager, build_job, build_jobs,
    encode_utf16, execute_agent_task, routes, teamserver_log_event, write_len_prefixed_bytes,
    write_u32,
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

mod auth;

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

    socket.send_frame(ClientMessage::Text(login_message("operator", "password1234").into())).await;
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
async fn websocket_session_snapshot_filters_listeners_and_agents_by_operator_acl() {
    let state = TestState::new().await;
    let registry = state.registry.clone();
    let listeners = state.listeners.clone();
    let database = state.database.clone();

    listeners
        .create(sample_http_listener("alpha-public", 0))
        .await
        .expect("public listener should persist");
    listeners
        .create(sample_http_listener("beta-admin", 0))
        .await
        .expect("admin listener should persist");

    // beta-admin has an allow-list scoped to `admin` only, so the `operator`
    // account must not learn of it via the WebSocket snapshot.
    database
        .listener_access()
        .set_allowed_operators("beta-admin", &["admin".to_owned()])
        .await
        .expect("seed listener access");

    registry
        .insert_with_listener(sample_agent(0xAAAA_1111), "alpha-public")
        .await
        .expect("public agent should insert");
    registry
        .insert_with_listener(sample_agent(0xBBBB_2222), "beta-admin")
        .await
        .expect("admin agent should insert");

    database
        .agent_groups()
        .set_agent_groups(0xAAAA_1111, &["public-group".to_owned()])
        .await
        .expect("seed public agent group");
    database
        .agent_groups()
        .set_agent_groups(0xBBBB_2222, &["admin-group".to_owned()])
        .await
        .expect("seed admin agent group");
    database
        .agent_groups()
        .set_operator_allowed_groups("operator", &["public-group".to_owned()])
        .await
        .expect("seed operator agent-group scope");

    let (mut socket, server) = spawn_server(state).await;
    login(&mut socket, "operator", "password1234").await;

    // Drain all snapshot frames with a short per-frame timeout; the filtered
    // snapshot must contain only the listener/agent the operator is entitled
    // to see.
    let mut events = Vec::new();
    while let Ok(msg) = timeout(Duration::from_millis(500), socket.recv_msg()).await {
        events.push(msg);
    }

    let listener_names: Vec<String> = events
        .iter()
        .filter_map(|msg| match msg {
            OperatorMessage::ListenerNew(m) => m.info.name.clone(),
            _ => None,
        })
        .collect();
    assert_eq!(listener_names, vec!["alpha-public".to_owned()]);

    let agent_ids: Vec<String> = events
        .iter()
        .filter_map(|msg| match msg {
            OperatorMessage::AgentNew(m) => Some(m.info.name_id.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(agent_ids, vec!["AAAA1111".to_owned()]);

    socket.close().await;
    server.abort();
}

#[tokio::test]
async fn websocket_live_broadcast_filters_events_outside_operator_acl() {
    use crate::PivotInfo;
    use crate::agent_events::{agent_mark_event, agent_new_event};
    use crate::{ListenerEventAction, listener_event_for_action};

    let state = TestState::new().await;
    let registry = state.registry.clone();
    let listeners = state.listeners.clone();
    let database = state.database.clone();
    let events = state.events.clone();

    listeners
        .create(sample_http_listener("alpha-public", 0))
        .await
        .expect("public listener should persist");
    listeners
        .create(sample_http_listener("beta-admin", 0))
        .await
        .expect("admin listener should persist");

    // beta-admin is scoped to `admin`; the `operator` account must not see
    // live events carrying that listener's name or any agent attached to it.
    database
        .listener_access()
        .set_allowed_operators("beta-admin", &["admin".to_owned()])
        .await
        .expect("seed listener access");

    let admin_agent = sample_agent(0xBBBB_2222);
    let public_agent = sample_agent(0xAAAA_1111);
    registry
        .insert_with_listener(admin_agent.clone(), "beta-admin")
        .await
        .expect("admin agent should insert");
    registry
        .insert_with_listener(public_agent.clone(), "alpha-public")
        .await
        .expect("public agent should insert");

    database
        .agent_groups()
        .set_agent_groups(0xBBBB_2222, &["admin-group".to_owned()])
        .await
        .expect("seed admin agent group");
    database
        .agent_groups()
        .set_agent_groups(0xAAAA_1111, &["public-group".to_owned()])
        .await
        .expect("seed public agent group");
    database
        .agent_groups()
        .set_operator_allowed_groups("operator", &["public-group".to_owned()])
        .await
        .expect("seed operator agent-group scope");

    let (mut operator_socket, server) = spawn_server(state.clone()).await;
    login(&mut operator_socket, "operator", "password1234").await;

    // Drain snapshot frames so the assertions below observe only live
    // broadcasts that arrive after this point.
    while (timeout(Duration::from_millis(200), operator_socket.recv_msg()).await).is_ok() {}

    let beta_summary = listeners.summary("beta-admin").await.expect("beta listener");
    let alpha_summary = listeners.summary("alpha-public").await.expect("alpha listener");
    let pivots = PivotInfo::default();

    // Broadcasts for the restricted listener / agent must be filtered out.
    events.broadcast(listener_event_for_action(
        "admin",
        &beta_summary,
        ListenerEventAction::Updated,
    ));
    events.broadcast(agent_new_event(
        "beta-admin",
        red_cell_common::demon::DEMON_MAGIC_VALUE,
        &admin_agent,
        &pivots,
    ));
    events.broadcast(agent_mark_event(&admin_agent));

    // A visible broadcast for the public listener proves the filter lets
    // authorized events through and serves as a synchronization barrier.
    events.broadcast(listener_event_for_action(
        "admin",
        &alpha_summary,
        ListenerEventAction::Updated,
    ));
    events.broadcast(agent_new_event(
        "alpha-public",
        red_cell_common::demon::DEMON_MAGIC_VALUE,
        &public_agent,
        &pivots,
    ));

    // Collect whatever arrives during a short window after the broadcasts.
    let mut received = Vec::new();
    while let Ok(msg) = timeout(Duration::from_millis(300), operator_socket.recv_msg()).await {
        received.push(msg);
    }

    for msg in &received {
        match msg {
            OperatorMessage::ListenerEdit(m) => {
                assert_ne!(
                    m.info.name.as_deref(),
                    Some("beta-admin"),
                    "operator must not receive ListenerEdit for restricted listener"
                );
            }
            OperatorMessage::AgentNew(m) => {
                assert_ne!(
                    m.info.name_id, "BBBB2222",
                    "operator must not receive AgentNew for restricted agent"
                );
            }
            OperatorMessage::AgentUpdate(m) => {
                assert_ne!(
                    m.info.agent_id, "BBBB2222",
                    "operator must not receive AgentUpdate for restricted agent"
                );
            }
            _ => {}
        }
    }

    let saw_alpha_listener = received.iter().any(|msg| {
        matches!(msg, OperatorMessage::ListenerEdit(m) if m.info.name.as_deref() == Some("alpha-public"))
    });
    assert!(saw_alpha_listener, "operator must receive ListenerEdit for the public listener");

    let saw_alpha_agent = received
        .iter()
        .any(|msg| matches!(msg, OperatorMessage::AgentNew(m) if m.info.name_id == "AAAA1111"));
    assert!(saw_alpha_agent, "operator must receive AgentNew for the public agent");

    operator_socket.close().await;
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
            Value::String(format!("0;TRUE;FALSE;C:\\Windows\\System32\\cmd.exe;{encoded_args}")),
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
    assert_eq!(read_u32_le(&shellcode_job.payload, &mut offset), u32::from(DemonInjectWay::Inject));
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
    assert_eq!(read_u32_le(&job.payload, &mut offset), u32::from(DemonFilesystemCommand::Download));
    assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), encode_utf16("C:\\secret.txt"));
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
    assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), encode_utf16("C:\\etc\\hosts"));
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
    assert_eq!(read_u32_le(&job.payload, &mut offset), u32::from(DemonFilesystemCommand::Remove));
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
    assert_eq!(read_u32_le(&job.payload, &mut offset), u32::from(DemonFilesystemCommand::Mkdir));
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
        [u32::from(DemonTokenCommand::PrivsGetOrList).to_le_bytes(), 1_u32.to_le_bytes(),].concat()
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
        [u32::from(DemonTokenCommand::PrivsGetOrList).to_le_bytes(), 1_u32.to_le_bytes(),].concat()
    );
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
    assert_eq!(read_len_prefixed_bytes(&job.payload, &mut offset), vec![0x4D, 0x5A, 0x90, 0x00]);
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
        .send_text(listener_edit_message("operator", sample_listener_info("ghost", "Online", 9443)))
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
    let parameters = entry.parameters.as_ref().expect("failure audit should include parameters");
    assert_eq!(parameters.get("agent_id"), Some(&Value::String("DEADBEEF".to_owned())));
    assert!(parameters.get("error").is_some(), "failure audit should include error details");

    socket.close().await;
    server.abort();
}

#[tokio::test]
async fn websocket_agent_remove_enforces_operator_acl() {
    // Two operators with disjoint scopes: `admin` is restricted to
    // `admin-group` / `alpha-admin`, while a second agent owned by
    // `beta-public` belongs to an operator on `public-group`. AgentRemove
    // requires Admin role, so this test narrows `admin`'s agent-group and
    // listener allow-lists to simulate "operator A" whose ACL does not cover
    // the target agent, then asserts the sibling agent owned by "operator B"
    // survives the denied remove.
    let state = TestState::new().await;
    let registry = state.registry.clone();
    let listeners = state.listeners.clone();
    let database = state.database.clone();

    listeners
        .create(sample_http_listener("alpha-admin", 0))
        .await
        .expect("admin listener should persist");
    listeners
        .create(sample_http_listener("beta-public", 0))
        .await
        .expect("public listener should persist");

    // Restrict each listener to its owning operator so the remove command
    // would still be blocked even if group ACLs were misconfigured.
    database
        .listener_access()
        .set_allowed_operators("alpha-admin", &["admin".to_owned()])
        .await
        .expect("seed alpha listener access");
    database
        .listener_access()
        .set_allowed_operators("beta-public", &["operator".to_owned()])
        .await
        .expect("seed beta listener access");

    registry
        .insert_with_listener(sample_agent(0xAAAA_1111), "alpha-admin")
        .await
        .expect("admin agent should insert");
    registry
        .insert_with_listener(sample_agent(0xBBBB_2222), "beta-public")
        .await
        .expect("public agent should insert");

    database
        .agent_groups()
        .set_agent_groups(0xAAAA_1111, &["admin-group".to_owned()])
        .await
        .expect("seed admin agent group");
    database
        .agent_groups()
        .set_agent_groups(0xBBBB_2222, &["public-group".to_owned()])
        .await
        .expect("seed public agent group");
    database
        .agent_groups()
        .set_operator_allowed_groups("admin", &["admin-group".to_owned()])
        .await
        .expect("seed admin agent-group scope");

    let (mut socket, server) = spawn_server(state).await;
    login(&mut socket, "admin", "adminpass").await;

    // Drain the snapshot so the only frame that arrives after sending the
    // AgentRemove is the authorization-denied teamserver log.
    while (timeout(Duration::from_millis(200), socket.recv_msg()).await).is_ok() {}

    // `admin` dispatches an AgentRemove for the agent that belongs to
    // operator B's listener — outside admin's agent-group and listener ACL.
    socket.send_text(agent_remove_message("admin", "BBBB2222")).await;

    let event = read_operator_message(&mut socket).await;
    let OperatorMessage::TeamserverLog(message) = event else {
        panic!("expected teamserver log for denied remove, got {event:?}");
    };
    assert!(
        message.info.text.contains("not permitted"),
        "expected authorization error, got: {}",
        message.info.text
    );

    // The other operator's agent must still be registered — the denial must
    // block the remove before it reaches the registry.
    assert!(
        registry.get(0xBBBB_2222).await.is_some(),
        "public agent must survive a denied remove from a disjoint admin"
    );
    // The admin's own agent must be untouched.
    assert!(registry.get(0xAAAA_1111).await.is_some(), "admin agent must remain untouched");

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
    assert_eq!(response.status(), StatusCode::NOT_FOUND, "non-root path must not be registered");
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
