//! Shared helpers for teamserver integration tests.
//!
//! Import this module in each integration test file with `mod common;`.
// Not every test file uses every helper; suppress dead_code warnings for this module.
#![allow(dead_code)]

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use red_cell::demon::INIT_EXT_MONOTONIC_CTR;
use red_cell::{
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, LoginRateLimiter, OperatorConnectionManager, PayloadBuilderService,
    SocketRelayManager, TeamserverState, build_router,
};
use red_cell_common::HttpListenerConfig;
use red_cell_common::OperatorInfo;
use red_cell_common::config::Profile;
use red_cell_common::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, WsEnvelope, ctr_blocks_for_len, derive_ws_hmac_key,
    encrypt_agent_data, encrypt_agent_data_at_offset, hash_password_sha3, open_ws_frame,
    seal_ws_frame,
};
use red_cell_common::demon::{ArchonEnvelope, DemonCommand, DemonEnvelope};
use red_cell_common::operator::{EventCode, LoginInfo, Message, MessageHead, OperatorMessage};
use tokio::net::TcpListener;
use tokio::time::{sleep, timeout};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message as ClientMessage};

/// Raw underlying WebSocket stream.
type RawWsStream = WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// A WebSocket session with HMAC envelope state for post-login frames.
///
/// After a successful login the teamserver wraps every outgoing frame in a
/// `WsEnvelope` (HMAC-SHA256 + monotonic seq).  Clients must likewise wrap
/// every post-login send.  This struct tracks the per-session key and sequence
/// counters so that [`login`], [`login_as`], [`read_operator_message`], and
/// direct sends all stay in sync.
///
/// The inner `socket` field is intentionally `pub` so that tests which need
/// low-level access (e.g. `socket.next()` for raw close frames) can reach it
/// directly.
pub struct WsSession {
    pub socket: RawWsStream,
    hmac_key: Option<[u8; 32]>,
    send_seq: u64,
    recv_seq: Option<u64>,
}

impl WsSession {
    /// Wrap a raw WebSocket stream into a fresh session (no HMAC key yet).
    pub fn new(socket: RawWsStream) -> Self {
        Self { socket, hmac_key: None, send_seq: 0, recv_seq: None }
    }

    /// Send a JSON string, HMAC-wrapping it when the session key is available.
    pub async fn send_text(
        &mut self,
        json: impl Into<String>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = json.into();
        if let Some(key) = &self.hmac_key {
            let seq = self.send_seq;
            self.send_seq += 1;
            let envelope = seal_ws_frame(key, seq, &json);
            let wire = serde_json::to_string(&envelope)?;
            self.socket.send(ClientMessage::Text(wire.into())).await?;
        } else {
            self.socket.send(ClientMessage::Text(json.into())).await?;
        }
        Ok(())
    }

    /// Send a raw WebSocket frame, bypassing HMAC (for pre-login or close frames).
    pub async fn send_frame(
        &mut self,
        frame: ClientMessage,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.socket.send(frame).await?;
        Ok(())
    }

    /// Close the WebSocket connection.
    pub async fn close(
        &mut self,
        code: Option<tokio_tungstenite::tungstenite::protocol::CloseFrame>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.socket.close(code).await?;
        Ok(())
    }

    /// Receive the next `OperatorMessage`, unwrapping the `WsEnvelope` when
    /// the HMAC key is established (i.e. after `InitConnectionSuccess`).
    ///
    /// On the first successful `InitConnectionSuccess` frame the session key
    /// is derived from the embedded token and stored for all subsequent frames.
    //
    // The 120s ceiling accommodates failed-login paths under workspace-wide
    // load: the server adds `FAILED_LOGIN_DELAY` (2 s) after each rejected
    // attempt on top of Argon2 verification, and when many tests run in
    // parallel Argon2 queues behind other CPU-bound work. A 60 s ceiling was
    // observed to flake (red-cell-c2-02sv8).
    pub async fn recv_msg(&mut self) -> Result<OperatorMessage, Box<dyn std::error::Error>> {
        let next = timeout(Duration::from_secs(120), self.socket.next()).await?;
        let frame = next.ok_or_else(|| "missing websocket frame".to_owned())??;
        match frame {
            ClientMessage::Text(payload) => {
                if let Some(key) = &self.hmac_key {
                    let envelope: WsEnvelope = serde_json::from_str(payload.as_str())?;
                    let inner_json = open_ws_frame(key, &envelope, self.recv_seq)
                        .map_err(|e| format!("HMAC verification failed: {e}"))?;
                    self.recv_seq = Some(envelope.seq);
                    Ok(serde_json::from_str(&inner_json)?)
                } else {
                    let msg: OperatorMessage = serde_json::from_str(payload.as_str())?;
                    if let OperatorMessage::InitConnectionSuccess(ref m) = msg {
                        if let Some(token) =
                            m.info.message.split_once("SessionToken=").map(|(_, t)| t)
                        {
                            self.hmac_key = Some(derive_ws_hmac_key(token));
                        }
                    }
                    Ok(msg)
                }
            }
            other => Err(format!("unexpected websocket frame: {other:?}").into()),
        }
    }
}

/// Type alias kept for backward compatibility with test files that reference `common::WsClient`.
pub type WsClient = WsSession;

/// Connect a WebSocket client to `url` and return a fresh [`WsSession`].
pub async fn connect_ws(url: &str) -> Result<WsSession, Box<dyn std::error::Error>> {
    let (inner, _) = tokio_tungstenite::connect_async(url).await?;
    Ok(WsSession::new(inner))
}

/// Handles returned by [`spawn_test_server`] so tests can interact with
/// the teamserver's listener manager and agent registry without duplicating
/// construction boilerplate.
pub struct TestServer {
    pub addr: std::net::SocketAddr,
    pub profile: Profile,
    pub listeners: ListenerManager,
    pub agent_registry: AgentRegistry,
    pub database: Database,
    pub events: EventBus,
    pub sockets: SocketRelayManager,
    pub webhooks: AuditWebhookNotifier,
    pub rate_limiter: LoginRateLimiter,
}

impl TestServer {
    /// Return the WebSocket URL that matches the production `/havoc` endpoint.
    pub fn ws_url(&self) -> String {
        format!("ws://{}/havoc", self.addr)
    }
}

/// Bind a free TCP port, start a teamserver from `profile`, and return a
/// [`TestServer`] with the socket address and shared handles.
pub async fn spawn_test_server(profile: Profile) -> Result<TestServer, Box<dyn std::error::Error>> {
    spawn_test_server_custom(profile, |lm| lm).await
}

/// Like [`spawn_test_server`], but applies `customize` to the [`ListenerManager`]
/// before it is cloned into the router state.  Useful for overriding rate-limit
/// thresholds in integration tests.
pub async fn spawn_test_server_custom(
    profile: Profile,
    customize: impl FnOnce(ListenerManager) -> ListenerManager,
) -> Result<TestServer, Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let listeners = customize(
        ListenerManager::new(
            database.clone(),
            registry.clone(),
            events.clone(),
            sockets.clone(),
            None,
        )
        .with_demon_allow_legacy_ctr(profile.demon.allow_legacy_ctr),
    );
    let webhooks = AuditWebhookNotifier::from_profile(&profile);
    let rate_limiter = LoginRateLimiter::new();
    let state = TeamserverState {
        profile: profile.clone(),
        profile_path: "test.yaotl".to_owned(),
        database: database.clone(),
        auth: AuthService::from_profile(&profile).expect("auth service should initialize"),
        api: ApiRuntime::from_profile(&profile).expect("rng should work in tests"),
        events: events.clone(),
        connections: OperatorConnectionManager::new(),
        agent_registry: registry.clone(),
        listeners: listeners.clone(),
        payload_builder: PayloadBuilderService::disabled_for_tests(),
        sockets: sockets.clone(),
        webhooks: webhooks.clone(),
        login_rate_limiter: rate_limiter.clone(),
        shutdown: red_cell::ShutdownController::new(),
        service_bridge: None,
        started_at: std::time::Instant::now(),
        plugins_loaded: 0,
        plugins_failed: 0,
        metrics: red_cell::metrics::standalone_metrics_handle(),
    };

    let tcp = TcpListener::bind("127.0.0.1:0").await?;
    let addr = tcp.local_addr()?;
    tokio::spawn(async move {
        let app = build_router(state);
        let _ = axum::serve(tcp, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await;
    });
    Ok(TestServer {
        addr,
        profile,
        listeners,
        agent_registry: registry,
        database,
        events,
        sockets,
        webhooks,
        rate_limiter,
    })
}

/// Authenticate over WebSocket as `"operator"` / `"password1234"` and consume the
/// success + snapshot frames.
pub async fn login(session: &mut WsSession) -> Result<(), Box<dyn std::error::Error>> {
    login_as(session, "operator", "password1234").await
}

/// Authenticate over WebSocket as `username`/`password`; consume the success + snapshot frames.
pub async fn login_as(
    session: &mut WsSession,
    username: &str,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = serde_json::to_string(&OperatorMessage::Login(Message {
        head: MessageHead {
            event: EventCode::InitConnection,
            user: username.to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: LoginInfo { user: username.to_owned(), password: hash_password_sha3(password) },
    }))?;
    // Login message is always sent plain (pre-auth, no HMAC key yet).
    session.socket.send(ClientMessage::Text(payload.into())).await?;
    let response = read_operator_message(session).await?;
    assert!(
        matches!(response, OperatorMessage::InitConnectionSuccess(_)),
        "expected InitConnectionSuccess, got {response:?}"
    );
    let _snapshot = read_operator_snapshot(session).await?;
    Ok(())
}

/// Read the next operator WebSocket frame, expecting a JSON [`OperatorMessage`].
///
/// Automatically unwraps `WsEnvelope` frames after login.
pub async fn read_operator_message(
    session: &mut WsSession,
) -> Result<OperatorMessage, Box<dyn std::error::Error>> {
    session.recv_msg().await
}

/// Read the next operator WebSocket frame and parse it as an operator snapshot
/// (`InitConnectionInfo`), returning the list of connected operators.
pub async fn read_operator_snapshot(
    session: &mut WsSession,
) -> Result<Vec<OperatorInfo>, Box<dyn std::error::Error>> {
    let message = read_operator_message(session).await?;
    let OperatorMessage::InitConnectionInfo(message) = message else {
        return Err("expected operator snapshot event".into());
    };

    Ok(serde_json::from_value(
        message
            .info
            .fields
            .get("Operators")
            .cloned()
            .ok_or_else(|| "operator snapshot missing operators".to_owned())?,
    )?)
}

/// Assert that no operator message arrives within `wait`.
pub async fn assert_no_operator_message(session: &mut WsSession, wait: Duration) {
    let result = timeout(wait, session.socket.next()).await;
    assert!(result.is_err(), "unexpected operator message during empty session snapshot");
}

/// After Demon callback dispatch fails (fake HTTP 404), the teamserver may broadcast a
/// retained [`OperatorMessage::TeamserverLog`] for `/debug/server-logs`. Consume that
/// optional frame so gameplay-focused tests stay stable.
pub async fn skip_optional_teamserver_log(session: &mut WsSession, wait: Duration) {
    match timeout(wait, session.recv_msg()).await {
        Err(_) => {}
        Ok(Ok(OperatorMessage::TeamserverLog(_))) => {}
        Ok(Ok(other)) => panic!(
            "expected silence or TeamserverLog diagnostic after dispatch failure, got {other:?}"
        ),
        Ok(Err(error)) => panic!("recv_msg failed: {error:?}"),
    }
}

/// Bind a free TCP port on `127.0.0.1` and return the port number together with
/// the [`std::net::TcpListener`] that keeps it reserved.
///
/// The caller must hold the returned listener alive until immediately before the
/// system-under-test binds to the port, then [`drop`] it.  This eliminates the
/// TOCTOU race that arises when only the port number is returned: keep the guard
/// until the last moment, then release it so the component under test can bind.
pub fn available_port() -> Result<(u16, std::net::TcpListener), Box<dyn std::error::Error>> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    Ok((port, listener))
}

/// Find a free TCP port on `127.0.0.1` that is not equal to `excluded`, and return
/// the port number together with the [`std::net::TcpListener`] that keeps it reserved.
///
/// See [`available_port`] for the correct usage pattern.
pub fn available_port_excluding(
    excluded: u16,
) -> Result<(u16, std::net::TcpListener), Box<dyn std::error::Error>> {
    for _ in 0..32 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        if port != excluded {
            return Ok((port, listener));
        }
        // port == excluded — release and try again
    }

    Err(format!("failed to allocate a port different from {excluded}").into())
}

/// Poll `http://127.0.0.1:{port}/` until the listener accepts connections (i.e. returns a
/// status code other than `501 Not Implemented`), or return an error after 40 attempts.
pub async fn wait_for_listener(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    for _ in 0..40 {
        if let Ok(response) = client.get(format!("http://127.0.0.1:{port}/")).send().await {
            if response.status() != reqwest::StatusCode::NOT_IMPLEMENTED {
                return Ok(());
            }
        }
        sleep(Duration::from_millis(25)).await;
    }

    Err(format!("listener on port {port} did not become ready").into())
}

/// Build a valid Demon `DemonInit` envelope for the given `agent_id`, `key`, and `iv`.
///
/// The metadata fields contain fixed test values (hostname `wkstn-01`, etc.) that the
/// teamserver integration tests assert against.
pub fn valid_demon_init_body(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> Vec<u8> {
    let mut metadata = Vec::new();
    metadata.extend_from_slice(&agent_id.to_be_bytes());
    add_length_prefixed_bytes_be(&mut metadata, b"wkstn-01");
    add_length_prefixed_bytes_be(&mut metadata, b"operator");
    add_length_prefixed_bytes_be(&mut metadata, b"REDCELL");
    add_length_prefixed_bytes_be(&mut metadata, b"10.0.0.25");
    add_length_prefixed_utf16_le(&mut metadata, "C:\\Windows\\explorer.exe");
    metadata.extend_from_slice(&1337_u32.to_be_bytes());
    metadata.extend_from_slice(&1338_u32.to_be_bytes());
    metadata.extend_from_slice(&512_u32.to_be_bytes());
    metadata.extend_from_slice(&2_u32.to_be_bytes());
    metadata.extend_from_slice(&1_u32.to_be_bytes());
    metadata.extend_from_slice(&0x401000_u64.to_be_bytes());
    metadata.extend_from_slice(&10_u32.to_be_bytes());
    metadata.extend_from_slice(&0_u32.to_be_bytes());
    metadata.extend_from_slice(&1_u32.to_be_bytes());
    metadata.extend_from_slice(&0_u32.to_be_bytes());
    metadata.extend_from_slice(&22000_u32.to_be_bytes());
    metadata.extend_from_slice(&9_u32.to_be_bytes());
    metadata.extend_from_slice(&15_u32.to_be_bytes());
    metadata.extend_from_slice(&20_u32.to_be_bytes());
    metadata.extend_from_slice(&1_893_456_000_u64.to_be_bytes());
    metadata.extend_from_slice(&0b101010_u32.to_be_bytes());

    let encrypted =
        encrypt_agent_data(&key, &iv, &metadata).expect("metadata encryption should succeed");
    let payload = [
        u32::from(DemonCommand::DemonInit).to_be_bytes().as_slice(),
        7_u32.to_be_bytes().as_slice(),
        key.as_slice(),
        iv.as_slice(),
        encrypted.as_slice(),
    ]
    .concat();

    DemonEnvelope::new(agent_id, payload)
        .unwrap_or_else(|error| panic!("failed to build demon init request body: {error}"))
        .to_bytes()
}

/// Build a valid Demon `DemonInit` envelope with extension flags appended after the standard
/// metadata fields.  Used to register agents that opt into monotonic CTR mode
/// (`INIT_EXT_MONOTONIC_CTR`).
///
/// All metadata fields take the same fixed test values as [`valid_demon_init_body`];
/// only the trailing `ext_flags` word differs.
pub fn valid_demon_init_body_with_ext_flags(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    ext_flags: u32,
) -> Vec<u8> {
    let mut metadata = Vec::new();
    metadata.extend_from_slice(&agent_id.to_be_bytes());
    add_length_prefixed_bytes_be(&mut metadata, b"wkstn-01");
    add_length_prefixed_bytes_be(&mut metadata, b"operator");
    add_length_prefixed_bytes_be(&mut metadata, b"REDCELL");
    add_length_prefixed_bytes_be(&mut metadata, b"10.0.0.25");
    add_length_prefixed_utf16_le(&mut metadata, "C:\\Windows\\explorer.exe");
    metadata.extend_from_slice(&1337_u32.to_be_bytes());
    metadata.extend_from_slice(&1338_u32.to_be_bytes());
    metadata.extend_from_slice(&512_u32.to_be_bytes());
    metadata.extend_from_slice(&2_u32.to_be_bytes());
    metadata.extend_from_slice(&1_u32.to_be_bytes());
    metadata.extend_from_slice(&0x401000_u64.to_be_bytes());
    metadata.extend_from_slice(&10_u32.to_be_bytes());
    metadata.extend_from_slice(&0_u32.to_be_bytes());
    metadata.extend_from_slice(&1_u32.to_be_bytes());
    metadata.extend_from_slice(&0_u32.to_be_bytes());
    metadata.extend_from_slice(&22000_u32.to_be_bytes());
    metadata.extend_from_slice(&9_u32.to_be_bytes());
    metadata.extend_from_slice(&15_u32.to_be_bytes());
    metadata.extend_from_slice(&20_u32.to_be_bytes());
    metadata.extend_from_slice(&1_893_456_000_u64.to_be_bytes());
    metadata.extend_from_slice(&0b101010_u32.to_be_bytes());
    // Specter/monotonic extension: append ext_flags after working_hours.
    metadata.extend_from_slice(&ext_flags.to_be_bytes());

    let encrypted =
        encrypt_agent_data(&key, &iv, &metadata).expect("metadata encryption should succeed");
    let payload = [
        u32::from(DemonCommand::DemonInit).to_be_bytes().as_slice(),
        7_u32.to_be_bytes().as_slice(),
        key.as_slice(),
        iv.as_slice(),
        encrypted.as_slice(),
    ]
    .concat();

    DemonEnvelope::new(agent_id, payload)
        .unwrap_or_else(|error| panic!("failed to build demon init request body: {error}"))
        .to_bytes()
}

/// Build a valid Demon callback envelope (post-registration) for the given parameters.
///
/// `ctr_offset` must be the cumulative AES-CTR block offset at the time of this call.
pub fn valid_demon_callback_body(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    ctr_offset: u64,
    command_id: u32,
    request_id: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut decrypted = Vec::new();
    decrypted.extend_from_slice(
        &u32::try_from(payload.len()).expect("test data fits in u32").to_be_bytes(),
    );
    decrypted.extend_from_slice(payload);

    let encrypted = encrypt_agent_data_at_offset(&key, &iv, ctr_offset, &decrypted)
        .unwrap_or_else(|error| panic!("callback encrypt failed: {error}"));
    let body = [
        command_id.to_be_bytes().as_slice(),
        request_id.to_be_bytes().as_slice(),
        encrypted.as_slice(),
    ]
    .concat();

    DemonEnvelope::new(agent_id, body)
        .unwrap_or_else(|error| panic!("failed to build demon callback request body: {error}"))
        .to_bytes()
}

/// Build a valid Demon reconnect probe envelope for the given `agent_id`.
///
/// A reconnect probe is a `DEMON_INIT` packet with an empty payload — it carries no
/// encrypted metadata.  The server recognises the empty body as a reconnect signal and
/// responds with [`build_reconnect_ack`] rather than treating it as a fresh init.
pub fn valid_demon_reconnect_body(agent_id: u32) -> Vec<u8> {
    let payload = [
        u32::from(DemonCommand::DemonInit).to_be_bytes().as_slice(),
        7_u32.to_be_bytes().as_slice(),
    ]
    .concat();

    DemonEnvelope::new(agent_id, payload)
        .unwrap_or_else(|error| panic!("failed to build demon reconnect request body: {error}"))
        .to_bytes()
}

/// Build a valid Archon `DemonInit` envelope for the given `agent_id`, `key`, `iv`, and `magic`.
///
/// The Archon header layout is `size(4) | agent_id(4) | magic(4)` — unlike the legacy Demon
/// header which places magic before agent_id.  The payload structure (command_id, key, iv,
/// encrypted metadata) is identical to [`valid_demon_init_body`].
pub fn valid_archon_init_body(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    magic: u32,
) -> Vec<u8> {
    let mut metadata = Vec::new();
    metadata.extend_from_slice(&agent_id.to_be_bytes());
    add_length_prefixed_bytes_be(&mut metadata, b"wkstn-01");
    add_length_prefixed_bytes_be(&mut metadata, b"operator");
    add_length_prefixed_bytes_be(&mut metadata, b"REDCELL");
    add_length_prefixed_bytes_be(&mut metadata, b"10.0.0.25");
    add_length_prefixed_utf16_le(&mut metadata, "C:\\Windows\\explorer.exe");
    metadata.extend_from_slice(&1337_u32.to_be_bytes());
    metadata.extend_from_slice(&1338_u32.to_be_bytes());
    metadata.extend_from_slice(&512_u32.to_be_bytes());
    metadata.extend_from_slice(&2_u32.to_be_bytes());
    metadata.extend_from_slice(&1_u32.to_be_bytes());
    metadata.extend_from_slice(&0x401000_u64.to_be_bytes());
    metadata.extend_from_slice(&10_u32.to_be_bytes());
    metadata.extend_from_slice(&0_u32.to_be_bytes());
    metadata.extend_from_slice(&1_u32.to_be_bytes());
    metadata.extend_from_slice(&0_u32.to_be_bytes());
    metadata.extend_from_slice(&22000_u32.to_be_bytes());
    metadata.extend_from_slice(&9_u32.to_be_bytes());
    metadata.extend_from_slice(&15_u32.to_be_bytes());
    metadata.extend_from_slice(&20_u32.to_be_bytes());
    metadata.extend_from_slice(&1_893_456_000_u64.to_be_bytes());
    metadata.extend_from_slice(&0b101010_u32.to_be_bytes());

    let encrypted =
        encrypt_agent_data(&key, &iv, &metadata).expect("metadata encryption should succeed");
    let payload = [
        u32::from(DemonCommand::DemonInit).to_be_bytes().as_slice(),
        7_u32.to_be_bytes().as_slice(),
        key.as_slice(),
        iv.as_slice(),
        encrypted.as_slice(),
    ]
    .concat();

    ArchonEnvelope::new(agent_id, magic, payload)
        .unwrap_or_else(|error| panic!("failed to build archon init request body: {error}"))
        .to_bytes()
}

/// Build an Archon callback envelope using the Archon header layout `size | agent_id | magic`.
///
/// `ctr_offset` must be the cumulative AES-CTR block offset at the time of this call.
pub fn valid_archon_callback_body(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    ctr_offset: u64,
    command_id: u32,
    request_id: u32,
    payload: &[u8],
    magic: u32,
) -> Vec<u8> {
    let mut decrypted = Vec::new();
    decrypted.extend_from_slice(
        &u32::try_from(payload.len()).expect("test data fits in u32").to_be_bytes(),
    );
    decrypted.extend_from_slice(payload);

    let encrypted = encrypt_agent_data_at_offset(&key, &iv, ctr_offset, &decrypted)
        .unwrap_or_else(|error| panic!("archon callback encrypt failed: {error}"));
    let body = [
        command_id.to_be_bytes().as_slice(),
        request_id.to_be_bytes().as_slice(),
        encrypted.as_slice(),
    ]
    .concat();

    ArchonEnvelope::new(agent_id, magic, body)
        .unwrap_or_else(|error| panic!("failed to build archon callback request body: {error}"))
        .to_bytes()
}

/// Serialize a `CommandOutput` payload (LE length-prefixed UTF-8 string).
pub fn command_output_payload(output: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(
        &u32::try_from(output.len()).expect("test data fits in u32").to_le_bytes(),
    );
    payload.extend_from_slice(output.as_bytes());
    payload
}

/// Build an [`HttpListenerConfig`] wrapped in a [`ListenerConfig`] with sensible
/// test defaults.  Only `name` and `port` vary across tests.
pub fn http_listener_config(name: &str, port: u16) -> red_cell_common::ListenerConfig {
    red_cell_common::ListenerConfig::from(HttpListenerConfig {
        name: name.to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["127.0.0.1".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: port,
        port_conn: Some(port),
        method: Some("POST".to_owned()),
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: None,
        headers: Vec::new(),
        uris: vec!["/".to_owned()],
        host_header: None,
        secure: false,
        cert: None,
        response: None,
        proxy: None,
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
        legacy_mode: true,
        suppress_opsec_warnings: true,
    })
}

/// Register a fresh agent via `DEMON_INIT` with the `INIT_EXT_MONOTONIC_CTR`
/// extension flag and return the AES-CTR block offset to use for subsequent
/// callback packets.
///
/// This mirrors the production-secure path: the server registers the agent
/// with `legacy_ctr = false` and the CTR offset advances monotonically.
/// The init ACK is a 4-byte agent-id (1 AES block), so the returned offset
/// is always 1.
///
/// Tests that need legacy CTR behavior should use [`register_legacy_agent`]
/// with a [`legacy_ctr_test_profile`] server instead.
pub async fn register_agent(
    client: &reqwest::Client,
    listener_port: u16,
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> Result<u64, Box<dyn std::error::Error>> {
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(valid_demon_init_body_with_ext_flags(agent_id, key, iv, INIT_EXT_MONOTONIC_CTR))
        .send()
        .await?
        .error_for_status()?;
    // Monotonic CTR: the init ACK is 4 bytes (1 AES block), so the next
    // callback must be encrypted at offset 1.
    Ok(ctr_blocks_for_len(4))
}

/// Register a fresh agent via legacy `DEMON_INIT` (no extension flags) and
/// return CTR offset 0.
///
/// Use this only with a server spawned from [`legacy_ctr_test_profile`] —
/// a production-default server will reject the legacy init.
pub async fn register_legacy_agent(
    client: &reqwest::Client,
    listener_port: u16,
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> Result<u64, Box<dyn std::error::Error>> {
    client
        .post(format!("http://127.0.0.1:{listener_port}/"))
        .body(valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    // Legacy CTR mode: every packet starts at block 0.
    Ok(0)
}

/// Build a standard test [`Profile`] with a single `operator`/`password1234`
/// user.  Uses the production-default `AllowLegacyCtr = false` setting so
/// that tests exercise the secure path by default.
///
/// Tests that intentionally cover legacy-CTR Demon agents should use
/// [`legacy_ctr_test_profile`] instead.
pub fn default_test_profile() -> Profile {
    Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 0
        }

        Operators {
          user "operator" {
            Password = "password1234"
            Role = "Operator"
          }
        }

        Demon {}
        "#,
    )
    .expect("default test profile should parse")
}

/// Build a test [`Profile`] identical to [`default_test_profile`] but with
/// `AllowLegacyCtr = true`.  Use this **only** for tests that intentionally
/// exercise legacy Demon agents that do not set `INIT_EXT_MONOTONIC_CTR`.
pub fn legacy_ctr_test_profile() -> Profile {
    Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 0
        }

        Operators {
          user "operator" {
            Password = "password1234"
            Role = "Operator"
          }
        }

        Demon {
          AllowLegacyCtr = true
        }
        "#,
    )
    .expect("legacy CTR test profile should parse")
}

/// Append `value` to `buffer` as a BE-length-prefixed byte slice.
pub fn add_length_prefixed_bytes_be(buffer: &mut Vec<u8>, value: &[u8]) {
    buffer.extend_from_slice(
        &u32::try_from(value.len()).expect("test data fits in u32").to_be_bytes(),
    );
    buffer.extend_from_slice(value);
}

/// Append `value` to `buffer` as a BE-length-prefixed UTF-16LE string (null-terminated).
///
/// The Demon agent encodes strings as UTF-16 little-endian (matching Windows-native
/// `WCHAR`/`wchar_t`). The length prefix itself is big-endian to match the rest of
/// the Demon binary protocol framing.
pub fn add_length_prefixed_utf16_le(buffer: &mut Vec<u8>, value: &str) {
    let mut encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
    encoded.extend_from_slice(&[0, 0]);
    add_length_prefixed_bytes_be(buffer, &encoded);
}
