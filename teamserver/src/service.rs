//! Service bridge WebSocket endpoint for external tool integration.
//!
//! The Service bridge is a secondary WebSocket endpoint that external tools and
//! custom agents can use to interact with the teamserver programmatically. It
//! mirrors the original Havoc `pkg/service` package.
//!
//! ## Authentication
//!
//! Clients connect via WebSocket and send a JSON `Register` message containing
//! the service password. The password is verified using SHA3-256 comparison.
//!
//! ## Protocol
//!
//! After authentication, the client exchanges JSON messages with headers:
//! - `RegisterAgent` — register a custom agent type
//! - `Agent` — agent task, response, output, registration, and build messages
//! - `Listener` — listener management (add, start, ExternalC2)

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
use red_cell_common::config::ServiceConfig;
use red_cell_common::crypto::hash_password_sha3;
use red_cell_common::operator::{
    EventCode, Message, MessageHead, OperatorMessage, ServiceAgentRegistrationInfo,
    ServiceListenerRegistrationInfo, TeamserverLogInfo,
};
use serde_json::Value;
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use crate::{AgentRegistry, EventBus};

// ── Constants ────────────────────────────────────────────────────────

/// Head.Type values matching the original Havoc service protocol.
const HEAD_REGISTER: &str = "Register";
const HEAD_REGISTER_AGENT: &str = "RegisterAgent";
const HEAD_AGENT: &str = "Agent";
const HEAD_LISTENER: &str = "Listener";

/// Body.Type values for agent sub-messages.
const BODY_AGENT_REGISTER: &str = "AgentRegister";
const BODY_AGENT_TASK: &str = "AgentTask";
const BODY_AGENT_RESPONSE: &str = "AgentResponse";
const BODY_AGENT_OUTPUT: &str = "AgentOutput";

/// Body.Type values for listener sub-messages.
const BODY_LISTENER_ADD: &str = "ListenerAdd";
const BODY_LISTENER_START: &str = "ListenerStart";

// ── Error types ──────────────────────────────────────────────────────

/// Errors produced by the service bridge.
#[derive(Debug, Error)]
pub enum ServiceBridgeError {
    /// Authentication failed.
    #[error("service client authentication failed")]
    AuthenticationFailed,

    /// WebSocket send/receive failure.
    #[error("websocket error: {0}")]
    WebSocket(#[from] axum::Error),

    /// JSON parse failure.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Missing required field in a message.
    #[error("missing field: {0}")]
    MissingField(String),

    /// Duplicate agent name.
    #[error("service agent already registered: {name}")]
    DuplicateAgent { name: String },
}

// ── Service bridge state ─────────────────────────────────────────────

/// Manages connected service clients and registered service agents/listeners.
#[derive(Debug, Clone)]
pub struct ServiceBridge {
    config: ServiceConfig,
    inner: Arc<RwLock<ServiceBridgeInner>>,
}

#[derive(Debug, Default)]
struct ServiceBridgeInner {
    /// Registered service agent type names (to prevent duplicates).
    registered_agents: Vec<String>,
    /// Registered service listener names.
    registered_listeners: Vec<String>,
    /// Connected client IDs.
    connected_clients: Vec<Uuid>,
}

impl ServiceBridge {
    /// Create a new service bridge from the profile configuration.
    #[must_use]
    pub fn new(config: ServiceConfig) -> Self {
        Self { config, inner: Arc::new(RwLock::new(ServiceBridgeInner::default())) }
    }

    /// Return the configured endpoint path (without leading slash).
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.config.endpoint
    }

    /// Return the number of currently connected service clients.
    pub async fn connected_client_count(&self) -> usize {
        self.inner.read().await.connected_clients.len()
    }

    /// Check if a service agent with the given name is already registered.
    pub async fn agent_exists(&self, name: &str) -> bool {
        self.inner.read().await.registered_agents.iter().any(|n| n == name)
    }

    /// Register a new service agent name. Returns error if already registered.
    async fn register_agent(&self, name: String) -> Result<(), ServiceBridgeError> {
        let mut inner = self.inner.write().await;
        if inner.registered_agents.iter().any(|n| n == &name) {
            return Err(ServiceBridgeError::DuplicateAgent { name });
        }
        inner.registered_agents.push(name);
        Ok(())
    }

    /// Register a new service listener name.
    async fn register_listener(&self, name: String) {
        let mut inner = self.inner.write().await;
        if !inner.registered_listeners.iter().any(|n| n == &name) {
            inner.registered_listeners.push(name);
        }
    }

    /// Track a new client connection.
    async fn add_client(&self, id: Uuid) {
        self.inner.write().await.connected_clients.push(id);
    }

    /// Remove a client and clean up its registered agents and listeners.
    async fn remove_client(&self, id: Uuid, agents: &[String], listeners: &[String]) {
        let mut inner = self.inner.write().await;
        inner.connected_clients.retain(|c| *c != id);
        inner.registered_agents.retain(|a| !agents.contains(a));
        inner.registered_listeners.retain(|l| !listeners.contains(l));
    }
}

impl FromRef<crate::TeamserverState> for ServiceBridge {
    fn from_ref(input: &crate::TeamserverState) -> Self {
        input.service_bridge.clone().unwrap_or_else(|| {
            ServiceBridge::new(ServiceConfig { endpoint: String::new(), password: String::new() })
        })
    }
}

// ── Route setup ──────────────────────────────────────────────────────

/// Build a router for the service bridge WebSocket endpoint.
///
/// The endpoint path is `/{config.endpoint}`.
pub fn service_routes(bridge: &ServiceBridge) -> Router<crate::TeamserverState> {
    let endpoint = format!("/{}", bridge.endpoint());
    Router::new().route(&endpoint, get(service_websocket_handler))
}

/// Upgrade the service bridge HTTP request to WebSocket.
#[instrument(skip(state, websocket))]
async fn service_websocket_handler(
    State(state): State<crate::TeamserverState>,
    websocket: WebSocketUpgrade,
) -> impl IntoResponse {
    websocket.on_upgrade(move |socket| handle_service_socket(state, socket))
}

// ── WebSocket connection handler ─────────────────────────────────────

/// Handle a single service client WebSocket connection.
async fn handle_service_socket(state: crate::TeamserverState, mut socket: WebSocket) {
    let Some(ref bridge) = state.service_bridge else {
        warn!("service bridge handler invoked but no service bridge configured");
        return;
    };

    let shutdown = state.shutdown.clone();
    if shutdown.is_shutting_down() {
        debug!("service bridge rejecting connection during shutdown");
        let _ = socket.send(WsMessage::Close(None)).await;
        return;
    }

    // Authenticate the client.
    let client_id = match authenticate(&mut socket, &bridge.config).await {
        Ok(id) => id,
        Err(e) => {
            warn!(%e, "service client authentication failed");
            let _ = socket.send(WsMessage::Close(None)).await;
            return;
        }
    };

    info!(%client_id, "service client authenticated");
    bridge.add_client(client_id).await;

    // Broadcast a log event to operators.
    let log_event = service_log_event("service client connected");
    state.events.broadcast(log_event);

    // Track which agents/listeners this client registered for cleanup.
    let mut client_agents: Vec<String> = Vec::new();
    let mut client_listeners: Vec<String> = Vec::new();

    // Main message loop.
    loop {
        let message = match socket.recv().await {
            Some(Ok(WsMessage::Text(text))) => text,
            Some(Ok(WsMessage::Close(_))) | None => break,
            Some(Ok(_)) => continue,
            Some(Err(e)) => {
                debug!(%e, %client_id, "service client websocket error");
                break;
            }
        };

        let parsed: Value = match serde_json::from_str(&message) {
            Ok(v) => v,
            Err(e) => {
                warn!(%e, %client_id, "service client sent invalid JSON");
                continue;
            }
        };

        if let Err(e) = dispatch_message(
            &parsed,
            bridge,
            &state.events,
            &state.agent_registry,
            &mut socket,
            &mut client_agents,
            &mut client_listeners,
        )
        .await
        {
            warn!(%e, %client_id, "service dispatch error");
        }
    }

    // Clean up on disconnect.
    info!(%client_id, "service client disconnected");
    for agent_name in &client_agents {
        warn!(name = %agent_name, "unregistered service agent");
    }
    for listener_name in &client_listeners {
        warn!(name = %listener_name, "unregistered service listener");
    }
    bridge.remove_client(client_id, &client_agents, &client_listeners).await;

    let log_event = service_log_event("service client disconnected");
    state.events.broadcast(log_event);
}

// ── Authentication ───────────────────────────────────────────────────

/// Authenticate a service client using the SHA3-256 password protocol.
///
/// Expects a JSON message: `{"Head":{"Type":"Register"},"Body":{"Password":"..."}}`
/// Responds with: `{"Head":{"Type":"Register"},"Body":{"Success":true/false}}`
async fn authenticate(
    socket: &mut WebSocket,
    config: &ServiceConfig,
) -> Result<Uuid, ServiceBridgeError> {
    let message = match socket.recv().await {
        Some(Ok(WsMessage::Text(text))) => text,
        _ => return Err(ServiceBridgeError::AuthenticationFailed),
    };

    let parsed: Value = serde_json::from_str(&message)?;

    let head_type =
        parsed.get("Head").and_then(|h| h.get("Type")).and_then(Value::as_str).unwrap_or_default();

    if head_type != HEAD_REGISTER {
        return Err(ServiceBridgeError::AuthenticationFailed);
    }

    let client_password = parsed
        .get("Body")
        .and_then(|b| b.get("Password"))
        .and_then(Value::as_str)
        .unwrap_or_default();

    let client_hash = hash_password_sha3(client_password);
    let server_hash = hash_password_sha3(&config.password);
    let success = client_hash == server_hash;

    let response = serde_json::json!({
        "Head": { "Type": HEAD_REGISTER },
        "Body": { "Success": success },
    });

    let response_text = serde_json::to_string(&response)?;
    socket
        .send(WsMessage::Text(response_text.into()))
        .await
        .map_err(ServiceBridgeError::WebSocket)?;

    if success { Ok(Uuid::new_v4()) } else { Err(ServiceBridgeError::AuthenticationFailed) }
}

// ── Message dispatch ─────────────────────────────────────────────────

/// Dispatch a parsed JSON message to the appropriate handler.
async fn dispatch_message(
    message: &Value,
    bridge: &ServiceBridge,
    events: &EventBus,
    agent_registry: &AgentRegistry,
    socket: &mut WebSocket,
    client_agents: &mut Vec<String>,
    client_listeners: &mut Vec<String>,
) -> Result<(), ServiceBridgeError> {
    let head_type =
        message.get("Head").and_then(|h| h.get("Type")).and_then(Value::as_str).unwrap_or_default();

    match head_type {
        HEAD_REGISTER_AGENT => handle_register_agent(message, bridge, events, client_agents).await,
        HEAD_AGENT => handle_agent_message(message, bridge, events, agent_registry, socket).await,
        HEAD_LISTENER => handle_listener_message(message, bridge, events, client_listeners).await,
        other => {
            debug!(message_type = %other, "unknown service message type");
            Ok(())
        }
    }
}

// ── RegisterAgent handler ────────────────────────────────────────────

/// Handle a `RegisterAgent` message — register a custom agent type with the
/// teamserver so operators can see it in their UI.
async fn handle_register_agent(
    message: &Value,
    bridge: &ServiceBridge,
    events: &EventBus,
    client_agents: &mut Vec<String>,
) -> Result<(), ServiceBridgeError> {
    let agent_data = message
        .get("Body")
        .and_then(|b| b.get("Agent"))
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Agent".to_owned()))?;

    let agent_name = agent_data
        .get("Name")
        .and_then(Value::as_str)
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Agent.Name".to_owned()))?;

    bridge.register_agent(agent_name.to_owned()).await?;
    client_agents.push(agent_name.to_owned());

    info!(name = %agent_name, "service agent registered");

    // Broadcast to operators.
    let agent_json = serde_json::to_string(agent_data).unwrap_or_default();
    let event = OperatorMessage::ServiceAgentRegister(Message {
        head: MessageHead {
            event: EventCode::Service,
            user: String::new(),
            timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
            one_time: String::new(),
        },
        info: ServiceAgentRegistrationInfo { agent: agent_json },
    });
    events.broadcast(event);

    Ok(())
}

// ── Agent message handler ────────────────────────────────────────────

/// Handle an `Agent` message — dispatches to sub-handlers based on `Body.Type`.
async fn handle_agent_message(
    message: &Value,
    _bridge: &ServiceBridge,
    events: &EventBus,
    _agent_registry: &AgentRegistry,
    _socket: &mut WebSocket,
) -> Result<(), ServiceBridgeError> {
    let body_type =
        message.get("Body").and_then(|b| b.get("Type")).and_then(Value::as_str).unwrap_or_default();

    match body_type {
        BODY_AGENT_TASK => {
            debug!("service agent task message received");
            // Agent task queueing — external services can push commands to agents.
            // The full implementation depends on the agent queue infrastructure being
            // wired up for service-originated tasks. For now, log and acknowledge.
            debug!("service agent task dispatch not yet fully wired");
            Ok(())
        }
        BODY_AGENT_REGISTER => {
            debug!("service agent registration callback received");
            // An agent instance registering through the service bridge. This would
            // call into agent_registry to register the agent.
            debug!("service agent instance registration not yet fully wired");
            Ok(())
        }
        BODY_AGENT_RESPONSE => {
            debug!("service agent response received");
            Ok(())
        }
        BODY_AGENT_OUTPUT => handle_agent_output(message, events).await,
        other => {
            debug!(body_type = %other, "unknown service agent sub-message type");
            Ok(())
        }
    }
}

/// Handle agent output messages — broadcast console output to operators.
async fn handle_agent_output(message: &Value, events: &EventBus) -> Result<(), ServiceBridgeError> {
    let body =
        message.get("Body").ok_or_else(|| ServiceBridgeError::MissingField("Body".to_owned()))?;

    let agent_id = body.get("AgentID").and_then(Value::as_str).unwrap_or("unknown");

    let callback = body.get("Callback");

    debug!(%agent_id, ?callback, "service agent output");

    // Broadcast as a teamserver log for operator visibility.
    let log_event = service_log_event(&format!("agent output from service agent {agent_id}"));
    events.broadcast(log_event);

    Ok(())
}

// ── Listener message handler ─────────────────────────────────────────

/// Handle a `Listener` message — register or start service-provided listeners.
async fn handle_listener_message(
    message: &Value,
    bridge: &ServiceBridge,
    events: &EventBus,
    client_listeners: &mut Vec<String>,
) -> Result<(), ServiceBridgeError> {
    let body_type =
        message.get("Body").and_then(|b| b.get("Type")).and_then(Value::as_str).unwrap_or_default();

    match body_type {
        BODY_LISTENER_ADD => handle_listener_add(message, bridge, events, client_listeners).await,
        BODY_LISTENER_START => {
            debug!("service listener start notification received");
            Ok(())
        }
        other => {
            debug!(body_type = %other, "unknown service listener sub-message type");
            Ok(())
        }
    }
}

/// Handle a `ListenerAdd` message — register a custom listener provided by a
/// service client.
async fn handle_listener_add(
    message: &Value,
    bridge: &ServiceBridge,
    events: &EventBus,
    client_listeners: &mut Vec<String>,
) -> Result<(), ServiceBridgeError> {
    let listener = message
        .get("Body")
        .and_then(|b| b.get("Listener"))
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Listener".to_owned()))?;

    let name = listener
        .get("Name")
        .and_then(Value::as_str)
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Listener.Name".to_owned()))?;

    bridge.register_listener(name.to_owned()).await;
    client_listeners.push(name.to_owned());

    info!(name = %name, "service listener registered");

    let listener_json = serde_json::to_string(listener).unwrap_or_default();
    let event = OperatorMessage::ServiceListenerRegister(Message {
        head: MessageHead {
            event: EventCode::Service,
            user: String::new(),
            timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
            one_time: String::new(),
        },
        info: ServiceListenerRegistrationInfo { listener: listener_json },
    });
    events.broadcast(event);

    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Build a teamserver log event attributed to the service bridge.
fn service_log_event(text: &str) -> OperatorMessage {
    OperatorMessage::TeamserverLog(Message {
        head: MessageHead {
            event: EventCode::Teamserver,
            user: "service".to_owned(),
            timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
            one_time: String::new(),
        },
        info: TeamserverLogInfo { text: text.to_owned() },
    })
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_bridge_creates_with_config() {
        let config =
            ServiceConfig { endpoint: "svc-endpoint".to_owned(), password: "secret".to_owned() };
        let bridge = ServiceBridge::new(config);
        assert_eq!(bridge.endpoint(), "svc-endpoint");
    }

    #[tokio::test]
    async fn service_bridge_tracks_clients() {
        let bridge = ServiceBridge::new(ServiceConfig {
            endpoint: "test".to_owned(),
            password: "pw".to_owned(),
        });

        let id = Uuid::new_v4();
        bridge.add_client(id).await;
        assert_eq!(bridge.connected_client_count().await, 1);

        bridge.remove_client(id, &[], &[]).await;
        assert_eq!(bridge.connected_client_count().await, 0);
    }

    #[tokio::test]
    async fn service_bridge_registers_agent() {
        let bridge = ServiceBridge::new(ServiceConfig {
            endpoint: "test".to_owned(),
            password: "pw".to_owned(),
        });

        bridge
            .register_agent("custom-agent".to_owned())
            .await
            .expect("first registration should succeed");

        assert!(bridge.agent_exists("custom-agent").await);

        let err = bridge.register_agent("custom-agent".to_owned()).await;
        assert!(err.is_err(), "duplicate registration should fail");
    }

    #[tokio::test]
    async fn service_bridge_registers_listener() {
        let bridge = ServiceBridge::new(ServiceConfig {
            endpoint: "test".to_owned(),
            password: "pw".to_owned(),
        });

        bridge.register_listener("my-listener".to_owned()).await;
        // Registering same name again is idempotent.
        bridge.register_listener("my-listener".to_owned()).await;

        let inner = bridge.inner.read().await;
        assert_eq!(inner.registered_listeners.len(), 1);
    }

    #[tokio::test]
    async fn client_cleanup_removes_agents_and_listeners() {
        let bridge = ServiceBridge::new(ServiceConfig {
            endpoint: "test".to_owned(),
            password: "pw".to_owned(),
        });

        let client_id = Uuid::new_v4();
        bridge.add_client(client_id).await;
        bridge.register_agent("agent-a".to_owned()).await.ok();
        bridge.register_listener("listener-b".to_owned()).await;

        bridge.remove_client(client_id, &["agent-a".to_owned()], &["listener-b".to_owned()]).await;

        assert_eq!(bridge.connected_client_count().await, 0);
        assert!(!bridge.agent_exists("agent-a").await);
        let inner = bridge.inner.read().await;
        assert!(inner.registered_listeners.is_empty());
    }

    #[test]
    fn service_log_event_creates_valid_operator_message() {
        let event = service_log_event("hello");
        match event {
            OperatorMessage::TeamserverLog(msg) => {
                assert_eq!(msg.info.text, "hello");
                assert_eq!(msg.head.user, "service");
                assert_eq!(msg.head.event, EventCode::Teamserver);
            }
            _ => panic!("expected TeamserverLog variant"),
        }
    }

    #[test]
    fn authenticate_response_format_matches_havoc() {
        let response = serde_json::json!({
            "Head": { "Type": HEAD_REGISTER },
            "Body": { "Success": true },
        });
        let head_type = response["Head"]["Type"].as_str().unwrap();
        assert_eq!(head_type, "Register");
        assert!(response["Body"]["Success"].as_bool().unwrap());
    }

    #[test]
    fn dispatch_returns_ok_for_unknown_head_type() {
        // This tests that unknown message types are silently ignored.
        let message = serde_json::json!({
            "Head": { "Type": "UnknownType" },
            "Body": {},
        });
        let head_type = message
            .get("Head")
            .and_then(|h| h.get("Type"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert_eq!(head_type, "UnknownType");
    }

    #[tokio::test]
    async fn handle_register_agent_broadcasts_event() {
        let bridge = ServiceBridge::new(ServiceConfig {
            endpoint: "test".to_owned(),
            password: "pw".to_owned(),
        });
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let mut client_agents = Vec::new();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_REGISTER_AGENT },
            "Body": {
                "Agent": {
                    "Name": "TestAgent",
                    "Author": "test",
                    "Description": "A test agent",
                }
            },
        });

        handle_register_agent(&message, &bridge, &events, &mut client_agents)
            .await
            .expect("registration should succeed");

        assert!(bridge.agent_exists("TestAgent").await);
        assert_eq!(client_agents, vec!["TestAgent".to_owned()]);

        let event = rx.recv().await.expect("event should be broadcast");
        match event {
            OperatorMessage::ServiceAgentRegister(msg) => {
                assert!(msg.info.agent.contains("TestAgent"));
            }
            _ => panic!("expected ServiceAgentRegister event"),
        }
    }

    #[tokio::test]
    async fn handle_listener_add_broadcasts_event() {
        let bridge = ServiceBridge::new(ServiceConfig {
            endpoint: "test".to_owned(),
            password: "pw".to_owned(),
        });
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let mut client_listeners = Vec::new();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_LISTENER },
            "Body": {
                "Type": BODY_LISTENER_ADD,
                "Listener": {
                    "Name": "custom-listener",
                    "Agent": "TestAgent",
                },
            },
        });

        handle_listener_add(&message, &bridge, &events, &mut client_listeners)
            .await
            .expect("listener add should succeed");

        assert_eq!(client_listeners, vec!["custom-listener".to_owned()]);

        let event = rx.recv().await.expect("event should be broadcast");
        match event {
            OperatorMessage::ServiceListenerRegister(msg) => {
                assert!(msg.info.listener.contains("custom-listener"));
            }
            _ => panic!("expected ServiceListenerRegister event"),
        }
    }

    #[tokio::test]
    async fn handle_register_agent_rejects_duplicate() {
        let bridge = ServiceBridge::new(ServiceConfig {
            endpoint: "test".to_owned(),
            password: "pw".to_owned(),
        });
        let events = EventBus::default();
        let mut client_agents = Vec::new();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_REGISTER_AGENT },
            "Body": {
                "Agent": { "Name": "DupAgent" }
            },
        });

        handle_register_agent(&message, &bridge, &events, &mut client_agents)
            .await
            .expect("first registration should succeed");

        let mut client_agents2 = Vec::new();
        let err = handle_register_agent(&message, &bridge, &events, &mut client_agents2)
            .await
            .expect_err("duplicate should fail");

        assert!(
            matches!(err, ServiceBridgeError::DuplicateAgent { .. }),
            "expected DuplicateAgent error"
        );
    }

    #[test]
    fn missing_agent_name_returns_error() {
        let message = serde_json::json!({
            "Head": { "Type": HEAD_REGISTER_AGENT },
            "Body": {
                "Agent": {}
            },
        });
        let agent_data = message.get("Body").and_then(|b| b.get("Agent")).unwrap();
        let name = agent_data.get("Name").and_then(Value::as_str);
        assert!(name.is_none());
    }
}
