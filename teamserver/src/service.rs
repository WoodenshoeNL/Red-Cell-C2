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

use crate::agent_events::agent_new_event;
use crate::database::TeamserverError;
use crate::{AgentRegistry, EventBus, PivotInfo};

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

    /// Agent registry operation failed.
    #[error("agent registry error: {0}")]
    AgentRegistry(#[from] TeamserverError),

    /// Base64 decoding failure.
    #[error("base64 decode error: {0}")]
    Base64Decode(String),
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
    let agent_json = serde_json::to_string(agent_data)?;
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
    agent_registry: &AgentRegistry,
    socket: &mut WebSocket,
) -> Result<(), ServiceBridgeError> {
    let body_type =
        message.get("Body").and_then(|b| b.get("Type")).and_then(Value::as_str).unwrap_or_default();

    match body_type {
        BODY_AGENT_TASK => handle_agent_task(message, events, agent_registry, socket).await,
        BODY_AGENT_REGISTER => {
            handle_agent_instance_register(message, events, agent_registry).await
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

/// Handle an `AgentTask` message — queue or retrieve tasks for a registered agent.
///
/// Supports two task modes matching the original Havoc protocol:
/// - `"Add"`: decode the base64-encoded command and enqueue a job for the agent
/// - `"Get"`: drain the agent's job queue and return combined payloads as base64
async fn handle_agent_task(
    message: &Value,
    events: &EventBus,
    agent_registry: &AgentRegistry,
    socket: &mut WebSocket,
) -> Result<(), ServiceBridgeError> {
    let body =
        message.get("Body").ok_or_else(|| ServiceBridgeError::MissingField("Body".to_owned()))?;

    let agent_info = body
        .get("Agent")
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Agent".to_owned()))?;

    let agent_id_str = agent_info
        .get("NameID")
        .and_then(Value::as_str)
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Agent.NameID".to_owned()))?;

    let agent_id = u32::from_str_radix(agent_id_str, 16).map_err(|_| {
        ServiceBridgeError::MissingField(format!("Body.Agent.NameID: invalid hex '{agent_id_str}'"))
    })?;

    let task = body
        .get("Task")
        .and_then(Value::as_str)
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Task".to_owned()))?;

    match task {
        "Add" => {
            let command_b64 = body
                .get("Command")
                .and_then(Value::as_str)
                .ok_or_else(|| ServiceBridgeError::MissingField("Body.Command".to_owned()))?;

            use base64::Engine as _;
            let payload = base64::engine::general_purpose::STANDARD
                .decode(command_b64)
                .map_err(|e| ServiceBridgeError::Base64Decode(e.to_string()))?;

            let job = crate::agents::Job {
                command: 0,
                request_id: 0,
                payload,
                command_line: String::new(),
                task_id: Uuid::new_v4().to_string(),
                created_at: OffsetDateTime::now_utc().unix_timestamp().to_string(),
                operator: "service".to_owned(),
            };

            agent_registry.enqueue_job(agent_id, job).await?;
            info!(agent_id = %agent_id_str, "service agent task enqueued");

            let log_event =
                service_log_event(&format!("task enqueued for agent {agent_id_str} via service"));
            events.broadcast(log_event);
            Ok(())
        }
        "Get" => {
            let jobs = agent_registry.dequeue_jobs(agent_id).await?;

            let mut combined_payload = Vec::new();
            for job in &jobs {
                combined_payload.extend_from_slice(&job.payload);
            }

            use base64::Engine as _;
            let encoded = base64::engine::general_purpose::STANDARD.encode(&combined_payload);

            let mut response = message.clone();
            if let Some(resp_body) = response.get_mut("Body") {
                resp_body["TasksQueue"] = Value::String(encoded);
            }

            let response_text = serde_json::to_string(&response)?;
            socket
                .send(WsMessage::Text(response_text.into()))
                .await
                .map_err(ServiceBridgeError::WebSocket)?;

            debug!(agent_id = %agent_id_str, count = jobs.len(), "service agent tasks returned");
            Ok(())
        }
        other => {
            debug!(task = %other, "unknown service agent task mode");
            Ok(())
        }
    }
}

/// Handle an `AgentRegister` message — register a new agent instance through the
/// service bridge.
///
/// Parses the registration info from the message body, constructs an `AgentRecord`,
/// inserts it into the agent registry, and broadcasts an `AgentNew` event to operators.
async fn handle_agent_instance_register(
    message: &Value,
    events: &EventBus,
    agent_registry: &AgentRegistry,
) -> Result<(), ServiceBridgeError> {
    let body =
        message.get("Body").ok_or_else(|| ServiceBridgeError::MissingField("Body".to_owned()))?;

    let register_info = body
        .get("RegisterInfo")
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.RegisterInfo".to_owned()))?;

    let agent_header = body
        .get("AgentHeader")
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.AgentHeader".to_owned()))?;

    let agent_id_str = agent_header
        .get("AgentID")
        .and_then(Value::as_str)
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.AgentHeader.AgentID".to_owned()))?;

    let agent_id = u32::from_str_radix(agent_id_str, 16).map_err(|_| {
        ServiceBridgeError::MissingField(format!(
            "Body.AgentHeader.AgentID: invalid hex '{agent_id_str}'"
        ))
    })?;

    let magic_value_str = agent_header.get("MagicValue").and_then(Value::as_str).unwrap_or("0");

    let magic_value = u32::from_str_radix(magic_value_str, 16).unwrap_or(0);

    let now = OffsetDateTime::now_utc().unix_timestamp().to_string();

    let agent = red_cell_common::AgentRecord {
        agent_id,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: red_cell_common::AgentEncryptionInfo::default(),
        hostname: register_info
            .get("Hostname")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        username: register_info
            .get("Username")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        domain_name: register_info
            .get("DomainName")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        external_ip: register_info
            .get("ExternalIP")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        internal_ip: register_info
            .get("InternalIP")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        process_name: register_info
            .get("ProcessName")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        process_path: register_info
            .get("ProcessPath")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        base_address: 0,
        process_pid: register_info.get("ProcessPID").and_then(Value::as_u64).unwrap_or(0) as u32,
        process_tid: 0,
        process_ppid: 0,
        process_arch: register_info
            .get("ProcessArch")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        elevated: register_info.get("Elevated").and_then(Value::as_bool).unwrap_or(false),
        os_version: register_info
            .get("OSVersion")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        os_build: 0,
        os_arch: register_info.get("OSArch").and_then(Value::as_str).unwrap_or_default().to_owned(),
        sleep_delay: register_info.get("SleepDelay").and_then(Value::as_u64).unwrap_or(0) as u32,
        sleep_jitter: register_info.get("SleepJitter").and_then(Value::as_u64).unwrap_or(0) as u32,
        kill_date: None,
        working_hours: None,
        first_call_in: now.clone(),
        last_call_in: now,
    };

    let pivots = PivotInfo::default();
    let event = agent_new_event("service", magic_value, &agent, &pivots);

    agent_registry.insert(agent).await?;
    info!(agent_id = %agent_id_str, "service agent instance registered");

    events.broadcast(event);

    Ok(())
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

    let listener_json = serde_json::to_string(listener)?;
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

    #[tokio::test]
    async fn dispatch_returns_ok_for_unknown_listener_subtype() {
        // `dispatch_message` requires a `WebSocket` (not constructable in unit
        // tests), so we test the equivalent "unknown type → Ok" path via
        // `handle_listener_message`, which `dispatch_message` delegates to for
        // HEAD_LISTENER messages and which has the same unknown-type branch.
        let bridge = ServiceBridge::new(ServiceConfig {
            endpoint: "test".to_owned(),
            password: "pw".to_owned(),
        });
        let events = EventBus::default();
        let mut client_listeners = Vec::new();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_LISTENER },
            "Body": { "Type": "CompletelyUnknownBodyType" },
        });

        let result =
            handle_listener_message(&message, &bridge, &events, &mut client_listeners).await;
        assert!(result.is_ok(), "unknown listener sub-type should be silently ignored");
        assert!(client_listeners.is_empty(), "no listener should be registered");
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

    #[tokio::test]
    async fn missing_agent_name_returns_error() {
        let bridge = ServiceBridge::new(ServiceConfig {
            endpoint: "test".to_owned(),
            password: "pw".to_owned(),
        });
        let events = EventBus::default();
        let mut client_agents = Vec::new();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_REGISTER_AGENT },
            "Body": {
                "Agent": {}
            },
        });

        let err = handle_register_agent(&message, &bridge, &events, &mut client_agents)
            .await
            .expect_err("missing Name should fail");

        assert!(
            matches!(err, ServiceBridgeError::MissingField(ref f) if f.contains("Name")),
            "expected MissingField error mentioning Name, got: {err:?}"
        );
    }

    // ── AgentTask handler tests ─────────────────────────────────────

    async fn test_registry() -> AgentRegistry {
        let database = crate::database::Database::connect_in_memory().await.expect("in-memory db");
        AgentRegistry::new(database)
    }

    fn test_agent_record(agent_id: u32) -> red_cell_common::AgentRecord {
        red_cell_common::AgentRecord {
            agent_id,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: red_cell_common::AgentEncryptionInfo::default(),
            hostname: "WORKSTATION".to_owned(),
            username: "admin".to_owned(),
            domain_name: "DOMAIN".to_owned(),
            external_ip: "10.0.0.1".to_owned(),
            internal_ip: "192.168.1.100".to_owned(),
            process_name: "svc.exe".to_owned(),
            process_path: "C:\\svc.exe".to_owned(),
            base_address: 0,
            process_pid: 1234,
            process_tid: 0,
            process_ppid: 0,
            process_arch: "x64".to_owned(),
            elevated: false,
            os_version: "Windows 10".to_owned(),
            os_build: 0,
            os_arch: "x64".to_owned(),
            sleep_delay: 5,
            sleep_jitter: 0,
            kill_date: None,
            working_hours: None,
            first_call_in: "0".to_owned(),
            last_call_in: "0".to_owned(),
        }
    }

    /// Create a WebSocket pair using a real TCP connection and axum upgrade.
    async fn ws_pair() -> (
        WebSocket,
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) {
        use tokio::net::TcpListener;

        let (tx, rx) = tokio::sync::mpsc::channel::<WebSocket>(1);

        let app = axum::Router::new().route(
            "/ws",
            axum::routing::get(move |ws: WebSocketUpgrade| {
                let tx = tx.clone();
                async move {
                    ws.on_upgrade(move |socket| async move {
                        let _ = tx.send(socket).await;
                    })
                }
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let server_handle =
            tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });

        let url = format!("ws://127.0.0.1:{}/ws", addr.port());
        let (client, _) = tokio_tungstenite::connect_async(&url).await.expect("ws connect");

        let mut rx = rx;
        let server_socket = rx.recv().await.expect("server socket");

        server_handle.abort();
        (server_socket, client)
    }

    #[tokio::test]
    async fn handle_agent_task_add_enqueues_job() {
        use base64::Engine as _;

        let registry = test_registry().await;
        let agent_id: u32 = 0xAABB_CCDD;
        registry.insert(test_agent_record(agent_id)).await.expect("insert agent");

        let events = EventBus::default();
        let mut rx = events.subscribe();

        let payload = vec![0x41, 0x42, 0x43];
        let encoded = base64::engine::general_purpose::STANDARD.encode(&payload);

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
            "Body": {
                "Type": BODY_AGENT_TASK,
                "Agent": { "NameID": "AABBCCDD" },
                "Task": "Add",
                "Command": encoded,
            },
        });

        let (mut server_ws, _client_ws) = ws_pair().await;

        handle_agent_task(&message, &events, &registry, &mut server_ws)
            .await
            .expect("task add should succeed");

        let jobs = registry.queued_jobs(agent_id).await.expect("queued jobs");
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].payload, payload);
        assert_eq!(jobs[0].operator, "service");

        let event = rx.recv().await.expect("event should be broadcast");
        assert!(
            matches!(event, OperatorMessage::TeamserverLog(_)),
            "expected teamserver log event"
        );
    }

    #[tokio::test]
    async fn handle_agent_task_get_returns_queued_payloads() {
        use base64::Engine as _;
        use futures_util::StreamExt as _;

        let registry = test_registry().await;
        let agent_id: u32 = 0x1122_3344;
        registry.insert(test_agent_record(agent_id)).await.expect("insert agent");

        let job1 = crate::agents::Job {
            payload: vec![0x01, 0x02],
            task_id: "t1".to_owned(),
            created_at: "0".to_owned(),
            operator: "op".to_owned(),
            ..Default::default()
        };
        let job2 = crate::agents::Job {
            payload: vec![0x03, 0x04],
            task_id: "t2".to_owned(),
            created_at: "0".to_owned(),
            operator: "op".to_owned(),
            ..Default::default()
        };
        registry.enqueue_job(agent_id, job1).await.expect("enqueue job1");
        registry.enqueue_job(agent_id, job2).await.expect("enqueue job2");

        let events = EventBus::default();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
            "Body": {
                "Type": BODY_AGENT_TASK,
                "Agent": { "NameID": "11223344" },
                "Task": "Get",
            },
        });

        let (mut server_ws, mut client_ws) = ws_pair().await;

        handle_agent_task(&message, &events, &registry, &mut server_ws)
            .await
            .expect("task get should succeed");

        // Read the response from the client side
        let resp = client_ws.next().await.expect("should receive").expect("not error");
        let text = resp.into_text().expect("text message");
        let parsed: Value = serde_json::from_str(&text).expect("valid json");
        let tasks_queue = parsed["Body"]["TasksQueue"].as_str().expect("TasksQueue");
        let decoded =
            base64::engine::general_purpose::STANDARD.decode(tasks_queue).expect("valid base64");
        assert_eq!(decoded, vec![0x01, 0x02, 0x03, 0x04]);

        // Queue should be drained
        let remaining = registry.queued_jobs(agent_id).await.expect("queued");
        assert!(remaining.is_empty());
    }

    #[tokio::test]
    async fn handle_agent_task_missing_body_returns_error() {
        let registry = test_registry().await;
        let events = EventBus::default();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
        });

        let (mut server_ws, _client_ws) = ws_pair().await;

        let err = handle_agent_task(&message, &events, &registry, &mut server_ws)
            .await
            .expect_err("should fail");
        assert!(matches!(err, ServiceBridgeError::MissingField(_)));
    }

    #[tokio::test]
    async fn handle_agent_task_add_invalid_base64_returns_error() {
        let registry = test_registry().await;
        let agent_id: u32 = 0xDEAD_BEEF;
        registry.insert(test_agent_record(agent_id)).await.expect("insert agent");
        let events = EventBus::default();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
            "Body": {
                "Type": BODY_AGENT_TASK,
                "Agent": { "NameID": "DEADBEEF" },
                "Task": "Add",
                "Command": "!!!not-base64!!!",
            },
        });

        let (mut server_ws, _client_ws) = ws_pair().await;

        let err = handle_agent_task(&message, &events, &registry, &mut server_ws)
            .await
            .expect_err("should fail");
        assert!(matches!(err, ServiceBridgeError::Base64Decode(_)));
    }

    #[tokio::test]
    async fn handle_agent_task_add_unknown_agent_returns_error() {
        let registry = test_registry().await;
        let events = EventBus::default();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
            "Body": {
                "Type": BODY_AGENT_TASK,
                "Agent": { "NameID": "99999999" },
                "Task": "Add",
                "Command": "AAAA",
            },
        });

        let (mut server_ws, _client_ws) = ws_pair().await;

        let err = handle_agent_task(&message, &events, &registry, &mut server_ws)
            .await
            .expect_err("should fail for unknown agent");
        assert!(matches!(err, ServiceBridgeError::AgentRegistry(_)));
    }

    // ── AgentRegister handler tests ─────────────────────────────────

    #[tokio::test]
    async fn handle_agent_instance_register_inserts_and_broadcasts() {
        let registry = test_registry().await;
        let events = EventBus::default();
        let mut rx = events.subscribe();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
            "Body": {
                "Type": BODY_AGENT_REGISTER,
                "AgentHeader": {
                    "Size": "256",
                    "MagicValue": "deadbeef",
                    "AgentID": "AABB0011",
                },
                "RegisterInfo": {
                    "Hostname": "SRV01",
                    "Username": "admin",
                    "DomainName": "CORP",
                    "ExternalIP": "10.0.0.5",
                    "InternalIP": "192.168.1.5",
                    "ProcessName": "agent.exe",
                    "ProcessArch": "x64",
                    "OSVersion": "Windows 11",
                    "OSArch": "x64",
                    "SleepDelay": 10,
                    "SleepJitter": 20,
                },
            },
        });

        handle_agent_instance_register(&message, &events, &registry)
            .await
            .expect("registration should succeed");

        let agent = registry.get(0xAABB_0011).await.expect("agent should exist");
        assert_eq!(agent.hostname, "SRV01");
        assert_eq!(agent.username, "admin");
        assert_eq!(agent.domain_name, "CORP");
        assert_eq!(agent.sleep_delay, 10);
        assert!(agent.active);

        let event = rx.recv().await.expect("event should be broadcast");
        assert!(matches!(event, OperatorMessage::AgentNew(_)), "expected AgentNew event");
    }

    #[tokio::test]
    async fn handle_agent_instance_register_duplicate_returns_error() {
        let registry = test_registry().await;
        let events = EventBus::default();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
            "Body": {
                "Type": BODY_AGENT_REGISTER,
                "AgentHeader": {
                    "Size": "0",
                    "MagicValue": "0",
                    "AgentID": "11223344",
                },
                "RegisterInfo": {
                    "Hostname": "H1",
                    "Username": "u1",
                },
            },
        });

        handle_agent_instance_register(&message, &events, &registry)
            .await
            .expect("first registration should succeed");

        let err = handle_agent_instance_register(&message, &events, &registry)
            .await
            .expect_err("duplicate should fail");
        assert!(matches!(err, ServiceBridgeError::AgentRegistry(_)));
    }

    #[tokio::test]
    async fn handle_agent_instance_register_missing_header_returns_error() {
        let registry = test_registry().await;
        let events = EventBus::default();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
            "Body": {
                "Type": BODY_AGENT_REGISTER,
                "RegisterInfo": { "Hostname": "H1" },
            },
        });

        let err = handle_agent_instance_register(&message, &events, &registry)
            .await
            .expect_err("should fail without AgentHeader");
        assert!(matches!(err, ServiceBridgeError::MissingField(_)));
    }

    #[tokio::test]
    async fn handle_agent_instance_register_invalid_hex_id_returns_error() {
        let registry = test_registry().await;
        let events = EventBus::default();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
            "Body": {
                "Type": BODY_AGENT_REGISTER,
                "AgentHeader": {
                    "AgentID": "ZZZZZZ",
                    "MagicValue": "0",
                },
                "RegisterInfo": { "Hostname": "H1" },
            },
        });

        let err = handle_agent_instance_register(&message, &events, &registry)
            .await
            .expect_err("should fail with invalid hex");
        assert!(matches!(err, ServiceBridgeError::MissingField(_)));
    }
}
