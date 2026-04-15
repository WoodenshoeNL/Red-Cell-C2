//! Service bridge WebSocket endpoint for external tool integration.
//!
//! The Service bridge is a secondary WebSocket endpoint that external tools and
//! custom agents can use to interact with the teamserver programmatically. It
//! mirrors the original Havoc `pkg/service` package.
//!
//! ## Authentication
//!
//! Clients connect via WebSocket and send a JSON `Register` message containing
//! the service password. The password is verified using Argon2id — the same
//! [`password_hashes_match`](crate::auth::password_hashes_match) used by operator auth.
//!
//! ## Protocol
//!
//! After authentication, the client exchanges JSON messages with headers:
//! - `RegisterAgent` — register a custom agent type
//! - `Agent` — agent task, response, output, registration, and build messages
//! - `Listener` — listener management (add, start, ExternalC2)

mod auth;
mod logging;

use auth::authenticate;
use logging::{log_service_action, service_log_event};

use axum::{
    Router,
    extract::{
        ConnectInfo, FromRef, State,
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
    },
    response::IntoResponse,
    routing::get,
};
use red_cell_common::config::ServiceConfig;
use red_cell_common::crypto::hash_password_sha3;
use red_cell_common::demon::DEMON_MAGIC_VALUE;
use red_cell_common::operator::{
    AgentResponseInfo, EventCode, ListenerErrorInfo, ListenerMarkInfo, Message, MessageHead,
    OperatorMessage, ServiceAgentRegistrationInfo, ServiceListenerRegistrationInfo,
};
use serde_json::Value;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use crate::agent_events::agent_new_event;
use crate::audit::{AuditResultStatus, audit_details};
use crate::auth::{AuthError, password_verifier_for_sha3};
use crate::database::TeamserverError;
use crate::{AgentRegistry, AuditWebhookNotifier, Database, EventBus, LoginRateLimiter, PivotInfo};

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

/// Maximum service bridge WebSocket message size accepted by the teamserver (1 MiB).
///
/// This matches the operator WebSocket limit and prevents a service client from
/// causing unbounded memory allocation via oversized frames.
const SERVICE_MAX_MESSAGE_SIZE: usize = 1024 * 1024;

// ── Error types ──────────────────────────────────────────────────────

/// Errors produced by the service bridge.
#[derive(Debug, Error)]
pub enum ServiceBridgeError {
    /// Authentication failed.
    #[error("service client authentication failed")]
    AuthenticationFailed,

    /// The client did not send the initial Register frame in time.
    #[error("service client authentication timed out")]
    AuthenticationTimeout,

    /// Too many failed authentication attempts from this IP.
    #[error("service client rate limited")]
    RateLimited,

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

    /// Magic value does not match the expected Demon protocol constant.
    #[error("invalid magic value: expected 0x{expected:08X}, got 0x{actual:08X}")]
    InvalidMagicValue { expected: u32, actual: u32 },
}

// ── Service bridge state ─────────────────────────────────────────────

/// Manages connected service clients and registered service agents/listeners.
#[derive(Debug, Clone)]
pub struct ServiceBridge {
    endpoint: String,
    /// Argon2id verifier derived from the SHA3-256 hash of the service password.
    ///
    /// The plaintext password is dropped at construction time.
    password_verifier: String,
    inner: Arc<RwLock<ServiceBridgeInner>>,
    /// Independent login rate limiter for service bridge authentication.
    ///
    /// Separate from the operator WebSocket rate limiter so that failed auth
    /// attempts on one surface cannot deny the other.
    login_rate_limiter: LoginRateLimiter,
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
    ///
    /// The password is hashed with SHA3-256 then wrapped in Argon2id at
    /// construction time. The plaintext password is dropped immediately.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] if the Argon2 hasher cannot be initialised.
    pub fn new(config: ServiceConfig) -> Result<Self, AuthError> {
        let password_verifier = password_verifier_for_sha3(&hash_password_sha3(&config.password))?;
        Ok(Self {
            endpoint: config.endpoint,
            password_verifier,
            inner: Arc::new(RwLock::new(ServiceBridgeInner::default())),
            login_rate_limiter: LoginRateLimiter::new(),
        })
    }

    /// Return the configured endpoint path (without leading slash).
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
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
            // Fallback bridge when no service is configured — auth will always reject
            // because the verifier is not a valid Argon2 PHC string.
            Self {
                endpoint: String::new(),
                password_verifier: String::new(),
                inner: Arc::new(RwLock::new(ServiceBridgeInner::default())),
                login_rate_limiter: LoginRateLimiter::new(),
            }
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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    websocket: WebSocketUpgrade,
) -> impl IntoResponse {
    websocket
        .max_message_size(SERVICE_MAX_MESSAGE_SIZE)
        .on_upgrade(move |socket| handle_service_socket(state, socket, addr.ip()))
}

// ── WebSocket connection handler ─────────────────────────────────────

/// Handle a single service client WebSocket connection.
async fn handle_service_socket(
    state: crate::TeamserverState,
    mut socket: WebSocket,
    client_ip: IpAddr,
) {
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

    let rate_limiter = &bridge.login_rate_limiter;

    // Authenticate the client (with rate limiting).
    let client_id =
        match authenticate(&mut socket, &bridge.password_verifier, rate_limiter, client_ip).await {
            Ok(id) => id,
            Err(e) => {
                warn!(%e, %client_ip, "service client authentication failed");
                log_service_action(
                    &state.database,
                    &state.webhooks,
                    "service.auth",
                    "service_client",
                    Some(client_ip.to_string()),
                    audit_details(AuditResultStatus::Failure, None, None, None),
                )
                .await;
                let _ = socket.send(WsMessage::Close(None)).await;
                return;
            }
        };

    info!(%client_id, "service client authenticated");
    log_service_action(
        &state.database,
        &state.webhooks,
        "service.auth",
        "service_client",
        Some(client_id.to_string()),
        audit_details(AuditResultStatus::Success, None, None, None),
    )
    .await;
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
            &state.database,
            &state.webhooks,
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

// ── Message dispatch ─────────────────────────────────────────────────

/// Dispatch a parsed JSON message to the appropriate handler.
#[allow(clippy::too_many_arguments)]
async fn dispatch_message(
    message: &Value,
    bridge: &ServiceBridge,
    events: &EventBus,
    agent_registry: &AgentRegistry,
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    socket: &mut WebSocket,
    client_agents: &mut Vec<String>,
    client_listeners: &mut Vec<String>,
) -> Result<(), ServiceBridgeError> {
    let head_type =
        message.get("Head").and_then(|h| h.get("Type")).and_then(Value::as_str).unwrap_or_default();

    match head_type {
        HEAD_REGISTER_AGENT => {
            handle_register_agent(message, bridge, events, database, webhooks, client_agents).await
        }
        HEAD_AGENT => {
            handle_agent_message(
                message,
                bridge,
                events,
                agent_registry,
                database,
                webhooks,
                socket,
            )
            .await
        }
        HEAD_LISTENER => {
            handle_listener_message(message, bridge, events, database, webhooks, client_listeners)
                .await
        }
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
    database: &Database,
    webhooks: &AuditWebhookNotifier,
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

    log_service_action(
        database,
        webhooks,
        "service.register_agent",
        "agent_type",
        Some(agent_name.to_owned()),
        audit_details(AuditResultStatus::Success, None, None, None),
    )
    .await;

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
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    socket: &mut WebSocket,
) -> Result<(), ServiceBridgeError> {
    let body_type =
        message.get("Body").and_then(|b| b.get("Type")).and_then(Value::as_str).unwrap_or_default();

    match body_type {
        BODY_AGENT_TASK => {
            handle_agent_task(message, events, agent_registry, database, webhooks, socket).await
        }
        BODY_AGENT_REGISTER => {
            handle_agent_instance_register(message, events, agent_registry, database, webhooks)
                .await
        }
        BODY_AGENT_RESPONSE => handle_agent_response(message, events).await,
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
    database: &Database,
    webhooks: &AuditWebhookNotifier,
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

            log_service_action(
                database,
                webhooks,
                "service.agent_task",
                "agent",
                Some(agent_id_str.to_owned()),
                audit_details(AuditResultStatus::Success, Some(agent_id), Some("Add"), None),
            )
            .await;

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
    database: &Database,
    webhooks: &AuditWebhookNotifier,
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

    let magic_value_str =
        agent_header.get("MagicValue").and_then(Value::as_str).ok_or_else(|| {
            ServiceBridgeError::MissingField("Body.AgentHeader.MagicValue".to_owned())
        })?;

    let magic_value = u32::from_str_radix(magic_value_str, 16).map_err(|_| {
        ServiceBridgeError::MissingField(format!(
            "Body.AgentHeader.MagicValue: invalid hex '{magic_value_str}'"
        ))
    })?;

    if magic_value != DEMON_MAGIC_VALUE {
        return Err(ServiceBridgeError::InvalidMagicValue {
            expected: DEMON_MAGIC_VALUE,
            actual: magic_value,
        });
    }

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
        process_pid: {
            let v = register_info.get("ProcessPID").and_then(Value::as_u64).unwrap_or(0);
            match u32::try_from(v) {
                Ok(n) => n,
                Err(_) => {
                    warn!(
                        agent_id,
                        field = "ProcessPID",
                        value = v,
                        "service bridge: u64 value exceeds u32::MAX, clamping to 0"
                    );
                    0
                }
            }
        },
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
        sleep_delay: {
            let v = register_info.get("SleepDelay").and_then(Value::as_u64).unwrap_or(0);
            match u32::try_from(v) {
                Ok(n) => n,
                Err(_) => {
                    warn!(
                        agent_id,
                        field = "SleepDelay",
                        value = v,
                        "service bridge: u64 value exceeds u32::MAX, clamping to 0"
                    );
                    0
                }
            }
        },
        sleep_jitter: {
            let v = register_info.get("SleepJitter").and_then(Value::as_u64).unwrap_or(0);
            match u32::try_from(v) {
                Ok(n) => n,
                Err(_) => {
                    warn!(
                        agent_id,
                        field = "SleepJitter",
                        value = v,
                        "service bridge: u64 value exceeds u32::MAX, clamping to 0"
                    );
                    0
                }
            }
        },
        kill_date: None,
        working_hours: None,
        first_call_in: now.clone(),
        last_call_in: now,
    };

    let pivots = PivotInfo::default();
    let event = agent_new_event("service", magic_value, &agent, &pivots);

    agent_registry.insert(agent).await?;
    info!(agent_id = %agent_id_str, "service agent instance registered");

    log_service_action(
        database,
        webhooks,
        "service.agent_register",
        "agent",
        Some(agent_id_str.to_owned()),
        audit_details(AuditResultStatus::Success, Some(agent_id), None, None),
    )
    .await;

    events.broadcast(event);

    Ok(())
}

/// Handle agent output messages — broadcast callback data to operators.
///
/// The `Callback` field carries the actual command output from the service
/// agent.  Previous code discarded this data and only emitted a generic log
/// line.  We now forward the callback as an `AgentResponse` event so that
/// connected operators receive the payload, matching the pattern used by
/// `handle_agent_response`.
async fn handle_agent_output(message: &Value, events: &EventBus) -> Result<(), ServiceBridgeError> {
    let body =
        message.get("Body").ok_or_else(|| ServiceBridgeError::MissingField("Body".to_owned()))?;

    let agent_id = body.get("AgentID").and_then(Value::as_str).unwrap_or("unknown");

    let callback = body.get("Callback");

    debug!(%agent_id, ?callback, "service agent output");

    // Serialize the Callback value so operators receive the full payload.
    let output = match callback {
        Some(v) => match v.as_str() {
            Some(s) => s.to_owned(),
            None => serde_json::to_string(v).unwrap_or_default(),
        },
        None => String::new(),
    };

    // Broadcast the callback data as an AgentResponse so operators see output.
    let response_event = OperatorMessage::AgentResponse(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "service".to_owned(),
            timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
            one_time: String::new(),
        },
        info: AgentResponseInfo {
            demon_id: agent_id.to_owned(),
            command_id: String::new(),
            output,
            command_line: None,
            extra: Default::default(),
        },
    });
    events.broadcast(response_event);

    Ok(())
}

/// Handle an `AgentResponse` message — extract response data from a service
/// client and broadcast it to connected operators.
///
/// The Havoc service protocol sends responses with the following body fields:
/// - `Agent.NameID` — hex agent identifier
/// - `Response` — base64-encoded response payload
/// - `RandID` — correlation identifier for request-response pairing
async fn handle_agent_response(
    message: &Value,
    events: &EventBus,
) -> Result<(), ServiceBridgeError> {
    let body =
        message.get("Body").ok_or_else(|| ServiceBridgeError::MissingField("Body".to_owned()))?;

    let agent_id = body
        .get("Agent")
        .and_then(|a| a.get("NameID"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");

    let response_data = body.get("Response").and_then(Value::as_str).unwrap_or_default();

    let rand_id = body.get("RandID").and_then(Value::as_str).unwrap_or_default();

    debug!(%agent_id, %rand_id, response_len = response_data.len(), "service agent response");

    // Broadcast the response as an AgentResponse event so operators see it.
    let event = OperatorMessage::AgentResponse(Message {
        head: MessageHead {
            event: EventCode::Session,
            user: "service".to_owned(),
            timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
            one_time: String::new(),
        },
        info: AgentResponseInfo {
            demon_id: agent_id.to_owned(),
            command_id: rand_id.to_owned(),
            output: response_data.to_owned(),
            command_line: None,
            extra: Default::default(),
        },
    });
    events.broadcast(event);

    Ok(())
}

// ── Listener message handler ─────────────────────────────────────────

/// Handle a `Listener` message — register or start service-provided listeners.
async fn handle_listener_message(
    message: &Value,
    bridge: &ServiceBridge,
    events: &EventBus,
    database: &Database,
    webhooks: &AuditWebhookNotifier,
    client_listeners: &mut Vec<String>,
) -> Result<(), ServiceBridgeError> {
    let body_type =
        message.get("Body").and_then(|b| b.get("Type")).and_then(Value::as_str).unwrap_or_default();

    match body_type {
        BODY_LISTENER_ADD => {
            handle_listener_add(message, bridge, events, database, webhooks, client_listeners).await
        }
        BODY_LISTENER_START => handle_listener_start(message, events, database, webhooks).await,
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
    database: &Database,
    webhooks: &AuditWebhookNotifier,
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

    log_service_action(
        database,
        webhooks,
        "service.listener_add",
        "listener",
        Some(name.to_owned()),
        audit_details(AuditResultStatus::Success, None, None, None),
    )
    .await;

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

/// Handle a `ListenerStart` notification — validate the listener metadata
/// and broadcast the start status to connected operators.
///
/// The Havoc service protocol sends start notifications with the following
/// fields inside `Body.Listener`:
/// - `Name` — listener name (required)
/// - `Protocol` — listener protocol, e.g. "HTTPS" (required)
/// - `Host` — bind host (required)
/// - `PortBind` — bind port (required)
/// - `Status` — start status string, e.g. "online" or "error" (required)
/// - `Error` — error description if the start failed (required, may be empty)
/// - `Info` — additional listener metadata (optional)
async fn handle_listener_start(
    message: &Value,
    events: &EventBus,
    database: &Database,
    webhooks: &AuditWebhookNotifier,
) -> Result<(), ServiceBridgeError> {
    let body =
        message.get("Body").ok_or_else(|| ServiceBridgeError::MissingField("Body".to_owned()))?;

    let listener = body
        .get("Listener")
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Listener".to_owned()))?;

    let name = listener
        .get("Name")
        .and_then(Value::as_str)
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Listener.Name".to_owned()))?;

    let protocol = listener
        .get("Protocol")
        .and_then(Value::as_str)
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Listener.Protocol".to_owned()))?;

    let host = listener
        .get("Host")
        .and_then(Value::as_str)
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Listener.Host".to_owned()))?;

    let port_bind = listener
        .get("PortBind")
        .and_then(Value::as_str)
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Listener.PortBind".to_owned()))?;

    let status = listener
        .get("Status")
        .and_then(Value::as_str)
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Listener.Status".to_owned()))?;

    let error_text = listener
        .get("Error")
        .and_then(Value::as_str)
        .ok_or_else(|| ServiceBridgeError::MissingField("Body.Listener.Error".to_owned()))?;

    let head = MessageHead {
        event: EventCode::Listener,
        user: "service".to_owned(),
        timestamp: OffsetDateTime::now_utc().unix_timestamp().to_string(),
        one_time: String::new(),
    };

    let is_error = status.eq_ignore_ascii_case("error") || !error_text.is_empty();

    if is_error {
        warn!(
            %name, %protocol, %host, %port_bind, %error_text,
            "service listener start failed"
        );
        log_service_action(
            database,
            webhooks,
            "service.listener_start",
            "listener",
            Some(name.to_owned()),
            audit_details(AuditResultStatus::Failure, None, None, None),
        )
        .await;
        let event = OperatorMessage::ListenerError(Message {
            head,
            info: ListenerErrorInfo { error: error_text.to_owned(), name: name.to_owned() },
        });
        events.broadcast(event);
    } else {
        info!(
            %name, %protocol, %host, %port_bind, %status,
            "service listener started"
        );
        log_service_action(
            database,
            webhooks,
            "service.listener_start",
            "listener",
            Some(name.to_owned()),
            audit_details(AuditResultStatus::Success, None, None, None),
        )
        .await;
        let event = OperatorMessage::ListenerMark(Message {
            head,
            info: ListenerMarkInfo { name: name.to_owned(), mark: "Online".to_owned() },
        });
        events.broadcast(event);
    }

    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Create a test database and webhook notifier pair for audit logging tests.
    async fn test_audit_deps() -> (Database, AuditWebhookNotifier) {
        let database = crate::database::Database::connect_in_memory().await.expect("in-memory db");
        let webhooks = AuditWebhookNotifier::default();
        (database, webhooks)
    }

    /// Create an Argon2id verifier from a plaintext password (for test use).
    fn test_verifier(password: &str) -> String {
        password_verifier_for_sha3(&hash_password_sha3(password))
            .expect("test verifier should be generated")
    }

    #[test]
    fn service_bridge_creates_with_config() {
        let config =
            ServiceConfig { endpoint: "svc-endpoint".to_owned(), password: "secret".to_owned() };
        let bridge = ServiceBridge::new(config).expect("service bridge");
        assert_eq!(bridge.endpoint(), "svc-endpoint");
    }

    #[tokio::test]
    async fn service_bridge_tracks_clients() {
        let bridge = ServiceBridge::new(ServiceConfig {
            endpoint: "test".to_owned(),
            password: "pw".to_owned(),
        })
        .expect("service bridge");

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
        })
        .expect("service bridge");

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
        })
        .expect("service bridge");

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
        })
        .expect("service bridge");

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
    fn authenticate_response_format_matches_havoc() {
        let response = serde_json::json!({
            "Head": { "Type": HEAD_REGISTER },
            "Body": { "Success": true },
        });
        let head_type = response["Head"]["Type"].as_str().expect("unwrap");
        assert_eq!(head_type, "Register");
        assert!(response["Body"]["Success"].as_bool().expect("unwrap"));
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
        })
        .expect("service bridge");
        let events = EventBus::default();
        let (db, wh) = test_audit_deps().await;
        let mut client_listeners = Vec::new();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_LISTENER },
            "Body": { "Type": "CompletelyUnknownBodyType" },
        });

        let result =
            handle_listener_message(&message, &bridge, &events, &db, &wh, &mut client_listeners)
                .await;
        assert!(result.is_ok(), "unknown listener sub-type should be silently ignored");
        assert!(client_listeners.is_empty(), "no listener should be registered");
    }

    #[tokio::test]
    async fn handle_register_agent_broadcasts_event() {
        let (db, wh) = test_audit_deps().await;
        let bridge = ServiceBridge::new(ServiceConfig {
            endpoint: "test".to_owned(),
            password: "pw".to_owned(),
        })
        .expect("service bridge");
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

        handle_register_agent(&message, &bridge, &events, &db, &wh, &mut client_agents)
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
        let (db, wh) = test_audit_deps().await;
        let bridge = ServiceBridge::new(ServiceConfig {
            endpoint: "test".to_owned(),
            password: "pw".to_owned(),
        })
        .expect("service bridge");
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

        handle_listener_add(&message, &bridge, &events, &db, &wh, &mut client_listeners)
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
        let (db, wh) = test_audit_deps().await;
        let bridge = ServiceBridge::new(ServiceConfig {
            endpoint: "test".to_owned(),
            password: "pw".to_owned(),
        })
        .expect("service bridge");
        let events = EventBus::default();
        let mut client_agents = Vec::new();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_REGISTER_AGENT },
            "Body": {
                "Agent": { "Name": "DupAgent" }
            },
        });

        handle_register_agent(&message, &bridge, &events, &db, &wh, &mut client_agents)
            .await
            .expect("first registration should succeed");

        let mut client_agents2 = Vec::new();
        let err = handle_register_agent(&message, &bridge, &events, &db, &wh, &mut client_agents2)
            .await
            .expect_err("duplicate should fail");

        assert!(
            matches!(err, ServiceBridgeError::DuplicateAgent { .. }),
            "expected DuplicateAgent error"
        );
    }

    #[tokio::test]
    async fn missing_agent_name_returns_error() {
        let (db, wh) = test_audit_deps().await;
        let bridge = ServiceBridge::new(ServiceConfig {
            endpoint: "test".to_owned(),
            password: "pw".to_owned(),
        })
        .expect("service bridge");
        let events = EventBus::default();
        let mut client_agents = Vec::new();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_REGISTER_AGENT },
            "Body": {
                "Agent": {}
            },
        });

        let err = handle_register_agent(&message, &bridge, &events, &db, &wh, &mut client_agents)
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
        let (db, wh) = test_audit_deps().await;

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

        handle_agent_task(&message, &events, &registry, &db, &wh, &mut server_ws)
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
        let (db, wh) = test_audit_deps().await;

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

        handle_agent_task(&message, &events, &registry, &db, &wh, &mut server_ws)
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
        let (db, wh) = test_audit_deps().await;
        let registry = test_registry().await;
        let events = EventBus::default();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
        });

        let (mut server_ws, _client_ws) = ws_pair().await;

        let err = handle_agent_task(&message, &events, &registry, &db, &wh, &mut server_ws)
            .await
            .expect_err("should fail");
        assert!(matches!(err, ServiceBridgeError::MissingField(_)));
    }

    #[tokio::test]
    async fn handle_agent_task_add_invalid_base64_returns_error() {
        let (db, wh) = test_audit_deps().await;
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

        let err = handle_agent_task(&message, &events, &registry, &db, &wh, &mut server_ws)
            .await
            .expect_err("should fail");
        assert!(matches!(err, ServiceBridgeError::Base64Decode(_)));
    }

    #[tokio::test]
    async fn handle_agent_task_add_unknown_agent_returns_error() {
        let (db, wh) = test_audit_deps().await;
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

        let err = handle_agent_task(&message, &events, &registry, &db, &wh, &mut server_ws)
            .await
            .expect_err("should fail for unknown agent");
        assert!(matches!(err, ServiceBridgeError::AgentRegistry(_)));
    }

    // ── AgentRegister handler tests ─────────────────────────────────

    #[tokio::test]
    async fn handle_agent_instance_register_inserts_and_broadcasts() {
        let (db, wh) = test_audit_deps().await;
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

        handle_agent_instance_register(&message, &events, &registry, &db, &wh)
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
        let (db, wh) = test_audit_deps().await;
        let registry = test_registry().await;
        let events = EventBus::default();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
            "Body": {
                "Type": BODY_AGENT_REGISTER,
                "AgentHeader": {
                    "Size": "0",
                    "MagicValue": "DEADBEEF",
                    "AgentID": "11223344",
                },
                "RegisterInfo": {
                    "Hostname": "H1",
                    "Username": "u1",
                },
            },
        });

        handle_agent_instance_register(&message, &events, &registry, &db, &wh)
            .await
            .expect("first registration should succeed");

        let err = handle_agent_instance_register(&message, &events, &registry, &db, &wh)
            .await
            .expect_err("duplicate should fail");
        assert!(matches!(err, ServiceBridgeError::AgentRegistry(_)));
    }

    #[tokio::test]
    async fn handle_agent_instance_register_missing_header_returns_error() {
        let (db, wh) = test_audit_deps().await;
        let registry = test_registry().await;
        let events = EventBus::default();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
            "Body": {
                "Type": BODY_AGENT_REGISTER,
                "RegisterInfo": { "Hostname": "H1" },
            },
        });

        let err = handle_agent_instance_register(&message, &events, &registry, &db, &wh)
            .await
            .expect_err("should fail without AgentHeader");
        assert!(matches!(err, ServiceBridgeError::MissingField(_)));
    }

    // ── AgentResponse handler tests ─────────────────────────────────

    #[tokio::test]
    async fn handle_agent_response_broadcasts_event() {
        let events = EventBus::default();
        let mut rx = events.subscribe();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
            "Body": {
                "Type": BODY_AGENT_RESPONSE,
                "Agent": { "NameID": "DEAD0001" },
                "Response": "SGVsbG8gV29ybGQ=",
                "RandID": "abc123",
            },
        });

        handle_agent_response(&message, &events).await.expect("response handling should succeed");

        let event = rx.recv().await.expect("event should be broadcast");
        match event {
            OperatorMessage::AgentResponse(msg) => {
                assert_eq!(msg.info.demon_id, "DEAD0001");
                assert_eq!(msg.info.command_id, "abc123");
                assert_eq!(msg.info.output, "SGVsbG8gV29ybGQ=");
                assert!(msg.info.command_line.is_none());
                assert_eq!(msg.head.event, EventCode::Session);
                assert_eq!(msg.head.user, "service");
            }
            _ => panic!("expected AgentResponse event"),
        }
    }

    #[tokio::test]
    async fn handle_agent_response_missing_body_returns_error() {
        let events = EventBus::default();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
        });

        let err =
            handle_agent_response(&message, &events).await.expect_err("should fail without Body");
        assert!(matches!(err, ServiceBridgeError::MissingField(_)));
    }

    #[tokio::test]
    async fn handle_agent_response_missing_optional_fields_uses_defaults() {
        let events = EventBus::default();
        let mut rx = events.subscribe();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
            "Body": {
                "Type": BODY_AGENT_RESPONSE,
            },
        });

        handle_agent_response(&message, &events).await.expect("should succeed with defaults");

        let event = rx.recv().await.expect("event should be broadcast");
        match event {
            OperatorMessage::AgentResponse(msg) => {
                assert_eq!(msg.info.demon_id, "unknown");
                assert_eq!(msg.info.command_id, "");
                assert_eq!(msg.info.output, "");
            }
            _ => panic!("expected AgentResponse event"),
        }
    }

    #[tokio::test]
    async fn handle_agent_instance_register_invalid_hex_id_returns_error() {
        let (db, wh) = test_audit_deps().await;
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

        let err = handle_agent_instance_register(&message, &events, &registry, &db, &wh)
            .await
            .expect_err("should fail with invalid hex");
        assert!(matches!(err, ServiceBridgeError::MissingField(_)));
    }

    #[tokio::test]
    async fn handle_agent_instance_register_rejects_wrong_magic_value() {
        let (db, wh) = test_audit_deps().await;
        let registry = test_registry().await;
        let events = EventBus::default();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
            "Body": {
                "Type": BODY_AGENT_REGISTER,
                "AgentHeader": {
                    "AgentID": "AABB0011",
                    "MagicValue": "CAFEBABE",
                },
                "RegisterInfo": { "Hostname": "H1" },
            },
        });

        let err = handle_agent_instance_register(&message, &events, &registry, &db, &wh)
            .await
            .expect_err("should fail with wrong magic value");
        assert!(
            matches!(
                err,
                ServiceBridgeError::InvalidMagicValue {
                    expected: 0xDEAD_BEEF,
                    actual: 0xCAFE_BABE
                }
            ),
            "expected InvalidMagicValue, got {err:?}"
        );
    }

    #[tokio::test]
    async fn handle_agent_instance_register_rejects_missing_magic_value() {
        let (db, wh) = test_audit_deps().await;
        let registry = test_registry().await;
        let events = EventBus::default();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
            "Body": {
                "Type": BODY_AGENT_REGISTER,
                "AgentHeader": {
                    "AgentID": "AABB0011",
                },
                "RegisterInfo": { "Hostname": "H1" },
            },
        });

        let err = handle_agent_instance_register(&message, &events, &registry, &db, &wh)
            .await
            .expect_err("should fail with missing magic value");
        assert!(
            matches!(err, ServiceBridgeError::MissingField(ref f) if f.contains("MagicValue")),
            "expected MissingField for MagicValue, got {err:?}"
        );
    }

    #[tokio::test]
    async fn handle_agent_instance_register_clamps_overflowing_u32_fields_to_zero() {
        let (db, wh) = test_audit_deps().await;
        let registry = test_registry().await;
        let events = EventBus::default();

        let over_u32_max: u64 = u32::MAX as u64 + 1;
        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
            "Body": {
                "Type": BODY_AGENT_REGISTER,
                "AgentHeader": {
                    "Size": "0",
                    "MagicValue": "DEADBEEF",
                    "AgentID": "DEAD0001",
                },
                "RegisterInfo": {
                    "Hostname": "H1",
                    "Username": "u1",
                    "ProcessPID": over_u32_max,
                    "SleepDelay": over_u32_max,
                    "SleepJitter": over_u32_max,
                },
            },
        });

        handle_agent_instance_register(&message, &events, &registry, &db, &wh)
            .await
            .expect("registration should succeed");

        let agent = registry.get(0xDEAD_0001).await.expect("agent should exist");
        assert_eq!(agent.process_pid, 0, "ProcessPID should clamp to 0 on overflow");
        assert_eq!(agent.sleep_delay, 0, "SleepDelay should clamp to 0 on overflow");
        assert_eq!(agent.sleep_jitter, 0, "SleepJitter should clamp to 0 on overflow");
    }

    #[tokio::test]
    async fn handle_agent_instance_register_accepts_u32_max_values() {
        let (db, wh) = test_audit_deps().await;
        let registry = test_registry().await;
        let events = EventBus::default();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
            "Body": {
                "Type": BODY_AGENT_REGISTER,
                "AgentHeader": {
                    "Size": "0",
                    "MagicValue": "DEADBEEF",
                    "AgentID": "DEAD0002",
                },
                "RegisterInfo": {
                    "Hostname": "H2",
                    "Username": "u2",
                    "ProcessPID": u32::MAX as u64,
                    "SleepDelay": u32::MAX as u64,
                    "SleepJitter": u32::MAX as u64,
                },
            },
        });

        handle_agent_instance_register(&message, &events, &registry, &db, &wh)
            .await
            .expect("registration should succeed");

        let agent = registry.get(0xDEAD_0002).await.expect("agent should exist");
        assert_eq!(agent.process_pid, u32::MAX, "ProcessPID at u32::MAX should be accepted");
        assert_eq!(agent.sleep_delay, u32::MAX, "SleepDelay at u32::MAX should be accepted");
        assert_eq!(agent.sleep_jitter, u32::MAX, "SleepJitter at u32::MAX should be accepted");
    }

    // ── ListenerStart handler tests ─────────────────────────────────

    fn listener_start_message(status: &str, error: &str) -> Value {
        serde_json::json!({
            "Head": { "Type": HEAD_LISTENER },
            "Body": {
                "Type": BODY_LISTENER_START,
                "Listener": {
                    "Name": "https-listener",
                    "Protocol": "HTTPS",
                    "Host": "0.0.0.0",
                    "PortBind": "443",
                    "Status": status,
                    "Error": error,
                    "Info": { "CertPath": "/tmp/cert.pem" },
                },
            },
        })
    }

    #[tokio::test]
    async fn listener_start_broadcasts_online_mark() {
        let (db, wh) = test_audit_deps().await;
        let events = EventBus::default();
        let mut rx = events.subscribe();

        let message = listener_start_message("online", "");

        handle_listener_start(&message, &events, &db, &wh)
            .await
            .expect("listener start should succeed");

        let event = rx.recv().await.expect("event should be broadcast");
        match event {
            OperatorMessage::ListenerMark(msg) => {
                assert_eq!(msg.info.name, "https-listener");
                assert_eq!(msg.info.mark, "Online");
            }
            other => panic!("expected ListenerMark, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn listener_start_broadcasts_error_on_failure() {
        let (db, wh) = test_audit_deps().await;
        let events = EventBus::default();
        let mut rx = events.subscribe();

        let message = listener_start_message("error", "bind: address already in use");

        handle_listener_start(&message, &events, &db, &wh)
            .await
            .expect("listener start should succeed even on error status");

        let event = rx.recv().await.expect("event should be broadcast");
        match event {
            OperatorMessage::ListenerError(msg) => {
                assert_eq!(msg.info.name, "https-listener");
                assert_eq!(msg.info.error, "bind: address already in use");
            }
            other => panic!("expected ListenerError, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn listener_start_error_text_nonempty_overrides_status() {
        let (db, wh) = test_audit_deps().await;
        let events = EventBus::default();
        let mut rx = events.subscribe();

        // Status is "online" but error text is non-empty — should still treat as error.
        let message = listener_start_message("online", "partial failure");

        handle_listener_start(&message, &events, &db, &wh)
            .await
            .expect("listener start should succeed");

        let event = rx.recv().await.expect("event should be broadcast");
        assert!(
            matches!(event, OperatorMessage::ListenerError(_)),
            "non-empty error text should produce ListenerError"
        );
    }

    #[tokio::test]
    async fn listener_start_rejects_missing_name() {
        let (db, wh) = test_audit_deps().await;
        let events = EventBus::default();

        let message = serde_json::json!({
            "Body": {
                "Type": BODY_LISTENER_START,
                "Listener": {
                    "Protocol": "HTTPS",
                    "Host": "0.0.0.0",
                    "PortBind": "443",
                    "Status": "online",
                    "Error": "",
                },
            },
        });

        let err = handle_listener_start(&message, &events, &db, &wh)
            .await
            .expect_err("missing Name should fail");
        assert!(
            matches!(err, ServiceBridgeError::MissingField(ref f) if f.contains("Name")),
            "expected MissingField mentioning Name, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn listener_start_rejects_missing_body() {
        let (db, wh) = test_audit_deps().await;
        let events = EventBus::default();
        let message = serde_json::json!({ "Head": { "Type": HEAD_LISTENER } });

        let err = handle_listener_start(&message, &events, &db, &wh)
            .await
            .expect_err("missing Body should fail");
        assert!(matches!(err, ServiceBridgeError::MissingField(ref f) if f.contains("Body")));
    }

    #[tokio::test]
    async fn listener_start_rejects_missing_status() {
        let (db, wh) = test_audit_deps().await;
        let events = EventBus::default();

        let message = serde_json::json!({
            "Body": {
                "Type": BODY_LISTENER_START,
                "Listener": {
                    "Name": "test",
                    "Protocol": "HTTPS",
                    "Host": "0.0.0.0",
                    "PortBind": "443",
                    "Error": "",
                },
            },
        });

        let err = handle_listener_start(&message, &events, &db, &wh)
            .await
            .expect_err("missing Status should fail");
        assert!(
            matches!(err, ServiceBridgeError::MissingField(ref f) if f.contains("Status")),
            "expected MissingField mentioning Status, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn listener_message_dispatches_start() {
        let (db, wh) = test_audit_deps().await;
        let bridge = ServiceBridge::new(ServiceConfig {
            endpoint: "test".to_owned(),
            password: "pw".to_owned(),
        })
        .expect("service bridge");
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let mut client_listeners = Vec::new();

        let message = listener_start_message("online", "");

        handle_listener_message(&message, &bridge, &events, &db, &wh, &mut client_listeners)
            .await
            .expect("dispatch to listener start should succeed");

        let event = rx.recv().await.expect("event should be broadcast");
        assert!(
            matches!(event, OperatorMessage::ListenerMark(_)),
            "expected ListenerMark from dispatched handler"
        );
    }

    // ── Audit logging tests ───────────────────────────────────────────

    #[tokio::test]
    async fn register_agent_creates_audit_entry() {
        let (db, wh) = test_audit_deps().await;
        let bridge = ServiceBridge::new(ServiceConfig {
            endpoint: "test".to_owned(),
            password: "pw".to_owned(),
        })
        .expect("service bridge");
        let events = EventBus::default();
        let mut client_agents = Vec::new();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_REGISTER_AGENT },
            "Body": { "Agent": { "Name": "AuditTestAgent" } },
        });

        handle_register_agent(&message, &bridge, &events, &db, &wh, &mut client_agents)
            .await
            .expect("registration should succeed");

        let query = crate::audit::AuditQuery {
            action: Some("service.register_agent".to_owned()),
            ..Default::default()
        };
        let page = crate::audit::query_audit_log(&db, &query).await.expect("query should succeed");
        assert_eq!(page.total, 1, "expected one audit entry for agent registration");
        assert_eq!(page.items[0].actor, "service");
        assert_eq!(page.items[0].target_kind, "agent_type");
        assert_eq!(page.items[0].target_id.as_deref(), Some("AuditTestAgent"));
    }

    #[tokio::test]
    async fn listener_add_creates_audit_entry() {
        let (db, wh) = test_audit_deps().await;
        let bridge = ServiceBridge::new(ServiceConfig {
            endpoint: "test".to_owned(),
            password: "pw".to_owned(),
        })
        .expect("service bridge");
        let events = EventBus::default();
        let mut client_listeners = Vec::new();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_LISTENER },
            "Body": {
                "Type": BODY_LISTENER_ADD,
                "Listener": { "Name": "audit-listener" },
            },
        });

        handle_listener_add(&message, &bridge, &events, &db, &wh, &mut client_listeners)
            .await
            .expect("listener add should succeed");

        let query = crate::audit::AuditQuery {
            action: Some("service.listener_add".to_owned()),
            ..Default::default()
        };
        let page = crate::audit::query_audit_log(&db, &query).await.expect("query should succeed");
        assert_eq!(page.total, 1, "expected one audit entry for listener add");
        assert_eq!(page.items[0].actor, "service");
        assert_eq!(page.items[0].target_id.as_deref(), Some("audit-listener"));
    }

    #[tokio::test]
    async fn listener_start_creates_audit_entry() {
        let (db, wh) = test_audit_deps().await;
        let events = EventBus::default();

        let message = listener_start_message("online", "");
        handle_listener_start(&message, &events, &db, &wh)
            .await
            .expect("listener start should succeed");

        let query = crate::audit::AuditQuery {
            action: Some("service.listener_start".to_owned()),
            ..Default::default()
        };
        let page = crate::audit::query_audit_log(&db, &query).await.expect("query should succeed");
        assert_eq!(page.total, 1, "expected one audit entry for listener start");
        assert_eq!(page.items[0].actor, "service");
        assert_eq!(page.items[0].result_status, AuditResultStatus::Success,);
    }

    #[tokio::test]
    async fn listener_start_failure_creates_audit_entry_with_failure_status() {
        let (db, wh) = test_audit_deps().await;
        let events = EventBus::default();

        let message = listener_start_message("error", "bind failed");
        handle_listener_start(&message, &events, &db, &wh)
            .await
            .expect("listener start (error) should succeed");

        let query = crate::audit::AuditQuery {
            action: Some("service.listener_start".to_owned()),
            ..Default::default()
        };
        let page = crate::audit::query_audit_log(&db, &query).await.expect("query should succeed");
        assert_eq!(page.total, 1);
        assert_eq!(page.items[0].result_status, AuditResultStatus::Failure,);
    }

    #[tokio::test]
    async fn agent_instance_register_creates_audit_entry() {
        let (db, wh) = test_audit_deps().await;
        let registry = test_registry().await;
        let events = EventBus::default();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
            "Body": {
                "Type": BODY_AGENT_REGISTER,
                "AgentHeader": { "AgentID": "ABCD1234", "MagicValue": "DEADBEEF" },
                "RegisterInfo": {
                    "Hostname": "HOST",
                    "Username": "user",
                    "DomainName": "DOMAIN",
                    "ExternalIP": "10.0.0.1",
                    "InternalIP": "192.168.1.1",
                    "ProcessName": "svc.exe",
                    "ProcessPID": 100,
                    "ProcessArch": "x64",
                    "OSVersion": "Windows 10",
                    "OSArch": "x64",
                },
            },
        });

        handle_agent_instance_register(&message, &events, &registry, &db, &wh)
            .await
            .expect("agent registration should succeed");

        let query = crate::audit::AuditQuery {
            action: Some("service.agent_register".to_owned()),
            ..Default::default()
        };
        let page = crate::audit::query_audit_log(&db, &query).await.expect("query should succeed");
        assert_eq!(page.total, 1, "expected one audit entry for agent instance register");
        assert_eq!(page.items[0].actor, "service");
        assert_eq!(page.items[0].target_kind, "agent");
        assert_eq!(page.items[0].agent_id.as_deref(), Some("ABCD1234"));
    }

    // ── authenticate() tests ─────────────────────────────────────────

    /// Helper: send a text message from the tungstenite client side of a ws_pair.
    async fn client_send(
        client: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        text: &str,
    ) {
        use futures_util::SinkExt as _;
        use tokio_tungstenite::tungstenite::Message as TungMsg;
        client.send(TungMsg::Text(text.into())).await.expect("client send");
    }

    /// Helper: read a text message from the tungstenite client side.
    async fn client_recv(
        client: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) -> String {
        use futures_util::StreamExt as _;
        let msg = client.next().await.expect("should receive").expect("not error");
        msg.into_text().expect("text message").to_string()
    }

    #[tokio::test]
    async fn authenticate_correct_password_succeeds() {
        let server_verifier = test_verifier("correct-pw");

        let (mut server_ws, mut client_ws) = ws_pair().await;

        let auth_handle = tokio::spawn(async move {
            let rl = LoginRateLimiter::new();
            let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");
            authenticate(&mut server_ws, &server_verifier, &rl, ip).await
        });

        let register_msg = serde_json::json!({
            "Head": { "Type": "Register" },
            "Body": { "Password": "correct-pw" },
        });
        client_send(&mut client_ws, &register_msg.to_string()).await;

        let response_text = client_recv(&mut client_ws).await;
        let response: Value = serde_json::from_str(&response_text).expect("valid json");
        assert!(response["Body"]["Success"].as_bool().expect("bool"), "auth should succeed");

        let result = auth_handle.await.expect("join");
        assert!(result.is_ok(), "authenticate should return Ok");
    }

    #[tokio::test]
    async fn authenticate_wrong_password_fails() {
        let server_verifier = test_verifier("correct-pw");

        let (mut server_ws, mut client_ws) = ws_pair().await;

        let auth_handle = tokio::spawn(async move {
            let rl = LoginRateLimiter::new();
            let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");
            authenticate(&mut server_ws, &server_verifier, &rl, ip).await
        });

        let register_msg = serde_json::json!({
            "Head": { "Type": "Register" },
            "Body": { "Password": "wrong-pw" },
        });
        client_send(&mut client_ws, &register_msg.to_string()).await;

        let response_text = client_recv(&mut client_ws).await;
        let response: Value = serde_json::from_str(&response_text).expect("valid json");
        assert!(
            !response["Body"]["Success"].as_bool().expect("bool"),
            "auth should report failure"
        );

        let result = auth_handle.await.expect("join");
        assert!(result.is_err(), "authenticate should return Err");
        assert!(
            matches!(result.expect_err("expected Err"), ServiceBridgeError::AuthenticationFailed),
            "expected AuthenticationFailed error"
        );
    }

    #[tokio::test]
    async fn authenticate_malformed_json_fails() {
        let server_verifier = test_verifier("pw");

        let (mut server_ws, mut client_ws) = ws_pair().await;

        let auth_handle = tokio::spawn(async move {
            let rl = LoginRateLimiter::new();
            let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");
            authenticate(&mut server_ws, &server_verifier, &rl, ip).await
        });

        client_send(&mut client_ws, "this is not json!!!").await;

        let result = auth_handle.await.expect("join");
        assert!(result.is_err(), "malformed JSON should fail");
        assert!(
            matches!(result.expect_err("expected Err"), ServiceBridgeError::Json(_)),
            "expected Json parse error"
        );
    }

    #[tokio::test]
    async fn authenticate_non_register_head_type_fails() {
        let server_verifier = test_verifier("pw");

        let (mut server_ws, mut client_ws) = ws_pair().await;

        let auth_handle = tokio::spawn(async move {
            let rl = LoginRateLimiter::new();
            let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");
            authenticate(&mut server_ws, &server_verifier, &rl, ip).await
        });

        let message = serde_json::json!({
            "Head": { "Type": "Agent" },
            "Body": { "Password": "pw" },
        });
        client_send(&mut client_ws, &message.to_string()).await;

        let result = auth_handle.await.expect("join");
        assert!(result.is_err(), "non-Register type should fail");
        assert!(
            matches!(result.expect_err("expected Err"), ServiceBridgeError::AuthenticationFailed),
            "expected AuthenticationFailed error"
        );
    }

    #[tokio::test]
    async fn authenticate_missing_password_field_fails() {
        let server_verifier = test_verifier("secret");

        let (mut server_ws, mut client_ws) = ws_pair().await;

        let auth_handle = tokio::spawn(async move {
            let rl = LoginRateLimiter::new();
            let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");
            authenticate(&mut server_ws, &server_verifier, &rl, ip).await
        });

        let message = serde_json::json!({
            "Head": { "Type": "Register" },
            "Body": {},
        });
        client_send(&mut client_ws, &message.to_string()).await;

        // Missing Password defaults to empty string, which won't match "secret"
        let response_text = client_recv(&mut client_ws).await;
        let response: Value = serde_json::from_str(&response_text).expect("valid json");
        assert!(
            !response["Body"]["Success"].as_bool().expect("bool"),
            "missing password should fail auth"
        );

        let result = auth_handle.await.expect("join");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn authenticate_empty_password_matches_empty_config() {
        let server_verifier = test_verifier("");

        let (mut server_ws, mut client_ws) = ws_pair().await;

        let auth_handle = tokio::spawn(async move {
            let rl = LoginRateLimiter::new();
            let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");
            authenticate(&mut server_ws, &server_verifier, &rl, ip).await
        });

        let message = serde_json::json!({
            "Head": { "Type": "Register" },
            "Body": { "Password": "" },
        });
        client_send(&mut client_ws, &message.to_string()).await;

        let response_text = client_recv(&mut client_ws).await;
        let response: Value = serde_json::from_str(&response_text).expect("valid json");
        assert!(response["Body"]["Success"].as_bool().expect("bool"));

        let result = auth_handle.await.expect("join");
        assert!(result.is_ok());
    }

    // ── handle_agent_output tests ────────────────────────────────────

    #[tokio::test]
    async fn handle_agent_output_broadcasts_callback_as_agent_response() {
        let events = EventBus::default();
        let mut rx = events.subscribe();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
            "Body": {
                "Type": BODY_AGENT_OUTPUT,
                "AgentID": "CAFE0001",
                "Callback": { "Output": "command output here" },
            },
        });

        handle_agent_output(&message, &events).await.expect("agent output should succeed");

        let event = rx.recv().await.expect("event should be broadcast");
        match event {
            OperatorMessage::AgentResponse(msg) => {
                assert_eq!(msg.info.demon_id, "CAFE0001");
                assert_eq!(msg.head.user, "service");
                assert_eq!(msg.head.event, EventCode::Session);
                // Callback was a JSON object — it should be serialized into output.
                assert!(
                    msg.info.output.contains("command output here"),
                    "callback content should be forwarded, got: {}",
                    msg.info.output
                );
            }
            other => panic!("expected AgentResponse, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn handle_agent_output_string_callback_forwarded_verbatim() {
        let events = EventBus::default();
        let mut rx = events.subscribe();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
            "Body": {
                "Type": BODY_AGENT_OUTPUT,
                "AgentID": "BEEF0002",
                "Callback": "raw text output",
            },
        });

        handle_agent_output(&message, &events).await.expect("agent output should succeed");

        let event = rx.recv().await.expect("event should be broadcast");
        match event {
            OperatorMessage::AgentResponse(msg) => {
                assert_eq!(msg.info.demon_id, "BEEF0002");
                assert_eq!(msg.info.output, "raw text output");
            }
            other => panic!("expected AgentResponse, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn handle_agent_output_missing_body_returns_error() {
        let events = EventBus::default();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
        });

        let err =
            handle_agent_output(&message, &events).await.expect_err("should fail without Body");
        assert!(matches!(err, ServiceBridgeError::MissingField(ref f) if f.contains("Body")));
    }

    #[tokio::test]
    async fn handle_agent_output_missing_agent_id_uses_unknown() {
        let events = EventBus::default();
        let mut rx = events.subscribe();

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
            "Body": {
                "Type": BODY_AGENT_OUTPUT,
            },
        });

        handle_agent_output(&message, &events).await.expect("should succeed with defaults");

        let event = rx.recv().await.expect("event should be broadcast");
        match event {
            OperatorMessage::AgentResponse(msg) => {
                assert_eq!(msg.info.demon_id, "unknown");
                assert!(msg.info.output.is_empty(), "no callback means empty output");
            }
            other => panic!("expected AgentResponse, got: {other:?}"),
        }
    }

    // ── handle_agent_message dispatch tests ──────────────────────────

    #[tokio::test]
    async fn handle_agent_message_dispatches_agent_register() {
        let (db, wh) = test_audit_deps().await;
        let bridge = ServiceBridge::new(ServiceConfig {
            endpoint: "test".to_owned(),
            password: "pw".to_owned(),
        })
        .expect("service bridge");
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let registry = test_registry().await;

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
            "Body": {
                "Type": BODY_AGENT_REGISTER,
                "AgentHeader": {
                    "AgentID": "FF001122",
                    "MagicValue": "DEADBEEF",
                },
                "RegisterInfo": {
                    "Hostname": "DISPATCH-TEST",
                    "Username": "user1",
                },
            },
        });

        let (mut server_ws, _client_ws) = ws_pair().await;

        handle_agent_message(&message, &bridge, &events, &registry, &db, &wh, &mut server_ws)
            .await
            .expect("dispatch to AgentRegister should succeed");

        let agent = registry.get(0xFF00_1122).await.expect("agent should be registered");
        assert_eq!(agent.hostname, "DISPATCH-TEST");

        let event = rx.recv().await.expect("event should be broadcast");
        assert!(matches!(event, OperatorMessage::AgentNew(_)));
    }

    #[tokio::test]
    async fn handle_agent_message_dispatches_agent_response() {
        let (db, wh) = test_audit_deps().await;
        let bridge = ServiceBridge::new(ServiceConfig {
            endpoint: "test".to_owned(),
            password: "pw".to_owned(),
        })
        .expect("service bridge");
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let registry = test_registry().await;

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
            "Body": {
                "Type": BODY_AGENT_RESPONSE,
                "Agent": { "NameID": "DISPATCH01" },
                "Response": "dGVzdA==",
                "RandID": "dispatch-rand",
            },
        });

        let (mut server_ws, _client_ws) = ws_pair().await;

        handle_agent_message(&message, &bridge, &events, &registry, &db, &wh, &mut server_ws)
            .await
            .expect("dispatch to AgentResponse should succeed");

        let event = rx.recv().await.expect("event should be broadcast");
        match event {
            OperatorMessage::AgentResponse(msg) => {
                assert_eq!(msg.info.demon_id, "DISPATCH01");
                assert_eq!(msg.info.command_id, "dispatch-rand");
            }
            other => panic!("expected AgentResponse, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn handle_agent_message_dispatches_agent_output() {
        let (db, wh) = test_audit_deps().await;
        let bridge = ServiceBridge::new(ServiceConfig {
            endpoint: "test".to_owned(),
            password: "pw".to_owned(),
        })
        .expect("service bridge");
        let events = EventBus::default();
        let mut rx = events.subscribe();
        let registry = test_registry().await;

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
            "Body": {
                "Type": BODY_AGENT_OUTPUT,
                "AgentID": "OUTPUT01",
                "Callback": { "Output": "hello" },
            },
        });

        let (mut server_ws, _client_ws) = ws_pair().await;

        handle_agent_message(&message, &bridge, &events, &registry, &db, &wh, &mut server_ws)
            .await
            .expect("dispatch to AgentOutput should succeed");

        let event = rx.recv().await.expect("event should be broadcast");
        match event {
            OperatorMessage::AgentResponse(msg) => {
                assert_eq!(msg.info.demon_id, "OUTPUT01");
                assert!(msg.info.output.contains("hello"));
            }
            other => panic!("expected AgentResponse, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn handle_agent_message_unknown_body_type_returns_ok() {
        let (db, wh) = test_audit_deps().await;
        let bridge = ServiceBridge::new(ServiceConfig {
            endpoint: "test".to_owned(),
            password: "pw".to_owned(),
        })
        .expect("service bridge");
        let events = EventBus::default();
        let registry = test_registry().await;

        let message = serde_json::json!({
            "Head": { "Type": HEAD_AGENT },
            "Body": {
                "Type": "SomethingCompletelyUnknown",
            },
        });

        let (mut server_ws, _client_ws) = ws_pair().await;

        let result =
            handle_agent_message(&message, &bridge, &events, &registry, &db, &wh, &mut server_ws)
                .await;
        assert!(result.is_ok(), "unknown agent body type should be silently ignored");
    }

    #[tokio::test]
    async fn authenticate_rate_limits_after_max_failures() {
        let server_verifier = test_verifier("correct-pw");
        let rate_limiter = LoginRateLimiter::new();
        let ip: IpAddr = "10.0.0.99".parse().expect("valid IP");

        // Exhaust the rate limiter for this IP (5 failures).
        for _ in 0..5 {
            rate_limiter.record_failure(ip).await;
        }

        // The next attempt should be rate-limited without even reading a message.
        let (mut server_ws, _client_ws) = ws_pair().await;
        let result = authenticate(&mut server_ws, &server_verifier, &rate_limiter, ip).await;
        assert!(result.is_err(), "should be rate limited");
        assert!(
            matches!(result.expect_err("expected Err"), ServiceBridgeError::RateLimited),
            "expected RateLimited error"
        );
    }

    #[tokio::test]
    async fn authenticate_allows_different_ip_when_one_is_limited() {
        let server_verifier = test_verifier("correct-pw");
        let rate_limiter = LoginRateLimiter::new();
        let blocked_ip: IpAddr = "10.0.0.100".parse().expect("valid IP");
        let allowed_ip: IpAddr = "10.0.0.101".parse().expect("valid IP");

        // Exhaust the rate limiter for blocked_ip.
        for _ in 0..5 {
            rate_limiter.record_failure(blocked_ip).await;
        }

        // blocked_ip should be rejected.
        let (mut server_ws, _client_ws) = ws_pair().await;
        let result =
            authenticate(&mut server_ws, &server_verifier, &rate_limiter, blocked_ip).await;
        assert!(matches!(result.expect_err("expected Err"), ServiceBridgeError::RateLimited));

        // allowed_ip should still work (correct password).
        let (mut server_ws2, mut client_ws2) = ws_pair().await;
        let rl = rate_limiter.clone();
        let hash = server_verifier.clone();
        let auth_handle =
            tokio::spawn(
                async move { authenticate(&mut server_ws2, &hash, &rl, allowed_ip).await },
            );

        let msg = serde_json::json!({
            "Head": { "Type": "Register" },
            "Body": { "Password": "correct-pw" },
        });
        client_send(&mut client_ws2, &msg.to_string()).await;
        let _ = client_recv(&mut client_ws2).await;

        let result = auth_handle.await.expect("join");
        assert!(result.is_ok(), "unblocked IP should authenticate successfully");
    }

    #[tokio::test]
    async fn authenticate_times_out_when_no_frame_sent() {
        let server_verifier = test_verifier("correct-pw");
        let rate_limiter = LoginRateLimiter::new();
        let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");

        let (mut server_ws, _client_ws) = ws_pair().await;

        // Hold `_client_ws` open but never send anything — the server side
        // should time out after SERVICE_AUTH_FRAME_TIMEOUT.
        let start = tokio::time::Instant::now();
        let result = authenticate(&mut server_ws, &server_verifier, &rate_limiter, ip).await;
        let elapsed = start.elapsed();

        assert!(
            matches!(result, Err(ServiceBridgeError::AuthenticationTimeout)),
            "expected AuthenticationTimeout, got {result:?}"
        );
        // Should complete within a reasonable margin of the timeout.
        assert!(
            elapsed < auth::SERVICE_AUTH_FRAME_TIMEOUT + Duration::from_secs(2),
            "took too long: {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn authenticate_binary_frame_returns_auth_failed() {
        let server_verifier = test_verifier("pw");

        let (mut server_ws, mut client_ws) = ws_pair().await;

        let auth_handle = tokio::spawn(async move {
            let rl = LoginRateLimiter::new();
            let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");
            authenticate(&mut server_ws, &server_verifier, &rl, ip).await
        });

        // Send a binary frame instead of a text frame.
        {
            use futures_util::SinkExt as _;
            use tokio_tungstenite::tungstenite::Message as TungMsg;
            client_ws
                .send(TungMsg::Binary(vec![0xDE, 0xAD, 0xBE, 0xEF].into()))
                .await
                .expect("client send binary");
        }

        let result = auth_handle.await.expect("join");
        assert!(result.is_err(), "binary frame should fail auth");
        assert!(
            matches!(result.expect_err("expected Err"), ServiceBridgeError::AuthenticationFailed),
            "expected AuthenticationFailed for binary frame"
        );
    }

    #[tokio::test]
    async fn authenticate_close_frame_returns_auth_failed() {
        let server_verifier = test_verifier("pw");

        let (mut server_ws, mut client_ws) = ws_pair().await;

        let auth_handle = tokio::spawn(async move {
            let rl = LoginRateLimiter::new();
            let ip: IpAddr = "127.0.0.1".parse().expect("valid IP");
            authenticate(&mut server_ws, &server_verifier, &rl, ip).await
        });

        // Send a close frame instead of a text frame.
        {
            use futures_util::SinkExt as _;
            use tokio_tungstenite::tungstenite::Message as TungMsg;
            client_ws.send(TungMsg::Close(None)).await.expect("client send close");
        }

        let result = auth_handle.await.expect("join");
        assert!(result.is_err(), "close frame should fail auth");
        assert!(
            matches!(result.expect_err("expected Err"), ServiceBridgeError::AuthenticationFailed),
            "expected AuthenticationFailed for close frame"
        );
    }

    // ── service_routes wiring tests ─────────────────────────────────

    /// Build a minimal `TeamserverState` with the given `ServiceBridge` attached.
    async fn test_state_with_bridge(bridge: ServiceBridge) -> crate::TeamserverState {
        use red_cell_common::config::Profile;

        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 0
            }

            Operators {
              user "op" {
                Password = "pw1234"
                Role = "Operator"
              }
            }

            Demon {}
            "#,
        )
        .expect("test profile should parse");
        let database = crate::database::Database::connect_in_memory()
            .await
            .expect("in-memory database should initialize");
        let agent_registry = crate::AgentRegistry::new(database.clone());
        let events = crate::EventBus::new(8);
        let sockets = crate::SocketRelayManager::new(agent_registry.clone(), events.clone());
        crate::TeamserverState {
            profile: profile.clone(),
            database: database.clone(),
            auth: crate::AuthService::from_profile(&profile)
                .expect("auth service should initialize"),
            api: crate::ApiRuntime::from_profile(&profile).expect("rng should work in tests"),
            events: events.clone(),
            connections: crate::OperatorConnectionManager::new(),
            agent_registry: agent_registry.clone(),
            listeners: crate::ListenerManager::new(
                database,
                agent_registry,
                events,
                sockets.clone(),
                None,
            )
            .with_demon_allow_legacy_ctr(true),
            payload_builder: crate::PayloadBuilderService::disabled_for_tests(),
            sockets,
            webhooks: crate::AuditWebhookNotifier::from_profile(&profile),
            login_rate_limiter: LoginRateLimiter::new(),
            shutdown: crate::ShutdownController::new(),
            service_bridge: Some(bridge),
            started_at: std::time::Instant::now(),
            plugins_loaded: 0,
            plugins_failed: 0,
            metrics: crate::metrics::standalone_metrics_handle(),
        }
    }

    #[tokio::test]
    async fn service_routes_registers_get_endpoint() {
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt as _;

        let bridge = ServiceBridge::new(ServiceConfig {
            endpoint: "svc-bridge".to_owned(),
            password: "pw".to_owned(),
        })
        .expect("service bridge");

        let state = test_state_with_bridge(bridge.clone()).await;
        let app = service_routes(&bridge).with_state(state);

        let response = app
            .oneshot(Request::get("/svc-bridge").body(String::new()).expect("request"))
            .await
            .expect("router should respond");

        // The route is registered; without WebSocket upgrade headers the extractor
        // rejects the request, but the status must NOT be 404 (unmounted) or
        // 405 (wrong method).
        assert_ne!(response.status(), StatusCode::NOT_FOUND, "GET /svc-bridge should be mounted");
        assert_ne!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "GET should be the accepted method"
        );
    }

    #[tokio::test]
    async fn service_routes_rejects_post_with_method_not_allowed() {
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt as _;

        let bridge = ServiceBridge::new(ServiceConfig {
            endpoint: "svc-bridge".to_owned(),
            password: "pw".to_owned(),
        })
        .expect("service bridge");

        let state = test_state_with_bridge(bridge.clone()).await;
        let app = service_routes(&bridge).with_state(state);

        let response = app
            .oneshot(Request::post("/svc-bridge").body(String::new()).expect("request"))
            .await
            .expect("router should respond");

        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "POST to the service endpoint should be rejected"
        );
    }

    #[tokio::test]
    async fn service_routes_returns_404_for_unregistered_path() {
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt as _;

        let bridge = ServiceBridge::new(ServiceConfig {
            endpoint: "svc-bridge".to_owned(),
            password: "pw".to_owned(),
        })
        .expect("service bridge");

        let state = test_state_with_bridge(bridge.clone()).await;
        let app = service_routes(&bridge).with_state(state);

        let response = app
            .oneshot(Request::get("/other-path").body(String::new()).expect("request"))
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::NOT_FOUND, "unregistered path should return 404");
    }

    #[tokio::test]
    async fn service_routes_normalizes_leading_slash() {
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt as _;

        // Endpoint configured without a leading slash — service_routes should
        // still mount it at exactly "/<endpoint>" (one slash, no double-slash).
        let bridge = ServiceBridge::new(ServiceConfig {
            endpoint: "no-leading-slash".to_owned(),
            password: "pw".to_owned(),
        })
        .expect("service bridge");

        let state = test_state_with_bridge(bridge.clone()).await;
        let app = service_routes(&bridge).with_state(state);

        let response = app
            .oneshot(Request::get("/no-leading-slash").body(String::new()).expect("request"))
            .await
            .expect("router should respond");

        assert_ne!(
            response.status(),
            StatusCode::NOT_FOUND,
            "endpoint should be reachable at /no-leading-slash"
        );

        // Double-slash variant should NOT match.
        let bridge2 = ServiceBridge::new(ServiceConfig {
            endpoint: "no-leading-slash".to_owned(),
            password: "pw".to_owned(),
        })
        .expect("service bridge");
        let state2 = test_state_with_bridge(bridge2.clone()).await;
        let app2 = service_routes(&bridge2).with_state(state2);

        let response2 = app2
            .oneshot(Request::get("//no-leading-slash").body(String::new()).expect("request"))
            .await
            .expect("router should respond");

        assert_eq!(
            response2.status(),
            StatusCode::NOT_FOUND,
            "double-slash path should not match the endpoint"
        );
    }
}
