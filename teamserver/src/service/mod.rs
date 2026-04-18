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

mod agent;
mod auth;
mod listeners;
mod logging;

use agent::{handle_agent_message, handle_register_agent};
use auth::authenticate;
use listeners::handle_listener_message;
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
use serde_json::Value;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use crate::audit::{AuditResultStatus, audit_details};
use crate::auth::{AuthError, password_verifier_for_sha3};
use crate::database::TeamserverError;
use crate::{AgentRegistry, AuditWebhookNotifier, Database, EventBus, LoginRateLimiter};

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

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
