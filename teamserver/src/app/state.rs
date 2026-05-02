//! Application state container and Axum [`FromRef`] extractors.

use std::path::PathBuf;
use std::time::Instant;

use axum::extract::FromRef;
use red_cell_common::config::Profile;

use crate::{
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, LoginRateLimiter, MetricsHandle, OperatorConnectionManager,
    PayloadBuilderService, ServiceBridge, ShutdownController, SocketRelayManager,
};

/// Shared state injected into Axum routes and middleware.
#[derive(Debug, Clone)]
pub struct TeamserverState {
    /// Loaded Havoc-compatible profile.
    pub profile: Profile,
    /// Filesystem path of the loaded profile (for diagnostic display).
    pub profile_path: String,
    /// SQLite-backed persistence services.
    pub database: Database,
    /// Operator WebSocket/session authentication.
    pub auth: AuthService,
    /// REST API authentication and rate limiting.
    pub api: ApiRuntime,
    /// Internal event fan-out bus.
    pub events: EventBus,
    /// Active operator WebSocket connections.
    pub connections: OperatorConnectionManager,
    /// In-memory agent registry.
    pub agent_registry: AgentRegistry,
    /// Listener lifecycle management.
    pub listeners: ListenerManager,
    /// Demon payload compilation service.
    pub payload_builder: PayloadBuilderService,
    /// Pivot socket relay manager.
    pub sockets: SocketRelayManager,
    /// Outbound audit webhook dispatcher.
    pub webhooks: AuditWebhookNotifier,
    /// WebSocket login rate limiter.
    pub login_rate_limiter: LoginRateLimiter,
    /// Coordinated graceful-shutdown controller.
    pub shutdown: ShutdownController,
    /// Optional service bridge for external tool integration.
    pub service_bridge: Option<ServiceBridge>,
    /// Instant at which the teamserver was started, used to compute uptime.
    pub started_at: Instant,
    /// Number of Python plugins successfully loaded at startup.
    pub plugins_loaded: u32,
    /// Number of Python plugins that failed to load at startup.
    pub plugins_failed: u32,
    /// Prometheus metrics exporter handle.
    pub metrics: MetricsHandle,
    /// Root corpus directory set by `--capture-corpus`.
    ///
    /// `None` in normal operation.  When `Some`, the `/debug/corpus-keys`
    /// endpoint is active and every HTTP listener writes packet corpus files.
    pub corpus_dir: Option<PathBuf>,
}

impl FromRef<TeamserverState> for AuthService {
    fn from_ref(input: &TeamserverState) -> Self {
        input.auth.clone()
    }
}

impl FromRef<TeamserverState> for ApiRuntime {
    fn from_ref(input: &TeamserverState) -> Self {
        input.api.clone()
    }
}

impl FromRef<TeamserverState> for Database {
    fn from_ref(input: &TeamserverState) -> Self {
        input.database.clone()
    }
}

impl FromRef<TeamserverState> for EventBus {
    fn from_ref(input: &TeamserverState) -> Self {
        input.events.clone()
    }
}

impl FromRef<TeamserverState> for OperatorConnectionManager {
    fn from_ref(input: &TeamserverState) -> Self {
        input.connections.clone()
    }
}

impl FromRef<TeamserverState> for ListenerManager {
    fn from_ref(input: &TeamserverState) -> Self {
        input.listeners.clone()
    }
}

impl FromRef<TeamserverState> for PayloadBuilderService {
    fn from_ref(input: &TeamserverState) -> Self {
        input.payload_builder.clone()
    }
}

impl FromRef<TeamserverState> for AgentRegistry {
    fn from_ref(input: &TeamserverState) -> Self {
        input.agent_registry.clone()
    }
}

impl FromRef<TeamserverState> for SocketRelayManager {
    fn from_ref(input: &TeamserverState) -> Self {
        input.sockets.clone()
    }
}

impl FromRef<TeamserverState> for AuditWebhookNotifier {
    fn from_ref(input: &TeamserverState) -> Self {
        input.webhooks.clone()
    }
}

impl FromRef<TeamserverState> for LoginRateLimiter {
    fn from_ref(input: &TeamserverState) -> Self {
        input.login_rate_limiter.clone()
    }
}

impl FromRef<TeamserverState> for ShutdownController {
    fn from_ref(input: &TeamserverState) -> Self {
        input.shutdown.clone()
    }
}

impl FromRef<TeamserverState> for MetricsHandle {
    fn from_ref(input: &TeamserverState) -> Self {
        input.metrics.clone()
    }
}
