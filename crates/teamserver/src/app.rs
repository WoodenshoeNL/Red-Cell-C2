//! Shared application state for the Red Cell teamserver.

use axum::{
    Router,
    body::Body,
    extract::FromRef,
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::any,
};
use red_cell_common::config::Profile;

use crate::{
    AgentRegistry, ApiRuntime, AuthService, Database, EventBus, ListenerManager, LoginRateLimiter,
    OperatorConnectionManager, PayloadBuilderService, SocketRelayManager, api_routes,
    websocket_routes,
};

/// Shared state injected into Axum routes and middleware.
#[derive(Debug, Clone)]
pub struct TeamserverState {
    /// Loaded Havoc-compatible profile.
    pub profile: Profile,
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
    /// WebSocket login rate limiter.
    pub login_rate_limiter: LoginRateLimiter,
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

impl FromRef<TeamserverState> for LoginRateLimiter {
    fn from_ref(input: &TeamserverState) -> Self {
        input.login_rate_limiter.clone()
    }
}

/// Build the main teamserver router used by the binary and integration tests.
pub fn build_router(state: TeamserverState) -> Router {
    let api = state.api.clone();

    Router::new()
        .nest("/havoc", websocket_routes())
        .nest("/api/v1", api_routes(api))
        .fallback(any(agent_listener_placeholder))
        .with_state(state)
}

async fn agent_listener_placeholder(
    axum::extract::State(state): axum::extract::State<TeamserverState>,
    request: Request<Body>,
) -> impl IntoResponse {
    tracing::debug!(
        method = %request.method(),
        path = %request.uri().path(),
        secure_listener_count = state
            .profile
            .listeners
            .http
            .iter()
            .filter(|listener| listener.secure)
            .count(),
        "agent listener placeholder hit"
    );

    (StatusCode::NOT_IMPLEMENTED, "agent listener endpoint not implemented yet")
}
