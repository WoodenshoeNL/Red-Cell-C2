//! Shared application state for the Red Cell teamserver.

use axum::extract::FromRef;
use red_cell_common::config::Profile;

use crate::{
    AgentRegistry, ApiRuntime, AuthService, Database, EventBus, ListenerManager,
    OperatorConnectionManager, SocketRelayManager,
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
    /// Pivot socket relay manager.
    pub sockets: SocketRelayManager,
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
