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
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, LoginRateLimiter, OperatorConnectionManager, PayloadBuilderService,
    ShutdownController, SocketRelayManager, api_routes, websocket_routes,
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
    /// Outbound audit webhook dispatcher.
    pub webhooks: AuditWebhookNotifier,
    /// WebSocket login rate limiter.
    pub login_rate_limiter: LoginRateLimiter,
    /// Coordinated graceful-shutdown controller.
    pub shutdown: ShutdownController,
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

/// Build the main teamserver router used by the binary and integration tests.
pub fn build_router(state: TeamserverState) -> Router {
    let api = state.api.clone();

    Router::new()
        .nest("/havoc", websocket_routes())
        .nest("/api/v1", api_routes(api))
        .fallback(any(agent_listener_placeholder))
        .with_state(state)
}

async fn agent_listener_placeholder(request: Request<Body>) -> impl IntoResponse {
    tracing::debug!(
        method = %request.method(),
        path = %request.uri().path(),
        "teamserver operator port fallback hit"
    );

    StatusCode::NOT_FOUND
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use tower::ServiceExt;

    use crate::{
        AgentRegistry, AuditWebhookNotifier, AuthService, Database, EventBus, ListenerManager,
        LoginRateLimiter, OperatorConnectionManager, PayloadBuilderService, ShutdownController,
        SocketRelayManager,
    };

    #[tokio::test]
    async fn operator_port_fallback_returns_empty_not_found() {
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
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");
        let database = Database::connect_in_memory().await.expect("database should initialize");
        let agent_registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(agent_registry.clone(), events.clone());
        let state = TeamserverState {
            profile: profile.clone(),
            database: database.clone(),
            auth: AuthService::from_profile(&profile).expect("auth service should initialize"),
            api: ApiRuntime::from_profile(&profile),
            events: events.clone(),
            connections: OperatorConnectionManager::new(),
            agent_registry: agent_registry.clone(),
            listeners: ListenerManager::new(
                database,
                agent_registry,
                events,
                sockets.clone(),
                None,
            ),
            payload_builder: PayloadBuilderService::disabled_for_tests(),
            sockets,
            webhooks: AuditWebhookNotifier::from_profile(&profile),
            login_rate_limiter: LoginRateLimiter::new(),
            shutdown: ShutdownController::new(),
        };

        let response = build_router(state)
            .oneshot(
                Request::builder()
                    .uri("/missing")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(response.into_body(), usize::MAX).await.expect("body should read");
        assert!(body.is_empty());
    }
}
