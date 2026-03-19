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

    async fn build_test_state() -> TeamserverState {
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
        TeamserverState {
            profile: profile.clone(),
            database: database.clone(),
            auth: AuthService::from_profile(&profile).expect("auth service should initialize"),
            api: ApiRuntime::from_profile(&profile).expect("rng should work in tests"),
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
        }
    }

    #[tokio::test]
    async fn operator_port_fallback_returns_empty_not_found() {
        let state = build_test_state().await;

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

    /// POST, PUT, and DELETE requests to unknown paths must also reach the
    /// `any()` fallback and return 404 NOT_FOUND with an empty body — not 405
    /// Method Not Allowed.  A regression replacing `any()` with `get()` would
    /// break agent POST requests.
    #[tokio::test]
    async fn fallback_handles_post_put_delete_not_just_get() {
        use axum::http::Method;

        let state = build_test_state().await;
        let router = build_router(state);

        for method in [Method::POST, Method::PUT, Method::DELETE] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(&method)
                        .uri("/missing")
                        .body(Body::empty())
                        .expect("request should build"),
                )
                .await
                .expect("router should respond");

            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "{method} /missing should return 404, not {}",
                response.status()
            );
            let body = to_bytes(response.into_body(), usize::MAX).await.expect("body should read");
            assert!(body.is_empty(), "{method} /missing should return an empty body");
        }
    }

    /// GET /api/v1 (the info root, which has no auth middleware) must return 200 OK.
    /// If the nest("/api/v1", …) call were misconfigured the request would fall
    /// through to the 404 fallback handler instead.
    #[tokio::test]
    async fn api_v1_prefix_is_routed_not_404() {
        let state = build_test_state().await;

        // Axum 0.8 does not add automatic trailing-slash redirects; the route is
        // registered at "/api/v1" (no trailing slash) by api_routes.
        let response = build_router(state)
            .oneshot(
                Request::builder()
                    .uri("/api/v1")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        // The /api/v1 info endpoint is outside the protected layer, so it
        // returns 200 OK without any API key.
        assert_ne!(
            response.status(),
            StatusCode::NOT_FOUND,
            "/api/v1 must be routed by api_routes, not fall through to the 404 fallback"
        );
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// GET /api/v1/nonexistent must reach the JSON not-found handler installed
    /// by `api_routes`, not the plain empty-body fallback installed on the root
    /// router.  The body must contain `{"error": {"code": "not_found", …}}`.
    #[tokio::test]
    async fn api_v1_unknown_sub_path_returns_json_not_found() {
        let state = build_test_state().await;

        let response = build_router(state)
            .oneshot(
                Request::builder()
                    .uri("/api/v1/nonexistent")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = to_bytes(response.into_body(), usize::MAX).await.expect("body should read");
        assert!(!body.is_empty(), "/api/v1/nonexistent must return a JSON body, not an empty 404");

        let json: serde_json::Value =
            serde_json::from_slice(&body).expect("body should be valid JSON");
        assert_eq!(
            json["error"]["code"], "not_found",
            "expected JSON error code 'not_found' from api_routes fallback"
        );
    }

    /// GET /havoc without WebSocket upgrade headers must reach the WebSocket
    /// handler and be rejected by axum's WebSocketUpgrade extractor rather than
    /// falling through to the 404 fallback.
    #[tokio::test]
    async fn havoc_prefix_is_routed_not_404() {
        let state = build_test_state().await;

        // A plain GET with no `Upgrade: websocket` header causes the
        // WebSocketUpgrade extractor to reject the request.  The exact status
        // code depends on which extractor runs first (ConnectInfo vs
        // WebSocketUpgrade), but any non-404 response confirms that the
        // nest("/havoc", …) wiring is correct.
        let response = build_router(state)
            .oneshot(
                Request::builder().uri("/havoc").body(Body::empty()).expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_ne!(
            response.status(),
            StatusCode::NOT_FOUND,
            "/havoc must be routed by websocket_routes, not fall through to the 404 fallback"
        );
    }
}
