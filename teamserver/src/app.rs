//! Shared application state for the Red Cell teamserver.

use std::net::SocketAddr;

use axum::{
    Router,
    body::{Body, Bytes},
    extract::{ConnectInfo, FromRef, State},
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::{any, get},
};
use red_cell_common::config::Profile;

use crate::{
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, LoginRateLimiter, MAX_AGENT_MESSAGE_LEN, OperatorConnectionManager,
    PayloadBuilderService, ServiceBridge, ShutdownController, SocketRelayManager, api_routes,
    handle_external_request, listeners::collect_body_with_magic_precheck, service_routes,
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
    /// Optional service bridge for external tool integration.
    pub service_bridge: Option<ServiceBridge>,
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

    let mut router = Router::new()
        .route("/havoc", get(crate::websocket_handler::<TeamserverState>))
        .nest("/api/v1", api_routes(api));

    if let Some(ref bridge) = state.service_bridge {
        router = router.merge(service_routes(bridge));
    }

    router.fallback(any(teamserver_fallback)).with_state(state)
}

async fn teamserver_fallback(
    State(state): State<TeamserverState>,
    request: Request<Body>,
) -> impl IntoResponse {
    let path = request.uri().path().to_owned();

    // Check if an active External listener owns this path.
    if let Some(ext_state) = state.listeners.external_state_for_path(&path).await {
        // Acquire the shutdown callback guard *before* body collection so this
        // request is tracked for the full duration of the external bridge path.
        // Without this, `run_shutdown_sequence` could decide the callback drain
        // is complete while body I/O is still in progress, closing the database
        // underneath the subsequent `handle_external_request` call.
        let Some(_fallback_guard) = ext_state.try_track_callback() else {
            return StatusCode::NOT_FOUND.into_response();
        };

        let peer = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)), |info| info.0);

        let body = match collect_body_with_magic_precheck(
            request.into_body(),
            MAX_AGENT_MESSAGE_LEN,
        )
        .await
        {
            Some(bytes) => bytes,
            // Return a camouflage 404 — do not expose the size limit or bad magic as a 400.
            None => return StatusCode::NOT_FOUND.into_response(),
        };

        match handle_external_request(&ext_state, peer, &body).await {
            Ok(payload) => (StatusCode::OK, Bytes::from(payload)).into_response(),
            Err(status) => status.into_response(),
        }
    } else {
        tracing::debug!(
            method = %request.method(),
            path = %path,
            "teamserver operator port fallback hit"
        );
        StatusCode::NOT_FOUND.into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use tower::ServiceExt;

    use crate::{
        AgentRegistry, AuditWebhookNotifier, AuthService, Database, EventBus, ListenerManager,
        LoginRateLimiter, MAX_AGENT_MESSAGE_LEN, OperatorConnectionManager, PayloadBuilderService,
        ShutdownController, SocketRelayManager,
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
            service_bridge: None,
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

    /// POST, PUT, DELETE, and HEAD requests to unknown paths must also reach
    /// the `any()` fallback and return 404 NOT_FOUND with an empty body — not
    /// 405 Method Not Allowed.  A regression replacing `any()` with `get()`
    /// would break agent POST requests.
    #[tokio::test]
    async fn fallback_handles_all_methods_not_just_get() {
        use axum::http::Method;

        let state = build_test_state().await;
        let router = build_router(state);

        for method in [Method::POST, Method::PUT, Method::DELETE, Method::HEAD] {
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

    /// Verify that `/havoc/` (with trailing slash) routes correctly when
    /// `NormalizePathLayer` is applied as an outer tower service wrapper,
    /// matching the production `main.rs` setup via `NormalizedMakeService`.
    #[tokio::test]
    async fn havoc_trailing_slash_routed_with_normalize_path_layer() {
        use tower::{Layer, ServiceExt as _};
        use tower_http::normalize_path::NormalizePathLayer;

        let state = build_test_state().await;
        // Apply NormalizePathLayer as an outer service wrapper (NOT via
        // Router::layer) so that the URI is rewritten before routing.
        let svc = NormalizePathLayer::trim_trailing_slash().layer(build_router(state));

        let response = svc
            .oneshot(
                Request::builder()
                    .uri("/havoc/")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_ne!(
            response.status(),
            StatusCode::NOT_FOUND,
            "/havoc/ must NOT 404 when NormalizePathLayer normalizes the trailing slash"
        );
    }

    /// Verify that `/api/v1/` (with trailing slash) routes correctly when
    /// `NormalizePathLayer` is applied, matching the production setup.
    #[tokio::test]
    async fn api_v1_trailing_slash_routed_with_normalize_path_layer() {
        use tower::{Layer, ServiceExt as _};
        use tower_http::normalize_path::NormalizePathLayer;

        let state = build_test_state().await;
        let svc = NormalizePathLayer::trim_trailing_slash().layer(build_router(state));

        let response = svc
            .oneshot(
                Request::builder()
                    .uri("/api/v1/")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_ne!(
            response.status(),
            StatusCode::NOT_FOUND,
            "/api/v1/ must NOT 404 when NormalizePathLayer normalizes the trailing slash"
        );
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Build a valid Demon init packet for use in external listener tests.
    ///
    /// Returns the raw bytes of a `DemonEnvelope` containing an init payload
    /// with the given agent id, AES key, and AES IV.
    fn build_demon_init_packet(agent_id: u32, key: [u8; 32], iv: [u8; 16]) -> Vec<u8> {
        use red_cell_common::crypto::encrypt_agent_data;
        use red_cell_common::demon::{DemonCommand, DemonEnvelope};

        fn add_len_prefixed(buf: &mut Vec<u8>, data: &[u8]) {
            buf.extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
            buf.extend_from_slice(data);
        }

        fn add_len_prefixed_utf16(buf: &mut Vec<u8>, s: &str) {
            let utf16: Vec<u16> = s.encode_utf16().collect();
            let byte_len = utf16.len() * 2;
            buf.extend_from_slice(&u32::try_from(byte_len).unwrap().to_be_bytes());
            for code_unit in &utf16 {
                buf.extend_from_slice(&code_unit.to_le_bytes());
            }
        }

        let mut metadata = Vec::new();
        metadata.extend_from_slice(&agent_id.to_be_bytes());
        add_len_prefixed(&mut metadata, b"wkstn-01");
        add_len_prefixed(&mut metadata, b"operator");
        add_len_prefixed(&mut metadata, b"REDCELL");
        add_len_prefixed(&mut metadata, b"10.0.0.25");
        add_len_prefixed_utf16(&mut metadata, "C:\\Windows\\explorer.exe");
        metadata.extend_from_slice(&1337_u32.to_be_bytes()); // pid
        metadata.extend_from_slice(&1338_u32.to_be_bytes()); // tid
        metadata.extend_from_slice(&512_u32.to_be_bytes()); // ppid
        metadata.extend_from_slice(&2_u32.to_be_bytes()); // arch
        metadata.extend_from_slice(&1_u32.to_be_bytes()); // elevated
        metadata.extend_from_slice(&0x401000_u64.to_be_bytes()); // base_address
        metadata.extend_from_slice(&10_u32.to_be_bytes()); // os_major
        metadata.extend_from_slice(&0_u32.to_be_bytes()); // os_minor
        metadata.extend_from_slice(&1_u32.to_be_bytes()); // os_product_type
        metadata.extend_from_slice(&0_u32.to_be_bytes()); // os_service_pack
        metadata.extend_from_slice(&22000_u32.to_be_bytes()); // os_build
        metadata.extend_from_slice(&9_u32.to_be_bytes()); // os_arch
        metadata.extend_from_slice(&15_u32.to_be_bytes()); // sleep_delay
        metadata.extend_from_slice(&20_u32.to_be_bytes()); // sleep_jitter
        metadata.extend_from_slice(&1_893_456_000_u64.to_be_bytes()); // kill_date
        metadata.extend_from_slice(&0b101010_u32.to_be_bytes()); // working_hours

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
            .expect("failed to build demon init envelope")
            .to_bytes()
    }

    /// When an External listener is registered and running, requests to its
    /// endpoint path must be routed through `handle_external_request` — not
    /// fall through to the 404 branch.  A valid Demon init packet should
    /// produce a 200 OK with a non-empty response payload (the init ACK).
    #[tokio::test]
    async fn fallback_routes_to_external_listener_path() {
        use red_cell_common::ExternalListenerConfig;

        let state = build_test_state().await;

        // Register and start an external listener on "/bridge".
        let config = red_cell_common::ListenerConfig::from(ExternalListenerConfig {
            name: "ext-test".to_owned(),
            endpoint: "/bridge".to_owned(),
        });
        state.listeners.create(config).await.expect("create should succeed");
        state.listeners.start("ext-test").await.expect("start should succeed");

        // Confirm endpoint is registered before sending the request.
        let ext = state
            .listeners
            .external_state_for_path("/bridge")
            .await
            .expect("external endpoint should be registered");
        assert_eq!(ext.listener_name(), "ext-test");

        // Build a valid Demon init packet.
        // Key and IV must NOT be single-byte repeating patterns (e.g. [0xAA; 32])
        // because the parser rejects degenerate key material via `is_weak_aes_key`.
        let key: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        let iv: [u8; 16] = [
            0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E,
            0x8F, 0x90,
        ];
        let init_body = build_demon_init_packet(0xCAFE_0001, key, iv);

        let response = build_router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/bridge")
                    .body(Body::from(init_body))
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "valid Demon init to external listener path should return 200 OK"
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.expect("body should read");
        assert!(
            !body.is_empty(),
            "200 OK response from external listener init should contain an ACK payload"
        );
    }

    /// When `service_bridge` is `Some`, `build_router` must merge the service
    /// routes so that the service endpoint path is routable (not 404).  This
    /// exercises the `if let Some(ref bridge) = state.service_bridge` branch
    /// that is otherwise never hit by tests using `service_bridge: None`.
    #[tokio::test]
    async fn build_router_with_service_bridge_routes_service_endpoint() {
        use red_cell_common::config::ServiceConfig;

        let mut state = build_test_state().await;
        let bridge = crate::ServiceBridge::new(ServiceConfig {
            endpoint: "service-ws".to_owned(),
            password: "test-password".to_owned(),
        })
        .expect("service bridge");
        state.service_bridge = Some(bridge);

        let response = build_router(state)
            .oneshot(
                Request::builder()
                    .uri("/service-ws")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        // The service endpoint expects a WebSocket upgrade, so a plain GET
        // without upgrade headers will be rejected — but critically it must
        // NOT return 404, which would indicate the route was never merged.
        assert_ne!(
            response.status(),
            StatusCode::NOT_FOUND,
            "/service-ws must be routed by service_routes when service_bridge is Some, not fall through to 404"
        );
    }

    /// An oversized request body on an external listener path must be silently
    /// rejected with a camouflage 404 — not a 400 BAD_REQUEST that would
    /// fingerprint the endpoint as a C2 bridge.  The limit is aligned with
    /// `MAX_AGENT_MESSAGE_LEN` (30 MiB) used by every other listener path.
    #[tokio::test]
    async fn fallback_rejects_oversized_body_for_external_listener() {
        use red_cell_common::ExternalListenerConfig;

        let state = build_test_state().await;

        // Register and start an external listener so the body-size branch is
        // reachable (without an external listener the request would 404 before
        // the body is ever read).
        let config = red_cell_common::ListenerConfig::from(ExternalListenerConfig {
            name: "ext-big".to_owned(),
            endpoint: "/bigbody".to_owned(),
        });
        state.listeners.create(config).await.expect("create should succeed");
        state.listeners.start("ext-big").await.expect("start should succeed");

        // Confirm endpoint is registered.
        assert!(
            state.listeners.external_state_for_path("/bigbody").await.is_some(),
            "external endpoint should be registered"
        );

        // Send a body that exceeds MAX_AGENT_MESSAGE_LEN (30 MiB).
        let oversized = vec![0x41_u8; MAX_AGENT_MESSAGE_LEN + 1];

        let response = build_router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/bigbody")
                    .body(Body::from(oversized))
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "body exceeding MAX_AGENT_MESSAGE_LEN should return camouflage 404, not 400 BAD_REQUEST"
        );
    }

    /// A request body with an incorrect Demon magic value on an external
    /// listener path must be silently rejected with a camouflage 404.
    /// This verifies the early magic precheck is applied to the external
    /// listener path, matching the behavior of HTTP listeners.
    #[tokio::test]
    async fn fallback_rejects_wrong_magic_body_for_external_listener() {
        use red_cell_common::ExternalListenerConfig;

        let state = build_test_state().await;

        let config = red_cell_common::ListenerConfig::from(ExternalListenerConfig {
            name: "ext-magic".to_owned(),
            endpoint: "/magic-check".to_owned(),
        });
        state.listeners.create(config).await.expect("create should succeed");
        state.listeners.start("ext-magic").await.expect("start should succeed");

        assert!(
            state.listeners.external_state_for_path("/magic-check").await.is_some(),
            "external endpoint should be registered"
        );

        // Build a body with valid length but wrong magic (0x00000000 instead of 0xDEADBEEF).
        let mut bad_magic_body = vec![0u8; 20];
        // bytes 0..4 = size, bytes 4..8 = magic — leave magic as all zeros.
        bad_magic_body[0..4].copy_from_slice(&20_u32.to_be_bytes());

        let response = build_router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/magic-check")
                    .body(Body::from(bad_magic_body))
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");

        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "body with wrong Demon magic should return camouflage 404"
        );
    }
}
