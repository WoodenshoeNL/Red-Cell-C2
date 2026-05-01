use super::*;

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
        profile_path: "test.yaotl".to_owned(),
        database: database.clone(),
        auth: crate::AuthService::from_profile(&profile).expect("auth service should initialize"),
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
        corpus_dir: None,
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
