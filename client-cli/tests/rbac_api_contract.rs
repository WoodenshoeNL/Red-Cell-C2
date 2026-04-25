//! Integration tests — RBAC agent groups + listener access REST shapes.
//!
//! Verifies the CLI's expected JSON bodies for `agent groups`, `operator show-agent-groups`,
//! and `listener access` stay aligned with `teamserver` `api_routes`.
//!
//! Note: `PUT /agents/{id}/groups` and `PUT /listeners/{name}/access` enforce foreign keys
//! (`ts_agents`, `ts_listeners`).  Those success paths are covered by unit tests and manual
//! harnesses — this file sticks to `GET` plus operator `PUT` (no agent/listener FK required).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use red_cell::{
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, LoginRateLimiter, OperatorConnectionManager, PayloadBuilderService,
    ShutdownController, SocketRelayManager, TeamserverState, build_router,
};
use red_cell_common::config::Profile;
use tower::ServiceExt as _;

const PROFILE_HCL: &str = r#"
    Teamserver {
        Host = "127.0.0.1"
        Port = 40057
    }
    Operators {
        user "testop" {
            Password = "password1234!"
            Role    = "Operator"
        }
    }
    Demon {}
    Api {
        RateLimitPerMinute = 60
        key "test-key" {
            Value = "test-secret"
            Role  = "Admin"
        }
    }
"#;

const API_KEY: &str = "test-secret";

async fn build_test_state() -> TeamserverState {
    let profile = Profile::parse(PROFILE_HCL).expect("profile parse");
    let database = Database::connect_in_memory().await.expect("database");
    let agent_registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(agent_registry.clone(), events.clone());
    let auth =
        AuthService::from_profile_with_database(&profile, &database).await.expect("auth service");
    TeamserverState {
        profile: profile.clone(),
        profile_path: "test.yaotl".to_owned(),
        database: database.clone(),
        auth,
        api: ApiRuntime::from_profile(&profile).expect("api runtime"),
        events: events.clone(),
        connections: OperatorConnectionManager::new(),
        agent_registry: agent_registry.clone(),
        listeners: ListenerManager::new(
            database,
            agent_registry.clone(),
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
        started_at: std::time::Instant::now(),
        plugins_loaded: 0,
        plugins_failed: 0,
        metrics: red_cell::metrics::standalone_metrics_handle(),
    }
}

async fn call(
    state: TeamserverState,
    method: &str,
    uri: &str,
    api_key: &str,
    body: Option<serde_json::Value>,
) -> axum::response::Response {
    let router = build_router(state);
    let mut builder = Request::builder().method(method).uri(uri).header("x-api-key", api_key);

    let req_body = match body {
        Some(json) => {
            builder = builder.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&json).expect("json serialise"))
        }
        None => Body::empty(),
    };

    router
        .oneshot(builder.body(req_body).expect("request build"))
        .await
        .expect("router should respond")
}

async fn read_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.expect("body bytes");
    serde_json::from_slice(&bytes).expect("json body")
}

#[tokio::test]
async fn get_agent_groups_returns_agent_id_and_groups_array() {
    let state = build_test_state().await;
    let response = call(state, "GET", "/api/v1/agents/DEADBEEF/groups", API_KEY, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = read_json(response).await;
    assert_eq!(json["agent_id"], "DEADBEEF");
    assert!(json["groups"].is_array());
}

#[tokio::test]
async fn get_operator_agent_groups_returns_username_and_allowed_groups() {
    let state = build_test_state().await;
    let response = call(state, "GET", "/api/v1/operators/testop/agent-groups", API_KEY, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = read_json(response).await;
    assert_eq!(json["username"], "testop");
    assert!(json["allowed_groups"].is_array());
}

#[tokio::test]
async fn put_operator_agent_groups_round_trips_allowed_groups() {
    let state = build_test_state().await;
    let body = serde_json::json!({ "allowed_groups": ["east", "west"] });
    let response =
        call(state, "PUT", "/api/v1/operators/testop/agent-groups", API_KEY, Some(body)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = read_json(response).await;
    assert_eq!(json["username"], "testop");
    assert_eq!(json["allowed_groups"], serde_json::json!(["east", "west"]));
}

#[tokio::test]
async fn get_listener_access_returns_listener_name_and_allowed_operators() {
    let state = build_test_state().await;
    let response = call(state, "GET", "/api/v1/listeners/any-listener/access", API_KEY, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = read_json(response).await;
    assert_eq!(json["listener_name"], "any-listener");
    assert!(json["allowed_operators"].is_array());
}
