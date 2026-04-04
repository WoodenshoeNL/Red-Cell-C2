//! Integration tests — operator commands against the real teamserver router.
//!
//! These tests verify that the CLI's expected request/response shapes for
//! `operator create` and `operator set-role` match the actual routes registered
//! in `red_cell::api_routes`.  Any schema drift between the CLI and teamserver
//! will cause a compile error or a test failure here.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use red_cell::{
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, LoginRateLimiter, OperatorConnectionManager, PayloadBuilderService,
    ShutdownController, SocketRelayManager, TeamserverState, build_router,
};
use red_cell_common::config::Profile;
use tower::ServiceExt as _;

// ── constants ─────────────────────────────────────────────────────────────────

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

// ── helpers ───────────────────────────────────────────────────────────────────

async fn build_test_state() -> TeamserverState {
    let profile = Profile::parse(PROFILE_HCL).expect("profile parse");
    let database = Database::connect_in_memory().await.expect("database");
    let agent_registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(agent_registry.clone(), events.clone());
    // Use from_profile_with_database so runtime operator create/update/delete
    // work correctly (they require the database-backed operator repository).
    let auth =
        AuthService::from_profile_with_database(&profile, &database).await.expect("auth service");
    TeamserverState {
        profile: profile.clone(),
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
    }
}

/// Issue a oneshot JSON request against the router.
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

// ── tests ─────────────────────────────────────────────────────────────────────

/// `POST /api/v1/operators` with `{username, password, role}` returns 201 and a
/// `CreatedOperatorResponse` shaped body with `username` and `role` fields.
///
/// This verifies the CLI's `create()` request body and `RawCreateResponse`
/// deserialization are in sync with the server.
#[tokio::test]
async fn post_operators_returns_201_with_username_and_role() {
    let state = build_test_state().await;
    let body = serde_json::json!({
        "username": "newop",
        "password": "S3cr3tP@ssw0rd!",
        "role": "operator"
    });
    let response = call(state, "POST", "/api/v1/operators", API_KEY, Some(body)).await;

    assert_eq!(response.status(), StatusCode::CREATED, "POST /operators must return 201");

    let json = read_json(response).await;
    assert_eq!(json["username"], "newop", "response must echo back the username");
    assert!(json["role"].is_string(), "response must have a string `role` field");
    // Verify the CLI's RawCreateResponse shape: {username, role} — no token, no ok field.
    assert!(json.get("token").is_none(), "response must NOT have a `token` field");
    assert!(json.get("ok").is_none(), "response must NOT have an `ok` field");
}

/// `POST /api/v1/operators` without `password` returns 422 (unprocessable).
///
/// This confirms the old buggy CLI body `{username, role}` (missing password)
/// would be rejected by the server, and that the fix is required.
#[tokio::test]
async fn post_operators_without_password_returns_error() {
    let state = build_test_state().await;
    let body = serde_json::json!({ "username": "newop", "role": "operator" });
    let response = call(state, "POST", "/api/v1/operators", API_KEY, Some(body)).await;

    assert!(
        response.status().is_client_error(),
        "POST /operators without password must be rejected (got {})",
        response.status()
    );
}

/// `PUT /api/v1/operators/{username}/role` returns 200 with an `OperatorSummary`
/// shaped body: `{username, role, online, last_seen}`.
///
/// This verifies the CLI's `set_role()` now correctly deserializes the response
/// into `RawOperatorSummary` rather than the old incorrect `RawOk { ok: bool }`.
#[tokio::test]
async fn put_operator_role_returns_200_with_operator_summary() {
    let state = build_test_state().await;

    // First create an operator so the role update has a target.
    let create_body = serde_json::json!({
        "username": "roleop",
        "password": "P@ssword123!",
        "role": "operator"
    });
    let create_resp =
        call(state.clone(), "POST", "/api/v1/operators", API_KEY, Some(create_body)).await;
    assert_eq!(create_resp.status(), StatusCode::CREATED, "prerequisite create must succeed");

    // Now change the role.
    let update_body = serde_json::json!({ "role": "analyst" });
    let response =
        call(state, "PUT", "/api/v1/operators/roleop/role", API_KEY, Some(update_body)).await;

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "PUT /operators/{{username}}/role must return 200"
    );

    let json = read_json(response).await;
    // Verify the OperatorSummary shape that `RawOperatorSummary` must deserialize.
    assert_eq!(json["username"], "roleop", "response must include the username");
    assert!(json["role"].is_string(), "response must have a string `role` field");
    assert!(json["online"].is_boolean(), "response must have a boolean `online` field");
    // `last_seen` is present but may be null.
    assert!(
        json.get("last_seen").is_some(),
        "response must have a `last_seen` field (null is fine)"
    );
    // Verify the old wrong shape fields are absent.
    assert!(json.get("ok").is_none(), "response must NOT have an `ok` field");
}

/// `PUT /api/v1/operators/{username}/role` for an unknown operator returns a
/// non-2xx status (404), not a deserialization error.
#[tokio::test]
async fn put_operator_role_for_unknown_operator_returns_404() {
    let state = build_test_state().await;
    let body = serde_json::json!({ "role": "analyst" });
    let response = call(state, "PUT", "/api/v1/operators/nobody/role", API_KEY, Some(body)).await;

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "PUT /operators/{{username}}/role for unknown operator must return 404"
    );
}
