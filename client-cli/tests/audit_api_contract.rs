//! Integration tests — audit log commands against the real teamserver router.
//!
//! These tests verify that the CLI's expected route, query parameters, and
//! response deserialization shape match the actual `GET /api/v1/audit` endpoint
//! registered in `red_cell::api_routes`.  Any schema drift between the CLI and
//! the teamserver will cause a compile error or a test failure here.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use red_cell::{
    AgentRegistry, ApiRuntime, AuditResultStatus, AuditWebhookNotifier, AuthService, Database,
    EventBus, ListenerManager, LoginRateLimiter, OperatorConnectionManager, PayloadBuilderService,
    ShutdownController, SocketRelayManager, TeamserverState, audit_details, build_router,
    record_operator_action,
};
use red_cell_common::config::Profile;
use tower::ServiceExt as _;

// ── constants ─────────────────────────────────────────────────────────────────

const PROFILE_HCL: &str = r#"
    Teamserver {
        Host = "127.0.0.1"
        Port = 40056
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

async fn build_test_state() -> (TeamserverState, Database) {
    let profile = Profile::parse(PROFILE_HCL).expect("profile parse");
    let database = Database::connect_in_memory().await.expect("database");
    let agent_registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(agent_registry.clone(), events.clone());
    let state = TeamserverState {
        profile: profile.clone(),
        database: database.clone(),
        auth: AuthService::from_profile(&profile).expect("auth service"),
        api: ApiRuntime::from_profile(&profile).expect("api runtime"),
        events: events.clone(),
        connections: OperatorConnectionManager::new(),
        agent_registry: agent_registry.clone(),
        listeners: ListenerManager::new(
            database.clone(),
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
    };
    (state, database)
}

async fn call(state: TeamserverState, uri: &str, api_key: &str) -> axum::response::Response {
    let router = build_router(state);
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-api-key", api_key)
        .body(Body::empty())
        .expect("request build");
    router.oneshot(req).await.expect("router should respond")
}

async fn read_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.expect("body bytes");
    serde_json::from_slice(&bytes).expect("json body")
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// `GET /api/v1/audit` returns 200 with an `AuditPage` shaped response even
/// when the log is empty.
#[tokio::test]
async fn get_audit_returns_200_with_empty_page() {
    let (state, _db) = build_test_state().await;
    let response = call(state, "/api/v1/audit", API_KEY).await;

    assert_eq!(response.status(), StatusCode::OK, "GET /audit must return 200");

    let json = read_json(response).await;
    assert!(json["total"].is_number(), "response must have numeric `total` field");
    assert!(json["limit"].is_number(), "response must have numeric `limit` field");
    assert!(json["offset"].is_number(), "response must have numeric `offset` field");
    assert!(json["items"].is_array(), "response must have array `items` field");
    assert_eq!(json["items"].as_array().unwrap().len(), 0, "empty log must have 0 items");
}

/// `GET /api/v1/audit` returns the expected `AuditRecord` field names so that
/// the CLI can deserialize them as `RawAuditRecord`.
///
/// Verifies: `id`, `actor`, `action`, `target_kind`, `target_id`, `agent_id`,
/// `command`, `result_status`, `occurred_at`.
#[tokio::test]
async fn get_audit_record_has_correct_field_names() {
    let (state, db) = build_test_state().await;

    // Insert one audit record so the items array is non-empty.
    record_operator_action(
        &db,
        "alice",
        "agent.task",
        "agent",
        Some("DEADBEEF".to_owned()),
        audit_details(AuditResultStatus::Success, Some(0xDEAD_BEEF), Some("whoami"), None),
    )
    .await
    .expect("insert audit record");

    let response = call(state, "/api/v1/audit", API_KEY).await;
    assert_eq!(response.status(), StatusCode::OK);

    let json = read_json(response).await;
    let items = json["items"].as_array().expect("items must be an array");
    assert_eq!(items.len(), 1, "one item must be returned");

    let record = &items[0];
    // Verify every field the CLI depends on is present with the correct name.
    assert!(record["id"].is_number(), "record must have `id`");
    assert_eq!(record["actor"], "alice", "actor must match");
    assert_eq!(record["action"], "agent.task", "action must match");
    assert_eq!(record["target_kind"], "agent", "target_kind must be present");
    assert_eq!(record["target_id"], "DEADBEEF", "target_id must be present");
    assert_eq!(record["agent_id"], "DEADBEEF", "agent_id must be present");
    assert_eq!(record["command"], "whoami", "command must be present");
    assert!(record["occurred_at"].is_string(), "occurred_at must be a string");
    assert!(record["result_status"].is_string(), "result_status must be a string (not an object)");
    assert_eq!(record["result_status"], "success", "result_status must be `success`");
}

/// `GET /api/v1/audit?operator=alice` filters by actor.
///
/// The server accepts both `operator` and `actor` as aliases; the CLI sends
/// `operator`.
#[tokio::test]
async fn get_audit_filters_by_operator_param() {
    let (state, db) = build_test_state().await;

    record_operator_action(
        &db,
        "alice",
        "agent.task",
        "agent",
        None,
        audit_details(AuditResultStatus::Success, None, None, None),
    )
    .await
    .expect("insert alice record");

    record_operator_action(
        &db,
        "bob",
        "operator.login",
        "session",
        None,
        audit_details(AuditResultStatus::Success, None, None, None),
    )
    .await
    .expect("insert bob record");

    let response = call(state, "/api/v1/audit?operator=alice", API_KEY).await;
    assert_eq!(response.status(), StatusCode::OK);

    let json = read_json(response).await;
    let items = json["items"].as_array().expect("items must be array");
    assert_eq!(items.len(), 1, "only alice's record should appear");
    assert_eq!(items[0]["actor"], "alice");
}

/// `GET /api/v1/audit?limit=1` returns at most 1 item and pagination metadata
/// reflects the cap.
#[tokio::test]
async fn get_audit_respects_limit_param() {
    let (state, db) = build_test_state().await;

    for i in 0u32..3 {
        record_operator_action(
            &db,
            "alice",
            "agent.task",
            "agent",
            Some(format!("{i:08X}")),
            audit_details(AuditResultStatus::Success, Some(i), None, None),
        )
        .await
        .expect("insert record");
    }

    let response = call(state, "/api/v1/audit?limit=1", API_KEY).await;
    assert_eq!(response.status(), StatusCode::OK);

    let json = read_json(response).await;
    assert_eq!(json["limit"], 1, "returned limit must be 1");
    assert_eq!(json["items"].as_array().unwrap().len(), 1, "only 1 item must be returned");
    assert_eq!(json["total"], 3, "total must reflect all 3 matching records");
}

/// `GET /api/v1/audit` without an API key returns 401 Unauthorized.
///
/// Ensures the route is protected, not accidentally left open.
#[tokio::test]
async fn get_audit_requires_authentication() {
    let (state, _db) = build_test_state().await;
    let router = build_router(state);
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/audit")
        .body(Body::empty())
        .expect("request build");
    let response = router.oneshot(req).await.expect("router should respond");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "unauthenticated request must get 401");
}

/// The old (now-removed) route `/api/v1/audit/log` must return 404, confirming
/// the CLI can no longer accidentally fall back to it.
#[tokio::test]
async fn old_audit_log_route_returns_404() {
    let (state, _db) = build_test_state().await;
    let response = call(state, "/api/v1/audit/log", API_KEY).await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "the stale /audit/log route must not exist"
    );
}
