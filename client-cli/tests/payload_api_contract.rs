//! Integration tests — payload commands against the real teamserver router.
//!
//! These tests verify that the CLI's expected request/response shapes for
//! `payload list`, `payload build`, and `payload download` match the actual
//! routes registered in `red_cell::api_routes`.  Any schema drift between the
//! CLI and the teamserver will cause a compile error or a test failure here.
//!
//! The tested contract:
//!
//! | CLI call site | Route |
//! |---|---|
//! | `list()` | `GET  /api/v1/payloads` |
//! | `build()` | `POST /api/v1/payloads/build` |
//! | `build()` poll | `GET  /api/v1/payloads/jobs/{job_id}` |
//! | `download()` | `GET  /api/v1/payloads/{id}/download` |

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
        Port = 40060
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
    TeamserverState {
        profile: profile.clone(),
        database: database.clone(),
        auth: AuthService::from_profile(&profile).expect("auth service"),
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

// ── GET /api/v1/payloads ──────────────────────────────────────────────────────

/// `GET /api/v1/payloads` returns 200 with a JSON array.
///
/// This verifies the route is registered at the exact path the CLI's `list()`
/// calls, and that the response is the array type that `Vec<RawPayloadSummary>`
/// expects to deserialize from.
#[tokio::test]
async fn get_payloads_returns_200_with_json_array() {
    let state = build_test_state().await;
    let response = call(state, "GET", "/api/v1/payloads", API_KEY, None).await;

    assert_eq!(response.status(), StatusCode::OK, "GET /payloads must return 200");

    let json = read_json(response).await;
    assert!(json.is_array(), "GET /payloads must return a JSON array, got: {json}");
}

/// `GET /api/v1/payloads` with no completed builds returns an empty array.
///
/// The CLI's `list()` must tolerate an empty result without error.
#[tokio::test]
async fn get_payloads_empty_database_returns_empty_array() {
    let state = build_test_state().await;
    let response = call(state, "GET", "/api/v1/payloads", API_KEY, None).await;

    let json = read_json(response).await;
    assert_eq!(
        json.as_array().map(|a| a.len()),
        Some(0),
        "fresh database must yield an empty payload list"
    );
}

/// `GET /api/v1/payloads` without an API key returns 401.
///
/// Ensures the route is protected — the CLI must always send `x-api-key`.
#[tokio::test]
async fn get_payloads_without_api_key_returns_401() {
    let state = build_test_state().await;
    let response = call(state, "GET", "/api/v1/payloads", "", None).await;

    assert!(
        response.status() == StatusCode::UNAUTHORIZED || response.status() == StatusCode::FORBIDDEN,
        "GET /payloads without API key must return 401 or 403, got {}",
        response.status()
    );
}

// ── POST /api/v1/payloads/build ───────────────────────────────────────────────

/// `POST /api/v1/payloads/build` with an unknown listener returns 404.
///
/// This verifies:
/// - The route is registered at `/payloads/build` (not `/payload/build` or
///   `/builds`).
/// - The CLI's request body fields `{listener, arch, format}` are accepted by
///   the server without a 422/400.
/// - The server returns 404 when the listener does not exist.
#[tokio::test]
async fn post_payloads_build_unknown_listener_returns_404() {
    let state = build_test_state().await;
    let body = serde_json::json!({
        "listener": "no-such-listener",
        "arch": "x64",
        "format": "exe"
    });
    let response = call(state, "POST", "/api/v1/payloads/build", API_KEY, Some(body)).await;

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "POST /payloads/build with unknown listener must return 404"
    );
}

/// `POST /api/v1/payloads/build` with an invalid architecture returns 400.
///
/// This validates that the server enforces `x64`/`x86` — not the libcs
/// convention of `x86_64`/`i686`.
#[tokio::test]
async fn post_payloads_build_invalid_arch_returns_400() {
    let state = build_test_state().await;
    let body = serde_json::json!({
        "listener": "http1",
        "arch": "x86_64",
        "format": "exe"
    });
    let response = call(state, "POST", "/api/v1/payloads/build", API_KEY, Some(body)).await;

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "POST /payloads/build with arch='x86_64' must return 400 (server expects 'x64')"
    );
}

/// `POST /api/v1/payloads/build` with an invalid format returns 400.
///
/// The CLI validates format client-side (`validate_format`) but the server also
/// enforces it.
#[tokio::test]
async fn post_payloads_build_invalid_format_returns_400() {
    let state = build_test_state().await;
    let body = serde_json::json!({
        "listener": "http1",
        "arch": "x64",
        "format": "elf"
    });
    let response = call(state, "POST", "/api/v1/payloads/build", API_KEY, Some(body)).await;

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "POST /payloads/build with format='elf' must return 400"
    );
}

/// `POST /api/v1/payloads/build` returns 202 with a `job_id` field.
///
/// This verifies the full request/response contract for a successful submission:
/// - A listener is created first via `POST /api/v1/listeners`.
/// - The build submission returns 202 Accepted.
/// - The response body has a `job_id` string field that the CLI deserializes
///   into `BuildSubmitResponse { job_id }`.
#[tokio::test]
async fn post_payloads_build_returns_202_with_job_id() {
    let state = build_test_state().await;

    // Create a listener so the build request can find it.
    let listener_body = serde_json::json!({
        "protocol": "smb",
        "config": {
            "name": "test-listener",
            "pipe_name": "test-pipe"
        }
    });
    let create_resp =
        call(state.clone(), "POST", "/api/v1/listeners", API_KEY, Some(listener_body)).await;
    assert_eq!(
        create_resp.status(),
        StatusCode::CREATED,
        "prerequisite listener creation must succeed"
    );

    // Submit a build job.
    let build_body = serde_json::json!({
        "listener": "test-listener",
        "arch": "x64",
        "format": "exe"
    });
    let response = call(state, "POST", "/api/v1/payloads/build", API_KEY, Some(build_body)).await;

    assert_eq!(
        response.status(),
        StatusCode::ACCEPTED,
        "POST /payloads/build with valid listener must return 202"
    );

    let json = read_json(response).await;
    assert!(
        json["job_id"].is_string() && !json["job_id"].as_str().unwrap_or("").is_empty(),
        "POST /payloads/build response must have a non-empty `job_id` string field, got: {json}"
    );
}

// ── GET /api/v1/payloads/jobs/{job_id} ───────────────────────────────────────

/// `GET /api/v1/payloads/jobs/{job_id}` for an unknown job returns 404.
///
/// This verifies the route is at `/payloads/jobs/` (not `/builds/` or `/jobs/`),
/// which is the path the CLI's `build --wait` polling loop uses.
#[tokio::test]
async fn get_payload_job_unknown_returns_404() {
    let state = build_test_state().await;
    let response = call(state, "GET", "/api/v1/payloads/jobs/no-such-job", API_KEY, None).await;

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "GET /payloads/jobs/{{id}} for unknown job must return 404"
    );
}

/// `GET /api/v1/payloads/jobs/{job_id}` for a submitted job returns 200 with
/// the schema the CLI's `BuildJobStatus` deserializes: `{job_id, status,
/// payload_id, size_bytes, error}`.
///
/// This verifies that the job status route returns the fields the CLI polls on.
#[tokio::test]
async fn get_payload_job_returns_correct_schema() {
    let state = build_test_state().await;

    // Create a listener then submit a build to get a real job_id.
    let listener_body = serde_json::json!({
        "protocol": "smb",
        "config": { "name": "schema-listener", "pipe_name": "schema-pipe" }
    });
    let create_resp =
        call(state.clone(), "POST", "/api/v1/listeners", API_KEY, Some(listener_body)).await;
    assert_eq!(create_resp.status(), StatusCode::CREATED, "listener create must succeed");

    let build_body =
        serde_json::json!({"listener": "schema-listener", "arch": "x64", "format": "bin"});
    let build_resp =
        call(state.clone(), "POST", "/api/v1/payloads/build", API_KEY, Some(build_body)).await;
    assert_eq!(build_resp.status(), StatusCode::ACCEPTED, "build submit must return 202");

    let build_json = read_json(build_resp).await;
    let job_id = build_json["job_id"].as_str().expect("job_id must be a string");

    // Poll the job status immediately.
    let job_uri = format!("/api/v1/payloads/jobs/{job_id}");
    let response = call(state, "GET", &job_uri, API_KEY, None).await;

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "GET /payloads/jobs/{{job_id}} for known job must return 200"
    );

    let json = read_json(response).await;
    // Verify every field the CLI's `BuildJobStatus` expects to deserialize.
    assert_eq!(json["job_id"].as_str(), Some(job_id), "job_id field must match");
    assert!(json["status"].is_string(), "status field must be a string");
    // payload_id and size_bytes are nullable — just assert the keys are present.
    assert!(json.get("payload_id").is_some(), "payload_id field must be present (may be null)");
    assert!(json.get("size_bytes").is_some(), "size_bytes field must be present (may be null)");
    assert!(json.get("error").is_some(), "error field must be present (may be null)");
}

// ── GET /api/v1/payloads/{id}/download ───────────────────────────────────────

/// `GET /api/v1/payloads/{id}/download` for an unknown id returns 404.
///
/// This verifies the route path is `/payloads/{id}/download` — the exact path
/// the CLI's `download()` constructs via `format!("/payloads/{id}/download")`.
#[tokio::test]
async fn get_payload_download_unknown_returns_404() {
    let state = build_test_state().await;
    let response = call(state, "GET", "/api/v1/payloads/no-such-id/download", API_KEY, None).await;

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "GET /payloads/{{id}}/download for unknown id must return 404"
    );
}

/// `GET /api/v1/payloads/{id}/download` for a job that is pending (not yet
/// done) returns 404, not 200.
///
/// The CLI's `download()` must only be called after the build succeeds; a
/// pending or failed build cannot be downloaded.
#[tokio::test]
async fn get_payload_download_pending_job_returns_404() {
    let state = build_test_state().await;

    // Create a listener and submit a build.
    let listener_body = serde_json::json!({
        "protocol": "smb",
        "config": { "name": "dl-listener", "pipe_name": "dl-pipe" }
    });
    let _ = call(state.clone(), "POST", "/api/v1/listeners", API_KEY, Some(listener_body)).await;

    let build_body = serde_json::json!({"listener": "dl-listener", "arch": "x64", "format": "dll"});
    let build_resp =
        call(state.clone(), "POST", "/api/v1/payloads/build", API_KEY, Some(build_body)).await;
    assert_eq!(build_resp.status(), StatusCode::ACCEPTED, "build submit must return 202");

    let build_json = read_json(build_resp).await;
    let job_id = build_json["job_id"].as_str().expect("job_id must be a string");

    // Try to download immediately — the build task is still pending/running.
    let dl_uri = format!("/api/v1/payloads/{job_id}/download");
    let response = call(state, "GET", &dl_uri, API_KEY, None).await;

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "GET /payloads/{{id}}/download for a non-done build must return 404"
    );
}
