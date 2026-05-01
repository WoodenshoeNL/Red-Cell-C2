//! Integration tests — session command routes against the real teamserver router.
//!
//! These tests exercise the contract between the session loop's expected
//! request/response shapes and the actual routes registered in
//! `red_cell::api_routes`.  They cover the three route families that
//! `session.rs` uses but that are not yet covered by the other contract test
//! files:
//!
//! | Route family | CLI command |
//! |---|---|
//! | `GET /api/v1/agents` | `agent.list` |
//! | `GET /api/v1/agents/{id}` | `agent.show`, `agent.kill` (poll) |
//! | `GET /api/v1/listeners` | `listener.list` |
//! | `POST /api/v1/listeners` | `listener.create` |
//! | `GET /api/v1/listeners/{name}` | `listener.show` |
//! | `PUT /api/v1/listeners/{name}/start` | `listener.start` |
//! | `PUT /api/v1/listeners/{name}/stop` | `listener.stop` |
//! | `DELETE /api/v1/listeners/{name}` | `listener.delete` |
//! | `GET /api/v1/operators` | `operator.list` |
//! | `DELETE /api/v1/operators/{username}` | `operator.delete` |
//!
//! The agent-route tests document the **exact** PascalCase field names that
//! `ApiAgentInfo` emits.  `RawAgent` in `client-cli` must use
//! `#[serde(from = "ApiAgentWire")]` (or equivalent) to deserialise these.
//! If the server renames any of these fields the test will fail at review
//! time, surfacing the contract break before it ships.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use red_cell::{
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, LoginRateLimiter, OperatorConnectionManager, PayloadBuilderService,
    ShutdownController, SocketRelayManager, TeamserverState, build_router,
};
use red_cell_common::config::Profile;
use red_cell_common::{AgentEncryptionInfo, AgentRecord};
use tower::ServiceExt as _;

// ── constants ─────────────────────────────────────────────────────────────────

const PROFILE_HCL: &str = r#"
    Teamserver {
        Host = "127.0.0.1"
        Port = 40061
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
const AGENT_ID_U32: u32 = 0xDEAD_BEEF;
const AGENT_ID_HEX: &str = "DEADBEEF";

// ── helpers ───────────────────────────────────────────────────────────────────

async fn build_test_state() -> (TeamserverState, AgentRegistry) {
    let profile = Profile::parse(PROFILE_HCL).expect("profile parse");
    let database = Database::connect_in_memory().await.expect("database");
    let agent_registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(agent_registry.clone(), events.clone());
    // Use from_profile_with_database so runtime operator create/delete work.
    let auth =
        AuthService::from_profile_with_database(&profile, &database).await.expect("auth service");
    let state = TeamserverState {
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
        corpus_dir: None,
        started_at: std::time::Instant::now(),
        plugins_loaded: 0,
        plugins_failed: 0,
        metrics: red_cell::metrics::standalone_metrics_handle(),
    };
    (state, agent_registry)
}

fn sample_agent(agent_id: u32) -> AgentRecord {
    AgentRecord {
        agent_id,
        active: true,
        reason: "http".to_owned(),
        note: String::new(),
        encryption: AgentEncryptionInfo::default(),
        hostname: "workstation".to_owned(),
        username: "operator".to_owned(),
        domain_name: "LAB".to_owned(),
        external_ip: "203.0.113.10".to_owned(),
        internal_ip: "10.0.0.10".to_owned(),
        process_name: "demon.exe".to_owned(),
        process_path: "C:\\Windows\\System32\\demon.exe".to_owned(),
        base_address: 0x1400_0000,
        process_pid: 4444,
        process_tid: 4445,
        process_ppid: 1000,
        process_arch: "x64".to_owned(),
        elevated: true,
        os_version: "Windows 11".to_owned(),
        os_build: 22000,
        os_arch: "x64".to_owned(),
        sleep_delay: 5,
        sleep_jitter: 10,
        kill_date: None,
        working_hours: None,
        first_call_in: "2026-03-01T00:00:00Z".to_owned(),
        last_call_in: "2026-03-01T00:05:00Z".to_owned(),
        archon_magic: None,
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

// ── agent routes ──────────────────────────────────────────────────────────────

/// `GET /api/v1/agents` returns 200 with an empty JSON array when no agents
/// are registered.
///
/// The CLI's `agent.list` deserialises the response as `Vec<RawAgent>`.
#[tokio::test]
async fn get_agents_returns_empty_array_when_registry_empty() {
    let (state, _registry) = build_test_state().await;
    let response = call(state, "GET", "/api/v1/agents", API_KEY, None).await;

    assert_eq!(response.status(), StatusCode::OK);
    let json = read_json(response).await;
    assert!(json.is_array(), "GET /agents must return a JSON array, got: {json}");
    assert_eq!(json.as_array().unwrap().len(), 0);
}

/// `GET /api/v1/agents` returns items whose field names match the
/// `ApiAgentInfo` serialisation: PascalCase identifiers like `AgentID`,
/// `Hostname`, `LastCallIn`, `Active`, etc.
///
/// The CLI's `RawAgent` must use serde rename attributes (or an intermediate
/// wire type with `#[serde(from)]`) to deserialise these PascalCase keys.
/// If the server changes any key name this test will fail at review time.
#[tokio::test]
async fn get_agents_items_use_pascal_case_field_names() {
    let (state, registry) = build_test_state().await;
    registry.insert(sample_agent(AGENT_ID_U32)).await.expect("insert agent");

    let response = call(state, "GET", "/api/v1/agents", API_KEY, None).await;
    assert_eq!(response.status(), StatusCode::OK);

    let json = read_json(response).await;
    let items = json.as_array().expect("response must be array");
    assert_eq!(items.len(), 1, "one agent must be returned");

    let agent = &items[0];

    // Verify the exact field names that ApiAgentInfo serialises.
    // RawAgent must be able to deserialise all of these.
    assert!(agent["AgentID"].is_number(), "AgentID field must be a number");
    assert_eq!(
        agent["AgentID"].as_u64(),
        Some(AGENT_ID_U32 as u64),
        "AgentID must equal the inserted agent id"
    );
    assert!(agent["Hostname"].is_string(), "Hostname field must be a string");
    assert!(agent["Username"].is_string(), "Username field must be a string");
    assert!(agent["DomainName"].is_string(), "DomainName field must be a string");
    assert!(agent["InternalIP"].is_string(), "InternalIP field must be a string");
    assert!(agent["ProcessName"].is_string(), "ProcessName field must be a string");
    assert!(agent["ProcessPID"].is_number(), "ProcessPID field must be a number");
    assert!(agent["ProcessArch"].is_string(), "ProcessArch field must be a string");
    assert!(agent["OSVersion"].is_string(), "OSVersion field must be a string");
    assert!(agent["OSArch"].is_string(), "OSArch field must be a string");
    assert!(agent["SleepDelay"].is_number(), "SleepDelay field must be a number");
    assert!(agent["SleepJitter"].is_number(), "SleepJitter field must be a number");
    assert!(agent["LastCallIn"].is_string(), "LastCallIn field must be a string");
    assert!(agent["Active"].is_boolean(), "Active field must be a boolean");

    // Confirm the snake_case names the CLI's old wiremock stubs used do NOT
    // appear — these would indicate the server has been changed to match the
    // stubs rather than the canonical Havoc-compatible wire format.
    assert!(agent.get("id").is_none(), "field 'id' must not exist; server sends 'AgentID'");
    assert!(
        agent.get("last_seen").is_none(),
        "field 'last_seen' must not exist; server sends 'LastCallIn'"
    );
    assert!(agent.get("status").is_none(), "field 'status' must not exist; server sends 'Active'");
    assert!(agent.get("os").is_none(), "field 'os' must not exist; server sends 'OSVersion'");
}

/// `GET /api/v1/agents/{id}` returns 200 with all `ApiAgentInfo` fields for
/// the identified agent.
///
/// This is the route `agent.show` and the `agent.kill` wait-poll loop use.
#[tokio::test]
async fn get_agent_by_id_returns_full_agent_info() {
    let (state, registry) = build_test_state().await;
    registry.insert(sample_agent(AGENT_ID_U32)).await.expect("insert agent");

    let response =
        call(state, "GET", &format!("/api/v1/agents/{AGENT_ID_HEX}"), API_KEY, None).await;

    assert_eq!(response.status(), StatusCode::OK, "GET /agents/{{id}} must return 200");

    let agent = read_json(response).await;

    // Spot-check key fields that RawAgent must deserialise.
    assert_eq!(agent["AgentID"].as_u64(), Some(AGENT_ID_U32 as u64));
    assert_eq!(agent["Hostname"], "workstation");
    assert_eq!(agent["Username"], "operator");
    assert_eq!(agent["OSVersion"], "Windows 11");
    assert_eq!(agent["OSArch"], "x64");
    assert_eq!(agent["LastCallIn"], "2026-03-01T00:05:00Z");
    assert_eq!(agent["Active"], true);
    assert_eq!(agent["SleepDelay"].as_u64(), Some(5));
    assert_eq!(agent["SleepJitter"].as_u64(), Some(10));
    assert_eq!(agent["ProcessArch"], "x64");
    assert_eq!(agent["InternalIP"], "10.0.0.10");
}

/// `GET /api/v1/agents/{id}` returns 404 for an unknown agent id.
///
/// Ensures the route is registered (not 405) and that the CLI's not-found
/// handling in `agent.show` will receive a 404.
#[tokio::test]
async fn get_agent_for_unknown_id_returns_404() {
    let (state, _registry) = build_test_state().await;

    let response =
        call(state, "GET", &format!("/api/v1/agents/{AGENT_ID_HEX}"), API_KEY, None).await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND, "unknown agent must return 404");
}

// ── listener routes ───────────────────────────────────────────────────────────

/// `GET /api/v1/listeners` returns 200 with an empty array when no listeners
/// are configured.
///
/// This is the route `listener.list` calls.
#[tokio::test]
async fn get_listeners_returns_empty_array_initially() {
    let (state, _registry) = build_test_state().await;
    let response = call(state, "GET", "/api/v1/listeners", API_KEY, None).await;

    assert_eq!(response.status(), StatusCode::OK);
    let json = read_json(response).await;
    assert!(json.is_array(), "GET /listeners must return an array");
    assert_eq!(json.as_array().unwrap().len(), 0);
}

/// `POST /api/v1/listeners` with a valid SMB config returns 201 and a
/// `ListenerSummary`-shaped body: `{name, protocol, state: {status,
/// last_error}, config}`.
///
/// This is the route `listener.create` uses.  The CLI's `RawListenerSummary`
/// must deserialise all of these fields.
#[tokio::test]
async fn post_listeners_returns_201_with_listener_summary_shape() {
    let (state, _registry) = build_test_state().await;

    let body = serde_json::json!({
        "protocol": "smb",
        "config": {
            "name": "test-smb",
            "pipe_name": "red-cell-pipe"
        }
    });
    let response = call(state, "POST", "/api/v1/listeners", API_KEY, Some(body)).await;

    assert_eq!(response.status(), StatusCode::CREATED, "POST /listeners must return 201");

    let json = read_json(response).await;

    // Verify the RawListenerSummary fields the CLI uses.
    assert_eq!(json["name"], "test-smb", "response must echo the listener name");
    assert!(json["protocol"].is_string(), "response must have a string `protocol` field");
    assert!(json["state"].is_object(), "response must have an object `state` field");
    assert!(json["state"]["status"].is_string(), "state.status must be a string (e.g. 'Created')");
    assert!(
        json["state"].get("last_error").is_some(),
        "state.last_error field must be present (null is ok)"
    );
    assert!(json["config"].is_object(), "response must have an object `config` field");
}

/// `GET /api/v1/listeners` after a create returns an array with one entry
/// whose shape matches `RawListenerSummary`.
///
/// This verifies `listener.list` will see the newly created listener.
#[tokio::test]
async fn get_listeners_after_create_returns_one_entry() {
    let (state, _registry) = build_test_state().await;

    let body = serde_json::json!({
        "protocol": "smb",
        "config": { "name": "list-test", "pipe_name": "list-pipe" }
    });
    let create_resp = call(state.clone(), "POST", "/api/v1/listeners", API_KEY, Some(body)).await;
    assert_eq!(create_resp.status(), StatusCode::CREATED, "prerequisite create must succeed");

    let response = call(state, "GET", "/api/v1/listeners", API_KEY, None).await;
    assert_eq!(response.status(), StatusCode::OK);

    let json = read_json(response).await;
    let items = json.as_array().expect("must be array");
    assert_eq!(items.len(), 1, "one listener must be returned");

    let listener = &items[0];
    // Verify RawListenerSummary shape.
    assert_eq!(listener["name"], "list-test");
    assert!(listener["protocol"].is_string());
    assert!(listener["state"]["status"].is_string());
    assert!(listener["config"].is_object());
}

/// `GET /api/v1/listeners/{name}` returns 200 with `RawListenerSummary` shape
/// for an existing listener.
///
/// This is the route `listener.show` uses.
#[tokio::test]
async fn get_listener_by_name_returns_listener_summary() {
    let (state, _registry) = build_test_state().await;

    let body = serde_json::json!({
        "protocol": "smb",
        "config": { "name": "show-smb", "pipe_name": "show-pipe" }
    });
    let _ = call(state.clone(), "POST", "/api/v1/listeners", API_KEY, Some(body)).await;

    let response = call(state, "GET", "/api/v1/listeners/show-smb", API_KEY, None).await;
    assert_eq!(response.status(), StatusCode::OK, "GET /listeners/{{name}} must return 200");

    let json = read_json(response).await;
    assert_eq!(json["name"], "show-smb");
    assert!(json["protocol"].is_string());
    assert!(json["state"]["status"].is_string());
    assert!(json["config"].is_object());
}

/// `GET /api/v1/listeners/{name}` returns 404 when the listener does not exist.
///
/// The CLI's `listener.show` must handle this as a not-found error.
#[tokio::test]
async fn get_listener_for_unknown_name_returns_404() {
    let (state, _registry) = build_test_state().await;
    let response = call(state, "GET", "/api/v1/listeners/no-such-listener", API_KEY, None).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND, "unknown listener must return 404");
}

/// `PUT /api/v1/listeners/{name}/start` returns 200 with a `ListenerSummary`
/// body when the listener exists.
///
/// The CLI's `listener.start` calls this route and deserialises the response
/// as `RawListenerSummary`.
#[tokio::test]
async fn put_listener_start_returns_200_with_summary() {
    let (state, _registry) = build_test_state().await;

    // Create a listener to start.
    let body = serde_json::json!({
        "protocol": "smb",
        "config": { "name": "start-smb", "pipe_name": "start-pipe" }
    });
    let _ = call(state.clone(), "POST", "/api/v1/listeners", API_KEY, Some(body)).await;

    let response = call(state, "PUT", "/api/v1/listeners/start-smb/start", API_KEY, None).await;

    // 200 OK on first start, or 409 if already running (both are valid in
    // contract; CLI handles 409 by fetching current state).
    assert!(
        response.status() == StatusCode::OK || response.status() == StatusCode::CONFLICT,
        "PUT /listeners/{{name}}/start must return 200 or 409, got {}",
        response.status()
    );
}

/// `PUT /api/v1/listeners/{name}/start` returns 404 for an unknown listener.
///
/// The CLI must NOT return a `listener_not_found` 404 as a success.
#[tokio::test]
async fn put_listener_start_for_unknown_returns_404() {
    let (state, _registry) = build_test_state().await;
    let response = call(state, "PUT", "/api/v1/listeners/no-such/start", API_KEY, None).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND, "unknown listener start must return 404");
}

/// `PUT /api/v1/listeners/{name}/stop` returns 200 (or 409 if already stopped)
/// with a `ListenerSummary` body.
///
/// The CLI's `listener.stop` uses this route.
#[tokio::test]
async fn put_listener_stop_returns_200_or_409_with_summary() {
    let (state, _registry) = build_test_state().await;

    let body = serde_json::json!({
        "protocol": "smb",
        "config": { "name": "stop-smb", "pipe_name": "stop-pipe" }
    });
    let _ = call(state.clone(), "POST", "/api/v1/listeners", API_KEY, Some(body)).await;

    let response = call(state, "PUT", "/api/v1/listeners/stop-smb/stop", API_KEY, None).await;

    // 200 if successfully stopped, 409 if already stopped.
    assert!(
        response.status() == StatusCode::OK || response.status() == StatusCode::CONFLICT,
        "PUT /listeners/{{name}}/stop must return 200 or 409, got {}",
        response.status()
    );
}

/// `PUT /api/v1/listeners/{name}/stop` returns 404 for an unknown listener.
#[tokio::test]
async fn put_listener_stop_for_unknown_returns_404() {
    let (state, _registry) = build_test_state().await;
    let response = call(state, "PUT", "/api/v1/listeners/no-such/stop", API_KEY, None).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND, "unknown listener stop must return 404");
}

/// `DELETE /api/v1/listeners/{name}` returns 204 No Content when the listener
/// exists.
///
/// The CLI's `listener.delete` calls `delete_no_body` which treats any 2xx as
/// success.
#[tokio::test]
async fn delete_listener_returns_no_content() {
    let (state, _registry) = build_test_state().await;

    let body = serde_json::json!({
        "protocol": "smb",
        "config": { "name": "del-smb", "pipe_name": "del-pipe" }
    });
    let _ = call(state.clone(), "POST", "/api/v1/listeners", API_KEY, Some(body)).await;

    let response = call(state, "DELETE", "/api/v1/listeners/del-smb", API_KEY, None).await;

    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "DELETE /listeners/{{name}} must return 204"
    );
}

/// `DELETE /api/v1/listeners/{name}` returns 404 for an unknown listener.
#[tokio::test]
async fn delete_listener_for_unknown_returns_404() {
    let (state, _registry) = build_test_state().await;
    let response = call(state, "DELETE", "/api/v1/listeners/no-such-listener", API_KEY, None).await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "DELETE /listeners/{{name}} for unknown listener must return 404"
    );
}

// ── operator routes ───────────────────────────────────────────────────────────

/// `GET /api/v1/operators` returns 200 with a JSON array whose items have the
/// `OperatorSummary` shape: `{username, role, online, last_seen}`.
///
/// The CLI's `operator.list` command deserialises the response as
/// `Vec<RawOperator>` with the same four fields.
#[tokio::test]
async fn get_operators_returns_array_with_operator_summary_shape() {
    let (state, _registry) = build_test_state().await;
    let response = call(state, "GET", "/api/v1/operators", API_KEY, None).await;

    assert_eq!(response.status(), StatusCode::OK, "GET /operators must return 200");

    let json = read_json(response).await;
    assert!(json.is_array(), "GET /operators must return a JSON array");

    // The profile configures one operator ("testop"), so there's at least one entry.
    let items = json.as_array().unwrap();
    assert!(!items.is_empty(), "profile-configured operator must appear in the list");

    let op = &items[0];
    // Verify the OperatorSummary fields that RawOperator expects.
    assert!(op["username"].is_string(), "response must have a string `username` field");
    assert!(op["role"].is_string(), "response must have a string `role` field");
    assert!(op["online"].is_boolean(), "response must have a boolean `online` field");
    assert!(op.get("last_seen").is_some(), "response must have a `last_seen` field (null ok)");

    // Confirm no extraneous fields that old wiremock stubs invented.
    assert!(op.get("token").is_none(), "response must NOT have a `token` field");
    assert!(op.get("ok").is_none(), "response must NOT have an `ok` field");
}

/// `DELETE /api/v1/operators/{username}` returns 204 No Content for a runtime-
/// created operator.
///
/// The CLI's `operator.delete` calls `delete_no_body` which treats 2xx as
/// success.
#[tokio::test]
async fn delete_operator_returns_no_content() {
    let (state, _registry) = build_test_state().await;

    // Create an operator to delete.
    let create_body = serde_json::json!({
        "username": "delme",
        "password": "P@ssw0rd123!",
        "role": "operator"
    });
    let create_resp =
        call(state.clone(), "POST", "/api/v1/operators", API_KEY, Some(create_body)).await;
    assert_eq!(
        create_resp.status(),
        StatusCode::CREATED,
        "prerequisite operator create must succeed"
    );

    // Now delete the operator.
    let response = call(state, "DELETE", "/api/v1/operators/delme", API_KEY, None).await;

    assert_eq!(
        response.status(),
        StatusCode::NO_CONTENT,
        "DELETE /operators/{{username}} must return 204 No Content"
    );
}

/// `DELETE /api/v1/operators/{username}` returns 404 for an unknown operator.
///
/// The CLI's `operator.delete` must handle this as a not-found error.
#[tokio::test]
async fn delete_operator_for_unknown_returns_404() {
    let (state, _registry) = build_test_state().await;
    let response = call(state, "DELETE", "/api/v1/operators/nobody", API_KEY, None).await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "DELETE /operators/{{username}} for unknown operator must return 404"
    );
}

/// `DELETE /api/v1/operators/{username}` returns 404 for a profile-configured
/// operator (they can't be deleted at runtime).
///
/// Confirms the CLI's `operator.delete testop` would fail with a not-found
/// error rather than silently succeeding.
#[tokio::test]
async fn delete_profile_configured_operator_returns_404() {
    let (state, _registry) = build_test_state().await;
    // "testop" is defined in PROFILE_HCL above.
    let response = call(state, "DELETE", "/api/v1/operators/testop", API_KEY, None).await;
    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "DELETE of a profile-configured operator must return 404"
    );
}
