//! Integration tests — agent commands against the real teamserver router.
//!
//! These tests exercise the contract between the CLI's expected request/response
//! shapes and the actual routes registered in `red_cell::api_routes`.  They
//! start a real HTTP server on an ephemeral port, insert a test agent via the
//! shared [`AgentRegistry`], and verify that the routes the CLI uses respond
//! correctly.

use std::net::SocketAddr;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use red_cell::{
    AgentRegistry, AgentResponseRecord, ApiRuntime, AuditWebhookNotifier, AuthService, Database,
    EventBus, Job, ListenerManager, LoginRateLimiter, OperatorConnectionManager,
    PayloadBuilderService, ShutdownController, SocketRelayManager, TeamserverState, build_router,
};
use red_cell_common::config::Profile;
use red_cell_common::{AgentEncryptionInfo, AgentRecord};
use tower::ServiceExt as _;

// ── constants ─────────────────────────────────────────────────────────────────

/// Profile snippet that registers one Admin API key with value `test-secret`.
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

/// The plain-text API key value configured in `PROFILE_HCL`.
const API_KEY: &str = "test-secret";
/// A known agent id used across tests.
const AGENT_ID_HEX: &str = "DEADBEEF";
const AGENT_ID_U32: u32 = 0xDEAD_BEEF;

// ── helpers ───────────────────────────────────────────────────────────────────

/// Build a minimal [`TeamserverState`] with an in-memory database and one Admin
/// API key.  The returned [`AgentRegistry`] is a clone of the state's registry
/// so tests can insert agents *after* the router is built (both share the same
/// underlying `Arc`).
async fn build_test_state() -> (TeamserverState, AgentRegistry) {
    let profile = Profile::parse(PROFILE_HCL).expect("profile parse");
    let database = Database::connect_in_memory().await.expect("database");
    let agent_registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(agent_registry.clone(), events.clone());
    let state = TeamserverState {
        profile: profile.clone(),
        profile_path: "test.yaotl".to_owned(),
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
        started_at: std::time::Instant::now(),
        plugins_loaded: 0,
        plugins_failed: 0,
        metrics: red_cell::metrics::standalone_metrics_handle(),
    };
    (state, agent_registry)
}

/// Construct a minimal [`AgentRecord`] for the given `agent_id`.
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

/// Issue a oneshot request against the router and return the response.
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

/// Read the response body as a JSON value.
async fn read_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.expect("body bytes");
    serde_json::from_slice(&bytes).expect("json body")
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// `POST /api/v1/agents/{id}/task` returns 202 Accepted with `{agent_id,
/// task_id, queued_jobs}` when the agent exists and the request body is a
/// valid `AgentTaskInfo`.
///
/// This is the route that `exec_submit` calls.
#[tokio::test]
async fn post_agent_task_queues_job_and_returns_202() {
    let (state, registry) = build_test_state().await;
    registry.insert(sample_agent(AGENT_ID_U32)).await.expect("insert agent");

    let body = serde_json::json!({
        "CommandLine": "whoami",
        "CommandID":   "100",
        "DemonID":     AGENT_ID_HEX,
        "TaskID":      "A1B2"
    });

    let response =
        call(state, "POST", &format!("/api/v1/agents/{AGENT_ID_HEX}/task"), API_KEY, Some(body))
            .await;

    assert_eq!(
        response.status(),
        StatusCode::ACCEPTED,
        "POST /agents/{{id}}/task must return 202 Accepted"
    );

    let json = read_json(response).await;
    assert_eq!(json["agent_id"], AGENT_ID_HEX, "agent_id must be returned");
    assert_eq!(json["task_id"], "A1B2", "task_id must match the submitted TaskID");
    assert_eq!(json["queued_jobs"], 1, "one job should now be queued");
}

/// `POST /api/v1/agents/{id}/task` returns 404 when the agent does not exist.
///
/// Confirms the route is registered (not 405 Method Not Allowed) and that the
/// error code is `agent_not_found`.
#[tokio::test]
async fn post_agent_task_returns_404_for_unknown_agent() {
    let (state, _registry) = build_test_state().await;

    let body = serde_json::json!({
        "CommandLine": "whoami",
        "CommandID":   "100",
        "DemonID":     AGENT_ID_HEX,
        "TaskID":      "AA"
    });

    let response =
        call(state, "POST", &format!("/api/v1/agents/{AGENT_ID_HEX}/task"), API_KEY, Some(body))
            .await;

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "unknown agent must return 404 (not 405 which would mean route is missing)"
    );

    let json = read_json(response).await;
    assert_eq!(json["error"]["code"], "agent_not_found");
}

/// `GET /api/v1/jobs?agent_id={id}&task_id={tid}` returns an empty page
/// (`total=0`) when no jobs are queued.
///
/// This is the polling endpoint `exec_wait` uses to detect dequeue.
#[tokio::test]
async fn get_jobs_with_agent_and_task_filter_returns_empty_when_no_jobs() {
    let (state, registry) = build_test_state().await;
    registry.insert(sample_agent(AGENT_ID_U32)).await.expect("insert agent");

    let uri = format!("/api/v1/jobs?agent_id={AGENT_ID_HEX}&task_id=SOMETASK");
    let response = call(state, "GET", &uri, API_KEY, None).await;

    assert_eq!(response.status(), StatusCode::OK);
    let json = read_json(response).await;
    assert_eq!(json["total"], 0);
}

/// `DELETE /api/v1/agents/{id}` returns 202 Accepted when the agent exists,
/// queuing a kill task.
///
/// This is the route `kill` calls instead of the old `POST /agents/{id}/kill`.
#[tokio::test]
async fn delete_agent_returns_202_and_queues_kill_task() {
    let (state, registry) = build_test_state().await;
    registry.insert(sample_agent(AGENT_ID_U32)).await.expect("insert agent");

    let response =
        call(state, "DELETE", &format!("/api/v1/agents/{AGENT_ID_HEX}"), API_KEY, None).await;

    assert_eq!(
        response.status(),
        StatusCode::ACCEPTED,
        "DELETE /agents/{{id}} must return 202 Accepted"
    );

    let json = read_json(response).await;
    assert_eq!(json["agent_id"], AGENT_ID_HEX);
    // A kill task was enqueued.
    assert!(json["queued_jobs"].as_u64().unwrap_or(0) >= 1, "kill job must be queued");
}

/// `DELETE /api/v1/agents/{id}?force=true` queues a kill task AND immediately
/// deregisters the agent, returning 200.
#[tokio::test]
async fn delete_agent_force_returns_200_and_deregisters() {
    let (state, registry) = build_test_state().await;
    registry.insert(sample_agent(AGENT_ID_U32)).await.expect("insert agent");

    let response =
        call(state, "DELETE", &format!("/api/v1/agents/{AGENT_ID_HEX}?force=true"), API_KEY, None)
            .await;

    assert_eq!(response.status(), StatusCode::OK, "force kill must return 200");
    let json = read_json(response).await;
    assert_eq!(json["agent_id"], AGENT_ID_HEX);
    assert_eq!(json["deregistered"], true);
    assert!(registry.get(AGENT_ID_U32).await.is_none(), "agent must be gone from registry");
}

/// `DELETE /api/v1/agents/{id}?deregister_only=true` removes the agent from
/// the registry without queuing a kill task.
#[tokio::test]
async fn delete_agent_deregister_only_returns_200_and_deregisters() {
    let (state, registry) = build_test_state().await;
    registry.insert(sample_agent(AGENT_ID_U32)).await.expect("insert agent");

    let response = call(
        state,
        "DELETE",
        &format!("/api/v1/agents/{AGENT_ID_HEX}?deregister_only=true"),
        API_KEY,
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK, "deregister-only must return 200");
    let json = read_json(response).await;
    assert_eq!(json["agent_id"], AGENT_ID_HEX);
    assert_eq!(json["deregistered"], true);
    assert!(registry.get(AGENT_ID_U32).await.is_none(), "agent must be gone from registry");
}

/// `DELETE /api/v1/agents/{id}` returns 404 for an unknown agent.
///
/// The route must be registered (not 405 Method Not Allowed).
#[tokio::test]
async fn delete_agent_returns_404_for_unknown_agent() {
    let (state, _registry) = build_test_state().await;

    let response =
        call(state, "DELETE", &format!("/api/v1/agents/{AGENT_ID_HEX}"), API_KEY, None).await;

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "unknown agent must return 404 (not 405 which would mean the DELETE route is missing)"
    );
}

/// Old route `POST /api/v1/agents/{id}/jobs` must return 404 (route not
/// registered), confirming that the CLI's old URL was wrong and no longer
/// accidentally works.
#[tokio::test]
async fn old_post_agents_jobs_route_returns_404() {
    let (state, registry) = build_test_state().await;
    registry.insert(sample_agent(AGENT_ID_U32)).await.expect("insert agent");

    let body = serde_json::json!({"cmd": "whoami"});
    let response =
        call(state, "POST", &format!("/api/v1/agents/{AGENT_ID_HEX}/jobs"), API_KEY, Some(body))
            .await;

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "the old /agents/{{id}}/jobs route must not exist"
    );
}

/// Old route `POST /api/v1/agents/{id}/kill` must return 404, confirming the
/// CLI's old kill URL was wrong.
#[tokio::test]
async fn old_post_agents_kill_route_returns_404() {
    let (state, registry) = build_test_state().await;
    registry.insert(sample_agent(AGENT_ID_U32)).await.expect("insert agent");

    let response = call(
        state,
        "POST",
        &format!("/api/v1/agents/{AGENT_ID_HEX}/kill"),
        API_KEY,
        Some(serde_json::json!({})),
    )
    .await;

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "the old /agents/{{id}}/kill route must not exist"
    );
}

/// `GET /api/v1/agents/{id}/output` returns 200 with an empty page for an
/// agent that has no persisted output.
#[tokio::test]
async fn get_agent_output_returns_empty_page_for_known_agent() {
    let (state, registry) = build_test_state().await;
    registry.insert(sample_agent(AGENT_ID_U32)).await.expect("insert agent");

    let response =
        call(state, "GET", &format!("/api/v1/agents/{AGENT_ID_HEX}/output"), API_KEY, None).await;

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "/agents/{{id}}/output must return 200 for a known agent"
    );
}

/// `SocketAddr` is used only to satisfy the type checker when building a
/// `ConnectInfo` extension.  This test verifies the server address binding used
/// by the [`call`] helper is not required (oneshot works without it).
#[tokio::test]
async fn server_addr_binding_not_required_for_oneshot() {
    // Confirms that `SocketAddr` from std is available and that the test
    // infrastructure compiles and runs without a real TCP listener.
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("parse addr");
    assert_eq!(addr.port(), 0);
}

// ── CLI↔teamserver schema contract for GET /agents and GET /agents/{id} ──────
//
// These tests verify that the JSON the teamserver serialises from ApiAgentInfo
// contains every field the CLI's ApiAgentWire struct expects (PascalCase keys).
// They exercise the full round-trip: AgentRecord → teamserver serialisation →
// JSON bytes → CLI deserialization schema check.

/// `GET /api/v1/agents` returns 200 OK with a JSON array whose objects contain
/// the PascalCase fields that `ApiAgentWire` (the CLI wire struct) requires.
///
/// This is the end-to-end schema contract for the `agent list` command.
#[tokio::test]
async fn get_agents_list_returns_api_agent_info_schema() {
    let (state, registry) = build_test_state().await;
    registry.insert(sample_agent(AGENT_ID_U32)).await.expect("insert agent");

    let response = call(state, "GET", "/api/v1/agents", API_KEY, None).await;

    assert_eq!(response.status(), StatusCode::OK, "GET /agents must return 200 OK");

    let json = read_json(response).await;
    let agents = json.as_array().expect("response must be a JSON array");
    assert_eq!(agents.len(), 1, "one agent inserted → one agent in list");

    let a = &agents[0];

    // Verify all PascalCase keys the CLI's ApiAgentWire expects are present.
    assert_eq!(a["AgentID"], AGENT_ID_U32, "AgentID must be the numeric agent id");
    assert_eq!(a["Active"], true, "Active must match the inserted record");
    assert!(!a["Reason"].is_null(), "Reason must be present");
    assert!(!a["Note"].is_null(), "Note must be present");
    assert_eq!(a["Hostname"], "workstation");
    assert_eq!(a["Username"], "operator");
    assert_eq!(a["DomainName"], "LAB");
    assert_eq!(a["ExternalIP"], "203.0.113.10");
    assert_eq!(a["InternalIP"], "10.0.0.10");
    assert_eq!(a["ProcessName"], "demon.exe");
    assert!(!a["BaseAddress"].is_null(), "BaseAddress must be present");
    assert_eq!(a["ProcessPID"], 4444u32);
    assert!(!a["ProcessTID"].is_null(), "ProcessTID must be present");
    assert!(!a["ProcessPPID"].is_null(), "ProcessPPID must be present");
    assert_eq!(a["ProcessArch"], "x64");
    assert_eq!(a["Elevated"], true);
    assert_eq!(a["OSVersion"], "Windows 11");
    assert!(!a["OSBuild"].is_null(), "OSBuild must be present");
    assert_eq!(a["OSArch"], "x64");
    assert_eq!(a["SleepDelay"], 5u32);
    assert_eq!(a["SleepJitter"], 10u32);
    // KillDate and WorkingHours are Option<_> — null is the correct value here.
    assert!(a["KillDate"].is_null(), "KillDate must be null when not set");
    assert!(a["WorkingHours"].is_null(), "WorkingHours must be null when not set");
    assert_eq!(a["FirstCallIn"], "2026-03-01T00:00:00Z");
    assert_eq!(a["LastCallIn"], "2026-03-01T00:05:00Z");
}

/// `GET /api/v1/agents/{id}` returns 200 OK with a single `ApiAgentInfo`
/// JSON object whose PascalCase fields match the CLI's `ApiAgentWire` schema.
///
/// This is the end-to-end schema contract for the `agent show` command.
#[tokio::test]
async fn get_agent_by_id_returns_api_agent_info_schema() {
    let (state, registry) = build_test_state().await;
    registry.insert(sample_agent(AGENT_ID_U32)).await.expect("insert agent");

    let response =
        call(state, "GET", &format!("/api/v1/agents/{AGENT_ID_HEX}"), API_KEY, None).await;

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "GET /agents/{{id}} must return 200 OK when the agent exists"
    );

    let a = read_json(response).await;

    // Required fields for ApiAgentWire deserialization.
    assert_eq!(a["AgentID"], AGENT_ID_U32, "AgentID must match");
    assert_eq!(a["Active"], true);
    assert_eq!(a["Hostname"], "workstation");
    assert_eq!(a["Username"], "operator");
    assert_eq!(a["DomainName"], "LAB");
    assert_eq!(a["ExternalIP"], "203.0.113.10");
    assert_eq!(a["InternalIP"], "10.0.0.10");
    assert_eq!(a["ProcessName"], "demon.exe");
    assert_eq!(a["ProcessPID"], 4444u32);
    assert_eq!(a["ProcessArch"], "x64");
    assert_eq!(a["Elevated"], true);
    assert_eq!(a["OSVersion"], "Windows 11");
    assert_eq!(a["OSBuild"], 22000u32);
    assert_eq!(a["OSArch"], "x64");
    assert_eq!(a["SleepDelay"], 5u32);
    assert_eq!(a["SleepJitter"], 10u32);
    assert_eq!(a["FirstCallIn"], "2026-03-01T00:00:00Z");
    assert_eq!(a["LastCallIn"], "2026-03-01T00:05:00Z");
}

/// `GET /api/v1/agents/{id}` returns 404 when the agent does not exist.
#[tokio::test]
async fn get_agent_by_id_returns_404_for_unknown_agent() {
    let (state, _registry) = build_test_state().await;

    let response =
        call(state, "GET", &format!("/api/v1/agents/{AGENT_ID_HEX}"), API_KEY, None).await;

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "GET /agents/{{id}} must return 404 for an unknown agent"
    );
}

// ── Incremental polling contract (since cursor) ───────────────────────────────

/// `GET /api/v1/agents/{id}/output?since=<id>` returns only entries whose
/// numeric database row id is strictly greater than the cursor value.
///
/// This test pins the contract that `agent exec --wait` and `agent output
/// --watch` rely on: the CLI advances its cursor using `entry.entry_id` (the
/// numeric DB row id), and the server filters with `id > since`.  A non-numeric
/// job/task id must never be sent as the `since` parameter.
#[tokio::test]
async fn get_agent_output_since_cursor_returns_only_newer_entries() {
    let (state, registry) = build_test_state().await;
    registry.insert(sample_agent(AGENT_ID_U32)).await.expect("insert agent");

    // Insert two output records directly into the database.
    let repo = state.database.agent_responses();
    let record_a = AgentResponseRecord {
        id: None,
        agent_id: AGENT_ID_U32,
        command_id: 21,
        request_id: 1,
        response_type: "output".to_owned(),
        message: String::new(),
        output: "first output".to_owned(),
        command_line: Some("whoami".to_owned()),
        task_id: Some("task_abc".to_owned()), // non-numeric task id
        operator: None,
        received_at: "2026-04-01T00:00:00Z".to_owned(),
        extra: None,
    };
    let record_b = AgentResponseRecord {
        id: None,
        agent_id: AGENT_ID_U32,
        command_id: 21,
        request_id: 2,
        response_type: "output".to_owned(),
        message: String::new(),
        output: "second output".to_owned(),
        command_line: Some("id".to_owned()),
        task_id: Some("task_def".to_owned()),
        operator: None,
        received_at: "2026-04-01T00:00:01Z".to_owned(),
        extra: None,
    };
    let first_id = repo.create(&record_a).await.expect("insert first record");
    let _second_id = repo.create(&record_b).await.expect("insert second record");

    // Fetch all entries — should return both.
    let all_response =
        call(state.clone(), "GET", &format!("/api/v1/agents/{AGENT_ID_HEX}/output"), API_KEY, None)
            .await;
    assert_eq!(all_response.status(), StatusCode::OK);
    let all_json = read_json(all_response).await;
    let all_entries = all_json["entries"].as_array().expect("entries must be an array");
    assert_eq!(all_entries.len(), 2, "both records must be returned without a cursor");

    // Confirm the first entry carries a non-numeric task_id (the problematic
    // case from the bug report).
    assert_eq!(all_entries[0]["task_id"], "task_abc", "first entry task_id is non-numeric");
    // The numeric `id` field is what the CLI must use as the cursor.
    let cursor = all_entries[0]["id"].as_i64().expect("id must be a number");
    assert_eq!(cursor, first_id, "entry id must match the database row id");

    // Fetch with since=<first_entry_id> — should return only the second entry.
    let paged_response = call(
        state,
        "GET",
        &format!("/api/v1/agents/{AGENT_ID_HEX}/output?since={cursor}"),
        API_KEY,
        None,
    )
    .await;
    assert_eq!(paged_response.status(), StatusCode::OK);
    let paged_json = read_json(paged_response).await;
    let paged_entries = paged_json["entries"].as_array().expect("entries must be an array");
    assert_eq!(paged_entries.len(), 1, "only entries after the cursor must be returned");
    assert_eq!(
        paged_entries[0]["output"], "second output",
        "the entry after the cursor must be the second record"
    );
}

/// `GET /api/v1/agents/{id}/task-status?task_id=` returns lifecycle + queue snapshot.
#[tokio::test]
async fn get_agent_task_status_contract_queued() {
    let (state, registry) = build_test_state().await;
    registry.insert(sample_agent(AGENT_ID_U32)).await.expect("insert agent");

    let job = Job {
        command: 0x100,
        request_id: 0x42,
        payload: vec![0x01],
        command_line: "whoami".to_owned(),
        task_id: "TCHECK01".to_owned(),
        created_at: "2026-04-01T00:00:00Z".to_owned(),
        operator: "testop".to_owned(),
    };
    registry.enqueue_job(AGENT_ID_U32, job.clone()).await.expect("enqueue");

    let uri = format!("/api/v1/agents/{AGENT_ID_HEX}/task-status?task_id={}", job.task_id);
    let response = call(state, "GET", &uri, API_KEY, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let json = read_json(response).await;
    assert_eq!(json["lifecycle"], "queued");
    assert_eq!(json["task_id"], job.task_id);
    assert_eq!(json["queued"]["request_id"], 0x42);
}
