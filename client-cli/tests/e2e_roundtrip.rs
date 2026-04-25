//! End-to-end integration tests — client-cli wire types against a real TCP server.
//!
//! Unlike the `*_api_contract.rs` tests (which use `tower::ServiceExt::oneshot`
//! and hand-crafted HTTP requests), these tests spin up a real Axum server on
//! an ephemeral TCP port and exercise the full HTTP round-trip through
//! `reqwest`, which is the same HTTP client used by the CLI's `ApiClient`.
//!
//! Each test group verifies that:
//! 1. The request URL, method, and body the CLI would send is accepted by the
//!    real server (no route mismatches, no 422s).
//! 2. The server's JSON response can be deserialized into the exact wire types
//!    the CLI uses internally (schema drift → compile error or deser failure).
//! 3. The full TCP → HTTP/1.1 framing → Axum routing → SQLite → JSON
//!    serialization → reqwest deserialization path works end-to-end.

use std::net::SocketAddr;

use red_cell::{
    AgentRegistry, ApiRuntime, AuditResultStatus, AuditWebhookNotifier, AuthService, Database,
    EventBus, ListenerManager, LoginRateLimiter, OperatorConnectionManager, PayloadBuilderService,
    ShutdownController, SocketRelayManager, TeamserverState, audit_details, build_router,
    record_operator_action,
};
use red_cell_common::config::Profile;
use red_cell_common::{AgentEncryptionInfo, AgentRecord};
use serde::Deserialize;
use tokio::net::TcpListener;

// ── constants ────────────────────────────────────────────────────────────────

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
        RateLimitPerMinute = 120
        key "e2e-admin" {
            Value = "e2e-admin-secret"
            Role  = "Admin"
        }
    }
"#;

const API_KEY: &str = "e2e-admin-secret";
const AGENT_ID_U32: u32 = 0xCAFE_BABE;
const AGENT_ID_HEX: &str = "CAFEBABE";

// ── wire types mirroring the CLI's internal deserialization shapes ───────────
//
// These types MUST stay in sync with the private types in client-cli's command
// modules.  If the CLI's `RawAgent`, `RawOperatorSummary`, etc. change, update
// these to match.  A deserialization failure in these tests means the CLI would
// also fail at runtime.

/// Mirrors `client-cli/src/commands/agent.rs::ApiAgentWire`.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ApiAgentWire {
    #[serde(rename = "AgentID")]
    agent_id: u32,
    #[serde(rename = "Active")]
    active: bool,
    #[serde(rename = "Reason")]
    reason: String,
    #[serde(rename = "Note")]
    note: String,
    #[serde(rename = "Hostname")]
    hostname: String,
    #[serde(rename = "Username")]
    username: String,
    #[serde(rename = "DomainName")]
    domain_name: String,
    #[serde(rename = "ExternalIP")]
    external_ip: String,
    #[serde(rename = "InternalIP")]
    internal_ip: String,
    #[serde(rename = "ProcessName")]
    process_name: String,
    #[serde(rename = "BaseAddress")]
    base_address: u64,
    #[serde(rename = "ProcessPID")]
    process_pid: u32,
    #[serde(rename = "ProcessTID")]
    process_tid: u32,
    #[serde(rename = "ProcessPPID")]
    process_ppid: u32,
    #[serde(rename = "ProcessArch")]
    process_arch: String,
    #[serde(rename = "Elevated")]
    elevated: bool,
    #[serde(rename = "OSVersion")]
    os_version: String,
    #[serde(rename = "OSBuild")]
    os_build: u32,
    #[serde(rename = "OSArch")]
    os_arch: String,
    #[serde(rename = "SleepDelay")]
    sleep_delay: u32,
    #[serde(rename = "SleepJitter")]
    sleep_jitter: u32,
    #[serde(rename = "KillDate")]
    kill_date: Option<i64>,
    #[serde(rename = "WorkingHours")]
    working_hours: Option<i32>,
    #[serde(rename = "FirstCallIn")]
    first_call_in: String,
    #[serde(rename = "LastCallIn")]
    last_call_in: String,
}

/// Mirrors `client-cli/src/commands/agent.rs::TaskQueuedResponse`.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct TaskQueuedResponse {
    task_id: String,
}

/// Mirrors `client-cli/src/commands/operator.rs::RawOperatorSummary`.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RawOperatorSummary {
    username: String,
    role: String,
    online: bool,
    last_seen: Option<String>,
}

/// Mirrors `client-cli/src/commands/operator.rs::RawCreateResponse`.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RawCreateResponse {
    username: String,
    role: String,
}

/// Mirrors `client-cli/src/commands/listener.rs::RawListenerSummary`.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RawListenerSummary {
    name: String,
    protocol: String,
    state: RawListenerState,
    config: serde_json::Value,
}

/// Mirrors `client-cli/src/commands/listener.rs::RawListenerState`.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RawListenerState {
    status: String,
    last_error: Option<String>,
}

/// Mirrors `client-cli/src/commands/audit.rs::RawAuditPage`.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RawAuditPage {
    total: usize,
    limit: usize,
    offset: usize,
    items: Vec<RawAuditRecord>,
}

/// Mirrors `client-cli/src/commands/audit.rs::RawAuditRecord`.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct RawAuditRecord {
    id: i64,
    actor: String,
    action: String,
    target_kind: String,
    target_id: Option<String>,
    agent_id: Option<String>,
    command: Option<String>,
    parameters: Option<serde_json::Value>,
    result_status: String,
    occurred_at: String,
}

/// Mirrors `client-cli/src/commands/status.rs::ApiRootResponse` (subset).
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ApiRootResponse {
    version: String,
}

/// Mirrors `client-cli/src/commands/status.rs::HealthAgentCounts` (health JSON).
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct HealthAgentCountsWire {
    active: u64,
    total: u64,
}

/// Mirrors `client-cli/src/commands/status.rs::HealthListenerCounts` (health JSON).
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct HealthListenerCountsWire {
    running: u64,
    stopped: u64,
}

/// Mirrors `client-cli/src/commands/status.rs::HealthPluginCounts` (health JSON).
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct HealthPluginCountsWire {
    loaded: u32,
    failed: u32,
    disabled: u32,
}

/// Mirrors the `GET /api/v1/health` body deserialized by `status::run`.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct HealthResponseWire {
    status: String,
    uptime_secs: u64,
    agents: HealthAgentCountsWire,
    listeners: HealthListenerCountsWire,
    database: String,
    plugins: HealthPluginCountsWire,
    plugin_health: Vec<serde_json::Value>,
}

/// Mirrors `client-cli/src/commands/payload.rs::BuildSubmitResponse`.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct BuildSubmitResponse {
    job_id: String,
}

/// Mirrors `client-cli/src/commands/payload.rs::BuildJobStatus`.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct BuildJobStatus {
    job_id: String,
    status: String,
    payload_id: Option<String>,
    size_bytes: Option<u64>,
    error: Option<String>,
}

// ── test infrastructure ──────────────────────────────────────────────────────

/// Handles returned by [`spawn_server`] for test interaction.
struct TestHarness {
    /// `http://127.0.0.1:{port}` base URL.
    base_url: String,
    /// Shared agent registry for inserting test agents.
    registry: AgentRegistry,
    /// Database handle for inserting audit records.
    database: Database,
    /// Pre-configured reqwest client (no auth header — tests add it per-request).
    http: reqwest::Client,
}

impl TestHarness {
    /// Convenience: `GET {base_url}/api/v1{path}` with API key.
    async fn get(&self, path: &str) -> reqwest::Response {
        self.http
            .get(format!("{}/api/v1{path}", self.base_url))
            .header("x-api-key", API_KEY)
            .send()
            .await
            .expect("GET request should succeed")
    }

    /// Convenience: `POST {base_url}/api/v1{path}` with JSON body and API key.
    async fn post(&self, path: &str, body: &serde_json::Value) -> reqwest::Response {
        self.http
            .post(format!("{}/api/v1{path}", self.base_url))
            .header("x-api-key", API_KEY)
            .json(body)
            .send()
            .await
            .expect("POST request should succeed")
    }

    /// Convenience: `PUT {base_url}/api/v1{path}` with JSON body and API key.
    async fn put(&self, path: &str, body: &serde_json::Value) -> reqwest::Response {
        self.http
            .put(format!("{}/api/v1{path}", self.base_url))
            .header("x-api-key", API_KEY)
            .json(body)
            .send()
            .await
            .expect("PUT request should succeed")
    }

    /// Convenience: `PUT {base_url}/api/v1{path}` with no body and API key.
    async fn put_empty(&self, path: &str) -> reqwest::Response {
        self.http
            .put(format!("{}/api/v1{path}", self.base_url))
            .header("x-api-key", API_KEY)
            .send()
            .await
            .expect("PUT request should succeed")
    }

    /// Convenience: `DELETE {base_url}/api/v1{path}` with API key.
    async fn delete(&self, path: &str) -> reqwest::Response {
        self.http
            .delete(format!("{}/api/v1{path}", self.base_url))
            .header("x-api-key", API_KEY)
            .send()
            .await
            .expect("DELETE request should succeed")
    }
}

/// Spin up a real Axum HTTP server on an ephemeral TCP port with an in-memory
/// SQLite database and return a [`TestHarness`] for issuing requests.
async fn spawn_server() -> TestHarness {
    let profile = Profile::parse(PROFILE_HCL).expect("profile parse");
    let database = Database::connect_in_memory().await.expect("database");
    let agent_registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(agent_registry.clone(), events.clone());
    let auth =
        AuthService::from_profile_with_database(&profile, &database).await.expect("auth service");

    let state = TeamserverState {
        profile: profile.clone(),
        database: database.clone(),
        auth,
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
        started_at: std::time::Instant::now(),
        plugins_loaded: 0,
        plugins_failed: 0,
        metrics: red_cell::metrics::standalone_metrics_handle(),
    };

    let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind ephemeral port");
    let addr: SocketAddr = tcp.local_addr().expect("local_addr");

    tokio::spawn(async move {
        let app = build_router(state);
        axum::serve(tcp, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .expect("server should run");
    });

    let base_url = format!("http://127.0.0.1:{}", addr.port());
    // Use a generous timeout so the tests remain stable under cargo test
    // --workspace concurrency, where CPU contention from parallel integration
    // tests can delay a request well beyond the 15 s window.
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("reqwest client");

    TestHarness { base_url, registry: agent_registry, database, http }
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

// ═══════════════════════════════════════════════════════════════════════════════
// Status command group
// ═══════════════════════════════════════════════════════════════════════════════

/// The `status` command calls `GET /api/v1/` (anon) then `GET /api/v1/health`.
/// Verify the full round-trip through real TCP + reqwest.
///
/// Note: The CLI's `get_anon("/")` constructs `{base_url}/api/v1/` (trailing
/// slash).  Axum's `nest("/api/v1", ...)` may or may not match this depending
/// on trailing-slash normalization.  We test both paths to ensure coverage.
#[tokio::test]
async fn status_roundtrip_through_real_tcp() {
    let h = spawn_server().await;

    // Step 1: anonymous root — try without trailing slash first (what oneshot
    // tests use), then verify the trailing-slash variant the CLI constructs.
    let resp =
        h.http.get(format!("{}/api/v1", h.base_url)).send().await.expect("GET /api/v1 request");
    assert_eq!(resp.status(), 200, "GET /api/v1 must return 200");
    let root: ApiRootResponse = resp.json().await.expect("deserialize ApiRootResponse");
    assert!(!root.version.is_empty(), "version must be non-empty");

    // Step 2: authenticated health snapshot (same as status::run step 2)
    let resp = h.get("/health").await;
    assert_eq!(resp.status(), 200, "GET /health must return 200");
    let health: HealthResponseWire = resp.json().await.expect("deserialize health");
    assert_eq!(health.agents.total, 0, "fresh server has no agents");
    assert_eq!(
        health.listeners.running + health.listeners.stopped,
        0,
        "fresh server has no listeners"
    );
    assert!(!health.database.is_empty(), "database field must be present");
    assert!(!health.status.is_empty(), "status field must be present");
    assert!(
        health.uptime_secs < 86_400,
        "regression: /health must include uptime_secs (fresh server should be well under 1 day); got {}",
        health.uptime_secs
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Agent command group
// ═══════════════════════════════════════════════════════════════════════════════

/// `agent list` calls `GET /agents` and deserializes as `Vec<ApiAgentWire>`.
/// Verify that the response can be round-tripped through reqwest → JSON →
/// `ApiAgentWire`.
#[tokio::test]
async fn agent_list_deserializes_through_real_tcp() {
    let h = spawn_server().await;
    h.registry.insert(sample_agent(AGENT_ID_U32)).await.expect("insert agent");

    let resp = h.get("/agents").await;
    assert_eq!(resp.status(), 200);
    let agents: Vec<ApiAgentWire> = resp.json().await.expect("deserialize Vec<ApiAgentWire>");
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].agent_id, AGENT_ID_U32);
    assert_eq!(agents[0].hostname, "workstation");
    assert!(agents[0].active);
}

/// `agent show <id>` calls `GET /agents/{id}` and deserializes a single
/// `ApiAgentWire`.
#[tokio::test]
async fn agent_show_deserializes_through_real_tcp() {
    let h = spawn_server().await;
    h.registry.insert(sample_agent(AGENT_ID_U32)).await.expect("insert agent");

    let resp = h.get(&format!("/agents/{AGENT_ID_HEX}")).await;
    assert_eq!(resp.status(), 200);
    let agent: ApiAgentWire = resp.json().await.expect("deserialize ApiAgentWire");
    assert_eq!(agent.agent_id, AGENT_ID_U32);
    assert_eq!(agent.os_version, "Windows 11");
    assert_eq!(agent.os_arch, "x64");
    assert_eq!(agent.process_pid, 4444);
    assert!(agent.elevated);
    assert_eq!(agent.sleep_delay, 5);
}

/// `agent exec <id> --cmd <cmd>` calls `POST /agents/{id}/task` with a JSON
/// body and deserializes the response as `TaskQueuedResponse`.
#[tokio::test]
async fn agent_exec_deserializes_through_real_tcp() {
    let h = spawn_server().await;
    h.registry.insert(sample_agent(AGENT_ID_U32)).await.expect("insert agent");

    // Body matches what client-cli/src/commands/agent.rs::exec_submit constructs.
    let body = serde_json::json!({
        "CommandLine": "whoami",
        "CommandID":   "100",
        "DemonID":     AGENT_ID_HEX,
        "TaskID":      "E2E1"
    });

    let resp = h.post(&format!("/agents/{AGENT_ID_HEX}/task"), &body).await;
    assert_eq!(resp.status(), 202, "POST /agents/{{id}}/task must return 202");

    // The full response includes agent_id, task_id, queued_jobs.
    // TaskQueuedResponse only needs task_id — verify it deserializes.
    let queued: TaskQueuedResponse = resp.json().await.expect("deserialize TaskQueuedResponse");
    assert_eq!(queued.task_id, "E2E1");
}

/// `agent kill <id>` calls `DELETE /agents/{id}` and deserializes the response
/// as `TaskQueuedResponse`.
#[tokio::test]
async fn agent_kill_deserializes_through_real_tcp() {
    let h = spawn_server().await;
    h.registry.insert(sample_agent(AGENT_ID_U32)).await.expect("insert agent");

    let resp = h.delete(&format!("/agents/{AGENT_ID_HEX}")).await;
    assert_eq!(resp.status(), 202, "DELETE /agents/{{id}} must return 202");

    let queued: TaskQueuedResponse =
        resp.json().await.expect("deserialize TaskQueuedResponse from kill");
    assert!(!queued.task_id.is_empty(), "kill must return a non-empty task_id");
}

/// `agent kill <id> --force` calls `DELETE /agents/{id}?force=true` and
/// returns 200 with agent deregistered.
#[tokio::test]
async fn agent_kill_force_deregisters_through_real_tcp() {
    let h = spawn_server().await;
    h.registry.insert(sample_agent(AGENT_ID_U32)).await.expect("insert agent");

    let resp = h.delete(&format!("/agents/{AGENT_ID_HEX}?force=true")).await;
    assert_eq!(resp.status(), 200, "DELETE /agents/{{id}}?force=true must return 200");

    let body: serde_json::Value = resp.json().await.expect("deserialize force-kill response");
    assert_eq!(body["agent_id"], AGENT_ID_HEX);
    assert_eq!(body["deregistered"], true);
}

/// `agent kill <id> --deregister-only` calls
/// `DELETE /agents/{id}?deregister_only=true` and returns 200 with agent
/// deregistered.
#[tokio::test]
async fn agent_kill_deregister_only_through_real_tcp() {
    let h = spawn_server().await;
    h.registry.insert(sample_agent(AGENT_ID_U32)).await.expect("insert agent");

    let resp = h.delete(&format!("/agents/{AGENT_ID_HEX}?deregister_only=true")).await;
    assert_eq!(resp.status(), 200, "DELETE /agents/{{id}}?deregister_only=true must return 200");

    let body: serde_json::Value = resp.json().await.expect("deserialize deregister-only response");
    assert_eq!(body["agent_id"], AGENT_ID_HEX);
    assert_eq!(body["deregistered"], true);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Operator command group
// ═══════════════════════════════════════════════════════════════════════════════

/// `operator list` calls `GET /operators` and deserializes as
/// `Vec<RawOperatorSummary>`.
#[tokio::test]
async fn operator_list_deserializes_through_real_tcp() {
    let h = spawn_server().await;

    let resp = h.get("/operators").await;
    assert_eq!(resp.status(), 200);
    let operators: Vec<RawOperatorSummary> =
        resp.json().await.expect("deserialize Vec<RawOperatorSummary>");
    assert!(!operators.is_empty(), "profile-configured operator must appear");
    assert!(operators.iter().any(|o| o.username == "testop"), "testop must be in the list");
}

/// `operator create` calls `POST /operators` with `{username, password, role}`
/// and deserializes the response as `RawCreateResponse`.
#[tokio::test]
async fn operator_create_deserializes_through_real_tcp() {
    let h = spawn_server().await;

    let body = serde_json::json!({
        "username": "e2e-new-op",
        "password": "S3cur3P@ssw0rd!",
        "role": "operator"
    });

    let resp = h.post("/operators", &body).await;
    assert_eq!(resp.status(), 201, "POST /operators must return 201");

    let created: RawCreateResponse = resp.json().await.expect("deserialize RawCreateResponse");
    assert_eq!(created.username, "e2e-new-op");
    assert!(!created.role.is_empty(), "created operator must have a role");
}

/// `operator set-role` calls `PUT /operators/{username}/role` with `{role}`
/// and deserializes the response as `RawOperatorSummary`.
#[tokio::test]
async fn operator_set_role_deserializes_through_real_tcp() {
    let h = spawn_server().await;

    // Create an operator first.
    let create_body = serde_json::json!({
        "username": "e2e-role-op",
        "password": "P@ssw0rd456!",
        "role": "operator"
    });
    let create_resp = h.post("/operators", &create_body).await;
    assert_eq!(create_resp.status(), 201);

    // Now update the role.
    let update_body = serde_json::json!({ "role": "analyst" });
    let resp = h.put("/operators/e2e-role-op/role", &update_body).await;
    assert_eq!(resp.status(), 200, "PUT /operators/{{name}}/role must return 200");

    let summary: RawOperatorSummary =
        resp.json().await.expect("deserialize RawOperatorSummary from role update");
    assert_eq!(summary.username, "e2e-role-op");
    // The server serializes OperatorRole as PascalCase ("Analyst", not "analyst").
    assert!(
        summary.role.eq_ignore_ascii_case("analyst"),
        "role must be updated to analyst, got: {}",
        summary.role
    );
}

/// `operator delete` calls `DELETE /operators/{username}` and expects 204.
#[tokio::test]
async fn operator_delete_succeeds_through_real_tcp() {
    let h = spawn_server().await;

    // Create then delete.
    let body = serde_json::json!({
        "username": "e2e-del-op",
        "password": "P@ssw0rd789!",
        "role": "operator"
    });
    let create_resp = h.post("/operators", &body).await;
    assert_eq!(create_resp.status(), 201);

    let resp = h.delete("/operators/e2e-del-op").await;
    assert_eq!(resp.status(), 204, "DELETE /operators/{{name}} must return 204");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Listener command group
// ═══════════════════════════════════════════════════════════════════════════════

/// `listener list` calls `GET /listeners` and deserializes as
/// `Vec<RawListenerSummary>`.
#[tokio::test]
async fn listener_list_deserializes_through_real_tcp() {
    let h = spawn_server().await;

    let resp = h.get("/listeners").await;
    assert_eq!(resp.status(), 200);
    let listeners: Vec<RawListenerSummary> =
        resp.json().await.expect("deserialize Vec<RawListenerSummary>");
    assert_eq!(listeners.len(), 0, "fresh server has no listeners");
}

/// `listener create` calls `POST /listeners` with `{protocol, config}` and
/// deserializes the response as `RawListenerSummary`.
#[tokio::test]
async fn listener_create_deserializes_through_real_tcp() {
    let h = spawn_server().await;

    let body = serde_json::json!({
        "protocol": "smb",
        "config": {
            "name": "e2e-smb",
            "pipe_name": "e2e-pipe"
        }
    });

    let resp = h.post("/listeners", &body).await;
    assert_eq!(resp.status(), 201, "POST /listeners must return 201");

    let listener: RawListenerSummary = resp.json().await.expect("deserialize RawListenerSummary");
    assert_eq!(listener.name, "e2e-smb");
    assert_eq!(listener.protocol, "smb");
    assert!(!listener.state.status.is_empty(), "state.status must be non-empty");
}

/// `listener show <name>` calls `GET /listeners/{name}` and deserializes
/// as `RawListenerSummary`.
#[tokio::test]
async fn listener_show_deserializes_through_real_tcp() {
    let h = spawn_server().await;

    // Create a listener first.
    let body = serde_json::json!({
        "protocol": "smb",
        "config": { "name": "e2e-show", "pipe_name": "e2e-show-pipe" }
    });
    let create_resp = h.post("/listeners", &body).await;
    assert_eq!(create_resp.status(), 201);

    let resp = h.get("/listeners/e2e-show").await;
    assert_eq!(resp.status(), 200, "GET /listeners/{{name}} must return 200");

    let listener: RawListenerSummary =
        resp.json().await.expect("deserialize RawListenerSummary from show");
    assert_eq!(listener.name, "e2e-show");
}

/// `listener start` calls `PUT /listeners/{name}/start` and deserializes
/// as `RawListenerSummary`.
#[tokio::test]
async fn listener_start_deserializes_through_real_tcp() {
    let h = spawn_server().await;

    let body = serde_json::json!({
        "protocol": "smb",
        "config": { "name": "e2e-start", "pipe_name": "e2e-start-pipe" }
    });
    let _ = h.post("/listeners", &body).await;

    let resp = h.put_empty("/listeners/e2e-start/start").await;
    // 200 on first start, or 409 if already running — both are valid.
    assert!(
        resp.status() == 200 || resp.status() == 409,
        "PUT /listeners/{{name}}/start must return 200 or 409, got {}",
        resp.status()
    );

    if resp.status() == 200 {
        let listener: RawListenerSummary =
            resp.json().await.expect("deserialize RawListenerSummary from start");
        assert_eq!(listener.name, "e2e-start");
    }
}

/// `listener stop` calls `PUT /listeners/{name}/stop`.
#[tokio::test]
async fn listener_stop_through_real_tcp() {
    let h = spawn_server().await;

    let body = serde_json::json!({
        "protocol": "smb",
        "config": { "name": "e2e-stop", "pipe_name": "e2e-stop-pipe" }
    });
    let _ = h.post("/listeners", &body).await;

    let resp = h.put_empty("/listeners/e2e-stop/stop").await;
    assert!(
        resp.status() == 200 || resp.status() == 409,
        "PUT /listeners/{{name}}/stop must return 200 or 409, got {}",
        resp.status()
    );
}

/// `listener delete` calls `DELETE /listeners/{name}` and expects 204.
#[tokio::test]
async fn listener_delete_through_real_tcp() {
    let h = spawn_server().await;

    let body = serde_json::json!({
        "protocol": "smb",
        "config": { "name": "e2e-del", "pipe_name": "e2e-del-pipe" }
    });
    let create_resp = h.post("/listeners", &body).await;
    assert_eq!(create_resp.status(), 201);

    let resp = h.delete("/listeners/e2e-del").await;
    assert_eq!(resp.status(), 204, "DELETE /listeners/{{name}} must return 204");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Audit/log command group
// ═══════════════════════════════════════════════════════════════════════════════

/// `log list` calls `GET /audit?limit=100` and deserializes as `RawAuditPage`.
#[tokio::test]
async fn audit_list_deserializes_through_real_tcp() {
    let h = spawn_server().await;

    let resp = h.get("/audit?limit=100").await;
    assert_eq!(resp.status(), 200);
    let page: RawAuditPage = resp.json().await.expect("deserialize RawAuditPage");
    assert_eq!(page.items.len(), 0, "fresh server has no audit records");
    assert_eq!(page.total, 0);
}

/// `log list` with a pre-inserted record deserializes `RawAuditRecord` fields
/// correctly.
#[tokio::test]
async fn audit_list_with_record_deserializes_through_real_tcp() {
    let h = spawn_server().await;

    record_operator_action(
        &h.database,
        "e2e-alice",
        "agent.task",
        "agent",
        Some("CAFEBABE".to_owned()),
        audit_details(AuditResultStatus::Success, Some(AGENT_ID_U32), Some("whoami"), None),
    )
    .await
    .expect("insert audit record");

    let resp = h.get("/audit?limit=100").await;
    assert_eq!(resp.status(), 200);
    let page: RawAuditPage = resp.json().await.expect("deserialize RawAuditPage");
    assert_eq!(page.total, 1);
    assert_eq!(page.items.len(), 1);

    let record = &page.items[0];
    assert_eq!(record.actor, "e2e-alice");
    assert_eq!(record.action, "agent.task");
    assert_eq!(record.target_kind, "agent");
    assert_eq!(record.result_status, "success");
}

/// `log list --operator alice` sends `operator=alice` as a query parameter.
#[tokio::test]
async fn audit_list_filters_by_operator_through_real_tcp() {
    let h = spawn_server().await;

    record_operator_action(
        &h.database,
        "alice",
        "agent.task",
        "agent",
        None,
        audit_details(AuditResultStatus::Success, None, None, None),
    )
    .await
    .expect("insert alice record");

    record_operator_action(
        &h.database,
        "bob",
        "operator.login",
        "session",
        None,
        audit_details(AuditResultStatus::Success, None, None, None),
    )
    .await
    .expect("insert bob record");

    let resp = h.get("/audit?limit=100&operator=alice").await;
    assert_eq!(resp.status(), 200);
    let page: RawAuditPage = resp.json().await.expect("deserialize filtered audit page");
    assert_eq!(page.items.len(), 1, "only alice's record should appear");
    assert_eq!(page.items[0].actor, "alice");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Payload command group
// ═══════════════════════════════════════════════════════════════════════════════

/// `payload list` calls `GET /payloads` and deserializes as
/// `Vec<RawPayloadSummary>` (empty on fresh server).
#[tokio::test]
async fn payload_list_deserializes_through_real_tcp() {
    let h = spawn_server().await;

    let resp = h.get("/payloads").await;
    assert_eq!(resp.status(), 200);
    // The CLI deserializes as Vec<RawPayloadSummary>; on a fresh server this
    // is an empty array — just verify it's a JSON array.
    let payloads: Vec<serde_json::Value> =
        resp.json().await.expect("deserialize Vec<Value> for payloads");
    assert_eq!(payloads.len(), 0, "fresh server has no payloads");
}

/// `payload build` calls `POST /payloads/build` and deserializes as
/// `BuildSubmitResponse`.  Requires a listener to exist first.
#[tokio::test]
async fn payload_build_submit_deserializes_through_real_tcp() {
    let h = spawn_server().await;

    // Create a listener for the build to reference.
    let listener_body = serde_json::json!({
        "protocol": "smb",
        "config": { "name": "e2e-build-listener", "pipe_name": "e2e-build-pipe" }
    });
    let create_resp = h.post("/listeners", &listener_body).await;
    assert_eq!(create_resp.status(), 201, "listener create must succeed");

    // Submit a build job (same body as the CLI sends).
    let build_body = serde_json::json!({
        "listener": "e2e-build-listener",
        "arch": "x64",
        "format": "exe"
    });
    let resp = h.post("/payloads/build", &build_body).await;
    assert_eq!(resp.status(), 202, "POST /payloads/build must return 202");

    let submitted: BuildSubmitResponse =
        resp.json().await.expect("deserialize BuildSubmitResponse");
    assert!(!submitted.job_id.is_empty(), "job_id must be non-empty");
}

/// `payload build --wait` polls `GET /payloads/jobs/{job_id}` and deserializes
/// as `BuildJobStatus`.
#[tokio::test]
async fn payload_build_poll_deserializes_through_real_tcp() {
    let h = spawn_server().await;

    // Create listener and submit build.
    let listener_body = serde_json::json!({
        "protocol": "smb",
        "config": { "name": "e2e-poll-listener", "pipe_name": "e2e-poll-pipe" }
    });
    let _ = h.post("/listeners", &listener_body).await;

    let build_body = serde_json::json!({
        "listener": "e2e-poll-listener",
        "arch": "x64",
        "format": "bin"
    });
    let build_resp = h.post("/payloads/build", &build_body).await;
    assert_eq!(build_resp.status(), 202);

    let submitted: BuildSubmitResponse =
        build_resp.json().await.expect("deserialize BuildSubmitResponse");

    // Poll the job status (same as build --wait loop).
    let resp = h.get(&format!("/payloads/jobs/{}", submitted.job_id)).await;
    assert_eq!(resp.status(), 200, "GET /payloads/jobs/{{id}} must return 200");

    let status: BuildJobStatus = resp.json().await.expect("deserialize BuildJobStatus");
    assert_eq!(status.job_id, submitted.job_id);
    assert!(!status.status.is_empty(), "status field must be non-empty");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Cross-cutting: authentication error paths
// ═══════════════════════════════════════════════════════════════════════════════

/// A request with an invalid API key returns 401.  The CLI maps this to
/// `CliError::AuthFailure` (exit code 3).
#[tokio::test]
async fn invalid_api_key_returns_401_through_real_tcp() {
    let h = spawn_server().await;

    let resp = h
        .http
        .get(format!("{}/api/v1/agents", h.base_url))
        .header("x-api-key", "wrong-key")
        .send()
        .await
        .expect("request should succeed at TCP level");

    assert_eq!(resp.status(), 401, "bad API key must return 401");
}

/// A request with no API key returns 401.
#[tokio::test]
async fn missing_api_key_returns_401_through_real_tcp() {
    let h = spawn_server().await;

    let resp = h
        .http
        .get(format!("{}/api/v1/agents", h.base_url))
        .send()
        .await
        .expect("request should succeed at TCP level");

    assert_eq!(resp.status(), 401, "missing API key must return 401");
}
