//! `red-cell-cli status` — teamserver health and connectivity check.
//!
//! Calls the REST API to verify that:
//! 1. The server is reachable (GET `/api/v1/` does not return a network error).
//! 2. The supplied credentials are accepted (GET `/api/v1/health` returns 200).
//! 3. The health snapshot (uptime, agent/listener counts, database probe) is surfaced.
//!
//! On success it prints:
//!
//! ```json
//! {"ok": true, "data": {"version": "v1", "status": "ok", "database": "ok", "uptime_secs": 42, "agents": 4, "listeners": 2}}
//! ```

use serde::{Deserialize, Serialize};

use crate::client::ApiClient;
use crate::error::CliError;
use crate::output::TextRender;

// ── server response shapes ───────────────────────────────────────────────────

/// Subset of the `/api/v1/` root response that we care about.
#[derive(Debug, Deserialize)]
struct ApiRootResponse {
    version: String,
    // Other fields (prefix, openapi_path, …) are ignored.
}

/// Body of `GET /api/v1/health` (teamserver `HealthResponse` JSON).
#[derive(Debug, Deserialize)]
struct HealthApiResponse {
    status: String,
    uptime_secs: u64,
    agents: HealthAgentCounts,
    listeners: HealthListenerCounts,
    database: String,
    #[allow(dead_code)]
    plugins: HealthPluginCounts,
    #[allow(dead_code)]
    plugin_health: Vec<HealthPluginEntry>,
}

#[derive(Debug, Deserialize)]
struct HealthAgentCounts {
    active: u64,
    total: u64,
}

#[derive(Debug, Deserialize)]
struct HealthListenerCounts {
    running: u64,
    stopped: u64,
}

#[derive(Debug, Deserialize)]
struct HealthPluginCounts {
    loaded: u32,
    failed: u32,
    disabled: u32,
}

#[derive(Debug, Deserialize)]
struct HealthPluginEntry {
    name: String,
    consecutive_failures: u32,
    disabled: bool,
}

// ── public output type ───────────────────────────────────────────────────────

/// Data returned by the `status` command.
#[derive(Debug, Clone, Serialize)]
pub struct StatusData {
    /// API version string reported by the teamserver.
    pub version: String,
    /// Overall health status from the teamserver (`ok` or `degraded`).
    pub status: String,
    /// Database probe result (`ok` or `degraded`).
    pub database: String,
    /// Server uptime in seconds from the health snapshot.
    pub uptime_secs: Option<u64>,
    /// Total agents tracked (matches health `agents.total`).
    pub agents: usize,
    /// Total listeners configured (running + stopped).
    pub listeners: usize,
}

impl TextRender for StatusData {
    fn render_text(&self) -> String {
        use comfy_table::{Cell, ContentArrangement, Table};
        let mut table = Table::new();
        table.set_content_arrangement(ContentArrangement::Dynamic);
        table.set_header([Cell::new("Field"), Cell::new("Value")]);
        table.add_row([Cell::new("version"), Cell::new(&self.version)]);
        table.add_row([Cell::new("status"), Cell::new(&self.status)]);
        table.add_row([Cell::new("database"), Cell::new(&self.database)]);
        table.add_row([
            Cell::new("uptime_secs"),
            Cell::new(self.uptime_secs.map_or_else(|| "unknown".to_owned(), |s| s.to_string())),
        ]);
        table.add_row([Cell::new("agents"), Cell::new(self.agents.to_string())]);
        table.add_row([Cell::new("listeners"), Cell::new(self.listeners.to_string())]);
        table.to_string()
    }
}

// ── command handler ──────────────────────────────────────────────────────────

/// Execute the `status` command and return the structured result.
///
/// # Errors
///
/// Returns a [`CliError`] if any of the API calls fail.  The error variant
/// indicates the appropriate process exit code.
pub async fn run(client: &ApiClient) -> Result<StatusData, CliError> {
    // Step 1 — API root (no auth required → proves reachability + API version string).
    let root: ApiRootResponse = client.get_anon("/").await?;

    // Step 2 — authenticated health snapshot (uptime, counts, database/plugin state).
    let health: HealthApiResponse = client.get("/health").await?;

    let agents = usize::try_from(health.agents.total).unwrap_or(usize::MAX);
    let listeners =
        usize::try_from(health.listeners.running.saturating_add(health.listeners.stopped))
            .unwrap_or(usize::MAX);

    Ok(StatusData {
        version: root.version,
        status: health.status,
        database: health.database,
        uptime_secs: Some(health.uptime_secs),
        agents,
        listeners,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn mock_cfg(server_uri: &str) -> crate::config::ResolvedConfig {
        crate::config::ResolvedConfig {
            server: server_uri.to_owned(),
            token: "test-token".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        }
    }

    /// JSON body matching a real `GET /api/v1/health` response shape.
    fn health_json(
        overall: &str,
        database: &str,
        uptime_secs: u64,
        agents_total: u64,
        listeners_running: u64,
        listeners_stopped: u64,
    ) -> serde_json::Value {
        serde_json::json!({
            "status": overall,
            "uptime_secs": uptime_secs,
            "agents": { "active": 0, "total": agents_total },
            "listeners": { "running": listeners_running, "stopped": listeners_stopped },
            "database": database,
            "plugins": { "loaded": 0, "failed": 0, "disabled": 0 },
            "plugin_health": [],
        })
    }

    // ── run() error-path tests ───────────────────────────────────────────────

    /// When the server is unreachable (port 1 is never open), `run()` must
    /// return `CliError::ServerUnreachable` on the very first call (`GET /`).
    #[tokio::test]
    async fn run_server_unreachable_on_get_root() {
        let cfg = mock_cfg("https://127.0.0.1:1");
        let client = ApiClient::new(&cfg).unwrap();
        let result = run(&client).await;
        assert!(
            matches!(result, Err(CliError::ServerUnreachable(_))),
            "expected ServerUnreachable, got: {result:?}",
        );
    }

    /// When `GET /health` returns 401 (bad token), `run()` must propagate
    /// `CliError::AuthFailure`.  The root endpoint succeeds first to confirm
    /// that only the auth step is failing.
    #[tokio::test]
    async fn run_auth_failure_on_get_health() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"version": "v1"})),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/health"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let cfg = mock_cfg(&server.uri());
        let client = ApiClient::new(&cfg).unwrap();
        let result = run(&client).await;
        assert!(
            matches!(result, Err(CliError::AuthFailure(_))),
            "expected AuthFailure, got: {result:?}",
        );
    }

    /// When `GET /health` returns 403, `run()` must also propagate
    /// `CliError::AuthFailure` (forbidden, not just unauthorised).
    #[tokio::test]
    async fn run_auth_failure_on_get_health_403() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"version": "v1"})),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/health"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let cfg = mock_cfg(&server.uri());
        let client = ApiClient::new(&cfg).unwrap();
        let result = run(&client).await;
        assert!(
            matches!(result, Err(CliError::AuthFailure(_))),
            "expected AuthFailure on 403, got: {result:?}",
        );
    }

    /// Partial-failure path: `GET /` succeeds but `GET /health` returns 500.
    #[tokio::test]
    async fn run_server_error_on_get_health() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"version": "v1"})),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/health"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .mount(&server)
            .await;

        let cfg = mock_cfg(&server.uri());
        let client = ApiClient::new(&cfg).unwrap();
        let result = run(&client).await;
        assert!(
            matches!(result, Err(CliError::ServerError(_))),
            "expected ServerError on health 500, got: {result:?}",
        );
    }

    /// Happy-path: health reports `ok` / database `ok` and counts map from the snapshot.
    #[tokio::test]
    async fn run_success_healthy_snapshot() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"version": "v2"})),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/health"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(health_json("ok", "ok", 42, 2, 1, 0)),
            )
            .mount(&server)
            .await;

        let cfg = mock_cfg(&server.uri());
        let client = ApiClient::new(&cfg).unwrap();
        let result = run(&client).await.unwrap();
        assert_eq!(result.version, "v2");
        assert_eq!(result.status, "ok");
        assert_eq!(result.database, "ok");
        assert_eq!(result.uptime_secs, Some(42));
        assert_eq!(result.agents, 2);
        assert_eq!(result.listeners, 1);
    }

    /// Degraded database is still HTTP 200 — `run()` succeeds and surfaces `degraded` fields.
    #[tokio::test]
    async fn run_success_degraded_database_snapshot() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"version": "v1"})),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/health"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(health_json("degraded", "degraded", 7, 0, 0, 2)),
            )
            .mount(&server)
            .await;

        let cfg = mock_cfg(&server.uri());
        let client = ApiClient::new(&cfg).unwrap();
        let result = run(&client).await.unwrap();
        assert_eq!(result.status, "degraded");
        assert_eq!(result.database, "degraded");
        assert_eq!(result.uptime_secs, Some(7));
        assert_eq!(result.listeners, 2);
    }

    // ── StatusData serialisation ─────────────────────────────────────────────

    #[test]
    fn status_data_serialises_with_null_uptime() {
        let data = StatusData {
            version: "v1".to_owned(),
            status: "ok".to_owned(),
            database: "ok".to_owned(),
            uptime_secs: None,
            agents: 3,
            listeners: 1,
        };
        let json = serde_json::to_value(&data).unwrap();
        assert_eq!(json["version"], "v1");
        assert_eq!(json["status"], "ok");
        assert_eq!(json["database"], "ok");
        assert!(json["uptime_secs"].is_null());
        assert_eq!(json["agents"], 3);
        assert_eq!(json["listeners"], 1);
    }

    #[test]
    fn status_data_serialises_with_uptime() {
        let data = StatusData {
            version: "v1".to_owned(),
            status: "ok".to_owned(),
            database: "ok".to_owned(),
            uptime_secs: Some(123),
            agents: 0,
            listeners: 0,
        };
        let json = serde_json::to_value(&data).unwrap();
        assert_eq!(json["uptime_secs"], 123);
    }

    #[test]
    fn render_text_none_uptime_shows_unknown() {
        let data = StatusData {
            version: "v1".to_owned(),
            status: "ok".to_owned(),
            database: "ok".to_owned(),
            uptime_secs: None,
            agents: 4,
            listeners: 2,
        };
        let output = data.render_text();
        assert!(output.contains("version"), "missing 'version' row label");
        assert!(output.contains("v1"), "missing version value");
        assert!(output.contains("status"), "missing 'status' row label");
        assert!(output.contains("database"), "missing 'database' row label");
        assert!(output.contains("uptime_secs"), "missing 'uptime_secs' row label");
        assert!(output.contains("unknown"), "None uptime should render as 'unknown'");
        assert!(output.contains("agents"), "missing 'agents' row label");
        assert!(output.contains('4'), "missing agents count");
        assert!(output.contains("listeners"), "missing 'listeners' row label");
        assert!(output.contains('2'), "missing listeners count");
    }

    #[test]
    fn render_text_some_uptime_shows_numeric_value() {
        let data = StatusData {
            version: "v2".to_owned(),
            status: "ok".to_owned(),
            database: "ok".to_owned(),
            uptime_secs: Some(3600),
            agents: 0,
            listeners: 0,
        };
        let output = data.render_text();
        assert!(output.contains("uptime_secs"), "missing 'uptime_secs' row label");
        assert!(output.contains("3600"), "Some(3600) uptime should render as '3600'");
        assert!(!output.contains("unknown"), "Some uptime must not render as 'unknown'");
    }
}
