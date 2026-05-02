//! `red-cell-cli status` — teamserver health and connectivity check.
//!
//! Calls the REST API to verify that:
//! 1. The server is reachable (`GET /api/v1/` does not return a network error).
//! 2. The supplied credentials are accepted and the teamserver returns a health
//!    snapshot (`GET /api/v1/health` returns 200).
//!
//! On success it prints structured data including uptime, database mode, and
//! inventory counts from the health endpoint.

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

/// `GET /api/v1/health` body — aligned with `teamserver::api::health::HealthResponse`.
#[derive(Debug, Deserialize)]
struct HealthResponse {
    status: String,
    uptime_secs: u64,
    agents: HealthAgentCounts,
    listeners: HealthListenerCounts,
    database: String,
    plugins: HealthPluginCounts,
    #[serde(default)]
    plugin_health: Vec<HealthPluginEntryWire>,
    #[serde(default)]
    subsystem_errors: Vec<HealthSubsystemErrorWire>,
}

#[derive(Debug, Deserialize)]
struct HealthSubsystemErrorWire {
    subsystem: String,
    message: String,
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
#[allow(dead_code)]
struct HealthPluginCounts {
    loaded: u32,
    failed: u32,
    disabled: u32,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct HealthPluginEntryWire {
    name: String,
    consecutive_failures: u32,
    disabled: bool,
}

// ── public output type ───────────────────────────────────────────────────────

/// Agent inventory counts from the health snapshot.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusAgentCounts {
    /// Agents currently marked active.
    pub active: u64,
    /// Total agents tracked (active + dead).
    pub total: u64,
}

/// Listener lifecycle counts from the health snapshot.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusListenerCounts {
    /// Listeners currently running.
    pub running: u64,
    /// Listeners stopped, created, or in error state.
    pub stopped: u64,
}

/// Python plugin load counts from the health snapshot.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusPluginCounts {
    /// Plugins successfully loaded at startup.
    pub loaded: u32,
    /// Plugins that failed to load at startup.
    pub failed: u32,
    /// Plugins auto-disabled due to repeated runtime failures.
    pub disabled: u32,
}

/// A subsystem that failed while the teamserver assembled the health snapshot.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusSubsystemError {
    /// Subsystem identifier (`listeners`, `plugins`, …).
    pub subsystem: String,
    /// Human-readable error from the teamserver.
    pub message: String,
}

/// Per-plugin runtime health entry (mirrors the REST health payload).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusPluginHealthEntry {
    /// Python module name (without `.py` extension).
    pub name: String,
    /// Consecutive callback/command failures since the last success.
    pub consecutive_failures: u32,
    /// Whether the plugin was automatically disabled.
    pub disabled: bool,
}

/// Data returned by the `status` command.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusData {
    /// API version string reported by the teamserver root document.
    pub version: String,
    /// Seconds since the teamserver process started.
    pub uptime_secs: u64,
    /// Overall health — `"ok"` when subsystems are healthy, otherwise `"degraded"`.
    pub status: String,
    /// Database probe result — `"ok"` or `"degraded"`.
    pub database: String,
    /// Agent inventory from the health snapshot.
    pub agents: StatusAgentCounts,
    /// Listener lifecycle counts from the health snapshot.
    pub listeners: StatusListenerCounts,
    /// Python plugin load counts from the health snapshot.
    pub plugins: StatusPluginCounts,
    /// Per-plugin runtime health (empty when no plugins are loaded).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub plugin_health: Vec<StatusPluginHealthEntry>,
    /// Subsystem probe failures reported by the teamserver (empty when all probes succeeded).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub subsystem_errors: Vec<StatusSubsystemError>,
}

impl TextRender for StatusData {
    fn render_text(&self) -> String {
        use comfy_table::{Cell, ContentArrangement, Table};
        let mut table = Table::new();
        table.set_content_arrangement(ContentArrangement::Dynamic);
        table.set_header([Cell::new("Field"), Cell::new("Value")]);
        table.add_row([Cell::new("version"), Cell::new(&self.version)]);
        table.add_row([Cell::new("uptime_secs"), Cell::new(self.uptime_secs.to_string())]);
        table.add_row([Cell::new("status"), Cell::new(&self.status)]);
        table.add_row([Cell::new("database"), Cell::new(&self.database)]);
        table.add_row([
            Cell::new("agents (active/total)"),
            Cell::new(format!("{}/{}", self.agents.active, self.agents.total)),
        ]);
        table.add_row([
            Cell::new("listeners (running/stopped)"),
            Cell::new(format!("{}/{}", self.listeners.running, self.listeners.stopped)),
        ]);
        table.add_row([
            Cell::new("plugins (loaded/failed/disabled)"),
            Cell::new(format!(
                "{}/{}/{}",
                self.plugins.loaded, self.plugins.failed, self.plugins.disabled
            )),
        ]);
        if !self.plugin_health.is_empty() {
            for entry in &self.plugin_health {
                table.add_row([
                    Cell::new(format!("plugin: {}", entry.name)),
                    Cell::new(format!(
                        "failures={} disabled={}",
                        entry.consecutive_failures, entry.disabled
                    )),
                ]);
            }
        }
        if !self.subsystem_errors.is_empty() {
            for err in &self.subsystem_errors {
                table.add_row([
                    Cell::new(format!("subsystem_error: {}", err.subsystem)),
                    Cell::new(&err.message),
                ]);
            }
        }
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
    let root: ApiRootResponse = client.get_anon("/").await?;
    let health: HealthResponse = client.get("/health").await?;

    let plugin_health = health
        .plugin_health
        .into_iter()
        .map(|e| StatusPluginHealthEntry {
            name: e.name,
            consecutive_failures: e.consecutive_failures,
            disabled: e.disabled,
        })
        .collect();

    let subsystem_errors = health
        .subsystem_errors
        .into_iter()
        .map(|e| StatusSubsystemError { subsystem: e.subsystem, message: e.message })
        .collect();

    Ok(StatusData {
        version: root.version,
        uptime_secs: health.uptime_secs,
        status: health.status,
        database: health.database,
        agents: StatusAgentCounts { active: health.agents.active, total: health.agents.total },
        listeners: StatusListenerCounts {
            running: health.listeners.running,
            stopped: health.listeners.stopped,
        },
        plugins: StatusPluginCounts {
            loaded: health.plugins.loaded,
            failed: health.plugins.failed,
            disabled: health.plugins.disabled,
        },
        plugin_health,
        subsystem_errors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ResolvedConfig;
    use crate::error::CliError;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn mock_cfg(server_uri: &str) -> ResolvedConfig {
        ResolvedConfig {
            server: server_uri.to_owned(),
            token: "test-token".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        }
    }

    fn sample_healthy() -> StatusData {
        StatusData {
            version: "v1".to_owned(),
            uptime_secs: 42,
            status: "ok".to_owned(),
            database: "ok".to_owned(),
            agents: StatusAgentCounts { active: 1, total: 2 },
            listeners: StatusListenerCounts { running: 0, stopped: 1 },
            plugins: StatusPluginCounts { loaded: 0, failed: 0, disabled: 0 },
            plugin_health: vec![],
            subsystem_errors: vec![],
        }
    }

    #[test]
    fn status_data_serialises_full_snapshot() {
        let data = sample_healthy();
        let json = serde_json::to_value(&data).expect("serialize");
        assert_eq!(json["version"], "v1");
        assert_eq!(json["uptime_secs"], 42);
        assert_eq!(json["status"], "ok");
        assert_eq!(json["database"], "ok");
        assert_eq!(json["agents"]["active"], 1);
        assert_eq!(json["agents"]["total"], 2);
        assert_eq!(json["listeners"]["running"], 0);
        assert_eq!(json["listeners"]["stopped"], 1);
    }

    #[test]
    fn status_data_serialises_degraded_without_hiding_database() {
        let mut data = sample_healthy();
        data.status = "degraded".to_owned();
        data.database = "degraded".to_owned();
        let json = serde_json::to_value(&data).expect("serialize");
        assert_eq!(json["status"], "degraded");
        assert_eq!(json["database"], "degraded");
    }

    #[test]
    fn plugin_health_skipped_in_json_when_empty() {
        let data = sample_healthy();
        let json = serde_json::to_value(&data).expect("serialize");
        assert!(json.get("plugin_health").is_none());
    }

    #[test]
    fn plugin_health_included_when_non_empty() {
        let mut data = sample_healthy();
        data.plugin_health.push(StatusPluginHealthEntry {
            name: "demo".to_owned(),
            consecutive_failures: 0,
            disabled: false,
        });
        let json = serde_json::to_value(&data).expect("serialize");
        assert_eq!(json["plugin_health"][0]["name"], "demo");
    }

    #[test]
    fn render_text_contains_core_fields() {
        let data = sample_healthy();
        let output = data.render_text();
        for needle in ["version", "v1", "uptime_secs", "42", "database", "agents", "listeners"] {
            assert!(output.contains(needle), "expected {needle:?} in:\n{output}");
        }
    }

    #[test]
    fn render_text_shows_degraded_database() {
        let mut data = sample_healthy();
        data.database = "degraded".to_owned();
        data.status = "degraded".to_owned();
        let output = data.render_text();
        assert!(output.contains("degraded"), "text output must show degraded database:\n{output}");
    }

    /// `GET /api/v1/` fails with a transport error — `run` surfaces [`CliError::ServerUnreachable`].
    #[tokio::test]
    async fn run_server_unreachable_on_get_root() {
        let cfg = mock_cfg("http://127.0.0.1:1");
        let client = crate::client::ApiClient::new(&cfg).expect("build client");
        let result = run(&client).await;
        assert!(
            matches!(result, Err(CliError::ServerUnreachable(_))),
            "expected ServerUnreachable when root GET cannot connect; got {result:?}"
        );
    }

    #[tokio::test]
    async fn run_auth_failure_on_get_health() {
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

        let client = crate::client::ApiClient::new(&mock_cfg(&server.uri())).expect("build client");
        let result = run(&client).await;
        assert!(
            matches!(result, Err(CliError::AuthFailure(_))),
            "expected AuthFailure on health 401; got {result:?}"
        );
    }

    #[tokio::test]
    async fn run_auth_failure_on_get_health_403() {
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

        let client = crate::client::ApiClient::new(&mock_cfg(&server.uri())).expect("build client");
        let result = run(&client).await;
        assert!(
            matches!(result, Err(CliError::AuthFailure(_))),
            "expected AuthFailure on health 403; got {result:?}"
        );
    }

    #[tokio::test]
    async fn run_server_error_on_get_health() {
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
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;

        let client = crate::client::ApiClient::new(&mock_cfg(&server.uri())).expect("build client");
        let result = run(&client).await;
        assert!(
            matches!(result, Err(CliError::ServerError(_))),
            "expected ServerError on health 500; got {result:?}"
        );
    }

    #[tokio::test]
    async fn run_success_healthy_snapshot() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"version": "2.0.0-test"})),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/health"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "ok",
                "uptime_secs": 3600u64,
                "agents": { "active": 3, "total": 10 },
                "listeners": { "running": 2, "stopped": 1 },
                "database": "ok",
                "plugins": { "loaded": 2, "failed": 0, "disabled": 1 },
                "plugin_health": [
                    { "name": "plug_a", "consecutive_failures": 0, "disabled": false },
                    { "name": "plug_b", "consecutive_failures": 3, "disabled": true },
                ],
            })))
            .mount(&server)
            .await;

        let client = crate::client::ApiClient::new(&mock_cfg(&server.uri())).expect("build client");
        let data = run(&client).await.expect("status run");

        assert_eq!(data.version, "2.0.0-test");
        assert_eq!(data.uptime_secs, 3600);
        assert_eq!(data.status, "ok");
        assert_eq!(data.database, "ok");
        assert_eq!(data.agents, StatusAgentCounts { active: 3, total: 10 });
        assert_eq!(data.listeners, StatusListenerCounts { running: 2, stopped: 1 });
        assert_eq!(data.plugins, StatusPluginCounts { loaded: 2, failed: 0, disabled: 1 });
        assert_eq!(
            data.plugin_health,
            vec![
                StatusPluginHealthEntry {
                    name: "plug_a".to_owned(),
                    consecutive_failures: 0,
                    disabled: false,
                },
                StatusPluginHealthEntry {
                    name: "plug_b".to_owned(),
                    consecutive_failures: 3,
                    disabled: true,
                },
            ]
        );
    }

    #[tokio::test]
    async fn run_success_degraded_database_snapshot() {
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
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "degraded",
                "uptime_secs": 99u64,
                "agents": { "active": 0, "total": 5 },
                "listeners": { "running": 0, "stopped": 2 },
                "database": "degraded",
                "plugins": { "loaded": 1, "failed": 0, "disabled": 0 },
                "plugin_health": [],
            })))
            .mount(&server)
            .await;

        let client = crate::client::ApiClient::new(&mock_cfg(&server.uri())).expect("build client");
        let data = run(&client).await.expect("status run");

        assert_eq!(data.status, "degraded");
        assert_eq!(data.database, "degraded");
        assert_eq!(data.uptime_secs, 99);
        assert_eq!(data.agents, StatusAgentCounts { active: 0, total: 5 });
        assert_eq!(data.listeners, StatusListenerCounts { running: 0, stopped: 2 });
        assert_eq!(data.plugins, StatusPluginCounts { loaded: 1, failed: 0, disabled: 0 });
        assert!(data.plugin_health.is_empty());
    }

    #[tokio::test]
    async fn run_success_degraded_when_subsystem_probe_fails() {
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
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "degraded",
                "uptime_secs": 12u64,
                "active_operators": 0u64,
                "agents": { "active": 1, "total": 1 },
                "listeners": { "running": 0, "stopped": 0 },
                "database": "ok",
                "plugins": { "loaded": 0, "failed": 0, "disabled": 0 },
                "plugin_health": [],
                "subsystem_errors": [
                    { "subsystem": "listeners", "message": "listener inventory failed: database locked" },
                ],
            })))
            .mount(&server)
            .await;

        let client = crate::client::ApiClient::new(&mock_cfg(&server.uri())).expect("build client");
        let data = run(&client).await.expect("status run");

        assert_eq!(data.status, "degraded");
        assert_eq!(data.database, "ok");
        assert_eq!(
            data.subsystem_errors,
            vec![StatusSubsystemError {
                subsystem: "listeners".to_owned(),
                message: "listener inventory failed: database locked".to_owned(),
            }]
        );
    }
}
