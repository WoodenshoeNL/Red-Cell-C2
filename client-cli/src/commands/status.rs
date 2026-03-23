//! `red-cell-cli status` — teamserver health and connectivity check.
//!
//! Calls the REST API to verify that:
//! 1. The server is reachable (GET `/api/v1/` does not return a network error).
//! 2. The supplied credentials are accepted (GET `/api/v1/agents` returns 200).
//!
//! On success it prints:
//!
//! ```json
//! {"ok": true, "data": {"version": "v1", "uptime_secs": null, "agents": 4, "listeners": 2}}
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

// ── public output type ───────────────────────────────────────────────────────

/// Data returned by the `status` command.
#[derive(Debug, Clone, Serialize)]
pub struct StatusData {
    /// API version string reported by the teamserver.
    pub version: String,
    /// Server uptime in seconds.  `null` until the teamserver exposes this.
    pub uptime_secs: Option<u64>,
    /// Number of currently tracked agents.
    pub agents: usize,
    /// Number of configured listeners.
    pub listeners: usize,
}

impl TextRender for StatusData {
    fn render_text(&self) -> String {
        use comfy_table::{Cell, ContentArrangement, Table};
        let mut table = Table::new();
        table.set_content_arrangement(ContentArrangement::Dynamic);
        table.set_header([Cell::new("Field"), Cell::new("Value")]);
        table.add_row([Cell::new("version"), Cell::new(&self.version)]);
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
    // Step 1 — API root (no auth required → proves reachability).
    let root: ApiRootResponse = client.get_anon("/").await?;

    // Step 2 — agent list (auth required → proves token is valid).
    let agents: Vec<serde_json::Value> = client.get("/agents").await?;

    // Step 3 — listener list (auth required).
    let listeners: Vec<serde_json::Value> = client.get("/listeners").await?;

    Ok(StatusData {
        version: root.version,
        uptime_secs: None, // not yet exposed by the teamserver REST API
        agents: agents.len(),
        listeners: listeners.len(),
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
        }
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

    /// When `GET /agents` returns 401 (bad token), `run()` must propagate
    /// `CliError::AuthFailure`.  The root endpoint succeeds first to confirm
    /// that only the auth step is failing.
    #[tokio::test]
    async fn run_auth_failure_on_get_agents() {
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
            .and(path("/api/v1/agents"))
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

    /// When `GET /agents` returns 403, `run()` must also propagate
    /// `CliError::AuthFailure` (forbidden, not just unauthorised).
    #[tokio::test]
    async fn run_auth_failure_on_get_agents_403() {
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
            .and(path("/api/v1/agents"))
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

    /// Partial-failure path: `GET /` and `GET /agents` both succeed, but
    /// `GET /listeners` returns 500.  `run()` must return `CliError::ServerError`.
    #[tokio::test]
    async fn run_server_error_on_get_listeners() {
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
            .and(path("/api/v1/agents"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/listeners"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .mount(&server)
            .await;

        let cfg = mock_cfg(&server.uri());
        let client = ApiClient::new(&cfg).unwrap();
        let result = run(&client).await;
        assert!(
            matches!(result, Err(CliError::ServerError(_))),
            "expected ServerError on listeners 500, got: {result:?}",
        );
    }

    /// Partial-failure path: `GET /listeners` returns 401 after both earlier
    /// calls succeed.  `run()` must return `CliError::AuthFailure`.
    #[tokio::test]
    async fn run_auth_failure_on_get_listeners() {
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
            .and(path("/api/v1/agents"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/listeners"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let cfg = mock_cfg(&server.uri());
        let client = ApiClient::new(&cfg).unwrap();
        let result = run(&client).await;
        assert!(
            matches!(result, Err(CliError::AuthFailure(_))),
            "expected AuthFailure on listeners 401, got: {result:?}",
        );
    }

    /// Happy-path smoke test: all three endpoints succeed and `run()` returns
    /// the correct counts.
    #[tokio::test]
    async fn run_success_returns_correct_counts() {
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
            .and(path("/api/v1/agents"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!([{"id": "a1"}, {"id": "a2"}])),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/listeners"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{"name": "http1"}])),
            )
            .mount(&server)
            .await;

        let cfg = mock_cfg(&server.uri());
        let client = ApiClient::new(&cfg).unwrap();
        let result = run(&client).await.unwrap();
        assert_eq!(result.version, "v2");
        assert_eq!(result.agents, 2);
        assert_eq!(result.listeners, 1);
        assert!(result.uptime_secs.is_none());
    }

    // ── StatusData serialisation ─────────────────────────────────────────────

    #[test]
    fn status_data_serialises_with_null_uptime() {
        let data =
            StatusData { version: "v1".to_owned(), uptime_secs: None, agents: 3, listeners: 1 };
        let json = serde_json::to_value(&data).unwrap();
        assert_eq!(json["version"], "v1");
        assert!(json["uptime_secs"].is_null());
        assert_eq!(json["agents"], 3);
        assert_eq!(json["listeners"], 1);
    }

    #[test]
    fn status_data_serialises_with_uptime() {
        let data = StatusData {
            version: "v1".to_owned(),
            uptime_secs: Some(123),
            agents: 0,
            listeners: 0,
        };
        let json = serde_json::to_value(&data).unwrap();
        assert_eq!(json["uptime_secs"], 123);
    }

    #[test]
    fn render_text_none_uptime_shows_unknown() {
        let data =
            StatusData { version: "v1".to_owned(), uptime_secs: None, agents: 4, listeners: 2 };
        let output = data.render_text();
        assert!(output.contains("version"), "missing 'version' row label");
        assert!(output.contains("v1"), "missing version value");
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
