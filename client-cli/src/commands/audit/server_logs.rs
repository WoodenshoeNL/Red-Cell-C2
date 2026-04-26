//! `log server-tail` — fetch recent teamserver log lines.

use tracing::instrument;

use crate::client::ApiClient;
use crate::error::CliError;

use super::types::{RawServerLogsResponse, ServerLogEntry};

/// `log server-tail` — fetch recent teamserver log lines.
///
/// # Examples
/// ```text
/// red-cell-cli log server-tail
/// red-cell-cli log server-tail --lines 50
/// ```
#[instrument(skip(client))]
pub(super) async fn server_tail(
    client: &ApiClient,
    lines: u32,
) -> Result<Vec<ServerLogEntry>, CliError> {
    let raw: RawServerLogsResponse =
        client.get(&format!("/debug/server-logs?lines={lines}")).await?;
    Ok(raw.logs)
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn server_tail_calls_debug_server_logs_and_returns_entries() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/debug/server-logs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "logs": [
                    {"timestamp": "12:00:01", "text": "teamserver started"},
                    {"timestamp": "12:00:02", "text": "listener bound"}
                ],
                "count": 2
            })))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let entries = server_tail(&client, 200).await.expect("server_tail must succeed");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].text, "teamserver started");
        assert_eq!(entries[1].text, "listener bound");
    }

    #[tokio::test]
    async fn server_tail_returns_not_found_on_404() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/debug/server-logs"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let err = server_tail(&client, 200).await.expect_err("must fail with 404");
        assert!(matches!(err, CliError::NotFound(_)), "expected NotFound, got {err:?}");
    }

    #[tokio::test]
    async fn server_tail_returns_auth_failure_on_401() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/debug/server-logs"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "bad-token".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let err = server_tail(&client, 200).await.expect_err("must fail with 401");
        assert!(matches!(err, CliError::AuthFailure(_)), "expected AuthFailure, got {err:?}");
    }
}
