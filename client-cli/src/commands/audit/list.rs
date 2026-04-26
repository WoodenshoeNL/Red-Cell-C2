//! One-shot audit log queries: `log list` and `log purge`.

use tracing::instrument;

use crate::AgentId;
use crate::client::ApiClient;
use crate::error::CliError;
use crate::util::percent_encode;

use super::types::{AuditEntry, PurgeResult, RawAuditPage, RawPurgeResponse, audit_entry_from_raw};

/// `log purge` — delete audit log entries older than the retention window.
///
/// # Examples
/// ```text
/// red-cell-cli log purge --confirm
/// red-cell-cli log purge --confirm --older-than-days 30
/// ```
#[instrument(skip(client))]
pub(super) async fn purge(
    client: &ApiClient,
    older_than_days: Option<u32>,
) -> Result<PurgeResult, CliError> {
    let path = match older_than_days {
        Some(days) => format!("/audit/purge?older_than_days={days}"),
        None => "/audit/purge".to_owned(),
    };
    let raw: RawPurgeResponse = client.delete_json(&path).await?;
    Ok(PurgeResult { deleted: raw.deleted, cutoff: raw.cutoff })
}

/// `log list` — fetch audit log entries with optional filters.
///
/// Entries are returned newest-first.
///
/// # Examples
/// ```text
/// red-cell-cli log list
/// red-cell-cli log list --operator alice --limit 50
/// red-cell-cli log list --since 2026-03-21T00:00:00Z --agent abc123
/// ```
#[instrument(skip(client))]
pub(super) async fn list(
    client: &ApiClient,
    limit: u32,
    since: Option<&str>,
    until: Option<&str>,
    operator: Option<&str>,
    agent_id: Option<AgentId>,
    action: Option<&str>,
) -> Result<Vec<AuditEntry>, CliError> {
    let mut params: Vec<String> = vec![format!("limit={limit}")];

    if let Some(s) = since {
        params.push(format!("since={}", percent_encode(s)));
    }
    if let Some(u) = until {
        params.push(format!("until={}", percent_encode(u)));
    }
    if let Some(op) = operator {
        params.push(format!("operator={}", percent_encode(op)));
    }
    if let Some(aid) = agent_id {
        params.push(format!("agent_id={}", percent_encode(&aid.to_string())));
    }
    if let Some(act) = action {
        params.push(format!("action={}", percent_encode(act)));
    }

    let path = format!("/audit?{}", params.join("&"));
    let page: RawAuditPage = client.get(&path).await?;
    Ok(page.items.into_iter().map(audit_entry_from_raw).collect())
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn purge_calls_delete_audit_purge_and_returns_result() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api/v1/audit/purge"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "deleted": 5,
                "cutoff": "2026-01-01T00:00:00Z"
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

        let result = purge(&client, None).await.expect("purge must succeed");
        assert_eq!(result.deleted, 5);
        assert_eq!(result.cutoff, "2026-01-01T00:00:00Z");
    }

    #[tokio::test]
    async fn purge_returns_auth_failure_on_403() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api/v1/audit/purge"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&server)
            .await;

        let cfg = crate::config::ResolvedConfig {
            server: server.uri(),
            token: "non-admin-token".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = crate::client::ApiClient::new(&cfg).expect("client");

        let err = purge(&client, None).await.expect_err("must fail with 403");
        assert!(matches!(err, CliError::AuthFailure(_)), "expected AuthFailure, got {err:?}");
    }
}
