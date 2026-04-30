use super::super::build;
use super::super::types::CacheFlushResult;
use crate::error::CliError;
use crate::output::TextRender;

// ── CacheFlushResult ──────────────────────────────────────────────────────────

#[test]
fn cache_flush_result_render_contains_count() {
    let r = CacheFlushResult { flushed: 7 };
    let text = r.render_text();
    assert!(text.contains("7"), "render must include flushed count");
    assert!(text.to_lowercase().contains("flush"), "render must mention flush");
}

#[test]
fn cache_flush_result_render_zero() {
    let r = CacheFlushResult { flushed: 0 };
    let text = r.render_text();
    assert!(text.contains("0"));
}

#[test]
fn cache_flush_result_serialises_flushed_field() {
    let r = CacheFlushResult { flushed: 42 };
    let v = serde_json::to_value(&r).expect("serialise");
    assert_eq!(v["flushed"], 42);
}

// ── cache_flush HTTP call ─────────────────────────────────────────────────────

#[tokio::test]
async fn cache_flush_calls_post_payload_cache_and_returns_count() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/payload-cache"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "flushed": 3 })))
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

    let result = build::cache_flush(&client).await.expect("cache_flush must succeed");
    assert_eq!(result.flushed, 3);
}

#[tokio::test]
async fn cache_flush_returns_auth_failure_on_403() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/payload-cache"))
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

    let err = build::cache_flush(&client).await.expect_err("must fail with 403");
    assert!(matches!(err, CliError::AuthFailure(_)), "expected AuthFailure, got {err:?}");
}
