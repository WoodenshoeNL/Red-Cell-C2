use super::super::build;
use super::super::build::validate_format;
use super::super::types::{
    BuildCompleted, BuildJobStatusResult, BuildJobSubmitted, BuildWaitCompleted,
};
use crate::defaults::PAYLOAD_BUILD_WAIT_TIMEOUT_SECS;
use crate::error::CliError;
use crate::output::TextRender;

// ── BuildJobSubmitted ─────────────────────────────────────────────────────────

#[test]
fn build_job_submitted_render_contains_job_id() {
    let r = BuildJobSubmitted { job_id: "job-001".to_owned() };
    assert!(r.render_text().contains("job-001"));
}

#[test]
fn build_job_submitted_serialises_job_id() {
    let r = BuildJobSubmitted { job_id: "j1".to_owned() };
    let v = serde_json::to_value(&r).expect("serialise");
    assert_eq!(v["job_id"], "j1");
}

// ── BuildCompleted ────────────────────────────────────────────────────────────

#[test]
fn build_completed_render_contains_id_and_size() {
    let r = BuildCompleted { id: "p1".to_owned(), size_bytes: 12345 };
    let rendered = r.render_text();
    assert!(rendered.contains("p1"));
    assert!(rendered.contains("12345"));
}

#[test]
fn build_completed_serialises_id_and_size() {
    let r = BuildCompleted { id: "p1".to_owned(), size_bytes: 99 };
    let v = serde_json::to_value(&r).expect("serialise");
    assert_eq!(v["id"], "p1");
    assert_eq!(v["size_bytes"], 99);
}

// ── build sends agent field ───────────────────────────────────────────────────

#[tokio::test]
async fn build_sends_agent_field_in_request_body() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/payloads/build"))
        .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({
            "job_id": "test-job-1"
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

    let result = build::build(
        &client,
        "http1",
        "x64",
        "exe",
        "phantom",
        None,
        false,
        PAYLOAD_BUILD_WAIT_TIMEOUT_SECS,
    )
    .await;
    assert!(result.is_ok(), "build must succeed: {result:?}");

    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 1);
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).expect("parse body");
    assert_eq!(body["agent"], "phantom", "request body must include agent field");
    assert_eq!(body["listener"], "http1");
    assert_eq!(body["arch"], "x64");
    assert_eq!(body["format"], "exe");
}

#[tokio::test]
async fn build_sends_default_demon_agent() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/payloads/build"))
        .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({
            "job_id": "test-job-2"
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

    let _ = build::build(
        &client,
        "http1",
        "x64",
        "exe",
        "demon",
        None,
        false,
        PAYLOAD_BUILD_WAIT_TIMEOUT_SECS,
    )
    .await;

    let requests = server.received_requests().await.expect("requests");
    let body: serde_json::Value = serde_json::from_slice(&requests[0].body).expect("parse body");
    assert_eq!(body["agent"], "demon", "default agent must be 'demon'");
}

// ── format validation ─────────────────────────────────────────────────────────

#[test]
fn validate_format_rejects_unknown_format() {
    assert!(matches!(validate_format("elf"), Err(CliError::InvalidArgs(_))));
    assert!(matches!(validate_format("shellcode"), Err(CliError::InvalidArgs(_))));
    assert!(matches!(validate_format(""), Err(CliError::InvalidArgs(_))));
}

#[test]
fn validate_format_accepts_valid_formats() {
    for fmt in ["exe", "dll", "bin"] {
        assert!(validate_format(fmt).is_ok(), "format '{fmt}' should be accepted");
    }
}

// ── BuildJobStatusResult ──────────────────────────────────────────────────────

#[test]
fn build_job_status_result_render_contains_job_id_and_status() {
    let r = BuildJobStatusResult {
        job_id: "job-42".to_owned(),
        status: "running".to_owned(),
        agent_type: Some("Demon".to_owned()),
        payload_id: None,
        size_bytes: None,
        error: None,
    };
    let text = r.render_text();
    assert!(text.contains("job-42"));
    assert!(text.contains("running"));
    assert!(text.contains("Demon"));
}

#[test]
fn build_job_status_result_render_done_includes_payload_id() {
    let r = BuildJobStatusResult {
        job_id: "job-99".to_owned(),
        status: "done".to_owned(),
        agent_type: None,
        payload_id: Some("pay-123".to_owned()),
        size_bytes: Some(65536),
        error: None,
    };
    let text = r.render_text();
    assert!(text.contains("pay-123"));
    assert!(text.contains("65536"));
}

#[test]
fn build_job_status_result_render_error_includes_message() {
    let r = BuildJobStatusResult {
        job_id: "job-err".to_owned(),
        status: "error".to_owned(),
        agent_type: None,
        payload_id: None,
        size_bytes: None,
        error: Some("linker failed".to_owned()),
    };
    let text = r.render_text();
    assert!(text.contains("linker failed"));
}

#[test]
fn build_job_status_result_serialises_all_fields() {
    let r = BuildJobStatusResult {
        job_id: "j1".to_owned(),
        status: "done".to_owned(),
        agent_type: Some("Phantom".to_owned()),
        payload_id: Some("p1".to_owned()),
        size_bytes: Some(100),
        error: None,
    };
    let v = serde_json::to_value(&r).expect("serialise");
    assert_eq!(v["job_id"], "j1");
    assert_eq!(v["status"], "done");
    assert_eq!(v["agent_type"], "Phantom");
    assert_eq!(v["payload_id"], "p1");
    assert_eq!(v["size_bytes"], 100);
    assert!(v["error"].is_null());
}

// ── BuildWaitCompleted ────────────────────────────────────────────────────────

#[test]
fn build_wait_completed_render_without_output() {
    let r = BuildWaitCompleted { payload_id: "pay-1".to_owned(), size_bytes: 2048, output: None };
    let text = r.render_text();
    assert!(text.contains("pay-1"));
    assert!(text.contains("2048"));
    assert!(!text.contains("→"));
}

#[test]
fn build_wait_completed_render_with_output() {
    let r = BuildWaitCompleted {
        payload_id: "pay-2".to_owned(),
        size_bytes: 4096,
        output: Some("./out.exe".to_owned()),
    };
    let text = r.render_text();
    assert!(text.contains("pay-2"));
    assert!(text.contains("./out.exe"));
    assert!(text.contains("→"));
}

#[test]
fn build_wait_completed_serialises_all_fields() {
    let r = BuildWaitCompleted {
        payload_id: "p99".to_owned(),
        size_bytes: 512,
        output: Some("/tmp/a.bin".to_owned()),
    };
    let v = serde_json::to_value(&r).expect("serialise");
    assert_eq!(v["payload_id"], "p99");
    assert_eq!(v["size_bytes"], 512);
    assert_eq!(v["output"], "/tmp/a.bin");
}

#[test]
fn build_wait_completed_serialises_null_output() {
    let r = BuildWaitCompleted { payload_id: "p100".to_owned(), size_bytes: 1, output: None };
    let v = serde_json::to_value(&r).expect("serialise");
    assert!(v["output"].is_null());
}

// ── build_status HTTP call ────────────────────────────────────────────────────

#[tokio::test]
async fn build_status_returns_pending_job() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/payloads/jobs/job-s1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "job_id": "job-s1",
            "status": "pending",
            "agent_type": "Demon"
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

    let result = build::build_status(&client, "job-s1").await.expect("build_status");
    assert_eq!(result.job_id, "job-s1");
    assert_eq!(result.status, "pending");
    assert_eq!(result.agent_type.as_deref(), Some("Demon"));
    assert!(result.payload_id.is_none());
}

#[tokio::test]
async fn build_status_returns_done_job() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/payloads/jobs/job-s2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "job_id": "job-s2",
            "status": "done",
            "agent_type": "Phantom",
            "payload_id": "pay-done",
            "size_bytes": 99999
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

    let result = build::build_status(&client, "job-s2").await.expect("build_status");
    assert_eq!(result.status, "done");
    assert_eq!(result.payload_id.as_deref(), Some("pay-done"));
    assert_eq!(result.size_bytes, Some(99999));
}

#[tokio::test]
async fn build_status_returns_not_found() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/payloads/jobs/no-such-job"))
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

    let err = build::build_status(&client, "no-such-job").await.expect_err("must fail with 404");
    assert!(matches!(err, CliError::NotFound(_)), "expected NotFound, got {err:?}");
}

// ── build_wait HTTP call ──────────────────────────────────────────────────────

#[tokio::test]
async fn build_wait_polls_until_done() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    let call_count = Arc::new(AtomicU32::new(0));
    let counter = call_count.clone();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/payloads/jobs/job-w1"))
        .respond_with(move |_req: &Request| {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            if n < 2 {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "job_id": "job-w1",
                    "status": "running",
                    "agent_type": "Demon"
                }))
            } else {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "job_id": "job-w1",
                    "status": "done",
                    "agent_type": "Demon",
                    "payload_id": "pay-w1",
                    "size_bytes": 8192
                }))
            }
        })
        .mount(&server)
        .await;

    let cfg = crate::config::ResolvedConfig {
        server: server.uri(),
        token: "tok".to_owned(),
        timeout: 5,
        tls_mode: crate::config::TlsMode::SystemRoots,
    };
    let client = crate::client::ApiClient::new(&cfg).expect("client");

    let result = build::build_wait(&client, "job-w1", None, 30).await.expect("build_wait");
    assert_eq!(result.payload_id, "pay-w1");
    assert_eq!(result.size_bytes, 8192);
    assert!(result.output.is_none());
    assert!(call_count.load(Ordering::SeqCst) >= 3, "must have polled at least 3 times");
}

#[tokio::test]
async fn build_wait_returns_error_on_build_failure() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/payloads/jobs/job-fail"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "job_id": "job-fail",
            "status": "error",
            "agent_type": "Demon",
            "error": "compilation failed"
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

    let err = build::build_wait(&client, "job-fail", None, 30)
        .await
        .expect_err("must fail on build error");
    let msg = format!("{err}");
    assert!(msg.contains("compilation failed"), "error must include message: {msg}");
}

#[tokio::test]
async fn build_wait_downloads_on_output() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    let call_count = Arc::new(AtomicU32::new(0));
    let counter = call_count.clone();

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/payloads/jobs/job-dl"))
        .respond_with(move |_req: &Request| {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "job_id": "job-dl",
                    "status": "pending",
                    "agent_type": "Demon"
                }))
            } else {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "job_id": "job-dl",
                    "status": "done",
                    "agent_type": "Demon",
                    "payload_id": "pay-dl",
                    "size_bytes": 5
                }))
            }
        })
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v1/payloads/pay-dl/download"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"ABCDE".as_ref()))
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

    let tmp = tempfile::tempdir().expect("tempdir");
    let dst = tmp.path().join("out.bin");
    let dst_str = dst.to_str().expect("valid path");

    let result = build::build_wait(&client, "job-dl", Some(dst_str), 30).await.expect("build_wait");
    assert_eq!(result.payload_id, "pay-dl");
    assert_eq!(result.output.as_deref(), Some(dst_str));
    assert_eq!(std::fs::read(&dst).expect("read file"), b"ABCDE");
}
