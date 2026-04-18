use std::sync::Arc;
use std::time::Duration;

use axum::{Json, Router, http::StatusCode as HttpStatusCode, routing::post};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use super::super::delivery::{build_retry_delays, is_transient_webhook_error};
use super::super::{AuditWebhookNotifier, WebhookError};
use red_cell_common::config::Profile;

use super::{
    discord_profile, flaky_webhook_server, notifier_with_timeout, sample_record, webhook_server,
};

/// Delivery that fails once then succeeds on the first retry should still
/// deliver the record and not increment the failure counter.
#[tokio::test]
async fn retry_succeeds_on_second_attempt() {
    // Server fails the first request, accepts the second.
    let (address, mut receiver, server) = flaky_webhook_server(1).await;
    // Use zero-delay retries so the test runs instantly.
    let notifier = AuditWebhookNotifier {
        retry_delays: Arc::from([Duration::ZERO, Duration::ZERO, Duration::ZERO].as_slice()),
        ..AuditWebhookNotifier::from_profile(&discord_profile(address))
    };

    notifier.notify_audit_record_detached(sample_record(30));
    assert!(notifier.shutdown(Duration::from_secs(5)).await, "shutdown should drain");

    assert!(receiver.try_recv().is_ok(), "record must arrive after successful retry");
    assert_eq!(notifier.discord_failure_count(), 0, "no permanent failure on successful retry");

    server.abort();
}

/// When all attempts fail the permanent failure counter must be incremented
/// and no payload should reach the webhook server after the final attempt.
#[tokio::test]
async fn failure_counter_increments_after_all_retries_exhausted() {
    let (address, _receiver, server) = webhook_server(HttpStatusCode::INTERNAL_SERVER_ERROR).await;
    // Three retries, all instantly, so we get 4 total attempts.
    let notifier = AuditWebhookNotifier {
        retry_delays: Arc::from([Duration::ZERO, Duration::ZERO, Duration::ZERO].as_slice()),
        ..AuditWebhookNotifier::from_profile(&discord_profile(address))
    };

    notifier.notify_audit_record_detached(sample_record(31));
    assert!(notifier.shutdown(Duration::from_secs(5)).await, "shutdown should drain");

    assert_eq!(notifier.discord_failure_count(), 1, "permanent failure after all retries");
    server.abort();
}

#[tokio::test]
async fn failure_counter_accumulates_across_multiple_failures() {
    let (address, _receiver, server) = webhook_server(HttpStatusCode::INTERNAL_SERVER_ERROR).await;
    let notifier = AuditWebhookNotifier {
        retry_delays: Arc::from([].as_slice()),
        ..AuditWebhookNotifier::from_profile(&discord_profile(address))
    };

    notifier.notify_audit_record_detached(sample_record(32));
    notifier.notify_audit_record_detached(sample_record(33));
    assert!(notifier.shutdown(Duration::from_secs(5)).await, "shutdown should drain");

    assert_eq!(notifier.discord_failure_count(), 2, "each failure independently increments");
    server.abort();
}

/// Retries must all be attempted before the failure counter increments,
/// even when the underlying error is a transport-level failure.
#[tokio::test]
async fn detached_retries_exhaust_on_connection_refused_before_incrementing_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("should bind");
    let address = listener.local_addr().expect("should resolve");
    let _accept_guard = tokio::spawn(async move {
        loop {
            let _ = listener.accept().await;
        }
    });

    let notifier = AuditWebhookNotifier {
        retry_delays: Arc::from([Duration::ZERO, Duration::ZERO, Duration::ZERO].as_slice()),
        ..notifier_with_timeout(address, Duration::from_secs(1))
    };

    notifier.notify_audit_record_detached(sample_record(64));
    assert!(notifier.shutdown(Duration::from_secs(5)).await, "shutdown should drain");
    assert_eq!(
        notifier.discord_failure_count(),
        1,
        "exactly one permanent failure after all retries exhausted"
    );
}

/// Two detached deliveries both hitting transport failure must each
/// increment the failure counter independently.
#[tokio::test]
async fn failure_counter_accumulates_across_multiple_transport_failures() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("should bind");
    let address = listener.local_addr().expect("should resolve");
    let _accept_guard = tokio::spawn(async move {
        loop {
            let _ = listener.accept().await;
        }
    });

    let notifier = notifier_with_timeout(address, Duration::from_secs(1));
    notifier.notify_audit_record_detached(sample_record(65));
    notifier.notify_audit_record_detached(sample_record(66));
    assert!(notifier.shutdown(Duration::from_secs(5)).await, "shutdown should drain");
    assert_eq!(
        notifier.discord_failure_count(),
        2,
        "each transport failure should independently increment the counter"
    );
}

// ── build_retry_delays unit tests ─────────────────────────────────────────

#[test]
fn build_retry_delays_produces_exponential_sequence() {
    let delays = build_retry_delays(3, 1);
    assert_eq!(
        delays.as_ref(),
        &[Duration::from_secs(1), Duration::from_secs(4), Duration::from_secs(16)],
        "base=1, retries=3 should yield 1s/4s/16s"
    );
}

#[test]
fn build_retry_delays_zero_retries_is_empty() {
    let delays = build_retry_delays(0, 1);
    assert!(delays.is_empty(), "MaxRetries=0 must produce an empty delay slice");
}

#[test]
fn build_retry_delays_custom_base() {
    let delays = build_retry_delays(3, 2);
    assert_eq!(
        delays.as_ref(),
        &[Duration::from_secs(2), Duration::from_secs(8), Duration::from_secs(32)],
        "base=2, retries=3 should yield 2s/8s/32s"
    );
}

// ── is_transient_webhook_error unit tests ────────────────────────────────

/// Verify status-code transience classification.
///
/// `reqwest::Error` (the `Request` variant) cannot be easily constructed in
/// unit tests without spawning an async runtime.  Transport-level transience
/// is covered by the async integration tests
/// (`detached_delivery_increments_failure_count_on_connection_refused` and
/// `detached_retries_exhaust_on_connection_refused_before_incrementing_failure`).
#[test]
fn transient_status_code_classification() {
    use reqwest::StatusCode;

    // Transient statuses — retries must fire.
    assert!(is_transient_webhook_error(&WebhookError::UnexpectedStatus(
        StatusCode::TOO_MANY_REQUESTS
    )));
    assert!(is_transient_webhook_error(&WebhookError::UnexpectedStatus(
        StatusCode::INTERNAL_SERVER_ERROR
    )));
    assert!(is_transient_webhook_error(&WebhookError::UnexpectedStatus(
        StatusCode::SERVICE_UNAVAILABLE
    )));
    assert!(is_transient_webhook_error(&WebhookError::UnexpectedStatus(StatusCode::BAD_GATEWAY)));

    // Permanent statuses — retries must NOT fire.
    assert!(
        !is_transient_webhook_error(&WebhookError::UnexpectedStatus(StatusCode::BAD_REQUEST)),
        "400 Bad Request is not transient"
    );
    assert!(
        !is_transient_webhook_error(&WebhookError::UnexpectedStatus(StatusCode::UNAUTHORIZED)),
        "401 Unauthorized is not transient"
    );
    assert!(
        !is_transient_webhook_error(&WebhookError::UnexpectedStatus(StatusCode::FORBIDDEN)),
        "403 Forbidden is not transient"
    );
    assert!(
        !is_transient_webhook_error(&WebhookError::UnexpectedStatus(StatusCode::NOT_FOUND)),
        "404 Not Found is not transient"
    );
}

// ── configurable retry integration tests ─────────────────────────────────

/// Profile `MaxRetries = 2` must produce exactly 2 retry delays and therefore
/// a total of 3 delivery attempts (1 initial + 2 retries).
#[tokio::test]
async fn profile_max_retries_limits_attempts() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let (request_count, server_addr, server) = {
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = count.clone();
        let app = Router::new().route(
            "/",
            post(move |Json(_): Json<Value>| {
                let count = count2.clone();
                async move {
                    count.fetch_add(1, Ordering::Relaxed);
                    (HttpStatusCode::INTERNAL_SERVER_ERROR, Json(json!({"ok": false})))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("should bind");
        let addr = listener.local_addr().expect("should resolve");
        let srv = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("server should not fail");
        });
        (count, addr, srv)
    };

    let profile = Profile::parse(&format!(
        r#"
        Teamserver {{
          Host = "127.0.0.1"
          Port = 40056
        }}

        Operators {{
          user "operator" {{
            Password = "password1234"
          }}
        }}

        WebHook {{
          Discord {{
            Url = "http://{server_addr}/"
            MaxRetries = 2
            RetryBaseDelaySecs = 0
          }}
        }}

        Demon {{}}
        "#
    ))
    .expect("profile should parse");

    let notifier = AuditWebhookNotifier::from_profile(&profile);

    notifier.notify_audit_record_detached(sample_record(200));
    assert!(notifier.shutdown(Duration::from_secs(5)).await, "shutdown should drain");

    // 1 initial + 2 retries = 3 total attempts.
    assert_eq!(
        request_count.load(std::sync::atomic::Ordering::Relaxed),
        3,
        "MaxRetries=2 should produce 3 total attempts (1 initial + 2 retries)"
    );
    assert_eq!(notifier.discord_failure_count(), 1, "all attempts exhausted → 1 failure");

    server.abort();
}

/// A permanent 4xx response (400 Bad Request) must not trigger retries —
/// only the initial attempt should reach the server.
#[tokio::test]
async fn non_transient_4xx_error_is_not_retried() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let (request_count, server_addr, server) = {
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = count.clone();
        let app = Router::new().route(
            "/",
            post(move |Json(_): Json<Value>| {
                let count = count2.clone();
                async move {
                    count.fetch_add(1, Ordering::Relaxed);
                    (HttpStatusCode::BAD_REQUEST, Json(json!({"ok": false})))
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("should bind");
        let addr = listener.local_addr().expect("should resolve");
        let srv = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("server should not fail");
        });
        (count, addr, srv)
    };

    // Three zero-delay retries configured — but 400 is non-transient, so none fire.
    let notifier = AuditWebhookNotifier {
        retry_delays: Arc::from([Duration::ZERO, Duration::ZERO, Duration::ZERO].as_slice()),
        ..AuditWebhookNotifier::from_profile(&discord_profile(server_addr))
    };

    notifier.notify_audit_record_detached(sample_record(201));
    assert!(notifier.shutdown(Duration::from_secs(5)).await, "shutdown should drain");

    assert_eq!(
        request_count.load(std::sync::atomic::Ordering::Relaxed),
        1,
        "400 Bad Request must not be retried — only 1 request should reach the server"
    );
    assert_eq!(notifier.discord_failure_count(), 1, "permanent failure should be recorded");

    server.abort();
}

/// 429 Too Many Requests is transient and must be retried.
#[tokio::test]
async fn rate_limit_429_is_retried() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let (request_count, server_addr, server) = {
        let count = Arc::new(AtomicUsize::new(0));
        let count2 = count.clone();
        let app = Router::new().route(
            "/",
            post(move |Json(_): Json<Value>| {
                let count = count2.clone();
                async move {
                    let n = count.fetch_add(1, Ordering::Relaxed);
                    if n == 0 {
                        (HttpStatusCode::TOO_MANY_REQUESTS, Json(json!({"ok": false})))
                    } else {
                        (HttpStatusCode::OK, Json(json!({"ok": true})))
                    }
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("should bind");
        let addr = listener.local_addr().expect("should resolve");
        let srv = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("server should not fail");
        });
        (count, addr, srv)
    };

    let notifier = AuditWebhookNotifier {
        retry_delays: Arc::from([Duration::ZERO, Duration::ZERO, Duration::ZERO].as_slice()),
        ..AuditWebhookNotifier::from_profile(&discord_profile(server_addr))
    };

    notifier.notify_audit_record_detached(sample_record(202));
    assert!(notifier.shutdown(Duration::from_secs(5)).await, "shutdown should drain");

    assert_eq!(
        request_count.load(std::sync::atomic::Ordering::Relaxed),
        2,
        "429 must be retried: 1 initial 429 + 1 successful retry = 2 requests"
    );
    assert_eq!(notifier.discord_failure_count(), 0, "retry succeeded so no permanent failure");

    server.abort();
}
