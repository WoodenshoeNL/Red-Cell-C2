use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::header::{AUTHORIZATION, RETRY_AFTER};
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use red_cell_common::config::OperatorRole;
use tokio::sync::Mutex;

use crate::Database;
use crate::api::auth::{
    API_KEY_HEADER, ApiAuthError, ApiIdentity, ApiKeyDigest, ApiRateLimit, ApiRuntime,
    MAX_FAILED_API_AUTH_ATTEMPTS, RATE_LIMIT_WINDOW, RateLimitSubject, RateLimitWindow,
};
use crate::api::json_error_response;
use crate::rate_limiter::AttemptWindow;

use super::helpers::*;

// ---- lookup_key_ct unit tests ----

fn make_digest(byte: u8) -> ApiKeyDigest {
    ApiKeyDigest::new_for_test([byte; 32])
}

fn make_identity(key_id: &str) -> ApiIdentity {
    ApiIdentity { key_id: key_id.to_owned(), role: OperatorRole::Analyst }
}

#[test]
fn lookup_key_ct_returns_matching_identity() {
    let keys = vec![
        (make_digest(0xAA), make_identity("key-a")),
        (make_digest(0xBB), make_identity("key-b")),
    ];
    let result = ApiRuntime::lookup_key_ct(&keys, &make_digest(0xBB));
    assert_eq!(result.expect("unwrap").key_id, "key-b");
}

#[test]
fn lookup_key_ct_returns_none_for_unknown_digest() {
    let keys = vec![(make_digest(0xAA), make_identity("key-a"))];
    let result = ApiRuntime::lookup_key_ct(&keys, &make_digest(0xFF));
    assert!(result.is_none());
}

#[test]
fn lookup_key_ct_returns_none_for_empty_key_list() {
    let result = ApiRuntime::lookup_key_ct(&[], &make_digest(0x01));
    assert!(result.is_none());
}

#[test]
fn lookup_key_ct_scans_all_entries_and_returns_last_match() {
    // Two entries with identical digests: the second one should win because
    // the scan never short-circuits after finding the first match.
    let digest = make_digest(0x42);
    let keys = vec![(digest, make_identity("first")), (digest, make_identity("second"))];
    let result = ApiRuntime::lookup_key_ct(&keys, &digest);
    // Always visits every entry; last match wins.
    assert_eq!(result.expect("unwrap").key_id, "second");
}

#[tokio::test]
async fn json_error_response_returns_status_and_documented_body_shape() {
    let response =
        json_error_response(StatusCode::BAD_REQUEST, "invalid_request", "Missing listener");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "invalid_request");
    assert_eq!(body["error"]["message"], "Missing listener");
    assert_eq!(
        body,
        serde_json::json!({
            "error": {
                "code": "invalid_request",
                "message": "Missing listener"
            }
        })
    );
}

#[tokio::test]
async fn json_error_response_preserves_error_fields_for_non_success_statuses() {
    let unauthorized =
        json_error_response(StatusCode::UNAUTHORIZED, "missing_api_key", "Missing API key header");
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    let unauthorized_body = read_json(unauthorized).await;
    assert_eq!(unauthorized_body["error"]["code"], "missing_api_key");
    assert_eq!(unauthorized_body["error"]["message"], "Missing API key header");

    let server_error = json_error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "listener_start_failed",
        "Listener startup failed",
    );
    assert_eq!(server_error.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let server_error_body = read_json(server_error).await;
    assert_eq!(server_error_body["error"]["code"], "listener_start_failed");
    assert_eq!(server_error_body["error"]["message"], "Listener startup failed");
}

#[tokio::test]
async fn json_error_response_serializes_punctuation_and_mixed_case_verbatim() {
    let response = json_error_response(
        StatusCode::CONFLICT,
        "Agent.State/Conflict",
        "Mixed-Case: listener 'HTTP-01' isn't ready!",
    );

    assert_eq!(response.status(), StatusCode::CONFLICT);

    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "Agent.State/Conflict");
    assert_eq!(body["error"]["message"], "Mixed-Case: listener 'HTTP-01' isn't ready!");
    assert!(body.get("error").and_then(Value::as_object).is_some());
}

#[tokio::test]
async fn root_reports_versioning_and_docs_metadata() {
    let app = test_router(None).await;

    let response = app
        .oneshot(Request::builder().uri("/").body(Body::empty()).expect("request"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);

    let body = read_json(response).await;
    assert_eq!(body["version"], "v1");
    assert_eq!(body["prefix"], "/api/v1");
    assert_eq!(body["openapi_path"], "/api/v1/openapi.json");
    assert_eq!(body["documentation_path"], "/api/v1/docs");
    assert_eq!(body["enabled"], false);
}

#[tokio::test]
async fn protected_routes_require_api_key() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(Request::builder().uri("/listeners").body(Body::empty()).expect("request"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "missing_api_key");
}

#[tokio::test]
async fn bearer_token_authenticates_protected_routes() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/listeners")
                .header(AUTHORIZATION, "Bearer secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn protected_routes_reject_unknown_api_key() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/listeners")
                .header(API_KEY_HEADER, "secret-admio")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "invalid_api_key");
}

#[tokio::test]
async fn analyst_key_can_read_but_cannot_modify() {
    let app =
        test_router(Some((60, "rest-analyst", "secret-analyst", OperatorRole::Analyst))).await;

    let get_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/listeners")
                .header(API_KEY_HEADER, "secret-analyst")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(get_response.status(), StatusCode::OK);

    let post_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/listeners")
                .header(API_KEY_HEADER, "secret-analyst")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"protocol":"smb","config":{"name":"pivot","pipe_name":"pivot-pipe"}}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(post_response.status(), StatusCode::FORBIDDEN);

    let body = read_json(post_response).await;
    assert_eq!(body["error"]["code"], "forbidden");
}

#[tokio::test]
async fn permission_denied_audit_record_created_when_analyst_key_attempts_write() {
    let database = Database::connect_in_memory().await.expect("database");
    let (app, _, _) = test_router_with_database(
        database.clone(),
        Some((60, "rest-analyst", "secret-analyst", OperatorRole::Analyst)),
    )
    .await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/listeners")
                .header(API_KEY_HEADER, "secret-analyst")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"protocol":"smb","config":{"name":"pivot","pipe_name":"pivot-pipe"}}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let page = crate::query_audit_log(
        &database,
        &crate::AuditQuery {
            action: Some("api.permission_denied".to_owned()),
            actor: Some("rest-analyst".to_owned()),
            ..crate::AuditQuery::default()
        },
    )
    .await
    .expect("audit query should succeed");

    assert_eq!(page.total, 1, "one api.permission_denied record expected");
    let record = &page.items[0];
    assert_eq!(record.action, "api.permission_denied");
    assert_eq!(record.actor, "rest-analyst");
    assert_eq!(record.result_status, crate::AuditResultStatus::Failure);
    let required =
        record.parameters.as_ref().and_then(|p| p.get("required")).and_then(|v| v.as_str());
    assert!(required.is_some(), "permission_denied record should include required permission");
}

// ---- rate_limiting tests ----

#[tokio::test]
async fn rate_limiting_rejects_excess_requests() {
    let app = test_router(Some((1, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/listeners")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(first.status(), StatusCode::OK);

    let second = app
        .oneshot(
            Request::builder()
                .uri("/listeners")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(second.headers().get(RETRY_AFTER).and_then(|v| v.to_str().ok()), Some("60"),);

    let body = read_json(second).await;
    assert_eq!(body["error"]["code"], "rate_limited");
}

#[tokio::test]
async fn rate_limiting_rejects_repeated_invalid_api_keys() {
    let app = test_router(Some((1, "rest-admin", "secret-admin", OperatorRole::Admin))).await;
    let client_ip = SocketAddr::from(([198, 51, 100, 10], 443));

    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/listeners")
                .header(API_KEY_HEADER, "wrong-key")
                .extension(ConnectInfo(client_ip))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(first.status(), StatusCode::UNAUTHORIZED);
    let body = read_json(first).await;
    assert_eq!(body["error"]["code"], "invalid_api_key");

    let second = app
        .oneshot(
            Request::builder()
                .uri("/listeners")
                .header(API_KEY_HEADER, "another-wrong-key")
                .extension(ConnectInfo(client_ip))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = read_json(second).await;
    assert_eq!(body["error"]["code"], "rate_limited");
}

#[tokio::test]
async fn rate_limiting_rejects_repeated_missing_api_keys() {
    let app = test_router(Some((1, "rest-admin", "secret-admin", OperatorRole::Admin))).await;
    let client_ip = SocketAddr::from(([203, 0, 113, 10], 443));

    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/listeners")
                .extension(ConnectInfo(client_ip))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(first.status(), StatusCode::UNAUTHORIZED);
    let body = read_json(first).await;
    assert_eq!(body["error"]["code"], "missing_api_key");

    let second = app
        .oneshot(
            Request::builder()
                .uri("/listeners")
                .extension(ConnectInfo(client_ip))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = read_json(second).await;
    assert_eq!(body["error"]["code"], "rate_limited");
}

#[tokio::test]
async fn rate_limiting_prunes_expired_windows_for_inactive_keys() {
    let api = ApiRuntime::new_for_test(
        Arc::new(ApiRuntime::generate_key_hash_secret().expect("rng should work in tests")),
        Arc::new(Vec::new()),
        ApiRateLimit { requests_per_minute: 60 },
        Arc::new(Mutex::new(BTreeMap::from([
            (
                RateLimitSubject::MissingApiKey,
                RateLimitWindow {
                    started_at: Instant::now() - RATE_LIMIT_WINDOW - Duration::from_secs(1),
                    request_count: 1,
                },
            ),
            (
                RateLimitSubject::InvalidAuthorizationHeader,
                RateLimitWindow { started_at: Instant::now(), request_count: 1 },
            ),
        ]))),
        Arc::new(Mutex::new(HashMap::new())),
    );

    api.check_rate_limit(&RateLimitSubject::PresentedCredential(ApiRuntime::hash_api_key(
        api.key_hash_secret(),
        "new-key",
    )))
    .await
    .expect("rate limit should allow request");

    let windows = api.windows().lock().await;
    assert!(!windows.contains_key(&RateLimitSubject::MissingApiKey));
    assert!(windows.contains_key(&RateLimitSubject::InvalidAuthorizationHeader));
    assert!(windows.contains_key(&RateLimitSubject::PresentedCredential(
        ApiRuntime::hash_api_key(api.key_hash_secret(), "new-key")
    )));
    assert_eq!(windows.len(), 2);
}

// ---- auth_failure_rate_limiter tests ----

#[tokio::test]
async fn auth_failure_rate_limiter_blocks_after_max_failed_attempts() {
    // Use a high per-request limit so only the auth-failure limiter fires.
    let app = test_router(Some((1000, "rest-admin", "secret-admin", OperatorRole::Admin))).await;
    let client_ip = SocketAddr::from(([192, 0, 2, 42], 1234));

    // Exhaust the allowed failure budget.
    for _ in 0..MAX_FAILED_API_AUTH_ATTEMPTS {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/listeners")
                    .header(API_KEY_HEADER, "wrong-key")
                    .extension(ConnectInfo(client_ip))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_api_key");
    }

    // The next attempt must be blocked before any HMAC work.
    let blocked = app
        .oneshot(
            Request::builder()
                .uri("/listeners")
                .header(API_KEY_HEADER, "yet-another-wrong-key")
                .extension(ConnectInfo(client_ip))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = read_json(blocked).await;
    assert_eq!(body["error"]["code"], "rate_limited");
}

#[tokio::test]
async fn auth_failure_rate_limiter_resets_on_successful_auth() {
    let app = test_router(Some((1000, "rest-admin", "secret-admin", OperatorRole::Admin))).await;
    let client_ip = SocketAddr::from(([192, 0, 2, 43], 1234));

    // Record some failures but stay below the threshold.
    for _ in 0..MAX_FAILED_API_AUTH_ATTEMPTS - 1 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/listeners")
                    .header(API_KEY_HEADER, "wrong-key")
                    .extension(ConnectInfo(client_ip))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // Successful auth clears the failure counter.
    let ok = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/listeners")
                .header(API_KEY_HEADER, "secret-admin")
                .extension(ConnectInfo(client_ip))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(ok.status(), StatusCode::OK);

    // After the reset, a full fresh budget is available — the first wrong attempt is allowed.
    let after_reset = app
        .oneshot(
            Request::builder()
                .uri("/listeners")
                .header(API_KEY_HEADER, "wrong-key-after-reset")
                .extension(ConnectInfo(client_ip))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(after_reset.status(), StatusCode::UNAUTHORIZED);
    let body = read_json(after_reset).await;
    assert_eq!(body["error"]["code"], "invalid_api_key");
}

#[tokio::test]
async fn auth_failure_rate_limiter_is_not_applied_without_client_ip() {
    // Without a ConnectInfo extension there is no IP to track.  A series of
    // unique wrong keys should each produce invalid_api_key, not rate_limited.
    let app = test_router(Some((1000, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    for i in 0..MAX_FAILED_API_AUTH_ATTEMPTS + 1 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/listeners")
                    .header(API_KEY_HEADER, format!("unique-wrong-key-{i}"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "invalid_api_key");
    }
}

#[tokio::test]
async fn openapi_spec_is_served() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(Request::builder().uri("/openapi.json").body(Body::empty()).expect("request"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);

    let body = read_json(response).await;
    assert_eq!(body["openapi"], "3.1.0");
    assert!(body["paths"]["/api/v1/listeners"].is_object());
    assert!(body["paths"]["/api/v1/credentials"].is_object());
    assert!(body["paths"]["/api/v1/jobs"].is_object());
}

#[tokio::test]
async fn missing_route_returns_json_not_found() {
    let app = test_router(None).await;

    let response = app
        .oneshot(Request::builder().uri("/missing").body(Body::empty()).expect("request"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "not_found");
}

// ---- Unit tests for auth failure tracking (is_auth_failure_allowed / record_auth_failure / record_auth_success) ----

/// Build a minimal `ApiRuntime` with no API keys and a disabled request
/// rate-limit, suitable for testing the auth-failure and rate-limit
/// internals in isolation.
fn test_api_runtime(requests_per_minute: u32) -> ApiRuntime {
    ApiRuntime::new_for_test(
        Arc::new(ApiRuntime::generate_key_hash_secret().expect("rng should work in tests")),
        Arc::new(Vec::new()),
        ApiRateLimit { requests_per_minute },
        Arc::new(Mutex::new(BTreeMap::new())),
        Arc::new(Mutex::new(HashMap::new())),
    )
}

fn test_ip(last_octet: u8) -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, last_octet))
}

#[tokio::test]
async fn auth_failure_n_minus_1_attempts_still_allowed() {
    let api = test_api_runtime(0);
    let ip = test_ip(1);

    for _ in 0..MAX_FAILED_API_AUTH_ATTEMPTS - 1 {
        api.record_auth_failure(ip).await;
    }

    assert!(api.is_auth_failure_allowed(ip).await, "N-1 failures must still be allowed");
}

#[tokio::test]
async fn auth_failure_nth_attempt_triggers_lockout() {
    let api = test_api_runtime(0);
    let ip = test_ip(2);

    for _ in 0..MAX_FAILED_API_AUTH_ATTEMPTS {
        api.record_auth_failure(ip).await;
    }

    assert!(!api.is_auth_failure_allowed(ip).await, "Nth failure must trigger lockout");
}

#[tokio::test]
async fn auth_failure_unknown_ip_is_always_allowed() {
    let api = test_api_runtime(0);
    assert!(
        api.is_auth_failure_allowed(test_ip(99)).await,
        "IP with no failure history must be allowed"
    );
}

#[tokio::test]
async fn auth_success_clears_failure_state() {
    let api = test_api_runtime(0);
    let ip = test_ip(3);

    // Accumulate failures up to the lockout threshold.
    for _ in 0..MAX_FAILED_API_AUTH_ATTEMPTS {
        api.record_auth_failure(ip).await;
    }
    assert!(!api.is_auth_failure_allowed(ip).await);

    // A successful auth must clear the failure window entirely.
    api.record_auth_success(ip).await;

    assert!(
        api.is_auth_failure_allowed(ip).await,
        "successful auth must reset the failure counter"
    );

    // Verify the window is completely removed, not just zeroed.
    let windows = api.auth_failure_windows().lock().await;
    assert!(!windows.contains_key(&ip), "window entry must be removed on success");
}

#[tokio::test]
async fn auth_failure_window_expiry_resets_allowance() {
    let api = test_api_runtime(0);
    let ip = test_ip(4);

    // Manually insert an expired window that exceeded the failure threshold.
    {
        let mut windows = api.auth_failure_windows().lock().await;
        windows.insert(
            ip,
            AttemptWindow {
                attempts: MAX_FAILED_API_AUTH_ATTEMPTS + 10,
                window_start: Instant::now() - RATE_LIMIT_WINDOW - Duration::from_secs(1),
            },
        );
    }

    assert!(
        api.is_auth_failure_allowed(ip).await,
        "expired window must be pruned, allowing the IP again"
    );

    // The expired entry should have been removed from the map.
    let windows = api.auth_failure_windows().lock().await;
    assert!(!windows.contains_key(&ip), "expired window must be removed");
}

#[tokio::test]
async fn auth_failure_record_resets_window_after_expiry() {
    let api = test_api_runtime(0);
    let ip = test_ip(5);

    // Insert an expired window with many failures.
    {
        let mut windows = api.auth_failure_windows().lock().await;
        windows.insert(
            ip,
            AttemptWindow {
                attempts: MAX_FAILED_API_AUTH_ATTEMPTS,
                window_start: Instant::now() - RATE_LIMIT_WINDOW - Duration::from_secs(1),
            },
        );
    }

    // Recording a new failure should start a fresh window with attempts=1.
    api.record_auth_failure(ip).await;

    let windows = api.auth_failure_windows().lock().await;
    let window = windows.get(&ip).expect("window must exist after recording failure");
    assert_eq!(window.attempts, 1, "expired window must reset to 1 attempt");
}

#[tokio::test]
async fn auth_failure_sequential_from_same_ip_count_correctly() {
    let api = test_api_runtime(0);
    let ip = test_ip(6);

    // Record failures one at a time (serialised by the mutex) and verify
    // that they increment linearly — no double-counting.
    for expected in 1..=MAX_FAILED_API_AUTH_ATTEMPTS {
        api.record_auth_failure(ip).await;
        let windows = api.auth_failure_windows().lock().await;
        let window = windows.get(&ip).expect("window must exist");
        assert_eq!(
            window.attempts, expected,
            "attempt count must equal {expected} after {expected} sequential failures"
        );
    }
}

#[tokio::test]
async fn auth_failure_different_ips_are_independent() {
    let api = test_api_runtime(0);
    let ip_a = test_ip(10);
    let ip_b = test_ip(11);

    // Lock out ip_a.
    for _ in 0..MAX_FAILED_API_AUTH_ATTEMPTS {
        api.record_auth_failure(ip_a).await;
    }

    // ip_b should be unaffected.
    assert!(!api.is_auth_failure_allowed(ip_a).await);
    assert!(api.is_auth_failure_allowed(ip_b).await);
}

#[tokio::test]
async fn auth_failure_success_on_one_ip_does_not_affect_another() {
    let api = test_api_runtime(0);
    let ip_a = test_ip(20);
    let ip_b = test_ip(21);

    for _ in 0..MAX_FAILED_API_AUTH_ATTEMPTS {
        api.record_auth_failure(ip_a).await;
        api.record_auth_failure(ip_b).await;
    }

    // Clear only ip_a.
    api.record_auth_success(ip_a).await;

    assert!(api.is_auth_failure_allowed(ip_a).await);
    assert!(!api.is_auth_failure_allowed(ip_b).await);
}

// ---- Unit tests for check_rate_limit ----

#[tokio::test]
async fn rate_limit_allows_requests_under_limit() {
    let api = test_api_runtime(10);
    let subject = RateLimitSubject::ClientIp(test_ip(1));

    for _ in 0..10 {
        assert!(api.check_rate_limit(&subject).await.is_ok());
    }
}

#[tokio::test]
async fn rate_limit_blocks_at_limit() {
    let api = test_api_runtime(3);
    let subject = RateLimitSubject::ClientIp(test_ip(2));

    for _ in 0..3 {
        api.check_rate_limit(&subject).await.expect("should be allowed");
    }

    let err = api.check_rate_limit(&subject).await.expect_err("expected Err");
    assert!(
        matches!(err, ApiAuthError::RateLimited { retry_after_seconds: 60 }),
        "4th request must be rate-limited, got {err:?}"
    );
}

#[tokio::test]
async fn rate_limit_disabled_allows_everything() {
    let api = test_api_runtime(0); // 0 means disabled
    let subject = RateLimitSubject::ClientIp(test_ip(3));

    for _ in 0..100 {
        assert!(api.check_rate_limit(&subject).await.is_ok());
    }
}

#[tokio::test]
async fn rate_limit_window_expiry_resets_count() {
    let api = test_api_runtime(2);
    let subject = RateLimitSubject::ClientIp(test_ip(4));

    // Exhaust the limit.
    for _ in 0..2 {
        api.check_rate_limit(&subject).await.expect("should be allowed");
    }
    assert!(api.check_rate_limit(&subject).await.is_err());

    // Simulate window expiry by back-dating the window.
    {
        let mut windows = api.windows().lock().await;
        if let Some(w) = windows.get_mut(&subject) {
            w.started_at = Instant::now() - RATE_LIMIT_WINDOW - Duration::from_secs(1);
        }
    }

    // After expiry, a new window starts and the request should succeed.
    assert!(
        api.check_rate_limit(&subject).await.is_ok(),
        "request must be allowed after window expiry"
    );

    // The window should be reset with count = 1.
    let windows = api.windows().lock().await;
    let w = windows.get(&subject).expect("window must exist");
    assert_eq!(w.request_count, 1, "request count must be 1 after window reset");
}

#[tokio::test]
async fn rate_limit_different_subjects_are_independent() {
    let api = test_api_runtime(1);
    let subject_a = RateLimitSubject::ClientIp(test_ip(5));
    let subject_b = RateLimitSubject::ClientIp(test_ip(6));

    api.check_rate_limit(&subject_a).await.expect("first request for A");
    assert!(api.check_rate_limit(&subject_a).await.is_err(), "A must be rate-limited");

    // B should still be allowed.
    assert!(api.check_rate_limit(&subject_b).await.is_ok(), "B must be independent");
}

#[tokio::test]
async fn disabled_api_rejects_authenticated_request() {
    let app = test_router(None).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/listeners")
                .header("X-Api-Key", "arbitrary-key-value")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "api_disabled");
}
