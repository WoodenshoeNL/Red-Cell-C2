use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use std::net::SocketAddr;

use red_cell_common::config::OperatorRole;
use red_cell_common::crypto::hash_password_sha3;

use super::helpers::*;
use crate::{AuditQuery, AuditResultStatus, Database};

fn login_request(user: &str, password_sha3: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(format!(r#"{{"user":"{user}","password_sha3":"{password_sha3}"}}"#)))
        .expect("request")
}

fn login_request_with_ip(user: &str, password_sha3: &str, addr: SocketAddr) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header("content-type", "application/json")
        .extension(ConnectInfo(addr))
        .body(Body::from(format!(r#"{{"user":"{user}","password_sha3":"{password_sha3}"}}"#)))
        .expect("request")
}

#[tokio::test]
async fn login_succeeds_with_valid_credentials() {
    let app = test_router(Some((60, "k", "test-key", OperatorRole::Admin))).await;
    let password_hash = hash_password_sha3("password1234");

    let response = app.oneshot(login_request("Neo", &password_hash)).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    let body = read_json(response).await;
    assert_eq!(body["user"], "Neo");
    assert!(body["token"].is_string(), "response must include a token");
    assert!(!body["token"].as_str().unwrap_or_default().is_empty(), "token must not be empty");
}

#[tokio::test]
async fn login_fails_with_wrong_password() {
    let app = test_router(Some((60, "k", "test-key", OperatorRole::Admin))).await;
    let wrong_hash = hash_password_sha3("wrong-password");

    let response = app.oneshot(login_request("Neo", &wrong_hash)).await.expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "authentication_failed");
}

#[tokio::test]
async fn login_fails_with_unknown_user() {
    let app = test_router(Some((60, "k", "test-key", OperatorRole::Admin))).await;
    let password_hash = hash_password_sha3("password1234");

    let response =
        app.oneshot(login_request("UnknownUser", &password_hash)).await.expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "authentication_failed");
}

#[tokio::test]
async fn login_rejects_empty_user() {
    let app = test_router(Some((60, "k", "test-key", OperatorRole::Admin))).await;

    let response =
        app.oneshot(login_request("", &hash_password_sha3("x"))).await.expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "invalid_request");
    assert!(
        body["error"]["message"].as_str().unwrap_or_default().contains("user"),
        "error should mention the user field"
    );
}

#[tokio::test]
async fn login_rejects_empty_password_sha3() {
    let app = test_router(Some((60, "k", "test-key", OperatorRole::Admin))).await;

    let response = app.oneshot(login_request("Neo", "")).await.expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "invalid_request");
    assert!(
        body["error"]["message"].as_str().unwrap_or_default().contains("password_sha3"),
        "error should mention the password_sha3 field"
    );
}

#[tokio::test]
async fn login_rejects_malformed_json() {
    let app = test_router(Some((60, "k", "test-key", OperatorRole::Admin))).await;

    let request = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header("content-type", "application/json")
        .body(Body::from("not json"))
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "invalid_request");
}

#[tokio::test]
async fn login_rejects_missing_fields() {
    let app = test_router(Some((60, "k", "test-key", OperatorRole::Admin))).await;

    let request = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"user":"Neo"}"#))
        .expect("request");

    let response = app.oneshot(request).await.expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "invalid_request");
}

#[tokio::test]
async fn login_rate_limits_after_max_attempts() {
    let (app, _registry, _auth) =
        test_router_with_registry(Some((60, "k", "test-key", OperatorRole::Admin))).await;
    let wrong_hash = hash_password_sha3("wrong");
    let client_addr: SocketAddr = "192.0.2.1:12345".parse().expect("addr");

    // Exhaust the 5-attempt window. The rate limiter's try_acquire pre-counts
    // each attempt, so after 5 calls the IP is blocked.
    for _ in 0..5 {
        let resp = app
            .clone()
            .oneshot(login_request_with_ip("Neo", &wrong_hash, client_addr))
            .await
            .expect("response");
        // First 5 should be 401 (bad password), not 429
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // The 6th attempt from the same IP should be rate-limited.
    let resp = app
        .clone()
        .oneshot(login_request_with_ip("Neo", &wrong_hash, client_addr))
        .await
        .expect("response");
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    let body = read_json(resp).await;
    assert_eq!(body["error"]["code"], "rate_limited");
}

#[tokio::test]
async fn login_does_not_require_api_key() {
    // Endpoint must be accessible without the x-api-key header.
    let app = test_router(Some((60, "k", "test-key", OperatorRole::Admin))).await;
    let password_hash = hash_password_sha3("password1234");

    let response = app.oneshot(login_request("Neo", &password_hash)).await.expect("response");
    // A 200 means the endpoint was reached and auth succeeded without an API key.
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn login_works_without_api_runtime_configured() {
    // Even when no API keys are configured, the login endpoint should still work
    // since it is outside the auth middleware.
    let app = test_router(None).await;
    let password_hash = hash_password_sha3("password1234");

    let response = app.oneshot(login_request("Neo", &password_hash)).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    let body = read_json(response).await;
    assert_eq!(body["user"], "Neo");
}

#[tokio::test]
async fn login_returns_different_tokens_per_call() {
    let app = test_router(Some((60, "k", "test-key", OperatorRole::Admin))).await;
    let password_hash = hash_password_sha3("password1234");

    let resp1 = app.clone().oneshot(login_request("Neo", &password_hash)).await.expect("resp1");
    let body1 = read_json(resp1).await;
    let token1 = body1["token"].as_str().expect("token1");

    let resp2 = app.oneshot(login_request("Neo", &password_hash)).await.expect("resp2");
    let body2 = read_json(resp2).await;
    let token2 = body2["token"].as_str().expect("token2");

    assert_ne!(token1, token2, "each login must produce a unique session token");
}

#[tokio::test]
async fn login_success_creates_audit_record() {
    let database = Database::connect_in_memory().await.expect("database");
    let (app, _, _) = test_router_with_database(
        database.clone(),
        Some((60, "k", "test-key", OperatorRole::Admin)),
    )
    .await;
    let password_hash = hash_password_sha3("password1234");

    let response = app.oneshot(login_request("Neo", &password_hash)).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    let page = crate::query_audit_log(
        &database,
        &AuditQuery {
            action: Some("operator.login".to_owned()),
            actor: Some("Neo".to_owned()),
            ..AuditQuery::default()
        },
    )
    .await
    .expect("audit query should succeed");

    assert_eq!(page.total, 1, "one operator.login record expected after successful login");
    let record = &page.items[0];
    assert_eq!(record.action, "operator.login");
    assert_eq!(record.actor, "Neo");
    assert_eq!(record.result_status, AuditResultStatus::Success);
    let username =
        record.parameters.as_ref().and_then(|p| p.get("username")).and_then(|v| v.as_str());
    assert_eq!(username, Some("Neo"), "audit parameters should include username");
}

#[tokio::test]
async fn login_failure_creates_audit_record() {
    let database = Database::connect_in_memory().await.expect("database");
    let (app, _, _) = test_router_with_database(
        database.clone(),
        Some((60, "k", "test-key", OperatorRole::Admin)),
    )
    .await;
    let wrong_hash = hash_password_sha3("wrong-password");

    let response = app.oneshot(login_request("Neo", &wrong_hash)).await.expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let page = crate::query_audit_log(
        &database,
        &AuditQuery {
            action: Some("operator.login".to_owned()),
            actor: Some("Neo".to_owned()),
            ..AuditQuery::default()
        },
    )
    .await
    .expect("audit query should succeed");

    assert_eq!(page.total, 1, "one operator.login record expected after failed login");
    let record = &page.items[0];
    assert_eq!(record.action, "operator.login");
    assert_eq!(record.actor, "Neo");
    assert_eq!(record.result_status, AuditResultStatus::Failure);
    let username =
        record.parameters.as_ref().and_then(|p| p.get("username")).and_then(|v| v.as_str());
    assert_eq!(username, Some("Neo"), "audit parameters should include username");
}
