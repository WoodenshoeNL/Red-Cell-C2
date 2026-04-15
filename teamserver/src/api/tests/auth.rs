use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::header::{AUTHORIZATION, RETRY_AFTER};
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

use std::net::SocketAddr;

use red_cell_common::config::OperatorRole;

use crate::Database;
use crate::api::auth::{API_KEY_HEADER, MAX_FAILED_API_AUTH_ATTEMPTS};
use crate::api::json_error_response;

use super::helpers::*;

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

// ---- rate_limiting integration tests ----

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

// ---- auth_failure_rate_limiter integration tests ----

#[tokio::test]
async fn auth_failure_rate_limiter_blocks_after_max_failed_attempts() {
    let app = test_router(Some((1000, "rest-admin", "secret-admin", OperatorRole::Admin))).await;
    let client_ip = SocketAddr::from(([192, 0, 2, 42], 1234));

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
