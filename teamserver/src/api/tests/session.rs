use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

use red_cell_common::config::OperatorRole;

use crate::AuditResultStatus;
use crate::Database;
use crate::api::auth::API_KEY_HEADER;
use crate::api::session::{
    SESSION_MAX_RESPONSE_BODY, session_api_dispatch_line, session_ws_envelope_response,
};
use crate::{audit_details, parameter_object};

use super::helpers::*;

#[tokio::test]
async fn session_activity_endpoint_returns_only_persisted_operator_session_events() {
    let database = Database::connect_in_memory().await.expect("database");
    crate::record_operator_action(
        &database,
        "neo",
        "operator.connect",
        "operator",
        Some("neo".to_owned()),
        audit_details(AuditResultStatus::Success, None, Some("connect"), None),
    )
    .await
    .expect("connect activity should persist");
    crate::record_operator_action(
        &database,
        "neo",
        "operator.chat",
        "operator",
        Some("neo".to_owned()),
        audit_details(
            AuditResultStatus::Success,
            None,
            Some("chat"),
            Some(parameter_object([("message", Value::String("hello".to_owned()))])),
        ),
    )
    .await
    .expect("chat activity should persist");
    crate::record_operator_action(
        &database,
        "rest-admin",
        "operator.create",
        "operator",
        Some("trinity".to_owned()),
        audit_details(AuditResultStatus::Success, None, Some("create"), None),
    )
    .await
    .expect("operator management audit should persist");

    let (app, _, _) = test_router_with_database(
        database,
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/session-activity?operator=neo")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 2);
    assert_eq!(body["items"][0]["activity"], "chat");
    assert_eq!(body["items"][0]["operator"], "neo");
    assert_eq!(body["items"][1]["activity"], "connect");
}

#[tokio::test]
async fn session_dispatch_status_returns_health_payload() {
    let (app, _, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;
    let value = serde_json::json!({"cmd": "status"});
    let line = session_api_dispatch_line(
        &app,
        "status",
        &value,
        std::net::SocketAddr::from(([127, 0, 0, 1], 12345)),
        "secret-admin",
    )
    .await;
    let parsed: Value = serde_json::from_str(&line).expect("session line json");
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["cmd"], "status");
    assert!(
        parsed["data"]["status"].is_string(),
        "health payload must include a `status` field, got: {}",
        parsed["data"]
    );
    assert!(
        parsed["data"]["uptime_secs"].is_number(),
        "health payload must include `uptime_secs`, got: {}",
        parsed["data"]
    );
}

#[tokio::test]
async fn session_dispatch_unknown_command_returns_envelope() {
    let (app, _, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;
    let value = serde_json::json!({"cmd": "nosuch"});
    let line = session_api_dispatch_line(
        &app,
        "nosuch",
        &value,
        std::net::SocketAddr::from(([127, 0, 0, 1], 12345)),
        "secret-admin",
    )
    .await;
    let parsed: Value = serde_json::from_str(&line).expect("session line json");
    assert_eq!(parsed["ok"], false);
    assert_eq!(parsed["error"], "UNKNOWN_COMMAND");
}

// ── session-activity endpoint additional coverage ──────────────────

#[tokio::test]
async fn session_activity_filters_by_activity_type() {
    let database = Database::connect_in_memory().await.expect("database");
    crate::record_operator_action(
        &database,
        "neo",
        "operator.connect",
        "operator",
        Some("neo".to_owned()),
        audit_details(AuditResultStatus::Success, None, Some("connect"), None),
    )
    .await
    .expect("connect event");
    crate::record_operator_action(
        &database,
        "neo",
        "operator.disconnect",
        "operator",
        Some("neo".to_owned()),
        audit_details(AuditResultStatus::Success, None, Some("disconnect"), None),
    )
    .await
    .expect("disconnect event");

    let (app, _, _) = test_router_with_database(
        database,
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/session-activity?activity=connect")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["items"][0]["activity"], "connect");
}

#[tokio::test]
async fn session_activity_paginates_results() {
    let database = Database::connect_in_memory().await.expect("database");
    for action in ["operator.connect", "operator.chat", "operator.disconnect"] {
        let activity = action.strip_prefix("operator.").expect("prefix");
        crate::record_operator_action(
            &database,
            "neo",
            action,
            "operator",
            Some("neo".to_owned()),
            audit_details(AuditResultStatus::Success, None, Some(activity), None),
        )
        .await
        .expect("session event");
    }

    let (app, _, _) = test_router_with_database(
        database,
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/session-activity?limit=2&offset=0")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 3);
    assert_eq!(body["limit"], 2);
    assert_eq!(body["offset"], 0);
    assert_eq!(body["items"].as_array().expect("items array").len(), 2);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/session-activity?limit=2&offset=2")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 3);
    assert_eq!(body["items"].as_array().expect("items array").len(), 1);
}

#[tokio::test]
async fn session_activity_invalid_limit_returns_client_error() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/session-activity?limit=not_a_number")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert!(
        response.status().is_client_error(),
        "non-numeric limit should produce a 4xx response, got {}",
        response.status()
    );
}

#[tokio::test]
async fn session_activity_returns_empty_page_when_no_events_match() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/session-activity?operator=nonexistent")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 0);
    assert!(body["items"].as_array().expect("items array").is_empty());
}

#[tokio::test]
async fn session_activity_filters_by_time_window() {
    let database = Database::connect_in_memory().await.expect("database");
    // Insert an event with a known timestamp via the audit log directly.
    database
        .audit_log()
        .create(&crate::AuditLogEntry {
            id: None,
            actor: "neo".to_owned(),
            action: "operator.connect".to_owned(),
            target_kind: "operator".to_owned(),
            target_id: Some("neo".to_owned()),
            details: Some(serde_json::json!({
                "result_status": "success",
                "command": "connect"
            })),
            occurred_at: "2026-03-10T12:00:00Z".to_owned(),
        })
        .await
        .expect("audit entry");

    let (app, _, _) = test_router_with_database(
        database,
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    // Query with a window that includes the event.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/session-activity?since=2026-03-10T00:00:00Z&until=2026-03-10T23:59:59Z")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 1);

    // Query with a window that excludes the event.
    let response = app
        .oneshot(
            Request::builder()
                .uri("/session-activity?since=2026-03-11T00:00:00Z")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 0);
}

// ── session response body size limit tests ──────────────────────────

#[tokio::test]
async fn session_envelope_rejects_oversized_response_body() {
    use axum::http::header::CONTENT_TYPE;
    use axum::response::Response;

    let oversized = vec![0xABu8; SESSION_MAX_RESPONSE_BODY + 1];
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(oversized))
        .expect("build response");

    let envelope = session_ws_envelope_response("payload.download", response).await;
    let parsed: Value = serde_json::from_str(&envelope).expect("valid json");
    assert_eq!(parsed["ok"], false);
    assert_eq!(parsed["error"], "RESPONSE_TOO_LARGE");
    assert!(parsed["message"].as_str().expect("message string").contains("session limit"),);
}

#[tokio::test]
async fn session_envelope_accepts_response_at_size_limit() {
    use axum::http::header::CONTENT_TYPE;
    use axum::response::Response;

    let at_limit = vec![0xCDu8; SESSION_MAX_RESPONSE_BODY];
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(at_limit))
        .expect("build response");

    let envelope = session_ws_envelope_response("payload.download", response).await;
    let parsed: Value = serde_json::from_str(&envelope).expect("valid json");
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["cmd"], "payload.download");
    assert_eq!(parsed["data"]["encoding"], "base64");
    assert!(parsed["data"]["data"].as_str().expect("base64 string").len() > 0);
}

#[tokio::test]
async fn session_envelope_accepts_small_json_response() {
    use axum::http::header::CONTENT_TYPE;
    use axum::response::Response;

    let json_body = serde_json::json!({"status": "ok"}).to_string();
    let response = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(json_body))
        .expect("build response");

    let envelope = session_ws_envelope_response("status", response).await;
    let parsed: Value = serde_json::from_str(&envelope).expect("valid json");
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["data"]["status"], "ok");
}

#[tokio::test]
async fn session_envelope_error_response_not_affected_by_size_limit() {
    use axum::http::header::CONTENT_TYPE;
    use axum::response::Response;

    let error_body = serde_json::json!({
        "error": {"code": "NOT_FOUND", "message": "resource not found"}
    })
    .to_string();
    let response = Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(error_body))
        .expect("build response");

    let envelope = session_ws_envelope_response("loot.download", response).await;
    let parsed: Value = serde_json::from_str(&envelope).expect("valid json");
    assert_eq!(parsed["ok"], false);
    assert_eq!(parsed["error"], "NOT_FOUND");
}
