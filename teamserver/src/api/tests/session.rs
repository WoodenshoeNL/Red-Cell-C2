use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

use red_cell_common::config::OperatorRole;

use crate::AuditResultStatus;
use crate::Database;
use crate::api::auth::API_KEY_HEADER;
use crate::api::session::session_api_dispatch_line;
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
async fn session_dispatch_status_matches_api_root() {
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
    assert_eq!(parsed["data"]["prefix"], "/api/v1");
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
