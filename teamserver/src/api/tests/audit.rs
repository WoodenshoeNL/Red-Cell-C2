use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use red_cell_common::config::OperatorRole;

use crate::api::auth::API_KEY_HEADER;

use super::helpers::*;

#[tokio::test]
async fn audit_endpoint_returns_filtered_paginated_results() {
    let (app, registry, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;
    registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/agents/DEADBEEF/task")
                .method("POST")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"TaskID":"2A","CommandLine":"checkin","DemonID":"DEADBEEF","CommandID":"100"}"#,
                ))
                .expect("request"),
        )
        .await;
    assert!(response.is_ok());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/audit?action=agent.task&agent_id=DEADBEEF&limit=1")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["limit"], 1);
    assert_eq!(body["items"][0]["action"], "agent.task");
    assert_eq!(body["items"][0]["agent_id"], "DEADBEEF");
    assert_eq!(body["items"][0]["result_status"], "success");
}

#[tokio::test]
async fn audit_endpoint_filters_by_operator_and_time_window() {
    let (app, registry, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;
    registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");

    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/agents/DEADBEEF/task")
                .method("POST")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"TaskID":"2A","CommandLine":"checkin","DemonID":"DEADBEEF","CommandID":"100"}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    let now = time::OffsetDateTime::now_utc();
    let since = (now - time::Duration::hours(1))
        .format(&time::format_description::well_known::Rfc3339)
        .expect("format since");
    let until = (now + time::Duration::hours(1))
        .format(&time::format_description::well_known::Rfc3339)
        .expect("format until");
    let uri = format!("/audit?operator=rest-admin&since={since}&until={until}");

    let response = app
        .oneshot(
            Request::builder()
                .uri(uri.as_str())
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["items"][0]["actor"], "rest-admin");
}
