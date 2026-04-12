use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use red_cell_common::config::OperatorRole;
use red_cell_common::demon::DemonCommand;

use crate::Job;
use crate::api::auth::API_KEY_HEADER;

use super::helpers::*;

#[tokio::test]
async fn jobs_endpoint_lists_queued_jobs_with_filters() {
    let (app, registry, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;
    registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
    registry.insert(sample_agent(0xABCD_EF01)).await.expect("agent should insert");

    let first_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agents/DEADBEEF/task")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"TaskID":"2A","CommandLine":"checkin","DemonID":"DEADBEEF","CommandID":"100"}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(first_response.status(), StatusCode::ACCEPTED);

    let second_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/agents/ABCDEF01")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(second_response.status(), StatusCode::ACCEPTED);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/jobs?agent_id=DEADBEEF&command=checkin")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["items"][0]["agent_id"], "DEADBEEF");
    assert_eq!(body["items"][0]["request_id"], "2A");
    assert_eq!(body["items"][0]["command_line"], "checkin");
}

#[tokio::test]
async fn get_job_returns_specific_queued_job() {
    let (app, registry, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;
    registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agents/DEADBEEF/task")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"TaskID":"2A","CommandLine":"checkin","DemonID":"DEADBEEF","CommandID":"100"}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/jobs/DEADBEEF/2A")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["agent_id"], "DEADBEEF");
    assert_eq!(body["request_id"], "2A");
    assert_eq!(body["command_id"], u32::from(DemonCommand::CommandCheckin));
}

// ── Job queue endpoint integration tests ──────────────────────────

fn sample_job(command: u32, request_id: u32, operator: &str) -> Job {
    Job {
        command,
        request_id,
        payload: vec![0xAA; 16],
        command_line: format!("cmd-{request_id}"),
        task_id: format!("task-{request_id:X}"),
        created_at: "2026-03-19T12:00:00Z".to_owned(),
        operator: operator.to_owned(),
    }
}

#[tokio::test]
async fn list_jobs_returns_enqueued_jobs() {
    let (app, registry, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;
    registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
    registry.enqueue_job(0xDEAD_BEEF, sample_job(10, 0x100, "Neo")).await.expect("enqueue");
    registry.enqueue_job(0xDEAD_BEEF, sample_job(20, 0x200, "Neo")).await.expect("enqueue");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/jobs")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 2);
    let items = body["items"].as_array().expect("items array");
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["agent_id"], "DEADBEEF");
    assert_eq!(items[0]["command_id"], 10);
    assert_eq!(items[0]["request_id"], "100");
    assert_eq!(items[0]["task_id"], "task-100");
    assert_eq!(items[0]["command_line"], "cmd-256");
    assert_eq!(items[0]["operator"], "Neo");
    assert_eq!(items[0]["payload_size"], 16);
    assert_eq!(items[1]["command_id"], 20);
    assert_eq!(items[1]["request_id"], "200");
}

#[tokio::test]
async fn get_job_returns_specific_enqueued_job() {
    let (app, registry, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;
    registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
    registry.enqueue_job(0xDEAD_BEEF, sample_job(42, 0xABC, "Neo")).await.expect("enqueue");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/jobs/DEADBEEF/ABC")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["agent_id"], "DEADBEEF");
    assert_eq!(body["command_id"], 42);
    assert_eq!(body["request_id"], "ABC");
    assert_eq!(body["task_id"], "task-ABC");
    assert_eq!(body["operator"], "Neo");
    assert_eq!(body["payload_size"], 16);
}

#[tokio::test]
async fn get_job_returns_not_found_for_unknown_job() {
    let (app, registry, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;
    registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/jobs/DEADBEEF/999")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "job_not_found");
}

#[tokio::test]
async fn list_jobs_returns_empty_after_dequeue() {
    let (app, registry, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;
    registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
    registry.enqueue_job(0xDEAD_BEEF, sample_job(10, 0x100, "Neo")).await.expect("enqueue");

    // Drain the queue before querying the API.
    let drained = registry.dequeue_jobs(0xDEAD_BEEF).await.expect("dequeue");
    assert_eq!(drained.len(), 1);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/jobs")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 0);
    assert_eq!(body["items"].as_array().expect("items array").len(), 0);
}

#[tokio::test]
async fn list_jobs_filters_by_agent_id() {
    let (app, registry, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;
    registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("insert agent 1");
    registry.insert(sample_agent(0xABCD_EF01)).await.expect("insert agent 2");
    registry.enqueue_job(0xDEAD_BEEF, sample_job(10, 0x100, "Neo")).await.expect("enqueue");
    registry.enqueue_job(0xABCD_EF01, sample_job(20, 0x200, "Trinity")).await.expect("enqueue");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/jobs?agent_id=ABCDEF01")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 1);
    let items = body["items"].as_array().expect("items array");
    assert_eq!(items[0]["agent_id"], "ABCDEF01");
    assert_eq!(items[0]["operator"], "Trinity");
}

#[tokio::test]
async fn get_job_accepts_0x_prefixed_agent_id() {
    let (app, registry, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;
    registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
    registry.enqueue_job(0xDEAD_BEEF, sample_job(7, 0x42, "Neo")).await.expect("enqueue");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/jobs/0xDEADBEEF/0x42")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["agent_id"], "DEADBEEF");
    assert_eq!(body["request_id"], "42");
}
