use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crate::api::agents::AgentApiError;
use crate::api::auth::API_KEY_HEADER;
use crate::{Database, Job};
use red_cell_common::config::OperatorRole;
use red_cell_common::demon::DemonCommand;

use super::helpers::*;

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
async fn list_agents_returns_registered_entries() {
    let (app, registry, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;
    registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/agents")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body.as_array().expect("agents array").len(), 1);
    assert_eq!(body[0]["AgentID"], 0xDEAD_BEEF_u32);
    assert!(body[0].get("Encryption").is_none());
}

#[tokio::test]
async fn list_agents_includes_dead_agents() {
    // Dead agents must remain visible in GET /agents so operators can use the
    // endpoint for forensics and inventory.  If someone mistakenly switches the
    // implementation to list_active() this test will fail.
    let (app, registry, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;

    registry.insert(sample_agent(0xDEAD_C0DE)).await.expect("agent should insert");
    registry.mark_dead(0xDEAD_C0DE, "killed by test").await.expect("mark_dead should succeed");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/agents")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    let agents = body.as_array().expect("agents array");
    assert_eq!(agents.len(), 1, "dead agent must still appear in the list");

    let agent = &agents[0];
    assert_eq!(agent["AgentID"], 0xDEAD_C0DE_u32);
    // Active must be false so callers can distinguish dead from alive agents.
    assert_eq!(agent["Active"], false, "Active field must be false for a dead agent");
    // LastCallIn must be present so callers can assess when the agent was last seen.
    assert!(agent.get("LastCallIn").is_some(), "LastCallIn field must be present in the response");
    // FirstCallIn must also be present for completeness.
    assert!(
        agent.get("FirstCallIn").is_some(),
        "FirstCallIn field must be present in the response"
    );
}

#[tokio::test]
async fn get_agent_omits_transport_crypto_material() {
    let (app, registry, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;
    registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/agents/DEADBEEF")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["AgentID"], 0xDEAD_BEEF_u32);
    assert!(body.get("Encryption").is_none());
}

#[tokio::test]
async fn get_agent_returns_not_found_for_unknown_agent() {
    let (app, _, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/agents/DEADBEEF")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "agent_not_found");
}

#[tokio::test]
async fn queue_agent_task_enqueues_job() {
    let (app, registry, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;
    registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");

    let response = app
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
    let body = read_json(response).await;
    assert_eq!(body["agent_id"], "DEADBEEF");
    assert_eq!(body["task_id"], "2A");
    assert_eq!(body["queued_jobs"], 1);

    let queued = registry.queued_jobs(0xDEAD_BEEF).await.expect("queue should load");
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].command, u32::from(DemonCommand::CommandCheckin));
    assert_eq!(queued[0].request_id, 0x2A);
}

#[tokio::test]
async fn queue_agent_task_returns_not_found_for_unknown_agent() {
    let (app, _, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;

    let response = app
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

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "agent_not_found");
}

#[tokio::test]
async fn queue_agent_task_returns_429_when_queue_is_full() {
    let (app, registry, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;
    registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");

    // Fill the queue to capacity.
    for i in 0..crate::agents::MAX_JOB_QUEUE_DEPTH {
        registry
            .enqueue_job(0xDEAD_BEEF, sample_job(i as u32, i as u32, "Neo"))
            .await
            .expect("enqueue should succeed");
    }

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agents/DEADBEEF/task")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"TaskID":"FF","CommandLine":"checkin","DemonID":"DEADBEEF","CommandID":"100"}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "QueueFull must map to 429, not 500"
    );
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "queue_full");
}

#[tokio::test]
async fn queue_agent_task_queue_full_audit_records_failure() {
    let database = Database::connect_in_memory().await.expect("database");
    let (app, registry, _) = test_router_with_database(
        database.clone(),
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;
    registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");

    // Fill the queue to capacity.
    for i in 0..crate::agents::MAX_JOB_QUEUE_DEPTH {
        registry
            .enqueue_job(0xDEAD_BEEF, sample_job(i as u32, i as u32, "Neo"))
            .await
            .expect("enqueue should succeed");
    }

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agents/DEADBEEF/task")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"TaskID":"FF","CommandLine":"checkin","DemonID":"DEADBEEF","CommandID":"100"}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    // Verify the audit trail recorded a failure entry.
    let audit_page = crate::audit::query_audit_log(
        &database,
        &crate::AuditQuery {
            action: Some("agent.task".to_owned()),
            agent_id: Some("DEADBEEF".to_owned()),
            limit: Some(10),
            ..Default::default()
        },
    )
    .await
    .expect("audit query");
    assert!(!audit_page.items.is_empty(), "audit should have at least one entry");
    let last = &audit_page.items[0];
    assert_eq!(
        last.result_status,
        crate::AuditResultStatus::Failure,
        "audit entry must record failure for QueueFull"
    );
}

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
async fn delete_agent_queues_kill_job() {
    let (app, registry, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;
    registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/agents/DEADBEEF")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = read_json(response).await;
    assert_eq!(body["agent_id"], "DEADBEEF");
    assert_eq!(body["queued_jobs"], 1);

    let queued = registry.queued_jobs(0xDEAD_BEEF).await.expect("queue should load");
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].command, u32::from(DemonCommand::CommandExit));
}

#[tokio::test]
async fn delete_agent_returns_not_found_for_unknown_agent() {
    let (app, _, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/agents/DEADBEEF")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "agent_not_found");
}

#[tokio::test]
async fn kill_agent_records_audit_entry_on_success() {
    let (app, registry, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;
    registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/agents/DEADBEEF")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let audit_response = app
        .oneshot(
            Request::builder()
                .uri("/audit?action=agent.task&agent_id=DEADBEEF&limit=10")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(audit_response.status(), StatusCode::OK);
    let body = read_json(audit_response).await;
    let items = body["items"].as_array().expect("items array");
    assert!(!items.is_empty(), "expected at least one agent.task audit entry");
    let entry = &items[0];
    assert_eq!(entry["action"], "agent.task");
    assert_eq!(entry["agent_id"], "DEADBEEF");
    assert_eq!(entry["result_status"], "success");
    assert_eq!(entry["command"], "kill");
}

#[tokio::test]
async fn kill_agent_records_audit_entry_on_failure() {
    let (app, _, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/agents/DEADBEEF")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let audit_response = app
        .oneshot(
            Request::builder()
                .uri("/audit?action=agent.task&agent_id=DEADBEEF&limit=10")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(audit_response.status(), StatusCode::OK);
    let body = read_json(audit_response).await;
    let items = body["items"].as_array().expect("items array");
    assert!(!items.is_empty(), "expected at least one agent.task audit entry for failure");
    let entry = &items[0];
    assert_eq!(entry["action"], "agent.task");
    assert_eq!(entry["agent_id"], "DEADBEEF");
    assert_eq!(entry["result_status"], "failure");
}

#[tokio::test]
async fn delete_agent_force_deregisters_immediately() {
    let (app, registry, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;
    registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/agents/DEADBEEF?force=true")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["agent_id"], "DEADBEEF");
    assert_eq!(body["deregistered"], true);
    assert!(registry.get(0xDEAD_BEEF).await.is_none(), "agent must be removed from registry");
}

#[tokio::test]
async fn delete_agent_deregister_only_skips_kill_task() {
    let (app, registry, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;
    registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/agents/DEADBEEF?deregister_only=true")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["agent_id"], "DEADBEEF");
    assert_eq!(body["deregistered"], true);
    assert!(registry.get(0xDEAD_BEEF).await.is_none(), "agent must be removed from registry");
}

#[tokio::test]
async fn delete_agent_deregister_only_returns_not_found_for_unknown_agent() {
    let (app, _, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/agents/DEADBEEF?deregister_only=true")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "agent_not_found");
}

/// Sends a GET request to `/agents/{id}` with the given malformed ID and asserts
/// a 400 Bad Request with error code `"invalid_agent_task"`.
async fn assert_get_agent_bad_request(malformed_id: &str) {
    let (app, _, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;

    let uri = format!("/agents/{malformed_id}");
    let response = app
        .oneshot(
            Request::builder()
                .uri(&uri)
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "GET {uri} should return 400, not {}",
        response.status()
    );
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "invalid_agent_task");
}

#[tokio::test]
async fn get_agent_rejects_non_hex_id() {
    assert_get_agent_bad_request("ZZZZZZZZ").await;
}

#[tokio::test]
async fn get_agent_returns_not_found_for_short_hex_id() {
    // "DEAD" is valid hex (parses as 0x0000DEAD) but no agent has that ID.
    let (app, _, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/agents/DEAD")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "agent_not_found");
}

#[tokio::test]
async fn get_agent_rejects_too_long_id() {
    assert_get_agent_bad_request("DEADBEEF00").await;
}

/// Sends a DELETE request to `/agents/{id}` with a malformed ID and asserts 400.
async fn assert_delete_agent_bad_request(malformed_id: &str) {
    let (app, _, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;

    let uri = format!("/agents/{malformed_id}");
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri(&uri)
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "DELETE {uri} should return 400, not {}",
        response.status()
    );
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "invalid_agent_task");
}

#[tokio::test]
async fn delete_agent_rejects_non_hex_id() {
    assert_delete_agent_bad_request("ZZZZZZZZ").await;
}

#[tokio::test]
async fn delete_agent_rejects_too_long_id() {
    assert_delete_agent_bad_request("DEADBEEF00").await;
}

/// Sends a POST request to `/agents/{id}/task` with a malformed ID and asserts 400.
async fn assert_queue_task_bad_request(malformed_id: &str) {
    let (app, _, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;

    let uri = format!("/agents/{malformed_id}/task");
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&uri)
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"TaskID":"01","CommandLine":"checkin","DemonID":"DEADBEEF","CommandID":"100"}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "POST {uri} should return 400, not {}",
        response.status()
    );
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "invalid_agent_task");
}

#[tokio::test]
async fn queue_task_rejects_non_hex_id() {
    assert_queue_task_bad_request("ZZZZZZZZ").await;
}

#[tokio::test]
async fn queue_task_returns_error_for_short_hex_id() {
    // "DEAD" is valid hex (parses as 0x0000DEAD) but the canonical 8-char form
    // "0000DEAD" differs from the body DemonID "DEAD", triggering a 400
    // mismatch error. Either 400 or 404 is acceptable — not 500.
    let (app, _, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agents/DEAD/task")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"TaskID":"01","CommandLine":"checkin","DemonID":"DEAD","CommandID":"100"}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    let status = response.status();
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND,
        "POST /agents/DEAD/task should return 400 or 404, not {status}"
    );
    let body = read_json(response).await;
    assert!(body["error"]["code"].is_string(), "error response should include an error code");
}

#[tokio::test]
async fn queue_task_rejects_too_long_id() {
    assert_queue_task_bad_request("DEADBEEF00").await;
}

#[tokio::test]
async fn analyst_key_cannot_task_agents() {
    let (app, registry, _) = test_router_with_registry(Some((
        60,
        "rest-analyst",
        "secret-analyst",
        OperatorRole::Analyst,
    )))
    .await;
    registry.insert(sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agents/DEADBEEF/task")
                .header(API_KEY_HEADER, "secret-analyst")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"TaskID":"2A","CommandLine":"checkin","DemonID":"DEADBEEF","CommandID":"100"}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// ── parse_api_agent_id unit tests ─────────────────────────────────────

#[test]
fn parse_api_agent_id_always_parses_hex() -> Result<(), AgentApiError> {
    assert_eq!(crate::api::parse_api_agent_id("DEADBEEF")?, 0xDEAD_BEEF);
    assert_eq!(crate::api::parse_api_agent_id("deadbeef")?, 0xDEAD_BEEF);
    assert_eq!(crate::api::parse_api_agent_id("0xDEADBEEF")?, 0xDEAD_BEEF);
    assert_eq!(crate::api::parse_api_agent_id("0XDEADBEEF")?, 0xDEAD_BEEF);
    Ok(())
}

#[test]
fn parse_api_agent_id_all_digit_hex_is_not_decimal() -> Result<(), AgentApiError> {
    // "00000010" is agent ID 0x10 (16), not decimal 10
    assert_eq!(crate::api::parse_api_agent_id("00000010")?, 0x10);
    assert_eq!(crate::api::parse_api_agent_id("10")?, 0x10);
    assert_eq!(crate::api::parse_api_agent_id("0x10")?, 0x10);
    Ok(())
}

#[test]
fn parse_api_agent_id_rejects_empty_and_invalid() {
    assert!(crate::api::parse_api_agent_id("").is_err());
    assert!(crate::api::parse_api_agent_id("   ").is_err());
    assert!(crate::api::parse_api_agent_id("ZZZZ").is_err());
    assert!(crate::api::parse_api_agent_id("not-hex").is_err());
}

#[test]
fn parse_api_agent_id_trims_whitespace() -> Result<(), AgentApiError> {
    assert_eq!(crate::api::parse_api_agent_id("  DEADBEEF  ")?, 0xDEAD_BEEF);
    assert_eq!(crate::api::parse_api_agent_id(" 0x10 ")?, 0x10);
    Ok(())
}

#[test]
fn parse_api_agent_id_u32_max_boundary() -> Result<(), AgentApiError> {
    // u32::MAX (0xFFFF_FFFF) must succeed
    assert_eq!(crate::api::parse_api_agent_id("FFFFFFFF")?, u32::MAX);
    assert_eq!(crate::api::parse_api_agent_id("ffffffff")?, u32::MAX);
    assert_eq!(crate::api::parse_api_agent_id("0xFFFFFFFF")?, u32::MAX);
    assert_eq!(crate::api::parse_api_agent_id("0xffffffff")?, u32::MAX);
    Ok(())
}

#[test]
fn parse_api_agent_id_rejects_overflow() {
    // 9 hex digits — value 0x1_0000_0000 overflows u32
    assert!(crate::api::parse_api_agent_id("100000000").is_err());
    assert!(crate::api::parse_api_agent_id("0x100000000").is_err());
    // Larger values also rejected
    assert!(crate::api::parse_api_agent_id("FFFFFFFFF").is_err());
    assert!(crate::api::parse_api_agent_id("0xFFFFFFFF0").is_err());
}

// ── GET /agents/{id}/output ─────────────────────────────────────────

#[tokio::test]
async fn get_agent_output_returns_empty_page_for_agent_with_no_output() {
    let database = Database::connect_in_memory().await.expect("database");
    let (app, registry, _) = test_router_with_database(
        database,
        Some((60, "reader", "secret-reader", OperatorRole::Operator)),
    )
    .await;

    let agent = sample_agent(0xDEAD_0001);
    registry.insert(agent).await.expect("insert");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/agents/DEAD0001/output")
                .header(API_KEY_HEADER, "secret-reader")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 0);
    assert_eq!(body["entries"], serde_json::json!([]));
}

#[tokio::test]
async fn get_agent_output_returns_persisted_responses() {
    let database = Database::connect_in_memory().await.expect("database");
    let agent_id = 0xDEAD_0002u32;

    let (app, registry, _) = test_router_with_database(
        database.clone(),
        Some((60, "reader", "secret-reader", OperatorRole::Operator)),
    )
    .await;

    // Register agent via registry (persists to DB for FK constraint).
    registry.insert(sample_agent(agent_id)).await.expect("insert");

    // Insert a response record.
    let record = crate::database::AgentResponseRecord {
        id: None,
        agent_id,
        command_id: 21,
        request_id: 1,
        response_type: "Good".to_owned(),
        message: "Process List".to_owned(),
        output: "whoami output".to_owned(),
        command_line: Some("whoami".to_owned()),
        task_id: Some("task-abc".to_owned()),
        operator: Some("neo".to_owned()),
        received_at: "2026-03-27T00:00:00Z".to_owned(),
        extra: None,
    };
    database.agent_responses().create(&record).await.expect("create response");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/agents/DEAD0002/output")
                .header(API_KEY_HEADER, "secret-reader")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["entries"][0]["task_id"], "task-abc");
    assert_eq!(body["entries"][0]["output"], "whoami output");
    assert_eq!(body["entries"][0]["command_line"], "whoami");
}

#[tokio::test]
async fn get_agent_output_since_cursor_filters_older_entries() {
    let database = Database::connect_in_memory().await.expect("database");
    let agent_id = 0xDEAD_0003u32;

    let (app, registry, _) = test_router_with_database(
        database.clone(),
        Some((60, "reader", "secret-reader", OperatorRole::Operator)),
    )
    .await;

    registry.insert(sample_agent(agent_id)).await.expect("insert");

    let record1 = crate::database::AgentResponseRecord {
        id: None,
        agent_id,
        command_id: 21,
        request_id: 1,
        response_type: "Good".to_owned(),
        message: "first".to_owned(),
        output: "output-1".to_owned(),
        command_line: None,
        task_id: Some("t1".to_owned()),
        operator: None,
        received_at: "2026-03-27T00:00:00Z".to_owned(),
        extra: None,
    };
    let id1 = database.agent_responses().create(&record1).await.expect("create r1");

    let record2 = crate::database::AgentResponseRecord {
        id: None,
        agent_id,
        command_id: 21,
        request_id: 2,
        response_type: "Good".to_owned(),
        message: "second".to_owned(),
        output: "output-2".to_owned(),
        command_line: None,
        task_id: Some("t2".to_owned()),
        operator: None,
        received_at: "2026-03-27T00:01:00Z".to_owned(),
        extra: None,
    };
    database.agent_responses().create(&record2).await.expect("create r2");

    // Request with since=id1 should only return the second record.
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/agents/DEAD0003/output?since={id1}"))
                .header(API_KEY_HEADER, "secret-reader")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["entries"][0]["task_id"], "t2");
}

#[tokio::test]
async fn get_agent_output_surfaces_exit_code_from_extra() {
    let database = Database::connect_in_memory().await.expect("database");
    let agent_id = 0xDEAD_0004u32;

    let (app, registry, _) = test_router_with_database(
        database.clone(),
        Some((60, "reader", "secret-reader", OperatorRole::Operator)),
    )
    .await;
    registry.insert(sample_agent(agent_id)).await.expect("insert");

    let record = crate::database::AgentResponseRecord {
        id: None,
        agent_id,
        command_id: u32::from(red_cell_common::demon::DemonCommand::CommandOutput),
        request_id: 7,
        response_type: "Good".to_owned(),
        message: "Received Output [3 bytes]:".to_owned(),
        output: "err".to_owned(),
        command_line: Some("exit 1".to_owned()),
        task_id: Some("task-exit1".to_owned()),
        operator: None,
        received_at: "2026-04-04T00:00:00Z".to_owned(),
        extra: Some(serde_json::json!({"ExitCode": 1})),
    };
    database.agent_responses().create(&record).await.expect("create response");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/agents/DEAD0004/output")
                .header(API_KEY_HEADER, "secret-reader")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["entries"][0]["exit_code"], 1);
    assert_eq!(body["entries"][0]["task_id"], "task-exit1");
}

#[tokio::test]
async fn get_agent_output_omits_exit_code_when_absent() {
    let database = Database::connect_in_memory().await.expect("database");
    let agent_id = 0xDEAD_0005u32;

    let (app, registry, _) = test_router_with_database(
        database.clone(),
        Some((60, "reader", "secret-reader", OperatorRole::Operator)),
    )
    .await;
    registry.insert(sample_agent(agent_id)).await.expect("insert");

    let record = crate::database::AgentResponseRecord {
        id: None,
        agent_id,
        command_id: u32::from(red_cell_common::demon::DemonCommand::CommandOutput),
        request_id: 8,
        response_type: "Good".to_owned(),
        message: "Received Output [2 bytes]:".to_owned(),
        output: "ok".to_owned(),
        command_line: Some("whoami".to_owned()),
        task_id: Some("task-legacy".to_owned()),
        operator: None,
        received_at: "2026-04-04T00:00:00Z".to_owned(),
        extra: None,
    };
    database.agent_responses().create(&record).await.expect("create response");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/agents/DEAD0005/output")
                .header(API_KEY_HEADER, "secret-reader")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 1);
    // `exit_code` must be absent when not known (skip_serializing_if = "Option::is_none").
    assert!(body["entries"][0].get("exit_code").is_none());
}

#[tokio::test]
async fn get_agent_output_returns_404_for_unknown_agent() {
    let app = test_router(Some((60, "reader", "secret-reader", OperatorRole::Operator))).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/agents/FFFFFFFF/output")
                .header(API_KEY_HEADER, "secret-reader")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ── GET /agents/{id}/task-status ────────────────────────────────────

#[tokio::test]
async fn get_agent_task_status_reports_queued_job() {
    let (app, registry, _) =
        test_router_with_registry(Some((60, "tasker", "secret-tasker", OperatorRole::Operator)))
            .await;
    let agent_id = 0xDEAD_00F0u32;
    registry.insert(sample_agent(agent_id)).await.expect("insert");
    let job = sample_job(0x100, 0x2A, "op");
    registry.enqueue_job(agent_id, job.clone()).await.expect("enqueue");

    let uri = format!("/agents/DEAD00F0/task-status?task_id={}", job.task_id);
    let response = app
        .oneshot(
            Request::builder()
                .uri(&uri)
                .header(API_KEY_HEADER, "secret-tasker")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["lifecycle"], "queued");
    assert_eq!(body["queued"]["queue_position"], 0);
    assert_eq!(body["queued"]["request_id"], 0x2A);
    assert_eq!(body["task_id"], job.task_id);
}

#[tokio::test]
async fn get_agent_task_status_rejects_empty_task_id_query() {
    let (app, registry, _) =
        test_router_with_registry(Some((60, "tasker", "secret-tasker", OperatorRole::Operator)))
            .await;
    registry.insert(sample_agent(0xDEAD_00F1u32)).await.expect("insert");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/agents/DEAD00F1/task-status?task_id=")
                .header(API_KEY_HEADER, "secret-tasker")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// ── POST /agents/{id}/upload ────────────────────────────────────────

#[tokio::test]
async fn agent_upload_queues_task_for_existing_agent() {
    let (app, registry, _) =
        test_router_with_registry(Some((60, "tasker", "secret-tasker", OperatorRole::Operator)))
            .await;

    let agent_id = 0xDEAD_0010u32;
    registry.insert(sample_agent(agent_id)).await.expect("insert");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agents/DEAD0010/upload")
                .header(API_KEY_HEADER, "secret-tasker")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "remote_path": "C:\\temp\\payload.bin",
                        "content": "SGVsbG8gV29ybGQ="
                    }))
                    .expect("json"),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = read_json(response).await;
    assert_eq!(body["agent_id"], "DEAD0010");
    assert!(!body["task_id"].as_str().expect("task_id").is_empty());
}

#[tokio::test]
async fn agent_upload_returns_404_for_unknown_agent() {
    let app = test_router(Some((60, "tasker", "secret-tasker", OperatorRole::Operator))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agents/FFFFFFFF/upload")
                .header(API_KEY_HEADER, "secret-tasker")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"remote_path":"C:\\x","content":"AA=="}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn agent_upload_accepts_body_larger_than_2mb() {
    let (app, registry, _) =
        test_router_with_registry(Some((60, "tasker", "secret-tasker", OperatorRole::Operator)))
            .await;

    let agent_id = 0xDEAD_0011u32;
    registry.insert(sample_agent(agent_id)).await.expect("insert");

    // Build a payload whose JSON body exceeds 2 MB (the old axum default).
    // 3 MB of binary → ~4 MB base64 → well over the 2 MB default limit.
    use base64::Engine;
    let raw = vec![0x42u8; 3 * 1024 * 1024];
    let b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
    let json_body = serde_json::to_string(&serde_json::json!({
        "remote_path": "C:\\temp\\big_payload.bin",
        "content": b64,
    }))
    .expect("json");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agents/DEAD0011/upload")
                .header(API_KEY_HEADER, "secret-tasker")
                .header("Content-Type", "application/json")
                .body(Body::from(json_body))
                .expect("request"),
        )
        .await
        .expect("response");

    // With the raised body limit this should succeed (202 Accepted),
    // not be rejected with 413 Payload Too Large.
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}

// ── POST /agents/{id}/download ──────────────────────────────────────

#[tokio::test]
async fn agent_download_queues_task_for_existing_agent() {
    let (app, registry, _) =
        test_router_with_registry(Some((60, "tasker", "secret-tasker", OperatorRole::Operator)))
            .await;

    let agent_id = 0xDEAD_0020u32;
    registry.insert(sample_agent(agent_id)).await.expect("insert");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agents/DEAD0020/download")
                .header(API_KEY_HEADER, "secret-tasker")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::to_string(&serde_json::json!({
                        "remote_path": "C:\\Users\\neo\\Documents\\secret.txt"
                    }))
                    .expect("json"),
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = read_json(response).await;
    assert_eq!(body["agent_id"], "DEAD0020");
    assert!(!body["task_id"].as_str().expect("task_id").is_empty());
}

#[tokio::test]
async fn agent_download_returns_404_for_unknown_agent() {
    let app = test_router(Some((60, "tasker", "secret-tasker", OperatorRole::Operator))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/agents/FFFFFFFF/download")
                .header(API_KEY_HEADER, "secret-tasker")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"remote_path":"C:\\x"}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
