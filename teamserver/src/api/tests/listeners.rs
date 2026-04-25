use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crate::api::api_routes;
use crate::api::auth::{API_KEY_HEADER, ApiRuntime};
use crate::app::TeamserverState;
use crate::{
    AgentRegistry, AuthService, Database, EventBus, ListenerManager, OperatorConnectionManager,
    SocketRelayManager,
};
use red_cell_common::config::{OperatorRole, Profile};

use super::helpers::*;

// ── POST /listeners ────────────────────────────────────────────────

#[tokio::test]
async fn create_listener_returns_created_summary_body() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(create_listener_request(&smb_listener_json("pivot", "pipe-a"), "secret-admin"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = read_json(response).await;
    assert_eq!(body["name"], "pivot");
    assert_eq!(body["protocol"], "smb");
    assert_eq!(body["state"]["status"], "Created");
    assert_eq!(body["config"]["protocol"], "smb");
    assert_eq!(body["config"]["config"]["name"], "pivot");
    assert_eq!(body["config"]["config"]["pipe_name"], "pipe-a");
}

#[tokio::test]
async fn create_listener_rejects_duplicate_name_and_records_audit_failure() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let create_response = app
        .clone()
        .oneshot(create_listener_request(&smb_listener_json("pivot", "pipe-a"), "secret-admin"))
        .await
        .expect("response");
    assert_eq!(create_response.status(), StatusCode::CREATED);

    let duplicate_response = app
        .clone()
        .oneshot(create_listener_request(&smb_listener_json("pivot", "pipe-b"), "secret-admin"))
        .await
        .expect("response");

    assert_eq!(duplicate_response.status(), StatusCode::CONFLICT);
    let body = read_json(duplicate_response).await;
    assert_eq!(body["error"]["code"], "listener_already_exists");

    let audit_response = app
        .oneshot(
            Request::builder()
                .uri("/audit?action=listener.create")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(audit_response.status(), StatusCode::OK);
    let audit_body = read_json(audit_response).await;
    let items = audit_body["items"].as_array().expect("items array");
    assert!(!items.is_empty(), "expected at least one listener.create audit entry");
    let entry = &items[0];
    assert_eq!(entry["action"], "listener.create");
    assert_eq!(entry["target_kind"], "listener");
    assert_eq!(entry["target_id"], "pivot");
    assert_eq!(entry["result_status"], "failure");
}

#[tokio::test]
async fn create_listener_rejects_empty_name() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(create_listener_request(&smb_listener_json("", "pipe-a"), "secret-admin"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "listener_invalid_config");
}

// ── GET /listeners/{name} ───────────────────────────────────────────

#[tokio::test]
async fn get_listener_returns_summary_for_existing_listener() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let create_response = app
        .clone()
        .oneshot(create_listener_request(&smb_listener_json("pivot", "pipe-a"), "secret-admin"))
        .await
        .expect("response");
    assert_eq!(create_response.status(), StatusCode::CREATED);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/listeners/pivot")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["name"], "pivot");
    assert_eq!(body["config"]["protocol"], "smb");
    assert_eq!(body["state"]["status"], "Created");
}

#[tokio::test]
async fn get_listener_returns_not_found_for_missing_listener() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/listeners/nonexistent")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "listener_not_found");
}

// ── PUT /listeners/{name} (update) ──────────────────────────────────

#[tokio::test]
async fn update_listener_replaces_config() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let create_response = app
        .clone()
        .oneshot(create_listener_request(&smb_listener_json("pivot", "old-pipe"), "secret-admin"))
        .await
        .expect("response");
    assert_eq!(create_response.status(), StatusCode::CREATED);

    let update_response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/pivot")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(smb_listener_json("pivot", "new-pipe")))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(update_response.status(), StatusCode::OK);
    let body = read_json(update_response).await;
    assert_eq!(body["name"], "pivot");
    assert_eq!(body["config"]["config"]["pipe_name"], "new-pipe");
}

#[tokio::test]
async fn update_listener_rejects_name_mismatch() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let _ = app
        .clone()
        .oneshot(create_listener_request(&smb_listener_json("pivot", "pipe-a"), "secret-admin"))
        .await
        .expect("response");

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/pivot")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(smb_listener_json("wrong-name", "pipe-b")))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "listener_invalid_config");
}

#[tokio::test]
async fn update_listener_returns_not_found_for_missing() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/nonexistent")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(smb_listener_json("nonexistent", "pipe")))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn update_listener_records_audit_entry_on_success() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let _ = app
        .clone()
        .oneshot(create_listener_request(&smb_listener_json("pivot", "old-pipe"), "secret-admin"))
        .await
        .expect("response");

    let update_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/pivot")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(smb_listener_json("pivot", "new-pipe")))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(update_response.status(), StatusCode::OK);

    let audit_response = app
        .oneshot(
            Request::builder()
                .uri("/audit?action=listener.update")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(audit_response.status(), StatusCode::OK);
    let body = read_json(audit_response).await;
    let items = body["items"].as_array().expect("items array");
    assert!(!items.is_empty(), "expected at least one listener.update audit entry");
    let entry = &items[0];
    assert_eq!(entry["action"], "listener.update");
    assert_eq!(entry["target_kind"], "listener");
    assert_eq!(entry["target_id"], "pivot");
    assert_eq!(entry["result_status"], "success");
}

#[tokio::test]
async fn update_listener_records_audit_entry_on_name_mismatch() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let _ = app
        .clone()
        .oneshot(create_listener_request(&smb_listener_json("pivot", "pipe-a"), "secret-admin"))
        .await
        .expect("response");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/pivot")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(smb_listener_json("wrong-name", "pipe-b")))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let audit_response = app
        .oneshot(
            Request::builder()
                .uri("/audit?action=listener.update")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(audit_response.status(), StatusCode::OK);
    let body = read_json(audit_response).await;
    let items = body["items"].as_array().expect("items array");
    assert!(!items.is_empty(), "expected at least one listener.update audit entry");
    let entry = &items[0];
    assert_eq!(entry["action"], "listener.update");
    assert_eq!(entry["result_status"], "failure");
}

// ── DELETE /listeners/{name} ────────────────────────────────────────

#[tokio::test]
async fn delete_listener_removes_persisted_entry() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let _ = app
        .clone()
        .oneshot(create_listener_request(&smb_listener_json("pivot", "pipe-del"), "secret-admin"))
        .await
        .expect("response");

    let delete_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/listeners/pivot")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);

    let get_response = app
        .oneshot(
            Request::builder()
                .uri("/listeners/pivot")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(get_response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_listener_returns_not_found_for_missing() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/listeners/ghost")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_listener_records_audit_entry_on_success() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let _ = app
        .clone()
        .oneshot(create_listener_request(&smb_listener_json("pivot", "pipe-del"), "secret-admin"))
        .await
        .expect("response");

    let delete_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/listeners/pivot")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);

    let audit_response = app
        .oneshot(
            Request::builder()
                .uri("/audit?action=listener.delete")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(audit_response.status(), StatusCode::OK);
    let body = read_json(audit_response).await;
    let items = body["items"].as_array().expect("items array");
    assert!(!items.is_empty(), "expected at least one listener.delete audit entry");
    let entry = &items[0];
    assert_eq!(entry["action"], "listener.delete");
    assert_eq!(entry["target_kind"], "listener");
    assert_eq!(entry["target_id"], "pivot");
    assert_eq!(entry["result_status"], "success");
}

#[tokio::test]
async fn delete_listener_records_audit_entry_on_not_found() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/listeners/ghost")
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
                .uri("/audit?action=listener.delete")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(audit_response.status(), StatusCode::OK);
    let body = read_json(audit_response).await;
    let items = body["items"].as_array().expect("items array");
    assert!(!items.is_empty(), "expected at least one listener.delete audit entry");
    let entry = &items[0];
    assert_eq!(entry["action"], "listener.delete");
    assert_eq!(entry["result_status"], "failure");
}

// ── PUT /listeners/{name}/start ─────────────────────────────────────

#[tokio::test]
async fn start_listener_transitions_to_running() {
    let port = free_tcp_port();
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let _ = app
        .clone()
        .oneshot(create_listener_request(&http_listener_json("edge", port), "secret-admin"))
        .await
        .expect("response");

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/edge/start")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["name"], "edge");
    assert_eq!(body["state"]["status"], "Running");
}

#[tokio::test]
async fn start_listener_returns_not_found_for_missing() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/ghost/start")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn start_listener_rejects_already_running() {
    let port = free_tcp_port();
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let _ = app
        .clone()
        .oneshot(create_listener_request(&http_listener_json("edge-dup", port), "secret-admin"))
        .await
        .expect("response");

    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/edge-dup/start")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/edge-dup/start")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "listener_already_running");
}

// ── PUT /listeners/{name}/stop ──────────────────────────────────────

#[tokio::test]
async fn stop_listener_transitions_to_stopped() {
    let port = free_tcp_port();
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let _ = app
        .clone()
        .oneshot(create_listener_request(&http_listener_json("edge-stop", port), "secret-admin"))
        .await
        .expect("response");

    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/edge-stop/start")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/edge-stop/stop")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["name"], "edge-stop");
    assert_eq!(body["state"]["status"], "Stopped");
}

#[tokio::test]
async fn stop_listener_returns_not_found_for_missing() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/ghost/stop")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn stop_listener_rejects_not_running() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let _ = app
        .clone()
        .oneshot(create_listener_request(&smb_listener_json("idle", "idle-pipe"), "secret-admin"))
        .await
        .expect("response");

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/idle/stop")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "listener_not_running");
}

// ── POST /listeners/{name}/mark ─────────────────────────────────────

#[tokio::test]
async fn mark_listener_start_transitions_to_running() {
    let port = free_tcp_port();
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let _ = app
        .clone()
        .oneshot(create_listener_request(&http_listener_json("mark-edge", port), "secret-admin"))
        .await
        .expect("response");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/listeners/mark-edge/mark")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"mark":"start"}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["name"], "mark-edge");
    assert_eq!(body["state"]["status"], "Running");
}

#[tokio::test]
async fn mark_listener_stop_transitions_to_stopped() {
    let port = free_tcp_port();
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let _ = app
        .clone()
        .oneshot(create_listener_request(&http_listener_json("mark-stop", port), "secret-admin"))
        .await
        .expect("response");

    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/mark-stop/start")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/listeners/mark-stop/mark")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"mark":"stop"}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["name"], "mark-stop");
    assert_eq!(body["state"]["status"], "Stopped");
}

#[tokio::test]
async fn mark_listener_online_alias_transitions_to_running() {
    let port = free_tcp_port();
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let _ = app
        .clone()
        .oneshot(create_listener_request(&http_listener_json("mark-online", port), "secret-admin"))
        .await
        .expect("response");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/listeners/mark-online/mark")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"mark":"online"}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["state"]["status"], "Running");
}

#[tokio::test]
async fn mark_listener_rejects_unsupported_mark() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let _ = app
        .clone()
        .oneshot(create_listener_request(
            &smb_listener_json("mark-bad", "pipe-bad"),
            "secret-admin",
        ))
        .await
        .expect("response");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/listeners/mark-bad/mark")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"mark":"explode"}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "listener_unsupported_mark");
}

#[tokio::test]
async fn mark_listener_returns_not_found_for_missing() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/listeners/ghost/mark")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"mark":"start"}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ── GET /listeners (list) ─────────────────────────────────────────

#[tokio::test]
async fn list_listeners_returns_empty_array_initially() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/listeners")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body, serde_json::json!([]));
}

#[tokio::test]
async fn list_listeners_returns_created_listeners() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let create_response = app
        .clone()
        .oneshot(create_listener_request(&smb_listener_json("pivot-a", "pipe-a"), "secret-admin"))
        .await
        .expect("response");
    assert_eq!(create_response.status(), StatusCode::CREATED);

    let create_response = app
        .clone()
        .oneshot(create_listener_request(&smb_listener_json("pivot-b", "pipe-b"), "secret-admin"))
        .await
        .expect("response");
    assert_eq!(create_response.status(), StatusCode::CREATED);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/listeners")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    let items = body.as_array().expect("array of listeners");
    assert_eq!(items.len(), 2);
    let names: Vec<&str> = items.iter().filter_map(|v| v["name"].as_str()).collect();
    assert!(names.contains(&"pivot-a"));
    assert!(names.contains(&"pivot-b"));
}

// ── Listener round-trip integration test ──────────────────────────

#[tokio::test]
async fn listener_rest_api_round_trip_create_get_list_update_start_stop_delete() {
    let port = free_tcp_port();
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    // 1. Create
    let response = app
        .clone()
        .oneshot(create_listener_request(&http_listener_json("roundtrip", port), "secret-admin"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = read_json(response).await;
    assert_eq!(body["name"], "roundtrip");
    assert_eq!(body["state"]["status"], "Created");

    // 2. Get
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/listeners/roundtrip")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["name"], "roundtrip");

    // 3. List
    let response = app
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
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    let items = body.as_array().expect("listener array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["name"], "roundtrip");

    // 4. Update (change port_bind to a new ephemeral port)
    let new_port = free_tcp_port();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/roundtrip")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(http_listener_json("roundtrip", new_port)))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["name"], "roundtrip");

    // 5. Start
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/roundtrip/start")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["state"]["status"], "Running");

    // 6. Stop
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/roundtrip/stop")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["state"]["status"], "Stopped");

    // 7. Delete
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/listeners/roundtrip")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify deletion
    let response = app
        .oneshot(
            Request::builder()
                .uri("/listeners/roundtrip")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ── Validation: empty SMB pipe name ───────────────────────────────

#[tokio::test]
async fn create_listener_rejects_empty_smb_pipe_name() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(create_listener_request(&smb_listener_json("pivot", ""), "secret-admin"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "listener_invalid_config");
}

// ── RBAC: analyst cannot delete listeners ─────────────────────────

#[tokio::test]
async fn analyst_key_cannot_delete_listeners() {
    let app =
        test_router(Some((60, "rest-analyst", "secret-analyst", OperatorRole::Analyst))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/listeners/any-listener")
                .header(API_KEY_HEADER, "secret-analyst")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "forbidden");
}

#[tokio::test]
async fn analyst_key_cannot_start_listeners() {
    let app =
        test_router(Some((60, "rest-analyst", "secret-analyst", OperatorRole::Analyst))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/any-listener/start")
                .header(API_KEY_HEADER, "secret-analyst")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "forbidden");
}

#[tokio::test]
async fn analyst_key_cannot_stop_listeners() {
    let app =
        test_router(Some((60, "rest-analyst", "secret-analyst", OperatorRole::Analyst))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/any-listener/stop")
                .header(API_KEY_HEADER, "secret-analyst")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "forbidden");
}

#[tokio::test]
async fn analyst_key_cannot_update_listeners() {
    let app =
        test_router(Some((60, "rest-analyst", "secret-analyst", OperatorRole::Analyst))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/any-listener")
                .header(API_KEY_HEADER, "secret-analyst")
                .header("content-type", "application/json")
                .body(Body::from(smb_listener_json("any-listener", "pipe")))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "forbidden");
}

#[tokio::test]
async fn analyst_key_cannot_mark_listeners() {
    let app =
        test_router(Some((60, "rest-analyst", "secret-analyst", OperatorRole::Analyst))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/listeners/any-listener/mark")
                .header(API_KEY_HEADER, "secret-analyst")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"mark":"start"}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "forbidden");
}

// ── Audit: start/stop record audit entries ────────────────────────

#[tokio::test]
async fn start_listener_records_audit_entry_on_success() {
    let port = free_tcp_port();
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let _ = app
        .clone()
        .oneshot(create_listener_request(&http_listener_json("audit-start", port), "secret-admin"))
        .await
        .expect("response");

    let start_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/audit-start/start")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(start_response.status(), StatusCode::OK);

    let audit_response = app
        .oneshot(
            Request::builder()
                .uri("/audit?action=listener.start")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(audit_response.status(), StatusCode::OK);
    let body = read_json(audit_response).await;
    let items = body["items"].as_array().expect("items array");
    assert!(!items.is_empty(), "expected at least one listener.start audit entry");
    let entry = &items[0];
    assert_eq!(entry["action"], "listener.start");
    assert_eq!(entry["target_kind"], "listener");
    assert_eq!(entry["target_id"], "audit-start");
    assert_eq!(entry["result_status"], "success");
}

#[tokio::test]
async fn stop_listener_records_audit_entry_on_success() {
    let port = free_tcp_port();
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let _ = app
        .clone()
        .oneshot(create_listener_request(&http_listener_json("audit-stop", port), "secret-admin"))
        .await
        .expect("response");

    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/audit-stop/start")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    let stop_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/audit-stop/stop")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(stop_response.status(), StatusCode::OK);

    let audit_response = app
        .oneshot(
            Request::builder()
                .uri("/audit?action=listener.stop")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(audit_response.status(), StatusCode::OK);
    let body = read_json(audit_response).await;
    let items = body["items"].as_array().expect("items array");
    assert!(!items.is_empty(), "expected at least one listener.stop audit entry");
    let entry = &items[0];
    assert_eq!(entry["action"], "listener.stop");
    assert_eq!(entry["target_kind"], "listener");
    assert_eq!(entry["target_id"], "audit-stop");
    assert_eq!(entry["result_status"], "success");
}

#[tokio::test]
async fn start_listener_records_audit_entry_on_not_found() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/ghost/start")
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
                .uri("/audit?action=listener.start")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(audit_response.status(), StatusCode::OK);
    let body = read_json(audit_response).await;
    let items = body["items"].as_array().expect("items array");
    assert!(!items.is_empty(), "expected at least one listener.start audit entry");
    let entry = &items[0];
    assert_eq!(entry["action"], "listener.start");
    assert_eq!(entry["result_status"], "failure");
}

#[tokio::test]
async fn stop_listener_records_audit_entry_on_not_found() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/ghost/stop")
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
                .uri("/audit?action=listener.stop")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(audit_response.status(), StatusCode::OK);
    let body = read_json(audit_response).await;
    let items = body["items"].as_array().expect("items array");
    assert!(!items.is_empty(), "expected at least one listener.stop audit entry");
    let entry = &items[0];
    assert_eq!(entry["action"], "listener.stop");
    assert_eq!(entry["result_status"], "failure");
}

// ── Analyst can GET a single listener ─────────────────────────────

#[tokio::test]
async fn analyst_key_can_get_individual_listener() {
    let database = Database::connect_in_memory().await.expect("database");
    let agent_registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(agent_registry.clone(), events.clone());
    let listeners = ListenerManager::new(
        database.clone(),
        agent_registry.clone(),
        events.clone(),
        sockets.clone(),
        None,
    )
    .with_demon_allow_legacy_ctr(true);

    // Build a profile with both admin and analyst keys.
    let profile = Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40056
        }

        Operators {
          user "Neo" {
            Password = "password1234"
          }
        }

        Api {
          RateLimitPerMinute = 60
          key "rest-admin" {
            Value = "secret-admin"
            Role = "Admin"
          }
          key "rest-analyst" {
            Value = "secret-analyst"
            Role = "Analyst"
          }
        }

        Demon {}
        "#,
    )
    .expect("profile");

    let api = ApiRuntime::from_profile(&profile).expect("rng should work in tests");
    let auth = AuthService::from_profile_with_database(&profile, &database).await.expect("auth");
    let app = api_routes(api.clone()).with_state(TeamserverState {
        profile: profile.clone(),
        profile_path: "test.yaotl".to_owned(),
        database,
        auth,
        api,
        events,
        connections: OperatorConnectionManager::new(),
        agent_registry,
        listeners,
        payload_builder: crate::PayloadBuilderService::disabled_for_tests(),
        sockets,
        webhooks: crate::AuditWebhookNotifier::from_profile(&profile),
        login_rate_limiter: crate::LoginRateLimiter::new(),
        shutdown: crate::ShutdownController::new(),
        service_bridge: None,
        started_at: std::time::Instant::now(),
        plugins_loaded: 0,
        plugins_failed: 0,
        metrics: crate::metrics::standalone_metrics_handle(),
    });

    // Admin creates a listener.
    let create_response = app
        .clone()
        .oneshot(create_listener_request(&smb_listener_json("pivot", "pipe-a"), "secret-admin"))
        .await
        .expect("response");
    assert_eq!(create_response.status(), StatusCode::CREATED);

    // Analyst can read the individual listener.
    let get_response = app
        .oneshot(
            Request::builder()
                .uri("/listeners/pivot")
                .header(API_KEY_HEADER, "secret-analyst")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(get_response.status(), StatusCode::OK);
    let body = read_json(get_response).await;
    assert_eq!(body["name"], "pivot");
}
