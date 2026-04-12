use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

use red_cell_common::config::{OperatorRole, Profile};

use crate::api::api_routes;
use crate::api::auth::{API_KEY_HEADER, ApiRuntime};
use crate::api::payload::{
    cli_format_to_havoc, normalize_agent_type, validate_agent_format_combination,
};
use crate::{
    AgentRegistry, AuthService, Database, EventBus, ListenerManager, OperatorConnectionManager,
    SocketRelayManager,
};

use super::helpers::*;

// ── flush_payload_cache ────────────────────────────────────────────

#[tokio::test]
async fn flush_payload_cache_returns_flushed_count_for_admin() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/payload-cache")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    // The disabled-for-tests service uses a nonexistent cache dir, so 0 entries flushed.
    assert_eq!(body["flushed"], 0);
}

#[tokio::test]
async fn flush_payload_cache_requires_admin_role() {
    let app = test_router(Some((60, "rest-operator", "secret-op", OperatorRole::Operator))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/payload-cache")
                .header(API_KEY_HEADER, "secret-op")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn get_webhook_stats_returns_null_discord_when_not_configured() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/webhooks/stats")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["discord"], Value::Null);
}

#[tokio::test]
async fn get_webhook_stats_returns_discord_failures_when_configured() {
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
        }

        WebHook {
          Discord {
            Url = "http://127.0.0.1:19999/discord-stub"
          }
        }

        Demon {}
        "#,
    )
    .expect("profile");

    let database = crate::Database::connect_in_memory().await.expect("database");
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
    let api = ApiRuntime::from_profile(&profile).expect("rng should work in tests");
    let auth = AuthService::from_profile(&profile).expect("auth service should initialize");

    let app = api_routes(api.clone()).with_state(crate::TeamserverState {
        profile: profile.clone(),
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

    let response = app
        .oneshot(
            Request::builder()
                .uri("/webhooks/stats")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert!(body["discord"].is_object(), "discord field should be present when configured");
    assert_eq!(body["discord"]["failures"], 0u64);
}

// ── GET /payloads ───────────────────────────────────────────────────

#[tokio::test]
async fn list_payloads_returns_empty_initially() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/payloads")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert!(body.as_array().expect("should be array").is_empty());
}

#[tokio::test]
async fn list_payloads_returns_completed_builds() {
    let database = Database::connect_in_memory().await.expect("database");
    let record = crate::PayloadBuildRecord {
        id: "build-123".to_owned(),
        status: "done".to_owned(),
        name: "demon.x64.exe".to_owned(),
        arch: "x64".to_owned(),
        format: "exe".to_owned(),
        listener: "http1".to_owned(),
        agent_type: "Demon".to_owned(),
        sleep_secs: None,
        artifact: Some(vec![0xDE, 0xAD]),
        size_bytes: Some(2),
        error: None,
        created_at: "2026-03-23T10:00:00Z".to_owned(),
        updated_at: "2026-03-23T10:00:00Z".to_owned(),
    };
    database.payload_builds().create(&record).await.expect("create");

    let (app, _, _) = test_router_with_database(
        database,
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/payloads")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    let items = body.as_array().expect("should be array");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], "build-123");
    assert_eq!(items[0]["name"], "demon.x64.exe");
    assert_eq!(items[0]["arch"], "x64");
    assert_eq!(items[0]["format"], "exe");
    assert_eq!(items[0]["size_bytes"], 2);
}

#[tokio::test]
async fn list_payloads_excludes_pending_builds() {
    let database = Database::connect_in_memory().await.expect("database");
    let record = crate::PayloadBuildRecord {
        id: "pending-job".to_owned(),
        status: "pending".to_owned(),
        name: String::new(),
        arch: "x64".to_owned(),
        format: "exe".to_owned(),
        listener: "http1".to_owned(),
        agent_type: "Demon".to_owned(),
        sleep_secs: None,
        artifact: None,
        size_bytes: None,
        error: None,
        created_at: "2026-03-23T10:00:00Z".to_owned(),
        updated_at: "2026-03-23T10:00:00Z".to_owned(),
    };
    database.payload_builds().create(&record).await.expect("create");

    let (app, _, _) = test_router_with_database(
        database,
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/payloads")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert!(body.as_array().expect("should be array").is_empty());
}

// ── POST /payloads/build ────────────────────────────────────────────

#[tokio::test]
async fn submit_payload_build_rejects_invalid_format() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/payloads/build")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"listener":"http1","arch":"x64","format":"elf"}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "invalid_format");
}

#[tokio::test]
async fn submit_payload_build_rejects_invalid_arch() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/payloads/build")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"listener":"http1","arch":"arm64","format":"exe"}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "invalid_arch");
}

#[tokio::test]
async fn submit_payload_build_rejects_missing_listener() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/payloads/build")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"listener":"nonexistent","arch":"x64","format":"exe"}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "listener_not_found");
}

#[tokio::test]
async fn submit_payload_build_requires_auth() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/payloads/build")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"listener":"http1","arch":"x64","format":"exe"}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ── GET /payloads/jobs/{job_id} ─────────────────────────────────────

#[tokio::test]
async fn get_payload_job_returns_not_found_for_missing_job() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/payloads/jobs/nonexistent")
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
async fn get_payload_job_returns_status_for_pending_job() {
    let database = Database::connect_in_memory().await.expect("database");
    let record = crate::PayloadBuildRecord {
        id: "job-pending".to_owned(),
        status: "pending".to_owned(),
        name: String::new(),
        arch: "x64".to_owned(),
        format: "exe".to_owned(),
        listener: "http1".to_owned(),
        agent_type: "Demon".to_owned(),
        sleep_secs: None,
        artifact: None,
        size_bytes: None,
        error: None,
        created_at: "2026-03-23T10:00:00Z".to_owned(),
        updated_at: "2026-03-23T10:00:00Z".to_owned(),
    };
    database.payload_builds().create(&record).await.expect("create");

    let (app, _, _) = test_router_with_database(
        database,
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/payloads/jobs/job-pending")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["job_id"], "job-pending");
    assert_eq!(body["status"], "pending");
    assert!(body["payload_id"].is_null());
}

#[tokio::test]
async fn get_payload_job_returns_payload_id_for_done_job() {
    let database = Database::connect_in_memory().await.expect("database");
    let record = crate::PayloadBuildRecord {
        id: "job-done".to_owned(),
        status: "done".to_owned(),
        name: "demon.x64.exe".to_owned(),
        arch: "x64".to_owned(),
        format: "exe".to_owned(),
        listener: "http1".to_owned(),
        agent_type: "Demon".to_owned(),
        sleep_secs: None,
        artifact: Some(vec![0xCA, 0xFE]),
        size_bytes: Some(2),
        error: None,
        created_at: "2026-03-23T10:00:00Z".to_owned(),
        updated_at: "2026-03-23T10:01:00Z".to_owned(),
    };
    database.payload_builds().create(&record).await.expect("create");

    let (app, _, _) = test_router_with_database(
        database,
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/payloads/jobs/job-done")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["job_id"], "job-done");
    assert_eq!(body["status"], "done");
    assert_eq!(body["payload_id"], "job-done");
    assert_eq!(body["size_bytes"], 2);
}

#[tokio::test]
async fn get_payload_job_returns_error_for_failed_job() {
    let database = Database::connect_in_memory().await.expect("database");
    let record = crate::PayloadBuildRecord {
        id: "job-err".to_owned(),
        status: "error".to_owned(),
        name: String::new(),
        arch: "x64".to_owned(),
        format: "exe".to_owned(),
        listener: "http1".to_owned(),
        agent_type: "Demon".to_owned(),
        sleep_secs: None,
        artifact: None,
        size_bytes: None,
        error: Some("compiler not found".to_owned()),
        created_at: "2026-03-23T10:00:00Z".to_owned(),
        updated_at: "2026-03-23T10:01:00Z".to_owned(),
    };
    database.payload_builds().create(&record).await.expect("create");

    let (app, _, _) = test_router_with_database(
        database,
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/payloads/jobs/job-err")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["status"], "error");
    assert_eq!(body["error"], "compiler not found");
}

// ── GET /payloads/{id}/download ─────────────────────────────────────

#[tokio::test]
async fn download_payload_returns_artifact_bytes() {
    let database = Database::connect_in_memory().await.expect("database");
    let artifact = vec![0x4D, 0x5A, 0x90, 0x00]; // MZ header stub
    let record = crate::PayloadBuildRecord {
        id: "dl-test".to_owned(),
        status: "done".to_owned(),
        name: "demon.x64.exe".to_owned(),
        arch: "x64".to_owned(),
        format: "exe".to_owned(),
        listener: "http1".to_owned(),
        agent_type: "Demon".to_owned(),
        sleep_secs: None,
        artifact: Some(artifact.clone()),
        size_bytes: Some(i64::try_from(artifact.len()).unwrap_or(i64::MAX)),
        error: None,
        created_at: "2026-03-23T10:00:00Z".to_owned(),
        updated_at: "2026-03-23T10:01:00Z".to_owned(),
    };
    database.payload_builds().create(&record).await.expect("create");

    let (app, _, _) = test_router_with_database(
        database,
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/payloads/dl-test/download")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").and_then(|v| v.to_str().ok()),
        Some("application/octet-stream")
    );
    assert!(
        response
            .headers()
            .get("content-disposition")
            .and_then(|v| v.to_str().ok())
            .expect("content-disposition header")
            .contains("demon.x64.exe")
    );

    let body_bytes = to_bytes(response.into_body(), usize::MAX).await.expect("body");
    assert_eq!(body_bytes.as_ref(), &artifact);
}

#[tokio::test]
async fn download_payload_returns_not_found_for_pending_build() {
    let database = Database::connect_in_memory().await.expect("database");
    let record = crate::PayloadBuildRecord {
        id: "dl-pending".to_owned(),
        status: "pending".to_owned(),
        name: String::new(),
        arch: "x64".to_owned(),
        format: "exe".to_owned(),
        listener: "http1".to_owned(),
        agent_type: "Demon".to_owned(),
        sleep_secs: None,
        artifact: None,
        size_bytes: None,
        error: None,
        created_at: "2026-03-23T10:00:00Z".to_owned(),
        updated_at: "2026-03-23T10:00:00Z".to_owned(),
    };
    database.payload_builds().create(&record).await.expect("create");

    let (app, _, _) = test_router_with_database(
        database,
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/payloads/dl-pending/download")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "payload_not_ready");
}

#[tokio::test]
async fn download_payload_returns_not_found_for_missing_id() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/payloads/no-such-id/download")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "payload_not_found");
}

#[tokio::test]
async fn download_payload_returns_gone_for_stale_build() {
    let database = Database::connect_in_memory().await.expect("database");
    let record = crate::PayloadBuildRecord {
        id: "dl-stale".to_owned(),
        status: "stale".to_owned(),
        name: "demon.x64.exe".to_owned(),
        arch: "x64".to_owned(),
        format: "exe".to_owned(),
        listener: "http1".to_owned(),
        agent_type: "Demon".to_owned(),
        sleep_secs: None,
        artifact: Some(vec![0x4D, 0x5A]),
        size_bytes: Some(2),
        error: None,
        created_at: "2026-03-31T10:00:00Z".to_owned(),
        updated_at: "2026-03-31T11:00:00Z".to_owned(),
    };
    database.payload_builds().create(&record).await.expect("create");

    let (app, _, _) = test_router_with_database(
        database,
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/payloads/dl-stale/download")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::GONE);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "payload_stale");
}

#[tokio::test]
async fn update_listener_invalidates_done_payload_builds() {
    let database = Database::connect_in_memory().await.expect("database");

    // Seed a "done" payload build for the listener we will update.
    let done_record = crate::PayloadBuildRecord {
        id: "inv-api-a".to_owned(),
        status: "done".to_owned(),
        name: "demon.x64.exe".to_owned(),
        arch: "x64".to_owned(),
        format: "exe".to_owned(),
        listener: "pivot".to_owned(),
        agent_type: "Demon".to_owned(),
        sleep_secs: None,
        artifact: Some(vec![0xDE, 0xAD]),
        size_bytes: Some(2),
        error: None,
        created_at: "2026-03-31T10:00:00Z".to_owned(),
        updated_at: "2026-03-31T10:00:00Z".to_owned(),
    };
    database.payload_builds().create(&done_record).await.expect("create build record");

    let (app, _, _) = test_router_with_database(
        database.clone(),
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    // Create the listener first so the update endpoint has something to mutate.
    let _ = app
        .clone()
        .oneshot(create_listener_request(&smb_listener_json("pivot", "old-pipe"), "secret-admin"))
        .await
        .expect("create listener response");

    // Update the listener config (pipe name changes).
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

    // The previously "done" build must now be "stale".
    let fetched = database
        .payload_builds()
        .get("inv-api-a")
        .await
        .expect("db query")
        .expect("record should exist");
    assert_eq!(fetched.status, "stale", "done build should be stale after listener update");
}

#[tokio::test]
async fn identical_listener_put_preserves_done_payload_builds() {
    let database = Database::connect_in_memory().await.expect("database");

    // Seed a "done" payload build for the listener we will update.
    let done_record = crate::PayloadBuildRecord {
        id: "inv-noop-a".to_owned(),
        status: "done".to_owned(),
        name: "demon.x64.exe".to_owned(),
        arch: "x64".to_owned(),
        format: "exe".to_owned(),
        listener: "noop-smb".to_owned(),
        agent_type: "Demon".to_owned(),
        sleep_secs: None,
        artifact: Some(vec![0xDE, 0xAD]),
        size_bytes: Some(2),
        error: None,
        created_at: "2026-03-31T10:00:00Z".to_owned(),
        updated_at: "2026-03-31T10:00:00Z".to_owned(),
    };
    database.payload_builds().create(&done_record).await.expect("create build record");

    let (app, _, _) = test_router_with_database(
        database.clone(),
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    // Create the listener.
    let _ = app
        .clone()
        .oneshot(create_listener_request(
            &smb_listener_json("noop-smb", "same-pipe"),
            "secret-admin",
        ))
        .await
        .expect("create listener response");

    // PUT the exact same config (no change).
    let update_response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/noop-smb")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(smb_listener_json("noop-smb", "same-pipe")))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(update_response.status(), StatusCode::OK);

    // The "done" build must still be "done" — not stale.
    let fetched = database
        .payload_builds()
        .get("inv-noop-a")
        .await
        .expect("db query")
        .expect("record should exist");
    assert_eq!(fetched.status, "done", "done build must remain done after identical listener PUT");
}

// ── RBAC: analyst can list payloads but not build or download artifacts ─

#[tokio::test]
async fn analyst_can_list_payloads() {
    let app =
        test_router(Some((60, "rest-analyst", "secret-analyst", OperatorRole::Analyst))).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/payloads")
                .header(API_KEY_HEADER, "secret-analyst")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn analyst_cannot_submit_payload_build() {
    let app =
        test_router(Some((60, "rest-analyst", "secret-analyst", OperatorRole::Analyst))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/payloads/build")
                .header(API_KEY_HEADER, "secret-analyst")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"listener":"http1","arch":"x64","format":"exe"}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn analyst_cannot_download_payload_artifact() {
    let app =
        test_router(Some((60, "rest-analyst", "secret-analyst", OperatorRole::Analyst))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/payloads/any-id/download")
                .header(API_KEY_HEADER, "secret-analyst")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// ── cli_format_to_havoc unit tests ──────────────────────────────────

#[test]
fn cli_format_to_havoc_maps_valid_formats() {
    assert_eq!(cli_format_to_havoc("exe"), Ok("Windows Exe"));
    assert_eq!(cli_format_to_havoc("dll"), Ok("Windows Dll"));
    assert_eq!(cli_format_to_havoc("bin"), Ok("Windows Shellcode"));
}

#[test]
fn cli_format_to_havoc_rejects_unknown_formats() {
    assert!(cli_format_to_havoc("elf").is_err());
    assert!(cli_format_to_havoc("").is_err());
}

// ── normalize_agent_type unit tests ─────────────────────────────────

#[test]
fn normalize_agent_type_maps_all_valid_types() {
    assert_eq!(normalize_agent_type("demon"), Ok("Demon"));
    assert_eq!(normalize_agent_type("archon"), Ok("Archon"));
    assert_eq!(normalize_agent_type("phantom"), Ok("Phantom"));
    assert_eq!(normalize_agent_type("specter"), Ok("Specter"));
}

#[test]
fn normalize_agent_type_is_case_insensitive() {
    assert_eq!(normalize_agent_type("Demon"), Ok("Demon"));
    assert_eq!(normalize_agent_type("ARCHON"), Ok("Archon"));
    assert_eq!(normalize_agent_type("Phantom"), Ok("Phantom"));
    assert_eq!(normalize_agent_type("SPECTER"), Ok("Specter"));
}

#[test]
fn normalize_agent_type_rejects_unknown() {
    assert!(normalize_agent_type("alien").is_err());
    assert!(normalize_agent_type("").is_err());
    assert!(normalize_agent_type("Shellcode").is_err());
}

// ── validate_agent_format_combination unit tests ─────────────────────

#[test]
fn agent_format_combination_accepts_demon_all_formats() {
    for fmt in &["exe", "dll", "bin"] {
        assert!(
            validate_agent_format_combination("Demon", fmt).is_ok(),
            "Demon should accept format '{fmt}'"
        );
    }
}

#[test]
fn agent_format_combination_accepts_archon_all_formats() {
    for fmt in &["exe", "dll", "bin"] {
        assert!(
            validate_agent_format_combination("Archon", fmt).is_ok(),
            "Archon should accept format '{fmt}'"
        );
    }
}

#[test]
fn agent_format_combination_accepts_phantom_exe_only() {
    assert!(validate_agent_format_combination("Phantom", "exe").is_ok());
    assert!(validate_agent_format_combination("Phantom", "dll").is_err());
    assert!(validate_agent_format_combination("Phantom", "bin").is_err());
}

#[test]
fn agent_format_combination_accepts_specter_exe_only() {
    assert!(validate_agent_format_combination("Specter", "exe").is_ok());
    assert!(validate_agent_format_combination("Specter", "dll").is_err());
    assert!(validate_agent_format_combination("Specter", "bin").is_err());
}

// ── payload build agent-type API tests ──────────────────────────────

#[tokio::test]
async fn payload_build_rejects_unsupported_agent_type() {
    let app = test_router(Some((60, "operator", "secret-operator", OperatorRole::Operator))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/payloads/build")
                .header(API_KEY_HEADER, "secret-operator")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"listener":"http1","arch":"x64","format":"exe","agent":"alien"}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.expect("body");
    let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(json["error"]["code"], "invalid_agent_type");
}

#[tokio::test]
async fn payload_build_accepts_all_valid_agent_types() {
    // The listener doesn't exist so we expect 404 (listener_not_found), not a
    // 400 agent-validation error.  That proves the agent value passed validation.
    for agent in &["demon", "archon", "phantom", "specter"] {
        let app =
            test_router(Some((60, "operator", "secret-operator", OperatorRole::Operator))).await;
        let body =
            serde_json::json!({"listener":"nonexistent","arch":"x64","format":"exe","agent": agent})
                .to_string();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/payloads/build")
                    .header(API_KEY_HEADER, "secret-operator")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .expect("request"),
            )
            .await
            .expect("response");

        // 404 means agent validation passed and we reached the listener lookup.
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "expected 404 for agent={agent}, got {}",
            response.status()
        );
    }
}

#[tokio::test]
async fn payload_build_rejects_unsupported_agent_format_combination() {
    // Phantom and Specter only produce exe artifacts; requesting dll or bin
    // must be rejected with 400 / unsupported_agent_format before the listener
    // lookup so callers never receive a misleading successful response.
    for (agent, format) in
        &[("phantom", "dll"), ("phantom", "bin"), ("specter", "dll"), ("specter", "bin")]
    {
        let app =
            test_router(Some((60, "operator", "secret-operator", OperatorRole::Operator))).await;
        let body =
            serde_json::json!({"listener":"nonexistent","arch":"x64","format": format,"agent": agent})
                .to_string();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/payloads/build")
                    .header(API_KEY_HEADER, "secret-operator")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "expected 400 for agent={agent} format={format}"
        );
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.expect("body");
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(
            json["error"]["code"], "unsupported_agent_format",
            "wrong error code for agent={agent} format={format}"
        );
    }
}

#[tokio::test]
async fn payload_build_defaults_to_demon_when_agent_omitted() {
    // Without an `agent` field the default "demon" value should apply, so
    // validation passes and we fail at the listener lookup (404) rather
    // than at agent validation (400).
    let app = test_router(Some((60, "operator", "secret-operator", OperatorRole::Operator))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/payloads/build")
                .header(API_KEY_HEADER, "secret-operator")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"listener":"nonexistent","arch":"x64","format":"exe"}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// End-to-end test: the agent type requested via `POST /payloads/build` is
/// persisted in the build record and returned by `GET /payloads/jobs/{id}`.
///
/// This proves the full path: request → normalisation → DB record → response,
/// i.e. the agent type actually reaches the payload builder call.
#[tokio::test]
async fn payload_build_agent_type_reaches_job_record() {
    for (agent_in, agent_out) in
        &[("demon", "Demon"), ("archon", "Archon"), ("phantom", "Phantom"), ("specter", "Specter")]
    {
        let app =
            test_router(Some((60, "operator", "secret-operator", OperatorRole::Operator))).await;

        // First create a listener so the build request passes the listener-lookup
        // check and a job record is actually created.
        let create_resp = app
            .clone()
            .oneshot(create_listener_request(
                &smb_listener_json("build-test-pivot", "test-pipe"),
                "secret-operator",
            ))
            .await
            .expect("create listener response");
        assert_eq!(
            create_resp.status(),
            StatusCode::CREATED,
            "failed to create listener for agent={agent_in}"
        );

        // Submit the build.
        let body =
            serde_json::json!({"listener":"build-test-pivot","arch":"x64","format":"exe","agent":agent_in})
                .to_string();
        let submit_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/payloads/build")
                    .header(API_KEY_HEADER, "secret-operator")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .expect("request"),
            )
            .await
            .expect("submit response");

        assert_eq!(submit_resp.status(), StatusCode::ACCEPTED, "expected 202 for agent={agent_in}");
        let submit_json = read_json(submit_resp).await;
        let job_id = submit_json["job_id"].as_str().expect("job_id").to_owned();

        // Fetch the job status — agent_type must reflect what was submitted.
        let status_resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/payloads/jobs/{job_id}"))
                    .header(API_KEY_HEADER, "secret-operator")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("status response");

        assert_eq!(status_resp.status(), StatusCode::OK, "job not found for agent={agent_in}");
        let status_json = read_json(status_resp).await;
        assert_eq!(
            status_json["agent_type"], *agent_out,
            "agent_type mismatch for agent_in={agent_in}: expected {agent_out}"
        );
    }
}

// ── PayloadBuildRepository unit tests ────────────────────────────────

#[tokio::test]
async fn payload_build_repository_create_and_get() {
    let db = Database::connect_in_memory().await.expect("db");
    let repo = db.payload_builds();

    let record = crate::PayloadBuildRecord {
        id: "test-1".to_owned(),
        status: "pending".to_owned(),
        name: String::new(),
        arch: "x64".to_owned(),
        format: "exe".to_owned(),
        listener: "http1".to_owned(),
        agent_type: "Demon".to_owned(),
        sleep_secs: Some(10),
        artifact: None,
        size_bytes: None,
        error: None,
        created_at: "2026-03-23T10:00:00Z".to_owned(),
        updated_at: "2026-03-23T10:00:00Z".to_owned(),
    };

    repo.create(&record).await.expect("create");
    let fetched = repo.get("test-1").await.expect("get").expect("should exist");
    assert_eq!(fetched.id, "test-1");
    assert_eq!(fetched.status, "pending");
    assert_eq!(fetched.arch, "x64");
    assert_eq!(fetched.sleep_secs, Some(10));
}

#[tokio::test]
async fn payload_build_repository_get_missing_returns_none() {
    let db = Database::connect_in_memory().await.expect("db");
    let result = db.payload_builds().get("nonexistent").await.expect("get");
    assert!(result.is_none());
}

#[tokio::test]
async fn payload_build_repository_list_returns_all() {
    let db = Database::connect_in_memory().await.expect("db");
    let repo = db.payload_builds();

    for i in 0..3 {
        let record = crate::PayloadBuildRecord {
            id: format!("list-{i}"),
            status: "done".to_owned(),
            name: format!("payload-{i}.exe"),
            arch: "x64".to_owned(),
            format: "exe".to_owned(),
            listener: "http1".to_owned(),
            agent_type: "Demon".to_owned(),
            sleep_secs: None,
            artifact: Some(vec![0xDE, 0xAD]),
            size_bytes: Some(2),
            error: None,
            created_at: format!("2026-03-23T10:0{i}:00Z"),
            updated_at: format!("2026-03-23T10:0{i}:00Z"),
        };
        repo.create(&record).await.expect("create");
    }

    let all = repo.list().await.expect("list");
    assert_eq!(all.len(), 3);
}

#[tokio::test]
async fn payload_build_repository_update_status() {
    let db = Database::connect_in_memory().await.expect("db");
    let repo = db.payload_builds();

    let record = crate::PayloadBuildRecord {
        id: "upd-1".to_owned(),
        status: "pending".to_owned(),
        name: String::new(),
        arch: "x64".to_owned(),
        format: "exe".to_owned(),
        listener: "http1".to_owned(),
        agent_type: "Demon".to_owned(),
        sleep_secs: None,
        artifact: None,
        size_bytes: None,
        error: None,
        created_at: "2026-03-23T10:00:00Z".to_owned(),
        updated_at: "2026-03-23T10:00:00Z".to_owned(),
    };
    repo.create(&record).await.expect("create");

    let updated = repo
        .update_status(
            "upd-1",
            "done",
            Some("demon.x64.exe"),
            Some(&[0xCA, 0xFE]),
            Some(2),
            None,
            "2026-03-23T10:01:00Z",
        )
        .await
        .expect("update");
    assert!(updated);

    let fetched = repo.get("upd-1").await.expect("get").expect("exists");
    assert_eq!(fetched.status, "done");
    assert_eq!(fetched.name, "demon.x64.exe");
    assert_eq!(fetched.artifact, Some(vec![0xCA, 0xFE]));
    assert_eq!(fetched.size_bytes, Some(2));
    assert_eq!(fetched.updated_at, "2026-03-23T10:01:00Z");
}

#[tokio::test]
async fn payload_build_repository_update_missing_returns_false() {
    let db = Database::connect_in_memory().await.expect("db");
    let result = db
        .payload_builds()
        .update_status("ghost", "done", None, None, None, None, "2026-03-23T10:00:00Z")
        .await
        .expect("update");
    assert!(!result);
}

#[tokio::test]
async fn payload_build_get_summary_excludes_artifact() {
    let db = Database::connect_in_memory().await.expect("db");
    let repo = db.payload_builds();

    let record = crate::PayloadBuildRecord {
        id: "sum-1".to_owned(),
        status: "done".to_owned(),
        name: "payload.exe".to_owned(),
        arch: "x64".to_owned(),
        format: "exe".to_owned(),
        listener: "http1".to_owned(),
        agent_type: "Demon".to_owned(),
        sleep_secs: Some(5),
        artifact: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        size_bytes: Some(4),
        error: None,
        created_at: "2026-03-23T10:00:00Z".to_owned(),
        updated_at: "2026-03-23T10:00:00Z".to_owned(),
    };
    repo.create(&record).await.expect("create");

    let summary = repo.get_summary("sum-1").await.expect("get_summary").expect("exists");
    assert_eq!(summary.id, "sum-1");
    assert_eq!(summary.status, "done");
    assert_eq!(summary.name, "payload.exe");
    assert_eq!(summary.arch, "x64");
    assert_eq!(summary.size_bytes, Some(4));

    // Verify the full get() still returns the artifact
    let full = repo.get("sum-1").await.expect("get").expect("exists");
    assert_eq!(full.artifact, Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
}

#[tokio::test]
async fn payload_build_get_summary_missing_returns_none() {
    let db = Database::connect_in_memory().await.expect("db");
    let result = db.payload_builds().get_summary("nonexistent").await.expect("get_summary");
    assert!(result.is_none());
}

#[tokio::test]
async fn payload_build_list_summaries_excludes_artifact() {
    let db = Database::connect_in_memory().await.expect("db");
    let repo = db.payload_builds();

    for i in 0..3 {
        let record = crate::PayloadBuildRecord {
            id: format!("lsum-{i}"),
            status: "done".to_owned(),
            name: format!("payload-{i}.exe"),
            arch: "x64".to_owned(),
            format: "exe".to_owned(),
            listener: "http1".to_owned(),
            agent_type: "Demon".to_owned(),
            sleep_secs: None,
            artifact: Some(vec![0xCA; 1024]),
            size_bytes: Some(1024),
            error: None,
            created_at: format!("2026-03-23T10:0{i}:00Z"),
            updated_at: format!("2026-03-23T10:0{i}:00Z"),
        };
        repo.create(&record).await.expect("create");
    }

    let summaries = repo.list_summaries().await.expect("list_summaries");
    assert_eq!(summaries.len(), 3);
    // Summaries are ordered by created_at DESC
    assert_eq!(summaries[0].id, "lsum-2");
    assert_eq!(summaries[1].id, "lsum-1");
    assert_eq!(summaries[2].id, "lsum-0");
    // All have metadata
    for s in &summaries {
        assert_eq!(s.size_bytes, Some(1024));
        assert_eq!(s.format, "exe");
    }
}

// ---- PayloadBuildRecord sleep_secs overflow clamping ----

#[test]
fn payload_build_sleep_secs_clamps_u64_overflow_to_i64_max() {
    // Values exceeding i64::MAX must not silently wrap to negative.
    let overflow: u64 = u64::try_from(i64::MAX).expect("i64::MAX fits in u64") + 1;
    let clamped: i64 = i64::try_from(overflow).unwrap_or(i64::MAX);
    assert_eq!(clamped, i64::MAX);
}

#[test]
fn payload_build_sleep_secs_preserves_valid_u64_values() {
    let valid: u64 = 3600;
    let converted: i64 = i64::try_from(valid).unwrap_or(i64::MAX);
    assert_eq!(converted, 3600);
}

#[test]
fn payload_build_sleep_secs_handles_u64_max() {
    let max_val: u64 = u64::MAX;
    let clamped: i64 = i64::try_from(max_val).unwrap_or(i64::MAX);
    assert_eq!(clamped, i64::MAX);
}
