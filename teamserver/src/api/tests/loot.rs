use axum::body::{Body, to_bytes};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

use red_cell_common::config::OperatorRole;

use crate::api::api_routes;
use crate::api::auth::{API_KEY_HEADER, ApiRuntime};
use crate::api::loot::{CredentialQuery, LootQuery};
use crate::app::TeamserverState;
use crate::{
    AgentRegistry, AuthService, Database, EventBus, ListenerManager, LootRecord,
    OperatorConnectionManager, SocketRelayManager, parameter_object,
};

use super::helpers::*;

#[tokio::test]
async fn loot_endpoint_lists_filtered_records() {
    let database = Database::connect_in_memory().await.expect("database");
    database.agents().create(&sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
    database
        .loot()
        .create(&LootRecord {
            id: None,
            agent_id: 0xDEAD_BEEF,
            kind: "credential".to_owned(),
            name: "credential-1".to_owned(),
            file_path: None,
            size_bytes: Some(12),
            captured_at: "2026-03-10T10:00:00Z".to_owned(),
            data: Some(b"Password: test".to_vec()),
            metadata: Some(parameter_object([
                ("operator", Value::String("neo".to_owned())),
                ("command_line", Value::String("sekurlsa::logonpasswords".to_owned())),
            ])),
        })
        .await
        .expect("loot should insert");

    let (router, _, _) = test_router_with_database(
        database,
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    let response = router
        .oneshot(
            Request::builder()
                .uri("/loot?kind=credential&operator=neo")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["items"][0]["kind"], "credential");
    assert_eq!(body["items"][0]["operator"], "neo");
}

#[tokio::test]
async fn credentials_endpoint_lists_filtered_records() {
    let database = Database::connect_in_memory().await.expect("database");
    database.agents().create(&sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
    let credential_id = database
        .loot()
        .create(&LootRecord {
            id: None,
            agent_id: 0xDEAD_BEEF,
            kind: "credential".to_owned(),
            name: "credential-1".to_owned(),
            file_path: None,
            size_bytes: Some(12),
            captured_at: "2026-03-10T10:00:00Z".to_owned(),
            data: Some(b"Password: test".to_vec()),
            metadata: Some(parameter_object([
                ("operator", Value::String("neo".to_owned())),
                ("command_line", Value::String("sekurlsa::logonpasswords".to_owned())),
                ("pattern", Value::String("password".to_owned())),
            ])),
        })
        .await
        .expect("loot should insert");

    let (router, _, _) = test_router_with_database(
        database,
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/credentials?operator=neo&pattern=pass")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["items"][0]["id"], credential_id);
    assert_eq!(body["items"][0]["content"], "Password: test");
    assert_eq!(body["items"][0]["pattern"], "password");
}

#[tokio::test]
async fn get_credential_returns_specific_record_and_not_found_error() {
    let database = Database::connect_in_memory().await.expect("database");
    database.agents().create(&sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
    let credential_id = database
        .loot()
        .create(&LootRecord {
            id: None,
            agent_id: 0xDEAD_BEEF,
            kind: "credential".to_owned(),
            name: "credential-1".to_owned(),
            file_path: None,
            size_bytes: Some(12),
            captured_at: "2026-03-10T10:00:00Z".to_owned(),
            data: Some(b"Password: test".to_vec()),
            metadata: Some(parameter_object([
                ("operator", Value::String("neo".to_owned())),
                ("command_line", Value::String("sekurlsa::logonpasswords".to_owned())),
                ("pattern", Value::String("password".to_owned())),
            ])),
        })
        .await
        .expect("loot should insert");

    let (router, _, _) = test_router_with_database(
        database,
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/credentials/{credential_id}"))
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["id"], credential_id);
    assert_eq!(body["name"], "credential-1");
    assert_eq!(body["content"], "Password: test");
    assert_eq!(body["operator"], "neo");
    assert_eq!(body["pattern"], "password");

    let response = router
        .oneshot(
            Request::builder()
                .uri("/credentials/999999")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "credential_not_found");
}

#[tokio::test]
async fn get_loot_returns_stored_bytes_and_not_found_error() {
    let profile = test_profile(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)));
    let database = Database::connect_in_memory().await.expect("database");
    database.agents().create(&sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
    let loot_id = database
        .loot()
        .create(&LootRecord {
            id: None,
            agent_id: 0xDEAD_BEEF,
            kind: "download".to_owned(),
            name: "secret.bin".to_owned(),
            file_path: Some("C:/temp/secret.bin".to_owned()),
            size_bytes: Some(4),
            captured_at: "2026-03-10T10:00:00Z".to_owned(),
            data: Some(vec![1, 2, 3, 4]),
            metadata: None,
        })
        .await
        .expect("loot should insert");
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
    let app = api_routes(api.clone()).with_state(TeamserverState {
        profile: profile.clone(),
        profile_path: "test.yaotl".to_owned(),
        database,
        auth: AuthService::from_profile(&profile).expect("auth service should initialize"),
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
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/loot/{loot_id}"))
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(CONTENT_TYPE).and_then(|value| value.to_str().ok()),
        Some("application/octet-stream"),
    );
    assert_eq!(
        response.headers().get(CONTENT_DISPOSITION).and_then(|value| value.to_str().ok()),
        Some("attachment; filename=\"secret.bin\""),
    );
    let bytes = to_bytes(response.into_body(), usize::MAX).await.expect("bytes");
    assert_eq!(bytes.as_ref(), [1, 2, 3, 4]);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/loot/999999")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "loot_not_found");
}

// ── Credential endpoint integration tests ─────────────────────────

#[tokio::test]
async fn credentials_pagination_returns_correct_slices() {
    let database = Database::connect_in_memory().await.expect("database");
    database.agents().create(&sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
    for i in 0..5 {
        database
            .loot()
            .create(&LootRecord {
                id: None,
                agent_id: 0xDEAD_BEEF,
                kind: "credential".to_owned(),
                name: format!("cred-{i}"),
                file_path: None,
                size_bytes: Some(8),
                captured_at: format!("2026-03-10T10:0{i}:00Z"),
                data: Some(format!("secret-{i}").into_bytes()),
                metadata: Some(parameter_object([("operator", Value::String("neo".to_owned()))])),
            })
            .await
            .expect("loot should insert");
    }

    let (router, _, _) = test_router_with_database(
        database,
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    // First page: offset=0, limit=2
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/credentials?limit=2&offset=0")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 5);
    assert_eq!(body["limit"], 2);
    assert_eq!(body["offset"], 0);
    assert_eq!(body["items"].as_array().expect("items array").len(), 2);

    // Second page: offset=2, limit=2
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/credentials?limit=2&offset=2")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 5);
    assert_eq!(body["limit"], 2);
    assert_eq!(body["offset"], 2);
    assert_eq!(body["items"].as_array().expect("items array").len(), 2);

    // Last page: offset=4, limit=2 — only 1 item left
    let response = router
        .oneshot(
            Request::builder()
                .uri("/credentials?limit=2&offset=4")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 5);
    assert_eq!(body["items"].as_array().expect("items array").len(), 1);
}

#[tokio::test]
async fn get_credential_with_invalid_id_returns_bad_request() {
    let (router, _, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;

    let response = router
        .oneshot(
            Request::builder()
                .uri("/credentials/not-a-number")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "invalid_credential_id");
}

#[tokio::test]
async fn get_credential_returns_not_found_for_non_credential_loot() {
    let database = Database::connect_in_memory().await.expect("database");
    database.agents().create(&sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
    let download_id = database
        .loot()
        .create(&LootRecord {
            id: None,
            agent_id: 0xDEAD_BEEF,
            kind: "download".to_owned(),
            name: "payload.bin".to_owned(),
            file_path: Some("C:/temp/payload.bin".to_owned()),
            size_bytes: Some(4),
            captured_at: "2026-03-10T10:00:00Z".to_owned(),
            data: Some(vec![0xDE, 0xAD]),
            metadata: None,
        })
        .await
        .expect("loot should insert");

    let (router, _, _) = test_router_with_database(
        database,
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!("/credentials/{download_id}"))
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "credential_not_found");
}

#[tokio::test]
async fn credentials_default_pagination_applies_when_no_params() {
    let database = Database::connect_in_memory().await.expect("database");
    database.agents().create(&sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
    database
        .loot()
        .create(&LootRecord {
            id: None,
            agent_id: 0xDEAD_BEEF,
            kind: "credential".to_owned(),
            name: "cred-only".to_owned(),
            file_path: None,
            size_bytes: Some(4),
            captured_at: "2026-03-10T10:00:00Z".to_owned(),
            data: Some(b"pass".to_vec()),
            metadata: None,
        })
        .await
        .expect("loot should insert");

    let (router, _, _) = test_router_with_database(
        database,
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    let response = router
        .oneshot(
            Request::builder()
                .uri("/credentials")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["limit"], CredentialQuery::DEFAULT_LIMIT);
    assert_eq!(body["offset"], 0);
    assert_eq!(body["items"].as_array().expect("items array").len(), 1);
}

// ── Loot endpoint integration tests ───────────────────────────────

#[tokio::test]
async fn loot_pagination_returns_correct_slices() {
    let database = Database::connect_in_memory().await.expect("database");
    database.agents().create(&sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
    for i in 0..5 {
        database
            .loot()
            .create(&LootRecord {
                id: None,
                agent_id: 0xDEAD_BEEF,
                kind: "download".to_owned(),
                name: format!("file-{i}.bin"),
                file_path: Some(format!("C:/temp/file-{i}.bin")),
                size_bytes: Some(4),
                captured_at: format!("2026-03-10T10:0{i}:00Z"),
                data: Some(vec![i as u8; 4]),
                metadata: None,
            })
            .await
            .expect("loot should insert");
    }

    let (router, _, _) = test_router_with_database(
        database,
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    // First page: offset=0, limit=3
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/loot?limit=3&offset=0")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 5);
    assert_eq!(body["limit"], 3);
    assert_eq!(body["offset"], 0);
    assert_eq!(body["items"].as_array().expect("items array").len(), 3);

    // Second page: offset=3, limit=3 — only 2 items left
    let response = router
        .oneshot(
            Request::builder()
                .uri("/loot?limit=3&offset=3")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 5);
    assert_eq!(body["limit"], 3);
    assert_eq!(body["offset"], 3);
    assert_eq!(body["items"].as_array().expect("items array").len(), 2);
}

#[tokio::test]
async fn get_loot_with_invalid_id_returns_bad_request() {
    let (router, _, _) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;

    let response = router
        .oneshot(
            Request::builder()
                .uri("/loot/not-a-number")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "invalid_loot_id");
}

#[tokio::test]
async fn get_loot_returns_conflict_when_data_is_missing() {
    let database = Database::connect_in_memory().await.expect("database");
    database.agents().create(&sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
    let loot_id = database
        .loot()
        .create(&LootRecord {
            id: None,
            agent_id: 0xDEAD_BEEF,
            kind: "screenshot".to_owned(),
            name: "screen.png".to_owned(),
            file_path: None,
            size_bytes: None,
            captured_at: "2026-03-10T10:00:00Z".to_owned(),
            data: None,
            metadata: None,
        })
        .await
        .expect("loot should insert");

    let (router, _, _) = test_router_with_database(
        database,
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    let response = router
        .oneshot(
            Request::builder()
                .uri(format!("/loot/{loot_id}"))
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "loot_missing_data");
}

#[tokio::test]
async fn loot_default_pagination_applies_when_no_params() {
    let database = Database::connect_in_memory().await.expect("database");
    database.agents().create(&sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
    database
        .loot()
        .create(&LootRecord {
            id: None,
            agent_id: 0xDEAD_BEEF,
            kind: "download".to_owned(),
            name: "single.bin".to_owned(),
            file_path: None,
            size_bytes: Some(1),
            captured_at: "2026-03-10T10:00:00Z".to_owned(),
            data: Some(vec![0x42]),
            metadata: None,
        })
        .await
        .expect("loot should insert");

    let (router, _, _) = test_router_with_database(
        database,
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    let response = router
        .oneshot(
            Request::builder()
                .uri("/loot")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["limit"], LootQuery::DEFAULT_LIMIT);
    assert_eq!(body["offset"], 0);
    assert_eq!(body["items"].as_array().expect("items array").len(), 1);
    assert!(body["items"][0]["has_data"].as_bool().expect("has_data should be bool"));
}

#[tokio::test]
async fn credentials_endpoint_excludes_non_credential_loot() {
    let database = Database::connect_in_memory().await.expect("database");
    database.agents().create(&sample_agent(0xDEAD_BEEF)).await.expect("agent should insert");
    // Insert a credential
    database
        .loot()
        .create(&LootRecord {
            id: None,
            agent_id: 0xDEAD_BEEF,
            kind: "credential".to_owned(),
            name: "cred-1".to_owned(),
            file_path: None,
            size_bytes: Some(4),
            captured_at: "2026-03-10T10:00:00Z".to_owned(),
            data: Some(b"pass".to_vec()),
            metadata: None,
        })
        .await
        .expect("credential should insert");
    // Insert a non-credential loot
    database
        .loot()
        .create(&LootRecord {
            id: None,
            agent_id: 0xDEAD_BEEF,
            kind: "download".to_owned(),
            name: "payload.bin".to_owned(),
            file_path: Some("C:/temp/payload.bin".to_owned()),
            size_bytes: Some(4),
            captured_at: "2026-03-10T10:01:00Z".to_owned(),
            data: Some(vec![0xDE, 0xAD]),
            metadata: None,
        })
        .await
        .expect("download should insert");

    let (router, _, _) = test_router_with_database(
        database,
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    let response = router
        .oneshot(
            Request::builder()
                .uri("/credentials")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"], 1, "only credential items should be counted");
    assert_eq!(body["items"].as_array().expect("items array").len(), 1);
    assert_eq!(body["items"][0]["name"], "cred-1");
}
