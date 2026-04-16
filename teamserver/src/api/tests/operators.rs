use std::net::IpAddr;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

use crate::Database;
use crate::api::auth::API_KEY_HEADER;
use red_cell_common::config::OperatorRole;
use red_cell_common::crypto::hash_password_sha3;

use super::helpers::*;

#[tokio::test]
async fn operators_endpoint_is_admin_only_and_lists_configured_accounts_with_presence() {
    let (app, _, auth) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;
    auth.authenticate_login(
        Uuid::new_v4(),
        &red_cell_common::operator::LoginInfo {
            user: "Neo".to_owned(),
            password: hash_password_sha3("password1234"),
        },
    )
    .await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/operators")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    let operators = body.as_array().expect("array");
    assert_eq!(operators.len(), 1);
    assert_eq!(operators[0]["username"], "Neo");
    assert_eq!(operators[0]["role"], "Admin");
    assert_eq!(operators[0]["online"], true);
    assert_eq!(operators[0]["last_seen"], Value::Null);
}

#[tokio::test]
async fn create_operator_endpoint_creates_runtime_account_and_lists_it_offline() {
    let (app, _, auth) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/operators")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"trinity","password":"zion","role":"Operator"}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = read_json(response).await;
    assert_eq!(body["username"], "trinity");
    assert_eq!(body["role"], "Operator");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/operators")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(
        body,
        serde_json::json!([
            {
                "username": "Neo",
                "role": "Admin",
                "online": false,
                "last_seen": null
            },
            {
                "username": "trinity",
                "role": "Operator",
                "online": false,
                "last_seen": null
            }
        ])
    );

    let result = auth
        .authenticate_login(
            Uuid::new_v4(),
            &red_cell_common::operator::LoginInfo {
                user: "trinity".to_owned(),
                password: hash_password_sha3("zion"),
            },
        )
        .await;
    assert!(matches!(result, crate::auth::AuthenticationResult::Success(_)));
}

#[tokio::test]
async fn create_operator_duplicate_username_returns_conflict() {
    let (app, _, _auth) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;

    // First creation should succeed.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/operators")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"trinity","password":"zion","role":"Operator"}"#))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::CREATED);

    // Second creation with the same username should return 409 Conflict.
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/operators")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"username":"trinity","password":"different","role":"Operator"}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "operator_exists");
}

#[tokio::test]
async fn create_operator_empty_username_returns_bad_request() {
    let (app, _, _auth) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/operators")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"","password":"zion","role":"Operator"}"#))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "invalid_operator");
}

#[tokio::test]
async fn create_operator_empty_password_returns_bad_request() {
    let (app, _, _auth) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/operators")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"trinity","password":"","role":"Operator"}"#))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "invalid_operator");
}

#[tokio::test]
async fn operators_endpoint_includes_persisted_runtime_accounts_loaded_at_startup() {
    let database = Database::connect_in_memory().await.expect("database");
    database
        .operators()
        .create(&crate::PersistedOperator {
            username: "trinity".to_owned(),
            password_verifier: crate::auth::password_verifier_for_sha3(&hash_password_sha3("zion"))
                .expect("password verifier should be generated"),
            role: OperatorRole::Operator,
        })
        .await
        .expect("runtime operator should persist");
    let (app, _, _) = test_router_with_database(
        database,
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/operators")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(
        body,
        serde_json::json!([
            {
                "username": "Neo",
                "role": "Admin",
                "online": false,
                "last_seen": null
            },
            {
                "username": "trinity",
                "role": "Operator",
                "online": false,
                "last_seen": null
            }
        ])
    );
}

#[tokio::test]
async fn operators_endpoint_includes_last_seen_from_persisted_session_activity() {
    let database = Database::connect_in_memory().await.expect("database");
    database
        .audit_log()
        .create(&crate::AuditLogEntry {
            id: None,
            actor: "Neo".to_owned(),
            action: "operator.disconnect".to_owned(),
            target_kind: "operator".to_owned(),
            target_id: Some("Neo".to_owned()),
            details: None,
            occurred_at: "2026-03-11T00:00:00Z".to_owned(),
        })
        .await
        .expect("session activity should persist");

    let (app, _, _) = test_router_with_database(
        database,
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/operators")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body[0]["last_seen"], "2026-03-11T00:00:00Z");
}

// ---- operator management RBAC tests ----

#[tokio::test]
async fn analyst_key_cannot_create_operator() {
    let app =
        test_router(Some((60, "rest-analyst", "secret-analyst", OperatorRole::Analyst))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/operators")
                .header(API_KEY_HEADER, "secret-analyst")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"username":"cypher","password":"steak123","role":"Analyst"}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "forbidden");
}

#[tokio::test]
async fn analyst_key_cannot_list_operators() {
    let app =
        test_router(Some((60, "rest-analyst", "secret-analyst", OperatorRole::Analyst))).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/operators")
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

// ---- DELETE /operators/{username} tests ----

#[tokio::test]
async fn delete_operator_removes_runtime_created_account() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let create_resp =
        create_runtime_operator(&app, "secret-admin", "tempuser", "pass1234", "Operator").await;
    assert_eq!(create_resp.status(), StatusCode::CREATED);

    let delete_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/operators/tempuser")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(delete_resp.status(), StatusCode::NO_CONTENT);

    // Verify the operator is gone from the listing.
    let list_resp = app
        .oneshot(
            Request::builder()
                .uri("/operators")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    let body = read_json(list_resp).await;
    let usernames: Vec<&str> =
        body.as_array().expect("array").iter().filter_map(|op| op["username"].as_str()).collect();
    assert!(!usernames.contains(&"tempuser"), "deleted operator should not appear in listing");
}

#[tokio::test]
async fn delete_operator_returns_not_found_for_unknown_user() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/operators/nonexistent")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "operator_not_found");
}

#[tokio::test]
async fn delete_operator_returns_not_found_for_profile_configured_user() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    // "Neo" is defined in the test profile — cannot be deleted at runtime.
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/operators/Neo")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "operator_not_found");
}

#[tokio::test]
async fn delete_operator_creates_audit_record() {
    let database = Database::connect_in_memory().await.expect("database");
    let (app, _, _) = test_router_with_database(
        database.clone(),
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    create_runtime_operator(&app, "secret-admin", "audituser", "pass1234", "Analyst").await;

    let _delete_resp = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/operators/audituser")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    let page = crate::query_audit_log(
        &database,
        &crate::AuditQuery {
            action: Some("operator.delete".to_owned()),
            ..crate::AuditQuery::default()
        },
    )
    .await
    .expect("audit query should succeed");

    assert_eq!(page.total, 1, "one operator.delete audit record expected");
    let record = &page.items[0];
    assert_eq!(record.action, "operator.delete");
    assert_eq!(record.result_status, crate::AuditResultStatus::Success);
}

// ---- PUT /operators/{username}/role tests ----

#[tokio::test]
async fn update_operator_role_changes_runtime_account_role() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let create_resp =
        create_runtime_operator(&app, "secret-admin", "roleuser", "pass1234", "Operator").await;
    assert_eq!(create_resp.status(), StatusCode::CREATED);

    let update_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/operators/roleuser/role")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"role":"Admin"}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(update_resp.status(), StatusCode::OK);
    let body = read_json(update_resp).await;
    assert_eq!(body["username"], "roleuser");
    assert_eq!(body["role"], "Admin");
}

#[tokio::test]
async fn update_operator_role_returns_not_found_for_unknown_user() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/operators/nonexistent/role")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"role":"Admin"}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "operator_not_found");
}

#[tokio::test]
async fn update_operator_role_returns_not_found_for_profile_configured_user() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/operators/Neo/role")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"role":"Analyst"}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "operator_not_found");
}

#[tokio::test]
async fn update_operator_role_returns_bad_request_for_invalid_role() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    create_runtime_operator(&app, "secret-admin", "badroleuser", "pass1234", "Operator").await;

    let response = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/operators/badroleuser/role")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"role":"SuperAdmin"}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    // Invalid JSON deserialization returns 422 (Unprocessable Entity) from Axum.
    assert!(
        response.status() == StatusCode::BAD_REQUEST
            || response.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "expected 400 or 422 for invalid role, got {}",
        response.status()
    );
}

#[tokio::test]
async fn update_operator_role_creates_audit_record() {
    let database = Database::connect_in_memory().await.expect("database");
    let (app, _, _) = test_router_with_database(
        database.clone(),
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    create_runtime_operator(&app, "secret-admin", "auditrole", "pass1234", "Operator").await;

    let _update_resp = app
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/operators/auditrole/role")
                .header(API_KEY_HEADER, "secret-admin")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"role":"Admin"}"#))
                .expect("request"),
        )
        .await
        .expect("response");

    let page = crate::query_audit_log(
        &database,
        &crate::AuditQuery {
            action: Some("operator.update_role".to_owned()),
            ..crate::AuditQuery::default()
        },
    )
    .await
    .expect("audit query should succeed");

    assert_eq!(page.total, 1, "one operator.update_role audit record expected");
    let record = &page.items[0];
    assert_eq!(record.action, "operator.update_role");
    assert_eq!(record.result_status, crate::AuditResultStatus::Success);
}

// ── Active operators endpoint tests ─────────────────────────────────────────

#[tokio::test]
async fn active_operators_returns_empty_list_when_no_connections() {
    let app = test_router(Some((60, "key", "secret", OperatorRole::Operator))).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/operators/active")
                .header(API_KEY_HEADER, "secret")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    let entries = body.as_array().expect("array");
    assert!(entries.is_empty(), "no connected operators expected");
}

#[tokio::test]
async fn active_operators_returns_authenticated_connections() {
    let (app, _, _auth, connections) =
        test_router_with_connections(Some((60, "key", "secret", OperatorRole::Operator))).await;

    let conn_id = Uuid::new_v4();
    let ip: IpAddr = [10, 0, 0, 1].into();
    connections.register(conn_id, ip).await;
    connections.authenticate(conn_id, "Neo".to_owned()).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/operators/active")
                .header(API_KEY_HEADER, "secret")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    let entries = body.as_array().expect("array");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["username"], "Neo");
    assert_eq!(entries[0]["remote_addr"], "10.0.0.1");
    assert!(entries[0]["connect_time"].as_str().is_some(), "connect_time should be a string");
}

#[tokio::test]
async fn active_operators_excludes_unauthenticated_connections() {
    let (app, _, _auth, connections) =
        test_router_with_connections(Some((60, "key", "secret", OperatorRole::Operator))).await;

    // Register but do not authenticate
    let conn_id = Uuid::new_v4();
    let ip: IpAddr = [10, 0, 0, 2].into();
    connections.register(conn_id, ip).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/operators/active")
                .header(API_KEY_HEADER, "secret")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    let entries = body.as_array().expect("array");
    assert!(entries.is_empty(), "unauthenticated connections should not appear");
}

#[tokio::test]
async fn active_operators_requires_api_key() {
    let app = test_router(Some((60, "key", "secret", OperatorRole::Operator))).await;

    let response = app
        .oneshot(Request::builder().uri("/operators/active").body(Body::empty()).expect("request"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn health_endpoint_includes_active_operators_count() {
    let (app, _, _auth, connections) =
        test_router_with_connections(Some((60, "key", "secret", OperatorRole::Operator))).await;

    // Register and authenticate two operators
    for ip_last_octet in [1u8, 2] {
        let conn_id = Uuid::new_v4();
        let ip: IpAddr = [10, 0, 0, ip_last_octet].into();
        connections.register(conn_id, ip).await;
        connections.authenticate(conn_id, format!("op{ip_last_octet}")).await;
    }

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .header(API_KEY_HEADER, "secret")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["active_operators"], 2);
}

// ── POST /operators/{username}/logout tests ─────────────────────────────────

#[tokio::test]
async fn logout_operator_revokes_active_sessions() {
    let (app, _, auth) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;

    auth.authenticate_login(
        Uuid::new_v4(),
        &red_cell_common::operator::LoginInfo {
            user: "Neo".to_owned(),
            password: hash_password_sha3("password1234"),
        },
    )
    .await;
    auth.authenticate_login(
        Uuid::new_v4(),
        &red_cell_common::operator::LoginInfo {
            user: "Neo".to_owned(),
            password: hash_password_sha3("password1234"),
        },
    )
    .await;
    assert_eq!(auth.session_count().await, 2);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/operators/Neo/logout")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["username"], "Neo");
    assert_eq!(body["revoked_sessions"], 2);
    assert_eq!(auth.session_count().await, 0);
}

#[tokio::test]
async fn logout_operator_succeeds_with_zero_when_no_active_sessions() {
    let (app, _, auth) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;

    assert_eq!(auth.session_count().await, 0);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/operators/Neo/logout")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["username"], "Neo");
    assert_eq!(body["revoked_sessions"], 0);
}

#[tokio::test]
async fn logout_operator_returns_not_found_for_unknown_user() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/operators/ghost/logout")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "operator_not_found");
}

#[tokio::test]
async fn logout_operator_only_revokes_target_user_sessions() {
    let (app, _, auth) =
        test_router_with_registry(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)))
            .await;

    // Create a second runtime operator and authenticate sessions for both.
    create_runtime_operator(&app, "secret-admin", "trinity", "zion1234", "Operator").await;

    auth.authenticate_login(
        Uuid::new_v4(),
        &red_cell_common::operator::LoginInfo {
            user: "Neo".to_owned(),
            password: hash_password_sha3("password1234"),
        },
    )
    .await;
    auth.authenticate_login(
        Uuid::new_v4(),
        &red_cell_common::operator::LoginInfo {
            user: "trinity".to_owned(),
            password: hash_password_sha3("zion1234"),
        },
    )
    .await;
    assert_eq!(auth.session_count().await, 2);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/operators/Neo/logout")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["revoked_sessions"], 1);

    // trinity's session must remain intact.
    assert_eq!(auth.session_count().await, 1);
    let remaining = auth.active_sessions().await;
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].username, "trinity");
}

#[tokio::test]
async fn logout_operator_is_admin_only() {
    let (app, _, auth) = test_router_with_registry(Some((
        60,
        "rest-analyst",
        "secret-analyst",
        OperatorRole::Analyst,
    )))
    .await;

    auth.authenticate_login(
        Uuid::new_v4(),
        &red_cell_common::operator::LoginInfo {
            user: "Neo".to_owned(),
            password: hash_password_sha3("password1234"),
        },
    )
    .await;
    assert_eq!(auth.session_count().await, 1);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/operators/Neo/logout")
                .header(API_KEY_HEADER, "secret-analyst")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = read_json(response).await;
    assert_eq!(body["error"]["code"], "forbidden");

    // The session must NOT have been revoked because the request was rejected.
    assert_eq!(auth.session_count().await, 1);
}

#[tokio::test]
async fn logout_operator_requires_api_key() {
    let app = test_router(Some((60, "rest-admin", "secret-admin", OperatorRole::Admin))).await;

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/operators/Neo/logout")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_operator_creates_audit_record() {
    let database = Database::connect_in_memory().await.expect("database");
    let (app, _, auth) = test_router_with_database(
        database.clone(),
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    auth.authenticate_login(
        Uuid::new_v4(),
        &red_cell_common::operator::LoginInfo {
            user: "Neo".to_owned(),
            password: hash_password_sha3("password1234"),
        },
    )
    .await;

    let _resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/operators/Neo/logout")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    let page = crate::query_audit_log(
        &database,
        &crate::AuditQuery {
            action: Some("operator.logout".to_owned()),
            ..crate::AuditQuery::default()
        },
    )
    .await
    .expect("audit query should succeed");

    assert_eq!(page.total, 1, "one operator.logout audit record expected");
    let record = &page.items[0];
    assert_eq!(record.action, "operator.logout");
    assert_eq!(record.target_kind, "operator");
    assert_eq!(record.target_id.as_deref(), Some("Neo"));
    assert_eq!(record.result_status, crate::AuditResultStatus::Success);
    let parameters = record.parameters.as_ref().expect("audit parameters");
    assert_eq!(parameters["revoked_sessions"], 1);
}

#[tokio::test]
async fn logout_operator_audit_records_failure_for_unknown_user() {
    let database = Database::connect_in_memory().await.expect("database");
    let (app, _, _auth) = test_router_with_database(
        database.clone(),
        Some((60, "rest-admin", "secret-admin", OperatorRole::Admin)),
    )
    .await;

    let _resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/operators/ghost/logout")
                .header(API_KEY_HEADER, "secret-admin")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    let page = crate::query_audit_log(
        &database,
        &crate::AuditQuery {
            action: Some("operator.logout".to_owned()),
            ..crate::AuditQuery::default()
        },
    )
    .await
    .expect("audit query should succeed");

    assert_eq!(page.total, 1, "failure audit record expected");
    let record = &page.items[0];
    assert_eq!(record.result_status, crate::AuditResultStatus::Failure);
    assert_eq!(record.target_id.as_deref(), Some("ghost"));
}
