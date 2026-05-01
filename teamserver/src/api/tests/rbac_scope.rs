//! Integration tests for per-operator ACL enforcement on agent-read, listener,
//! and payload REST endpoints.
//!
//! These tests seed the per-listener operator allow-list and the per-operator
//! agent-group allow-list, then verify that an API key whose `key_id` is not
//! in the allow-list cannot read, list, mutate, or build payloads for the
//! resources outside its scope.

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use red_cell_common::config::Profile;
use tower::ServiceExt;

use crate::agents::Job;
use crate::api::api_routes;
use crate::api::auth::{API_KEY_HEADER, ApiRuntime};
use crate::app::TeamserverState;
use crate::database::LootRecord;
use crate::{
    AgentRegistry, AuthService, Database, EventBus, ListenerManager, OperatorConnectionManager,
    PayloadBuildRecord, SocketRelayManager,
};

use super::helpers::{http_listener_json, read_json, sample_agent};

/// Build a profile with two API keys (`"alice"` and `"bob"`, both Admin) so the
/// tests can impersonate two distinct operators sharing the same role.
fn two_key_profile() -> Profile {
    Profile::parse(
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

          key "alice" {
            Value = "alice-key"
            Role  = "Admin"
          }

          key "bob" {
            Value = "bob-key"
            Role  = "Admin"
          }
        }

        Demon {}
        "#,
    )
    .expect("two-key profile")
}

/// Build the API router plus a handle to the underlying database and agent
/// registry so the test can seed ACL rows before issuing requests.
async fn two_operator_router() -> (Router, Database, AgentRegistry) {
    let database = Database::connect_in_memory().await.expect("database");
    let profile = two_key_profile();
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

    let api = ApiRuntime::from_profile(&profile).expect("api");
    let auth = AuthService::from_profile_with_database(&profile, &database).await.expect("auth");

    let state = TeamserverState {
        profile: profile.clone(),
        profile_path: "test.yaotl".to_owned(),
        database: database.clone(),
        auth,
        api: api.clone(),
        events,
        connections: OperatorConnectionManager::new(),
        agent_registry: agent_registry.clone(),
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
        corpus_dir: None,
    };

    let router = api_routes(api).with_state(state);
    (router, database, agent_registry)
}

fn get(router: &Router, uri: &str, api_key: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header(API_KEY_HEADER, api_key)
        .body(Body::empty())
        .expect("request");
    // Rebuild so the `Router` reference above is only used for side effects; we
    // actually return a fresh builder to the caller.  (Keeps the helper happy
    // without forcing `Router` ownership transfer at every call site.)
    let _ = router;
    Request::builder()
        .method("GET")
        .uri(uri)
        .header(API_KEY_HEADER, api_key)
        .body(Body::empty())
        .expect("request")
}

// ── list_listeners ────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_listeners_filters_out_listeners_operator_cannot_use() {
    let (app, database, _) = two_operator_router().await;

    // Create two listeners. `public-http` is unrestricted (no allow-list), so
    // both alice and bob may see it.  `alice-only` has an allow-list containing
    // only alice.
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/listeners")
                .header(API_KEY_HEADER, "alice-key")
                .header("content-type", "application/json")
                .body(Body::from(http_listener_json("public-http", 40100)))
                .expect("create public"),
        )
        .await
        .expect("response");
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/listeners")
                .header(API_KEY_HEADER, "alice-key")
                .header("content-type", "application/json")
                .body(Body::from(http_listener_json("alice-only", 40101)))
                .expect("create alice-only"),
        )
        .await
        .expect("response");

    database
        .listener_access()
        .set_allowed_operators("alice-only", &["alice".to_owned()])
        .await
        .expect("seed listener access");

    // bob sees only the unrestricted listener.
    let response = app.clone().oneshot(get(&app, "/listeners", "bob-key")).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    let names: Vec<&str> =
        body.as_array().expect("array").iter().map(|v| v["name"].as_str().unwrap_or("")).collect();
    assert!(names.contains(&"public-http"));
    assert!(!names.contains(&"alice-only"));

    // alice sees both.
    let response =
        app.clone().oneshot(get(&app, "/listeners", "alice-key")).await.expect("response");
    let body = read_json(response).await;
    let names: Vec<&str> =
        body.as_array().expect("array").iter().map(|v| v["name"].as_str().unwrap_or("")).collect();
    assert!(names.contains(&"public-http"));
    assert!(names.contains(&"alice-only"));
}

// ── get_listener / update / delete / start / stop / mark / reload_tls ─────────

#[tokio::test]
async fn listener_admin_endpoints_deny_operators_outside_allow_list() {
    let (app, database, _) = two_operator_router().await;

    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/listeners")
                .header(API_KEY_HEADER, "alice-key")
                .header("content-type", "application/json")
                .body(Body::from(http_listener_json("alice-only", 40110)))
                .expect("create"),
        )
        .await
        .expect("response");

    database
        .listener_access()
        .set_allowed_operators("alice-only", &["alice".to_owned()])
        .await
        .expect("seed listener access");

    // bob must be blocked on every listener management verb.

    // GET
    let response =
        app.clone().oneshot(get(&app, "/listeners/alice-only", "bob-key")).await.expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // PUT (update)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/alice-only")
                .header(API_KEY_HEADER, "bob-key")
                .header("content-type", "application/json")
                .body(Body::from(http_listener_json("alice-only", 40110)))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // DELETE
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/listeners/alice-only")
                .header(API_KEY_HEADER, "bob-key")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // PUT /start
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/alice-only/start")
                .header(API_KEY_HEADER, "bob-key")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // PUT /stop
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/listeners/alice-only/stop")
                .header(API_KEY_HEADER, "bob-key")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // POST /mark
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/listeners/alice-only/mark")
                .header(API_KEY_HEADER, "bob-key")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"mark":"start"}"#))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // POST /tls-cert
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/listeners/alice-only/tls-cert")
                .header(API_KEY_HEADER, "bob-key")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"cert_pem":"x","key_pem":"y"}"#))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // alice may still read her own listener.
    let response = app
        .clone()
        .oneshot(get(&app, "/listeners/alice-only", "alice-key"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);
}

// ── list_agents / get_agent / get_agent_output / get_agent_groups ─────────────

#[tokio::test]
async fn agent_read_endpoints_filter_by_operator_group_allow_list() {
    let (app, database, registry) = two_operator_router().await;

    registry.insert(sample_agent(0x0000_0AAA)).await.expect("insert aaa");
    registry.insert(sample_agent(0x0000_0BBB)).await.expect("insert bbb");

    database
        .agent_groups()
        .set_agent_groups(0x0000_0AAA, &["alice-group".to_owned()])
        .await
        .expect("group alice");
    database
        .agent_groups()
        .set_agent_groups(0x0000_0BBB, &["bob-group".to_owned()])
        .await
        .expect("group bob");

    database
        .agent_groups()
        .set_operator_allowed_groups("alice", &["alice-group".to_owned()])
        .await
        .expect("alice scope");
    database
        .agent_groups()
        .set_operator_allowed_groups("bob", &["bob-group".to_owned()])
        .await
        .expect("bob scope");

    // list_agents → alice sees only her agent.
    let response = app.clone().oneshot(get(&app, "/agents", "alice-key")).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    let ids: Vec<u64> = body
        .as_array()
        .expect("array")
        .iter()
        .map(|v| v["AgentID"].as_u64().unwrap_or(0))
        .collect();
    assert_eq!(ids, vec![0x0AAA]);

    // get_agent on alice's agent works; on bob's agent it is denied.
    let ok =
        app.clone().oneshot(get(&app, "/agents/00000AAA", "alice-key")).await.expect("response");
    assert_eq!(ok.status(), StatusCode::OK);
    let denied =
        app.clone().oneshot(get(&app, "/agents/00000BBB", "alice-key")).await.expect("response");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    // get_agent_output is denied for agents outside the scope.
    let denied = app
        .clone()
        .oneshot(get(&app, "/agents/00000BBB/output", "alice-key"))
        .await
        .expect("response");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    // get_agent_groups is denied for agents outside the scope.
    let denied = app
        .clone()
        .oneshot(get(&app, "/agents/00000BBB/groups", "alice-key"))
        .await
        .expect("response");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
}

// ── list_payloads / submit_build / get_job / download ─────────────────────────

async fn seed_payload_build(
    database: &Database,
    id: &str,
    listener: &str,
    artifact: Option<Vec<u8>>,
) {
    let status = if artifact.is_some() { "done" } else { "pending" };
    let record = PayloadBuildRecord {
        id: id.to_owned(),
        status: status.to_owned(),
        name: format!("{id}.exe"),
        arch: "x64".to_owned(),
        format: "exe".to_owned(),
        listener: listener.to_owned(),
        agent_type: "Demon".to_owned(),
        sleep_secs: None,
        size_bytes: artifact.as_ref().map(|b| b.len() as i64),
        artifact,
        error: None,
        export_name: None,
        created_at: "2026-04-17T12:00:00Z".to_owned(),
        updated_at: "2026-04-17T12:00:00Z".to_owned(),
    };
    database.payload_builds().create(&record).await.expect("seed payload");
}

#[tokio::test]
async fn payload_endpoints_enforce_listener_allow_list() {
    let (app, database, _) = two_operator_router().await;

    // Create a listener restricted to alice and seed a completed build against it.
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/listeners")
                .header(API_KEY_HEADER, "alice-key")
                .header("content-type", "application/json")
                .body(Body::from(http_listener_json("alice-only", 40120)))
                .expect("create"),
        )
        .await
        .expect("response");
    database
        .listener_access()
        .set_allowed_operators("alice-only", &["alice".to_owned()])
        .await
        .expect("seed listener access");

    seed_payload_build(&database, "job-1", "alice-only", Some(vec![0xAA, 0xBB, 0xCC])).await;

    // list_payloads: bob must not see alice-only builds.
    let response = app.clone().oneshot(get(&app, "/payloads", "bob-key")).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    let ids: Vec<&str> =
        body.as_array().expect("array").iter().map(|v| v["id"].as_str().unwrap_or("")).collect();
    assert!(!ids.contains(&"job-1"), "bob saw restricted build: {ids:?}");

    // alice does see it.
    let response =
        app.clone().oneshot(get(&app, "/payloads", "alice-key")).await.expect("response");
    let body = read_json(response).await;
    let ids: Vec<&str> =
        body.as_array().expect("array").iter().map(|v| v["id"].as_str().unwrap_or("")).collect();
    assert!(ids.contains(&"job-1"));

    // get_payload_job: bob is denied.
    let response =
        app.clone().oneshot(get(&app, "/payloads/jobs/job-1", "bob-key")).await.expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // download_payload: bob is denied.
    let response = app
        .clone()
        .oneshot(get(&app, "/payloads/job-1/download", "bob-key"))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // submit_payload_build: bob cannot submit for a listener outside his scope.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/payloads/build")
                .header(API_KEY_HEADER, "bob-key")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"listener":"alice-only","arch":"x64","format":"exe","agent":"demon"}"#,
                ))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// ── list_loot / get_loot / list_credentials / get_credential ─────────────────

async fn seed_loot(database: &Database, agent_id: u32, kind: &str, name: &str) -> i64 {
    let record = LootRecord {
        id: None,
        agent_id,
        kind: kind.to_owned(),
        name: name.to_owned(),
        file_path: None,
        size_bytes: Some(3),
        captured_at: "2026-04-17T12:00:00Z".to_owned(),
        data: Some(b"abc".to_vec()),
        metadata: None,
    };
    database.loot().create(&record).await.expect("seed loot")
}

#[tokio::test]
async fn loot_endpoints_filter_by_operator_agent_group_allow_list() {
    let (app, database, registry) = two_operator_router().await;

    registry.insert(sample_agent(0x0000_0AAA)).await.expect("insert aaa");
    registry.insert(sample_agent(0x0000_0BBB)).await.expect("insert bbb");

    database
        .agent_groups()
        .set_agent_groups(0x0000_0AAA, &["alice-group".to_owned()])
        .await
        .expect("group alice");
    database
        .agent_groups()
        .set_agent_groups(0x0000_0BBB, &["bob-group".to_owned()])
        .await
        .expect("group bob");
    database
        .agent_groups()
        .set_operator_allowed_groups("alice", &["alice-group".to_owned()])
        .await
        .expect("alice scope");
    database
        .agent_groups()
        .set_operator_allowed_groups("bob", &["bob-group".to_owned()])
        .await
        .expect("bob scope");

    let alice_loot_id = seed_loot(&database, 0x0000_0AAA, "screenshot", "alice.png").await;
    let bob_loot_id = seed_loot(&database, 0x0000_0BBB, "screenshot", "bob.png").await;
    let alice_cred_id = seed_loot(&database, 0x0000_0AAA, "credential", "alice-cred").await;
    let bob_cred_id = seed_loot(&database, 0x0000_0BBB, "credential", "bob-cred").await;

    // list_loot: alice sees only her agent's loot (both screenshot + credential
    // kinds); bob sees neither alice item.
    let response = app.clone().oneshot(get(&app, "/loot", "alice-key")).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    let names: Vec<&str> = body["items"]
        .as_array()
        .expect("items array")
        .iter()
        .map(|v| v["name"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(body["total"].as_u64(), Some(2));
    assert!(names.contains(&"alice.png"));
    assert!(names.contains(&"alice-cred"));
    assert!(!names.contains(&"bob.png"));
    assert!(!names.contains(&"bob-cred"));

    // get_loot: bob is denied for alice's loot, allowed for his own.
    let denied = app
        .clone()
        .oneshot(get(&app, &format!("/loot/{alice_loot_id}"), "bob-key"))
        .await
        .expect("response");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let ok = app
        .clone()
        .oneshot(get(&app, &format!("/loot/{bob_loot_id}"), "bob-key"))
        .await
        .expect("response");
    assert_eq!(ok.status(), StatusCode::OK);

    // list_credentials: same filtering applies.
    let response =
        app.clone().oneshot(get(&app, "/credentials", "alice-key")).await.expect("response");
    let body = read_json(response).await;
    assert_eq!(body["total"].as_u64(), Some(1));
    let names: Vec<&str> = body["items"]
        .as_array()
        .expect("items array")
        .iter()
        .map(|v| v["name"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(names, vec!["alice-cred"]);

    // get_credential: bob is denied for alice's credential, allowed for his own.
    let denied = app
        .clone()
        .oneshot(get(&app, &format!("/credentials/{alice_cred_id}"), "bob-key"))
        .await
        .expect("response");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let ok = app
        .clone()
        .oneshot(get(&app, &format!("/credentials/{bob_cred_id}"), "bob-key"))
        .await
        .expect("response");
    assert_eq!(ok.status(), StatusCode::OK);
}

// ── list_jobs / get_job ───────────────────────────────────────────────────────

#[tokio::test]
async fn job_endpoints_filter_by_operator_agent_group_allow_list() {
    let (app, database, registry) = two_operator_router().await;

    registry.insert(sample_agent(0x0000_0AAA)).await.expect("insert aaa");
    registry.insert(sample_agent(0x0000_0BBB)).await.expect("insert bbb");

    database
        .agent_groups()
        .set_agent_groups(0x0000_0AAA, &["alice-group".to_owned()])
        .await
        .expect("group alice");
    database
        .agent_groups()
        .set_agent_groups(0x0000_0BBB, &["bob-group".to_owned()])
        .await
        .expect("group bob");
    database
        .agent_groups()
        .set_operator_allowed_groups("alice", &["alice-group".to_owned()])
        .await
        .expect("alice scope");
    database
        .agent_groups()
        .set_operator_allowed_groups("bob", &["bob-group".to_owned()])
        .await
        .expect("bob scope");

    registry
        .enqueue_job(
            0x0000_0AAA,
            Job {
                command: 1,
                request_id: 0x11,
                payload: vec![0; 4],
                command_line: "alice-job".to_owned(),
                task_id: "task-alice".to_owned(),
                created_at: "2026-04-17T12:00:00Z".to_owned(),
                operator: "alice".to_owned(),
            },
        )
        .await
        .expect("enqueue alice");
    registry
        .enqueue_job(
            0x0000_0BBB,
            Job {
                command: 1,
                request_id: 0x22,
                payload: vec![0; 4],
                command_line: "bob-job".to_owned(),
                task_id: "task-bob".to_owned(),
                created_at: "2026-04-17T12:00:00Z".to_owned(),
                operator: "bob".to_owned(),
            },
        )
        .await
        .expect("enqueue bob");

    // list_jobs: alice sees only her agent's job; total reflects visible count.
    let response = app.clone().oneshot(get(&app, "/jobs", "alice-key")).await.expect("response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;
    assert_eq!(body["total"].as_u64(), Some(1));
    let agent_ids: Vec<&str> = body["items"]
        .as_array()
        .expect("items array")
        .iter()
        .map(|v| v["agent_id"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(agent_ids, vec!["00000AAA"]);

    // get_job: bob is denied for alice's job, allowed for his own.
    let denied =
        app.clone().oneshot(get(&app, "/jobs/00000AAA/11", "bob-key")).await.expect("response");
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let ok =
        app.clone().oneshot(get(&app, "/jobs/00000BBB/22", "bob-key")).await.expect("response");
    assert_eq!(ok.status(), StatusCode::OK);
}
