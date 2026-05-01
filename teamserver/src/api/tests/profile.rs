use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use red_cell_common::config::OperatorRole;

use crate::api::auth::API_KEY_HEADER;

use super::helpers::{read_json, test_router};

#[tokio::test]
async fn get_profile_returns_redacted_profile() {
    let app = test_router(Some((60, "key", "secret", OperatorRole::Admin))).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/profile")
                .header(API_KEY_HEADER, "secret")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);

    let body = read_json(response).await;
    assert_eq!(body["host"], "127.0.0.1");
    assert_eq!(body["port"], 40056);
    assert_eq!(body["path"], "test.yaotl");

    let operators = body["operators"].as_array().expect("operators array");
    assert_eq!(operators.len(), 1);
    assert_eq!(operators[0]["name"], "Neo");
    assert_eq!(operators[0]["has_password"], true);
    assert!(operators[0].get("password").is_none(), "password must not be exposed in the response");

    let api_keys = body["api_keys"].as_array().expect("api_keys array");
    assert_eq!(api_keys.len(), 1);
    assert_eq!(api_keys[0]["name"], "key");
    assert!(api_keys[0].get("value").is_none(), "API key value must not be exposed");
}

#[tokio::test]
async fn get_profile_requires_auth() {
    let app = test_router(Some((60, "key", "secret", OperatorRole::Admin))).await;

    let response = app
        .oneshot(Request::builder().uri("/profile").body(Body::empty()).expect("request"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn get_profile_rejects_non_admin() {
    let app = test_router(Some((60, "key", "secret", OperatorRole::Operator))).await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/profile")
                .header(API_KEY_HEADER, "secret")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn get_profile_includes_listener_summaries() {
    use crate::api::api_routes;
    use crate::api::auth::ApiRuntime;
    use crate::app::TeamserverState;
    use crate::{
        AgentRegistry, AuthService, Database, EventBus, ListenerManager, OperatorConnectionManager,
        SocketRelayManager,
    };
    use red_cell_common::config::Profile;

    let profile = Profile::parse(
        r#"
        Teamserver {
          Host = "10.0.0.1"
          Port = 40056
        }

        Operators {
          user "admin" {
            Password = "pw"
            Role = "Admin"
          }
        }

        Api {
          RateLimitPerMinute = 60
          key "rest" {
            Value = "tok"
            Role = "Admin"
          }
        }

        Listeners {
          Http {
            Name     = "http1"
            Hosts    = ["10.0.0.1"]
            HostBind = "0.0.0.0"
            HostRotation = "round-robin"
            PortBind = 19100
            Secure   = false
          }
        }

        Demon {
          Sleep  = 5
          Jitter = 20
        }
        "#,
    )
    .expect("profile");

    let database = Database::connect_in_memory().await.expect("db");
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

    let app = api_routes(api.clone()).with_state(TeamserverState {
        profile: profile.clone(),
        profile_path: "profiles/test.yaotl".to_owned(),
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
        corpus_dir: None,
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/profile")
                .header(API_KEY_HEADER, "tok")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json(response).await;

    let http = body["listeners"]["http"].as_array().expect("http listeners");
    assert_eq!(http.len(), 1);
    assert_eq!(http[0]["name"], "http1");
    assert_eq!(http[0]["protocol"], "http");
    assert_eq!(http[0]["host_bind"], "0.0.0.0");
    assert_eq!(http[0]["port_bind"], 19100);

    assert_eq!(body["demon"]["sleep"], 5);
    assert_eq!(body["demon"]["jitter"], 20);
    assert_eq!(body["path"], "profiles/test.yaotl");
}
