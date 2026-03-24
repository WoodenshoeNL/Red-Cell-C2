//! Integration test for REST API key authentication flow.
//!
//! Configures API keys in a profile, starts an Axum server with the full API
//! router, and verifies authenticated/unauthenticated request handling plus
//! RBAC enforcement on the authenticated identity.

mod common;

use red_cell::{
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, OperatorConnectionManager, PayloadBuilderService, SocketRelayManager,
    TeamserverState,
};
use red_cell_common::config::Profile;
use reqwest::{Client, StatusCode};
use tokio::net::TcpListener;

/// Build a profile with an Admin key and an Analyst key.
fn profile_with_api_keys() -> Profile {
    Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 0
        }

        Operators {
          user "operator" {
            Password = "password1234"
            Role = "Operator"
          }
        }

        Api {
          RateLimitPerMinute = 120

          key "admin-key" {
            Value = "secret-admin-value"
            Role  = "Admin"
          }

          key "analyst-key" {
            Value = "secret-analyst-value"
            Role  = "Analyst"
          }
        }

        Demon {}
        "#,
    )
    .expect("test profile should parse")
}

/// Spawn a teamserver with the full router (including `/api/v1`) on a random
/// port and return the base URL.
async fn spawn_api_server(profile: Profile) -> String {
    let database = Database::connect_in_memory().await.expect("database");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let listeners = ListenerManager::new(
        database.clone(),
        registry.clone(),
        events.clone(),
        sockets.clone(),
        None,
    );
    let webhooks = AuditWebhookNotifier::from_profile(&profile);

    let state = TeamserverState {
        profile: profile.clone(),
        database: database.clone(),
        auth: AuthService::from_profile(&profile).expect("auth"),
        api: ApiRuntime::from_profile(&profile).expect("api"),
        events,
        connections: OperatorConnectionManager::new(),
        agent_registry: registry,
        listeners,
        payload_builder: PayloadBuilderService::disabled_for_tests(),
        sockets,
        webhooks,
        login_rate_limiter: red_cell::LoginRateLimiter::new(),
        shutdown: red_cell::ShutdownController::new(),
        service_bridge: None,
    };

    let tcp = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = tcp.local_addr().expect("local_addr");

    tokio::spawn(async move {
        let app = red_cell::build_router(state);
        let _ = axum::serve(tcp, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await;
    });

    format!("http://127.0.0.1:{}", addr.port())
}

/// GET /api/v1/agents — the simplest protected endpoint (ReadApiAccess).
async fn get_agents(client: &Client, base: &str, api_key: Option<&str>) -> reqwest::Response {
    let mut req = client.get(format!("{base}/api/v1/agents"));
    if let Some(key) = api_key {
        req = req.header("x-api-key", key);
    }
    req.send().await.expect("request should succeed")
}

/// POST /api/v1/operators — admin-only endpoint (AdminApiAccess).
async fn create_operator(client: &Client, base: &str, api_key: &str) -> reqwest::Response {
    client
        .post(format!("{base}/api/v1/operators"))
        .header("x-api-key", api_key)
        .header("content-type", "application/json")
        .body(r#"{"username":"newop","password":"somepass","role":"Operator"}"#)
        .send()
        .await
        .expect("request should succeed")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unauthenticated_request_returns_401_missing_api_key() {
    let base = spawn_api_server(profile_with_api_keys()).await;
    let client = Client::new();

    let resp = get_agents(&client, &base, None).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"]["code"], "missing_api_key");
}

#[tokio::test]
async fn invalid_api_key_returns_401() {
    let base = spawn_api_server(profile_with_api_keys()).await;
    let client = Client::new();

    let resp = get_agents(&client, &base, Some("totally-wrong-key")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"]["code"], "invalid_api_key");
}

#[tokio::test]
async fn valid_admin_key_returns_200() {
    let base = spawn_api_server(profile_with_api_keys()).await;
    let client = Client::new();

    let resp = get_agents(&client, &base, Some("secret-admin-value")).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Should return an empty agent list (no agents registered).
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert!(body.is_array(), "expected JSON array, got {body}");
    assert_eq!(body.as_array().expect("array").len(), 0);
}

#[tokio::test]
async fn valid_analyst_key_can_read() {
    let base = spawn_api_server(profile_with_api_keys()).await;
    let client = Client::new();

    let resp = get_agents(&client, &base, Some("secret-analyst-value")).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn analyst_key_denied_admin_endpoint() {
    let base = spawn_api_server(profile_with_api_keys()).await;
    let client = Client::new();

    // POST /operators requires AdminApiAccess — analyst should get 403.
    let resp = create_operator(&client, &base, "secret-analyst-value").await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"]["code"], "forbidden");
}

#[tokio::test]
async fn admin_key_can_access_admin_endpoint() {
    let base = spawn_api_server(profile_with_api_keys()).await;
    let client = Client::new();

    // POST /operators with admin key — may fail for other reasons (e.g. bad
    // body) but should NOT be 401 or 403.
    let resp = create_operator(&client, &base, "secret-admin-value").await;
    let status = resp.status();
    assert_ne!(status, StatusCode::UNAUTHORIZED, "admin key should authenticate");
    assert_ne!(status, StatusCode::FORBIDDEN, "admin key should be authorized");
}

#[tokio::test]
async fn bearer_prefix_is_accepted() {
    let base = spawn_api_server(profile_with_api_keys()).await;
    let client = Client::new();

    // The API also supports `Authorization: Bearer <key>`.
    let resp = client
        .get(format!("{base}/api/v1/agents"))
        .header("authorization", "Bearer secret-admin-value")
        .send()
        .await
        .expect("request should succeed");
    assert_eq!(resp.status(), StatusCode::OK);
}

/// Build a profile with NO `Api { ... }` section — the REST API runtime should
/// report itself as disabled.
fn profile_without_api_keys() -> Profile {
    Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 0
        }

        Operators {
          user "operator" {
            Password = "password1234"
            Role = "Operator"
          }
        }

        Demon {}
        "#,
    )
    .expect("test profile should parse")
}

#[tokio::test]
async fn api_disabled_profile_returns_503() {
    let base = spawn_api_server(profile_without_api_keys()).await;
    let client = Client::new();

    let resp = get_agents(&client, &base, None).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"]["code"], "api_disabled");
}

#[tokio::test]
async fn api_disabled_profile_rejects_with_key_present() {
    let base = spawn_api_server(profile_without_api_keys()).await;
    let client = Client::new();

    // Even when a key header is provided, the response should be 503 api_disabled
    // (not 401 invalid_api_key) because the API is entirely disabled.
    let resp = get_agents(&client, &base, Some("any-key-value")).await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"]["code"], "api_disabled");
}

#[tokio::test]
async fn bearer_prefix_with_wrong_key_returns_invalid_api_key() {
    let base = spawn_api_server(profile_with_api_keys()).await;
    let client = Client::new();

    let resp = client
        .get(format!("{base}/api/v1/agents"))
        .header("authorization", "Bearer totally-wrong-key")
        .send()
        .await
        .expect("request should succeed");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"]["code"], "invalid_api_key");
}

#[tokio::test]
async fn unprotected_root_accessible_without_key() {
    let base = spawn_api_server(profile_with_api_keys()).await;
    let client = Client::new();

    // GET /api/v1 is the discovery endpoint — not behind auth middleware.
    let resp = client.get(format!("{base}/api/v1")).send().await.expect("request should succeed");
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["enabled"], true);
    assert_eq!(body["authentication_header"], "x-api-key");
}
