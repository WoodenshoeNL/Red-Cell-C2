//! Integration test for REST API key authentication flow.
//!
//! Configures API keys in a profile, starts an Axum server with the full API
//! router, and verifies authenticated/unauthenticated request handling plus
//! RBAC enforcement on the authenticated identity.

mod common;

use std::path::PathBuf;

use red_cell::{
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, OperatorConnectionManager, PayloadBuilderService, SocketRelayManager,
    TeamserverState,
};
use red_cell_common::config::Profile;
use red_cell_common::corpus::CorpusSessionKeys;
use red_cell_common::{AgentEncryptionInfo, AgentRecord};
use reqwest::{Client, StatusCode};
use tokio::net::TcpListener;
use zeroize::Zeroizing;

/// Build a profile with Admin / Analyst / Operator REST API keys.
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

          key "operator-rest-key" {
            Value = "secret-operator-rest-value"
            Role  = "Operator"
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
    spawn_api_server_with_options(profile, None, None).await
}

/// Like [`spawn_api_server`], with optional corpus capture directory and optional
/// pre-registered CTR agent fixture (for `/debug/corpus-keys` scenarios).
async fn spawn_api_server_with_options(
    profile: Profile,
    corpus_dir: Option<PathBuf>,
    pre_registered_ctr_agent: Option<AgentRecord>,
) -> String {
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
    )
    .with_demon_allow_legacy_ctr(true);
    let webhooks = AuditWebhookNotifier::from_profile(&profile);

    if let Some(agent) = pre_registered_ctr_agent {
        registry
            .insert_full(agent, "test-listener", 0, false, false, false)
            .await
            .expect("register corpus-keys fixture agent");
    }

    let state = TeamserverState {
        profile: profile.clone(),
        profile_path: "test.yaotl".to_owned(),
        database,
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
        started_at: std::time::Instant::now(),
        plugins_loaded: 0,
        plugins_failed: 0,
        metrics: red_cell::metrics::standalone_metrics_handle(),
        corpus_dir,
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

/// CTR (non-ECDH) [`AgentRecord`] fixture for corpus-keys integration tests (`0xcafebabE`).
fn corpus_ctr_agent_fixture(agent_id: u32) -> AgentRecord {
    let aes_key: Vec<u8> = (0u8..32).collect();
    let aes_iv: Vec<u8> = (0u8..16).collect();
    AgentRecord {
        agent_id,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: AgentEncryptionInfo {
            aes_key: Zeroizing::new(aes_key),
            aes_iv: Zeroizing::new(aes_iv),
            monotonic_ctr: true,
        },
        hostname: "test-host".to_owned(),
        username: "user".to_owned(),
        domain_name: "DOMAIN".to_owned(),
        external_ip: "1.2.3.4".to_owned(),
        internal_ip: "10.0.0.1".to_owned(),
        process_name: "test.exe".to_owned(),
        process_path: "C:\\test.exe".to_owned(),
        base_address: 0,
        process_pid: 1,
        process_tid: 1,
        process_ppid: 0,
        process_arch: "x64".to_owned(),
        elevated: false,
        os_version: "Windows 10".to_owned(),
        os_build: 0,
        os_arch: "x64".to_owned(),
        sleep_delay: 5,
        sleep_jitter: 0,
        kill_date: None,
        working_hours: None,
        first_call_in: "2026-01-01T00:00:00Z".to_owned(),
        last_call_in: "2026-01-01T00:00:00Z".to_owned(),
        archon_magic: None,
    }
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
async fn analyst_key_denied_debug_corpus_keys() {
    let base = spawn_api_server(profile_with_api_keys()).await;
    let client = Client::new();

    let resp = client
        .get(format!("{base}/api/v1/debug/corpus-keys?agent_id=0xcafebabE"))
        .header("x-api-key", "secret-analyst-value")
        .send()
        .await
        .expect("request should succeed");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"]["code"], "forbidden");
}

#[tokio::test]
async fn operator_rest_api_key_denied_debug_corpus_keys() {
    let base = spawn_api_server(profile_with_api_keys()).await;
    let client = Client::new();

    let resp = client
        .get(format!("{base}/api/v1/debug/corpus-keys?agent_id=0xcafebabE"))
        .header("x-api-key", "secret-operator-rest-value")
        .send()
        .await
        .expect("request should succeed");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"]["code"], "forbidden");
}

#[tokio::test]
async fn admin_rest_api_key_succeeds_on_debug_corpus_keys_when_capture_enabled() {
    let agent_id = 0xcafebabEu32;
    let agent = corpus_ctr_agent_fixture(agent_id);
    let base = spawn_api_server_with_options(
        profile_with_api_keys(),
        Some(std::env::temp_dir()),
        Some(agent),
    )
    .await;
    let client = Client::new();

    let resp = client
        .get(format!("{base}/api/v1/debug/corpus-keys?agent_id=0xcafebabE"))
        .header("x-api-key", "secret-admin-value")
        .send()
        .await
        .expect("request should succeed");
    assert_eq!(resp.status(), StatusCode::OK);

    let keys: CorpusSessionKeys = resp.json().await.expect("corpus-keys json");
    let expected_aes_hex: String = (0u8..32).map(|b| format!("{b:02x}")).collect();
    let expected_iv_hex: String = (0u8..16).map(|b| format!("{b:02x}")).collect();
    assert_eq!(keys.aes_key_hex.as_deref(), Some(expected_aes_hex.as_str()));
    assert_eq!(keys.aes_iv_hex.as_deref(), Some(expected_iv_hex.as_str()));
    assert_eq!(keys.encryption_scheme.as_deref(), Some("aes-256-ctr"));
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
async fn admin_key_can_create_operator_and_persist() {
    let base = spawn_api_server(profile_with_api_keys()).await;
    let client = Client::new();

    // POST /operators with admin key should return 201 with the created operator.
    let resp = create_operator(&client, &base, "secret-admin-value").await;
    assert_eq!(resp.status(), StatusCode::CREATED, "operator creation should succeed");

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["username"], "newop");
    assert_eq!(body["role"], "Operator");

    // Verify persistence: GET /operators should include the new operator.
    let list_resp = client
        .get(format!("{base}/api/v1/operators"))
        .header("x-api-key", "secret-admin-value")
        .send()
        .await
        .expect("list request should succeed");
    assert_eq!(list_resp.status(), StatusCode::OK);

    let operators: serde_json::Value = list_resp.json().await.expect("json body");
    let operators = operators.as_array().expect("expected JSON array");
    let found = operators.iter().any(|op| op["username"] == "newop");
    assert!(found, "newly created operator should appear in operator list: {operators:?}");

    // Verify idempotency guard: creating the same operator again should return 409.
    let dup_resp = create_operator(&client, &base, "secret-admin-value").await;
    assert_eq!(dup_resp.status(), StatusCode::CONFLICT, "duplicate creation should be rejected");
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

/// Send a GET /api/v1/agents with a raw `Authorization` header value.
async fn get_agents_with_authorization(
    client: &Client,
    base: &str,
    auth_value: &str,
) -> reqwest::Response {
    client
        .get(format!("{base}/api/v1/agents"))
        .header("authorization", auth_value)
        .send()
        .await
        .expect("request should succeed")
}

#[tokio::test]
async fn bearer_no_space_no_token_returns_invalid_authorization_header() {
    let base = spawn_api_server(profile_with_api_keys()).await;
    let client = Client::new();

    // "Bearer" without trailing space — strip_prefix("Bearer ") fails.
    let resp = get_agents_with_authorization(&client, &base, "Bearer").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"]["code"], "invalid_authorization_header");
}

#[tokio::test]
async fn bearer_empty_token_returns_401() {
    let base = spawn_api_server(profile_with_api_keys()).await;
    let client = Client::new();

    // "Bearer " with nothing after the prefix — the HTTP layer trims trailing
    // whitespace from header values, so this becomes "Bearer" which fails the
    // "Bearer " prefix match → invalid_authorization_header.
    let resp = get_agents_with_authorization(&client, &base, "Bearer ").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"]["code"], "invalid_authorization_header");
}

#[tokio::test]
async fn bearer_whitespace_only_token_returns_401() {
    let base = spawn_api_server(profile_with_api_keys()).await;
    let client = Client::new();

    // "Bearer   " — the HTTP layer trims trailing whitespace, reducing this to
    // "Bearer" which fails the "Bearer " prefix match.
    let resp = get_agents_with_authorization(&client, &base, "Bearer   ").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"]["code"], "invalid_authorization_header");
}

#[tokio::test]
async fn bearer_extra_tokens_returns_401() {
    let base = spawn_api_server(profile_with_api_keys()).await;
    let client = Client::new();

    // "Bearer token1 token2" — the extracted key is "token1 token2" which won't
    // match any configured key, so it should be rejected.
    let resp =
        get_agents_with_authorization(&client, &base, "Bearer secret-admin-value extra").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"]["code"], "invalid_api_key");
}

#[tokio::test]
async fn bearer_lowercase_returns_invalid_authorization_header() {
    let base = spawn_api_server(profile_with_api_keys()).await;
    let client = Client::new();

    // RFC 7235 says scheme names are case-insensitive, but the current parser
    // uses a case-sensitive prefix match. Lowercase "bearer" should be rejected.
    let resp = get_agents_with_authorization(&client, &base, "bearer secret-admin-value").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"]["code"], "invalid_authorization_header");
}

// ---------------------------------------------------------------------------
// Conflicting header precedence tests
// ---------------------------------------------------------------------------

/// Send a GET /api/v1/agents with both `x-api-key` and `Authorization: Bearer` headers.
async fn get_agents_with_both_headers(
    client: &Client,
    base: &str,
    api_key: &str,
    bearer_token: &str,
) -> reqwest::Response {
    client
        .get(format!("{base}/api/v1/agents"))
        .header("x-api-key", api_key)
        .header("authorization", format!("Bearer {bearer_token}"))
        .send()
        .await
        .expect("request should succeed")
}

#[tokio::test]
async fn valid_api_key_with_invalid_bearer_succeeds() {
    let base = spawn_api_server(profile_with_api_keys()).await;
    let client = Client::new();

    // x-api-key takes precedence — valid x-api-key should succeed even when
    // the Authorization header carries an invalid bearer token.
    let resp =
        get_agents_with_both_headers(&client, &base, "secret-admin-value", "totally-wrong").await;
    assert_eq!(resp.status(), StatusCode::OK);

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert!(body.is_array(), "expected JSON array, got {body}");
}

#[tokio::test]
async fn invalid_api_key_with_valid_bearer_returns_401() {
    let base = spawn_api_server(profile_with_api_keys()).await;
    let client = Client::new();

    // x-api-key takes precedence — invalid x-api-key should fail even when
    // the Authorization header carries a valid bearer token.
    let resp =
        get_agents_with_both_headers(&client, &base, "totally-wrong", "secret-admin-value").await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"]["code"], "invalid_api_key");
}

#[tokio::test]
async fn both_valid_headers_uses_api_key_identity() {
    let base = spawn_api_server(profile_with_api_keys()).await;
    let client = Client::new();

    // Both headers carry valid keys but for different roles: x-api-key is
    // Analyst (read-only), bearer is Admin. Since x-api-key wins, the
    // admin-only endpoint should be forbidden.
    let resp = client
        .post(format!("{base}/api/v1/operators"))
        .header("x-api-key", "secret-analyst-value")
        .header("authorization", "Bearer secret-admin-value")
        .header("content-type", "application/json")
        .body(r#"{"username":"newop2","password":"somepass","role":"Operator"}"#)
        .send()
        .await
        .expect("request should succeed");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "x-api-key identity (Analyst) should win over Authorization bearer (Admin)"
    );

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"]["code"], "forbidden");
}

/// Build a profile with a very low rate limit for testing enforcement.
fn profile_with_low_rate_limit() -> Profile {
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
          RateLimitPerMinute = 3

          key "test-key" {
            Value = "rate-limit-test-value"
            Role  = "Admin"
          }
        }

        Demon {}
        "#,
    )
    .expect("test profile should parse")
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

#[tokio::test]
async fn rate_limit_enforced_after_exceeding_limit() {
    let base = spawn_api_server(profile_with_low_rate_limit()).await;
    let client = Client::new();

    // Profile sets RateLimitPerMinute = 3.  Requests 1–3 should succeed;
    // request 4 must be rejected with 429.
    for i in 1..=3 {
        let resp = get_agents(&client, &base, Some("rate-limit-test-value")).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "request {i} of 3 should succeed within the rate limit"
        );
    }

    // The 4th request exceeds the limit.
    let resp = get_agents(&client, &base, Some("rate-limit-test-value")).await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    let retry_after = resp
        .headers()
        .get("retry-after")
        .expect("Retry-After header should be present")
        .to_str()
        .expect("Retry-After should be a valid string");
    assert_eq!(retry_after, "60");

    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["error"]["code"], "rate_limited");
}
