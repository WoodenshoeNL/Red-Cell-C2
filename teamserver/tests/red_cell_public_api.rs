mod common;

use std::path::PathBuf;
use std::time::Duration;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use futures_util::StreamExt;
use red_cell::{
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, LoginRateLimiter, OperatorConnectionManager, PayloadBuilderService,
    PluginError, PluginRuntime, ShutdownController, SocketRelayManager, TeamserverState,
    build_router, hash_password_sha3,
};
use red_cell_common::config::Profile;
use red_cell_common::crypto::hash_password_sha3 as sha3;
use red_cell_common::operator::{EventCode, LoginInfo, Message, MessageHead, OperatorMessage};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::Message as ClientMessage;
use tower::ServiceExt;
use uuid::Uuid;

fn test_profile() -> Profile {
    Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40056
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

/// Profile that includes an API section with a valid key so REST endpoints can
/// be exercised through `build_router`.
fn test_profile_with_api() -> Profile {
    Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40056
        }

        Operators {
          user "operator" {
            Password = "password1234"
            Role = "Operator"
          }
        }

        Api {
          RateLimitPerMinute = 120

          key "test-key" {
            Value = "test-api-secret"
            Role  = "Admin"
          }
        }

        Demon {}
        "#,
    )
    .expect("test profile with API should parse")
}

fn missing_plugins_dir() -> PathBuf {
    std::env::temp_dir().join(format!("red-cell-missing-plugins-{}", Uuid::new_v4()))
}

#[tokio::test]
async fn crate_root_reexports_support_minimal_teamserver_bootstrap() {
    let profile = test_profile();
    let database =
        Database::connect_in_memory().await.expect("in-memory database should initialize");
    let agent_registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(8);
    let sockets = SocketRelayManager::new(agent_registry.clone(), events.clone());
    let shutdown = ShutdownController::new();
    let state = TeamserverState {
        profile: profile.clone(),
        database: database.clone(),
        auth: AuthService::from_profile(&profile).expect("auth service should initialize"),
        api: ApiRuntime::from_profile(&profile).expect("rng should work in tests"),
        events: events.clone(),
        connections: OperatorConnectionManager::new(),
        agent_registry: agent_registry.clone(),
        listeners: ListenerManager::new(database, agent_registry, events, sockets.clone(), None),
        payload_builder: PayloadBuilderService::disabled_for_tests(),
        sockets,
        webhooks: AuditWebhookNotifier::from_profile(&profile),
        login_rate_limiter: LoginRateLimiter::new(),
        shutdown: shutdown.clone(),
        service_bridge: None,
        started_at: std::time::Instant::now(),
        plugins_loaded: 0,
        plugins_failed: 0,
        metrics: red_cell::metrics::standalone_metrics_handle(),
    };

    let response = build_router(state)
        .oneshot(
            Request::builder().uri("/missing").body(Body::empty()).expect("request should build"),
        )
        .await
        .expect("router should respond");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(
        to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body should be readable")
            .is_empty()
    );
    assert!(!shutdown.is_shutting_down());
    assert_eq!(
        hash_password_sha3("password1234"),
        "2f7d3e77d0786c5d305c0afadd4c1a2a6869a3210956c963ad2420c52e797022"
    );
}

#[tokio::test]
async fn plugin_runtime_reports_invalid_plugin_directory_via_crate_root_exports() {
    let database =
        Database::connect_in_memory().await.expect("in-memory database should initialize");
    let agents = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(agents.clone(), events.clone());
    let plugins_dir = missing_plugins_dir();

    let runtime = PluginRuntime::initialize(database, agents, events, sockets, Some(plugins_dir))
        .await
        .expect("plugin runtime should initialize without loading plugins");
    let error =
        runtime.load_plugins().await.expect_err("loading a missing plugin directory should fail");

    assert!(matches!(error, PluginError::InvalidPluginDirectory { .. }));
}

// ---------------------------------------------------------------------------
// Helper: build TeamserverState from a profile
// ---------------------------------------------------------------------------

async fn build_state(profile: Profile) -> TeamserverState {
    let database =
        Database::connect_in_memory().await.expect("in-memory database should initialize");
    let agent_registry = AgentRegistry::new(database.clone());
    let events = EventBus::new(8);
    let sockets = SocketRelayManager::new(agent_registry.clone(), events.clone());
    TeamserverState {
        profile: profile.clone(),
        database: database.clone(),
        auth: AuthService::from_profile(&profile).expect("auth service should initialize"),
        api: ApiRuntime::from_profile(&profile).expect("rng should work in tests"),
        events: events.clone(),
        connections: OperatorConnectionManager::new(),
        agent_registry: agent_registry.clone(),
        listeners: ListenerManager::new(database, agent_registry, events, sockets.clone(), None),
        payload_builder: PayloadBuilderService::disabled_for_tests(),
        sockets,
        webhooks: AuditWebhookNotifier::from_profile(&profile),
        login_rate_limiter: LoginRateLimiter::new(),
        shutdown: ShutdownController::new(),
        service_bridge: None,
        started_at: std::time::Instant::now(),
        plugins_loaded: 0,
        plugins_failed: 0,
        metrics: red_cell::metrics::standalone_metrics_handle(),
    }
}

/// Spawn a teamserver using `build_router` (the full router including REST API
/// and `/havoc` WebSocket) on a random port and return the socket address.
async fn spawn_full_router_server(profile: Profile) -> std::net::SocketAddr {
    let state = build_state(profile).await;
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind should succeed");
    let addr = tcp.local_addr().expect("local_addr should succeed");
    tokio::spawn(async move {
        let app = build_router(state);
        let _ = axum::serve(tcp, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await;
    });
    addr
}

// ---------------------------------------------------------------------------
// REST API tests through build_router
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rest_api_discovery_endpoint_responds_through_build_router() {
    let state = build_state(test_profile_with_api()).await;
    let response = build_router(state)
        .oneshot(
            Request::builder().uri("/api/v1").body(Body::empty()).expect("request should build"),
        )
        .await
        .expect("router should respond");

    assert_eq!(response.status(), StatusCode::OK);
    let body =
        to_bytes(response.into_body(), usize::MAX).await.expect("response body should be readable");
    let json: serde_json::Value =
        serde_json::from_slice(&body).expect("response should be valid JSON");
    assert_eq!(json["enabled"], true);
    assert_eq!(json["authentication_header"], "x-api-key");
}

#[tokio::test]
async fn rest_api_agents_rejects_missing_api_key_through_build_router() {
    let state = build_state(test_profile_with_api()).await;
    let response = build_router(state)
        .oneshot(
            Request::builder()
                .uri("/api/v1/agents")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("router should respond");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body =
        to_bytes(response.into_body(), usize::MAX).await.expect("response body should be readable");
    let json: serde_json::Value =
        serde_json::from_slice(&body).expect("response should be valid JSON");
    assert_eq!(json["error"]["code"], "missing_api_key");
}

#[tokio::test]
async fn rest_api_agents_accepts_valid_api_key_through_build_router() {
    let state = build_state(test_profile_with_api()).await;
    let response = build_router(state)
        .oneshot(
            Request::builder()
                .uri("/api/v1/agents")
                .header("x-api-key", "test-api-secret")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("router should respond");

    assert_eq!(response.status(), StatusCode::OK);
    let body =
        to_bytes(response.into_body(), usize::MAX).await.expect("response body should be readable");
    let json: serde_json::Value =
        serde_json::from_slice(&body).expect("response should be valid JSON");
    assert!(json.is_array(), "expected JSON array of agents, got {json}");
}

#[tokio::test]
async fn rest_api_rejects_invalid_api_key_through_build_router() {
    let state = build_state(test_profile_with_api()).await;
    let response = build_router(state)
        .oneshot(
            Request::builder()
                .uri("/api/v1/agents")
                .header("x-api-key", "wrong-key")
                .body(Body::empty())
                .expect("request should build"),
        )
        .await
        .expect("router should respond");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body =
        to_bytes(response.into_body(), usize::MAX).await.expect("response body should be readable");
    let json: serde_json::Value =
        serde_json::from_slice(&body).expect("response should be valid JSON");
    assert_eq!(json["error"]["code"], "invalid_api_key");
}

// ---------------------------------------------------------------------------
// WebSocket login tests through build_router (/havoc)
// ---------------------------------------------------------------------------

/// Helper: build and send a login message over WebSocket.
async fn send_login(
    socket: &mut common::WsSession,
    username: &str,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let payload = serde_json::to_string(&OperatorMessage::Login(Message {
        head: MessageHead {
            event: EventCode::InitConnection,
            user: username.to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: LoginInfo { user: username.to_owned(), password: sha3(password) },
    }))?;
    socket.send_text(payload).await?;
    Ok(())
}

#[tokio::test]
async fn websocket_login_succeeds_with_valid_credentials_via_build_router() {
    let addr = spawn_full_router_server(test_profile()).await;
    let (raw_socket_, response) = tokio_tungstenite::connect_async(format!("ws://{addr}/havoc"))
        .await
        .expect("WebSocket handshake should succeed");
    let mut socket = common::WsSession::new(raw_socket_);

    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);

    send_login(&mut socket, "operator", "password1234")
        .await
        .expect("sending login should succeed");

    let msg =
        common::read_operator_message(&mut socket).await.expect("should receive login response");
    assert!(
        matches!(msg, OperatorMessage::InitConnectionSuccess(_)),
        "expected InitConnectionSuccess, got {msg:?}"
    );
}

#[tokio::test]
async fn websocket_login_rejected_with_wrong_password_via_build_router() {
    let addr = spawn_full_router_server(test_profile()).await;
    let (raw_socket_, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/havoc"))
        .await
        .expect("WebSocket handshake should succeed");
    let mut socket = common::WsSession::new(raw_socket_);

    send_login(&mut socket, "operator", "wrong-password")
        .await
        .expect("sending login should succeed");

    // The server should respond with an error and close the connection.
    // Allow generous timeout for Argon2id password verification.
    let msg = timeout(Duration::from_secs(30), socket.socket.next()).await;
    match msg {
        Ok(Some(Ok(ClientMessage::Text(text)))) => {
            let parsed: OperatorMessage =
                serde_json::from_str(&text).expect("response should be valid OperatorMessage");
            assert!(
                matches!(parsed, OperatorMessage::InitConnectionError(_)),
                "expected InitConnectionError for wrong password, got {parsed:?}"
            );
        }
        Ok(Some(Ok(ClientMessage::Close(_)))) => {
            // Server closed connection without sending an error frame — acceptable
            // rejection behavior.
        }
        other => {
            panic!("expected error message or close frame for wrong password, got {other:?}");
        }
    }
}

#[tokio::test]
async fn websocket_login_rejected_for_nonexistent_user_via_build_router() {
    let addr = spawn_full_router_server(test_profile()).await;
    let (raw_socket_, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/havoc"))
        .await
        .expect("WebSocket handshake should succeed");
    let mut socket = common::WsSession::new(raw_socket_);

    send_login(&mut socket, "nonexistent", "password1234")
        .await
        .expect("sending login should succeed");

    let msg = timeout(Duration::from_secs(30), socket.socket.next()).await;
    match msg {
        Ok(Some(Ok(ClientMessage::Text(text)))) => {
            let parsed: OperatorMessage =
                serde_json::from_str(&text).expect("response should be valid OperatorMessage");
            assert!(
                matches!(parsed, OperatorMessage::InitConnectionError(_)),
                "expected InitConnectionError for nonexistent user, got {parsed:?}"
            );
        }
        Ok(Some(Ok(ClientMessage::Close(_)))) => {
            // Closed without error frame — acceptable.
        }
        other => {
            panic!("expected error message or close frame for nonexistent user, got {other:?}");
        }
    }
}
