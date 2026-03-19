use std::path::PathBuf;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use red_cell::{
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, LoginRateLimiter, OperatorConnectionManager, PayloadBuilderService,
    PluginError, PluginRuntime, ShutdownController, SocketRelayManager, TeamserverState,
    build_router, hash_password_sha3,
};
use red_cell_common::config::Profile;
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
