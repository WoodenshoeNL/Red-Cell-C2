use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::Request;
use axum::response::Response;
use serde_json::Value;
use tower::ServiceExt;
use zeroize::Zeroizing;

use red_cell_common::AgentRecord;
use red_cell_common::config::{OperatorRole, Profile};

use crate::api::api_routes;
use crate::api::auth::{API_KEY_HEADER, ApiRuntime};
use crate::app::TeamserverState;
use crate::{
    AgentRegistry, AuthService, Database, EventBus, ListenerManager, OperatorConnectionManager,
    SocketRelayManager,
};

pub(super) async fn test_router(api_key: Option<(u32, &str, &str, OperatorRole)>) -> Router {
    test_router_with_registry(api_key).await.0
}

pub(super) async fn test_router_with_database(
    database: Database,
    api_key: Option<(u32, &str, &str, OperatorRole)>,
) -> (Router, AgentRegistry, AuthService) {
    let profile = test_profile(api_key);
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
    let auth = AuthService::from_profile_with_database(&profile, &database).await.expect("auth");

    (
        api_routes(api.clone()).with_state(TeamserverState {
            profile: profile.clone(),
            database,
            auth: auth.clone(),
            api,
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
        }),
        agent_registry,
        auth,
    )
}

pub(super) async fn build_router_from_profile(profile: Profile, database: Database) -> Router {
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
    let auth = AuthService::from_profile_with_database(&profile, &database).await.expect("auth");

    api_routes(api.clone()).with_state(TeamserverState {
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
    })
}

pub(super) async fn test_router_with_registry(
    api_key: Option<(u32, &str, &str, OperatorRole)>,
) -> (Router, AgentRegistry, AuthService) {
    let database = Database::connect_in_memory().await.expect("database");
    test_router_with_database(database, api_key).await
}

/// Like [`test_router_with_registry`] but also returns the shared
/// [`OperatorConnectionManager`] so tests can pre-populate connected operators.
pub(super) async fn test_router_with_connections(
    api_key: Option<(u32, &str, &str, OperatorRole)>,
) -> (Router, AgentRegistry, AuthService, OperatorConnectionManager) {
    let database = Database::connect_in_memory().await.expect("database");
    let profile = test_profile(api_key);
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
    let auth = AuthService::from_profile_with_database(&profile, &database).await.expect("auth");
    let connections = OperatorConnectionManager::new();

    let router = api_routes(api.clone()).with_state(TeamserverState {
        profile: profile.clone(),
        database,
        auth: auth.clone(),
        api,
        events,
        connections: connections.clone(),
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
    });

    (router, agent_registry, auth, connections)
}

pub(super) fn test_profile(api_key: Option<(u32, &str, &str, OperatorRole)>) -> Profile {
    let api_block = api_key.map_or_else(String::new, |(limit, name, value, role)| {
        format!(
            r#"
                Api {{
                  RateLimitPerMinute = {limit}
                  key "{name}" {{
                    Value = "{value}"
                    Role = "{role:?}"
                  }}
                }}
                "#
        )
    });

    Profile::parse(&format!(
        r#"
            Teamserver {{
              Host = "127.0.0.1"
              Port = 40056
            }}

            Operators {{
              user "Neo" {{
                Password = "password1234"
              }}
            }}

            {api_block}

            Demon {{}}
            "#
    ))
    .expect("profile")
}

pub(super) async fn read_json(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.expect("response body bytes");
    serde_json::from_slice(&bytes).expect("json body")
}

pub(super) fn sample_agent(agent_id: u32) -> AgentRecord {
    AgentRecord {
        agent_id,
        active: true,
        reason: "http".to_owned(),
        note: String::new(),
        encryption: red_cell_common::AgentEncryptionInfo {
            aes_key: Zeroizing::new(vec![0u8; 32]),
            aes_iv: Zeroizing::new(vec![0u8; 16]),
        },
        hostname: "workstation".to_owned(),
        username: "neo".to_owned(),
        domain_name: "LAB".to_owned(),
        external_ip: "203.0.113.10".to_owned(),
        internal_ip: "10.0.0.10".to_owned(),
        process_name: "demon.exe".to_owned(),
        process_path: "C:\\Windows\\System32\\demon.exe".to_owned(),
        base_address: 0x140000000,
        process_pid: 4444,
        process_tid: 4445,
        process_ppid: 1000,
        process_arch: "x64".to_owned(),
        elevated: true,
        os_version: "Windows 11".to_owned(),
        os_build: 0,
        os_arch: "x64".to_owned(),
        sleep_delay: 5,
        sleep_jitter: 10,
        kill_date: None,
        working_hours: None,
        first_call_in: "2026-03-09T20:00:00Z".to_owned(),
        last_call_in: "2026-03-09T20:05:00Z".to_owned(),
        archon_magic: None,
    }
}

pub(super) fn smb_listener_json(name: &str, pipe_name: &str) -> String {
    format!(r#"{{"protocol":"smb","config":{{"name":"{name}","pipe_name":"{pipe_name}"}}}}"#)
}

pub(super) fn http_listener_json(name: &str, port: u16) -> String {
    format!(
        r#"{{"protocol":"http","config":{{"name":"{name}","hosts":["127.0.0.1"],"host_bind":"127.0.0.1","host_rotation":"round-robin","port_bind":{port},"uris":["/"],"secure":false}}}}"#
    )
}

pub(super) fn free_tcp_port() -> u16 {
    let sock =
        std::net::TcpListener::bind("127.0.0.1:0").expect("failed to bind ephemeral TCP socket");
    sock.local_addr().expect("failed to read local addr").port()
}

pub(super) fn create_listener_request(body: &str, api_key: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/listeners")
        .header(API_KEY_HEADER, api_key)
        .header("content-type", "application/json")
        .body(Body::from(body.to_owned()))
        .expect("request")
}

pub(super) async fn create_runtime_operator(
    app: &Router,
    api_key: &str,
    username: &str,
    password: &str,
    role: &str,
) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/operators")
                .header(API_KEY_HEADER, api_key)
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"username":"{username}","password":"{password}","role":"{role}"}}"#
                )))
                .expect("request"),
        )
        .await
        .expect("response")
}
