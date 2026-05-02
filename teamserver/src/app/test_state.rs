//! Test-only [`TeamserverState`] bootstrap used by unit tests across the crate.

use std::time::Instant;

use red_cell_common::config::Profile;

use crate::{
    AgentRegistry, ApiRuntime, AuditWebhookNotifier, AuthService, Database, EventBus,
    ListenerManager, LoginRateLimiter, OperatorConnectionManager, PayloadBuilderService,
    ShutdownController, SocketRelayManager,
};

use super::state::TeamserverState;

pub(crate) async fn build_test_state() -> TeamserverState {
    let profile = Profile::parse(
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
    .expect("profile should parse");
    let database = Database::connect_in_memory().await.expect("database should initialize");
    let agent_registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(agent_registry.clone(), events.clone());
    TeamserverState {
        profile: profile.clone(),
        profile_path: "test.yaotl".to_owned(),
        database: database.clone(),
        auth: AuthService::from_profile(&profile).expect("auth service should initialize"),
        api: ApiRuntime::from_profile(&profile).expect("rng should work in tests"),
        events: events.clone(),
        connections: OperatorConnectionManager::new(),
        agent_registry: agent_registry.clone(),
        listeners: ListenerManager::new(database, agent_registry, events, sockets.clone(), None)
            .with_demon_allow_legacy_ctr(true),
        payload_builder: PayloadBuilderService::disabled_for_tests(),
        sockets,
        webhooks: AuditWebhookNotifier::from_profile(&profile),
        login_rate_limiter: LoginRateLimiter::new(),
        shutdown: ShutdownController::new(),
        service_bridge: None,
        started_at: Instant::now(),
        plugins_loaded: 0,
        plugins_failed: 0,
        metrics: crate::metrics::standalone_metrics_handle(),
        corpus_dir: None,
    }
}
