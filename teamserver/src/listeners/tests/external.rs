use std::net::SocketAddr;

use super::super::{
    MAX_DEMON_INIT_ATTEMPTS_PER_IP, handle_external_request, listener_config_from_operator,
    profile_listener_configs,
};
use super::*;
use axum::http::StatusCode;
use red_cell_common::config::Profile;
use red_cell_common::crypto::decrypt_agent_data;

#[test]
fn listener_config_from_operator_parses_external() {
    let info = ListenerInfo {
        name: Some("bridge".to_owned()),
        protocol: Some("External".to_owned()),
        extra: [("Endpoint".to_owned(), serde_json::Value::String("/ext".to_owned()))]
            .into_iter()
            .collect(),
        ..ListenerInfo::default()
    };

    let config = listener_config_from_operator(&info).expect("should parse external config");
    assert_eq!(config.name(), "bridge");
    assert_eq!(config.protocol(), ListenerProtocol::External);
    match &config {
        ListenerConfig::External(c) => {
            assert_eq!(c.endpoint, "/ext");
        }
        other => panic!("expected External config, got {other:?}"),
    }
}

#[test]
fn listener_config_from_operator_rejects_external_without_endpoint() {
    let info = ListenerInfo {
        name: Some("bridge".to_owned()),
        protocol: Some("External".to_owned()),
        extra: std::collections::BTreeMap::new(),
        ..ListenerInfo::default()
    };

    let error = listener_config_from_operator(&info).expect_err("missing endpoint should fail");
    assert!(
        matches!(error, ListenerManagerError::InvalidConfig { .. }),
        "expected InvalidConfig, got {error:?}"
    );
}

#[tokio::test]
async fn external_listener_create_start_stop_lifecycle() {
    let database = Database::connect_in_memory().await.expect("db");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

    let config = external_listener_config("ext1", "/bridge");

    // Create persists the listener.
    manager.create(config).await.expect("create should succeed");
    let summary = manager.summary("ext1").await.expect("listener should exist");
    assert_eq!(summary.protocol, ListenerProtocol::External);
    assert_eq!(summary.state.status, ListenerStatus::Created);

    // Start should register the endpoint.
    manager.start("ext1").await.expect("start should succeed");
    let summary = manager.summary("ext1").await.expect("listener should exist");
    assert_eq!(summary.state.status, ListenerStatus::Running);

    // The external endpoint should be registered.
    let state =
        manager.external_state_for_path("/bridge").await.expect("endpoint should be registered");
    assert_eq!(state.listener_name(), "ext1");
    assert_eq!(state.endpoint(), "/bridge");

    // Stop should deregister the endpoint.
    manager.stop("ext1").await.expect("stop should succeed");

    // Give the managed task a moment to clean up.
    sleep(Duration::from_millis(50)).await;

    let removed = manager.external_state_for_path("/bridge").await;
    assert!(removed.is_none(), "endpoint should be deregistered after stop");
}

#[tokio::test]
async fn external_listener_to_operator_info_includes_endpoint() {
    let database = Database::connect_in_memory().await.expect("db");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

    let config = external_listener_config("ext-info", "/c2");
    manager.create(config).await.expect("create should succeed");

    let summary = manager.summary("ext-info").await.expect("listener should exist");
    let info = summary.to_operator_info();
    assert_eq!(info.protocol.as_deref(), Some("External"));
    assert_eq!(info.extra.get("Endpoint").and_then(|v| v.as_str()), Some("/c2"),);
    assert_eq!(info.extra.get("Info").and_then(|v| v.as_str()), Some("/c2"),);
}

#[test]
fn profile_listener_configs_includes_external() {
    let profile = Profile::parse(
        r#"
        Teamserver {
          Host = "127.0.0.1"
          Port = 40056
        }

        Operators {
          user "op" { Password = "password1234" }
        }

        Listeners {
          External {
            Name = "bridge"
            Endpoint = "/ext"
          }
        }

        Demon {}
        "#,
    )
    .expect("profile should parse");

    let configs = profile_listener_configs(&profile).expect("configs should be valid");
    assert_eq!(configs.len(), 1);
    assert_eq!(configs[0].name(), "bridge");
    assert_eq!(configs[0].protocol(), ListenerProtocol::External);
}

#[tokio::test]
async fn external_state_for_path_returns_none_for_unknown() {
    let database = Database::connect_in_memory().await.expect("db");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

    assert!(
        manager.external_state_for_path("/nonexistent").await.is_none(),
        "unknown path should return None"
    );
}

#[tokio::test]
async fn external_listener_serializes_and_restores() {
    let database = Database::connect_in_memory().await.expect("db");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

    let config = external_listener_config("ext-persist", "/persist");
    manager.create(config).await.expect("create");

    // Verify the config round-trips through the database.
    let summary = manager.summary("ext-persist").await.expect("should exist");
    assert_eq!(summary.config.protocol(), ListenerProtocol::External);
    match &summary.config {
        ListenerConfig::External(c) => {
            assert_eq!(c.name, "ext-persist");
            assert_eq!(c.endpoint, "/persist");
        }
        other => panic!("expected External, got {other:?}"),
    }
}

#[tokio::test]
async fn update_external_listener_rejects_duplicate_endpoint() {
    let database = Database::connect_in_memory().await.expect("db");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

    // Create two external listeners with distinct endpoints.
    manager.create(external_listener_config("ext-a", "/alpha")).await.expect("create ext-a");
    manager.create(external_listener_config("ext-b", "/beta")).await.expect("create ext-b");

    // Updating ext-b to use ext-a's endpoint must fail.
    let conflict = manager.update(external_listener_config("ext-b", "/alpha")).await;
    assert!(
        matches!(conflict, Err(ListenerManagerError::DuplicateEndpoint { .. })),
        "expected DuplicateEndpoint, got {conflict:?}"
    );

    // Updating ext-a to its own endpoint must succeed (no self-conflict).
    manager
        .update(external_listener_config("ext-a", "/alpha"))
        .await
        .expect("self-update should succeed");

    // Updating ext-b to a new unique endpoint must succeed.
    manager
        .update(external_listener_config("ext-b", "/gamma"))
        .await
        .expect("update to unique endpoint should succeed");
}

// ── External listener preflight guard tests ──────────────────────────────

/// Verify that `handle_external_request` enforces the per-IP DEMON_INIT
/// rate limit in the same way as the HTTP listener.
#[tokio::test]
async fn handle_external_request_rate_limits_demon_init_per_source_ip() {
    let database = Database::connect_in_memory().await.expect("db");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

    manager.create(external_listener_config("ext-rate", "/rate")).await.expect("create");
    manager.start("ext-rate").await.expect("start");

    let state = manager.external_state_for_path("/rate").await.expect("state must be registered");

    let peer: SocketAddr = "10.0.0.1:5000".parse().expect("unwrap");

    // Exhaust the allowed DEMON_INIT budget for this IP.
    for attempt in 0..MAX_DEMON_INIT_ATTEMPTS_PER_IP {
        let agent_id = 0xEE00_0000 + attempt;
        let body = valid_demon_init_body(agent_id, test_key(0x11), test_iv(0x22));
        let result: Result<Vec<u8>, StatusCode> =
            handle_external_request(&state, peer, &body).await;
        assert!(result.is_ok(), "attempt {attempt} should be allowed, got {result:?}");
    }

    // The next DEMON_INIT from the same IP must be blocked (404).
    let blocked_id = 0xEE00_00FF;
    let blocked_body = valid_demon_init_body(blocked_id, test_key(0x11), test_iv(0x22));
    let blocked = handle_external_request(&state, peer, &blocked_body).await;
    assert_eq!(blocked, Err(StatusCode::NOT_FOUND), "over-limit init must return 404");
    assert!(registry.get(blocked_id).await.is_none(), "blocked agent must not be registered");

    manager.stop("ext-rate").await.expect("stop");
}

/// Verify that `handle_external_request` returns 503 when shutdown is in
/// progress (matching the behaviour of the HTTP and DNS listener paths).
#[tokio::test]
async fn handle_external_request_rejects_new_callbacks_during_shutdown() {
    let database = Database::connect_in_memory().await.expect("db");
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

    manager.create(external_listener_config("ext-shutdown", "/shutdown")).await.expect("create");
    manager.start("ext-shutdown").await.expect("start");

    let state =
        manager.external_state_for_path("/shutdown").await.expect("state must be registered");

    // Initiate shutdown before issuing a request.
    manager.shutdown_controller().initiate();

    let peer: SocketAddr = "10.0.0.2:6000".parse().expect("unwrap");
    let body = valid_demon_init_body(0xDEAD_0001, test_key(0x33), test_iv(0x44));
    let result = handle_external_request(&state, peer, &body).await;
    assert_eq!(
        result,
        Err(StatusCode::SERVICE_UNAVAILABLE),
        "request during shutdown must return 503"
    );
}

// ── HTTP required-field rejection tests ──────────────────────────────────

/// Helper: returns a fully-valid HTTP `ListenerInfo` that
/// `listener_config_from_operator` accepts.  Individual tests blank out one
/// field at a time to verify rejection.

#[tokio::test]
async fn external_listener_with_init_secret_registers_agent_and_ack_uses_derived_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let secret = b"ext-test-server-secret".to_vec();
    let (manager, registry, _db, _events) = manager_with_secret(secret.clone()).await?;

    manager.create(external_listener_config("ext-secret", "/secret")).await?;
    manager.start("ext-secret").await?;

    let state = manager.external_state_for_path("/secret").await.expect("state must be registered");

    let key = test_key(0x81);
    let iv = test_iv(0x54);
    let agent_id = 0xEEFF_0001_u32;
    let peer: SocketAddr = "10.0.0.50:7000".parse().expect("unwrap");

    let body = valid_demon_init_body(agent_id, key, iv);
    let result: Result<Vec<u8>, StatusCode> = handle_external_request(&state, peer, &body).await;
    let ack_bytes = result.expect("DEMON_INIT with matching secret should succeed");

    // Agent must be registered.
    let stored = registry.get(agent_id).await.expect("agent should be registered");

    // The stored keys should be HKDF-derived.
    let derived = red_cell_common::crypto::derive_session_keys(&key, &iv, &secret)?;
    assert_eq!(stored.encryption.aes_key.as_slice(), &derived.key);
    assert_eq!(stored.encryption.aes_iv.as_slice(), &derived.iv);

    // ACK decryptable with derived keys.
    let ack_plain = decrypt_agent_data(&derived.key, &derived.iv, &ack_bytes)?;
    assert_eq!(ack_plain.as_slice(), &agent_id.to_le_bytes());

    manager.stop("ext-secret").await?;
    Ok(())
}

/// External listener with init secret rejects callbacks that use the raw
/// (non-derived) agent keys — `handle_external_request` returns 404.
#[tokio::test]
async fn external_listener_with_init_secret_rejects_callback_with_raw_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let secret = b"ext-callback-reject-secret".to_vec();
    let (manager, registry, _db, _events) = manager_with_secret(secret).await?;

    manager.create(external_listener_config("ext-secret-cb", "/secret-cb")).await?;
    manager.start("ext-secret-cb").await?;

    let state =
        manager.external_state_for_path("/secret-cb").await.expect("state must be registered");

    let key = test_key(0x91);
    let iv = test_iv(0x64);
    let agent_id = 0xEEFF_0002_u32;
    let peer: SocketAddr = "10.0.0.51:8000".parse().expect("unwrap");

    // Register agent via DEMON_INIT.
    let init_body = valid_demon_init_body(agent_id, key, iv);
    let init_result: Result<Vec<u8>, StatusCode> =
        handle_external_request(&state, peer, &init_body).await;
    assert!(init_result.is_ok());
    assert!(registry.get(agent_id).await.is_some());

    // Callback with raw keys — server stored derived keys, so parse fails.
    let callback_body = valid_demon_callback_body(
        agent_id,
        key,
        iv,
        u32::from(DemonCommand::CommandCheckin),
        7,
        &[0xDE, 0xAD],
    );
    let callback_result: Result<Vec<u8>, StatusCode> =
        handle_external_request(&state, peer, &callback_body).await;
    assert_eq!(
        callback_result,
        Err(StatusCode::NOT_FOUND),
        "callback with raw keys must be rejected when init_secret is configured"
    );

    manager.stop("ext-secret-cb").await?;
    Ok(())
}
