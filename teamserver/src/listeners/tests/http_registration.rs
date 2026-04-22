use super::super::MAX_DEMON_INIT_ATTEMPTS_PER_IP;
use super::*;
use crate::{AuditQuery, AuditResultStatus, query_audit_log};
use axum::http::StatusCode;
use red_cell_common::crypto::decrypt_agent_data;
use red_cell_common::operator::OperatorMessage;

// ── legacy listener integration tests ────────────────────────────────────────

#[tokio::test]
async fn http_listener_registers_demon_init_and_broadcasts_agent_event()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager =
        ListenerManager::new(database.clone(), registry.clone(), events.clone(), sockets, None)
            .with_demon_allow_legacy_ctr(true);
    let mut event_receiver = events.subscribe();
    let port = available_port()?;

    manager.create(http_listener("edge-http-init", port)).await?;
    manager.start("edge-http-init").await?;
    wait_for_listener(port, false).await?;

    let key = test_key(0x41);
    let iv = test_iv(0x24);
    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_init_body(0x1234_5678, key, iv))
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let decrypted = decrypt_agent_data(&key, &iv, &response.bytes().await?)?;
    assert_eq!(decrypted.as_slice(), &0x1234_5678_u32.to_le_bytes());

    let stored = registry.get(0x1234_5678).await.expect("agent should be registered");
    assert_eq!(stored.hostname, "wkstn-01");
    assert_eq!(stored.external_ip, "127.0.0.1");
    assert_eq!(database.agents().get(0x1234_5678).await?, Some(stored.clone()));

    let event = event_receiver.recv().await.expect("agent registration should broadcast");
    let OperatorMessage::AgentNew(message) = event else {
        panic!("unexpected operator event");
    };
    assert_eq!(message.info.name_id, "12345678");
    assert_eq!(message.info.listener, "edge-http-init");
    assert_eq!(message.info.process_name, "explorer.exe");
    assert_eq!(message.info.process_path, "C:\\Windows\\explorer.exe");
    assert_eq!(message.info.sleep_delay, serde_json::json!(15));
    manager.stop("edge-http-init").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_demon_init_records_agent_registered_audit_entry()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database.clone(), registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;

    manager.create(http_listener("edge-http-audit-init", port)).await?;
    manager.start("edge-http-audit-init").await?;
    wait_for_listener(port, false).await?;

    let key = test_key(0x41);
    let iv = test_iv(0x24);
    let agent_id = 0xDEAD_CAFE_u32;
    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let page = query_audit_log(
        &database,
        &AuditQuery { action: Some("agent.registered".to_owned()), ..AuditQuery::default() },
    )
    .await
    .expect("audit query should succeed");

    assert!(!page.items.is_empty(), "expected at least one agent.registered audit entry");
    let entry = &page.items[0];
    assert_eq!(entry.actor, "teamserver");
    assert_eq!(entry.action, "agent.registered");
    assert_eq!(entry.target_kind, "agent");
    assert_eq!(entry.target_id.as_deref(), Some("DEADCAFE"));
    assert_eq!(entry.result_status, AuditResultStatus::Success);
    let params = entry.parameters.as_ref().expect("parameters must be present");
    assert_eq!(params["listener"], "edge-http-audit-init");

    manager.stop("edge-http-audit-init").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_uses_peer_ip_when_not_behind_redirector()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;

    manager.create(http_listener("edge-http-peer-ip", port)).await?;
    manager.start("edge-http-peer-ip").await?;
    wait_for_listener(port, false).await?;

    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .header("X-Forwarded-For", "198.51.100.24")
        .header("X-Real-IP", "198.51.100.25")
        .body(valid_demon_init_body(0x1111_2222, test_key(0x41), test_iv(0x24)))
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let stored = registry.get(0x1111_2222).await.expect("agent should be registered");
    assert_eq!(stored.external_ip, "127.0.0.1");

    manager.stop("edge-http-peer-ip").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_trusts_forwarded_ip_from_trusted_redirector()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;

    manager
        .create(http_listener_with_redirector(
            "edge-http-redirector",
            port,
            vec!["127.0.0.1/32".to_owned()],
        ))
        .await?;
    manager.start("edge-http-redirector").await?;
    wait_for_listener(port, false).await?;

    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .header("X-Forwarded-For", "203.0.113.200, 198.51.100.24")
        .body(valid_demon_init_body(0x3333_4444, test_key(0x41), test_iv(0x24)))
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let stored = registry.get(0x3333_4444).await.expect("agent should be registered");
    assert_eq!(stored.external_ip, "198.51.100.24");

    manager.stop("edge-http-redirector").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_rate_limits_demon_init_per_source_ip()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;

    manager.create(http_listener("edge-http-init-limit", port)).await?;
    manager.start("edge-http-init-limit").await?;
    wait_for_listener(port, false).await?;

    let client = Client::new();
    for attempt in 0..MAX_DEMON_INIT_ATTEMPTS_PER_IP {
        let agent_id = 0x1000_0000 + attempt;
        let response = client
            .post(format!("http://127.0.0.1:{port}/"))
            .body(valid_demon_init_body(agent_id, test_key(0x41), test_iv(0x24)))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(registry.get(agent_id).await.is_some());
    }

    let blocked_agent_id = 0x1000_00FF;
    let blocked = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_init_body(blocked_agent_id, test_key(0x41), test_iv(0x24)))
        .send()
        .await?;
    assert_eq!(blocked.status(), StatusCode::NOT_FOUND);
    assert!(registry.get(blocked_agent_id).await.is_none());

    manager.stop("edge-http-init-limit").await?;
    Ok(())
}
