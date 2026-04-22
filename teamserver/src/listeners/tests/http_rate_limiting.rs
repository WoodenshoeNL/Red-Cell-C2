use super::super::MAX_DEMON_INIT_ATTEMPTS_PER_IP;
use super::*;
use crate::{AuditQuery, AuditResultStatus, query_audit_log};
use axum::http::StatusCode;

#[tokio::test]
async fn http_listener_unknown_callback_probe_is_rate_limited_before_auditing()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database.clone(), registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;
    let client = Client::new();
    // Use an agent_id that is never registered so decrypt_from_agent returns AgentNotFound.
    let agent_id = 0xCAFE_BABE;
    let key = test_key(0xAA);
    let iv = test_iv(0xBB);

    manager.create(http_listener("edge-http-unknown-callback", port)).await?;
    manager.start("edge-http-unknown-callback").await?;
    wait_for_listener(port, false).await?;

    let first_callback_response = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_callback_body(agent_id, key, iv, 1, 1, b"data"))
        .send()
        .await?;

    assert_eq!(first_callback_response.status(), StatusCode::NOT_FOUND);

    let second_callback_response = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_callback_body(agent_id.wrapping_add(1), key, iv, 1, 1, b"data"))
        .send()
        .await?;

    assert_eq!(second_callback_response.status(), StatusCode::NOT_FOUND);

    let audit_page = query_audit_log(
        &database,
        &AuditQuery { action: Some("agent.callback_probe".to_owned()), ..AuditQuery::default() },
    )
    .await?;

    assert_eq!(audit_page.total, 1);
    let entry = &audit_page.items[0];
    assert_eq!(entry.actor, "teamserver");
    assert_eq!(entry.action, "agent.callback_probe");
    assert_eq!(entry.target_kind, "agent");
    assert_eq!(entry.target_id.as_deref(), Some("CAFEBABE"));
    assert_eq!(entry.agent_id.as_deref(), Some("CAFEBABE"));
    assert_eq!(entry.command.as_deref(), Some("callback_probe"));
    assert_eq!(entry.result_status, AuditResultStatus::Failure);
    assert_eq!(
        entry
            .parameters
            .as_ref()
            .and_then(|value| value.get("listener"))
            .and_then(serde_json::Value::as_str),
        Some("edge-http-unknown-callback")
    );
    assert_eq!(
        entry
            .parameters
            .as_ref()
            .and_then(|value| value.get("external_ip"))
            .and_then(serde_json::Value::as_str),
        Some("127.0.0.1")
    );

    manager.stop("edge-http-unknown-callback").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_unknown_reconnect_probe_is_rate_limited_before_auditing()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database.clone(), registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;
    let client = Client::new();
    let agent_id = 0xDEAD_BEEF;

    manager.create(http_listener("edge-http-unknown-reconnect", port)).await?;
    manager.start("edge-http-unknown-reconnect").await?;
    wait_for_listener(port, false).await?;

    let reconnect_response = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_request_body(agent_id))
        .send()
        .await?;

    assert_eq!(reconnect_response.status(), StatusCode::NOT_FOUND);

    let second_reconnect_response = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_request_body(agent_id.wrapping_add(1)))
        .send()
        .await?;

    assert_eq!(second_reconnect_response.status(), StatusCode::NOT_FOUND);

    let audit_page = query_audit_log(
        &database,
        &AuditQuery { action: Some("agent.reconnect_probe".to_owned()), ..AuditQuery::default() },
    )
    .await?;

    assert_eq!(audit_page.total, 1);
    let entry = &audit_page.items[0];
    assert_eq!(entry.actor, "teamserver");
    assert_eq!(entry.action, "agent.reconnect_probe");
    assert_eq!(entry.target_kind, "agent");
    assert_eq!(entry.target_id.as_deref(), Some("DEADBEEF"));
    assert_eq!(entry.agent_id.as_deref(), Some("DEADBEEF"));
    assert_eq!(entry.command.as_deref(), Some("reconnect_probe"));
    assert_eq!(entry.result_status, AuditResultStatus::Failure);
    assert_eq!(
        entry
            .parameters
            .as_ref()
            .and_then(|value| value.get("listener"))
            .and_then(serde_json::Value::as_str),
        Some("edge-http-unknown-reconnect")
    );
    assert_eq!(
        entry
            .parameters
            .as_ref()
            .and_then(|value| value.get("external_ip"))
            .and_then(serde_json::Value::as_str),
        Some("127.0.0.1")
    );

    manager.stop("edge-http-unknown-reconnect").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_unknown_reconnect_probes_share_per_ip_budget()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database.clone(), registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;
    let client = Client::new();

    manager.create(http_listener("edge-http-probe-limit", port)).await?;
    manager.start("edge-http-probe-limit").await?;
    wait_for_listener(port, false).await?;

    // Send MAX_DEMON_INIT_ATTEMPTS_PER_IP probes with *different* unknown agent IDs from the
    // same source IP. Each must return 404 and consume one slot from the shared per-IP budget.
    for i in 0..MAX_DEMON_INIT_ATTEMPTS_PER_IP {
        let agent_id = 0xCAFE_0000_u32 + i;
        let resp = client
            .post(format!("http://127.0.0.1:{port}/"))
            .body(valid_demon_request_body(agent_id))
            .send()
            .await?;
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "probe {i} should return 404 (unknown agent)"
        );
    }

    // The (MAX+1)-th probe — with yet another random agent_id — must also return 404.
    // It is silently dropped by the per-IP limiter (no 429 to avoid leaking rate-limit state
    // to unauthenticated sources).
    let limited = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_request_body(0xDEAD_BEEF))
        .send()
        .await?;
    assert_eq!(
        limited.status(),
        StatusCode::NOT_FOUND,
        "unknown-agent probe exceeding per-IP limit must return 404"
    );

    manager.stop("edge-http-probe-limit").await?;
    Ok(())
}
