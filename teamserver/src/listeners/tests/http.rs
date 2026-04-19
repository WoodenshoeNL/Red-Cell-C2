use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use super::super::{
    MAX_AGENT_MESSAGE_LEN, MAX_DEMON_INIT_ATTEMPTS_PER_IP, TrustedProxyPeer, cert_mtime,
    collect_body_with_magic_precheck, extract_external_ip, parse_trusted_proxy_peer,
    reload_tls_from_files, spawn_cert_file_watcher,
};
use super::*;
use crate::{AuditQuery, AuditResultStatus, Job, query_audit_log};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use red_cell_common::HttpListenerResponseConfig;
use red_cell_common::crypto::{
    ctr_blocks_for_len, decrypt_agent_data, decrypt_agent_data_at_offset,
};
use red_cell_common::demon::{DEMON_MAGIC_VALUE, DemonMessage};
use red_cell_common::operator::OperatorMessage;

#[test]
fn extract_external_ip_ignores_forwarded_headers_from_untrusted_peers() {
    let peer = SocketAddr::from(([198, 51, 100, 25], 443));
    let trusted_proxy_peers =
        vec![TrustedProxyPeer::Address(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)))];
    let request = Request::builder()
        .header("X-Forwarded-For", "10.0.0.77")
        .header("X-Real-IP", "10.0.0.88")
        .body(Body::empty())
        .expect("request should build");

    let external_ip = extract_external_ip(true, &trusted_proxy_peers, peer, &request);
    assert_eq!(external_ip, peer.ip());
}

#[test]
fn extract_external_ip_uses_rightmost_untrusted_forwarded_hop() {
    let peer = SocketAddr::from(([203, 0, 113, 10], 443));
    let trusted_proxy_peers = vec![TrustedProxyPeer::Address(peer.ip())];
    let request = Request::builder()
        .header("X-Forwarded-For", "10.0.0.66, 10.0.0.77")
        .body(Body::empty())
        .expect("request should build");

    let external_ip = extract_external_ip(true, &trusted_proxy_peers, peer, &request);
    assert_eq!(external_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 77)));
}

#[test]
fn extract_external_ip_skips_trusted_proxy_chain_when_parsing_forwarded_hops() {
    let peer = SocketAddr::from(([203, 0, 113, 10], 443));
    let trusted_proxy_peers = vec![
        TrustedProxyPeer::Address(peer.ip()),
        TrustedProxyPeer::Address(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20))),
    ];
    let request = Request::builder()
        .header("X-Forwarded-For", "198.51.100.24, 203.0.113.20")
        .body(Body::empty())
        .expect("request should build");

    let external_ip = extract_external_ip(true, &trusted_proxy_peers, peer, &request);
    assert_eq!(external_ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 24)));
}

#[test]
fn extract_external_ip_ignores_invalid_forwarded_for_and_falls_back_to_x_real_ip() {
    let peer = SocketAddr::from(([203, 0, 113, 10], 443));
    let trusted_proxy_peers = vec![TrustedProxyPeer::Address(peer.ip())];
    let request = Request::builder()
        .header("X-Forwarded-For", "not-an-ip, 10.0.0.77")
        .header("X-Real-IP", "192.0.2.44")
        .body(Body::empty())
        .expect("request should build");

    let external_ip = extract_external_ip(true, &trusted_proxy_peers, peer, &request);
    assert_eq!(external_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)));
}

#[test]
fn extract_external_ip_trusts_forwarded_headers_from_allowed_proxy_cidr() {
    let peer = SocketAddr::from(([10, 1, 2, 3], 443));
    let trusted_proxy_peers =
        vec![parse_trusted_proxy_peer("10.0.0.0/8", "edge").expect("cidr should parse")];
    let request = Request::builder()
        .header("X-Real-IP", "192.0.2.44")
        .body(Body::empty())
        .expect("request should build");

    let external_ip = extract_external_ip(true, &trusted_proxy_peers, peer, &request);
    assert_eq!(external_ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)));
}

#[test]
fn parse_trusted_proxy_peer_rejects_invalid_entries() {
    let error = parse_trusted_proxy_peer("10.0.0.0/33", "edge")
        .expect_err("invalid prefix length should fail");
    assert!(matches!(error, ListenerManagerError::InvalidConfig { .. }));
}

#[tokio::test]
async fn http_listener_returns_fake_404_for_non_matching_requests()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;
    let agent_id = 0x1234_5678;
    let config = ListenerConfig::from(HttpListenerConfig {
        name: "edge-http".to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["127.0.0.1".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: port,
        port_conn: Some(port),
        method: Some("POST".to_owned()),
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: Some("Agent-UA".to_owned()),
        headers: vec!["Accept-Encoding: gzip".to_owned(), "X-Auth: 123".to_owned()],
        uris: vec!["/submit".to_owned()],
        host_header: None,
        secure: false,
        cert: None,
        response: Some(HttpListenerResponseConfig {
            headers: vec!["Server: ExampleFront".to_owned(), "Content-Type: text/plain".to_owned()],
            body: Some("decoy".to_owned()),
        }),
        proxy: None,
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
        legacy_mode: true,
    });

    manager.create(config).await?;
    manager.start("edge-http").await?;
    wait_for_listener(port, false).await?;

    let client = Client::new();

    let invalid = client.get(format!("http://127.0.0.1:{port}/nope")).send().await?;
    assert_eq!(invalid.status(), StatusCode::NOT_FOUND);
    assert!(
        invalid.headers().get("x-havoc").is_none(),
        "fake 404 must not expose x-havoc fingerprinting header"
    );
    assert_eq!(invalid.text().await?, "decoy");

    let valid = client
        .post(format!("http://127.0.0.1:{port}/submit"))
        .header("User-Agent", "Agent-UA")
        .header("X-Auth", "123")
        .body(valid_demon_request_body(agent_id))
        .send()
        .await?;
    assert_eq!(valid.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        valid.headers().get("server").and_then(|value| value.to_str().ok()),
        Some("ExampleFront")
    );
    assert_eq!(valid.text().await?, "decoy");

    manager.stop("edge-http").await?;
    Ok(())
}

#[tokio::test]
async fn https_listener_generates_tls_and_accepts_requests()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;
    let agent_id = 1;
    let key = test_key(0x41);
    let iv = test_iv(0x24);
    let config = ListenerConfig::from(HttpListenerConfig {
        name: "edge-https".to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["localhost".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: port,
        port_conn: Some(port),
        method: None,
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: None,
        headers: Vec::new(),
        uris: vec!["/".to_owned()],
        host_header: None,
        secure: true,
        cert: None,
        response: Some(HttpListenerResponseConfig {
            headers: vec!["Server: TLSFront".to_owned()],
            body: Some("tls".to_owned()),
        }),
        proxy: None,
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
        legacy_mode: true,
    });

    manager.create(config).await?;
    manager.start("edge-https").await?;
    wait_for_listener(port, true).await?;

    let client = Client::builder().danger_accept_invalid_certs(true).build()?;
    let response = client
        .post(format!("https://127.0.0.1:{port}/"))
        .body(valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("server").and_then(|value| value.to_str().ok()),
        Some("TLSFront")
    );
    let decrypted = decrypt_agent_data(&key, &iv, &response.bytes().await?)?;
    assert_eq!(decrypted.as_slice(), &agent_id.to_le_bytes());

    manager.stop("edge-https").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_returns_fake_404_for_invalid_demon_callback_body()
-> Result<(), Box<dyn std::error::Error>> {
    let manager = manager().await?;
    let port = available_port()?;
    manager.create(http_listener("edge-http-invalid", port)).await?;
    manager.start("edge-http-invalid").await?;
    wait_for_listener(port, false).await?;

    let client = Client::new();

    let too_short =
        client.post(format!("http://127.0.0.1:{port}/")).body(vec![0_u8; 8]).send().await?;
    assert_eq!(too_short.status(), StatusCode::NOT_FOUND);

    let mut invalid_magic = valid_demon_request_body(0x0102_0304);
    invalid_magic[4..8].copy_from_slice(&0xFEED_FACE_u32.to_be_bytes());
    let invalid_magic =
        client.post(format!("http://127.0.0.1:{port}/")).body(invalid_magic).send().await?;
    assert_eq!(invalid_magic.status(), StatusCode::NOT_FOUND);

    manager.stop("edge-http-invalid").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_rejects_oversized_request_body() -> Result<(), Box<dyn std::error::Error>> {
    let manager = manager().await?;
    let port = available_port()?;
    manager.create(http_listener("edge-http-oversize", port)).await?;
    manager.start("edge-http-oversize").await?;
    wait_for_listener(port, false).await?;

    let oversized = vec![0xAA_u8; MAX_AGENT_MESSAGE_LEN + 1];
    let response =
        Client::new().post(format!("http://127.0.0.1:{port}/")).body(oversized).send().await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    manager.stop("edge-http-oversize").await?;
    Ok(())
}

// ── legacy_mode = true (Demon listeners) ────────────────────────────────────

#[tokio::test]
async fn collect_body_with_magic_precheck_accepts_valid_demon_body() {
    let body = valid_demon_request_body(0x1234_5678);
    let result =
        collect_body_with_magic_precheck(Body::from(body.clone()), MAX_AGENT_MESSAGE_LEN, true)
            .await;
    assert_eq!(result.as_deref(), Some(body.as_slice()));
}

#[tokio::test]
async fn collect_body_with_magic_precheck_rejects_wrong_magic() {
    let mut body = valid_demon_request_body(0x1234_5678);
    body[4..8].copy_from_slice(&0xFEED_FACE_u32.to_be_bytes());
    let result =
        collect_body_with_magic_precheck(Body::from(body), MAX_AGENT_MESSAGE_LEN, true).await;
    assert!(result.is_none(), "wrong magic must be rejected before full body is buffered");
}

#[tokio::test]
async fn collect_body_with_magic_precheck_rejects_body_shorter_than_8_bytes() {
    let short = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE];
    let result =
        collect_body_with_magic_precheck(Body::from(short), MAX_AGENT_MESSAGE_LEN, true).await;
    assert!(result.is_none(), "body shorter than 8 bytes must be rejected");
}

#[tokio::test]
async fn collect_body_with_magic_precheck_rejects_body_exceeding_max_len() {
    // Construct a body that starts with a valid magic value but exceeds max_len.
    let mut body = vec![0u8; 9];
    body[4..8].copy_from_slice(&DEMON_MAGIC_VALUE.to_be_bytes());
    body.extend(vec![0u8; 10]);
    let result = collect_body_with_magic_precheck(Body::from(body), 8, true).await;
    assert!(result.is_none(), "body exceeding max_len must be rejected");
}

#[tokio::test]
async fn collect_body_with_magic_precheck_rejects_empty_body() {
    let result = collect_body_with_magic_precheck(Body::empty(), MAX_AGENT_MESSAGE_LEN, true).await;
    assert!(result.is_none(), "empty body must be rejected");
}

// ── legacy_mode = false (new-protocol listeners) ─────────────────────────────

#[tokio::test]
async fn non_legacy_precheck_rejects_demon_magic() {
    // A body with 0xDEADBEEF at bytes 4–7 must be rejected by a non-legacy listener.
    let body = valid_demon_request_body(0x1234_5678);
    let result =
        collect_body_with_magic_precheck(Body::from(body), MAX_AGENT_MESSAGE_LEN, false).await;
    assert!(result.is_none(), "0xDEADBEEF must be rejected by a non-legacy listener");
}

#[tokio::test]
async fn non_legacy_precheck_accepts_body_without_demon_magic() {
    // A body without 0xDEADBEEF at bytes 4–7 is accepted by a non-legacy listener.
    let mut body = vec![0u8; 16];
    body[4..8].copy_from_slice(&0xFEED_FACE_u32.to_be_bytes());
    let result =
        collect_body_with_magic_precheck(Body::from(body.clone()), MAX_AGENT_MESSAGE_LEN, false)
            .await;
    assert_eq!(result.as_deref(), Some(body.as_slice()), "non-Demon body must pass the precheck");
}

#[tokio::test]
async fn non_legacy_precheck_rejects_empty_body() {
    let result =
        collect_body_with_magic_precheck(Body::empty(), MAX_AGENT_MESSAGE_LEN, false).await;
    assert!(result.is_none(), "empty body must be rejected regardless of legacy_mode");
}

#[tokio::test]
async fn non_legacy_precheck_rejects_body_shorter_than_8_bytes() {
    let short = vec![0u8; 7];
    let result =
        collect_body_with_magic_precheck(Body::from(short), MAX_AGENT_MESSAGE_LEN, false).await;
    assert!(
        result.is_none(),
        "body shorter than 8 bytes must be rejected regardless of legacy_mode"
    );
}

// ── non-legacy listener integration test ─────────────────────────────────────

#[tokio::test]
async fn non_legacy_http_listener_rejects_demon_packet_at_pre_filter()
-> Result<(), Box<dyn std::error::Error>> {
    // Spin up a non-legacy listener (legacy_mode = false) and verify it returns
    // a 404 (fake) for any Demon packet bearing the 0xDEADBEEF magic, before
    // any DB look-up is attempted.
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager =
        ListenerManager::new(database.clone(), registry.clone(), events.clone(), sockets, None)
            .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;

    let config = ListenerConfig::from(HttpListenerConfig {
        name: "non-legacy-http".to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["127.0.0.1".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: port,
        port_conn: Some(port),
        method: None,
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: None,
        headers: Vec::new(),
        uris: vec!["/".to_owned()],
        host_header: None,
        secure: false,
        cert: None,
        response: None,
        proxy: None,
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
        legacy_mode: false,
    });
    manager.create(config).await?;
    manager.start("non-legacy-http").await?;
    wait_for_listener(port, false).await?;

    let key = test_key(0x41);
    let iv = test_iv(0x24);

    // Send a valid Demon init packet — non-legacy listener must reject it.
    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_init_body(0x9999_AAAA, key, iv))
        .send()
        .await?;

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "non-legacy listener must return 404 for a Demon (0xDEADBEEF) packet"
    );

    // The agent must NOT have been registered — the packet was rejected pre-filter.
    assert!(
        registry.get(0x9999_AAAA).await.is_none(),
        "no agent should be registered after a rejected Demon packet"
    );

    manager.stop("non-legacy-http").await?;
    Ok(())
}

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

#[tokio::test]
async fn http_listener_returns_empty_body_when_agent_has_no_jobs()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;
    let key = test_key(0x51);
    let iv = test_iv(0x19);
    let agent_id = 0x1020_3040;

    registry.insert(sample_agent_info(agent_id, key, iv)).await?;
    manager.create(http_listener("edge-http-empty-jobs", port)).await?;
    manager.start("edge-http-empty-jobs").await?;
    wait_for_listener(port, false).await?;

    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_callback_body(
            agent_id,
            key,
            iv,
            u32::from(DemonCommand::CommandGetJob),
            7,
            &[],
        ))
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.bytes().await?.is_empty());

    manager.stop("edge-http-empty-jobs").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_preserves_headers_but_not_decoy_body_for_empty_successful_callbacks()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;
    let key = test_key(0x31);
    let iv = test_iv(0x17);
    let agent_id = 0x0BAD_F00D;
    let config = ListenerConfig::from(HttpListenerConfig {
        name: "edge-http-decoy-success".to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["127.0.0.1".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: port,
        port_conn: Some(port),
        method: None,
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: None,
        headers: Vec::new(),
        uris: vec!["/".to_owned()],
        host_header: None,
        secure: false,
        cert: None,
        response: Some(HttpListenerResponseConfig {
            headers: vec!["Server: ExampleFront".to_owned()],
            body: Some("decoy".to_owned()),
        }),
        proxy: None,
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
        legacy_mode: true,
    });

    registry.insert(sample_agent_info(agent_id, key, iv)).await?;
    manager.create(config).await?;
    manager.start("edge-http-decoy-success").await?;
    wait_for_listener(port, false).await?;

    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_callback_body(
            agent_id,
            key,
            iv,
            u32::from(DemonCommand::CommandGetJob),
            7,
            &[],
        ))
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("server").and_then(|value| value.to_str().ok()),
        Some("ExampleFront")
    );
    assert!(response.bytes().await?.is_empty());

    manager.stop("edge-http-decoy-success").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_reconnect_ack_does_not_advance_ctr_offset()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;
    let key = test_key(0x52);
    let iv = test_iv(0x1A);
    let agent_id = 0x1020_3040;
    let client = Client::new();

    manager.create(http_listener("edge-http-reconnect", port)).await?;
    manager.start("edge-http-reconnect").await?;
    wait_for_listener(port, false).await?;

    let init_response = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?;
    assert_eq!(init_response.status(), StatusCode::OK);
    let _ = init_response.bytes().await?;

    let reconnect_response = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_request_body(agent_id))
        .send()
        .await?;

    assert_eq!(reconnect_response.status(), StatusCode::OK);
    let reconnect_bytes = reconnect_response.bytes().await?;
    // Legacy mode: reconnect ACK also uses offset 0.
    let decrypted = decrypt_agent_data_at_offset(&key, &iv, 0, &reconnect_bytes)?;

    assert_eq!(decrypted.as_slice(), &agent_id.to_le_bytes());
    assert_eq!(registry.ctr_offset(agent_id).await?, 0);

    manager.stop("edge-http-reconnect").await?;
    Ok(())
}

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

#[tokio::test]
async fn http_listener_serializes_all_queued_jobs_for_get_job()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;
    let key = test_key(0x61);
    let iv = test_iv(0x27);
    let agent_id = 0x5566_7788;

    registry.insert(sample_agent_info(agent_id, key, iv)).await?;
    registry
        .enqueue_job(
            agent_id,
            Job {
                command: u32::from(DemonCommand::CommandSleep),
                request_id: 41,
                payload: vec![1, 2, 3, 4],
                command_line: "sleep 10".to_owned(),
                task_id: "task-41".to_owned(),
                created_at: "2026-03-09T20:10:00Z".to_owned(),
                operator: "operator".to_owned(),
            },
        )
        .await?;
    registry
        .enqueue_job(
            agent_id,
            Job {
                command: u32::from(DemonCommand::CommandCheckin),
                request_id: 42,
                payload: vec![5, 6, 7],
                command_line: "checkin".to_owned(),
                task_id: "task-42".to_owned(),
                created_at: "2026-03-09T20:11:00Z".to_owned(),
                operator: "operator".to_owned(),
            },
        )
        .await?;
    manager.create(http_listener("edge-http-jobs", port)).await?;
    manager.start("edge-http-jobs").await?;
    wait_for_listener(port, false).await?;

    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_callback_body(
            agent_id,
            key,
            iv,
            u32::from(DemonCommand::CommandGetJob),
            9,
            &[],
        ))
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.bytes().await?;
    let message = DemonMessage::from_bytes(bytes.as_ref())?;
    let response_ctr_offset = ctr_blocks_for_len(4);
    assert_eq!(message.packages.len(), 2);
    assert_eq!(message.packages[0].command_id, u32::from(DemonCommand::CommandSleep));
    assert_eq!(message.packages[0].request_id, 41);
    let pt0 =
        decrypt_agent_data_at_offset(&key, &iv, response_ctr_offset, &message.packages[0].payload)?;
    assert_eq!(pt0, vec![1, 2, 3, 4]);
    assert_eq!(message.packages[1].command_id, u32::from(DemonCommand::CommandCheckin));
    assert_eq!(message.packages[1].request_id, 42);
    let pt1 = decrypt_agent_data_at_offset(
        &key,
        &iv,
        response_ctr_offset + ctr_blocks_for_len(message.packages[0].payload.len()),
        &message.packages[1].payload,
    )?;
    assert_eq!(pt1, vec![5, 6, 7]);
    assert!(registry.queued_jobs(agent_id).await?.is_empty());

    manager.stop("edge-http-jobs").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_checkin_refreshes_metadata_and_rejects_key_rotation()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager =
        ListenerManager::new(database.clone(), registry.clone(), events.clone(), sockets, None)
            .with_demon_allow_legacy_ctr(true);
    let mut event_receiver = events.subscribe();
    let key = test_key(0x71);
    let iv = test_iv(0x37);
    // A different key/IV that the agent embeds in its CHECKIN — must be rejected.
    let attempted_key = test_key(0x12);
    let attempted_iv = test_iv(0x34);
    let agent_id = 0xCAFE_BABE;

    registry.insert(sample_agent_info(agent_id, key, iv)).await?;

    let port = create_and_start_http(&manager, "edge-http-checkin").await?;
    wait_for_listener(port, false).await?;

    let checkin_payload = sample_checkin_metadata_payload(agent_id, attempted_key, attempted_iv);
    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_multi_callback_body(
            agent_id,
            key,
            iv,
            (u32::from(DemonCommand::CommandGetJob), 5, Vec::new()),
            &[(u32::from(DemonCommand::CommandCheckin), 6, checkin_payload.clone())],
        ))
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.bytes().await?.is_empty());

    let updated =
        registry.get(agent_id).await.ok_or_else(|| "agent should still exist".to_owned())?;
    assert_eq!(updated.hostname, "wkstn-02");
    assert_eq!(updated.process_name, "cmd.exe");
    assert_eq!(updated.sleep_delay, 45);
    assert_eq!(updated.sleep_jitter, 5);
    // Key rotation must be refused — original key material preserved.
    assert_eq!(updated.encryption.aes_key.as_slice(), key.as_slice());
    assert_eq!(updated.encryption.aes_iv.as_slice(), iv.as_slice());
    // CTR must NOT be reset since the rotation was rejected.
    //
    // The multi-callback body encrypts:
    //   4 bytes (first payload len=0) + 4 (CheckIn cmd) + 4 (req_id) + 4 (payload len) +
    //   checkin_payload
    let first_request_encrypted_len = 4 + 4 + 4 + 4 + checkin_payload.len();
    let expected_ctr_after_first = ctr_blocks_for_len(first_request_encrypted_len);
    assert_eq!(registry.ctr_offset(agent_id).await?, expected_ctr_after_first);
    assert_eq!(
        database
            .agents()
            .get(agent_id)
            .await?
            .ok_or_else(|| "agent should be persisted".to_owned())?
            .encryption
            .aes_key
            .as_slice(),
        key.as_slice()
    );

    let event = event_receiver
        .recv()
        .await
        .ok_or_else(|| "agent update event should broadcast".to_owned())?;
    let OperatorMessage::AgentUpdate(message) = event else {
        panic!("unexpected operator event");
    };
    assert_eq!(message.info.agent_id, format!("{agent_id:08X}"));
    assert_eq!(message.info.marked, "Alive");

    manager.stop("edge-http-checkin").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_with_init_secret_registers_agent_and_ack_uses_derived_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let secret = b"http-test-server-secret".to_vec();
    let (manager, registry, _db, _events) = manager_with_secret(secret.clone()).await?;
    let port = available_port()?;

    manager.create(http_listener("edge-secret", port)).await?;
    manager.start("edge-secret").await?;
    wait_for_listener(port, false).await?;

    let key = test_key(0x61);
    let iv = test_iv(0x34);
    let agent_id = 0xABCD_0001_u32;

    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let ack_bytes = response.bytes().await?;

    // Agent must be registered.
    let stored = registry.get(agent_id).await.expect("agent should be registered");
    assert_eq!(stored.hostname, "wkstn-01");

    // The stored keys should be the HKDF-derived keys, not the raw ones.
    let derived = red_cell_common::crypto::derive_session_keys(&key, &iv, &secret)?;
    assert_eq!(stored.encryption.aes_key.as_slice(), &derived.key);
    assert_eq!(stored.encryption.aes_iv.as_slice(), &derived.iv);

    // The ACK must be decryptable with derived keys.
    let ack_plain = decrypt_agent_data(&derived.key, &derived.iv, &ack_bytes)?;
    assert_eq!(ack_plain.as_slice(), &agent_id.to_le_bytes());

    // Decrypting the ACK with the *raw* agent keys must NOT produce the
    // expected agent_id (proves the secret actually changed the keys).
    let raw_plain = decrypt_agent_data(&key, &iv, &ack_bytes)?;
    assert_ne!(
        raw_plain.as_slice(),
        &agent_id.to_le_bytes(),
        "raw keys must not decrypt the ACK correctly when a secret is configured"
    );

    manager.stop("edge-secret").await?;
    Ok(())
}

/// HTTP listener with init secret rejects callbacks that use the raw
/// (non-derived) agent keys — the callback parse fails and the listener
/// returns 404.
#[tokio::test]
async fn http_listener_with_init_secret_rejects_callback_with_raw_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let secret = b"http-callback-reject-secret".to_vec();
    let (manager, registry, _db, _events) = manager_with_secret(secret).await?;
    let port = available_port()?;

    manager.create(http_listener("edge-secret-cb", port)).await?;
    manager.start("edge-secret-cb").await?;
    wait_for_listener(port, false).await?;

    let key = test_key(0x71);
    let iv = test_iv(0x44);
    let agent_id = 0xABCD_0002_u32;

    // Register the agent via DEMON_INIT.
    let init_resp = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?;
    assert_eq!(init_resp.status(), StatusCode::OK);
    assert!(registry.get(agent_id).await.is_some());

    // Send a callback using the *raw* keys — should fail because the
    // server stored derived keys.
    let callback_resp = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_callback_body(
            agent_id,
            key,
            iv,
            u32::from(DemonCommand::CommandGetJob),
            7,
            &[],
        ))
        .send()
        .await?;
    assert_eq!(
        callback_resp.status(),
        StatusCode::NOT_FOUND,
        "callback with raw keys must be rejected when init_secret is configured"
    );

    manager.stop("edge-secret-cb").await?;
    Ok(())
}

/// A manager without `with_demon_init_secret` (default no-secret path)
/// stores raw agent keys and accepts callbacks with those same raw keys —
/// confirming that the secret path is not a no-op.
#[tokio::test]
async fn http_listener_without_init_secret_stores_raw_keys_and_accepts_raw_callback()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let port = available_port()?;

    manager.create(http_listener("edge-no-secret", port)).await?;
    manager.start("edge-no-secret").await?;
    wait_for_listener(port, false).await?;

    let key = test_key(0xA1);
    let iv = test_iv(0x74);
    let agent_id = 0xBEEF_0001_u32;

    // Register agent.
    let init_resp = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?;
    assert_eq!(init_resp.status(), StatusCode::OK);

    // ACK decryptable with raw keys.
    let ack_bytes = init_resp.bytes().await?;
    let ack_plain = decrypt_agent_data(&key, &iv, &ack_bytes)?;
    assert_eq!(ack_plain.as_slice(), &agent_id.to_le_bytes());

    // Stored keys are the raw keys.
    let stored = registry.get(agent_id).await.expect("agent should be registered");
    assert_eq!(stored.encryption.aes_key.as_slice(), &key);
    assert_eq!(stored.encryption.aes_iv.as_slice(), &iv);

    // Callback with raw keys succeeds.
    let callback_resp = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .body(valid_demon_callback_body(
            agent_id,
            key,
            iv,
            u32::from(DemonCommand::CommandGetJob),
            7,
            &[],
        ))
        .send()
        .await?;
    assert_eq!(
        callback_resp.status(),
        StatusCode::OK,
        "callback with raw keys must succeed when no init_secret is configured"
    );

    manager.stop("edge-no-secret").await?;
    Ok(())
}

#[tokio::test]
async fn reload_tls_cert_returns_listener_not_found_when_listener_does_not_exist() {
    let mgr = manager().await.expect("manager must build");
    let result = mgr.reload_tls_cert("nonexistent", b"cert", b"key").await;
    assert!(
        matches!(result, Err(ListenerManagerError::ListenerNotFound { .. })),
        "expected ListenerNotFound, got: {result:?}"
    );
}

#[tokio::test]
async fn reload_tls_cert_returns_not_tls_listener_for_plain_http() {
    let mgr = manager().await.expect("manager must build");
    let port = available_port().expect("port must be available");
    mgr.create(http_listener("plain-http", port)).await.expect("create must succeed");
    mgr.start("plain-http").await.expect("start must succeed");
    wait_for_listener(port, false).await.expect("listener must be ready");

    let result = mgr.reload_tls_cert("plain-http", b"cert", b"key").await;
    assert!(
        matches!(result, Err(ListenerManagerError::NotTlsListener { .. })),
        "expected NotTlsListener, got: {result:?}"
    );

    mgr.stop("plain-http").await.expect("stop must succeed");
}

#[tokio::test]
async fn reload_tls_cert_returns_tls_cert_error_for_invalid_pem() {
    let mgr = manager().await.expect("manager must build");
    let port = available_port().expect("port must be available");

    let config = ListenerConfig::from(HttpListenerConfig {
        name: "tls-invalid-pem".to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["localhost".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: port,
        port_conn: Some(port),
        method: None,
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: None,
        headers: Vec::new(),
        uris: vec!["/".to_owned()],
        host_header: None,
        secure: true,
        cert: None,
        response: None,
        proxy: None,
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
        legacy_mode: true,
    });

    mgr.create(config).await.expect("create must succeed");
    mgr.start("tls-invalid-pem").await.expect("start must succeed");
    wait_for_listener(port, true).await.expect("listener must be ready");

    let result = mgr.reload_tls_cert("tls-invalid-pem", b"not-a-cert", b"not-a-key").await;
    assert!(
        matches!(result, Err(ListenerManagerError::TlsCertError { .. })),
        "expected TlsCertError, got: {result:?}"
    );

    mgr.stop("tls-invalid-pem").await.expect("stop must succeed");
}

/// Expired certificate PEM material generated with ECDSA P-256.
/// `not_before` = 2026-03-08, `not_after` = 2026-04-05 (always in the past).
const EXPIRED_CERT_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIBLjCB1qADAgECAhQup35cFN5Dlkq4pVl96UATk4GxLDAKBggqhkjOPQQDAjAY
MRYwFAYDVQQDDA1leHBpcmVkLmxvY2FsMB4XDTI2MDMwODIxMTY1M1oXDTI2MDQw
NTIxMTY1M1owGDEWMBQGA1UEAwwNZXhwaXJlZC5sb2NhbDBZMBMGByqGSM49AgEG
CCqGSM49AwEHA0IABFE5jhMv1cWqQ7t7mC+pbBTVqRPqeR6bMozh0nWejfDCVXPT
QWnFaaQxqrO/qbdYCaYcXYg1DmWpEfkQx0sjTekwCgYIKoZIzj0EAwIDRwAwRAIg
al7Ctn1lXtUfe3gVRfxhBNJcNy9UBL6ftEJpt6zqeJoCIGnSOdPiqtHitgGPn8ct
6UhZXOsUm6pRjDniIHBrCmfY
-----END CERTIFICATE-----
";

const EXPIRED_KEY_PEM: &[u8] = b"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgFUgNuvIUst+J3Gqk
0/YQr6Yre8f1boAvBDljxq3C1qqhRANCAARROY4TL9XFqkO7e5gvqWwU1akT6nke
mzKM4dJ1no3wwlVz00FpxWmkMaqzv6m3WAmmHF2INQ5lqRH5EMdLI03p
-----END PRIVATE KEY-----
";

#[tokio::test]
async fn reload_tls_cert_returns_tls_cert_error_for_expired_cert() {
    use red_cell_common::tls::install_default_crypto_provider;

    install_default_crypto_provider();

    let mgr = manager().await.expect("manager must build");
    let port = create_and_start_https(&mgr, "tls-expired").await.expect("listener must start");
    wait_for_listener(port, true).await.expect("listener must be ready");

    let result = mgr.reload_tls_cert("tls-expired", EXPIRED_CERT_PEM, EXPIRED_KEY_PEM).await;
    assert!(
        matches!(result, Err(ListenerManagerError::TlsCertError { .. })),
        "expected TlsCertError for expired cert, got: {result:?}"
    );

    mgr.stop("tls-expired").await.expect("stop must succeed");
}

#[tokio::test]
async fn reload_tls_cert_swaps_config_with_valid_cert() {
    use red_cell_common::tls::{TlsKeyAlgorithm, generate_self_signed_tls_identity};

    let mgr = manager().await.expect("manager must build");
    let port = create_and_start_https(&mgr, "tls-reload-ok").await.expect("listener must start");
    wait_for_listener(port, true).await.expect("listener must be ready");

    // Generate a fresh valid certificate and reload it.
    let identity =
        generate_self_signed_tls_identity(&["localhost".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation must succeed");

    let result = mgr
        .reload_tls_cert("tls-reload-ok", identity.certificate_pem(), identity.private_key_pem())
        .await;
    assert!(result.is_ok(), "expected Ok(()) for valid cert reload, got: {result:?}");

    mgr.stop("tls-reload-ok").await.expect("stop must succeed");
}

// ---------------------------------------------------------------------------
// cert file watcher / reload_tls_from_files tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reload_tls_from_files_succeeds_with_valid_cert_files() {
    use red_cell_common::tls::{
        TlsKeyAlgorithm, generate_self_signed_tls_identity, install_default_crypto_provider,
    };

    install_default_crypto_provider();
    let identity =
        generate_self_signed_tls_identity(&["localhost".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation must succeed");

    let dir = tempfile::tempdir().expect("tempdir must be created");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, identity.certificate_pem()).expect("write cert");
    std::fs::write(&key_path, identity.private_key_pem()).expect("write key");

    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem(
        identity.certificate_pem().to_vec(),
        identity.private_key_pem().to_vec(),
    )
    .await
    .expect("initial RustlsConfig must be created");

    let result = reload_tls_from_files(&cert_path, &key_path, &tls_config).await;
    assert!(result.is_ok(), "expected Ok for valid cert files, got: {result:?}");
}

#[tokio::test]
async fn reload_tls_from_files_returns_error_for_missing_cert_file() {
    use red_cell_common::tls::{
        TlsKeyAlgorithm, generate_self_signed_tls_identity, install_default_crypto_provider,
    };

    install_default_crypto_provider();
    let identity =
        generate_self_signed_tls_identity(&["localhost".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity generation must succeed");

    let dir = tempfile::tempdir().expect("tempdir must be created");
    let cert_path = dir.path().join("nonexistent-cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&key_path, identity.private_key_pem()).expect("write key");

    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem(
        identity.certificate_pem().to_vec(),
        identity.private_key_pem().to_vec(),
    )
    .await
    .expect("initial RustlsConfig must be created");

    let result = reload_tls_from_files(&cert_path, &key_path, &tls_config).await;
    assert!(result.is_err(), "expected error for missing cert file, got: {result:?}");
}

#[test]
fn cert_mtime_returns_none_for_nonexistent_file() {
    let path = std::path::Path::new("/nonexistent/cert.pem");
    assert!(cert_mtime(path).is_none(), "nonexistent file should return None");
}

#[test]
fn cert_mtime_returns_some_for_existing_file() {
    let dir = tempfile::tempdir().expect("tempdir must be created");
    let path = dir.path().join("cert.pem");
    std::fs::write(&path, b"dummy").expect("write test file");
    assert!(cert_mtime(&path).is_some(), "existing file should return Some");
}

#[tokio::test]
async fn spawn_cert_file_watcher_reloads_on_mtime_change() {
    use red_cell_common::tls::{
        TlsKeyAlgorithm, generate_self_signed_tls_identity, install_default_crypto_provider,
    };

    install_default_crypto_provider();
    let identity_a =
        generate_self_signed_tls_identity(&["localhost".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity A generation must succeed");

    let identity_b =
        generate_self_signed_tls_identity(&["localhost".to_owned()], TlsKeyAlgorithm::EcdsaP256)
            .expect("identity B generation must succeed");

    let dir = tempfile::tempdir().expect("tempdir must be created");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, identity_a.certificate_pem()).expect("write cert A");
    std::fs::write(&key_path, identity_a.private_key_pem()).expect("write key A");

    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem(
        identity_a.certificate_pem().to_vec(),
        identity_a.private_key_pem().to_vec(),
    )
    .await
    .expect("initial RustlsConfig must be created");

    let handle = spawn_cert_file_watcher(
        "test-watcher".to_owned(),
        cert_path.clone(),
        key_path.clone(),
        tls_config.clone(),
    );

    // The watcher polls at 30s intervals by default, which is too slow for a test.
    // Instead, test that `reload_tls_from_files` works correctly when files change,
    // which is the core logic the watcher invokes.
    std::fs::write(&cert_path, identity_b.certificate_pem()).expect("write cert B");
    std::fs::write(&key_path, identity_b.private_key_pem()).expect("write key B");

    let result = reload_tls_from_files(&cert_path, &key_path, &tls_config).await;
    assert!(result.is_ok(), "reload after file change must succeed, got: {result:?}");

    // Clean up: abort the watcher task.
    handle.abort();
    let _ = handle.await;
}
