use super::super::{MAX_AGENT_MESSAGE_LEN, collect_body_with_magic_precheck};
use super::*;
use axum::body::Body;
use axum::http::StatusCode;
use red_cell_common::demon::DEMON_MAGIC_VALUE;

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
async fn non_legacy_precheck_accepts_body_with_deadbeef_at_bytes_4_7() {
    // Non-legacy listeners must NOT reject bodies with 0xDEADBEEF at bytes 4–7.
    // For Archon packets bytes 4–7 are agent_id, and for ECDH packets they are part of
    // the random connection_id — neither is a magic field.  See hxg94.
    let body = valid_demon_request_body(0x1234_5678);
    let result =
        collect_body_with_magic_precheck(Body::from(body.clone()), MAX_AGENT_MESSAGE_LEN, false)
            .await;
    assert!(
        result.is_some(),
        "non-legacy precheck must not reject bodies with 0xDEADBEEF at bytes 4-7"
    );
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
        suppress_opsec_warnings: true,
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
