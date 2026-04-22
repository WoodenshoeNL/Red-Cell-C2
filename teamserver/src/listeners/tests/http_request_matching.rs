use super::super::MAX_AGENT_MESSAGE_LEN;
use super::*;
use axum::http::StatusCode;
use red_cell_common::HttpListenerResponseConfig;
use red_cell_common::crypto::decrypt_agent_data;

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
        suppress_opsec_warnings: true,
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
        suppress_opsec_warnings: true,
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
