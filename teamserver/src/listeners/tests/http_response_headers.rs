use super::*;
use axum::http::StatusCode;
use red_cell_common::HttpListenerResponseConfig;
use red_cell_common::crypto::decrypt_agent_data_at_offset;
use red_cell_common::demon::{DemonCommand, DemonMessage};

#[tokio::test]
async fn http_listener_returns_no_job_when_agent_has_no_queued_tasks()
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
    let bytes = response.bytes().await?;
    // Server must always return DEMON_COMMAND_NO_JOB (not empty) so the Demon
    // agent's CommandDispatcher loop keeps running and reaches JobCheckList().
    let msg = DemonMessage::from_bytes(&bytes)?;
    assert_eq!(msg.packages.len(), 1);
    assert_eq!(msg.packages[0].command_id, u32::from(DemonCommand::CommandNoJob));
    assert_eq!(msg.packages[0].request_id, 7);
    assert!(msg.packages[0].payload.is_empty());

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
        suppress_opsec_warnings: true,
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
    // The response body is the DEMON_COMMAND_NO_JOB package, not the decoy body.
    let bytes = response.bytes().await?;
    let msg = DemonMessage::from_bytes(&bytes)?;
    assert_eq!(msg.packages.len(), 1);
    assert_eq!(msg.packages[0].command_id, u32::from(DemonCommand::CommandNoJob));

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
