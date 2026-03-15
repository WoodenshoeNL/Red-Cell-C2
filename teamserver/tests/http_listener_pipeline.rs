mod common;

use std::time::Duration;

use red_cell::{AgentRegistry, Database, EventBus, ListenerManager, SocketRelayManager};
use red_cell_common::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len, decrypt_agent_data_at_offset,
};
use red_cell_common::demon::{DemonCommand, DemonEnvelope};
use red_cell_common::operator::OperatorMessage;
use red_cell_common::{HttpListenerConfig, ListenerConfig};
use reqwest::Client;
use tokio::time::timeout;

#[tokio::test]
async fn http_listener_pipeline_registers_agent_and_broadcasts_checkin()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events.clone(), sockets, None);
    let mut event_receiver = events.subscribe();
    let port = common::available_port()?;
    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    let agent_id = 0x1234_5678;
    let mut ctr_offset = 0_u64;

    manager.create(http_listener("edge-http-pipeline", port)).await?;
    manager.start("edge-http-pipeline").await?;
    common::wait_for_listener(port).await?;

    let client = Client::new();
    let init_response = client
        .post(format!("http://127.0.0.1:{port}/"))
        .header("x-real-ip", "198.51.100.44")
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let init_ack = init_response.bytes().await?;

    let decrypted_ack = decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &init_ack)?;
    assert_eq!(decrypted_ack.as_slice(), &agent_id.to_le_bytes());
    ctr_offset += ctr_blocks_for_len(init_ack.len());

    let stored = registry.get(agent_id).await.ok_or("agent should be registered")?;
    let before_checkin = stored.last_call_in.clone();
    assert_eq!(stored.hostname, "wkstn-01");
    assert_eq!(stored.external_ip, "127.0.0.1");

    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    let Some(OperatorMessage::AgentNew(message)) = event else {
        panic!("expected agent registration event");
    };
    assert_eq!(message.info.name_id, "12345678");
    assert_eq!(message.info.listener, "edge-http-pipeline");
    assert_eq!(message.info.external_ip, "127.0.0.1");

    let checkin_response = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(common::valid_demon_callback_body(
            agent_id,
            key,
            iv,
            ctr_offset,
            u32::from(DemonCommand::CommandCheckin),
            6,
            &[],
        ))
        .send()
        .await?
        .error_for_status()?;
    assert!(checkin_response.bytes().await?.is_empty());

    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    let Some(OperatorMessage::AgentUpdate(message)) = event else {
        panic!("expected agent checkin event");
    };
    assert_eq!(message.info.agent_id, "12345678");
    assert_eq!(message.info.marked, "Alive");

    let updated = registry.get(agent_id).await.ok_or("agent should remain registered")?;
    assert_ne!(updated.last_call_in, before_checkin);

    manager.stop("edge-http-pipeline").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_pipeline_rejects_plaintext_zero_key_init()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None);
    let port = common::available_port()?;
    let agent_id = 0x1357_9BDF;

    manager.create(http_listener("edge-http-zero-key", port)).await?;
    manager.start("edge-http-zero-key").await?;
    common::wait_for_listener(port).await?;

    let client = Client::new();
    let response = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(plaintext_zero_key_demon_init_body(agent_id))
        .send()
        .await?;

    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
    assert!(registry.get(agent_id).await.is_none(), "zero-key init must not register");

    manager.stop("edge-http-zero-key").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_pipeline_rejects_callbacks_from_unregistered_agent()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None);
    let port = common::available_port()?;
    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    let agent_id = 0xCAFE_BABE;

    manager.create(http_listener("edge-http-unknown-agent", port)).await?;
    manager.start("edge-http-unknown-agent").await?;
    common::wait_for_listener(port).await?;

    let client = Client::new();

    for (command_id, request_id) in
        [(u32::from(DemonCommand::CommandGetJob), 6), (u32::from(DemonCommand::CommandCheckin), 7)]
    {
        let response = client
            .post(format!("http://127.0.0.1:{port}/"))
            .body(common::valid_demon_callback_body(
                agent_id,
                key,
                iv,
                0,
                command_id,
                request_id,
                &[],
            ))
            .send()
            .await?;

        assert_eq!(
            response.status(),
            reqwest::StatusCode::NOT_FOUND,
            "unexpected status for callback command {command_id:#x}"
        );
        assert!(
            registry.get(agent_id).await.is_none(),
            "unknown callback command {command_id:#x} must not create registry state"
        );
        assert!(
            registry.list_active().await.is_empty(),
            "unknown callback command {command_id:#x} must not register an active agent"
        );
    }

    manager.stop("edge-http-unknown-agent").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_pipeline_attributes_real_ip_from_trusted_redirector()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None);
    let port = common::available_port()?;
    let agent_id = 0xABCD_1234;

    manager
        .create(http_listener_with_redirector(
            "edge-http-trusted-redirector",
            port,
            vec!["127.0.0.1".to_owned()],
        ))
        .await?;
    manager.start("edge-http-trusted-redirector").await?;
    common::wait_for_listener(port).await?;

    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .header("x-real-ip", "198.51.100.44")
        .body(common::valid_demon_init_body(
            agent_id,
            [0x41; AGENT_KEY_LENGTH],
            [0x24; AGENT_IV_LENGTH],
        ))
        .send()
        .await?
        .error_for_status()?;
    assert!(!response.bytes().await?.is_empty());

    let stored = registry.get(agent_id).await.ok_or("agent should be registered")?;
    assert_eq!(stored.external_ip, "198.51.100.44");

    manager.stop("edge-http-trusted-redirector").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_pipeline_ignores_real_ip_from_untrusted_redirector()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None);
    let port = common::available_port()?;
    let agent_id = 0xABCD_5678;

    manager
        .create(http_listener_with_redirector(
            "edge-http-untrusted-redirector",
            port,
            vec!["192.0.2.1".to_owned()],
        ))
        .await?;
    manager.start("edge-http-untrusted-redirector").await?;
    common::wait_for_listener(port).await?;

    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .header("x-real-ip", "198.51.100.44")
        .body(common::valid_demon_init_body(
            agent_id,
            [0x41; AGENT_KEY_LENGTH],
            [0x24; AGENT_IV_LENGTH],
        ))
        .send()
        .await?
        .error_for_status()?;
    assert!(!response.bytes().await?.is_empty());

    let stored = registry.get(agent_id).await.ok_or("agent should be registered")?;
    assert_eq!(stored.external_ip, "127.0.0.1");

    manager.stop("edge-http-untrusted-redirector").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_pipeline_ignores_forwarded_for_when_not_behind_redirector()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None);
    let port = common::available_port()?;
    let agent_id = 0xF0F0_A0D1_u32;

    // Listener with behind_redirector=false — no proxy headers should ever be trusted.
    manager.create(http_listener("edge-http-xff-no-redirector", port)).await?;
    manager.start("edge-http-xff-no-redirector").await?;
    common::wait_for_listener(port).await?;

    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        // Attacker-injected X-Forwarded-For header claiming a spoofed source IP.
        .header("x-forwarded-for", "1.2.3.4")
        .body(common::valid_demon_init_body(
            agent_id,
            [0x41; AGENT_KEY_LENGTH],
            [0x24; AGENT_IV_LENGTH],
        ))
        .send()
        .await?
        .error_for_status()?;
    assert!(!response.bytes().await?.is_empty());

    let stored = registry.get(agent_id).await.ok_or("agent should be registered")?;
    assert_eq!(
        stored.external_ip, "127.0.0.1",
        "X-Forwarded-For must be ignored when behind_redirector=false; got {}",
        stored.external_ip
    );

    manager.stop("edge-http-xff-no-redirector").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_pipeline_ignores_forwarded_for_from_untrusted_peer()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None);
    let port = common::available_port()?;
    let agent_id = 0xF0F0_B0D2_u32;

    // Listener with behind_redirector=true but TrustedProxyPeers set to a *different* address
    // (192.0.2.1), so the connecting peer (127.0.0.1) is untrusted.
    manager
        .create(http_listener_with_redirector(
            "edge-http-xff-untrusted-peer",
            port,
            vec!["192.0.2.1".to_owned()],
        ))
        .await?;
    manager.start("edge-http-xff-untrusted-peer").await?;
    common::wait_for_listener(port).await?;

    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        // Attacker-injected X-Forwarded-For header from an untrusted peer.
        .header("x-forwarded-for", "1.2.3.4")
        .body(common::valid_demon_init_body(
            agent_id,
            [0x41; AGENT_KEY_LENGTH],
            [0x24; AGENT_IV_LENGTH],
        ))
        .send()
        .await?
        .error_for_status()?;
    assert!(!response.bytes().await?.is_empty());

    let stored = registry.get(agent_id).await.ok_or("agent should be registered")?;
    assert_eq!(
        stored.external_ip, "127.0.0.1",
        "X-Forwarded-For must be ignored when peer is not in TrustedProxyPeers; got {}",
        stored.external_ip
    );

    manager.stop("edge-http-xff-untrusted-peer").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_pipeline_rejects_duplicate_init_preserves_original_key()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None);
    let port = common::available_port()?;
    let agent_id = 0xDEAD_C0DE;
    let original_key = [0x41_u8; AGENT_KEY_LENGTH];
    let original_iv = [0x24_u8; AGENT_IV_LENGTH];
    let hijack_key = [0xBB_u8; AGENT_KEY_LENGTH];
    let hijack_iv = [0xCC_u8; AGENT_IV_LENGTH];

    manager.create(http_listener("edge-http-dup-init", port)).await?;
    manager.start("edge-http-dup-init").await?;
    common::wait_for_listener(port).await?;

    let client = Client::new();

    // First INIT — must succeed.
    client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(common::valid_demon_init_body(agent_id, original_key, original_iv))
        .send()
        .await?
        .error_for_status()?;

    let stored_after_first =
        registry.get(agent_id).await.ok_or("agent should be registered after first init")?;
    assert_eq!(stored_after_first.encryption.aes_key.as_slice(), &original_key);

    // Second INIT with the same agent_id but attacker-controlled key material — must be rejected.
    let replay_response = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(common::valid_demon_init_body(agent_id, hijack_key, hijack_iv))
        .send()
        .await?;

    assert_eq!(
        replay_response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "duplicate DemonInit must be rejected with 404"
    );

    // The original key must still be in place — the hijack attempt must not overwrite it.
    let stored_after_replay = registry
        .get(agent_id)
        .await
        .ok_or("agent should still be registered after rejected replay")?;
    assert_eq!(
        stored_after_replay.encryption.aes_key.as_slice(),
        &original_key,
        "original AES key must not be overwritten by a duplicate init"
    );
    assert_eq!(
        stored_after_replay.encryption.aes_iv.as_slice(),
        &original_iv,
        "original AES IV must not be overwritten by a duplicate init"
    );

    // No duplicate registration: exactly one active entry must exist.
    let active = registry.list_active().await;
    assert_eq!(active.len(), 1, "duplicate DemonInit must not create a second registry entry");
    assert_eq!(active[0].agent_id, agent_id);

    manager.stop("edge-http-dup-init").await?;
    Ok(())
}

fn http_listener(name: &str, port: u16) -> ListenerConfig {
    ListenerConfig::from(HttpListenerConfig {
        name: name.to_owned(),
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
        user_agent: None,
        headers: Vec::new(),
        uris: vec!["/".to_owned()],
        host_header: None,
        secure: false,
        cert: None,
        response: None,
        proxy: None,
    })
}

fn http_listener_with_redirector(
    name: &str,
    port: u16,
    trusted_proxy_peers: Vec<String>,
) -> ListenerConfig {
    ListenerConfig::from(HttpListenerConfig {
        name: name.to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["127.0.0.1".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: port,
        port_conn: Some(port),
        method: Some("POST".to_owned()),
        behind_redirector: true,
        trusted_proxy_peers,
        user_agent: None,
        headers: Vec::new(),
        uris: vec!["/".to_owned()],
        host_header: None,
        secure: false,
        cert: None,
        response: None,
        proxy: None,
    })
}

fn plaintext_zero_key_demon_init_body(agent_id: u32) -> Vec<u8> {
    let mut metadata = Vec::new();
    metadata.extend_from_slice(&agent_id.to_be_bytes());
    common::add_length_prefixed_bytes_be(&mut metadata, b"wkstn-01");
    common::add_length_prefixed_bytes_be(&mut metadata, b"operator");
    common::add_length_prefixed_bytes_be(&mut metadata, b"REDCELL");
    common::add_length_prefixed_bytes_be(&mut metadata, b"10.0.0.25");
    common::add_length_prefixed_utf16_be(&mut metadata, "C:\\Windows\\explorer.exe");
    metadata.extend_from_slice(&1337_u32.to_be_bytes());
    metadata.extend_from_slice(&1338_u32.to_be_bytes());
    metadata.extend_from_slice(&512_u32.to_be_bytes());
    metadata.extend_from_slice(&2_u32.to_be_bytes());
    metadata.extend_from_slice(&1_u32.to_be_bytes());
    metadata.extend_from_slice(&0x401000_u64.to_be_bytes());
    metadata.extend_from_slice(&10_u32.to_be_bytes());
    metadata.extend_from_slice(&0_u32.to_be_bytes());
    metadata.extend_from_slice(&1_u32.to_be_bytes());
    metadata.extend_from_slice(&0_u32.to_be_bytes());
    metadata.extend_from_slice(&22000_u32.to_be_bytes());
    metadata.extend_from_slice(&9_u32.to_be_bytes());
    metadata.extend_from_slice(&15_u32.to_be_bytes());
    metadata.extend_from_slice(&20_u32.to_be_bytes());
    metadata.extend_from_slice(&1_893_456_000_u64.to_be_bytes());
    metadata.extend_from_slice(&0b101010_u32.to_be_bytes());

    let payload = [
        u32::from(DemonCommand::DemonInit).to_be_bytes().as_slice(),
        7_u32.to_be_bytes().as_slice(),
        [0_u8; AGENT_KEY_LENGTH].as_slice(),
        [0_u8; AGENT_IV_LENGTH].as_slice(),
        metadata.as_slice(),
    ]
    .concat();

    DemonEnvelope::new(agent_id, payload)
        .unwrap_or_else(|error| panic!("failed to build zero-key init request body: {error}"))
        .to_bytes()
}
