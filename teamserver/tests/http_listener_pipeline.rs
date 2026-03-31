mod common;

use std::time::Duration;

use futures_util::future::join_all;
use red_cell::{
    AgentRegistry, Database, EventBus, ListenerManager, MAX_AGENT_MESSAGE_LEN, SocketRelayManager,
};
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, decrypt_agent_data_at_offset};
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
    let manager = ListenerManager::new(database, registry.clone(), events.clone(), sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let mut event_receiver = events.subscribe();
    let (port, guard) = common::available_port()?;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F,
        0x90,
    ];
    let agent_id = 0x1234_5678;
    let ctr_offset = 0_u64;

    manager.create(http_listener("edge-http-pipeline", port)).await?;
    drop(guard);
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
    // Legacy CTR mode: offset stays at 0.

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
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let (port, guard) = common::available_port()?;
    let agent_id = 0x1357_9BDF;

    manager.create(http_listener("edge-http-zero-key", port)).await?;
    drop(guard);
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
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let (port, guard) = common::available_port()?;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E,
        0x3F, 0x40,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0,
        0x01,
    ];
    let agent_id = 0xCAFE_BABE;

    manager.create(http_listener("edge-http-unknown-agent", port)).await?;
    drop(guard);
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
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let (port, guard) = common::available_port()?;
    let agent_id = 0xABCD_1234;

    manager
        .create(http_listener_with_redirector(
            "edge-http-trusted-redirector",
            port,
            vec!["127.0.0.1".to_owned()],
        ))
        .await?;
    drop(guard);
    manager.start("edge-http-trusted-redirector").await?;
    common::wait_for_listener(port).await?;

    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .header("x-real-ip", "198.51.100.44")
        .body(common::valid_demon_init_body(
            agent_id,
            [
                0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E,
                0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C,
                0x5D, 0x5E, 0x5F, 0x60,
            ],
            [
                0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9A, 0xAB, 0xBC, 0xCD, 0xDE, 0xEF,
                0xF0, 0x01,
            ],
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
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let (port, guard) = common::available_port()?;
    let agent_id = 0xABCD_5678;

    manager
        .create(http_listener_with_redirector(
            "edge-http-untrusted-redirector",
            port,
            vec!["192.0.2.1".to_owned()],
        ))
        .await?;
    drop(guard);
    manager.start("edge-http-untrusted-redirector").await?;
    common::wait_for_listener(port).await?;

    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        .header("x-real-ip", "198.51.100.44")
        .body(common::valid_demon_init_body(
            agent_id,
            [
                0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
                0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C,
                0x7D, 0x7E, 0x7F, 0x80,
            ],
            [
                0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x0F, 0x1E, 0x2D, 0x3C, 0x4B, 0x5A,
                0x69, 0x78,
            ],
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
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let (port, guard) = common::available_port()?;
    let agent_id = 0xF0F0_A0D1_u32;

    // Listener with behind_redirector=false — no proxy headers should ever be trusted.
    manager.create(http_listener("edge-http-xff-no-redirector", port)).await?;
    drop(guard);
    manager.start("edge-http-xff-no-redirector").await?;
    common::wait_for_listener(port).await?;

    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        // Attacker-injected X-Forwarded-For header claiming a spoofed source IP.
        .header("x-forwarded-for", "1.2.3.4")
        .body(common::valid_demon_init_body(
            agent_id,
            [
                0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E,
                0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C,
                0x9D, 0x9E, 0x9F, 0xA0,
            ],
            [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
                0x32, 0x10,
            ],
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
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let (port, guard) = common::available_port()?;
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
    drop(guard);
    manager.start("edge-http-xff-untrusted-peer").await?;
    common::wait_for_listener(port).await?;

    let response = Client::new()
        .post(format!("http://127.0.0.1:{port}/"))
        // Attacker-injected X-Forwarded-For header from an untrusted peer.
        .header("x-forwarded-for", "1.2.3.4")
        .body(common::valid_demon_init_body(
            agent_id,
            [
                0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE,
                0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC,
                0xBD, 0xBE, 0xBF, 0xC0,
            ],
            [
                0xC0, 0xDE, 0xFA, 0xCE, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xD0, 0x0D, 0xDE, 0xAD,
                0xC0, 0xDE,
            ],
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

/// A second DEMON_INIT for an already-registered `agent_id` is treated as a re-registration
/// (agent restart after crash or kill-date reset).  The session key is replaced and the
/// teamserver returns a fresh init ACK.
///
/// The teamserver rejects re-registration with different key material (key-rotation hijack
/// prevention).  This test uses the same keys to simulate a legitimate agent restart.
#[tokio::test]
async fn http_listener_pipeline_reinit_updates_key_material()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let (port, guard) = common::available_port()?;
    let agent_id = 0xDEAD_C0DE;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E,
        0x5F, 0x60,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
        0x33,
    ];

    manager.create(http_listener("edge-http-reinit", port)).await?;
    drop(guard);
    manager.start("edge-http-reinit").await?;
    common::wait_for_listener(port).await?;

    let client = Client::new();

    // First INIT — must succeed and register the key.
    client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;

    let stored_after_first =
        registry.get(agent_id).await.ok_or("agent should be registered after first init")?;
    assert_eq!(stored_after_first.encryption.aes_key.as_slice(), &key);

    // Second INIT (same agent_id, same key material) — legitimate agent restart.
    client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;

    // Key must remain unchanged.
    let stored_after_reinit =
        registry.get(agent_id).await.ok_or("agent should still be registered after re-init")?;
    assert_eq!(
        stored_after_reinit.encryption.aes_key.as_slice(),
        &key,
        "re-init must preserve the session key"
    );
    assert_eq!(
        stored_after_reinit.encryption.aes_iv.as_slice(),
        &iv,
        "re-init must preserve the session IV"
    );

    // Still exactly one active entry.
    let active = registry.list_active().await;
    assert_eq!(active.len(), 1, "re-init must not create a second registry entry");
    assert_eq!(active[0].agent_id, agent_id);

    manager.stop("edge-http-reinit").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_rejects_malformed_and_truncated_bodies()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let (port, guard) = common::available_port()?;

    manager.create(http_listener("edge-http-malformed", port)).await?;
    drop(guard);
    manager.start("edge-http-malformed").await?;
    common::wait_for_listener(port).await?;

    let client = Client::new();
    let url = format!("http://127.0.0.1:{port}/");

    // Case 1: Empty body (zero-length POST).
    let response = client.post(&url).body(Vec::<u8>::new()).send().await?;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "empty body must be rejected with 404"
    );

    // Case 2: Body shorter than minimum envelope length (1–3 bytes).
    for len in 1..=3 {
        let response = client.post(&url).body(vec![0xAA; len]).send().await?;
        assert_eq!(
            response.status(),
            reqwest::StatusCode::NOT_FOUND,
            "body of {len} bytes must be rejected with 404"
        );
    }

    // Case 3: Body with wrong magic number (0xCAFEBABE instead of 0xDEADBEEF).
    // Build a 16-byte buffer: 4-byte size (BE) + 4-byte bad magic + 4-byte agent_id + padding.
    let mut bad_magic_body = Vec::new();
    bad_magic_body.extend_from_slice(&12_u32.to_be_bytes()); // size = rest of packet
    bad_magic_body.extend_from_slice(&0xCAFE_BABE_u32.to_be_bytes()); // wrong magic
    bad_magic_body.extend_from_slice(&0x1111_2222_u32.to_be_bytes()); // agent_id
    bad_magic_body.extend_from_slice(&[0x00; 4]); // padding
    let response = client.post(&url).body(bad_magic_body).send().await?;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "wrong magic number must be rejected with 404"
    );

    // Case 4: Body with correct length prefix but truncated payload.
    // The size field claims 100 bytes follow, but only 8 bytes are present.
    let mut truncated_body = Vec::new();
    truncated_body.extend_from_slice(&100_u32.to_be_bytes()); // size = 100 (lie)
    truncated_body.extend_from_slice(&0xDEAD_BEEF_u32.to_be_bytes()); // correct magic
    truncated_body.extend_from_slice(&0x3333_4444_u32.to_be_bytes()); // agent_id
    // Payload should be 100 - 8 = 92 bytes, but we provide nothing — truncated.
    let response = client.post(&url).body(truncated_body).send().await?;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "truncated payload must be rejected with 404"
    );

    // Verify the listener is still alive and accepting requests after all malformed inputs.
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE,
        0xDF, 0xE0,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x91, 0x82, 0x73, 0x64, 0x55, 0x46, 0x37, 0x28, 0x19, 0x0A, 0xF1, 0xE2, 0xD3, 0xC4, 0xB5,
        0xA6,
    ];
    let agent_id = 0xAAAA_BBBB;
    let valid_response = client
        .post(&url)
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    assert!(
        !valid_response.bytes().await?.is_empty(),
        "valid init must succeed after malformed inputs"
    );
    assert!(
        registry.get(agent_id).await.is_some(),
        "agent must be registered — listener survived malformed inputs"
    );

    manager.stop("edge-http-malformed").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_rejects_oversized_body() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let (port, guard) = common::available_port()?;

    manager.create(http_listener("edge-http-oversized", port)).await?;
    drop(guard);
    manager.start("edge-http-oversized").await?;
    common::wait_for_listener(port).await?;

    let client = Client::new();
    let url = format!("http://127.0.0.1:{port}/");

    // Build a body that exceeds MAX_AGENT_MESSAGE_LEN (30 MiB).
    // Include valid Demon magic at bytes 4–7 so the rejection is due to size, not magic.
    let oversized_len = MAX_AGENT_MESSAGE_LEN + 1;
    let mut oversized_body = vec![0_u8; oversized_len];
    // bytes 0–3: size field (BE) — claim the rest of the packet
    let rest_len = u32::try_from(oversized_len - 4).unwrap_or(u32::MAX);
    oversized_body[0..4].copy_from_slice(&rest_len.to_be_bytes());
    // bytes 4–7: valid Demon magic (0xDEADBEEF BE)
    oversized_body[4..8].copy_from_slice(&0xDEAD_BEEF_u32.to_be_bytes());
    // bytes 8–11: fake agent_id
    oversized_body[8..12].copy_from_slice(&0xBAAD_F00D_u32.to_be_bytes());

    let response = client.post(&url).body(oversized_body).send().await?;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::NOT_FOUND,
        "oversized body must be rejected with 404"
    );

    // The oversized request must not register an agent.
    assert!(registry.get(0xBAAD_F00D).await.is_none(), "oversized body must not register an agent");
    assert!(
        registry.list_active().await.is_empty(),
        "no agent should be active after oversized body"
    );

    // Verify the listener remains responsive after the oversized request.
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE,
        0xFF, 0x00,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19,
    ];
    let valid_agent_id = 0xBBBB_CCCC;
    let valid_response = client
        .post(&url)
        .body(common::valid_demon_init_body(valid_agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    assert!(
        !valid_response.bytes().await?.is_empty(),
        "valid init must succeed after oversized body rejection"
    );
    assert!(
        registry.get(valid_agent_id).await.is_some(),
        "agent must be registered — listener survived oversized body"
    );

    manager.stop("edge-http-oversized").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_pipeline_reconnect_probe_after_registration()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let (port, guard) = common::available_port()?;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x01, 0x03, 0x05, 0x07, 0x09, 0x0B, 0x0D, 0x0F, 0x11, 0x13, 0x15, 0x17, 0x19, 0x1B, 0x1D,
        0x1F, 0x21, 0x23, 0x25, 0x27, 0x29, 0x2B, 0x2D, 0x2F, 0x31, 0x33, 0x35, 0x37, 0x39, 0x3B,
        0x3D, 0x3F,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E,
        0x5F,
    ];
    let agent_id = 0x5678_ABCD;

    manager.create(http_listener("edge-http-reconnect", port)).await?;
    drop(guard);
    manager.start("edge-http-reconnect").await?;
    common::wait_for_listener(port).await?;

    let client = Client::new();

    // Step 1: Register the agent via a normal DemonInit.
    let init_response = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(common::valid_demon_init_body(agent_id, key, iv))
        .send()
        .await?
        .error_for_status()?;
    let init_ack = init_response.bytes().await?;

    let decrypted_init_ack = decrypt_agent_data_at_offset(&key, &iv, 0, &init_ack)?;
    assert_eq!(decrypted_init_ack.as_slice(), &agent_id.to_le_bytes());
    // DEMON_INIT registers in legacy CTR mode — offset stays at 0.
    let ctr_offset = 0_u64;

    // Verify the stored CTR offset is 0 (legacy mode).
    assert_eq!(registry.ctr_offset(agent_id).await?, 0);

    // Step 2: Send a reconnect probe (DemonInit with empty payload).
    let reconnect_response = client
        .post(format!("http://127.0.0.1:{port}/"))
        .body(common::valid_demon_reconnect_body(agent_id))
        .send()
        .await?
        .error_for_status()?;
    let reconnect_ack = reconnect_response.bytes().await?;

    // Step 3: Verify the reconnect ACK decrypts to agent_id LE bytes at the current CTR offset.
    let decrypted_reconnect_ack =
        decrypt_agent_data_at_offset(&key, &iv, ctr_offset, &reconnect_ack)?;
    assert_eq!(
        decrypted_reconnect_ack.as_slice(),
        &agent_id.to_le_bytes(),
        "reconnect ACK must decrypt to agent_id in little-endian at the current CTR offset"
    );

    // Step 4: Verify the stored CTR offset did NOT advance — reconnect ACK is not
    // counter-consuming.
    assert_eq!(
        registry.ctr_offset(agent_id).await?,
        ctr_offset,
        "reconnect ACK must not advance the stored CTR offset"
    );

    // Step 5: Verify the agent is still registered and intact.
    assert!(
        registry.get(agent_id).await.is_some(),
        "agent must remain registered after reconnect probe"
    );

    manager.stop("edge-http-reconnect").await?;
    Ok(())
}

#[tokio::test]
async fn http_listener_pipeline_concurrent_multi_agent_init()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events.clone(), sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let mut event_receiver = events.subscribe();
    let (port, guard) = common::available_port()?;

    manager.create(http_listener("edge-http-concurrent-init", port)).await?;
    drop(guard);
    manager.start("edge-http-concurrent-init").await?;
    common::wait_for_listener(port).await?;

    // Five distinct agents, each with unique key/IV material.
    let agents: Vec<(u32, [u8; AGENT_KEY_LENGTH], [u8; AGENT_IV_LENGTH])> = (0..5)
        .map(|i| {
            let mut key = [0x41_u8; AGENT_KEY_LENGTH];
            key[0] = 0x10 + i;
            let mut iv = [0x24_u8; AGENT_IV_LENGTH];
            iv[0] = 0x30 + i;
            let agent_id = 0xCC00_0000_u32 + u32::from(i);
            (agent_id, key, iv)
        })
        .collect();

    let client = Client::new();

    // Spawn all five init requests concurrently.
    let futures: Vec<_> = agents
        .iter()
        .map(|&(agent_id, key, iv)| {
            let client = client.clone();
            async move {
                client
                    .post(format!("http://127.0.0.1:{port}/"))
                    .body(common::valid_demon_init_body(agent_id, key, iv))
                    .send()
                    .await
            }
        })
        .collect();

    let results = join_all(futures).await;
    for (i, result) in results.into_iter().enumerate() {
        let response = result?;
        assert!(
            response.status().is_success(),
            "agent {i} init should succeed, got {}",
            response.status()
        );
        let body = response.bytes().await?;
        assert!(!body.is_empty(), "agent {i} init ACK should not be empty");

        // Verify the ACK decrypts to the agent_id LE bytes.
        let (agent_id, key, iv) = agents[i];
        let decrypted = decrypt_agent_data_at_offset(&key, &iv, 0, &body)?;
        assert_eq!(
            decrypted.as_slice(),
            &agent_id.to_le_bytes(),
            "agent {i} init ACK must decrypt to its own agent_id"
        );
    }

    // Verify each agent is independently registered with the correct key/IV.
    for (i, &(agent_id, key, iv)) in agents.iter().enumerate() {
        let stored = registry
            .get(agent_id)
            .await
            .ok_or_else(|| format!("agent {i} ({agent_id:#x}) should be registered"))?;
        assert_eq!(
            stored.encryption.aes_key.as_slice(),
            &key,
            "agent {i} must have its own AES key"
        );
        assert_eq!(stored.encryption.aes_iv.as_slice(), &iv, "agent {i} must have its own AES IV");
    }

    // Verify exactly 5 active agents — no duplicates or missing entries.
    let active = registry.list_active().await;
    assert_eq!(active.len(), 5, "all five agents must be registered");

    // Drain event bus and verify exactly 5 AgentNew events were broadcast.
    let mut agent_new_count = 0_usize;
    for _ in 0..5 {
        let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
        let Some(OperatorMessage::AgentNew(_)) = event else {
            panic!("expected AgentNew event, got {event:?}");
        };
        agent_new_count += 1;
    }
    assert_eq!(agent_new_count, 5, "exactly 5 AgentNew events must be broadcast");

    manager.stop("edge-http-concurrent-init").await?;
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
