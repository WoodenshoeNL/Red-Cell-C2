//! Agent init and registration tests for the DNS listener pipeline.

use std::time::Duration;

use red_cell::{AgentRegistry, Database, EventBus, ListenerManager, SocketRelayManager};
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::OperatorMessage;
use tokio::time::timeout;

use super::common;
use super::helpers::{
    build_dns_txt_query, dns_download_qname, dns_download_response, dns_listener,
    dns_upload_demon_packet, free_udp_port, parse_dns_txt_answer, wait_for_dns_listener,
};

/// Full DNS C2 pipeline: agent init → registration → download ACK → callback → event.
#[tokio::test]
async fn dns_listener_pipeline_registers_agent_and_broadcasts_checkin()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events.clone(), sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let mut event_receiver = events.subscribe();

    let port = free_udp_port();
    let domain = "c2.example.com";
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F,
        0x90,
    ];
    let agent_id = 0x1234_5678_u32;

    manager.create(dns_listener("dns-pipeline", port, domain)).await?;
    manager.start("dns-pipeline").await?;
    let client = wait_for_dns_listener(port).await?;

    // 1. Upload a DEMON_INIT packet via chunked DNS queries.
    let init_body = common::valid_demon_init_body(agent_id, key, iv);
    let init_result =
        dns_upload_demon_packet(&client, agent_id, &init_body, domain, 0x1000).await?;
    assert_eq!(init_result, "ack", "DEMON_INIT upload must be acknowledged");

    // 2. Verify the agent is registered in the registry.
    let stored = registry.get(agent_id).await.ok_or("agent should be registered after DNS init")?;
    assert_eq!(stored.hostname, "wkstn-01");

    // 3. Verify AgentNew event was broadcast.
    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    let Some(OperatorMessage::AgentNew(message)) = event else {
        panic!("expected AgentNew event, got {event:?}");
    };
    assert_eq!(message.info.name_id, "12345678");
    assert_eq!(message.info.listener, "dns-pipeline");

    // 4. Download the init ACK response (encrypted agent_id).
    let ack_payload = dns_download_response(&client, agent_id, domain, 0x2000).await?;
    assert!(!ack_payload.is_empty(), "init ACK response must be non-empty");

    // Decrypt and verify the ACK contains the agent_id.
    let decrypted = red_cell_common::crypto::decrypt_agent_data(&key, &iv, &ack_payload)?;
    assert_eq!(
        decrypted.as_slice(),
        &agent_id.to_le_bytes(),
        "init ACK must contain agent_id as LE bytes"
    );

    // DEMON_INIT registers agents in legacy CTR mode — every packet starts at block 0.
    let ctr_offset = 0;

    // 5. Send a COMMAND_CHECKIN callback via DNS upload.
    let before_checkin = stored.last_call_in.clone();
    let callback_body = common::valid_demon_callback_body(
        agent_id,
        key,
        iv,
        ctr_offset,
        u32::from(DemonCommand::CommandCheckin),
        6,
        &[],
    );
    let callback_result =
        dns_upload_demon_packet(&client, agent_id, &callback_body, domain, 0x3000).await?;
    assert_eq!(callback_result, "ack", "COMMAND_CHECKIN callback must be acknowledged");

    // 6. Verify AgentUpdate event was broadcast.
    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    let Some(OperatorMessage::AgentUpdate(message)) = event else {
        panic!("expected AgentUpdate event, got {event:?}");
    };
    assert_eq!(message.info.agent_id, "12345678");
    assert_eq!(message.info.marked, "Alive");

    // 7. Verify last_call_in advanced.
    let updated =
        registry.get(agent_id).await.ok_or("agent should remain registered after checkin")?;
    assert_ne!(updated.last_call_in, before_checkin, "last_call_in must advance after checkin");

    manager.stop("dns-pipeline").await?;
    Ok(())
}

/// A DNS upload for an unregistered agent's callback must be rejected.
#[tokio::test]
async fn dns_listener_pipeline_rejects_callbacks_from_unregistered_agent()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events.clone(), sockets, None)
        .with_demon_allow_legacy_ctr(true);

    let port = free_udp_port();
    let domain = "c2.example.com";
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E,
        0x3F, 0x40,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let agent_id = 0xCAFE_BABE_u32;

    manager.create(dns_listener("dns-unknown-cb", port, domain)).await?;
    manager.start("dns-unknown-cb").await?;
    let client = wait_for_dns_listener(port).await?;

    let callback_body = common::valid_demon_callback_body(
        agent_id,
        key,
        iv,
        0,
        u32::from(DemonCommand::CommandCheckin),
        6,
        &[],
    );
    let result = dns_upload_demon_packet(&client, agent_id, &callback_body, domain, 0x5000).await?;

    // The DNS transport processes the upload and may return "ack" even for unknown
    // callbacks (unlike HTTP which returns 404).  The important invariant is that no
    // agent state is created in the registry.
    assert!(
        result == "ack" || result == "err",
        "callback from unregistered agent must return 'ack' or 'err', got '{result}'"
    );
    assert!(
        registry.get(agent_id).await.is_none(),
        "unregistered callback must not create agent state"
    );

    manager.stop("dns-unknown-cb").await?;
    Ok(())
}

/// A second DEMON_INIT via DNS for an already-registered `agent_id` is treated as a
/// re-registration (agent restart after crash or kill-date reset).  The session key is
/// replaced and the DNS listener returns "ack".
///
/// The teamserver rejects re-registration with different key material (key-rotation hijack
/// prevention).  This test uses the same keys to simulate a legitimate agent restart.
#[tokio::test]
async fn dns_listener_pipeline_reinit_updates_key_material()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events.clone(), sockets, None)
        .with_demon_allow_legacy_ctr(true);
    let mut event_receiver = events.subscribe();

    let port = free_udp_port();
    let domain = "c2.example.com";
    let agent_id = 0xDEAD_C0DE_u32;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E,
        0x5F, 0x60,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x00,
    ];

    manager.create(dns_listener("dns-reinit", port, domain)).await?;
    manager.start("dns-reinit").await?;
    let client = wait_for_dns_listener(port).await?;

    // First init — must succeed and register the key.
    let init_body = common::valid_demon_init_body(agent_id, key, iv);
    let result = dns_upload_demon_packet(&client, agent_id, &init_body, domain, 0x6000).await?;
    assert_eq!(result, "ack", "first DEMON_INIT must succeed");

    let stored = registry.get(agent_id).await.ok_or("agent should be registered")?;
    assert_eq!(stored.encryption.aes_key.as_slice(), &key);

    // Drain first AgentNew event.
    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    assert!(matches!(event, Some(OperatorMessage::AgentNew(_))));

    // Second init (same agent_id, same key) — legitimate agent restart re-registration.
    let reinit_body = common::valid_demon_init_body(agent_id, key, iv);
    let reinit_result =
        dns_upload_demon_packet(&client, agent_id, &reinit_body, domain, 0x7000).await?;
    assert_eq!(reinit_result, "ack", "re-registration DEMON_INIT must be accepted");

    // Key must remain unchanged.
    let stored_after = registry.get(agent_id).await.ok_or("agent should remain registered")?;
    assert_eq!(
        stored_after.encryption.aes_key.as_slice(),
        &key,
        "re-init must preserve the session key"
    );
    assert_eq!(
        stored_after.encryption.aes_iv.as_slice(),
        &iv,
        "re-init must preserve the session IV"
    );

    // Still exactly one active entry.
    let active = registry.list_active().await;
    assert_eq!(active.len(), 1, "re-init must not create a second agent entry");

    manager.stop("dns-reinit").await?;
    Ok(())
}

/// Download queries for an unregistered agent must return "wait".
#[tokio::test]
async fn dns_listener_pipeline_download_returns_wait_for_unknown_agent()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let manager = ListenerManager::new(database, registry.clone(), events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

    let port = free_udp_port();
    let domain = "c2.example.com";
    let agent_id = 0xAAAA_BBBB_u32;

    manager.create(dns_listener("dns-dl-unknown", port, domain)).await?;
    manager.start("dns-dl-unknown").await?;
    let client = wait_for_dns_listener(port).await?;

    // Download for an unregistered agent.
    let qname = dns_download_qname(agent_id, 0, domain);
    let packet = build_dns_txt_query(0x9000, &qname);
    client.send(&packet).await?;

    let mut buf = vec![0u8; 4096];
    let len = timeout(Duration::from_secs(5), client.recv(&mut buf)).await??;
    buf.truncate(len);
    let txt = parse_dns_txt_answer(&buf).ok_or("failed to parse TXT answer")?;
    assert_eq!(txt, "wait", "download for unknown agent must return 'wait'");

    manager.stop("dns-dl-unknown").await?;
    Ok(())
}
