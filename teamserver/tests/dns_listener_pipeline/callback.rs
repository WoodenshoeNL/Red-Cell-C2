//! Callback, task delivery, and concurrent session tests for the DNS listener pipeline.

use std::time::Duration;

use red_cell::{AgentRegistry, Database, EventBus, Job, ListenerManager, SocketRelayManager};
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, decrypt_agent_data_at_offset};
use red_cell_common::demon::{DemonCommand, DemonMessage};
use red_cell_common::operator::OperatorMessage;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use super::common;
use super::helpers::{
    dns_download_response, dns_listener, dns_upload_demon_packet, dns_upload_demon_packet_ordered,
    free_udp_port, wait_for_dns_listener,
};

/// Two agents communicating concurrently through the same DNS listener must not
/// have their upload chunk buffers or download response queues mixed up.
#[tokio::test]
async fn dns_listener_concurrent_multi_agent_sessions_are_isolated()
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

    // Agent A parameters.
    let agent_id_a = 0xAAAA_0001_u32;
    let key_a: [u8; AGENT_KEY_LENGTH] = [
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E,
        0x7F, 0x80,
    ];
    let iv_a: [u8; AGENT_IV_LENGTH] = [
        0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F, 0x80, 0x91, 0xA2, 0xB3, 0xC4, 0xD5, 0xE6, 0xF7, 0x08,
        0x19,
    ];

    // Agent B parameters — distinct key/iv so cross-contamination is detectable.
    let agent_id_b = 0xBBBB_0002_u32;
    let key_b: [u8; AGENT_KEY_LENGTH] = [
        0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E,
        0x9F, 0xA0,
    ];
    let iv_b: [u8; AGENT_IV_LENGTH] = [
        0x3B, 0x4C, 0x5D, 0x6E, 0x7F, 0x80, 0x91, 0xA2, 0xB3, 0xC4, 0xD5, 0xE6, 0xF7, 0x08, 0x19,
        0x2A,
    ];

    manager.create(dns_listener("dns-concurrent", port, domain)).await?;
    manager.start("dns-concurrent").await?;

    // Each agent needs its own UDP socket so their packets interleave naturally.
    let client_a = {
        let s = UdpSocket::bind("127.0.0.1:0").await?;
        s.connect(format!("127.0.0.1:{port}")).await?;
        s
    };
    let client_b = {
        let s = UdpSocket::bind("127.0.0.1:0").await?;
        s.connect(format!("127.0.0.1:{port}")).await?;
        s
    };

    // Wait for the listener to be ready using a throwaway probe.
    let _probe_client = wait_for_dns_listener(port).await?;

    // 1. Upload DEMON_INIT for both agents concurrently.
    let init_body_a = common::valid_demon_init_body(agent_id_a, key_a, iv_a);
    let init_body_b = common::valid_demon_init_body(agent_id_b, key_b, iv_b);

    let (init_result_a, init_result_b) = tokio::join!(
        dns_upload_demon_packet(&client_a, agent_id_a, &init_body_a, domain, 0x1000),
        dns_upload_demon_packet(&client_b, agent_id_b, &init_body_b, domain, 0x2000),
    );

    assert_eq!(init_result_a?, "ack", "agent A DEMON_INIT must be acknowledged");
    assert_eq!(init_result_b?, "ack", "agent B DEMON_INIT must be acknowledged");

    // 2. Verify both agents are registered with correct, distinct keys.
    let stored_a =
        registry.get(agent_id_a).await.ok_or("agent A should be registered after init")?;
    let stored_b =
        registry.get(agent_id_b).await.ok_or("agent B should be registered after init")?;

    assert_eq!(
        stored_a.encryption.aes_key.as_slice(),
        &key_a,
        "agent A must have its own AES key (no cross-contamination)"
    );
    assert_eq!(stored_a.encryption.aes_iv.as_slice(), &iv_a, "agent A must have its own AES IV");
    assert_eq!(
        stored_b.encryption.aes_key.as_slice(),
        &key_b,
        "agent B must have its own AES key (no cross-contamination)"
    );
    assert_eq!(stored_b.encryption.aes_iv.as_slice(), &iv_b, "agent B must have its own AES IV");

    // 3. Drain the two AgentNew events (order is non-deterministic).
    let mut new_agent_ids = Vec::new();
    for _ in 0..2 {
        let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
        let Some(OperatorMessage::AgentNew(msg)) = event else {
            panic!("expected AgentNew event, got {event:?}");
        };
        new_agent_ids.push(msg.info.name_id.clone());
    }
    new_agent_ids.sort();
    let mut expected_ids = vec![format!("{agent_id_a:08X}"), format!("{agent_id_b:08X}")];
    expected_ids.sort();
    assert_eq!(new_agent_ids, expected_ids, "both AgentNew events must fire");

    // 4. Download init ACK for each agent and verify decryption with the correct key.
    let (ack_a, ack_b) = tokio::join!(
        dns_download_response(&client_a, agent_id_a, domain, 0x3000),
        dns_download_response(&client_b, agent_id_b, domain, 0x4000),
    );

    let ack_payload_a = ack_a?;
    let ack_payload_b = ack_b?;

    let decrypted_a = red_cell_common::crypto::decrypt_agent_data(&key_a, &iv_a, &ack_payload_a)?;
    assert_eq!(
        decrypted_a.as_slice(),
        &agent_id_a.to_le_bytes(),
        "agent A's init ACK must contain agent A's id"
    );

    let decrypted_b = red_cell_common::crypto::decrypt_agent_data(&key_b, &iv_b, &ack_payload_b)?;
    assert_eq!(
        decrypted_b.as_slice(),
        &agent_id_b.to_le_bytes(),
        "agent B's init ACK must contain agent B's id"
    );

    // Cross-check: decrypting A's ACK with B's key must NOT produce A's agent_id.
    let cross_decrypt = red_cell_common::crypto::decrypt_agent_data(&key_b, &iv_b, &ack_payload_a);
    if let Ok(cross) = cross_decrypt {
        assert_ne!(
            cross.as_slice(),
            &agent_id_a.to_le_bytes(),
            "decrypting agent A's ACK with agent B's key must not produce a valid agent_id"
        );
    }

    // DEMON_INIT registers agents in legacy CTR mode — every packet starts at block 0.
    let ctr_offset_a = 0;
    let ctr_offset_b = 0;

    // 5. Send COMMAND_CHECKIN callbacks from both agents concurrently.
    let callback_body_a = common::valid_demon_callback_body(
        agent_id_a,
        key_a,
        iv_a,
        ctr_offset_a,
        u32::from(DemonCommand::CommandCheckin),
        6,
        &[],
    );
    let callback_body_b = common::valid_demon_callback_body(
        agent_id_b,
        key_b,
        iv_b,
        ctr_offset_b,
        u32::from(DemonCommand::CommandCheckin),
        7,
        &[],
    );

    let (cb_result_a, cb_result_b) = tokio::join!(
        dns_upload_demon_packet(&client_a, agent_id_a, &callback_body_a, domain, 0x5000),
        dns_upload_demon_packet(&client_b, agent_id_b, &callback_body_b, domain, 0x6000),
    );

    assert_eq!(cb_result_a?, "ack", "agent A COMMAND_CHECKIN must be acknowledged");
    assert_eq!(cb_result_b?, "ack", "agent B COMMAND_CHECKIN must be acknowledged");

    // 6. Drain the two AgentUpdate events and verify both agents are marked Alive.
    let mut update_agent_ids = Vec::new();
    for _ in 0..2 {
        let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
        let Some(OperatorMessage::AgentUpdate(msg)) = event else {
            panic!("expected AgentUpdate event, got {event:?}");
        };
        assert_eq!(msg.info.marked, "Alive", "checkin must mark agent as Alive");
        update_agent_ids.push(msg.info.agent_id.clone());
    }
    update_agent_ids.sort();
    assert_eq!(update_agent_ids, expected_ids, "both agents must receive AgentUpdate events");

    // 7. Verify both agents still exist in the registry with correct metadata.
    let active = registry.list_active().await;
    assert_eq!(active.len(), 2, "registry must contain exactly two agents");

    manager.stop("dns-concurrent").await?;
    Ok(())
}

/// A registered agent with no pending tasks must receive "wait" when polling
/// the download endpoint — not garbage data or an error.
#[tokio::test]
async fn dns_listener_pipeline_download_returns_wait_for_registered_agent_with_no_tasks()
-> Result<(), Box<dyn std::error::Error>> {
    use super::helpers::{build_dns_txt_query, dns_download_qname, parse_dns_txt_answer};

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
        0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
        0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE,
        0xEF, 0xF0,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        0x00,
    ];
    let agent_id = 0xFEED_0001_u32;

    manager.create(dns_listener("dns-idle-dl", port, domain)).await?;
    manager.start("dns-idle-dl").await?;
    let client = wait_for_dns_listener(port).await?;

    // 1. Register the agent via DEMON_INIT.
    let init_body = common::valid_demon_init_body(agent_id, key, iv);
    let init_result =
        dns_upload_demon_packet(&client, agent_id, &init_body, domain, 0xA000).await?;
    assert_eq!(init_result, "ack", "DEMON_INIT upload must be acknowledged");

    // Verify registration.
    assert!(registry.get(agent_id).await.is_some(), "agent must be registered after init");

    // Drain the AgentNew event.
    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    assert!(matches!(event, Some(OperatorMessage::AgentNew(_))));

    // 2. Download the init ACK (consuming the pending response).
    let ack_payload = dns_download_response(&client, agent_id, domain, 0xA100).await?;
    assert!(!ack_payload.is_empty(), "init ACK response must be non-empty");

    // 3. Poll download again — no tasks have been queued, so response must be "wait".
    let qname = dns_download_qname(agent_id, 0, domain);
    let packet = build_dns_txt_query(0xA200, &qname);
    client.send(&packet).await?;

    let mut buf = vec![0u8; 4096];
    let len = timeout(Duration::from_secs(5), client.recv(&mut buf)).await??;
    buf.truncate(len);
    let txt = parse_dns_txt_answer(&buf).ok_or("failed to parse TXT answer")?;
    assert_eq!(
        txt, "wait",
        "download for registered agent with no tasks must return 'wait', got '{txt}'"
    );

    manager.stop("dns-idle-dl").await?;
    Ok(())
}

/// After a registered agent consumes its init ACK and then a task is enqueued,
/// the next checkin callback must deliver the task via the download channel.
#[tokio::test]
async fn dns_listener_pipeline_registered_agent_downloads_task_after_enqueue()
-> Result<(), Box<dyn std::error::Error>> {
    use super::helpers::{build_dns_txt_query, dns_download_qname, parse_dns_txt_answer};

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
        0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE,
        0xDF, 0xE0,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
        0xF0,
    ];
    let agent_id = 0xFEED_0002_u32;

    manager.create(dns_listener("dns-task-dl", port, domain)).await?;
    manager.start("dns-task-dl").await?;
    let client = wait_for_dns_listener(port).await?;

    // 1. Register via DEMON_INIT.
    let init_body = common::valid_demon_init_body(agent_id, key, iv);
    let init_result =
        dns_upload_demon_packet(&client, agent_id, &init_body, domain, 0xB000).await?;
    assert_eq!(init_result, "ack");

    assert!(registry.get(agent_id).await.is_some());

    // Drain AgentNew.
    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    assert!(matches!(event, Some(OperatorMessage::AgentNew(_))));

    // 2. Download and consume the init ACK.
    let ack_payload = dns_download_response(&client, agent_id, domain, 0xB100).await?;
    assert!(!ack_payload.is_empty());

    // 3. Verify "wait" before enqueuing any task.
    let qname = dns_download_qname(agent_id, 0, domain);
    let packet = build_dns_txt_query(0xB200, &qname);
    client.send(&packet).await?;

    let mut buf = vec![0u8; 4096];
    let len = timeout(Duration::from_secs(5), client.recv(&mut buf)).await??;
    buf.truncate(len);
    let txt = parse_dns_txt_answer(&buf).ok_or("failed to parse TXT answer")?;
    assert_eq!(txt, "wait", "no tasks queued yet — download must return 'wait'");

    // 4. Enqueue a job for the agent.
    registry
        .enqueue_job(
            agent_id,
            Job {
                command: u32::from(DemonCommand::CommandCheckin),
                request_id: 100,
                payload: vec![0xDE, 0xAD],
                command_line: "test-task".to_owned(),
                task_id: "task-001".to_owned(),
                created_at: String::new(),
                operator: String::new(),
            },
        )
        .await?;

    // 5. Send a COMMAND_GET_JOB callback — this triggers the dispatcher to
    //    dequeue jobs and build an encrypted response for the agent.
    //    Legacy Demon agents reset AES-CTR to block 0 for every packet, so the
    //    callback must be encrypted at offset 0 regardless of prior traffic.
    let callback_body = common::valid_demon_callback_body(
        agent_id,
        key,
        iv,
        0,
        u32::from(DemonCommand::CommandGetJob),
        8,
        &[],
    );
    let callback_result =
        dns_upload_demon_packet(&client, agent_id, &callback_body, domain, 0xB300).await?;
    assert_eq!(callback_result, "ack", "COMMAND_GET_JOB callback must be acknowledged");

    // 6. Download the task response — must NOT be "wait" since a job was queued.
    let task_payload = dns_download_response(&client, agent_id, domain, 0xB400).await?;
    assert!(
        !task_payload.is_empty(),
        "download after task enqueue must return actual data, not empty/wait"
    );

    manager.stop("dns-task-dl").await?;
    Ok(())
}

/// Happy path: agent registers → operator queues task → agent downloads via DNS
/// → decrypted DemonMessage contains the correct command_id and request_id.
#[tokio::test]
async fn dns_task_delivery_happy_path_decrypts_correctly() -> Result<(), Box<dyn std::error::Error>>
{
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
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE,
        0xBF, 0xC0,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xD1, 0xE4, 0xF7, 0x0A, 0x1D, 0x30, 0x43, 0x56, 0x69, 0x7C, 0x8F, 0xA2, 0xB5, 0xC8, 0xDB,
        0xEE,
    ];
    let agent_id = 0xFEED_1001_u32;

    manager.create(dns_listener("dns-happy", port, domain)).await?;
    manager.start("dns-happy").await?;
    let client = wait_for_dns_listener(port).await?;

    // 1. Register via DEMON_INIT.
    let init_body = common::valid_demon_init_body(agent_id, key, iv);
    let init_result =
        dns_upload_demon_packet(&client, agent_id, &init_body, domain, 0xC000).await?;
    assert_eq!(init_result, "ack");
    assert!(registry.get(agent_id).await.is_some());

    // Drain AgentNew event.
    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    assert!(matches!(event, Some(OperatorMessage::AgentNew(_))));

    // 2. Consume the init ACK.
    let ack_payload = dns_download_response(&client, agent_id, domain, 0xC100).await?;
    assert!(!ack_payload.is_empty());

    // 3. Enqueue a task for the agent.
    let task_payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
    registry
        .enqueue_job(
            agent_id,
            Job {
                command: u32::from(DemonCommand::CommandCheckin),
                request_id: 0x3A,
                payload: task_payload.clone(),
                command_line: "checkin".to_owned(),
                task_id: "task-happy-1".to_owned(),
                created_at: String::new(),
                operator: String::new(),
            },
        )
        .await?;

    // 4. Agent sends CommandGetJob to trigger task dispatch.
    let callback_body = common::valid_demon_callback_body(
        agent_id,
        key,
        iv,
        0,
        u32::from(DemonCommand::CommandGetJob),
        9,
        &[],
    );
    let callback_result =
        dns_upload_demon_packet(&client, agent_id, &callback_body, domain, 0xC200).await?;
    assert_eq!(callback_result, "ack");

    // 5. Download the task response.
    let response_bytes = dns_download_response(&client, agent_id, domain, 0xC300).await?;
    assert!(!response_bytes.is_empty(), "task response must not be empty");

    // 6. Parse DemonMessage and verify structure.
    let msg = DemonMessage::from_bytes(&response_bytes)?;
    assert_eq!(msg.packages.len(), 1, "exactly one task package expected");
    assert_eq!(
        msg.packages[0].command_id,
        u32::from(DemonCommand::CommandCheckin),
        "task command must match queued CommandCheckin"
    );
    assert_eq!(msg.packages[0].request_id, 0x3A, "request_id must match queued value");

    // 7. Decrypt the payload and verify it matches the original task data.
    //    Legacy CTR mode: server encrypts at offset 0.
    let decrypted = decrypt_agent_data_at_offset(&key, &iv, 0, &msg.packages[0].payload)?;
    assert_eq!(decrypted, task_payload, "decrypted task payload must match original");

    manager.stop("dns-happy").await?;
    Ok(())
}

/// Multi-chunk delivery: queue a task large enough to require more than one DNS
/// TXT chunk and verify reassembly + decryption are correct.
#[tokio::test]
async fn dns_task_delivery_multi_chunk() -> Result<(), Box<dyn std::error::Error>> {
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
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E,
        0x6F, 0x70,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
        0x80,
    ];
    let agent_id = 0xFEED_2002_u32;

    manager.create(dns_listener("dns-multichunk", port, domain)).await?;
    manager.start("dns-multichunk").await?;
    let client = wait_for_dns_listener(port).await?;

    // 1. Register via DEMON_INIT.
    let init_body = common::valid_demon_init_body(agent_id, key, iv);
    let init_result =
        dns_upload_demon_packet(&client, agent_id, &init_body, domain, 0xD000).await?;
    assert_eq!(init_result, "ack");
    assert!(registry.get(agent_id).await.is_some());

    // Drain AgentNew event.
    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    assert!(matches!(event, Some(OperatorMessage::AgentNew(_))));

    // 2. Consume the init ACK.
    let ack_payload = dns_download_response(&client, agent_id, domain, 0xD100).await?;
    assert!(!ack_payload.is_empty());

    // 3. Build a large task payload that will require multiple DNS TXT chunks.
    //    DNS TXT records have a ~255 byte limit; base32hex encoding expands data
    //    by 8/5, so a 500-byte payload will definitely span multiple chunks.
    let large_payload: Vec<u8> = (0..500).map(|i| (i % 256) as u8).collect();

    registry
        .enqueue_job(
            agent_id,
            Job {
                command: u32::from(DemonCommand::CommandCheckin),
                request_id: 0x7B,
                payload: large_payload.clone(),
                command_line: "large-task".to_owned(),
                task_id: "task-multi-1".to_owned(),
                created_at: String::new(),
                operator: String::new(),
            },
        )
        .await?;

    // 4. Agent sends CommandGetJob.
    let callback_body = common::valid_demon_callback_body(
        agent_id,
        key,
        iv,
        0,
        u32::from(DemonCommand::CommandGetJob),
        10,
        &[],
    );
    let callback_result =
        dns_upload_demon_packet(&client, agent_id, &callback_body, domain, 0xD200).await?;
    assert_eq!(callback_result, "ack");

    // 5. Download the multi-chunk response.
    let response_bytes = dns_download_response(&client, agent_id, domain, 0xD300).await?;
    assert!(!response_bytes.is_empty(), "multi-chunk task response must not be empty");

    // 6. Parse and verify DemonMessage structure.
    let msg = DemonMessage::from_bytes(&response_bytes)?;
    assert_eq!(msg.packages.len(), 1);
    assert_eq!(msg.packages[0].command_id, u32::from(DemonCommand::CommandCheckin));
    assert_eq!(msg.packages[0].request_id, 0x7B);

    // 7. Decrypt and verify the payload matches byte-for-byte.
    let decrypted = decrypt_agent_data_at_offset(&key, &iv, 0, &msg.packages[0].payload)?;
    assert_eq!(
        decrypted,
        large_payload,
        "multi-chunk decrypted payload must match original ({} bytes)",
        large_payload.len()
    );

    manager.stop("dns-multichunk").await?;
    Ok(())
}

/// Uploading a multi-chunk DEMON_INIT with chunks arriving out of order must
/// reassemble the original packet correctly and register the agent.
#[tokio::test]
async fn dns_listener_out_of_order_upload_reassembles_correctly()
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
        0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0,
        0x01,
    ];
    let agent_id = 0x000D_0001_u32;

    manager.create(dns_listener("dns-ooo-upload", port, domain)).await?;
    manager.start("dns-ooo-upload").await?;
    let client = wait_for_dns_listener(port).await?;

    // Build the DEMON_INIT payload and determine natural chunk count.
    let init_body = common::valid_demon_init_body(agent_id, key, iv);
    let num_chunks = init_body.chunks(39).count();
    assert!(
        num_chunks >= 3,
        "test requires at least 3 chunks to exercise out-of-order delivery, got {num_chunks}"
    );

    // Reverse the chunk order: last chunk first, first chunk last.
    let reversed_order: Vec<usize> = (0..num_chunks).rev().collect();

    let results = dns_upload_demon_packet_ordered(
        &client,
        agent_id,
        &init_body,
        domain,
        0xE000,
        &reversed_order,
    )
    .await?;

    // Intermediate chunks must return "ok"; the final chunk that completes
    // the set must return "ack".
    let last_txt = &results.last().expect("must have at least one result").1;
    assert_eq!(
        last_txt, "ack",
        "last chunk completing the out-of-order upload must return 'ack', got '{last_txt}'"
    );

    // The agent must be fully registered with the correct key.
    let stored = registry
        .get(agent_id)
        .await
        .ok_or("agent should be registered after out-of-order DEMON_INIT upload")?;
    assert_eq!(stored.encryption.aes_key.as_slice(), &key);
    assert_eq!(stored.encryption.aes_iv.as_slice(), &iv);
    assert_eq!(stored.hostname, "wkstn-01");

    // AgentNew event must have fired.
    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    assert!(
        matches!(event, Some(OperatorMessage::AgentNew(_))),
        "expected AgentNew after out-of-order init, got {event:?}"
    );

    // Download the init ACK and verify decryption to confirm no data corruption.
    let ack_payload = dns_download_response(&client, agent_id, domain, 0xE100).await?;
    let decrypted = red_cell_common::crypto::decrypt_agent_data(&key, &iv, &ack_payload)?;
    assert_eq!(
        decrypted.as_slice(),
        &agent_id.to_le_bytes(),
        "init ACK after out-of-order upload must decrypt to the correct agent_id"
    );

    manager.stop("dns-ooo-upload").await?;
    Ok(())
}

/// Retransmitting an already-received chunk during a multi-chunk upload must
/// not corrupt reassembly or create duplicate agent state.
#[tokio::test]
async fn dns_listener_duplicate_chunk_retransmission_is_idempotent()
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
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE,
        0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD,
        0xBE, 0xBF,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE,
        0xCF,
    ];
    let agent_id = 0xDDDD_0002_u32;

    manager.create(dns_listener("dns-dup-chunk", port, domain)).await?;
    manager.start("dns-dup-chunk").await?;
    let client = wait_for_dns_listener(port).await?;

    // Build the DEMON_INIT payload.
    let init_body = common::valid_demon_init_body(agent_id, key, iv);
    let num_chunks = init_body.chunks(39).count();
    assert!(
        num_chunks >= 3,
        "test requires at least 3 chunks to exercise duplicate retransmission, got {num_chunks}"
    );

    // Send chunks in order but retransmit chunk 0 and chunk 1 after their
    // initial delivery: [0, 1, 0, 1, 2, 3, ..., N-1].
    let mut send_order: Vec<usize> = vec![0, 1, 0, 1]; // duplicate retransmits of 0 and 1
    for i in 2..num_chunks {
        send_order.push(i);
    }

    let results =
        dns_upload_demon_packet_ordered(&client, agent_id, &init_body, domain, 0xF000, &send_order)
            .await?;

    // The final response must be "ack" — the duplicate chunks must not have
    // confused the reassembly logic.
    let last_txt = &results.last().expect("must have at least one result").1;
    assert_eq!(
        last_txt, "ack",
        "final chunk after duplicate retransmission must return 'ack', got '{last_txt}'"
    );

    // Agent must be registered with correct key material.
    let stored = registry
        .get(agent_id)
        .await
        .ok_or("agent should be registered after upload with duplicate chunks")?;
    assert_eq!(stored.encryption.aes_key.as_slice(), &key);
    assert_eq!(stored.encryption.aes_iv.as_slice(), &iv);
    assert_eq!(stored.hostname, "wkstn-01");

    // Exactly one agent should exist — no duplicates from retransmission.
    let active = registry.list_active().await;
    assert_eq!(
        active.len(),
        1,
        "duplicate chunk retransmission must not create extra agent entries"
    );

    // AgentNew must have fired exactly once.
    let event = timeout(Duration::from_secs(5), event_receiver.recv()).await?;
    assert!(
        matches!(event, Some(OperatorMessage::AgentNew(_))),
        "expected AgentNew after upload with duplicates, got {event:?}"
    );

    // Download init ACK and verify correctness.
    let ack_payload = dns_download_response(&client, agent_id, domain, 0xF100).await?;
    let decrypted = red_cell_common::crypto::decrypt_agent_data(&key, &iv, &ack_payload)?;
    assert_eq!(
        decrypted.as_slice(),
        &agent_id.to_le_bytes(),
        "init ACK after duplicate-chunk upload must decrypt to the correct agent_id"
    );

    // A subsequent in-order upload for a *different* agent must succeed,
    // proving the retransmission did not poison shared state.
    let agent_id_2 = 0xDDDD_0003_u32;
    let key_2: [u8; AGENT_KEY_LENGTH] = [
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E,
        0x2F, 0x30,
    ];
    let iv_2: [u8; AGENT_IV_LENGTH] = [
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        0x40,
    ];
    let init_body_2 = common::valid_demon_init_body(agent_id_2, key_2, iv_2);
    let result_2 =
        dns_upload_demon_packet(&client, agent_id_2, &init_body_2, domain, 0xF200).await?;
    assert_eq!(
        result_2, "ack",
        "subsequent normal upload after duplicate-chunk session must succeed"
    );
    assert!(
        registry.get(agent_id_2).await.is_some(),
        "second agent must be registered, proving no state poisoning"
    );

    manager.stop("dns-dup-chunk").await?;
    Ok(())
}
