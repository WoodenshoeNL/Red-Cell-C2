use super::*;
use crate::Job;
use axum::http::StatusCode;
use red_cell_common::crypto::{
    ctr_blocks_for_len, decrypt_agent_data, decrypt_agent_data_at_offset,
};
use red_cell_common::demon::{DemonCommand, DemonMessage};
use red_cell_common::operator::OperatorMessage;

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
    // Demon batched GET_JOB with empty body encrypts 0 bytes, so response
    // starts at CTR offset 0.
    let response_ctr_offset = ctr_blocks_for_len(0);
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
    // Demon batched format: GET_JOB is a container with sub-packages.
    // The encrypted body contains only the CheckIn sub-package:
    //   4 (CheckIn cmd) + 4 (req_id) + 4 (payload len) + checkin_payload
    let first_request_encrypted_len = 4 + 4 + 4 + checkin_payload.len();
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

/// HTTP listener configured with `with_demon_init_secret` accepts a
/// DEMON_INIT packet and the returned ACK is encrypted with the derived
/// (HKDF) session keys — not the raw agent keys.
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
            u32::from(DemonCommand::CommandCheckin),
            7,
            &[0xDE, 0xAD],
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
