//! Tests for the builtin CHECKIN command handler.

use super::common::*;

use red_cell_common::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len, encrypt_agent_data_at_offset,
};
use red_cell_common::demon::DemonCommand;
use red_cell_common::operator::OperatorMessage;
use tokio::time::{Duration, timeout};

use super::super::{CommandDispatchError, CommandDispatcher};
use crate::{AgentRegistry, Database, EventBus, SocketRelayManager, TeamserverError};

#[tokio::test]
async fn builtin_checkin_handler_updates_last_call_in_and_broadcasts()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets, None);
    let key = test_key(0x77);
    let iv = test_iv(0x44);
    let agent_id = 0x1020_3040;

    registry.insert(sample_agent_info(agent_id, key, iv)).await?;
    let before = registry
        .get(agent_id)
        .await
        .ok_or_else(|| "agent should exist before checkin".to_owned())?
        .last_call_in;

    let response =
        dispatcher.dispatch(agent_id, u32::from(DemonCommand::CommandCheckin), 6, &[]).await?;

    assert_eq!(response, None);

    let updated = registry
        .get(agent_id)
        .await
        .ok_or_else(|| "agent should exist after checkin".to_owned())?;
    assert_ne!(updated.last_call_in, before);

    let event =
        receiver.recv().await.ok_or_else(|| "agent update event should be broadcast".to_owned())?;
    let OperatorMessage::AgentUpdate(message) = event else {
        panic!("unexpected operator event");
    };
    assert_eq!(message.info.agent_id, format!("{agent_id:08X}"));
    assert_eq!(message.info.marked, "Alive");
    Ok(())
}

#[tokio::test]
async fn builtin_checkin_handler_rejects_truncated_metadata_payload()
-> Result<(), Box<dyn std::error::Error>> {
    // Any non-empty payload shorter than the 48-byte metadata prefix must be rejected
    // as a protocol error — not silently accepted as a heartbeat.
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets, None);
    let key = test_key(0x77);
    let iv = test_iv(0x44);
    let agent_id = 0x1020_3040;

    registry.insert(sample_agent_info(agent_id, key, iv)).await?;

    // Test a range of truncated payload lengths: 1 byte, the boundary-minus-one (47 bytes),
    // and a mid-range value.
    for truncated_len in [1_usize, 16, 47] {
        let truncated_payload = vec![0xAA; truncated_len];
        let err = dispatcher
            .dispatch(agent_id, u32::from(DemonCommand::CommandCheckin), 6, &truncated_payload)
            .await
            .expect_err("truncated CHECKIN payload must be rejected");
        assert!(
            matches!(
                err,
                CommandDispatchError::InvalidCallbackPayload { command_id, .. }
                if command_id == u32::from(DemonCommand::CommandCheckin)
            ),
            "expected InvalidCallbackPayload for {truncated_len}-byte payload, got {err:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn builtin_checkin_handler_truncated_payload_does_not_mutate_state()
-> Result<(), Box<dyn std::error::Error>> {
    // A truncated CHECKIN must not update last_call_in or broadcast any event.
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets, None);
    let key = test_key(0x77);
    let iv = test_iv(0x44);
    let agent_id = 0x1020_3040;

    registry.insert(sample_agent_info(agent_id, key, iv)).await?;
    let before = registry
        .get(agent_id)
        .await
        .ok_or_else(|| "agent should exist before checkin".to_owned())?
        .last_call_in;

    let truncated_payload = vec![0xAA; 10];
    let _ = dispatcher
        .dispatch(agent_id, u32::from(DemonCommand::CommandCheckin), 6, &truncated_payload)
        .await
        .expect_err("truncated CHECKIN payload must be rejected");

    let after = registry
        .get(agent_id)
        .await
        .ok_or_else(|| "agent should still exist after rejected checkin".to_owned())?
        .last_call_in;

    assert_eq!(before, after, "last_call_in must not change on rejected truncated CHECKIN");
    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "rejected truncated CHECKIN must not broadcast an agent update event"
    );
    Ok(())
}

#[tokio::test]
async fn builtin_checkin_handler_refreshes_metadata_and_transport_state()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events,
        database.clone(),
        sockets,
        None,
    );
    let key = test_key(0x77);
    let iv = test_iv(0x44);
    let refreshed_key = test_key(0x12);
    let refreshed_iv = test_iv(0x34);
    let agent_id = 0x1020_3040;

    registry.insert(sample_agent_info(agent_id, key, iv)).await?;
    registry.set_ctr_offset(agent_id, 7).await?;
    let payload = sample_checkin_metadata_payload(agent_id, refreshed_key, refreshed_iv);

    let response =
        dispatcher.dispatch(agent_id, u32::from(DemonCommand::CommandCheckin), 6, &payload).await?;

    assert_eq!(response, None);

    let updated = registry
        .get(agent_id)
        .await
        .ok_or_else(|| "agent should exist after metadata-bearing checkin".to_owned())?;
    assert_eq!(updated.hostname, "wkstn-02");
    assert_eq!(updated.username, "svc-op");
    assert_eq!(updated.domain_name, "research");
    assert_eq!(updated.internal_ip, "10.10.10.50");
    assert_eq!(updated.process_name, "cmd.exe");
    assert_eq!(updated.process_path, "C:\\Windows\\System32\\cmd.exe");
    assert_eq!(updated.process_pid, 4040);
    assert_eq!(updated.process_tid, 5050);
    assert_eq!(updated.process_ppid, 3030);
    assert_eq!(updated.process_arch, "x86");
    assert!(!updated.elevated);
    assert_eq!(updated.base_address, 0x401000);
    assert_eq!(updated.os_version, "Windows 11");
    assert_eq!(updated.os_arch, "x64/AMD64");
    assert_eq!(updated.sleep_delay, 45);
    assert_eq!(updated.sleep_jitter, 5);
    assert_eq!(updated.kill_date, Some(1_725_000_000));
    assert_eq!(updated.working_hours, Some(0x00FF_00FF));
    // Key rotation from CHECKIN is rejected — original key material must be preserved.
    assert_eq!(updated.encryption.aes_key.as_slice(), key.as_slice());
    assert_eq!(updated.encryption.aes_iv.as_slice(), iv.as_slice());
    // CTR offset must not be reset when rotation is refused.
    assert_eq!(registry.ctr_offset(agent_id).await?, 7);

    let persisted = database
        .agents()
        .get(agent_id)
        .await?
        .ok_or_else(|| "agent should be persisted after checkin".to_owned())?;
    assert_eq!(persisted, updated);

    let event =
        receiver.recv().await.ok_or_else(|| "agent update event should be broadcast".to_owned())?;
    let OperatorMessage::AgentUpdate(message) = event else {
        panic!("unexpected operator event");
    };
    assert_eq!(message.info.agent_id, format!("{agent_id:08X}"));
    assert_eq!(message.info.marked, "Alive");
    Ok(())
}

#[tokio::test]
async fn builtin_checkin_handler_rejects_key_rotation_and_preserves_ctr_offset()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets, None);
    let original_key = test_key(0x77);
    let original_iv = test_iv(0x44);
    let attempted_key = test_key(0x12);
    let attempted_iv = test_iv(0x34);
    let agent_id = 0x1020_304A;
    let pre_checkin_plaintext = b"advance shared ctr state";
    let post_checkin_plaintext = b"sleep 45 5";

    registry.insert(sample_agent_info(agent_id, original_key, original_iv)).await?;

    // Advance the CTR offset to a non-zero value before the CHECKIN.
    let pre_checkin_ciphertext =
        encrypt_agent_data_at_offset(&original_key, &original_iv, 0, pre_checkin_plaintext)?;
    assert_eq!(
        registry.decrypt_from_agent(agent_id, &pre_checkin_ciphertext).await?,
        pre_checkin_plaintext
    );
    let advanced_offset = registry.ctr_offset(agent_id).await?;
    assert_eq!(advanced_offset, ctr_blocks_for_len(pre_checkin_ciphertext.len()));
    assert!(advanced_offset > 0);

    // Dispatch a CHECKIN that attempts to rotate to a different key.
    let payload = sample_checkin_metadata_payload(agent_id, attempted_key, attempted_iv);
    let response =
        dispatcher.dispatch(agent_id, u32::from(DemonCommand::CommandCheckin), 6, &payload).await?;
    assert_eq!(response, None);

    // The rotation must be refused: CTR offset preserved, original key still active.
    assert_eq!(registry.ctr_offset(agent_id).await?, advanced_offset);
    assert_eq!(
        registry.get(agent_id).await.expect("unwrap").encryption.aes_key.as_slice(),
        original_key.as_slice()
    );
    assert_eq!(
        registry.get(agent_id).await.expect("unwrap").encryption.aes_iv.as_slice(),
        original_iv.as_slice()
    );

    // Subsequent encryption must still use the original key at the preserved offset.
    let post_checkin_ciphertext =
        registry.encrypt_for_agent(agent_id, post_checkin_plaintext).await?;
    assert_eq!(
        post_checkin_ciphertext,
        encrypt_agent_data_at_offset(
            &original_key,
            &original_iv,
            advanced_offset,
            post_checkin_plaintext,
        )?
    );
    // Must NOT encrypt with the attempted rotated key.
    assert_ne!(
        post_checkin_ciphertext,
        encrypt_agent_data_at_offset(&attempted_key, &attempted_iv, 0, post_checkin_plaintext)?
    );

    Ok(())
}

#[tokio::test]
async fn builtin_checkin_handler_rejects_kill_date_exceeding_i64_range()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry.clone(), events, database, sockets, None);
    let key = test_key(0x77);
    let iv = test_iv(0x44);
    let refreshed_key = test_key(0x12);
    let refreshed_iv = test_iv(0x34);
    let agent_id = 0x1020_3041;

    registry.insert(sample_agent_info(agent_id, key, iv)).await?;
    registry.set_ctr_offset(agent_id, 7).await?;
    let payload = sample_checkin_metadata_payload_with_kill_date_and_working_hours(
        agent_id,
        refreshed_key,
        refreshed_iv,
        i64::MAX as u64 + 1,
        0x00FF_00FF,
    );

    let error = dispatcher
        .dispatch(agent_id, u32::from(DemonCommand::CommandCheckin), 6, &payload)
        .await
        .expect_err("overflowing kill date checkin must be rejected");

    assert!(matches!(
        error,
        CommandDispatchError::InvalidCallbackPayload { command_id, ref message }
            if command_id == u32::from(DemonCommand::CommandCheckin)
                && message == "checkin kill date exceeds i64 range"
    ));
    assert_eq!(
        registry
            .get(agent_id)
            .await
            .ok_or_else(|| "agent should remain registered".to_owned())?
            .kill_date,
        None
    );
    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "rejected checkin should not broadcast updates"
    );
    Ok(())
}

#[tokio::test]
async fn builtin_checkin_handler_rejects_all_zero_rotated_aes_key_without_mutating_state()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events,
        database.clone(),
        sockets,
        None,
    );
    let original_key = test_key(0x77);
    let original_iv = test_iv(0x44);
    let agent_id = 0x1020_3043;

    let original = sample_agent_info(agent_id, original_key, original_iv);
    registry.insert(original.clone()).await?;
    registry.set_ctr_offset(agent_id, 7).await?;

    let error = dispatcher
        .dispatch(
            agent_id,
            u32::from(DemonCommand::CommandCheckin),
            6,
            &sample_checkin_metadata_payload(agent_id, [0; AGENT_KEY_LENGTH], test_iv(0x34)),
        )
        .await
        .expect_err("all-zero key rotation must be rejected");

    assert!(matches!(
        error,
        CommandDispatchError::InvalidCallbackPayload { command_id, ref message }
            if command_id == u32::from(DemonCommand::CommandCheckin)
                && message == "degenerate AES key is not allowed"
    ));

    let updated = registry
        .get(agent_id)
        .await
        .ok_or_else(|| "agent should remain registered after rejected checkin".to_owned())?;
    assert_eq!(updated, original);
    assert_eq!(registry.ctr_offset(agent_id).await?, 7);

    let persisted = database
        .agents()
        .get(agent_id)
        .await?
        .ok_or_else(|| "agent should remain persisted after rejected checkin".to_owned())?;
    assert_eq!(persisted, original);

    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "rejected checkin should not broadcast updates"
    );

    Ok(())
}

#[tokio::test]
async fn builtin_checkin_handler_rejects_all_zero_rotated_aes_iv_without_mutating_state()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events,
        database.clone(),
        sockets,
        None,
    );
    let original_key = test_key(0x77);
    let original_iv = test_iv(0x44);
    let agent_id = 0x1020_3044;

    let original = sample_agent_info(agent_id, original_key, original_iv);
    registry.insert(original.clone()).await?;
    registry.set_ctr_offset(agent_id, 7).await?;

    let error = dispatcher
        .dispatch(
            agent_id,
            u32::from(DemonCommand::CommandCheckin),
            6,
            &sample_checkin_metadata_payload(agent_id, test_key(0x55), [0; AGENT_IV_LENGTH]),
        )
        .await
        .expect_err("all-zero IV rotation must be rejected");

    assert!(matches!(
        error,
        CommandDispatchError::InvalidCallbackPayload { command_id, ref message }
            if command_id == u32::from(DemonCommand::CommandCheckin)
                && message == "degenerate AES IV is not allowed"
    ));

    let updated = registry
        .get(agent_id)
        .await
        .ok_or_else(|| "agent should remain registered after rejected checkin".to_owned())?;
    assert_eq!(updated, original);
    assert_eq!(registry.ctr_offset(agent_id).await?, 7);

    let persisted = database
        .agents()
        .get(agent_id)
        .await?
        .ok_or_else(|| "agent should remain persisted after rejected checkin".to_owned())?;
    assert_eq!(persisted, original);

    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "rejected checkin should not broadcast updates"
    );

    Ok(())
}

#[tokio::test]
async fn builtin_checkin_handler_returns_agent_not_found_for_unknown_agent()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut receiver = events.subscribe();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher =
        CommandDispatcher::with_builtin_handlers(registry, events, database, sockets, None);
    let agent_id = 0x1020_3042;

    let error = dispatcher
        .dispatch(agent_id, u32::from(DemonCommand::CommandCheckin), 6, &[0xAA, 0xBB])
        .await
        .expect_err("unknown agent checkin should fail");

    assert!(matches!(
        error,
        CommandDispatchError::Registry(TeamserverError::AgentNotFound { agent_id: missing_id })
            if missing_id == agent_id
    ));
    assert!(
        timeout(Duration::from_millis(50), receiver.recv()).await.is_err(),
        "unknown agent checkin should not broadcast an event"
    );
    Ok(())
}

#[tokio::test]
async fn builtin_checkin_handler_preserves_high_bit_working_hours()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events,
        database.clone(),
        sockets,
        None,
    );
    let key = test_key(0x77);
    let iv = test_iv(0x44);
    let refreshed_key = test_key(0x12);
    let refreshed_iv = test_iv(0x34);
    let agent_id = 0x1020_3041;
    let working_hours = 0x8000_002A;

    registry.insert(sample_agent_info(agent_id, key, iv)).await?;
    let payload = sample_checkin_metadata_payload_with_working_hours(
        agent_id,
        refreshed_key,
        refreshed_iv,
        working_hours,
    );

    let response =
        dispatcher.dispatch(agent_id, u32::from(DemonCommand::CommandCheckin), 7, &payload).await?;

    assert_eq!(response, None);

    let updated = registry
        .get(agent_id)
        .await
        .ok_or_else(|| "agent should exist after metadata-bearing checkin".to_owned())?;
    assert_eq!(updated.working_hours, Some(i32::from_be_bytes(working_hours.to_be_bytes())));

    let persisted = database
        .agents()
        .get(agent_id)
        .await?
        .ok_or_else(|| "agent should be persisted after checkin".to_owned())?;
    assert_eq!(persisted.working_hours, updated.working_hours);

    Ok(())
}

#[tokio::test]
async fn builtin_checkin_handler_refuses_transport_rotation_for_pivoted_agents()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events,
        database.clone(),
        sockets,
        None,
    );
    let parent_id = 0x4546_4748;
    let parent_key = test_key(0x21);
    let parent_iv = test_iv(0x31);
    let agent_id = 0x5152_5354;
    let key = test_key(0x77);
    let iv = test_iv(0x44);
    let rotated_key = test_key(0x12);
    let rotated_iv = test_iv(0x34);

    registry.insert(sample_agent_info(parent_id, parent_key, parent_iv)).await?;
    registry.insert_with_listener(sample_agent_info(agent_id, key, iv), "smb").await?;
    registry.add_link(parent_id, agent_id).await?;
    registry.set_ctr_offset(agent_id, 7).await?;

    let response = dispatcher
        .dispatch(
            agent_id,
            u32::from(DemonCommand::CommandCheckin),
            7,
            &sample_checkin_metadata_payload(agent_id, rotated_key, rotated_iv),
        )
        .await?;

    assert_eq!(response, None);

    let updated = registry
        .get(agent_id)
        .await
        .ok_or_else(|| "pivoted agent should exist after checkin".to_owned())?;
    assert_eq!(updated.hostname, "wkstn-02");
    assert_eq!(updated.encryption.aes_key.as_slice(), key.as_slice());
    assert_eq!(updated.encryption.aes_iv.as_slice(), iv.as_slice());
    assert_eq!(registry.ctr_offset(agent_id).await?, 7);

    let persisted = database
        .agents()
        .get(agent_id)
        .await?
        .ok_or_else(|| "pivoted agent should remain persisted after checkin".to_owned())?;
    assert_eq!(persisted.encryption.aes_key.as_slice(), key.as_slice());
    assert_eq!(persisted.encryption.aes_iv.as_slice(), iv.as_slice());

    Ok(())
}

#[tokio::test]
async fn builtin_checkin_handler_records_agent_checkin_audit_entry()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let dispatcher = CommandDispatcher::with_builtin_handlers(
        registry.clone(),
        events,
        database.clone(),
        sockets,
        None,
    );
    let key = test_key(0x77);
    let iv = test_iv(0x44);
    let agent_id = 0xABCD_1234_u32;

    registry.insert(sample_agent_info(agent_id, key, iv)).await?;
    dispatcher.dispatch(agent_id, u32::from(DemonCommand::CommandCheckin), 6, &[]).await?;

    // The audit write is spawned as a background task; yield to let it complete.
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    let entries = database.audit_log().list().await?;
    let checkin_entry = entries
        .iter()
        .find(|e| e.action == "agent.checkin")
        .expect("a checkin audit entry with action=\"agent.checkin\" should have been persisted");
    assert_eq!(checkin_entry.actor, "teamserver");
    assert_eq!(checkin_entry.target_kind, "agent");
    assert_eq!(checkin_entry.target_id.as_deref(), Some("ABCD1234"));
    let details = checkin_entry.details.as_ref().expect("checkin audit entry must include details");
    assert_eq!(details["result_status"], "success");
    assert_eq!(details["command"], "checkin");
    assert_eq!(details["agent_id"], "ABCD1234");
    Ok(())
}
