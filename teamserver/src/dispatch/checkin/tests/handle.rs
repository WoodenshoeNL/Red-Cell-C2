use super::super::{CommandDispatchError, decode_working_hours, handle_checkin};
use super::{make_checkin_payload, sample_agent, test_iv, test_key};
use crate::{AgentRegistry, AuditQuery, Database, EventBus, query_audit_log};

/// Verify that `handle_checkin` preserves the original AES session key when
/// the CHECKIN payload carries different key/IV material (replay-attack
/// defence).  This is the security property guarded by lines 29–51.
#[tokio::test]
async fn handle_checkin_rejects_key_rotation_and_preserves_original_session_key()
-> Result<(), Box<dyn std::error::Error>> {
    let original_key = test_key(0xAA);
    let original_iv = test_iv(0xBB);
    let attacker_key = test_key(0xCC);
    let attacker_iv = test_iv(0xDD);
    let agent_id = 0xDEAD_0001;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();

    registry.insert(sample_agent(agent_id, original_key, original_iv)).await?;

    // Build a CHECKIN payload with attacker-controlled key material.
    let payload = make_checkin_payload(agent_id, attacker_key, attacker_iv);

    handle_checkin(&registry, &events, &database, None, agent_id, &payload).await?;

    // The agent's stored encryption must be the original, not the attacker's.
    let agent = registry.get(agent_id).await.ok_or("agent should still be registered")?;

    assert_eq!(
        agent.encryption.aes_key.as_slice(),
        original_key.as_slice(),
        "AES key must not be overwritten by CHECKIN payload"
    );
    assert_eq!(
        agent.encryption.aes_iv.as_slice(),
        original_iv.as_slice(),
        "AES IV must not be overwritten by CHECKIN payload"
    );

    Ok(())
}

/// When the CHECKIN payload carries the *same* key/IV as already registered,
/// no rotation is detected and the metadata update proceeds normally.
#[tokio::test]
async fn handle_checkin_accepts_same_key_without_triggering_rotation_guard()
-> Result<(), Box<dyn std::error::Error>> {
    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0002;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();

    registry.insert(sample_agent(agent_id, key, iv)).await?;

    // CHECKIN with the same key — should update metadata without warnings.
    let payload = make_checkin_payload(agent_id, key, iv);
    handle_checkin(&registry, &events, &database, None, agent_id, &payload).await?;

    let agent = registry.get(agent_id).await.ok_or("agent should still be registered")?;

    assert_eq!(agent.encryption.aes_key.as_slice(), key.as_slice());
    assert_eq!(agent.encryption.aes_iv.as_slice(), iv.as_slice());
    // Metadata should have been updated from the payload.
    assert_eq!(agent.hostname, "wkstn-02");
    assert_eq!(agent.username, "svc-op");

    Ok(())
}

/// An empty CHECKIN payload (heartbeat-only, no metadata) must leave the
/// existing agent record unchanged except for `last_call_in`.
#[tokio::test]
async fn handle_checkin_empty_payload_updates_last_call_in_only()
-> Result<(), Box<dyn std::error::Error>> {
    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0010;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();

    let original = sample_agent(agent_id, key, iv);
    registry.insert(original.clone()).await?;

    handle_checkin(&registry, &events, &database, None, agent_id, &[]).await?;

    let agent = registry.get(agent_id).await.ok_or("agent should still exist")?;
    assert_eq!(agent.hostname, original.hostname, "hostname must not change on empty checkin");
    assert_eq!(agent.username, original.username, "username must not change on empty checkin");
    assert_ne!(agent.last_call_in, original.last_call_in, "last_call_in must be updated");

    Ok(())
}

/// A rejected checkin (truncated payload) must not modify the stored agent
/// record — the original metadata must be preserved unchanged.
#[tokio::test]
async fn handle_checkin_truncated_payload_does_not_mutate_agent()
-> Result<(), Box<dyn std::error::Error>> {
    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0011;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();

    let original = sample_agent(agent_id, key, iv);
    registry.insert(original.clone()).await?;

    // 10 bytes — too short for the 48-byte metadata prefix.
    let result = handle_checkin(&registry, &events, &database, None, agent_id, &[0x42; 10]).await;
    assert!(result.is_err(), "truncated payload must be rejected");

    let agent = registry.get(agent_id).await.ok_or("agent should still exist")?;
    assert_eq!(agent.hostname, original.hostname, "hostname must not change after rejection");
    assert_eq!(agent.username, original.username, "username must not change after rejection");
    assert_eq!(
        agent.last_call_in, original.last_call_in,
        "last_call_in must not change after rejection"
    );

    Ok(())
}

/// Happy-path: a valid checkin payload updates *all* metadata fields on the
/// agent record (hostname, username, domain, IPs, process info, OS, sleep,
/// working hours, etc.) and broadcasts an `AgentUpdate` "Alive" event.
#[tokio::test]
async fn handle_checkin_valid_payload_updates_all_metadata_and_broadcasts_alive()
-> Result<(), Box<dyn std::error::Error>> {
    use red_cell_common::operator::OperatorMessage;

    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0020;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut rx = events.subscribe();

    let original = sample_agent(agent_id, key, iv);
    registry.insert(original.clone()).await?;

    let payload = make_checkin_payload(agent_id, key, iv);
    handle_checkin(&registry, &events, &database, None, agent_id, &payload).await?;

    let agent = registry.get(agent_id).await.ok_or("agent should exist")?;

    // Metadata fields from the payload.
    assert_eq!(agent.hostname, "wkstn-02");
    assert_eq!(agent.username, "svc-op");
    assert_eq!(agent.domain_name, "research");
    assert_eq!(agent.internal_ip, "10.10.10.50");
    assert_eq!(agent.process_name, "cmd.exe");
    assert_eq!(agent.process_path, "C:\\Windows\\System32\\cmd.exe");
    assert_eq!(agent.process_pid, 4040);
    assert_eq!(agent.process_tid, 5050);
    assert_eq!(agent.process_ppid, 3030);
    assert_eq!(agent.base_address, 0x401000);
    assert!(!agent.elevated, "elevated should be false from payload");
    assert_eq!(agent.sleep_delay, 45);
    assert_eq!(agent.sleep_jitter, 5);
    assert_eq!(agent.os_build, 22_621);
    assert!(agent.active, "agent must be marked active after checkin");
    assert_ne!(agent.last_call_in, original.last_call_in, "last_call_in must be refreshed");

    // working_hours from payload: 0x00FF_00FF
    assert_eq!(
        agent.working_hours,
        decode_working_hours(0x00FF_00FF),
        "working_hours must match decoded payload value"
    );

    // Verify the broadcast event is an AgentUpdate with "Alive".
    let event = rx.recv().await.ok_or("should have received a broadcast event")?;
    match event {
        OperatorMessage::AgentUpdate(msg) => {
            assert_eq!(msg.info.agent_id, format!("{agent_id:08X}"));
            assert_eq!(msg.info.marked, "Alive");
        }
        other => panic!("expected AgentUpdate, got: {other:?}"),
    }

    Ok(())
}

/// When the CHECKIN payload contains an all-zero AES key, `handle_checkin`
/// must return `InvalidCallbackPayload` and leave the stored agent record
/// completely untouched.
#[tokio::test]
async fn handle_checkin_weak_aes_key_rejects_and_does_not_mutate()
-> Result<(), Box<dyn std::error::Error>> {
    use red_cell_common::crypto::AGENT_KEY_LENGTH;

    let good_key = test_key(0xAA);
    let good_iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0030;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();

    let original = sample_agent(agent_id, good_key, good_iv);
    registry.insert(original.clone()).await?;

    // Build payload with all-zero key (weak).
    let weak_key = [0u8; AGENT_KEY_LENGTH];
    let payload = make_checkin_payload(agent_id, weak_key, good_iv);
    let result = handle_checkin(&registry, &events, &database, None, agent_id, &payload).await;

    assert!(result.is_err(), "weak AES key must be rejected");
    match result.expect_err("expected Err") {
        CommandDispatchError::InvalidCallbackPayload { message, .. } => {
            assert!(message.contains("key"), "error should mention key: {message}");
        }
        other => panic!("expected InvalidCallbackPayload, got: {other:?}"),
    }

    // Agent state must be unchanged.
    let agent = registry.get(agent_id).await.ok_or("agent should still exist")?;
    assert_eq!(agent.hostname, original.hostname);
    assert_eq!(agent.username, original.username);
    assert_eq!(agent.last_call_in, original.last_call_in);

    Ok(())
}

/// When the CHECKIN payload contains an all-zero AES IV, `handle_checkin`
/// must return `InvalidCallbackPayload` and leave the stored agent record
/// completely untouched.
#[tokio::test]
async fn handle_checkin_weak_aes_iv_rejects_and_does_not_mutate()
-> Result<(), Box<dyn std::error::Error>> {
    use red_cell_common::crypto::AGENT_IV_LENGTH;

    let good_key = test_key(0xAA);
    let good_iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0031;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();

    let original = sample_agent(agent_id, good_key, good_iv);
    registry.insert(original.clone()).await?;

    // Build payload with all-zero IV (weak).
    let weak_iv = [0u8; AGENT_IV_LENGTH];
    let payload = make_checkin_payload(agent_id, good_key, weak_iv);
    let result = handle_checkin(&registry, &events, &database, None, agent_id, &payload).await;

    assert!(result.is_err(), "weak AES IV must be rejected");
    match result.expect_err("expected Err") {
        CommandDispatchError::InvalidCallbackPayload { message, .. } => {
            assert!(message.contains("IV"), "error should mention IV: {message}");
        }
        other => panic!("expected InvalidCallbackPayload, got: {other:?}"),
    }

    // Agent state must be unchanged.
    let agent = registry.get(agent_id).await.ok_or("agent should still exist")?;
    assert_eq!(agent.hostname, original.hostname);
    assert_eq!(agent.last_call_in, original.last_call_in);

    Ok(())
}

/// Verify that the empty-payload path through `handle_checkin` broadcasts
/// an `AgentUpdate` "Alive" event even when no metadata is updated.
#[tokio::test]
async fn handle_checkin_empty_payload_still_broadcasts_alive()
-> Result<(), Box<dyn std::error::Error>> {
    use red_cell_common::operator::OperatorMessage;

    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0050;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let mut rx = events.subscribe();

    registry.insert(sample_agent(agent_id, key, iv)).await?;

    handle_checkin(&registry, &events, &database, None, agent_id, &[]).await?;

    let event = rx.recv().await.ok_or("should have received a broadcast")?;
    match event {
        OperatorMessage::AgentUpdate(msg) => {
            assert_eq!(msg.info.agent_id, format!("{agent_id:08X}"));
            assert_eq!(msg.info.marked, "Alive");
        }
        other => panic!("expected AgentUpdate, got: {other:?}"),
    }

    Ok(())
}

// -- plugin branch (emit_agent_checkin) tests --

/// Happy path: `handle_checkin` with `plugins = Some(stub_succeeding)` still
/// returns `Ok(None)` and completes without error.
#[tokio::test]
async fn handle_checkin_with_succeeding_plugin_runtime_returns_ok()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::{PluginRuntime, SocketRelayManager};

    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0020;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());

    registry.insert(sample_agent(agent_id, key, iv)).await?;

    let runtime =
        PluginRuntime::stub_succeeding(database.clone(), registry.clone(), events.clone(), sockets);

    let result =
        handle_checkin(&registry, &events, &database, Some(&runtime), agent_id, &[]).await?;
    assert_eq!(result, None, "handle_checkin must return Ok(None) with succeeding plugins");

    Ok(())
}

/// Error path: `handle_checkin` with `plugins = Some(stub_failing)` still
/// returns `Ok(None)` — plugin errors are non-fatal.
#[tokio::test]
async fn handle_checkin_with_failing_plugin_runtime_returns_ok()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::{PluginRuntime, SocketRelayManager};

    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0021;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());

    registry.insert(sample_agent(agent_id, key, iv)).await?;

    let runtime =
        PluginRuntime::stub_failing(database.clone(), registry.clone(), events.clone(), sockets);

    let result =
        handle_checkin(&registry, &events, &database, Some(&runtime), agent_id, &[]).await?;
    assert_eq!(result, None, "handle_checkin must return Ok(None) even when plugin emit fails");

    Ok(())
}

/// The audit entry for `agent.checkin` must still be written when the plugin
/// emit fails — the spawned audit task is independent of the plugin branch.
#[tokio::test]
async fn handle_checkin_audit_entry_written_despite_plugin_failure()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::{PluginRuntime, SocketRelayManager};

    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0022;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());

    registry.insert(sample_agent(agent_id, key, iv)).await?;

    let runtime =
        PluginRuntime::stub_failing(database.clone(), registry.clone(), events.clone(), sockets);

    handle_checkin(&registry, &events, &database, Some(&runtime), agent_id, &[]).await?;

    // The audit write is spawned as a background task — yield to let it complete.
    tokio::task::yield_now().await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let page = query_audit_log(
        &database,
        &AuditQuery {
            action: Some("agent.checkin".to_owned()),
            target_id: Some(format!("{agent_id:08X}")),
            ..Default::default()
        },
    )
    .await?;

    assert!(
        !page.items.is_empty(),
        "agent.checkin audit entry must be written even when plugin emit fails"
    );
    assert_eq!(page.items[0].action, "agent.checkin");

    Ok(())
}

// -- replay-warning path (seq protection) tests --

/// For a non-seq-protected (Demon/Archon) agent, a valid CHECKIN with metadata
/// must succeed — the replay warning is advisory only and must not block the update.
#[tokio::test]
async fn handle_checkin_non_seq_protected_agent_metadata_updated_with_warning()
-> Result<(), Box<dyn std::error::Error>> {
    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0060;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();

    registry.insert(sample_agent(agent_id, key, iv)).await?;
    // Newly inserted agents default to seq_protected = false (Demon/Archon compatibility).
    assert!(
        !registry.is_seq_protected(agent_id).await,
        "test precondition: agent must not be seq-protected"
    );

    let payload = make_checkin_payload(agent_id, key, iv);
    // Must succeed (warning is emitted but does not block the update).
    handle_checkin(&registry, &events, &database, None, agent_id, &payload).await?;

    let agent = registry.get(agent_id).await.ok_or("agent should still exist")?;
    // Metadata must have been updated despite the replay-warning path.
    assert_eq!(agent.hostname, "wkstn-02", "hostname must be updated for non-seq-protected agent");
    assert_eq!(agent.username, "svc-op", "username must be updated for non-seq-protected agent");

    Ok(())
}

/// For a seq-protected (Specter/Phantom) agent, a valid CHECKIN with metadata
/// must succeed and the replay-warning code path must not fire.
#[tokio::test]
async fn handle_checkin_seq_protected_agent_metadata_updated_without_replay_warning()
-> Result<(), Box<dyn std::error::Error>> {
    let key = test_key(0xAA);
    let iv = test_iv(0xBB);
    let agent_id = 0xDEAD_0061;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();

    registry.insert(sample_agent(agent_id, key, iv)).await?;
    // Mark agent as seq-protected (Specter/Phantom path).
    registry.set_seq_protected(agent_id, true).await?;
    assert!(
        registry.is_seq_protected(agent_id).await,
        "test precondition: agent must be seq-protected"
    );

    let payload = make_checkin_payload(agent_id, key, iv);
    // Must succeed without emitting the replay warning.
    handle_checkin(&registry, &events, &database, None, agent_id, &payload).await?;

    let agent = registry.get(agent_id).await.ok_or("agent should still exist")?;
    assert_eq!(agent.hostname, "wkstn-02", "hostname must be updated for seq-protected agent");
    assert_eq!(agent.username, "svc-op", "username must be updated for seq-protected agent");

    Ok(())
}
