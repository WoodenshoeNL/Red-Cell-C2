use std::sync::Arc;

use super::super::AgentRegistry;
use super::{sample_agent_with_crypto, test_database, test_iv, test_key};
use crate::database::TeamserverError;

#[tokio::test]
async fn check_callback_seq_accepts_first_seq_after_init() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let agent = sample_agent_with_crypto(0x200A_0001, test_key(0xE1), test_iv(0xF1));
    registry.insert(agent.clone()).await?;

    // With last_seen_seq=0 (default), any seq in 1..=MAX_SEQ_GAP must be accepted.
    registry.check_callback_seq(agent.agent_id, 1).await?;
    Ok(())
}

#[tokio::test]
async fn check_callback_seq_rejects_replay() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let agent = sample_agent_with_crypto(0x200A_0002, test_key(0xE2), test_iv(0xF2));
    registry.insert(agent.clone()).await?;

    // Advance to seq=5
    registry.advance_last_seen_seq(agent.agent_id, 5).await?;

    // Same seq must be rejected as a replay.
    let err = registry
        .check_callback_seq(agent.agent_id, 5)
        .await
        .expect_err("same seq must be rejected");
    assert!(
        matches!(
            err,
            TeamserverError::CallbackSeqReplay { agent_id: _, incoming_seq: 5, last_seen_seq: 5 }
        ),
        "expected CallbackSeqReplay, got: {err:?}"
    );

    // Lower seq must also be rejected.
    let err = registry
        .check_callback_seq(agent.agent_id, 3)
        .await
        .expect_err("lower seq must be rejected");
    assert!(matches!(err, TeamserverError::CallbackSeqReplay { .. }), "got: {err:?}");

    Ok(())
}

#[tokio::test]
async fn check_callback_seq_rejects_large_gap() -> Result<(), TeamserverError> {
    use red_cell_common::callback_seq::MAX_SEQ_GAP;

    let registry = AgentRegistry::new(test_database().await?);
    let agent = sample_agent_with_crypto(0x200A_0003, test_key(0xE3), test_iv(0xF3));
    registry.insert(agent.clone()).await?;

    let err = registry
        .check_callback_seq(agent.agent_id, MAX_SEQ_GAP + 1)
        .await
        .expect_err("gap > MAX_SEQ_GAP must be rejected");
    assert!(
        matches!(err, TeamserverError::CallbackSeqGapTooLarge { .. }),
        "expected CallbackSeqGapTooLarge, got: {err:?}"
    );

    // Exactly MAX_SEQ_GAP must be accepted.
    registry.check_callback_seq(agent.agent_id, MAX_SEQ_GAP).await?;

    Ok(())
}

#[tokio::test]
async fn advance_last_seen_seq_persists_across_reload() -> Result<(), TeamserverError> {
    let database = test_database().await?;

    {
        let registry = AgentRegistry::new(database.clone());
        let agent = sample_agent_with_crypto(0x200A_0004, test_key(0xE4), test_iv(0xF4));
        registry.insert(agent.clone()).await?;
        registry.advance_last_seen_seq(agent.agent_id, 42).await?;
    }

    let registry = AgentRegistry::load(database.clone()).await?;
    let persisted =
        database.agents().get_persisted(0x200A_0004).await?.expect("agent must still exist");
    assert_eq!(persisted.last_seen_seq, 42, "last_seen_seq must survive registry reload");

    // After reload, check_callback_seq must also use the persisted value.
    let err = registry
        .check_callback_seq(0x200A_0004, 42)
        .await
        .expect_err("seq=42 must be rejected after loading last_seen_seq=42");
    assert!(matches!(err, TeamserverError::CallbackSeqReplay { .. }));

    Ok(())
}

#[tokio::test]
async fn set_seq_protected_persists_and_controls_is_seq_protected() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database.clone());
    let agent = sample_agent_with_crypto(0x200A_0005, test_key(0xE5), test_iv(0xF5));
    registry.insert(agent.clone()).await?;

    // Default must be false.
    assert!(!registry.is_seq_protected(agent.agent_id).await);

    // Enable seq-protection.
    registry.set_seq_protected(agent.agent_id, true).await?;
    assert!(registry.is_seq_protected(agent.agent_id).await);

    // Must be persisted.
    let persisted = database.agents().get_persisted(agent.agent_id).await?.expect("must exist");
    assert!(persisted.seq_protected, "seq_protected must be persisted to DB");

    // Disable again.
    registry.set_seq_protected(agent.agent_id, false).await?;
    assert!(!registry.is_seq_protected(agent.agent_id).await);

    Ok(())
}

#[tokio::test]
async fn reregister_full_resets_last_seen_seq() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database.clone());
    let key = test_key(0xE6);
    let iv = test_iv(0xF6);
    let mut agent = sample_agent_with_crypto(0x200A_0006, key, iv);
    agent.active = true;
    registry.insert_full(agent.clone(), "http", 0, false, false, false).await?;

    // Advance seq so it is non-zero before re-registration.
    registry.advance_last_seen_seq(agent.agent_id, 99).await?;

    // Re-register (simulates agent restart).
    registry.reregister_full(agent.clone(), "http", false, false).await?;

    // last_seen_seq must be reset to 0.
    let persisted = database.agents().get_persisted(agent.agent_id).await?.expect("must exist");
    assert_eq!(persisted.last_seen_seq, 0, "reregister_full must reset last_seen_seq to 0");

    // check_callback_seq should accept seq=1 after reset.
    registry.check_callback_seq(agent.agent_id, 1).await?;

    Ok(())
}

#[tokio::test]
async fn is_seq_protected_returns_false_for_unknown_agent() {
    let registry = AgentRegistry::new(test_database().await.expect("db"));
    assert!(!registry.is_seq_protected(0xDEAD_BEEF).await);
}

#[tokio::test]
async fn check_and_advance_callback_seq_accepts_and_advances() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let agent = sample_agent_with_crypto(0x200A_0007, test_key(0xE7), test_iv(0xF7));
    registry.insert(agent.clone()).await?;

    registry.check_and_advance_callback_seq(agent.agent_id, 1).await?;

    // Same seq must now be rejected as a replay.
    let err = registry
        .check_and_advance_callback_seq(agent.agent_id, 1)
        .await
        .expect_err("replay of seq=1 must be rejected");
    assert!(matches!(err, TeamserverError::CallbackSeqReplay { .. }), "got: {err:?}");

    // Forward progress still works.
    registry.check_and_advance_callback_seq(agent.agent_id, 2).await?;
    Ok(())
}

#[tokio::test]
async fn check_and_advance_callback_seq_rejects_replay_without_persisting()
-> Result<(), TeamserverError> {
    // A rejected seq must not advance the stored value — a later legitimate callback
    // with that seq must still be accepted.
    let database = test_database().await?;
    let registry = AgentRegistry::new(database.clone());
    let agent = sample_agent_with_crypto(0x200A_0008, test_key(0xE8), test_iv(0xF8));
    registry.insert(agent.clone()).await?;

    registry.check_and_advance_callback_seq(agent.agent_id, 5).await?;

    // Replay attempt at seq=5 must fail and must NOT touch stored state.
    let err = registry
        .check_and_advance_callback_seq(agent.agent_id, 5)
        .await
        .expect_err("replay must be rejected");
    assert!(matches!(err, TeamserverError::CallbackSeqReplay { .. }));

    let persisted =
        database.agents().get_persisted(agent.agent_id).await?.expect("agent must exist");
    assert_eq!(persisted.last_seen_seq, 5, "rejected replay must not advance last_seen_seq");
    Ok(())
}

/// Regression test for red-cell-c2-6ae3y: split check/advance created a TOCTOU window
/// where two concurrent callbacks with the same seq could both pass validation.
/// With the atomic check-and-advance, exactly one concurrent caller must succeed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn check_and_advance_callback_seq_is_atomic_under_concurrency() -> Result<(), TeamserverError>
{
    let registry = Arc::new(AgentRegistry::new(test_database().await?));
    let agent = sample_agent_with_crypto(0x200A_0009, test_key(0xE9), test_iv(0xF9));
    registry.insert(agent.clone()).await?;

    const CONCURRENT_CALLERS: usize = 16;
    const TARGET_SEQ: u64 = 1;

    let barrier = Arc::new(tokio::sync::Barrier::new(CONCURRENT_CALLERS));
    let mut handles = Vec::with_capacity(CONCURRENT_CALLERS);
    for _ in 0..CONCURRENT_CALLERS {
        let registry = Arc::clone(&registry);
        let barrier = Arc::clone(&barrier);
        let agent_id = agent.agent_id;
        handles.push(tokio::spawn(async move {
            // Synchronise tasks so all calls pile up on the same seq simultaneously.
            barrier.wait().await;
            registry.check_and_advance_callback_seq(agent_id, TARGET_SEQ).await
        }));
    }

    let mut successes = 0usize;
    let mut replays = 0usize;
    for h in handles {
        match h.await.expect("task must not panic") {
            Ok(()) => successes += 1,
            Err(TeamserverError::CallbackSeqReplay { .. }) => replays += 1,
            Err(other) => panic!("unexpected error from concurrent caller: {other:?}"),
        }
    }

    assert_eq!(successes, 1, "exactly one concurrent caller must advance the seq");
    assert_eq!(
        replays,
        CONCURRENT_CALLERS - 1,
        "all other concurrent callers must be rejected as replays"
    );
    Ok(())
}
