use super::super::AgentRegistry;
use super::{sample_agent_with_crypto, test_database, test_iv, test_key};
use crate::database::TeamserverError;

// ── apply_replay_lockout_config ────────────────────────────────────────────────

/// Both `None` → no-op: the registry keeps the compile-time defaults.
///
/// Verified behaviorally: after `apply_replay_lockout_config(None, None)` the
/// registry still requires the default K consecutive replays before triggering
/// lockout — i.e. the threshold was not changed to some other value.
#[tokio::test]
async fn apply_replay_lockout_config_both_none_is_noop() -> Result<(), TeamserverError> {
    use red_cell_common::callback_seq::REPLAY_LOCKOUT_THRESHOLD;

    let mut registry = AgentRegistry::new(test_database().await?);

    // Call with both None — must be a no-op.
    registry.apply_replay_lockout_config(None, None);

    let agent = sample_agent_with_crypto(0x200E_0001, test_key(0xE1), test_iv(0xF1));
    registry.insert(agent.clone()).await?;
    registry.check_and_advance_callback_seq(agent.agent_id, 10).await?;

    // K-1 replay attempts must yield CallbackSeqReplay (not yet locked out).
    // If the threshold had been set to something other than the default these
    // counts would differ.
    for attempt in 1..(REPLAY_LOCKOUT_THRESHOLD) {
        let err = registry
            .check_and_advance_callback_seq(agent.agent_id, 5)
            .await
            .expect_err("replay must be rejected");
        assert!(
            matches!(err, TeamserverError::CallbackSeqReplay { .. }),
            "attempt {attempt}: expected CallbackSeqReplay (default threshold intact), got: {err:?}"
        );
    }

    // K-th attempt must flip to lockout — confirming the default threshold is active.
    let err = registry
        .check_and_advance_callback_seq(agent.agent_id, 5)
        .await
        .expect_err("K-th replay must trigger lockout");
    assert!(
        matches!(err, TeamserverError::CallbackSeqReplayLockout { .. }),
        "K-th attempt: expected CallbackSeqReplayLockout, got: {err:?}"
    );

    Ok(())
}

/// `threshold=Some(2), duration_secs=None` → threshold updated, duration stays default.
///
/// A lower-than-default threshold of 2 means lockout fires on the 2nd replay
/// rather than the default K-th. Duration is not changed, so the lockout persists.
#[tokio::test]
async fn apply_replay_lockout_config_threshold_some_duration_none() -> Result<(), TeamserverError> {
    use red_cell_common::callback_seq::REPLAY_LOCKOUT_THRESHOLD;

    const CUSTOM_THRESHOLD: u32 = 2;
    // Sanity guard: the custom value must be less than the default so the
    // test can distinguish between them.
    assert!(
        CUSTOM_THRESHOLD < REPLAY_LOCKOUT_THRESHOLD,
        "test requires CUSTOM_THRESHOLD < default threshold"
    );

    let mut registry = AgentRegistry::new(test_database().await?);
    registry.apply_replay_lockout_config(Some(CUSTOM_THRESHOLD), None);

    let agent = sample_agent_with_crypto(0x200E_0002, test_key(0xE2), test_iv(0xF2));
    registry.insert(agent.clone()).await?;
    registry.check_and_advance_callback_seq(agent.agent_id, 10).await?;

    // First replay (attempt 1 of 2): must be CallbackSeqReplay, not yet locked.
    let err = registry
        .check_and_advance_callback_seq(agent.agent_id, 5)
        .await
        .expect_err("first replay must be rejected");
    assert!(
        matches!(err, TeamserverError::CallbackSeqReplay { .. }),
        "attempt 1: expected CallbackSeqReplay, got: {err:?}"
    );

    // Second replay (attempt 2 of 2, at the custom threshold): must trigger lockout.
    let err = registry
        .check_and_advance_callback_seq(agent.agent_id, 5)
        .await
        .expect_err("second replay must trigger lockout (custom threshold=2)");
    assert!(
        matches!(err, TeamserverError::CallbackSeqReplayLockout { .. }),
        "attempt 2: expected CallbackSeqReplayLockout at custom threshold, got: {err:?}"
    );

    // The lockout must still be active (duration was not changed to 0).
    let err = registry
        .check_and_advance_callback_seq(agent.agent_id, 11)
        .await
        .expect_err("valid seq must still be blocked while locked out");
    assert!(
        matches!(err, TeamserverError::CallbackSeqReplayLockout { .. }),
        "post-lockout valid seq: expected ReplayLockout (duration intact), got: {err:?}"
    );

    Ok(())
}

/// `threshold=Some(2), duration_secs=Some(120)` → both values updated.
///
/// Lockout fires after exactly 2 replays and persists (positive duration).
#[tokio::test]
async fn apply_replay_lockout_config_both_some_happy_path() -> Result<(), TeamserverError> {
    use red_cell_common::callback_seq::REPLAY_LOCKOUT_THRESHOLD;

    const CUSTOM_THRESHOLD: u32 = 2;
    const CUSTOM_DURATION: u64 = 120;
    assert!(
        CUSTOM_THRESHOLD < REPLAY_LOCKOUT_THRESHOLD,
        "test requires CUSTOM_THRESHOLD < default threshold"
    );

    let mut registry = AgentRegistry::new(test_database().await?);
    registry.apply_replay_lockout_config(Some(CUSTOM_THRESHOLD), Some(CUSTOM_DURATION));

    let agent = sample_agent_with_crypto(0x200E_0003, test_key(0xE3), test_iv(0xF3));
    registry.insert(agent.clone()).await?;
    registry.check_and_advance_callback_seq(agent.agent_id, 10).await?;

    // Attempt 1: CallbackSeqReplay (below threshold).
    let err = registry
        .check_and_advance_callback_seq(agent.agent_id, 5)
        .await
        .expect_err("first replay must be rejected");
    assert!(
        matches!(err, TeamserverError::CallbackSeqReplay { .. }),
        "attempt 1: expected CallbackSeqReplay, got: {err:?}"
    );

    // Attempt 2: CallbackSeqReplayLockout (hits custom threshold).
    let err = registry
        .check_and_advance_callback_seq(agent.agent_id, 5)
        .await
        .expect_err("second replay must trigger lockout");
    assert!(
        matches!(err, TeamserverError::CallbackSeqReplayLockout { .. }),
        "attempt 2: expected CallbackSeqReplayLockout, got: {err:?}"
    );

    // Lockout still active (custom positive duration means it has not expired).
    let err = registry
        .check_and_advance_callback_seq(agent.agent_id, 11)
        .await
        .expect_err("valid seq must be blocked during lockout");
    assert!(
        matches!(err, TeamserverError::CallbackSeqReplayLockout { .. }),
        "post-lockout: expected ReplayLockout (custom duration active), got: {err:?}"
    );

    Ok(())
}

/// `threshold=Some(0), duration_secs=None` → degenerate threshold is rejected.
///
/// `set_replay_lockout_params` silently ignores threshold=0. The wrapper must
/// propagate this correctly: the stored threshold must remain the default.
#[tokio::test]
async fn apply_replay_lockout_config_degenerate_threshold_keeps_default()
-> Result<(), TeamserverError> {
    use red_cell_common::callback_seq::REPLAY_LOCKOUT_THRESHOLD;

    let mut registry = AgentRegistry::new(test_database().await?);

    // Degenerate: threshold=0 must be rejected by set_replay_lockout_params.
    // duration_secs=None means duration stays at compile-time default.
    registry.apply_replay_lockout_config(Some(0), None);

    let agent = sample_agent_with_crypto(0x200E_0004, test_key(0xE4), test_iv(0xF4));
    registry.insert(agent.clone()).await?;
    registry.check_and_advance_callback_seq(agent.agent_id, 10).await?;

    // K-1 attempts must still produce CallbackSeqReplay, not lockout.
    // If threshold=0 had been stored we would see lockout immediately.
    for attempt in 1..(REPLAY_LOCKOUT_THRESHOLD) {
        let err = registry
            .check_and_advance_callback_seq(agent.agent_id, 5)
            .await
            .expect_err("replay must be rejected");
        assert!(
            matches!(err, TeamserverError::CallbackSeqReplay { .. }),
            "attempt {attempt}: expected CallbackSeqReplay (degenerate threshold ignored), got: {err:?}"
        );
    }

    // K-th attempt must trigger lockout (default threshold is in force).
    let err = registry
        .check_and_advance_callback_seq(agent.agent_id, 5)
        .await
        .expect_err("K-th replay must trigger lockout with default threshold");
    assert!(
        matches!(err, TeamserverError::CallbackSeqReplayLockout { .. }),
        "K-th attempt: expected CallbackSeqReplayLockout (default threshold), got: {err:?}"
    );

    Ok(())
}
