use std::sync::Arc;

use super::super::AgentRegistry;
use super::{sample_agent, test_database};
use crate::database::TeamserverError;

#[tokio::test]
async fn update_agent_replaces_snapshot_and_persists() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database.clone());
    let mut agent = sample_agent(0x1000_0005);
    registry.insert_with_listener(agent.clone(), "http-alpha").await?;

    agent.sleep_delay = 60;
    agent.reason = "updated".to_owned();
    agent.last_call_in = "2026-03-09T20:00:00Z".to_owned();
    registry.update_agent_with_listener(agent.clone(), "http-beta").await?;

    assert_eq!(registry.get(agent.agent_id).await, Some(agent.clone()));
    assert_eq!(database.agents().get(agent.agent_id).await?, Some(agent));
    assert_eq!(registry.listener_name(0x1000_0005).await.as_deref(), Some("http-beta"));
    Ok(())
}

#[tokio::test]
async fn mark_dead_updates_memory_and_database() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database.clone());
    let agent = sample_agent(0x1000_0006);
    let cleaned = Arc::new(std::sync::Mutex::new(Vec::new()));
    let cleanup_observer = cleaned.clone();
    registry.register_cleanup_hook(move |agent_id| {
        let cleaned = cleanup_observer.clone();
        async move {
            let mut cleaned = cleaned.lock().expect("cleanup tracker lock should succeed");
            cleaned.push(agent_id);
        }
    });
    registry.insert(agent.clone()).await?;

    registry.mark_dead(agent.agent_id, "lost contact").await?;

    let stored = registry
        .get(agent.agent_id)
        .await
        .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
    assert!(!stored.active);
    assert_eq!(stored.reason, "lost contact");

    let persisted = database
        .agents()
        .get(agent.agent_id)
        .await?
        .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
    assert!(!persisted.active);
    assert_eq!(persisted.reason, "lost contact");
    assert_eq!(
        cleaned.lock().expect("cleanup tracker lock should succeed").as_slice(),
        &[agent.agent_id]
    );

    Ok(())
}

#[tokio::test]
async fn set_note_updates_memory_and_database() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database.clone());
    let agent = sample_agent(0x1000_000C);
    registry.insert(agent.clone()).await?;

    let updated = registry.set_note(agent.agent_id, "tracked through VPN").await?;

    assert_eq!(updated.note, "tracked through VPN");
    assert_eq!(
        registry
            .get(agent.agent_id)
            .await
            .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?
            .note,
        "tracked through VPN"
    );
    assert_eq!(
        database
            .agents()
            .get(agent.agent_id)
            .await?
            .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?
            .note,
        "tracked through VPN"
    );

    Ok(())
}

#[tokio::test]
async fn remove_deletes_agent_from_memory_and_database() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database.clone());
    let agent = sample_agent(0x1000_000D);
    let cleaned = Arc::new(std::sync::Mutex::new(Vec::new()));
    let cleanup_observer = cleaned.clone();
    registry.register_cleanup_hook(move |agent_id| {
        let cleaned = cleanup_observer.clone();
        async move {
            let mut cleaned = cleaned.lock().expect("cleanup tracker lock should succeed");
            cleaned.push(agent_id);
        }
    });
    registry.insert(agent.clone()).await?;

    let removed = registry.remove(agent.agent_id).await?;

    assert_eq!(removed, agent);
    assert!(registry.get(agent.agent_id).await.is_none());
    assert_eq!(database.agents().get(agent.agent_id).await?, None);
    assert_eq!(
        cleaned.lock().expect("cleanup tracker lock should succeed").as_slice(),
        &[agent.agent_id]
    );

    Ok(())
}

#[tokio::test]
async fn set_last_call_in_updates_memory_and_database() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database.clone());
    let agent = sample_agent(0x1000_000B);
    registry.insert(agent.clone()).await?;

    let updated = registry.set_last_call_in(agent.agent_id, "2026-03-09T21:00:00Z").await?;

    assert_eq!(updated.last_call_in, "2026-03-09T21:00:00Z");
    assert_eq!(
        registry
            .get(agent.agent_id)
            .await
            .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?
            .last_call_in,
        "2026-03-09T21:00:00Z"
    );
    assert_eq!(
        database
            .agents()
            .get(agent.agent_id)
            .await?
            .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?
            .last_call_in,
        "2026-03-09T21:00:00Z"
    );

    Ok(())
}

#[tokio::test]
async fn set_last_call_in_revives_inactive_agent_and_clears_reason() -> Result<(), TeamserverError>
{
    let database = test_database().await?;
    let registry = AgentRegistry::new(database.clone());
    let agent = sample_agent(0x1000_00C0);
    registry.insert(agent.clone()).await?;
    registry.mark_dead(agent.agent_id, "agent timed out").await?;

    let updated = registry.set_last_call_in(agent.agent_id, "2026-03-09T21:05:00Z").await?;

    assert!(updated.active);
    assert!(updated.reason.is_empty());
    assert_eq!(updated.last_call_in, "2026-03-09T21:05:00Z");
    let persisted = database
        .agents()
        .get(agent.agent_id)
        .await?
        .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
    assert!(persisted.active);
    assert!(persisted.reason.is_empty());

    Ok(())
}

#[tokio::test]
async fn set_last_call_in_revival_persists_cleared_reason_across_load()
-> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database.clone());
    let agent = sample_agent(0x1000_00C1);
    registry.insert(agent.clone()).await?;
    registry.mark_dead(agent.agent_id, "connection lost").await?;

    registry.set_last_call_in(agent.agent_id, "2026-03-09T22:00:00Z").await?;

    let reloaded = AgentRegistry::load(database).await?;
    let restored = reloaded
        .get(agent.agent_id)
        .await
        .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
    assert!(restored.active);
    assert!(restored.reason.is_empty());
    assert_eq!(restored.last_call_in, "2026-03-09T22:00:00Z");

    Ok(())
}

#[tokio::test]
async fn set_last_call_in_returns_agent_not_found_for_unknown_id() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database);
    let unknown_id = 0x1000_00C2_u32;

    let error = registry
        .set_last_call_in(unknown_id, "2026-03-09T22:00:00Z")
        .await
        .expect_err("set_last_call_in must fail for an unknown agent_id");

    assert!(matches!(error, TeamserverError::AgentNotFound { agent_id } if agent_id == unknown_id));

    Ok(())
}

#[tokio::test]
async fn set_last_call_in_rolls_back_in_memory_state_on_persistence_failure()
-> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database.clone());
    let mut agent = sample_agent(0x1000_00C3);
    // Start the agent as inactive with a reason so the revival branch is exercised.
    agent.active = false;
    agent.reason = "connection lost".to_owned();
    agent.last_call_in = "2026-03-09T18:00:00Z".to_owned();
    registry.insert(agent.clone()).await?;
    // Mark dead through the registry so persistence is consistent.
    registry.mark_dead(agent.agent_id, "connection lost").await?;

    let before = registry
        .get(agent.agent_id)
        .await
        .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;

    // Close the pool to force any subsequent DB write to fail.
    database.close().await;

    let result = registry.set_last_call_in(agent.agent_id, "2026-03-10T12:00:00Z").await;
    assert!(result.is_err(), "set_last_call_in must fail when the database is closed");

    // The in-memory record must be unchanged — no partial mutation.
    let after = registry
        .get(agent.agent_id)
        .await
        .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
    assert_eq!(after.last_call_in, before.last_call_in);
    assert_eq!(after.active, before.active);
    assert_eq!(after.reason, before.reason);

    Ok(())
}

#[tokio::test]
async fn mark_dead_returns_agent_not_found_for_unknown_id() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database);
    let unknown_id = 0xFFFF_FFFF_u32;

    let error = registry
        .mark_dead(unknown_id, "reason")
        .await
        .expect_err("mark_dead must fail for an unknown agent_id");

    assert!(matches!(error, TeamserverError::AgentNotFound { agent_id } if agent_id == unknown_id));

    Ok(())
}

#[tokio::test]
async fn mark_dead_on_already_dead_agent_is_idempotent() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database.clone());
    let agent = sample_agent(0x1000_00DD);
    let cleaned = Arc::new(std::sync::Mutex::new(Vec::new()));
    let cleanup_observer = cleaned.clone();
    registry.register_cleanup_hook(move |agent_id| {
        let cleaned = cleanup_observer.clone();
        async move {
            let mut cleaned = cleaned.lock().expect("cleanup tracker lock should succeed");
            cleaned.push(agent_id);
        }
    });
    registry.insert(agent.clone()).await?;

    // First call: mark the agent dead.
    registry.mark_dead(agent.agent_id, "lost contact").await?;
    let after_first = registry
        .get(agent.agent_id)
        .await
        .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
    assert!(!after_first.active);
    assert_eq!(after_first.reason, "lost contact");

    // Second call: mark the already-dead agent dead again with a different reason.
    registry.mark_dead(agent.agent_id, "operator kill").await?;
    let after_second = registry
        .get(agent.agent_id)
        .await
        .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
    assert!(!after_second.active);
    assert_eq!(after_second.reason, "operator kill");

    // Verify the database also reflects the updated reason.
    let persisted = database
        .agents()
        .get(agent.agent_id)
        .await?
        .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
    assert!(!persisted.active);
    assert_eq!(persisted.reason, "operator kill");

    // Cleanup hooks fire on every mark_dead call (current behavior).
    assert_eq!(
        cleaned.lock().expect("cleanup tracker lock should succeed").as_slice(),
        &[agent.agent_id, agent.agent_id]
    );

    Ok(())
}

#[tokio::test]
async fn set_note_returns_agent_not_found_for_unknown_id() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database);
    let unknown_id = 0xFFFF_FFFF_u32;

    let error = registry
        .set_note(unknown_id, "note")
        .await
        .expect_err("set_note must fail for an unknown agent_id");

    assert!(matches!(error, TeamserverError::AgentNotFound { agent_id } if agent_id == unknown_id));

    Ok(())
}
