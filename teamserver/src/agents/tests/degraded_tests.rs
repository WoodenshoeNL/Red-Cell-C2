use super::super::AgentRegistry;
use super::{sample_agent, test_database};
use crate::database::TeamserverError;

#[tokio::test]
async fn insert_queues_write_when_degraded() -> Result<(), TeamserverError> {
    use crate::database::{DatabaseHealthState, WriteQueue};

    let db = test_database().await?;
    let mut registry = AgentRegistry::new(db.clone());

    let health = DatabaseHealthState::new_degraded();
    let wq = WriteQueue::new(16);
    registry.set_degraded_mode_support(health, wq.clone());

    let agent = sample_agent(0xDEAD_0001);
    registry.insert(agent.clone()).await?;

    // Agent should be in memory despite degraded DB.
    assert!(registry.get(0xDEAD_0001).await.is_some());
    // Write should be queued.
    assert_eq!(wq.len().await, 1);

    // Flush the queue and verify the agent is persisted.
    let (ok, fail) = wq.flush(&db).await;
    assert_eq!(ok, 1);
    assert_eq!(fail, 0);

    // Verify in DB.
    let persisted = db.agents().get(0xDEAD_0001).await?;
    assert!(persisted.is_some());
    Ok(())
}

#[tokio::test]
async fn update_queues_write_when_degraded() -> Result<(), TeamserverError> {
    use crate::database::{DatabaseHealthState, WriteQueue};

    let db = test_database().await?;
    let mut registry = AgentRegistry::new(db.clone());

    // Insert while healthy.
    let agent = sample_agent(0xDEAD_0002);
    registry.insert(agent.clone()).await?;

    // Now enter degraded mode.
    let health = DatabaseHealthState::new_degraded();
    let wq = WriteQueue::new(16);
    registry.set_degraded_mode_support(health, wq.clone());

    // Update agent metadata.
    let mut updated = agent.clone();
    updated.hostname = "wkstn-updated".to_owned();
    registry.update_agent(updated).await?;

    // In-memory state should be updated.
    let in_mem = registry.get(0xDEAD_0002).await.expect("should exist");
    assert_eq!(in_mem.hostname, "wkstn-updated");

    // Write should be queued.
    assert_eq!(wq.len().await, 1);

    // Flush.
    let (ok, fail) = wq.flush(&db).await;
    assert_eq!(ok, 1);
    assert_eq!(fail, 0);
    Ok(())
}

#[tokio::test]
async fn set_ctr_offset_queues_when_degraded() -> Result<(), TeamserverError> {
    use crate::database::{DatabaseHealthState, WriteQueue};

    let db = test_database().await?;
    let mut registry = AgentRegistry::new(db.clone());

    let agent = sample_agent(0xDEAD_0003);
    registry.insert(agent).await?;

    let health = DatabaseHealthState::new_degraded();
    let wq = WriteQueue::new(16);
    registry.set_degraded_mode_support(health, wq.clone());

    registry.set_ctr_offset(0xDEAD_0003, 42).await?;

    // In-memory offset should be updated.
    assert_eq!(registry.ctr_offset(0xDEAD_0003).await?, 42);
    // DB write should be queued.
    assert_eq!(wq.len().await, 1);

    let (ok, _) = wq.flush(&db).await;
    assert_eq!(ok, 1);
    Ok(())
}
