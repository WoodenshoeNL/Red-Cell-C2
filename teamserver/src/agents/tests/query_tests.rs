use super::super::AgentRegistry;
use super::{sample_agent, test_database};
use crate::database::TeamserverError;

#[tokio::test]
async fn list_active_filters_dead_agents() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let alive = sample_agent(0x1000_0003);
    let mut dead = sample_agent(0x1000_0004);
    dead.active = false;
    dead.reason = "lost".to_owned();

    registry.insert(alive.clone()).await?;
    registry.insert(dead).await?;

    assert_eq!(registry.list_active().await, vec![alive]);
    Ok(())
}

#[tokio::test]
async fn list_returns_active_and_inactive_agents() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let alive = sample_agent(0x1000_0001);
    let mut dead = sample_agent(0x1000_0002);
    dead.active = false;
    dead.reason = "operator requested exit".to_owned();

    registry.insert(dead.clone()).await?;
    registry.insert(alive.clone()).await?;

    assert_eq!(registry.list().await, vec![alive, dead]);
    Ok(())
}
