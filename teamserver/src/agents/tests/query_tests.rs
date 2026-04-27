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

#[tokio::test]
async fn list_with_listeners_pairs_agents_with_correct_listener() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);

    let agent_a = sample_agent(0x1000_0003);
    let agent_b = sample_agent(0x1000_0001);
    let agent_c = sample_agent(0x1000_0002);

    registry.insert_with_listener(agent_a.clone(), "https-443").await?;
    registry.insert_with_listener(agent_b.clone(), "smb-pipe").await?;
    registry.insert_with_listener(agent_c.clone(), "https-443").await?;

    let result = registry.list_with_listeners().await;

    assert_eq!(result.len(), 3);
    // Results must be sorted by agent_id ascending.
    assert_eq!(result[0], (agent_b, "smb-pipe".to_owned()));
    assert_eq!(result[1], (agent_c, "https-443".to_owned()));
    assert_eq!(result[2], (agent_a, "https-443".to_owned()));
    Ok(())
}

#[tokio::test]
async fn list_with_listeners_empty_registry() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let result = registry.list_with_listeners().await;
    assert!(result.is_empty());
    Ok(())
}
