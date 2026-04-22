use super::super::SocketRelayError;
use super::{register_pending_client, sample_agent, test_manager};

#[tokio::test]
async fn remove_agent_clears_tracked_socket_state() -> Result<(), SocketRelayError> {
    let (_database, registry, manager) = test_manager().await?;
    registry.insert(sample_agent(0xDEAD_BEEF)).await?;

    manager.add_socks_server(0xDEAD_BEEF, "0").await?;
    assert!(manager.state.read().await.contains_key(&0xDEAD_BEEF));

    assert!(manager.remove_agent(0xDEAD_BEEF).await);
    assert!(!manager.state.read().await.contains_key(&0xDEAD_BEEF));
    assert_eq!(manager.list_socks_servers(0xDEAD_BEEF).await, "No active SOCKS5 servers");

    Ok(())
}

#[tokio::test]
async fn prune_stale_agents_removes_inactive_agent_state() -> Result<(), SocketRelayError> {
    let (_database, registry, manager) = test_manager().await?;
    registry.insert(sample_agent(0xDEAD_BEEF)).await?;
    registry.insert(sample_agent(0xFEED_FACE)).await?;

    manager.add_socks_server(0xDEAD_BEEF, "0").await?;
    manager.add_socks_server(0xFEED_FACE, "0").await?;
    registry.mark_dead(0xDEAD_BEEF, "lost contact").await?;

    assert_eq!(manager.prune_stale_agents().await, 1);
    let state = manager.state.read().await;
    assert!(!state.contains_key(&0xDEAD_BEEF));
    assert!(state.contains_key(&0xFEED_FACE));

    Ok(())
}

/// `prune_stale_agents` with many agents: marks half as dead and verifies the sweeper
/// removes exactly those agents while retaining the rest.
#[tokio::test]
async fn prune_stale_agents_under_load_removes_only_dead_agents() -> std::io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| std::io::Error::other(e.to_string()))?;

    let total_agents = 50_u32;
    for agent_id in 1..=total_agents {
        registry
            .insert(sample_agent(agent_id))
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;
    }

    // Give each agent a few clients so there is real state to sweep.
    for agent_id in 1..=total_agents {
        for i in 0..5_u32 {
            let socket_id = agent_id * 1000 + i;
            let (_peer_read, _peer_write) =
                register_pending_client(&manager, agent_id, socket_id).await?;
        }
    }

    // Mark odd-numbered agents as dead.
    let dead_count = (1..=total_agents).filter(|id| id % 2 == 1).count();
    for agent_id in 1..=total_agents {
        if agent_id % 2 == 1 {
            registry
                .mark_dead(agent_id, "test sweep")
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))?;
        }
    }

    let removed = manager.prune_stale_agents().await;
    assert_eq!(removed, dead_count, "sweeper must remove exactly the dead agents");

    let state = manager.state.read().await;
    for agent_id in 1..=total_agents {
        if agent_id % 2 == 1 {
            assert!(
                !state.contains_key(&agent_id),
                "dead agent {agent_id} must be removed from state"
            );
        } else {
            assert!(
                state.contains_key(&agent_id),
                "live agent {agent_id} must be retained in state"
            );
            assert_eq!(
                state.get(&agent_id).map_or(0, |s| s.clients.len()),
                5,
                "live agent {agent_id} must retain all its clients"
            );
        }
    }

    Ok(())
}

/// Successive sweeper runs are idempotent — a second prune after no state changes must
/// remove nothing.
#[tokio::test]
async fn prune_stale_agents_is_idempotent() -> std::io::Result<()> {
    let (_database, registry, manager) =
        test_manager().await.map_err(|e| std::io::Error::other(e.to_string()))?;

    for agent_id in 1..=10_u32 {
        registry
            .insert(sample_agent(agent_id))
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        let (_peer_read, _peer_write) =
            register_pending_client(&manager, agent_id, agent_id * 100).await?;
    }

    // Kill agents 1–5.
    for agent_id in 1..=5_u32 {
        registry
            .mark_dead(agent_id, "gone")
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;
    }

    let first_sweep = manager.prune_stale_agents().await;
    assert_eq!(first_sweep, 5);

    let second_sweep = manager.prune_stale_agents().await;
    assert_eq!(second_sweep, 0, "second sweep with no new state changes must remove nothing");

    // Remaining agents still intact.
    let state = manager.state.read().await;
    for agent_id in 6..=10_u32 {
        assert!(state.contains_key(&agent_id));
    }

    Ok(())
}
