//! Stale-agent cleanup: periodic sweeper and state-teardown helpers.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::runtime::Handle;
use tokio::sync::{RwLock, oneshot};

use crate::AgentRegistry;

use super::types::{AgentSocketState, RelayStateSweeper, STALE_AGENT_SWEEP_INTERVAL};

/// Spawn a background task that periodically prunes relay state for agents that
/// are no longer active in the registry.
pub(super) fn spawn_stale_agent_sweeper(
    registry: AgentRegistry,
    state: Arc<RwLock<HashMap<u32, AgentSocketState>>>,
) -> Option<Arc<RelayStateSweeper>> {
    let handle = Handle::try_current().ok()?;
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let task = handle.spawn(async move {
        let mut ticker = tokio::time::interval(STALE_AGENT_SWEEP_INTERVAL);
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                _ = ticker.tick() => {
                    let _ = prune_stale_agent_state(&registry, &state).await;
                }
            }
        }
    });

    Some(Arc::new(RelayStateSweeper { shutdown: Some(shutdown_tx), task }))
}

/// Remove relay state for agents that are missing or inactive in the registry.
///
/// Returns the number of agents whose state was removed.
pub(super) async fn prune_stale_agent_state(
    registry: &AgentRegistry,
    state: &Arc<RwLock<HashMap<u32, AgentSocketState>>>,
) -> usize {
    let active_agents = registry
        .list_active()
        .await
        .into_iter()
        .map(|agent| agent.agent_id)
        .collect::<std::collections::HashSet<_>>();
    let stale_states = {
        let mut state = state.write().await;
        let stale_agent_ids = state
            .keys()
            .copied()
            .filter(|agent_id| !active_agents.contains(agent_id))
            .collect::<Vec<_>>();
        stale_agent_ids
            .into_iter()
            .filter_map(|agent_id| state.remove(&agent_id))
            .collect::<Vec<_>>()
    };

    let removed = stale_states.len();
    for agent_state in stale_states {
        close_agent_state(agent_state).await;
    }
    removed
}

/// Shut down all SOCKS server handles and client writers for an agent.
pub(super) async fn close_agent_state(agent_state: AgentSocketState) {
    for mut handle in agent_state.servers.into_values() {
        handle.shutdown();
    }

    for client in agent_state.clients.into_values() {
        let mut writer = client.writer.lock().await;
        let _ = writer.shutdown().await;
    }
}
