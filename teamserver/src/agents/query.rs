//! Read-only queries on the agent registry: fetching snapshots of individual
//! agents, listing the full or active population, and resolving the listener
//! that accepted a given session.

use std::sync::Arc;

use red_cell_common::AgentRecord;
use tracing::instrument;

use super::{AgentEntry, AgentRegistry};

impl AgentRegistry {
    /// Fetch a cloned snapshot of an agent by identifier.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn get(&self, agent_id: u32) -> Option<AgentRecord> {
        let entry = self.entry(agent_id).await?;
        let info = entry.info.read().await;
        Some(info.clone())
    }

    /// Return all agents that are still marked active.
    #[instrument(skip(self))]
    pub async fn list_active(&self) -> Vec<AgentRecord> {
        let entries = self.entries.read().await;
        let handles: Vec<_> = entries.values().cloned().collect();
        drop(entries);

        let mut agents = Vec::new();
        for handle in handles {
            let info = handle.info.read().await;
            if info.active {
                agents.push(info.clone());
            }
        }
        agents.sort_by_key(|agent| agent.agent_id);
        agents
    }

    /// Return all tracked agents, including inactive historical entries.
    #[instrument(skip(self))]
    pub async fn list(&self) -> Vec<AgentRecord> {
        let entries = self.entries.read().await;
        let handles: Vec<_> = entries.values().cloned().collect();
        drop(entries);

        let mut agents = Vec::with_capacity(handles.len());
        for handle in handles {
            let info = handle.info.read().await;
            agents.push(info.clone());
        }

        agents.sort_by_key(|agent| agent.agent_id);
        agents
    }

    /// Return all tracked agents paired with their listener names.
    #[instrument(skip(self))]
    pub async fn list_with_listeners(&self) -> Vec<(AgentRecord, String)> {
        let entries = self.entries.read().await;
        let handles: Vec<_> = entries.values().cloned().collect();
        drop(entries);

        let mut agents = Vec::with_capacity(handles.len());
        for handle in handles {
            let info = handle.info.read().await;
            let listener = handle.listener_name.read().await;
            agents.push((info.clone(), listener.clone()));
        }

        agents.sort_by_key(|(agent, _)| agent.agent_id);
        agents
    }

    /// Return the listener that accepted the current or most recent session.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn listener_name(&self, agent_id: u32) -> Option<String> {
        let entry = self.entry(agent_id).await?;
        let listener_name = entry.listener_name.read().await;
        Some(listener_name.clone())
    }

    pub(super) async fn entry(&self, agent_id: u32) -> Option<Arc<AgentEntry>> {
        let entries = self.entries.read().await;
        entries.get(&agent_id).cloned()
    }
}
