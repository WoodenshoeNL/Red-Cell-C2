//! State-mutation operations on the agent registry: updating agent metadata,
//! marking agents dead, setting operator notes, refreshing call-in timestamps,
//! and registering cleanup hooks.

use std::future::Future;
use std::sync::Arc;

use red_cell_common::AgentRecord;
use tracing::{instrument, warn};

use super::AgentRegistry;
use crate::database::{DatabaseHealthState, DeferredWrite, TeamserverError, WriteQueue};

impl AgentRegistry {
    /// Attach database health state and write queue for degraded-mode support.
    ///
    /// When the health state indicates degradation, write operations update
    /// in-memory state optimistically and queue the database write for later
    /// replay via the [`WriteQueue`].
    pub fn set_degraded_mode_support(
        &mut self,
        health_state: DatabaseHealthState,
        write_queue: WriteQueue,
    ) {
        self.health_state = Some(health_state);
        self.write_queue = Some(write_queue);
    }

    /// Replace the stored metadata for an existing agent and persist the change.
    #[instrument(skip(self, agent), fields(agent_id = format_args!("0x{:08X}", agent.agent_id)))]
    pub async fn update_agent(&self, agent: AgentRecord) -> Result<(), TeamserverError> {
        let listener_name =
            self.listener_name(agent.agent_id).await.unwrap_or_else(|| "null".to_owned());
        self.update_agent_with_listener(agent, &listener_name).await
    }

    /// Replace the stored metadata and listener provenance for an existing agent.
    #[instrument(skip(self, agent, listener_name), fields(agent_id = format_args!("0x{:08X}", agent.agent_id), listener_name = %listener_name))]
    pub async fn update_agent_with_listener(
        &self,
        agent: AgentRecord,
        listener_name: &str,
    ) -> Result<(), TeamserverError> {
        let entry = self
            .entry(agent.agent_id)
            .await
            .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;

        let deferred = DeferredWrite::AgentUpdate {
            agent: agent.clone(),
            listener_name: listener_name.to_owned(),
        };
        let repo = self.repository.clone();
        let ln = listener_name.to_owned();
        self.persist_or_queue(deferred, || {
            let agent_ref = agent.clone();
            let ln = ln.clone();
            async move { repo.update_with_listener(&agent_ref, &ln).await }
        })
        .await?;

        let mut info = entry.info.write().await;
        *info = agent;
        drop(info);
        let mut stored_listener_name = entry.listener_name.write().await;
        *stored_listener_name = listener_name.to_owned();
        Ok(())
    }

    /// Mark an agent inactive with the supplied reason and persist the status change.
    #[instrument(skip(self, reason), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn mark_dead(
        &self,
        agent_id: u32,
        reason: impl Into<String>,
    ) -> Result<(), TeamserverError> {
        let reason = reason.into();
        self.mark_subtree_member_dead(agent_id, &reason).await?;

        let descendants = self.child_subtree(agent_id).await;
        for child_id in descendants {
            self.mark_subtree_member_dead(child_id, "pivot parent disconnected").await?;
            self.clear_links_for_agent(child_id).await?;
            self.purge_request_contexts(child_id).await;
        }

        self.clear_links_for_agent(agent_id).await?;
        self.purge_request_contexts(agent_id).await;
        self.refresh_active_agent_gauge().await;
        Ok(())
    }

    /// Update an operator-authored note for an agent and persist the change.
    #[instrument(skip(self, note), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn set_note(
        &self,
        agent_id: u32,
        note: impl Into<String>,
    ) -> Result<AgentRecord, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let note = note.into();

        self.repository.set_note(agent_id, &note).await?;

        let mut info = entry.info.write().await;
        info.note = note;
        Ok(info.clone())
    }

    /// Register an async cleanup hook that runs whenever an agent is marked dead or removed.
    pub fn register_cleanup_hook<F, Fut>(&self, hook: F)
    where
        F: Fn(u32) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let mut cleanup_hooks = match self.cleanup_hooks.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("agent cleanup hooks mutex poisoned — recovering");
                poisoned.into_inner()
            }
        };
        cleanup_hooks.push(Arc::new(move |agent_id| Box::pin(hook(agent_id))));
    }

    /// Update an agent's last callback timestamp and persist the change.
    #[instrument(skip(self, last_call_in), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn set_last_call_in(
        &self,
        agent_id: u32,
        last_call_in: impl Into<String>,
    ) -> Result<AgentRecord, TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let last_call_in = last_call_in.into();

        // Snapshot the fields we are about to mutate so we can roll back on
        // persistence failure and keep in-memory state consistent with SQLite.
        let (prev_last_call_in, prev_active, prev_reason) = {
            let info = entry.info.read().await;
            (info.last_call_in.clone(), info.active, info.reason.clone())
        };

        let updated = {
            let mut info = entry.info.write().await;
            info.last_call_in = last_call_in;
            if !info.active {
                info.active = true;
                info.reason.clear();
            }
            info.clone()
        };

        let listener_name = entry.listener_name.read().await.clone();
        if let Err(err) = self.repository.update_with_listener(&updated, &listener_name).await {
            // Roll back the in-memory mutation so callers never observe a
            // state that diverges from what is persisted.
            let mut info = entry.info.write().await;
            info.last_call_in = prev_last_call_in;
            info.active = prev_active;
            info.reason = prev_reason;
            return Err(err);
        }
        Ok(updated)
    }
}
