//! Lifecycle operations on the agent registry: initial registration,
//! re-registration (session restart), and removal.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use red_cell_common::AgentRecord;
use tracing::{instrument, warn};

use crate::database::{DeferredWrite, TeamserverError};

use super::{AgentEntry, AgentRegistry};

impl AgentRegistry {
    /// Insert a newly registered agent and persist it to SQLite.
    #[instrument(skip(self, agent), fields(agent_id = format_args!("0x{:08X}", agent.agent_id)))]
    pub async fn insert(&self, agent: AgentRecord) -> Result<(), TeamserverError> {
        self.insert_with_listener(agent, "null").await
    }

    /// Insert a newly registered agent and persist its accepting listener.
    #[instrument(skip(self, agent, listener_name), fields(agent_id = format_args!("0x{:08X}", agent.agent_id), listener_name = %listener_name))]
    pub async fn insert_with_listener(
        &self,
        agent: AgentRecord,
        listener_name: &str,
    ) -> Result<(), TeamserverError> {
        self.insert_with_listener_and_ctr_offset(agent, listener_name, 0).await
    }

    /// Insert a newly registered agent and atomically persist its initial CTR state.
    ///
    /// Uses monotonic (non-legacy) CTR mode.  Call [`AgentRegistry::insert_full`]
    /// with `legacy_ctr = true` for Demon/Archon agents that reset CTR per packet.
    #[instrument(skip(self, agent, listener_name), fields(agent_id = format_args!("0x{:08X}", agent.agent_id), listener_name = %listener_name, ctr_block_offset))]
    pub async fn insert_with_listener_and_ctr_offset(
        &self,
        agent: AgentRecord,
        listener_name: &str,
        ctr_block_offset: u64,
    ) -> Result<(), TeamserverError> {
        self.insert_full(agent, listener_name, ctr_block_offset, false, false, false).await
    }

    /// Insert a newly registered agent with explicit control over all transport parameters.
    ///
    /// When `legacy_ctr` is `true`, AES-CTR resets to block offset 0 for every packet
    /// (Demon/Archon compatibility).  When `false`, the monotonic block offset advances
    /// across packets (Specter behaviour).
    ///
    /// `seq_protected` records whether the agent negotiated callback sequence-number
    /// replay protection (`INIT_EXT_SEQ_PROTECTED`).  The flag is persisted atomically
    /// with the agent row so that any logic keyed off [`AgentRegistry::is_seq_protected`]
    /// sees the correct state from the moment the agent is registered.
    ///
    /// # Security warning — legacy CTR mode
    ///
    /// `legacy_ctr = true` causes the teamserver to use **the same AES-CTR keystream
    /// (key, IV, offset 0) for every packet**.  This is a two-time-pad: any passive
    /// network observer who captures two ciphertexts `C1` and `C2` from the same agent
    /// can compute `C1 ⊕ C2 = P1 ⊕ P2` and, with knowledge of the Demon protocol
    /// structure (which is public), recover both plaintexts entirely.
    ///
    /// Legacy mode exists solely for backward compatibility with Havoc Demon and Archon
    /// agents that do not send the `INIT_EXT_MONOTONIC_CTR` extension flag during
    /// `DEMON_INIT`.  **Use it only in controlled environments where traffic
    /// confidentiality is not a requirement.**  All new agent builds should set
    /// `INIT_EXT_MONOTONIC_CTR` so the teamserver registers them with `legacy_ctr = false`.
    #[instrument(skip(self, agent, listener_name), fields(agent_id = format_args!("0x{:08X}", agent.agent_id), listener_name = %listener_name, ctr_block_offset, legacy_ctr, seq_protected))]
    pub async fn insert_full(
        &self,
        agent: AgentRecord,
        listener_name: &str,
        ctr_block_offset: u64,
        legacy_ctr: bool,
        ecdh_transport: bool,
        seq_protected: bool,
    ) -> Result<(), TeamserverError> {
        let mut entries = self.entries.write().await;

        if entries.contains_key(&agent.agent_id) {
            return Err(TeamserverError::DuplicateAgent { agent_id: agent.agent_id });
        }

        if entries.len() >= self.max_registered_agents {
            return Err(TeamserverError::MaxRegisteredAgentsExceeded {
                max_registered_agents: self.max_registered_agents,
                registered: entries.len(),
            });
        }

        if legacy_ctr {
            warn!(
                agent_id = format_args!("0x{:08X}", agent.agent_id),
                "agent registered in LEGACY CTR mode: AES keystream is reset to offset 0 for \
                 every packet — this is a two-time-pad vulnerability (C1⊕C2=P1⊕P2). \
                 Only deploy legacy-mode agents in controlled environments. \
                 Upgrade agents to set INIT_EXT_MONOTONIC_CTR to eliminate this risk."
            );
        }

        let deferred = DeferredWrite::AgentCreateFull {
            agent: agent.clone(),
            listener_name: listener_name.to_owned(),
            ctr_block_offset,
            legacy_ctr,
            seq_protected,
        };
        let repo = self.repository.clone();
        let ln = listener_name.to_owned();
        self.persist_or_queue(deferred, || {
            let agent_ref = agent.clone();
            let ln = ln.clone();
            async move {
                repo.create_full(&agent_ref, &ln, ctr_block_offset, legacy_ctr, seq_protected).await
            }
        })
        .await?;

        entries.insert(
            agent.agent_id,
            Arc::new(AgentEntry::new(
                agent,
                listener_name.to_owned(),
                ctr_block_offset,
                legacy_ctr,
                0, // last_seen_seq starts at 0 for new agents
                seq_protected,
                ecdh_transport,
                0,    // replay_attempt_count starts at 0
                None, // no lockout for new agents
            )),
        );
        self.update_active_agent_gauge(&entries).await;
        Ok(())
    }

    /// Update an existing agent's full metadata on re-registration (same `agent_id`, fresh
    /// `DEMON_INIT` payload).  Resets the CTR block offset to 0 and persists all new runtime
    /// fields to SQLite.  Preserves the original `first_call_in` and the operator `note`.
    ///
    /// `seq_protected` records whether the agent negotiated callback sequence-number replay
    /// protection on the fresh session and is persisted atomically with the rest of the
    /// re-registration update so that [`AgentRegistry::is_seq_protected`] and the SQLite row
    /// can never disagree after a re-init.
    #[instrument(skip(self, agent, listener_name), fields(agent_id = format_args!("0x{:08X}", agent.agent_id), listener_name = %listener_name, legacy_ctr, seq_protected))]
    pub async fn reregister_full(
        &self,
        mut agent: AgentRecord,
        listener_name: &str,
        legacy_ctr: bool,
        seq_protected: bool,
    ) -> Result<(), TeamserverError> {
        let entry = self
            .entry(agent.agent_id)
            .await
            .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;

        // Preserve the original first-seen timestamp and the operator's note.
        {
            let old = entry.info.read().await;
            agent.first_call_in = old.first_call_in.clone();
            agent.note = old.note.clone();
        }

        // Persist (or queue if degraded) before updating in-memory state.
        let deferred = DeferredWrite::AgentReregisterFull {
            agent: agent.clone(),
            listener_name: listener_name.to_owned(),
            legacy_ctr,
            seq_protected,
        };
        let repo = self.repository.clone();
        let ln = listener_name.to_owned();
        self.persist_or_queue(deferred, || {
            let agent_ref = agent.clone();
            let ln = ln.clone();
            async move { repo.reregister_full(&agent_ref, &ln, legacy_ctr, seq_protected).await }
        })
        .await?;

        let mut info = entry.info.write().await;
        *info = agent;
        drop(info);

        let mut stored_listener_name = entry.listener_name.write().await;
        *stored_listener_name = listener_name.to_owned();
        drop(stored_listener_name);

        // Reset transport state — the re-registering agent starts a fresh session.
        *entry.ctr_block_offset.lock().await = 0;
        entry.legacy_ctr.store(legacy_ctr, Ordering::Relaxed);
        entry.seq_protected.store(seq_protected, Ordering::Relaxed);
        // Reset last_seen_seq to 0 so the fresh session begins at seq=1.
        *entry.last_seen_seq.lock().await = 0;
        // Clear any replay lockout — a fresh registration proves the agent is legitimate.
        *entry.replay_attempt_count.lock().await = 0;
        *entry.lockout_until.lock().await = None;

        Ok(())
    }

    /// Remove an agent from memory and SQLite.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id)))]
    pub async fn remove(&self, agent_id: u32) -> Result<AgentRecord, TeamserverError> {
        self.clear_links_for_agent(agent_id).await?;
        self.purge_request_contexts(agent_id).await;
        let entry = {
            let mut entries = self.entries.write().await;
            entries.remove(&agent_id).ok_or(TeamserverError::AgentNotFound { agent_id })?
        };

        self.repository.delete(agent_id).await?;
        self.run_cleanup_hooks(agent_id).await;

        let info = entry.info.read().await;
        Ok(info.clone())
    }
}
