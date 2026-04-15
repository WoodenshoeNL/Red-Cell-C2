//! Sequence number tracking for callback replay protection.

use std::sync::atomic::Ordering;

use tracing::instrument;

use crate::database::{DeferredWrite, TeamserverError};

use super::AgentRegistry;

impl AgentRegistry {
    /// Returns `true` when the agent has sequence-number replay protection enabled.
    ///
    /// Demon and Archon agents are not seq-protected (returns `false`).
    /// Returns `false` also when the agent is not registered.
    pub(crate) async fn is_seq_protected(&self, agent_id: u32) -> bool {
        match self.entry(agent_id).await {
            Some(entry) => entry.seq_protected.load(Ordering::Relaxed),
            None => false,
        }
    }

    /// Validate that `incoming_seq` is acceptable for `agent_id` without advancing
    /// the stored last-seen sequence number.
    ///
    /// Returns [`TeamserverError::CallbackSeqReplay`] when `incoming_seq <= last_seen_seq`
    /// and [`TeamserverError::CallbackSeqGapTooLarge`] when the forward gap exceeds
    /// [`red_cell_common::callback_seq::MAX_SEQ_GAP`].
    ///
    /// The stored value is **not** updated by this call; call
    /// [`AgentRegistry::advance_last_seen_seq`] after a successful payload parse.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id), incoming_seq))]
    pub(crate) async fn check_callback_seq(
        &self,
        agent_id: u32,
        incoming_seq: u64,
    ) -> Result<(), TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let last_seen_seq = *entry.last_seen_seq.lock().await;
        red_cell_common::callback_seq::validate_seq(agent_id, incoming_seq, last_seen_seq).map_err(
            |e| match e {
                red_cell_common::callback_seq::CallbackSeqError::Replay {
                    incoming_seq,
                    last_seen_seq,
                    ..
                } => TeamserverError::CallbackSeqReplay { agent_id, incoming_seq, last_seen_seq },
                red_cell_common::callback_seq::CallbackSeqError::GapTooLarge {
                    incoming_seq,
                    last_seen_seq,
                    gap,
                    ..
                } => TeamserverError::CallbackSeqGapTooLarge {
                    agent_id,
                    incoming_seq,
                    last_seen_seq,
                    gap,
                },
                red_cell_common::callback_seq::CallbackSeqError::PayloadTooShort {
                    actual, ..
                } => TeamserverError::InvalidPersistedValue {
                    field: "callback_seq_prefix",
                    message: format!("payload too short: {actual} bytes"),
                },
            },
        )
    }

    /// Advance the last-seen sequence number for `agent_id` to `new_seq` and persist it.
    ///
    /// This must only be called after a successful payload parse to avoid burning a sequence
    /// number on an unvalidated (garbage) payload.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id), new_seq))]
    pub(crate) async fn advance_last_seen_seq(
        &self,
        agent_id: u32,
        new_seq: u64,
    ) -> Result<(), TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;

        let deferred = DeferredWrite::AgentSetLastSeenSeq { agent_id, seq: new_seq };
        let repo = self.repository.clone();
        self.persist_or_queue(deferred, || async move {
            repo.set_last_seen_seq(agent_id, new_seq).await
        })
        .await?;

        *entry.last_seen_seq.lock().await = new_seq;
        Ok(())
    }

    /// Enable or disable seq-protection for `agent_id` and persist the flag.
    ///
    /// Called during agent registration when the agent signals seq-protection support
    /// via a protocol extension flag.  Demon and Archon agents never call this.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id), seq_protected))]
    pub(crate) async fn set_seq_protected(
        &self,
        agent_id: u32,
        seq_protected: bool,
    ) -> Result<(), TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        self.repository.set_seq_protected(agent_id, seq_protected).await?;
        entry.seq_protected.store(seq_protected, Ordering::Relaxed);
        Ok(())
    }
}
