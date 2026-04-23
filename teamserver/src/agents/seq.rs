//! Sequence number tracking for callback replay protection.

use std::sync::atomic::Ordering;

use tracing::instrument;

use crate::database::{DeferredWrite, TeamserverError};

use super::AgentRegistry;

fn map_seq_error(
    agent_id: u32,
    e: red_cell_common::callback_seq::CallbackSeqError,
) -> TeamserverError {
    match e {
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
        } => TeamserverError::CallbackSeqGapTooLarge { agent_id, incoming_seq, last_seen_seq, gap },
        red_cell_common::callback_seq::CallbackSeqError::PayloadTooShort { actual, .. } => {
            TeamserverError::InvalidPersistedValue {
                field: "callback_seq_prefix",
                message: format!("payload too short: {actual} bytes"),
            }
        }
    }
}

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
    /// The stored value is **not** updated by this call.
    ///
    /// Production callers must use [`AgentRegistry::check_and_advance_callback_seq`]
    /// instead — splitting validation and advance across two lock acquisitions opens
    /// a TOCTOU window where concurrent callbacks with the same seq both pass the
    /// check. This method is retained only for unit tests that exercise the
    /// validation logic in isolation.
    #[cfg(test)]
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id), incoming_seq))]
    pub(crate) async fn check_callback_seq(
        &self,
        agent_id: u32,
        incoming_seq: u64,
    ) -> Result<(), TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let last_seen_seq = *entry.last_seen_seq.lock().await;
        red_cell_common::callback_seq::validate_seq(agent_id, incoming_seq, last_seen_seq)
            .map_err(|e| map_seq_error(agent_id, e))
    }

    /// Advance the last-seen sequence number for `agent_id` to `new_seq` and persist it.
    ///
    /// Production callers must use [`AgentRegistry::check_and_advance_callback_seq`]
    /// so that validation and advance happen under a single lock acquisition.
    /// This method is retained for unit tests.
    #[cfg(test)]
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id), new_seq))]
    pub(crate) async fn advance_last_seen_seq(
        &self,
        agent_id: u32,
        new_seq: u64,
    ) -> Result<(), TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;

        let mut last_seen = entry.last_seen_seq.lock().await;
        let deferred = DeferredWrite::AgentSetLastSeenSeq { agent_id, seq: new_seq };
        let repo = self.repository.clone();
        self.persist_or_queue(deferred, || async move {
            repo.set_last_seen_seq(agent_id, new_seq).await
        })
        .await?;

        *last_seen = new_seq;
        Ok(())
    }

    /// Atomically validate `incoming_seq` and, on success, persist and advance
    /// the last-seen sequence number for `agent_id`.
    ///
    /// The per-agent `last_seen_seq` mutex is held for the entire validate →
    /// persist → in-memory update sequence, eliminating the TOCTOU window
    /// where a concurrent callback with the same seq could pass validation
    /// before the first call advances the stored value.
    ///
    /// Callers must only invoke this after successful AES-CTR decryption so the
    /// payload is already authenticated. A successful return consumes the seq
    /// slot even if subsequent parsing fails — a genuine agent will not resend
    /// a failed packet, so burning the slot on an authenticated-but-unparseable
    /// payload is the correct choice.
    #[instrument(skip(self), fields(agent_id = format_args!("0x{:08X}", agent_id), incoming_seq))]
    pub(crate) async fn check_and_advance_callback_seq(
        &self,
        agent_id: u32,
        incoming_seq: u64,
    ) -> Result<(), TeamserverError> {
        let entry =
            self.entry(agent_id).await.ok_or(TeamserverError::AgentNotFound { agent_id })?;
        let mut last_seen = entry.last_seen_seq.lock().await;

        red_cell_common::callback_seq::validate_seq(agent_id, incoming_seq, *last_seen)
            .map_err(|e| map_seq_error(agent_id, e))?;

        let deferred = DeferredWrite::AgentSetLastSeenSeq { agent_id, seq: incoming_seq };
        let repo = self.repository.clone();
        self.persist_or_queue(deferred, || async move {
            repo.set_last_seen_seq(agent_id, incoming_seq).await
        })
        .await?;

        *last_seen = incoming_seq;
        Ok(())
    }

    /// Enable or disable seq-protection for `agent_id` and persist the flag.
    ///
    /// Production registration paths persist `seq_protected` atomically via
    /// [`AgentRegistry::insert_full`] / [`AgentRegistry::reregister_full`]; this method
    /// is retained as a test helper that flips the flag on an already-registered agent.
    /// Unlike the registration paths it performs two non-atomic writes (DB then memory)
    /// with no write-queue fallback, so it must not be used from production code.
    #[cfg(test)]
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
