//! Sequence number tracking for callback replay protection.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::instrument;

use crate::database::audit::AuditLogEntry;
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
        red_cell_common::callback_seq::CallbackSeqError::ReplayLockout {
            lockout_until, ..
        } => TeamserverError::CallbackSeqReplayLockout { agent_id, lockout_until },
    }
}

/// Compute the Unix-seconds timestamp for a lockout expiring `duration_secs` from now.
fn lockout_expiry_unix_secs(duration_secs: u64) -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
        .saturating_add(duration_secs)
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
    /// Before validating the sequence number, this method checks whether the agent
    /// is currently replay-locked.  If so, it returns
    /// [`TeamserverError::CallbackSeqReplayLockout`] immediately.  After
    /// [`red_cell_common::callback_seq::REPLAY_LOCKOUT_THRESHOLD`] consecutive
    /// replay rejections the agent is locked for
    /// [`red_cell_common::callback_seq::REPLAY_LOCKOUT_DURATION_SECS`] seconds.
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

        // ── Lockout check ─────────────────────────────────────────────────────
        {
            let mut lockout_guard = entry.lockout_until.lock().await;
            if let Some(until) = *lockout_guard {
                if Instant::now() < until {
                    // Still locked — compute expiry as a Unix timestamp for the error.
                    let remaining = until.saturating_duration_since(Instant::now());
                    let lockout_until = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or(Duration::ZERO)
                        .as_secs()
                        .saturating_add(remaining.as_secs());
                    return Err(map_seq_error(
                        agent_id,
                        red_cell_common::callback_seq::CallbackSeqError::ReplayLockout {
                            agent_id,
                            lockout_until,
                        },
                    ));
                }
                // Lockout expired — lazily clear it.
                *lockout_guard = None;
                *entry.replay_attempt_count.lock().await = 0;
                let repo = self.repository.clone();
                self.persist_or_queue(
                    DeferredWrite::AgentSetReplayLockout {
                        agent_id,
                        attempt_count: 0,
                        lockout_until: None,
                    },
                    move || async move { repo.set_replay_lockout(agent_id, 0, None).await },
                )
                .await?;
            }
        }

        // ── Sequence validation ───────────────────────────────────────────────
        match red_cell_common::callback_seq::validate_seq(agent_id, incoming_seq, *last_seen) {
            Ok(()) => {
                // Success — advance seq and reset replay counter.
                let deferred = DeferredWrite::AgentSetLastSeenSeq { agent_id, seq: incoming_seq };
                let repo = self.repository.clone();
                self.persist_or_queue(deferred, || async move {
                    repo.set_last_seen_seq(agent_id, incoming_seq).await
                })
                .await?;
                *last_seen = incoming_seq;

                // Reset attempt counter if it was non-zero.
                let mut count = entry.replay_attempt_count.lock().await;
                if *count > 0 {
                    *count = 0;
                    let repo2 = self.repository.clone();
                    self.persist_or_queue(
                        DeferredWrite::AgentSetReplayLockout {
                            agent_id,
                            attempt_count: 0,
                            lockout_until: None,
                        },
                        move || async move { repo2.set_replay_lockout(agent_id, 0, None).await },
                    )
                    .await?;
                }
                Ok(())
            }
            Err(red_cell_common::callback_seq::CallbackSeqError::Replay {
                incoming_seq,
                last_seen_seq,
                ..
            }) => {
                // Increment the consecutive-replay counter and possibly trigger lockout.
                let mut count = entry.replay_attempt_count.lock().await;
                *count = count.saturating_add(1);

                if *count >= self.replay_lockout_threshold {
                    // Threshold reached — activate lockout and surface it to the caller
                    // so they know immediately that a lockout is now in effect.
                    let expiry_unix = lockout_expiry_unix_secs(self.replay_lockout_duration_secs);
                    let expiry_unix_db: i64 = i64::try_from(expiry_unix).unwrap_or(i64::MAX);
                    let until =
                        Instant::now() + Duration::from_secs(self.replay_lockout_duration_secs);
                    *entry.lockout_until.lock().await = Some(until);

                    let new_count = *count;
                    let repo = self.repository.clone();
                    self.persist_or_queue(
                        DeferredWrite::AgentSetReplayLockout {
                            agent_id,
                            attempt_count: new_count,
                            lockout_until: Some(expiry_unix_db),
                        },
                        move || async move {
                            repo.set_replay_lockout(agent_id, new_count, Some(expiry_unix_db)).await
                        },
                    )
                    .await?;

                    let occurred_at = OffsetDateTime::now_utc()
                        .format(&Rfc3339)
                        .unwrap_or_else(|_| String::from("unknown"));
                    let lockout_details = format!(
                        "agent 0x{:08X} replay-locked until unix={}",
                        agent_id, expiry_unix
                    );
                    let audit_repo = self.audit_log_repository.clone();
                    let audit_entry = AuditLogEntry {
                        id: None,
                        actor: "teamserver".to_owned(),
                        action: "replay_lockout".to_owned(),
                        target_kind: "agent".to_owned(),
                        target_id: Some(format!("0x{:08X}", agent_id)),
                        details: Some(
                            serde_json::json!({ "message": lockout_details, "lockout_until_unix": expiry_unix, "attempt_count": new_count }),
                        ),
                        occurred_at,
                    };
                    self.persist_or_queue(
                        DeferredWrite::AuditLogCreate { entry: audit_entry.clone() },
                        move || async move { audit_repo.create(&audit_entry).await.map(|_| ()) },
                    )
                    .await?;

                    Err(TeamserverError::CallbackSeqReplayLockout {
                        agent_id,
                        lockout_until: expiry_unix,
                    })
                } else {
                    let new_count = *count;
                    let repo = self.repository.clone();
                    self.persist_or_queue(
                        DeferredWrite::AgentSetReplayLockout {
                            agent_id,
                            attempt_count: new_count,
                            lockout_until: None,
                        },
                        move || async move {
                            repo.set_replay_lockout(agent_id, new_count, None).await
                        },
                    )
                    .await?;

                    Err(TeamserverError::CallbackSeqReplay {
                        agent_id,
                        incoming_seq,
                        last_seen_seq,
                    })
                }
            }
            Err(e) => {
                // GapTooLarge or other errors do not count toward lockout.
                Err(map_seq_error(agent_id, e))
            }
        }
    }

    /// Return the current in-memory replay attempt counter for `agent_id`.
    ///
    /// Retained for unit tests that verify the counter is reset correctly.
    #[cfg(test)]
    pub(crate) async fn replay_attempt_count(&self, agent_id: u32) -> Option<u32> {
        let entry = self.entry(agent_id).await?;
        Some(*entry.replay_attempt_count.lock().await)
    }

    /// Manually set the in-memory `lockout_until` instant for `agent_id`.
    ///
    /// Used by tests to fast-forward past the lockout window without sleeping.
    #[cfg(test)]
    pub(crate) async fn set_lockout_until(
        &self,
        agent_id: u32,
        instant: Option<std::time::Instant>,
    ) {
        if let Some(entry) = self.entry(agent_id).await {
            *entry.lockout_until.lock().await = instant;
        }
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
