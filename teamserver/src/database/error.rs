//! Error types for the teamserver database layer.

use std::path::PathBuf;

use red_cell_common::demon::DemonProtocolError;
use thiserror::Error;

use super::crypto;

/// Errors returned by the teamserver library.
#[derive(Debug, Error)]
pub enum TeamserverError {
    /// Returned when SQLite operations fail.
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    /// Returned when a migration fails to apply.
    #[error("database migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    /// Returned when JSON fields cannot be encoded or decoded.
    #[error("json serialization error: {0}")]
    Json(#[from] serde_json::Error),
    /// Returned when Demon wire-format serialization fails.
    #[error("demon protocol error: {0}")]
    DemonProtocol(#[from] DemonProtocolError),
    /// Returned when a path cannot be represented as a valid SQLite filename.
    #[error("invalid sqlite database path `{path}`")]
    InvalidDatabasePath { path: PathBuf },
    /// Returned when persisted values cannot be mapped into domain types.
    #[error("invalid persisted value for `{field}`: {message}")]
    InvalidPersistedValue {
        /// Column or field name.
        field: &'static str,
        /// Human-readable conversion failure reason.
        message: String,
    },
    /// Returned when attempting to register an agent that already exists in memory.
    #[error("agent 0x{agent_id:08X} already exists")]
    DuplicateAgent {
        /// Duplicate agent identifier.
        agent_id: u32,
    },
    /// Returned when the registry has reached its configured capacity.
    #[error(
        "agent registry limit reached: {registered} registered agents already tracked (max {max_registered_agents})"
    )]
    MaxRegisteredAgentsExceeded {
        /// Configured upper bound for registered agents.
        max_registered_agents: usize,
        /// Number of agents already tracked when the insert was attempted.
        registered: usize,
    },
    /// Returned when an in-memory agent cannot be found.
    #[error("agent 0x{agent_id:08X} not found")]
    AgentNotFound {
        /// Missing agent identifier.
        agent_id: u32,
    },
    /// Returned when persisted or supplied agent AES material is forbidden.
    #[error("invalid agent crypto material for agent 0x{agent_id:08X}: {message}")]
    InvalidAgentCrypto {
        /// Agent identifier associated with the invalid AES material.
        agent_id: u32,
        /// Human-readable validation failure.
        message: String,
    },
    /// Returned when attempting to persist an unsupported listener lifecycle state.
    #[error("invalid listener state `{state}`")]
    InvalidListenerState {
        /// Invalid state string.
        state: String,
    },
    /// Returned when a requested pivot relationship is invalid.
    #[error("invalid pivot link: {message}")]
    InvalidPivotLink {
        /// Human-readable validation failure.
        message: String,
    },
    /// Returned when a buffer exceeds the 4 GiB length-prefix limit of the Demon wire format.
    #[error("payload too large: {length} bytes exceeds u32::MAX")]
    PayloadTooLarge {
        /// Actual buffer length in bytes.
        length: usize,
    },
    /// Returned when an AES transport operation fails.
    #[error("agent crypto error: {0}")]
    Crypto(#[from] red_cell_common::crypto::CryptoError),
    /// Returned when at-rest column encryption or decryption fails.
    #[error("database column crypto error: {0}")]
    DbCrypto(#[from] crypto::DbCryptoError),
    /// Returned when the OS random-number generator is unavailable.
    #[error("OS RNG unavailable: {0}")]
    Rng(#[from] getrandom::Error),
    /// General-purpose internal error with a human-readable message.
    #[error("internal error: {0}")]
    Internal(String),
    /// SQLx database error (named alias; use for map_err(TeamserverError::Sqlx)).
    #[error("database error: {0}")]
    Sqlx(sqlx::Error),
    /// Returned when a sequence number exceeds i64::MAX and cannot be stored in SQLite.
    #[error("seq_num {seq_num} exceeds i64::MAX and cannot be stored")]
    SeqNumOverflow {
        /// The sequence number that overflowed.
        seq_num: u64,
    },
    /// Returned when a per-agent job queue has reached its capacity limit.
    #[error(
        "job queue full for agent 0x{agent_id:08X}: {queued} jobs already queued (max {max_queue_depth})"
    )]
    QueueFull {
        /// Agent whose job queue is at capacity.
        agent_id: u32,
        /// Configured upper bound for the per-agent job queue.
        max_queue_depth: usize,
        /// Number of jobs already queued when the enqueue was attempted.
        queued: usize,
    },
    /// Returned when a seq-protected callback is a replay of a previously seen sequence number.
    #[error(
        "callback replay for agent 0x{agent_id:08X}: \
         incoming seq {incoming_seq} <= last_seen_seq {last_seen_seq}"
    )]
    CallbackSeqReplay {
        /// Agent for which the replay was detected.
        agent_id: u32,
        /// Sequence number carried in the incoming callback.
        incoming_seq: u64,
        /// Last sequence number accepted for this agent.
        last_seen_seq: u64,
    },
    /// Returned when the gap between the incoming and last-seen sequence numbers exceeds
    /// the allowed maximum, indicating a suspicious large forward jump.
    #[error(
        "callback seq gap too large for agent 0x{agent_id:08X}: \
         incoming seq {incoming_seq}, last_seen_seq {last_seen_seq}, gap {gap} > max"
    )]
    CallbackSeqGapTooLarge {
        /// Agent for which the large gap was detected.
        agent_id: u32,
        /// Sequence number carried in the incoming callback.
        incoming_seq: u64,
        /// Last sequence number accepted for this agent.
        last_seen_seq: u64,
        /// Computed gap (`incoming_seq - last_seen_seq`).
        gap: u64,
    },
}
