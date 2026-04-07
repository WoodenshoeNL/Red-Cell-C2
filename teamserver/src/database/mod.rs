//! SQLite-backed persistence for the Red Cell teamserver.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use red_cell_common::demon::DemonProtocolError;
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use thiserror::Error;
use tracing::instrument;

pub mod agent_groups;
pub mod agents;
pub mod audit;
pub mod crypto;
pub mod jobs;
pub mod links;
pub mod listener_access;
pub mod listeners;
pub mod loot;
pub mod operators;

pub use agent_groups::AgentGroupRepository;
pub use agents::{AgentRepository, PersistedAgent};
pub use audit::{AuditLogEntry, AuditLogFilter, AuditLogRepository};
pub use crypto::DbMasterKey;
pub use jobs::{
    AgentResponseRecord, AgentResponseRepository, PayloadBuildRecord, PayloadBuildRepository,
    PayloadBuildSummary,
};
pub use links::{LinkRecord, LinkRepository};
pub use listener_access::ListenerAccessRepository;
pub use listeners::{
    ListenerRepository, ListenerStatus, PersistedListener, PersistedListenerState,
};
pub use loot::{LootFilter, LootRecord, LootRepository};
pub use operators::{OperatorRepository, PersistedOperator};

static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

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

/// Connection pool and repository factory for the teamserver database.
#[derive(Clone, Debug)]
pub struct Database {
    pool: SqlitePool,
    /// Master key used to encrypt/decrypt sensitive columns (agent session keys).
    master_key: Arc<DbMasterKey>,
}

impl Database {
    /// Open a SQLite database at `path` with a provided master key.
    ///
    /// The master key is used to encrypt and decrypt the `aes_key` / `aes_iv`
    /// columns in the `ts_agents` table.  It must be loaded from the key file
    /// before calling this function; see `load_or_create_master_key` in `main.rs`.
    #[instrument(fields(path = %path.as_ref().display()), skip(master_key))]
    pub async fn connect_with_master_key(
        path: impl AsRef<Path>,
        master_key: DbMasterKey,
    ) -> Result<Self, TeamserverError> {
        let path = path.as_ref();
        let options =
            SqliteConnectOptions::new().filename(path).create_if_missing(true).foreign_keys(true);
        Self::connect_with_options_and_key(options, master_key).await
    }

    /// Open a SQLite database at `path` with a **random** ephemeral master key.
    ///
    /// Intended for tests and dev tooling.  Do **not** use this in production —
    /// data written with one ephemeral key cannot be read back after a restart.
    #[instrument(fields(path = %path.as_ref().display()))]
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, TeamserverError> {
        let key = DbMasterKey::random()?;
        Self::connect_with_master_key(path, key).await
    }

    /// Open an in-memory SQLite database with a random ephemeral master key.
    ///
    /// All data is lost when the pool is closed.  Used in tests.
    #[instrument]
    pub async fn connect_in_memory() -> Result<Self, TeamserverError> {
        let key = DbMasterKey::random()?;
        let options = SqliteConnectOptions::new().filename(":memory:").foreign_keys(true);
        Self::connect_with_options_and_key(options, key).await
    }

    /// Build a database pool from fully-specified SQLite connection options and master key.
    #[instrument(skip(options, master_key))]
    pub async fn connect_with_options_and_key(
        options: SqliteConnectOptions,
        master_key: DbMasterKey,
    ) -> Result<Self, TeamserverError> {
        let pool = SqlitePoolOptions::new().max_connections(1).connect_with(options).await?;
        MIGRATOR.run(&pool).await?;
        Ok(Self { pool, master_key: Arc::new(master_key) })
    }

    /// Build a database pool from fully-specified SQLite connection options.
    ///
    /// Generates a random ephemeral master key.  Use [`Self::connect_with_options_and_key`]
    /// when a stable key is required.
    #[instrument(skip(options))]
    pub async fn connect_with_options(
        options: SqliteConnectOptions,
    ) -> Result<Self, TeamserverError> {
        let key = DbMasterKey::random()?;
        Self::connect_with_options_and_key(options, key).await
    }

    /// Borrow the underlying SQLx connection pool.
    #[must_use]
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Access agent/session persistence methods.
    #[must_use]
    pub fn agents(&self) -> AgentRepository {
        AgentRepository::new(self.pool.clone(), self.master_key.clone())
    }

    /// Access listener persistence methods.
    #[must_use]
    pub fn listeners(&self) -> ListenerRepository {
        ListenerRepository::new(self.pool.clone())
    }

    /// Access pivot-link persistence methods.
    #[must_use]
    pub fn links(&self) -> LinkRepository {
        LinkRepository::new(self.pool.clone())
    }

    /// Access captured-loot persistence methods.
    #[must_use]
    pub fn loot(&self) -> LootRepository {
        LootRepository::new(self.pool.clone())
    }

    /// Access persisted agent-response history methods.
    #[must_use]
    pub fn agent_responses(&self) -> AgentResponseRepository {
        AgentResponseRepository::new(self.pool.clone())
    }

    /// Access structured audit-log persistence methods.
    #[must_use]
    pub fn audit_log(&self) -> AuditLogRepository {
        AuditLogRepository::new(self.pool.clone())
    }

    /// Access runtime-operator persistence methods.
    #[must_use]
    pub fn operators(&self) -> OperatorRepository {
        OperatorRepository::new(self.pool.clone())
    }

    /// Access payload build job persistence methods.
    #[must_use]
    pub fn payload_builds(&self) -> PayloadBuildRepository {
        PayloadBuildRepository::new(self.pool.clone())
    }

    /// Access agent group and operator group-access persistence methods.
    #[must_use]
    pub fn agent_groups(&self) -> AgentGroupRepository {
        AgentGroupRepository::new(self.pool.clone())
    }

    /// Access per-listener operator allow-list persistence methods.
    #[must_use]
    pub fn listener_access(&self) -> ListenerAccessRepository {
        ListenerAccessRepository::new(self.pool.clone())
    }

    /// Close the SQLite pool and wait for all checked-out connections to return.
    pub async fn close(&self) {
        self.pool.close().await;
    }

    /// Run a cheap `SELECT 1` query to verify database connectivity.
    ///
    /// Returns `true` if the query completes within `timeout`, `false` if it times
    /// out or returns an error.
    pub async fn probe(&self, timeout: std::time::Duration) -> bool {
        tokio::time::timeout(timeout, sqlx::query("SELECT 1").execute(&self.pool))
            .await
            .is_ok_and(|result| result.is_ok())
    }
}

fn bool_to_i64(value: bool) -> i64 {
    if value { 1 } else { 0 }
}

fn bool_from_i64(field: &'static str, value: i64) -> Result<bool, TeamserverError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid_value(field, "expected 0 or 1")),
    }
}

fn u32_from_i64(field: &'static str, value: i64) -> Result<u32, TeamserverError> {
    u32::try_from(value).map_err(|_| invalid_value(field, "value does not fit in u32"))
}

fn u64_from_i64(field: &'static str, value: i64) -> Result<u64, TeamserverError> {
    u64::try_from(value).map_err(|_| invalid_value(field, "value does not fit in u64"))
}

fn i64_from_u64(field: &'static str, value: u64) -> Result<i64, TeamserverError> {
    i64::try_from(value).map_err(|_| invalid_value(field, "value does not fit in i64"))
}

fn invalid_value(field: &'static str, message: &str) -> TeamserverError {
    TeamserverError::InvalidPersistedValue { field, message: message.to_owned() }
}

#[cfg(test)]
mod tests {
    use super::{Database, bool_from_i64, i64_from_u64, u32_from_i64, u64_from_i64};

    // ── bool_from_i64 tests ─────────────────────────────────────────────

    #[test]
    fn bool_from_i64_accepts_sqlite_boolean_values() {
        assert_eq!(bool_from_i64("active", 0).ok(), Some(false));
        assert_eq!(bool_from_i64("active", 1).ok(), Some(true));
    }

    #[test]
    fn bool_from_i64_rejects_out_of_range_values() {
        assert!(bool_from_i64("active", 2).is_err());
        assert!(bool_from_i64("active", -1).is_err());
        assert!(bool_from_i64("active", i64::MIN).is_err());
        assert!(bool_from_i64("active", i64::MAX).is_err());
    }

    // ── i64_from_u64 tests ──────────────────────────────────────────────

    #[test]
    fn i64_from_u64_accepts_zero() {
        assert_eq!(i64_from_u64("field", 0).expect("zero"), 0);
    }

    #[test]
    fn i64_from_u64_accepts_one() {
        assert_eq!(i64_from_u64("field", 1).expect("one"), 1);
    }

    #[test]
    fn i64_from_u64_accepts_i64_max() {
        let val = i64::MAX as u64;
        assert_eq!(i64_from_u64("field", val).expect("i64::MAX"), i64::MAX);
    }

    #[test]
    fn i64_from_u64_rejects_i64_max_plus_one() {
        let val = i64::MAX as u64 + 1;
        assert!(i64_from_u64("field", val).is_err());
    }

    #[test]
    fn i64_from_u64_rejects_values_bigger_than_sqlite_integer() {
        assert!(i64_from_u64("base_address", u64::MAX).is_err());
    }

    // ── u32_from_i64 tests ──────────────────────────────────────────────

    #[test]
    fn u32_from_i64_accepts_zero() {
        assert_eq!(u32_from_i64("field", 0).expect("zero"), 0u32);
    }

    #[test]
    fn u32_from_i64_accepts_u32_max() {
        assert_eq!(u32_from_i64("field", i64::from(u32::MAX)).expect("u32::MAX"), u32::MAX);
    }

    #[test]
    fn u32_from_i64_rejects_negative() {
        assert!(u32_from_i64("field", -1).is_err());
        assert!(u32_from_i64("field", i64::MIN).is_err());
    }

    #[test]
    fn u32_from_i64_rejects_above_u32_max() {
        assert!(u32_from_i64("field", i64::from(u32::MAX) + 1).is_err());
        assert!(u32_from_i64("field", i64::MAX).is_err());
    }

    // ── u64_from_i64 tests ──────────────────────────────────────────────

    #[test]
    fn u64_from_i64_accepts_zero() {
        assert_eq!(u64_from_i64("field", 0).expect("zero"), 0u64);
    }

    #[test]
    fn u64_from_i64_accepts_i64_max() {
        assert_eq!(u64_from_i64("field", i64::MAX).expect("i64::MAX"), i64::MAX as u64);
    }

    #[test]
    fn u64_from_i64_rejects_negative() {
        assert!(u64_from_i64("field", -1).is_err());
        assert!(u64_from_i64("field", i64::MIN).is_err());
    }

    // ── Database connection error tests ─────────────────────────────────

    #[tokio::test]
    async fn connect_returns_error_for_nonexistent_parent_directory() {
        let result = Database::connect("/nonexistent/parent/dir/test.sqlite").await;
        assert!(result.is_err(), "expected error for path with nonexistent parent directory");
    }

    #[tokio::test]
    async fn connect_returns_error_for_unwritable_path() {
        // /proc is a read-only filesystem on Linux; SQLite cannot create files there.
        let result = Database::connect("/proc/fake_dir/test.sqlite").await;
        assert!(result.is_err(), "expected error for unwritable path");
    }
}
