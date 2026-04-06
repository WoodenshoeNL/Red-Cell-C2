//! SQLite-backed persistence for the Red Cell teamserver.

use std::path::{Path, PathBuf};

use red_cell_common::demon::DemonProtocolError;
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use thiserror::Error;
use tracing::instrument;

pub mod agent_groups;
pub mod agents;
pub mod audit;
pub mod jobs;
pub mod links;
pub mod listener_access;
pub mod listeners;
pub mod loot;
pub mod operators;

pub use agent_groups::AgentGroupRepository;
pub use agents::{AgentRepository, PersistedAgent};
pub use audit::{AuditLogEntry, AuditLogFilter, AuditLogRepository};
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

#[cfg(test)]
use operators::parse_operator_role;

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
}

impl Database {
    /// Open a SQLite database at `path`, creating it if needed, and apply migrations.
    #[instrument(fields(path = %path.as_ref().display()))]
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, TeamserverError> {
        let path = path.as_ref();
        let options =
            SqliteConnectOptions::new().filename(path).create_if_missing(true).foreign_keys(true);

        Self::connect_with_options(options).await
    }

    /// Open an in-memory SQLite database and apply migrations.
    #[instrument]
    pub async fn connect_in_memory() -> Result<Self, TeamserverError> {
        let options = SqliteConnectOptions::new().filename(":memory:").foreign_keys(true);

        Self::connect_with_options(options).await
    }

    /// Build a database pool from fully-specified SQLite connection options.
    #[instrument(skip(options))]
    pub async fn connect_with_options(
        options: SqliteConnectOptions,
    ) -> Result<Self, TeamserverError> {
        let pool = SqlitePoolOptions::new().max_connections(1).connect_with(options).await?;

        MIGRATOR.run(&pool).await?;

        Ok(Self { pool })
    }

    /// Borrow the underlying SQLx connection pool.
    #[must_use]
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Access agent/session persistence methods.
    #[must_use]
    pub fn agents(&self) -> AgentRepository {
        AgentRepository::new(self.pool.clone())
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
    use super::{
        AgentResponseRecord, AuditLogEntry, AuditLogFilter, Database, LinkRecord, ListenerStatus,
        LootFilter, LootRecord, PayloadBuildRecord, PersistedOperator, bool_from_i64, i64_from_u64,
        parse_operator_role, u32_from_i64, u64_from_i64,
    };
    use red_cell_common::config::OperatorRole;
    use red_cell_common::{AgentEncryptionInfo, AgentRecord, HttpListenerConfig, ListenerConfig};
    use serde_json::json;
    use zeroize::Zeroizing;

    /// Create a minimal agent record suitable for satisfying foreign-key constraints.
    fn stub_agent(agent_id: u32) -> AgentRecord {
        AgentRecord {
            agent_id,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: AgentEncryptionInfo {
                aes_key: Zeroizing::new(b"k".to_vec()),
                aes_iv: Zeroizing::new(b"i".to_vec()),
            },
            hostname: String::new(),
            username: String::new(),
            domain_name: String::new(),
            external_ip: String::new(),
            internal_ip: String::new(),
            process_name: String::new(),
            process_path: String::new(),
            base_address: 0,
            process_pid: 0,
            process_tid: 0,
            process_ppid: 0,
            process_arch: String::new(),
            elevated: false,
            os_version: String::new(),
            os_build: 0,
            os_arch: String::new(),
            sleep_delay: 0,
            sleep_jitter: 0,
            kill_date: None,
            working_hours: None,
            first_call_in: String::new(),
            last_call_in: String::new(),
        }
    }

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

    #[test]
    fn i64_from_u64_accepts_zero() {
        assert_eq!(i64_from_u64("field", 0).expect("unwrap"), 0);
    }

    #[test]
    fn i64_from_u64_accepts_one() {
        assert_eq!(i64_from_u64("field", 1).expect("unwrap"), 1);
    }

    #[test]
    fn i64_from_u64_accepts_i64_max() {
        let val = i64::MAX as u64;
        assert_eq!(i64_from_u64("field", val).expect("unwrap"), i64::MAX);
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

    // ── LootRepository tests ───────────────────────────────────────────

    fn sample_loot(agent_id: u32, kind: &str, name: &str) -> LootRecord {
        LootRecord {
            id: None,
            agent_id,
            kind: kind.to_string(),
            name: name.to_string(),
            file_path: Some("/tmp/creds.txt".to_string()),
            size_bytes: Some(256),
            captured_at: "2026-03-19T12:00:00Z".to_string(),
            data: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            metadata: Some(json!({"operator": "admin", "command_line": "hashdump"})),
        }
    }

    /// Insert stub agent rows so loot FK constraints are satisfied.
    async fn seed_agents(db: &Database, ids: &[u32]) {
        for &id in ids {
            db.agents().create(&stub_agent(id)).await.expect("unwrap");
        }
    }

    #[tokio::test]
    async fn loot_create_and_get_round_trips_all_fields() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_agents(&db, &[100]).await;
        let repo = db.loot();
        let record = sample_loot(100, "hash", "NTLM hashes");

        let id = repo.create(&record).await.expect("unwrap");
        let fetched = repo.get(id).await.expect("unwrap").expect("record should exist");

        assert_eq!(fetched.id, Some(id));
        assert_eq!(fetched.agent_id, record.agent_id);
        assert_eq!(fetched.kind, record.kind);
        assert_eq!(fetched.name, record.name);
        assert_eq!(fetched.file_path, record.file_path);
        assert_eq!(fetched.size_bytes, record.size_bytes);
        assert_eq!(fetched.captured_at, record.captured_at);
        assert_eq!(fetched.data, record.data);
        assert_eq!(fetched.metadata, record.metadata);
    }

    #[tokio::test]
    async fn loot_get_returns_none_for_missing_id() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.loot();

        let fetched = repo.get(999).await.expect("unwrap");
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn loot_list_for_agent_returns_correct_grouping() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_agents(&db, &[10, 20]).await;
        let repo = db.loot();

        repo.create(&sample_loot(10, "hash", "agent10-hash")).await.expect("unwrap");
        repo.create(&sample_loot(10, "ticket", "agent10-ticket")).await.expect("unwrap");
        repo.create(&sample_loot(20, "token", "agent20-token")).await.expect("unwrap");

        let agent10 = repo.list_for_agent(10).await.expect("unwrap");
        assert_eq!(agent10.len(), 2);
        assert!(agent10.iter().all(|r| r.agent_id == 10));

        let agent20 = repo.list_for_agent(20).await.expect("unwrap");
        assert_eq!(agent20.len(), 1);
        assert_eq!(agent20[0].agent_id, 20);
        assert_eq!(agent20[0].name, "agent20-token");

        let agent99 = repo.list_for_agent(99).await.expect("unwrap");
        assert!(agent99.is_empty());
    }

    #[tokio::test]
    async fn loot_list_returns_all_records() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_agents(&db, &[1, 2, 3]).await;
        let repo = db.loot();

        repo.create(&sample_loot(1, "hash", "a")).await.expect("unwrap");
        repo.create(&sample_loot(2, "ticket", "b")).await.expect("unwrap");
        repo.create(&sample_loot(3, "token", "c")).await.expect("unwrap");

        let all = repo.list().await.expect("unwrap");
        assert_eq!(all.len(), 3);
    }

    #[tokio::test]
    async fn loot_empty_content_and_label_round_trips() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_agents(&db, &[42]).await;
        let repo = db.loot();

        let record = LootRecord {
            id: None,
            agent_id: 42,
            kind: String::new(),
            name: String::new(),
            file_path: None,
            size_bytes: None,
            captured_at: String::new(),
            data: None,
            metadata: None,
        };

        let id = repo.create(&record).await.expect("unwrap");
        let fetched = repo.get(id).await.expect("unwrap").expect("record should exist");

        assert_eq!(fetched.agent_id, 42);
        assert_eq!(fetched.kind, "");
        assert_eq!(fetched.name, "");
        assert_eq!(fetched.file_path, None);
        assert_eq!(fetched.size_bytes, None);
        assert_eq!(fetched.captured_at, "");
        assert_eq!(fetched.data, None);
        assert_eq!(fetched.metadata, None);
    }

    #[tokio::test]
    async fn loot_delete_removes_record() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_agents(&db, &[1]).await;
        let repo = db.loot();

        let id = repo.create(&sample_loot(1, "hash", "to-delete")).await.expect("unwrap");
        assert!(repo.get(id).await.expect("unwrap").is_some());

        repo.delete(id).await.expect("unwrap");
        assert!(repo.get(id).await.expect("unwrap").is_none());
    }

    #[tokio::test]
    async fn loot_query_filtered_by_kind_exact() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_agents(&db, &[1, 2]).await;
        let repo = db.loot();

        repo.create(&sample_loot(1, "hash", "h1")).await.expect("unwrap");
        repo.create(&sample_loot(1, "ticket", "t1")).await.expect("unwrap");
        repo.create(&sample_loot(2, "hash", "h2")).await.expect("unwrap");

        let filter = LootFilter { kind_exact: Some("hash".to_string()), ..Default::default() };
        let results = repo.query_filtered(&filter, 100, 0).await.expect("unwrap");
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.kind == "hash"));
    }

    #[tokio::test]
    async fn loot_query_filtered_by_agent_id() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_agents(&db, &[10, 20]).await;
        let repo = db.loot();

        repo.create(&sample_loot(10, "hash", "a")).await.expect("unwrap");
        repo.create(&sample_loot(20, "hash", "b")).await.expect("unwrap");

        let filter = LootFilter { agent_id: Some(10), ..Default::default() };
        let results = repo.query_filtered(&filter, 100, 0).await.expect("unwrap");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].agent_id, 10);
    }

    #[tokio::test]
    async fn loot_count_filtered_matches_query_length() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_agents(&db, &[1]).await;
        let repo = db.loot();

        repo.create(&sample_loot(1, "hash", "h1")).await.expect("unwrap");
        repo.create(&sample_loot(1, "hash", "h2")).await.expect("unwrap");
        repo.create(&sample_loot(1, "ticket", "t1")).await.expect("unwrap");

        let filter = LootFilter { kind_exact: Some("hash".to_string()), ..Default::default() };
        let count = repo.count_filtered(&filter).await.expect("unwrap");
        let results = repo.query_filtered(&filter, 100, 0).await.expect("unwrap");
        assert_eq!(count, results.len() as i64);
    }

    #[tokio::test]
    async fn loot_query_filtered_pagination() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_agents(&db, &[1]).await;
        let repo = db.loot();

        for i in 0..5 {
            repo.create(&sample_loot(1, "hash", &format!("item-{i}"))).await.expect("unwrap");
        }

        let filter = LootFilter::default();
        let page1 = repo.query_filtered(&filter, 2, 0).await.expect("unwrap");
        let page2 = repo.query_filtered(&filter, 2, 2).await.expect("unwrap");
        let page3 = repo.query_filtered(&filter, 2, 4).await.expect("unwrap");

        assert_eq!(page1.len(), 2);
        assert_eq!(page2.len(), 2);
        assert_eq!(page3.len(), 1);

        // query_filtered orders by id DESC, so no overlap
        let all_ids: Vec<_> =
            page1.iter().chain(page2.iter()).chain(page3.iter()).map(|r| r.id).collect();
        let mut deduped = all_ids.clone();
        deduped.dedup();
        assert_eq!(all_ids.len(), deduped.len(), "pages should not overlap");
    }

    // ── LinkRepository tests ──────────────────────────────────────────

    /// Seed agents and create a link chain A→B→C.
    async fn seed_link_chain(db: &Database, a: u32, b: u32, c: u32) {
        seed_agents(db, &[a, b, c]).await;
        let links = db.links();
        links.create(LinkRecord { parent_agent_id: a, link_agent_id: b }).await.expect("unwrap");
        links.create(LinkRecord { parent_agent_id: b, link_agent_id: c }).await.expect("unwrap");
    }

    #[tokio::test]
    async fn link_chain_children_of_returns_direct_children_only() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_link_chain(&db, 1, 2, 3).await;
        let links = db.links();

        let children_of_a = links.children_of(1).await.expect("unwrap");
        assert_eq!(children_of_a, vec![2], "A should have only direct child B");

        let children_of_b = links.children_of(2).await.expect("unwrap");
        assert_eq!(children_of_b, vec![3], "B should have only direct child C");

        let children_of_c = links.children_of(3).await.expect("unwrap");
        assert!(children_of_c.is_empty(), "C is a leaf and should have no children");
    }

    #[tokio::test]
    async fn link_delete_parent_removes_only_direct_link() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_link_chain(&db, 1, 2, 3).await;
        let links = db.links();

        // Delete A→B link
        links.delete(1, 2).await.expect("unwrap");

        assert!(!links.exists(1, 2).await.expect("unwrap"), "A→B link should be gone");
        assert!(links.exists(2, 3).await.expect("unwrap"), "B→C link should still exist");
        assert_eq!(links.parent_of(2).await.expect("unwrap"), None, "B should have no parent");
        assert_eq!(links.parent_of(3).await.expect("unwrap"), Some(2), "C still has parent B");
    }

    #[tokio::test]
    async fn link_cascade_simulation_marks_all_transitive_children() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_link_chain(&db, 1, 2, 3).await;
        let links = db.links();

        // Simulate the cascade disconnect_link performs at the repo layer:
        // 1. Collect the subtree rooted at B by walking children_of recursively
        let mut affected = vec![2u32];
        let mut queue = vec![2u32];
        while let Some(node) = queue.pop() {
            let children = links.children_of(node).await.expect("unwrap");
            for &child in &children {
                affected.push(child);
                queue.push(child);
            }
        }
        assert_eq!(affected, vec![2, 3], "subtree of B should include B and C");

        // 2. Delete the link A→B
        links.delete(1, 2).await.expect("unwrap");

        // 3. Verify the remaining state
        let remaining = links.list().await.expect("unwrap");
        assert_eq!(remaining.len(), 1, "only B→C should remain");
        assert_eq!(remaining[0].parent_agent_id, 2);
        assert_eq!(remaining[0].link_agent_id, 3);
    }

    #[tokio::test]
    async fn link_delete_nonexistent_returns_ok() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_agents(&db, &[10, 20]).await;
        let links = db.links();

        // Deleting a link that was never created should succeed silently
        let result = links.delete(10, 20).await;
        assert!(result.is_ok(), "deleting non-existent link should not error");
    }

    #[tokio::test]
    async fn link_relink_after_disconnect_succeeds() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_agents(&db, &[1, 2]).await;
        let links = db.links();

        // Create, delete, re-create
        links.create(LinkRecord { parent_agent_id: 1, link_agent_id: 2 }).await.expect("unwrap");
        assert!(links.exists(1, 2).await.expect("unwrap"));

        links.delete(1, 2).await.expect("unwrap");
        assert!(!links.exists(1, 2).await.expect("unwrap"));

        links.create(LinkRecord { parent_agent_id: 1, link_agent_id: 2 }).await.expect("unwrap");
        assert!(links.exists(1, 2).await.expect("unwrap"), "re-linked A→B should exist");
        assert_eq!(links.parent_of(2).await.expect("unwrap"), Some(1));
    }

    #[tokio::test]
    async fn link_list_returns_all_links_in_chain() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_link_chain(&db, 10, 20, 30).await;
        let links = db.links();

        let all = links.list().await.expect("unwrap");
        assert_eq!(all.len(), 2);
        assert_eq!(
            all,
            vec![
                LinkRecord { parent_agent_id: 10, link_agent_id: 20 },
                LinkRecord { parent_agent_id: 20, link_agent_id: 30 },
            ]
        );
    }

    #[tokio::test]
    async fn link_parent_of_returns_correct_parent() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_link_chain(&db, 5, 6, 7).await;
        let links = db.links();

        assert_eq!(links.parent_of(5).await.expect("unwrap"), None, "root has no parent");
        assert_eq!(links.parent_of(6).await.expect("unwrap"), Some(5));
        assert_eq!(links.parent_of(7).await.expect("unwrap"), Some(6));
        assert_eq!(links.parent_of(99).await.expect("unwrap"), None, "unknown agent has no parent");
    }

    // ── AuditLogRepository tests ─────────────────────────────────────

    fn audit_entry(actor: &str, action: &str, occurred_at: &str) -> AuditLogEntry {
        AuditLogEntry {
            id: None,
            actor: actor.to_string(),
            action: action.to_string(),
            target_kind: "agent".to_string(),
            target_id: Some("0x00000001".to_string()),
            details: Some(json!({"agent_id": "1", "command": "whoami", "result_status": "ok"})),
            occurred_at: occurred_at.to_string(),
        }
    }

    async fn seed_audit_entries(db: &Database) {
        let repo = db.audit_log();
        repo.create(&audit_entry("alice", "task.create", "2026-03-01T10:00:00Z"))
            .await
            .expect("unwrap");
        repo.create(&audit_entry("bob", "task.create", "2026-03-02T10:00:00Z"))
            .await
            .expect("unwrap");
        repo.create(&audit_entry("alice", "task.complete", "2026-03-03T10:00:00Z"))
            .await
            .expect("unwrap");
        repo.create(&audit_entry("carol", "agent.checkin", "2026-03-04T10:00:00Z"))
            .await
            .expect("unwrap");
        repo.create(&audit_entry("bob", "task.complete", "2026-03-05T10:00:00Z"))
            .await
            .expect("unwrap");
    }

    #[tokio::test]
    async fn audit_query_filtered_by_actor_substring() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        let filter =
            AuditLogFilter { actor_contains: Some("ali".to_string()), ..Default::default() };
        let results = repo.query_filtered(&filter, 100, 0).await.expect("unwrap");
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|e| e.actor == "alice"));
    }

    #[tokio::test]
    async fn audit_query_filtered_by_action_substring() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        let filter =
            AuditLogFilter { action_contains: Some("complete".to_string()), ..Default::default() };
        let results = repo.query_filtered(&filter, 100, 0).await.expect("unwrap");
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|e| e.action == "task.complete"));
    }

    #[tokio::test]
    async fn audit_query_filtered_by_date_range() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        let filter = AuditLogFilter {
            since: Some("2026-03-02T00:00:00Z".to_string()),
            until: Some("2026-03-04T00:00:00Z".to_string()),
            ..Default::default()
        };
        let results = repo.query_filtered(&filter, 100, 0).await.expect("unwrap");
        assert_eq!(results.len(), 2, "only entries on 03-02 and 03-03 should match");
    }

    #[tokio::test]
    async fn audit_query_filtered_combined_actor_and_action() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        let filter = AuditLogFilter {
            actor_contains: Some("bob".to_string()),
            action_contains: Some("create".to_string()),
            ..Default::default()
        };
        let results = repo.query_filtered(&filter, 100, 0).await.expect("unwrap");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].actor, "bob");
        assert_eq!(results[0].action, "task.create");
    }

    #[tokio::test]
    async fn audit_query_filtered_action_in_list() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        let filter = AuditLogFilter {
            action_in: Some(vec!["task.create".to_string(), "agent.checkin".to_string()]),
            ..Default::default()
        };
        let results = repo.query_filtered(&filter, 100, 0).await.expect("unwrap");
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn audit_query_filtered_pagination_newest_first() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        let filter = AuditLogFilter::default();
        let page1 = repo.query_filtered(&filter, 2, 0).await.expect("unwrap");
        let page2 = repo.query_filtered(&filter, 2, 2).await.expect("unwrap");
        let page3 = repo.query_filtered(&filter, 2, 4).await.expect("unwrap");

        assert_eq!(page1.len(), 2);
        assert_eq!(page2.len(), 2);
        assert_eq!(page3.len(), 1);

        // Newest first: page1 should have the latest occurred_at values.
        assert!(page1[0].occurred_at >= page1[1].occurred_at);
        assert!(page1[1].occurred_at >= page2[0].occurred_at);

        // No overlapping ids.
        let all_ids: Vec<_> =
            page1.iter().chain(page2.iter()).chain(page3.iter()).map(|e| e.id).collect();
        let mut deduped = all_ids.clone();
        deduped.dedup();
        assert_eq!(all_ids.len(), deduped.len(), "pages should not overlap");
    }

    #[tokio::test]
    async fn audit_query_filtered_no_matches_returns_empty() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        let filter = AuditLogFilter {
            actor_contains: Some("nonexistent".to_string()),
            ..Default::default()
        };
        let results = repo.query_filtered(&filter, 100, 0).await.expect("unwrap");
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn audit_query_filtered_by_json_details_fields() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        // Filter by agent_id in details JSON.
        let filter = AuditLogFilter { agent_id: Some("1".to_string()), ..Default::default() };
        let results = repo.query_filtered(&filter, 100, 0).await.expect("unwrap");
        assert_eq!(results.len(), 5, "all seeded entries have agent_id=1");

        // Filter by command substring in details JSON.
        let filter =
            AuditLogFilter { command_contains: Some("who".to_string()), ..Default::default() };
        let results = repo.query_filtered(&filter, 100, 0).await.expect("unwrap");
        assert_eq!(results.len(), 5);

        // Filter by result_status in details JSON.
        let filter = AuditLogFilter { result_status: Some("ok".to_string()), ..Default::default() };
        let results = repo.query_filtered(&filter, 100, 0).await.expect("unwrap");
        assert_eq!(results.len(), 5);

        // Non-matching result_status.
        let filter =
            AuditLogFilter { result_status: Some("error".to_string()), ..Default::default() };
        let results = repo.query_filtered(&filter, 100, 0).await.expect("unwrap");
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn audit_count_filtered_matches_query_length() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        // Unfiltered count.
        let count = repo.count_filtered(&AuditLogFilter::default()).await.expect("unwrap");
        let results =
            repo.query_filtered(&AuditLogFilter::default(), 100, 0).await.expect("unwrap");
        assert_eq!(count, results.len() as i64);

        // Filtered count.
        let filter =
            AuditLogFilter { actor_contains: Some("alice".to_string()), ..Default::default() };
        let count = repo.count_filtered(&filter).await.expect("unwrap");
        let results = repo.query_filtered(&filter, 100, 0).await.expect("unwrap");
        assert_eq!(count, results.len() as i64);
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn audit_count_filtered_with_date_range() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        let filter = AuditLogFilter {
            since: Some("2026-03-03T00:00:00Z".to_string()),
            until: Some("2026-03-05T23:59:59Z".to_string()),
            ..Default::default()
        };
        let count = repo.count_filtered(&filter).await.expect("unwrap");
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn audit_latest_timestamps_no_matching_rows() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.audit_log();

        // No data at all.
        let result =
            repo.latest_timestamps_by_actor_for_actions(&["task.create"]).await.expect("unwrap");
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn audit_latest_timestamps_empty_actions_returns_empty() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        let result = repo.latest_timestamps_by_actor_for_actions(&[]).await.expect("unwrap");
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn audit_latest_timestamps_multiple_actors() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        let result = repo
            .latest_timestamps_by_actor_for_actions(&["task.create", "task.complete"])
            .await
            .expect("unwrap");
        // alice: max of 2026-03-01 (create) and 2026-03-03 (complete) → 2026-03-03
        assert_eq!(result.get("alice").map(String::as_str), Some("2026-03-03T10:00:00Z"));
        // bob: max of 2026-03-02 (create) and 2026-03-05 (complete) → 2026-03-05
        assert_eq!(result.get("bob").map(String::as_str), Some("2026-03-05T10:00:00Z"));
        // carol only has agent.checkin, not in the action list.
        assert!(!result.contains_key("carol"));
    }

    #[tokio::test]
    async fn audit_latest_timestamps_single_action() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        let result =
            repo.latest_timestamps_by_actor_for_actions(&["agent.checkin"]).await.expect("unwrap");
        assert_eq!(result.len(), 1);
        assert_eq!(result.get("carol").map(String::as_str), Some("2026-03-04T10:00:00Z"));
    }

    #[tokio::test]
    async fn audit_latest_timestamps_nonexistent_action_returns_empty() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        let result = repo
            .latest_timestamps_by_actor_for_actions(&["nonexistent.action"])
            .await
            .expect("unwrap");
        assert!(result.is_empty());
    }

    // ── OperatorRepository tests ─────────────────────────────────────

    fn sample_operator(username: &str) -> PersistedOperator {
        PersistedOperator {
            username: username.to_string(),
            password_verifier: "argon2:initial_hash".to_string(),
            role: OperatorRole::Operator,
        }
    }

    #[tokio::test]
    async fn operator_update_password_verifier_succeeds_for_existing_user() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.operators();

        repo.create(&sample_operator("admin")).await.expect("unwrap");
        repo.update_password_verifier("admin", "argon2:new_hash").await.expect("unwrap");

        let fetched = repo.get("admin").await.expect("unwrap").expect("operator should exist");
        assert_eq!(fetched.password_verifier, "argon2:new_hash");
    }

    #[tokio::test]
    async fn operator_update_password_verifier_silently_succeeds_for_nonexistent_user() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.operators();

        // UPDATE WHERE username = ? affects zero rows — SQLite does not error.
        let result = repo.update_password_verifier("ghost", "argon2:hash").await;
        assert!(result.is_ok(), "update for non-existent user should not error");

        // Confirm the user was not accidentally created.
        let fetched = repo.get("ghost").await.expect("unwrap");
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn operator_create_and_get_round_trips() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.operators();
        let op = sample_operator("testuser");

        repo.create(&op).await.expect("unwrap");
        let fetched = repo.get("testuser").await.expect("unwrap").expect("operator should exist");

        assert_eq!(fetched.username, "testuser");
        assert_eq!(fetched.password_verifier, "argon2:initial_hash");
        assert_eq!(fetched.role, OperatorRole::Operator);
    }

    #[tokio::test]
    async fn operator_get_returns_none_for_missing_user() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.operators();

        let fetched = repo.get("nobody").await.expect("unwrap");
        assert!(fetched.is_none());
    }

    // ── ListenerRepository tests ─────────────────────────────────────

    fn stub_http_listener(name: &str) -> ListenerConfig {
        ListenerConfig::from(HttpListenerConfig {
            name: name.to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["127.0.0.1".to_owned()],
            host_bind: "0.0.0.0".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: 8080,
            port_conn: None,
            method: None,
            behind_redirector: false,
            trusted_proxy_peers: Vec::new(),
            user_agent: None,
            headers: Vec::new(),
            uris: vec!["/".to_owned()],
            host_header: None,
            secure: false,
            cert: None,
            response: None,
            proxy: None,
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
        })
    }

    #[tokio::test]
    async fn listener_set_state_created_to_running() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.listeners();

        repo.create(&stub_http_listener("ls-test")).await.expect("unwrap");

        // Initial state should be Created.
        let persisted = repo.get("ls-test").await.expect("unwrap").expect("listener should exist");
        assert_eq!(persisted.state.status, ListenerStatus::Created);
        assert!(persisted.state.last_error.is_none());

        // Transition to Running.
        repo.set_state("ls-test", ListenerStatus::Running, None).await.expect("unwrap");
        let persisted = repo.get("ls-test").await.expect("unwrap").expect("unwrap");
        assert_eq!(persisted.state.status, ListenerStatus::Running);
        assert!(persisted.state.last_error.is_none());
    }

    #[tokio::test]
    async fn listener_set_state_running_to_error_with_message() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.listeners();

        repo.create(&stub_http_listener("ls-err")).await.expect("unwrap");
        repo.set_state("ls-err", ListenerStatus::Running, None).await.expect("unwrap");

        // Transition to Error with a reason.
        repo.set_state("ls-err", ListenerStatus::Error, Some("bind failed: port in use"))
            .await
            .expect("unwrap");
        let persisted = repo.get("ls-err").await.expect("unwrap").expect("unwrap");
        assert_eq!(persisted.state.status, ListenerStatus::Error);
        assert_eq!(persisted.state.last_error.as_deref(), Some("bind failed: port in use"));
    }

    #[tokio::test]
    async fn listener_set_state_error_to_stopped_clears_error() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.listeners();

        repo.create(&stub_http_listener("ls-clr")).await.expect("unwrap");
        repo.set_state("ls-clr", ListenerStatus::Error, Some("crash")).await.expect("unwrap");

        // Transition back to Stopped with no error.
        repo.set_state("ls-clr", ListenerStatus::Stopped, None).await.expect("unwrap");
        let persisted = repo.get("ls-clr").await.expect("unwrap").expect("unwrap");
        assert_eq!(persisted.state.status, ListenerStatus::Stopped);
        assert!(persisted.state.last_error.is_none());
    }

    #[tokio::test]
    async fn listener_set_state_full_lifecycle() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.listeners();

        repo.create(&stub_http_listener("ls-life")).await.expect("unwrap");

        let transitions = [
            (ListenerStatus::Running, None),
            (ListenerStatus::Stopped, None),
            (ListenerStatus::Running, None),
            (ListenerStatus::Error, Some("unexpected EOF")),
            (ListenerStatus::Stopped, None),
        ];

        for (status, error) in &transitions {
            repo.set_state("ls-life", *status, error.as_deref()).await.expect("unwrap");
            let persisted = repo.get("ls-life").await.expect("unwrap").expect("unwrap");
            assert_eq!(persisted.state.status, *status);
            assert_eq!(persisted.state.last_error.as_deref(), *error);
        }
    }

    #[tokio::test]
    async fn listener_set_state_nonexistent_listener_silently_succeeds() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.listeners();

        // UPDATE WHERE name = ? on non-existent row affects zero rows — no error.
        let result = repo.set_state("ghost", ListenerStatus::Running, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn listener_create_duplicate_name_returns_error() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.listeners();

        repo.create(&stub_http_listener("dup")).await.expect("unwrap");
        let result = repo.create(&stub_http_listener("dup")).await;
        assert!(result.is_err(), "inserting a listener with a duplicate name should fail");
    }

    // ── ListenerStatus::try_from_str tests ──────────────────────────────

    #[test]
    fn listener_status_try_from_str_valid_values() {
        assert_eq!(
            ListenerStatus::try_from_str("created").expect("unwrap"),
            ListenerStatus::Created
        );
        assert_eq!(
            ListenerStatus::try_from_str("running").expect("unwrap"),
            ListenerStatus::Running
        );
        assert_eq!(
            ListenerStatus::try_from_str("stopped").expect("unwrap"),
            ListenerStatus::Stopped
        );
        assert_eq!(ListenerStatus::try_from_str("error").expect("unwrap"), ListenerStatus::Error);
    }

    #[test]
    fn listener_status_try_from_str_rejects_invalid_string() {
        assert!(ListenerStatus::try_from_str("").is_err());
        assert!(ListenerStatus::try_from_str("RUNNING").is_err());
        assert!(ListenerStatus::try_from_str("Created").is_err());
        assert!(ListenerStatus::try_from_str("unknown").is_err());
        assert!(ListenerStatus::try_from_str(" running").is_err());
    }

    // ── u32_from_i64 tests ──────────────────────────────────────────────

    #[test]
    fn u32_from_i64_accepts_zero() {
        assert_eq!(u32_from_i64("field", 0).expect("unwrap"), 0u32);
    }

    #[test]
    fn u32_from_i64_accepts_u32_max() {
        assert_eq!(u32_from_i64("field", i64::from(u32::MAX)).expect("unwrap"), u32::MAX);
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
        assert_eq!(u64_from_i64("field", 0).expect("unwrap"), 0u64);
    }

    #[test]
    fn u64_from_i64_accepts_i64_max() {
        assert_eq!(u64_from_i64("field", i64::MAX).expect("unwrap"), i64::MAX as u64);
    }

    #[test]
    fn u64_from_i64_rejects_negative() {
        assert!(u64_from_i64("field", -1).is_err());
        assert!(u64_from_i64("field", i64::MIN).is_err());
    }

    // ── parse_operator_role tests ───────────────────────────────────────

    #[test]
    fn parse_operator_role_accepts_titlecase() {
        assert_eq!(parse_operator_role("Admin").expect("unwrap"), OperatorRole::Admin);
        assert_eq!(parse_operator_role("Operator").expect("unwrap"), OperatorRole::Operator);
        assert_eq!(parse_operator_role("Analyst").expect("unwrap"), OperatorRole::Analyst);
    }

    #[test]
    fn parse_operator_role_accepts_lowercase() {
        assert_eq!(parse_operator_role("admin").expect("unwrap"), OperatorRole::Admin);
        assert_eq!(parse_operator_role("operator").expect("unwrap"), OperatorRole::Operator);
        assert_eq!(parse_operator_role("analyst").expect("unwrap"), OperatorRole::Analyst);
    }

    #[test]
    fn parse_operator_role_rejects_uppercase() {
        assert!(parse_operator_role("ADMIN").is_err());
        assert!(parse_operator_role("OPERATOR").is_err());
        assert!(parse_operator_role("ANALYST").is_err());
    }

    #[test]
    fn parse_operator_role_rejects_mixed_case() {
        assert!(parse_operator_role("aDmIn").is_err());
        assert!(parse_operator_role("oPeRaToR").is_err());
    }

    #[test]
    fn parse_operator_role_rejects_empty_and_unknown() {
        assert!(parse_operator_role("").is_err());
        assert!(parse_operator_role("root").is_err());
        assert!(parse_operator_role("viewer").is_err());
        assert!(parse_operator_role(" admin").is_err());
    }

    #[tokio::test]
    async fn operator_repository_delete_removes_existing_row() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.operators();
        let operator = PersistedOperator {
            username: "delme".to_owned(),
            password_verifier: "v".to_owned(),
            role: OperatorRole::Operator,
        };
        repo.create(&operator).await.expect("create");
        assert!(repo.delete("delme").await.expect("delete"), "should delete existing row");
        assert!(repo.get("delme").await.expect("get").is_none(), "row should be gone");
    }

    #[tokio::test]
    async fn operator_repository_delete_returns_false_for_missing_user() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.operators();
        assert!(
            !repo.delete("ghost").await.expect("delete"),
            "should return false for missing user"
        );
    }

    #[tokio::test]
    async fn operator_repository_update_role_changes_stored_role() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.operators();
        let operator = PersistedOperator {
            username: "rolechange".to_owned(),
            password_verifier: "v".to_owned(),
            role: OperatorRole::Analyst,
        };
        repo.create(&operator).await.expect("create");
        assert!(
            repo.update_role("rolechange", OperatorRole::Admin).await.expect("update"),
            "should update existing row"
        );
        let updated = repo.get("rolechange").await.expect("get").expect("should exist");
        assert_eq!(updated.role, OperatorRole::Admin);
    }

    #[tokio::test]
    async fn operator_repository_update_role_returns_false_for_missing_user() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.operators();
        assert!(
            !repo.update_role("ghost", OperatorRole::Admin).await.expect("update"),
            "should return false for missing user"
        );
    }

    // ── AgentResponseRepository::list_for_agent_since ───────────────────

    #[tokio::test]
    async fn list_for_agent_since_returns_all_when_no_cursor() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_agents(&db, &[100]).await;
        let repo = db.agent_responses();

        let record = AgentResponseRecord {
            id: None,
            agent_id: 100,
            command_id: 21,
            request_id: 1,
            response_type: "Good".to_owned(),
            message: "ok".to_owned(),
            output: "hello".to_owned(),
            command_line: None,
            task_id: Some("t1".to_owned()),
            operator: None,
            received_at: "2026-03-27T00:00:00Z".to_owned(),
            extra: None,
        };
        repo.create(&record).await.expect("create");

        let all = repo.list_for_agent_since(100, None).await.expect("query");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].output, "hello");
    }

    #[tokio::test]
    async fn list_for_agent_since_filters_by_cursor() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_agents(&db, &[101]).await;
        let repo = db.agent_responses();

        let r1 = AgentResponseRecord {
            id: None,
            agent_id: 101,
            command_id: 21,
            request_id: 1,
            response_type: "Good".to_owned(),
            message: "first".to_owned(),
            output: "out-1".to_owned(),
            command_line: None,
            task_id: Some("t1".to_owned()),
            operator: None,
            received_at: "2026-03-27T00:00:00Z".to_owned(),
            extra: None,
        };
        let id1 = repo.create(&r1).await.expect("create r1");

        let r2 = AgentResponseRecord {
            id: None,
            agent_id: 101,
            command_id: 21,
            request_id: 2,
            response_type: "Good".to_owned(),
            message: "second".to_owned(),
            output: "out-2".to_owned(),
            command_line: None,
            task_id: Some("t2".to_owned()),
            operator: None,
            received_at: "2026-03-27T00:01:00Z".to_owned(),
            extra: None,
        };
        repo.create(&r2).await.expect("create r2");

        let after_first = repo.list_for_agent_since(101, Some(id1)).await.expect("query");
        assert_eq!(after_first.len(), 1);
        assert_eq!(after_first[0].output, "out-2");

        let empty = repo.list_for_agent_since(101, Some(id1 + 100)).await.expect("query");
        assert!(empty.is_empty());
    }

    // ── payload_builds factory tests ─────────────────────────────────────

    /// Helper to create a minimal `PayloadBuildRecord` for tests.
    fn stub_payload_build(id: &str) -> PayloadBuildRecord {
        PayloadBuildRecord {
            id: id.to_owned(),
            status: "pending".to_owned(),
            name: "test-payload".to_owned(),
            arch: "x64".to_owned(),
            format: "exe".to_owned(),
            listener: "http-default".to_owned(),
            agent_type: "Demon".to_owned(),
            sleep_secs: Some(10),
            artifact: None,
            size_bytes: None,
            error: None,
            created_at: "2026-03-27T00:00:00Z".to_owned(),
            updated_at: "2026-03-27T00:00:00Z".to_owned(),
        }
    }

    #[tokio::test]
    async fn payload_builds_factory_insert_and_read_back() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.payload_builds();

        let record = stub_payload_build("build-001");
        repo.create(&record).await.expect("unwrap");

        let fetched = repo.get("build-001").await.expect("unwrap");
        assert_eq!(fetched, Some(record));
    }

    #[tokio::test]
    async fn payload_builds_factory_errors_after_close() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.payload_builds();
        db.close().await;

        let result = repo.create(&stub_payload_build("build-closed")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn payload_builds_factory_two_handles_see_same_row() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo_a = db.payload_builds();
        let repo_b = db.payload_builds();

        let record = stub_payload_build("build-shared");
        repo_a.create(&record).await.expect("unwrap");

        let fetched = repo_b.get("build-shared").await.expect("unwrap");
        assert_eq!(fetched, Some(record));
    }

    // ── AgentRepository transport-state persistence tests ─────────────

    #[tokio::test]
    async fn create_full_persists_listener_ctr_offset_and_legacy_ctr() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.agents();
        let agent = stub_agent(0xAA);

        repo.create_full(&agent, "https-listener", 42, true).await.expect("unwrap");

        let persisted =
            repo.get_persisted(0xAA).await.expect("unwrap").expect("agent should exist");
        assert_eq!(persisted.listener_name, "https-listener");
        assert_eq!(persisted.ctr_block_offset, 42);
        assert!(persisted.legacy_ctr);
        assert_eq!(persisted.info.agent_id, 0xAA);
    }

    #[tokio::test]
    async fn set_legacy_ctr_on_missing_agent_returns_agent_not_found() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.agents();

        let err = repo.set_legacy_ctr(0xDEAD, true).await.expect_err("expected Err");
        assert!(
            matches!(err, super::TeamserverError::AgentNotFound { agent_id } if agent_id == 0xDEAD),
            "expected AgentNotFound, got: {err:?}",
        );

        // Verify no row was created as a side-effect.
        let fetched = repo.get_persisted(0xDEAD).await.expect("unwrap");
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn toggle_legacy_ctr_preserves_other_fields() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.agents();
        let agent = stub_agent(0xBB);

        repo.create_full(&agent, "smb-pipe", 99, true).await.expect("unwrap");

        // Toggle legacy_ctr from true → false.
        repo.set_legacy_ctr(0xBB, false).await.expect("unwrap");

        let persisted =
            repo.get_persisted(0xBB).await.expect("unwrap").expect("agent should exist");
        assert!(!persisted.legacy_ctr, "legacy_ctr should now be false");
        // Other transport fields must be unchanged.
        assert_eq!(persisted.listener_name, "smb-pipe");
        assert_eq!(persisted.ctr_block_offset, 99);
        assert_eq!(persisted.info.agent_id, 0xBB);
        assert!(persisted.info.active);
    }

    // ── set_status tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn set_status_persists_active_and_reason() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.agents();
        let agent = stub_agent(0xCC);

        repo.create_full(&agent, "https-listener", 0, false).await.expect("unwrap");

        // Mark agent as inactive with a reason.
        repo.set_status(0xCC, false, "timed out").await.expect("unwrap");

        let persisted =
            repo.get_persisted(0xCC).await.expect("unwrap").expect("agent should exist");
        assert!(!persisted.info.active, "active should be false after set_status");
        assert_eq!(persisted.info.reason, "timed out");
        // Other fields must be unchanged.
        assert_eq!(persisted.listener_name, "https-listener");
        assert_eq!(persisted.ctr_block_offset, 0);
        assert_eq!(persisted.info.agent_id, 0xCC);
    }

    #[tokio::test]
    async fn set_status_on_missing_agent_returns_agent_not_found() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.agents();

        let err = repo.set_status(0xDEAD, false, "gone").await.expect_err("expected Err");
        assert!(
            matches!(err, super::TeamserverError::AgentNotFound { agent_id } if agent_id == 0xDEAD),
            "expected AgentNotFound, got: {err:?}",
        );

        // Verify no row was created as a side-effect.
        let fetched = repo.get_persisted(0xDEAD).await.expect("unwrap");
        assert!(fetched.is_none());
    }

    // ── payload_builds CRUD round-trip tests ──────────────────────────────

    #[tokio::test]
    async fn payload_builds_crud_round_trip_with_artifact_blobs() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.payload_builds();

        // Build two records with non-empty artifact blobs and all optional fields.
        let record_a = PayloadBuildRecord {
            id: "crud-a".to_owned(),
            status: "done".to_owned(),
            name: "agent-alpha.exe".to_owned(),
            arch: "x64".to_owned(),
            format: "exe".to_owned(),
            listener: "https-main".to_owned(),
            agent_type: "Demon".to_owned(),
            sleep_secs: Some(30),
            artifact: Some(vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]),
            size_bytes: Some(6),
            error: None,
            created_at: "2026-03-27T10:00:00Z".to_owned(),
            updated_at: "2026-03-27T10:05:00Z".to_owned(),
        };
        let record_b = PayloadBuildRecord {
            id: "crud-b".to_owned(),
            status: "error".to_owned(),
            name: "agent-beta.dll".to_owned(),
            arch: "x86".to_owned(),
            format: "dll".to_owned(),
            listener: "dns-backup".to_owned(),
            agent_type: "Archon".to_owned(),
            sleep_secs: None,
            artifact: Some(vec![0xFF; 256]),
            size_bytes: Some(256),
            error: Some("linker failure".to_owned()),
            created_at: "2026-03-27T11:00:00Z".to_owned(),
            updated_at: "2026-03-27T11:01:00Z".to_owned(),
        };

        repo.create(&record_a).await.expect("unwrap");
        repo.create(&record_b).await.expect("unwrap");

        // get() must reproduce every field exactly.
        let fetched_a = repo.get("crud-a").await.expect("unwrap").expect("record_a should exist");
        assert_eq!(fetched_a, record_a);

        let fetched_b = repo.get("crud-b").await.expect("unwrap").expect("record_b should exist");
        assert_eq!(fetched_b, record_b);
    }

    #[tokio::test]
    async fn payload_builds_list_returns_newest_first() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.payload_builds();

        let mut older = stub_payload_build("list-older");
        older.created_at = "2026-03-27T08:00:00Z".to_owned();
        older.artifact = Some(vec![0x01, 0x02, 0x03]);
        older.size_bytes = Some(3);

        let mut newer = stub_payload_build("list-newer");
        newer.created_at = "2026-03-27T09:00:00Z".to_owned();
        newer.artifact = Some(vec![0xAA, 0xBB]);
        newer.size_bytes = Some(2);

        // Insert older first, then newer.
        repo.create(&older).await.expect("unwrap");
        repo.create(&newer).await.expect("unwrap");

        let all = repo.list().await.expect("unwrap");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].id, "list-newer", "newest record should be first");
        assert_eq!(all[1].id, "list-older", "oldest record should be second");

        // Verify artifact blobs survived the round-trip.
        assert_eq!(all[0].artifact, Some(vec![0xAA, 0xBB]));
        assert_eq!(all[1].artifact, Some(vec![0x01, 0x02, 0x03]));
    }

    #[tokio::test]
    async fn payload_builds_get_returns_none_for_unknown_id() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.payload_builds();

        let result = repo.get("nonexistent-build-id").await.expect("unwrap");
        assert!(result.is_none(), "get() should return None for unknown id");
    }

    // ── payload_builds summary query tests ──────────────────────────────

    #[tokio::test]
    async fn get_summary_returns_metadata_without_artifact() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.payload_builds();

        let mut record = stub_payload_build("sum-001");
        record.artifact = Some(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        record.size_bytes = Some(4);
        record.status = "done".to_owned();
        repo.create(&record).await.expect("unwrap");

        let summary = repo.get_summary("sum-001").await.expect("unwrap").expect("should exist");
        assert_eq!(summary.id, "sum-001");
        assert_eq!(summary.status, "done");
        assert_eq!(summary.name, "test-payload");
        assert_eq!(summary.arch, "x64");
        assert_eq!(summary.format, "exe");
        assert_eq!(summary.listener, "http-default");
        assert_eq!(summary.agent_type, "Demon");
        assert_eq!(summary.sleep_secs, Some(10));
        assert_eq!(summary.size_bytes, Some(4));
        assert!(summary.error.is_none());
        assert_eq!(summary.created_at, "2026-03-27T00:00:00Z");
        assert_eq!(summary.updated_at, "2026-03-27T00:00:00Z");
        // PayloadBuildSummary has no artifact field — this is enforced at compile time.
    }

    #[tokio::test]
    async fn get_summary_returns_none_for_missing_id() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.payload_builds();

        let result = repo.get_summary("nonexistent-id").await.expect("unwrap");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn list_summaries_returns_metadata_ordered_by_created_at_desc() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.payload_builds();

        // Insert builds with distinct timestamps (oldest first).
        let mut b1 = stub_payload_build("ls-001");
        b1.created_at = "2026-03-27T01:00:00Z".to_owned();
        b1.name = "first".to_owned();

        let mut b2 = stub_payload_build("ls-002");
        b2.created_at = "2026-03-27T02:00:00Z".to_owned();
        b2.name = "second".to_owned();
        b2.artifact = Some(vec![0xFF; 128]);
        b2.size_bytes = Some(128);

        let mut b3 = stub_payload_build("ls-003");
        b3.created_at = "2026-03-27T03:00:00Z".to_owned();
        b3.name = "third".to_owned();

        repo.create(&b1).await.expect("unwrap");
        repo.create(&b2).await.expect("unwrap");
        repo.create(&b3).await.expect("unwrap");

        let summaries = repo.list_summaries().await.expect("unwrap");
        assert_eq!(summaries.len(), 3);

        // Descending order: newest first.
        assert_eq!(summaries[0].id, "ls-003");
        assert_eq!(summaries[0].name, "third");
        assert_eq!(summaries[1].id, "ls-002");
        assert_eq!(summaries[1].name, "second");
        assert_eq!(summaries[1].size_bytes, Some(128));
        assert_eq!(summaries[2].id, "ls-001");
        assert_eq!(summaries[2].name, "first");

        // Verify metadata fields are present.
        for s in &summaries {
            assert_eq!(s.arch, "x64");
            assert_eq!(s.format, "exe");
            assert_eq!(s.listener, "http-default");
        }
    }

    #[tokio::test]
    async fn list_summaries_empty_table_returns_empty_vec() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.payload_builds();

        let summaries = repo.list_summaries().await.expect("unwrap");
        assert!(summaries.is_empty());
    }

    // ── payload_builds update_status tests ──────────────────────────────

    #[tokio::test]
    async fn update_status_happy_path_persists_all_fields() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.payload_builds();

        let record = stub_payload_build("upd-001");
        repo.create(&record).await.expect("unwrap");

        let artifact_bytes: &[u8] = &[0xCA, 0xFE, 0xBA, 0xBE];
        let updated = repo
            .update_status(
                "upd-001",
                "done",
                Some("final-payload.exe"),
                Some(artifact_bytes),
                Some(4),
                None,
                "2026-03-27T12:00:00Z",
            )
            .await
            .expect("unwrap");
        assert!(updated, "update_status should return true for existing row");

        let fetched = repo.get("upd-001").await.expect("unwrap").expect("row should exist");
        assert_eq!(fetched.status, "done");
        assert_eq!(fetched.name, "final-payload.exe");
        assert_eq!(fetched.artifact, Some(artifact_bytes.to_vec()));
        assert_eq!(fetched.size_bytes, Some(4));
        assert!(fetched.error.is_none());
        assert_eq!(fetched.updated_at, "2026-03-27T12:00:00Z");
        // Immutable fields should be unchanged.
        assert_eq!(fetched.arch, "x64");
        assert_eq!(fetched.format, "exe");
        assert_eq!(fetched.listener, "http-default");
        assert_eq!(fetched.created_at, "2026-03-27T00:00:00Z");
    }

    #[tokio::test]
    async fn update_status_missing_id_returns_false() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.payload_builds();

        let updated = repo
            .update_status(
                "nonexistent-id",
                "done",
                Some("payload.bin"),
                Some(&[0xFF]),
                Some(1),
                None,
                "2026-03-27T12:00:00Z",
            )
            .await
            .expect("unwrap");
        assert!(!updated, "update_status should return false for missing row");

        // Verify no row was created as a side-effect.
        let fetched = repo.get("nonexistent-id").await.expect("unwrap");
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn update_status_partial_fields_preserves_existing_values() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.payload_builds();

        // Seed a record with some optional fields populated.
        let mut record = stub_payload_build("upd-partial");
        record.name = "original-name.exe".to_owned();
        record.artifact = Some(vec![0x01, 0x02]);
        record.size_bytes = Some(2);
        repo.create(&record).await.expect("unwrap");

        // Update only status and error, leaving name/artifact/size_bytes as None.
        let updated = repo
            .update_status(
                "upd-partial",
                "error",
                None, // name unchanged
                None, // artifact unchanged
                None, // size_bytes unchanged
                Some("build timed out"),
                "2026-03-27T13:00:00Z",
            )
            .await
            .expect("unwrap");
        assert!(updated);

        let fetched = repo.get("upd-partial").await.expect("unwrap").expect("row should exist");
        assert_eq!(fetched.status, "error");
        assert_eq!(fetched.error, Some("build timed out".to_owned()));
        assert_eq!(fetched.updated_at, "2026-03-27T13:00:00Z");
        // These columns should be preserved by the COALESCE logic.
        assert_eq!(fetched.name, "original-name.exe");
        assert_eq!(fetched.artifact, Some(vec![0x01, 0x02]));
        assert_eq!(fetched.size_bytes, Some(2));
    }

    // ── payload_builds invalidate_done_builds_for_listener tests ────────

    #[tokio::test]
    async fn invalidate_done_builds_for_listener_marks_done_records_stale() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.payload_builds();

        // Two "done" builds for the target listener and one for another listener.
        let mut a = stub_payload_build("inv-a");
        a.status = "done".to_owned();
        a.listener = "http-main".to_owned();
        a.artifact = Some(vec![0xDE, 0xAD]);
        a.size_bytes = Some(2);

        let mut b = stub_payload_build("inv-b");
        b.status = "done".to_owned();
        b.listener = "http-main".to_owned();
        b.artifact = Some(vec![0xBE, 0xEF]);
        b.size_bytes = Some(2);

        let mut other = stub_payload_build("inv-other");
        other.status = "done".to_owned();
        other.listener = "dns-backup".to_owned();
        other.artifact = Some(vec![0xFF]);
        other.size_bytes = Some(1);

        repo.create(&a).await.expect("unwrap");
        repo.create(&b).await.expect("unwrap");
        repo.create(&other).await.expect("unwrap");

        let count = repo
            .invalidate_done_builds_for_listener("http-main", "2026-03-31T00:00:00Z")
            .await
            .expect("unwrap");
        assert_eq!(count, 2, "both done builds for http-main should be invalidated");

        // The two http-main builds must now be "stale".
        let fetched_a = repo.get("inv-a").await.expect("unwrap").expect("inv-a should exist");
        assert_eq!(fetched_a.status, "stale");
        assert_eq!(fetched_a.updated_at, "2026-03-31T00:00:00Z");

        let fetched_b = repo.get("inv-b").await.expect("unwrap").expect("inv-b should exist");
        assert_eq!(fetched_b.status, "stale");

        // The dns-backup build must be untouched.
        let fetched_other =
            repo.get("inv-other").await.expect("unwrap").expect("inv-other should exist");
        assert_eq!(fetched_other.status, "done");
    }

    #[tokio::test]
    async fn invalidate_done_builds_for_listener_ignores_non_done_records() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.payload_builds();

        // A pending and an error record for the same listener — must not be touched.
        let mut pending = stub_payload_build("inv-pend");
        pending.status = "pending".to_owned();
        pending.listener = "http-main".to_owned();

        let mut errored = stub_payload_build("inv-err");
        errored.status = "error".to_owned();
        errored.listener = "http-main".to_owned();

        repo.create(&pending).await.expect("unwrap");
        repo.create(&errored).await.expect("unwrap");

        let count = repo
            .invalidate_done_builds_for_listener("http-main", "2026-03-31T00:00:00Z")
            .await
            .expect("unwrap");
        assert_eq!(count, 0, "no done records exist — nothing should be invalidated");

        let fetched_pend =
            repo.get("inv-pend").await.expect("unwrap").expect("inv-pend should exist");
        assert_eq!(fetched_pend.status, "pending");

        let fetched_err = repo.get("inv-err").await.expect("unwrap").expect("inv-err should exist");
        assert_eq!(fetched_err.status, "error");
    }

    #[tokio::test]
    async fn invalidate_done_builds_for_listener_returns_zero_for_unknown_listener() {
        let db = Database::connect_in_memory().await.expect("unwrap");
        let repo = db.payload_builds();

        let count = repo
            .invalidate_done_builds_for_listener("nonexistent-listener", "2026-03-31T00:00:00Z")
            .await
            .expect("unwrap");
        assert_eq!(count, 0);
    }

    // ── AgentGroupRepository tests ────────────────────────────────────────────

    #[tokio::test]
    async fn agent_group_ensure_and_list() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.agent_groups();
        repo.ensure_group("dc").await.expect("ensure dc");
        repo.ensure_group("workstation").await.expect("ensure workstation");
        repo.ensure_group("dc").await.expect("ensure dc again (idempotent)");
        let groups = repo.list_groups().await.expect("list");
        assert_eq!(groups, vec!["dc", "workstation"]);
    }

    #[tokio::test]
    async fn agent_group_delete_removes_group() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.agent_groups();
        repo.ensure_group("exfil").await.expect("ensure");
        assert!(repo.delete_group("exfil").await.expect("delete"));
        assert!(!repo.delete_group("exfil").await.expect("delete again"));
        assert!(repo.list_groups().await.expect("list").is_empty());
    }

    #[tokio::test]
    async fn agent_group_set_agent_groups_round_trips() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_agents(&db, &[0xDEAD_BEEF]).await;
        let repo = db.agent_groups();
        let groups = vec!["dc".to_owned(), "pivot".to_owned()];
        repo.set_agent_groups(0xDEAD_BEEF, &groups).await.expect("set");
        let fetched = repo.groups_for_agent(0xDEAD_BEEF).await.expect("get");
        assert_eq!(fetched, groups);
    }

    #[tokio::test]
    async fn agent_group_set_agent_groups_replace() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_agents(&db, &[0x0000_0001]).await;
        let repo = db.agent_groups();
        repo.set_agent_groups(0x0000_0001, &["a".to_owned(), "b".to_owned()]).await.expect("set1");
        repo.set_agent_groups(0x0000_0001, &["c".to_owned()]).await.expect("set2");
        let fetched = repo.groups_for_agent(0x0000_0001).await.expect("get");
        assert_eq!(fetched, vec!["c"]);
    }

    #[tokio::test]
    async fn agent_group_add_remove_membership() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_agents(&db, &[0x0000_0002]).await;
        let repo = db.agent_groups();
        repo.ensure_group("srv").await.expect("ensure");
        repo.add_agent_to_group(0x0000_0002, "srv").await.expect("add");
        assert_eq!(repo.groups_for_agent(0x0000_0002).await.expect("get"), vec!["srv"]);
        let removed = repo.remove_agent_from_group(0x0000_0002, "srv").await.expect("remove");
        assert!(removed);
        assert!(repo.groups_for_agent(0x0000_0002).await.expect("get").is_empty());
    }

    #[tokio::test]
    async fn agent_group_operator_may_task_agent_unrestricted() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.agent_groups();
        // No restrictions → always permitted.
        assert!(repo.operator_may_task_agent("alice", &["dc".to_owned()]).await.expect("check"));
        assert!(repo.operator_may_task_agent("alice", &[]).await.expect("check"));
    }

    #[tokio::test]
    async fn agent_group_operator_may_task_agent_restricted() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.agent_groups();
        repo.set_operator_allowed_groups("alice", &["dc".to_owned()]).await.expect("set");
        // Agent in allowed group → permitted.
        assert!(repo.operator_may_task_agent("alice", &["dc".to_owned()]).await.expect("check"));
        // Agent not in allowed group → denied.
        assert!(
            !repo
                .operator_may_task_agent("alice", &["workstation".to_owned()])
                .await
                .expect("check")
        );
        // Ungrouped agent → denied.
        assert!(!repo.operator_may_task_agent("alice", &[]).await.expect("check"));
    }

    #[tokio::test]
    async fn agent_group_set_operator_allowed_groups_replace() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.agent_groups();
        repo.set_operator_allowed_groups("bob", &["a".to_owned(), "b".to_owned()])
            .await
            .expect("set1");
        assert_eq!(repo.operator_allowed_groups("bob").await.expect("list"), vec!["a", "b"]);
        repo.set_operator_allowed_groups("bob", &[]).await.expect("set2");
        assert!(repo.operator_allowed_groups("bob").await.expect("list").is_empty());
    }

    // ── ListenerAccessRepository tests ────────────────────────────────────────

    fn stub_http_listener_for_access(name: &str) -> ListenerConfig {
        stub_http_listener(name)
    }

    #[tokio::test]
    async fn listener_access_unrestricted_by_default() {
        let db = Database::connect_in_memory().await.expect("db");
        db.listeners().create(&stub_http_listener_for_access("http-main")).await.expect("create");
        let repo = db.listener_access();
        assert!(repo.allowed_operators("http-main").await.expect("list").is_empty());
        assert!(repo.operator_may_use_listener("anyone", "http-main").await.expect("check"));
    }

    #[tokio::test]
    async fn listener_access_set_and_enforce() {
        let db = Database::connect_in_memory().await.expect("db");
        db.listeners().create(&stub_http_listener_for_access("exfil")).await.expect("create");
        let repo = db.listener_access();
        repo.set_allowed_operators("exfil", &["alice".to_owned()]).await.expect("set");
        assert!(repo.operator_may_use_listener("alice", "exfil").await.expect("alice"));
        assert!(!repo.operator_may_use_listener("bob", "exfil").await.expect("bob"));
    }

    #[tokio::test]
    async fn listener_access_set_empty_removes_restrictions() {
        let db = Database::connect_in_memory().await.expect("db");
        db.listeners().create(&stub_http_listener_for_access("http-test")).await.expect("create");
        let repo = db.listener_access();
        repo.set_allowed_operators("http-test", &["alice".to_owned()]).await.expect("set");
        repo.set_allowed_operators("http-test", &[]).await.expect("clear");
        assert!(repo.allowed_operators("http-test").await.expect("list").is_empty());
        assert!(repo.operator_may_use_listener("anyone", "http-test").await.expect("check"));
    }
}
