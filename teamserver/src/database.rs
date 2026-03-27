//! SQLite-backed persistence for the Red Cell teamserver.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell_common::config::OperatorRole;
use red_cell_common::demon::DemonProtocolError;
use red_cell_common::{AgentRecord, ListenerConfig, ListenerProtocol};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{FromRow, QueryBuilder, Row, Sqlite, SqlitePool};
use thiserror::Error;
use tracing::instrument;
use utoipa::ToSchema;
use zeroize::Zeroizing;

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

    /// Close the SQLite pool and wait for all checked-out connections to return.
    pub async fn close(&self) {
        self.pool.close().await;
    }
}

/// CRUD operations for persisted agents.
#[derive(Clone, Debug)]
pub struct AgentRepository {
    pool: SqlitePool,
}

/// Persisted agent row plus transport state needed by the in-memory registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedAgent {
    /// Agent metadata mirrored into operator-facing APIs.
    pub info: AgentRecord,
    /// Listener that accepted the current or most recent session.
    pub listener_name: String,
    /// Shared AES-CTR block offset tracked across decrypt/encrypt operations.
    pub ctr_block_offset: u64,
    /// When `true`, AES-CTR resets to block offset 0 for every packet (Demon/Archon
    /// compatibility).  When `false`, the monotonic `ctr_block_offset` advances across
    /// packets (Specter behaviour).
    pub legacy_ctr: bool,
}

impl AgentRepository {
    /// Create a new agent repository from a shared pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Insert a new agent row.
    pub async fn create(&self, agent: &AgentRecord) -> Result<(), TeamserverError> {
        self.create_with_listener(agent, "null").await
    }

    /// Insert a new agent row with the listener that accepted the session.
    pub async fn create_with_listener(
        &self,
        agent: &AgentRecord,
        listener_name: &str,
    ) -> Result<(), TeamserverError> {
        self.create_with_listener_and_ctr_offset(agent, listener_name, 0).await
    }

    /// Insert a new agent row with the listener and initial CTR state for the session.
    ///
    /// Uses non-legacy (monotonic) CTR mode.  Use [`AgentRepository::create_full`] to
    /// set legacy mode for Demon/Archon agents.
    pub async fn create_with_listener_and_ctr_offset(
        &self,
        agent: &AgentRecord,
        listener_name: &str,
        ctr_block_offset: u64,
    ) -> Result<(), TeamserverError> {
        self.create_full(agent, listener_name, ctr_block_offset, false).await
    }

    /// Insert a new agent row with all transport parameters.
    pub async fn create_full(
        &self,
        agent: &AgentRecord,
        listener_name: &str,
        ctr_block_offset: u64,
        legacy_ctr: bool,
    ) -> Result<(), TeamserverError> {
        let mut transaction = self.pool.begin().await?;
        insert_agent_row(&mut *transaction, agent, listener_name, ctr_block_offset, legacy_ctr)
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Update an existing agent row.
    pub async fn update(&self, agent: &AgentRecord) -> Result<(), TeamserverError> {
        self.update_with_listener(agent, "null").await
    }

    /// Update an existing agent row and the listener that accepted the session.
    pub async fn update_with_listener(
        &self,
        agent: &AgentRecord,
        listener_name: &str,
    ) -> Result<(), TeamserverError> {
        let result = sqlx::query(
            r#"
            UPDATE ts_agents SET
                active = ?, reason = ?, note = ?, aes_key = ?, aes_iv = ?, hostname = ?, username = ?,
                domain_name = ?, external_ip = ?, internal_ip = ?, process_name = ?, process_path = ?,
                base_address = ?, process_pid = ?, process_tid = ?, process_ppid = ?,
                process_arch = ?, elevated = ?, os_version = ?, os_build = ?, os_arch = ?, listener_name = ?, sleep_delay = ?,
                sleep_jitter = ?, kill_date = ?, working_hours = ?, first_call_in = ?,
                last_call_in = ?
            WHERE agent_id = ?
            "#,
        )
        .bind(bool_to_i64(agent.active))
        .bind(&agent.reason)
        .bind(&agent.note)
        .bind(BASE64_STANDARD.encode(&*agent.encryption.aes_key))
        .bind(BASE64_STANDARD.encode(&*agent.encryption.aes_iv))
        .bind(&agent.hostname)
        .bind(&agent.username)
        .bind(&agent.domain_name)
        .bind(&agent.external_ip)
        .bind(&agent.internal_ip)
        .bind(&agent.process_name)
        .bind(&agent.process_path)
        .bind(i64_from_u64("base_address", agent.base_address)?)
        .bind(i64::from(agent.process_pid))
        .bind(i64::from(agent.process_tid))
        .bind(i64::from(agent.process_ppid))
        .bind(&agent.process_arch)
        .bind(bool_to_i64(agent.elevated))
        .bind(&agent.os_version)
        .bind(i64::from(agent.os_build))
        .bind(&agent.os_arch)
        .bind(listener_name)
        .bind(i64::from(agent.sleep_delay))
        .bind(i64::from(agent.sleep_jitter))
        .bind(agent.kill_date)
        .bind(agent.working_hours.map(i64::from))
        .bind(&agent.first_call_in)
        .bind(&agent.last_call_in)
        .bind(i64::from(agent.agent_id))
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(TeamserverError::AgentNotFound { agent_id: agent.agent_id });
        }

        Ok(())
    }

    /// Fetch a single agent by identifier.
    pub async fn get(&self, agent_id: u32) -> Result<Option<AgentRecord>, TeamserverError> {
        let row = sqlx::query_as::<_, AgentRow>("SELECT * FROM ts_agents WHERE agent_id = ?")
            .bind(i64::from(agent_id))
            .fetch_optional(&self.pool)
            .await?;

        row.map(TryInto::try_into).transpose()
    }

    /// Return all persisted agents.
    pub async fn list(&self) -> Result<Vec<AgentRecord>, TeamserverError> {
        let rows = sqlx::query_as::<_, AgentRow>("SELECT * FROM ts_agents ORDER BY agent_id")
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// Return only agents still marked active.
    pub async fn list_active(&self) -> Result<Vec<AgentRecord>, TeamserverError> {
        let rows = sqlx::query_as::<_, AgentRow>(
            "SELECT * FROM ts_agents WHERE active = 1 ORDER BY agent_id",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// Check whether an agent row exists.
    pub async fn exists(&self, agent_id: u32) -> Result<bool, TeamserverError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ts_agents WHERE agent_id = ?")
            .bind(i64::from(agent_id))
            .fetch_one(&self.pool)
            .await?;

        Ok(count > 0)
    }

    /// Update the active flag and reason for an agent.
    pub async fn set_status(
        &self,
        agent_id: u32,
        active: bool,
        reason: &str,
    ) -> Result<(), TeamserverError> {
        sqlx::query("UPDATE ts_agents SET active = ?, reason = ? WHERE agent_id = ?")
            .bind(bool_to_i64(active))
            .bind(reason)
            .bind(i64::from(agent_id))
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Delete an agent row.
    pub async fn delete(&self, agent_id: u32) -> Result<(), TeamserverError> {
        sqlx::query("DELETE FROM ts_agents WHERE agent_id = ?")
            .bind(i64::from(agent_id))
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Update the operator-authored note for an agent.
    pub async fn set_note(&self, agent_id: u32, note: &str) -> Result<(), TeamserverError> {
        let result = sqlx::query("UPDATE ts_agents SET note = ? WHERE agent_id = ?")
            .bind(note)
            .bind(i64::from(agent_id))
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(TeamserverError::AgentNotFound { agent_id });
        }

        Ok(())
    }

    /// Fetch a single persisted agent plus its CTR state.
    pub async fn get_persisted(
        &self,
        agent_id: u32,
    ) -> Result<Option<PersistedAgent>, TeamserverError> {
        let row = sqlx::query_as::<_, AgentRow>("SELECT * FROM ts_agents WHERE agent_id = ?")
            .bind(i64::from(agent_id))
            .fetch_optional(&self.pool)
            .await?;

        row.map(TryInto::try_into).transpose()
    }

    /// Return all persisted agents plus their CTR state.
    pub async fn list_persisted(&self) -> Result<Vec<PersistedAgent>, TeamserverError> {
        let rows = sqlx::query_as::<_, AgentRow>("SELECT * FROM ts_agents ORDER BY agent_id")
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// Persist the current CTR block offset for an agent.
    pub async fn set_ctr_block_offset(
        &self,
        agent_id: u32,
        ctr_block_offset: u64,
    ) -> Result<(), TeamserverError> {
        update_agent_ctr_block_offset(&self.pool, agent_id, ctr_block_offset).await
    }

    /// Persist the legacy CTR mode flag for an agent.
    pub async fn set_legacy_ctr(
        &self,
        agent_id: u32,
        legacy_ctr: bool,
    ) -> Result<(), TeamserverError> {
        let result = sqlx::query("UPDATE ts_agents SET legacy_ctr = ? WHERE agent_id = ?")
            .bind(bool_to_i64(legacy_ctr))
            .bind(i64::from(agent_id))
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(TeamserverError::AgentNotFound { agent_id });
        }
        Ok(())
    }
}

async fn insert_agent_row(
    executor: impl sqlx::Executor<'_, Database = Sqlite>,
    agent: &AgentRecord,
    listener_name: &str,
    ctr_block_offset: u64,
    legacy_ctr: bool,
) -> Result<(), TeamserverError> {
    sqlx::query(
        r#"
        INSERT INTO ts_agents (
            agent_id, active, reason, note, ctr_block_offset, legacy_ctr, aes_key, aes_iv, hostname, username, domain_name,
            external_ip, internal_ip, process_name, process_path, base_address, process_pid, process_tid,
            process_ppid, process_arch, elevated, os_version, os_build, os_arch, listener_name, sleep_delay,
            sleep_jitter, kill_date, working_hours, first_call_in, last_call_in
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(i64::from(agent.agent_id))
    .bind(bool_to_i64(agent.active))
    .bind(&agent.reason)
    .bind(&agent.note)
    .bind(i64_from_u64("ctr_block_offset", ctr_block_offset)?)
    .bind(bool_to_i64(legacy_ctr))
    .bind(BASE64_STANDARD.encode(&*agent.encryption.aes_key))
    .bind(BASE64_STANDARD.encode(&*agent.encryption.aes_iv))
    .bind(&agent.hostname)
    .bind(&agent.username)
    .bind(&agent.domain_name)
    .bind(&agent.external_ip)
    .bind(&agent.internal_ip)
    .bind(&agent.process_name)
    .bind(&agent.process_path)
    .bind(i64_from_u64("base_address", agent.base_address)?)
    .bind(i64::from(agent.process_pid))
    .bind(i64::from(agent.process_tid))
    .bind(i64::from(agent.process_ppid))
    .bind(&agent.process_arch)
    .bind(bool_to_i64(agent.elevated))
    .bind(&agent.os_version)
    .bind(i64::from(agent.os_build))
    .bind(&agent.os_arch)
    .bind(listener_name)
    .bind(i64::from(agent.sleep_delay))
    .bind(i64::from(agent.sleep_jitter))
    .bind(agent.kill_date)
    .bind(agent.working_hours.map(i64::from))
    .bind(&agent.first_call_in)
    .bind(&agent.last_call_in)
    .execute(executor)
    .await?;

    Ok(())
}

async fn update_agent_ctr_block_offset(
    executor: impl sqlx::Executor<'_, Database = Sqlite>,
    agent_id: u32,
    ctr_block_offset: u64,
) -> Result<(), TeamserverError> {
    let result = sqlx::query("UPDATE ts_agents SET ctr_block_offset = ? WHERE agent_id = ?")
        .bind(i64_from_u64("ctr_block_offset", ctr_block_offset)?)
        .bind(i64::from(agent_id))
        .execute(executor)
        .await?;

    if result.rows_affected() == 0 {
        return Err(TeamserverError::AgentNotFound { agent_id });
    }

    Ok(())
}

/// Persisted listener record stored in SQLite.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PersistedListener {
    /// Unique listener name.
    pub name: String,
    /// Transport protocol family.
    pub protocol: ListenerProtocol,
    /// Full listener configuration.
    pub config: ListenerConfig,
    /// Persisted runtime state.
    pub state: PersistedListenerState,
}

/// Persisted listener runtime state stored in SQLite.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PersistedListenerState {
    /// Lifecycle status.
    pub status: ListenerStatus,
    /// Most recent start failure, if any.
    pub last_error: Option<String>,
}

/// Listener lifecycle status persisted in SQLite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum ListenerStatus {
    /// Listener is configured but has never been started in this database.
    Created,
    /// Listener runtime is active.
    Running,
    /// Listener runtime is currently stopped.
    Stopped,
    /// Listener failed to start or crashed unexpectedly.
    Error,
}

impl ListenerStatus {
    /// Return the canonical storage label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Error => "error",
        }
    }

    fn try_from_str(value: &str) -> Result<Self, TeamserverError> {
        match value {
            "created" => Ok(Self::Created),
            "running" => Ok(Self::Running),
            "stopped" => Ok(Self::Stopped),
            "error" => Ok(Self::Error),
            _ => Err(TeamserverError::InvalidListenerState { state: value.to_owned() }),
        }
    }
}

/// CRUD operations for persisted listeners.
#[derive(Clone, Debug)]
pub struct ListenerRepository {
    pool: SqlitePool,
}

/// Persisted runtime operator credential record stored in SQLite.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedOperator {
    /// Operator username.
    pub username: String,
    /// Stored password verifier for the operator's Havoc-compatible SHA3 password digest.
    pub password_verifier: String,
    /// RBAC role granted to the operator.
    pub role: OperatorRole,
}

/// CRUD operations for persisted runtime operators.
#[derive(Clone, Debug)]
pub struct OperatorRepository {
    pool: SqlitePool,
}

impl OperatorRepository {
    /// Create a new operator repository from a shared pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Insert a runtime operator credential row.
    pub async fn create(&self, operator: &PersistedOperator) -> Result<(), TeamserverError> {
        sqlx::query(
            "INSERT INTO ts_runtime_operators (username, password_verifier, role) VALUES (?, ?, ?)",
        )
        .bind(&operator.username)
        .bind(&operator.password_verifier)
        .bind(operator_role_label(operator.role))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Fetch a runtime operator by username.
    pub async fn get(&self, username: &str) -> Result<Option<PersistedOperator>, TeamserverError> {
        let row = sqlx::query_as::<_, OperatorRow>(
            "SELECT username, password_verifier, role FROM ts_runtime_operators WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    /// Return all persisted runtime operators sorted by username.
    pub async fn list(&self) -> Result<Vec<PersistedOperator>, TeamserverError> {
        let rows = sqlx::query_as::<_, OperatorRow>(
            "SELECT username, password_verifier, role FROM ts_runtime_operators ORDER BY username",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// Replace the stored verifier for a runtime operator.
    pub async fn update_password_verifier(
        &self,
        username: &str,
        password_verifier: &str,
    ) -> Result<(), TeamserverError> {
        sqlx::query("UPDATE ts_runtime_operators SET password_verifier = ? WHERE username = ?")
            .bind(password_verifier)
            .bind(username)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Delete a runtime operator by username.
    ///
    /// Returns `true` if a row was deleted, `false` if no matching row existed.
    pub async fn delete(&self, username: &str) -> Result<bool, TeamserverError> {
        let result = sqlx::query("DELETE FROM ts_runtime_operators WHERE username = ?")
            .bind(username)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Update the role of a runtime operator.
    ///
    /// Returns `true` if a row was updated, `false` if no matching row existed.
    pub async fn update_role(
        &self,
        username: &str,
        role: OperatorRole,
    ) -> Result<bool, TeamserverError> {
        let result = sqlx::query("UPDATE ts_runtime_operators SET role = ? WHERE username = ?")
            .bind(operator_role_label(role))
            .bind(username)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }
}

impl ListenerRepository {
    /// Create a new listener repository from a shared pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Insert a listener configuration.
    pub async fn create(&self, listener: &ListenerConfig) -> Result<(), TeamserverError> {
        let config = serde_json::to_string(listener)?;
        sqlx::query(
            "INSERT INTO ts_listeners (name, protocol, config, status, last_error) VALUES (?, ?, ?, ?, ?)",
        )
            .bind(listener.name())
            .bind(listener.protocol().as_str())
            .bind(config)
            .bind(ListenerStatus::Created.as_str())
            .bind(Option::<String>::None)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Replace the stored configuration for a listener name.
    pub async fn update(&self, listener: &ListenerConfig) -> Result<(), TeamserverError> {
        let config = serde_json::to_string(listener)?;
        sqlx::query("UPDATE ts_listeners SET protocol = ?, config = ? WHERE name = ?")
            .bind(listener.protocol().as_str())
            .bind(config)
            .bind(listener.name())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Fetch a listener by name.
    pub async fn get(&self, name: &str) -> Result<Option<PersistedListener>, TeamserverError> {
        let row = sqlx::query_as::<_, ListenerRow>(
            "SELECT name, protocol, config, status, last_error FROM ts_listeners WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    /// List all listeners.
    pub async fn list(&self) -> Result<Vec<PersistedListener>, TeamserverError> {
        let rows = sqlx::query_as::<_, ListenerRow>(
            "SELECT name, protocol, config, status, last_error FROM ts_listeners ORDER BY name",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// Return all listener names.
    pub async fn names(&self) -> Result<Vec<String>, TeamserverError> {
        sqlx::query_scalar("SELECT name FROM ts_listeners ORDER BY name")
            .fetch_all(&self.pool)
            .await
            .map_err(Into::into)
    }

    /// Return the total number of listeners.
    pub async fn count(&self) -> Result<i64, TeamserverError> {
        sqlx::query_scalar("SELECT COUNT(*) FROM ts_listeners")
            .fetch_one(&self.pool)
            .await
            .map_err(Into::into)
    }

    /// Check whether a listener row exists.
    pub async fn exists(&self, name: &str) -> Result<bool, TeamserverError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ts_listeners WHERE name = ?")
            .bind(name)
            .fetch_one(&self.pool)
            .await?;

        Ok(count > 0)
    }

    /// Delete a listener row.
    pub async fn delete(&self, name: &str) -> Result<(), TeamserverError> {
        sqlx::query("DELETE FROM ts_listeners WHERE name = ?")
            .bind(name)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Update only the runtime state fields for a listener.
    pub async fn set_state(
        &self,
        name: &str,
        status: ListenerStatus,
        last_error: Option<&str>,
    ) -> Result<(), TeamserverError> {
        sqlx::query("UPDATE ts_listeners SET status = ?, last_error = ? WHERE name = ?")
            .bind(status.as_str())
            .bind(last_error)
            .bind(name)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

/// Parent/child pivot relationship between agents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkRecord {
    /// Upstream agent identifier.
    pub parent_agent_id: u32,
    /// Downstream linked agent identifier.
    pub link_agent_id: u32,
}

/// CRUD operations for persisted pivot links.
#[derive(Clone, Debug)]
pub struct LinkRepository {
    pool: SqlitePool,
}

impl LinkRepository {
    /// Create a new link repository from a shared pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Insert a parent/link relationship.
    pub async fn create(&self, link: LinkRecord) -> Result<(), TeamserverError> {
        sqlx::query("INSERT INTO ts_links (parent_agent_id, link_agent_id) VALUES (?, ?)")
            .bind(i64::from(link.parent_agent_id))
            .bind(i64::from(link.link_agent_id))
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Check whether a parent/link relationship exists.
    pub async fn exists(
        &self,
        parent_agent_id: u32,
        link_agent_id: u32,
    ) -> Result<bool, TeamserverError> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM ts_links WHERE parent_agent_id = ? AND link_agent_id = ?",
        )
        .bind(i64::from(parent_agent_id))
        .bind(i64::from(link_agent_id))
        .fetch_one(&self.pool)
        .await?;

        Ok(count > 0)
    }

    /// Return the parent agent for a linked child.
    pub async fn parent_of(&self, link_agent_id: u32) -> Result<Option<u32>, TeamserverError> {
        let parent = sqlx::query_scalar::<_, i64>(
            "SELECT parent_agent_id FROM ts_links WHERE link_agent_id = ?",
        )
        .bind(i64::from(link_agent_id))
        .fetch_optional(&self.pool)
        .await?;

        parent.map(|value| u32_from_i64("parent_agent_id", value)).transpose()
    }

    /// Return all directly linked child agents for a parent.
    pub async fn children_of(&self, parent_agent_id: u32) -> Result<Vec<u32>, TeamserverError> {
        let children = sqlx::query_scalar::<_, i64>(
            "SELECT link_agent_id FROM ts_links WHERE parent_agent_id = ? ORDER BY link_agent_id",
        )
        .bind(i64::from(parent_agent_id))
        .fetch_all(&self.pool)
        .await?;

        children.into_iter().map(|value| u32_from_i64("link_agent_id", value)).collect()
    }

    /// Return all stored pivot links.
    pub async fn list(&self) -> Result<Vec<LinkRecord>, TeamserverError> {
        let rows = sqlx::query("SELECT parent_agent_id, link_agent_id FROM ts_links ORDER BY parent_agent_id, link_agent_id")
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter()
            .map(|row| {
                Ok(LinkRecord {
                    parent_agent_id: u32_from_i64("parent_agent_id", row.get("parent_agent_id"))?,
                    link_agent_id: u32_from_i64("link_agent_id", row.get("link_agent_id"))?,
                })
            })
            .collect()
    }

    /// Delete a parent/link relationship.
    pub async fn delete(
        &self,
        parent_agent_id: u32,
        link_agent_id: u32,
    ) -> Result<(), TeamserverError> {
        sqlx::query("DELETE FROM ts_links WHERE parent_agent_id = ? AND link_agent_id = ?")
            .bind(i64::from(parent_agent_id))
            .bind(i64::from(link_agent_id))
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

/// Persisted loot entry captured from an agent.
#[derive(Clone, Debug, PartialEq)]
pub struct LootRecord {
    /// Database-assigned primary key.
    pub id: Option<i64>,
    /// Source agent identifier.
    pub agent_id: u32,
    /// Loot type label such as `download` or `screenshot`.
    pub kind: String,
    /// Display name for the captured item.
    pub name: String,
    /// Original file-system path when relevant.
    pub file_path: Option<String>,
    /// Captured size in bytes, when known.
    pub size_bytes: Option<i64>,
    /// Capture timestamp string.
    pub captured_at: String,
    /// Raw binary data, when stored inline.
    pub data: Option<Vec<u8>>,
    /// Optional structured metadata payload.
    pub metadata: Option<Value>,
}

/// CRUD operations for persisted loot.
#[derive(Clone, Debug)]
pub struct LootRepository {
    pool: SqlitePool,
}

/// Filter criteria for paginated loot queries pushed down to SQL.
///
/// All fields are optional. When `None`, the corresponding filter is not applied.
/// Substring filters use SQLite `instr()` for literal matching (no wildcard
/// interpretation). JSON-embedded fields are extracted with `json_extract()`.
#[derive(Clone, Debug, Default)]
pub struct LootFilter {
    /// Exact match against the `kind` column.
    pub kind_exact: Option<String>,
    /// Substring match against the `kind` column.
    pub kind_contains: Option<String>,
    /// Exact match against the `agent_id` column.
    pub agent_id: Option<u32>,
    /// Substring match against the `name` column.
    pub name_contains: Option<String>,
    /// Substring match against the `file_path` column.
    pub file_path_contains: Option<String>,
    /// Substring match against `json_extract(metadata, '$.operator')`.
    pub operator_contains: Option<String>,
    /// Substring match against `json_extract(metadata, '$.command_line')`.
    pub command_contains: Option<String>,
    /// Substring match against `json_extract(metadata, '$.pattern')`.
    pub pattern_contains: Option<String>,
    /// Inclusive lower bound on `captured_at` (UTC RFC 3339 string).
    pub since: Option<String>,
    /// Inclusive upper bound on `captured_at` (UTC RFC 3339 string).
    pub until: Option<String>,
}

impl LootRepository {
    /// Create a new loot repository from a shared pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Insert a loot record and return its generated primary key.
    pub async fn create(&self, loot: &LootRecord) -> Result<i64, TeamserverError> {
        let metadata = loot.metadata.as_ref().map(serde_json::to_string).transpose()?;
        let result = sqlx::query(
            r#"
            INSERT INTO ts_loot (
                agent_id, kind, name, file_path, size_bytes, captured_at, data, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(i64::from(loot.agent_id))
        .bind(&loot.kind)
        .bind(&loot.name)
        .bind(&loot.file_path)
        .bind(loot.size_bytes)
        .bind(&loot.captured_at)
        .bind(&loot.data)
        .bind(metadata)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    /// Fetch a single loot record by id.
    pub async fn get(&self, id: i64) -> Result<Option<LootRecord>, TeamserverError> {
        let row = sqlx::query_as::<_, LootRow>("SELECT * FROM ts_loot WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        row.map(TryInto::try_into).transpose()
    }

    /// List all loot records for an agent.
    pub async fn list_for_agent(&self, agent_id: u32) -> Result<Vec<LootRecord>, TeamserverError> {
        let rows =
            sqlx::query_as::<_, LootRow>("SELECT * FROM ts_loot WHERE agent_id = ? ORDER BY id")
                .bind(i64::from(agent_id))
                .fetch_all(&self.pool)
                .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// Return every loot record.
    pub async fn list(&self) -> Result<Vec<LootRecord>, TeamserverError> {
        let rows = sqlx::query_as::<_, LootRow>("SELECT * FROM ts_loot ORDER BY id")
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// Query loot rows ordered newest-first with SQL-level pagination.
    pub async fn query_filtered(
        &self,
        filter: &LootFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<LootRecord>, TeamserverError> {
        let mut builder = QueryBuilder::new(
            "SELECT id, agent_id, kind, name, file_path, size_bytes, captured_at, data, metadata \
             FROM ts_loot WHERE 1=1",
        );
        append_loot_filters(&mut builder, filter);
        builder.push(" ORDER BY id DESC LIMIT ").push_bind(limit);
        builder.push(" OFFSET ").push_bind(offset);

        let rows = builder.build_query_as::<LootRow>().fetch_all(&self.pool).await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// Count loot rows matching the given filters without fetching row data.
    pub async fn count_filtered(&self, filter: &LootFilter) -> Result<i64, TeamserverError> {
        let mut builder = QueryBuilder::new("SELECT COUNT(*) FROM ts_loot WHERE 1=1");
        append_loot_filters(&mut builder, filter);

        let row = builder.build().fetch_one(&self.pool).await?;
        Ok(row.get::<i64, _>(0))
    }

    /// Delete a loot record by id.
    pub async fn delete(&self, id: i64) -> Result<(), TeamserverError> {
        sqlx::query("DELETE FROM ts_loot WHERE id = ?").bind(id).execute(&self.pool).await?;

        Ok(())
    }
}

/// Persisted agent response entry captured from a callback.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentResponseRecord {
    /// Database-assigned primary key.
    pub id: Option<i64>,
    /// Source agent identifier.
    pub agent_id: u32,
    /// Callback command identifier.
    pub command_id: u32,
    /// Original teamserver request identifier.
    pub request_id: u32,
    /// Response severity/type label.
    pub response_type: String,
    /// Human-readable status text.
    pub message: String,
    /// Raw output string emitted by the agent.
    pub output: String,
    /// Operator command line associated with the request, when known.
    pub command_line: Option<String>,
    /// Stable task identifier associated with the request, when known.
    pub task_id: Option<String>,
    /// Operator username associated with the request, when known.
    pub operator: Option<String>,
    /// Response timestamp string.
    pub received_at: String,
    /// Optional structured metadata payload.
    pub extra: Option<Value>,
}

/// CRUD operations for persisted agent-response rows.
#[derive(Clone, Debug)]
pub struct AgentResponseRepository {
    pool: SqlitePool,
}

impl AgentResponseRepository {
    /// Create a new agent-response repository from a shared pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Insert an agent-response row and return its generated primary key.
    pub async fn create(&self, response: &AgentResponseRecord) -> Result<i64, TeamserverError> {
        let extra = response.extra.as_ref().map(serde_json::to_string).transpose()?;
        let result = sqlx::query(
            r#"
            INSERT INTO ts_agent_responses (
                agent_id, command_id, request_id, response_type, message, output,
                command_line, task_id, operator, received_at, extra
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(i64::from(response.agent_id))
        .bind(i64::from(response.command_id))
        .bind(i64::from(response.request_id))
        .bind(&response.response_type)
        .bind(&response.message)
        .bind(&response.output)
        .bind(&response.command_line)
        .bind(&response.task_id)
        .bind(&response.operator)
        .bind(&response.received_at)
        .bind(extra)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    /// Fetch a single agent-response row by id.
    pub async fn get(&self, id: i64) -> Result<Option<AgentResponseRecord>, TeamserverError> {
        let row =
            sqlx::query_as::<_, AgentResponseRow>("SELECT * FROM ts_agent_responses WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;

        row.map(TryInto::try_into).transpose()
    }

    /// List all persisted responses for an agent.
    pub async fn list_for_agent(
        &self,
        agent_id: u32,
    ) -> Result<Vec<AgentResponseRecord>, TeamserverError> {
        let rows = sqlx::query_as::<_, AgentResponseRow>(
            "SELECT * FROM ts_agent_responses WHERE agent_id = ? ORDER BY id",
        )
        .bind(i64::from(agent_id))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// List persisted responses for an agent with cursor-based pagination.
    ///
    /// When `since_id` is `Some(id)`, only rows with `id > since_id` are
    /// returned, enabling efficient polling for new output.
    pub async fn list_for_agent_since(
        &self,
        agent_id: u32,
        since_id: Option<i64>,
    ) -> Result<Vec<AgentResponseRecord>, TeamserverError> {
        let min_id = since_id.unwrap_or(0);
        let rows = sqlx::query_as::<_, AgentResponseRow>(
            "SELECT * FROM ts_agent_responses WHERE agent_id = ? AND id > ? ORDER BY id",
        )
        .bind(i64::from(agent_id))
        .bind(min_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// Return every persisted response in insertion order.
    pub async fn list(&self) -> Result<Vec<AgentResponseRecord>, TeamserverError> {
        let rows =
            sqlx::query_as::<_, AgentResponseRow>("SELECT * FROM ts_agent_responses ORDER BY id")
                .fetch_all(&self.pool)
                .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// Delete an agent-response row by id.
    pub async fn delete(&self, id: i64) -> Result<(), TeamserverError> {
        sqlx::query("DELETE FROM ts_agent_responses WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

/// Structured audit-log row persisted by the teamserver.
#[derive(Clone, Debug, PartialEq)]
pub struct AuditLogEntry {
    /// Database-assigned primary key.
    pub id: Option<i64>,
    /// Principal responsible for the action.
    pub actor: String,
    /// Action label.
    pub action: String,
    /// Entity category acted upon.
    pub target_kind: String,
    /// Optional entity identifier.
    pub target_id: Option<String>,
    /// Optional structured details payload.
    pub details: Option<Value>,
    /// Event timestamp string.
    pub occurred_at: String,
}

/// CRUD operations for persisted audit-log rows.
#[derive(Clone, Debug)]
pub struct AuditLogRepository {
    pool: SqlitePool,
}

impl AuditLogRepository {
    /// Create a new audit-log repository from a shared pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Insert an audit-log row and return its generated primary key.
    pub async fn create(&self, entry: &AuditLogEntry) -> Result<i64, TeamserverError> {
        let details = entry.details.as_ref().map(serde_json::to_string).transpose()?;
        let result = sqlx::query(
            r#"
            INSERT INTO ts_audit_log (
                actor, action, target_kind, target_id, details, occurred_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&entry.actor)
        .bind(&entry.action)
        .bind(&entry.target_kind)
        .bind(&entry.target_id)
        .bind(details)
        .bind(&entry.occurred_at)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    /// Fetch a single audit-log row by id.
    pub async fn get(&self, id: i64) -> Result<Option<AuditLogEntry>, TeamserverError> {
        let row = sqlx::query_as::<_, AuditLogRow>("SELECT * FROM ts_audit_log WHERE id = ?")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        row.map(TryInto::try_into).transpose()
    }

    /// Return all audit-log rows in insertion order.
    pub async fn list(&self) -> Result<Vec<AuditLogEntry>, TeamserverError> {
        let rows = sqlx::query_as::<_, AuditLogRow>("SELECT * FROM ts_audit_log ORDER BY id")
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// Delete an audit-log row by id.
    pub async fn delete(&self, id: i64) -> Result<(), TeamserverError> {
        sqlx::query("DELETE FROM ts_audit_log WHERE id = ?").bind(id).execute(&self.pool).await?;

        Ok(())
    }

    /// Return filtered audit-log rows ordered newest-first with SQL-level pagination.
    pub async fn query_filtered(
        &self,
        filter: &AuditLogFilter,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditLogEntry>, TeamserverError> {
        let mut builder = QueryBuilder::new(
            "SELECT id, actor, action, target_kind, target_id, details, occurred_at \
             FROM ts_audit_log WHERE 1=1",
        );
        append_audit_filters(&mut builder, filter);
        builder.push(" ORDER BY id DESC LIMIT ").push_bind(limit);
        builder.push(" OFFSET ").push_bind(offset);

        let rows = builder.build_query_as::<AuditLogRow>().fetch_all(&self.pool).await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// Count audit-log rows matching the given filters without fetching row data.
    pub async fn count_filtered(&self, filter: &AuditLogFilter) -> Result<i64, TeamserverError> {
        let mut builder = QueryBuilder::new("SELECT COUNT(*) FROM ts_audit_log WHERE 1=1");
        append_audit_filters(&mut builder, filter);

        let row = builder.build().fetch_one(&self.pool).await?;
        Ok(row.get::<i64, _>(0))
    }

    /// Return the latest timestamp for each actor across the supplied actions.
    pub async fn latest_timestamps_by_actor_for_actions(
        &self,
        actions: &[&str],
    ) -> Result<BTreeMap<String, String>, TeamserverError> {
        if actions.is_empty() {
            return Ok(BTreeMap::new());
        }

        let mut builder = QueryBuilder::new(
            "SELECT actor, MAX(occurred_at) AS occurred_at FROM ts_audit_log WHERE action IN (",
        );
        let mut separated = builder.separated(", ");
        for action in actions {
            separated.push_bind(*action);
        }
        separated.push_unseparated(") GROUP BY actor");

        let rows = builder.build().fetch_all(&self.pool).await?;
        let mut latest = BTreeMap::new();
        for row in rows {
            latest.insert(row.get::<String, _>("actor"), row.get::<String, _>("occurred_at"));
        }

        Ok(latest)
    }
}

/// Filter criteria for paginated audit-log queries pushed down to SQL.
///
/// All fields are optional. When `None`, the corresponding filter is not applied.
/// Substring filters use SQLite `instr()` for literal matching (no wildcard
/// interpretation). JSON-embedded fields are extracted with `json_extract()`.
#[derive(Clone, Debug, Default)]
pub struct AuditLogFilter {
    /// Substring match against the `actor` column.
    pub actor_contains: Option<String>,
    /// Substring match against the `action` column.
    pub action_contains: Option<String>,
    /// Substring match against the `target_kind` column.
    pub target_kind_contains: Option<String>,
    /// Substring match against the `target_id` column.
    pub target_id_contains: Option<String>,
    /// Exact match against `json_extract(details, '$.agent_id')`.
    pub agent_id: Option<String>,
    /// Substring match against `json_extract(details, '$.command')`.
    pub command_contains: Option<String>,
    /// Exact match against `json_extract(details, '$.result_status')`.
    pub result_status: Option<String>,
    /// Inclusive lower bound on `occurred_at` (UTC RFC 3339 string).
    pub since: Option<String>,
    /// Inclusive upper bound on `occurred_at` (UTC RFC 3339 string).
    pub until: Option<String>,
    /// Exact action labels allowed by the query.
    pub action_in: Option<Vec<String>>,
}

fn append_loot_filters(builder: &mut QueryBuilder<'_, Sqlite>, filter: &LootFilter) {
    if let Some(ref value) = filter.kind_exact {
        builder.push(" AND kind = ").push_bind(value.clone());
    }
    if let Some(ref value) = filter.kind_contains {
        builder.push(" AND instr(kind, ").push_bind(value.clone()).push(") > 0");
    }
    if let Some(value) = filter.agent_id {
        builder.push(" AND agent_id = ").push_bind(i64::from(value));
    }
    if let Some(ref value) = filter.name_contains {
        builder.push(" AND instr(name, ").push_bind(value.clone()).push(") > 0");
    }
    if let Some(ref value) = filter.file_path_contains {
        builder.push(" AND instr(file_path, ").push_bind(value.clone()).push(") > 0");
    }
    if let Some(ref value) = filter.operator_contains {
        builder
            .push(" AND instr(json_extract(metadata, '$.operator'), ")
            .push_bind(value.clone())
            .push(") > 0");
    }
    if let Some(ref value) = filter.command_contains {
        builder
            .push(" AND instr(json_extract(metadata, '$.command_line'), ")
            .push_bind(value.clone())
            .push(") > 0");
    }
    if let Some(ref value) = filter.pattern_contains {
        builder
            .push(" AND instr(json_extract(metadata, '$.pattern'), ")
            .push_bind(value.clone())
            .push(") > 0");
    }
    if let Some(ref value) = filter.since {
        builder.push(" AND captured_at >= ").push_bind(value.clone());
    }
    if let Some(ref value) = filter.until {
        builder.push(" AND captured_at <= ").push_bind(value.clone());
    }
}

fn append_audit_filters(builder: &mut QueryBuilder<'_, Sqlite>, filter: &AuditLogFilter) {
    if let Some(ref value) = filter.actor_contains {
        builder.push(" AND instr(actor, ").push_bind(value.clone()).push(") > 0");
    }
    if let Some(ref value) = filter.action_contains {
        builder.push(" AND instr(action, ").push_bind(value.clone()).push(") > 0");
    }
    if let Some(ref value) = filter.target_kind_contains {
        builder.push(" AND instr(target_kind, ").push_bind(value.clone()).push(") > 0");
    }
    if let Some(ref value) = filter.target_id_contains {
        builder.push(" AND instr(target_id, ").push_bind(value.clone()).push(") > 0");
    }
    if let Some(ref value) = filter.agent_id {
        builder.push(" AND json_extract(details, '$.agent_id') = ").push_bind(value.clone());
    }
    if let Some(ref value) = filter.command_contains {
        builder
            .push(" AND instr(json_extract(details, '$.command'), ")
            .push_bind(value.clone())
            .push(") > 0");
    }
    if let Some(ref value) = filter.result_status {
        builder.push(" AND json_extract(details, '$.result_status') = ").push_bind(value.clone());
    }
    if let Some(ref value) = filter.since {
        builder.push(" AND occurred_at >= ").push_bind(value.clone());
    }
    if let Some(ref value) = filter.until {
        builder.push(" AND occurred_at <= ").push_bind(value.clone());
    }
    if let Some(ref actions) = filter.action_in {
        if !actions.is_empty() {
            builder.push(" AND action IN (");
            let mut separated = builder.separated(", ");
            for action in actions {
                separated.push_bind(action.clone());
            }
            separated.push_unseparated(")");
        }
    }
}

#[derive(Debug, FromRow)]
struct AgentRow {
    agent_id: i64,
    active: i64,
    reason: String,
    note: String,
    ctr_block_offset: i64,
    aes_key: String,
    aes_iv: String,
    hostname: String,
    username: String,
    domain_name: String,
    external_ip: String,
    internal_ip: String,
    process_name: String,
    process_path: String,
    base_address: i64,
    process_pid: i64,
    process_tid: i64,
    process_ppid: i64,
    process_arch: String,
    elevated: i64,
    os_version: String,
    os_build: i64,
    os_arch: String,
    listener_name: String,
    sleep_delay: i64,
    sleep_jitter: i64,
    kill_date: Option<i64>,
    working_hours: Option<i64>,
    first_call_in: String,
    last_call_in: String,
    legacy_ctr: i64,
}

impl TryFrom<AgentRow> for AgentRecord {
    type Error = TeamserverError;

    fn try_from(row: AgentRow) -> Result<Self, Self::Error> {
        Ok(Self {
            agent_id: u32_from_i64("agent_id", row.agent_id)?,
            active: bool_from_i64("active", row.active)?,
            reason: row.reason,
            note: row.note,
            encryption: red_cell_common::AgentEncryptionInfo {
                aes_key: Zeroizing::new(BASE64_STANDARD.decode(&row.aes_key).map_err(|e| {
                    TeamserverError::InvalidPersistedValue {
                        field: "aes_key",
                        message: format!("base64 decode failed: {e}"),
                    }
                })?),
                aes_iv: Zeroizing::new(BASE64_STANDARD.decode(&row.aes_iv).map_err(|e| {
                    TeamserverError::InvalidPersistedValue {
                        field: "aes_iv",
                        message: format!("base64 decode failed: {e}"),
                    }
                })?),
            },
            hostname: row.hostname,
            username: row.username,
            domain_name: row.domain_name,
            external_ip: row.external_ip,
            internal_ip: row.internal_ip,
            process_name: row.process_name,
            process_path: row.process_path,
            base_address: u64_from_i64("base_address", row.base_address)?,
            process_pid: u32_from_i64("process_pid", row.process_pid)?,
            process_tid: u32_from_i64("process_tid", row.process_tid)?,
            process_ppid: u32_from_i64("process_ppid", row.process_ppid)?,
            process_arch: row.process_arch,
            elevated: bool_from_i64("elevated", row.elevated)?,
            os_version: row.os_version,
            os_build: u32_from_i64("os_build", row.os_build)?,
            os_arch: row.os_arch,
            sleep_delay: u32_from_i64("sleep_delay", row.sleep_delay)?,
            sleep_jitter: u32_from_i64("sleep_jitter", row.sleep_jitter)?,
            kill_date: row.kill_date,
            working_hours: row
                .working_hours
                .map(i32::try_from)
                .transpose()
                .map_err(|_| invalid_value("working_hours", "value does not fit in i32"))?,
            first_call_in: row.first_call_in,
            last_call_in: row.last_call_in,
        })
    }
}

impl TryFrom<AgentRow> for PersistedAgent {
    type Error = TeamserverError;

    fn try_from(row: AgentRow) -> Result<Self, Self::Error> {
        let ctr_block_offset = u64_from_i64("ctr_block_offset", row.ctr_block_offset)?;
        let legacy_ctr = bool_from_i64("legacy_ctr", row.legacy_ctr)?;
        let listener_name = row.listener_name.clone();
        let info = AgentRecord::try_from(row)?;
        Ok(Self { info, listener_name, ctr_block_offset, legacy_ctr })
    }
}

#[derive(Debug, FromRow)]
struct ListenerRow {
    name: String,
    protocol: String,
    config: String,
    status: String,
    last_error: Option<String>,
}

impl TryFrom<ListenerRow> for PersistedListener {
    type Error = TeamserverError;

    fn try_from(row: ListenerRow) -> Result<Self, Self::Error> {
        let protocol = ListenerProtocol::try_from_str(&row.protocol)
            .map_err(|error| invalid_value("protocol", &error.to_string()))?;
        let config: ListenerConfig = serde_json::from_str(&row.config)?;
        let status = ListenerStatus::try_from_str(&row.status)?;

        Ok(Self {
            name: row.name,
            protocol,
            config,
            state: PersistedListenerState { status, last_error: row.last_error },
        })
    }
}

#[derive(Debug, FromRow)]
struct OperatorRow {
    username: String,
    password_verifier: String,
    role: String,
}

impl TryFrom<OperatorRow> for PersistedOperator {
    type Error = TeamserverError;

    fn try_from(row: OperatorRow) -> Result<Self, Self::Error> {
        Ok(Self {
            username: row.username,
            password_verifier: row.password_verifier,
            role: parse_operator_role(&row.role)?,
        })
    }
}

const fn operator_role_label(role: OperatorRole) -> &'static str {
    match role {
        OperatorRole::Admin => "Admin",
        OperatorRole::Operator => "Operator",
        OperatorRole::Analyst => "Analyst",
    }
}

fn parse_operator_role(value: &str) -> Result<OperatorRole, TeamserverError> {
    match value {
        "Admin" | "admin" => Ok(OperatorRole::Admin),
        "Operator" | "operator" => Ok(OperatorRole::Operator),
        "Analyst" | "analyst" => Ok(OperatorRole::Analyst),
        _ => Err(TeamserverError::InvalidPersistedValue {
            field: "ts_runtime_operators.role",
            message: format!("unsupported operator role `{value}`"),
        }),
    }
}

#[derive(Debug, FromRow)]
struct LootRow {
    id: i64,
    agent_id: i64,
    kind: String,
    name: String,
    file_path: Option<String>,
    size_bytes: Option<i64>,
    captured_at: String,
    data: Option<Vec<u8>>,
    metadata: Option<String>,
}

impl TryFrom<LootRow> for LootRecord {
    type Error = TeamserverError;

    fn try_from(row: LootRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Some(row.id),
            agent_id: u32_from_i64("agent_id", row.agent_id)?,
            kind: row.kind,
            name: row.name,
            file_path: row.file_path,
            size_bytes: row.size_bytes,
            captured_at: row.captured_at,
            data: row.data,
            metadata: row.metadata.map(|value| serde_json::from_str(&value)).transpose()?,
        })
    }
}

#[derive(Debug, FromRow)]
struct AgentResponseRow {
    id: i64,
    agent_id: i64,
    command_id: i64,
    request_id: i64,
    response_type: String,
    message: String,
    output: String,
    command_line: Option<String>,
    task_id: Option<String>,
    operator: Option<String>,
    received_at: String,
    extra: Option<String>,
}

impl TryFrom<AgentResponseRow> for AgentResponseRecord {
    type Error = TeamserverError;

    fn try_from(row: AgentResponseRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Some(row.id),
            agent_id: u32_from_i64("agent_id", row.agent_id)?,
            command_id: u32_from_i64("command_id", row.command_id)?,
            request_id: u32_from_i64("request_id", row.request_id)?,
            response_type: row.response_type,
            message: row.message,
            output: row.output,
            command_line: row.command_line,
            task_id: row.task_id,
            operator: row.operator,
            received_at: row.received_at,
            extra: row.extra.map(|value| serde_json::from_str(&value)).transpose()?,
        })
    }
}

#[derive(Debug, FromRow)]
struct AuditLogRow {
    id: i64,
    actor: String,
    action: String,
    target_kind: String,
    target_id: Option<String>,
    details: Option<String>,
    occurred_at: String,
}

impl TryFrom<AuditLogRow> for AuditLogEntry {
    type Error = TeamserverError;

    fn try_from(row: AuditLogRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Some(row.id),
            actor: row.actor,
            action: row.action,
            target_kind: row.target_kind,
            target_id: row.target_id,
            details: row.details.map(|value| serde_json::from_str(&value)).transpose()?,
            occurred_at: row.occurred_at,
        })
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

// ── Payload Build Repository ─────────────────────────────────────────────────

/// Persisted payload build job record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadBuildRecord {
    /// Unique build identifier (UUID).
    pub id: String,
    /// Current build status: `"pending"`, `"running"`, `"done"`, `"error"`.
    pub status: String,
    /// Display name for the finished payload.
    pub name: String,
    /// Target CPU architecture.
    pub arch: String,
    /// Requested output format.
    pub format: String,
    /// Listener name embedded in the payload.
    pub listener: String,
    /// Optional sleep interval in seconds.
    pub sleep_secs: Option<i64>,
    /// Compiled payload bytes (populated when status is `"done"`).
    pub artifact: Option<Vec<u8>>,
    /// Artifact size in bytes.
    pub size_bytes: Option<i64>,
    /// Error message (populated when status is `"error"`).
    pub error: Option<String>,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// RFC 3339 last-update timestamp.
    pub updated_at: String,
}

/// SQLite row shape for the `ts_payload_builds` table.
#[derive(Debug, FromRow)]
struct PayloadBuildRow {
    id: String,
    status: String,
    name: String,
    arch: String,
    format: String,
    listener: String,
    sleep_secs: Option<i64>,
    artifact: Option<Vec<u8>>,
    size_bytes: Option<i64>,
    error: Option<String>,
    created_at: String,
    updated_at: String,
}

impl From<PayloadBuildRow> for PayloadBuildRecord {
    fn from(row: PayloadBuildRow) -> Self {
        Self {
            id: row.id,
            status: row.status,
            name: row.name,
            arch: row.arch,
            format: row.format,
            listener: row.listener,
            sleep_secs: row.sleep_secs,
            artifact: row.artifact,
            size_bytes: row.size_bytes,
            error: row.error,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

/// Lightweight payload build metadata without the artifact blob.
///
/// Used by list/status endpoints to avoid loading compiled payload bytes into memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadBuildSummary {
    /// Unique build identifier (UUID).
    pub id: String,
    /// Current build status: `"pending"`, `"running"`, `"done"`, `"error"`.
    pub status: String,
    /// Display name for the finished payload.
    pub name: String,
    /// Target CPU architecture.
    pub arch: String,
    /// Requested output format.
    pub format: String,
    /// Listener name embedded in the payload.
    pub listener: String,
    /// Optional sleep interval in seconds.
    pub sleep_secs: Option<i64>,
    /// Artifact size in bytes.
    pub size_bytes: Option<i64>,
    /// Error message (populated when status is `"error"`).
    pub error: Option<String>,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// RFC 3339 last-update timestamp.
    pub updated_at: String,
}

/// SQLite row shape for summary projections (no artifact column).
#[derive(Debug, FromRow)]
struct PayloadBuildSummaryRow {
    id: String,
    status: String,
    name: String,
    arch: String,
    format: String,
    listener: String,
    sleep_secs: Option<i64>,
    size_bytes: Option<i64>,
    error: Option<String>,
    created_at: String,
    updated_at: String,
}

impl From<PayloadBuildSummaryRow> for PayloadBuildSummary {
    fn from(row: PayloadBuildSummaryRow) -> Self {
        Self {
            id: row.id,
            status: row.status,
            name: row.name,
            arch: row.arch,
            format: row.format,
            listener: row.listener,
            sleep_secs: row.sleep_secs,
            size_bytes: row.size_bytes,
            error: row.error,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

/// Repository for payload build job persistence.
#[derive(Clone, Debug)]
pub struct PayloadBuildRepository {
    pool: SqlitePool,
}

impl PayloadBuildRepository {
    /// Create a new payload build repository from a shared pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Insert a new payload build job record.
    pub async fn create(&self, record: &PayloadBuildRecord) -> Result<(), TeamserverError> {
        sqlx::query(
            r#"
            INSERT INTO ts_payload_builds (
                id, status, name, arch, format, listener, sleep_secs,
                artifact, size_bytes, error, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&record.id)
        .bind(&record.status)
        .bind(&record.name)
        .bind(&record.arch)
        .bind(&record.format)
        .bind(&record.listener)
        .bind(record.sleep_secs)
        .bind(&record.artifact)
        .bind(record.size_bytes)
        .bind(&record.error)
        .bind(&record.created_at)
        .bind(&record.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Fetch a single build record by id.
    pub async fn get(&self, id: &str) -> Result<Option<PayloadBuildRecord>, TeamserverError> {
        let row =
            sqlx::query_as::<_, PayloadBuildRow>("SELECT * FROM ts_payload_builds WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(Into::into))
    }

    /// List all build records, ordered by creation time descending.
    pub async fn list(&self) -> Result<Vec<PayloadBuildRecord>, TeamserverError> {
        let rows = sqlx::query_as::<_, PayloadBuildRow>(
            "SELECT * FROM ts_payload_builds ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Fetch metadata for a single build record by id, excluding the artifact blob.
    pub async fn get_summary(
        &self,
        id: &str,
    ) -> Result<Option<PayloadBuildSummary>, TeamserverError> {
        const QUERY: &str = "\
            SELECT id, status, name, arch, format, listener, sleep_secs, \
                   size_bytes, error, created_at, updated_at \
            FROM ts_payload_builds WHERE id = ?";
        let row = sqlx::query_as::<_, PayloadBuildSummaryRow>(QUERY)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(Into::into))
    }

    /// List all build records as summaries (no artifact), ordered by creation time descending.
    pub async fn list_summaries(&self) -> Result<Vec<PayloadBuildSummary>, TeamserverError> {
        const QUERY: &str = "\
            SELECT id, status, name, arch, format, listener, sleep_secs, \
                   size_bytes, error, created_at, updated_at \
            FROM ts_payload_builds ORDER BY created_at DESC";
        let rows = sqlx::query_as::<_, PayloadBuildSummaryRow>(QUERY).fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Update the status and optional artifact of a build record.
    pub async fn update_status(
        &self,
        id: &str,
        status: &str,
        name: Option<&str>,
        artifact: Option<&[u8]>,
        size_bytes: Option<i64>,
        error: Option<&str>,
        updated_at: &str,
    ) -> Result<bool, TeamserverError> {
        let result = sqlx::query(
            r#"
            UPDATE ts_payload_builds
            SET status = ?,
                name = COALESCE(?, name),
                artifact = COALESCE(?, artifact),
                size_bytes = COALESCE(?, size_bytes),
                error = COALESCE(?, error),
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(status)
        .bind(name)
        .bind(artifact)
        .bind(size_bytes)
        .bind(error)
        .bind(updated_at)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
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
        assert_eq!(i64_from_u64("field", 0).unwrap(), 0);
    }

    #[test]
    fn i64_from_u64_accepts_one() {
        assert_eq!(i64_from_u64("field", 1).unwrap(), 1);
    }

    #[test]
    fn i64_from_u64_accepts_i64_max() {
        let val = i64::MAX as u64;
        assert_eq!(i64_from_u64("field", val).unwrap(), i64::MAX);
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
            db.agents().create(&stub_agent(id)).await.unwrap();
        }
    }

    #[tokio::test]
    async fn loot_create_and_get_round_trips_all_fields() {
        let db = Database::connect_in_memory().await.unwrap();
        seed_agents(&db, &[100]).await;
        let repo = db.loot();
        let record = sample_loot(100, "hash", "NTLM hashes");

        let id = repo.create(&record).await.unwrap();
        let fetched = repo.get(id).await.unwrap().expect("record should exist");

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
        let db = Database::connect_in_memory().await.unwrap();
        let repo = db.loot();

        let fetched = repo.get(999).await.unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn loot_list_for_agent_returns_correct_grouping() {
        let db = Database::connect_in_memory().await.unwrap();
        seed_agents(&db, &[10, 20]).await;
        let repo = db.loot();

        repo.create(&sample_loot(10, "hash", "agent10-hash")).await.unwrap();
        repo.create(&sample_loot(10, "ticket", "agent10-ticket")).await.unwrap();
        repo.create(&sample_loot(20, "token", "agent20-token")).await.unwrap();

        let agent10 = repo.list_for_agent(10).await.unwrap();
        assert_eq!(agent10.len(), 2);
        assert!(agent10.iter().all(|r| r.agent_id == 10));

        let agent20 = repo.list_for_agent(20).await.unwrap();
        assert_eq!(agent20.len(), 1);
        assert_eq!(agent20[0].agent_id, 20);
        assert_eq!(agent20[0].name, "agent20-token");

        let agent99 = repo.list_for_agent(99).await.unwrap();
        assert!(agent99.is_empty());
    }

    #[tokio::test]
    async fn loot_list_returns_all_records() {
        let db = Database::connect_in_memory().await.unwrap();
        seed_agents(&db, &[1, 2, 3]).await;
        let repo = db.loot();

        repo.create(&sample_loot(1, "hash", "a")).await.unwrap();
        repo.create(&sample_loot(2, "ticket", "b")).await.unwrap();
        repo.create(&sample_loot(3, "token", "c")).await.unwrap();

        let all = repo.list().await.unwrap();
        assert_eq!(all.len(), 3);
    }

    #[tokio::test]
    async fn loot_empty_content_and_label_round_trips() {
        let db = Database::connect_in_memory().await.unwrap();
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

        let id = repo.create(&record).await.unwrap();
        let fetched = repo.get(id).await.unwrap().expect("record should exist");

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
        let db = Database::connect_in_memory().await.unwrap();
        seed_agents(&db, &[1]).await;
        let repo = db.loot();

        let id = repo.create(&sample_loot(1, "hash", "to-delete")).await.unwrap();
        assert!(repo.get(id).await.unwrap().is_some());

        repo.delete(id).await.unwrap();
        assert!(repo.get(id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn loot_query_filtered_by_kind_exact() {
        let db = Database::connect_in_memory().await.unwrap();
        seed_agents(&db, &[1, 2]).await;
        let repo = db.loot();

        repo.create(&sample_loot(1, "hash", "h1")).await.unwrap();
        repo.create(&sample_loot(1, "ticket", "t1")).await.unwrap();
        repo.create(&sample_loot(2, "hash", "h2")).await.unwrap();

        let filter = LootFilter { kind_exact: Some("hash".to_string()), ..Default::default() };
        let results = repo.query_filtered(&filter, 100, 0).await.unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.kind == "hash"));
    }

    #[tokio::test]
    async fn loot_query_filtered_by_agent_id() {
        let db = Database::connect_in_memory().await.unwrap();
        seed_agents(&db, &[10, 20]).await;
        let repo = db.loot();

        repo.create(&sample_loot(10, "hash", "a")).await.unwrap();
        repo.create(&sample_loot(20, "hash", "b")).await.unwrap();

        let filter = LootFilter { agent_id: Some(10), ..Default::default() };
        let results = repo.query_filtered(&filter, 100, 0).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].agent_id, 10);
    }

    #[tokio::test]
    async fn loot_count_filtered_matches_query_length() {
        let db = Database::connect_in_memory().await.unwrap();
        seed_agents(&db, &[1]).await;
        let repo = db.loot();

        repo.create(&sample_loot(1, "hash", "h1")).await.unwrap();
        repo.create(&sample_loot(1, "hash", "h2")).await.unwrap();
        repo.create(&sample_loot(1, "ticket", "t1")).await.unwrap();

        let filter = LootFilter { kind_exact: Some("hash".to_string()), ..Default::default() };
        let count = repo.count_filtered(&filter).await.unwrap();
        let results = repo.query_filtered(&filter, 100, 0).await.unwrap();
        assert_eq!(count, results.len() as i64);
    }

    #[tokio::test]
    async fn loot_query_filtered_pagination() {
        let db = Database::connect_in_memory().await.unwrap();
        seed_agents(&db, &[1]).await;
        let repo = db.loot();

        for i in 0..5 {
            repo.create(&sample_loot(1, "hash", &format!("item-{i}"))).await.unwrap();
        }

        let filter = LootFilter::default();
        let page1 = repo.query_filtered(&filter, 2, 0).await.unwrap();
        let page2 = repo.query_filtered(&filter, 2, 2).await.unwrap();
        let page3 = repo.query_filtered(&filter, 2, 4).await.unwrap();

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
        links.create(LinkRecord { parent_agent_id: a, link_agent_id: b }).await.unwrap();
        links.create(LinkRecord { parent_agent_id: b, link_agent_id: c }).await.unwrap();
    }

    #[tokio::test]
    async fn link_chain_children_of_returns_direct_children_only() {
        let db = Database::connect_in_memory().await.unwrap();
        seed_link_chain(&db, 1, 2, 3).await;
        let links = db.links();

        let children_of_a = links.children_of(1).await.unwrap();
        assert_eq!(children_of_a, vec![2], "A should have only direct child B");

        let children_of_b = links.children_of(2).await.unwrap();
        assert_eq!(children_of_b, vec![3], "B should have only direct child C");

        let children_of_c = links.children_of(3).await.unwrap();
        assert!(children_of_c.is_empty(), "C is a leaf and should have no children");
    }

    #[tokio::test]
    async fn link_delete_parent_removes_only_direct_link() {
        let db = Database::connect_in_memory().await.unwrap();
        seed_link_chain(&db, 1, 2, 3).await;
        let links = db.links();

        // Delete A→B link
        links.delete(1, 2).await.unwrap();

        assert!(!links.exists(1, 2).await.unwrap(), "A→B link should be gone");
        assert!(links.exists(2, 3).await.unwrap(), "B→C link should still exist");
        assert_eq!(links.parent_of(2).await.unwrap(), None, "B should have no parent");
        assert_eq!(links.parent_of(3).await.unwrap(), Some(2), "C still has parent B");
    }

    #[tokio::test]
    async fn link_cascade_simulation_marks_all_transitive_children() {
        let db = Database::connect_in_memory().await.unwrap();
        seed_link_chain(&db, 1, 2, 3).await;
        let links = db.links();

        // Simulate the cascade disconnect_link performs at the repo layer:
        // 1. Collect the subtree rooted at B by walking children_of recursively
        let mut affected = vec![2u32];
        let mut queue = vec![2u32];
        while let Some(node) = queue.pop() {
            let children = links.children_of(node).await.unwrap();
            for &child in &children {
                affected.push(child);
                queue.push(child);
            }
        }
        assert_eq!(affected, vec![2, 3], "subtree of B should include B and C");

        // 2. Delete the link A→B
        links.delete(1, 2).await.unwrap();

        // 3. Verify the remaining state
        let remaining = links.list().await.unwrap();
        assert_eq!(remaining.len(), 1, "only B→C should remain");
        assert_eq!(remaining[0].parent_agent_id, 2);
        assert_eq!(remaining[0].link_agent_id, 3);
    }

    #[tokio::test]
    async fn link_delete_nonexistent_returns_ok() {
        let db = Database::connect_in_memory().await.unwrap();
        seed_agents(&db, &[10, 20]).await;
        let links = db.links();

        // Deleting a link that was never created should succeed silently
        let result = links.delete(10, 20).await;
        assert!(result.is_ok(), "deleting non-existent link should not error");
    }

    #[tokio::test]
    async fn link_relink_after_disconnect_succeeds() {
        let db = Database::connect_in_memory().await.unwrap();
        seed_agents(&db, &[1, 2]).await;
        let links = db.links();

        // Create, delete, re-create
        links.create(LinkRecord { parent_agent_id: 1, link_agent_id: 2 }).await.unwrap();
        assert!(links.exists(1, 2).await.unwrap());

        links.delete(1, 2).await.unwrap();
        assert!(!links.exists(1, 2).await.unwrap());

        links.create(LinkRecord { parent_agent_id: 1, link_agent_id: 2 }).await.unwrap();
        assert!(links.exists(1, 2).await.unwrap(), "re-linked A→B should exist");
        assert_eq!(links.parent_of(2).await.unwrap(), Some(1));
    }

    #[tokio::test]
    async fn link_list_returns_all_links_in_chain() {
        let db = Database::connect_in_memory().await.unwrap();
        seed_link_chain(&db, 10, 20, 30).await;
        let links = db.links();

        let all = links.list().await.unwrap();
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
        let db = Database::connect_in_memory().await.unwrap();
        seed_link_chain(&db, 5, 6, 7).await;
        let links = db.links();

        assert_eq!(links.parent_of(5).await.unwrap(), None, "root has no parent");
        assert_eq!(links.parent_of(6).await.unwrap(), Some(5));
        assert_eq!(links.parent_of(7).await.unwrap(), Some(6));
        assert_eq!(links.parent_of(99).await.unwrap(), None, "unknown agent has no parent");
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
        repo.create(&audit_entry("alice", "task.create", "2026-03-01T10:00:00Z")).await.unwrap();
        repo.create(&audit_entry("bob", "task.create", "2026-03-02T10:00:00Z")).await.unwrap();
        repo.create(&audit_entry("alice", "task.complete", "2026-03-03T10:00:00Z")).await.unwrap();
        repo.create(&audit_entry("carol", "agent.checkin", "2026-03-04T10:00:00Z")).await.unwrap();
        repo.create(&audit_entry("bob", "task.complete", "2026-03-05T10:00:00Z")).await.unwrap();
    }

    #[tokio::test]
    async fn audit_query_filtered_by_actor_substring() {
        let db = Database::connect_in_memory().await.unwrap();
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        let filter =
            AuditLogFilter { actor_contains: Some("ali".to_string()), ..Default::default() };
        let results = repo.query_filtered(&filter, 100, 0).await.unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|e| e.actor == "alice"));
    }

    #[tokio::test]
    async fn audit_query_filtered_by_action_substring() {
        let db = Database::connect_in_memory().await.unwrap();
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        let filter =
            AuditLogFilter { action_contains: Some("complete".to_string()), ..Default::default() };
        let results = repo.query_filtered(&filter, 100, 0).await.unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|e| e.action == "task.complete"));
    }

    #[tokio::test]
    async fn audit_query_filtered_by_date_range() {
        let db = Database::connect_in_memory().await.unwrap();
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        let filter = AuditLogFilter {
            since: Some("2026-03-02T00:00:00Z".to_string()),
            until: Some("2026-03-04T00:00:00Z".to_string()),
            ..Default::default()
        };
        let results = repo.query_filtered(&filter, 100, 0).await.unwrap();
        assert_eq!(results.len(), 2, "only entries on 03-02 and 03-03 should match");
    }

    #[tokio::test]
    async fn audit_query_filtered_combined_actor_and_action() {
        let db = Database::connect_in_memory().await.unwrap();
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        let filter = AuditLogFilter {
            actor_contains: Some("bob".to_string()),
            action_contains: Some("create".to_string()),
            ..Default::default()
        };
        let results = repo.query_filtered(&filter, 100, 0).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].actor, "bob");
        assert_eq!(results[0].action, "task.create");
    }

    #[tokio::test]
    async fn audit_query_filtered_action_in_list() {
        let db = Database::connect_in_memory().await.unwrap();
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        let filter = AuditLogFilter {
            action_in: Some(vec!["task.create".to_string(), "agent.checkin".to_string()]),
            ..Default::default()
        };
        let results = repo.query_filtered(&filter, 100, 0).await.unwrap();
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn audit_query_filtered_pagination_newest_first() {
        let db = Database::connect_in_memory().await.unwrap();
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        let filter = AuditLogFilter::default();
        let page1 = repo.query_filtered(&filter, 2, 0).await.unwrap();
        let page2 = repo.query_filtered(&filter, 2, 2).await.unwrap();
        let page3 = repo.query_filtered(&filter, 2, 4).await.unwrap();

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
        let db = Database::connect_in_memory().await.unwrap();
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        let filter = AuditLogFilter {
            actor_contains: Some("nonexistent".to_string()),
            ..Default::default()
        };
        let results = repo.query_filtered(&filter, 100, 0).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn audit_query_filtered_by_json_details_fields() {
        let db = Database::connect_in_memory().await.unwrap();
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        // Filter by agent_id in details JSON.
        let filter = AuditLogFilter { agent_id: Some("1".to_string()), ..Default::default() };
        let results = repo.query_filtered(&filter, 100, 0).await.unwrap();
        assert_eq!(results.len(), 5, "all seeded entries have agent_id=1");

        // Filter by command substring in details JSON.
        let filter =
            AuditLogFilter { command_contains: Some("who".to_string()), ..Default::default() };
        let results = repo.query_filtered(&filter, 100, 0).await.unwrap();
        assert_eq!(results.len(), 5);

        // Filter by result_status in details JSON.
        let filter = AuditLogFilter { result_status: Some("ok".to_string()), ..Default::default() };
        let results = repo.query_filtered(&filter, 100, 0).await.unwrap();
        assert_eq!(results.len(), 5);

        // Non-matching result_status.
        let filter =
            AuditLogFilter { result_status: Some("error".to_string()), ..Default::default() };
        let results = repo.query_filtered(&filter, 100, 0).await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn audit_count_filtered_matches_query_length() {
        let db = Database::connect_in_memory().await.unwrap();
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        // Unfiltered count.
        let count = repo.count_filtered(&AuditLogFilter::default()).await.unwrap();
        let results = repo.query_filtered(&AuditLogFilter::default(), 100, 0).await.unwrap();
        assert_eq!(count, results.len() as i64);

        // Filtered count.
        let filter =
            AuditLogFilter { actor_contains: Some("alice".to_string()), ..Default::default() };
        let count = repo.count_filtered(&filter).await.unwrap();
        let results = repo.query_filtered(&filter, 100, 0).await.unwrap();
        assert_eq!(count, results.len() as i64);
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn audit_count_filtered_with_date_range() {
        let db = Database::connect_in_memory().await.unwrap();
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        let filter = AuditLogFilter {
            since: Some("2026-03-03T00:00:00Z".to_string()),
            until: Some("2026-03-05T23:59:59Z".to_string()),
            ..Default::default()
        };
        let count = repo.count_filtered(&filter).await.unwrap();
        assert_eq!(count, 3);
    }

    #[tokio::test]
    async fn audit_latest_timestamps_no_matching_rows() {
        let db = Database::connect_in_memory().await.unwrap();
        let repo = db.audit_log();

        // No data at all.
        let result = repo.latest_timestamps_by_actor_for_actions(&["task.create"]).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn audit_latest_timestamps_empty_actions_returns_empty() {
        let db = Database::connect_in_memory().await.unwrap();
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        let result = repo.latest_timestamps_by_actor_for_actions(&[]).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn audit_latest_timestamps_multiple_actors() {
        let db = Database::connect_in_memory().await.unwrap();
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        let result = repo
            .latest_timestamps_by_actor_for_actions(&["task.create", "task.complete"])
            .await
            .unwrap();
        // alice: max of 2026-03-01 (create) and 2026-03-03 (complete) → 2026-03-03
        assert_eq!(result.get("alice").map(String::as_str), Some("2026-03-03T10:00:00Z"));
        // bob: max of 2026-03-02 (create) and 2026-03-05 (complete) → 2026-03-05
        assert_eq!(result.get("bob").map(String::as_str), Some("2026-03-05T10:00:00Z"));
        // carol only has agent.checkin, not in the action list.
        assert!(result.get("carol").is_none());
    }

    #[tokio::test]
    async fn audit_latest_timestamps_single_action() {
        let db = Database::connect_in_memory().await.unwrap();
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        let result = repo.latest_timestamps_by_actor_for_actions(&["agent.checkin"]).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result.get("carol").map(String::as_str), Some("2026-03-04T10:00:00Z"));
    }

    #[tokio::test]
    async fn audit_latest_timestamps_nonexistent_action_returns_empty() {
        let db = Database::connect_in_memory().await.unwrap();
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        let result =
            repo.latest_timestamps_by_actor_for_actions(&["nonexistent.action"]).await.unwrap();
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
        let db = Database::connect_in_memory().await.unwrap();
        let repo = db.operators();

        repo.create(&sample_operator("admin")).await.unwrap();
        repo.update_password_verifier("admin", "argon2:new_hash").await.unwrap();

        let fetched = repo.get("admin").await.unwrap().expect("operator should exist");
        assert_eq!(fetched.password_verifier, "argon2:new_hash");
    }

    #[tokio::test]
    async fn operator_update_password_verifier_silently_succeeds_for_nonexistent_user() {
        let db = Database::connect_in_memory().await.unwrap();
        let repo = db.operators();

        // UPDATE WHERE username = ? affects zero rows — SQLite does not error.
        let result = repo.update_password_verifier("ghost", "argon2:hash").await;
        assert!(result.is_ok(), "update for non-existent user should not error");

        // Confirm the user was not accidentally created.
        let fetched = repo.get("ghost").await.unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn operator_create_and_get_round_trips() {
        let db = Database::connect_in_memory().await.unwrap();
        let repo = db.operators();
        let op = sample_operator("testuser");

        repo.create(&op).await.unwrap();
        let fetched = repo.get("testuser").await.unwrap().expect("operator should exist");

        assert_eq!(fetched.username, "testuser");
        assert_eq!(fetched.password_verifier, "argon2:initial_hash");
        assert_eq!(fetched.role, OperatorRole::Operator);
    }

    #[tokio::test]
    async fn operator_get_returns_none_for_missing_user() {
        let db = Database::connect_in_memory().await.unwrap();
        let repo = db.operators();

        let fetched = repo.get("nobody").await.unwrap();
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
        })
    }

    #[tokio::test]
    async fn listener_set_state_created_to_running() {
        let db = Database::connect_in_memory().await.unwrap();
        let repo = db.listeners();

        repo.create(&stub_http_listener("ls-test")).await.unwrap();

        // Initial state should be Created.
        let persisted = repo.get("ls-test").await.unwrap().expect("listener should exist");
        assert_eq!(persisted.state.status, ListenerStatus::Created);
        assert!(persisted.state.last_error.is_none());

        // Transition to Running.
        repo.set_state("ls-test", ListenerStatus::Running, None).await.unwrap();
        let persisted = repo.get("ls-test").await.unwrap().unwrap();
        assert_eq!(persisted.state.status, ListenerStatus::Running);
        assert!(persisted.state.last_error.is_none());
    }

    #[tokio::test]
    async fn listener_set_state_running_to_error_with_message() {
        let db = Database::connect_in_memory().await.unwrap();
        let repo = db.listeners();

        repo.create(&stub_http_listener("ls-err")).await.unwrap();
        repo.set_state("ls-err", ListenerStatus::Running, None).await.unwrap();

        // Transition to Error with a reason.
        repo.set_state("ls-err", ListenerStatus::Error, Some("bind failed: port in use"))
            .await
            .unwrap();
        let persisted = repo.get("ls-err").await.unwrap().unwrap();
        assert_eq!(persisted.state.status, ListenerStatus::Error);
        assert_eq!(persisted.state.last_error.as_deref(), Some("bind failed: port in use"));
    }

    #[tokio::test]
    async fn listener_set_state_error_to_stopped_clears_error() {
        let db = Database::connect_in_memory().await.unwrap();
        let repo = db.listeners();

        repo.create(&stub_http_listener("ls-clr")).await.unwrap();
        repo.set_state("ls-clr", ListenerStatus::Error, Some("crash")).await.unwrap();

        // Transition back to Stopped with no error.
        repo.set_state("ls-clr", ListenerStatus::Stopped, None).await.unwrap();
        let persisted = repo.get("ls-clr").await.unwrap().unwrap();
        assert_eq!(persisted.state.status, ListenerStatus::Stopped);
        assert!(persisted.state.last_error.is_none());
    }

    #[tokio::test]
    async fn listener_set_state_full_lifecycle() {
        let db = Database::connect_in_memory().await.unwrap();
        let repo = db.listeners();

        repo.create(&stub_http_listener("ls-life")).await.unwrap();

        let transitions = [
            (ListenerStatus::Running, None),
            (ListenerStatus::Stopped, None),
            (ListenerStatus::Running, None),
            (ListenerStatus::Error, Some("unexpected EOF")),
            (ListenerStatus::Stopped, None),
        ];

        for (status, error) in &transitions {
            repo.set_state("ls-life", *status, error.as_deref()).await.unwrap();
            let persisted = repo.get("ls-life").await.unwrap().unwrap();
            assert_eq!(persisted.state.status, *status);
            assert_eq!(persisted.state.last_error.as_deref(), *error);
        }
    }

    #[tokio::test]
    async fn listener_set_state_nonexistent_listener_silently_succeeds() {
        let db = Database::connect_in_memory().await.unwrap();
        let repo = db.listeners();

        // UPDATE WHERE name = ? on non-existent row affects zero rows — no error.
        let result = repo.set_state("ghost", ListenerStatus::Running, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn listener_create_duplicate_name_returns_error() {
        let db = Database::connect_in_memory().await.unwrap();
        let repo = db.listeners();

        repo.create(&stub_http_listener("dup")).await.unwrap();
        let result = repo.create(&stub_http_listener("dup")).await;
        assert!(result.is_err(), "inserting a listener with a duplicate name should fail");
    }

    // ── ListenerStatus::try_from_str tests ──────────────────────────────

    #[test]
    fn listener_status_try_from_str_valid_values() {
        assert_eq!(ListenerStatus::try_from_str("created").unwrap(), ListenerStatus::Created);
        assert_eq!(ListenerStatus::try_from_str("running").unwrap(), ListenerStatus::Running);
        assert_eq!(ListenerStatus::try_from_str("stopped").unwrap(), ListenerStatus::Stopped);
        assert_eq!(ListenerStatus::try_from_str("error").unwrap(), ListenerStatus::Error);
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
        assert_eq!(u32_from_i64("field", 0).unwrap(), 0u32);
    }

    #[test]
    fn u32_from_i64_accepts_u32_max() {
        assert_eq!(u32_from_i64("field", i64::from(u32::MAX)).unwrap(), u32::MAX);
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
        assert_eq!(u64_from_i64("field", 0).unwrap(), 0u64);
    }

    #[test]
    fn u64_from_i64_accepts_i64_max() {
        assert_eq!(u64_from_i64("field", i64::MAX).unwrap(), i64::MAX as u64);
    }

    #[test]
    fn u64_from_i64_rejects_negative() {
        assert!(u64_from_i64("field", -1).is_err());
        assert!(u64_from_i64("field", i64::MIN).is_err());
    }

    // ── parse_operator_role tests ───────────────────────────────────────

    #[test]
    fn parse_operator_role_accepts_titlecase() {
        assert_eq!(parse_operator_role("Admin").unwrap(), OperatorRole::Admin);
        assert_eq!(parse_operator_role("Operator").unwrap(), OperatorRole::Operator);
        assert_eq!(parse_operator_role("Analyst").unwrap(), OperatorRole::Analyst);
    }

    #[test]
    fn parse_operator_role_accepts_lowercase() {
        assert_eq!(parse_operator_role("admin").unwrap(), OperatorRole::Admin);
        assert_eq!(parse_operator_role("operator").unwrap(), OperatorRole::Operator);
        assert_eq!(parse_operator_role("analyst").unwrap(), OperatorRole::Analyst);
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
        let db = Database::connect_in_memory().await.unwrap();
        let repo = db.payload_builds();

        let record = stub_payload_build("build-001");
        repo.create(&record).await.unwrap();

        let fetched = repo.get("build-001").await.unwrap();
        assert_eq!(fetched, Some(record));
    }

    #[tokio::test]
    async fn payload_builds_factory_errors_after_close() {
        let db = Database::connect_in_memory().await.unwrap();
        let repo = db.payload_builds();
        db.close().await;

        let result = repo.create(&stub_payload_build("build-closed")).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn payload_builds_factory_two_handles_see_same_row() {
        let db = Database::connect_in_memory().await.unwrap();
        let repo_a = db.payload_builds();
        let repo_b = db.payload_builds();

        let record = stub_payload_build("build-shared");
        repo_a.create(&record).await.unwrap();

        let fetched = repo_b.get("build-shared").await.unwrap();
        assert_eq!(fetched, Some(record));
    }

    // ── AgentRepository transport-state persistence tests ─────────────

    #[tokio::test]
    async fn create_full_persists_listener_ctr_offset_and_legacy_ctr() {
        let db = Database::connect_in_memory().await.unwrap();
        let repo = db.agents();
        let agent = stub_agent(0xAA);

        repo.create_full(&agent, "https-listener", 42, true).await.unwrap();

        let persisted = repo.get_persisted(0xAA).await.unwrap().expect("agent should exist");
        assert_eq!(persisted.listener_name, "https-listener");
        assert_eq!(persisted.ctr_block_offset, 42);
        assert!(persisted.legacy_ctr);
        assert_eq!(persisted.info.agent_id, 0xAA);
    }

    #[tokio::test]
    async fn set_legacy_ctr_on_missing_agent_returns_agent_not_found() {
        let db = Database::connect_in_memory().await.unwrap();
        let repo = db.agents();

        let err = repo.set_legacy_ctr(0xDEAD, true).await.unwrap_err();
        assert!(
            matches!(err, super::TeamserverError::AgentNotFound { agent_id } if agent_id == 0xDEAD),
            "expected AgentNotFound, got: {err:?}",
        );

        // Verify no row was created as a side-effect.
        let fetched = repo.get_persisted(0xDEAD).await.unwrap();
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn toggle_legacy_ctr_preserves_other_fields() {
        let db = Database::connect_in_memory().await.unwrap();
        let repo = db.agents();
        let agent = stub_agent(0xBB);

        repo.create_full(&agent, "smb-pipe", 99, true).await.unwrap();

        // Toggle legacy_ctr from true → false.
        repo.set_legacy_ctr(0xBB, false).await.unwrap();

        let persisted = repo.get_persisted(0xBB).await.unwrap().expect("agent should exist");
        assert!(!persisted.legacy_ctr, "legacy_ctr should now be false");
        // Other transport fields must be unchanged.
        assert_eq!(persisted.listener_name, "smb-pipe");
        assert_eq!(persisted.ctr_block_offset, 99);
        assert_eq!(persisted.info.agent_id, 0xBB);
        assert_eq!(persisted.info.active, true);
    }
}
