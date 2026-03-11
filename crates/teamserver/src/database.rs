//! SQLite-backed persistence for the Red Cell teamserver.

use std::path::{Path, PathBuf};

use red_cell_common::demon::DemonProtocolError;
use red_cell_common::{AgentInfo, ListenerConfig, ListenerProtocol};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{FromRow, QueryBuilder, Row, Sqlite, SqlitePool};
use thiserror::Error;
use tracing::instrument;
use utoipa::ToSchema;

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
    pub info: AgentInfo,
    /// Shared AES-CTR block offset tracked across decrypt/encrypt operations.
    pub ctr_block_offset: u64,
}

impl AgentRepository {
    /// Create a new agent repository from a shared pool.
    #[must_use]
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Insert a new agent row.
    pub async fn create(&self, agent: &AgentInfo) -> Result<(), TeamserverError> {
        sqlx::query(
            r#"
            INSERT INTO ts_agents (
                agent_id, active, reason, note, ctr_block_offset, aes_key, aes_iv, hostname, username, domain_name,
                external_ip, internal_ip, process_name, base_address, process_pid, process_tid,
                process_ppid, process_arch, elevated, os_version, os_arch, sleep_delay,
                sleep_jitter, kill_date, working_hours, first_call_in, last_call_in
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(i64::from(agent.agent_id))
        .bind(bool_to_i64(agent.active))
        .bind(&agent.reason)
        .bind(&agent.note)
        .bind(0_i64)
        .bind(&agent.encryption.aes_key)
        .bind(&agent.encryption.aes_iv)
        .bind(&agent.hostname)
        .bind(&agent.username)
        .bind(&agent.domain_name)
        .bind(&agent.external_ip)
        .bind(&agent.internal_ip)
        .bind(&agent.process_name)
        .bind(i64_from_u64("base_address", agent.base_address)?)
        .bind(i64::from(agent.process_pid))
        .bind(i64::from(agent.process_tid))
        .bind(i64::from(agent.process_ppid))
        .bind(&agent.process_arch)
        .bind(bool_to_i64(agent.elevated))
        .bind(&agent.os_version)
        .bind(&agent.os_arch)
        .bind(i64::from(agent.sleep_delay))
        .bind(i64::from(agent.sleep_jitter))
        .bind(agent.kill_date)
        .bind(agent.working_hours.map(i64::from))
        .bind(&agent.first_call_in)
        .bind(&agent.last_call_in)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Update an existing agent row.
    pub async fn update(&self, agent: &AgentInfo) -> Result<(), TeamserverError> {
        sqlx::query(
            r#"
            UPDATE ts_agents SET
                active = ?, reason = ?, note = ?, aes_key = ?, aes_iv = ?, hostname = ?, username = ?,
                domain_name = ?, external_ip = ?, internal_ip = ?, process_name = ?,
                base_address = ?, process_pid = ?, process_tid = ?, process_ppid = ?,
                process_arch = ?, elevated = ?, os_version = ?, os_arch = ?, sleep_delay = ?,
                sleep_jitter = ?, kill_date = ?, working_hours = ?, first_call_in = ?,
                last_call_in = ?
            WHERE agent_id = ?
            "#,
        )
        .bind(bool_to_i64(agent.active))
        .bind(&agent.reason)
        .bind(&agent.note)
        .bind(&agent.encryption.aes_key)
        .bind(&agent.encryption.aes_iv)
        .bind(&agent.hostname)
        .bind(&agent.username)
        .bind(&agent.domain_name)
        .bind(&agent.external_ip)
        .bind(&agent.internal_ip)
        .bind(&agent.process_name)
        .bind(i64_from_u64("base_address", agent.base_address)?)
        .bind(i64::from(agent.process_pid))
        .bind(i64::from(agent.process_tid))
        .bind(i64::from(agent.process_ppid))
        .bind(&agent.process_arch)
        .bind(bool_to_i64(agent.elevated))
        .bind(&agent.os_version)
        .bind(&agent.os_arch)
        .bind(i64::from(agent.sleep_delay))
        .bind(i64::from(agent.sleep_jitter))
        .bind(agent.kill_date)
        .bind(agent.working_hours.map(i64::from))
        .bind(&agent.first_call_in)
        .bind(&agent.last_call_in)
        .bind(i64::from(agent.agent_id))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Fetch a single agent by identifier.
    pub async fn get(&self, agent_id: u32) -> Result<Option<AgentInfo>, TeamserverError> {
        let row = sqlx::query_as::<_, AgentRow>("SELECT * FROM ts_agents WHERE agent_id = ?")
            .bind(i64::from(agent_id))
            .fetch_optional(&self.pool)
            .await?;

        row.map(TryInto::try_into).transpose()
    }

    /// Return all persisted agents.
    pub async fn list(&self) -> Result<Vec<AgentInfo>, TeamserverError> {
        let rows = sqlx::query_as::<_, AgentRow>("SELECT * FROM ts_agents ORDER BY agent_id")
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    /// Return only agents still marked active.
    pub async fn list_active(&self) -> Result<Vec<AgentInfo>, TeamserverError> {
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
        sqlx::query("UPDATE ts_agents SET note = ? WHERE agent_id = ?")
            .bind(note)
            .bind(i64::from(agent_id))
            .execute(&self.pool)
            .await?;

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
        sqlx::query("UPDATE ts_agents SET ctr_block_offset = ? WHERE agent_id = ?")
            .bind(i64_from_u64("ctr_block_offset", ctr_block_offset)?)
            .bind(i64::from(agent_id))
            .execute(&self.pool)
            .await?;

        Ok(())
    }
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
    base_address: i64,
    process_pid: i64,
    process_tid: i64,
    process_ppid: i64,
    process_arch: String,
    elevated: i64,
    os_version: String,
    os_arch: String,
    sleep_delay: i64,
    sleep_jitter: i64,
    kill_date: Option<i64>,
    working_hours: Option<i64>,
    first_call_in: String,
    last_call_in: String,
}

impl TryFrom<AgentRow> for AgentInfo {
    type Error = TeamserverError;

    fn try_from(row: AgentRow) -> Result<Self, Self::Error> {
        Ok(Self {
            agent_id: u32_from_i64("agent_id", row.agent_id)?,
            active: bool_from_i64("active", row.active)?,
            reason: row.reason,
            note: row.note,
            encryption: red_cell_common::AgentEncryptionInfo {
                aes_key: row.aes_key,
                aes_iv: row.aes_iv,
            },
            hostname: row.hostname,
            username: row.username,
            domain_name: row.domain_name,
            external_ip: row.external_ip,
            internal_ip: row.internal_ip,
            process_name: row.process_name,
            base_address: u64_from_i64("base_address", row.base_address)?,
            process_pid: u32_from_i64("process_pid", row.process_pid)?,
            process_tid: u32_from_i64("process_tid", row.process_tid)?,
            process_ppid: u32_from_i64("process_ppid", row.process_ppid)?,
            process_arch: row.process_arch,
            elevated: bool_from_i64("elevated", row.elevated)?,
            os_version: row.os_version,
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
        let info = AgentInfo::try_from(row)?;
        Ok(Self { info, ctr_block_offset })
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

#[cfg(test)]
mod tests {
    use super::{bool_from_i64, i64_from_u64};

    #[test]
    fn bool_from_i64_accepts_sqlite_boolean_values() {
        assert_eq!(bool_from_i64("active", 0).ok(), Some(false));
        assert_eq!(bool_from_i64("active", 1).ok(), Some(true));
    }

    #[test]
    fn bool_from_i64_rejects_out_of_range_values() {
        assert!(bool_from_i64("active", 2).is_err());
    }

    #[test]
    fn i64_from_u64_rejects_values_bigger_than_sqlite_integer() {
        assert!(i64_from_u64("base_address", u64::MAX).is_err());
    }
}
