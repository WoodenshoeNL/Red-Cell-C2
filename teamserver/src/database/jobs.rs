//! Payload-build and agent-response repositories.

use serde_json::Value;
use sqlx::{FromRow, SqlitePool};

use super::TeamserverError;

// ── AgentResponseRepository ───────────────────────────────────────────────────

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
            agent_id: super::u32_from_i64("agent_id", row.agent_id)?,
            command_id: super::u32_from_i64("command_id", row.command_id)?,
            request_id: super::u32_from_i64("request_id", row.request_id)?,
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

// ── PayloadBuildRepository ────────────────────────────────────────────────────

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
    /// Agent type requested for this build (e.g. `"Demon"`, `"Phantom"`).
    pub agent_type: String,
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
    agent_type: String,
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
            agent_type: row.agent_type,
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
    /// Agent type requested for this build (e.g. `"Demon"`, `"Phantom"`).
    pub agent_type: String,
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
    agent_type: String,
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
            agent_type: row.agent_type,
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
                id, status, name, arch, format, listener, agent_type, sleep_secs,
                artifact, size_bytes, error, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&record.id)
        .bind(&record.status)
        .bind(&record.name)
        .bind(&record.arch)
        .bind(&record.format)
        .bind(&record.listener)
        .bind(&record.agent_type)
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
            SELECT id, status, name, arch, format, listener, agent_type, sleep_secs, \
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
            SELECT id, status, name, arch, format, listener, agent_type, sleep_secs, \
                   size_bytes, error, created_at, updated_at \
            FROM ts_payload_builds ORDER BY created_at DESC";
        let rows = sqlx::query_as::<_, PayloadBuildSummaryRow>(QUERY).fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Mark all `"done"` payload build records for `listener` as `"stale"`.
    ///
    /// Called when a listener's configuration is updated so that existing
    /// artifacts embedding the old callback address can no longer be downloaded.
    /// Returns the number of records invalidated.
    pub async fn invalidate_done_builds_for_listener(
        &self,
        listener: &str,
        updated_at: &str,
    ) -> Result<u64, TeamserverError> {
        let result = sqlx::query(
            "UPDATE ts_payload_builds SET status = 'stale', updated_at = ? \
             WHERE listener = ? AND status = 'done'",
        )
        .bind(updated_at)
        .bind(listener)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
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
