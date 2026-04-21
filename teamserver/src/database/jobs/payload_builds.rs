//! Payload-build repository: job records for compiled agent artifacts.

use sqlx::{FromRow, SqlitePool};

use crate::database::TeamserverError;

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
    /// For Archon DLL/ReflectiveDll builds: the randomized export function name
    /// injected at compile time.  `None` for all other agent types and formats.
    pub export_name: Option<String>,
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
    export_name: Option<String>,
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
            export_name: row.export_name,
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
    /// For Archon DLL/ReflectiveDll builds: the randomized export function name.
    pub export_name: Option<String>,
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
    export_name: Option<String>,
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
            export_name: row.export_name,
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
                   size_bytes, error, export_name, created_at, updated_at \
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
                   size_bytes, error, export_name, created_at, updated_at \
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
    #[allow(clippy::too_many_arguments)]
    pub async fn update_status(
        &self,
        id: &str,
        status: &str,
        name: Option<&str>,
        artifact: Option<&[u8]>,
        size_bytes: Option<i64>,
        error: Option<&str>,
        export_name: Option<&str>,
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
                export_name = COALESCE(?, export_name),
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(status)
        .bind(name)
        .bind(artifact)
        .bind(size_bytes)
        .bind(error)
        .bind(export_name)
        .bind(updated_at)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}
