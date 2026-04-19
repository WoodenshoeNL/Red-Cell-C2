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

#[cfg(test)]
mod tests {
    use red_cell_common::{AgentEncryptionInfo, AgentRecord};
    use zeroize::Zeroizing;

    use crate::database::Database;

    use super::{AgentResponseRecord, PayloadBuildRecord};

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
            archon_magic: None,
        }
    }

    async fn seed_agents(db: &Database, ids: &[u32]) {
        for &id in ids {
            db.agents().create(&stub_agent(id)).await.expect("seed_agent");
        }
    }

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
            export_name: None,
            created_at: "2026-03-27T00:00:00Z".to_owned(),
            updated_at: "2026-03-27T00:00:00Z".to_owned(),
        }
    }

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
        let make_record = |request_id: u32, output: &str, received_at: &str| AgentResponseRecord {
            id: None,
            agent_id: 101,
            command_id: 21,
            request_id,
            response_type: "Good".to_owned(),
            message: String::new(),
            output: output.to_owned(),
            command_line: None,
            task_id: None,
            operator: None,
            received_at: received_at.to_owned(),
            extra: None,
        };
        let id1 =
            repo.create(&make_record(1, "out-1", "2026-03-27T00:00:00Z")).await.expect("create r1");
        repo.create(&make_record(2, "out-2", "2026-03-27T00:01:00Z")).await.expect("create r2");

        let after_first = repo.list_for_agent_since(101, Some(id1)).await.expect("query");
        assert_eq!(after_first.len(), 1);
        assert_eq!(after_first[0].output, "out-2");

        assert!(repo.list_for_agent_since(101, Some(id1 + 100)).await.expect("query").is_empty());
    }

    #[tokio::test]
    async fn payload_builds_factory_insert_and_read_back() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.payload_builds();
        let record = stub_payload_build("build-001");
        repo.create(&record).await.expect("create");
        assert_eq!(repo.get("build-001").await.expect("get"), Some(record));
    }

    #[tokio::test]
    async fn payload_builds_factory_errors_after_close() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.payload_builds();
        db.close().await;
        assert!(repo.create(&stub_payload_build("build-closed")).await.is_err());
    }

    #[tokio::test]
    async fn payload_builds_factory_two_handles_see_same_row() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo_a = db.payload_builds();
        let repo_b = db.payload_builds();
        let record = stub_payload_build("build-shared");
        repo_a.create(&record).await.expect("create");
        assert_eq!(repo_b.get("build-shared").await.expect("get"), Some(record));
    }

    #[tokio::test]
    async fn payload_builds_crud_round_trip_with_artifact_blobs() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.payload_builds();
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
            export_name: None,
            created_at: "2026-03-27T10:00:00Z".to_owned(),
            updated_at: "2026-03-27T10:05:00Z".to_owned(),
        };
        repo.create(&record_a).await.expect("create");
        let fetched = repo.get("crud-a").await.expect("get").expect("should exist");
        assert_eq!(fetched, record_a);
    }

    #[tokio::test]
    async fn payload_builds_list_returns_newest_first() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.payload_builds();
        let mut older = stub_payload_build("list-older");
        older.created_at = "2026-03-27T08:00:00Z".to_owned();
        let mut newer = stub_payload_build("list-newer");
        newer.created_at = "2026-03-27T09:00:00Z".to_owned();
        repo.create(&older).await.expect("create");
        repo.create(&newer).await.expect("create");
        let all = repo.list().await.expect("list");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].id, "list-newer", "newest record should be first");
        assert_eq!(all[1].id, "list-older");
    }

    #[tokio::test]
    async fn payload_builds_get_returns_none_for_unknown_id() {
        let db = Database::connect_in_memory().await.expect("db");
        assert!(db.payload_builds().get("nonexistent-id").await.expect("get").is_none());
    }

    #[tokio::test]
    async fn get_summary_returns_metadata_without_artifact() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.payload_builds();
        let mut record = stub_payload_build("sum-001");
        record.artifact = Some(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        record.size_bytes = Some(4);
        record.status = "done".to_owned();
        repo.create(&record).await.expect("create");

        let summary =
            repo.get_summary("sum-001").await.expect("get_summary").expect("should exist");
        assert_eq!(summary.id, "sum-001");
        assert_eq!(summary.status, "done");
        assert_eq!(summary.size_bytes, Some(4));
        assert!(summary.error.is_none());
    }

    #[tokio::test]
    async fn get_summary_returns_none_for_missing_id() {
        let db = Database::connect_in_memory().await.expect("db");
        assert!(db.payload_builds().get_summary("nonexistent-id").await.expect("get").is_none());
    }

    #[tokio::test]
    async fn list_summaries_returns_metadata_ordered_by_created_at_desc() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.payload_builds();
        let mut b1 = stub_payload_build("ls-001");
        b1.created_at = "2026-03-27T01:00:00Z".to_owned();
        b1.name = "first".to_owned();
        let mut b2 = stub_payload_build("ls-002");
        b2.created_at = "2026-03-27T02:00:00Z".to_owned();
        b2.name = "second".to_owned();
        let mut b3 = stub_payload_build("ls-003");
        b3.created_at = "2026-03-27T03:00:00Z".to_owned();
        b3.name = "third".to_owned();
        repo.create(&b1).await.expect("create");
        repo.create(&b2).await.expect("create");
        repo.create(&b3).await.expect("create");
        let summaries = repo.list_summaries().await.expect("list");
        assert_eq!(summaries.len(), 3);
        assert_eq!(summaries[0].id, "ls-003");
        assert_eq!(summaries[1].id, "ls-002");
        assert_eq!(summaries[2].id, "ls-001");
    }

    #[tokio::test]
    async fn list_summaries_empty_table_returns_empty_vec() {
        let db = Database::connect_in_memory().await.expect("db");
        assert!(db.payload_builds().list_summaries().await.expect("list").is_empty());
    }

    #[tokio::test]
    async fn update_status_happy_path_persists_all_fields() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.payload_builds();
        repo.create(&stub_payload_build("upd-001")).await.expect("create");
        let artifact_bytes: &[u8] = &[0xCA, 0xFE, 0xBA, 0xBE];
        let updated = repo
            .update_status(
                "upd-001",
                "done",
                Some("final.exe"),
                Some(artifact_bytes),
                Some(4),
                None,
                None,
                "2026-03-27T12:00:00Z",
            )
            .await
            .expect("update_status");
        assert!(updated);
        let fetched = repo.get("upd-001").await.expect("get").expect("should exist");
        assert_eq!(fetched.status, "done");
        assert_eq!(fetched.artifact, Some(artifact_bytes.to_vec()));
        assert_eq!(fetched.size_bytes, Some(4));
        assert_eq!(fetched.updated_at, "2026-03-27T12:00:00Z");
    }

    #[tokio::test]
    async fn update_status_missing_id_returns_false() {
        let db = Database::connect_in_memory().await.expect("db");
        let updated = db
            .payload_builds()
            .update_status(
                "nonexistent-id",
                "done",
                None,
                None,
                None,
                None,
                None,
                "2026-03-27T12:00:00Z",
            )
            .await
            .expect("update_status");
        assert!(!updated);
    }

    #[tokio::test]
    async fn update_status_partial_fields_preserves_existing_values() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.payload_builds();
        let mut record = stub_payload_build("upd-partial");
        record.name = "original-name.exe".to_owned();
        record.artifact = Some(vec![0x01, 0x02]);
        record.size_bytes = Some(2);
        repo.create(&record).await.expect("create");
        let updated = repo
            .update_status(
                "upd-partial",
                "error",
                None,
                None,
                None,
                Some("build timed out"),
                None,
                "2026-03-27T13:00:00Z",
            )
            .await
            .expect("update_status");
        assert!(updated);
        let fetched = repo.get("upd-partial").await.expect("get").expect("should exist");
        assert_eq!(fetched.status, "error");
        assert_eq!(fetched.error, Some("build timed out".to_owned()));
        assert_eq!(fetched.name, "original-name.exe");
        assert_eq!(fetched.artifact, Some(vec![0x01, 0x02]));
    }

    #[tokio::test]
    async fn invalidate_done_builds_for_listener_marks_done_records_stale() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.payload_builds();
        let mut a = stub_payload_build("inv-a");
        a.status = "done".to_owned();
        a.listener = "http-main".to_owned();
        let mut b = stub_payload_build("inv-b");
        b.status = "done".to_owned();
        b.listener = "http-main".to_owned();
        let mut other = stub_payload_build("inv-other");
        other.status = "done".to_owned();
        other.listener = "dns-backup".to_owned();
        repo.create(&a).await.expect("create");
        repo.create(&b).await.expect("create");
        repo.create(&other).await.expect("create");

        let count = repo
            .invalidate_done_builds_for_listener("http-main", "2026-03-31T00:00:00Z")
            .await
            .expect("invalidate");
        assert_eq!(count, 2);

        assert_eq!(repo.get("inv-a").await.expect("get").expect("inv-a").status, "stale");
        assert_eq!(repo.get("inv-b").await.expect("get").expect("inv-b").status, "stale");
        assert_eq!(repo.get("inv-other").await.expect("get").expect("inv-other").status, "done");
    }

    #[tokio::test]
    async fn invalidate_done_builds_for_listener_ignores_non_done_records() {
        let db = Database::connect_in_memory().await.expect("db");
        let repo = db.payload_builds();
        let mut pending = stub_payload_build("inv-pend");
        pending.status = "pending".to_owned();
        pending.listener = "http-main".to_owned();
        let mut errored = stub_payload_build("inv-err");
        errored.status = "error".to_owned();
        errored.listener = "http-main".to_owned();
        repo.create(&pending).await.expect("create");
        repo.create(&errored).await.expect("create");
        let count = repo
            .invalidate_done_builds_for_listener("http-main", "2026-03-31T00:00:00Z")
            .await
            .expect("invalidate");
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn invalidate_done_builds_for_listener_returns_zero_for_unknown_listener() {
        let db = Database::connect_in_memory().await.expect("db");
        let count = db
            .payload_builds()
            .invalidate_done_builds_for_listener("nonexistent", "2026-03-31T00:00:00Z")
            .await
            .expect("invalidate");
        assert_eq!(count, 0);
    }
}
