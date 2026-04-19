//! Loot CRUD repository.

use serde_json::Value;
use sqlx::{FromRow, QueryBuilder, Row, Sqlite, SqlitePool};

use super::TeamserverError;

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

pub(super) fn append_loot_filters(builder: &mut QueryBuilder<'_, Sqlite>, filter: &LootFilter) {
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
            agent_id: super::u32_from_i64("agent_id", row.agent_id)?,
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

#[cfg(test)]
mod tests {
    use red_cell_common::{AgentEncryptionInfo, AgentRecord};
    use serde_json::json;
    use zeroize::Zeroizing;

    use crate::database::Database;

    use super::{LootFilter, LootRecord};

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

    #[tokio::test]
    async fn loot_create_and_get_round_trips_all_fields() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_agents(&db, &[100]).await;
        let repo = db.loot();
        let record = sample_loot(100, "hash", "NTLM hashes");

        let id = repo.create(&record).await.expect("create");
        let fetched = repo.get(id).await.expect("get").expect("record should exist");

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
        let db = Database::connect_in_memory().await.expect("db");
        let fetched = db.loot().get(999).await.expect("get");
        assert!(fetched.is_none());
    }

    #[tokio::test]
    async fn loot_list_for_agent_returns_correct_grouping() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_agents(&db, &[10, 20]).await;
        let repo = db.loot();

        repo.create(&sample_loot(10, "hash", "agent10-hash")).await.expect("create");
        repo.create(&sample_loot(10, "ticket", "agent10-ticket")).await.expect("create");
        repo.create(&sample_loot(20, "token", "agent20-token")).await.expect("create");

        let agent10 = repo.list_for_agent(10).await.expect("list");
        assert_eq!(agent10.len(), 2);
        assert!(agent10.iter().all(|r| r.agent_id == 10));

        let agent20 = repo.list_for_agent(20).await.expect("list");
        assert_eq!(agent20.len(), 1);
        assert_eq!(agent20[0].name, "agent20-token");

        assert!(repo.list_for_agent(99).await.expect("list").is_empty());
    }

    #[tokio::test]
    async fn loot_list_returns_all_records() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_agents(&db, &[1, 2, 3]).await;
        let repo = db.loot();
        repo.create(&sample_loot(1, "hash", "a")).await.expect("create");
        repo.create(&sample_loot(2, "ticket", "b")).await.expect("create");
        repo.create(&sample_loot(3, "token", "c")).await.expect("create");
        assert_eq!(repo.list().await.expect("list").len(), 3);
    }

    #[tokio::test]
    async fn loot_empty_content_and_label_round_trips() {
        let db = Database::connect_in_memory().await.expect("db");
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
        let id = repo.create(&record).await.expect("create");
        let fetched = repo.get(id).await.expect("get").expect("exist");
        assert_eq!(fetched.agent_id, 42);
        assert!(fetched.file_path.is_none());
        assert!(fetched.metadata.is_none());
    }

    #[tokio::test]
    async fn loot_delete_removes_record() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_agents(&db, &[1]).await;
        let repo = db.loot();
        let id = repo.create(&sample_loot(1, "hash", "to-delete")).await.expect("create");
        assert!(repo.get(id).await.expect("get").is_some());
        repo.delete(id).await.expect("delete");
        assert!(repo.get(id).await.expect("get").is_none());
    }

    #[tokio::test]
    async fn loot_query_filtered_by_kind_exact() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_agents(&db, &[1, 2]).await;
        let repo = db.loot();
        repo.create(&sample_loot(1, "hash", "h1")).await.expect("create");
        repo.create(&sample_loot(1, "ticket", "t1")).await.expect("create");
        repo.create(&sample_loot(2, "hash", "h2")).await.expect("create");

        let filter = LootFilter { kind_exact: Some("hash".to_string()), ..Default::default() };
        let results = repo.query_filtered(&filter, 100, 0).await.expect("query");
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.kind == "hash"));
    }

    #[tokio::test]
    async fn loot_query_filtered_by_agent_id() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_agents(&db, &[10, 20]).await;
        let repo = db.loot();
        repo.create(&sample_loot(10, "hash", "a")).await.expect("create");
        repo.create(&sample_loot(20, "hash", "b")).await.expect("create");

        let filter = LootFilter { agent_id: Some(10), ..Default::default() };
        let results = repo.query_filtered(&filter, 100, 0).await.expect("query");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].agent_id, 10);
    }

    #[tokio::test]
    async fn loot_count_filtered_matches_query_length() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_agents(&db, &[1]).await;
        let repo = db.loot();
        repo.create(&sample_loot(1, "hash", "h1")).await.expect("create");
        repo.create(&sample_loot(1, "hash", "h2")).await.expect("create");
        repo.create(&sample_loot(1, "ticket", "t1")).await.expect("create");

        let filter = LootFilter { kind_exact: Some("hash".to_string()), ..Default::default() };
        let count = repo.count_filtered(&filter).await.expect("count");
        let results = repo.query_filtered(&filter, 100, 0).await.expect("query");
        assert_eq!(count, results.len() as i64);
    }

    #[tokio::test]
    async fn loot_query_filtered_pagination() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_agents(&db, &[1]).await;
        let repo = db.loot();
        for i in 0..5 {
            repo.create(&sample_loot(1, "hash", &format!("item-{i}"))).await.expect("create");
        }
        let filter = LootFilter::default();
        let page1 = repo.query_filtered(&filter, 2, 0).await.expect("p1");
        let page2 = repo.query_filtered(&filter, 2, 2).await.expect("p2");
        let page3 = repo.query_filtered(&filter, 2, 4).await.expect("p3");
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
}
