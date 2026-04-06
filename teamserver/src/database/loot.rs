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
