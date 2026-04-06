//! Audit-log CRUD repository.

use std::collections::BTreeMap;

use serde_json::Value;
use sqlx::{FromRow, QueryBuilder, Row, Sqlite, SqlitePool};

use super::TeamserverError;

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

pub(super) fn append_audit_filters(
    builder: &mut QueryBuilder<'_, Sqlite>,
    filter: &AuditLogFilter,
) {
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
