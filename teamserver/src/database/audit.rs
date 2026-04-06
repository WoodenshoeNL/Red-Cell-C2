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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::database::Database;

    use super::{AuditLogEntry, AuditLogFilter};

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
            .expect("create");
        repo.create(&audit_entry("bob", "task.create", "2026-03-02T10:00:00Z"))
            .await
            .expect("create");
        repo.create(&audit_entry("alice", "task.complete", "2026-03-03T10:00:00Z"))
            .await
            .expect("create");
        repo.create(&audit_entry("carol", "agent.checkin", "2026-03-04T10:00:00Z"))
            .await
            .expect("create");
        repo.create(&audit_entry("bob", "task.complete", "2026-03-05T10:00:00Z"))
            .await
            .expect("create");
    }

    #[tokio::test]
    async fn audit_query_filtered_by_actor_substring() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_audit_entries(&db).await;
        let filter =
            AuditLogFilter { actor_contains: Some("ali".to_string()), ..Default::default() };
        let results = db.audit_log().query_filtered(&filter, 100, 0).await.expect("query");
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|e| e.actor == "alice"));
    }

    #[tokio::test]
    async fn audit_query_filtered_by_action_substring() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_audit_entries(&db).await;
        let filter =
            AuditLogFilter { action_contains: Some("complete".to_string()), ..Default::default() };
        let results = db.audit_log().query_filtered(&filter, 100, 0).await.expect("query");
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|e| e.action == "task.complete"));
    }

    #[tokio::test]
    async fn audit_query_filtered_by_date_range() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_audit_entries(&db).await;
        let filter = AuditLogFilter {
            since: Some("2026-03-02T00:00:00Z".to_string()),
            until: Some("2026-03-04T00:00:00Z".to_string()),
            ..Default::default()
        };
        let results = db.audit_log().query_filtered(&filter, 100, 0).await.expect("query");
        assert_eq!(results.len(), 2, "only entries on 03-02 and 03-03 should match");
    }

    #[tokio::test]
    async fn audit_query_filtered_combined_actor_and_action() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_audit_entries(&db).await;
        let filter = AuditLogFilter {
            actor_contains: Some("bob".to_string()),
            action_contains: Some("create".to_string()),
            ..Default::default()
        };
        let results = db.audit_log().query_filtered(&filter, 100, 0).await.expect("query");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].actor, "bob");
        assert_eq!(results[0].action, "task.create");
    }

    #[tokio::test]
    async fn audit_query_filtered_action_in_list() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_audit_entries(&db).await;
        let filter = AuditLogFilter {
            action_in: Some(vec!["task.create".to_string(), "agent.checkin".to_string()]),
            ..Default::default()
        };
        let results = db.audit_log().query_filtered(&filter, 100, 0).await.expect("query");
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn audit_query_filtered_pagination_newest_first() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_audit_entries(&db).await;
        let filter = AuditLogFilter::default();
        let repo = db.audit_log();
        let page1 = repo.query_filtered(&filter, 2, 0).await.expect("p1");
        let page2 = repo.query_filtered(&filter, 2, 2).await.expect("p2");
        let page3 = repo.query_filtered(&filter, 2, 4).await.expect("p3");

        assert_eq!(page1.len(), 2);
        assert_eq!(page2.len(), 2);
        assert_eq!(page3.len(), 1);

        // Newest first.
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
        let db = Database::connect_in_memory().await.expect("db");
        seed_audit_entries(&db).await;
        let filter = AuditLogFilter {
            actor_contains: Some("nonexistent".to_string()),
            ..Default::default()
        };
        assert!(db.audit_log().query_filtered(&filter, 100, 0).await.expect("query").is_empty());
    }

    #[tokio::test]
    async fn audit_query_filtered_by_json_details_fields() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        let filter = AuditLogFilter { agent_id: Some("1".to_string()), ..Default::default() };
        assert_eq!(repo.query_filtered(&filter, 100, 0).await.expect("query").len(), 5);

        let filter =
            AuditLogFilter { command_contains: Some("who".to_string()), ..Default::default() };
        assert_eq!(repo.query_filtered(&filter, 100, 0).await.expect("query").len(), 5);

        let filter = AuditLogFilter { result_status: Some("ok".to_string()), ..Default::default() };
        assert_eq!(repo.query_filtered(&filter, 100, 0).await.expect("query").len(), 5);

        let filter =
            AuditLogFilter { result_status: Some("error".to_string()), ..Default::default() };
        assert!(repo.query_filtered(&filter, 100, 0).await.expect("query").is_empty());
    }

    #[tokio::test]
    async fn audit_count_filtered_matches_query_length() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_audit_entries(&db).await;
        let repo = db.audit_log();

        let count = repo.count_filtered(&AuditLogFilter::default()).await.expect("count");
        let results = repo.query_filtered(&AuditLogFilter::default(), 100, 0).await.expect("query");
        assert_eq!(count, results.len() as i64);

        let filter =
            AuditLogFilter { actor_contains: Some("alice".to_string()), ..Default::default() };
        let count = repo.count_filtered(&filter).await.expect("count");
        let results = repo.query_filtered(&filter, 100, 0).await.expect("query");
        assert_eq!(count, results.len() as i64);
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn audit_count_filtered_with_date_range() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_audit_entries(&db).await;
        let filter = AuditLogFilter {
            since: Some("2026-03-03T00:00:00Z".to_string()),
            until: Some("2026-03-05T23:59:59Z".to_string()),
            ..Default::default()
        };
        assert_eq!(db.audit_log().count_filtered(&filter).await.expect("count"), 3);
    }

    #[tokio::test]
    async fn audit_latest_timestamps_no_matching_rows() {
        let db = Database::connect_in_memory().await.expect("db");
        let result = db
            .audit_log()
            .latest_timestamps_by_actor_for_actions(&["task.create"])
            .await
            .expect("query");
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn audit_latest_timestamps_empty_actions_returns_empty() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_audit_entries(&db).await;
        let result =
            db.audit_log().latest_timestamps_by_actor_for_actions(&[]).await.expect("query");
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn audit_latest_timestamps_multiple_actors() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_audit_entries(&db).await;
        let result = db
            .audit_log()
            .latest_timestamps_by_actor_for_actions(&["task.create", "task.complete"])
            .await
            .expect("query");
        assert_eq!(result.get("alice").map(String::as_str), Some("2026-03-03T10:00:00Z"));
        assert_eq!(result.get("bob").map(String::as_str), Some("2026-03-05T10:00:00Z"));
        assert!(!result.contains_key("carol"));
    }

    #[tokio::test]
    async fn audit_latest_timestamps_single_action() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_audit_entries(&db).await;
        let result = db
            .audit_log()
            .latest_timestamps_by_actor_for_actions(&["agent.checkin"])
            .await
            .expect("query");
        assert_eq!(result.len(), 1);
        assert_eq!(result.get("carol").map(String::as_str), Some("2026-03-04T10:00:00Z"));
    }

    #[tokio::test]
    async fn audit_latest_timestamps_nonexistent_action_returns_empty() {
        let db = Database::connect_in_memory().await.expect("db");
        seed_audit_entries(&db).await;
        let result = db
            .audit_log()
            .latest_timestamps_by_actor_for_actions(&["nonexistent.action"])
            .await
            .expect("query");
        assert!(result.is_empty());
    }
}
