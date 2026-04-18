use serde_json::json;
use sqlx::Row as _;

use super::super::{AuditResultStatus, audit_details};
use crate::{Database, record_operator_action};

#[tokio::test]
async fn record_operator_action_persists_entry_and_returns_valid_id() {
    let database = Database::connect_in_memory().await.expect("database should initialize");

    let id = record_operator_action(
        &database,
        "test-operator",
        "agent.task",
        "agent",
        Some("CAFE0001".to_owned()),
        audit_details(
            AuditResultStatus::Success,
            Some(0xCAFE_0001),
            Some("checkin"),
            Some(json!({"key": "value"})),
        ),
    )
    .await
    .expect("record_operator_action should succeed");

    assert!(id > 0, "returned ID should be positive");

    let entry = database
        .audit_log()
        .get(id)
        .await
        .expect("database read should succeed")
        .expect("audit row should exist for the returned ID");

    assert_eq!(entry.actor, "test-operator");
    assert_eq!(entry.action, "agent.task");
    assert_eq!(entry.target_kind, "agent");
    assert_eq!(entry.target_id.as_deref(), Some("CAFE0001"));

    let details = entry.details.expect("details should be present");
    assert_eq!(details["agent_id"], "CAFE0001");
    assert_eq!(details["command"], "checkin");
    assert_eq!(details["parameters"]["key"], "value");
    assert_eq!(details["result_status"], "success");
}

#[tokio::test]
async fn record_operator_action_with_none_target_id_persists_null() {
    let database = Database::connect_in_memory().await.expect("database should initialize");

    let id = record_operator_action(
        &database,
        "admin",
        "config.update",
        "config",
        None,
        audit_details(AuditResultStatus::Success, None, None, None),
    )
    .await
    .expect("record_operator_action should succeed");

    let entry = database
        .audit_log()
        .get(id)
        .await
        .expect("database read should succeed")
        .expect("audit row should exist");

    assert_eq!(entry.actor, "admin");
    assert_eq!(entry.action, "config.update");
    assert_eq!(entry.target_kind, "config");
    assert!(entry.target_id.is_none(), "target_id should be None");
}

/// Collect the names of all indexes on `ts_audit_log` via SQLite PRAGMA.
async fn audit_log_index_names(database: &Database) -> Vec<String> {
    let rows = sqlx::query("PRAGMA index_list(ts_audit_log)")
        .fetch_all(database.pool())
        .await
        .expect("PRAGMA index_list should succeed");
    rows.into_iter().map(|row| row.get::<String, _>("name")).collect()
}

#[tokio::test]
async fn audit_log_actor_timestamp_composite_index_exists() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    let names = audit_log_index_names(&database).await;
    assert!(
        names.iter().any(|n| n == "idx_ts_audit_log_actor_ts"),
        "expected idx_ts_audit_log_actor_ts, found: {names:?}"
    );
}

#[tokio::test]
async fn audit_log_action_timestamp_composite_index_exists() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    let names = audit_log_index_names(&database).await;
    assert!(
        names.iter().any(|n| n == "idx_ts_audit_log_action_ts"),
        "expected idx_ts_audit_log_action_ts, found: {names:?}"
    );
}

#[tokio::test]
async fn audit_log_agent_id_timestamp_expression_index_exists() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    let names = audit_log_index_names(&database).await;
    assert!(
        names.iter().any(|n| n == "idx_ts_audit_log_agent_id_ts"),
        "expected idx_ts_audit_log_agent_id_ts, found: {names:?}"
    );
}
