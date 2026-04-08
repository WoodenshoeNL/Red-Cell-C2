use red_cell::database::{AuditLogEntry, AuditLogFilter, Database, TeamserverError};
use red_cell::{
    AuditQuery, AuditResultStatus, SessionActivityQuery, audit_details, query_audit_log,
    query_session_activity, record_operator_action,
};
use serde_json::json;

#[path = "database_common.rs"]
mod database_common;
use database_common::test_database;

// ---------------------------------------------------------------------------
// Audit & session-activity pagination boundary conditions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn audit_log_repository_supports_insert_query_and_delete() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let audit = database.audit_log();
    let entry = AuditLogEntry {
        id: None,
        actor: "neo".to_owned(),
        action: "listener.create".to_owned(),
        target_kind: "listener".to_owned(),
        target_id: Some("http-main".to_owned()),
        details: Some(json!({ "protocol": "http" })),
        occurred_at: "2026-03-09T19:15:00Z".to_owned(),
    };

    let id = audit.create(&entry).await?;
    let stored = audit.get(id).await?.expect("audit row should exist");
    assert_eq!(stored.id, Some(id));
    assert_eq!(audit.list().await?, vec![stored.clone()]);

    audit.delete(id).await?;
    assert!(audit.get(id).await?.is_none());

    Ok(())
}

#[tokio::test]
async fn audit_helpers_persist_and_filter_structured_records() -> Result<(), TeamserverError> {
    let database = test_database().await?;

    record_operator_action(
        &database,
        "neo",
        "agent.task",
        "agent",
        Some("DEADBEEF".to_owned()),
        audit_details(
            AuditResultStatus::Success,
            Some(0xDEAD_BEEF),
            Some("checkin"),
            Some(json!({ "task_id": "2A" })),
        ),
    )
    .await?;
    record_operator_action(
        &database,
        "neo",
        "listener.start",
        "listener",
        Some("http-main".to_owned()),
        audit_details(
            AuditResultStatus::Failure,
            None,
            Some("start"),
            Some(json!({ "error": "bind failed" })),
        ),
    )
    .await?;

    let page = query_audit_log(
        &database,
        &AuditQuery {
            action: Some("agent.task".to_owned()),
            agent_id: Some("DEADBEEF".to_owned()),
            result_status: Some(AuditResultStatus::Success),
            limit: Some(10),
            offset: Some(0),
            ..AuditQuery::default()
        },
    )
    .await?;

    assert_eq!(page.total, 1);
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].actor, "neo");
    assert_eq!(page.items[0].command.as_deref(), Some("checkin"));
    assert_eq!(page.items[0].agent_id.as_deref(), Some("DEADBEEF"));
    assert_eq!(page.items[0].result_status, AuditResultStatus::Success);

    Ok(())
}

#[tokio::test]
async fn audit_query_filtered_pushes_pagination_to_sql() -> Result<(), TeamserverError> {
    let database = test_database().await?;

    for i in 0..5 {
        let ts = format!("2026-03-10T10:{i:02}:00Z");
        database
            .audit_log()
            .create(&AuditLogEntry {
                id: None,
                actor: "neo".to_owned(),
                action: format!("action.{i}"),
                target_kind: "agent".to_owned(),
                target_id: None,
                details: Some(
                    serde_json::to_value(audit_details(
                        AuditResultStatus::Success,
                        None,
                        None,
                        None,
                    ))
                    .map_err(TeamserverError::Json)?,
                ),
                occurred_at: ts,
            })
            .await?;
    }

    let page = query_audit_log(
        &database,
        &AuditQuery { limit: Some(2), offset: Some(1), ..AuditQuery::default() },
    )
    .await?;

    assert_eq!(page.total, 5);
    assert_eq!(page.items.len(), 2);
    assert_eq!(page.items[0].action, "action.3");
    assert_eq!(page.items[1].action, "action.2");

    Ok(())
}

#[tokio::test]
async fn audit_query_filtered_applies_timestamp_range() -> Result<(), TeamserverError> {
    let database = test_database().await?;

    for i in 0..3 {
        let ts = format!("2026-03-1{i}T12:00:00Z");
        database
            .audit_log()
            .create(&AuditLogEntry {
                id: None,
                actor: "morpheus".to_owned(),
                action: "check".to_owned(),
                target_kind: "system".to_owned(),
                target_id: None,
                details: None,
                occurred_at: ts,
            })
            .await?;
    }

    let page = query_audit_log(
        &database,
        &AuditQuery {
            since: Some("2026-03-11T00:00:00Z".to_owned()),
            until: Some("2026-03-11T23:59:59Z".to_owned()),
            ..AuditQuery::default()
        },
    )
    .await?;

    assert_eq!(page.total, 1);
    assert_eq!(page.items[0].occurred_at, "2026-03-11T12:00:00Z");

    Ok(())
}

#[tokio::test]
async fn audit_repository_count_filtered_matches_query_filtered_length()
-> Result<(), TeamserverError> {
    let database = test_database().await?;

    record_operator_action(
        &database,
        "trinity",
        "agent.task",
        "agent",
        Some("CAFEBABE".to_owned()),
        audit_details(AuditResultStatus::Success, Some(0xCAFE_BABE), Some("ls"), None),
    )
    .await?;
    record_operator_action(
        &database,
        "trinity",
        "listener.create",
        "listener",
        Some("https-main".to_owned()),
        audit_details(AuditResultStatus::Failure, None, Some("create"), None),
    )
    .await?;
    record_operator_action(
        &database,
        "neo",
        "agent.task",
        "agent",
        Some("DEADBEEF".to_owned()),
        audit_details(AuditResultStatus::Success, Some(0xDEAD_BEEF), Some("pwd"), None),
    )
    .await?;

    let filter = AuditLogFilter {
        actor_contains: Some("trinity".to_owned()),
        result_status: Some("success".to_owned()),
        ..AuditLogFilter::default()
    };

    let repo = database.audit_log();
    let count = repo.count_filtered(&filter).await?;
    let rows = repo.query_filtered(&filter, 100, 0).await?;

    assert_eq!(count, 1);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].actor, "trinity");
    assert_eq!(rows[0].action, "agent.task");

    Ok(())
}

#[tokio::test]
async fn audit_query_filtered_supports_json_field_filters() -> Result<(), TeamserverError> {
    let database = test_database().await?;

    record_operator_action(
        &database,
        "neo",
        "agent.task",
        "agent",
        Some("DEADBEEF".to_owned()),
        audit_details(AuditResultStatus::Success, Some(0xDEAD_BEEF), Some("checkin"), None),
    )
    .await?;
    record_operator_action(
        &database,
        "neo",
        "agent.task",
        "agent",
        Some("CAFEBABE".to_owned()),
        audit_details(AuditResultStatus::Failure, Some(0xCAFE_BABE), Some("shell"), None),
    )
    .await?;

    let page = query_audit_log(
        &database,
        &AuditQuery { command: Some("shell".to_owned()), ..AuditQuery::default() },
    )
    .await?;
    assert_eq!(page.total, 1);
    assert_eq!(page.items[0].command.as_deref(), Some("shell"));

    let page = query_audit_log(
        &database,
        &AuditQuery { agent_id: Some("0xCAFEBABE".to_owned()), ..AuditQuery::default() },
    )
    .await?;
    assert_eq!(page.total, 1);
    assert_eq!(page.items[0].agent_id.as_deref(), Some("CAFEBABE"));

    let page = query_audit_log(
        &database,
        &AuditQuery { result_status: Some(AuditResultStatus::Failure), ..AuditQuery::default() },
    )
    .await?;
    assert_eq!(page.total, 1);
    assert_eq!(page.items[0].result_status, AuditResultStatus::Failure);

    Ok(())
}

#[tokio::test]
async fn session_activity_query_returns_only_operator_session_events() -> Result<(), TeamserverError>
{
    let database = test_database().await?;

    record_operator_action(
        &database,
        "neo",
        "operator.connect",
        "operator",
        Some("neo".to_owned()),
        audit_details(AuditResultStatus::Success, None, Some("connect"), None),
    )
    .await?;
    record_operator_action(
        &database,
        "neo",
        "operator.chat",
        "operator",
        Some("neo".to_owned()),
        audit_details(
            AuditResultStatus::Success,
            None,
            Some("chat"),
            Some(json!({"message":"hello team"})),
        ),
    )
    .await?;
    record_operator_action(
        &database,
        "neo",
        "operator.create",
        "operator",
        Some("trinity".to_owned()),
        audit_details(AuditResultStatus::Success, None, Some("create"), None),
    )
    .await?;

    let page = query_session_activity(
        &database,
        &SessionActivityQuery {
            operator: Some("neo".to_owned()),
            ..SessionActivityQuery::default()
        },
    )
    .await?;

    assert_eq!(page.total, 2);
    assert_eq!(page.items.len(), 2);
    assert_eq!(page.items[0].activity, "chat");
    assert_eq!(page.items[1].activity, "connect");

    Ok(())
}

#[tokio::test]
async fn audit_repository_tracks_latest_session_activity_per_operator()
-> Result<(), TeamserverError> {
    let database = test_database().await?;

    database
        .audit_log()
        .create(&AuditLogEntry {
            id: None,
            actor: "neo".to_owned(),
            action: "operator.connect".to_owned(),
            target_kind: "operator".to_owned(),
            target_id: Some("neo".to_owned()),
            details: None,
            occurred_at: "2026-03-10T08:00:00Z".to_owned(),
        })
        .await?;
    database
        .audit_log()
        .create(&AuditLogEntry {
            id: None,
            actor: "neo".to_owned(),
            action: "operator.chat".to_owned(),
            target_kind: "operator".to_owned(),
            target_id: Some("neo".to_owned()),
            details: None,
            occurred_at: "2026-03-10T09:00:00Z".to_owned(),
        })
        .await?;
    database
        .audit_log()
        .create(&AuditLogEntry {
            id: None,
            actor: "trinity".to_owned(),
            action: "operator.disconnect".to_owned(),
            target_kind: "operator".to_owned(),
            target_id: Some("trinity".to_owned()),
            details: None,
            occurred_at: "2026-03-10T10:00:00Z".to_owned(),
        })
        .await?;

    let latest = database
        .audit_log()
        .latest_timestamps_by_actor_for_actions(&[
            "operator.connect",
            "operator.disconnect",
            "operator.chat",
        ])
        .await?;

    assert_eq!(latest.get("neo").map(String::as_str), Some("2026-03-10T09:00:00Z"));
    assert_eq!(latest.get("trinity").map(String::as_str), Some("2026-03-10T10:00:00Z"));

    Ok(())
}

#[tokio::test]
async fn audit_latest_timestamps_returns_empty_map_for_empty_actions_slice()
-> Result<(), TeamserverError> {
    let database = test_database().await?;

    // Insert a row so the DB is not empty — the early-return must fire before any DB round-trip.
    database
        .audit_log()
        .create(&AuditLogEntry {
            id: None,
            actor: "neo".to_owned(),
            action: "operator.connect".to_owned(),
            target_kind: "operator".to_owned(),
            target_id: Some("neo".to_owned()),
            details: None,
            occurred_at: "2026-03-10T08:00:00Z".to_owned(),
        })
        .await?;

    let result = database.audit_log().latest_timestamps_by_actor_for_actions(&[]).await?;

    assert!(result.is_empty(), "empty actions slice must return an empty BTreeMap immediately");

    Ok(())
}

#[tokio::test]
async fn audit_latest_timestamps_returns_only_most_recent_for_single_actor()
-> Result<(), TeamserverError> {
    let database = test_database().await?;
    let audit = database.audit_log();

    // Three rows for the same actor and action — timestamps are deliberately out-of-order.
    for occurred_at in &["2026-03-10T07:00:00Z", "2026-03-10T09:00:00Z", "2026-03-10T08:00:00Z"] {
        audit
            .create(&AuditLogEntry {
                id: None,
                actor: "neo".to_owned(),
                action: "operator.connect".to_owned(),
                target_kind: "operator".to_owned(),
                target_id: Some("neo".to_owned()),
                details: None,
                occurred_at: (*occurred_at).to_owned(),
            })
            .await?;
    }

    let result = audit.latest_timestamps_by_actor_for_actions(&["operator.connect"]).await?;

    assert_eq!(result.len(), 1, "only one actor should appear");
    assert_eq!(
        result.get("neo").map(String::as_str),
        Some("2026-03-10T09:00:00Z"),
        "MAX(occurred_at) must be returned, not the first-inserted timestamp"
    );

    Ok(())
}

/// Helper: insert `count` audit log entries with distinct actions.
async fn insert_audit_entries(database: &Database, count: usize) -> Result<(), TeamserverError> {
    for i in 0..count {
        database
            .audit_log()
            .create(&AuditLogEntry {
                id: None,
                actor: format!("op-{}", i % 3),
                action: format!("test.action.{i}"),
                target_kind: "system".to_owned(),
                target_id: None,
                details: Some(
                    serde_json::to_value(audit_details(
                        AuditResultStatus::Success,
                        None,
                        None,
                        None,
                    ))
                    .map_err(TeamserverError::Json)?,
                ),
                occurred_at: format!("2026-03-10T10:{:02}:{:02}Z", i / 60, i % 60),
            })
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn audit_query_offset_beyond_total_returns_empty() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    insert_audit_entries(&database, 5).await?;

    let page = query_audit_log(
        &database,
        &AuditQuery { limit: Some(10), offset: Some(100), ..AuditQuery::default() },
    )
    .await?;

    assert_eq!(page.total, 5, "total should reflect all matching rows");
    assert!(page.items.is_empty(), "offset past total should yield no items");
    assert_eq!(page.offset, 100);

    Ok(())
}

#[tokio::test]
async fn audit_query_limit_zero_clamps_to_one() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    insert_audit_entries(&database, 5).await?;

    let page =
        query_audit_log(&database, &AuditQuery { limit: Some(0), ..AuditQuery::default() }).await?;

    // AuditQuery::limit() clamps to 1..=200, so limit=0 → 1.
    assert_eq!(page.limit, 1);
    assert_eq!(page.items.len(), 1, "clamped limit should return exactly 1 item");
    assert_eq!(page.total, 5);

    Ok(())
}

#[tokio::test]
async fn audit_query_large_offset_returns_empty() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    insert_audit_entries(&database, 3).await?;

    // Use a very large offset that still fits in i64.
    let large_offset: usize = i64::MAX as usize;

    let page = query_audit_log(
        &database,
        &AuditQuery { offset: Some(large_offset), ..AuditQuery::default() },
    )
    .await?;

    assert_eq!(page.total, 3);
    assert!(page.items.is_empty());

    Ok(())
}

#[tokio::test]
async fn audit_query_combined_filters_with_pagination() -> Result<(), TeamserverError> {
    let database = test_database().await?;

    // Insert 10 entries, alternating between two actors and two actions.
    for i in 0..10 {
        let actor = if i % 2 == 0 { "alice" } else { "bob" };
        let action = if i < 5 { "deploy.start" } else { "deploy.finish" };
        database
            .audit_log()
            .create(&AuditLogEntry {
                id: None,
                actor: actor.to_owned(),
                action: action.to_owned(),
                target_kind: "service".to_owned(),
                target_id: None,
                details: Some(
                    serde_json::to_value(audit_details(
                        AuditResultStatus::Success,
                        None,
                        None,
                        None,
                    ))
                    .map_err(TeamserverError::Json)?,
                ),
                occurred_at: format!("2026-03-10T10:00:{i:02}Z"),
            })
            .await?;
    }

    // Filter: actor=alice AND action=deploy.start, with limit=2 offset=1.
    let page = query_audit_log(
        &database,
        &AuditQuery {
            actor: Some("alice".to_owned()),
            action: Some("deploy.start".to_owned()),
            limit: Some(2),
            offset: Some(1),
            ..AuditQuery::default()
        },
    )
    .await?;

    // alice + deploy.start = indices 0, 2, 4 → 3 entries total.
    assert_eq!(page.total, 3, "should match alice+deploy.start entries");
    assert_eq!(page.items.len(), 2, "limit=2 should cap returned items");
    assert_eq!(page.offset, 1);
    for item in &page.items {
        assert_eq!(item.actor, "alice");
        assert_eq!(item.action, "deploy.start");
    }

    // Offset past the filtered total.
    let page = query_audit_log(
        &database,
        &AuditQuery {
            actor: Some("alice".to_owned()),
            action: Some("deploy.start".to_owned()),
            offset: Some(50),
            ..AuditQuery::default()
        },
    )
    .await?;

    assert_eq!(page.total, 3);
    assert!(page.items.is_empty());

    Ok(())
}

/// Helper: insert session activity entries.
async fn insert_session_events(
    database: &Database,
    operator: &str,
    count: usize,
) -> Result<(), TeamserverError> {
    for i in 0..count {
        let action = if i % 2 == 0 { "operator.connect" } else { "operator.disconnect" };
        record_operator_action(
            database,
            operator,
            action,
            "operator",
            Some(operator.to_owned()),
            audit_details(AuditResultStatus::Success, None, None, None),
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn session_activity_offset_beyond_total_returns_empty() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    insert_session_events(&database, "neo", 5).await?;

    let page = query_session_activity(
        &database,
        &SessionActivityQuery {
            operator: Some("neo".to_owned()),
            offset: Some(100),
            ..SessionActivityQuery::default()
        },
    )
    .await?;

    assert_eq!(page.total, 5);
    assert!(page.items.is_empty(), "offset past total should yield no items");

    Ok(())
}

#[tokio::test]
async fn session_activity_limit_zero_clamps_to_one() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    insert_session_events(&database, "neo", 5).await?;

    let page = query_session_activity(
        &database,
        &SessionActivityQuery {
            operator: Some("neo".to_owned()),
            limit: Some(0),
            ..SessionActivityQuery::default()
        },
    )
    .await?;

    assert_eq!(page.limit, 1);
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.total, 5);

    Ok(())
}

#[tokio::test]
async fn session_activity_large_offset_returns_empty() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    insert_session_events(&database, "neo", 3).await?;

    let large_offset: usize = i64::MAX as usize;

    let page = query_session_activity(
        &database,
        &SessionActivityQuery {
            operator: Some("neo".to_owned()),
            offset: Some(large_offset),
            ..SessionActivityQuery::default()
        },
    )
    .await?;

    assert_eq!(page.total, 3);
    assert!(page.items.is_empty());

    Ok(())
}

#[tokio::test]
async fn session_activity_combined_activity_filter_with_pagination() -> Result<(), TeamserverError>
{
    let database = test_database().await?;

    // Insert 6 events (3 connect, 3 disconnect) for "neo".
    insert_session_events(&database, "neo", 6).await?;
    // Insert 2 events for "trinity" (should not appear in neo's results).
    insert_session_events(&database, "trinity", 2).await?;

    let page = query_session_activity(
        &database,
        &SessionActivityQuery {
            operator: Some("neo".to_owned()),
            activity: Some("connect".to_owned()),
            limit: Some(2),
            offset: Some(1),
            ..SessionActivityQuery::default()
        },
    )
    .await?;

    // neo has 3 connect events.
    assert_eq!(page.total, 3, "should match only neo's connect events");
    assert_eq!(page.items.len(), 2, "limit=2 should cap returned items");
    for item in &page.items {
        assert_eq!(item.operator, "neo");
        assert_eq!(item.activity, "connect");
    }

    // Offset past the filtered total.
    let page = query_session_activity(
        &database,
        &SessionActivityQuery {
            operator: Some("neo".to_owned()),
            activity: Some("connect".to_owned()),
            offset: Some(50),
            ..SessionActivityQuery::default()
        },
    )
    .await?;

    assert_eq!(page.total, 3);
    assert!(page.items.is_empty());

    Ok(())
}

#[tokio::test]
async fn audit_log_insert_after_pool_close_returns_connection_error() -> Result<(), TeamserverError>
{
    let database = test_database().await?;
    let audit = database.audit_log();

    let entry = AuditLogEntry {
        id: None,
        actor: "operator".to_owned(),
        action: "test_action".to_owned(),
        target_kind: "agent".to_owned(),
        target_id: Some("0x1234".to_owned()),
        details: None,
        occurred_at: "2026-03-20T12:00:00Z".to_owned(),
    };

    audit.create(&entry).await?;
    database.close().await;

    let err = audit.create(&entry).await.expect_err("audit insert after close should fail");
    assert!(matches!(err, TeamserverError::Database(_)));

    Ok(())
}
