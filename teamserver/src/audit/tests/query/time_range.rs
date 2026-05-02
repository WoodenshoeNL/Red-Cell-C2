use super::super::super::{
    AuditQuery, SessionActivityQuery, query_audit_log, query_session_activity,
};
use super::{seed_diverse_audit_rows, seed_timestamped_audit_rows};
use crate::{AuditLogEntry, AuditResultStatus, Database, audit_details};

#[tokio::test]
async fn query_audit_log_since_filter_excludes_older_rows() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_timestamped_audit_rows(&database).await;

    // since = Jan 20 at 16:00 UTC — should include rows at Jan 20, Jan 25, Jan 30
    let query =
        AuditQuery { since: Some("2026-01-20T16:00:00Z".to_owned()), ..AuditQuery::default() };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 3, "since filter should include 3 rows at or after the cutoff");
    assert!(
        page.items.iter().all(|r| r.occurred_at.as_str() >= "2026-01-20T16:00:00Z"),
        "all returned rows must be at or after the since timestamp"
    );
}

#[tokio::test]
async fn query_audit_log_until_filter_excludes_newer_rows() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_timestamped_audit_rows(&database).await;

    // until = Jan 15 at 12:00 UTC — should include rows at Jan 10 and Jan 15
    let query =
        AuditQuery { until: Some("2026-01-15T12:00:00Z".to_owned()), ..AuditQuery::default() };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 2, "until filter should include 2 rows at or before the cutoff");
    assert!(
        page.items.iter().all(|r| r.occurred_at.as_str() <= "2026-01-15T12:00:00Z"),
        "all returned rows must be at or before the until timestamp"
    );
}

#[tokio::test]
async fn query_audit_log_since_and_until_combined_returns_window() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_timestamped_audit_rows(&database).await;

    // Window: Jan 15 through Jan 25 — should include rows at Jan 15, Jan 20, Jan 25
    let query = AuditQuery {
        since: Some("2026-01-15T12:00:00Z".to_owned()),
        until: Some("2026-01-25T20:00:00Z".to_owned()),
        ..AuditQuery::default()
    };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 3, "combined since/until should return 3 rows in window");
    assert!(
        page.items.iter().all(|r| {
            r.occurred_at.as_str() >= "2026-01-15T12:00:00Z"
                && r.occurred_at.as_str() <= "2026-01-25T20:00:00Z"
        }),
        "all rows must fall within the since/until window"
    );
}

#[tokio::test]
async fn query_audit_log_since_filter_normalizes_non_utc_offset() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_timestamped_audit_rows(&database).await;

    // "+02:00" offset — 2026-01-20T18:00:00+02:00 == 2026-01-20T16:00:00Z
    let query =
        AuditQuery { since: Some("2026-01-20T18:00:00+02:00".to_owned()), ..AuditQuery::default() };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 3, "non-UTC offset should normalize to UTC before filtering");
}

#[tokio::test]
async fn query_audit_log_until_filter_normalizes_non_utc_offset() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_timestamped_audit_rows(&database).await;

    // "+02:00" offset — 2026-01-15T14:00:00+02:00 == 2026-01-15T12:00:00Z
    let query =
        AuditQuery { until: Some("2026-01-15T14:00:00+02:00".to_owned()), ..AuditQuery::default() };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 2, "non-UTC until offset should normalize to UTC before filtering");
}

#[tokio::test]
async fn query_audit_log_since_after_all_rows_returns_empty() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_timestamped_audit_rows(&database).await;

    let query =
        AuditQuery { since: Some("2027-01-01T00:00:00Z".to_owned()), ..AuditQuery::default() };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 0, "since after all rows should return nothing");
    assert!(page.items.is_empty());
}

#[tokio::test]
async fn query_audit_log_until_before_all_rows_returns_empty() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_timestamped_audit_rows(&database).await;

    let query =
        AuditQuery { until: Some("2025-01-01T00:00:00Z".to_owned()), ..AuditQuery::default() };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 0, "until before all rows should return nothing");
    assert!(page.items.is_empty());
}

#[tokio::test]
async fn query_audit_log_time_window_with_filter_intersects() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_diverse_audit_rows(&database).await;

    // Window Feb 3 through Feb 7 + target_kind=agent → rows 3, 4, 6
    let query = AuditQuery {
        since: Some("2026-02-03T00:00:00Z".to_owned()),
        until: Some("2026-02-07T00:00:00Z".to_owned()),
        target_kind: Some("agent".to_owned()),
        ..AuditQuery::default()
    };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 3, "time window + target_kind=agent should yield 3 rows");
    assert!(
        page.items.iter().all(|r| r.target_kind == "agent"),
        "all returned rows must have target_kind=agent"
    );
    assert!(
        page.items.iter().all(|r| {
            r.occurred_at.as_str() >= "2026-02-03T00:00:00Z"
                && r.occurred_at.as_str() <= "2026-02-07T00:00:00Z"
        }),
        "all returned rows must fall within the time window"
    );
}

#[tokio::test]
async fn query_audit_log_since_boundary_is_inclusive() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_timestamped_audit_rows(&database).await;

    // since == exact timestamp of a row — that row must be included
    let query =
        AuditQuery { since: Some("2026-01-20T16:00:00Z".to_owned()), ..AuditQuery::default() };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert!(
        page.items.iter().any(|r| r.occurred_at == "2026-01-20T16:00:00Z"),
        "since boundary must be inclusive — the row at exactly the cutoff must be returned"
    );
}

#[tokio::test]
async fn query_audit_log_until_boundary_is_inclusive() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_timestamped_audit_rows(&database).await;

    // until == exact timestamp of a row — that row must be included
    let query =
        AuditQuery { until: Some("2026-01-15T12:00:00Z".to_owned()), ..AuditQuery::default() };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert!(
        page.items.iter().any(|r| r.occurred_at == "2026-01-15T12:00:00Z"),
        "until boundary must be inclusive — the row at exactly the cutoff must be returned"
    );
}

#[tokio::test]
async fn query_audit_log_offset_timezone_returns_same_items_as_utc() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_timestamped_audit_rows(&database).await;

    // UTC query
    let utc_query = AuditQuery {
        since: Some("2026-01-15T12:00:00Z".to_owned()),
        until: Some("2026-01-25T20:00:00Z".to_owned()),
        ..AuditQuery::default()
    };
    let utc_page = query_audit_log(&database, &utc_query).await.expect("UTC query should succeed");

    // Equivalent +05:30 query
    let offset_query = AuditQuery {
        since: Some("2026-01-15T17:30:00+05:30".to_owned()),
        until: Some("2026-01-26T01:30:00+05:30".to_owned()),
        ..AuditQuery::default()
    };
    let offset_page =
        query_audit_log(&database, &offset_query).await.expect("offset query should succeed");

    assert_eq!(
        utc_page.total, offset_page.total,
        "UTC and offset-equivalent queries must return the same total"
    );
    assert_eq!(
        utc_page.items.len(),
        offset_page.items.len(),
        "UTC and offset-equivalent queries must return the same items"
    );
}

#[tokio::test]
async fn query_audit_log_negative_offset_timezone_normalizes_correctly() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_timestamped_audit_rows(&database).await;

    // -05:00 offset — 2026-01-20T11:00:00-05:00 == 2026-01-20T16:00:00Z
    let query =
        AuditQuery { since: Some("2026-01-20T11:00:00-05:00".to_owned()), ..AuditQuery::default() };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 3, "negative UTC offset should normalize correctly before filtering");
}

#[tokio::test]
async fn query_audit_log_since_until_single_row_boundary() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_timestamped_audit_rows(&database).await;

    // since == until == exact row timestamp — must return exactly that row
    let query = AuditQuery {
        since: Some("2026-01-20T16:00:00Z".to_owned()),
        until: Some("2026-01-20T16:00:00Z".to_owned()),
        ..AuditQuery::default()
    };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 1, "since == until == row timestamp must return exactly that one row");
    assert_eq!(page.items[0].occurred_at, "2026-01-20T16:00:00Z");
}

// ---------------------------------------------------------------
// Invalid timestamp normalization — query_audit_log
// ---------------------------------------------------------------

#[tokio::test]
async fn query_audit_log_invalid_since_is_ignored() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_diverse_audit_rows(&database).await;

    let baseline = query_audit_log(&database, &AuditQuery::default())
        .await
        .expect("baseline query should succeed");

    for bad_ts in ["not-a-date", "2026-13-01", "yesterday", ""] {
        let query = AuditQuery { since: Some(bad_ts.to_owned()), ..AuditQuery::default() };
        let page = query_audit_log(&database, &query)
            .await
            .unwrap_or_else(|e| panic!("query with since={bad_ts:?} should not error: {e}"));
        assert_eq!(
            page.total, baseline.total,
            "invalid since={bad_ts:?} should be ignored, returning all rows"
        );
    }
}

#[tokio::test]
async fn query_audit_log_invalid_until_is_ignored() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_diverse_audit_rows(&database).await;

    let baseline = query_audit_log(&database, &AuditQuery::default())
        .await
        .expect("baseline query should succeed");

    for bad_ts in ["not-a-date", "32/01/2026", "\u{221e}", ""] {
        let query = AuditQuery { until: Some(bad_ts.to_owned()), ..AuditQuery::default() };
        let page = query_audit_log(&database, &query)
            .await
            .unwrap_or_else(|e| panic!("query with until={bad_ts:?} should not error: {e}"));
        assert_eq!(
            page.total, baseline.total,
            "invalid until={bad_ts:?} should be ignored, returning all rows"
        );
    }
}

// ---------------------------------------------------------------
// Invalid timestamp normalization — query_session_activity
// ---------------------------------------------------------------

#[tokio::test]
async fn query_session_activity_invalid_since_is_ignored() {
    let database = Database::connect_in_memory().await.expect("database should initialize");

    for action in ["operator.connect", "operator.disconnect", "operator.chat"] {
        database
            .audit_log()
            .create(&AuditLogEntry {
                id: None,
                actor: "op".to_owned(),
                action: action.to_owned(),
                target_kind: "operator".to_owned(),
                target_id: None,
                details: None,
                occurred_at: "2026-03-10T12:00:00Z".to_owned(),
            })
            .await
            .expect("seed row should insert");
    }

    let baseline = query_session_activity(&database, &SessionActivityQuery::default())
        .await
        .expect("baseline query should succeed");
    assert_eq!(baseline.total, 3, "three seeded session rows expected");

    for bad_ts in ["not-a-date", "yesterday", "2026-99-01", ""] {
        let query = SessionActivityQuery { since: Some(bad_ts.to_owned()), ..Default::default() };
        let page = query_session_activity(&database, &query).await.unwrap_or_else(|e| {
            panic!("session query with since={bad_ts:?} should not error: {e}")
        });
        assert_eq!(
            page.total, baseline.total,
            "invalid since={bad_ts:?} should be ignored for session activity"
        );
    }
}

#[tokio::test]
async fn query_session_activity_invalid_until_is_ignored() {
    let database = Database::connect_in_memory().await.expect("database should initialize");

    for action in ["operator.connect", "operator.disconnect"] {
        database
            .audit_log()
            .create(&AuditLogEntry {
                id: None,
                actor: "op".to_owned(),
                action: action.to_owned(),
                target_kind: "operator".to_owned(),
                target_id: None,
                details: None,
                occurred_at: "2026-03-10T12:00:00Z".to_owned(),
            })
            .await
            .expect("seed row should insert");
    }

    let baseline = query_session_activity(&database, &SessionActivityQuery::default())
        .await
        .expect("baseline query should succeed");
    assert_eq!(baseline.total, 2, "two seeded session rows expected");

    for bad_ts in ["not-a-date", "\u{221e}", "32/01/2026", ""] {
        let query = SessionActivityQuery { until: Some(bad_ts.to_owned()), ..Default::default() };
        let page = query_session_activity(&database, &query).await.unwrap_or_else(|e| {
            panic!("session query with until={bad_ts:?} should not error: {e}")
        });
        assert_eq!(
            page.total, baseline.total,
            "invalid until={bad_ts:?} should be ignored for session activity"
        );
    }
}

#[tokio::test]
async fn query_session_activity_invalid_since_and_until_combined_returns_unfiltered() {
    let database = Database::connect_in_memory().await.expect("database should initialize");

    for action in
        ["operator.connect", "operator.disconnect", "operator.chat", "operator.session_timeout"]
    {
        database
            .audit_log()
            .create(&AuditLogEntry {
                id: None,
                actor: "op".to_owned(),
                action: action.to_owned(),
                target_kind: "operator".to_owned(),
                target_id: None,
                details: None,
                occurred_at: "2026-03-10T12:00:00Z".to_owned(),
            })
            .await
            .expect("seed row should insert");
    }

    let baseline = query_session_activity(&database, &SessionActivityQuery::default())
        .await
        .expect("baseline query should succeed");
    assert_eq!(baseline.total, 4, "four seeded session rows expected");

    let query = SessionActivityQuery {
        since: Some("garbage".to_owned()),
        until: Some("also-garbage".to_owned()),
        ..Default::default()
    };
    let page = query_session_activity(&database, &query)
        .await
        .expect("session query with all invalid timestamps should succeed");
    assert_eq!(
        page.total, baseline.total,
        "invalid since+until should be ignored, returning full session activity set"
    );
}

#[tokio::test]
async fn query_audit_log_since_coarse_includes_fractional_same_second_row() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    let repo = database.audit_log();
    let details = audit_details(AuditResultStatus::Success, None, Some("test"), None);
    repo.create(&AuditLogEntry {
        id: None,
        actor: "op".to_owned(),
        action: "listener.create".to_owned(),
        target_kind: "listener".to_owned(),
        target_id: None,
        details: Some(serde_json::to_value(&details).expect("serialize")),
        occurred_at: "2026-05-02T14:41:54.639287358Z".to_owned(),
    })
    .await
    .expect("seed");

    let query =
        AuditQuery { since: Some("2026-05-02T14:41:54Z".to_owned()), ..AuditQuery::default() };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 1, "fractional occurred_at in same UTC second must match coarse since");
    assert_eq!(page.items[0].action.as_str(), "listener.create");
}
