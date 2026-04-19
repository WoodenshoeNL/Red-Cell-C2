use super::super::super::{
    AuditQuery, AuditResultStatus, SessionActivityQuery, query_audit_log, query_session_activity,
};
use super::seed_diverse_audit_rows;
use crate::{Database, TeamserverError};

#[test]
fn query_validates_limit_and_offset_defaults() {
    let query = AuditQuery::default();
    assert_eq!(query.limit(), 50);
    assert_eq!(query.offset(), 0);

    let clamped = AuditQuery { limit: Some(500), offset: Some(4), ..AuditQuery::default() };
    assert_eq!(clamped.limit(), 200);
    assert_eq!(clamped.offset(), 4);
}

#[test]
fn session_activity_query_default_limit_and_offset() {
    let q = SessionActivityQuery { limit: None, offset: None, ..Default::default() };
    assert_eq!(q.limit(), 50);
    assert_eq!(q.offset(), 0);
}

#[test]
fn session_activity_query_oversized_limit_is_clamped() {
    let q = SessionActivityQuery { limit: Some(9999), ..Default::default() };
    assert_eq!(q.limit(), 200);
}

#[test]
fn session_activity_query_explicit_small_limit_and_nonzero_offset_are_preserved() {
    let q = SessionActivityQuery { limit: Some(10), offset: Some(25), ..Default::default() };
    assert_eq!(q.limit(), 10);
    assert_eq!(q.offset(), 25);
}

#[test]
fn session_activity_query_validates_limit_and_offset_defaults() {
    let query = SessionActivityQuery::default();
    assert_eq!(query.limit(), 50);
    assert_eq!(query.offset(), 0);

    let clamped = SessionActivityQuery {
        limit: Some(500),
        offset: Some(7),
        ..SessionActivityQuery::default()
    };
    assert_eq!(clamped.limit(), 200);
    assert_eq!(clamped.offset(), 7);
}

#[tokio::test]
async fn query_audit_log_newest_first_ordering() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_diverse_audit_rows(&database).await;

    let query = AuditQuery::default();
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 10);
    // Verify strict descending order by occurred_at
    for window in page.items.windows(2) {
        assert!(
            window[0].occurred_at >= window[1].occurred_at,
            "results must be ordered newest-to-oldest, but {} came before {}",
            window[0].occurred_at,
            window[1].occurred_at
        );
    }
}

#[tokio::test]
async fn query_audit_log_pagination_preserves_newest_first_across_pages() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_diverse_audit_rows(&database).await;

    // Page 1: first 3 rows
    let page1_query = AuditQuery { limit: Some(3), offset: Some(0), ..AuditQuery::default() };
    let page1 = query_audit_log(&database, &page1_query).await.expect("page 1 should succeed");

    // Page 2: next 3 rows
    let page2_query = AuditQuery { limit: Some(3), offset: Some(3), ..AuditQuery::default() };
    let page2 = query_audit_log(&database, &page2_query).await.expect("page 2 should succeed");

    // Page 3: next 3 rows
    let page3_query = AuditQuery { limit: Some(3), offset: Some(6), ..AuditQuery::default() };
    let page3 = query_audit_log(&database, &page3_query).await.expect("page 3 should succeed");

    // Page 4: last row
    let page4_query = AuditQuery { limit: Some(3), offset: Some(9), ..AuditQuery::default() };
    let page4 = query_audit_log(&database, &page4_query).await.expect("page 4 should succeed");

    // All pages report the same total
    assert_eq!(page1.total, 10);
    assert_eq!(page2.total, 10);
    assert_eq!(page3.total, 10);
    assert_eq!(page4.total, 10);

    // Page sizes correct
    assert_eq!(page1.items.len(), 3);
    assert_eq!(page2.items.len(), 3);
    assert_eq!(page3.items.len(), 3);
    assert_eq!(page4.items.len(), 1);

    // Concatenate all pages and verify global ordering
    let mut all_timestamps: Vec<String> = Vec::new();
    for page in [&page1, &page2, &page3, &page4] {
        for item in &page.items {
            all_timestamps.push(item.occurred_at.clone());
        }
    }
    for window in all_timestamps.windows(2) {
        assert!(
            window[0] >= window[1],
            "cross-page ordering must be newest-first: {} came before {}",
            window[0],
            window[1]
        );
    }

    // The last item on page 1 must be newer-or-equal to the first item on page 2
    assert!(
        page1.items.last().expect("page1 non-empty").occurred_at
            >= page2.items.first().expect("page2 non-empty").occurred_at,
        "page boundary must preserve newest-first ordering"
    );
}

#[tokio::test]
async fn query_audit_log_rejects_offset_exceeding_i64() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    let overflowing_offset = (i64::MAX as usize).saturating_add(1);
    let query = AuditQuery { offset: Some(overflowing_offset), ..AuditQuery::default() };
    let error = query_audit_log(&database, &query)
        .await
        .expect_err("offset exceeding i64 should be rejected");
    match error {
        TeamserverError::InvalidPersistedValue { field, message } => {
            assert_eq!(field, "offset");
            assert!(
                message.contains("i64"),
                "error message should mention i64 range, got: {message}"
            );
        }
        other => panic!("expected InvalidPersistedValue for offset, got: {other:?}"),
    }
}

#[tokio::test]
async fn query_session_activity_rejects_offset_exceeding_i64() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    let overflowing_offset = (i64::MAX as usize).saturating_add(1);
    let query = SessionActivityQuery {
        offset: Some(overflowing_offset),
        ..SessionActivityQuery::default()
    };
    let error = query_session_activity(&database, &query)
        .await
        .expect_err("offset exceeding i64 should be rejected");
    match error {
        TeamserverError::InvalidPersistedValue { field, message } => {
            assert_eq!(field, "offset");
            assert!(
                message.contains("i64"),
                "error message should mention i64 range, got: {message}"
            );
        }
        other => panic!("expected InvalidPersistedValue for offset, got: {other:?}"),
    }
}

#[tokio::test]
async fn query_audit_log_result_status_filter_with_empty_page() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_diverse_audit_rows(&database).await;

    // Request a page past the end — offset beyond total should return empty items but correct total
    let query = AuditQuery {
        result_status: Some(AuditResultStatus::Failure),
        limit: Some(10),
        offset: Some(1000),
        ..AuditQuery::default()
    };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 4, "total should reflect all matching rows regardless of offset");
    assert!(page.items.is_empty(), "items must be empty past end of result set");
}

#[tokio::test]
async fn query_audit_log_single_item_page() {
    let database = Database::connect_in_memory().await.expect("database should initialize");

    database
        .audit_log()
        .create(&crate::AuditLogEntry {
            id: None,
            actor: "alice".to_owned(),
            action: "agent.task".to_owned(),
            target_kind: "agent".to_owned(),
            target_id: None,
            details: None,
            occurred_at: "2026-03-01T00:00:00Z".to_owned(),
        })
        .await
        .expect("row should insert");

    let query = AuditQuery { limit: Some(1), offset: Some(0), ..AuditQuery::default() };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 1);
    assert_eq!(page.items.len(), 1);

    // Page 2 must be empty
    let query2 = AuditQuery { limit: Some(1), offset: Some(1), ..AuditQuery::default() };
    let page2 = query_audit_log(&database, &query2).await.expect("query should succeed");
    assert_eq!(page2.total, 1, "total must still report 1 on the empty trailing page");
    assert!(page2.items.is_empty(), "second page must be empty when only 1 row exists");
}
