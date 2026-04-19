use super::super::super::{SessionActivityQuery, query_session_activity};
use crate::{AuditLogEntry, Database};

#[tokio::test]
async fn query_session_activity_returns_empty_page_for_unknown_activity() {
    let database = Database::connect_in_memory().await.expect("database should initialize");

    // Populate the DB with known-good session activity rows so that a
    // missing early-return (issuing `action_in = []` to SQL) would
    // silently return these rows instead of an empty page.
    for action in ["operator.connect", "operator.disconnect", "operator.chat"] {
        database
            .audit_log()
            .create(&AuditLogEntry {
                id: None,
                actor: "operator".to_owned(),
                action: action.to_owned(),
                target_kind: "operator".to_owned(),
                target_id: None,
                details: None,
                occurred_at: "2026-03-10T12:00:00Z".to_owned(),
            })
            .await
            .expect("seed row should insert");
    }

    let query = SessionActivityQuery {
        activity: Some("hack".to_owned()),
        ..SessionActivityQuery::default()
    };

    let page = query_session_activity(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 0, "unrecognized activity should yield zero total");
    assert!(page.items.is_empty(), "unrecognized activity should yield no items");
}

#[tokio::test]
async fn query_session_activity_includes_session_timeout_and_permission_denied_events() {
    let database = Database::connect_in_memory().await.expect("database should initialize");

    for action in [
        "operator.connect",
        "operator.disconnect",
        "operator.chat",
        "operator.session_timeout",
        "operator.permission_denied",
    ] {
        database
            .audit_log()
            .create(&AuditLogEntry {
                id: None,
                actor: "operator".to_owned(),
                action: action.to_owned(),
                target_kind: "operator".to_owned(),
                target_id: None,
                details: None,
                occurred_at: "2026-03-10T12:00:00Z".to_owned(),
            })
            .await
            .expect("seed row should insert");
    }

    // Querying without an activity filter should return all five event types.
    let page = query_session_activity(&database, &SessionActivityQuery::default())
        .await
        .expect("query should succeed");
    assert_eq!(page.total, 5, "all five session activity types should be returned");

    // Filtering by the new activity types should return exactly one record each.
    for activity in ["session_timeout", "permission_denied"] {
        let q = SessionActivityQuery {
            activity: Some(activity.to_owned()),
            ..SessionActivityQuery::default()
        };
        let p = query_session_activity(&database, &q).await.expect("query should succeed");
        assert_eq!(p.total, 1, "filtering by `{activity}` should return exactly one record");
        assert_eq!(p.items[0].activity, activity);
    }
}

#[tokio::test]
async fn query_session_activity_connect_filter_returns_only_connect_entries() {
    let database = Database::connect_in_memory().await.expect("database should initialize");

    for action in ["operator.connect", "operator.connect", "operator.chat"] {
        database
            .audit_log()
            .create(&AuditLogEntry {
                id: None,
                actor: "operator".to_owned(),
                action: action.to_owned(),
                target_kind: "operator".to_owned(),
                target_id: None,
                details: None,
                occurred_at: "2026-03-10T12:00:00Z".to_owned(),
            })
            .await
            .expect("seed row should insert");
    }

    let query = SessionActivityQuery {
        activity: Some("connect".to_owned()),
        ..SessionActivityQuery::default()
    };
    let page = query_session_activity(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 2, "connect filter should return 2 connect entries");
    assert!(
        page.items.iter().all(|r| r.activity == "connect"),
        "all returned items must have activity=connect"
    );
}

#[tokio::test]
async fn query_session_activity_chat_filter_excludes_connect_entries() {
    let database = Database::connect_in_memory().await.expect("database should initialize");

    for action in ["operator.connect", "operator.chat", "operator.chat"] {
        database
            .audit_log()
            .create(&AuditLogEntry {
                id: None,
                actor: "operator".to_owned(),
                action: action.to_owned(),
                target_kind: "operator".to_owned(),
                target_id: None,
                details: None,
                occurred_at: "2026-03-10T12:00:00Z".to_owned(),
            })
            .await
            .expect("seed row should insert");
    }

    let query = SessionActivityQuery {
        activity: Some("chat".to_owned()),
        ..SessionActivityQuery::default()
    };
    let page = query_session_activity(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 2, "chat filter should return 2 chat entries");
    assert!(
        page.items.iter().all(|r| r.activity == "chat"),
        "connect entries must be excluded by chat filter"
    );
}

#[tokio::test]
async fn query_session_activity_nonexistent_action_triggers_empty_set_guard() {
    let database = Database::connect_in_memory().await.expect("database should initialize");

    for action in ["operator.connect", "operator.chat"] {
        database
            .audit_log()
            .create(&AuditLogEntry {
                id: None,
                actor: "operator".to_owned(),
                action: action.to_owned(),
                target_kind: "operator".to_owned(),
                target_id: None,
                details: None,
                occurred_at: "2026-03-10T12:00:00Z".to_owned(),
            })
            .await
            .expect("seed row should insert");
    }

    let query = SessionActivityQuery {
        activity: Some("totally_unknown_action".to_owned()),
        ..SessionActivityQuery::default()
    };
    let page = query_session_activity(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 0, "unrecognized activity name must return 0 results");
    assert!(page.items.is_empty());
}

#[tokio::test]
async fn query_session_activity_no_filter_includes_all_five_event_types() {
    let database = Database::connect_in_memory().await.expect("database should initialize");

    for action in [
        "operator.connect",
        "operator.disconnect",
        "operator.chat",
        "operator.session_timeout",
        "operator.permission_denied",
    ] {
        database
            .audit_log()
            .create(&AuditLogEntry {
                id: None,
                actor: "operator".to_owned(),
                action: action.to_owned(),
                target_kind: "operator".to_owned(),
                target_id: None,
                details: None,
                occurred_at: "2026-03-10T12:00:00Z".to_owned(),
            })
            .await
            .expect("seed row should insert");
    }

    let page = query_session_activity(&database, &SessionActivityQuery::default())
        .await
        .expect("query should succeed");

    assert_eq!(page.total, 5, "no filter should return all 5 session event types");

    let activities: Vec<&str> = page.items.iter().map(|r| r.activity.as_str()).collect();
    for expected in ["connect", "disconnect", "chat", "session_timeout", "permission_denied"] {
        assert!(
            activities.contains(&expected),
            "activity={expected} must appear in unfiltered result set"
        );
    }
}
