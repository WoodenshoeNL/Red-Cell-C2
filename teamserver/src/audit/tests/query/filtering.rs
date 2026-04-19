use super::super::super::{AuditQuery, AuditResultStatus, query_audit_log};
use super::{seed_audit_rows, seed_diverse_audit_rows};
use crate::Database;

#[tokio::test]
async fn filtered_query_by_actor_returns_correct_subset_at_scale() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_audit_rows(&database, 500).await;

    let query = AuditQuery { actor: Some("alice".to_owned()), ..AuditQuery::default() };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert!(page.total > 0, "alice rows should be present");
    assert!(page.items.iter().all(|r| r.actor == "alice"), "only alice rows should be returned");
}

#[tokio::test]
async fn filtered_query_by_action_returns_correct_subset_at_scale() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_audit_rows(&database, 500).await;

    let query = AuditQuery { action: Some("agent.task".to_owned()), ..AuditQuery::default() };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert!(page.total > 0, "agent.task rows should be present");
    assert!(
        page.items.iter().all(|r| r.action.contains("agent.task")),
        "only agent.task rows should be returned"
    );
}

#[tokio::test]
async fn filtered_query_by_agent_id_returns_correct_subset_at_scale() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_audit_rows(&database, 500).await;

    let query = AuditQuery { agent_id: Some("DEADBEEF".to_owned()), ..AuditQuery::default() };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert!(page.total > 0, "DEADBEEF rows should be present");
    assert!(
        page.items.iter().all(|r| r.agent_id.as_deref() == Some("DEADBEEF")),
        "only DEADBEEF rows should be returned"
    );
}

#[tokio::test]
async fn actor_filter_operator_takes_precedence_over_actor() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_audit_rows(&database, 100).await;

    // Both `operator` and `actor` are set — `operator` must win.
    let query = AuditQuery {
        operator: Some("alice".to_owned()),
        actor: Some("bob".to_owned()),
        ..AuditQuery::default()
    };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert!(page.total > 0, "alice rows should be present");
    assert!(
        page.items.iter().all(|r| r.actor == "alice"),
        "operator field should take precedence — only alice rows expected, \
         but found: {:?}",
        page.items.iter().map(|r| &r.actor).collect::<Vec<_>>()
    );
    assert!(
        page.items.iter().all(|r| r.actor != "bob"),
        "bob rows must not appear when operator=alice takes precedence"
    );
}

#[tokio::test]
async fn query_audit_log_result_status_filter_narrows_correctly() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_diverse_audit_rows(&database).await;

    let query =
        AuditQuery { result_status: Some(AuditResultStatus::Failure), ..AuditQuery::default() };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    // Rows 3, 5, 8, 10 are failures = 4 total
    assert_eq!(page.total, 4, "exactly 4 failure rows should match");
    assert!(
        page.items.iter().all(|r| r.result_status == AuditResultStatus::Failure),
        "only failure rows should be returned"
    );
}

#[tokio::test]
async fn query_audit_log_target_kind_filter_narrows_correctly() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_diverse_audit_rows(&database).await;

    let query = AuditQuery { target_kind: Some("listener".to_owned()), ..AuditQuery::default() };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    // Rows 2, 5, 9 have target_kind=listener
    assert_eq!(page.total, 3, "exactly 3 listener rows should match");
    assert!(
        page.items.iter().all(|r| r.target_kind == "listener"),
        "only listener rows should be returned"
    );
}

#[tokio::test]
async fn query_audit_log_target_id_filter_narrows_correctly() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_diverse_audit_rows(&database).await;

    let query = AuditQuery { target_id: Some("A1".to_owned()), ..AuditQuery::default() };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    // Rows 1, 4, 8 have target_id=A1
    assert_eq!(page.total, 3, "exactly 3 rows with target_id=A1 should match");
    assert!(
        page.items.iter().all(|r| r.target_id.as_deref() == Some("A1")),
        "only rows with target_id=A1 should be returned"
    );
}

#[tokio::test]
async fn query_audit_log_command_filter_narrows_correctly() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_diverse_audit_rows(&database).await;

    let query = AuditQuery { command: Some("shell".to_owned()), ..AuditQuery::default() };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    // Rows 1, 4, 8 have command=shell
    assert_eq!(page.total, 3, "exactly 3 rows with command=shell should match");
    assert!(
        page.items.iter().all(|r| r.command.as_deref() == Some("shell")),
        "only rows with command=shell should be returned"
    );
}

#[tokio::test]
async fn query_audit_log_operator_alias_behaves_like_actor() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_diverse_audit_rows(&database).await;

    // Query using `operator` field alone — should filter by actor.
    let by_operator = AuditQuery { operator: Some("alice".to_owned()), ..AuditQuery::default() };
    let page_op = query_audit_log(&database, &by_operator).await.expect("query should succeed");

    // Query using `actor` field alone — should produce identical results.
    let by_actor = AuditQuery { actor: Some("alice".to_owned()), ..AuditQuery::default() };
    let page_act = query_audit_log(&database, &by_actor).await.expect("query should succeed");

    assert_eq!(page_op.total, page_act.total, "operator and actor must produce the same total");
    assert_eq!(
        page_op.items.len(),
        page_act.items.len(),
        "operator and actor must return the same number of items"
    );
    assert!(
        page_op.items.iter().all(|r| r.actor == "alice"),
        "operator filter must narrow to alice"
    );
}

#[tokio::test]
async fn query_audit_log_combined_filters_intersect() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_diverse_audit_rows(&database).await;

    // alice + agent.task + failure → only row 3
    let query = AuditQuery {
        actor: Some("alice".to_owned()),
        action: Some("agent.task".to_owned()),
        result_status: Some(AuditResultStatus::Failure),
        ..AuditQuery::default()
    };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 1, "combined filters should yield exactly 1 row");
    assert_eq!(page.items[0].actor, "alice");
    assert_eq!(page.items[0].action, "agent.task");
    assert_eq!(page.items[0].result_status, AuditResultStatus::Failure);
}

#[tokio::test]
async fn actor_filter_falls_back_to_actor_when_operator_absent() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_audit_rows(&database, 100).await;

    // Only `actor` set, no `operator` — should fall back to actor value.
    let query = AuditQuery { actor: Some("bob".to_owned()), ..AuditQuery::default() };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert!(page.total > 0, "bob rows should be present");
    assert!(
        page.items.iter().all(|r| r.actor == "bob"),
        "actor fallback should filter to bob only, \
         but found: {:?}",
        page.items.iter().map(|r| &r.actor).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn query_audit_log_result_status_success_filter_narrows_correctly() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_diverse_audit_rows(&database).await;

    let query =
        AuditQuery { result_status: Some(AuditResultStatus::Success), ..AuditQuery::default() };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    // Rows 1, 2, 4, 6, 7, 9 are successes = 6 total
    assert_eq!(page.total, 6, "exactly 6 success rows should match");
    assert!(
        page.items.iter().all(|r| r.result_status == AuditResultStatus::Success),
        "only success rows should be returned"
    );
}

#[tokio::test]
async fn query_audit_log_target_kind_and_result_status_combined() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_diverse_audit_rows(&database).await;

    // agent + Failure → rows 3, 8
    let query = AuditQuery {
        target_kind: Some("agent".to_owned()),
        result_status: Some(AuditResultStatus::Failure),
        ..AuditQuery::default()
    };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 2, "agent + failure should yield 2 rows");
    assert!(
        page.items
            .iter()
            .all(|r| r.target_kind == "agent" && r.result_status == AuditResultStatus::Failure),
        "all rows must match both filters"
    );
}

#[tokio::test]
async fn query_audit_log_target_id_and_actor_combined() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_diverse_audit_rows(&database).await;

    // actor=alice + target_id=A1 → only row 1
    let query = AuditQuery {
        actor: Some("alice".to_owned()),
        target_id: Some("A1".to_owned()),
        ..AuditQuery::default()
    };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 1, "alice + target_id=A1 should yield 1 row");
    assert_eq!(page.items[0].actor, "alice");
    assert_eq!(page.items[0].target_id.as_deref(), Some("A1"));
}

#[tokio::test]
async fn query_audit_log_operator_and_target_kind_combined() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_diverse_audit_rows(&database).await;

    // operator=bob + target_kind=agent → rows 4, 6, 8
    let query = AuditQuery {
        operator: Some("bob".to_owned()),
        target_kind: Some("agent".to_owned()),
        ..AuditQuery::default()
    };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 3, "bob + agent should yield 3 rows");
    assert!(
        page.items.iter().all(|r| r.actor == "bob" && r.target_kind == "agent"),
        "all rows must match both operator and target_kind"
    );
}

#[tokio::test]
async fn query_audit_log_target_id_and_result_status_combined() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_diverse_audit_rows(&database).await;

    // target_id=A1 + Success → rows 1, 4
    let query = AuditQuery {
        target_id: Some("A1".to_owned()),
        result_status: Some(AuditResultStatus::Success),
        ..AuditQuery::default()
    };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 2, "A1 + success should yield 2 rows");
    assert!(
        page.items.iter().all(|r| r.target_id.as_deref() == Some("A1")
            && r.result_status == AuditResultStatus::Success),
        "all rows must match both filters"
    );
}

#[tokio::test]
async fn query_audit_log_nonexistent_target_kind_returns_empty() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_diverse_audit_rows(&database).await;

    let query = AuditQuery { target_kind: Some("nonexistent".to_owned()), ..AuditQuery::default() };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 0, "no rows should match a nonexistent target_kind");
    assert!(page.items.is_empty());
}

#[tokio::test]
async fn query_audit_log_nonexistent_target_id_returns_empty() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_diverse_audit_rows(&database).await;

    let query = AuditQuery { target_id: Some("ZZZZZ".to_owned()), ..AuditQuery::default() };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 0, "no rows should match a nonexistent target_id");
    assert!(page.items.is_empty());
}

#[tokio::test]
async fn query_audit_log_target_id_substring_match() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_diverse_audit_rows(&database).await;

    // "L" should match both "L1" (rows 2, 5) and "L2" (row 9) via instr()
    let query = AuditQuery { target_id: Some("L".to_owned()), ..AuditQuery::default() };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 3, "substring 'L' should match L1 and L2 target_ids");
    assert!(
        page.items.iter().all(|r| r.target_id.as_deref().is_some_and(|id| id.contains('L'))),
        "all returned target_ids must contain 'L'"
    );
}

#[tokio::test]
async fn query_audit_log_target_kind_substring_match() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_diverse_audit_rows(&database).await;

    // "lis" should match "listener" (rows 2, 5, 9) via instr()
    let query = AuditQuery { target_kind: Some("lis".to_owned()), ..AuditQuery::default() };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 3, "substring 'lis' should match listener target_kind");
    assert!(
        page.items.iter().all(|r| r.target_kind.contains("lis")),
        "all returned target_kinds must contain 'lis'"
    );
}

#[tokio::test]
async fn query_audit_log_triple_filter_target_kind_target_id_result_status() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_diverse_audit_rows(&database).await;

    // listener + L1 + Failure → only row 5
    let query = AuditQuery {
        target_kind: Some("listener".to_owned()),
        target_id: Some("L1".to_owned()),
        result_status: Some(AuditResultStatus::Failure),
        ..AuditQuery::default()
    };
    let page = query_audit_log(&database, &query).await.expect("query should succeed");

    assert_eq!(page.total, 1, "listener + L1 + failure should yield exactly 1 row");
    let item = &page.items[0];
    assert_eq!(item.target_kind, "listener");
    assert_eq!(item.target_id.as_deref(), Some("L1"));
    assert_eq!(item.result_status, AuditResultStatus::Failure);
}

// ---------------------------------------------------------------
// Invalid filter normalization — query_audit_log
// ---------------------------------------------------------------

#[tokio::test]
async fn query_audit_log_invalid_agent_id_is_ignored() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_diverse_audit_rows(&database).await;

    let baseline = query_audit_log(&database, &AuditQuery::default())
        .await
        .expect("baseline query should succeed");
    assert!(baseline.total > 0, "seeded rows should exist");

    for bad_id in ["not-hex", "ZZZZ", "\u{1f980}", "  ", "0xGG", "0x-1"] {
        let query = AuditQuery { agent_id: Some(bad_id.to_owned()), ..AuditQuery::default() };
        let page = query_audit_log(&database, &query)
            .await
            .unwrap_or_else(|e| panic!("query with agent_id={bad_id:?} should not error: {e}"));
        assert_eq!(
            page.total, baseline.total,
            "invalid agent_id={bad_id:?} should be ignored, returning all rows"
        );
    }
}

#[tokio::test]
async fn query_audit_log_all_invalid_filters_combined_returns_unfiltered() {
    let database = Database::connect_in_memory().await.expect("database should initialize");
    seed_diverse_audit_rows(&database).await;

    let baseline = query_audit_log(&database, &AuditQuery::default())
        .await
        .expect("baseline query should succeed");

    let query = AuditQuery {
        agent_id: Some("ZZZZ".to_owned()),
        since: Some("garbage".to_owned()),
        until: Some("also-garbage".to_owned()),
        ..AuditQuery::default()
    };
    let page = query_audit_log(&database, &query)
        .await
        .expect("query with all invalid filters should succeed");
    assert_eq!(
        page.total, baseline.total,
        "all-invalid filters should be ignored, returning full result set"
    );
}
