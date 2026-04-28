use red_cell_common::{AgentEncryptionInfo, AgentRecord};
use zeroize::Zeroizing;

use crate::database::Database;

use super::{AgentResponseRecord, PayloadBuildRecord};

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

fn stub_payload_build(id: &str) -> PayloadBuildRecord {
    PayloadBuildRecord {
        id: id.to_owned(),
        status: "pending".to_owned(),
        name: "test-payload".to_owned(),
        arch: "x64".to_owned(),
        format: "exe".to_owned(),
        listener: "http-default".to_owned(),
        agent_type: "Demon".to_owned(),
        sleep_secs: Some(10),
        artifact: None,
        size_bytes: None,
        error: None,
        export_name: None,
        created_at: "2026-03-27T00:00:00Z".to_owned(),
        updated_at: "2026-03-27T00:00:00Z".to_owned(),
    }
}

#[tokio::test]
async fn list_for_agent_since_returns_all_when_no_cursor() {
    let db = Database::connect_in_memory().await.expect("db");
    seed_agents(&db, &[100]).await;
    let repo = db.agent_responses();
    let record = AgentResponseRecord {
        id: None,
        agent_id: 100,
        command_id: 21,
        request_id: 1,
        response_type: "Good".to_owned(),
        message: "ok".to_owned(),
        output: "hello".to_owned(),
        command_line: None,
        task_id: Some("t1".to_owned()),
        operator: None,
        received_at: "2026-03-27T00:00:00Z".to_owned(),
        extra: None,
    };
    repo.create(&record).await.expect("create");
    let all = repo.list_for_agent_since(100, None).await.expect("query");
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].output, "hello");
}

#[tokio::test]
async fn list_for_agent_since_filters_by_cursor() {
    let db = Database::connect_in_memory().await.expect("db");
    seed_agents(&db, &[101]).await;
    let repo = db.agent_responses();
    let make_record = |request_id: u32, output: &str, received_at: &str| AgentResponseRecord {
        id: None,
        agent_id: 101,
        command_id: 21,
        request_id,
        response_type: "Good".to_owned(),
        message: String::new(),
        output: output.to_owned(),
        command_line: None,
        task_id: None,
        operator: None,
        received_at: received_at.to_owned(),
        extra: None,
    };
    let id1 =
        repo.create(&make_record(1, "out-1", "2026-03-27T00:00:00Z")).await.expect("create r1");
    repo.create(&make_record(2, "out-2", "2026-03-27T00:01:00Z")).await.expect("create r2");

    let after_first = repo.list_for_agent_since(101, Some(id1)).await.expect("query");
    assert_eq!(after_first.len(), 1);
    assert_eq!(after_first[0].output, "out-2");

    assert!(repo.list_for_agent_since(101, Some(id1 + 100)).await.expect("query").is_empty());
}

#[tokio::test]
async fn payload_builds_factory_insert_and_read_back() {
    let db = Database::connect_in_memory().await.expect("db");
    let repo = db.payload_builds();
    let record = stub_payload_build("build-001");
    repo.create(&record).await.expect("create");
    assert_eq!(repo.get("build-001").await.expect("get"), Some(record));
}

#[tokio::test]
async fn payload_builds_factory_errors_after_close() {
    let db = Database::connect_in_memory().await.expect("db");
    let repo = db.payload_builds();
    db.close().await;
    assert!(repo.create(&stub_payload_build("build-closed")).await.is_err());
}

#[tokio::test]
async fn payload_builds_factory_two_handles_see_same_row() {
    let db = Database::connect_in_memory().await.expect("db");
    let repo_a = db.payload_builds();
    let repo_b = db.payload_builds();
    let record = stub_payload_build("build-shared");
    repo_a.create(&record).await.expect("create");
    assert_eq!(repo_b.get("build-shared").await.expect("get"), Some(record));
}

#[tokio::test]
async fn payload_builds_crud_round_trip_with_artifact_blobs() {
    let db = Database::connect_in_memory().await.expect("db");
    let repo = db.payload_builds();
    let record_a = PayloadBuildRecord {
        id: "crud-a".to_owned(),
        status: "done".to_owned(),
        name: "agent-alpha.exe".to_owned(),
        arch: "x64".to_owned(),
        format: "exe".to_owned(),
        listener: "https-main".to_owned(),
        agent_type: "Demon".to_owned(),
        sleep_secs: Some(30),
        artifact: Some(vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]),
        size_bytes: Some(6),
        error: None,
        export_name: None,
        created_at: "2026-03-27T10:00:00Z".to_owned(),
        updated_at: "2026-03-27T10:05:00Z".to_owned(),
    };
    repo.create(&record_a).await.expect("create");
    let fetched = repo.get("crud-a").await.expect("get").expect("should exist");
    assert_eq!(fetched, record_a);
}

#[tokio::test]
async fn payload_builds_list_returns_newest_first() {
    let db = Database::connect_in_memory().await.expect("db");
    let repo = db.payload_builds();
    let mut older = stub_payload_build("list-older");
    older.created_at = "2026-03-27T08:00:00Z".to_owned();
    let mut newer = stub_payload_build("list-newer");
    newer.created_at = "2026-03-27T09:00:00Z".to_owned();
    repo.create(&older).await.expect("create");
    repo.create(&newer).await.expect("create");
    let all = repo.list().await.expect("list");
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].id, "list-newer", "newest record should be first");
    assert_eq!(all[1].id, "list-older");
}

#[tokio::test]
async fn payload_builds_get_returns_none_for_unknown_id() {
    let db = Database::connect_in_memory().await.expect("db");
    assert!(db.payload_builds().get("nonexistent-id").await.expect("get").is_none());
}

#[tokio::test]
async fn get_summary_returns_metadata_without_artifact() {
    let db = Database::connect_in_memory().await.expect("db");
    let repo = db.payload_builds();
    let mut record = stub_payload_build("sum-001");
    record.artifact = Some(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    record.size_bytes = Some(4);
    record.status = "done".to_owned();
    repo.create(&record).await.expect("create");

    let summary = repo.get_summary("sum-001").await.expect("get_summary").expect("should exist");
    assert_eq!(summary.id, "sum-001");
    assert_eq!(summary.status, "done");
    assert_eq!(summary.size_bytes, Some(4));
    assert!(summary.error.is_none());
}

#[tokio::test]
async fn get_summary_returns_none_for_missing_id() {
    let db = Database::connect_in_memory().await.expect("db");
    assert!(db.payload_builds().get_summary("nonexistent-id").await.expect("get").is_none());
}

#[tokio::test]
async fn list_summaries_returns_metadata_ordered_by_created_at_desc() {
    let db = Database::connect_in_memory().await.expect("db");
    let repo = db.payload_builds();
    let mut b1 = stub_payload_build("ls-001");
    b1.created_at = "2026-03-27T01:00:00Z".to_owned();
    b1.name = "first".to_owned();
    let mut b2 = stub_payload_build("ls-002");
    b2.created_at = "2026-03-27T02:00:00Z".to_owned();
    b2.name = "second".to_owned();
    let mut b3 = stub_payload_build("ls-003");
    b3.created_at = "2026-03-27T03:00:00Z".to_owned();
    b3.name = "third".to_owned();
    repo.create(&b1).await.expect("create");
    repo.create(&b2).await.expect("create");
    repo.create(&b3).await.expect("create");
    let summaries = repo.list_summaries().await.expect("list");
    assert_eq!(summaries.len(), 3);
    assert_eq!(summaries[0].id, "ls-003");
    assert_eq!(summaries[1].id, "ls-002");
    assert_eq!(summaries[2].id, "ls-001");
}

#[tokio::test]
async fn list_summaries_empty_table_returns_empty_vec() {
    let db = Database::connect_in_memory().await.expect("db");
    assert!(db.payload_builds().list_summaries().await.expect("list").is_empty());
}

#[tokio::test]
async fn update_status_happy_path_persists_all_fields() {
    let db = Database::connect_in_memory().await.expect("db");
    let repo = db.payload_builds();
    repo.create(&stub_payload_build("upd-001")).await.expect("create");
    let artifact_bytes: &[u8] = &[0xCA, 0xFE, 0xBA, 0xBE];
    let updated = repo
        .update_status(
            "upd-001",
            "done",
            Some("final.exe"),
            Some(artifact_bytes),
            Some(4),
            None,
            None,
            "2026-03-27T12:00:00Z",
        )
        .await
        .expect("update_status");
    assert!(updated);
    let fetched = repo.get("upd-001").await.expect("get").expect("should exist");
    assert_eq!(fetched.status, "done");
    assert_eq!(fetched.artifact, Some(artifact_bytes.to_vec()));
    assert_eq!(fetched.size_bytes, Some(4));
    assert_eq!(fetched.updated_at, "2026-03-27T12:00:00Z");
}

#[tokio::test]
async fn update_status_missing_id_returns_false() {
    let db = Database::connect_in_memory().await.expect("db");
    let updated = db
        .payload_builds()
        .update_status(
            "nonexistent-id",
            "done",
            None,
            None,
            None,
            None,
            None,
            "2026-03-27T12:00:00Z",
        )
        .await
        .expect("update_status");
    assert!(!updated);
}

#[tokio::test]
async fn update_status_partial_fields_preserves_existing_values() {
    let db = Database::connect_in_memory().await.expect("db");
    let repo = db.payload_builds();
    let mut record = stub_payload_build("upd-partial");
    record.name = "original-name.exe".to_owned();
    record.artifact = Some(vec![0x01, 0x02]);
    record.size_bytes = Some(2);
    repo.create(&record).await.expect("create");
    let updated = repo
        .update_status(
            "upd-partial",
            "error",
            None,
            None,
            None,
            Some("build timed out"),
            None,
            "2026-03-27T13:00:00Z",
        )
        .await
        .expect("update_status");
    assert!(updated);
    let fetched = repo.get("upd-partial").await.expect("get").expect("should exist");
    assert_eq!(fetched.status, "error");
    assert_eq!(fetched.error, Some("build timed out".to_owned()));
    assert_eq!(fetched.name, "original-name.exe");
    assert_eq!(fetched.artifact, Some(vec![0x01, 0x02]));
}

#[tokio::test]
async fn invalidate_done_builds_for_listener_marks_done_records_stale() {
    let db = Database::connect_in_memory().await.expect("db");
    let repo = db.payload_builds();
    let mut a = stub_payload_build("inv-a");
    a.status = "done".to_owned();
    a.listener = "http-main".to_owned();
    let mut b = stub_payload_build("inv-b");
    b.status = "done".to_owned();
    b.listener = "http-main".to_owned();
    let mut other = stub_payload_build("inv-other");
    other.status = "done".to_owned();
    other.listener = "dns-backup".to_owned();
    repo.create(&a).await.expect("create");
    repo.create(&b).await.expect("create");
    repo.create(&other).await.expect("create");

    let count = repo
        .invalidate_done_builds_for_listener("http-main", "2026-03-31T00:00:00Z")
        .await
        .expect("invalidate");
    assert_eq!(count, 2);

    assert_eq!(repo.get("inv-a").await.expect("get").expect("inv-a").status, "stale");
    assert_eq!(repo.get("inv-b").await.expect("get").expect("inv-b").status, "stale");
    assert_eq!(repo.get("inv-other").await.expect("get").expect("inv-other").status, "done");
}

#[tokio::test]
async fn invalidate_done_builds_for_listener_ignores_non_done_records() {
    let db = Database::connect_in_memory().await.expect("db");
    let repo = db.payload_builds();
    let mut pending = stub_payload_build("inv-pend");
    pending.status = "pending".to_owned();
    pending.listener = "http-main".to_owned();
    let mut errored = stub_payload_build("inv-err");
    errored.status = "error".to_owned();
    errored.listener = "http-main".to_owned();
    repo.create(&pending).await.expect("create");
    repo.create(&errored).await.expect("create");
    let count = repo
        .invalidate_done_builds_for_listener("http-main", "2026-03-31T00:00:00Z")
        .await
        .expect("invalidate");
    assert_eq!(count, 0);
}

#[tokio::test]
async fn invalidate_done_builds_for_listener_returns_zero_for_unknown_listener() {
    let db = Database::connect_in_memory().await.expect("db");
    let count = db
        .payload_builds()
        .invalidate_done_builds_for_listener("nonexistent", "2026-03-31T00:00:00Z")
        .await
        .expect("invalidate");
    assert_eq!(count, 0);
}

#[tokio::test]
async fn list_correlated_for_task_excludes_other_task_same_request_id() {
    let db = Database::connect_in_memory().await.expect("db");
    seed_agents(&db, &[200]).await;
    let repo = db.agent_responses();

    let shared_rid: u32 = 42;

    let task_a = AgentResponseRecord {
        id: None,
        agent_id: 200,
        command_id: 1,
        request_id: shared_rid,
        response_type: "Good".to_owned(),
        message: String::new(),
        output: "from-task-a".to_owned(),
        command_line: None,
        task_id: Some("task-a".to_owned()),
        operator: None,
        received_at: "2026-04-28T00:00:00Z".to_owned(),
        extra: None,
    };
    let task_b = AgentResponseRecord {
        id: None,
        agent_id: 200,
        command_id: 2,
        request_id: shared_rid,
        response_type: "Good".to_owned(),
        message: String::new(),
        output: "from-task-b".to_owned(),
        command_line: None,
        task_id: Some("task-b".to_owned()),
        operator: None,
        received_at: "2026-04-28T00:01:00Z".to_owned(),
        extra: None,
    };
    let orphan = AgentResponseRecord {
        id: None,
        agent_id: 200,
        command_id: 3,
        request_id: shared_rid,
        response_type: "Good".to_owned(),
        message: String::new(),
        output: "orphan-row".to_owned(),
        command_line: None,
        task_id: None,
        operator: None,
        received_at: "2026-04-28T00:02:00Z".to_owned(),
        extra: None,
    };

    repo.create(&task_a).await.expect("create a");
    repo.create(&task_b).await.expect("create b");
    repo.create(&orphan).await.expect("create orphan");

    // Query for task-a with the shared request_id: must NOT see task-b's row.
    let results_a =
        repo.list_correlated_for_task(200, "task-a", Some(shared_rid)).await.expect("query a");
    assert_eq!(results_a.len(), 2, "should include task-a row + orphan row");
    assert!(results_a.iter().any(|r| r.output == "from-task-a"));
    assert!(results_a.iter().any(|r| r.output == "orphan-row"));
    assert!(!results_a.iter().any(|r| r.output == "from-task-b"));

    // Query for task-b with the shared request_id: must NOT see task-a's row.
    let results_b =
        repo.list_correlated_for_task(200, "task-b", Some(shared_rid)).await.expect("query b");
    assert_eq!(results_b.len(), 2, "should include task-b row + orphan row");
    assert!(results_b.iter().any(|r| r.output == "from-task-b"));
    assert!(results_b.iter().any(|r| r.output == "orphan-row"));
    assert!(!results_b.iter().any(|r| r.output == "from-task-a"));

    // Query without request_id hint: only exact task_id match.
    let results_no_rid =
        repo.list_correlated_for_task(200, "task-a", None).await.expect("query no rid");
    assert_eq!(results_no_rid.len(), 1);
    assert_eq!(results_no_rid[0].output, "from-task-a");
}
