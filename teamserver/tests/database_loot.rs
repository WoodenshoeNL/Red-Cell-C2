use red_cell::database::{LootFilter, LootRecord, TeamserverError};
use serde_json::json;
use std::sync::Arc;

#[path = "database_common.rs"]
mod database_common;
use database_common::{sample_agent, test_database};

#[tokio::test]
async fn loot_repository_supports_insert_query_and_delete() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let agents = database.agents();
    let loot = database.loot();
    let agent = sample_agent(0x2200_0001);

    agents.create(&agent).await?;

    let record = LootRecord {
        id: None,
        agent_id: agent.agent_id,
        kind: "download".to_owned(),
        name: "sam.dump".to_owned(),
        file_path: Some("C:\\Windows\\Temp\\sam.dump".to_owned()),
        size_bytes: Some(2048),
        captured_at: "2026-03-09T19:10:00Z".to_owned(),
        data: Some(vec![1, 2, 3, 4]),
        metadata: Some(json!({ "sha256": "deadbeef" })),
    };

    let id = loot.create(&record).await?;
    let stored = loot.get(id).await?.expect("loot record should exist");
    assert_eq!(stored.id, Some(id));
    assert_eq!(stored.agent_id, record.agent_id);
    assert_eq!(loot.list_for_agent(agent.agent_id).await?, vec![stored.clone()]);
    assert_eq!(loot.list().await?, vec![stored.clone()]);

    loot.delete(id).await?;
    assert!(loot.get(id).await?.is_none());

    Ok(())
}

#[tokio::test]
async fn loot_get_returns_inserted_record() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let agents = database.agents();
    let loot = database.loot();
    let agent = sample_agent(0x2200_0010);

    agents.create(&agent).await?;

    let record = LootRecord {
        id: None,
        agent_id: agent.agent_id,
        kind: "credential".to_owned(),
        name: "ntds.dit".to_owned(),
        file_path: Some("C:\\Windows\\NTDS\\ntds.dit".to_owned()),
        size_bytes: Some(4096),
        captured_at: "2026-03-15T12:00:00Z".to_owned(),
        data: Some(vec![0xDE, 0xAD]),
        metadata: Some(json!({ "source": "dcsync" })),
    };

    let id = loot.create(&record).await?;
    let fetched = loot.get(id).await?.expect("record should exist");

    assert_eq!(fetched.id, Some(id));
    assert_eq!(fetched.agent_id, record.agent_id);
    assert_eq!(fetched.kind, record.kind);
    assert_eq!(fetched.name, record.name);
    assert_eq!(fetched.file_path, record.file_path);
    assert_eq!(fetched.size_bytes, record.size_bytes);
    assert_eq!(fetched.captured_at, record.captured_at);
    assert_eq!(fetched.data, record.data);
    assert_eq!(fetched.metadata, record.metadata);

    Ok(())
}

#[tokio::test]
async fn loot_get_missing_id_returns_none() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let result = database.loot().get(9999).await?;
    assert!(result.is_none(), "get on nonexistent id should return None");
    Ok(())
}

#[tokio::test]
async fn loot_list_returns_all_agents_while_list_for_agent_filters() -> Result<(), TeamserverError>
{
    let database = test_database().await?;
    let agents = database.agents();
    let loot = database.loot();

    let agent_a = sample_agent(0x2200_0020);
    let agent_b = sample_agent(0x2200_0021);
    agents.create(&agent_a).await?;
    agents.create(&agent_b).await?;

    let record_a = LootRecord {
        id: None,
        agent_id: agent_a.agent_id,
        kind: "download".to_owned(),
        name: "secrets_a.txt".to_owned(),
        file_path: None,
        size_bytes: Some(10),
        captured_at: "2026-03-15T13:00:00Z".to_owned(),
        data: Some(vec![0xAA]),
        metadata: None,
    };

    let record_b = LootRecord {
        id: None,
        agent_id: agent_b.agent_id,
        kind: "download".to_owned(),
        name: "secrets_b.txt".to_owned(),
        file_path: None,
        size_bytes: Some(20),
        captured_at: "2026-03-15T14:00:00Z".to_owned(),
        data: Some(vec![0xBB]),
        metadata: None,
    };

    let id_a = loot.create(&record_a).await?;
    let id_b = loot.create(&record_b).await?;

    // list() must return records from both agents
    let all = loot.list().await?;
    assert_eq!(all.len(), 2);
    let all_ids: Vec<Option<i64>> = all.iter().map(|r| r.id).collect();
    assert!(all_ids.contains(&Some(id_a)));
    assert!(all_ids.contains(&Some(id_b)));

    // list_for_agent must return only that agent's record
    let only_a = loot.list_for_agent(agent_a.agent_id).await?;
    assert_eq!(only_a.len(), 1);
    assert_eq!(only_a[0].id, Some(id_a));
    assert_eq!(only_a[0].name, "secrets_a.txt");

    let only_b = loot.list_for_agent(agent_b.agent_id).await?;
    assert_eq!(only_b.len(), 1);
    assert_eq!(only_b[0].id, Some(id_b));
    assert_eq!(only_b[0].name, "secrets_b.txt");

    Ok(())
}

#[tokio::test]
async fn loot_repository_count_filtered_matches_query_filtered_length()
-> Result<(), TeamserverError> {
    let database = test_database().await?;
    let agents = database.agents();
    let loot = database.loot();
    let agent = sample_agent(0x2200_0003);

    agents.create(&agent).await?;

    for (name, kind, captured_at, operator, pattern) in [
        ("credential-1", "credential", "2026-03-10T10:00:00Z", "neo", Some("password")),
        ("credential-2", "credential", "2026-03-11T10:00:00Z", "neo", Some("hash")),
        ("download-1", "download", "2026-03-11T11:00:00Z", "trinity", None),
    ] {
        loot.create(&LootRecord {
            id: None,
            agent_id: agent.agent_id,
            kind: kind.to_owned(),
            name: name.to_owned(),
            file_path: Some(format!("C:\\Temp\\{name}.bin")),
            size_bytes: Some(32),
            captured_at: captured_at.to_owned(),
            data: Some(b"secret".to_vec()),
            metadata: Some(json!({
                "operator": operator,
                "command_line": "sekurlsa::logonpasswords",
                "pattern": pattern,
            })),
        })
        .await?;
    }

    let filter = LootFilter {
        kind_exact: Some("credential".to_owned()),
        operator_contains: Some("neo".to_owned()),
        pattern_contains: Some("pass".to_owned()),
        since: Some("2026-03-10T00:00:00Z".to_owned()),
        until: Some("2026-03-10T23:59:59Z".to_owned()),
        ..LootFilter::default()
    };

    let count = loot.count_filtered(&filter).await?;
    let rows = loot.query_filtered(&filter, 10, 0).await?;

    assert_eq!(count, 1);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].name, "credential-1");

    Ok(())
}

#[tokio::test]
async fn loot_repository_query_filtered_pushes_pagination_to_sql() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let agents = database.agents();
    let loot = database.loot();
    let agent = sample_agent(0x2200_0004);

    agents.create(&agent).await?;

    for i in 0..5 {
        loot.create(&LootRecord {
            id: None,
            agent_id: agent.agent_id,
            kind: "download".to_owned(),
            name: format!("artifact-{i}"),
            file_path: Some(format!("C:\\Temp\\artifact-{i}.bin")),
            size_bytes: Some(64),
            captured_at: format!("2026-03-10T10:{i:02}:00Z"),
            data: Some(vec![u8::try_from(i).map_err(|_| {
                TeamserverError::InvalidPersistedValue {
                    field: "i",
                    message: "loop index does not fit in u8".to_owned(),
                }
            })?]),
            metadata: Some(json!({
                "operator": "neo",
                "command_line": "download C:\\Temp\\artifact.bin",
            })),
        })
        .await?;
    }

    let filter = LootFilter { operator_contains: Some("neo".to_owned()), ..LootFilter::default() };
    let rows = loot.query_filtered(&filter, 2, 1).await?;

    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].name, "artifact-3");
    assert_eq!(rows[1].name, "artifact-2");

    Ok(())
}

#[tokio::test]
async fn loot_repository_agent_id_and_kind_combined_filter_isolates_correct_row()
-> Result<(), TeamserverError> {
    let database = test_database().await?;
    let agents = database.agents();
    let loot = database.loot();
    let agent_a = sample_agent(0x2200_0010);
    let agent_b = sample_agent(0x2200_0011);

    agents.create(&agent_a).await?;
    agents.create(&agent_b).await?;

    // agent_a has a "credential" and a "download"
    loot.create(&LootRecord {
        id: None,
        agent_id: agent_a.agent_id,
        kind: "credential".to_owned(),
        name: "cred-a".to_owned(),
        file_path: None,
        size_bytes: None,
        captured_at: "2026-03-15T10:00:00Z".to_owned(),
        data: None,
        metadata: None,
    })
    .await?;
    loot.create(&LootRecord {
        id: None,
        agent_id: agent_a.agent_id,
        kind: "download".to_owned(),
        name: "dl-a".to_owned(),
        file_path: None,
        size_bytes: None,
        captured_at: "2026-03-15T10:01:00Z".to_owned(),
        data: None,
        metadata: None,
    })
    .await?;

    // agent_b has a "credential" row — same kind, different agent
    loot.create(&LootRecord {
        id: None,
        agent_id: agent_b.agent_id,
        kind: "credential".to_owned(),
        name: "cred-b".to_owned(),
        file_path: None,
        size_bytes: None,
        captured_at: "2026-03-15T10:02:00Z".to_owned(),
        data: None,
        metadata: None,
    })
    .await?;

    let filter = LootFilter {
        agent_id: Some(agent_a.agent_id),
        kind_exact: Some("credential".to_owned()),
        ..LootFilter::default()
    };
    let rows = loot.query_filtered(&filter, 10, 0).await?;

    assert_eq!(rows.len(), 1, "only the credential row for agent_a should match");
    assert_eq!(rows[0].name, "cred-a");
    assert_eq!(rows[0].agent_id, agent_a.agent_id);

    Ok(())
}

#[tokio::test]
async fn loot_repository_operator_contains_matches_json_metadata_field()
-> Result<(), TeamserverError> {
    let database = test_database().await?;
    let agents = database.agents();
    let loot = database.loot();
    let agent = sample_agent(0x2200_0012);

    agents.create(&agent).await?;

    loot.create(&LootRecord {
        id: None,
        agent_id: agent.agent_id,
        kind: "credential".to_owned(),
        name: "row-morpheus".to_owned(),
        file_path: None,
        size_bytes: None,
        captured_at: "2026-03-15T09:00:00Z".to_owned(),
        data: None,
        metadata: Some(
            json!({ "operator": "morpheus", "command_line": "sekurlsa::logonpasswords" }),
        ),
    })
    .await?;
    loot.create(&LootRecord {
        id: None,
        agent_id: agent.agent_id,
        kind: "credential".to_owned(),
        name: "row-trinity".to_owned(),
        file_path: None,
        size_bytes: None,
        captured_at: "2026-03-15T09:01:00Z".to_owned(),
        data: None,
        metadata: Some(
            json!({ "operator": "trinity", "command_line": "sekurlsa::logonpasswords" }),
        ),
    })
    .await?;
    // Row with no metadata — operator_contains must not match this
    loot.create(&LootRecord {
        id: None,
        agent_id: agent.agent_id,
        kind: "download".to_owned(),
        name: "row-no-meta".to_owned(),
        file_path: None,
        size_bytes: None,
        captured_at: "2026-03-15T09:02:00Z".to_owned(),
        data: None,
        metadata: None,
    })
    .await?;

    let filter =
        LootFilter { operator_contains: Some("morpheus".to_owned()), ..LootFilter::default() };
    let rows = loot.query_filtered(&filter, 10, 0).await?;

    assert_eq!(rows.len(), 1, "only the morpheus row should match operator_contains");
    assert_eq!(rows[0].name, "row-morpheus");

    Ok(())
}

#[tokio::test]
async fn loot_repository_count_filtered_equals_query_filtered_len_with_multi_field_filter()
-> Result<(), TeamserverError> {
    let database = test_database().await?;
    let agents = database.agents();
    let loot = database.loot();
    let agent = sample_agent(0x2200_0013);

    agents.create(&agent).await?;

    for (name, kind, operator, pattern) in [
        ("r1", "credential", "neo", Some("lsass")),
        ("r2", "credential", "neo", None),
        ("r3", "download", "neo", Some("lsass")),
        ("r4", "credential", "morpheus", Some("lsass")),
    ] {
        loot.create(&LootRecord {
            id: None,
            agent_id: agent.agent_id,
            kind: kind.to_owned(),
            name: name.to_owned(),
            file_path: None,
            size_bytes: None,
            captured_at: "2026-03-15T12:00:00Z".to_owned(),
            data: None,
            metadata: Some(json!({ "operator": operator, "pattern": pattern })),
        })
        .await?;
    }

    // Simultaneously active: kind_exact, agent_id, operator_contains, pattern_contains
    let filter = LootFilter {
        kind_exact: Some("credential".to_owned()),
        agent_id: Some(agent.agent_id),
        operator_contains: Some("neo".to_owned()),
        pattern_contains: Some("lsass".to_owned()),
        ..LootFilter::default()
    };

    let count = loot.count_filtered(&filter).await?;
    let rows = loot.query_filtered(&filter, 100, 0).await?;

    assert_eq!(count, rows.len() as i64, "count_filtered must equal query_filtered length");
    assert_eq!(count, 1, "only r1 satisfies all four filters simultaneously");
    assert_eq!(rows[0].name, "r1");

    Ok(())
}

#[tokio::test]
async fn loot_repository_since_until_range_outside_all_rows_returns_empty()
-> Result<(), TeamserverError> {
    let database = test_database().await?;
    let agents = database.agents();
    let loot = database.loot();
    let agent = sample_agent(0x2200_0014);

    agents.create(&agent).await?;

    for (name, captured_at) in [
        ("row-a", "2026-03-10T10:00:00Z"),
        ("row-b", "2026-03-11T10:00:00Z"),
        ("row-c", "2026-03-12T10:00:00Z"),
    ] {
        loot.create(&LootRecord {
            id: None,
            agent_id: agent.agent_id,
            kind: "download".to_owned(),
            name: name.to_owned(),
            file_path: None,
            size_bytes: None,
            captured_at: captured_at.to_owned(),
            data: None,
            metadata: None,
        })
        .await?;
    }

    // Range entirely before all rows
    let filter = LootFilter {
        since: Some("2026-03-01T00:00:00Z".to_owned()),
        until: Some("2026-03-09T23:59:59Z".to_owned()),
        ..LootFilter::default()
    };

    let rows = loot.query_filtered(&filter, 10, 0).await?;
    let count = loot.count_filtered(&filter).await?;

    assert!(rows.is_empty(), "no rows should fall within the range");
    assert_eq!(count, 0);

    Ok(())
}

#[tokio::test]
async fn loot_repository_rejects_insert_for_unknown_agent_id() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let loot = database.loot();

    // Attempt to insert a loot record whose agent_id was never created.
    let record = LootRecord {
        id: None,
        agent_id: 0xDEAD_FFFF,
        kind: "credential".to_owned(),
        name: "orphan.dmp".to_owned(),
        file_path: Some("C:\\Temp\\orphan.dmp".to_owned()),
        size_bytes: Some(256),
        captured_at: "2026-03-19T10:00:00Z".to_owned(),
        data: Some(vec![0xDE, 0xAD]),
        metadata: None,
    };

    let error =
        loot.create(&record).await.expect_err("loot insert with unknown agent_id should fail");

    assert!(
        matches!(error, TeamserverError::Database(_)),
        "expected Database error for missing agent FK, got: {error:?}"
    );

    // No loot row should have been stored.
    assert!(loot.list().await?.is_empty(), "list() must remain empty after rejected insert");

    Ok(())
}

#[tokio::test]
async fn loot_operations_after_pool_close_return_connection_error() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let agents = database.agents();
    let loot = database.loot();

    agents.create(&sample_agent(0xCE00_0010)).await?;
    let record = LootRecord {
        id: None,
        agent_id: 0xCE00_0010,
        kind: "credential".to_owned(),
        name: "test.dmp".to_owned(),
        file_path: None,
        size_bytes: Some(16),
        captured_at: "2026-03-20T12:00:00Z".to_owned(),
        data: Some(vec![0xAB]),
        metadata: None,
    };

    loot.create(&record).await?;
    database.close().await;

    let err = loot.create(&record).await.expect_err("loot create after close should fail");
    assert!(matches!(err, TeamserverError::Database(_)));

    let err = loot.list().await.expect_err("loot list after close should fail");
    assert!(matches!(err, TeamserverError::Database(_)));

    Ok(())
}

#[tokio::test]
async fn concurrent_loot_writes_with_fk_serialize_correctly() -> Result<(), TeamserverError> {
    let database = Arc::new(test_database().await?);
    let agents = database.agents();

    agents.create(&sample_agent(0xCC00_0100)).await?;

    let mut handles = Vec::new();
    for i in 0u32..10 {
        let db = Arc::clone(&database);
        handles.push(tokio::spawn(async move {
            let record = LootRecord {
                id: None,
                agent_id: 0xCC00_0100,
                kind: "file".to_owned(),
                name: format!("loot-{i}.bin"),
                file_path: None,
                size_bytes: Some(i64::from(i)),
                captured_at: "2026-03-20T12:00:00Z".to_owned(),
                data: Some(vec![i as u8]),
                metadata: None,
            };
            db.loot().create(&record).await
        }));
    }

    for handle in handles {
        handle.await.expect("task should not panic")?;
    }

    let stored = database.loot().list_for_agent(0xCC00_0100).await?;
    assert_eq!(stored.len(), 10, "all 10 concurrent loot inserts should succeed");

    Ok(())
}
