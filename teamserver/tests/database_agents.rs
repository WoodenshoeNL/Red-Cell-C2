use red_cell::database::{
    AgentResponseRecord, Database, DbMasterKey, LinkRecord, LootRecord, TeamserverError,
};
use serde_json::json;
use std::sync::Arc;
use tempfile::TempDir;

#[path = "database_common.rs"]
mod database_common;
use database_common::{sample_agent, test_database};

// ---------------------------------------------------------------------------
// Corrupted-row rejection tests for reload / conversion error paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn agent_repository_supports_crud_and_status_updates() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.agents();
    let mut agent = sample_agent(0x00AB_CDEF);

    repository.create(&agent).await?;
    assert!(repository.exists(agent.agent_id).await?);

    let stored = repository.get(agent.agent_id).await?;
    assert_eq!(stored, Some(agent.clone()));
    assert_eq!(repository.list_active().await?, vec![agent.clone()]);

    agent.reason = "sleeping".to_owned();
    agent.sleep_delay = 45;
    agent.last_call_in = "2026-03-09T19:00:00Z".to_owned();
    repository.update(&agent).await?;
    assert_eq!(repository.get(agent.agent_id).await?, Some(agent.clone()));

    repository.set_status(agent.agent_id, false, "lost contact").await?;
    let stored = repository.get(agent.agent_id).await?.expect("agent should still exist");
    assert!(!stored.active);
    assert_eq!(stored.reason, "lost contact");
    assert!(repository.list_active().await?.is_empty());

    repository.delete(agent.agent_id).await?;
    assert!(!repository.exists(agent.agent_id).await?);

    Ok(())
}

#[tokio::test]
async fn agent_repository_persists_listener_note_and_ctr_state_across_reload()
-> Result<(), TeamserverError> {
    let temp_dir = TempDir::new().expect("tempdir should be created");
    let database_path = temp_dir.path().join("agents.sqlite");
    // Use a fixed key so the same key can decrypt at-rest data after the DB is closed
    // and re-opened.  Database::connect() generates a random ephemeral key each time,
    // which would make the reload step always fail decryption.
    let master_key = DbMasterKey::from_bytes([0x42u8; 32]);
    let database = Database::connect_with_master_key(&database_path, master_key).await?;
    let repository = database.agents();
    let mut first = sample_agent(0x00AB_CDEF);
    let second = sample_agent(0x00AB_CDF0);

    repository.create_with_listener(&first, "http-alpha").await?;
    repository.create_with_listener_and_ctr_offset(&second, "http-bravo", 19).await?;

    first.note = "primary foothold".to_owned();
    first.reason = "interactive".to_owned();
    first.sleep_delay = 30;
    first.last_call_in = "2026-03-10T08:15:00Z".to_owned();
    repository.update_with_listener(&first, "http-charlie").await?;
    repository.set_note(first.agent_id, &first.note).await?;
    repository.set_ctr_block_offset(first.agent_id, 7).await?;

    let persisted_first =
        repository.get_persisted(first.agent_id).await?.expect("first agent should exist");
    assert_eq!(persisted_first.info, first);
    assert_eq!(persisted_first.listener_name, "http-charlie");
    assert_eq!(persisted_first.ctr_block_offset, 7);

    let persisted = repository.list_persisted().await?;
    assert_eq!(
        persisted.iter().map(|agent| agent.info.agent_id).collect::<Vec<_>>(),
        vec![first.agent_id, second.agent_id]
    );
    assert_eq!(persisted[0].listener_name, "http-charlie");
    assert_eq!(persisted[0].info.note, "primary foothold");
    assert_eq!(persisted[0].ctr_block_offset, 7);
    assert_eq!(persisted[1].listener_name, "http-bravo");
    assert_eq!(persisted[1].ctr_block_offset, 19);

    database.close().await;

    let master_key = DbMasterKey::from_bytes([0x42u8; 32]);
    let reloaded = Database::connect_with_master_key(&database_path, master_key).await?;
    let reloaded_repository = reloaded.agents();
    let reloaded_first = reloaded_repository
        .get_persisted(first.agent_id)
        .await?
        .expect("first agent should persist across reload");
    let reloaded_agents = reloaded_repository.list_persisted().await?;

    assert_eq!(reloaded_first, persisted_first);
    assert_eq!(reloaded_agents, persisted);

    Ok(())
}

#[tokio::test]
async fn agent_repository_listener_bound_updates_fail_for_missing_agents()
-> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.agents();
    let missing_agent = sample_agent(0xDEAD_BEEF);

    let update_error = repository
        .update_with_listener(&missing_agent, "http-missing")
        .await
        .expect_err("updating a missing agent should fail");
    assert!(matches!(
        update_error,
        TeamserverError::AgentNotFound { agent_id } if agent_id == missing_agent.agent_id
    ));

    let note_error = repository
        .set_note(missing_agent.agent_id, "missing")
        .await
        .expect_err("setting a note for a missing agent should fail");
    assert!(matches!(
        note_error,
        TeamserverError::AgentNotFound { agent_id } if agent_id == missing_agent.agent_id
    ));

    let ctr_error = repository
        .set_ctr_block_offset(missing_agent.agent_id, 9)
        .await
        .expect_err("setting CTR state for a missing agent should fail");
    assert!(matches!(
        ctr_error,
        TeamserverError::AgentNotFound { agent_id } if agent_id == missing_agent.agent_id
    ));

    assert!(repository.get_persisted(missing_agent.agent_id).await?.is_none());

    Ok(())
}

#[tokio::test]
async fn agent_repository_set_ctr_block_offset_accepts_zero() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.agents();
    let agent = sample_agent(0xC0DE_0001);

    repository.create_with_listener_and_ctr_offset(&agent, "http-test", 42).await?;
    // Reset the offset back to zero — must succeed without error.
    repository.set_ctr_block_offset(agent.agent_id, 0).await?;

    let persisted = repository.get_persisted(agent.agent_id).await?.expect("agent should exist");
    assert_eq!(persisted.ctr_block_offset, 0);

    Ok(())
}

#[tokio::test]
async fn link_repository_supports_parent_child_queries() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let agents = database.agents();
    let links = database.links();
    let parent = sample_agent(0x1000_0001);
    let child = sample_agent(0x1000_0002);

    agents.create(&parent).await?;
    agents.create(&child).await?;

    links
        .create(LinkRecord { parent_agent_id: parent.agent_id, link_agent_id: child.agent_id })
        .await?;

    assert!(links.exists(parent.agent_id, child.agent_id).await?);
    assert_eq!(links.parent_of(child.agent_id).await?, Some(parent.agent_id));
    assert_eq!(links.children_of(parent.agent_id).await?, vec![child.agent_id]);
    assert_eq!(
        links.list().await?,
        vec![LinkRecord { parent_agent_id: parent.agent_id, link_agent_id: child.agent_id }]
    );

    links.delete(parent.agent_id, child.agent_id).await?;
    assert!(!links.exists(parent.agent_id, child.agent_id).await?);

    Ok(())
}

#[tokio::test]
async fn agent_response_repository_supports_insert_query_and_delete() -> Result<(), TeamserverError>
{
    let database = test_database().await?;
    let agents = database.agents();
    let responses = database.agent_responses();
    let agent = sample_agent(0x2200_0002);

    agents.create(&agent).await?;

    let record = AgentResponseRecord {
        id: None,
        agent_id: agent.agent_id,
        command_id: 94,
        request_id: 0x2A,
        response_type: "Good".to_owned(),
        message: "Received Output [5 bytes]:".to_owned(),
        output: "whoami".to_owned(),
        command_line: Some("shell whoami".to_owned()),
        task_id: Some("2A".to_owned()),
        operator: Some("neo".to_owned()),
        received_at: "2026-03-10T12:00:00Z".to_owned(),
        extra: Some(json!({ "RequestID": "2A", "Type": "Good" })),
    };

    let id = responses.create(&record).await?;
    let stored = responses.get(id).await?.expect("agent response should exist");
    assert_eq!(stored.id, Some(id));
    assert_eq!(stored.agent_id, record.agent_id);
    assert_eq!(responses.list_for_agent(agent.agent_id).await?, vec![stored.clone()]);
    assert_eq!(responses.list().await?, vec![stored.clone()]);

    responses.delete(id).await?;
    assert!(responses.get(id).await?.is_none());

    Ok(())
}

#[tokio::test]
async fn agent_response_list_for_agent_returns_empty_for_unknown_agent_id()
-> Result<(), TeamserverError> {
    let database = test_database().await?;
    let responses = database.agent_responses();

    // No agent registered, no responses inserted — should return Ok(empty vec).
    let result = responses.list_for_agent(0xFFFF_FFFF).await?;
    assert!(
        result.is_empty(),
        "list_for_agent with unknown agent_id must return an empty Vec, not an error"
    );

    Ok(())
}

#[tokio::test]
async fn agent_response_list_preserves_insertion_order_across_agents() -> Result<(), TeamserverError>
{
    let database = test_database().await?;
    let agents = database.agents();
    let responses = database.agent_responses();

    let agent_a = sample_agent(0x4400_0001);
    let agent_b = sample_agent(0x4400_0002);
    agents.create(&agent_a).await?;
    agents.create(&agent_b).await?;

    let make_record = |agent_id: u32, seq: u32, ts: &str| AgentResponseRecord {
        id: None,
        agent_id,
        command_id: 1,
        request_id: seq,
        response_type: "Good".to_owned(),
        message: format!("msg-{seq}"),
        output: format!("out-{seq}"),
        command_line: None,
        task_id: None,
        operator: None,
        received_at: ts.to_owned(),
        extra: None,
    };

    // Insert three rows: two for agent_a, one for agent_b, interleaved.
    let id1 = responses.create(&make_record(agent_a.agent_id, 1, "2026-03-17T10:00:00Z")).await?;
    let id2 = responses.create(&make_record(agent_b.agent_id, 2, "2026-03-17T10:01:00Z")).await?;
    let id3 = responses.create(&make_record(agent_a.agent_id, 3, "2026-03-17T10:02:00Z")).await?;

    // list() must return all three in insertion (id) order.
    let all = responses.list().await?;
    assert_eq!(all.len(), 3);
    assert_eq!(all[0].id, Some(id1));
    assert_eq!(all[1].id, Some(id2));
    assert_eq!(all[2].id, Some(id3));

    // list_for_agent returns only the two rows for agent_a, in insertion order.
    let for_a = responses.list_for_agent(agent_a.agent_id).await?;
    assert_eq!(for_a.len(), 2);
    assert_eq!(for_a[0].id, Some(id1));
    assert_eq!(for_a[1].id, Some(id3));

    // list_for_agent for agent_b returns exactly the one row belonging to it.
    let for_b = responses.list_for_agent(agent_b.agent_id).await?;
    assert_eq!(for_b.len(), 1);
    assert_eq!(for_b[0].id, Some(id2));

    Ok(())
}

#[tokio::test]
async fn agent_response_delete_nonexistent_id_is_silent_noop() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let responses = database.agent_responses();

    // Deleting an id that was never inserted must not return an error.
    responses.delete(999_999_999).await?;

    // Subsequent list() must be empty — nothing was affected.
    assert!(responses.list().await?.is_empty());

    Ok(())
}

#[tokio::test]
async fn agent_response_repository_rejects_insert_for_unknown_agent_id()
-> Result<(), TeamserverError> {
    let database = test_database().await?;
    let responses = database.agent_responses();

    // Attempt to insert an agent response whose agent_id was never created.
    let record = AgentResponseRecord {
        id: None,
        agent_id: 0xDEAD_FFFF,
        command_id: 1,
        request_id: 0x01,
        response_type: "Good".to_owned(),
        message: "orphan response".to_owned(),
        output: "should not persist".to_owned(),
        command_line: Some("shell whoami".to_owned()),
        task_id: Some("01".to_owned()),
        operator: Some("neo".to_owned()),
        received_at: "2026-03-19T10:00:00Z".to_owned(),
        extra: None,
    };

    let error = responses
        .create(&record)
        .await
        .expect_err("agent response insert with unknown agent_id should fail");

    assert!(
        matches!(error, TeamserverError::Database(_)),
        "expected Database error for missing agent FK, got: {error:?}"
    );

    // No response rows should have been stored.
    assert!(responses.list().await?.is_empty(), "list() must remain empty after rejected insert");
    assert!(
        responses.list_for_agent(0xDEAD_FFFF).await?.is_empty(),
        "list_for_agent() must remain empty after rejected insert"
    );

    Ok(())
}

#[tokio::test]
async fn agent_delete_cascades_to_loot_rows() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let agents = database.agents();
    let loot = database.loot();
    let agent = sample_agent(0x3300_0001);

    agents.create(&agent).await?;

    let record = LootRecord {
        id: None,
        agent_id: agent.agent_id,
        kind: "credential".to_owned(),
        name: "lsass.dmp".to_owned(),
        file_path: Some("C:\\Temp\\lsass.dmp".to_owned()),
        size_bytes: Some(512),
        captured_at: "2026-03-14T10:00:00Z".to_owned(),
        data: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        metadata: None,
    };

    let loot_id = loot.create(&record).await?;
    assert!(loot.get(loot_id).await?.is_some(), "loot row should exist before agent delete");

    agents.delete(agent.agent_id).await?;

    assert!(
        loot.get(loot_id).await?.is_none(),
        "loot row should be cascade-deleted when agent is deleted"
    );
    assert!(
        loot.list_for_agent(agent.agent_id).await?.is_empty(),
        "list_for_agent should return empty after cascade delete"
    );

    Ok(())
}

#[tokio::test]
async fn agent_delete_cascades_to_agent_response_rows() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let agents = database.agents();
    let responses = database.agent_responses();
    let agent = sample_agent(0x3300_0002);

    agents.create(&agent).await?;

    let record = AgentResponseRecord {
        id: None,
        agent_id: agent.agent_id,
        command_id: 94,
        request_id: 0x01,
        response_type: "Good".to_owned(),
        message: "output".to_owned(),
        output: "nt authority\\system".to_owned(),
        command_line: Some("shell whoami".to_owned()),
        task_id: Some("01".to_owned()),
        operator: Some("neo".to_owned()),
        received_at: "2026-03-14T10:01:00Z".to_owned(),
        extra: None,
    };

    let response_id = responses.create(&record).await?;
    assert!(
        responses.get(response_id).await?.is_some(),
        "response row should exist before agent delete"
    );

    agents.delete(agent.agent_id).await?;

    assert!(
        responses.get(response_id).await?.is_none(),
        "response row should be cascade-deleted when agent is deleted"
    );
    assert!(
        responses.list_for_agent(agent.agent_id).await?.is_empty(),
        "list_for_agent should return empty after cascade delete"
    );

    Ok(())
}

#[tokio::test]
async fn agent_delete_cascades_to_link_rows() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let agents = database.agents();
    let links = database.links();
    let parent = sample_agent(0x3300_0003);
    let child = sample_agent(0x3300_0004);

    agents.create(&parent).await?;
    agents.create(&child).await?;

    links
        .create(LinkRecord { parent_agent_id: parent.agent_id, link_agent_id: child.agent_id })
        .await?;

    assert!(
        links.exists(parent.agent_id, child.agent_id).await?,
        "link should exist before parent agent delete"
    );

    // Deleting the parent agent should cascade-delete the link.
    agents.delete(parent.agent_id).await?;

    assert!(
        !links.exists(parent.agent_id, child.agent_id).await?,
        "link row should be cascade-deleted when parent agent is deleted"
    );
    assert!(
        links.children_of(parent.agent_id).await?.is_empty(),
        "children_of should return empty after parent cascade delete"
    );

    Ok(())
}

#[tokio::test]
async fn child_agent_delete_also_cascades_link_row() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let agents = database.agents();
    let links = database.links();
    let parent = sample_agent(0x3300_0005);
    let child = sample_agent(0x3300_0006);

    agents.create(&parent).await?;
    agents.create(&child).await?;

    links
        .create(LinkRecord { parent_agent_id: parent.agent_id, link_agent_id: child.agent_id })
        .await?;

    assert!(
        links.exists(parent.agent_id, child.agent_id).await?,
        "link should exist before child agent delete"
    );

    // Deleting the child agent should also cascade-delete the link.
    agents.delete(child.agent_id).await?;

    assert!(
        !links.exists(parent.agent_id, child.agent_id).await?,
        "link row should be cascade-deleted when child agent is deleted"
    );
    assert!(
        links.parent_of(child.agent_id).await?.is_none(),
        "parent_of should return None after child cascade delete"
    );

    Ok(())
}

#[tokio::test]
async fn agent_list_active_returns_only_active_agents() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.agents();

    let active_agent = sample_agent(0x0011_2233);
    let mut inactive_agent = sample_agent(0x0044_5566);
    inactive_agent.active = false;
    inactive_agent.reason = "decommissioned".to_owned();
    inactive_agent.hostname = "wkstn-02".to_owned();

    repository.create(&active_agent).await?;
    repository.create(&inactive_agent).await?;

    let active_list = repository.list_active().await?;
    assert_eq!(active_list.len(), 1, "only the active agent should be returned");
    assert_eq!(active_list[0].agent_id, active_agent.agent_id);

    // list() should still return both agents.
    let all = repository.list().await?;
    assert_eq!(all.len(), 2, "list() must return both active and inactive agents");

    Ok(())
}

#[tokio::test]
async fn agent_update_persists_changed_fields_on_re_read() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.agents();

    let mut agent = sample_agent(0x00AA_BB01);
    repository.create(&agent).await?;

    // Mutate several fields.
    agent.hostname = "wkstn-updated".to_owned();
    agent.username = "new-operator".to_owned();
    agent.domain_name = "NEWDOMAIN".to_owned();
    agent.external_ip = "198.51.100.5".to_owned();
    agent.internal_ip = "10.0.0.99".to_owned();
    agent.process_name = "svchost.exe".to_owned();
    agent.process_path = "C:\\Windows\\System32\\svchost.exe".to_owned();
    agent.process_pid = 9999;
    agent.elevated = true;
    agent.os_version = "Windows 11".to_owned();
    agent.os_build = 22631;
    agent.sleep_delay = 120;
    agent.sleep_jitter = 25;

    repository.update(&agent).await?;

    let stored = repository.get(agent.agent_id).await?.expect("agent must exist after update");
    assert_eq!(stored.hostname, "wkstn-updated");
    assert_eq!(stored.username, "new-operator");
    assert_eq!(stored.domain_name, "NEWDOMAIN");
    assert_eq!(stored.external_ip, "198.51.100.5");
    assert_eq!(stored.internal_ip, "10.0.0.99");
    assert_eq!(stored.process_name, "svchost.exe");
    assert_eq!(stored.process_path, "C:\\Windows\\System32\\svchost.exe");
    assert_eq!(stored.process_pid, 9999);
    assert!(stored.elevated);
    assert_eq!(stored.os_version, "Windows 11");
    assert_eq!(stored.os_build, 22631);
    assert_eq!(stored.sleep_delay, 120);
    assert_eq!(stored.sleep_jitter, 25);
    assert_eq!(stored, agent, "full round-trip must match the updated record");

    Ok(())
}

#[tokio::test]
async fn agent_update_nonexistent_returns_agent_not_found() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.agents();

    let phantom = sample_agent(0xDEAD_0001);

    let result = repository.update(&phantom).await;
    assert!(result.is_err(), "updating a non-existent agent must fail");
    let err = result.expect_err("expected Err");
    assert!(
        matches!(err, TeamserverError::AgentNotFound { agent_id } if agent_id == 0xDEAD_0001),
        "expected AgentNotFound, got: {err:?}",
    );

    Ok(())
}

#[tokio::test]
async fn agent_delete_nonexistent_is_silent_noop() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.agents();

    // Deleting an agent_id that was never inserted should succeed silently.
    repository.delete(0xDEAD_0002).await?;

    // The repository should still be empty.
    let all = repository.list().await?;
    assert!(all.is_empty(), "no agents should exist after deleting a phantom");

    Ok(())
}

#[tokio::test]
async fn agent_list_with_corrupt_base64_aes_key_returns_error() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.agents();

    // Insert a valid agent first, then corrupt its aes_key directly via SQL.
    let agent = sample_agent(0xBAD0_0001);
    repository.create(&agent).await?;

    sqlx::query("UPDATE ts_agents SET aes_key_enc = '!!!not-valid-base64!!!' WHERE agent_id = ?")
        .bind(i64::from(agent.agent_id))
        .execute(database.pool())
        .await
        .expect("raw SQL update must succeed");

    let result = repository.list().await;
    assert!(result.is_err(), "list() must fail when a row has invalid aes_key_enc");
    let err = result.expect_err("expected Err");
    assert!(
        matches!(&err, TeamserverError::InvalidPersistedValue { field, .. } if *field == "aes_key"),
        "expected InvalidPersistedValue for aes_key, got: {err:?}",
    );

    Ok(())
}

#[tokio::test]
async fn agent_list_with_corrupt_base64_aes_iv_returns_error() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.agents();

    let agent = sample_agent(0xBAD0_0002);
    repository.create(&agent).await?;

    sqlx::query("UPDATE ts_agents SET aes_iv_enc = '!!!not-valid-base64!!!' WHERE agent_id = ?")
        .bind(i64::from(agent.agent_id))
        .execute(database.pool())
        .await
        .expect("raw SQL update must succeed");

    let result = repository.list().await;
    assert!(result.is_err(), "list() must fail when a row has invalid aes_iv_enc");
    let err = result.expect_err("expected Err");
    assert!(
        matches!(&err, TeamserverError::InvalidPersistedValue { field, .. } if *field == "aes_iv"),
        "expected InvalidPersistedValue for aes_iv, got: {err:?}",
    );

    Ok(())
}

#[tokio::test]
async fn agent_get_with_corrupt_base64_returns_error() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.agents();

    let agent = sample_agent(0xBAD0_0003);
    repository.create(&agent).await?;

    sqlx::query("UPDATE ts_agents SET aes_key_enc = '@@invalid@@' WHERE agent_id = ?")
        .bind(i64::from(agent.agent_id))
        .execute(database.pool())
        .await
        .expect("raw SQL update must succeed");

    let result = repository.get(agent.agent_id).await;
    assert!(result.is_err(), "get() must fail when the row has invalid aes_key_enc");
    let err = result.expect_err("expected Err");
    assert!(
        matches!(&err, TeamserverError::InvalidPersistedValue { field, .. } if *field == "aes_key"),
        "expected InvalidPersistedValue for aes_key, got: {err:?}",
    );

    Ok(())
}

#[tokio::test]
async fn agent_get_persisted_with_corrupt_aes_key_returns_error() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.agents();

    let agent = sample_agent(0xBAD1_0001);
    repository.create(&agent).await?;

    sqlx::query("UPDATE ts_agents SET aes_key_enc = '!!!bad!!!' WHERE agent_id = ?")
        .bind(i64::from(agent.agent_id))
        .execute(database.pool())
        .await
        .expect("raw SQL update must succeed");

    let result = repository.get_persisted(agent.agent_id).await;
    assert!(result.is_err(), "get_persisted() must fail on invalid aes_key_enc");
    let err = result.expect_err("expected Err");
    assert!(
        matches!(&err, TeamserverError::InvalidPersistedValue { field, .. } if *field == "aes_key"),
        "expected InvalidPersistedValue for aes_key, got: {err:?}",
    );

    Ok(())
}

#[tokio::test]
async fn agent_list_persisted_with_corrupt_aes_iv_returns_error() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.agents();

    let agent = sample_agent(0xBAD1_0002);
    repository.create(&agent).await?;

    sqlx::query("UPDATE ts_agents SET aes_iv_enc = '!!!bad!!!' WHERE agent_id = ?")
        .bind(i64::from(agent.agent_id))
        .execute(database.pool())
        .await
        .expect("raw SQL update must succeed");

    let result = repository.list_persisted().await;
    assert!(result.is_err(), "list_persisted() must fail on invalid aes_iv_enc");
    let err = result.expect_err("expected Err");
    assert!(
        matches!(&err, TeamserverError::InvalidPersistedValue { field, .. } if *field == "aes_iv"),
        "expected InvalidPersistedValue for aes_iv, got: {err:?}",
    );

    Ok(())
}

#[tokio::test]
async fn agent_reload_with_negative_ctr_block_offset_returns_error() -> Result<(), TeamserverError>
{
    let database = test_database().await?;
    let repository = database.agents();

    let agent = sample_agent(0xBAD1_0003);
    repository.create(&agent).await?;

    sqlx::query("UPDATE ts_agents SET ctr_block_offset = -1 WHERE agent_id = ?")
        .bind(i64::from(agent.agent_id))
        .execute(database.pool())
        .await
        .expect("raw SQL update must succeed");

    let result = repository.get_persisted(agent.agent_id).await;
    assert!(result.is_err(), "get_persisted() must fail on negative ctr_block_offset");
    let err = result.expect_err("expected Err");
    assert!(
        matches!(&err, TeamserverError::InvalidPersistedValue { field, .. } if *field == "ctr_block_offset"),
        "expected InvalidPersistedValue for ctr_block_offset, got: {err:?}",
    );

    Ok(())
}

#[tokio::test]
async fn agent_reload_with_negative_process_pid_returns_error() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.agents();

    let agent = sample_agent(0xBAD1_0004);
    repository.create(&agent).await?;

    sqlx::query("UPDATE ts_agents SET process_pid = -1 WHERE agent_id = ?")
        .bind(i64::from(agent.agent_id))
        .execute(database.pool())
        .await
        .expect("raw SQL update must succeed");

    let result = repository.get(agent.agent_id).await;
    assert!(result.is_err(), "get() must fail on negative process_pid");
    let err = result.expect_err("expected Err");
    assert!(
        matches!(&err, TeamserverError::InvalidPersistedValue { field, .. } if *field == "process_pid"),
        "expected InvalidPersistedValue for process_pid, got: {err:?}",
    );

    Ok(())
}

#[tokio::test]
async fn agent_reload_with_overflowed_os_build_returns_error() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.agents();

    let agent = sample_agent(0xBAD1_0005);
    repository.create(&agent).await?;

    // u32::MAX + 1 does not fit in u32.
    sqlx::query("UPDATE ts_agents SET os_build = ? WHERE agent_id = ?")
        .bind(i64::from(u32::MAX) + 1)
        .bind(i64::from(agent.agent_id))
        .execute(database.pool())
        .await
        .expect("raw SQL update must succeed");

    let result = repository.get(agent.agent_id).await;
    assert!(result.is_err(), "get() must fail on overflowed os_build");
    let err = result.expect_err("expected Err");
    assert!(
        matches!(&err, TeamserverError::InvalidPersistedValue { field, .. } if *field == "os_build"),
        "expected InvalidPersistedValue for os_build, got: {err:?}",
    );

    Ok(())
}

#[tokio::test]
async fn agent_list_active_with_corrupt_row_returns_error() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.agents();

    let agent = sample_agent(0xBAD1_0006);
    repository.create(&agent).await?;

    // Corrupt base_address to a value that overflows u64 conversion (negative).
    sqlx::query("UPDATE ts_agents SET base_address = -999 WHERE agent_id = ?")
        .bind(i64::from(agent.agent_id))
        .execute(database.pool())
        .await
        .expect("raw SQL update must succeed");

    let result = repository.list_active().await;
    assert!(result.is_err(), "list_active() must fail on negative base_address");
    let err = result.expect_err("expected Err");
    assert!(
        matches!(&err, TeamserverError::InvalidPersistedValue { field, .. } if *field == "base_address"),
        "expected InvalidPersistedValue for base_address, got: {err:?}",
    );

    Ok(())
}

#[tokio::test]
async fn link_repository_rejects_duplicate_insert() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let agents = database.agents();
    let links = database.links();
    let parent = sample_agent(0x5500_0001);
    let child = sample_agent(0x5500_0002);

    agents.create(&parent).await?;
    agents.create(&child).await?;

    let link = LinkRecord { parent_agent_id: parent.agent_id, link_agent_id: child.agent_id };
    links.create(link).await?;

    let error = links.create(link).await.expect_err("duplicate link insert should fail");

    assert!(matches!(error, TeamserverError::Database(_)));
    let TeamserverError::Database(sqlx::Error::Database(database_error)) = &error else {
        panic!("expected sqlite database error for duplicate link insert");
    };
    assert_eq!(database_error.code().as_deref(), Some("1555"));

    // The original link must still be intact.
    assert!(links.exists(parent.agent_id, child.agent_id).await?);
    assert_eq!(links.list().await?.len(), 1);

    Ok(())
}

#[tokio::test]
async fn link_repository_rejects_missing_parent_agent() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let agents = database.agents();
    let links = database.links();
    let child = sample_agent(0x5500_0003);

    agents.create(&child).await?;

    let error = links
        .create(LinkRecord { parent_agent_id: 0xDEAD_FFFF, link_agent_id: child.agent_id })
        .await
        .expect_err("link with missing parent agent should fail");

    assert!(
        matches!(error, TeamserverError::Database(_)),
        "expected Database error for missing parent, got: {error:?}"
    );

    // No link should have been stored.
    assert!(links.list().await?.is_empty());

    Ok(())
}

#[tokio::test]
async fn link_repository_rejects_missing_child_agent() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let agents = database.agents();
    let links = database.links();
    let parent = sample_agent(0x5500_0004);

    agents.create(&parent).await?;

    let error = links
        .create(LinkRecord { parent_agent_id: parent.agent_id, link_agent_id: 0xDEAD_FFFE })
        .await
        .expect_err("link with missing child agent should fail");

    assert!(
        matches!(error, TeamserverError::Database(_)),
        "expected Database error for missing child, got: {error:?}"
    );

    // No link should have been stored.
    assert!(links.list().await?.is_empty());

    Ok(())
}

#[tokio::test]
async fn agent_duplicate_primary_key_returns_constraint_error() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let agents = database.agents();

    agents.create(&sample_agent(0xCE00_0020)).await?;

    let error = agents
        .create(&sample_agent(0xCE00_0020))
        .await
        .expect_err("duplicate agent_id insert should fail");

    assert!(matches!(error, TeamserverError::Database(_)));
    let TeamserverError::Database(sqlx::Error::Database(db_err)) = &error else {
        panic!("expected sqlite constraint error for duplicate agent_id");
    };
    assert!(
        db_err.message().contains("UNIQUE constraint failed"),
        "message should mention UNIQUE constraint: {}",
        db_err.message()
    );

    // Original row must still be intact.
    let agents_list = agents.list().await?;
    assert_eq!(agents_list.len(), 1);
    assert_eq!(agents_list[0].agent_id, 0xCE00_0020);

    Ok(())
}

#[tokio::test]
async fn transaction_rollback_on_duplicate_agent_preserves_database_state()
-> Result<(), TeamserverError> {
    let database = test_database().await?;
    let agents = database.agents();

    // Insert two distinct agents.
    agents.create(&sample_agent(0xCE00_0030)).await?;
    agents.create(&sample_agent(0xCE00_0031)).await?;

    // Attempting a duplicate should fail but leave both originals intact.
    let _ = agents.create(&sample_agent(0xCE00_0030)).await;

    let stored = agents.list().await?;
    assert_eq!(stored.len(), 2, "both original agents must survive failed insert");
    assert!(stored.iter().any(|a| a.agent_id == 0xCE00_0030));
    assert!(stored.iter().any(|a| a.agent_id == 0xCE00_0031));

    Ok(())
}

#[tokio::test]
async fn concurrent_writes_serialize_correctly_with_single_connection()
-> Result<(), TeamserverError> {
    let database = Arc::new(test_database().await?);
    let mut handles = Vec::new();

    // Spawn 10 concurrent agent inserts, each with a unique ID.
    for i in 0u32..10 {
        let db = Arc::clone(&database);
        handles.push(tokio::spawn(async move {
            let agent = sample_agent(0xCC00_0000 + i);
            db.agents().create(&agent).await
        }));
    }

    for handle in handles {
        handle.await.expect("task should not panic")?;
    }

    let stored = database.agents().list().await?;
    assert_eq!(stored.len(), 10, "all 10 concurrent inserts should succeed");

    // Verify all IDs are present.
    for i in 0u32..10 {
        assert!(
            stored.iter().any(|a| a.agent_id == 0xCC00_0000 + i),
            "agent 0x{:08X} missing",
            0xCC00_0000 + i
        );
    }

    Ok(())
}

#[tokio::test]
async fn agent_response_fk_violation_leaves_table_unchanged() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let agents = database.agents();
    let responses = database.agent_responses();

    // Create a valid agent and insert one response.
    agents.create(&sample_agent(0xCE00_0050)).await?;
    let valid_response = AgentResponseRecord {
        id: None,
        agent_id: 0xCE00_0050,
        command_id: 1,
        request_id: 100,
        response_type: "info".to_owned(),
        message: "ok".to_owned(),
        output: "done".to_owned(),
        command_line: None,
        task_id: None,
        operator: None,
        received_at: "2026-03-20T12:00:00Z".to_owned(),
        extra: None,
    };
    responses.create(&valid_response).await?;

    // Attempt to insert a response for a non-existent agent.
    let invalid_response = AgentResponseRecord { agent_id: 0xDEAD_BEEF, ..valid_response.clone() };

    let err = responses
        .create(&invalid_response)
        .await
        .expect_err("response insert with unknown agent_id should fail");

    assert!(
        matches!(err, TeamserverError::Database(_)),
        "expected Database error for FK violation, got: {err:?}"
    );

    // Only the valid response should exist.
    let stored = responses.list_for_agent(0xCE00_0050).await?;
    assert_eq!(stored.len(), 1, "valid response must survive FK-violating insert attempt");

    Ok(())
}

#[tokio::test]
async fn concurrent_duplicate_agent_inserts_only_one_succeeds() -> Result<(), TeamserverError> {
    let database = Arc::new(test_database().await?);
    let mut handles = Vec::new();

    // Spawn 5 tasks all trying to insert the same agent_id.
    for _ in 0..5 {
        let db = Arc::clone(&database);
        handles.push(tokio::spawn(
            async move { db.agents().create(&sample_agent(0xCC00_D000)).await },
        ));
    }

    let mut successes = 0usize;
    let mut failures = 0usize;
    for handle in handles {
        match handle.await.expect("task should not panic") {
            Ok(()) => successes += 1,
            Err(_) => failures += 1,
        }
    }

    assert_eq!(successes, 1, "exactly one concurrent insert should succeed");
    assert_eq!(failures, 4, "remaining inserts should fail with constraint error");

    let stored = database.agents().list().await?;
    assert_eq!(stored.len(), 1);

    Ok(())
}

#[tokio::test]
async fn link_create_after_pool_close_returns_connection_error() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let agents = database.agents();
    let links = database.links();

    let parent = sample_agent(0xCE00_0060);
    let child = sample_agent(0xCE00_0061);
    agents.create(&parent).await?;
    agents.create(&child).await?;

    database.close().await;

    let err = links
        .create(LinkRecord { parent_agent_id: parent.agent_id, link_agent_id: child.agent_id })
        .await
        .expect_err("link create after close should fail");

    assert!(matches!(err, TeamserverError::Database(_)));

    Ok(())
}
