use red_cell::database::{
    AgentResponseRecord, AuditLogEntry, AuditLogFilter, Database, LinkRecord, ListenerStatus,
    LootFilter, LootRecord, PersistedListener, PersistedListenerState, PersistedOperator,
    TeamserverError,
};
use red_cell::{
    AuditQuery, AuditResultStatus, SessionActivityQuery, audit_details, query_audit_log,
    query_session_activity, record_operator_action,
};
use red_cell_common::config::OperatorRole;
use red_cell_common::{
    AgentEncryptionInfo, AgentRecord, HttpListenerConfig, HttpListenerProxyConfig,
    HttpListenerResponseConfig, ListenerConfig, ListenerTlsConfig,
};
use serde_json::json;
use sqlx::sqlite::SqliteConnectOptions;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use uuid::Uuid;
use zeroize::Zeroizing;

fn temp_db_path() -> PathBuf {
    std::env::temp_dir().join(format!("red-cell-teamserver-db-{}.sqlite", Uuid::new_v4()))
}

fn sqlite_options(path: &Path) -> SqliteConnectOptions {
    SqliteConnectOptions::new().filename(path).create_if_missing(true).foreign_keys(true)
}

fn sample_agent(agent_id: u32) -> AgentRecord {
    AgentRecord {
        agent_id,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: AgentEncryptionInfo {
            aes_key: Zeroizing::new(b"aes-key".to_vec()),
            aes_iv: Zeroizing::new(b"aes-iv".to_vec()),
        },
        hostname: "wkstn-01".to_owned(),
        username: "operator".to_owned(),
        domain_name: "REDCELL".to_owned(),
        external_ip: "203.0.113.10".to_owned(),
        internal_ip: "10.0.0.25".to_owned(),
        process_name: "explorer.exe".to_owned(),
        process_path: "C:\\Windows\\explorer.exe".to_owned(),
        base_address: 0x401000,
        process_pid: 1337,
        process_tid: 1338,
        process_ppid: 512,
        process_arch: "x64".to_owned(),
        elevated: true,
        os_version: "Windows 11".to_owned(),
        os_build: 22000,
        os_arch: "x64".to_owned(),
        sleep_delay: 15,
        sleep_jitter: 20,
        kill_date: Some(1_893_456_000),
        working_hours: Some(0b101010),
        first_call_in: "2026-03-09T18:45:00Z".to_owned(),
        last_call_in: "2026-03-09T18:46:00Z".to_owned(),
    }
}

fn sample_listener() -> ListenerConfig {
    ListenerConfig::from(HttpListenerConfig {
        name: "http-main".to_owned(),
        kill_date: Some("2026-12-31".to_owned()),
        working_hours: Some("08:00-18:00".to_owned()),
        hosts: vec!["c2.red-cell.test".to_owned()],
        host_bind: "0.0.0.0".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: 8443,
        port_conn: Some(443),
        method: Some("POST".to_owned()),
        behind_redirector: true,
        trusted_proxy_peers: Vec::new(),
        user_agent: Some("Mozilla/5.0".to_owned()),
        headers: vec!["X-Test: true".to_owned()],
        uris: vec!["/index".to_owned()],
        host_header: Some("cdn.red-cell.test".to_owned()),
        secure: true,
        cert: Some(ListenerTlsConfig {
            cert: "server.pem".to_owned(),
            key: "server.key".to_owned(),
        }),
        response: Some(HttpListenerResponseConfig {
            headers: vec!["Server: nginx".to_owned()],
            body: Some("{\"status\":\"ok\"}".to_owned()),
        }),
        proxy: Some(HttpListenerProxyConfig {
            enabled: true,
            proxy_type: Some("http".to_owned()),
            host: "127.0.0.1".to_owned(),
            port: 8080,
            username: Some("proxy".to_owned()),
            password: Some(Zeroizing::new("secret".to_owned())),
        }),
    })
}

async fn test_database() -> Result<Database, TeamserverError> {
    Database::connect(temp_db_path()).await
}

#[tokio::test]
async fn connect_with_options_migrates_fresh_database_and_reports_open_failures()
-> Result<(), TeamserverError> {
    let temp_dir = TempDir::new().expect("tempdir should be created");
    let database_path = temp_dir.path().join("fresh.sqlite");

    let database = Database::connect_with_options(sqlite_options(&database_path)).await?;
    let tables: Vec<String> =
        sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .fetch_all(database.pool())
            .await?;
    database.close().await;

    assert!(database_path.exists());
    assert!(tables.iter().any(|name| name == "ts_agents"));
    assert!(tables.iter().any(|name| name == "ts_listeners"));

    let missing_parent_path =
        temp_dir.path().join("missing-parent").join("nested").join("broken.sqlite");
    let error = Database::connect_with_options(sqlite_options(&missing_parent_path))
        .await
        .expect_err("connect_with_options should fail when sqlite cannot open the path");

    assert!(matches!(error, TeamserverError::Database(_)));
    let TeamserverError::Database(sqlx::Error::Database(database_error)) = &error else {
        panic!("expected sqlite database open failure");
    };
    assert!(database_error.message().contains("unable to open database file"));

    Ok(())
}

#[tokio::test]
async fn database_runs_migrations_for_all_tables() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let tables: Vec<String> =
        sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .fetch_all(database.pool())
            .await?;

    assert!(tables.iter().any(|name| name == "ts_agents"));
    assert!(tables.iter().any(|name| name == "ts_listeners"));
    assert!(tables.iter().any(|name| name == "ts_links"));
    assert!(tables.iter().any(|name| name == "ts_loot"));
    assert!(tables.iter().any(|name| name == "ts_agent_responses"));
    assert!(tables.iter().any(|name| name == "ts_audit_log"));
    assert!(tables.iter().any(|name| name == "ts_runtime_operators"));

    Ok(())
}

#[tokio::test]
async fn operator_repository_supports_runtime_operator_crud_queries() -> Result<(), TeamserverError>
{
    let database = test_database().await?;
    let repository = database.operators();
    let operator = PersistedOperator {
        username: "trinity".to_owned(),
        password_verifier: "abc123".to_owned(),
        role: OperatorRole::Analyst,
    };

    repository.create(&operator).await?;

    assert_eq!(repository.get("trinity").await?, Some(operator.clone()));
    assert_eq!(repository.list().await?, vec![operator]);

    Ok(())
}

#[tokio::test]
async fn operator_repository_rejects_duplicate_usernames_without_mutating_existing_row()
-> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.operators();
    let original = PersistedOperator {
        username: "trinity".to_owned(),
        password_verifier: "abc123".to_owned(),
        role: OperatorRole::Analyst,
    };
    let duplicate = PersistedOperator {
        username: original.username.clone(),
        password_verifier: "def456".to_owned(),
        role: OperatorRole::Operator,
    };

    repository.create(&original).await?;

    let error =
        repository.create(&duplicate).await.expect_err("duplicate operator insert should fail");

    assert!(matches!(error, TeamserverError::Database(_)));
    let TeamserverError::Database(sqlx::Error::Database(database_error)) = &error else {
        panic!("expected sqlite database error for duplicate operator insert");
    };
    assert_eq!(database_error.code().as_deref(), Some("1555"));
    assert!(
        database_error
            .message()
            .contains("UNIQUE constraint failed: ts_runtime_operators.username")
    );

    assert_eq!(repository.get(&original.username).await?, Some(original.clone()));
    assert_eq!(repository.list().await?, vec![original]);

    Ok(())
}

#[tokio::test]
async fn operator_repository_updates_password_verifier_for_existing_runtime_operator()
-> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.operators();
    let operator = PersistedOperator {
        username: "trinity".to_owned(),
        password_verifier: "abc123".to_owned(),
        role: OperatorRole::Analyst,
    };

    repository.create(&operator).await?;
    repository.update_password_verifier(&operator.username, "updated-verifier").await?;

    assert_eq!(
        repository.get(&operator.username).await?,
        Some(PersistedOperator {
            username: operator.username,
            password_verifier: "updated-verifier".to_owned(),
            role: operator.role,
        })
    );

    Ok(())
}

#[tokio::test]
async fn operator_repository_update_password_verifier_is_a_noop_for_missing_operator()
-> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.operators();
    let existing = PersistedOperator {
        username: "neo".to_owned(),
        password_verifier: "keep-me".to_owned(),
        role: OperatorRole::Operator,
    };

    repository.create(&existing).await?;
    repository.update_password_verifier("missing", "new-verifier").await?;

    assert_eq!(repository.get("missing").await?, None);
    assert_eq!(repository.get(&existing.username).await?, Some(existing.clone()));
    assert_eq!(repository.list().await?, vec![existing]);

    Ok(())
}

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
    let database = Database::connect(&database_path).await?;
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

    let reloaded = Database::connect(&database_path).await?;
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
async fn listener_repository_supports_crud_queries() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.listeners();
    let mut listener = sample_listener();

    repository.create(&listener).await?;
    assert!(repository.exists(listener.name()).await?);
    assert_eq!(repository.count().await?, 1);
    assert_eq!(repository.names().await?, vec![listener.name().to_owned()]);

    let stored = repository.get(listener.name()).await?;
    assert_eq!(
        stored,
        Some(PersistedListener {
            name: listener.name().to_owned(),
            protocol: listener.protocol(),
            config: listener.clone(),
            state: PersistedListenerState { status: ListenerStatus::Created, last_error: None },
        })
    );

    if let ListenerConfig::Http(config) = &mut listener {
        config.port_bind = 9443;
    }
    repository.update(&listener).await?;
    assert_eq!(
        repository.list().await?,
        vec![PersistedListener {
            name: listener.name().to_owned(),
            protocol: listener.protocol(),
            config: listener.clone(),
            state: PersistedListenerState { status: ListenerStatus::Created, last_error: None },
        }]
    );

    repository.delete(listener.name()).await?;
    assert_eq!(repository.count().await?, 0);

    Ok(())
}

#[tokio::test]
async fn listener_repository_set_state_updates_runtime_fields_without_rewriting_config()
-> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.listeners();
    let listener = sample_listener();

    repository.create(&listener).await?;
    repository.set_state(listener.name(), ListenerStatus::Error, Some("bind failed")).await?;

    let stored =
        repository.get(listener.name()).await?.expect("listener should exist after set_state");
    assert_eq!(stored.config, listener);
    assert_eq!(
        stored.state,
        PersistedListenerState {
            status: ListenerStatus::Error,
            last_error: Some("bind failed".to_owned()),
        }
    );

    repository.set_state(listener.name(), ListenerStatus::Running, None).await?;

    let stored = repository
        .get(listener.name())
        .await?
        .expect("listener should exist after clearing last_error");
    assert_eq!(stored.config, listener);
    assert_eq!(
        stored.state,
        PersistedListenerState { status: ListenerStatus::Running, last_error: None }
    );

    Ok(())
}

#[tokio::test]
async fn listener_repository_update_persists_config_changes() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.listeners();
    let mut listener = sample_listener();

    repository.create(&listener).await?;

    if let ListenerConfig::Http(config) = &mut listener {
        config.port_bind = 9443;
        config.host_bind = "127.0.0.1".to_owned();
    }
    repository.update(&listener).await?;

    let stored =
        repository.get(listener.name()).await?.expect("listener should still exist after update");
    assert_eq!(stored.config, listener);
    assert_eq!(stored.state.status, ListenerStatus::Created);

    Ok(())
}

#[tokio::test]
async fn listener_repository_update_is_a_noop_for_missing_listener() -> Result<(), TeamserverError>
{
    let database = test_database().await?;
    let repository = database.listeners();
    let existing = sample_listener();

    repository.create(&existing).await?;

    let mut ghost = sample_listener();
    if let ListenerConfig::Http(config) = &mut ghost {
        config.name = "never-created".to_owned();
        config.port_bind = 9999;
    }
    // update on a non-existent listener should succeed silently (no-op)
    repository.update(&ghost).await?;

    assert_eq!(repository.get("never-created").await?, None);
    assert_eq!(repository.count().await?, 1);

    Ok(())
}

#[tokio::test]
async fn listener_repository_exists_tracks_creation_and_deletion() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.listeners();
    let listener = sample_listener();

    assert!(!repository.exists(listener.name()).await?, "should not exist before creation");

    repository.create(&listener).await?;
    assert!(repository.exists(listener.name()).await?, "should exist after creation");

    repository.delete(listener.name()).await?;
    assert!(!repository.exists(listener.name()).await?, "should not exist after deletion");

    Ok(())
}

#[tokio::test]
async fn listener_repository_set_state_is_a_noop_for_missing_listener()
-> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.listeners();
    let existing = sample_listener();

    repository.create(&existing).await?;
    repository.set_state("missing-listener", ListenerStatus::Stopped, Some("offline")).await?;

    assert_eq!(repository.get("missing-listener").await?, None);
    assert_eq!(
        repository.get(existing.name()).await?,
        Some(PersistedListener {
            name: existing.name().to_owned(),
            protocol: existing.protocol(),
            config: existing.clone(),
            state: PersistedListenerState { status: ListenerStatus::Created, last_error: None },
        })
    );

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
    let err = result.unwrap_err();
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

    sqlx::query("UPDATE ts_agents SET aes_key = '!!!not-valid-base64!!!' WHERE agent_id = ?")
        .bind(i64::from(agent.agent_id))
        .execute(database.pool())
        .await
        .expect("raw SQL update must succeed");

    let result = repository.list().await;
    assert!(result.is_err(), "list() must fail when a row has invalid base64 aes_key");
    let err = result.unwrap_err();
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

    sqlx::query("UPDATE ts_agents SET aes_iv = '!!!not-valid-base64!!!' WHERE agent_id = ?")
        .bind(i64::from(agent.agent_id))
        .execute(database.pool())
        .await
        .expect("raw SQL update must succeed");

    let result = repository.list().await;
    assert!(result.is_err(), "list() must fail when a row has invalid base64 aes_iv");
    let err = result.unwrap_err();
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

    sqlx::query("UPDATE ts_agents SET aes_key = '@@invalid@@' WHERE agent_id = ?")
        .bind(i64::from(agent.agent_id))
        .execute(database.pool())
        .await
        .expect("raw SQL update must succeed");

    let result = repository.get(agent.agent_id).await;
    assert!(result.is_err(), "get() must fail when the row has invalid base64 aes_key");
    let err = result.unwrap_err();
    assert!(
        matches!(&err, TeamserverError::InvalidPersistedValue { field, .. } if *field == "aes_key"),
        "expected InvalidPersistedValue for aes_key, got: {err:?}",
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Corrupted-row rejection tests for reload / conversion error paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn agent_get_persisted_with_corrupt_aes_key_returns_error() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.agents();

    let agent = sample_agent(0xBAD1_0001);
    repository.create(&agent).await?;

    sqlx::query("UPDATE ts_agents SET aes_key = '!!!bad!!!' WHERE agent_id = ?")
        .bind(i64::from(agent.agent_id))
        .execute(database.pool())
        .await
        .expect("raw SQL update must succeed");

    let result = repository.get_persisted(agent.agent_id).await;
    assert!(result.is_err(), "get_persisted() must fail on invalid base64 aes_key");
    let err = result.unwrap_err();
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

    sqlx::query("UPDATE ts_agents SET aes_iv = '!!!bad!!!' WHERE agent_id = ?")
        .bind(i64::from(agent.agent_id))
        .execute(database.pool())
        .await
        .expect("raw SQL update must succeed");

    let result = repository.list_persisted().await;
    assert!(result.is_err(), "list_persisted() must fail on invalid base64 aes_iv");
    let err = result.unwrap_err();
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
    let err = result.unwrap_err();
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
    let err = result.unwrap_err();
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
    let err = result.unwrap_err();
    assert!(
        matches!(&err, TeamserverError::InvalidPersistedValue { field, .. } if *field == "os_build"),
        "expected InvalidPersistedValue for os_build, got: {err:?}",
    );

    Ok(())
}

#[tokio::test]
async fn listener_get_with_unsupported_protocol_returns_error() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.listeners();

    let listener = sample_listener();
    repository.create(&listener).await?;

    sqlx::query("UPDATE ts_listeners SET protocol = 'QUIC' WHERE name = ?")
        .bind(listener.name())
        .execute(database.pool())
        .await
        .expect("raw SQL update must succeed");

    let result = repository.get(listener.name()).await;
    assert!(result.is_err(), "get() must fail on unsupported protocol 'QUIC'");
    let err = result.unwrap_err();
    assert!(
        matches!(&err, TeamserverError::InvalidPersistedValue { field, .. } if *field == "protocol"),
        "expected InvalidPersistedValue for protocol, got: {err:?}",
    );

    Ok(())
}

#[tokio::test]
async fn listener_list_with_unsupported_status_returns_error() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.listeners();

    let listener = sample_listener();
    repository.create(&listener).await?;

    sqlx::query("UPDATE ts_listeners SET status = 'exploded' WHERE name = ?")
        .bind(listener.name())
        .execute(database.pool())
        .await
        .expect("raw SQL update must succeed");

    let result = repository.list().await;
    assert!(result.is_err(), "list() must fail on unsupported listener status 'exploded'");
    let err = result.unwrap_err();
    assert!(
        matches!(&err, TeamserverError::InvalidListenerState { state } if state == "exploded"),
        "expected InvalidListenerState for 'exploded', got: {err:?}",
    );

    Ok(())
}

#[tokio::test]
async fn operator_get_with_unsupported_role_returns_error() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.operators();

    let operator = PersistedOperator {
        username: "bad-role-user".to_owned(),
        password_verifier: "dummy-verifier".to_owned(),
        role: OperatorRole::Admin,
    };
    repository.create(&operator).await?;

    sqlx::query("UPDATE ts_runtime_operators SET role = 'Superuser' WHERE username = ?")
        .bind(&operator.username)
        .execute(database.pool())
        .await
        .expect("raw SQL update must succeed");

    let result = repository.get(&operator.username).await;
    assert!(result.is_err(), "get() must fail on unsupported operator role 'Superuser'");
    let err = result.unwrap_err();
    assert!(
        matches!(&err, TeamserverError::InvalidPersistedValue { field, .. } if *field == "ts_runtime_operators.role"),
        "expected InvalidPersistedValue for role, got: {err:?}",
    );

    Ok(())
}

#[tokio::test]
async fn operator_list_with_unsupported_role_returns_error() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.operators();

    let operator = PersistedOperator {
        username: "bad-role-list".to_owned(),
        password_verifier: "dummy-verifier".to_owned(),
        role: OperatorRole::Operator,
    };
    repository.create(&operator).await?;

    sqlx::query("UPDATE ts_runtime_operators SET role = 'Root' WHERE username = ?")
        .bind(&operator.username)
        .execute(database.pool())
        .await
        .expect("raw SQL update must succeed");

    let result = repository.list().await;
    assert!(result.is_err(), "list() must fail on unsupported operator role 'Root'");
    let err = result.unwrap_err();
    assert!(
        matches!(&err, TeamserverError::InvalidPersistedValue { field, .. } if *field == "ts_runtime_operators.role"),
        "expected InvalidPersistedValue for role, got: {err:?}",
    );

    Ok(())
}

#[tokio::test]
async fn listener_get_with_corrupt_config_json_returns_error() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.listeners();

    let listener = sample_listener();
    repository.create(&listener).await?;

    sqlx::query("UPDATE ts_listeners SET config = '{not valid json' WHERE name = ?")
        .bind(listener.name())
        .execute(database.pool())
        .await
        .expect("raw SQL update must succeed");

    let result = repository.get(listener.name()).await;
    assert!(result.is_err(), "get() must fail on corrupt config JSON");
    let err = result.unwrap_err();
    assert!(
        matches!(&err, TeamserverError::Json(_)),
        "expected Json error for corrupt config, got: {err:?}",
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
    let err = result.unwrap_err();
    assert!(
        matches!(&err, TeamserverError::InvalidPersistedValue { field, .. } if *field == "base_address"),
        "expected InvalidPersistedValue for base_address, got: {err:?}",
    );

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
async fn link_repository_rejects_duplicate_insert() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let agents = database.agents();
    let links = database.links();
    let parent = sample_agent(0x5500_0001);
    let child = sample_agent(0x5500_0002);

    agents.create(&parent).await?;
    agents.create(&child).await?;

    let link = LinkRecord { parent_agent_id: parent.agent_id, link_agent_id: child.agent_id };
    links.create(link.clone()).await?;

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

// ---------------------------------------------------------------------------
// Audit & session-activity pagination boundary conditions
// ---------------------------------------------------------------------------

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
