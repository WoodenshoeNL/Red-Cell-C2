use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use red_cell::database::{
    AuditLogEntry, Database, LinkRecord, ListenerStatus, LootRecord, PersistedListener,
    PersistedListenerState, TeamserverError,
};
use red_cell_common::{
    AgentEncryptionInfo, AgentInfo, HttpListenerConfig, HttpListenerProxyConfig,
    HttpListenerResponseConfig, ListenerConfig, ListenerTlsConfig,
};
use serde_json::json;

fn temp_db_path() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();

    std::env::temp_dir().join(format!("red-cell-teamserver-db-{unique}.sqlite"))
}

fn sample_agent(agent_id: u32) -> AgentInfo {
    AgentInfo {
        agent_id,
        active: true,
        reason: String::new(),
        encryption: AgentEncryptionInfo {
            aes_key: "YWVzLWtleQ==".to_owned(),
            aes_iv: "YWVzLWl2".to_owned(),
        },
        hostname: "wkstn-01".to_owned(),
        username: "operator".to_owned(),
        domain_name: "REDCELL".to_owned(),
        external_ip: "203.0.113.10".to_owned(),
        internal_ip: "10.0.0.25".to_owned(),
        process_name: "explorer.exe".to_owned(),
        base_address: 0x401000,
        process_pid: 1337,
        process_tid: 1338,
        process_ppid: 512,
        process_arch: "x64".to_owned(),
        elevated: true,
        os_version: "Windows 11".to_owned(),
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
        user_agent: Some("Mozilla/5.0".to_owned()),
        headers: vec!["X-Test: true".to_owned()],
        uris: vec!["/index".to_owned()],
        host_header: Some("cdn.red-cell.test".to_owned()),
        secure: true,
        cert: Some(ListenerTlsConfig {
            cert: "server.pem".to_owned(),
            key: "server.key".to_owned(),
        }),
        response: Some(HttpListenerResponseConfig { headers: vec!["Server: nginx".to_owned()] }),
        proxy: Some(HttpListenerProxyConfig {
            enabled: true,
            proxy_type: Some("http".to_owned()),
            host: "127.0.0.1".to_owned(),
            port: 8080,
            username: Some("proxy".to_owned()),
            password: Some("secret".to_owned()),
        }),
    })
}

async fn test_database() -> Result<Database, TeamserverError> {
    Database::connect(temp_db_path()).await
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
    assert!(tables.iter().any(|name| name == "ts_audit_log"));

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
