use red_cell::database::{Database, DbMasterKey, TeamserverError};
use sqlx::sqlite::SqliteConnectOptions;
use tempfile::TempDir;

#[path = "database_common.rs"]
mod database_common;
use database_common::{sample_agent, sqlite_options, test_database};

// ---------------------------------------------------------------------------
// Failure injection tests
// ---------------------------------------------------------------------------

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
async fn operations_after_pool_close_return_connection_error() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let agents = database.agents();

    // Seed one agent so we know the schema is valid.
    agents.create(&sample_agent(0xCE00_0001)).await?;

    // Close the pool — simulates connection loss.
    database.close().await;

    // Every subsequent operation should fail with a pool/connection error.
    let create_err = agents
        .create(&sample_agent(0xCE00_0002))
        .await
        .expect_err("create after pool close should fail");
    assert!(
        matches!(create_err, TeamserverError::Database(_)),
        "expected Database error after pool close, got: {create_err:?}"
    );

    let list_err = agents.list().await.expect_err("list after pool close should fail");
    assert!(matches!(list_err, TeamserverError::Database(_)));

    let get_err = agents.get(0xCE00_0001).await.expect_err("get after pool close should fail");
    assert!(matches!(get_err, TeamserverError::Database(_)));

    Ok(())
}

#[tokio::test]
async fn write_to_read_only_database_returns_error() -> Result<(), TeamserverError> {
    let temp_dir = TempDir::new().expect("tempdir should be created");
    let db_path = temp_dir.path().join("readonly.sqlite");

    // Use a stable master key so both connections can decrypt at-rest data.
    // Create the database and seed it.
    let database =
        Database::connect_with_master_key(&db_path, DbMasterKey::from_bytes([0x42u8; 32])).await?;
    database.agents().create(&sample_agent(0xCE00_0040)).await?;
    database.close().await;

    // Make the database file read-only.
    let mut perms = std::fs::metadata(&db_path).expect("metadata").permissions();
    perms.set_readonly(true);
    std::fs::set_permissions(&db_path, perms).expect("set_permissions");

    // Reconnect to the read-only file with the same master key.
    let options = SqliteConnectOptions::new().filename(&db_path).foreign_keys(true);
    let database =
        Database::connect_with_options_and_key(options, DbMasterKey::from_bytes([0x42u8; 32]))
            .await?;

    let write_err = database
        .agents()
        .create(&sample_agent(0xCE00_0041))
        .await
        .expect_err("write to read-only database should fail");

    assert!(
        matches!(write_err, TeamserverError::Database(_)),
        "expected Database error for read-only write, got: {write_err:?}"
    );

    // Original data should still be readable.
    let agents = database.agents().list().await?;
    assert_eq!(agents.len(), 1);
    assert_eq!(agents[0].agent_id, 0xCE00_0040);

    // Restore permissions so temp_dir cleanup succeeds.
    let mut perms = std::fs::metadata(&db_path).expect("metadata").permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    std::fs::set_permissions(&db_path, perms).expect("restore permissions");

    Ok(())
}
