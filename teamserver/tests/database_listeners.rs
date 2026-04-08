use red_cell::database::{
    ListenerStatus, PersistedListener, PersistedListenerState, TeamserverError,
};
use red_cell_common::ListenerConfig;

#[path = "database_common.rs"]
mod database_common;
use database_common::{sample_listener, test_database};

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
async fn listener_repository_names_returns_sorted_names() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let repository = database.listeners();

    // Empty table — names() should return an empty vec.
    assert!(repository.names().await?.is_empty(), "names should be empty initially");

    // Insert two listeners with names that sort alphabetically: "alpha" < "http-main".
    let listener_a = {
        let mut l = sample_listener();
        if let ListenerConfig::Http(config) = &mut l {
            config.name = "alpha".to_owned();
        }
        l
    };
    let listener_b = sample_listener(); // name = "http-main"

    // Insert in reverse alphabetical order to verify ORDER BY, not insertion order.
    repository.create(&listener_b).await?;
    repository.create(&listener_a).await?;

    assert_eq!(
        repository.names().await?,
        vec!["alpha".to_owned(), "http-main".to_owned()],
        "names must be returned in alphabetical order"
    );

    // Delete one listener and verify the list shrinks.
    repository.delete("alpha").await?;
    assert_eq!(
        repository.names().await?,
        vec!["http-main".to_owned()],
        "names must reflect deletion"
    );

    Ok(())
}

#[tokio::test]
async fn listener_repository_count_tracks_insertions_and_deletions() -> Result<(), TeamserverError>
{
    let database = test_database().await?;
    let repository = database.listeners();

    // Empty table.
    assert_eq!(repository.count().await?, 0, "count should be 0 initially");

    let listener_a = {
        let mut l = sample_listener();
        if let ListenerConfig::Http(config) = &mut l {
            config.name = "alpha".to_owned();
        }
        l
    };
    let listener_b = sample_listener(); // name = "http-main"

    repository.create(&listener_a).await?;
    assert_eq!(repository.count().await?, 1, "count should be 1 after first insert");

    repository.create(&listener_b).await?;
    assert_eq!(repository.count().await?, 2, "count should be 2 after second insert");

    // Delete one — count should decrement.
    repository.delete("alpha").await?;
    assert_eq!(repository.count().await?, 1, "count should be 1 after deletion");

    // Delete the other — back to zero.
    repository.delete("http-main").await?;
    assert_eq!(repository.count().await?, 0, "count should be 0 after all deletions");

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
    let err = result.expect_err("expected Err");
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
    let err = result.expect_err("expected Err");
    assert!(
        matches!(&err, TeamserverError::InvalidListenerState { state } if state == "exploded"),
        "expected InvalidListenerState for 'exploded', got: {err:?}",
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
    let err = result.expect_err("expected Err");
    assert!(
        matches!(&err, TeamserverError::Json(_)),
        "expected Json error for corrupt config, got: {err:?}",
    );

    Ok(())
}

#[tokio::test]
async fn listener_operations_after_pool_close_return_connection_error()
-> Result<(), TeamserverError> {
    let database = test_database().await?;
    let listeners = database.listeners();

    listeners.create(&sample_listener()).await?;
    database.close().await;

    let err = listeners.list().await.expect_err("listener list after close should fail");
    assert!(matches!(err, TeamserverError::Database(_)));

    let err = listeners
        .create(&sample_listener())
        .await
        .expect_err("listener create after close should fail");
    assert!(matches!(err, TeamserverError::Database(_)));

    Ok(())
}
