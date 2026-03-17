//! Listener lifecycle integration tests.
//!
//! These tests exercise the [`ListenerManager`] state machine via its public API
//! and verify that the persisted database state remains consistent with the actual
//! task state across start, stop, restart, crash recovery, and concurrent operations.

mod common;

use std::time::Duration;

use red_cell::{
    AgentRegistry, Database, EventBus, ListenerManager, ListenerStatus, SocketRelayManager,
};
use red_cell_common::{HttpListenerConfig, ListenerConfig};
use tokio::time::timeout;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a minimal in-memory [`ListenerManager`] for testing.
async fn test_manager() -> Result<ListenerManager, Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    Ok(ListenerManager::new(database, registry, events, sockets, None))
}

/// Build a minimal HTTP listener config bound to `port`.
fn http_config(name: &str, port: u16) -> ListenerConfig {
    ListenerConfig::from(HttpListenerConfig {
        name: name.to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["127.0.0.1".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: port,
        port_conn: Some(port),
        method: Some("POST".to_owned()),
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: None,
        headers: Vec::new(),
        uris: vec!["/".to_owned()],
        host_header: None,
        secure: false,
        cert: None,
        response: None,
        proxy: None,
    })
}

// ---------------------------------------------------------------------------
// State transition tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_persists_listener_in_created_state() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, _guard) = common::available_port()?;

    manager.create(http_config("lc-create", port)).await?;

    let summary = manager.summary("lc-create").await?;
    assert_eq!(summary.state.status, ListenerStatus::Created);
    assert!(summary.state.last_error.is_none());
    Ok(())
}

#[tokio::test]
async fn start_transitions_to_running_state() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    manager.create(http_config("lc-start", port)).await?;
    drop(guard);
    let summary = manager.start("lc-start").await?;

    assert_eq!(summary.state.status, ListenerStatus::Running);

    // Verify the DB is consistent.
    let db_summary = manager.summary("lc-start").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Running);

    manager.stop("lc-start").await?;
    Ok(())
}

#[tokio::test]
async fn stop_transitions_running_listener_to_stopped_state()
-> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    manager.create(http_config("lc-stop", port)).await?;
    drop(guard);
    manager.start("lc-stop").await?;
    let summary = manager.stop("lc-stop").await?;

    assert_eq!(summary.state.status, ListenerStatus::Stopped);

    let db_summary = manager.summary("lc-stop").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Stopped);
    Ok(())
}

#[tokio::test]
async fn restart_after_stop_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    manager.create(http_config("lc-restart", port)).await?;
    drop(guard);
    manager.start("lc-restart").await?;
    manager.stop("lc-restart").await?;

    // The port is now free; a restart should succeed.
    let summary = manager.start("lc-restart").await?;
    assert_eq!(summary.state.status, ListenerStatus::Running);

    let db_summary = manager.summary("lc-restart").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Running);

    manager.stop("lc-restart").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Error condition tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn start_already_running_listener_returns_error() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    manager.create(http_config("lc-double-start", port)).await?;
    drop(guard);
    manager.start("lc-double-start").await?;

    let result = manager.start("lc-double-start").await;
    assert!(result.is_err(), "starting an already-running listener must return an error");

    // Status should remain Running.
    let db_summary = manager.summary("lc-double-start").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Running);

    manager.stop("lc-double-start").await?;
    Ok(())
}

#[tokio::test]
async fn stop_non_running_listener_returns_error() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, _guard) = common::available_port()?;

    manager.create(http_config("lc-double-stop", port)).await?;

    // Listener is in Created state — stop should fail.
    let result = manager.stop("lc-double-stop").await;
    assert!(result.is_err(), "stopping a non-running listener must return an error");

    // Status must still be Created.
    let db_summary = manager.summary("lc-double-stop").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Created);
    Ok(())
}

#[tokio::test]
async fn start_fails_when_port_is_already_in_use() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    // The guard returned by available_port() is already bound to the port, so it acts
    // as the external listener that prevents ListenerManager from claiming the same port.
    let (port, _guard) = common::available_port()?;

    manager.create(http_config("lc-port-in-use", port)).await?;
    let result = manager.start("lc-port-in-use").await;

    assert!(result.is_err(), "starting on a bound port must return an error");

    // The DB should record the error state.
    let db_summary = manager.summary("lc-port-in-use").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Error);
    assert!(db_summary.state.last_error.is_some(), "error state must record the failure message");
    Ok(())
}

#[tokio::test]
async fn start_nonexistent_listener_returns_error() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;

    let result = manager.start("no-such-listener").await;
    assert!(result.is_err(), "starting a listener that does not exist must return an error");
    Ok(())
}

// ---------------------------------------------------------------------------
// Delete tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_running_listener_stops_then_removes() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    manager.create(http_config("lc-delete-running", port)).await?;
    drop(guard);
    manager.start("lc-delete-running").await?;
    common::wait_for_listener(port).await?;

    // Delete should stop the runtime and remove the persisted record.
    manager.delete("lc-delete-running").await?;

    let result = manager.summary("lc-delete-running").await;
    assert!(result.is_err(), "deleted listener must not be found");

    // The port should be released — a new listener can bind it.
    manager.create(http_config("lc-after-delete", port)).await?;
    manager.start("lc-after-delete").await?;
    manager.stop("lc-after-delete").await?;
    Ok(())
}

#[tokio::test]
async fn delete_stopped_listener_removes_record() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, _guard) = common::available_port()?;

    manager.create(http_config("lc-delete-stopped", port)).await?;
    manager.delete("lc-delete-stopped").await?;

    let result = manager.summary("lc-delete-stopped").await;
    assert!(result.is_err(), "deleted listener must not be found");
    Ok(())
}

// ---------------------------------------------------------------------------
// List tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_returns_all_persisted_listeners() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port_a, _guard_a) = common::available_port()?;
    let (port_b, _guard_b) = common::available_port_excluding(port_a)?;

    manager.create(http_config("lc-list-a", port_a)).await?;
    manager.create(http_config("lc-list-b", port_b)).await?;

    let summaries = manager.list().await?;
    let names: Vec<&str> = summaries.iter().map(|s| s.name.as_str()).collect();
    assert!(names.contains(&"lc-list-a"), "list must contain lc-list-a");
    assert!(names.contains(&"lc-list-b"), "list must contain lc-list-b");
    Ok(())
}

// ---------------------------------------------------------------------------
// Crash recovery / restore_running tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn restore_running_restarts_persisted_running_listeners()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let (port, guard) = common::available_port()?;

    // Simulate a teamserver crash: create the listener config in the DB and manually
    // set its state to Running without actually spawning a runtime task.  This mimics
    // a teamserver that died while a listener was active and left a stale Running entry.
    {
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager = ListenerManager::new(database.clone(), registry, events, sockets, None);
        manager.create(http_config("lc-restore", port)).await?;
        // Force the DB state to Running without starting the actual runtime task.
        manager.repository().set_state("lc-restore", ListenerStatus::Running, None).await?;
        let summary = manager.summary("lc-restore").await?;
        assert_eq!(summary.state.status, ListenerStatus::Running);
        // manager is dropped — no live runtime task, DB still says Running.
    }

    // A new manager over the same DB should call restore_running and actually start it.
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let restored = ListenerManager::new(database, registry, events, sockets, None);

    // Release the port reservation so restore_running() can bind it.
    drop(guard);
    restored.restore_running().await?;

    let summary = restored.summary("lc-restore").await?;
    assert_eq!(
        summary.state.status,
        ListenerStatus::Running,
        "restore_running must transition the listener back to Running"
    );

    // Verify the runtime is actually accepting connections.
    timeout(Duration::from_secs(2), common::wait_for_listener(port)).await??;

    restored.stop("lc-restore").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Concurrent operations test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn concurrent_create_and_start_for_independent_listeners_do_not_interfere()
-> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port_a, guard_a) = common::available_port()?;
    let (port_b, guard_b) = common::available_port_excluding(port_a)?;
    let (port_c, guard_c) = common::available_port_excluding(port_b)?;

    // Create all three listeners.
    manager.create(http_config("lc-concurrent-a", port_a)).await?;
    manager.create(http_config("lc-concurrent-b", port_b)).await?;
    manager.create(http_config("lc-concurrent-c", port_c)).await?;

    // Release port reservations before the concurrent starts bind.
    drop(guard_a);
    drop(guard_b);
    drop(guard_c);

    // Start them concurrently.
    let (r_a, r_b, r_c) = tokio::join!(
        manager.start("lc-concurrent-a"),
        manager.start("lc-concurrent-b"),
        manager.start("lc-concurrent-c"),
    );
    r_a?;
    r_b?;
    r_c?;

    // All three should be Running.
    for name in ["lc-concurrent-a", "lc-concurrent-b", "lc-concurrent-c"] {
        let summary = manager.summary(name).await?;
        assert_eq!(
            summary.state.status,
            ListenerStatus::Running,
            "{name} should be Running after concurrent start"
        );
    }

    // Stop all.
    manager.stop("lc-concurrent-a").await?;
    manager.stop("lc-concurrent-b").await?;
    manager.stop("lc-concurrent-c").await?;
    Ok(())
}
