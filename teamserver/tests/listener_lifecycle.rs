//! Listener lifecycle integration tests.
//!
//! These tests exercise the [`ListenerManager`] state machine via its public API
//! and verify that the persisted database state remains consistent with the actual
//! task state across start, stop, restart, crash recovery, and concurrent operations.

mod common;

use std::time::Duration;

use red_cell::{
    AgentRegistry, Database, EventBus, ListenerManager, ListenerManagerError, ListenerStatus,
    SocketRelayManager,
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

#[tokio::test]
async fn create_duplicate_name_returns_error_and_preserves_original()
-> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port_a, _guard_a) = common::available_port()?;
    let (port_b, _guard_b) = common::available_port_excluding(port_a)?;

    // First create succeeds.
    manager.create(http_config("lc-dup", port_a)).await?;

    // Second create with the same name but different port must fail.
    let result = manager.create(http_config("lc-dup", port_b)).await;
    assert!(result.is_err(), "duplicate create must return an error");

    let err = result.unwrap_err();
    assert!(
        matches!(err, ListenerManagerError::DuplicateListener { .. }),
        "error must be DuplicateListener, got: {err}"
    );

    // The original config must be unchanged — still bound to port_a.
    let summary = manager.summary("lc-dup").await?;
    assert_eq!(summary.state.status, ListenerStatus::Created);
    match &summary.config {
        ListenerConfig::Http(http) => {
            assert_eq!(http.port_bind, port_a, "original port must be preserved");
        }
        other => panic!("expected Http config, got {:?}", other.protocol()),
    }

    // Only one listener entry must exist.
    let all = manager.list().await?;
    let dup_count = all.iter().filter(|s| s.name == "lc-dup").count();
    assert_eq!(dup_count, 1, "exactly one listener with the name must exist");

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

#[tokio::test]
async fn restore_running_with_port_in_use_transitions_to_error_state()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let (port, guard) = common::available_port()?;

    // Simulate a stale Running entry left behind by a crashed teamserver.
    {
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager = ListenerManager::new(database.clone(), registry, events, sockets, None);
        manager.create(http_config("lc-restore-err", port)).await?;
        manager.repository().set_state("lc-restore-err", ListenerStatus::Running, None).await?;
    }

    // Build a new manager over the same DB — keep the guard alive so the port
    // remains occupied and restore_running() cannot bind it.
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let restored = ListenerManager::new(database, registry, events, sockets, None);

    let result = restored.restore_running().await;
    assert!(result.is_err(), "restore_running must propagate the bind failure");

    // Even though restore_running returned an error, the DB should have been
    // transitioned to Error with a descriptive message.
    let summary = restored.summary("lc-restore-err").await?;
    assert_eq!(
        summary.state.status,
        ListenerStatus::Error,
        "listener must be in Error state when port is occupied"
    );
    assert!(
        summary.state.last_error.is_some(),
        "Error state must include a non-empty last_error message"
    );

    // Ensure the guard kept the port occupied for the duration of the test.
    drop(guard);
    Ok(())
}

#[tokio::test]
async fn restore_running_failure_halts_before_remaining_listeners()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let (port_fail, guard_fail) = common::available_port()?;
    let (port_ok, guard_ok) = common::available_port_excluding(port_fail)?;

    // Seed two listeners as Running in the DB.  Names are chosen so that the
    // failing listener ("lc-restore-aa-fail") sorts before the healthy one
    // ("lc-restore-bb-ok") in the `ORDER BY name` iteration that
    // `restore_running` uses.
    {
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager = ListenerManager::new(database.clone(), registry, events, sockets, None);
        manager.create(http_config("lc-restore-aa-fail", port_fail)).await?;
        manager.create(http_config("lc-restore-bb-ok", port_ok)).await?;
        manager.repository().set_state("lc-restore-aa-fail", ListenerStatus::Running, None).await?;
        manager.repository().set_state("lc-restore-bb-ok", ListenerStatus::Running, None).await?;
    }

    // Build a new manager over the same DB.  Keep `guard_fail` alive so
    // "lc-restore-aa-fail" cannot bind, but release `guard_ok` so the other
    // port is free.
    drop(guard_ok);
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let restored = ListenerManager::new(database, registry, events, sockets, None);

    let result = restored.restore_running().await;
    assert!(result.is_err(), "restore_running must return an error when a listener cannot rebind");

    // The failing listener must have been transitioned to Error with a message.
    let fail_summary = restored.summary("lc-restore-aa-fail").await?;
    assert_eq!(
        fail_summary.state.status,
        ListenerStatus::Error,
        "the failing listener must be in Error state"
    );
    assert!(
        fail_summary.state.last_error.is_some(),
        "the failing listener must record an error message"
    );

    // Because restore_running returns early on the first bind failure, the
    // second listener is never attempted — it still has its stale Running
    // status from the previous session, with no live runtime behind it.
    let ok_summary = restored.summary("lc-restore-bb-ok").await?;
    assert_eq!(
        ok_summary.state.status,
        ListenerStatus::Running,
        "the second listener is left with stale Running state (early return)"
    );

    drop(guard_fail);
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

// ---------------------------------------------------------------------------
// Update tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn update_stopped_listener_replaces_config() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port_a, _guard_a) = common::available_port()?;
    let (port_b, guard_b) = common::available_port_excluding(port_a)?;

    manager.create(http_config("lc-update-stopped", port_a)).await?;

    // Update the config to use a different port while still in Created state.
    let updated = manager.update(http_config("lc-update-stopped", port_b)).await?;

    // The listener should be in Stopped state after update (update sets Stopped).
    assert_eq!(updated.state.status, ListenerStatus::Stopped);

    // Verify the persisted config has the new port.
    let summary = manager.summary("lc-update-stopped").await?;
    match &summary.config {
        ListenerConfig::Http(http) => {
            assert_eq!(http.port_bind, port_b, "port must be updated to the new value");
        }
        other => panic!("expected Http config, got {:?}", other.protocol()),
    }

    // Start on the new port to confirm it actually works.
    drop(guard_b);
    let running = manager.start("lc-update-stopped").await?;
    assert_eq!(running.state.status, ListenerStatus::Running);

    timeout(Duration::from_secs(2), common::wait_for_listener(port_b)).await??;

    manager.stop("lc-update-stopped").await?;
    Ok(())
}

#[tokio::test]
async fn update_running_listener_restarts_with_new_config() -> Result<(), Box<dyn std::error::Error>>
{
    let manager = test_manager().await?;
    let (port_a, guard_a) = common::available_port()?;
    let (port_b, guard_b) = common::available_port_excluding(port_a)?;

    manager.create(http_config("lc-update-running", port_a)).await?;
    drop(guard_a);
    manager.start("lc-update-running").await?;
    common::wait_for_listener(port_a).await?;

    // Update with a new port while the listener is running — should stop, update, restart.
    drop(guard_b);
    let updated = manager.update(http_config("lc-update-running", port_b)).await?;
    assert_eq!(
        updated.state.status,
        ListenerStatus::Running,
        "a running listener must be restarted after update"
    );

    // The new port should be reachable.
    timeout(Duration::from_secs(2), common::wait_for_listener(port_b)).await??;

    // Verify the persisted config reflects the new port.
    let summary = manager.summary("lc-update-running").await?;
    match &summary.config {
        ListenerConfig::Http(http) => {
            assert_eq!(http.port_bind, port_b, "port must be updated to the new value");
        }
        other => panic!("expected Http config, got {:?}", other.protocol()),
    }

    manager.stop("lc-update-running").await?;
    Ok(())
}

#[tokio::test]
async fn update_nonexistent_listener_returns_error() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, _guard) = common::available_port()?;

    let result = manager.update(http_config("no-such-listener", port)).await;
    assert!(result.is_err(), "updating a listener that does not exist must return an error");
    Ok(())
}

// ---------------------------------------------------------------------------
// Delete nonexistent test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delete_nonexistent_listener_returns_error() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;

    let result = manager.delete("no-such-listener").await;
    assert!(result.is_err(), "deleting a listener that does not exist must return an error");
    Ok(())
}

// ---------------------------------------------------------------------------
// Error-state recovery tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn start_succeeds_after_error_state_recovery() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    // 1. Create a listener and attempt to start it while the port is occupied.
    manager.create(http_config("lc-error-recovery", port)).await?;
    let result = manager.start("lc-error-recovery").await;
    assert!(result.is_err(), "start must fail when port is occupied");

    let summary = manager.summary("lc-error-recovery").await?;
    assert_eq!(summary.state.status, ListenerStatus::Error);
    assert!(summary.state.last_error.is_some(), "error state must record a failure message");

    // 2. Release the port so the listener can bind.
    drop(guard);

    // 3. Retry start — should transition from Error to Running.
    let running = manager.start("lc-error-recovery").await?;
    assert_eq!(
        running.state.status,
        ListenerStatus::Running,
        "listener must transition from Error to Running after port is freed"
    );

    // 4. Verify the DB is consistent.
    let db_summary = manager.summary("lc-error-recovery").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Running);
    assert!(
        db_summary.state.last_error.is_none(),
        "last_error must be cleared after successful restart"
    );

    // 5. Verify the listener is actually accepting connections.
    timeout(Duration::from_secs(2), common::wait_for_listener(port)).await??;

    manager.stop("lc-error-recovery").await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Same-port conflict between managed listeners
// ---------------------------------------------------------------------------

#[tokio::test]
async fn start_second_listener_on_same_port_fails_and_preserves_first()
-> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    // Create two listeners with different names but the same bind port.
    manager.create(http_config("lc-port-first", port)).await?;
    manager.create(http_config("lc-port-second", port)).await?;

    // Start the first listener — release the port guard so it can bind.
    drop(guard);
    manager.start("lc-port-first").await?;
    common::wait_for_listener(port).await?;

    // Starting the second listener on the same port must fail.
    let result = manager.start("lc-port-second").await;
    assert!(result.is_err(), "starting a second listener on an occupied port must fail");

    // The second listener must be in Error state with a recorded error message.
    let second_summary = manager.summary("lc-port-second").await?;
    assert_eq!(
        second_summary.state.status,
        ListenerStatus::Error,
        "the colliding listener must be in Error state"
    );
    assert!(
        second_summary.state.last_error.is_some(),
        "the colliding listener must record a last_error message"
    );

    // The first listener must still be Running.
    let first_summary = manager.summary("lc-port-first").await?;
    assert_eq!(
        first_summary.state.status,
        ListenerStatus::Running,
        "the original listener must remain Running"
    );

    // The first listener must still be reachable.
    timeout(Duration::from_secs(2), common::wait_for_listener(port)).await??;

    manager.stop("lc-port-first").await?;
    Ok(())
}
