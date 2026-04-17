//! External listener lifecycle tests.
//!
//! External listeners own no sockets — they register an endpoint on the main
//! teamserver router.  These tests verify state transitions, restart, crash
//! recovery (endpoint re-registration), and deletion.

mod common;
mod listener_helpers;

use listener_helpers::{external_config, test_manager};
use red_cell::{
    AgentRegistry, Database, EventBus, ListenerManager, ListenerStatus, SocketRelayManager,
};

#[tokio::test]
async fn external_listener_create_start_stop_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;

    // Create — persisted in Created state.
    manager.create(external_config("lc-ext-lifecycle", "/bridge-lc")).await?;
    let summary = manager.summary("lc-ext-lifecycle").await?;
    assert_eq!(summary.state.status, ListenerStatus::Created);

    // Start — transitions to Running (no socket owned, just registration).
    let started = manager.start("lc-ext-lifecycle").await?;
    assert_eq!(started.state.status, ListenerStatus::Running);

    let db_summary = manager.summary("lc-ext-lifecycle").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Running);

    // Stop — transitions to Stopped.
    let stopped = manager.stop("lc-ext-lifecycle").await?;
    assert_eq!(stopped.state.status, ListenerStatus::Stopped);

    let db_summary = manager.summary("lc-ext-lifecycle").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Stopped);

    Ok(())
}

#[tokio::test]
async fn external_listener_restart_after_stop() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;

    manager.create(external_config("lc-ext-restart", "/bridge-restart")).await?;
    manager.start("lc-ext-restart").await?;
    manager.stop("lc-ext-restart").await?;

    // Restart — should succeed (external listeners have no socket to rebind).
    let restarted = manager.start("lc-ext-restart").await?;
    assert_eq!(restarted.state.status, ListenerStatus::Running);

    let db_summary = manager.summary("lc-ext-restart").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Running);
    assert!(db_summary.state.last_error.is_none(), "no error after successful restart");

    manager.stop("lc-ext-restart").await?;
    Ok(())
}

#[tokio::test]
async fn restore_running_restarts_persisted_external_listener()
-> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;

    // Simulate a teamserver crash: create the External listener in the DB and manually
    // set its state to Running without actually spawning a runtime task.
    {
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager = ListenerManager::new(database.clone(), registry, events, sockets, None)
            .with_demon_allow_legacy_ctr(true);
        manager.create(external_config("lc-ext-restore", "/bridge-restore")).await?;
        manager.repository().set_state("lc-ext-restore", ListenerStatus::Running, None).await?;
        let summary = manager.summary("lc-ext-restore").await?;
        assert_eq!(summary.state.status, ListenerStatus::Running);
        // manager is dropped — no live runtime task, DB still says Running,
        // but external_endpoints map is empty (simulates crash).
    }

    // A new manager over the same DB should call restore_running and re-register
    // the external listener endpoint.
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let restored = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

    restored.restore_running().await?;

    let summary = restored.summary("lc-ext-restore").await?;
    assert_eq!(
        summary.state.status,
        ListenerStatus::Running,
        "restore_running must transition the external listener back to Running"
    );

    // Yield to let the spawned task register the endpoint in external_endpoints.
    tokio::task::yield_now().await;

    // The key assertion: the endpoint map must be repopulated so the Axum
    // fallback handler can route bridge requests to this listener.
    let state = restored.external_state_for_path("/bridge-restore").await.expect(
        "restore_running must re-register external listener endpoint in external_endpoints",
    );
    assert_eq!(state.listener_name(), "lc-ext-restore");
    assert_eq!(state.endpoint(), "/bridge-restore");

    restored.stop("lc-ext-restore").await?;
    Ok(())
}

#[tokio::test]
async fn external_listener_delete_while_running() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;

    manager.create(external_config("lc-ext-delete", "/bridge-delete")).await?;
    manager.start("lc-ext-delete").await?;

    // Delete should stop and remove.
    manager.delete("lc-ext-delete").await?;

    let result = manager.summary("lc-ext-delete").await;
    assert!(result.is_err(), "deleted external listener must not be found");

    // The endpoint should be freed — a new listener can claim it.
    manager.create(external_config("lc-ext-delete-2", "/bridge-delete")).await?;
    Ok(())
}
