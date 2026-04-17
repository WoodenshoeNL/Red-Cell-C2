//! HTTP listener crash-recovery tests.
//!
//! These tests simulate a teamserver crash that leaves stale `Running` rows in
//! the database with no live runtime task, then verify that
//! [`ListenerManager::restore_running`] brings them back up or transitions
//! them to `Error` with a descriptive message.

mod common;
mod listener_helpers;

use std::time::Duration;

use listener_helpers::http_config;
use red_cell::{
    AgentRegistry, Database, EventBus, ListenerManager, ListenerStatus, SocketRelayManager,
};
use tokio::time::timeout;

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
        let manager = ListenerManager::new(database.clone(), registry, events, sockets, None)
            .with_demon_allow_legacy_ctr(true);
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
    let restored = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

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
        let manager = ListenerManager::new(database.clone(), registry, events, sockets, None)
            .with_demon_allow_legacy_ctr(true);
        manager.create(http_config("lc-restore-err", port)).await?;
        manager.repository().set_state("lc-restore-err", ListenerStatus::Running, None).await?;
    }

    // Build a new manager over the same DB — keep the guard alive so the port
    // remains occupied and restore_running() cannot bind it.
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let restored = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

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
        let manager = ListenerManager::new(database.clone(), registry, events, sockets, None)
            .with_demon_allow_legacy_ctr(true);
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
    let restored = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

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
