//! DNS listener lifecycle tests.
//!
//! These tests exercise the [`ListenerManager`] state machine for DNS
//! listeners, including crash recovery via `restore_running`.  Pipeline-level
//! behaviour (DEMON_INIT over DNS, encrypted callbacks) is covered in
//! `dns_listener_pipeline.rs`.

mod common;
mod listener_helpers;

use std::time::Duration;

use listener_helpers::{dns_config, test_manager, wait_for_dns_listener};
use red_cell::{
    AgentRegistry, Database, EventBus, ListenerManager, ListenerStatus, SocketRelayManager,
};
use tokio::time::timeout;

#[tokio::test]
async fn dns_listener_create_start_stop_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    // Create — persisted in Created state.
    manager.create(dns_config("lc-dns-lifecycle", port)).await?;
    let summary = manager.summary("lc-dns-lifecycle").await?;
    assert_eq!(summary.state.status, ListenerStatus::Created);

    // Start — transitions to Running.
    drop(guard);
    let started = manager.start("lc-dns-lifecycle").await?;
    assert_eq!(started.state.status, ListenerStatus::Running);

    // Verify the UDP socket is accepting queries.
    timeout(Duration::from_secs(2), wait_for_dns_listener(port)).await??;

    // DB state must be consistent.
    let db_summary = manager.summary("lc-dns-lifecycle").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Running);

    // Stop — transitions to Stopped.
    let stopped = manager.stop("lc-dns-lifecycle").await?;
    assert_eq!(stopped.state.status, ListenerStatus::Stopped);

    let db_summary = manager.summary("lc-dns-lifecycle").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Stopped);

    Ok(())
}

#[tokio::test]
async fn dns_listener_restart_after_stop_rebinds_port() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    manager.create(dns_config("lc-dns-restart", port)).await?;
    drop(guard);
    manager.start("lc-dns-restart").await?;
    timeout(Duration::from_secs(2), wait_for_dns_listener(port)).await??;

    manager.stop("lc-dns-restart").await?;

    // Restart — UDP port must be re-bound.
    let restarted = manager.start("lc-dns-restart").await?;
    assert_eq!(restarted.state.status, ListenerStatus::Running);

    timeout(Duration::from_secs(2), wait_for_dns_listener(port)).await??;

    let db_summary = manager.summary("lc-dns-restart").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Running);
    assert!(db_summary.state.last_error.is_none(), "no error after successful restart");

    manager.stop("lc-dns-restart").await?;
    Ok(())
}

#[tokio::test]
async fn restore_running_restarts_persisted_dns_listener() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let (port, guard) = common::available_port()?;

    // Simulate a teamserver crash: create the DNS listener in the DB and manually
    // set its state to Running without actually spawning a runtime task.
    {
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager = ListenerManager::new(database.clone(), registry, events, sockets, None)
            .with_demon_allow_legacy_ctr(true);
        manager.create(dns_config("lc-dns-restore", port)).await?;
        manager.repository().set_state("lc-dns-restore", ListenerStatus::Running, None).await?;
        let summary = manager.summary("lc-dns-restore").await?;
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

    let summary = restored.summary("lc-dns-restore").await?;
    assert_eq!(
        summary.state.status,
        ListenerStatus::Running,
        "restore_running must transition the DNS listener back to Running"
    );

    // Verify the runtime is actually accepting queries.
    timeout(Duration::from_secs(2), wait_for_dns_listener(port)).await??;

    restored.stop("lc-dns-restore").await?;
    Ok(())
}
