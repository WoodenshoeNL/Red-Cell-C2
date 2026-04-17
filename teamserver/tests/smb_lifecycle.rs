//! SMB listener lifecycle tests.
//!
//! These tests exercise the [`ListenerManager`] state machine for SMB
//! (named-pipe) listeners, including crash recovery via `restore_running`.
//! Pipeline-level behaviour (DEMON_INIT handshake, encrypted callbacks) is
//! covered in `smb_listener.rs`.

mod common;
mod listener_helpers;

use std::time::Duration;

use listener_helpers::{smb_config, test_manager, unique_pipe_name, wait_for_smb_listener};
use red_cell::{
    AgentRegistry, Database, EventBus, ListenerManager, ListenerStatus, SocketRelayManager,
};
use tokio::time::timeout;

#[cfg(unix)]
#[tokio::test]
async fn smb_listener_create_start_stop_lifecycle() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let pipe = unique_pipe_name("lifecycle");

    // Create — persisted in Created state.
    manager.create(smb_config("lc-smb-lifecycle", &pipe)).await?;
    let summary = manager.summary("lc-smb-lifecycle").await?;
    assert_eq!(summary.state.status, ListenerStatus::Created);

    // Start — transitions to Running.
    let started = manager.start("lc-smb-lifecycle").await?;
    assert_eq!(started.state.status, ListenerStatus::Running);

    // Verify the pipe is actually accepting connections.
    timeout(Duration::from_secs(2), wait_for_smb_listener(&pipe)).await??;

    // DB state must be consistent.
    let db_summary = manager.summary("lc-smb-lifecycle").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Running);

    // Stop — transitions to Stopped.
    let stopped = manager.stop("lc-smb-lifecycle").await?;
    assert_eq!(stopped.state.status, ListenerStatus::Stopped);

    let db_summary = manager.summary("lc-smb-lifecycle").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Stopped);

    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn smb_listener_restart_after_stop_rebinds_pipe() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let pipe = unique_pipe_name("restart");

    manager.create(smb_config("lc-smb-restart", &pipe)).await?;
    manager.start("lc-smb-restart").await?;

    // Verify the pipe is reachable.
    timeout(Duration::from_secs(2), wait_for_smb_listener(&pipe)).await??;

    // Stop — pipe should be cleaned up.
    manager.stop("lc-smb-restart").await?;

    // Restart — pipe must be re-created and accepting connections again.
    let restarted = manager.start("lc-smb-restart").await?;
    assert_eq!(restarted.state.status, ListenerStatus::Running);

    timeout(Duration::from_secs(2), wait_for_smb_listener(&pipe)).await??;

    // DB state must be consistent.
    let db_summary = manager.summary("lc-smb-restart").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Running);
    assert!(db_summary.state.last_error.is_none(), "no error after successful restart");

    manager.stop("lc-smb-restart").await?;
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn smb_listener_multiple_restart_cycles_succeed() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let pipe = unique_pipe_name("multi-restart");

    manager.create(smb_config("lc-smb-multi-restart", &pipe)).await?;

    for cycle in 0..3 {
        let started = manager.start("lc-smb-multi-restart").await?;
        assert_eq!(
            started.state.status,
            ListenerStatus::Running,
            "cycle {cycle}: listener must be Running after start"
        );

        timeout(Duration::from_secs(2), wait_for_smb_listener(&pipe)).await??;

        let stopped = manager.stop("lc-smb-multi-restart").await?;
        assert_eq!(
            stopped.state.status,
            ListenerStatus::Stopped,
            "cycle {cycle}: listener must be Stopped after stop"
        );
    }

    let db_summary = manager.summary("lc-smb-multi-restart").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Stopped);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn restore_running_restarts_persisted_smb_listener() -> Result<(), Box<dyn std::error::Error>>
{
    let database = Database::connect_in_memory().await?;
    let pipe = unique_pipe_name("restore");

    // Simulate a teamserver crash with a stale Running SMB listener.
    {
        let registry = AgentRegistry::new(database.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let manager = ListenerManager::new(database.clone(), registry, events, sockets, None)
            .with_demon_allow_legacy_ctr(true);
        manager.create(smb_config("lc-smb-restore", &pipe)).await?;
        manager.repository().set_state("lc-smb-restore", ListenerStatus::Running, None).await?;
    }

    // A new manager should restore the SMB listener.
    let registry = AgentRegistry::new(database.clone());
    let events = EventBus::default();
    let sockets = SocketRelayManager::new(registry.clone(), events.clone());
    let restored = ListenerManager::new(database, registry, events, sockets, None)
        .with_demon_allow_legacy_ctr(true);

    restored.restore_running().await?;

    let summary = restored.summary("lc-smb-restore").await?;
    assert_eq!(
        summary.state.status,
        ListenerStatus::Running,
        "restore_running must transition the SMB listener back to Running"
    );

    // Verify the pipe is actually accepting connections.
    timeout(Duration::from_secs(2), wait_for_smb_listener(&pipe)).await??;

    restored.stop("lc-smb-restore").await?;
    Ok(())
}
