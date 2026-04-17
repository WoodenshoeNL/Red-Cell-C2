//! HTTP listener lifecycle tests — core state transitions.
//!
//! These tests exercise the [`ListenerManager`] state machine for HTTP
//! listeners via its public API and verify that the persisted database state
//! remains consistent with the actual task state across create, start, stop,
//! restart, delete, and list operations.

mod common;
mod listener_helpers;

use std::time::Duration;

use listener_helpers::{http_config, test_manager};
use red_cell::{ListenerManagerError, ListenerStatus};
use red_cell_common::ListenerConfig;
use tokio::time::timeout;

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
// Restart coverage tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn restart_after_stop_rebinds_port_and_accepts_connections()
-> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    manager.create(http_config("lc-restart-port", port)).await?;
    drop(guard);
    manager.start("lc-restart-port").await?;

    // Verify the listener is actually accepting connections before stopping.
    timeout(Duration::from_secs(2), common::wait_for_listener(port)).await??;

    manager.stop("lc-restart-port").await?;

    // Restart — the port should be re-bound.
    let summary = manager.start("lc-restart-port").await?;
    assert_eq!(summary.state.status, ListenerStatus::Running);

    // Verify port rebinding by actually connecting.
    timeout(Duration::from_secs(2), common::wait_for_listener(port)).await??;

    // DB state must be consistent.
    let db_summary = manager.summary("lc-restart-port").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Running);
    assert!(db_summary.state.last_error.is_none(), "no error after successful restart");

    manager.stop("lc-restart-port").await?;
    Ok(())
}

#[tokio::test]
async fn multiple_restart_cycles_succeed() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    manager.create(http_config("lc-multi-restart", port)).await?;
    drop(guard);

    // Perform three stop-then-restart cycles.
    for cycle in 0..3 {
        let started = manager.start("lc-multi-restart").await?;
        assert_eq!(
            started.state.status,
            ListenerStatus::Running,
            "cycle {cycle}: listener must be Running after start"
        );

        timeout(Duration::from_secs(2), common::wait_for_listener(port)).await??;

        let stopped = manager.stop("lc-multi-restart").await?;
        assert_eq!(
            stopped.state.status,
            ListenerStatus::Stopped,
            "cycle {cycle}: listener must be Stopped after stop"
        );
    }

    // Final DB consistency check.
    let db_summary = manager.summary("lc-multi-restart").await?;
    assert_eq!(db_summary.state.status, ListenerStatus::Stopped);
    Ok(())
}

#[tokio::test]
async fn agent_reconnects_after_listener_restart() -> Result<(), Box<dyn std::error::Error>> {
    use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH};

    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    manager.create(http_config("lc-agent-reconnect", port)).await?;
    drop(guard);
    manager.start("lc-agent-reconnect").await?;
    timeout(Duration::from_secs(2), common::wait_for_listener(port)).await??;

    // Register an agent via DEMON_INIT.
    let client = reqwest::Client::new();
    let agent_id: u32 = 0xDEAD_0001;
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xB0, 0xC3, 0xD6, 0xE9, 0xFC, 0x0F, 0x22, 0x35, 0x48, 0x5B, 0x6E, 0x81, 0x94, 0xA7, 0xBA,
        0xCD,
    ];

    let _ctr_offset = common::register_agent(&client, port, agent_id, key, iv).await?;

    // Stop and restart the listener.
    manager.stop("lc-agent-reconnect").await?;
    manager.start("lc-agent-reconnect").await?;
    timeout(Duration::from_secs(2), common::wait_for_listener(port)).await??;

    // The agent should be able to reconnect after the listener restarts.
    let reconnect_body = common::valid_demon_reconnect_body(agent_id);
    let resp = client.post(format!("http://127.0.0.1:{port}/")).body(reconnect_body).send().await?;

    // The server should accept the reconnect probe (200 OK with a body).
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "reconnect probe after restart must succeed"
    );
    let body = resp.bytes().await?;
    assert!(!body.is_empty(), "reconnect ACK must have a non-empty body");

    manager.stop("lc-agent-reconnect").await?;
    Ok(())
}

#[tokio::test]
async fn restart_preserves_config_unchanged() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    let config = http_config("lc-restart-cfg", port);
    manager.create(config).await?;
    drop(guard);

    // Capture config before restart cycle.
    let before = manager.summary("lc-restart-cfg").await?;

    manager.start("lc-restart-cfg").await?;
    manager.stop("lc-restart-cfg").await?;
    manager.start("lc-restart-cfg").await?;

    // Config must be identical after the stop-start cycle.
    let after = manager.summary("lc-restart-cfg").await?;
    match (&before.config, &after.config) {
        (ListenerConfig::Http(before_http), ListenerConfig::Http(after_http)) => {
            assert_eq!(before_http.port_bind, after_http.port_bind, "port must be preserved");
            assert_eq!(before_http.host_bind, after_http.host_bind, "host must be preserved");
            assert_eq!(
                before_http.host_rotation, after_http.host_rotation,
                "host_rotation must be preserved"
            );
            assert_eq!(before_http.uris, after_http.uris, "URIs must be preserved");
            assert_eq!(before_http.method, after_http.method, "method must be preserved");
        }
        _ => panic!("expected Http config on both sides"),
    }

    manager.stop("lc-restart-cfg").await?;
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

    let err = result.expect_err("expected Err");
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

#[tokio::test]
async fn delete_nonexistent_listener_returns_error() -> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;

    let result = manager.delete("no-such-listener").await;
    assert!(result.is_err(), "deleting a listener that does not exist must return an error");
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
