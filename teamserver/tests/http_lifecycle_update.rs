//! HTTP listener update tests.
//!
//! These tests verify that [`ListenerManager::update`] correctly replaces the
//! persisted config, restarts the runtime when needed, and rejects updates on
//! non-existent listeners.

mod common;
mod listener_helpers;

use std::time::Duration;

use listener_helpers::{http_config, test_manager};
use red_cell::ListenerStatus;
use red_cell_common::{HttpListenerConfig, ListenerConfig};
use tokio::time::timeout;

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
async fn update_running_listener_persists_non_port_config_changes()
-> Result<(), Box<dyn std::error::Error>> {
    let manager = test_manager().await?;
    let (port, guard) = common::available_port()?;

    // Create and start a listener with default host_rotation and no user_agent.
    manager.create(http_config("lc-update-cfg", port)).await?;
    drop(guard);
    manager.start("lc-update-cfg").await?;
    common::wait_for_listener(port).await?;

    // Build an updated config that keeps the same port but changes host_rotation
    // and sets a user_agent — these are non-port fields that should be persisted
    // without affecting the bind address.
    let updated_cfg = HttpListenerConfig {
        name: "lc-update-cfg".to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["127.0.0.1".to_owned()],
        host_bind: "127.0.0.1".to_owned(),
        host_rotation: "random".to_owned(),
        port_bind: port,
        port_conn: Some(port),
        method: Some("POST".to_owned()),
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: Some("RedCell/1.0".to_owned()),
        headers: Vec::new(),
        uris: vec!["/".to_owned()],
        host_header: None,
        secure: false,
        cert: None,
        response: None,
        proxy: None,
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
        legacy_mode: true,
    };

    let updated = manager.update(ListenerConfig::from(updated_cfg.clone())).await?;

    // (1) The listener must still be Running after the update.
    assert_eq!(
        updated.state.status,
        ListenerStatus::Running,
        "listener must remain Running after config update"
    );

    // (2) summary() must reflect the new config values.
    let summary = manager.summary("lc-update-cfg").await?;
    assert_eq!(summary.state.status, ListenerStatus::Running, "persisted state must be Running");
    match &summary.config {
        ListenerConfig::Http(http) => {
            assert_eq!(http.host_rotation, "random", "host_rotation must be updated");
            assert_eq!(
                http.user_agent.as_deref(),
                Some("RedCell/1.0"),
                "user_agent must be updated"
            );
            assert_eq!(http.port_bind, port, "port must remain unchanged");
        }
        other => panic!("expected Http config, got {:?}", other.protocol()),
    }

    // (3) Verify the DB persisted the update by reading a fresh summary (which
    //     always reads from the database).
    let db_summary = manager.summary("lc-update-cfg").await?;
    match &db_summary.config {
        ListenerConfig::Http(http) => {
            assert_eq!(http.host_rotation, "random", "DB must persist host_rotation");
            assert_eq!(
                http.user_agent.as_deref(),
                Some("RedCell/1.0"),
                "DB must persist user_agent"
            );
        }
        other => panic!("expected Http config, got {:?}", other.protocol()),
    }

    // The listener should still be accepting connections on the same port.
    timeout(Duration::from_secs(2), common::wait_for_listener(port)).await??;

    manager.stop("lc-update-cfg").await?;
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
