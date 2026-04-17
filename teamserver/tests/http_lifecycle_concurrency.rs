//! HTTP listener concurrency, error-recovery, and same-port conflict tests.
//!
//! These tests cover scenarios where multiple listener operations interact:
//! concurrent starts across independent listeners, recovery from a previous
//! `Error` state, and the collision that happens when a second managed
//! listener attempts to bind an already-claimed port.

mod common;
mod listener_helpers;

use std::time::Duration;

use listener_helpers::{http_config, test_manager};
use red_cell::ListenerStatus;
use tokio::time::timeout;

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
