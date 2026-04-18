use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use super::super::{AuditWebhookNotifier, WebhookError};

use super::{
    discord_profile, flaky_webhook_server, notifier_with_timeout, sample_record, webhook_server,
};
use axum::http::StatusCode as HttpStatusCode;

/// Synchronous delivery to a port that accepts but immediately closes must return
/// `WebhookError::Request`. Using an accept-and-drop server avoids the TOCTOU race
/// that occurs when relying on a dropped OS ephemeral port staying unbound.
#[tokio::test]
async fn notify_audit_record_returns_request_error_on_connection_refused() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("should bind");
    let address = listener.local_addr().expect("should resolve");
    // Keep the port bound; accept and immediately drop each connection so the HTTP
    // request fails with a transport error rather than ECONNREFUSED.
    let _accept_guard = tokio::spawn(async move {
        loop {
            let _ = listener.accept().await;
        }
    });

    let notifier = notifier_with_timeout(address, Duration::from_secs(1));
    let result = notifier.notify_audit_record(&sample_record(60)).await;

    assert!(
        matches!(result, Err(WebhookError::Request(_))),
        "transport failure should produce WebhookError::Request, got {result:?}"
    );
}

/// Detached delivery to a port that accepts but immediately closes must drain on
/// shutdown and increment the permanent failure counter.
#[tokio::test]
async fn detached_delivery_increments_failure_count_on_connection_refused() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("should bind");
    let address = listener.local_addr().expect("should resolve");
    let _accept_guard = tokio::spawn(async move {
        loop {
            let _ = listener.accept().await;
        }
    });

    let notifier = notifier_with_timeout(address, Duration::from_secs(1));
    notifier.notify_audit_record_detached(sample_record(61));
    assert!(notifier.shutdown(Duration::from_secs(5)).await, "shutdown should drain");
    assert_eq!(
        notifier.discord_failure_count(),
        1,
        "permanent failure should be recorded after connection refusal"
    );
}

/// Synchronous delivery to a server that accepts but never responds must
/// return `WebhookError::Request` once the client timeout elapses.
#[tokio::test]
async fn notify_audit_record_returns_request_error_on_client_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("should bind");
    let address = listener.local_addr().expect("should resolve");
    let server = tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(300)).await;
                drop(socket);
            });
        }
    });

    let notifier = notifier_with_timeout(address, Duration::from_millis(100));
    let result = notifier.notify_audit_record(&sample_record(62)).await;

    assert!(
        matches!(result, Err(WebhookError::Request(_))),
        "client timeout should produce WebhookError::Request, got {result:?}"
    );
    server.abort();
}

/// Detached delivery to a stalling server must drain on shutdown and
/// increment the permanent failure counter once the client timeout fires.
#[tokio::test]
async fn detached_delivery_increments_failure_count_on_client_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("should bind");
    let address = listener.local_addr().expect("should resolve");
    let server = tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(300)).await;
                drop(socket);
            });
        }
    });

    let notifier = notifier_with_timeout(address, Duration::from_millis(100));
    notifier.notify_audit_record_detached(sample_record(63));
    assert!(notifier.shutdown(Duration::from_secs(5)).await, "shutdown should drain");
    assert_eq!(
        notifier.discord_failure_count(),
        1,
        "permanent failure should be recorded after client timeout"
    );
    server.abort();
}

/// Concurrent detached deliveries where some succeed and some fail must
/// correctly update both the `pending` counter and `discord_failure_count`.
///
/// Uses `flaky_webhook_server(2)` with 4 deliveries (zero-delay retries so
/// each gets a single attempt).  The first 2 requests the server sees return
/// 500; the next 2 return 200.  After shutdown the failure counter must be 2
/// and exactly 2 payloads must have reached the server.
#[tokio::test]
async fn concurrent_mixed_success_and_failure_detached_deliveries() {
    let (address, mut receiver, server) = flaky_webhook_server(2).await;
    let notifier = AuditWebhookNotifier {
        retry_delays: Arc::from([].as_slice()),
        ..AuditWebhookNotifier::from_profile(&discord_profile(address))
    };

    // Fire 4 detached deliveries concurrently.
    for i in 0..4 {
        notifier.notify_audit_record_detached(sample_record(100 + i));
    }

    assert!(notifier.shutdown(Duration::from_secs(5)).await, "shutdown should drain all");

    // Exactly 2 deliveries should have permanently failed.
    assert_eq!(
        notifier.discord_failure_count(),
        2,
        "first 2 server hits return 500 with no retries → 2 permanent failures"
    );

    // Exactly 2 payloads should have been delivered successfully.
    let mut delivered = 0;
    while receiver.try_recv().is_ok() {
        delivered += 1;
    }
    assert_eq!(delivered, 2, "2 of 4 deliveries should reach the server successfully");

    // pending must be fully drained.
    assert_eq!(
        notifier.delivery_state.pending.load(Ordering::SeqCst),
        0,
        "pending counter must be zero after shutdown"
    );

    server.abort();
}

/// When an in-flight delivery never completes before the shutdown deadline,
/// `shutdown()` must return `false` rather than hanging or reporting success.
#[tokio::test]
async fn shutdown_returns_false_when_delivery_exceeds_timeout() {
    // Spin up a server that accepts connections but never sends a response.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener should bind");
    let address = listener.local_addr().expect("listener address should resolve");
    let server = tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            // Hold the connection open without responding.
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(300)).await;
                drop(socket);
            });
        }
    });

    let notifier = AuditWebhookNotifier {
        retry_delays: Arc::from([].as_slice()),
        ..AuditWebhookNotifier::from_profile(&discord_profile(address))
    };

    // Fire a detached notification — it will hang waiting for a response.
    notifier.notify_audit_record_detached(sample_record(50));

    // Give the spawned task a moment to start the HTTP request.
    tokio::time::sleep(Duration::from_millis(20)).await;

    // shutdown with a very short timeout must return false.
    let drained = notifier.shutdown(Duration::from_millis(50)).await;
    assert!(
        !drained,
        "shutdown must return false when a delivery is still in-flight past the deadline"
    );

    server.abort();
}

// --- simulate_stuck_delivery tests (require the test-helpers feature) --------

/// Happy path: `shutdown` must block while a `StuckDeliveryGuard` is alive and
/// complete successfully once the guard is dropped.
#[cfg(feature = "test-helpers")]
#[tokio::test]
async fn simulate_stuck_delivery_blocks_shutdown_until_guard_dropped() {
    let notifier = AuditWebhookNotifier::default();

    let guard = notifier.simulate_stuck_delivery();

    // shutdown should not resolve while the guard is still alive.
    let blocked =
        tokio::time::timeout(Duration::from_millis(50), notifier.shutdown(Duration::from_secs(5)))
            .await;
    assert!(blocked.is_err(), "shutdown must not complete while guard is alive");

    // Dropping the guard decrements pending and wakes the shutdown waiter.
    drop(guard);

    // A fresh shutdown call must now resolve immediately (closing is already
    // true; pending == 0).
    let drained =
        tokio::time::timeout(Duration::from_millis(100), notifier.shutdown(Duration::from_secs(5)))
            .await
            .expect("shutdown should complete promptly after guard is dropped");
    assert!(drained, "shutdown must return true once pending reaches zero");
}

/// Drop semantics: verify that the `pending` counter returns to zero when the
/// guard is dropped, so subsequent `shutdown` calls drain without waiting.
#[cfg(feature = "test-helpers")]
#[tokio::test]
async fn simulate_stuck_delivery_guard_drop_resets_pending_counter() {
    let notifier = AuditWebhookNotifier::default();

    let guard = notifier.simulate_stuck_delivery();
    assert_eq!(
        notifier.delivery_state.pending.load(Ordering::SeqCst),
        1,
        "pending must be 1 while guard is alive"
    );

    drop(guard);
    assert_eq!(
        notifier.delivery_state.pending.load(Ordering::SeqCst),
        0,
        "pending must return to zero after guard is dropped"
    );

    // Shutdown must now drain immediately since pending is zero.
    let drained =
        tokio::time::timeout(Duration::from_millis(100), notifier.shutdown(Duration::from_secs(1)))
            .await
            .expect("shutdown should complete immediately with pending=0");
    assert!(drained, "shutdown must return true when no deliveries are pending");
}

/// Events submitted when the concurrency cap is exhausted must be dropped with
/// a warning rather than spawning an unbounded number of tasks.
///
/// The test builds a notifier whose semaphore is pre-exhausted (cap = 0) so
/// every `notify_audit_record_detached` call hits the cap immediately.  No
/// tasks should be spawned, the pending counter must stay at zero, and no
/// payload must reach the mock server.
#[tokio::test]
async fn detached_events_dropped_when_concurrency_cap_is_reached() {
    let (address, mut receiver, server) = webhook_server(HttpStatusCode::OK).await;
    let profile = discord_profile(address);

    // Build a notifier with an already-exhausted semaphore (cap = 0).
    let notifier = AuditWebhookNotifier {
        delivery_semaphore: Arc::new(Semaphore::new(0)),
        ..AuditWebhookNotifier::from_profile(&profile)
    };

    // Fire several detached notifications — all should be dropped.
    for i in 0..5 {
        notifier.notify_audit_record_detached(sample_record(500 + i));
    }

    // Yield so any erroneously spawned tasks get a chance to run.
    tokio::task::yield_now().await;

    // No payload must have reached the server.
    assert!(
        receiver.try_recv().is_err(),
        "no webhook request should be sent when the concurrency cap is exhausted"
    );

    // The pending counter must be zero — dropped events must not inflate it.
    assert_eq!(
        notifier.delivery_state.pending.load(Ordering::SeqCst),
        0,
        "pending counter must be zero after all events are dropped at the cap"
    );

    // shutdown must drain immediately (nothing in flight).
    assert!(
        notifier.shutdown(Duration::from_millis(100)).await,
        "shutdown must return true immediately when no tasks were spawned"
    );

    server.abort();
}

/// Multiple guards: `shutdown` must continue to block after the first guard is
/// dropped and only complete once every guard has been dropped.
#[cfg(feature = "test-helpers")]
#[tokio::test]
async fn simulate_stuck_delivery_multiple_guards_all_must_drop_before_shutdown() {
    let notifier = AuditWebhookNotifier::default();

    let guard1 = notifier.simulate_stuck_delivery();
    let guard2 = notifier.simulate_stuck_delivery();
    assert_eq!(
        notifier.delivery_state.pending.load(Ordering::SeqCst),
        2,
        "pending must be 2 with two guards alive"
    );

    // Drop guard1 — pending falls to 1, shutdown must still block.
    drop(guard1);
    assert_eq!(
        notifier.delivery_state.pending.load(Ordering::SeqCst),
        1,
        "pending must be 1 after first guard is dropped"
    );

    let still_blocked =
        tokio::time::timeout(Duration::from_millis(50), notifier.shutdown(Duration::from_secs(5)))
            .await;
    assert!(
        still_blocked.is_err(),
        "shutdown must still block after dropping only one of two guards"
    );

    // Drop guard2 — pending falls to 0, shutdown must now complete.
    drop(guard2);

    let drained =
        tokio::time::timeout(Duration::from_millis(100), notifier.shutdown(Duration::from_secs(5)))
            .await
            .expect("shutdown should complete after all guards are dropped");
    assert!(drained, "shutdown must return true after all guards are dropped");
}
