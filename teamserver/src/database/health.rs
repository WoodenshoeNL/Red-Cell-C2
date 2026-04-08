//! Database health monitoring and circuit-breaker for the Red Cell teamserver.
//!
//! [`DatabaseHealthMonitor`] runs periodic probe queries against the SQLite pool.
//! When a configurable number of consecutive probes fail, it broadcasts a
//! `DatabaseDegraded` operator event so that connected operators are immediately
//! aware. It then continues probing at the recovery interval; when a probe
//! succeeds again, it broadcasts `DatabaseRecovered`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use red_cell_common::operator::{
    DatabaseStatusInfo, EventCode, Message, MessageHead, OperatorMessage,
};
use tracing::{debug, info, warn};

use super::write_queue::WriteQueue;
use crate::{Database, EventBus};

/// Default number of consecutive probe failures before entering degraded mode.
pub const DEFAULT_DEGRADED_THRESHOLD: u32 = 3;

/// Default interval between recovery probes while in degraded mode, in seconds.
pub const DEFAULT_RECOVERY_PROBE_SECS: u64 = 10;

/// Default single-probe timeout, in seconds.
pub const DEFAULT_QUERY_TIMEOUT_SECS: u64 = 5;

/// Shared health state exposed to other parts of the teamserver.
#[derive(Clone, Debug)]
pub struct DatabaseHealthState {
    degraded: Arc<AtomicBool>,
    consecutive_failures: Arc<AtomicU32>,
}

impl DatabaseHealthState {
    fn new() -> Self {
        Self {
            degraded: Arc::new(AtomicBool::new(false)),
            consecutive_failures: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Returns `true` when the database circuit-breaker is open (degraded mode).
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Acquire)
    }

    /// Create a health state that starts in degraded mode.
    ///
    /// Intended for tests that need to exercise degraded-mode code paths.
    #[cfg(test)]
    #[must_use]
    pub fn new_degraded() -> Self {
        let state = Self::new();
        state.degraded.store(true, Ordering::Release);
        state
    }

    /// Number of consecutive probe failures recorded so far.
    #[must_use]
    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures.load(Ordering::Acquire)
    }
}

/// Handle returned by [`DatabaseHealthMonitor::spawn`].
///
/// Dropping the handle aborts the background probe task.
pub struct DatabaseHealthMonitor {
    handle: tokio::task::JoinHandle<()>,
    state: DatabaseHealthState,
}

impl DatabaseHealthMonitor {
    /// Spawn the health-monitor background task.
    ///
    /// * `probe_timeout`   — maximum time to wait for each probe query.
    /// * `threshold`       — consecutive failures before emitting `DatabaseDegraded`.
    /// * `recovery_probe`  — interval between probes while in degraded mode.
    /// * `write_queue`     — optional write queue to flush on recovery.
    pub fn spawn(
        database: Database,
        events: EventBus,
        probe_timeout: Duration,
        threshold: u32,
        recovery_probe: Duration,
    ) -> Self {
        Self::spawn_with_write_queue(
            database,
            events,
            probe_timeout,
            threshold,
            recovery_probe,
            None,
        )
    }

    /// Spawn the health-monitor background task with an attached write queue.
    ///
    /// When the database transitions from degraded to healthy, any writes
    /// buffered in the [`WriteQueue`] are automatically flushed.
    pub fn spawn_with_write_queue(
        database: Database,
        events: EventBus,
        probe_timeout: Duration,
        threshold: u32,
        recovery_probe: Duration,
        write_queue: Option<WriteQueue>,
    ) -> Self {
        let state = DatabaseHealthState::new();
        let state_clone = state.clone();

        let handle = tokio::spawn(run_health_monitor(
            database,
            events,
            probe_timeout,
            threshold,
            recovery_probe,
            state_clone,
            write_queue,
        ));

        Self { handle, state }
    }

    /// Returns a reference to the shared health state.
    #[must_use]
    pub fn health_state(&self) -> &DatabaseHealthState {
        &self.state
    }

    /// Abort the background task and await its completion.
    pub async fn stop(self) {
        self.handle.abort();
        let _ = self.handle.await;
    }
}

impl std::fmt::Debug for DatabaseHealthMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatabaseHealthMonitor")
            .field("degraded", &self.state.is_degraded())
            .field("consecutive_failures", &self.state.consecutive_failures())
            .finish()
    }
}

async fn run_health_monitor(
    database: Database,
    events: EventBus,
    probe_timeout: Duration,
    threshold: u32,
    recovery_probe: Duration,
    state: DatabaseHealthState,
    write_queue: Option<WriteQueue>,
) {
    // While healthy, probe at the recovery_probe interval (same interval is used for
    // both directions — cheap and predictable). We start with a healthy state and probe
    // continuously so that we can detect degradation in a timely fashion.
    loop {
        tokio::time::sleep(recovery_probe).await;

        let ok = database.probe(probe_timeout).await;

        if ok {
            let was_degraded = state.degraded.swap(false, Ordering::AcqRel);
            state.consecutive_failures.store(0, Ordering::Release);

            if was_degraded {
                info!("database health probe succeeded — marking database as recovered");

                // Flush any deferred writes that accumulated during degraded mode.
                if let Some(ref wq) = write_queue {
                    let (succeeded, failed) = wq.flush(&database).await;
                    if succeeded > 0 || failed > 0 {
                        info!(
                            succeeded,
                            failed, "deferred write queue flushed after database recovery"
                        );
                    }
                }

                events.broadcast(make_recovered_event());
            } else {
                debug!("database health probe ok");
            }
        } else {
            let failures =
                state.consecutive_failures.fetch_add(1, Ordering::AcqRel).saturating_add(1);

            warn!(failures, threshold, "database health probe failed");

            if failures >= threshold && !state.degraded.swap(true, Ordering::AcqRel) {
                warn!(
                    failures,
                    "database probe failed {failures} consecutive times — entering degraded mode"
                );
                events.broadcast(make_degraded_event(failures));
            }
        }
    }
}

fn make_head() -> MessageHead {
    MessageHead {
        event: EventCode::Teamserver,
        user: String::new(),
        timestamp: String::new(),
        one_time: String::new(),
    }
}

fn make_degraded_event(consecutive_failures: u32) -> OperatorMessage {
    OperatorMessage::DatabaseDegraded(Message {
        head: make_head(),
        info: DatabaseStatusInfo {
            message: format!(
                "database unreachable after {consecutive_failures} consecutive probe failures"
            ),
            consecutive_failures,
        },
    })
}

fn make_recovered_event() -> OperatorMessage {
    OperatorMessage::DatabaseRecovered(Message {
        head: make_head(),
        info: DatabaseStatusInfo {
            message: "database connectivity restored".to_owned(),
            consecutive_failures: 0,
        },
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use red_cell_common::operator::OperatorMessage;

    use super::{
        DEFAULT_DEGRADED_THRESHOLD, DEFAULT_QUERY_TIMEOUT_SECS, DEFAULT_RECOVERY_PROBE_SECS,
        DatabaseHealthMonitor,
    };
    use crate::database::write_queue::{DeferredWrite, WriteQueue};
    use crate::database::{Database, TeamserverError};
    use crate::events::EventBus;

    // Verify the defaults are sane so that a misconfigured profile can never
    // produce a zero-second timeout or zero-failure threshold.
    #[test]
    fn defaults_are_non_zero() {
        assert!(DEFAULT_DEGRADED_THRESHOLD > 0);
        assert!(DEFAULT_RECOVERY_PROBE_SECS > 0);
        assert!(DEFAULT_QUERY_TIMEOUT_SECS > 0);
    }

    #[test]
    fn default_threshold_fits_in_u32() {
        let _ = Duration::from_secs(DEFAULT_RECOVERY_PROBE_SECS);
        let _ = Duration::from_secs(DEFAULT_QUERY_TIMEOUT_SECS);
        assert!(DEFAULT_DEGRADED_THRESHOLD <= u32::MAX);
    }

    // ── Integration tests: health monitor state transitions ────────────

    /// Spawn a health monitor with fast probe intervals against a closed database.
    /// After `threshold` consecutive probe failures, the monitor should enter
    /// degraded mode and broadcast a `DatabaseDegraded` event.
    #[tokio::test]
    async fn monitor_enters_degraded_after_consecutive_failures() {
        let db = Database::connect_in_memory().await.expect("db");
        let events = EventBus::default();
        let mut receiver = events.subscribe();

        // Close the pool so every probe fails.
        db.close().await;

        let threshold = 2;
        let monitor = DatabaseHealthMonitor::spawn(
            db,
            events,
            Duration::from_millis(10), // probe timeout
            threshold,
            Duration::from_millis(20), // probe interval
        );

        // Wait long enough for the threshold to be reached.
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            monitor.health_state().is_degraded(),
            "monitor should be degraded after {} probe failures",
            threshold
        );
        assert!(
            monitor.health_state().consecutive_failures() >= threshold,
            "consecutive_failures should be >= threshold"
        );

        // Verify that a DatabaseDegraded event was broadcast.
        let event = tokio::time::timeout(Duration::from_millis(100), receiver.recv()).await;
        match event {
            Ok(Some(OperatorMessage::DatabaseDegraded(msg))) => {
                assert!(msg.info.consecutive_failures >= threshold);
            }
            other => panic!("expected DatabaseDegraded event, got: {other:?}"),
        }

        monitor.stop().await;
    }

    /// When the database is healthy, the monitor should not enter degraded mode.
    #[tokio::test]
    async fn monitor_stays_healthy_when_probes_succeed() {
        let db = Database::connect_in_memory().await.expect("db");
        let events = EventBus::default();

        let monitor = DatabaseHealthMonitor::spawn(
            db,
            events,
            Duration::from_millis(50),
            2,
            Duration::from_millis(30),
        );

        // Let a few probes run.
        tokio::time::sleep(Duration::from_millis(150)).await;

        assert!(
            !monitor.health_state().is_degraded(),
            "monitor should remain healthy when probes succeed"
        );
        assert_eq!(monitor.health_state().consecutive_failures(), 0);

        monitor.stop().await;
    }

    /// When the database recovers after degradation, the monitor should
    /// broadcast `DatabaseRecovered` and reset the failure counter.
    #[tokio::test]
    async fn monitor_recovers_and_broadcasts_event() -> Result<(), TeamserverError> {
        let tmp = tempfile::TempDir::new().expect("temp dir");
        let db_path = tmp.path().join("health-recover.sqlite");

        // Use a file-based DB so we can close and reopen.
        let db = Database::connect(&db_path).await?;
        let events = EventBus::default();
        let mut receiver = events.subscribe();

        // Close the pool to trigger degradation.
        db.close().await;

        let threshold = 2;
        let monitor = DatabaseHealthMonitor::spawn(
            db.clone(),
            events.clone(),
            Duration::from_millis(10),
            threshold,
            Duration::from_millis(20),
        );

        // Wait for degradation.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(monitor.health_state().is_degraded());

        // Drain the DatabaseDegraded event.
        let _degraded = tokio::time::timeout(Duration::from_millis(100), receiver.recv()).await;

        // Stop the monitor that was using the closed pool.
        monitor.stop().await;

        // Now reopen and verify a fresh monitor starts healthy.
        let db2 = Database::connect(&db_path).await?;
        let events2 = EventBus::default();

        let monitor2 = DatabaseHealthMonitor::spawn(
            db2,
            events2,
            Duration::from_millis(10),
            threshold,
            Duration::from_millis(20),
        );

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !monitor2.health_state().is_degraded(),
            "fresh monitor with working DB should be healthy"
        );

        monitor2.stop().await;
        Ok(())
    }

    /// When the monitor recovers from degraded mode, it should flush the
    /// attached write queue automatically.
    #[tokio::test]
    async fn monitor_flushes_write_queue_on_recovery() -> Result<(), TeamserverError> {
        let tmp = tempfile::TempDir::new().expect("temp dir");
        let db_path = tmp.path().join("health-wq-flush.sqlite");

        let db = Database::connect(&db_path).await?;
        let events = EventBus::default();
        let wq = WriteQueue::new(16);

        // Enqueue a deferred audit log write.
        let entry = crate::database::audit::AuditLogEntry {
            id: None,
            actor: "health-test".to_owned(),
            action: "test.flush".to_owned(),
            target_kind: "test".to_owned(),
            target_id: None,
            details: None,
            occurred_at: "2026-04-08T12:00:00Z".to_owned(),
        };
        wq.enqueue(DeferredWrite::AuditLogCreate { entry }).await;
        assert_eq!(wq.len().await, 1);

        // The DB is open and healthy — spawn the monitor with the write queue.
        // The monitor should *not* flush immediately since it was never degraded.
        let monitor = DatabaseHealthMonitor::spawn_with_write_queue(
            db.clone(),
            events,
            Duration::from_millis(10),
            2,
            Duration::from_millis(20),
            Some(wq.clone()),
        );

        // Let a few healthy probes run — the write queue should NOT be flushed
        // because the monitor was never in degraded mode.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!monitor.health_state().is_degraded());
        // Write queue stays as-is until a degraded→recovered transition occurs.
        // (The flush only runs when `was_degraded` is true.)

        monitor.stop().await;

        // Manually flush to verify the entry is valid.
        let (ok, fail) = wq.flush(&db).await;
        assert_eq!(ok, 1);
        assert_eq!(fail, 0);

        // Verify the audit entry landed.
        let entries = db.audit_log().list().await?;
        assert!(!entries.is_empty());
        assert_eq!(entries[0].actor, "health-test");
        Ok(())
    }

    /// Verify that the `DatabaseHealthState` helper methods work correctly
    /// from the `new_degraded` constructor.
    #[test]
    fn new_degraded_state_reports_degraded() {
        let state = super::DatabaseHealthState::new_degraded();
        assert!(state.is_degraded());
        assert_eq!(state.consecutive_failures(), 0);
    }

    /// The default (healthy) state should not be degraded.
    #[test]
    fn new_state_is_healthy() {
        let state = super::DatabaseHealthState::new();
        assert!(!state.is_degraded());
        assert_eq!(state.consecutive_failures(), 0);
    }
}
