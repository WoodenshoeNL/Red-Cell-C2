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
    pub fn spawn(
        database: Database,
        events: EventBus,
        probe_timeout: Duration,
        threshold: u32,
        recovery_probe: Duration,
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

    use super::{
        DEFAULT_DEGRADED_THRESHOLD, DEFAULT_QUERY_TIMEOUT_SECS, DEFAULT_RECOVERY_PROBE_SECS,
    };

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
}
