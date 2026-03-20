//! Coordinated graceful-shutdown state and drain tracking.

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

/// Shared graceful-shutdown coordinator for the teamserver runtime.
#[derive(Debug, Clone, Default)]
pub struct ShutdownController {
    inner: Arc<ShutdownState>,
}

impl ShutdownController {
    /// Create a new controller in the running state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Enter shutdown mode and notify subscribed tasks exactly once.
    pub fn initiate(&self) {
        if self.inner.shutting_down.swap(true, Ordering::SeqCst) {
            return;
        }

        self.inner.notify.notify_waiters();
        self.inner.notify_drain_if_complete();
    }

    /// Return `true` when the teamserver is draining toward shutdown.
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.inner.shutting_down.load(Ordering::SeqCst)
    }

    /// Subscribe to the shutdown notification.
    ///
    /// Returns immediately once shutdown has already started.
    pub async fn notified(&self) {
        let notified = self.inner.notify.notified();
        tokio::pin!(notified);

        if self.is_shutting_down() {
            return;
        }

        notified.await;
    }

    /// Register a callback that should be allowed to finish during shutdown draining.
    ///
    /// Returns `None` once shutdown has already started.
    pub fn try_track_callback(&self) -> Option<ActiveCallbackGuard> {
        if self.is_shutting_down() {
            return None;
        }

        self.inner.active_callbacks.fetch_add(1, Ordering::SeqCst);

        // Test-only: pause here so a test can call initiate() in the gap.
        #[cfg(test)]
        if self.inner.hook_enabled.load(Ordering::SeqCst) {
            self.inner.post_increment_hook.notify_one();
            // Spin-wait until shutdown is initiated by the test harness.
            while !self.inner.shutting_down.load(Ordering::SeqCst) {
                std::hint::spin_loop();
            }
        }

        if self.is_shutting_down() {
            self.inner.active_callbacks.fetch_sub(1, Ordering::SeqCst);
            self.inner.notify_drain_if_complete();
            return None;
        }

        Some(ActiveCallbackGuard { inner: self.inner.clone() })
    }

    /// Wait until all tracked callbacks have drained, or until `timeout` elapses.
    ///
    /// Returns `true` when the drain completed before the timeout.
    pub async fn wait_for_callback_drain(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;

        loop {
            let notified = self.inner.drain_notify.notified();
            tokio::pin!(notified);

            if self.inner.active_callbacks.load(Ordering::SeqCst) == 0 {
                return true;
            }

            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };

            if tokio::time::timeout(remaining, &mut notified).await.is_err() {
                return self.inner.active_callbacks.load(Ordering::SeqCst) == 0;
            }
        }
    }

    /// Return the current number of tracked in-flight callbacks.
    #[must_use]
    pub fn active_callback_count(&self) -> usize {
        self.inner.active_callbacks.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Default)]
struct ShutdownState {
    shutting_down: AtomicBool,
    active_callbacks: AtomicUsize,
    notify: Notify,
    drain_notify: Notify,
    /// Test-only hook: when set, `try_track_callback` waits on this notify
    /// after incrementing the counter but before re-checking the shutdown flag.
    /// This allows a test to force the exact interleaving where `initiate()`
    /// runs between the increment and the re-check.
    #[cfg(test)]
    post_increment_hook: Notify,
    /// Test-only flag: enables the `post_increment_hook` pause point.
    #[cfg(test)]
    hook_enabled: AtomicBool,
}

impl ShutdownState {
    fn notify_drain_if_complete(&self) {
        if self.active_callbacks.load(Ordering::SeqCst) == 0 {
            self.drain_notify.notify_waiters();
        }
    }
}

/// RAII guard tracking a callback that is allowed to finish during shutdown drain.
#[derive(Debug)]
pub struct ActiveCallbackGuard {
    inner: Arc<ShutdownState>,
}

impl Drop for ActiveCallbackGuard {
    fn drop(&mut self) {
        self.inner.active_callbacks.fetch_sub(1, Ordering::SeqCst);
        self.inner.notify_drain_if_complete();
    }
}

#[cfg(test)]
impl ShutdownController {
    /// Enable the test hook that pauses `try_track_callback` after
    /// incrementing the counter, before re-checking the shutdown flag.
    fn enable_post_increment_hook(&self) {
        self.inner.hook_enabled.store(true, Ordering::SeqCst);
    }

    /// Wait until a `try_track_callback` caller has incremented the counter
    /// and is paused at the hook point.
    async fn wait_for_hook_pause(&self) {
        self.inner.post_increment_hook.notified().await;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::ShutdownController;

    #[tokio::test]
    async fn controller_rejects_new_callbacks_after_shutdown() {
        let controller = ShutdownController::new();
        let callback = controller.try_track_callback();
        assert!(callback.is_some());

        controller.initiate();
        assert!(controller.try_track_callback().is_none());

        drop(callback);
        assert!(controller.wait_for_callback_drain(Duration::from_millis(10)).await);
    }

    #[tokio::test]
    async fn controller_times_out_when_callbacks_remain_active() {
        let controller = ShutdownController::new();
        let callback = controller.try_track_callback();
        assert!(callback.is_some());

        controller.initiate();

        assert!(!controller.wait_for_callback_drain(Duration::from_millis(10)).await);
        drop(callback);
        assert!(controller.wait_for_callback_drain(Duration::from_millis(10)).await);
    }

    #[tokio::test]
    async fn wait_for_callback_drain_returns_immediately_when_callbacks_are_already_gone() {
        let controller = ShutdownController::new();
        let callback = controller.try_track_callback();
        assert!(callback.is_some());

        controller.initiate();
        drop(callback);

        let result = tokio::time::timeout(
            Duration::from_millis(10),
            controller.wait_for_callback_drain(Duration::from_secs(30)),
        )
        .await;

        assert_eq!(result, Ok(true));
    }

    #[tokio::test]
    async fn notified_returns_immediately_after_shutdown_has_started() {
        let controller = ShutdownController::new();
        controller.initiate();

        tokio::time::timeout(Duration::from_millis(10), controller.notified())
            .await
            .expect("notified should complete immediately once shutdown has started");
    }

    #[test]
    fn is_shutting_down_stays_false_until_shutdown_is_initiated() {
        let controller = ShutdownController::new();

        assert!(!controller.is_shutting_down());

        controller.initiate();
        assert!(controller.is_shutting_down());

        controller.initiate();
        controller.initiate();
        assert!(controller.is_shutting_down());
    }

    #[tokio::test]
    async fn accessors_report_callback_count_before_and_after_shutdown() {
        let controller = ShutdownController::new();

        assert!(!controller.is_shutting_down());
        assert_eq!(controller.active_callback_count(), 0);

        let first = controller.try_track_callback();
        let second = controller.try_track_callback();

        assert!(first.is_some());
        assert!(second.is_some());
        assert_eq!(controller.active_callback_count(), 2);
        assert!(!controller.is_shutting_down());

        controller.initiate();

        assert!(controller.is_shutting_down());
        assert_eq!(controller.active_callback_count(), 2);

        drop(first);
        assert_eq!(controller.active_callback_count(), 1);

        drop(second);
        assert_eq!(controller.active_callback_count(), 0);
        assert!(controller.wait_for_callback_drain(Duration::from_millis(10)).await);
    }

    #[tokio::test]
    async fn active_callback_count_returns_to_zero_when_guard_drops_after_shutdown() {
        let controller = ShutdownController::new();
        let callback = controller.try_track_callback();

        assert!(callback.is_some());
        assert_eq!(controller.active_callback_count(), 1);

        controller.initiate();
        assert!(controller.is_shutting_down());
        assert_eq!(controller.active_callback_count(), 1);

        drop(callback);
        assert_eq!(controller.active_callback_count(), 0);
        assert!(controller.wait_for_callback_drain(Duration::from_millis(10)).await);
    }

    #[tokio::test]
    async fn pre_shutdown_waiters_all_wake_on_initiate() {
        use tokio::sync::oneshot;

        let controller = ShutdownController::new();

        // Spawn 5 waiter tasks that await notified() before shutdown.
        let mut receivers = Vec::new();
        for _ in 0..5 {
            let ctrl = controller.clone();
            let (tx, rx) = oneshot::channel::<()>();
            tokio::spawn(async move {
                ctrl.notified().await;
                let _ = tx.send(());
            });
            receivers.push(rx);
        }

        // Yield to let waiters register their notified() futures.
        tokio::task::yield_now().await;

        // No waiter should have completed yet.
        for rx in &mut receivers {
            assert!(rx.try_recv().is_err(), "waiter must remain pending before shutdown");
        }

        // Initiate shutdown — all waiters should unblock.
        controller.initiate();

        for (i, rx) in receivers.into_iter().enumerate() {
            tokio::time::timeout(Duration::from_millis(100), rx)
                .await
                .unwrap_or_else(|_| panic!("waiter {i} did not complete after initiate()"))
                .unwrap_or_else(|_| panic!("waiter {i} sender was dropped unexpectedly"));
        }
    }

    #[tokio::test]
    async fn repeated_initiate_does_not_break_waiter_semantics() {
        use tokio::sync::oneshot;

        let controller = ShutdownController::new();

        let ctrl = controller.clone();
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            ctrl.notified().await;
            let _ = tx.send(());
        });

        tokio::task::yield_now().await;

        // Multiple initiate() calls should be idempotent.
        controller.initiate();
        controller.initiate();
        controller.initiate();

        tokio::time::timeout(Duration::from_millis(100), rx)
            .await
            .expect("waiter must complete after initiate()")
            .expect("sender must not be dropped");

        // A new waiter after repeated initiate() should also return immediately.
        tokio::time::timeout(Duration::from_millis(10), controller.notified())
            .await
            .expect("notified() after repeated initiate() must return immediately");
    }

    /// Verify that concurrent `try_track_callback` and `initiate` calls
    /// never leave the controller in an inconsistent state: either the
    /// callback is tracked and must be drained, or it is rejected.
    #[tokio::test]
    async fn try_track_callback_race_with_concurrent_initiate() {
        use std::sync::{Arc, Barrier};

        for _ in 0..100 {
            let controller = ShutdownController::new();
            let barrier = Arc::new(Barrier::new(2));

            let ctrl = controller.clone();
            let bar = barrier.clone();
            let tracker = std::thread::spawn(move || {
                bar.wait();
                ctrl.try_track_callback()
            });

            let ctrl2 = controller.clone();
            let bar2 = barrier.clone();
            let initiator = std::thread::spawn(move || {
                bar2.wait();
                ctrl2.initiate();
            });

            let guard = tracker.join().expect("tracker thread should not panic");
            initiator.join().expect("initiator thread should not panic");

            assert!(controller.is_shutting_down());

            match guard {
                Some(g) => {
                    // Callback was accepted — count must be 1 until dropped.
                    assert_eq!(controller.active_callback_count(), 1);
                    drop(g);
                    assert_eq!(controller.active_callback_count(), 0);
                }
                None => {
                    // Callback was rejected — count must already be 0.
                    assert_eq!(controller.active_callback_count(), 0);
                }
            }

            // Drain must always succeed quickly after guards are dropped.
            assert!(controller.wait_for_callback_drain(Duration::from_millis(50)).await);
        }
    }

    /// Deterministic test for the rollback path in `try_track_callback` (lines 63-67).
    ///
    /// Forces the exact interleaving: `try_track_callback` increments the counter,
    /// then `initiate()` runs, then the re-check sees shutdown and rolls back.
    /// Verifies that the counter returns to zero and drain completes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn try_track_callback_rollback_when_shutdown_races_after_increment() {
        let controller = ShutdownController::new();
        controller.enable_post_increment_hook();

        // spawn_blocking so the sync spin-wait doesn't block the async runtime.
        let ctrl = controller.clone();
        let tracker = tokio::task::spawn_blocking(move || ctrl.try_track_callback());

        // Wait until the tracker has incremented the counter and paused.
        controller.wait_for_hook_pause().await;

        // The counter is incremented but the tracker hasn't re-checked the flag yet.
        assert_eq!(controller.active_callback_count(), 1);

        // Initiate shutdown in the gap — this is the race we want to exercise.
        controller.initiate();

        // The tracker should now see shutdown on re-check and roll back.
        let guard = tracker.await.expect("tracker task should not panic");

        // The rollback path must have returned None and decremented the counter.
        assert!(guard.is_none(), "callback must be rejected when shutdown raced after increment");
        assert_eq!(controller.active_callback_count(), 0, "counter must be zero after rollback");

        // Drain must succeed immediately since no callbacks are tracked.
        assert!(controller.wait_for_callback_drain(Duration::from_millis(50)).await);
    }
}
