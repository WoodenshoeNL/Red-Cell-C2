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
    pub async fn notified(&self) {
        self.inner.notify.notified().await;
    }

    /// Register a callback that should be allowed to finish during shutdown draining.
    ///
    /// Returns `None` once shutdown has already started.
    pub fn try_track_callback(&self) -> Option<ActiveCallbackGuard> {
        if self.is_shutting_down() {
            return None;
        }

        self.inner.active_callbacks.fetch_add(1, Ordering::SeqCst);
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
            if self.inner.active_callbacks.load(Ordering::SeqCst) == 0 {
                return true;
            }

            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };

            if tokio::time::timeout(remaining, self.inner.drain_notify.notified()).await.is_err() {
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
}
