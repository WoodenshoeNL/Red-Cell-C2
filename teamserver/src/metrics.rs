//! Prometheus metrics for the Red Cell teamserver.
//!
//! This module exposes application-level metrics via a Prometheus text-format
//! endpoint (`GET /api/v1/metrics`).  Metrics are recorded through the
//! [`metrics`] facade and rendered by a [`metrics_exporter_prometheus`]
//! exporter.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

// ---------------------------------------------------------------------------
// Metric name constants
// ---------------------------------------------------------------------------

/// Gauge: number of agents currently considered alive.
pub const AGENTS_ACTIVE: &str = "red_cell_agents_active";

/// Counter: total inbound callback packets, labelled by `command`.
pub const CALLBACKS_TOTAL: &str = "red_cell_callbacks_total";

/// Histogram: time spent dispatching a single callback, labelled by `command`.
pub const CALLBACK_LATENCY_SECONDS: &str = "red_cell_callback_latency_seconds";

/// Counter: total bytes received via agent file-download transfers.
pub const DOWNLOAD_BYTES_TOTAL: &str = "red_cell_download_bytes_total";

/// Counter: listener-level errors, labelled by `listener` and `error`.
pub const LISTENER_ERRORS_TOTAL: &str = "red_cell_listener_errors_total";

/// Counter: plugin execution failures, labelled by `plugin`.
pub const PLUGIN_FAILURES_TOTAL: &str = "red_cell_plugin_failures_total";

/// Counter: ECDH replay-guard DB errors that caused a registration to be
/// rejected (fail-closed path), labelled by `listener`.
///
/// A non-zero rate here means the replay-fingerprint database is unhealthy.
/// Check SQLite WAL pressure, disk space, and connection-pool exhaustion.
pub const ECDH_REPLAY_DB_ERRORS_TOTAL: &str = "red_cell_ecdh_replay_db_errors_total";

/// Counter: ECDH registrations rejected because the ephemeral pubkey/nonce
/// fingerprint was already seen within the replay window, labelled by `listener`.
///
/// A non-zero rate here means the replay guard is actively blocking duplicate
/// packets.  A sustained high rate indicates a replay attack in progress.
pub const ECDH_REPLAYS_REJECTED_TOTAL: &str = "red_cell_ecdh_replays_rejected_total";

// ---------------------------------------------------------------------------
// Metrics handle
// ---------------------------------------------------------------------------

/// Shared handle to the Prometheus metrics exporter.
///
/// Cloned into [`TeamserverState`] at startup so the `/metrics` handler can
/// render a text-format snapshot.
#[derive(Clone, Debug)]
pub struct MetricsHandle {
    inner: Arc<PrometheusHandle>,
}

impl MetricsHandle {
    /// Render the current metrics as Prometheus text exposition format.
    pub fn render(&self) -> String {
        self.inner.render()
    }
}

/// Install the global [`metrics`] recorder backed by a Prometheus exporter
/// and return a handle for rendering.
///
/// This must be called **once** before any metrics are recorded.  Calling it
/// a second time returns an error (the `metrics` crate allows only one global
/// recorder).
pub fn install_prometheus_recorder() -> Result<MetricsHandle, MetricsInitError> {
    let builder = PrometheusBuilder::new();
    let handle = builder
        .install_recorder()
        .map_err(|source| MetricsInitError::Install { message: source.to_string() })?;

    Ok(MetricsHandle { inner: Arc::new(handle) })
}

/// Create a [`MetricsHandle`] backed by a standalone (non-global) recorder.
///
/// Useful in tests where multiple recorders may coexist and the global
/// recorder slot may already be taken.
pub fn standalone_metrics_handle() -> MetricsHandle {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    // We intentionally do NOT install this as the global recorder.
    // Drop the recorder — metrics recorded via the global facade will not
    // reach this handle, but the handle itself remains usable for rendering
    // (it will show an empty scrape).
    drop(recorder);
    MetricsHandle { inner: Arc::new(handle) }
}

/// Error returned when the Prometheus recorder cannot be installed.
#[derive(Debug, thiserror::Error)]
pub enum MetricsInitError {
    #[error("failed to install prometheus recorder: {message}")]
    Install { message: String },
}

// ---------------------------------------------------------------------------
// Recording helpers
// ---------------------------------------------------------------------------

/// Set the current active-agent gauge.
pub fn set_agents_active(count: u64) {
    gauge!(AGENTS_ACTIVE).set(count as f64);
}

/// Increment the callback counter for the given command name.
pub fn inc_callbacks_total(command: &str) {
    counter!(CALLBACKS_TOTAL, "command" => command.to_owned()).increment(1);
}

/// Record the dispatch latency for a callback command.
pub fn observe_callback_latency(command: &str, seconds: f64) {
    histogram!(CALLBACK_LATENCY_SECONDS, "command" => command.to_owned()).record(seconds);
}

/// Add bytes to the download byte counter.
pub fn add_download_bytes(bytes: u64) {
    counter!(DOWNLOAD_BYTES_TOTAL).increment(bytes);
}

/// Increment the listener error counter.
pub fn inc_listener_errors(listener: &str, error: &str) {
    counter!(LISTENER_ERRORS_TOTAL, "listener" => listener.to_owned(), "error" => error.to_owned())
        .increment(1);
}

/// Increment the plugin failure counter.
pub fn inc_plugin_failures(plugin: &str) {
    counter!(PLUGIN_FAILURES_TOTAL, "plugin" => plugin.to_owned()).increment(1);
}

/// Increment the ECDH replay-guard DB error counter for a listener.
///
/// Called when `try_record_reg_fingerprint` returns an error and the
/// registration is rejected (fail-closed).  A sustained non-zero rate
/// indicates database instability on the replay-fingerprint store.
pub fn inc_ecdh_replay_db_errors(listener: &str) {
    counter!(ECDH_REPLAY_DB_ERRORS_TOTAL, "listener" => listener.to_owned()).increment(1);
}

/// Increment the ECDH replay-rejected counter for a listener.
///
/// Called when `try_record_reg_fingerprint` returns `Ok(false)` (fingerprint
/// already seen within the replay window).  A sustained non-zero rate indicates
/// a replay attack or misbehaving agent.
pub fn inc_ecdh_replays_rejected(listener: &str) {
    counter!(ECDH_REPLAYS_REJECTED_TOTAL, "listener" => listener.to_owned()).increment(1);
}

// ---------------------------------------------------------------------------
// Axum handler
// ---------------------------------------------------------------------------

/// `GET /api/v1/metrics` — return Prometheus text exposition.
pub async fn get_metrics(State(handle): State<MetricsHandle>) -> impl IntoResponse {
    let body = handle.render();
    (StatusCode::OK, [("content-type", "text/plain; version=0.0.4; charset=utf-8")], body)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_handle_is_clone_and_debug() {
        fn assert_clone_debug<T: Clone + std::fmt::Debug>() {}
        assert_clone_debug::<MetricsHandle>();
    }

    #[test]
    fn metric_name_constants_are_prefixed() {
        assert!(AGENTS_ACTIVE.starts_with("red_cell_"));
        assert!(CALLBACKS_TOTAL.starts_with("red_cell_"));
        assert!(CALLBACK_LATENCY_SECONDS.starts_with("red_cell_"));
        assert!(DOWNLOAD_BYTES_TOTAL.starts_with("red_cell_"));
        assert!(LISTENER_ERRORS_TOTAL.starts_with("red_cell_"));
        assert!(PLUGIN_FAILURES_TOTAL.starts_with("red_cell_"));
        assert!(ECDH_REPLAY_DB_ERRORS_TOTAL.starts_with("red_cell_"));
    }

    #[test]
    fn standalone_handle_renders_empty_scrape() {
        let handle = standalone_metrics_handle();
        let output = handle.render();
        // A freshly-created standalone handle has no registered metrics.
        assert!(output.is_empty() || output.starts_with('#'));
    }

    #[test]
    fn metrics_init_error_display_contains_message() {
        let err = MetricsInitError::Install { message: "already set".into() };
        let display = format!("{err}");
        assert!(display.contains("already set"), "display should include the message: {display}");
    }

    #[tokio::test]
    async fn get_metrics_handler_returns_prometheus_content_type() {
        let handle = standalone_metrics_handle();
        let response = get_metrics(State(handle)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let ct = response.headers().get("content-type").map(|v| v.to_str().unwrap_or(""));
        assert_eq!(ct, Some("text/plain; version=0.0.4; charset=utf-8"));
    }
}
