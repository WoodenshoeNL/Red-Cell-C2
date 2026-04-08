//! Connection-management types and send helpers for the operator WebSocket.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{Message as WsMessage, WebSocket};
use red_cell_common::crypto::{derive_ws_hmac_key, seal_ws_frame};
use red_cell_common::operator::OperatorMessage;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, instrument, warn};
use uuid::Uuid;

use crate::rate_limiter::{AttemptWindow, evict_oldest_windows, prune_expired_windows};
use crate::{AuthenticationFailure, login_failure_message};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum failed login attempts per IP within the sliding window.
pub(super) const MAX_FAILED_LOGIN_ATTEMPTS: u32 = 5;

/// Duration of the sliding window for tracking failed login attempts.
pub(super) const LOGIN_WINDOW_DURATION: Duration = Duration::from_secs(60);

/// Maximum number of IP windows retained before oldest entries are evicted.
pub(super) const MAX_LOGIN_ATTEMPT_WINDOWS: usize = 10_000;

/// Delay applied before responding to a failed login attempt to slow brute-force attacks.
pub(super) const FAILED_LOGIN_DELAY: Duration = Duration::from_secs(2);

/// Maximum time an unauthenticated socket may idle before sending the first login frame.
pub(super) const AUTHENTICATION_FRAME_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum operator WebSocket message size accepted by the teamserver.
pub(super) const OPERATOR_MAX_MESSAGE_SIZE: usize = 1024 * 1024;

// ── OperatorConnectionManager ────────────────────────────────────────────────

/// Tracks currently connected operator WebSocket clients.
#[derive(Debug, Clone, Default)]
pub struct OperatorConnectionManager {
    connections: Arc<RwLock<BTreeMap<Uuid, OperatorConnection>>>,
}

impl OperatorConnectionManager {
    /// Create an empty connection registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the number of currently open WebSocket connections.
    #[instrument(skip(self))]
    pub async fn connection_count(&self) -> usize {
        self.connections.read().await.len()
    }

    /// Return the number of authenticated WebSocket connections.
    #[instrument(skip(self))]
    pub async fn authenticated_count(&self) -> usize {
        self.connections
            .read()
            .await
            .values()
            .filter(|connection| connection.username.is_some())
            .count()
    }

    pub(super) async fn register(&self, id: Uuid) {
        self.connections.write().await.insert(id, OperatorConnection { username: None });
    }

    pub(super) async fn authenticate(&self, id: Uuid, username: String) {
        if let Some(connection) = self.connections.write().await.get_mut(&id) {
            connection.username = Some(username);
        }
    }

    pub(super) async fn unregister(&self, id: Uuid) {
        self.connections.write().await.remove(&id);
    }
}

#[derive(Debug, Clone, Default)]
struct OperatorConnection {
    username: Option<String>,
}

// ── LoginRateLimiter ─────────────────────────────────────────────────────────

/// Per-source-IP rate limiter for WebSocket operator login attempts.
///
/// Tracks failed login attempts in a sliding window per IP address. Once the
/// maximum number of failures is reached, further attempts from that IP are
/// rejected until the window expires.
#[derive(Debug, Clone, Default)]
pub struct LoginRateLimiter {
    windows: Arc<tokio::sync::Mutex<HashMap<IpAddr, AttemptWindow>>>,
}

impl LoginRateLimiter {
    /// Create an empty rate limiter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return `true` if the given IP has not exceeded the failed-attempt threshold.
    ///
    /// Read-only check for tests and diagnostics; production code should use
    /// [`try_acquire`] (which atomically checks **and** reserves a slot).
    pub async fn is_allowed(&self, ip: IpAddr) -> bool {
        let mut windows = self.windows.lock().await;
        let Some(window) = windows.get_mut(&ip) else {
            return true;
        };

        if window.window_start.elapsed() >= LOGIN_WINDOW_DURATION {
            windows.remove(&ip);
            return true;
        }

        window.attempts < MAX_FAILED_LOGIN_ATTEMPTS
    }

    /// Atomically check whether this IP is under the rate-limit threshold and,
    /// if so, reserve a slot for this attempt.
    ///
    /// Returns `true` if the attempt is allowed (and has been pre-counted),
    /// `false` if the IP is currently rate-limited.
    ///
    /// This method is race-free: concurrent calls from the same IP cannot all
    /// pass the check before any attempt is recorded.
    ///
    /// On successful authentication the caller must call [`record_success`] to
    /// clear the counter.  On failure no further call is needed — the attempt is
    /// already counted.
    pub(crate) async fn try_acquire(&self, ip: IpAddr) -> bool {
        let mut windows = self.windows.lock().await;
        let now = Instant::now();

        prune_expired_windows(&mut windows, LOGIN_WINDOW_DURATION, now);
        if !windows.contains_key(&ip) && windows.len() >= MAX_LOGIN_ATTEMPT_WINDOWS {
            evict_oldest_windows(&mut windows, MAX_LOGIN_ATTEMPT_WINDOWS / 2);
        }

        let window = windows.entry(ip).or_default();

        if now.duration_since(window.window_start) >= LOGIN_WINDOW_DURATION {
            // Expired window: reset and allow this attempt as the first.
            window.attempts = 1;
            window.window_start = now;
            return true;
        }

        if window.attempts >= MAX_FAILED_LOGIN_ATTEMPTS {
            return false;
        }

        window.attempts += 1;
        true
    }

    /// Record a failed login attempt from the given IP without going through
    /// the full WebSocket login flow.
    ///
    /// Intended for tests that need to pre-populate the limiter without
    /// incurring `FAILED_LOGIN_DELAY` on every attempt.  Production callers
    /// should use [`try_acquire`] instead, which atomically checks and records.
    pub async fn record_failure(&self, ip: IpAddr) {
        let mut windows = self.windows.lock().await;
        let now = Instant::now();

        prune_expired_windows(&mut windows, LOGIN_WINDOW_DURATION, now);
        if !windows.contains_key(&ip) && windows.len() >= MAX_LOGIN_ATTEMPT_WINDOWS {
            evict_oldest_windows(&mut windows, MAX_LOGIN_ATTEMPT_WINDOWS / 2);
        }

        let window = windows.entry(ip).or_default();

        if now.duration_since(window.window_start) >= LOGIN_WINDOW_DURATION {
            window.attempts = 1;
            window.window_start = now;
        } else {
            window.attempts += 1;
        }
    }

    /// Clear the failure counter for an IP after a successful login.
    pub(crate) async fn record_success(&self, ip: IpAddr) {
        self.windows.lock().await.remove(&ip);
    }

    /// Return the number of IPs currently tracked (for tests).
    #[cfg(test)]
    pub(super) async fn tracked_ip_count(&self) -> usize {
        self.windows.lock().await.len()
    }

    /// Return `(attempts, window_start)` for a given IP (for tests).
    #[cfg(test)]
    pub(super) async fn window_state(&self, ip: IpAddr) -> Option<(u32, std::time::Instant)> {
        self.windows.lock().await.get(&ip).map(|w| (w.attempts, w.window_start))
    }

    /// Direct mutable access to the underlying windows map (for tests that
    /// need to inject synthetic window state such as expired timestamps).
    #[cfg(test)]
    pub(super) async fn with_windows_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut HashMap<IpAddr, AttemptWindow>) -> R,
    {
        let mut guard = self.windows.lock().await;
        f(&mut guard)
    }
}

// ── WsSession ────────────────────────────────────────────────────────────────

/// Per-connection HMAC state for post-login WebSocket frames.
pub(super) struct WsSession {
    pub(super) key: [u8; 32],
    pub(super) send_seq: u64,
    pub(super) recv_seq: Option<u64>,
}

impl WsSession {
    pub(super) fn new(token: &str) -> Self {
        Self { key: derive_ws_hmac_key(token), send_seq: 0, recv_seq: None }
    }
}

// ── DisconnectKind ───────────────────────────────────────────────────────────

/// Reason a WebSocket operator connection was closed.
#[derive(Debug, Clone, Copy)]
pub(super) enum DisconnectKind {
    /// Client sent a clean WebSocket close frame.
    CleanClose,
    /// Connection dropped due to a socket or protocol error.
    Error,
    /// Teamserver is shutting down and terminated the connection.
    ServerShutdown,
}

impl DisconnectKind {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::CleanClose => "clean_close",
            Self::Error => "error",
            Self::ServerShutdown => "server_shutdown",
        }
    }
}

// ── SocketLoopControl ────────────────────────────────────────────────────────

pub(super) enum SocketLoopControl {
    Continue,
    Break,
}

// ── SendMessageError ─────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub(super) enum SendMessageError {
    #[error("failed to serialize operator message: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("failed to send operator websocket message: {0}")]
    Socket(#[from] axum::Error),
}

// ── Send helpers ─────────────────────────────────────────────────────────────

pub(super) async fn send_operator_message(
    socket: &mut WebSocket,
    message: &OperatorMessage,
) -> Result<(), SendMessageError> {
    let payload = serde_json::to_string(message)?;
    socket.send(WsMessage::Text(payload.into())).await?;
    Ok(())
}

/// Send an `OperatorMessage` wrapped in an HMAC `WsEnvelope`.
pub(super) async fn send_hmac_message(
    socket: &mut WebSocket,
    message: &OperatorMessage,
    ws_session: &mut WsSession,
) -> Result<(), SendMessageError> {
    let inner_json = serde_json::to_string(message)?;
    let envelope = seal_ws_frame(&ws_session.key, ws_session.send_seq, &inner_json);
    ws_session.send_seq += 1;
    let wire = serde_json::to_string(&envelope)?;
    socket.send(WsMessage::Text(wire.into())).await?;
    Ok(())
}

pub(super) async fn send_login_error(
    socket: &mut WebSocket,
    user: &str,
    failure: AuthenticationFailure,
    connection_id: Uuid,
) {
    if let Err(error) = send_operator_message(socket, &login_failure_message(user, &failure)).await
    {
        warn!(%connection_id, %error, "failed to send operator websocket authentication error");
    }

    if let Err(e) = socket.send(WsMessage::Close(None)).await {
        debug!(%connection_id, error = %e, "failed to send close frame after auth failure");
    }
}
