//! Operator session tracking and connection registry.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use red_cell_common::config::OperatorRole;
use subtle::ConstantTimeEq;
use uuid::Uuid;

/// Maximum number of simultaneously authenticated operator sessions across all accounts.
///
/// Keeping N small ensures that the constant-time O(N) token scan in [`SessionRegistry`]
/// provides meaningful timing protection. Beyond this limit new logins are rejected.
pub const MAX_OPERATOR_SESSIONS: usize = 64;

/// Maximum number of simultaneously authenticated sessions per individual operator account.
///
/// This prevents a single compromised account from consuming the entire global session pool
/// and allows other operators to authenticate even under targeted abuse.
pub const MAX_SESSIONS_PER_ACCOUNT: usize = 8;

/// Default absolute session lifetime before the operator is forced to re-authenticate.
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Default idle timeout after which an inactive session is revoked.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Policy controlling when an authenticated operator session expires.
///
/// `None` on either field disables that expiry dimension. By default both
/// a 24-hour absolute TTL and a 30-minute idle timeout are enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionPolicy {
    /// Absolute session lifetime measured from the time of successful login.
    pub ttl: Option<Duration>,
    /// Maximum permissible gap between authenticated operator activities.
    pub idle_timeout: Option<Duration>,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self { ttl: Some(DEFAULT_SESSION_TTL), idle_timeout: Some(DEFAULT_IDLE_TIMEOUT) }
    }
}

impl SessionPolicy {
    /// Build a policy with no expiry — used by tests that need long-lived sessions.
    #[must_use]
    pub const fn unbounded() -> Self {
        Self { ttl: None, idle_timeout: None }
    }
}

/// Reason an authenticated operator session was considered expired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionExpiryReason {
    /// The absolute session lifetime (policy TTL) has been exceeded.
    TtlExceeded,
    /// No authenticated activity within the configured idle window.
    IdleTimeout,
}

impl SessionExpiryReason {
    /// Short machine-readable identifier used as the audit log `reason`.
    #[must_use]
    pub const fn as_reason_str(self) -> &'static str {
        match self {
            Self::TtlExceeded => "ttl_exceeded",
            Self::IdleTimeout => "idle_timeout",
        }
    }

    /// Operator-facing message included in the `InitConnectionError` payload.
    #[must_use]
    pub const fn client_message(self) -> &'static str {
        match self {
            Self::TtlExceeded => {
                "Session expired: maximum lifetime exceeded; please re-authenticate"
            }
            Self::IdleTimeout => "Session expired: inactivity timeout; please re-authenticate",
        }
    }
}

/// Outcome of [`SessionRegistry::touch_activity`] and
/// [`crate::AuthService::touch_session_activity`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionActivity {
    /// Session is valid; its last-activity timestamp has been refreshed.
    Ok,
    /// Session was expired. The session has been removed from the registry;
    /// the caller should notify the operator and close the connection.
    Expired {
        /// Reason the session was revoked.
        reason: SessionExpiryReason,
        /// Username of the expired session (for audit logging).
        username: String,
    },
    /// No session matched the supplied connection id.
    NotFound,
}

/// Authenticated operator session metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorSession {
    /// Stable token returned to the operator after login.
    pub token: String,
    /// Username for the authenticated operator.
    pub username: String,
    /// RBAC role assigned to the operator account.
    pub role: OperatorRole,
    /// Connection identifier used by the current WebSocket.
    pub connection_id: Uuid,
    /// Monotonic instant at which the session was first issued.
    pub created_at: Instant,
    /// Monotonic instant of the most recent authenticated activity.
    pub last_activity_at: Instant,
}

impl OperatorSession {
    /// Returns the expiry reason if the session violates `policy` at `now`,
    /// otherwise returns `None`.
    #[must_use]
    pub fn expiry_at(&self, now: Instant, policy: &SessionPolicy) -> Option<SessionExpiryReason> {
        if let Some(ttl) = policy.ttl
            && now.saturating_duration_since(self.created_at) >= ttl
        {
            return Some(SessionExpiryReason::TtlExceeded);
        }
        if let Some(idle) = policy.idle_timeout
            && now.saturating_duration_since(self.last_activity_at) >= idle
        {
            return Some(SessionExpiryReason::IdleTimeout);
        }
        None
    }
}

#[derive(Debug, Default)]
pub(super) struct SessionRegistry {
    by_token: BTreeMap<String, OperatorSession>,
    token_by_connection: BTreeMap<Uuid, String>,
}

impl SessionRegistry {
    pub(super) fn insert(&mut self, session: OperatorSession) {
        if let Some(previous_token) =
            self.token_by_connection.insert(session.connection_id, session.token.clone())
        {
            self.by_token.remove(&previous_token);
        }

        self.by_token.insert(session.token.clone(), session);
    }

    pub(super) fn remove_by_connection(&mut self, connection_id: Uuid) -> Option<OperatorSession> {
        let token = self.token_by_connection.remove(&connection_id)?;
        self.by_token.remove(&token)
    }

    pub(super) fn get_by_connection(&self, connection_id: Uuid) -> Option<&OperatorSession> {
        let token = self.token_by_connection.get(&connection_id)?;
        self.by_token.get(token)
    }

    /// Retrieve a session by its token using a constant-time byte comparison.
    ///
    /// `BTreeMap::get` short-circuits on the first unequal byte, which can leak
    /// timing information allowing an attacker to enumerate valid tokens. This
    /// implementation performs a linear scan comparing every token with
    /// [`subtle::ConstantTimeEq`] so that the per-byte comparison time does not
    /// depend on where the mismatch occurs.
    pub(super) fn get_by_token(&self, token: &str) -> Option<&OperatorSession> {
        let token_bytes = token.as_bytes();
        let mut found: Option<&OperatorSession> = None;
        for session in self.by_token.values() {
            let is_match: bool = session.token.as_bytes().ct_eq(token_bytes).into();
            if is_match {
                found = Some(session);
            }
        }
        found
    }

    pub(super) fn len(&self) -> usize {
        self.by_token.len()
    }

    /// Count the number of active sessions belonging to `username`.
    pub(super) fn sessions_for_account(&self, username: &str) -> usize {
        self.by_token.values().filter(|s| s.username == username).count()
    }

    pub(super) fn list(&self) -> Vec<OperatorSession> {
        self.by_token.values().cloned().collect()
    }

    /// Remove all sessions belonging to `username`, returning the removed sessions.
    pub(super) fn remove_by_username(&mut self, username: &str) -> Vec<OperatorSession> {
        let tokens_to_remove: Vec<String> = self
            .by_token
            .iter()
            .filter(|(_, session)| session.username == username)
            .map(|(token, _)| token.clone())
            .collect();

        let mut removed = Vec::with_capacity(tokens_to_remove.len());
        for token in tokens_to_remove {
            if let Some(session) = self.by_token.remove(&token) {
                self.token_by_connection.remove(&session.connection_id);
                removed.push(session);
            }
        }
        removed
    }

    /// Update the role on all sessions belonging to `username`.
    pub(super) fn update_role_by_username(&mut self, username: &str, role: OperatorRole) {
        for session in self.by_token.values_mut() {
            if session.username == username {
                session.role = role;
            }
        }
    }

    /// Validate the session bound to `connection_id` against `policy` and, if
    /// still valid, refresh its last-activity timestamp to `now`. Expired
    /// sessions are removed from the registry and their identity is returned so
    /// the caller can log the revocation and notify the client.
    pub(super) fn touch_activity(
        &mut self,
        connection_id: Uuid,
        now: Instant,
        policy: &SessionPolicy,
    ) -> SessionActivity {
        let Some(token) = self.token_by_connection.get(&connection_id).cloned() else {
            return SessionActivity::NotFound;
        };
        let Some(session) = self.by_token.get_mut(&token) else {
            // Registry invariant broken; treat as missing.
            self.token_by_connection.remove(&connection_id);
            return SessionActivity::NotFound;
        };

        if let Some(reason) = session.expiry_at(now, policy) {
            let username = session.username.clone();
            self.by_token.remove(&token);
            self.token_by_connection.remove(&connection_id);
            return SessionActivity::Expired { reason, username };
        }

        session.last_activity_at = now;
        SessionActivity::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session(now: Instant, username: &str) -> OperatorSession {
        OperatorSession {
            token: format!("token-{username}"),
            username: username.to_owned(),
            role: OperatorRole::Operator,
            connection_id: Uuid::new_v4(),
            created_at: now,
            last_activity_at: now,
        }
    }

    #[test]
    fn default_policy_applies_24h_ttl_and_30m_idle() {
        let policy = SessionPolicy::default();
        assert_eq!(policy.ttl, Some(DEFAULT_SESSION_TTL));
        assert_eq!(policy.idle_timeout, Some(DEFAULT_IDLE_TIMEOUT));
        assert_eq!(DEFAULT_SESSION_TTL, Duration::from_secs(86_400));
        assert_eq!(DEFAULT_IDLE_TIMEOUT, Duration::from_secs(1_800));
    }

    #[test]
    fn expiry_at_returns_ttl_exceeded_when_session_older_than_ttl() {
        let now = Instant::now();
        let session = make_session(now, "op");
        let policy = SessionPolicy {
            ttl: Some(Duration::from_secs(10)),
            idle_timeout: Some(Duration::from_secs(60)),
        };

        assert_eq!(session.expiry_at(now, &policy), None);
        assert_eq!(
            session.expiry_at(now + Duration::from_secs(10), &policy),
            Some(SessionExpiryReason::TtlExceeded),
        );
    }

    #[test]
    fn expiry_at_returns_idle_timeout_when_last_activity_stale() {
        let now = Instant::now();
        let mut session = make_session(now, "op");
        session.last_activity_at = now - Duration::from_secs(120);
        let policy = SessionPolicy {
            ttl: Some(Duration::from_secs(3600)),
            idle_timeout: Some(Duration::from_secs(60)),
        };

        assert_eq!(session.expiry_at(now, &policy), Some(SessionExpiryReason::IdleTimeout),);
    }

    #[test]
    fn expiry_at_prefers_ttl_over_idle_when_both_breached() {
        // TTL is reported first so an operator forced to re-auth after the
        // maximum lifetime sees the more accurate reason even if idle also
        // fires at the same wall-clock instant.
        let now = Instant::now();
        let mut session = make_session(now, "op");
        session.last_activity_at = now - Duration::from_secs(120);
        let policy = SessionPolicy {
            ttl: Some(Duration::from_secs(30)),
            idle_timeout: Some(Duration::from_secs(60)),
        };

        assert_eq!(
            session.expiry_at(now + Duration::from_secs(30), &policy),
            Some(SessionExpiryReason::TtlExceeded),
        );
    }

    #[test]
    fn expiry_at_never_expires_when_policy_unbounded() {
        let now = Instant::now();
        let mut session = make_session(now, "op");
        session.last_activity_at = now - Duration::from_secs(86_400);
        assert_eq!(
            session.expiry_at(now + Duration::from_secs(86_400 * 7), &SessionPolicy::unbounded()),
            None,
        );
    }

    #[test]
    fn touch_activity_refreshes_last_activity_when_valid() {
        let now = Instant::now();
        let mut registry = SessionRegistry::default();
        let session = make_session(now, "op");
        let connection_id = session.connection_id;
        registry.insert(session);

        let later = now + Duration::from_secs(5);
        assert_eq!(
            registry.touch_activity(connection_id, later, &SessionPolicy::default()),
            SessionActivity::Ok,
        );

        let refreshed =
            registry.get_by_connection(connection_id).expect("session should still be present");
        assert_eq!(refreshed.last_activity_at, later);
        assert_eq!(refreshed.created_at, now);
    }

    #[test]
    fn touch_activity_removes_expired_session_and_returns_reason() {
        let now = Instant::now();
        let mut registry = SessionRegistry::default();
        let session = make_session(now, "op");
        let connection_id = session.connection_id;
        let token = session.token.clone();
        registry.insert(session);

        let policy = SessionPolicy { ttl: Some(Duration::from_secs(10)), idle_timeout: None };
        let later = now + Duration::from_secs(15);

        match registry.touch_activity(connection_id, later, &policy) {
            SessionActivity::Expired { reason, username } => {
                assert_eq!(reason, SessionExpiryReason::TtlExceeded);
                assert_eq!(username, "op");
            }
            other => panic!("expected Expired, got {other:?}"),
        }

        assert!(registry.get_by_connection(connection_id).is_none());
        assert!(registry.get_by_token(&token).is_none());
    }

    #[test]
    fn touch_activity_returns_not_found_for_unknown_connection() {
        let mut registry = SessionRegistry::default();
        assert_eq!(
            registry.touch_activity(Uuid::new_v4(), Instant::now(), &SessionPolicy::default(),),
            SessionActivity::NotFound,
        );
    }
}
