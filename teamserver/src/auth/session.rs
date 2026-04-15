//! Operator session tracking and connection registry.

use std::collections::BTreeMap;

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
}
