//! Operator authentication and session tracking.

mod messages;
mod password;
mod session;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use red_cell_common::config::{OperatorRole, OperatorsConfig, Profile};
use red_cell_common::crypto::hash_password_sha3;
use red_cell_common::operator::OperatorMessage;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{instrument, warn};
use uuid::Uuid;

use crate::{Database, OperatorRepository, PersistedOperator, TeamserverError};

pub use messages::{
    OperatorPresence, login_failure_message, login_success_message, session_expired_message,
};
pub(crate) use password::{password_hashes_match, password_verifier_for_sha3};
pub use session::{
    DEFAULT_IDLE_TIMEOUT, DEFAULT_SESSION_TTL, MAX_OPERATOR_SESSIONS, MAX_SESSIONS_PER_ACCOUNT,
    OperatorSession, SessionActivity, SessionExpiryReason, SessionPolicy,
};

use password::{generate_dummy_verifier, normalize_persisted_verifier};
use session::SessionRegistry;

/// Errors returned while preparing or validating operator authentication state.
#[derive(Debug, Error)]
pub enum AuthError {
    /// The WebSocket client sent a message that was not a login request.
    #[error("expected an operator login message")]
    InvalidLoginMessage,
    /// The WebSocket client sent a text frame that was not valid operator JSON.
    #[error("invalid operator message json: {0}")]
    InvalidMessageJson(String),
    /// An operator username already exists.
    #[error("operator `{username}` already exists")]
    DuplicateUser {
        /// Duplicate operator username.
        username: String,
    },
    /// The submitted username was blank.
    #[error("operator username must not be empty")]
    EmptyUsername,
    /// The submitted password was blank.
    #[error("operator password must not be empty")]
    EmptyPassword,
    /// The requested operator does not exist.
    #[error("operator `{username}` not found")]
    OperatorNotFound {
        /// Missing operator username.
        username: String,
    },
    /// The operator was loaded from the profile and cannot be modified at runtime.
    #[error("operator `{username}` is profile-configured and cannot be modified at runtime")]
    ProfileOperator {
        /// Profile-configured operator username.
        username: String,
    },
    /// Password verifier generation failed.
    #[error("password verifier error: {0}")]
    PasswordVerifier(String),
    /// Runtime operator persistence failed.
    #[error(transparent)]
    Persistence(#[from] TeamserverError),
    /// Audit log query failed while loading operator presence metadata.
    #[error(transparent)]
    AuditLog(TeamserverError),
}

impl PartialEq for AuthError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::InvalidLoginMessage, Self::InvalidLoginMessage)
            | (Self::EmptyUsername, Self::EmptyUsername)
            | (Self::EmptyPassword, Self::EmptyPassword) => true,
            (Self::DuplicateUser { username: left }, Self::DuplicateUser { username: right }) => {
                left == right
            }
            (
                Self::OperatorNotFound { username: left },
                Self::OperatorNotFound { username: right },
            ) => left == right,
            (
                Self::ProfileOperator { username: left },
                Self::ProfileOperator { username: right },
            ) => left == right,
            (Self::InvalidMessageJson(left), Self::InvalidMessageJson(right)) => left == right,
            (Self::PasswordVerifier(left), Self::PasswordVerifier(right)) => left == right,
            (Self::Persistence(left), Self::Persistence(right)) => {
                left.to_string() == right.to_string()
            }
            (Self::AuditLog(left), Self::AuditLog(right)) => left.to_string() == right.to_string(),
            _ => false,
        }
    }
}

impl Eq for AuthError {}

/// Successful login result with a newly issued session token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationSuccess {
    /// Username associated with the authenticated session.
    pub username: String,
    /// Newly issued opaque session token.
    pub token: String,
}

/// Failed login result mapped onto Havoc-compatible error responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticationFailure {
    /// Submitted credentials did not authenticate an operator account.
    InvalidCredentials,
    /// The global or per-account session cap has been reached; no new sessions can be created.
    SessionCapExceeded,
}

impl AuthenticationFailure {
    /// Build the Havoc-compatible error message returned to the client.
    #[must_use]
    pub fn message(&self) -> &'static str {
        match self {
            Self::InvalidCredentials => "Authentication failed",
            Self::SessionCapExceeded => "Too many active sessions; try again later",
        }
    }
}

/// Result of validating a login message against the loaded profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticationResult {
    /// Login succeeded and a new session has been created.
    Success(AuthenticationSuccess),
    /// Login failed due to an unknown user or invalid password hash.
    Failure(AuthenticationFailure),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OperatorAccount {
    password_verifier: String,
    role: OperatorRole,
}

/// In-memory operator credential store and active session registry.
#[derive(Debug, Clone)]
pub struct AuthService {
    credentials: Arc<RwLock<BTreeMap<String, OperatorAccount>>>,
    dummy_password_verifier: String,
    sessions: Arc<RwLock<SessionRegistry>>,
    runtime_operators: Option<OperatorRepository>,
    audit_log: Option<crate::AuditLogRepository>,
    session_policy: SessionPolicy,
}

fn session_policy_from_operators(operators: &OperatorsConfig) -> SessionPolicy {
    let defaults = SessionPolicy::default();
    SessionPolicy {
        ttl: operators
            .session_ttl_hours
            .map(|hours| Duration::from_secs(hours.saturating_mul(3600)))
            .or(defaults.ttl),
        idle_timeout: operators
            .idle_timeout_minutes
            .map(|minutes| Duration::from_secs(minutes.saturating_mul(60)))
            .or(defaults.idle_timeout),
    }
}

impl AuthService {
    /// Build an authentication service from a validated profile.
    pub fn from_profile(profile: &Profile) -> Result<Self, AuthError> {
        Ok(Self {
            credentials: Arc::new(RwLock::new(configured_credentials(profile)?)),
            dummy_password_verifier: generate_dummy_verifier()?,
            sessions: Arc::new(RwLock::new(SessionRegistry::default())),
            runtime_operators: None,
            audit_log: None,
            session_policy: session_policy_from_operators(&profile.operators),
        })
    }

    /// Build an authentication service from a validated profile and load persisted runtime users.
    pub async fn from_profile_with_database(
        profile: &Profile,
        database: &Database,
    ) -> Result<Self, AuthError> {
        let service = Self {
            credentials: Arc::new(RwLock::new(configured_credentials(profile)?)),
            dummy_password_verifier: generate_dummy_verifier()?,
            sessions: Arc::new(RwLock::new(SessionRegistry::default())),
            runtime_operators: Some(database.operators()),
            audit_log: Some(database.audit_log()),
            session_policy: session_policy_from_operators(&profile.operators),
        };

        service.load_runtime_operators().await?;
        Ok(service)
    }

    /// Override the session expiry policy.
    ///
    /// Used by integration tests and by the teamserver bootstrap to wire through
    /// operator-configured TTL and idle-timeout values before sessions are issued.
    #[must_use]
    pub fn with_session_policy(mut self, policy: SessionPolicy) -> Self {
        self.session_policy = policy;
        self
    }

    /// Return the active session policy.
    #[must_use]
    pub fn session_policy(&self) -> SessionPolicy {
        self.session_policy
    }

    /// Authenticate a parsed login payload and create a session on success.
    #[instrument(skip(self, login), fields(connection_id = %connection_id, username = %login.user))]
    pub async fn authenticate_login(
        &self,
        connection_id: Uuid,
        login: &red_cell_common::operator::LoginInfo,
    ) -> AuthenticationResult {
        // Extract owned data under the read lock so we can drop it before the blocking await.
        let (expected, account_role) = {
            let credentials = self.credentials.read().await;
            let account = credentials.get(&login.user);
            let verifier = account
                .map(|a| a.password_verifier.as_str())
                .unwrap_or(self.dummy_password_verifier.as_str())
                .to_owned();
            let role = account.map(|a| a.role);
            (verifier, role)
        };

        let submitted = login.password.clone();
        let hashes_match =
            tokio::task::spawn_blocking(move || password_hashes_match(&submitted, &expected))
                .await
                .map_err(|e| {
                    tracing::error!("spawn_blocking for password_hashes_match panicked: {e}");
                    AuthenticationResult::Failure(AuthenticationFailure::InvalidCredentials)
                });
        let hashes_match = match hashes_match {
            Ok(v) => v,
            Err(result) => return result,
        };
        if !hashes_match {
            return AuthenticationResult::Failure(AuthenticationFailure::InvalidCredentials);
        }

        let Some(role) = account_role else {
            return AuthenticationResult::Failure(AuthenticationFailure::InvalidCredentials);
        };

        let token = Uuid::new_v4().to_string();
        let now = Instant::now();
        let session = OperatorSession {
            token: token.clone(),
            username: login.user.clone(),
            role,
            connection_id,
            created_at: now,
            last_activity_at: now,
        };

        {
            let mut registry = self.sessions.write().await;
            if registry.len() >= MAX_OPERATOR_SESSIONS {
                tracing::warn!(
                    username = %login.user,
                    "login rejected: global session cap ({MAX_OPERATOR_SESSIONS}) reached"
                );
                return AuthenticationResult::Failure(AuthenticationFailure::SessionCapExceeded);
            }
            if registry.sessions_for_account(&login.user) >= MAX_SESSIONS_PER_ACCOUNT {
                tracing::warn!(
                    username = %login.user,
                    "login rejected: per-account session cap ({MAX_SESSIONS_PER_ACCOUNT}) reached"
                );
                return AuthenticationResult::Failure(AuthenticationFailure::SessionCapExceeded);
            }
            registry.insert(session);
        }

        AuthenticationResult::Success(AuthenticationSuccess { username: login.user.clone(), token })
    }

    /// Create a new runtime operator account.
    pub async fn create_operator(
        &self,
        username: &str,
        password: &str,
        role: OperatorRole,
    ) -> Result<(), AuthError> {
        let username = username.trim();
        if username.is_empty() {
            return Err(AuthError::EmptyUsername);
        }

        if password.trim().is_empty() {
            return Err(AuthError::EmptyPassword);
        }

        let mut credentials = self.credentials.write().await;
        if credentials.contains_key(username) {
            return Err(AuthError::DuplicateUser { username: username.to_owned() });
        }

        let password_verifier = password_verifier_for_sha3(&hash_password_sha3(password))?;
        if let Some(runtime_operators) = &self.runtime_operators {
            runtime_operators
                .create(&PersistedOperator {
                    username: username.to_owned(),
                    password_verifier: password_verifier.clone(),
                    role,
                })
                .await?;
        }

        credentials.insert(username.to_owned(), OperatorAccount { password_verifier, role });
        Ok(())
    }

    /// Delete a runtime-created operator account.
    ///
    /// Profile-configured operators cannot be deleted at runtime.
    /// Returns an error if the operator does not exist or was loaded from the profile.
    pub async fn delete_operator(&self, username: &str) -> Result<(), AuthError> {
        let username = username.trim();
        if username.is_empty() {
            return Err(AuthError::EmptyUsername);
        }

        let mut credentials = self.credentials.write().await;
        if !credentials.contains_key(username) {
            return Err(AuthError::OperatorNotFound { username: username.to_owned() });
        }

        let Some(runtime_operators) = &self.runtime_operators else {
            return Err(AuthError::ProfileOperator { username: username.to_owned() });
        };

        let deleted = runtime_operators.delete(username).await?;
        if !deleted {
            return Err(AuthError::ProfileOperator { username: username.to_owned() });
        }

        credentials.remove(username);

        let revoked = self.sessions.write().await.remove_by_username(username);
        if !revoked.is_empty() {
            tracing::info!(
                username,
                count = revoked.len(),
                "revoked active sessions for deleted operator"
            );
        }

        Ok(())
    }

    /// Update the RBAC role for a runtime-created operator account.
    ///
    /// Profile-configured operators cannot be modified at runtime.
    /// Returns an error if the operator does not exist or was loaded from the profile.
    pub async fn update_operator_role(
        &self,
        username: &str,
        role: OperatorRole,
    ) -> Result<(), AuthError> {
        let username = username.trim();
        if username.is_empty() {
            return Err(AuthError::EmptyUsername);
        }

        let mut credentials = self.credentials.write().await;
        if !credentials.contains_key(username) {
            return Err(AuthError::OperatorNotFound { username: username.to_owned() });
        }

        let Some(runtime_operators) = &self.runtime_operators else {
            return Err(AuthError::ProfileOperator { username: username.to_owned() });
        };

        let updated = runtime_operators.update_role(username, role).await?;
        if !updated {
            return Err(AuthError::ProfileOperator { username: username.to_owned() });
        }

        if let Some(account) = credentials.get_mut(username) {
            account.role = role;
        }

        self.sessions.write().await.update_role_by_username(username, role);

        Ok(())
    }

    /// Return all currently authenticated operator sessions.
    pub async fn active_sessions(&self) -> Vec<OperatorSession> {
        self.sessions.read().await.list()
    }

    /// Return all configured and runtime-created operators with current presence state.
    ///
    /// When an audit log repository is configured (`from_profile_with_database`), a failure
    /// to query last-activity timestamps is returned as [`AuthError::AuditLog`] so callers do
    /// not silently return empty `last_seen` values while the backing store is broken.
    pub async fn operator_inventory(&self) -> Result<Vec<OperatorPresence>, AuthError> {
        let credentials = self.credentials.read().await.clone();
        let sessions = self.sessions.read().await.list();
        let last_seen = match &self.audit_log {
            Some(audit_log) => audit_log
                .latest_timestamps_by_actor_for_actions(&[
                    "operator.connect",
                    "operator.disconnect",
                    "operator.chat",
                ])
                .await
                .inspect_err(|err| {
                    warn!(
                        error = %err,
                        "operator_inventory: audit log query failed; last_seen cannot be trusted"
                    );
                })
                .map_err(AuthError::AuditLog)?,
            None => BTreeMap::new(),
        };
        let mut operators = credentials
            .into_iter()
            .map(|(username, account)| {
                let last_seen = last_seen.get(&username).cloned();
                (
                    username.clone(),
                    OperatorPresence { username, role: account.role, online: false, last_seen },
                )
            })
            .collect::<BTreeMap<_, _>>();

        for session in sessions {
            let session_last_seen = last_seen.get(&session.username).cloned();
            operators
                .entry(session.username.clone())
                .and_modify(|operator| operator.online = true)
                .or_insert(OperatorPresence {
                    username: session.username,
                    role: session.role,
                    online: true,
                    last_seen: session_last_seen,
                });
        }

        Ok(operators.into_values().collect())
    }

    /// Parse and authenticate a raw JSON operator message.
    #[instrument(skip(self, payload), fields(connection_id = %connection_id))]
    pub async fn authenticate_message(
        &self,
        connection_id: Uuid,
        payload: &str,
    ) -> Result<AuthenticationResult, AuthError> {
        let message = serde_json::from_str::<OperatorMessage>(payload)
            .map_err(|error| AuthError::InvalidMessageJson(error.to_string()))?;

        match message {
            OperatorMessage::Login(message) => {
                Ok(self.authenticate_login(connection_id, &message.info).await)
            }
            _ => Err(AuthError::InvalidLoginMessage),
        }
    }

    /// Remove any active session associated with the given connection id.
    #[instrument(skip(self), fields(connection_id = %connection_id))]
    pub async fn remove_connection(&self, connection_id: Uuid) -> Option<OperatorSession> {
        self.sessions.write().await.remove_by_connection(connection_id)
    }

    /// Return the session currently bound to `connection_id`, if any.
    #[instrument(skip(self), fields(connection_id = %connection_id))]
    pub async fn session_for_connection(&self, connection_id: Uuid) -> Option<OperatorSession> {
        self.sessions.read().await.get_by_connection(connection_id).cloned()
    }

    /// Return the session currently bound to `token`, if any.
    #[instrument(skip(self, token))]
    pub async fn session_for_token(&self, token: &str) -> Option<OperatorSession> {
        self.sessions.read().await.get_by_token(token).cloned()
    }

    /// Return the number of active authenticated sessions.
    #[instrument(skip(self))]
    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Validate the session bound to `connection_id` against the active policy
    /// and, if still valid, refresh its last-activity timestamp. Expired
    /// sessions are removed before returning.
    ///
    /// The caller is responsible for notifying the operator and terminating the
    /// underlying WebSocket when [`SessionActivity::Expired`] is returned.
    #[instrument(skip(self), fields(connection_id = %connection_id))]
    pub async fn touch_session_activity(&self, connection_id: Uuid) -> SessionActivity {
        self.touch_session_activity_at(connection_id, Instant::now()).await
    }

    /// Test-only variant of [`AuthService::touch_session_activity`] that
    /// accepts an injected monotonic instant, enabling deterministic expiry
    /// assertions without sleeping.
    pub async fn touch_session_activity_at(
        &self,
        connection_id: Uuid,
        now: Instant,
    ) -> SessionActivity {
        self.sessions.write().await.touch_activity(connection_id, now, &self.session_policy)
    }

    /// Revoke every authenticated session belonging to `username`.
    ///
    /// Returns the sessions that were removed from the registry so the caller
    /// can record an audit entry describing which tokens/connections were
    /// invalidated. The underlying WebSocket is not closed synchronously; the
    /// operator session loop detects the revocation via
    /// [`SessionActivity::NotFound`] on the next authenticated frame and
    /// terminates the connection.
    #[instrument(skip(self), fields(username = %username))]
    pub async fn revoke_sessions_for_username(&self, username: &str) -> Vec<OperatorSession> {
        self.sessions.write().await.remove_by_username(username)
    }

    /// Return whether an operator account is configured with the given username.
    ///
    /// Covers both profile-configured and runtime-created operators; does not
    /// consider whether the account currently has an active session.
    #[instrument(skip(self), fields(username = %username))]
    pub async fn is_operator_configured(&self, username: &str) -> bool {
        self.credentials.read().await.contains_key(username)
    }

    async fn load_runtime_operators(&self) -> Result<(), AuthError> {
        let Some(runtime_operators) = &self.runtime_operators else {
            return Ok(());
        };

        let persisted = runtime_operators.list().await?;
        let mut credentials = self.credentials.write().await;
        for operator in persisted {
            let password_verifier =
                normalize_persisted_verifier(runtime_operators, &operator).await?;
            credentials
                .entry(operator.username)
                .or_insert(OperatorAccount { password_verifier, role: operator.role });
        }

        Ok(())
    }
}

fn configured_credentials(
    profile: &Profile,
) -> Result<BTreeMap<String, OperatorAccount>, AuthError> {
    profile
        .operators
        .users
        .iter()
        .map(|(username, config)| {
            Ok((
                username.clone(),
                OperatorAccount {
                    password_verifier: password_verifier_for_sha3(&hash_password_sha3(
                        &config.password,
                    ))?,
                    role: config.role,
                },
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests;
