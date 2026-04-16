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
        let credentials = self.credentials.read().await;
        let account = credentials.get(&login.user);
        let expected_verifier = account
            .map(|account| account.password_verifier.as_str())
            .unwrap_or(self.dummy_password_verifier.as_str());

        if !password_hashes_match(&login.password, expected_verifier) {
            return AuthenticationResult::Failure(AuthenticationFailure::InvalidCredentials);
        }

        let Some(account) = account else {
            return AuthenticationResult::Failure(AuthenticationFailure::InvalidCredentials);
        };

        let token = Uuid::new_v4().to_string();
        let now = Instant::now();
        let session = OperatorSession {
            token: token.clone(),
            username: login.user.clone(),
            role: account.role,
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
mod tests {
    use crate::{Database, PersistedOperator};
    use red_cell_common::config::{OperatorRole, Profile};
    use red_cell_common::crypto::hash_password_sha3;
    use red_cell_common::operator::{
        EventCode, InitConnectionCode, LoginInfo, Message, MessageHead, OperatorMessage,
    };
    use serde_json::json;
    use uuid::Uuid;

    use super::{
        AuthError, AuthService, AuthenticationFailure, AuthenticationResult, login_failure_message,
        login_success_message, password_hashes_match, password_verifier_for_sha3,
    };

    fn profile() -> Profile {
        Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "operator" {
                Password = "password1234"
                Role = "Operator"
              }
              user "admin" {
                Password = "adminpw"
                Role = "Admin"
              }
              user "analyst" {
                Password = "readonly"
                Role = "Analyst"
              }
            }

            Demon {}
            "#,
        )
        .expect("test profile should parse")
    }

    #[tokio::test]
    async fn authenticate_login_accepts_valid_hash_and_tracks_session() {
        let service =
            AuthService::from_profile(&profile()).expect("auth service should initialize");
        let connection_id = Uuid::new_v4();

        let result = service
            .authenticate_message(
                connection_id,
                &serde_json::to_string(&OperatorMessage::Login(Message {
                    head: MessageHead {
                        event: EventCode::InitConnection,
                        user: "operator".to_owned(),
                        timestamp: String::new(),
                        one_time: String::new(),
                    },
                    info: LoginInfo {
                        user: "operator".to_owned(),
                        password: hash_password_sha3("password1234"),
                    },
                }))
                .expect("login message should serialize"),
            )
            .await
            .expect("login message should parse");

        let AuthenticationResult::Success(success) = result else {
            panic!("expected successful authentication");
        };

        assert_eq!(success.username, "operator");
        assert_eq!(service.session_count().await, 1);

        let by_connection = service
            .session_for_connection(connection_id)
            .await
            .expect("session should be associated to the connection");
        assert_eq!(by_connection.username, "operator");
        assert_eq!(by_connection.role, red_cell_common::config::OperatorRole::Operator);
        assert_eq!(by_connection.token, success.token);

        let by_token = service
            .session_for_token(&success.token)
            .await
            .expect("session should be retrievable by token");
        assert_eq!(by_token.connection_id, connection_id);
    }

    #[tokio::test]
    async fn authenticate_login_rejects_unknown_users() {
        let service =
            AuthService::from_profile(&profile()).expect("auth service should initialize");
        let connection_id = Uuid::new_v4();

        let result = service
            .authenticate_login(
                connection_id,
                &LoginInfo {
                    user: "ghost".to_owned(),
                    password: hash_password_sha3("password1234"),
                },
            )
            .await;

        assert_eq!(
            result,
            AuthenticationResult::Failure(AuthenticationFailure::InvalidCredentials)
        );
        assert_eq!(service.session_count().await, 0);
    }

    #[tokio::test]
    async fn authenticate_login_rejects_wrong_password_hash() {
        let service =
            AuthService::from_profile(&profile()).expect("auth service should initialize");

        let result = service
            .authenticate_login(
                Uuid::new_v4(),
                &LoginInfo { user: "operator".to_owned(), password: hash_password_sha3("wrong") },
            )
            .await;

        assert_eq!(
            result,
            AuthenticationResult::Failure(AuthenticationFailure::InvalidCredentials)
        );
        assert_eq!(service.session_count().await, 0);
    }

    #[tokio::test]
    async fn authenticate_login_accepts_uppercase_password_hash() {
        let service =
            AuthService::from_profile(&profile()).expect("auth service should initialize");

        let result = service
            .authenticate_login(
                Uuid::new_v4(),
                &LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("password1234").to_ascii_uppercase(),
                },
            )
            .await;

        assert!(matches!(result, AuthenticationResult::Success(_)));
    }

    #[tokio::test]
    async fn authenticate_message_rejects_non_login_messages() {
        let service =
            AuthService::from_profile(&profile()).expect("auth service should initialize");
        let payload = json!({
            "Head": { "Event": 1, "User": "operator" },
            "Body": { "SubEvent": 4, "Info": { "Any": "value" } }
        });

        let error = service
            .authenticate_message(Uuid::new_v4(), &payload.to_string())
            .await
            .expect_err("non-login message should be rejected");

        assert_eq!(error, AuthError::InvalidLoginMessage);
    }

    #[tokio::test]
    async fn authenticate_message_rejects_invalid_json() {
        let service =
            AuthService::from_profile(&profile()).expect("auth service should initialize");

        let error = service
            .authenticate_message(Uuid::new_v4(), "not-valid-json{")
            .await
            .expect_err("invalid JSON should be rejected");

        assert!(
            matches!(error, AuthError::InvalidMessageJson(_)),
            "expected InvalidMessageJson, got {error:?}"
        );
        assert!(
            service.active_sessions().await.is_empty(),
            "no session should be created on invalid JSON"
        );
    }

    #[tokio::test]
    async fn authenticate_message_accepts_password_sha3_alias() {
        let service =
            AuthService::from_profile(&profile()).expect("auth service should initialize");
        let connection_id = Uuid::new_v4();
        let payload = json!({
            "Head": {
                "Event": EventCode::InitConnection.as_u32(),
                "User": "operator"
            },
            "Body": {
                "SubEvent": InitConnectionCode::Login.as_u32(),
                "Info": {
                    "User": "operator",
                    "Password_SHA3": hash_password_sha3("password1234")
                }
            }
        });

        let result = service
            .authenticate_message(connection_id, &payload.to_string())
            .await
            .expect("login payload should parse");

        assert!(matches!(result, AuthenticationResult::Success(_)));
    }

    #[tokio::test]
    async fn remove_connection_drops_associated_session() {
        let service =
            AuthService::from_profile(&profile()).expect("auth service should initialize");
        let connection_id = Uuid::new_v4();

        let result = service
            .authenticate_login(
                connection_id,
                &LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("password1234"),
                },
            )
            .await;

        let AuthenticationResult::Success(success) = result else {
            panic!("expected successful authentication");
        };

        let removed =
            service.remove_connection(connection_id).await.expect("session should be removed");
        assert_eq!(removed.token, success.token);
        assert_eq!(service.session_count().await, 0);
        assert!(service.session_for_token(&success.token).await.is_none());
    }

    #[tokio::test]
    async fn session_registry_replaces_old_session_on_same_connection_id() {
        let service =
            AuthService::from_profile(&profile()).expect("auth service should initialize");
        let connection_id = Uuid::new_v4();

        let first = service
            .authenticate_login(
                connection_id,
                &LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("password1234"),
                },
            )
            .await;
        let AuthenticationResult::Success(first_success) = first else {
            panic!("expected successful first authentication");
        };
        assert_eq!(service.session_count().await, 1);

        let second = service
            .authenticate_login(
                connection_id,
                &LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("password1234"),
                },
            )
            .await;
        let AuthenticationResult::Success(second_success) = second else {
            panic!("expected successful second authentication");
        };

        assert_eq!(service.session_count().await, 1);

        assert!(
            service.session_for_token(&first_success.token).await.is_none(),
            "stale token must not be retrievable after re-authentication"
        );

        let new_session = service
            .session_for_token(&second_success.token)
            .await
            .expect("new token must be retrievable");
        assert_eq!(new_session.connection_id, connection_id);
        assert_eq!(new_session.username, "operator");
    }

    #[tokio::test]
    async fn authenticate_login_tracks_configured_role_on_session() {
        let service =
            AuthService::from_profile(&profile()).expect("auth service should initialize");
        let connection_id = Uuid::new_v4();

        let result = service
            .authenticate_login(
                connection_id,
                &LoginInfo { user: "analyst".to_owned(), password: hash_password_sha3("readonly") },
            )
            .await;

        assert!(matches!(result, AuthenticationResult::Success(_)));

        let session =
            service.session_for_connection(connection_id).await.expect("session should be stored");
        assert_eq!(session.role, red_cell_common::config::OperatorRole::Analyst);
    }

    #[tokio::test]
    async fn create_operator_adds_runtime_credentials() {
        let service =
            AuthService::from_profile(&profile()).expect("auth service should initialize");
        service
            .create_operator("trinity", "zion", red_cell_common::config::OperatorRole::Operator)
            .await
            .expect("operator should be created");

        let result = service
            .authenticate_login(
                Uuid::new_v4(),
                &LoginInfo { user: "trinity".to_owned(), password: hash_password_sha3("zion") },
            )
            .await;

        assert!(matches!(result, AuthenticationResult::Success(_)));
    }

    #[tokio::test]
    async fn create_operator_rejects_blank_usernames() {
        let service =
            AuthService::from_profile(&profile()).expect("auth service should initialize");

        let cases: &[(&str, &str)] = &[
            ("", "empty string"),
            ("   ", "spaces only"),
            ("\t\n", "tab and newline only"),
            (" \t \n ", "mixed whitespace"),
        ];

        for (input, label) in cases {
            let error = service
                .create_operator(input, "zion", red_cell_common::config::OperatorRole::Operator)
                .await
                .expect_err(&format!("username {label:?} ({input:?}) should be rejected"));

            assert_eq!(
                error,
                AuthError::EmptyUsername,
                "username {label:?} ({input:?}) should produce EmptyUsername"
            );
        }
    }

    #[tokio::test]
    async fn create_operator_rejects_blank_passwords() {
        let service =
            AuthService::from_profile(&profile()).expect("auth service should initialize");

        let cases: &[(&str, &str)] = &[
            ("", "empty string"),
            ("   ", "spaces only"),
            ("\t\n", "tab and newline only"),
            (" \t \n ", "mixed whitespace"),
        ];

        for (input, label) in cases {
            let error = service
                .create_operator("trinity", input, red_cell_common::config::OperatorRole::Operator)
                .await
                .expect_err(&format!("password {label:?} ({input:?}) should be rejected"));

            assert_eq!(
                error,
                AuthError::EmptyPassword,
                "password {label:?} ({input:?}) should produce EmptyPassword"
            );
        }
    }

    #[tokio::test]
    async fn create_operator_rejects_duplicate_username() {
        let service =
            AuthService::from_profile(&profile()).expect("auth service should initialize");
        service
            .create_operator("trinity", "zion", red_cell_common::config::OperatorRole::Operator)
            .await
            .expect("initial operator should be created");

        let error = service
            .create_operator("trinity", "matrix", red_cell_common::config::OperatorRole::Analyst)
            .await
            .expect_err("duplicate usernames should be rejected");

        assert_eq!(error, AuthError::DuplicateUser { username: "trinity".to_owned() });
    }

    #[tokio::test]
    async fn from_profile_with_database_loads_persisted_runtime_operators() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        database
            .operators()
            .create(&PersistedOperator {
                username: "trinity".to_owned(),
                password_verifier: password_verifier_for_sha3(&hash_password_sha3("zion"))
                    .expect("password verifier should be generated"),
                role: red_cell_common::config::OperatorRole::Operator,
            })
            .await
            .expect("runtime operator should persist");

        let service = AuthService::from_profile_with_database(&profile(), &database)
            .await
            .expect("auth service should load runtime operators");
        let result = service
            .authenticate_login(
                Uuid::new_v4(),
                &LoginInfo { user: "trinity".to_owned(), password: hash_password_sha3("zion") },
            )
            .await;

        assert!(matches!(result, AuthenticationResult::Success(_)));
    }

    #[tokio::test]
    async fn create_operator_persists_runtime_credentials_when_database_backed() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        let service = AuthService::from_profile_with_database(&profile(), &database)
            .await
            .expect("auth service should initialize");

        service
            .create_operator("trinity", "zion", red_cell_common::config::OperatorRole::Analyst)
            .await
            .expect("operator should be created");

        let persisted = database
            .operators()
            .get("trinity")
            .await
            .expect("query should succeed")
            .expect("runtime operator should be persisted");
        assert_eq!(persisted.username, "trinity");
        assert_ne!(persisted.password_verifier, hash_password_sha3("zion"));
        assert!(password_hashes_match(&hash_password_sha3("zion"), &persisted.password_verifier));
        assert_eq!(persisted.role, red_cell_common::config::OperatorRole::Analyst);
    }

    #[tokio::test]
    async fn active_sessions_returns_authenticated_operators() {
        let service =
            AuthService::from_profile(&profile()).expect("auth service should initialize");
        let connection_id = Uuid::new_v4();
        let result = service
            .authenticate_login(
                connection_id,
                &LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("password1234"),
                },
            )
            .await;
        assert!(matches!(result, AuthenticationResult::Success(_)));

        let sessions = service.active_sessions().await;
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].connection_id, connection_id);
        assert_eq!(sessions[0].username, "operator");
    }

    #[tokio::test]
    async fn operator_inventory_includes_configured_and_runtime_accounts_with_presence() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        let service = AuthService::from_profile_with_database(&profile(), &database)
            .await
            .expect("auth service should initialize");
        service
            .create_operator("trinity", "zion", red_cell_common::config::OperatorRole::Operator)
            .await
            .expect("runtime operator should be created");
        let result = service
            .authenticate_login(
                Uuid::new_v4(),
                &LoginInfo { user: "analyst".to_owned(), password: hash_password_sha3("readonly") },
            )
            .await;
        assert!(matches!(result, AuthenticationResult::Success(_)));

        let inventory = service
            .operator_inventory()
            .await
            .expect("operator inventory should succeed when audit log is healthy");
        assert_eq!(
            inventory,
            vec![
                super::OperatorPresence {
                    username: "admin".to_owned(),
                    role: red_cell_common::config::OperatorRole::Admin,
                    online: false,
                    last_seen: None,
                },
                super::OperatorPresence {
                    username: "analyst".to_owned(),
                    role: red_cell_common::config::OperatorRole::Analyst,
                    online: true,
                    last_seen: None,
                },
                super::OperatorPresence {
                    username: "operator".to_owned(),
                    role: red_cell_common::config::OperatorRole::Operator,
                    online: false,
                    last_seen: None,
                },
                super::OperatorPresence {
                    username: "trinity".to_owned(),
                    role: red_cell_common::config::OperatorRole::Operator,
                    online: false,
                    last_seen: None,
                },
            ]
        );
    }

    #[tokio::test]
    async fn operator_inventory_populates_last_seen_from_audit_log() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        database
            .audit_log()
            .create(&crate::AuditLogEntry {
                id: None,
                actor: "operator".to_owned(),
                action: "operator.disconnect".to_owned(),
                target_kind: "operator".to_owned(),
                target_id: Some("operator".to_owned()),
                details: None,
                occurred_at: "2026-03-11T08:00:00Z".to_owned(),
            })
            .await
            .expect("audit row should persist");
        let service = AuthService::from_profile_with_database(&profile(), &database)
            .await
            .expect("auth service should initialize");

        let inventory = service
            .operator_inventory()
            .await
            .expect("operator inventory should succeed when audit log is healthy");
        let operator = inventory
            .into_iter()
            .find(|entry| entry.username == "operator")
            .expect("operator entry should exist");

        assert_eq!(operator.last_seen.as_deref(), Some("2026-03-11T08:00:00Z"));
    }

    #[tokio::test]
    async fn from_profile_with_database_upgrades_legacy_runtime_operator_digests() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        sqlx::query(
            "INSERT INTO ts_runtime_operators (username, password_verifier, role) VALUES (?, ?, ?)",
        )
        .bind("legacy")
        .bind(hash_password_sha3("zion"))
        .bind("Operator")
        .execute(database.pool())
        .await
        .expect("legacy runtime operator should persist");

        let service = AuthService::from_profile_with_database(&profile(), &database)
            .await
            .expect("auth service should load runtime operators");
        let result = service
            .authenticate_login(
                Uuid::new_v4(),
                &LoginInfo { user: "legacy".to_owned(), password: hash_password_sha3("zion") },
            )
            .await;
        assert!(matches!(result, AuthenticationResult::Success(_)));

        let persisted = database
            .operators()
            .get("legacy")
            .await
            .expect("query should succeed")
            .expect("runtime operator should exist");
        assert_ne!(persisted.password_verifier, hash_password_sha3("zion"));
        assert!(password_hashes_match(&hash_password_sha3("zion"), &persisted.password_verifier));
    }

    #[tokio::test]
    async fn session_for_token_returns_none_for_unknown_token() {
        let service =
            AuthService::from_profile(&profile()).expect("auth service should initialize");

        let result = service
            .authenticate_login(
                Uuid::new_v4(),
                &LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("password1234"),
                },
            )
            .await;
        assert!(matches!(result, AuthenticationResult::Success(_)));

        assert!(
            service.session_for_token("nonexistent-token").await.is_none(),
            "unknown token should not match any session"
        );
    }

    #[tokio::test]
    async fn session_for_token_returns_none_for_wrong_length_token() {
        let service =
            AuthService::from_profile(&profile()).expect("auth service should initialize");

        let result = service
            .authenticate_login(
                Uuid::new_v4(),
                &LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("password1234"),
                },
            )
            .await;
        let AuthenticationResult::Success(success) = result else {
            panic!("expected successful authentication");
        };

        let truncated = &success.token[..success.token.len() - 1];
        assert!(
            service.session_for_token(truncated).await.is_none(),
            "truncated token should not match"
        );

        let extended = format!("{}x", success.token);
        assert!(
            service.session_for_token(&extended).await.is_none(),
            "extended token should not match"
        );
    }

    #[tokio::test]
    async fn session_for_token_returns_matching_session_across_multiple_sessions() {
        let service =
            AuthService::from_profile(&profile()).expect("auth service should initialize");

        let mut tokens = Vec::new();
        let users = [("operator", "password1234"), ("admin", "adminpw"), ("analyst", "readonly")];
        for (user, password) in &users {
            let result = service
                .authenticate_login(
                    Uuid::new_v4(),
                    &LoginInfo { user: (*user).to_owned(), password: hash_password_sha3(password) },
                )
                .await;
            let AuthenticationResult::Success(success) = result else {
                panic!("expected successful authentication for {user}");
            };
            tokens.push(((*user).to_owned(), success.token));
        }

        for (expected_user, token) in &tokens {
            let session =
                service.session_for_token(token).await.expect("token should match a session");
            assert_eq!(&session.username, expected_user, "token should map to the correct user");
        }
    }

    #[tokio::test]
    async fn authenticate_login_rejects_when_per_account_cap_reached() {
        use super::{AuthenticationFailure, MAX_SESSIONS_PER_ACCOUNT};

        let service =
            AuthService::from_profile(&profile()).expect("auth service should initialize");

        for _ in 0..MAX_SESSIONS_PER_ACCOUNT {
            let result = service
                .authenticate_login(
                    Uuid::new_v4(),
                    &LoginInfo {
                        user: "operator".to_owned(),
                        password: hash_password_sha3("password1234"),
                    },
                )
                .await;
            assert!(matches!(result, AuthenticationResult::Success(_)));
        }

        assert_eq!(service.session_count().await, MAX_SESSIONS_PER_ACCOUNT);

        let result = service
            .authenticate_login(
                Uuid::new_v4(),
                &LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("password1234"),
                },
            )
            .await;

        assert_eq!(
            result,
            AuthenticationResult::Failure(AuthenticationFailure::SessionCapExceeded)
        );
        assert_eq!(service.session_count().await, MAX_SESSIONS_PER_ACCOUNT);
    }

    #[tokio::test]
    async fn authenticate_login_rejects_when_global_cap_reached() {
        use super::{AuthenticationFailure, MAX_OPERATOR_SESSIONS, MAX_SESSIONS_PER_ACCOUNT};

        let accounts_needed = MAX_OPERATOR_SESSIONS.div_ceil(MAX_SESSIONS_PER_ACCOUNT);

        let mut hcl =
            String::from("Teamserver {\n  Host = \"127.0.0.1\"\n  Port = 40057\n}\nOperators {\n");
        for i in 0..accounts_needed {
            hcl.push_str(&format!(
                "  user \"op{i}\" {{\n    Password = \"pass{i}\"\n    Role = \"Operator\"\n  }}\n"
            ));
        }
        hcl.push_str("}\nDemon {}");

        let profile = Profile::parse(&hcl).expect("test profile should parse");
        let service = AuthService::from_profile(&profile).expect("auth service should initialize");

        let mut sessions_created = 0usize;
        'outer: for i in 0..accounts_needed {
            let username = format!("op{i}");
            let password = format!("pass{i}");
            for _ in 0..MAX_SESSIONS_PER_ACCOUNT {
                if sessions_created >= MAX_OPERATOR_SESSIONS {
                    break 'outer;
                }
                let result = service
                    .authenticate_login(
                        Uuid::new_v4(),
                        &LoginInfo {
                            user: username.clone(),
                            password: hash_password_sha3(&password),
                        },
                    )
                    .await;
                assert!(
                    matches!(result, AuthenticationResult::Success(_)),
                    "session {sessions_created} should succeed"
                );
                sessions_created += 1;
            }
        }

        assert_eq!(service.session_count().await, MAX_OPERATOR_SESSIONS);

        let result = service
            .authenticate_login(
                Uuid::new_v4(),
                &LoginInfo { user: "op0".to_owned(), password: hash_password_sha3("pass0") },
            )
            .await;

        assert_eq!(
            result,
            AuthenticationResult::Failure(AuthenticationFailure::SessionCapExceeded)
        );
        assert_eq!(service.session_count().await, MAX_OPERATOR_SESSIONS);
    }

    #[tokio::test]
    async fn authenticate_login_succeeds_after_session_removed() {
        use super::{AuthenticationFailure, MAX_SESSIONS_PER_ACCOUNT};

        let service =
            AuthService::from_profile(&profile()).expect("auth service should initialize");

        let mut connection_ids: Vec<Uuid> = Vec::new();

        for _ in 0..MAX_SESSIONS_PER_ACCOUNT {
            let conn = Uuid::new_v4();
            connection_ids.push(conn);
            let result = service
                .authenticate_login(
                    conn,
                    &LoginInfo {
                        user: "operator".to_owned(),
                        password: hash_password_sha3("password1234"),
                    },
                )
                .await;
            assert!(matches!(result, AuthenticationResult::Success(_)));
        }

        let over_cap = service
            .authenticate_login(
                Uuid::new_v4(),
                &LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("password1234"),
                },
            )
            .await;
        assert_eq!(
            over_cap,
            AuthenticationResult::Failure(AuthenticationFailure::SessionCapExceeded)
        );

        service.remove_connection(connection_ids[0]).await;
        assert_eq!(service.session_count().await, MAX_SESSIONS_PER_ACCOUNT - 1);

        let result = service
            .authenticate_login(
                Uuid::new_v4(),
                &LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("password1234"),
                },
            )
            .await;
        assert!(matches!(result, AuthenticationResult::Success(_)));
    }

    #[tokio::test]
    async fn from_profile_with_database_returns_error_on_malformed_password_verifier() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        database
            .operators()
            .create(&PersistedOperator {
                username: "corrupted".to_owned(),
                password_verifier: "not-a-valid-phc-string".to_owned(),
                role: red_cell_common::config::OperatorRole::Operator,
            })
            .await
            .expect("runtime operator should persist");

        let result = AuthService::from_profile_with_database(&profile(), &database).await;

        let error = result.expect_err(
            "from_profile_with_database should fail when a persisted operator has an invalid \
             password verifier",
        );
        assert!(
            matches!(
                error,
                AuthError::Persistence(crate::TeamserverError::InvalidPersistedValue {
                    field: "ts_runtime_operators.password_verifier",
                    ..
                })
            ),
            "expected Persistence(InvalidPersistedValue) with field \
             ts_runtime_operators.password_verifier, got {error:?}"
        );
    }

    #[tokio::test]
    async fn from_profile_with_database_does_not_override_profile_operators() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        database
            .operators()
            .create(&PersistedOperator {
                username: "operator".to_owned(),
                password_verifier: password_verifier_for_sha3(&hash_password_sha3("runtimepw"))
                    .expect("password verifier should be generated"),
                role: red_cell_common::config::OperatorRole::Analyst,
            })
            .await
            .expect("runtime operator should persist");

        let service = AuthService::from_profile_with_database(&profile(), &database)
            .await
            .expect("auth service should load without error");

        let connection_id = Uuid::new_v4();
        let result = service
            .authenticate_login(
                connection_id,
                &LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("password1234"),
                },
            )
            .await;
        assert!(
            matches!(result, AuthenticationResult::Success(_)),
            "profile operator credentials should take precedence over persisted runtime duplicate"
        );

        let session = service
            .session_for_connection(connection_id)
            .await
            .expect("session should exist after successful login");
        assert_eq!(
            session.role,
            red_cell_common::config::OperatorRole::Operator,
            "session role must reflect the profile-configured role, not the persisted runtime role"
        );

        let result = service
            .authenticate_login(
                Uuid::new_v4(),
                &LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("runtimepw"),
                },
            )
            .await;
        assert!(
            matches!(
                result,
                AuthenticationResult::Failure(AuthenticationFailure::InvalidCredentials)
            ),
            "persisted runtime credentials must not override profile-configured operator"
        );
    }

    #[tokio::test]
    async fn operator_inventory_returns_none_last_seen_with_empty_audit_log() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        let service = AuthService::from_profile_with_database(&profile(), &database)
            .await
            .expect("auth service should initialize");

        let inventory = service
            .operator_inventory()
            .await
            .expect("operator inventory should succeed when audit log is healthy");
        assert!(!inventory.is_empty(), "inventory should contain configured operators");
        for entry in &inventory {
            assert_eq!(
                entry.last_seen, None,
                "operator `{}` should have last_seen None when audit log is empty",
                entry.username
            );
        }
    }

    #[tokio::test]
    async fn operator_inventory_returns_audit_error_after_database_closed() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        let service = AuthService::from_profile_with_database(&profile(), &database)
            .await
            .expect("auth service should initialize");

        database.close().await;

        let result = service.operator_inventory().await;
        assert!(
            matches!(result, Err(AuthError::AuditLog(_))),
            "expected AuditLog error after database close, got {result:?}"
        );
    }

    #[tokio::test]
    async fn create_operator_rejects_duplicate_profile_configured_username() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        let service = AuthService::from_profile_with_database(&profile(), &database)
            .await
            .expect("auth service should initialize");

        let error = service
            .create_operator(
                "operator",
                "different_password",
                red_cell_common::config::OperatorRole::Admin,
            )
            .await
            .expect_err("duplicate profile-configured username should be rejected");

        assert_eq!(error, AuthError::DuplicateUser { username: "operator".to_owned() });
    }

    // ---- AuthService::delete_operator tests ----

    #[tokio::test]
    async fn delete_operator_removes_runtime_created_account() {
        let database = Database::connect_in_memory().await.expect("database");
        let auth =
            AuthService::from_profile_with_database(&profile(), &database).await.expect("auth");

        auth.create_operator("runtime_user", "pass1234", OperatorRole::Operator)
            .await
            .expect("create should succeed");

        auth.delete_operator("runtime_user").await.expect("delete should succeed");

        let inventory = auth
            .operator_inventory()
            .await
            .expect("operator inventory should succeed when audit log is healthy");
        assert!(
            !inventory.iter().any(|op| op.username == "runtime_user"),
            "deleted operator should not appear in inventory"
        );
    }

    #[tokio::test]
    async fn delete_operator_rejects_profile_configured_user() {
        let database = Database::connect_in_memory().await.expect("database");
        let auth =
            AuthService::from_profile_with_database(&profile(), &database).await.expect("auth");

        let result = auth.delete_operator("operator").await;
        assert!(
            matches!(result, Err(AuthError::ProfileOperator { .. })),
            "expected ProfileOperator error, got {result:?}"
        );
    }

    #[tokio::test]
    async fn delete_operator_returns_not_found_for_unknown_user() {
        let database = Database::connect_in_memory().await.expect("database");
        let auth =
            AuthService::from_profile_with_database(&profile(), &database).await.expect("auth");

        let result = auth.delete_operator("nonexistent").await;
        assert!(
            matches!(result, Err(AuthError::OperatorNotFound { .. })),
            "expected OperatorNotFound error, got {result:?}"
        );
    }

    #[tokio::test]
    async fn delete_operator_rejects_empty_username() {
        let database = Database::connect_in_memory().await.expect("database");
        let auth =
            AuthService::from_profile_with_database(&profile(), &database).await.expect("auth");

        let result = auth.delete_operator("").await;
        assert_eq!(result, Err(AuthError::EmptyUsername));
    }

    #[tokio::test]
    async fn delete_operator_revokes_active_sessions() {
        let database = Database::connect_in_memory().await.expect("database");
        let auth =
            AuthService::from_profile_with_database(&profile(), &database).await.expect("auth");

        auth.create_operator("victim", "pass1234", OperatorRole::Admin)
            .await
            .expect("create should succeed");

        let connection_id = Uuid::new_v4();
        let result = auth
            .authenticate_login(
                connection_id,
                &LoginInfo { user: "victim".to_owned(), password: hash_password_sha3("pass1234") },
            )
            .await;
        let AuthenticationResult::Success(success) = result else {
            panic!("expected successful authentication");
        };

        assert!(auth.session_for_token(&success.token).await.is_some());

        auth.delete_operator("victim").await.expect("delete should succeed");

        assert!(
            auth.session_for_token(&success.token).await.is_none(),
            "session should be revoked after operator deletion"
        );
        assert!(
            auth.session_for_connection(connection_id).await.is_none(),
            "connection should be revoked after operator deletion"
        );
    }

    #[tokio::test]
    async fn delete_operator_revokes_multiple_sessions() {
        let database = Database::connect_in_memory().await.expect("database");
        let auth =
            AuthService::from_profile_with_database(&profile(), &database).await.expect("auth");

        auth.create_operator("multi", "pass1234", OperatorRole::Operator)
            .await
            .expect("create should succeed");

        let mut tokens = Vec::new();
        for _ in 0..2 {
            let cid = Uuid::new_v4();
            let result = auth
                .authenticate_login(
                    cid,
                    &LoginInfo {
                        user: "multi".to_owned(),
                        password: hash_password_sha3("pass1234"),
                    },
                )
                .await;
            let AuthenticationResult::Success(success) = result else {
                panic!("expected successful authentication");
            };
            tokens.push(success.token);
        }

        let count_before = auth.session_count().await;

        auth.delete_operator("multi").await.expect("delete should succeed");

        for token in &tokens {
            assert!(
                auth.session_for_token(token).await.is_none(),
                "session {token} should be revoked"
            );
        }
        assert_eq!(auth.session_count().await, count_before - 2);
    }

    // ---- AuthService::update_operator_role tests ----

    #[tokio::test]
    async fn update_operator_role_changes_runtime_account() {
        let database = Database::connect_in_memory().await.expect("database");
        let auth =
            AuthService::from_profile_with_database(&profile(), &database).await.expect("auth");

        auth.create_operator("roleuser", "pass1234", OperatorRole::Analyst)
            .await
            .expect("create should succeed");

        auth.update_operator_role("roleuser", OperatorRole::Admin)
            .await
            .expect("update should succeed");

        let inventory = auth
            .operator_inventory()
            .await
            .expect("operator inventory should succeed when audit log is healthy");
        let op = inventory.iter().find(|op| op.username == "roleuser").expect("should exist");
        assert_eq!(op.role, OperatorRole::Admin);
    }

    #[tokio::test]
    async fn update_operator_role_rejects_profile_configured_user() {
        let database = Database::connect_in_memory().await.expect("database");
        let auth =
            AuthService::from_profile_with_database(&profile(), &database).await.expect("auth");

        let result = auth.update_operator_role("operator", OperatorRole::Analyst).await;
        assert!(
            matches!(result, Err(AuthError::ProfileOperator { .. })),
            "expected ProfileOperator error, got {result:?}"
        );
    }

    #[tokio::test]
    async fn update_operator_role_returns_not_found_for_unknown_user() {
        let database = Database::connect_in_memory().await.expect("database");
        let auth =
            AuthService::from_profile_with_database(&profile(), &database).await.expect("auth");

        let result = auth.update_operator_role("nonexistent", OperatorRole::Admin).await;
        assert!(
            matches!(result, Err(AuthError::OperatorNotFound { .. })),
            "expected OperatorNotFound error, got {result:?}"
        );
    }

    #[tokio::test]
    async fn update_operator_role_rejects_empty_username() {
        let database = Database::connect_in_memory().await.expect("database");
        let auth =
            AuthService::from_profile_with_database(&profile(), &database).await.expect("auth");

        let result = auth.update_operator_role("  ", OperatorRole::Admin).await;
        assert_eq!(result, Err(AuthError::EmptyUsername));
    }

    #[tokio::test]
    async fn update_operator_role_updates_active_session_role() {
        let database = Database::connect_in_memory().await.expect("database");
        let auth =
            AuthService::from_profile_with_database(&profile(), &database).await.expect("auth");

        auth.create_operator("rbac_user", "pass1234", OperatorRole::Admin)
            .await
            .expect("create should succeed");

        let connection_id = Uuid::new_v4();
        let result = auth
            .authenticate_login(
                connection_id,
                &LoginInfo {
                    user: "rbac_user".to_owned(),
                    password: hash_password_sha3("pass1234"),
                },
            )
            .await;
        let AuthenticationResult::Success(success) = result else {
            panic!("expected successful authentication");
        };

        let session = auth.session_for_token(&success.token).await.expect("session should exist");
        assert_eq!(session.role, OperatorRole::Admin);

        auth.update_operator_role("rbac_user", OperatorRole::Analyst)
            .await
            .expect("update should succeed");

        let session =
            auth.session_for_token(&success.token).await.expect("session should still exist");
        assert_eq!(
            session.role,
            OperatorRole::Analyst,
            "session role should be updated to Analyst after downgrade"
        );

        let session = auth
            .session_for_connection(connection_id)
            .await
            .expect("session should still exist by connection");
        assert_eq!(session.role, OperatorRole::Analyst);
    }

    #[tokio::test]
    async fn update_operator_role_updates_multiple_sessions() {
        let database = Database::connect_in_memory().await.expect("database");
        let auth =
            AuthService::from_profile_with_database(&profile(), &database).await.expect("auth");

        auth.create_operator("multi_role", "pass1234", OperatorRole::Admin)
            .await
            .expect("create should succeed");

        let mut tokens = Vec::new();
        for _ in 0..2 {
            let cid = Uuid::new_v4();
            let result = auth
                .authenticate_login(
                    cid,
                    &LoginInfo {
                        user: "multi_role".to_owned(),
                        password: hash_password_sha3("pass1234"),
                    },
                )
                .await;
            let AuthenticationResult::Success(success) = result else {
                panic!("expected successful authentication");
            };
            tokens.push(success.token);
        }

        auth.update_operator_role("multi_role", OperatorRole::Analyst)
            .await
            .expect("update should succeed");

        for token in &tokens {
            let session = auth.session_for_token(token).await.expect("session should exist");
            assert_eq!(
                session.role,
                OperatorRole::Analyst,
                "all sessions should reflect the updated role"
            );
        }
    }

    #[tokio::test]
    async fn update_operator_role_does_not_affect_other_operator_sessions() {
        let database = Database::connect_in_memory().await.expect("database");
        let auth =
            AuthService::from_profile_with_database(&profile(), &database).await.expect("auth");

        auth.create_operator("target", "pass1234", OperatorRole::Admin)
            .await
            .expect("create target");
        auth.create_operator("bystander", "pass1234", OperatorRole::Admin)
            .await
            .expect("create bystander");

        let _target_result = auth
            .authenticate_login(
                Uuid::new_v4(),
                &LoginInfo { user: "target".to_owned(), password: hash_password_sha3("pass1234") },
            )
            .await;
        let bystander_result = auth
            .authenticate_login(
                Uuid::new_v4(),
                &LoginInfo {
                    user: "bystander".to_owned(),
                    password: hash_password_sha3("pass1234"),
                },
            )
            .await;

        let AuthenticationResult::Success(bystander_success) = bystander_result else {
            panic!("expected bystander auth success");
        };

        auth.update_operator_role("target", OperatorRole::Analyst)
            .await
            .expect("update should succeed");

        let bystander_session = auth
            .session_for_token(&bystander_success.token)
            .await
            .expect("bystander session should exist");
        assert_eq!(
            bystander_session.role,
            OperatorRole::Admin,
            "bystander session role should be unaffected"
        );
    }

    // ── Session expiry / idle-timeout ─────────────────────────────────────────

    #[tokio::test]
    async fn auth_service_has_default_session_policy() {
        let service =
            AuthService::from_profile(&profile()).expect("auth service should initialize");
        let policy = service.session_policy();
        assert_eq!(
            policy.ttl,
            Some(std::time::Duration::from_secs(24 * 60 * 60)),
            "default session TTL should be 24h"
        );
        assert_eq!(
            policy.idle_timeout,
            Some(std::time::Duration::from_secs(30 * 60)),
            "default idle timeout should be 30 min"
        );
    }

    #[tokio::test]
    async fn from_profile_applies_operators_session_policy_from_hcl() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              SessionTtlHours = 48
              IdleTimeoutMinutes = 45
              user "operator" {
                Password = "password1234"
                Role = "Operator"
              }
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        let service = AuthService::from_profile(&profile).expect("auth service should initialize");
        let policy = service.session_policy();
        assert_eq!(policy.ttl, Some(std::time::Duration::from_secs(48 * 3600)));
        assert_eq!(policy.idle_timeout, Some(std::time::Duration::from_secs(45 * 60)));
    }

    #[tokio::test]
    async fn with_session_policy_overrides_default() {
        use super::SessionPolicy;
        let service = AuthService::from_profile(&profile())
            .expect("auth service should initialize")
            .with_session_policy(SessionPolicy {
                ttl: Some(std::time::Duration::from_secs(10)),
                idle_timeout: Some(std::time::Duration::from_secs(1)),
            });
        let policy = service.session_policy();
        assert_eq!(policy.ttl, Some(std::time::Duration::from_secs(10)));
        assert_eq!(policy.idle_timeout, Some(std::time::Duration::from_secs(1)));
    }

    #[tokio::test]
    async fn touch_session_activity_refreshes_last_activity_for_live_session() {
        use super::{SessionActivity, SessionPolicy};

        let service = AuthService::from_profile(&profile())
            .expect("auth service should initialize")
            .with_session_policy(SessionPolicy {
                ttl: Some(std::time::Duration::from_secs(3600)),
                idle_timeout: Some(std::time::Duration::from_secs(60)),
            });
        let connection_id = Uuid::new_v4();
        let result = service
            .authenticate_login(
                connection_id,
                &LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("password1234"),
                },
            )
            .await;
        assert!(matches!(result, AuthenticationResult::Success(_)));

        let before =
            service.session_for_connection(connection_id).await.expect("session should be present");
        let later = before.last_activity_at + std::time::Duration::from_secs(30);
        assert_eq!(
            service.touch_session_activity_at(connection_id, later).await,
            SessionActivity::Ok,
        );

        let after = service
            .session_for_connection(connection_id)
            .await
            .expect("session should still exist");
        assert_eq!(after.last_activity_at, later);
        assert_eq!(after.created_at, before.created_at);
    }

    #[tokio::test]
    async fn touch_session_activity_expires_session_past_ttl() {
        use super::{SessionActivity, SessionExpiryReason, SessionPolicy};

        let service = AuthService::from_profile(&profile())
            .expect("auth service should initialize")
            .with_session_policy(SessionPolicy {
                ttl: Some(std::time::Duration::from_secs(10)),
                idle_timeout: Some(std::time::Duration::from_secs(600)),
            });
        let connection_id = Uuid::new_v4();
        let login = service
            .authenticate_login(
                connection_id,
                &LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("password1234"),
                },
            )
            .await;
        let AuthenticationResult::Success(success) = login else {
            panic!("expected success");
        };

        let session =
            service.session_for_connection(connection_id).await.expect("session should be present");
        let past_ttl = session.created_at + std::time::Duration::from_secs(11);

        match service.touch_session_activity_at(connection_id, past_ttl).await {
            SessionActivity::Expired { reason, username } => {
                assert_eq!(reason, SessionExpiryReason::TtlExceeded);
                assert_eq!(username, "operator");
            }
            other => panic!("expected Expired, got {other:?}"),
        }

        assert!(
            service.session_for_token(&success.token).await.is_none(),
            "expired session must be removed from registry"
        );
        assert_eq!(service.session_count().await, 0);
    }

    #[tokio::test]
    async fn touch_session_activity_expires_session_past_idle_timeout() {
        use super::{SessionActivity, SessionExpiryReason, SessionPolicy};

        let service = AuthService::from_profile(&profile())
            .expect("auth service should initialize")
            .with_session_policy(SessionPolicy {
                ttl: Some(std::time::Duration::from_secs(3600)),
                idle_timeout: Some(std::time::Duration::from_secs(60)),
            });
        let connection_id = Uuid::new_v4();
        let login = service
            .authenticate_login(
                connection_id,
                &LoginInfo { user: "analyst".to_owned(), password: hash_password_sha3("readonly") },
            )
            .await;
        assert!(matches!(login, AuthenticationResult::Success(_)));

        let session =
            service.session_for_connection(connection_id).await.expect("session should be present");
        let past_idle = session.last_activity_at + std::time::Duration::from_secs(61);

        match service.touch_session_activity_at(connection_id, past_idle).await {
            SessionActivity::Expired { reason, username } => {
                assert_eq!(reason, SessionExpiryReason::IdleTimeout);
                assert_eq!(username, "analyst");
            }
            other => panic!("expected Expired, got {other:?}"),
        }
        assert_eq!(service.session_count().await, 0);
    }

    #[tokio::test]
    async fn touch_session_activity_preserves_session_when_policy_unbounded() {
        use super::{SessionActivity, SessionPolicy};

        let service = AuthService::from_profile(&profile())
            .expect("auth service should initialize")
            .with_session_policy(SessionPolicy::unbounded());
        let connection_id = Uuid::new_v4();
        let login = service
            .authenticate_login(
                connection_id,
                &LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("password1234"),
                },
            )
            .await;
        assert!(matches!(login, AuthenticationResult::Success(_)));

        let session =
            service.session_for_connection(connection_id).await.expect("session should be present");
        let far_future = session.created_at + std::time::Duration::from_secs(7 * 24 * 3600);

        assert_eq!(
            service.touch_session_activity_at(connection_id, far_future).await,
            SessionActivity::Ok,
        );
        assert_eq!(service.session_count().await, 1);
    }

    #[tokio::test]
    async fn touch_session_activity_after_expiry_returns_not_found() {
        use super::{SessionActivity, SessionPolicy};

        let service = AuthService::from_profile(&profile())
            .expect("auth service should initialize")
            .with_session_policy(SessionPolicy {
                ttl: Some(std::time::Duration::from_secs(10)),
                idle_timeout: None,
            });
        let connection_id = Uuid::new_v4();
        let login = service
            .authenticate_login(
                connection_id,
                &LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("password1234"),
                },
            )
            .await;
        assert!(matches!(login, AuthenticationResult::Success(_)));

        let session =
            service.session_for_connection(connection_id).await.expect("session should be present");
        let future = session.created_at + std::time::Duration::from_secs(20);

        assert!(matches!(
            service.touch_session_activity_at(connection_id, future).await,
            SessionActivity::Expired { .. },
        ));
        assert_eq!(
            service.touch_session_activity_at(connection_id, future).await,
            SessionActivity::NotFound,
            "second call after expiry must report NotFound",
        );
    }

    #[tokio::test]
    async fn touch_session_activity_refresh_extends_idle_window() {
        use super::{SessionActivity, SessionPolicy};

        let service = AuthService::from_profile(&profile())
            .expect("auth service should initialize")
            .with_session_policy(SessionPolicy {
                ttl: Some(std::time::Duration::from_secs(3600)),
                idle_timeout: Some(std::time::Duration::from_secs(60)),
            });
        let connection_id = Uuid::new_v4();
        let login = service
            .authenticate_login(
                connection_id,
                &LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("password1234"),
                },
            )
            .await;
        assert!(matches!(login, AuthenticationResult::Success(_)));

        let session =
            service.session_for_connection(connection_id).await.expect("session should be present");
        // 40 seconds after login — within idle window.
        let first_tick = session.last_activity_at + std::time::Duration::from_secs(40);
        assert_eq!(
            service.touch_session_activity_at(connection_id, first_tick).await,
            SessionActivity::Ok,
        );

        // 40 seconds after the previous tick (80 seconds since login) — would
        // have exceeded the 60s idle window, but the previous tick refreshed
        // last_activity_at so the session is still valid.
        let second_tick = first_tick + std::time::Duration::from_secs(40);
        assert_eq!(
            service.touch_session_activity_at(connection_id, second_tick).await,
            SessionActivity::Ok,
        );
    }
}
