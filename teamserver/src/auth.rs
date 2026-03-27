//! Operator authentication and session tracking.

use std::collections::BTreeMap;
use std::sync::Arc;

use argon2::password_hash::phc::PasswordHash;
use argon2::{Algorithm, Argon2, ParamsBuilder, PasswordHasher, PasswordVerifier, Version};
use red_cell_common::OperatorInfo;
use red_cell_common::config::{OperatorRole, Profile};
use red_cell_common::crypto::hash_password_sha3;
use red_cell_common::operator::{
    EventCode, LoginInfo, Message, MessageHead, MessageInfo, OperatorMessage,
};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::instrument;
use uuid::Uuid;

use crate::{Database, OperatorRepository, PersistedOperator, TeamserverError};

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

/// Operator account inventory entry with current presence metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorPresence {
    /// Operator username.
    pub username: String,
    /// RBAC role assigned to the operator account.
    pub role: OperatorRole,
    /// Whether the operator currently has an authenticated session.
    pub online: bool,
    /// Most recent persisted operator activity timestamp.
    pub last_seen: Option<String>,
}

impl OperatorPresence {
    /// Convert the operator-presence entry into the shared wire/domain representation.
    #[must_use]
    pub fn as_operator_info(&self) -> OperatorInfo {
        OperatorInfo {
            username: self.username.clone(),
            password_hash: None,
            role: Some(operator_role_name(self.role).to_owned()),
            online: self.online,
            last_seen: self.last_seen.clone(),
        }
    }
}

/// In-memory operator credential store and active session registry.
#[derive(Debug, Clone)]
pub struct AuthService {
    credentials: Arc<RwLock<BTreeMap<String, OperatorAccount>>>,
    dummy_password_verifier: String,
    sessions: Arc<RwLock<SessionRegistry>>,
    runtime_operators: Option<OperatorRepository>,
    audit_log: Option<crate::AuditLogRepository>,
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
        };

        service.load_runtime_operators().await?;
        Ok(service)
    }

    /// Authenticate a parsed login payload and create a session on success.
    #[instrument(skip(self, login), fields(connection_id = %connection_id, username = %login.user))]
    pub async fn authenticate_login(
        &self,
        connection_id: Uuid,
        login: &LoginInfo,
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
        let session = OperatorSession {
            token: token.clone(),
            username: login.user.clone(),
            role: account.role,
            connection_id,
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

        // Only runtime operators (those persisted in the database) can be deleted.
        let Some(runtime_operators) = &self.runtime_operators else {
            return Err(AuthError::ProfileOperator { username: username.to_owned() });
        };

        let deleted = runtime_operators.delete(username).await?;
        if !deleted {
            // The operator exists in credentials but not in the runtime database,
            // meaning it was loaded from the profile configuration.
            return Err(AuthError::ProfileOperator { username: username.to_owned() });
        }

        credentials.remove(username);

        // Revoke all active sessions so the deleted operator cannot continue using
        // previously issued tokens.
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

        // Update the role on all active sessions so subsequent authorization checks
        // observe the new role immediately rather than using the stale login-time copy.
        self.sessions.write().await.update_role_by_username(username, role);

        Ok(())
    }

    /// Return all currently authenticated operator sessions.
    pub async fn active_sessions(&self) -> Vec<OperatorSession> {
        self.sessions.read().await.list()
    }

    /// Return all configured and runtime-created operators with current presence state.
    pub async fn operator_inventory(&self) -> Vec<OperatorPresence> {
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
                .unwrap_or_default(),
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

        operators.into_values().collect()
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct OperatorAccount {
    password_verifier: String,
    role: OperatorRole,
}

#[derive(Debug, Default)]
struct SessionRegistry {
    by_token: BTreeMap<String, OperatorSession>,
    token_by_connection: BTreeMap<Uuid, String>,
}

impl SessionRegistry {
    fn insert(&mut self, session: OperatorSession) {
        if let Some(previous_token) =
            self.token_by_connection.insert(session.connection_id, session.token.clone())
        {
            self.by_token.remove(&previous_token);
        }

        self.by_token.insert(session.token.clone(), session);
    }

    fn remove_by_connection(&mut self, connection_id: Uuid) -> Option<OperatorSession> {
        let token = self.token_by_connection.remove(&connection_id)?;
        self.by_token.remove(&token)
    }

    fn get_by_connection(&self, connection_id: Uuid) -> Option<&OperatorSession> {
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
    fn get_by_token(&self, token: &str) -> Option<&OperatorSession> {
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

    fn len(&self) -> usize {
        self.by_token.len()
    }

    /// Count the number of active sessions belonging to `username`.
    fn sessions_for_account(&self, username: &str) -> usize {
        self.by_token.values().filter(|s| s.username == username).count()
    }

    fn list(&self) -> Vec<OperatorSession> {
        self.by_token.values().cloned().collect()
    }

    /// Remove all sessions belonging to `username`, returning the removed sessions.
    fn remove_by_username(&mut self, username: &str) -> Vec<OperatorSession> {
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
    fn update_role_by_username(&mut self, username: &str, role: OperatorRole) {
        for session in self.by_token.values_mut() {
            if session.username == username {
                session.role = role;
            }
        }
    }
}

/// Build a success response for an authenticated login handshake.
#[must_use]
pub fn login_success_message(user: &str, token: &str) -> OperatorMessage {
    OperatorMessage::InitConnectionSuccess(Message {
        head: login_response_head(user),
        info: MessageInfo { message: format!("Successful Authenticated; SessionToken={token}") },
    })
}

/// Build an error response for a rejected login handshake.
#[must_use]
pub fn login_failure_message(user: &str, failure: &AuthenticationFailure) -> OperatorMessage {
    OperatorMessage::InitConnectionError(Message {
        head: login_response_head(user),
        info: MessageInfo { message: failure.message().to_owned() },
    })
}

fn login_response_head(user: &str) -> MessageHead {
    MessageHead {
        event: EventCode::InitConnection,
        user: user.to_owned(),
        timestamp: String::new(),
        one_time: String::new(),
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

/// Construct an [`Argon2`] instance with OWASP-recommended parameters.
///
/// Uses Argon2id with m_cost=65536 (64 MiB), t_cost=3, p_cost=4 — the
/// recommended configuration from the OWASP Password Storage Cheat Sheet.
///
/// In test builds, minimal Argon2 parameters are used instead to keep tests
/// fast. The production-strength parameters are only needed for brute-force
/// resistance; the hashing/verification code paths exercised in tests are
/// identical regardless of cost parameters.
fn argon2_hasher() -> Result<Argon2<'static>, AuthError> {
    #[cfg(not(test))]
    let params = ParamsBuilder::new()
        .m_cost(65536)
        .t_cost(3)
        .p_cost(4)
        .build()
        .map_err(|e| AuthError::PasswordVerifier(format!("Argon2 parameter error: {e}")))?;
    #[cfg(test)]
    let params = ParamsBuilder::new()
        .m_cost(256)
        .t_cost(1)
        .p_cost(1)
        .build()
        .map_err(|e| AuthError::PasswordVerifier(format!("Argon2 parameter error: {e}")))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

pub(crate) fn password_hashes_match(submitted: &str, expected: &str) -> bool {
    #[cfg(test)]
    return password_hashes_match_cached(submitted, expected);
    #[cfg(not(test))]
    return password_hashes_match_impl(submitted, expected);
}

fn password_hashes_match_impl(submitted: &str, expected: &str) -> bool {
    let submitted = submitted.to_ascii_lowercase();
    let Ok(parsed_hash) = PasswordHash::new(expected) else {
        return false;
    };
    let Ok(hasher) = argon2_hasher() else {
        return false;
    };

    hasher.verify_password(submitted.as_bytes(), &parsed_hash).is_ok()
}

/// Test-only cached wrapper around [`password_hashes_match_impl`].
///
/// Argon2 verification is intentionally slow (~1-2 s per call with production
/// parameters). Tests that create many sessions (e.g. the global session cap
/// test with 64+ verifications) become pathologically slow without caching.
/// The cache key is `(submitted_lowercase, expected_verifier)` and values are
/// append-only, so mutex poisoning is safe to recover from.
#[cfg(test)]
fn password_hashes_match_cached(submitted: &str, expected: &str) -> bool {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    static CACHE: OnceLock<Mutex<HashMap<(String, String), bool>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    let key = (submitted.to_ascii_lowercase(), expected.to_owned());
    {
        let guard = cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(&cached) = guard.get(&key) {
            return cached;
        }
    }

    let result = password_hashes_match_impl(submitted, expected);
    cache.lock().unwrap_or_else(|e| e.into_inner()).insert(key, result);
    result
}

pub(crate) fn password_verifier_for_sha3(password_hash: &str) -> Result<String, AuthError> {
    #[cfg(test)]
    return password_verifier_for_sha3_cached(password_hash);
    #[cfg(not(test))]
    return password_verifier_for_sha3_impl(password_hash);
}

fn password_verifier_for_sha3_impl(password_hash: &str) -> Result<String, AuthError> {
    argon2_hasher()?
        .hash_password(password_hash.to_ascii_lowercase().as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|error| AuthError::PasswordVerifier(error.to_string()))
}

/// Test-only cached wrapper around `password_verifier_for_sha3_impl`.
///
/// Argon2 hashing is intentionally slow (memory-hard), which makes full test
/// suite runs infeasible when every `AuthService::from_profile` call hashes
/// N profile operators + 1 dummy verifier. This cache computes each Argon2
/// verifier at most once per unique SHA3 input across the entire test process,
/// keeping individual test setup instantaneous after the first warm-up.
///
/// The production path via `password_verifier_for_sha3_impl` is unaffected.
#[cfg(test)]
fn password_verifier_for_sha3_cached(password_hash: &str) -> Result<String, AuthError> {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    static CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    let key = password_hash.to_ascii_lowercase();
    {
        // Safety: poison recovery is acceptable here because the cache is append-only
        // (values are never modified after insertion). A poisoned state means a prior
        // thread panicked while inserting, leaving the HashMap in a valid-but-incomplete
        // state — missing one entry at worst, never corrupted.
        let guard = cache.lock().unwrap_or_else(|e| {
            tracing::warn!(
                "password verifier cache mutex poisoned — recovering (append-only cache)"
            );
            e.into_inner()
        });
        if let Some(cached) = guard.get(&key) {
            return Ok(cached.clone());
        }
    }

    let verifier = password_verifier_for_sha3_impl(password_hash)?;
    cache
        .lock()
        .unwrap_or_else(|e| {
            tracing::warn!(
                "password verifier cache mutex poisoned — recovering (append-only cache)"
            );
            e.into_inner()
        })
        .entry(key)
        .or_insert_with(|| verifier.clone());
    Ok(verifier)
}

async fn normalize_persisted_verifier(
    runtime_operators: &OperatorRepository,
    operator: &PersistedOperator,
) -> Result<String, AuthError> {
    if is_legacy_sha3_digest(&operator.password_verifier) {
        let password_verifier = password_verifier_for_sha3(&operator.password_verifier)?;
        runtime_operators.update_password_verifier(&operator.username, &password_verifier).await?;
        return Ok(password_verifier);
    }

    PasswordHash::new(&operator.password_verifier).map_err(|error| {
        AuthError::Persistence(TeamserverError::InvalidPersistedValue {
            field: "ts_runtime_operators.password_verifier",
            message: format!("invalid password verifier: {error}"),
        })
    })?;
    Ok(operator.password_verifier.clone())
}

fn is_legacy_sha3_digest(value: &str) -> bool {
    value.len() == 64 && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

/// Generate a one-time Argon2id PHC hash from random bytes for timing equalization.
///
/// When a login attempt uses an unknown username the service verifies the submitted
/// credential against this dummy hash instead of returning immediately.  The hash
/// must be a syntactically valid Argon2 PHC string so that [`password_hashes_match`]
/// runs the full Argon2 computation rather than failing on a parse error in
/// microseconds — which would otherwise expose user-enumeration via timing.
///
/// The password material is 16 bytes from the OS CSPRNG (via [`Uuid::new_v4`]), so
/// the resulting hash is unpredictable and cannot be precomputed by an attacker.
fn generate_dummy_verifier() -> Result<String, AuthError> {
    #[cfg(test)]
    return generate_dummy_verifier_cached();
    #[cfg(not(test))]
    return generate_dummy_verifier_impl();
}

fn generate_dummy_verifier_impl() -> Result<String, AuthError> {
    let random_bytes = Uuid::new_v4();
    argon2_hasher()?
        .hash_password(random_bytes.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| AuthError::PasswordVerifier(e.to_string()))
}

/// Test-only cached wrapper around [`generate_dummy_verifier_impl`].
///
/// The dummy hash must be a valid Argon2 PHC string, but its exact value is
/// irrelevant for correctness tests — reusing one across the test process avoids
/// paying the Argon2 memory-hard cost on every [`AuthService`] construction.
#[cfg(test)]
fn generate_dummy_verifier_cached() -> Result<String, AuthError> {
    use std::sync::OnceLock;
    static DUMMY: OnceLock<Result<String, String>> = OnceLock::new();
    DUMMY
        .get_or_init(|| generate_dummy_verifier_impl().map_err(|e| e.to_string()))
        .as_ref()
        .cloned()
        .map_err(|e| AuthError::PasswordVerifier(e.clone()))
}

const fn operator_role_name(role: OperatorRole) -> &'static str {
    match role {
        OperatorRole::Admin => "Admin",
        OperatorRole::Operator => "Operator",
        OperatorRole::Analyst => "Analyst",
    }
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
        AuthError, AuthService, AuthenticationFailure, AuthenticationResult,
        generate_dummy_verifier, login_failure_message, login_success_message,
        password_hashes_match, password_verifier_for_sha3,
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

    #[test]
    fn hash_password_matches_havoc_sha3_256() {
        assert_eq!(
            hash_password_sha3("password1234"),
            "2f7d3e77d0786c5d305c0afadd4c1a2a6869a3210956c963ad2420c52e797022"
        );
    }

    /// `argon2_hasher` must return `Ok` with the configured test parameters and must
    /// never panic — parameter construction failures are mapped to `AuthError`.
    #[test]
    fn argon2_hasher_returns_ok_and_maps_errors_to_auth_error() {
        use super::argon2_hasher;

        let hasher = argon2_hasher();
        assert!(hasher.is_ok(), "argon2_hasher() should succeed with valid parameters");

        // Verify the error variant used for parameter failures is PasswordVerifier.
        let err = AuthError::PasswordVerifier("Argon2 parameter error: test".to_owned());
        assert!(
            matches!(err, AuthError::PasswordVerifier(ref msg) if msg.contains("Argon2 parameter")),
            "Argon2 parameter errors should map to AuthError::PasswordVerifier"
        );
    }

    /// Regression test: the dummy verifier used for unknown-username timing equalization must be
    /// a syntactically valid Argon2 PHC string so that `password_hashes_match` always runs the
    /// full Argon2 computation rather than returning `false` immediately on a PHC parse error.
    #[test]
    fn dummy_verifier_is_valid_argon2_phc_string() {
        use argon2::password_hash::phc::PasswordHash;

        let verifier = generate_dummy_verifier().expect("dummy verifier should be generated");
        PasswordHash::new(&verifier).expect("dummy verifier must be a valid Argon2 PHC string");
        assert!(
            verifier.starts_with("$argon2"),
            "dummy verifier must use the argon2 algorithm family"
        );
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

        // First authentication on the connection.
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

        // Second authentication on the same connection (re-auth / protocol reconnect).
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

        // Session count must remain 1 — the old entry must have been evicted.
        assert_eq!(service.session_count().await, 1);

        // The old token must no longer be in the registry.
        assert!(
            service.session_for_token(&first_success.token).await.is_none(),
            "stale token must not be retrievable after re-authentication"
        );

        // The new token must be retrievable and bound to the same connection.
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

        let inventory = service.operator_inventory().await;
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

        let inventory = service.operator_inventory().await;
        let operator = inventory
            .into_iter()
            .find(|entry| entry.username == "operator")
            .expect("operator entry should exist");

        assert_eq!(operator.last_seen.as_deref(), Some("2026-03-11T08:00:00Z"));
    }

    #[test]
    fn operator_presence_as_operator_info_preserves_wire_fields() {
        let presence = super::OperatorPresence {
            username: "operator".to_owned(),
            role: OperatorRole::Admin,
            online: true,
            last_seen: Some("2026-03-11T08:00:00Z".to_owned()),
        };

        let info = presence.as_operator_info();

        assert_eq!(info.username, "operator");
        assert_eq!(info.password_hash, None);
        assert_eq!(info.role.as_deref(), Some("Admin"));
        assert!(info.online);
        assert_eq!(info.last_seen.as_deref(), Some("2026-03-11T08:00:00Z"));
    }

    #[test]
    fn operator_presence_as_operator_info_keeps_unusual_username_without_password_material() {
        let presence = super::OperatorPresence {
            username: "MiXeD-Case_99@example.local".to_owned(),
            role: OperatorRole::Operator,
            online: true,
            last_seen: Some("2026-03-12T09:30:00Z".to_owned()),
        };

        let info = presence.as_operator_info();
        let payload = serde_json::to_value(&info).expect("operator info should serialize");

        assert_eq!(info.username, "MiXeD-Case_99@example.local");
        assert_eq!(info.role.as_deref(), Some("Operator"));
        assert_eq!(info.last_seen.as_deref(), Some("2026-03-12T09:30:00Z"));
        assert_eq!(payload["Username"], json!("MiXeD-Case_99@example.local"));
        assert_eq!(payload["Role"], json!("Operator"));
        assert_eq!(payload["Online"], json!(true));
        assert_eq!(payload["LastSeen"], json!("2026-03-12T09:30:00Z"));
        assert!(payload.get("PasswordHash").is_none());
    }

    #[test]
    fn operator_presence_as_operator_info_supports_offline_operator_without_last_seen() {
        let presence = super::OperatorPresence {
            username: "analyst".to_owned(),
            role: OperatorRole::Analyst,
            online: false,
            last_seen: None,
        };

        let info = presence.as_operator_info();
        let payload = serde_json::to_value(&info).expect("operator info should serialize");

        assert_eq!(info.username, "analyst");
        assert_eq!(info.role.as_deref(), Some("Analyst"));
        assert!(!info.online);
        assert_eq!(info.last_seen, None);
        assert_eq!(payload["Username"], json!("analyst"));
        assert_eq!(payload["Role"], json!("Analyst"));
        assert_eq!(payload["Online"], json!(false));
        assert!(payload.get("LastSeen").is_none());
        assert!(payload.get("PasswordHash").is_none());
    }

    #[test]
    fn login_success_message_uses_init_connection_success_wire_shape() {
        let message = login_success_message("operator", "token-123");
        let value = serde_json::to_value(&message).expect("message should serialize");

        assert_eq!(value["Head"]["Event"], json!(EventCode::InitConnection.as_u32()));
        assert_eq!(value["Body"]["SubEvent"], json!(InitConnectionCode::Success.as_u32()));
        assert_eq!(
            value["Body"]["Info"]["Message"],
            json!("Successful Authenticated; SessionToken=token-123")
        );
    }

    #[test]
    fn authentication_failure_invalid_credentials_message_returns_expected_string() {
        assert_eq!(AuthenticationFailure::InvalidCredentials.message(), "Authentication failed");
    }

    #[test]
    fn login_failure_message_embeds_variant_message_unchanged() {
        let variants =
            [AuthenticationFailure::InvalidCredentials, AuthenticationFailure::SessionCapExceeded];
        for variant in &variants {
            let msg = login_failure_message("user", variant);
            let value = serde_json::to_value(&msg).expect("message should serialize");
            assert_eq!(
                value["Body"]["Info"]["Message"],
                json!(variant.message()),
                "login_failure_message must embed {variant:?}.message() unchanged"
            );
        }
    }

    #[test]
    fn login_failure_message_uses_generic_authentication_error_text() {
        let message = login_failure_message("ghost", &AuthenticationFailure::InvalidCredentials);
        let value = serde_json::to_value(&message).expect("message should serialize");

        assert_eq!(value["Body"]["SubEvent"], json!(InitConnectionCode::Error.as_u32()));
        assert_eq!(value["Body"]["Info"]["Message"], json!("Authentication failed"));
    }

    #[test]
    fn authentication_failure_session_cap_exceeded_message_returns_expected_string() {
        assert_eq!(
            AuthenticationFailure::SessionCapExceeded.message(),
            "Too many active sessions; try again later"
        );
    }

    #[test]
    fn login_failure_message_session_cap_exceeded_uses_init_connection_error_wire_shape() {
        let message =
            login_failure_message("overloaded", &AuthenticationFailure::SessionCapExceeded);
        let value = serde_json::to_value(&message).expect("message should serialize");

        assert_eq!(value["Body"]["SubEvent"], json!(InitConnectionCode::Error.as_u32()));
        assert_eq!(
            value["Body"]["Info"]["Message"],
            json!("Too many active sessions; try again later")
        );
    }

    #[test]
    fn all_authentication_failure_variants_have_non_empty_messages() {
        let variants =
            [AuthenticationFailure::InvalidCredentials, AuthenticationFailure::SessionCapExceeded];
        for variant in &variants {
            assert!(
                !variant.message().is_empty(),
                "AuthenticationFailure::{variant:?} must have a non-empty message"
            );
        }
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

        // A token that is the right length but wrong value must not match.
        let fake_token = "00000000-0000-0000-0000-000000000000";
        assert!(service.session_for_token(fake_token).await.is_none());
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
        assert!(matches!(result, AuthenticationResult::Success(_)));

        // Tokens shorter or longer than a UUID must not match any session.
        assert!(service.session_for_token("short").await.is_none());
        assert!(
            service
                .session_for_token("this-is-a-much-longer-string-that-is-not-a-uuid-token")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn session_for_token_returns_matching_session_across_multiple_sessions() {
        let service =
            AuthService::from_profile(&profile()).expect("auth service should initialize");

        let conn_a = Uuid::new_v4();
        let conn_b = Uuid::new_v4();

        let result_a = service
            .authenticate_login(
                conn_a,
                &LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("password1234"),
                },
            )
            .await;
        let AuthenticationResult::Success(success_a) = result_a else {
            panic!("expected successful authentication for operator");
        };

        let result_b = service
            .authenticate_login(
                conn_b,
                &LoginInfo { user: "admin".to_owned(), password: hash_password_sha3("adminpw") },
            )
            .await;
        let AuthenticationResult::Success(success_b) = result_b else {
            panic!("expected successful authentication for admin");
        };

        let session_a = service
            .session_for_token(&success_a.token)
            .await
            .expect("operator session should be found");
        assert_eq!(session_a.username, "operator");
        assert_eq!(session_a.connection_id, conn_a);

        let session_b = service
            .session_for_token(&success_b.token)
            .await
            .expect("admin session should be found");
        assert_eq!(session_b.username, "admin");
        assert_eq!(session_b.connection_id, conn_b);
    }

    #[tokio::test]
    async fn authenticate_login_rejects_when_per_account_cap_reached() {
        use super::{AuthenticationFailure, MAX_SESSIONS_PER_ACCOUNT};

        let service =
            AuthService::from_profile(&profile()).expect("auth service should initialize");

        // Fill the per-account cap for "operator".
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

        // The next login for the same account must be rejected.
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
        // Session count must not have grown.
        assert_eq!(service.session_count().await, MAX_SESSIONS_PER_ACCOUNT);
    }

    #[tokio::test]
    async fn authenticate_login_rejects_when_global_cap_reached() {
        use super::{AuthenticationFailure, MAX_OPERATOR_SESSIONS, MAX_SESSIONS_PER_ACCOUNT};

        // Build a profile with enough distinct accounts to reach the global cap without
        // hitting the per-account cap.  We need ceil(MAX_OPERATOR_SESSIONS /
        // MAX_SESSIONS_PER_ACCOUNT) accounts.
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

        // Authenticate sessions until the global cap is exactly hit.
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

        // Any further login (any account) must be rejected.
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

        // Fill the per-account cap.
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

        // Verify cap is enforced.
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

        // Remove one session.
        service.remove_connection(connection_ids[0]).await;
        assert_eq!(service.session_count().await, MAX_SESSIONS_PER_ACCOUNT - 1);

        // A new login should now succeed.
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
        // Persist a runtime operator whose username collides with a profile operator.
        // Use a different password AND role so we can assert both are rejected.
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

        // The profile password ("password1234") should still work — profile takes precedence.
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

        // The session role must be the profile-defined role (Operator), not the
        // persisted runtime role (Analyst).
        let session = service
            .session_for_connection(connection_id)
            .await
            .expect("session should exist after successful login");
        assert_eq!(
            session.role,
            red_cell_common::config::OperatorRole::Operator,
            "session role must reflect the profile-configured role, not the persisted runtime role"
        );

        // The persisted password should NOT authenticate.
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

    // ------------------------------------------------------------------
    // is_legacy_sha3_digest boundary tests
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn operator_inventory_returns_none_last_seen_with_empty_audit_log() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        let service = AuthService::from_profile_with_database(&profile(), &database)
            .await
            .expect("auth service should initialize");

        // No audit rows inserted — every operator should have last_seen: None.
        let inventory = service.operator_inventory().await;
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
    async fn operator_inventory_returns_results_after_database_closed() {
        let database = Database::connect_in_memory().await.expect("database should initialize");
        let service = AuthService::from_profile_with_database(&profile(), &database)
            .await
            .expect("auth service should initialize");

        // Close the database — the audit log query should fail gracefully.
        database.close().await;

        let inventory = service.operator_inventory().await;
        assert!(
            !inventory.is_empty(),
            "inventory should still return configured operators after database close"
        );
        for entry in &inventory {
            assert_eq!(
                entry.last_seen, None,
                "operator `{}` should have last_seen None when audit log query fails",
                entry.username
            );
        }
    }

    #[tokio::test]
    async fn create_operator_rejects_duplicate_profile_configured_username() {
        let service =
            AuthService::from_profile(&profile()).expect("auth service should initialize");

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

    #[test]
    fn is_legacy_sha3_digest_accepts_valid_64_char_hex() {
        assert!(super::is_legacy_sha3_digest(
            "2f7d3e77d0786c5d305c0afadd4c1a2a6869a3210956c963ad2420c52e797022"
        ));
    }

    #[test]
    fn is_legacy_sha3_digest_rejects_63_char_hex() {
        // One char too short.
        assert!(!super::is_legacy_sha3_digest(
            "2f7d3e77d0786c5d305c0afadd4c1a2a6869a3210956c963ad2420c52e79702"
        ));
    }

    #[test]
    fn is_legacy_sha3_digest_rejects_65_char_hex() {
        // One char too long.
        assert!(!super::is_legacy_sha3_digest(
            "2f7d3e77d0786c5d305c0afadd4c1a2a6869a3210956c963ad2420c52e7970220"
        ));
    }

    #[test]
    fn is_legacy_sha3_digest_rejects_non_hex_char_at_position_32() {
        // 'g' at position 32 is not a hex digit.
        let mut s = "2f7d3e77d0786c5d305c0afadd4c1a2a".to_owned();
        s.push('g');
        s.push_str("869a3210956c963ad2420c52e797022");
        assert_eq!(s.len(), 64);
        assert!(!super::is_legacy_sha3_digest(&s));
    }

    #[test]
    fn is_legacy_sha3_digest_rejects_argon2_phc_string() {
        assert!(!super::is_legacy_sha3_digest("$argon2id$v=19$m=19456,t=2,p=1$salt$hash"));
    }

    #[test]
    fn is_legacy_sha3_digest_rejects_empty_string() {
        assert!(!super::is_legacy_sha3_digest(""));
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

        let inventory = auth.operator_inventory().await;
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

        // Authenticate to obtain a session token.
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

        // Session exists before deletion.
        assert!(auth.session_for_token(&success.token).await.is_some());

        // Delete the operator.
        auth.delete_operator("victim").await.expect("delete should succeed");

        // Session must be revoked.
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

        // Create two sessions for the same operator.
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

        // Both sessions must be gone.
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

        let inventory = auth.operator_inventory().await;
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

        // Login to get a session with Admin role.
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

        // Verify initial role is Admin.
        let session = auth.session_for_token(&success.token).await.expect("session should exist");
        assert_eq!(session.role, OperatorRole::Admin);

        // Downgrade to Analyst.
        auth.update_operator_role("rbac_user", OperatorRole::Analyst)
            .await
            .expect("update should succeed");

        // Session must now reflect the new role.
        let session =
            auth.session_for_token(&success.token).await.expect("session should still exist");
        assert_eq!(
            session.role,
            OperatorRole::Analyst,
            "session role should be updated to Analyst after downgrade"
        );

        // Also verify via connection lookup.
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

        // Create two sessions.
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

        // Downgrade to Analyst.
        auth.update_operator_role("multi_role", OperatorRole::Analyst)
            .await
            .expect("update should succeed");

        // Both sessions must reflect the new role.
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

        // Login both.
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

        // Downgrade target only.
        auth.update_operator_role("target", OperatorRole::Analyst)
            .await
            .expect("update should succeed");

        // Bystander should still be Admin.
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
}
