//! Operator authentication and session tracking.

use std::collections::BTreeMap;
use std::sync::Arc;

use argon2::password_hash::phc::PasswordHash;
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use red_cell_common::OperatorInfo;
use red_cell_common::config::{OperatorRole, Profile};
use red_cell_common::crypto::hash_password_sha3;
use red_cell_common::operator::{
    EventCode, LoginInfo, Message, MessageHead, MessageInfo, OperatorMessage,
};
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

/// Failed login result mapped onto Havoc-compatible error responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticationFailure {
    /// Submitted credentials did not authenticate an operator account.
    InvalidCredentials,
}

impl AuthenticationFailure {
    /// Build the Havoc-compatible error message returned to the client.
    #[must_use]
    pub fn message(&self) -> &'static str {
        "Authentication failed"
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
            dummy_password_verifier: password_verifier_for_sha3(DUMMY_PASSWORD_HASH)?,
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
            dummy_password_verifier: password_verifier_for_sha3(DUMMY_PASSWORD_HASH)?,
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

        self.sessions.write().await.insert(session);

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

    fn get_by_token(&self, token: &str) -> Option<&OperatorSession> {
        self.by_token.get(token)
    }

    fn len(&self) -> usize {
        self.by_token.len()
    }

    fn list(&self) -> Vec<OperatorSession> {
        self.by_token.values().cloned().collect()
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

fn password_hashes_match(submitted: &str, expected: &str) -> bool {
    let submitted = submitted.to_ascii_lowercase();
    let Ok(parsed_hash) = PasswordHash::new(expected) else {
        return false;
    };

    Argon2::default().verify_password(submitted.as_bytes(), &parsed_hash).is_ok()
}

pub(crate) fn password_verifier_for_sha3(password_hash: &str) -> Result<String, AuthError> {
    #[cfg(test)]
    return password_verifier_for_sha3_cached(password_hash);
    #[cfg(not(test))]
    return password_verifier_for_sha3_impl(password_hash);
}

fn password_verifier_for_sha3_impl(password_hash: &str) -> Result<String, AuthError> {
    Argon2::default()
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
        let guard = cache.lock().unwrap();
        if let Some(cached) = guard.get(&key) {
            return Ok(cached.clone());
        }
    }

    let verifier = password_verifier_for_sha3_impl(password_hash)?;
    cache.lock().unwrap().entry(key).or_insert_with(|| verifier.clone());
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

const DUMMY_PASSWORD_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

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
    use red_cell_common::config::Profile;
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

    #[test]
    fn hash_password_matches_havoc_sha3_256() {
        assert_eq!(
            hash_password_sha3("password1234"),
            "2f7d3e77d0786c5d305c0afadd4c1a2a6869a3210956c963ad2420c52e797022"
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
    async fn create_operator_rejects_empty_username() {
        let service =
            AuthService::from_profile(&profile()).expect("auth service should initialize");

        let error = service
            .create_operator("   ", "zion", red_cell_common::config::OperatorRole::Operator)
            .await
            .expect_err("blank usernames should be rejected");

        assert_eq!(error, AuthError::EmptyUsername);
    }

    #[tokio::test]
    async fn create_operator_rejects_empty_password() {
        let service =
            AuthService::from_profile(&profile()).expect("auth service should initialize");

        let error = service
            .create_operator("trinity", "   ", red_cell_common::config::OperatorRole::Operator)
            .await
            .expect_err("blank passwords should be rejected");

        assert_eq!(error, AuthError::EmptyPassword);
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
    fn login_failure_message_uses_generic_authentication_error_text() {
        let message = login_failure_message("ghost", &AuthenticationFailure::InvalidCredentials);
        let value = serde_json::to_value(&message).expect("message should serialize");

        assert_eq!(value["Body"]["SubEvent"], json!(InitConnectionCode::Error.as_u32()));
        assert_eq!(value["Body"]["Info"]["Message"], json!("Authentication failed"));
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
}
