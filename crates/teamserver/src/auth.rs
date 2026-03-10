//! Operator authentication and session tracking.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;

use red_cell_common::config::{OperatorRole, Profile};
use red_cell_common::operator::{
    EventCode, LoginInfo, Message, MessageHead, MessageInfo, OperatorMessage,
};
use sha3::{Digest, Sha3_256};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::instrument;
use uuid::Uuid;

/// Errors returned while preparing or validating operator authentication state.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthError {
    /// The WebSocket client sent a message that was not a login request.
    #[error("expected an operator login message")]
    InvalidLoginMessage,
    /// The WebSocket client sent a text frame that was not valid operator JSON.
    #[error("invalid operator message json: {0}")]
    InvalidMessageJson(String),
}

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
    /// Username is not present in the loaded profile.
    UnknownUser,
    /// Password hash does not match the loaded profile credential.
    WrongPassword,
}

impl AuthenticationFailure {
    /// Build the Havoc-compatible error message returned to the client.
    #[must_use]
    pub fn message(&self) -> &'static str {
        match self {
            Self::UnknownUser => "User doesn't exits",
            Self::WrongPassword => "Wrong Password",
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

/// In-memory operator credential store and active session registry.
#[derive(Debug, Clone)]
pub struct AuthService {
    credentials: Arc<BTreeMap<String, OperatorAccount>>,
    sessions: Arc<RwLock<SessionRegistry>>,
}

impl AuthService {
    /// Build an authentication service from a validated profile.
    #[must_use]
    pub fn from_profile(profile: &Profile) -> Self {
        let credentials = profile
            .operators
            .users
            .iter()
            .map(|(username, config)| {
                (
                    username.clone(),
                    OperatorAccount {
                        password_hash: hash_password(&config.password),
                        role: config.role,
                    },
                )
            })
            .collect();

        Self {
            credentials: Arc::new(credentials),
            sessions: Arc::new(RwLock::new(SessionRegistry::default())),
        }
    }

    /// Authenticate a parsed login payload and create a session on success.
    #[instrument(skip(self, login), fields(connection_id = %connection_id, username = %login.user))]
    pub async fn authenticate_login(
        &self,
        connection_id: Uuid,
        login: &LoginInfo,
    ) -> AuthenticationResult {
        let Some(account) = self.credentials.get(&login.user) else {
            return AuthenticationResult::Failure(AuthenticationFailure::UnknownUser);
        };

        if !login.password.eq_ignore_ascii_case(&account.password_hash) {
            return AuthenticationResult::Failure(AuthenticationFailure::WrongPassword);
        }

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OperatorAccount {
    password_hash: String,
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
}

/// Compute the Havoc-compatible SHA3-256 hex digest for a plaintext password.
#[must_use]
pub fn hash_password(password: &str) -> String {
    let digest = Sha3_256::digest(password.as_bytes());
    let mut encoded = String::with_capacity(digest.len() * 2);

    for byte in digest {
        let _ = write!(&mut encoded, "{byte:02x}");
    }

    encoded
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

#[cfg(test)]
mod tests {
    use red_cell_common::config::Profile;
    use red_cell_common::operator::{
        EventCode, InitConnectionCode, LoginInfo, Message, MessageHead, OperatorMessage,
    };
    use serde_json::json;
    use uuid::Uuid;

    use super::{
        AuthError, AuthService, AuthenticationFailure, AuthenticationResult, hash_password,
        login_failure_message, login_success_message,
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
            hash_password("password1234"),
            "2f7d3e77d0786c5d305c0afadd4c1a2a6869a3210956c963ad2420c52e797022"
        );
    }

    #[tokio::test]
    async fn authenticate_login_accepts_valid_hash_and_tracks_session() {
        let service = AuthService::from_profile(&profile());
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
                        password: hash_password("password1234"),
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
        let service = AuthService::from_profile(&profile());
        let connection_id = Uuid::new_v4();

        let result = service
            .authenticate_login(
                connection_id,
                &LoginInfo { user: "ghost".to_owned(), password: hash_password("password1234") },
            )
            .await;

        assert_eq!(result, AuthenticationResult::Failure(AuthenticationFailure::UnknownUser));
        assert_eq!(service.session_count().await, 0);
    }

    #[tokio::test]
    async fn authenticate_login_rejects_wrong_password_hash() {
        let service = AuthService::from_profile(&profile());

        let result = service
            .authenticate_login(
                Uuid::new_v4(),
                &LoginInfo { user: "operator".to_owned(), password: hash_password("wrong") },
            )
            .await;

        assert_eq!(result, AuthenticationResult::Failure(AuthenticationFailure::WrongPassword));
        assert_eq!(service.session_count().await, 0);
    }

    #[tokio::test]
    async fn authenticate_message_rejects_non_login_messages() {
        let service = AuthService::from_profile(&profile());
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
        let service = AuthService::from_profile(&profile());
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
                    "Password_SHA3": hash_password("password1234")
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
        let service = AuthService::from_profile(&profile());
        let connection_id = Uuid::new_v4();

        let result = service
            .authenticate_login(
                connection_id,
                &LoginInfo { user: "operator".to_owned(), password: hash_password("password1234") },
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
        let service = AuthService::from_profile(&profile());
        let connection_id = Uuid::new_v4();

        let result = service
            .authenticate_login(
                connection_id,
                &LoginInfo { user: "analyst".to_owned(), password: hash_password("readonly") },
            )
            .await;

        assert!(matches!(result, AuthenticationResult::Success(_)));

        let session =
            service.session_for_connection(connection_id).await.expect("session should be stored");
        assert_eq!(session.role, red_cell_common::config::OperatorRole::Analyst);
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
    fn login_failure_message_preserves_havoc_error_text() {
        let message = login_failure_message("ghost", &AuthenticationFailure::UnknownUser);
        let value = serde_json::to_value(&message).expect("message should serialize");

        assert_eq!(value["Body"]["SubEvent"], json!(InitConnectionCode::Error.as_u32()));
        assert_eq!(value["Body"]["Info"]["Message"], json!("User doesn't exits"));
    }
}
