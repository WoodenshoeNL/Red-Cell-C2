//! Role-based access control for REST and operator WebSocket actions.

use std::marker::PhantomData;
use std::ops::Deref;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::{http::HeaderMap, http::StatusCode};
use red_cell_common::config::OperatorRole;
use red_cell_common::operator::OperatorMessage;
use thiserror::Error;

use crate::auth::{AuthService, OperatorSession};
use crate::database::Database;
use crate::json_error_response;

const SESSION_TOKEN_HEADER: &str = "x-session-token";

/// Permission granted by one or more operator roles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// Read-only access to teamserver state.
    Read,
    /// Queue tasks for agents or sessions.
    TaskAgents,
    /// Create, modify, or remove listeners.
    ManageListeners,
    /// Administrative access for all remaining operations.
    Admin,
}

impl Permission {
    /// Return a human-readable permission name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::TaskAgents => "task_agents",
            Self::ManageListeners => "manage_listeners",
            Self::Admin => "admin",
        }
    }
}

/// Errors returned by RBAC checks.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthorizationError {
    /// No session token was present on the request.
    #[error("missing session token")]
    MissingSessionToken,
    /// The authorization header format was invalid.
    #[error("invalid authorization header")]
    InvalidAuthorizationHeader,
    /// The provided session token is not active.
    #[error("unknown session token")]
    UnknownSessionToken,
    /// The operator role does not satisfy the requested permission.
    #[error("operator role `{role:?}` lacks `{required}` permission")]
    PermissionDenied {
        /// Role tied to the current session.
        role: OperatorRole,
        /// Permission required by the operation.
        required: &'static str,
    },
    /// The message is not a valid operator-originated WebSocket command.
    #[error("unsupported operator websocket command")]
    UnsupportedWebSocketCommand,
    /// The operator is not permitted to task this agent due to group restrictions.
    #[error(
        "operator `{username}` is not permitted to task agent 0x{agent_id:08X}: \
         agent is not in any of the operator's allowed groups"
    )]
    AgentGroupDenied {
        /// Operator username.
        username: String,
        /// Agent that was denied.
        agent_id: u32,
    },
    /// The operator is not permitted to use this listener.
    #[error("operator `{username}` is not permitted to use listener `{listener_name}`")]
    ListenerAccessDenied {
        /// Operator username.
        username: String,
        /// Listener name that was denied.
        listener_name: String,
    },
    /// A database error occurred while checking RBAC constraints.
    ///
    /// Stored as a `String` so the error type remains `PartialEq + Eq`.
    #[error("rbac database error: {0}")]
    DatabaseError(String),
}

impl IntoResponse for AuthorizationError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::MissingSessionToken
            | Self::InvalidAuthorizationHeader
            | Self::UnknownSessionToken => StatusCode::UNAUTHORIZED,
            Self::PermissionDenied { .. }
            | Self::AgentGroupDenied { .. }
            | Self::ListenerAccessDenied { .. } => StatusCode::FORBIDDEN,
            Self::UnsupportedWebSocketCommand => StatusCode::BAD_REQUEST,
            Self::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        json_error_response(status, "authorization_error", self.to_string())
    }
}

/// Extractor for any authenticated operator session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedOperator(pub OperatorSession);

impl Deref for AuthenticatedOperator {
    type Target = OperatorSession;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for AuthenticatedOperator
where
    S: Send + Sync,
    AuthService: FromRef<S>,
{
    type Rejection = AuthorizationError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let token = session_token(&parts.headers)?;
        let auth = AuthService::from_ref(state);
        let session = auth
            .session_for_token(token.as_str())
            .await
            .ok_or(AuthorizationError::UnknownSessionToken)?;

        Ok(Self(session))
    }
}

/// Marker trait used to bind a permission requirement to an extractor type.
pub trait PermissionMarker {
    /// Permission required by the extractor.
    const PERMISSION: Permission;
}

/// Extractor that authenticates the operator and enforces a permission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequirePermission<P> {
    session: OperatorSession,
    _marker: PhantomData<P>,
}

impl<P> Deref for RequirePermission<P> {
    type Target = OperatorSession;

    fn deref(&self) -> &Self::Target {
        &self.session
    }
}

impl<S, P> FromRequestParts<S> for RequirePermission<P>
where
    S: Send + Sync,
    AuthService: FromRef<S>,
    P: PermissionMarker + Send + Sync,
{
    type Rejection = AuthorizationError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let session = AuthenticatedOperator::from_request_parts(parts, state).await?;
        authorize_permission(&session, P::PERMISSION)?;

        Ok(Self { session: session.0, _marker: PhantomData })
    }
}

/// Read-only REST access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanRead;

impl PermissionMarker for CanRead {
    const PERMISSION: Permission = Permission::Read;
}

/// Agent tasking REST access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanTaskAgents;

impl PermissionMarker for CanTaskAgents {
    const PERMISSION: Permission = Permission::TaskAgents;
}

/// Listener management REST access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanManageListeners;

impl PermissionMarker for CanManageListeners {
    const PERMISSION: Permission = Permission::ManageListeners;
}

/// Administrative REST access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanAdminister;

impl PermissionMarker for CanAdminister {
    const PERMISSION: Permission = Permission::Admin;
}

/// Read-only route guard.
pub type ReadAccess = RequirePermission<CanRead>;
/// Agent-tasking route guard.
pub type TaskAgentAccess = RequirePermission<CanTaskAgents>;
/// Listener-management route guard.
pub type ListenerManagementAccess = RequirePermission<CanManageListeners>;
/// Administrative route guard.
pub type AdminAccess = RequirePermission<CanAdminister>;

/// Enforce a permission against an authenticated operator session.
pub fn authorize_permission(
    session: &OperatorSession,
    permission: Permission,
) -> Result<(), AuthorizationError> {
    if role_grants(session.role, permission) {
        Ok(())
    } else {
        Err(AuthorizationError::PermissionDenied {
            role: session.role,
            required: permission.as_str(),
        })
    }
}

/// Return `true` when the given role includes the requested permission.
pub const fn role_grants(role: OperatorRole, permission: Permission) -> bool {
    match role {
        OperatorRole::Admin => true,
        OperatorRole::Operator => {
            matches!(
                permission,
                Permission::Read | Permission::TaskAgents | Permission::ManageListeners
            )
        }
        OperatorRole::Analyst => matches!(permission, Permission::Read),
    }
}

/// Enforce the permission required by an operator-originated WebSocket command.
pub fn authorize_websocket_command(
    session: &OperatorSession,
    message: &OperatorMessage,
) -> Result<Permission, AuthorizationError> {
    let permission = required_permission(message)?;
    authorize_permission(session, permission)?;
    Ok(permission)
}

fn required_permission(message: &OperatorMessage) -> Result<Permission, AuthorizationError> {
    match message {
        OperatorMessage::ListenerNew(_)
        | OperatorMessage::ListenerEdit(_)
        | OperatorMessage::ListenerRemove(_)
        | OperatorMessage::ListenerMark(_) => Ok(Permission::ManageListeners),
        OperatorMessage::AgentTask(_) => Ok(Permission::TaskAgents),
        OperatorMessage::Login(_)
        | OperatorMessage::InitConnectionSuccess(_)
        | OperatorMessage::InitConnectionError(_)
        | OperatorMessage::InitConnectionInfo(_)
        | OperatorMessage::InitConnectionProfile(_)
        | OperatorMessage::ListenerError(_)
        | OperatorMessage::AgentNew(_)
        | OperatorMessage::AgentReregistered(_)
        | OperatorMessage::AgentResponse(_)
        | OperatorMessage::AgentUpdate(_)
        | OperatorMessage::ChatListener(_)
        | OperatorMessage::ChatAgent(_)
        | OperatorMessage::ChatUserConnected(_)
        | OperatorMessage::ChatUserDisconnected(_)
        | OperatorMessage::ServiceAgentRegister(_)
        | OperatorMessage::ServiceListenerRegister(_)
        | OperatorMessage::TeamserverLog(_)
        | OperatorMessage::DatabaseDegraded(_)
        | OperatorMessage::DatabaseRecovered(_) => Err(AuthorizationError::UnsupportedWebSocketCommand),
        OperatorMessage::ChatMessage(_) => Ok(Permission::Read),
        OperatorMessage::CredentialsAdd(_)
        | OperatorMessage::CredentialsEdit(_)
        | OperatorMessage::CredentialsRemove(_)
        | OperatorMessage::BuildPayloadStaged(_)
        | OperatorMessage::BuildPayloadRequest(_)
        | OperatorMessage::BuildPayloadResponse(_)
        | OperatorMessage::BuildPayloadMessage(_)
        | OperatorMessage::BuildPayloadMsOffice(_)
        | OperatorMessage::HostFileAdd(_)
        | OperatorMessage::HostFileRemove(_)
        | OperatorMessage::AgentRemove(_)
        | OperatorMessage::TeamserverProfile(_) => Ok(Permission::Admin),
    }
}

/// Check that `username` is allowed to task `agent_id` based on per-operator
/// group restrictions.
///
/// Returns `Ok(())` when the operator has no group restrictions, or when at
/// least one of the agent's groups is in the operator's allow-list.
pub async fn authorize_agent_group_access(
    database: &Database,
    username: &str,
    agent_id: u32,
) -> Result<(), AuthorizationError> {
    let repo = database.agent_groups();
    let agent_groups = repo
        .groups_for_agent(agent_id)
        .await
        .map_err(|e| AuthorizationError::DatabaseError(e.to_string()))?;
    let may_task = repo
        .operator_may_task_agent(username, &agent_groups)
        .await
        .map_err(|e| AuthorizationError::DatabaseError(e.to_string()))?;
    if may_task {
        Ok(())
    } else {
        Err(AuthorizationError::AgentGroupDenied { username: username.to_owned(), agent_id })
    }
}

/// Check that `username` is allowed to interact with `listener_name` based on
/// the listener's per-operator allow-list.
///
/// Returns `Ok(())` when the allow-list is empty (unrestricted) or when the
/// operator appears in the list.
pub async fn authorize_listener_access(
    database: &Database,
    username: &str,
    listener_name: &str,
) -> Result<(), AuthorizationError> {
    let may_use = database
        .listener_access()
        .operator_may_use_listener(username, listener_name)
        .await
        .map_err(|e| AuthorizationError::DatabaseError(e.to_string()))?;
    if may_use {
        Ok(())
    } else {
        Err(AuthorizationError::ListenerAccessDenied {
            username: username.to_owned(),
            listener_name: listener_name.to_owned(),
        })
    }
}

fn session_token(headers: &HeaderMap) -> Result<String, AuthorizationError> {
    if let Some(value) = headers.get(AUTHORIZATION) {
        let raw = value.to_str().map_err(|_| AuthorizationError::InvalidAuthorizationHeader)?;
        let Some(token) = raw.strip_prefix("Bearer ") else {
            return Err(AuthorizationError::InvalidAuthorizationHeader);
        };
        if token.is_empty() {
            return Err(AuthorizationError::InvalidAuthorizationHeader);
        }
        return Ok(token.to_owned());
    }

    if let Some(value) = headers.get(SESSION_TOKEN_HEADER) {
        let token = value.to_str().map_err(|_| AuthorizationError::InvalidAuthorizationHeader)?;
        if token.is_empty() {
            return Err(AuthorizationError::InvalidAuthorizationHeader);
        }
        return Ok(token.to_owned());
    }

    Err(AuthorizationError::MissingSessionToken)
}

#[cfg(test)]
mod tests {
    use axum::extract::{FromRef, FromRequestParts};
    use axum::http::header::AUTHORIZATION;
    use axum::http::{HeaderValue, Request, StatusCode};
    use red_cell_common::config::{OperatorRole, Profile};
    use red_cell_common::operator::{
        AgentTaskInfo, FlatInfo, ListenerInfo, Message, MessageHead, OperatorMessage,
        TeamserverProfileInfo,
    };
    use uuid::Uuid;

    use axum::body::to_bytes;
    use axum::response::IntoResponse;
    use serde_json::Value;

    use super::{
        AdminAccess, AuthenticatedOperator, AuthorizationError, ListenerManagementAccess,
        Permission, ReadAccess, TaskAgentAccess, authorize_permission, authorize_websocket_command,
    };
    use crate::auth::{AuthService, OperatorSession};
    use red_cell_common::crypto::hash_password_sha3;

    #[derive(Debug, Clone)]
    struct TestState {
        auth: AuthService,
    }

    impl FromRef<TestState> for AuthService {
        fn from_ref(input: &TestState) -> Self {
            input.auth.clone()
        }
    }

    fn profile() -> Profile {
        Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
            }

            Operators {
              user "admin" {
                Password = "adminpw"
                Role = "Admin"
              }
              user "operator" {
                Password = "operatorpw"
                Role = "Operator"
              }
              user "analyst" {
                Password = "analystpw"
                Role = "Analyst"
              }
            }

            Demon {}
            "#,
        )
        .expect("rbac test profile should parse")
    }

    fn session(role: OperatorRole) -> OperatorSession {
        OperatorSession {
            token: "session-token".to_owned(),
            username: format!("{role:?}").to_lowercase(),
            role,
            connection_id: Uuid::new_v4(),
        }
    }

    fn message_head() -> MessageHead {
        MessageHead {
            event: red_cell_common::operator::EventCode::Session,
            user: "operator".to_owned(),
            timestamp: String::new(),
            one_time: String::new(),
        }
    }

    #[test]
    fn permissions_enforce_role_boundaries() {
        let cases = [
            (OperatorRole::Admin, Permission::Read, true),
            (OperatorRole::Admin, Permission::TaskAgents, true),
            (OperatorRole::Admin, Permission::ManageListeners, true),
            (OperatorRole::Admin, Permission::Admin, true),
            (OperatorRole::Operator, Permission::Read, true),
            (OperatorRole::Operator, Permission::TaskAgents, true),
            (OperatorRole::Operator, Permission::ManageListeners, true),
            (OperatorRole::Operator, Permission::Admin, false),
            (OperatorRole::Analyst, Permission::Read, true),
            (OperatorRole::Analyst, Permission::TaskAgents, false),
            (OperatorRole::Analyst, Permission::ManageListeners, false),
            (OperatorRole::Analyst, Permission::Admin, false),
        ];

        for (role, permission, allowed) in cases {
            let result = authorize_permission(&session(role), permission);
            if allowed {
                assert_eq!(
                    result,
                    Ok(()),
                    "expected {role:?} to be allowed {}",
                    permission.as_str()
                );
            } else {
                assert_eq!(
                    result,
                    Err(AuthorizationError::PermissionDenied {
                        role,
                        required: permission.as_str(),
                    }),
                    "expected {role:?} to be denied {}",
                    permission.as_str()
                );
            }
        }
    }

    #[test]
    fn websocket_command_authorization_matches_expected_permissions() {
        let task = OperatorMessage::AgentTask(Message {
            head: message_head(),
            info: AgentTaskInfo {
                task_id: "task-1".to_owned(),
                command_line: "pwd".to_owned(),
                demon_id: "abcd".to_owned(),
                command_id: "1".to_owned(),
                ..AgentTaskInfo::default()
            },
        });
        let listener = OperatorMessage::ListenerNew(Message {
            head: MessageHead {
                event: red_cell_common::operator::EventCode::Listener,
                ..message_head()
            },
            info: ListenerInfo::default(),
        });
        let admin = OperatorMessage::TeamserverProfile(Message {
            head: MessageHead {
                event: red_cell_common::operator::EventCode::Teamserver,
                ..message_head()
            },
            info: TeamserverProfileInfo { profile: "{}".to_owned() },
        });

        assert_eq!(
            authorize_websocket_command(&session(OperatorRole::Operator), &task),
            Ok(Permission::TaskAgents)
        );
        assert_eq!(
            authorize_websocket_command(&session(OperatorRole::Operator), &listener),
            Ok(Permission::ManageListeners)
        );
        assert_eq!(
            authorize_websocket_command(&session(OperatorRole::Analyst), &task),
            Err(AuthorizationError::PermissionDenied {
                role: OperatorRole::Analyst,
                required: Permission::TaskAgents.as_str(),
            })
        );
        assert_eq!(
            authorize_websocket_command(&session(OperatorRole::Operator), &admin),
            Err(AuthorizationError::PermissionDenied {
                role: OperatorRole::Operator,
                required: Permission::Admin.as_str(),
            })
        );
    }

    #[test]
    fn websocket_command_requires_admin_for_agent_remove() {
        let message = OperatorMessage::AgentRemove(Message {
            head: message_head(),
            info: FlatInfo::default(),
        });

        assert_eq!(
            authorize_websocket_command(&session(OperatorRole::Admin), &message),
            Ok(Permission::Admin)
        );
        assert_eq!(
            authorize_websocket_command(&session(OperatorRole::Operator), &message),
            Err(AuthorizationError::PermissionDenied {
                role: OperatorRole::Operator,
                required: Permission::Admin.as_str(),
            })
        );
    }

    #[test]
    fn websocket_chat_message_requires_only_read_access() {
        let message = OperatorMessage::ChatMessage(Message {
            head: MessageHead {
                event: red_cell_common::operator::EventCode::Chat,
                ..message_head()
            },
            info: FlatInfo::default(),
        });

        assert_eq!(
            authorize_websocket_command(&session(OperatorRole::Analyst), &message),
            Ok(Permission::Read)
        );
    }

    #[test]
    fn websocket_server_push_messages_are_rejected_for_all_roles() {
        let roles = [OperatorRole::Admin, OperatorRole::Operator, OperatorRole::Analyst];
        let messages = [
            OperatorMessage::Login(Message {
                head: MessageHead {
                    event: red_cell_common::operator::EventCode::InitConnection,
                    ..message_head()
                },
                info: red_cell_common::operator::LoginInfo::default(),
            }),
            OperatorMessage::AgentNew(Box::new(Message {
                head: MessageHead {
                    event: red_cell_common::operator::EventCode::Session,
                    ..message_head()
                },
                info: red_cell_common::operator::AgentInfo::default(),
            })),
            OperatorMessage::ListenerError(Message {
                head: MessageHead {
                    event: red_cell_common::operator::EventCode::Listener,
                    ..message_head()
                },
                info: red_cell_common::operator::ListenerErrorInfo::default(),
            }),
            OperatorMessage::TeamserverLog(Message {
                head: MessageHead {
                    event: red_cell_common::operator::EventCode::Teamserver,
                    ..message_head()
                },
                info: red_cell_common::operator::TeamserverLogInfo::default(),
            }),
        ];

        for role in roles {
            for message in &messages {
                assert_eq!(
                    authorize_websocket_command(&session(role), message),
                    Err(AuthorizationError::UnsupportedWebSocketCommand)
                );
            }
        }
    }

    #[tokio::test]
    async fn authenticated_operator_extractor_accepts_bearer_tokens() {
        let auth = AuthService::from_profile(&profile()).expect("auth service should initialize");
        let connection_id = Uuid::new_v4();
        let result = auth
            .authenticate_login(
                connection_id,
                &red_cell_common::operator::LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("operatorpw"),
                },
            )
            .await;

        assert!(matches!(result, crate::auth::AuthenticationResult::Success(_)));

        let request = Request::builder()
            .header(AUTHORIZATION, "Bearer session-token-placeholder")
            .body(())
            .expect("request should build");
        let (mut parts, _) = request.into_parts();
        let stored =
            auth.session_for_connection(connection_id).await.expect("session should exist");
        parts.headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", stored.token))
                .expect("token header should be valid"),
        );

        let extracted = AuthenticatedOperator::from_request_parts(
            &mut parts,
            &TestState { auth: auth.clone() },
        )
        .await
        .expect("session token should authorize");

        assert_eq!(extracted.username, "operator");
        assert_eq!(extracted.role, OperatorRole::Operator);
    }

    #[tokio::test]
    async fn authenticated_operator_extractor_rejects_empty_bearer_tokens() {
        let auth = AuthService::from_profile(&profile()).expect("auth service should initialize");
        let request = Request::builder()
            .header(AUTHORIZATION, "Bearer ")
            .body(())
            .expect("request should build");
        let (mut parts, _) = request.into_parts();

        let error = AuthenticatedOperator::from_request_parts(&mut parts, &TestState { auth })
            .await
            .expect_err("empty bearer tokens should be rejected");

        assert_eq!(error, AuthorizationError::InvalidAuthorizationHeader);
    }

    #[tokio::test]
    async fn authenticated_operator_extractor_rejects_non_utf8_authorization_headers() {
        let auth = AuthService::from_profile(&profile()).expect("auth service should initialize");
        let request = Request::builder()
            .header(AUTHORIZATION, HeaderValue::from_bytes(b"Bearer \xFF").expect("header value"))
            .body(())
            .expect("request should build");
        let (mut parts, _) = request.into_parts();

        let error = AuthenticatedOperator::from_request_parts(&mut parts, &TestState { auth })
            .await
            .expect_err("non-utf8 authorization headers should be rejected");

        assert_eq!(error, AuthorizationError::InvalidAuthorizationHeader);
    }

    #[tokio::test]
    async fn authenticated_operator_extractor_rejects_empty_x_session_token_header() {
        let auth = AuthService::from_profile(&profile()).expect("auth service should initialize");
        let request = Request::builder()
            .header("x-session-token", "")
            .body(())
            .expect("request should build");
        let (mut parts, _) = request.into_parts();

        let error = AuthenticatedOperator::from_request_parts(&mut parts, &TestState { auth })
            .await
            .expect_err("empty x-session-token should be rejected");

        assert_eq!(error, AuthorizationError::InvalidAuthorizationHeader);
    }

    #[tokio::test]
    async fn authenticated_operator_extractor_rejects_non_utf8_x_session_token_header() {
        let auth = AuthService::from_profile(&profile()).expect("auth service should initialize");
        let request = Request::builder()
            .header("x-session-token", HeaderValue::from_bytes(b"\xFF").expect("header value"))
            .body(())
            .expect("request should build");
        let (mut parts, _) = request.into_parts();

        let error = AuthenticatedOperator::from_request_parts(&mut parts, &TestState { auth })
            .await
            .expect_err("non-utf8 x-session-token should be rejected");

        assert_eq!(error, AuthorizationError::InvalidAuthorizationHeader);
    }

    #[tokio::test]
    async fn authenticated_operator_extractor_prefers_authorization_header_over_session_token() {
        let auth = AuthService::from_profile(&profile()).expect("auth service should initialize");

        let operator_connection_id = Uuid::new_v4();
        let operator_result = auth
            .authenticate_login(
                operator_connection_id,
                &red_cell_common::operator::LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("operatorpw"),
                },
            )
            .await;
        assert!(matches!(operator_result, crate::auth::AuthenticationResult::Success(_)));

        let admin_connection_id = Uuid::new_v4();
        let admin_result = auth
            .authenticate_login(
                admin_connection_id,
                &red_cell_common::operator::LoginInfo {
                    user: "admin".to_owned(),
                    password: hash_password_sha3("adminpw"),
                },
            )
            .await;
        assert!(matches!(admin_result, crate::auth::AuthenticationResult::Success(_)));

        let operator_session = auth
            .session_for_connection(operator_connection_id)
            .await
            .expect("operator session should exist");
        let admin_session = auth
            .session_for_connection(admin_connection_id)
            .await
            .expect("admin session should exist");

        let request = Request::builder()
            .header(AUTHORIZATION, format!("Bearer {}", operator_session.token))
            .header("x-session-token", admin_session.token.as_str())
            .body(())
            .expect("request should build");
        let (mut parts, _) = request.into_parts();

        let extracted = AuthenticatedOperator::from_request_parts(&mut parts, &TestState { auth })
            .await
            .expect("authorization header should take precedence");

        assert_eq!(extracted.username, "operator");
        assert_eq!(extracted.role, OperatorRole::Operator);
    }

    #[tokio::test]
    async fn authenticated_operator_extractor_requires_a_session_token_header() {
        let auth = AuthService::from_profile(&profile()).expect("auth service should initialize");
        let request = Request::builder().body(()).expect("request should build");
        let (mut parts, _) = request.into_parts();

        let error = AuthenticatedOperator::from_request_parts(&mut parts, &TestState { auth })
            .await
            .expect_err("requests without a session token should be rejected");

        assert_eq!(error, AuthorizationError::MissingSessionToken);
    }

    #[tokio::test]
    async fn permission_extractors_reject_insufficient_roles() {
        let auth = AuthService::from_profile(&profile()).expect("auth service should initialize");
        let connection_id = Uuid::new_v4();
        let result = auth
            .authenticate_login(
                connection_id,
                &red_cell_common::operator::LoginInfo {
                    user: "analyst".to_owned(),
                    password: hash_password_sha3("analystpw"),
                },
            )
            .await;

        assert!(matches!(result, crate::auth::AuthenticationResult::Success(_)));

        let stored =
            auth.session_for_connection(connection_id).await.expect("session should exist");
        let request = Request::builder()
            .header("x-session-token", stored.token.as_str())
            .body(())
            .expect("request should build");
        let (mut parts, _) = request.into_parts();
        let state = TestState { auth };

        let read =
            <ReadAccess as FromRequestParts<TestState>>::from_request_parts(&mut parts, &state)
                .await
                .expect("analyst should be allowed to read");
        assert_eq!(read.role, OperatorRole::Analyst);

        let request = Request::builder()
            .header("x-session-token", stored.token.as_str())
            .body(())
            .expect("request should build");
        let (mut parts, _) = request.into_parts();
        let denied = <TaskAgentAccess as FromRequestParts<TestState>>::from_request_parts(
            &mut parts, &state,
        )
        .await
        .expect_err("analyst should not task agents");

        assert_eq!(
            denied,
            AuthorizationError::PermissionDenied {
                role: OperatorRole::Analyst,
                required: Permission::TaskAgents.as_str(),
            }
        );
    }

    #[tokio::test]
    async fn listener_management_access_extractor_accepts_operator_and_rejects_analyst() {
        let auth = AuthService::from_profile(&profile()).expect("auth service should initialize");

        let operator_id = Uuid::new_v4();
        assert!(matches!(
            auth.authenticate_login(
                operator_id,
                &red_cell_common::operator::LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("operatorpw"),
                },
            )
            .await,
            crate::auth::AuthenticationResult::Success(_)
        ));
        let operator_session =
            auth.session_for_connection(operator_id).await.expect("operator session should exist");

        let analyst_id = Uuid::new_v4();
        assert!(matches!(
            auth.authenticate_login(
                analyst_id,
                &red_cell_common::operator::LoginInfo {
                    user: "analyst".to_owned(),
                    password: hash_password_sha3("analystpw"),
                },
            )
            .await,
            crate::auth::AuthenticationResult::Success(_)
        ));
        let analyst_session =
            auth.session_for_connection(analyst_id).await.expect("analyst session should exist");

        let state = TestState { auth };

        // Operator must be allowed to manage listeners.
        let request = Request::builder()
            .header("x-session-token", operator_session.token.as_str())
            .body(())
            .expect("request should build");
        let (mut parts, _) = request.into_parts();
        let extracted =
            <ListenerManagementAccess as FromRequestParts<TestState>>::from_request_parts(
                &mut parts, &state,
            )
            .await
            .expect("operator should be allowed to manage listeners");
        assert_eq!(extracted.role, OperatorRole::Operator);

        // Analyst must be denied listener management.
        let request = Request::builder()
            .header("x-session-token", analyst_session.token.as_str())
            .body(())
            .expect("request should build");
        let (mut parts, _) = request.into_parts();
        let denied = <ListenerManagementAccess as FromRequestParts<TestState>>::from_request_parts(
            &mut parts, &state,
        )
        .await
        .expect_err("analyst should not be allowed to manage listeners");
        assert_eq!(
            denied,
            AuthorizationError::PermissionDenied {
                role: OperatorRole::Analyst,
                required: Permission::ManageListeners.as_str(),
            }
        );
    }

    #[tokio::test]
    async fn task_agent_access_extractor_accepts_operator() {
        let auth = AuthService::from_profile(&profile()).expect("auth service should initialize");
        let connection_id = Uuid::new_v4();
        assert!(matches!(
            auth.authenticate_login(
                connection_id,
                &red_cell_common::operator::LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("operatorpw"),
                },
            )
            .await,
            crate::auth::AuthenticationResult::Success(_)
        ));

        let stored =
            auth.session_for_connection(connection_id).await.expect("session should exist");
        let request = Request::builder()
            .header("x-session-token", stored.token.as_str())
            .body(())
            .expect("request should build");
        let (mut parts, _) = request.into_parts();
        let extracted = <TaskAgentAccess as FromRequestParts<TestState>>::from_request_parts(
            &mut parts,
            &TestState { auth },
        )
        .await
        .expect("operator should be allowed to task agents");

        assert_eq!(extracted.role, OperatorRole::Operator);
    }

    #[tokio::test]
    async fn admin_permission_extractor_accepts_admin_sessions() {
        let auth = AuthService::from_profile(&profile()).expect("auth service should initialize");
        let connection_id = Uuid::new_v4();
        let result = auth
            .authenticate_login(
                connection_id,
                &red_cell_common::operator::LoginInfo {
                    user: "admin".to_owned(),
                    password: hash_password_sha3("adminpw"),
                },
            )
            .await;

        assert!(matches!(result, crate::auth::AuthenticationResult::Success(_)));

        let stored =
            auth.session_for_connection(connection_id).await.expect("session should exist");
        let request = Request::builder()
            .header("x-session-token", stored.token.as_str())
            .body(())
            .expect("request should build");
        let (mut parts, _) = request.into_parts();
        let extracted = <AdminAccess as FromRequestParts<TestState>>::from_request_parts(
            &mut parts,
            &TestState { auth },
        )
        .await
        .expect("admin should be allowed");

        assert_eq!(extracted.role, OperatorRole::Admin);
    }

    #[tokio::test]
    async fn authenticated_operator_extractor_rejects_non_bearer_authorization_scheme() {
        let auth = AuthService::from_profile(&profile()).expect("auth service should initialize");
        let request = Request::builder()
            .header(AUTHORIZATION, "Basic dXNlcjpwYXNz")
            .body(())
            .expect("request should build");
        let (mut parts, _) = request.into_parts();

        let error = AuthenticatedOperator::from_request_parts(&mut parts, &TestState { auth })
            .await
            .expect_err("non-Bearer authorization scheme should be rejected");

        assert_eq!(error, AuthorizationError::InvalidAuthorizationHeader);
    }

    #[tokio::test]
    async fn authenticated_operator_extractor_rejects_bearer_without_space() {
        let auth = AuthService::from_profile(&profile()).expect("auth service should initialize");
        let request = Request::builder()
            .header(AUTHORIZATION, "Bearertoken")
            .body(())
            .expect("request should build");
        let (mut parts, _) = request.into_parts();

        let error = AuthenticatedOperator::from_request_parts(&mut parts, &TestState { auth })
            .await
            .expect_err("Bearer without trailing space should be rejected");

        assert_eq!(error, AuthorizationError::InvalidAuthorizationHeader);
    }

    #[tokio::test]
    async fn authenticated_operator_extractor_rejects_unknown_bearer_token() {
        let auth = AuthService::from_profile(&profile()).expect("auth service should initialize");
        let request = Request::builder()
            .header(AUTHORIZATION, "Bearer totally-valid-but-unknown-token")
            .body(())
            .expect("request should build");
        let (mut parts, _) = request.into_parts();

        let error = AuthenticatedOperator::from_request_parts(&mut parts, &TestState { auth })
            .await
            .expect_err("unknown bearer token should be rejected");

        assert_eq!(error, AuthorizationError::UnknownSessionToken);
    }

    #[tokio::test]
    async fn authenticated_operator_extractor_rejects_unknown_x_session_token() {
        let auth = AuthService::from_profile(&profile()).expect("auth service should initialize");
        let request = Request::builder()
            .header("x-session-token", "totally-valid-but-unknown-token")
            .body(())
            .expect("request should build");
        let (mut parts, _) = request.into_parts();

        let error = AuthenticatedOperator::from_request_parts(&mut parts, &TestState { auth })
            .await
            .expect_err("unknown x-session-token should be rejected");

        assert_eq!(error, AuthorizationError::UnknownSessionToken);
    }

    async fn read_json(response: axum::response::Response) -> Value {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.expect("response body bytes");
        serde_json::from_slice(&bytes).expect("json body")
    }

    #[tokio::test]
    async fn into_response_missing_session_token_returns_401() {
        let response = AuthorizationError::MissingSessionToken.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "authorization_error");
        assert_eq!(body["error"]["message"], "missing session token");
    }

    #[tokio::test]
    async fn into_response_invalid_authorization_header_returns_401() {
        let response = AuthorizationError::InvalidAuthorizationHeader.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "authorization_error");
        assert_eq!(body["error"]["message"], "invalid authorization header");
    }

    #[tokio::test]
    async fn into_response_unknown_session_token_returns_401() {
        let response = AuthorizationError::UnknownSessionToken.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "authorization_error");
        assert_eq!(body["error"]["message"], "unknown session token");
    }

    #[tokio::test]
    async fn into_response_permission_denied_returns_403() {
        let response =
            AuthorizationError::PermissionDenied { role: OperatorRole::Analyst, required: "admin" }
                .into_response();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "authorization_error");
        assert_eq!(body["error"]["message"], "operator role `Analyst` lacks `admin` permission");
    }

    #[tokio::test]
    async fn into_response_unsupported_websocket_command_returns_400() {
        let response = AuthorizationError::UnsupportedWebSocketCommand.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = read_json(response).await;
        assert_eq!(body["error"]["code"], "authorization_error");
        assert_eq!(body["error"]["message"], "unsupported operator websocket command");
    }

    #[tokio::test]
    async fn session_token_rejects_lowercase_bearer_prefix() {
        let auth = AuthService::from_profile(&profile()).expect("auth service should initialize");
        let request = Request::builder()
            .header(AUTHORIZATION, "bearer token123")
            .body(())
            .expect("request should build");
        let (mut parts, _) = request.into_parts();

        let error = AuthenticatedOperator::from_request_parts(&mut parts, &TestState { auth })
            .await
            .expect_err("lowercase 'bearer' prefix should be rejected");

        assert_eq!(error, AuthorizationError::InvalidAuthorizationHeader);
    }

    #[tokio::test]
    async fn session_token_rejects_uppercase_bearer_prefix() {
        let auth = AuthService::from_profile(&profile()).expect("auth service should initialize");
        let request = Request::builder()
            .header(AUTHORIZATION, "BEARER token123")
            .body(())
            .expect("request should build");
        let (mut parts, _) = request.into_parts();

        let error = AuthenticatedOperator::from_request_parts(&mut parts, &TestState { auth })
            .await
            .expect_err("uppercase 'BEARER' prefix should be rejected");

        assert_eq!(error, AuthorizationError::InvalidAuthorizationHeader);
    }

    #[tokio::test]
    async fn session_token_rejects_mixed_case_bearer_prefix() {
        let auth = AuthService::from_profile(&profile()).expect("auth service should initialize");
        let request = Request::builder()
            .header(AUTHORIZATION, "bEaReR token123")
            .body(())
            .expect("request should build");
        let (mut parts, _) = request.into_parts();

        let error = AuthenticatedOperator::from_request_parts(&mut parts, &TestState { auth })
            .await
            .expect_err("mixed-case 'bEaReR' prefix should be rejected");

        assert_eq!(error, AuthorizationError::InvalidAuthorizationHeader);
    }

    #[tokio::test]
    async fn session_token_double_space_after_bearer_causes_lookup_miss() {
        let auth = AuthService::from_profile(&profile()).expect("auth service should initialize");

        // Log in to get a real token.
        let connection_id = Uuid::new_v4();
        let result = auth
            .authenticate_login(
                connection_id,
                &red_cell_common::operator::LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("operatorpw"),
                },
            )
            .await;
        assert!(matches!(result, crate::auth::AuthenticationResult::Success(_)));

        let stored =
            auth.session_for_connection(connection_id).await.expect("session should exist");

        // Double space: "Bearer  <token>" — strip_prefix("Bearer ") yields " <token>",
        // which includes a leading space and won't match the real token.
        let request = Request::builder()
            .header(AUTHORIZATION, format!("Bearer  {}", stored.token))
            .body(())
            .expect("request should build");
        let (mut parts, _) = request.into_parts();

        let error = AuthenticatedOperator::from_request_parts(
            &mut parts,
            &TestState { auth: auth.clone() },
        )
        .await
        .expect_err("double-spaced bearer should not match real token");

        assert_eq!(error, AuthorizationError::UnknownSessionToken);
    }

    #[tokio::test]
    async fn session_token_trailing_whitespace_in_token_causes_lookup_miss() {
        let auth = AuthService::from_profile(&profile()).expect("auth service should initialize");

        let connection_id = Uuid::new_v4();
        let result = auth
            .authenticate_login(
                connection_id,
                &red_cell_common::operator::LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password_sha3("operatorpw"),
                },
            )
            .await;
        assert!(matches!(result, crate::auth::AuthenticationResult::Success(_)));

        let stored =
            auth.session_for_connection(connection_id).await.expect("session should exist");

        // Trailing space: "Bearer <token> " — token parsed includes trailing space.
        let request = Request::builder()
            .header(AUTHORIZATION, format!("Bearer {} ", stored.token))
            .body(())
            .expect("request should build");
        let (mut parts, _) = request.into_parts();

        let error = AuthenticatedOperator::from_request_parts(
            &mut parts,
            &TestState { auth: auth.clone() },
        )
        .await
        .expect_err("trailing whitespace in token should not match real token");

        assert_eq!(error, AuthorizationError::UnknownSessionToken);
    }
}
