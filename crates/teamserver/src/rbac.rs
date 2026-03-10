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
}

impl IntoResponse for AuthorizationError {
    fn into_response(self) -> Response {
        let status = match self {
            Self::MissingSessionToken
            | Self::InvalidAuthorizationHeader
            | Self::UnknownSessionToken => StatusCode::UNAUTHORIZED,
            Self::PermissionDenied { .. } => StatusCode::FORBIDDEN,
            Self::UnsupportedWebSocketCommand => StatusCode::BAD_REQUEST,
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
    if role_allows(session.role, permission) {
        Ok(())
    } else {
        Err(AuthorizationError::PermissionDenied {
            role: session.role,
            required: permission.as_str(),
        })
    }
}

const fn role_allows(role: OperatorRole, permission: Permission) -> bool {
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
        | OperatorMessage::AgentResponse(_)
        | OperatorMessage::AgentUpdate(_)
        | OperatorMessage::ChatListener(_)
        | OperatorMessage::ChatAgent(_)
        | OperatorMessage::ChatUserConnected(_)
        | OperatorMessage::ChatUserDisconnected(_)
        | OperatorMessage::ServiceAgentRegister(_)
        | OperatorMessage::ServiceListenerRegister(_)
        | OperatorMessage::TeamserverLog(_) => Err(AuthorizationError::UnsupportedWebSocketCommand),
        OperatorMessage::CredentialsAdd(_)
        | OperatorMessage::CredentialsEdit(_)
        | OperatorMessage::CredentialsRemove(_)
        | OperatorMessage::ChatMessage(_)
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
    use axum::http::{HeaderValue, Request};
    use red_cell_common::config::{OperatorRole, Profile};
    use red_cell_common::operator::{
        AgentTaskInfo, FlatInfo, ListenerInfo, Message, MessageHead, OperatorMessage,
        TeamserverProfileInfo,
    };
    use uuid::Uuid;

    use super::{
        AdminAccess, AuthenticatedOperator, AuthorizationError, Permission, ReadAccess,
        TaskAgentAccess, authorize_permission, authorize_websocket_command,
    };
    use crate::auth::{AuthService, OperatorSession, hash_password};

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

    #[tokio::test]
    async fn authenticated_operator_extractor_accepts_bearer_tokens() {
        let auth = AuthService::from_profile(&profile());
        let connection_id = Uuid::new_v4();
        let result = auth
            .authenticate_login(
                connection_id,
                &red_cell_common::operator::LoginInfo {
                    user: "operator".to_owned(),
                    password: hash_password("operatorpw"),
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
    async fn permission_extractors_reject_insufficient_roles() {
        let auth = AuthService::from_profile(&profile());
        let connection_id = Uuid::new_v4();
        let result = auth
            .authenticate_login(
                connection_id,
                &red_cell_common::operator::LoginInfo {
                    user: "analyst".to_owned(),
                    password: hash_password("analystpw"),
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

        let read = ReadAccess::from_request_parts(&mut parts, &state)
            .await
            .expect("analyst should be allowed to read");
        assert_eq!(read.role, OperatorRole::Analyst);

        let request = Request::builder()
            .header("x-session-token", stored.token.as_str())
            .body(())
            .expect("request should build");
        let (mut parts, _) = request.into_parts();
        let denied = TaskAgentAccess::from_request_parts(&mut parts, &state)
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
    async fn admin_permission_extractor_accepts_admin_sessions() {
        let auth = AuthService::from_profile(&profile());
        let connection_id = Uuid::new_v4();
        let result = auth
            .authenticate_login(
                connection_id,
                &red_cell_common::operator::LoginInfo {
                    user: "admin".to_owned(),
                    password: hash_password("adminpw"),
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
        let extracted = AdminAccess::from_request_parts(&mut parts, &TestState { auth })
            .await
            .expect("admin should be allowed");

        assert_eq!(extracted.role, OperatorRole::Admin);
    }
}
