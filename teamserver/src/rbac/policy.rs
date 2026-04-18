//! Authorization errors, session extraction, and policy evaluation functions.

use std::ops::Deref;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use red_cell_common::config::OperatorRole;
use red_cell_common::operator::OperatorMessage;
use thiserror::Error;

use crate::auth::{AuthService, OperatorSession};
use crate::database::Database;
use crate::json_error_response;

use super::permissions::Permission;

const SESSION_TOKEN_HEADER: &str = "x-session-token";

/// Errors returned by RBAC checks.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
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

/// Enforce the permission required by an operator-originated WebSocket command.
pub fn authorize_websocket_command(
    session: &OperatorSession,
    message: &OperatorMessage,
) -> Result<Permission, AuthorizationError> {
    let permission = required_permission(message)?;
    super::roles::authorize_permission(session, permission)?;
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
        | OperatorMessage::DatabaseRecovered(_) => {
            Err(AuthorizationError::UnsupportedWebSocketCommand)
        }
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

pub(super) fn session_token(headers: &HeaderMap) -> Result<String, AuthorizationError> {
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
