//! Permission enum, marker traits, and typed extractor guards.

use std::marker::PhantomData;
use std::ops::Deref;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;

use crate::auth::{AuthService, OperatorSession};

use super::policy::{AuthenticatedOperator, AuthorizationError};
use super::roles::authorize_permission;

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
