//! REST API RBAC guards and permission checks.

use std::marker::PhantomData;
use std::ops::Deref;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use red_cell_common::config::OperatorRole;
use serde_json::Value;

use crate::app::TeamserverState;
use crate::rbac::{
    CanAdminister, CanManageListeners, CanRead, CanTaskAgents, Permission, PermissionMarker,
};
use crate::{audit_details, parameter_object, record_operator_action_with_notifications};

use super::{ApiAuthError, ApiIdentity};

/// Extractor that exposes an authenticated API identity and enforces a permission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiPermissionGuard<P> {
    identity: ApiIdentity,
    _marker: PhantomData<P>,
}

impl<P> Deref for ApiPermissionGuard<P> {
    type Target = ApiIdentity;

    fn deref(&self) -> &Self::Target {
        &self.identity
    }
}

impl<P> FromRequestParts<TeamserverState> for ApiPermissionGuard<P>
where
    P: PermissionMarker + Send + Sync,
{
    type Rejection = ApiAuthError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &TeamserverState,
    ) -> Result<Self, Self::Rejection> {
        let identity =
            parts.extensions.get::<ApiIdentity>().cloned().ok_or(ApiAuthError::MissingIdentity)?;

        if let Err(error) = authorize_api_role(identity.role, P::PERMISSION) {
            if let Err(audit_error) = record_operator_action_with_notifications(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "api.permission_denied",
                "api_key",
                Some(identity.key_id.clone()),
                audit_details(
                    crate::AuditResultStatus::Failure,
                    None,
                    Some("permission_denied"),
                    Some(parameter_object([
                        ("required", Value::String(P::PERMISSION.as_str().to_owned())),
                        ("role", Value::String(format!("{:?}", identity.role))),
                    ])),
                ),
            )
            .await
            {
                tracing::warn!(%audit_error, "failed to persist api permission-denied audit record");
            }
            return Err(error);
        }

        Ok(Self { identity, _marker: PhantomData })
    }
}

/// Read-only access to protected REST API routes.
pub type ReadApiAccess = ApiPermissionGuard<CanRead>;
/// Listener-management access to protected REST API routes.
pub type ListenerManagementApiAccess = ApiPermissionGuard<CanManageListeners>;
/// Agent-tasking access to protected REST API routes.
pub type TaskAgentApiAccess = ApiPermissionGuard<CanTaskAgents>;
/// Administrative access to protected REST API routes.
pub type AdminApiAccess = ApiPermissionGuard<CanAdminister>;

pub(super) fn authorize_api_role(
    role: OperatorRole,
    permission: Permission,
) -> Result<(), ApiAuthError> {
    if api_role_allows(role, permission) {
        Ok(())
    } else {
        Err(ApiAuthError::PermissionDenied { role, required: permission.as_str() })
    }
}

pub(super) const fn api_role_allows(role: OperatorRole, permission: Permission) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_role_allows_all_permissions() {
        for permission in [
            Permission::Read,
            Permission::ManageListeners,
            Permission::TaskAgents,
            Permission::Admin,
        ] {
            assert!(api_role_allows(OperatorRole::Admin, permission));
            assert!(authorize_api_role(OperatorRole::Admin, permission).is_ok());
        }
    }

    #[test]
    fn operator_role_allows_expected_permissions_only() {
        for permission in [Permission::Read, Permission::ManageListeners, Permission::TaskAgents] {
            assert!(api_role_allows(OperatorRole::Operator, permission));
            assert!(authorize_api_role(OperatorRole::Operator, permission).is_ok());
        }

        let err = authorize_api_role(OperatorRole::Operator, Permission::Admin)
            .expect_err("operator should not receive admin permission");
        assert!(matches!(
            err,
            ApiAuthError::PermissionDenied { role: OperatorRole::Operator, required: "admin" }
        ));
    }

    #[test]
    fn analyst_role_only_allows_read() {
        assert!(api_role_allows(OperatorRole::Analyst, Permission::Read));
        assert!(authorize_api_role(OperatorRole::Analyst, Permission::Read).is_ok());

        for permission in [Permission::ManageListeners, Permission::TaskAgents, Permission::Admin] {
            let err = authorize_api_role(OperatorRole::Analyst, permission)
                .expect_err("analyst should be read-only");
            assert!(matches!(
                err,
                ApiAuthError::PermissionDenied { role: OperatorRole::Analyst, .. }
            ));
        }
    }
}
