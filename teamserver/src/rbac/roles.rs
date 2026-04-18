//! Role-permission mapping and permission enforcement.

use red_cell_common::config::OperatorRole;

use crate::auth::OperatorSession;

use super::permissions::Permission;
use super::policy::AuthorizationError;

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
