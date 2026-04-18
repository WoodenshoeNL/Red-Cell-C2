//! Role-based access control for REST and operator WebSocket actions.

mod permissions;
mod policy;
mod roles;

#[cfg(test)]
mod tests;

pub use permissions::{
    AdminAccess, CanAdminister, CanManageListeners, CanRead, CanTaskAgents,
    ListenerManagementAccess, Permission, PermissionMarker, ReadAccess, RequirePermission,
    TaskAgentAccess,
};
pub use policy::{
    AuthenticatedOperator, AuthorizationError, authorize_agent_group_access,
    authorize_listener_access, authorize_websocket_command,
};
pub use roles::{authorize_permission, role_grants};
