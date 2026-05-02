//! Agent REST ACL: listener + agent-group checks shared by handlers.

use crate::app::TeamserverState;
use crate::{AuthorizationError, authorize_agent_group_access, authorize_listener_access};

/// Authorize agent access for read/mutation handlers by composing both the
/// agent-group and listener-access checks.  Returns the underlying
/// [`AuthorizationError`] on denial so the handler maps to 403.
pub(crate) async fn authorize_agent_access(
    state: &TeamserverState,
    username: &str,
    agent_id: u32,
) -> Result<(), AuthorizationError> {
    authorize_agent_group_access(&state.database, username, agent_id).await?;
    if let Some(listener_name) = state.agent_registry.listener_name(agent_id).await {
        authorize_listener_access(&state.database, username, &listener_name).await?;
    }
    Ok(())
}

/// Non-raising variant of [`authorize_agent_access`] used by list endpoints to
/// skip agents the caller cannot see.  Database errors are logged and treated
/// as non-visible so a partial result is returned rather than leaking other
/// operators' agents.
pub(crate) async fn operator_may_access_agent(
    state: &TeamserverState,
    username: &str,
    agent_id: u32,
) -> bool {
    match authorize_agent_access(state, username, agent_id).await {
        Ok(()) => true,
        Err(AuthorizationError::AgentGroupDenied { .. })
        | Err(AuthorizationError::ListenerAccessDenied { .. }) => false,
        Err(err) => {
            tracing::warn!(%username, agent_id, %err, "agent ACL check failed; hiding agent");
            false
        }
    }
}
