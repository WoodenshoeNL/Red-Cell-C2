//! Agent group membership endpoints.

use axum::Json;
use axum::extract::{Path, State};
use serde_json::Value;

use crate::app::TeamserverState;
use crate::{AuditResultStatus, audit_details, parameter_object};

use super::super::{AdminApiAccess, ReadApiAccess, parse_api_agent_id, record_audit_entry};
use super::{AgentApiError, AgentGroupsResponse, SetAgentGroupsRequest, authorize_agent_access};

pub(crate) async fn get_agent_groups(
    State(state): State<TeamserverState>,
    identity: ReadApiAccess,
    Path(id): Path<String>,
) -> Result<Json<AgentGroupsResponse>, AgentApiError> {
    let agent_id = parse_api_agent_id(&id)?;
    authorize_agent_access(&state, &identity.key_id, agent_id).await?;
    let groups = state.database.agent_groups().groups_for_agent(agent_id).await?;
    Ok(Json(AgentGroupsResponse { agent_id: format!("{agent_id:08X}"), groups }))
}

pub(crate) async fn set_agent_groups(
    State(state): State<TeamserverState>,
    identity: AdminApiAccess,
    Path(id): Path<String>,
    Json(request): Json<SetAgentGroupsRequest>,
) -> Result<Json<AgentGroupsResponse>, AgentApiError> {
    let agent_id = parse_api_agent_id(&id)?;
    state.database.agent_groups().set_agent_groups(agent_id, &request.groups).await?;
    record_audit_entry(
        &state.database,
        &state.webhooks,
        &identity.key_id,
        "agent.set_groups",
        "agent",
        Some(format!("{agent_id:08X}")),
        audit_details(
            AuditResultStatus::Success,
            Some(agent_id),
            Some("set_groups"),
            Some(parameter_object([(
                "groups",
                serde_json::to_value(&request.groups).unwrap_or(Value::Null),
            )])),
        ),
    )
    .await;
    Ok(Json(AgentGroupsResponse { agent_id: format!("{agent_id:08X}"), groups: request.groups }))
}
