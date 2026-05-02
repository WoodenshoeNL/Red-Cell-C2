//! Agent inventory, tasking, upload/download, and group-membership REST handlers.

pub(crate) mod access;
pub(crate) mod debug;
pub(crate) mod read;
pub(crate) mod tasking;

pub(crate) mod groups;
pub(crate) mod task_status;
pub(crate) mod transfer;

pub(super) use access::{authorize_agent_access, operator_may_access_agent};
pub(super) use debug::get_agent_packet_ring;
pub(super) use read::{get_agent, get_agent_output, list_agents};
pub(super) use tasking::{kill_agent, queue_agent_task};

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use utoipa::ToSchema;

use crate::AuthorizationError;
use crate::websocket::AgentCommandError;

use super::json_error_response;

pub(super) use crate::api::{ReadApiAccess, parse_api_agent_id};

// ── Shared request/response types (multiple agent sub-modules) ────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub(crate) struct AgentTaskQueuedResponse {
    agent_id: String,
    task_id: String,
    queued_jobs: usize,
}

/// Response body returned when an agent is deregistered via `?force` or
/// `?deregister_only`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub(crate) struct AgentDeregisteredResponse {
    agent_id: String,
    deregistered: bool,
}

/// Request body for `POST /agents/{id}/upload`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub(crate) struct AgentUploadRequest {
    /// Remote path on the target where the file should be written.
    pub(crate) remote_path: String,
    /// File content encoded as base64.
    pub(crate) content: String,
}

/// Request body for `POST /agents/{id}/download`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub(crate) struct AgentDownloadRequest {
    /// Remote path on the target to download.
    pub(crate) remote_path: String,
}

/// Response body for agent group membership endpoints.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AgentGroupsResponse {
    /// Hex-encoded agent id (e.g. `"DEADBEEF"`).
    pub agent_id: String,
    /// Group names the agent currently belongs to.
    pub groups: Vec<String>,
}

/// Request body for setting agent group membership.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SetAgentGroupsRequest {
    /// Replacement group list.  An empty array removes all memberships.
    pub groups: Vec<String>,
}

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub(crate) enum AgentApiError {
    #[error("{0}")]
    Teamserver(#[from] crate::TeamserverError),
    #[error("{0}")]
    Task(#[from] AgentCommandError),
    #[error("{0}")]
    Authorization(#[from] AuthorizationError),
}

impl IntoResponse for AgentApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::Teamserver(crate::TeamserverError::AgentNotFound { .. }) => {
                (StatusCode::NOT_FOUND, "agent_not_found")
            }
            Self::Task(
                AgentCommandError::InvalidAgentId { .. }
                | AgentCommandError::MissingAgentId
                | AgentCommandError::MissingNote
                | AgentCommandError::NoteTooLong { .. }
                | AgentCommandError::InvalidCommandId { .. }
                | AgentCommandError::MissingField { .. }
                | AgentCommandError::InvalidBooleanField { .. }
                | AgentCommandError::InvalidNumericField { .. }
                | AgentCommandError::InvalidBase64Field { .. }
                | AgentCommandError::UnsupportedProcessSubcommand { .. }
                | AgentCommandError::UnsupportedFilesystemSubcommand { .. }
                | AgentCommandError::UnsupportedTokenSubcommand { .. }
                | AgentCommandError::UnsupportedSocketSubcommand { .. }
                | AgentCommandError::UnsupportedKerberosSubcommand { .. }
                | AgentCommandError::UnsupportedInjectionWay { .. }
                | AgentCommandError::UnsupportedInjectionTechnique { .. }
                | AgentCommandError::UnsupportedArchitecture { .. }
                | AgentCommandError::InvalidProcessCreateArguments
                | AgentCommandError::InvalidRemovePayload
                | AgentCommandError::UnsupportedCommandId { .. },
            ) => (StatusCode::BAD_REQUEST, "invalid_agent_task"),
            Self::Task(AgentCommandError::Teamserver(crate::TeamserverError::AgentNotFound {
                ..
            })) => (StatusCode::NOT_FOUND, "agent_not_found"),
            Self::Teamserver(crate::TeamserverError::QueueFull { .. })
            | Self::Task(AgentCommandError::Teamserver(crate::TeamserverError::QueueFull {
                ..
            })) => (StatusCode::TOO_MANY_REQUESTS, "queue_full"),
            Self::Task(AgentCommandError::Authorization(
                AuthorizationError::AgentGroupDenied { .. }
                | AuthorizationError::ListenerAccessDenied { .. },
            ))
            | Self::Authorization(
                AuthorizationError::AgentGroupDenied { .. }
                | AuthorizationError::ListenerAccessDenied { .. },
            ) => (StatusCode::FORBIDDEN, "agent_access_denied"),
            Self::Teamserver(_) | Self::Task(_) | Self::Authorization(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "agent_api_error")
            }
        };

        json_error_response(status, code, self.to_string())
    }
}
