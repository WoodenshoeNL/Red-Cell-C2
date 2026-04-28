//! Agent file upload and download endpoints.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde_json::Value;

use red_cell_common::demon::{DemonCommand, DemonFilesystemCommand};
use red_cell_common::operator::{AgentTaskInfo, EventCode, Message, MessageHead};

use crate::app::TeamserverState;
use crate::events::broadcast_teamserver_warning;
use crate::websocket::{AgentCommandError, execute_agent_task};
use crate::{
    AuditResultStatus, audit_details, authorize_agent_group_access, authorize_listener_access,
    parameter_object,
};

use super::super::{TaskAgentApiAccess, next_task_id, parse_api_agent_id, record_audit_entry};
use super::{AgentApiError, AgentDownloadRequest, AgentTaskQueuedResponse, AgentUploadRequest};

#[utoipa::path(
    post,
    path = "/agents/{id}/upload",
    context_path = "/api/v1",
    tag = "agents",
    security(("api_key" = [])),
    params(("id" = String, Path, description = "Agent id in hex (with optional 0x prefix)")),
    request_body = AgentUploadRequest,
    responses(
        (status = 202, description = "Upload task queued", body = AgentTaskQueuedResponse),
        (status = 400, description = "Invalid agent id or payload", body = super::super::ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = super::super::ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = super::super::ApiErrorBody),
        (status = 404, description = "Agent not found", body = super::super::ApiErrorBody),
        (status = 429, description = "Agent task queue full", body = super::super::ApiErrorBody)
    )
)]
pub(crate) async fn agent_upload(
    State(state): State<TeamserverState>,
    identity: TaskAgentApiAccess,
    Path(id): Path<String>,
    Json(body): Json<AgentUploadRequest>,
) -> Result<(StatusCode, Json<AgentTaskQueuedResponse>), AgentApiError> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    let agent_id = parse_api_agent_id(&id)?;
    authorize_agent_group_access(&state.database, &identity.key_id, agent_id).await?;
    if let Some(listener_name) = state.agent_registry.listener_name(agent_id).await {
        authorize_listener_access(&state.database, &identity.key_id, &listener_name).await?;
    }
    let canonical_id = format!("{agent_id:08X}");
    let task_id = next_task_id();

    // Validate the base64 content before queuing.
    let _ = BASE64
        .decode(&body.content)
        .map_err(|_| AgentCommandError::MissingField { field: "content: invalid base64" })?;

    // Encode remote_path and content as the semicolon-delimited base64 pair that
    // the existing `build_upload_jobs` helper expects in `Arguments`.
    let remote_b64 = BASE64.encode(body.remote_path.as_bytes());
    let arguments = format!("{remote_b64};{}", body.content);

    let command_line = format!("upload {} (via REST API)", body.remote_path);
    let task = AgentTaskInfo {
        task_id: task_id.clone(),
        command_line: command_line.clone(),
        demon_id: canonical_id.clone(),
        command_id: u32::from(DemonCommand::CommandFs).to_string(),
        command: Some("upload".to_owned()),
        sub_command: Some(u32::from(DemonFilesystemCommand::Upload).to_string()),
        arguments: Some(arguments),
        ..AgentTaskInfo::default()
    };

    let message = Message {
        head: MessageHead {
            event: EventCode::Session,
            user: identity.key_id.clone(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: task,
    };

    let queued_jobs = match execute_agent_task(
        &state.agent_registry,
        &state.sockets,
        &state.events,
        &identity.key_id,
        identity.role,
        message,
    )
    .await
    {
        Ok(queued_jobs) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "agent.upload",
                "agent",
                Some(canonical_id.clone()),
                audit_details(
                    AuditResultStatus::Success,
                    Some(agent_id),
                    Some("upload"),
                    Some(parameter_object([
                        ("task_id", Value::String(task_id.clone())),
                        ("remote_path", Value::String(body.remote_path)),
                    ])),
                ),
            )
            .await;
            queued_jobs
        }
        Err(error) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "agent.upload",
                "agent",
                Some(canonical_id.clone()),
                audit_details(
                    AuditResultStatus::Failure,
                    Some(agent_id),
                    Some("upload"),
                    Some(parameter_object([
                        ("task_id", Value::String(task_id.clone())),
                        ("error", Value::String(error.to_string())),
                    ])),
                ),
            )
            .await;
            broadcast_teamserver_warning(
                &state.events,
                format!(
                    "[rest agent.upload] key={} agent={} upload task failed: {}",
                    identity.key_id, canonical_id, error
                ),
            );
            return Err(error.into());
        }
    };

    Ok((
        StatusCode::ACCEPTED,
        Json(AgentTaskQueuedResponse { agent_id: canonical_id, task_id, queued_jobs }),
    ))
}

#[utoipa::path(
    post,
    path = "/agents/{id}/download",
    context_path = "/api/v1",
    tag = "agents",
    security(("api_key" = [])),
    params(("id" = String, Path, description = "Agent id in hex (with optional 0x prefix)")),
    request_body = AgentDownloadRequest,
    responses(
        (status = 202, description = "Download task queued", body = AgentTaskQueuedResponse),
        (status = 401, description = "Missing or invalid API key", body = super::super::ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = super::super::ApiErrorBody),
        (status = 404, description = "Agent not found", body = super::super::ApiErrorBody),
        (status = 429, description = "Agent task queue full", body = super::super::ApiErrorBody)
    )
)]
pub(crate) async fn agent_download(
    State(state): State<TeamserverState>,
    identity: TaskAgentApiAccess,
    Path(id): Path<String>,
    Json(body): Json<AgentDownloadRequest>,
) -> Result<(StatusCode, Json<AgentTaskQueuedResponse>), AgentApiError> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;

    let agent_id = parse_api_agent_id(&id)?;
    authorize_agent_group_access(&state.database, &identity.key_id, agent_id).await?;
    if let Some(listener_name) = state.agent_registry.listener_name(agent_id).await {
        authorize_listener_access(&state.database, &identity.key_id, &listener_name).await?;
    }
    let canonical_id = format!("{agent_id:08X}");
    let task_id = next_task_id();

    // The filesystem download handler expects Arguments to be base64-encoded.
    let arguments_b64 = BASE64.encode(body.remote_path.as_bytes());

    let command_line = format!("download {} (via REST API)", body.remote_path);
    let task = AgentTaskInfo {
        task_id: task_id.clone(),
        command_line: command_line.clone(),
        demon_id: canonical_id.clone(),
        command_id: u32::from(DemonCommand::CommandFs).to_string(),
        command: Some("download".to_owned()),
        sub_command: Some(u32::from(DemonFilesystemCommand::Download).to_string()),
        arguments: Some(arguments_b64),
        ..AgentTaskInfo::default()
    };

    let message = Message {
        head: MessageHead {
            event: EventCode::Session,
            user: identity.key_id.clone(),
            timestamp: String::new(),
            one_time: String::new(),
        },
        info: task,
    };

    let queued_jobs = match execute_agent_task(
        &state.agent_registry,
        &state.sockets,
        &state.events,
        &identity.key_id,
        identity.role,
        message,
    )
    .await
    {
        Ok(queued_jobs) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "agent.download",
                "agent",
                Some(canonical_id.clone()),
                audit_details(
                    AuditResultStatus::Success,
                    Some(agent_id),
                    Some("download"),
                    Some(parameter_object([
                        ("task_id", Value::String(task_id.clone())),
                        ("remote_path", Value::String(body.remote_path)),
                    ])),
                ),
            )
            .await;
            queued_jobs
        }
        Err(error) => {
            record_audit_entry(
                &state.database,
                &state.webhooks,
                &identity.key_id,
                "agent.download",
                "agent",
                Some(canonical_id.clone()),
                audit_details(
                    AuditResultStatus::Failure,
                    Some(agent_id),
                    Some("download"),
                    Some(parameter_object([
                        ("task_id", Value::String(task_id.clone())),
                        ("error", Value::String(error.to_string())),
                    ])),
                ),
            )
            .await;
            broadcast_teamserver_warning(
                &state.events,
                format!(
                    "[rest agent.download] key={} agent={} download task failed: {}",
                    identity.key_id, canonical_id, error
                ),
            );
            return Err(error.into());
        }
    };

    Ok((
        StatusCode::ACCEPTED,
        Json(AgentTaskQueuedResponse { agent_id: canonical_id, task_id, queued_jobs }),
    ))
}
