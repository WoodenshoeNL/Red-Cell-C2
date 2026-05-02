//! Debug-only agent endpoints (transport packet ring snapshots).

use axum::Json;
use axum::extract::{Path, Query, State};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::api::{ReadApiAccess, parse_api_agent_id};
use crate::app::TeamserverState;
use crate::corpus_capture::bytes_to_hex;

use super::AgentApiError;
use super::access::authorize_agent_access;

/// Query parameters for `GET /agents/{id}/debug/packet-ring`.
#[derive(Debug, Deserialize, IntoParams)]
pub(crate) struct PacketRingQuery {
    /// Number of frames to return per direction (default: 5, max: 20).
    n: Option<u8>,
}

/// A single captured raw transport frame from the per-agent ring-buffer.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct PacketRingFrame {
    /// Direction of the frame: `"rx"` (agent → teamserver) or `"tx"` (teamserver → agent).
    pub direction: String,
    /// Agent-protocol sequence number for this frame, if known.
    pub seq: Option<u64>,
    /// Raw frame bytes, hex-encoded.
    pub bytes_hex: String,
}

/// Response body for `GET /agents/{id}/debug/packet-ring`.
#[derive(Debug, Serialize, ToSchema)]
pub(crate) struct PacketRingResponse {
    /// Agent id in hex.
    pub agent_id: String,
    /// Requested frame count per direction.
    pub n: u8,
    /// Captured frames (last *n* per direction, oldest-first among the selection).
    pub frames: Vec<PacketRingFrame>,
    /// Optional human-readable note (reserved for future partial-capture cases).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'static str>,
}

#[utoipa::path(
    get,
    path = "/agents/{id}/debug/packet-ring",
    context_path = "/api/v1",
    tag = "agents",
    security(("api_key" = [])),
    params(
        ("id" = String, Path, description = "Agent id in hex (with optional 0x prefix)"),
        PacketRingQuery,
    ),
    responses(
        (status = 200, description = "Last N raw frames per direction from the in-memory ring-buffer", body = PacketRingResponse),
        (status = 400, description = "Invalid agent id", body = crate::api::ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = crate::api::ApiErrorBody),
        (status = 403, description = "API key role lacks permission", body = crate::api::ApiErrorBody),
        (status = 404, description = "Agent not found", body = crate::api::ApiErrorBody)
    )
)]
pub(crate) async fn get_agent_packet_ring(
    State(state): State<TeamserverState>,
    identity: ReadApiAccess,
    Path(id): Path<String>,
    Query(query): Query<PacketRingQuery>,
) -> Result<Json<PacketRingResponse>, AgentApiError> {
    let agent_id = parse_api_agent_id(&id)?;

    state
        .agent_registry
        .get(agent_id)
        .await
        .ok_or(crate::TeamserverError::AgentNotFound { agent_id })?;
    authorize_agent_access(&state, &identity.key_id, agent_id).await?;

    let n = query.n.unwrap_or(5).min(20);

    let captured = state.agent_registry.packet_ring_snapshot(agent_id, n).await;
    let frames: Vec<PacketRingFrame> = captured
        .into_iter()
        .map(|f| PacketRingFrame {
            direction: f.direction.as_str().to_owned(),
            seq: f.seq,
            bytes_hex: bytes_to_hex(&f.bytes),
        })
        .collect();

    Ok(Json(PacketRingResponse { agent_id: format!("{agent_id:08X}"), n, frames, note: None }))
}
