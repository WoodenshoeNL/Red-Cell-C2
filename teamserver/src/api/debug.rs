//! `GET /api/v1/debug/corpus-keys` — fetch AES session keys for a captured agent.
//!
//! This endpoint is only active when the teamserver was started with
//! `--capture-corpus`.  It is restricted to loopback connections so that
//! the Python test harness can retrieve key material without it being
//! reachable from the network.

use std::net::{IpAddr, SocketAddr};

use axum::Json;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use red_cell_common::corpus::CorpusSessionKeys;
use serde::Deserialize;
use utoipa::IntoParams;

use crate::app::TeamserverState;
use crate::corpus_capture::bytes_to_hex;

use super::parse_api_agent_id;

/// Query parameters for `GET /debug/corpus-keys`.
#[derive(Debug, Deserialize, IntoParams)]
pub(super) struct CorpusKeysQuery {
    /// Agent ID in hex (e.g. `0xDEADBEEF` or `DEADBEEF`).
    agent_id: String,
}

/// Error type for corpus-keys endpoint failures.
#[derive(Debug)]
pub(super) enum CorpusKeysError {
    NotEnabled,
    NotLoopback,
    AgentNotFound,
    InvalidAgentId,
}

impl IntoResponse for CorpusKeysError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::NotEnabled => (StatusCode::NOT_FOUND, "corpus capture is not active"),
            Self::NotLoopback => {
                (StatusCode::FORBIDDEN, "this endpoint is only accessible from loopback")
            }
            Self::AgentNotFound => (StatusCode::NOT_FOUND, "agent not found"),
            Self::InvalidAgentId => (StatusCode::BAD_REQUEST, "invalid agent_id"),
        };
        (status, body).into_response()
    }
}

#[utoipa::path(
    get,
    path = "/debug/corpus-keys",
    context_path = "/api/v1",
    tag = "rest",
    params(CorpusKeysQuery),
    security(("api_key" = [])),
    responses(
        (status = 200, description = "AES session key material for the agent", body = CorpusSessionKeys),
        (status = 400, description = "Invalid agent_id parameter"),
        (status = 403, description = "Not a loopback connection"),
        (status = 404, description = "Corpus capture inactive or agent not found"),
        (status = 401, description = "Missing or invalid API key", body = super::errors::ApiErrorBody),
    )
)]
pub(super) async fn get_corpus_keys(
    State(state): State<TeamserverState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(query): Query<CorpusKeysQuery>,
) -> Result<Json<CorpusSessionKeys>, CorpusKeysError> {
    // Only accessible when corpus capture mode is active.
    if state.corpus_dir.is_none() {
        return Err(CorpusKeysError::NotEnabled);
    }

    // Restrict to loopback to protect raw key material from network exposure.
    if !is_loopback(peer.ip()) {
        return Err(CorpusKeysError::NotLoopback);
    }

    let agent_id =
        parse_api_agent_id(&query.agent_id).map_err(|_| CorpusKeysError::InvalidAgentId)?;

    let enc = state
        .agent_registry
        .encryption(agent_id)
        .await
        .map_err(|_| CorpusKeysError::AgentNotFound)?;

    let is_legacy = state.agent_registry.legacy_ctr(agent_id).await.unwrap_or(true);

    let keys = CorpusSessionKeys::new(
        bytes_to_hex(enc.aes_key.as_slice()),
        bytes_to_hex(enc.aes_iv.as_slice()),
        !is_legacy,
        0,
        format!("0x{agent_id:08x}"),
    );

    Ok(Json(keys))
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_127_0_0_1_is_accepted() {
        assert!(is_loopback("127.0.0.1".parse().expect("parse")));
    }

    #[test]
    fn loopback_ipv6_is_accepted() {
        assert!(is_loopback("::1".parse().expect("parse")));
    }

    #[test]
    fn non_loopback_is_rejected() {
        assert!(!is_loopback("192.168.1.1".parse().expect("parse")));
        assert!(!is_loopback("10.0.0.1".parse().expect("parse")));
        assert!(!is_loopback("2001:db8::1".parse().expect("parse")));
    }

    #[test]
    fn corpus_keys_error_not_enabled_is_not_found() {
        let resp = CorpusKeysError::NotEnabled.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn corpus_keys_error_not_loopback_is_forbidden() {
        let resp = CorpusKeysError::NotLoopback.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn corpus_keys_error_agent_not_found_is_not_found() {
        let resp = CorpusKeysError::AgentNotFound.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn corpus_keys_error_invalid_agent_id_is_bad_request() {
        let resp = CorpusKeysError::InvalidAgentId.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
