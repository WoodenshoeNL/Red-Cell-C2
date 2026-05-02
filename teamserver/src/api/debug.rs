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

use super::auth::AdminApiAccess;
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
    NoEcdhSession,
    Internal,
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
            Self::NoEcdhSession => (StatusCode::NOT_FOUND, "no ECDH session found for agent"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
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
        (status = 403, description = "Administrative API role required, or caller is not on loopback"),
        (status = 404, description = "Corpus capture inactive, agent not found, or no ECDH session"),
        (status = 401, description = "Missing or invalid API key", body = super::errors::ApiErrorBody),
        (status = 500, description = "Internal error retrieving ECDH session key"),
    )
)]
pub(super) async fn get_corpus_keys(
    State(state): State<TeamserverState>,
    _identity: AdminApiAccess,
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

    // Verify the agent exists before deciding which key path to use.
    state.agent_registry.encryption(agent_id).await.map_err(|_| CorpusKeysError::AgentNotFound)?;

    let agent_id_hex = format!("0x{agent_id:08x}");

    if state.agent_registry.is_ecdh_transport(agent_id).await {
        // ECDH/GCM agent: the AES-CTR key slot in the registry is intentionally
        // zeroed.  Fetch the real session key from ts_ecdh_sessions instead.
        let session_key = state
            .database
            .ecdh()
            .get_session_key_by_agent_id(agent_id)
            .await
            .map_err(|_| CorpusKeysError::Internal)?
            .ok_or(CorpusKeysError::NoEcdhSession)?;

        let keys = CorpusSessionKeys::new_gcm(bytes_to_hex(&session_key), agent_id_hex, None);
        return Ok(Json(keys));
    }

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
        agent_id_hex,
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
    use std::path::PathBuf;

    use crate::api::auth::{AdminApiAccess, ApiIdentity, ApiPermissionGuard, AuthMethod};
    use axum::extract::{ConnectInfo, Query, State};
    use red_cell_common::config::OperatorRole;
    use red_cell_common::crypto::ecdh::ConnectionId;
    use red_cell_common::{AgentEncryptionInfo, AgentRecord};
    use zeroize::Zeroizing;

    use super::*;

    const LOOPBACK: &str = "127.0.0.1:1234";

    fn admin_api_access_fixture() -> AdminApiAccess {
        ApiPermissionGuard::from_identity_for_test(ApiIdentity {
            key_id: "test-key".into(),
            role: OperatorRole::Admin,
            auth_method: AuthMethod::ApiKey,
        })
    }

    fn loopback_addr() -> std::net::SocketAddr {
        LOOPBACK.parse().expect("parse loopback")
    }

    /// Build a minimal AgentRecord with zeroed AES material (as used for ECDH agents).
    fn zero_key_agent(agent_id: u32) -> AgentRecord {
        AgentRecord {
            agent_id,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: AgentEncryptionInfo {
                aes_key: Zeroizing::new(vec![0u8; 32]),
                aes_iv: Zeroizing::new(vec![0u8; 16]),
                monotonic_ctr: false,
            },
            hostname: "test-host".to_owned(),
            username: "user".to_owned(),
            domain_name: "DOMAIN".to_owned(),
            external_ip: "1.2.3.4".to_owned(),
            internal_ip: "10.0.0.1".to_owned(),
            process_name: "test.exe".to_owned(),
            process_path: "C:\\test.exe".to_owned(),
            base_address: 0,
            process_pid: 1,
            process_tid: 1,
            process_ppid: 0,
            process_arch: "x64".to_owned(),
            elevated: false,
            os_version: "Windows 10".to_owned(),
            os_build: 0,
            os_arch: "x64".to_owned(),
            sleep_delay: 5,
            sleep_jitter: 0,
            kill_date: None,
            working_hours: None,
            first_call_in: "2026-01-01T00:00:00Z".to_owned(),
            last_call_in: "2026-01-01T00:00:00Z".to_owned(),
            archon_magic: None,
        }
    }

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

    #[test]
    fn corpus_keys_error_no_ecdh_session_is_not_found() {
        let resp = CorpusKeysError::NoEcdhSession.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn corpus_keys_error_internal_is_server_error() {
        let resp = CorpusKeysError::Internal.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// ECDH agent: the endpoint must return the real session key from
    /// `ts_ecdh_sessions`, not the all-zero AES-CTR key from the registry,
    /// and the encryption scheme must be `aes-256-gcm`.
    #[tokio::test]
    async fn get_corpus_keys_ecdh_returns_real_session_key_with_gcm_scheme() {
        let agent_id: u32 = 0xDEAD_BEEFu32;
        let real_session_key: [u8; 32] = {
            let mut k = [0u8; 32];
            for (i, b) in k.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(7).wrapping_add(13);
            }
            k
        };

        let mut state = crate::app::build_test_state().await;
        state.corpus_dir = Some(PathBuf::from("/tmp"));

        // Insert an ECDH agent with zeroed AES key (as done in registration.rs).
        state
            .agent_registry
            .insert_full(
                zero_key_agent(agent_id),
                "test-listener",
                0u64,
                false,
                true, // ecdh_transport = true
                false,
            )
            .await
            .expect("insert agent");

        // Persist a real session key in ts_ecdh_sessions.
        let conn_id = ConnectionId([1u8; 16]);
        state
            .database
            .ecdh()
            .store_session(&conn_id, agent_id, &real_session_key)
            .await
            .expect("store session");

        let result = get_corpus_keys(
            State(state),
            admin_api_access_fixture(),
            ConnectInfo(loopback_addr()),
            Query(CorpusKeysQuery { agent_id: format!("0x{agent_id:08x}") }),
        )
        .await
        .expect("handler should succeed");

        let keys = result.0;
        assert_eq!(
            keys.encryption_scheme.as_deref(),
            Some("aes-256-gcm"),
            "ECDH agent must report aes-256-gcm"
        );
        let expected_hex = bytes_to_hex(&real_session_key);
        assert_eq!(
            keys.aes_key_hex.as_deref(),
            Some(expected_hex.as_str()),
            "aes_key_hex must match the stored session key, not zeros"
        );
        // GCM has no IV / monotonic-ctr fields.
        assert!(keys.aes_iv_hex.is_none(), "aes_iv_hex must be None for GCM");
        assert!(keys.monotonic_ctr.is_none(), "monotonic_ctr must be None for GCM");
    }

    /// Non-ECDH (AES-CTR) agent: the endpoint must return the registry AES key
    /// and report `aes-256-ctr` as the scheme.
    #[tokio::test]
    async fn get_corpus_keys_ctr_returns_aes_key_with_ctr_scheme() {
        let agent_id: u32 = 0xCAFE_BABEu32;
        let aes_key: Vec<u8> = (0u8..32).collect();
        let aes_iv: Vec<u8> = (0u8..16).collect();

        let mut state = crate::app::build_test_state().await;
        state.corpus_dir = Some(PathBuf::from("/tmp"));

        let agent = AgentRecord {
            agent_id,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: AgentEncryptionInfo {
                aes_key: Zeroizing::new(aes_key.clone()),
                aes_iv: Zeroizing::new(aes_iv.clone()),
                monotonic_ctr: true,
            },
            hostname: "test-host".to_owned(),
            username: "user".to_owned(),
            domain_name: "DOMAIN".to_owned(),
            external_ip: "1.2.3.4".to_owned(),
            internal_ip: "10.0.0.1".to_owned(),
            process_name: "test.exe".to_owned(),
            process_path: "C:\\test.exe".to_owned(),
            base_address: 0,
            process_pid: 1,
            process_tid: 1,
            process_ppid: 0,
            process_arch: "x64".to_owned(),
            elevated: false,
            os_version: "Windows 10".to_owned(),
            os_build: 0,
            os_arch: "x64".to_owned(),
            sleep_delay: 5,
            sleep_jitter: 0,
            kill_date: None,
            working_hours: None,
            first_call_in: "2026-01-01T00:00:00Z".to_owned(),
            last_call_in: "2026-01-01T00:00:00Z".to_owned(),
            archon_magic: None,
        };

        state
            .agent_registry
            .insert_full(
                agent,
                "test-listener",
                0u64,
                false,
                false, // ecdh_transport = false
                false,
            )
            .await
            .expect("insert agent");

        let result = get_corpus_keys(
            State(state),
            admin_api_access_fixture(),
            ConnectInfo(loopback_addr()),
            Query(CorpusKeysQuery { agent_id: format!("0x{agent_id:08x}") }),
        )
        .await
        .expect("handler should succeed");

        let keys = result.0;
        assert_eq!(
            keys.encryption_scheme.as_deref(),
            Some("aes-256-ctr"),
            "non-ECDH agent must report aes-256-ctr"
        );
        assert_eq!(
            keys.aes_key_hex.as_deref(),
            Some(bytes_to_hex(&aes_key).as_str()),
            "aes_key_hex must match the registry AES key"
        );
        assert_eq!(
            keys.aes_iv_hex.as_deref(),
            Some(bytes_to_hex(&aes_iv).as_str()),
            "aes_iv_hex must match the registry IV"
        );
    }

    /// ECDH agent registered without a session row: asserts handler returns NoEcdhSession + 404.
    #[tokio::test]
    async fn get_corpus_keys_ecdh_missing_session_returns_404() {
        let agent_id: u32 = 0xBEEF_DEADu32;

        let mut state = crate::app::build_test_state().await;
        state.corpus_dir = Some(PathBuf::from("/tmp"));

        // Insert an ECDH agent, but deliberately skip store_session so the
        // ts_ecdh_sessions table has no row for this agent.
        state
            .agent_registry
            .insert_full(
                zero_key_agent(agent_id),
                "test-listener",
                0u64,
                false,
                true, // ecdh_transport = true
                false,
            )
            .await
            .expect("insert agent");

        let result = get_corpus_keys(
            State(state),
            admin_api_access_fixture(),
            ConnectInfo(loopback_addr()),
            Query(CorpusKeysQuery { agent_id: format!("0x{agent_id:08x}") }),
        )
        .await;

        let err = result.expect_err("handler must fail when ECDH session row is absent");
        assert!(
            matches!(err, CorpusKeysError::NoEcdhSession),
            "error must be NoEcdhSession, got {err:?}"
        );
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
