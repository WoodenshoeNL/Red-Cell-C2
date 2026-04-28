//! Request classification and top-level ECDH entrypoints.

use std::net::IpAddr;

use tracing::{debug, warn};

use red_cell_common::crypto::ecdh::{
    ECDH_REG_MIN_LEN, EcdhError, ListenerKeypair, extract_connection_id_candidate,
    open_registration_packet,
};

use crate::listeners::{
    ECDH_REGISTRATION_WINDOW_DURATION, EcdhRegistrationRateLimiter, ListenerManagerError,
    MAX_ECDH_REGISTRATIONS_PER_IP,
};
use crate::{AgentRegistry, CommandDispatcher, Database, events::EventBus};

use super::registration::process_ecdh_registration;
use super::session::process_ecdh_session;
use super::types::{ECDH_REPLAY_WINDOW_SECS, EcdhOutcome};

/// Returns `true` when the client IP is allowed to attempt an ECDH
/// registration; `false` if the per-IP budget for the current window has
/// been exhausted.  Logs a warning on rejection so operators can see the
/// source of abusive traffic.
///
/// This mirrors the `allow_demon_init_for_ip` helper used on the Archon
/// path, with the difference that every registration-shaped body counts
/// toward the budget (there is no cheap classification step that would let
/// us distinguish valid from invalid bodies before the AES-GCM tag check).
pub(crate) async fn allow_ecdh_registration_for_ip(
    listener_name: &str,
    rate_limiter: &EcdhRegistrationRateLimiter,
    client_ip: IpAddr,
) -> bool {
    if rate_limiter.allow(client_ip).await {
        return true;
    }

    warn!(
        listener = listener_name,
        client_ip = %client_ip,
        max_attempts = MAX_ECDH_REGISTRATIONS_PER_IP,
        window_seconds = ECDH_REGISTRATION_WINDOW_DURATION.as_secs(),
        "rejecting ECDH registration because the per-IP rate limit was exceeded"
    );
    false
}

/// Process a non-legacy HTTP body as an ECDH new-protocol packet.
///
/// First tries to classify as a session packet (connection_id lookup), then as
/// a registration packet. Returns [`EcdhOutcome::NotEcdh`] when the body is not
/// a valid ECDH packet (caller should fall through to the Archon handler) and
/// [`EcdhOutcome::RateLimited`] when a registration-shaped body is dropped by
/// the per-IP limiter (caller should return a fake 404).
///
/// Registration-shaped bodies are gated by a per-IP rate limiter applied before
/// the X25519 + AES-GCM work in [`open_registration_packet`].  Both valid and
/// invalid registration bodies consume budget so that an unauthenticated
/// source cannot force unbounded asymmetric crypto by spamming garbage.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn process_ecdh_packet(
    listener_name: &str,
    keypair: Option<&ListenerKeypair>,
    registry: &AgentRegistry,
    database: &Database,
    events: &EventBus,
    dispatcher: &CommandDispatcher,
    registration_rate_limiter: &EcdhRegistrationRateLimiter,
    body: &[u8],
    external_ip: IpAddr,
) -> Result<EcdhOutcome, ListenerManagerError> {
    let ecdh_db = database.ecdh();

    // Try session first: look up the first 16 bytes as a connection_id.
    if let Some(candidate_id) = extract_connection_id_candidate(body) {
        if let Ok(Some((agent_id, session_key))) = ecdh_db.lookup_session(&candidate_id).await {
            return Ok(EcdhOutcome::Handled(
                process_ecdh_session(
                    body,
                    &session_key,
                    agent_id,
                    &candidate_id,
                    ecdh_db,
                    dispatcher,
                    events,
                    listener_name,
                )
                .await?,
            ));
        }
    }

    // Try registration.
    let Some(kp) = keypair else {
        // Non-legacy listener without a keypair cannot handle ECDH registration.
        return Ok(EcdhOutcome::NotEcdh);
    };

    if body.len() < ECDH_REG_MIN_LEN {
        return Ok(EcdhOutcome::NotEcdh);
    }

    // Registration-shaped body — gate on the per-IP limiter before any
    // X25519 / AES-GCM work. Invalid bodies still consume budget so
    // garbage-packet spam cannot bypass the limiter.
    if !allow_ecdh_registration_for_ip(listener_name, registration_rate_limiter, external_ip).await
    {
        return Ok(EcdhOutcome::RateLimited);
    }

    let parsed = match open_registration_packet(kp, ECDH_REPLAY_WINDOW_SECS, body) {
        Ok(parsed) => parsed,
        Err(e) => {
            if matches!(&e, EcdhError::ReplayDetected) {
                warn!(
                    listener = listener_name,
                    client_ip = %external_ip,
                    window_secs = ECDH_REPLAY_WINDOW_SECS,
                    "ECDH registration rejected: agent timestamp outside replay window \
                     (synchronize system time on the agent and teamserver; max skew {}s)",
                    ECDH_REPLAY_WINDOW_SECS
                );
            } else {
                debug!(listener = listener_name, error = %e, "ECDH registration packet open failed");
            }
            return Ok(EcdhOutcome::NotEcdh);
        }
    };

    Ok(EcdhOutcome::Handled(
        process_ecdh_registration(
            listener_name,
            parsed.session_key,
            &parsed.metadata,
            registry,
            database,
            events,
            external_ip,
        )
        .await?,
    ))
}
