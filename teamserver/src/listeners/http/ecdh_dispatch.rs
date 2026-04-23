//! ECDH packet processing for Phantom and Specter new-protocol agents.
//!
//! Incoming packets are classified as:
//! - **Registration**: first 16 bytes do NOT match a known `connection_id` in the DB,
//!   and length ≥ `ECDH_REG_MIN_LEN`. The server performs ECDH, registers the agent,
//!   and returns a response containing a new `ConnectionId` + encrypted ack.
//! - **Session**: first 16 bytes match a `connection_id` in the DB. The server decrypts
//!   the payload with the session key, routes to the command dispatcher, and returns
//!   an encrypted response.

use std::net::IpAddr;

use time::OffsetDateTime;
use tracing::{debug, warn};

use red_cell_common::crypto::ecdh::{
    ConnectionId, ECDH_REG_MIN_LEN, ListenerKeypair, build_registration_response,
    extract_connection_id_candidate, open_registration_packet, open_session_packet,
    seal_session_response,
};
use red_cell_common::demon::{DemonMessage, DemonPackage};

use crate::database::ecdh::EcdhRepository;

use crate::demon::parse_ecdh_agent_metadata;
use crate::listeners::{
    ECDH_REGISTRATION_WINDOW_DURATION, EcdhRegistrationRateLimiter, ListenerManagerError,
    MAX_ECDH_REGISTRATIONS_PER_IP,
};
use crate::{
    AgentRegistry, AuditResultStatus, CommandDispatcher, Database, DemonCallbackPackage,
    PluginRuntime, agent_events::agent_new_event, audit_details, events::EventBus,
    parameter_object, record_operator_action, sockets::AgentSocketSnapshot,
};

/// Replay-protection window: registration packets older or newer than this are rejected.
pub(crate) const ECDH_REPLAY_WINDOW_SECS: u64 = 300;

/// Result of processing an ECDH packet.
#[derive(Debug)]
pub(crate) struct EcdhResponse {
    pub(crate) payload: Vec<u8>,
}

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
/// a registration packet. Returns `None` if the packet is not a valid ECDH packet
/// (caller should fall through to the Archon handler).
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
) -> Result<Option<EcdhResponse>, ListenerManagerError> {
    let ecdh_db = database.ecdh();

    // Try session first: look up the first 16 bytes as a connection_id.
    if let Some(candidate_id) = extract_connection_id_candidate(body) {
        if let Ok(Some((agent_id, session_key))) = ecdh_db.lookup_session(&candidate_id).await {
            return Ok(Some(
                process_ecdh_session(
                    body,
                    &session_key,
                    agent_id,
                    &candidate_id,
                    ecdh_db,
                    dispatcher,
                )
                .await?,
            ));
        }
    }

    // Try registration.
    let Some(kp) = keypair else {
        // Non-legacy listener without a keypair cannot handle ECDH registration.
        return Ok(None);
    };

    if body.len() < ECDH_REG_MIN_LEN {
        return Ok(None);
    }

    // Registration-shaped body — gate on the per-IP limiter before any
    // X25519 / AES-GCM work. Invalid bodies still consume budget so
    // garbage-packet spam cannot bypass the limiter.
    if !allow_ecdh_registration_for_ip(listener_name, registration_rate_limiter, external_ip).await
    {
        return Err(ListenerManagerError::InvalidConfig {
            message: format!(
                "ECDH registration rejected: per-IP rate limit exceeded for {external_ip}"
            ),
        });
    }

    let parsed = match open_registration_packet(kp, ECDH_REPLAY_WINDOW_SECS, body) {
        Ok(parsed) => parsed,
        Err(e) => {
            debug!(listener = listener_name, error = %e, "ECDH registration packet failed to decrypt");
            return Ok(None);
        }
    };

    Ok(Some(
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

async fn process_ecdh_registration(
    listener_name: &str,
    session_key: [u8; 32],
    metadata: &[u8],
    registry: &AgentRegistry,
    database: &Database,
    events: &EventBus,
    external_ip: IpAddr,
) -> Result<EcdhResponse, ListenerManagerError> {
    let now = OffsetDateTime::now_utc();
    let external_ip_str = external_ip.to_string();

    let (agent, legacy_ctr, seq_protected) =
        parse_ecdh_agent_metadata(metadata, &external_ip_str, now).map_err(|e| {
            ListenerManagerError::InvalidConfig {
                message: format!("ECDH metadata parse failed: {e}"),
            }
        })?;

    let agent_id = agent.agent_id;

    // Register in registry + DB.  The ECDH agent has no AES key — use zeros
    // (the session key is stored separately in ts_ecdh_sessions).
    registry
        .insert_full(agent.clone(), listener_name, 0, legacy_ctr, true, seq_protected)
        .await
        .map_err(|e| ListenerManagerError::InvalidConfig {
            message: format!("ECDH agent registry insert failed: {e}"),
        })?;

    // Persist ECDH session: connection_id → (agent_id, session_key).
    let connection_id =
        ConnectionId::generate().map_err(|e| ListenerManagerError::InvalidConfig {
            message: format!("ECDH connection_id generation: {e}"),
        })?;

    database.ecdh().store_session(&connection_id, agent_id, &session_key).await.map_err(|e| {
        ListenerManagerError::InvalidConfig { message: format!("ECDH session store failed: {e}") }
    })?;

    // Build the registration response.
    let response =
        build_registration_response(&connection_id, &session_key, agent_id).map_err(|e| {
            ListenerManagerError::InvalidConfig {
                message: format!("ECDH build_registration_response failed: {e}"),
            }
        })?;

    // Emit events and audit.
    let pivots = registry.pivots(agent_id).await;
    events.broadcast(agent_new_event(
        listener_name,
        0, // no plaintext magic for new protocol
        &agent,
        &pivots,
        AgentSocketSnapshot::default(),
    ));

    let listener_name_for_audit = listener_name.to_owned();
    let external_ip_for_audit = external_ip.to_string();
    if let Err(error) = record_operator_action(
        database,
        "teamserver",
        "agent.registered",
        "agent",
        Some(format!("{agent_id:08X}")),
        audit_details(
            AuditResultStatus::Success,
            Some(agent_id),
            Some("registered"),
            Some(parameter_object([
                ("listener", serde_json::Value::String(listener_name_for_audit)),
                ("external_ip", serde_json::Value::String(external_ip_for_audit)),
                ("protocol", serde_json::Value::String("ecdh".into())),
            ])),
        ),
    )
    .await
    {
        warn!(
            listener = listener_name,
            agent_id = format_args!("{agent_id:08X}"),
            %error,
            "failed to persist ECDH agent.registered audit entry"
        );
    }

    if let Ok(Some(plugins)) = PluginRuntime::current() {
        if let Err(error) = plugins.emit_agent_registered(agent_id).await {
            tracing::warn!(
                agent_id = format_args!("{agent_id:08X}"),
                %error,
                "failed to emit python agent_registered event (ECDH)"
            );
        }
    }

    Ok(EcdhResponse { payload: response })
}

async fn process_ecdh_session(
    body: &[u8],
    session_key: &[u8; 32],
    agent_id: u32,
    connection_id: &[u8; 16],
    ecdh_db: EcdhRepository,
    dispatcher: &CommandDispatcher,
) -> Result<EcdhResponse, ListenerManagerError> {
    // body = [connection_id: 16] | [nonce: 12] | [ciphertext] | [tag: 16]
    let decrypted = open_session_packet(session_key, &body[16..]).map_err(|e| {
        ListenerManagerError::InvalidConfig { message: format!("ECDH session decrypt failed: {e}") }
    })?;

    let packages: Vec<DemonCallbackPackage> = if decrypted.is_empty() {
        Vec::new()
    } else {
        let (seq_num, payload) =
            parse_seq_num_prefix(&decrypted).map_err(|e| ListenerManagerError::InvalidConfig {
                message: format!("ECDH session seq_num prefix: {e}"),
            })?;

        // Reject replays: seq_num must be strictly greater than the last accepted.
        let accepted = ecdh_db.advance_seq_num(connection_id, seq_num).await.map_err(|e| {
            ListenerManagerError::InvalidConfig {
                message: format!("ECDH seq_num DB update failed: {e}"),
            }
        })?;

        if !accepted {
            return Err(ListenerManagerError::InvalidConfig {
                message: format!("ECDH session replay detected: seq_num {seq_num} already seen"),
            });
        }

        parse_ecdh_session_payload(payload)
            .map_err(|e| ListenerManagerError::InvalidConfig {
                message: format!("ECDH session payload parse failed: {e}"),
            })?
            .into_iter()
            .map(|p: DemonPackage| DemonCallbackPackage {
                command_id: p.command_id,
                request_id: p.request_id,
                payload: p.payload,
            })
            .collect()
    };

    // Packet is authenticated and seq-validated — now it is safe to refresh liveness.
    let _ = ecdh_db.touch_session(connection_id).await;

    let response_bytes = dispatcher
        .dispatch_packages(agent_id, &packages)
        .await
        .map_err(|e| ListenerManagerError::InvalidConfig { message: e.to_string() })?;

    let sealed = seal_session_response(session_key, &response_bytes).map_err(|e| {
        ListenerManagerError::InvalidConfig {
            message: format!("ECDH seal_session_response failed: {e}"),
        }
    })?;

    Ok(EcdhResponse { payload: sealed })
}

/// Strip the 8-byte little-endian seq_num prefix from the decrypted session payload.
///
/// Returns `(seq_num, remaining_bytes)`.
fn parse_seq_num_prefix(decrypted: &[u8]) -> Result<(u64, &[u8]), &'static str> {
    if decrypted.len() < 8 {
        return Err("payload too short for seq_num prefix (need ≥ 8 bytes)");
    }
    let seq_num = u64::from_le_bytes([
        decrypted[0],
        decrypted[1],
        decrypted[2],
        decrypted[3],
        decrypted[4],
        decrypted[5],
        decrypted[6],
        decrypted[7],
    ]);
    Ok((seq_num, &decrypted[8..]))
}

fn parse_ecdh_session_payload(bytes: &[u8]) -> Result<Vec<DemonPackage>, String> {
    DemonMessage::from_bytes(bytes)
        .map(|msg| msg.packages)
        .map_err(|e| format!("DemonMessage parse: {e}"))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use red_cell_common::crypto::ecdh::{ListenerKeypair, build_registration_packet};
    use sqlx::Row;

    use crate::AgentRegistry;
    use crate::database::{Database, DbMasterKey, EcdhRepository};
    use crate::dispatch::CommandDispatcher;
    use crate::events::EventBus;
    use crate::listeners::MAX_ECDH_REGISTRATIONS_PER_IP;

    use super::*;

    async fn test_ecdh_db() -> (Database, EcdhRepository) {
        let db = Database::connect_in_memory().await.expect("db");
        let master_key = Arc::new(DbMasterKey::random().expect("master key"));
        let repo = EcdhRepository::new(db.pool().clone(), master_key);
        (db, repo)
    }

    /// Build the fixed scaffolding shared by the `process_ecdh_packet`
    /// integration tests: an in-memory database, registry, event bus,
    /// dispatcher, listener keypair, and a fresh ECDH registration limiter.
    async fn ecdh_test_fixture() -> (
        Database,
        AgentRegistry,
        EventBus,
        CommandDispatcher,
        ListenerKeypair,
        EcdhRegistrationRateLimiter,
    ) {
        let db = Database::connect_in_memory().await.expect("db");
        let registry = AgentRegistry::new(db.clone());
        let events = EventBus::default();
        let dispatcher = CommandDispatcher::new();
        let keypair = ListenerKeypair::generate().expect("keypair");
        let limiter = EcdhRegistrationRateLimiter::new();
        (db, registry, events, dispatcher, keypair, limiter)
    }

    /// Length-adequate but cryptographically invalid registration body —
    /// `open_registration_packet` will fail on the AEAD tag check.  The
    /// body still crosses the `ECDH_REG_MIN_LEN` threshold so the limiter
    /// must treat the attempt as a registration.
    fn invalid_registration_body() -> Vec<u8> {
        vec![0xAB; ECDH_REG_MIN_LEN]
    }

    /// Cryptographically valid registration body built against `keypair` but
    /// carrying metadata that will fail `parse_ecdh_agent_metadata`.  The
    /// limiter must fire before metadata parsing begins.
    fn valid_registration_body(keypair: &ListenerKeypair) -> Vec<u8> {
        let (packet, _session_key) =
            build_registration_packet(&keypair.public_bytes, b"unused-metadata")
                .expect("build ECDH registration packet");
        packet
    }

    async fn query_last_seen(db: &Database, conn_id: &[u8; 16]) -> i64 {
        sqlx::query("SELECT last_seen FROM ts_ecdh_sessions WHERE connection_id = ?")
            .bind(conn_id.as_slice())
            .fetch_one(db.pool())
            .await
            .expect("row")
            .get(0)
    }

    /// Invalid ciphertext must not advance `last_seen` — regression for the
    /// pre-auth touch_session bug.
    #[tokio::test]
    async fn invalid_ciphertext_does_not_refresh_last_seen() {
        let (db, repo) = test_ecdh_db().await;
        let conn_id = red_cell_common::crypto::ecdh::ConnectionId::generate().expect("conn_id");
        let session_key = [0u8; 32];
        repo.store_session(&conn_id, 1, &session_key).await.expect("store");

        let last_seen_before = query_last_seen(&db, &conn_id.0).await;

        // Build a body: [connection_id: 16] | [nonce: 12] | [garbage ciphertext: 1] | [bad tag: 16]
        let mut body = Vec::with_capacity(16 + 12 + 1 + 16);
        body.extend_from_slice(&conn_id.0);
        body.extend_from_slice(&[0u8; 12]); // nonce
        body.push(0xAB); // ciphertext byte
        body.extend_from_slice(&[0u8; 16]); // bad tag

        let dispatcher = CommandDispatcher::new();
        let result =
            process_ecdh_session(&body, &session_key, 1, &conn_id.0, repo, &dispatcher).await;
        assert!(result.is_err(), "expected decrypt failure");

        let last_seen_after = query_last_seen(&db, &conn_id.0).await;
        assert_eq!(last_seen_before, last_seen_after, "last_seen must not change on failed auth");
    }

    #[test]
    fn parse_seq_num_prefix_round_trips() {
        let seq: u64 = 0xDEAD_BEEF_1234_5678;
        let payload = b"hello world";
        let mut buf = seq.to_le_bytes().to_vec();
        buf.extend_from_slice(payload);

        let (got_seq, got_payload) = parse_seq_num_prefix(&buf).expect("parse");
        assert_eq!(got_seq, seq);
        assert_eq!(got_payload, payload);
    }

    #[test]
    fn parse_seq_num_prefix_zero() {
        let mut buf = 0u64.to_le_bytes().to_vec();
        buf.push(0xAB);
        let (seq, rest) = parse_seq_num_prefix(&buf).expect("parse");
        assert_eq!(seq, 0);
        assert_eq!(rest, &[0xAB]);
    }

    #[test]
    fn parse_seq_num_prefix_exact_8_bytes() {
        let buf = 42u64.to_le_bytes().to_vec();
        let (seq, rest) = parse_seq_num_prefix(&buf).expect("parse");
        assert_eq!(seq, 42);
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_seq_num_prefix_too_short_fails() {
        assert!(parse_seq_num_prefix(&[0u8; 7]).is_err());
        assert!(parse_seq_num_prefix(&[]).is_err());
    }

    // ── ECDH registration rate limiter ────────────────────────────────────

    /// `allow_ecdh_registration_for_ip` must reject a source IP once it has
    /// used up its per-IP budget in the current window.
    #[tokio::test]
    async fn allow_ecdh_registration_for_ip_blocks_after_budget_exhausted() {
        let limiter = EcdhRegistrationRateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

        for _ in 0..MAX_ECDH_REGISTRATIONS_PER_IP {
            assert!(
                allow_ecdh_registration_for_ip("test-listener", &limiter, ip).await,
                "attempts under the budget must be allowed"
            );
        }

        assert!(
            !allow_ecdh_registration_for_ip("test-listener", &limiter, ip).await,
            "budget-exceeding attempt must be rejected"
        );

        // A different IP must still be allowed — budget is per-IP.
        let other_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8));
        assert!(
            allow_ecdh_registration_for_ip("test-listener", &limiter, other_ip).await,
            "a second IP must have its own budget"
        );
    }

    /// Invalid ECDH registration bodies (garbage bytes of length ≥
    /// `ECDH_REG_MIN_LEN`) must consume the per-IP budget so that
    /// garbage-packet spam cannot bypass the limiter and still trigger
    /// the X25519 + AES-GCM work the helper exists to prevent.
    #[tokio::test]
    async fn process_ecdh_packet_rate_limits_invalid_registrations() {
        let (db, registry, events, dispatcher, keypair, limiter) = ecdh_test_fixture().await;
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42));
        let body = invalid_registration_body();

        // Send MAX invalid registrations — each returns Ok(None) (crypto fails)
        // but each consumes one budget slot.
        for _ in 0..MAX_ECDH_REGISTRATIONS_PER_IP {
            let result = process_ecdh_packet(
                "test-listener",
                Some(&keypair),
                &registry,
                &db,
                &events,
                &dispatcher,
                &limiter,
                &body,
                ip,
            )
            .await;
            assert!(
                matches!(result, Ok(None)),
                "invalid body must decrypt-fail but not trigger rate limiter yet; got: {result:?}"
            );
        }

        // The next attempt from the same IP must be rejected.
        let blocked = process_ecdh_packet(
            "test-listener",
            Some(&keypair),
            &registry,
            &db,
            &events,
            &dispatcher,
            &limiter,
            &body,
            ip,
        )
        .await;
        assert!(
            matches!(blocked, Err(ListenerManagerError::InvalidConfig { ref message })
                if message.contains("rate limit")),
            "invalid registration must be rate-limited after budget exhaustion; got: {blocked:?}"
        );
    }

    /// Valid ECDH registration bodies (cryptographically correct packets
    /// against the listener keypair, but carrying unparseable metadata)
    /// must also consume budget and be rejected once the limit is hit.
    /// This guards the expensive X25519 + AES-GCM path from unbounded
    /// abuse by a source that happens to know the listener's public key.
    #[tokio::test]
    async fn process_ecdh_packet_rate_limits_valid_registrations() {
        let (db, registry, events, dispatcher, keypair, limiter) = ecdh_test_fixture().await;
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 43));

        for _ in 0..MAX_ECDH_REGISTRATIONS_PER_IP {
            // Each iteration builds a fresh packet with a new ephemeral pubkey
            // so the server cannot dedupe by shape.
            let body = valid_registration_body(&keypair);
            let _ = process_ecdh_packet(
                "test-listener",
                Some(&keypair),
                &registry,
                &db,
                &events,
                &dispatcher,
                &limiter,
                &body,
                ip,
            )
            .await;
        }

        // The (MAX + 1)th valid registration attempt from the same IP must be
        // rejected by the limiter, regardless of body validity.
        let body = valid_registration_body(&keypair);
        let blocked = process_ecdh_packet(
            "test-listener",
            Some(&keypair),
            &registry,
            &db,
            &events,
            &dispatcher,
            &limiter,
            &body,
            ip,
        )
        .await;
        assert!(
            matches!(blocked, Err(ListenerManagerError::InvalidConfig { ref message })
                if message.contains("rate limit")),
            "valid registration must be rate-limited after budget exhaustion; got: {blocked:?}"
        );

        // A different IP is still allowed — budget is per-IP.
        let other_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 44));
        let body = valid_registration_body(&keypair);
        let other_result = process_ecdh_packet(
            "test-listener",
            Some(&keypair),
            &registry,
            &db,
            &events,
            &dispatcher,
            &limiter,
            &body,
            other_ip,
        )
        .await;
        assert!(
            !matches!(other_result, Err(ListenerManagerError::InvalidConfig { ref message })
                if message.contains("rate limit")),
            "a fresh IP must not be rate-limited; got: {other_result:?}"
        );
    }

    /// Bodies shorter than `ECDH_REG_MIN_LEN` are not registration
    /// candidates and must not consume the limiter's budget — otherwise
    /// an attacker could exhaust it with tiny garbage packets.
    #[tokio::test]
    async fn process_ecdh_packet_short_body_does_not_consume_budget() {
        let (db, registry, events, dispatcher, keypair, limiter) = ecdh_test_fixture().await;
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 45));
        let short = vec![0xCDu8; ECDH_REG_MIN_LEN - 1];

        // Send many short bodies — they fall through (Ok(None)) without
        // consuming budget.
        for _ in 0..(MAX_ECDH_REGISTRATIONS_PER_IP * 2) {
            let result = process_ecdh_packet(
                "test-listener",
                Some(&keypair),
                &registry,
                &db,
                &events,
                &dispatcher,
                &limiter,
                &short,
                ip,
            )
            .await;
            assert!(
                matches!(result, Ok(None)),
                "short body must fall through to Archon path; got: {result:?}"
            );
        }

        // The IP must still have a full budget available for real attempts.
        assert_eq!(
            limiter.tracked_ip_count().await,
            0,
            "short bodies must not register an entry in the limiter"
        );
    }

    /// ECDH session packets (first 16 bytes match a known `connection_id`)
    /// must not consume the registration budget — legitimate agents keep
    /// calling back with session packets and would otherwise DoS themselves.
    #[tokio::test]
    async fn process_ecdh_packet_session_does_not_consume_budget() {
        let (db, registry, events, dispatcher, keypair, limiter) = ecdh_test_fixture().await;
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 46));

        // Store an ECDH session so the session-lookup path fires first.
        let conn_id = red_cell_common::crypto::ecdh::ConnectionId::generate().expect("conn_id");
        let session_key = [0u8; 32];
        db.ecdh().store_session(&conn_id, 1, &session_key).await.expect("store");

        // Body: [connection_id: 16] | [nonce: 12] | [ciphertext: 1] | [bad tag: 16]
        let mut body = Vec::with_capacity(16 + 12 + 1 + 16);
        body.extend_from_slice(&conn_id.0);
        body.extend_from_slice(&[0u8; 12]);
        body.push(0xAB);
        body.extend_from_slice(&[0u8; 16]);

        // The session path is taken (matched connection_id) and returns Err
        // on AEAD failure — but the registration limiter is never touched.
        for _ in 0..(MAX_ECDH_REGISTRATIONS_PER_IP * 2) {
            let _ = process_ecdh_packet(
                "test-listener",
                Some(&keypair),
                &registry,
                &db,
                &events,
                &dispatcher,
                &limiter,
                &body,
                ip,
            )
            .await;
        }

        assert_eq!(
            limiter.tracked_ip_count().await,
            0,
            "session packets must never register an entry in the registration limiter"
        );
    }

    /// Listeners without a keypair (mis-configured non-legacy listeners)
    /// cannot handle ECDH registrations at all, so registration-shaped
    /// bodies must fall through to Archon without consuming budget.
    #[tokio::test]
    async fn process_ecdh_packet_no_keypair_does_not_consume_budget() {
        let (db, registry, events, dispatcher, _keypair, limiter) = ecdh_test_fixture().await;
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 47));
        let body = invalid_registration_body();

        for _ in 0..(MAX_ECDH_REGISTRATIONS_PER_IP * 2) {
            let result = process_ecdh_packet(
                "test-listener",
                None,
                &registry,
                &db,
                &events,
                &dispatcher,
                &limiter,
                &body,
                ip,
            )
            .await;
            assert!(
                matches!(result, Ok(None)),
                "no-keypair must fall through to Archon; got: {result:?}"
            );
        }

        assert_eq!(
            limiter.tracked_ip_count().await,
            0,
            "no-keypair path must not touch the limiter"
        );
    }

    // ── ECDH registration seq_protected persistence ─────────────────────
    //
    // Helpers for building valid ECDH init metadata inline — the demon
    // test module is private, so we reconstruct the payload layout here.

    fn put_u32_be(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_be_bytes());
    }

    fn put_u64_be(buf: &mut Vec<u8>, v: u64) {
        buf.extend_from_slice(&v.to_be_bytes());
    }

    fn put_str_be(buf: &mut Vec<u8>, s: &str) {
        let bytes = s.as_bytes();
        put_u32_be(buf, u32::try_from(bytes.len()).expect("str len fits in u32"));
        buf.extend_from_slice(bytes);
    }

    fn put_utf16_be(buf: &mut Vec<u8>, s: &str) {
        let utf16: Vec<u16> = s.encode_utf16().collect();
        let nbytes = utf16.len() * 2;
        put_u32_be(buf, u32::try_from(nbytes).expect("utf16 len fits in u32"));
        for unit in utf16 {
            buf.extend_from_slice(&unit.to_be_bytes());
        }
    }

    fn build_ecdh_init_metadata(agent_id: u32, ext_flags: u32) -> Vec<u8> {
        let mut m = Vec::new();
        put_u32_be(&mut m, agent_id);
        put_str_be(&mut m, "wkstn-01");
        put_str_be(&mut m, "operator");
        put_str_be(&mut m, "REDCELL");
        put_str_be(&mut m, "10.0.0.25");
        put_utf16_be(&mut m, "C:\\Windows\\explorer.exe");
        put_u32_be(&mut m, 1337); // process_pid
        put_u32_be(&mut m, 1338); // process_tid
        put_u32_be(&mut m, 512); // process_ppid
        put_u32_be(&mut m, 2); // process_arch
        put_u32_be(&mut m, 1); // elevated
        put_u64_be(&mut m, 0x0040_1000); // base_address
        put_u32_be(&mut m, 10); // os major
        put_u32_be(&mut m, 0); // os minor
        put_u32_be(&mut m, 1); // os product type
        put_u32_be(&mut m, 0); // os service pack
        put_u32_be(&mut m, 22000); // os build
        put_u32_be(&mut m, 9); // os arch
        put_u32_be(&mut m, 15); // sleep delay
        put_u32_be(&mut m, 20); // sleep jitter
        put_u64_be(&mut m, 1_893_456_000); // kill date
        m.extend_from_slice(&0_i32.to_be_bytes()); // working hours
        put_u32_be(&mut m, ext_flags);
        m
    }

    /// Regression for red-cell-c2-pivna: an ECDH registration that sets
    /// `INIT_EXT_SEQ_PROTECTED` must register the agent with
    /// `seq_protected = true` both in the in-memory registry and in the
    /// persisted row, so `handle_checkin` does not emit a bogus replay
    /// warning and any future logic keyed off `is_seq_protected()` sees
    /// the correct state.
    #[tokio::test]
    async fn ecdh_registration_persists_seq_protected_flag() {
        use crate::demon::{INIT_EXT_MONOTONIC_CTR, INIT_EXT_SEQ_PROTECTED};

        let (db, registry, events, _dispatcher, keypair, _limiter) = ecdh_test_fixture().await;
        let agent_id: u32 = 0xFEED_BEEF;
        let metadata =
            build_ecdh_init_metadata(agent_id, INIT_EXT_MONOTONIC_CTR | INIT_EXT_SEQ_PROTECTED);
        let (packet, _session_key) =
            build_registration_packet(&keypair.public_bytes, &metadata).expect("build packet");

        let limiter = EcdhRegistrationRateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 99));
        let dispatcher = CommandDispatcher::new();
        let resp = process_ecdh_packet(
            "test-listener",
            Some(&keypair),
            &registry,
            &db,
            &events,
            &dispatcher,
            &limiter,
            &packet,
            ip,
        )
        .await
        .expect("registration should succeed");
        assert!(resp.is_some(), "expected registration response");

        assert!(
            registry.is_seq_protected(agent_id).await,
            "ECDH registration with INIT_EXT_SEQ_PROTECTED must set registry.is_seq_protected = true"
        );

        let persisted =
            db.agents().get_persisted(agent_id).await.expect("db query").expect("agent row");
        assert!(
            persisted.seq_protected,
            "ECDH registration with INIT_EXT_SEQ_PROTECTED must persist seq_protected = true"
        );
    }

    /// Counterpart: an ECDH registration that does NOT set
    /// `INIT_EXT_SEQ_PROTECTED` must leave `seq_protected = false`.
    #[tokio::test]
    async fn ecdh_registration_without_seq_protected_flag_defaults_false() {
        use crate::demon::INIT_EXT_MONOTONIC_CTR;

        let (db, registry, events, _dispatcher, keypair, _limiter) = ecdh_test_fixture().await;
        let agent_id: u32 = 0xC0FF_EE01;
        let metadata = build_ecdh_init_metadata(agent_id, INIT_EXT_MONOTONIC_CTR);
        let (packet, _session_key) =
            build_registration_packet(&keypair.public_bytes, &metadata).expect("build packet");

        let limiter = EcdhRegistrationRateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 100));
        let dispatcher = CommandDispatcher::new();
        process_ecdh_packet(
            "test-listener",
            Some(&keypair),
            &registry,
            &db,
            &events,
            &dispatcher,
            &limiter,
            &packet,
            ip,
        )
        .await
        .expect("registration should succeed");

        assert!(!registry.is_seq_protected(agent_id).await);
        let persisted =
            db.agents().get_persisted(agent_id).await.expect("db query").expect("agent row");
        assert!(!persisted.seq_protected);
    }
}
