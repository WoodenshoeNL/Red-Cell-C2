use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use red_cell_common::crypto::ecdh::{ECDH_REG_MIN_LEN, ListenerKeypair, build_registration_packet};
use red_cell_common::demon::{ArchonEnvelope, DemonCommand};
use sqlx::Row;

use crate::AgentRegistry;
use crate::database::{Database, DbMasterKey, EcdhRepository};
use crate::dispatch::CommandDispatcher;
use crate::events::EventBus;
use crate::listeners::MAX_ECDH_REGISTRATIONS_PER_IP;

use super::classify::{allow_ecdh_registration_for_ip, process_ecdh_packet};
use super::parse::parse_seq_num_prefix;
use super::registration::process_ecdh_registration;
use super::session::{EcdhSessionContext, process_ecdh_session};
use super::types::EcdhOutcome;
use crate::listeners::EcdhRegistrationRateLimiter;
use crate::listeners::http::test_helpers::build_ecdh_metadata;

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

    let registry = AgentRegistry::new(db.clone());
    let dispatcher = CommandDispatcher::new();
    let events = EventBus::default();
    let result = process_ecdh_session(
        &body,
        &session_key,
        1,
        &conn_id.0,
        EcdhSessionContext {
            ecdh_db: repo,
            registry: &registry,
            dispatcher: &dispatcher,
            events: &events,
            listener_name: "test-listener",
        },
    )
    .await;
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

    // Send MAX invalid registrations — each returns NotEcdh (crypto fails)
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
            matches!(result, Ok(EcdhOutcome::NotEcdh)),
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
        matches!(blocked, Ok(EcdhOutcome::RateLimited)),
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
        matches!(blocked, Ok(EcdhOutcome::RateLimited)),
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
        !matches!(other_result, Ok(EcdhOutcome::RateLimited)),
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

    // Send many short bodies — they fall through (NotEcdh) without
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
            matches!(result, Ok(EcdhOutcome::NotEcdh)),
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
            matches!(result, Ok(EcdhOutcome::NotEcdh)),
            "no-keypair must fall through to Archon; got: {result:?}"
        );
    }

    assert_eq!(limiter.tracked_ip_count().await, 0, "no-keypair path must not touch the limiter");
}

/// Archon INIT/callback packets are large enough to pass the ECDH_REG_MIN_LEN
/// threshold but must NOT consume the ECDH registration budget. The
/// ArchonEnvelope size-field validation reliably distinguishes them from ECDH
/// registration packets (whose first 4 bytes are random X25519 key material).
///
/// Regression test: stale Archon agents from previous runs would exhaust the
/// per-IP ECDH budget, blocking the new Archon agent's DEMON_INIT.
#[tokio::test]
async fn process_ecdh_packet_archon_body_does_not_consume_budget() {
    let (db, registry, events, dispatcher, keypair, limiter) = ecdh_test_fixture().await;
    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 48));

    let cmd = u32::from(DemonCommand::DemonInit);
    let mut payload = Vec::new();
    payload.extend_from_slice(&cmd.to_be_bytes());
    payload.extend_from_slice(&0u32.to_be_bytes()); // request_id
    payload.extend_from_slice(&[0xAA; 80]); // simulated key + encrypted metadata

    let body =
        ArchonEnvelope::new(0x1234_5678, 0xCAFE_BABE, payload).expect("archon envelope").to_bytes();
    assert!(
        body.len() >= ECDH_REG_MIN_LEN,
        "Archon body must be large enough to cross the ECDH threshold"
    );

    for _ in 0..(MAX_ECDH_REGISTRATIONS_PER_IP * 2) {
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
            matches!(result, Ok(EcdhOutcome::NotEcdh)),
            "Archon body must fall through to Demon transport; got: {result:?}"
        );
    }

    assert_eq!(
        limiter.tracked_ip_count().await,
        0,
        "Archon packets must not register an entry in the ECDH registration limiter"
    );
}

// ── ECDH registration seq_protected persistence ─────────────────────

fn build_ecdh_init_metadata(agent_id: u32, ext_flags: u32) -> Vec<u8> {
    build_ecdh_metadata(agent_id, "wkstn-01", "10.0.0.25", 1337, 1338, 1, ext_flags)
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
    assert!(
        matches!(resp, EcdhOutcome::Handled(_)),
        "expected registration response; got: {resp:?}"
    );

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

// ── Ghost-agent rollback tests ────────────────────────────────────────

async fn count_ecdh_sessions_for_agent(db: &Database, agent_id: u32) -> i64 {
    sqlx::query("SELECT COUNT(*) FROM ts_ecdh_sessions WHERE agent_id = ?")
        .bind(i64::from(agent_id))
        .fetch_one(db.pool())
        .await
        .expect("count query")
        .get(0)
}

/// A duplicate registration (same agent_id) must not leave an orphaned
/// ECDH session row.  Before the fix, `insert_full` was called first —
/// if it succeeded the first time and a later step failed, a ghost agent
/// row was left behind.  After the reorder, `insert_full` is last, and
/// its failure triggers cleanup of the session row it cannot own.
#[tokio::test]
async fn duplicate_registration_does_not_leak_session_row() {
    use crate::demon::INIT_EXT_MONOTONIC_CTR;

    let (db, registry, events, _dispatcher, _keypair, _limiter) = ecdh_test_fixture().await;
    let agent_id: u32 = 0xDEAD_0001;
    let session_key = [0x42u8; 32];
    let metadata = build_ecdh_init_metadata(agent_id, INIT_EXT_MONOTONIC_CTR);
    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 200));

    // First registration must succeed.
    let result = process_ecdh_registration(
        "test-listener",
        session_key,
        &metadata,
        &registry,
        &db,
        &events,
        ip,
        None,
    )
    .await;
    assert!(result.is_ok(), "first registration must succeed; got: {result:?}");
    assert_eq!(count_ecdh_sessions_for_agent(&db, agent_id).await, 1);
    assert!(registry.get(agent_id).await.is_some(), "agent must be in registry");

    // Second registration with the same agent_id must fail (DuplicateAgent)
    // and must NOT leave an extra session row behind.
    let dup_result = process_ecdh_registration(
        "test-listener",
        session_key,
        &metadata,
        &registry,
        &db,
        &events,
        ip,
        None,
    )
    .await;
    assert!(dup_result.is_err(), "duplicate registration must fail");
    assert_eq!(
        count_ecdh_sessions_for_agent(&db, agent_id).await,
        1,
        "failed duplicate must not leave an extra session row"
    );
}

/// Replaying an identical registration packet within the replay window must be
/// rejected.  The ephemeral-pubkey+nonce fingerprint is recorded in the DB on
/// the first successful delivery; the second identical call hits the
/// `try_record_reg_fingerprint` duplicate check and returns `NotEcdh`.
///
/// This exercises the full `process_ecdh_packet` → `classify.rs` path and
/// catches regressions in fingerprint-slice extraction (wrong offset or length
/// would record a different fingerprint and allow the replay through).
#[tokio::test]
async fn reg_replay_within_window_rejected() {
    use crate::demon::INIT_EXT_MONOTONIC_CTR;
    use metrics_exporter_prometheus::PrometheusBuilder;

    let (db, registry, events, dispatcher, keypair, limiter) = ecdh_test_fixture().await;
    let agent_id: u32 = 0xDEAD_CAFE;
    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 101));
    let metadata = build_ecdh_init_metadata(agent_id, INIT_EXT_MONOTONIC_CTR);
    let (packet, _session_key) =
        build_registration_packet(&keypair.public_bytes, &metadata).expect("build packet");

    // Install a thread-local Prometheus recorder so counter! calls are captured.
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let _recorder_guard = metrics::set_default_local_recorder(&recorder);

    // First call: valid registration — fingerprint recorded, agent registered.
    let first = process_ecdh_packet(
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
    .expect("first registration should not error");
    assert!(
        matches!(first, EcdhOutcome::Handled(_)),
        "first registration must be accepted; got: {first:?}"
    );

    // Second call with identical bytes — fingerprint already in DB, replay rejected.
    let second = process_ecdh_packet(
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
    .expect("replay call should not error");
    assert!(
        matches!(second, EcdhOutcome::NotEcdh),
        "replayed packet must be rejected with NotEcdh; got: {second:?}"
    );

    // Verify the SOC-observable replay-rejected counter was incremented.
    let rendered = handle.render();
    let expected_line = r#"red_cell_ecdh_replays_rejected_total{listener="test-listener"} 1"#;
    assert!(
        rendered.contains(expected_line),
        "counter value must be 1 after one replay rejection;\nexpected line: {expected_line}\ngot:\n{rendered}"
    );
}

/// When `try_record_reg_fingerprint` cannot reach the database (pool closed),
/// `process_ecdh_packet` must fail closed — returning `NotEcdh` instead of
/// proceeding without replay protection.  A sustained non-zero rate on the
/// `red_cell_ecdh_replay_db_errors_total` counter signals DB instability.
///
/// This test also asserts that `red_cell_ecdh_replay_db_errors_total` is
/// actually incremented so a future regression that silently removes the
/// `inc_ecdh_replay_db_errors` call does not go undetected.
#[tokio::test]
async fn process_ecdh_packet_fails_closed_on_replay_db_error() {
    use metrics_exporter_prometheus::PrometheusBuilder;

    let (db, registry, events, dispatcher, keypair, limiter) = ecdh_test_fixture().await;
    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77));

    // Build a cryptographically valid packet so it passes AEAD + timestamp
    // checks and reaches the replay-fingerprint DB call.
    let body = valid_registration_body(&keypair);

    // Install a thread-local Prometheus recorder so counter! calls inside
    // process_ecdh_packet are captured without racing against other tests.
    // #[tokio::test] uses the current_thread executor, so all polls of the
    // future below happen on this same thread and see the same thread-local.
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let _recorder_guard = metrics::set_default_local_recorder(&recorder);

    // Close the pool — any subsequent DB call will return an error.
    db.close().await;

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
        matches!(result, Ok(EcdhOutcome::NotEcdh)),
        "DB error during replay guard must return NotEcdh (fail-closed); got: {result:?}"
    );

    // Verify the SOC-observable counter was actually incremented.
    let rendered = handle.render();
    assert!(
        rendered.contains("red_cell_ecdh_replay_db_errors_total"),
        "counter red_cell_ecdh_replay_db_errors_total must appear in metrics output;\n\
         got:\n{rendered}"
    );
    assert!(
        rendered.contains(r#"red_cell_ecdh_replay_db_errors_total{listener="test-listener"}"#),
        "counter must be labelled listener=\"test-listener\";\ngot:\n{rendered}"
    );
    // The exact Prometheus text line is:
    //   red_cell_ecdh_replay_db_errors_total{listener="test-listener"} 1
    let expected_line = r#"red_cell_ecdh_replay_db_errors_total{listener="test-listener"} 1"#;
    assert!(
        rendered.contains(expected_line),
        "counter value must be 1 after one DB-error rejection;\nexpected line: {expected_line}\ngot:\n{rendered}"
    );
}

/// A successful registration must commit both the agent row and the ECDH
/// session row — verify the happy path end-to-end via the internal
/// `process_ecdh_registration` helper.
#[tokio::test]
async fn successful_registration_commits_agent_and_session() {
    use crate::demon::INIT_EXT_MONOTONIC_CTR;

    let (db, registry, events, _dispatcher, _keypair, _limiter) = ecdh_test_fixture().await;
    let agent_id: u32 = 0xDEAD_0002;
    let session_key = [0x43u8; 32];
    let metadata = build_ecdh_init_metadata(agent_id, INIT_EXT_MONOTONIC_CTR);
    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 201));

    let result = process_ecdh_registration(
        "test-listener",
        session_key,
        &metadata,
        &registry,
        &db,
        &events,
        ip,
        None,
    )
    .await;
    assert!(result.is_ok(), "registration must succeed; got: {result:?}");

    assert!(
        registry.get(agent_id).await.is_some(),
        "agent must be registered in the in-memory registry"
    );
    assert_eq!(
        count_ecdh_sessions_for_agent(&db, agent_id).await,
        1,
        "exactly one ECDH session row must exist"
    );
    let persisted =
        db.agents().get_persisted(agent_id).await.expect("db query").expect("agent row");
    assert_eq!(persisted.info.agent_id, agent_id);
}

/// `process_ecdh_registration` must populate `agent_id` and `session_key` on
/// the returned `EcdhResponse` so the handler can write corpus entries without
/// an extra registry lookup.
#[tokio::test]
async fn ecdh_registration_response_carries_agent_id_and_session_key() {
    use crate::demon::INIT_EXT_MONOTONIC_CTR;

    let (db, registry, events, _dispatcher, _keypair, _limiter) = ecdh_test_fixture().await;
    let agent_id: u32 = 0xC0_DE_00_01;
    let session_key = [0x77u8; 32];
    let metadata = build_ecdh_init_metadata(agent_id, INIT_EXT_MONOTONIC_CTR);
    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77));

    let resp = process_ecdh_registration(
        "test-listener",
        session_key,
        &metadata,
        &registry,
        &db,
        &events,
        ip,
        None,
    )
    .await
    .expect("registration must succeed");

    assert_eq!(resp.agent_id, agent_id, "EcdhResponse.agent_id must match the registered agent");
    assert_eq!(
        resp.session_key, session_key,
        "EcdhResponse.session_key must carry the ECDH session key"
    );
    assert!(!resp.payload.is_empty(), "EcdhResponse.payload must be non-empty");
}

/// Simulates the corpus-write logic that runs inside `handler.rs` when
/// `EcdhOutcome::Handled` is returned: verifies that `record_packet` (RX + TX)
/// and `write_session_keys_once` produce the expected files under the agent
/// subdirectory when the data comes from an `EcdhResponse`.
///
/// This complements the `CorpusCapture` unit tests in `corpus_capture.rs`
/// by coupling them to the fields we added to `EcdhResponse` in this bug fix.
#[tokio::test]
async fn ecdh_handled_path_writes_corpus_files() {
    use red_cell_common::corpus::{CorpusAgentType, CorpusPacketDir, CorpusSessionKeys};
    use tempfile::TempDir;

    use crate::corpus_capture::{CorpusCapture, bytes_to_hex};
    use crate::demon::INIT_EXT_MONOTONIC_CTR;

    let (db, registry, events, _dispatcher, _keypair, _limiter) = ecdh_test_fixture().await;
    let agent_id: u32 = 0xC0_DE_00_02;
    let session_key = [0xABu8; 32];
    let metadata = build_ecdh_init_metadata(agent_id, INIT_EXT_MONOTONIC_CTR);
    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 78));

    let resp = process_ecdh_registration(
        "test-listener",
        session_key,
        &metadata,
        &registry,
        &db,
        &events,
        ip,
        None,
    )
    .await
    .expect("registration must succeed");

    let tmp = TempDir::new().expect("tempdir");
    let corpus = CorpusCapture::new(tmp.path().to_path_buf(), CorpusAgentType::Archon);

    let fake_rx = b"fake-ecdh-registration-ciphertext";
    corpus.record_packet(resp.agent_id, CorpusPacketDir::Rx, fake_rx, None).await;
    corpus.record_packet(resp.agent_id, CorpusPacketDir::Tx, &resp.payload, None).await;

    let keys = CorpusSessionKeys::new_gcm(
        bytes_to_hex(&resp.session_key),
        format!("0x{:08x}", resp.agent_id),
        None,
    );
    corpus.write_session_keys_once(resp.agent_id, keys).await;

    let agent_dir = tmp.path().join("archon").join(format!("{:08x}", resp.agent_id));
    assert!(agent_dir.join("0000.bin").exists(), "RX corpus packet must be written as 0000.bin");
    assert!(
        agent_dir.join("0000.meta.json").exists(),
        "RX corpus meta must be written as 0000.meta.json"
    );
    assert!(agent_dir.join("0001.bin").exists(), "TX corpus packet must be written as 0001.bin");
    assert!(
        agent_dir.join("0001.meta.json").exists(),
        "TX corpus meta must be written as 0001.meta.json"
    );
    assert!(agent_dir.join("session.keys.json").exists(), "session.keys.json must be written");

    let keys_json = std::fs::read_to_string(agent_dir.join("session.keys.json"))
        .expect("read session.keys.json");
    let parsed: serde_json::Value =
        serde_json::from_str(&keys_json).expect("session.keys.json must be valid JSON");
    let expected_key_hex = bytes_to_hex(&session_key);
    assert_eq!(
        parsed["aes_key_hex"].as_str().expect("aes_key_hex"),
        expected_key_hex,
        "session.keys.json must embed the ECDH session key"
    );
    assert_eq!(
        parsed["agent_id_hex"].as_str().expect("agent_id_hex"),
        format!("0x{agent_id:08x}"),
        "session.keys.json must embed the correct agent_id"
    );
    assert!(
        parsed["aes_iv_hex"].is_null(),
        "ECDH (GCM) session must have null aes_iv_hex — nonce is per-packet"
    );
    assert!(
        parsed["monotonic_ctr"].is_null(),
        "ECDH (GCM) session must have null monotonic_ctr — concept does not apply to GCM"
    );
    assert!(
        parsed["initial_ctr_block_offset"].is_null(),
        "ECDH (GCM) session must have null initial_ctr_block_offset — concept does not apply to GCM"
    );
    assert_eq!(
        parsed["encryption_scheme"].as_str().expect("encryption_scheme"),
        "aes-256-gcm",
        "ECDH session must identify as aes-256-gcm"
    );
}
