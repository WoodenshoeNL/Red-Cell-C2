use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, encrypt_agent_data};
use red_cell_common::demon::{DEMON_MAGIC_VALUE, DemonCommand, DemonEnvelope};
use time::macros::datetime;

use super::{
    build_init_metadata, build_init_metadata_with_ext_flags, build_init_packet,
    build_init_packet_with_ext_flags, build_init_packet_with_kill_date_and_working_hours,
    build_init_packet_with_working_hours, build_plaintext_zero_iv_init_packet,
    build_plaintext_zero_key_init_packet, legacy_parser, temp_db_path, test_iv, test_key,
    test_registry, u32_be,
};
use crate::demon::{
    DemonPacketParser, DemonParserError, INIT_EXT_MONOTONIC_CTR, INIT_EXT_SEQ_PROTECTED,
    ParsedDemonPacket,
};
use crate::{AgentRegistry, Database};

#[tokio::test]
async fn parse_registers_new_agent_from_demon_init() {
    let registry = test_registry().await;
    let parser = legacy_parser(registry.clone());
    let key = test_key(0x41);
    let iv = test_iv(0x24);
    let packet = build_init_packet(0x1234_5678, key, iv);

    let parsed = parser
        .parse_at(&packet, "203.0.113.10".to_owned(), datetime!(2026-03-09 19:30:00 UTC))
        .await
        .expect("init packet should parse");

    let ParsedDemonPacket::Init(init) = parsed else {
        panic!("expected init packet");
    };

    assert_eq!(init.header.magic, DEMON_MAGIC_VALUE);
    assert_eq!(init.request_id, 7);
    assert_eq!(init.agent.agent_id, 0x1234_5678);
    assert_eq!(init.agent.hostname, "wkstn-01");
    assert_eq!(init.agent.process_name, "explorer.exe");
    assert_eq!(init.agent.process_path, "C:\\Windows\\explorer.exe");
    assert_eq!(init.agent.os_version, "Windows 11");
    assert_eq!(init.agent.os_arch, "x64/AMD64");
    assert_eq!(init.agent.external_ip, "203.0.113.10");
    assert_eq!(init.agent.sleep_delay, 15);
    assert_eq!(init.agent.kill_date, Some(1_893_456_000));
    assert_eq!(init.agent.working_hours, Some(0b101010));
    assert_eq!(registry.get(0x1234_5678).await, Some(init.agent));

    assert_eq!(registry.ctr_offset(0x1234_5678).await.expect("offset should be set"), 0);
}

#[tokio::test]
async fn parse_preserves_signed_working_hours_bitmask_from_demon_init() {
    let registry = test_registry().await;
    let parser = legacy_parser(registry);
    let key = test_key(0x41);
    let iv = test_iv(0x24);
    let working_hours = i32::MIN | 0x2A;
    let packet = build_init_packet_with_working_hours(0x1234_5678, key, iv, working_hours);

    let parsed = parser
        .parse_at(&packet, "203.0.113.10".to_owned(), datetime!(2026-03-09 19:30:00 UTC))
        .await
        .expect("init packet should parse");

    let ParsedDemonPacket::Init(init) = parsed else {
        panic!("expected init packet");
    };

    assert_eq!(init.agent.working_hours, Some(working_hours));
}

#[tokio::test]
async fn parse_stores_no_kill_date_when_init_kill_date_is_zero() {
    let registry = test_registry().await;
    let parser = legacy_parser(registry);
    let key = test_key(0x51);
    let iv = test_iv(0x34);
    let packet =
        build_init_packet_with_kill_date_and_working_hours(0x1234_5678, key, iv, 0, 0b101010);

    let parsed = parser
        .parse_at(&packet, "203.0.113.10".to_owned(), datetime!(2026-03-09 19:30:00 UTC))
        .await
        .expect("init packet should parse");

    let ParsedDemonPacket::Init(init) = parsed else {
        panic!("expected init packet");
    };

    assert_eq!(init.agent.kill_date, None);
}

#[tokio::test]
async fn parse_for_listener_persists_accepting_listener_name() {
    let registry = test_registry().await;
    let parser = legacy_parser(registry.clone());
    let packet = build_init_packet(0x2233_4455, test_key(0x31), test_iv(0x42));

    parser
        .parse_for_listener(&packet, "203.0.113.20", "http-main")
        .await
        .expect("init packet should parse");

    assert_eq!(registry.listener_name(0x2233_4455).await.as_deref(), Some("http-main"));
}

#[tokio::test]
async fn parse_returns_reconnect_for_existing_agent_init_probe() {
    let registry = test_registry().await;
    let parser = legacy_parser(registry.clone());
    let key = test_key(0x41);
    let iv = test_iv(0x24);
    let init_packet = build_init_packet(0x1111_2222, key, iv);
    parser
        .parse_at(&init_packet, "192.0.2.10".to_owned(), datetime!(2026-03-09 19:33:00 UTC))
        .await
        .expect("init should succeed");

    let payload =
        [u32_be(u32::from(DemonCommand::DemonInit)).as_slice(), u32_be(123).as_slice()].concat();
    let reconnect = DemonEnvelope::new(0x1111_2222, payload)
        .expect("reconnect envelope should be valid")
        .to_bytes();

    let parsed = parser
        .parse_at(&reconnect, "192.0.2.10".to_owned(), datetime!(2026-03-09 19:34:00 UTC))
        .await
        .expect("reconnect should parse");

    assert_eq!(
        parsed,
        ParsedDemonPacket::Reconnect {
            header: red_cell_common::demon::DemonHeader {
                size: 16,
                magic: DEMON_MAGIC_VALUE,
                agent_id: 0x1111_2222,
            },
            request_id: 123,
        }
    );
}

#[tokio::test]
async fn parse_reinit_updates_existing_agent_and_returns_reinit_packet() {
    let registry = test_registry().await;
    let parser = legacy_parser(registry.clone());
    let agent_id = 0x1111_2222;
    let first_key = test_key(0x41);
    let first_iv = test_iv(0x24);
    let first_packet = build_init_packet(agent_id, first_key, first_iv);
    parser
        .parse_for_listener(&first_packet, "192.0.2.10", "http-main")
        .await
        .expect("initial init should succeed");

    let first_call_in_before =
        registry.get(agent_id).await.expect("agent should be registered").first_call_in;

    // Advance the stored CTR offset so we can verify it resets on re-init.
    registry.set_ctr_offset(agent_id, 99).await.expect("set ctr offset should succeed");

    // Agent restarts: sends a fresh DEMON_INIT with the same keys from a new IP
    // via a new listener.  Key material must match for re-registration to succeed.
    let reinit_packet = build_init_packet(agent_id, first_key, first_iv);
    let parsed = parser
        .parse_for_listener(&reinit_packet, "198.51.100.99", "smb-secondary")
        .await
        .expect("re-registration must succeed");

    let ParsedDemonPacket::ReInit(reinit) = parsed else {
        panic!("expected ReInit packet, got {parsed:?}");
    };

    // Agent record reflects the fresh metadata from the second DEMON_INIT.
    assert_eq!(reinit.agent.agent_id, agent_id);
    assert_eq!(reinit.agent.external_ip, "198.51.100.99");

    // Verify the registry is updated.
    let stored = registry.get(agent_id).await.expect("agent should still be registered");
    assert_eq!(stored.external_ip, "198.51.100.99");
    assert!(stored.active, "re-registered agent must be active");

    // first_call_in is preserved from the original registration.
    assert_eq!(stored.first_call_in, first_call_in_before);

    // CTR offset is reset to 0 for the fresh session.
    assert_eq!(registry.ctr_offset(agent_id).await.expect("ctr offset"), 0);

    // Listener is updated to the new one.
    assert_eq!(registry.listener_name(agent_id).await.as_deref(), Some("smb-secondary"));
}

#[tokio::test]
async fn parse_reinit_preserves_operator_note() {
    let registry = test_registry().await;
    let parser = legacy_parser(registry.clone());
    let agent_id = 0x3344_5566;
    let key = test_key(0x10);
    let iv = test_iv(0x20);
    let init_packet = build_init_packet(agent_id, key, iv);
    parser
        .parse_for_listener(&init_packet, "10.0.0.1", "http-main")
        .await
        .expect("initial init should succeed");

    registry
        .set_note(agent_id, "important target — do not lose")
        .await
        .expect("set_note should succeed");

    let reinit_packet = build_init_packet(agent_id, key, iv);
    parser
        .parse_for_listener(&reinit_packet, "10.0.0.2", "http-main")
        .await
        .expect("re-registration should succeed");

    let stored = registry.get(agent_id).await.expect("agent should be registered");
    assert_eq!(stored.note, "important target — do not lose");
}

#[tokio::test]
async fn parse_reinit_reactivates_dead_agent() {
    let registry = test_registry().await;
    let parser = legacy_parser(registry.clone());
    let agent_id = 0xDEAD_0001;
    let key = test_key(0x30);
    let iv = test_iv(0x40);
    let init_packet = build_init_packet(agent_id, key, iv);
    parser
        .parse_for_listener(&init_packet, "10.10.10.10", "http-main")
        .await
        .expect("initial init should succeed");

    // Mark the agent dead (simulates a kill-date trigger or operator kill).
    registry.mark_dead(agent_id, "kill-date expired").await.expect("mark_dead should succeed");
    let stored = registry.get(agent_id).await.expect("agent should still be in registry");
    assert!(!stored.active, "agent should be dead before re-registration");

    // Agent restarts and sends a fresh DEMON_INIT with the same key material.
    let reinit_packet = build_init_packet(agent_id, key, iv);
    let parsed = parser
        .parse_for_listener(&reinit_packet, "10.10.10.11", "http-main")
        .await
        .expect("re-registration of dead agent should succeed");

    assert!(
        matches!(parsed, ParsedDemonPacket::ReInit(_)),
        "expected ReInit packet, got {parsed:?}"
    );

    let stored = registry.get(agent_id).await.expect("agent should be in registry");
    assert!(stored.active, "re-registered agent must be active again");
    assert_eq!(stored.reason, "", "reason must be cleared on re-registration");
}

#[tokio::test]
async fn parse_reinit_rejects_mismatched_key_material() {
    let registry = test_registry().await;
    let parser = legacy_parser(registry.clone());
    let agent_id = 0xBEEF_0001;
    let init_packet = build_init_packet(agent_id, test_key(0xAA), test_iv(0xBB));
    parser
        .parse_for_listener(&init_packet, "10.0.0.1", "http-main")
        .await
        .expect("initial init should succeed");

    // An attacker who knows the agent_id tries to re-register with different keys.
    let hijack_packet = build_init_packet(agent_id, test_key(0xCC), test_iv(0xDD));
    let err = parser
        .parse_for_listener(&hijack_packet, "10.0.0.99", "http-main")
        .await
        .expect_err("re-registration with different keys must fail");

    assert!(
        matches!(err, DemonParserError::KeyMismatchOnReInit { agent_id: id } if id == agent_id),
        "expected KeyMismatchOnReInit, got {err:?}"
    );

    // Verify the original agent record is untouched.
    let stored = registry.get(agent_id).await.expect("agent should still be registered");
    assert_eq!(stored.external_ip, "10.0.0.1", "original IP must be preserved");
    assert_eq!(
        stored.encryption.aes_key.as_slice(),
        test_key(0xAA).as_slice(),
        "original AES key must be preserved"
    );
}

#[tokio::test]
async fn parse_reinit_rejects_mismatched_iv_only() {
    let registry = test_registry().await;
    let parser = legacy_parser(registry.clone());
    let agent_id = 0xBEEF_0002;
    let key = test_key(0xAA);
    let init_packet = build_init_packet(agent_id, key, test_iv(0xBB));
    parser
        .parse_for_listener(&init_packet, "10.0.0.1", "http-main")
        .await
        .expect("initial init should succeed");

    // Same key but different IV — still a mismatch.
    let hijack_packet = build_init_packet(agent_id, key, test_iv(0xCC));
    let err = parser
        .parse_for_listener(&hijack_packet, "10.0.0.99", "http-main")
        .await
        .expect_err("re-registration with different IV must fail");

    assert!(
        matches!(err, DemonParserError::KeyMismatchOnReInit { agent_id: id } if id == agent_id),
        "expected KeyMismatchOnReInit, got {err:?}"
    );
}

/// Build an init packet where the outer envelope carries `outer_id` but the encrypted
/// inner metadata carries `inner_id`, exercising the outer/inner agent_id mismatch check.
fn build_mismatched_init_packet(
    outer_id: u32,
    inner_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> Vec<u8> {
    let metadata = build_init_metadata(inner_id);
    let encrypted =
        encrypt_agent_data(&key, &iv, &metadata).expect("metadata encryption should succeed");
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32_be(u32::from(DemonCommand::DemonInit)));
    payload.extend_from_slice(&u32_be(7));
    payload.extend_from_slice(&key);
    payload.extend_from_slice(&iv);
    payload.extend_from_slice(&encrypted);

    DemonEnvelope::new(outer_id, payload).expect("init envelope should be valid").to_bytes()
}

#[tokio::test]
async fn parse_rejects_init_with_mismatched_agent_id() {
    let outer_id = 0x9999_AAAA;
    let inner_id = 0x1111_2222;
    let registry = test_registry().await;
    let parser = DemonPacketParser::new(registry.clone());
    let packet = build_mismatched_init_packet(outer_id, inner_id, test_key(0x41), test_iv(0x24));

    let error = parser
        .parse_at(&packet, "203.0.113.1".to_owned(), datetime!(2026-03-09 19:35:00 UTC))
        .await
        .expect_err("mismatched outer/inner agent_id should fail");

    assert!(
        matches!(error, DemonParserError::InvalidInit("decrypted agent id does not match header")),
        "expected outer/inner agent_id mismatch rejection, got: {error}"
    );
    // Neither the outer nor the inner agent_id should be registered.
    assert!(registry.get(outer_id).await.is_none(), "outer id must not be registered");
    assert!(registry.get(inner_id).await.is_none(), "inner id must not be registered");
}

#[tokio::test]
async fn parse_rejects_plaintext_zero_key_init() {
    let registry = test_registry().await;
    let parser = DemonPacketParser::new(registry.clone());
    let packet = build_plaintext_zero_key_init_packet(0x1357_9BDF);

    let error = parser
        .parse_at(&packet, "203.0.113.77".to_owned(), datetime!(2026-03-10 10:15:00 UTC))
        .await
        .expect_err("zero-key init must be rejected");

    assert!(
        matches!(error, DemonParserError::InvalidInit("degenerate AES key is not allowed")),
        "expected degenerate-key init rejection, got: {error}"
    );
    assert!(registry.get(0x1357_9BDF).await.is_none(), "rejected init must not register");
}

#[tokio::test]
async fn parse_rejects_plaintext_zero_iv_init() {
    let registry = test_registry().await;
    let parser = DemonPacketParser::new(registry.clone());
    let packet = build_plaintext_zero_iv_init_packet(0x1357_9BDF);

    let error = parser
        .parse_at(&packet, "203.0.113.77".to_owned(), datetime!(2026-03-10 10:15:00 UTC))
        .await
        .expect_err("zero-IV init must be rejected");

    assert!(
        matches!(error, DemonParserError::InvalidInit("degenerate AES IV is not allowed")),
        "expected degenerate-IV init rejection, got: {error}"
    );
    assert!(registry.get(0x1357_9BDF).await.is_none(), "rejected init must not register");
}

#[tokio::test]
async fn parse_rejects_init_with_kill_date_exceeding_i64_range() {
    let registry = test_registry().await;
    let parser = DemonPacketParser::new(registry.clone());
    let agent_id = 0x1357_9BDF;
    let key = test_key(0x21);
    let iv = test_iv(0x31);
    let packet =
        build_init_packet_with_kill_date_and_working_hours(agent_id, key, iv, u64::MAX, 0b101010);

    let error = parser
        .parse_at(&packet, "203.0.113.77".to_owned(), datetime!(2026-03-10 10:15:00 UTC))
        .await
        .expect_err("overflowing kill date init must be rejected");

    assert!(matches!(error, DemonParserError::InvalidInit("kill date exceeds i64 range")));
    assert!(registry.get(agent_id).await.is_none(), "rejected init must not register");
}

#[tokio::test]
async fn parse_rejects_init_when_registry_limit_is_reached() {
    let database =
        Database::connect(temp_db_path()).await.expect("temp database should initialize");
    let registry = AgentRegistry::with_max_registered_agents(database, 1);
    let parser = legacy_parser(registry.clone());

    parser
        .parse_at(
            &build_init_packet(0x1357_9BDF, test_key(0x21), test_iv(0x31)),
            "203.0.113.77".to_owned(),
            datetime!(2026-03-10 10:15:00 UTC),
        )
        .await
        .expect("first init should succeed");

    let error = parser
        .parse_at(
            &build_init_packet(0x2468_ACED, test_key(0x22), test_iv(0x32)),
            "203.0.113.78".to_owned(),
            datetime!(2026-03-10 10:16:00 UTC),
        )
        .await
        .expect_err("second init must be rejected");

    assert!(matches!(
        error,
        DemonParserError::Registry(crate::TeamserverError::MaxRegisteredAgentsExceeded {
            max_registered_agents: 1,
            registered: 1,
        })
    ));
    assert!(registry.get(0x2468_ACED).await.is_none(), "rejected init must not register");
}

/// Regression test for red-cell-c2-1a5: a header `agent_id = 0` must NOT
/// bypass the identity mismatch check.
#[tokio::test]
async fn parse_rejects_init_with_zero_header_id_and_different_payload_id() {
    let registry = test_registry().await;
    let parser = DemonPacketParser::new(registry);
    let key = test_key(0x55);
    let iv = test_iv(0x66);
    let spoofed_id: u32 = 0xAAAA_BBBB;

    let metadata = build_init_metadata(spoofed_id);
    let encrypted =
        encrypt_agent_data(&key, &iv, &metadata).expect("metadata encryption should succeed");

    let mut payload = Vec::new();
    payload.extend_from_slice(&u32_be(u32::from(DemonCommand::DemonInit)));
    payload.extend_from_slice(&u32_be(1));
    payload.extend_from_slice(&key);
    payload.extend_from_slice(&iv);
    payload.extend_from_slice(&encrypted);

    let packet = DemonEnvelope::new(0, payload).expect("envelope should be valid").to_bytes();

    let error = parser
        .parse_at(&packet, "203.0.113.99".to_owned(), datetime!(2026-03-10 12:00:00 UTC))
        .await
        .expect_err("zero-header spoofed init must be rejected");

    assert!(
        matches!(error, DemonParserError::InvalidInit(_)),
        "expected InvalidInit error, got: {error}"
    );
}

/// Regression test for red-cell-c2-4rsi: a DEMON_INIT where both the
/// transport header `agent_id` *and* the encrypted metadata `agent_id` are
/// zero must be rejected.  Previously the header/payload mismatch check
/// passed (both equal) and the zero-id agent was registered.
#[tokio::test]
async fn parse_rejects_init_with_zero_agent_id_in_both_header_and_payload() {
    let registry = test_registry().await;
    let parser = DemonPacketParser::new(registry);
    let key = test_key(0x55);
    let iv = test_iv(0x66);

    // Build a fully well-formed init packet with agent_id=0 everywhere.
    let packet = build_init_packet(0, key, iv);

    let error = parser
        .parse_at(&packet, "203.0.113.99".to_owned(), datetime!(2026-03-16 10:00:00 UTC))
        .await
        .expect_err("zero agent_id init must be rejected");

    assert!(
        matches!(error, DemonParserError::InvalidInit(_)),
        "expected InvalidInit error, got: {error}"
    );
}

// ── truncated DEMON_INIT error-path coverage ──────────────────────────────

/// Build an init packet whose inner payload (key + IV + encrypted metadata)
/// is truncated to `inner_payload_len` bytes.  The envelope size field is set
/// consistently so that `DemonEnvelope::from_bytes` accepts the packet and
/// the truncation is only visible to `parse_init_agent`.
fn build_truncated_init_packet(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    inner_payload_len: usize,
) -> Vec<u8> {
    let metadata = build_init_metadata(agent_id);
    let encrypted =
        encrypt_agent_data(&key, &iv, &metadata).expect("metadata encryption should succeed");

    let mut full_inner = Vec::with_capacity(AGENT_KEY_LENGTH + AGENT_IV_LENGTH + encrypted.len());
    full_inner.extend_from_slice(&key);
    full_inner.extend_from_slice(&iv);
    full_inner.extend_from_slice(&encrypted);

    let truncated_inner = &full_inner[..inner_payload_len];

    let mut payload = Vec::new();
    payload.extend_from_slice(&u32_be(u32::from(DemonCommand::DemonInit)));
    payload.extend_from_slice(&u32_be(7));
    payload.extend_from_slice(truncated_inner);

    DemonEnvelope::new(agent_id, payload).expect("init envelope should be valid").to_bytes()
}

/// Truncating an otherwise valid DEMON_INIT payload at several offsets must
/// always return a `BufferTooShort` protocol error and must never register
/// the agent in the registry.
#[tokio::test]
async fn parse_returns_buffer_too_short_for_truncated_demon_init_payload() {
    use red_cell_common::demon::DemonProtocolError;

    let agent_id: u32 = 0xCAFE_BABE;
    let key = test_key(0x41);
    let iv = test_iv(0x24);

    // (label, inner_payload_len)
    // inner_payload_len is the number of bytes of (key ++ iv ++ encrypted_metadata)
    // to include in the envelope payload after the 8-byte command/request prefix.
    let truncation_cases: &[(&str, usize)] = &[
        // 16 of 32 key bytes present — read_fixed::<32> fails immediately.
        ("mid-key", AGENT_KEY_LENGTH / 2),
        // Full key + 8 of 16 IV bytes — read_fixed::<16> fails.
        ("mid-IV", AGENT_KEY_LENGTH + AGENT_IV_LENGTH / 2),
        // Full key + full IV + zero encrypted bytes — decrypt_agent_data returns
        // empty plaintext; the subsequent read_u32_be for the agent-id field fails.
        ("no-encrypted-bytes", AGENT_KEY_LENGTH + AGENT_IV_LENGTH),
        // Full key + full IV + 6 encrypted bytes — decrypts to 6 bytes of plaintext.
        // The agent-id (4 bytes) reads OK; the hostname length-prefix read (4 bytes)
        // fails because only 2 bytes remain.
        ("mid-hostname-length-prefix-in-decrypted", AGENT_KEY_LENGTH + AGENT_IV_LENGTH + 6),
    ];

    for &(label, inner_payload_len) in truncation_cases {
        let registry = test_registry().await;
        let parser = DemonPacketParser::new(registry.clone());
        let packet = build_truncated_init_packet(agent_id, key, iv, inner_payload_len);

        let result = parser
            .parse_at(&packet, "203.0.113.1".to_owned(), datetime!(2026-03-14 00:00:00 UTC))
            .await;

        assert!(
            matches!(
                result,
                Err(DemonParserError::Protocol(DemonProtocolError::BufferTooShort { .. }))
            ),
            "truncation '{label}' (inner_payload_len={inner_payload_len}) must return \
             BufferTooShort, got: {result:?}"
        );
        assert!(
            registry.get(agent_id).await.is_none(),
            "truncation '{label}' must not register the agent in the registry"
        );
    }
}

// ── init_secret / HKDF tests ────────────────────────────────────────────────

#[tokio::test]
async fn parse_init_with_init_secret_derives_different_session_keys() {
    let registry = test_registry().await;
    let secret = b"test-server-secret-value".to_vec();
    let parser = DemonPacketParser::with_init_secret(registry.clone(), Some(secret))
        .with_allow_legacy_ctr(true);
    let key = test_key(0x41);
    let iv = test_iv(0x24);
    let packet = build_init_packet(0xAABB_CCDD, key, iv);

    let parsed = parser
        .parse_at(&packet, "10.0.0.1".to_owned(), datetime!(2026-03-09 19:30:00 UTC))
        .await
        .expect("init with init_secret should succeed");

    let ParsedDemonPacket::Init(init) = parsed else {
        panic!("expected init packet");
    };

    // The stored session keys should be HKDF-derived, not the raw agent keys.
    assert_ne!(
        init.agent.encryption.aes_key.as_slice(),
        &key,
        "session key must differ from raw agent key when init_secret is set"
    );
    assert_ne!(
        init.agent.encryption.aes_iv.as_slice(),
        &iv,
        "session IV must differ from raw agent IV when init_secret is set"
    );

    // Verify the agent was registered with the derived keys.
    let stored = registry.get(0xAABB_CCDD).await.expect("agent should be registered");
    assert_eq!(stored.encryption, init.agent.encryption);
}

#[tokio::test]
async fn parse_init_without_init_secret_stores_raw_keys() {
    let registry = test_registry().await;
    let parser = legacy_parser(registry.clone());
    let key = test_key(0x41);
    let iv = test_iv(0x24);
    let packet = build_init_packet(0xDDCC_BBAA, key, iv);

    let parsed = parser
        .parse_at(&packet, "10.0.0.2".to_owned(), datetime!(2026-03-09 19:30:00 UTC))
        .await
        .expect("init without init_secret should succeed");

    let ParsedDemonPacket::Init(init) = parsed else {
        panic!("expected init packet");
    };

    // Without init_secret, the raw agent keys should be stored directly.
    assert_eq!(
        init.agent.encryption.aes_key.as_slice(),
        &key,
        "session key must equal raw agent key when no init_secret"
    );
    assert_eq!(
        init.agent.encryption.aes_iv.as_slice(),
        &iv,
        "session IV must equal raw agent IV when no init_secret"
    );
}

// ── versioned init_secret tests ──────────────────────────────────────────

/// Build a DEMON_INIT packet that includes a 1-byte version field between
/// the raw key/IV and the encrypted payload — required for versioned mode.
fn build_versioned_init_packet(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    secret_version: u8,
) -> Vec<u8> {
    let metadata = build_init_metadata(agent_id);
    let mut encrypted = red_cell_common::crypto::encrypt_agent_data(&key, &iv, &metadata)
        .expect("encryption must succeed");

    let command_id = u32::from(DemonCommand::DemonInit);
    let mut inner = Vec::new();
    inner.extend_from_slice(&u32_be(command_id));
    inner.extend_from_slice(&u32_be(0)); // request id
    inner.extend_from_slice(&key);
    inner.extend_from_slice(&iv);
    inner.push(secret_version);
    inner.append(&mut encrypted);

    red_cell_common::demon::DemonEnvelope::new(agent_id, inner)
        .expect("versioned init envelope must be valid")
        .to_bytes()
}

#[tokio::test]
async fn parse_init_with_versioned_secrets_derives_correct_keys() {
    let registry = test_registry().await;
    let secret1 = b"versioned-secret-v1".to_vec();
    let secret2 = b"versioned-secret-v2".to_vec();
    let secrets = vec![(1u8, secret1.clone()), (2u8, secret2.clone())];
    let parser =
        DemonPacketParser::with_init_secrets(registry.clone(), secrets).with_allow_legacy_ctr(true);

    let key = test_key(0x51);
    let iv = test_iv(0x62);
    let agent_id = 0x1122_3344_u32;
    let packet = build_versioned_init_packet(agent_id, key, iv, 1);

    let parsed = parser
        .parse_at(&packet, "10.0.0.3".to_owned(), datetime!(2026-04-07 10:00:00 UTC))
        .await
        .expect("versioned init with version 1 should succeed");

    let ParsedDemonPacket::Init(init) = parsed else {
        panic!("expected init packet");
    };

    // Keys must be HKDF-derived using secret1 (version 1).
    let expected = red_cell_common::crypto::derive_session_keys(&key, &iv, &secret1).unwrap();
    assert_eq!(
        init.agent.encryption.aes_key.as_slice(),
        &expected.key,
        "versioned key derivation must use the matching secret"
    );
    assert_ne!(
        init.agent.encryption.aes_key.as_slice(),
        &key,
        "derived key must differ from raw agent key"
    );
}

#[tokio::test]
async fn parse_init_with_versioned_secrets_unknown_version_rejected() {
    let registry = test_registry().await;
    let secrets = vec![(1u8, b"versioned-secret-v1".to_vec())];
    let parser =
        DemonPacketParser::with_init_secrets(registry.clone(), secrets).with_allow_legacy_ctr(true);

    let key = test_key(0x71);
    let iv = test_iv(0x82);
    let agent_id = 0x5566_7788_u32;
    // Send version byte 9 — not in the configured list.
    let packet = build_versioned_init_packet(agent_id, key, iv, 9);

    let result =
        parser.parse_at(&packet, "10.0.0.4".to_owned(), datetime!(2026-04-07 10:05:00 UTC)).await;

    assert!(
        matches!(result, Err(DemonParserError::InvalidInit(_))),
        "unknown secret version must be rejected with InvalidInit, got: {result:?}"
    );
}

#[tokio::test]
async fn parse_init_versioned_without_version_byte_rejected() {
    let registry = test_registry().await;
    let secrets = vec![(1u8, b"versioned-secret-v1".to_vec())];
    let parser =
        DemonPacketParser::with_init_secrets(registry.clone(), secrets).with_allow_legacy_ctr(true);

    let key = test_key(0x81);
    let iv = test_iv(0x92);
    let agent_id = 0x9900_AABB_u32;
    // Build a standard (non-versioned) packet — no version byte after IV.
    let packet = build_init_packet(agent_id, key, iv);

    let result =
        parser.parse_at(&packet, "10.0.0.5".to_owned(), datetime!(2026-04-07 10:10:00 UTC)).await;

    // The decrypted payload will fail to parse (the first decrypted byte is
    // treated as the version, and the remainder as the encrypted payload with
    // a wrong key).  This must not succeed.
    assert!(result.is_err(), "versioned parser must not accept a packet without a version byte");
}

// ── ext_flags / legacy-CTR tests ────────────────────────────────────────────

#[tokio::test]
async fn parse_legacy_init_without_ext_flags_registers_legacy_ctr() {
    let registry = test_registry().await;
    let parser = legacy_parser(registry.clone());
    let agent_id = 0xAAAA_1111;
    let key = test_key(0xC1);
    let iv = test_iv(0xD2);
    let packet = build_init_packet(agent_id, key, iv);

    let parsed = parser
        .parse_at(&packet, "10.0.0.50".to_owned(), datetime!(2026-03-20 12:00:00 UTC))
        .await
        .expect("legacy init should succeed");

    let ParsedDemonPacket::Init(init) = parsed else {
        panic!("expected init packet");
    };
    assert_eq!(init.agent.agent_id, agent_id);

    assert!(
        registry.legacy_ctr(agent_id).await.expect("legacy_ctr should be queryable"),
        "legacy Demon init (no ext flags) must register with legacy_ctr = true"
    );
}

#[tokio::test]
async fn parse_specter_init_with_monotonic_ctr_flag_registers_non_legacy() {
    let registry = test_registry().await;
    let parser = DemonPacketParser::new(registry.clone());
    let agent_id = 0xBBBB_2222;
    let key = test_key(0xE3);
    let iv = test_iv(0xF4);
    let packet = build_init_packet_with_ext_flags(agent_id, key, iv, INIT_EXT_MONOTONIC_CTR);

    let parsed = parser
        .parse_at(&packet, "10.0.0.51".to_owned(), datetime!(2026-03-20 12:01:00 UTC))
        .await
        .expect("Specter init with monotonic CTR flag should succeed");

    let ParsedDemonPacket::Init(init) = parsed else {
        panic!("expected init packet");
    };
    assert_eq!(init.agent.agent_id, agent_id);

    assert!(
        !registry.legacy_ctr(agent_id).await.expect("legacy_ctr should be queryable"),
        "Specter init with INIT_EXT_MONOTONIC_CTR must register with legacy_ctr = false"
    );
}

#[tokio::test]
async fn parse_init_with_zero_ext_flags_registers_legacy_ctr() {
    let registry = test_registry().await;
    let parser = legacy_parser(registry.clone());
    let agent_id = 0xCCCC_3333;
    let key = test_key(0xA5);
    let iv = test_iv(0xB6);
    // Extension flags present but all zero — no monotonic CTR requested.
    let packet = build_init_packet_with_ext_flags(agent_id, key, iv, 0);

    let parsed = parser
        .parse_at(&packet, "10.0.0.52".to_owned(), datetime!(2026-03-20 12:02:00 UTC))
        .await
        .expect("init with zero ext flags should succeed");

    let ParsedDemonPacket::Init(init) = parsed else {
        panic!("expected init packet");
    };
    assert_eq!(init.agent.agent_id, agent_id);

    assert!(
        registry.legacy_ctr(agent_id).await.expect("legacy_ctr should be queryable"),
        "init with ext_flags=0 must register with legacy_ctr = true"
    );
}

#[tokio::test]
async fn parse_legacy_init_rejected_when_allow_legacy_ctr_disabled() {
    // Default parser has allow_legacy_ctr = false — must reject Demon/Archon agents
    // that do not set INIT_EXT_MONOTONIC_CTR.
    let registry = test_registry().await;
    let parser = DemonPacketParser::new(registry.clone());
    let agent_id = 0xEEEE_0001;
    let key = test_key(0xA1);
    let iv = test_iv(0xB1);
    let packet = build_init_packet(agent_id, key, iv);

    let err = parser
        .parse_at(&packet, "10.0.0.60".to_owned(), datetime!(2026-03-30 00:00:00 UTC))
        .await
        .expect_err("legacy CTR init must be rejected when allow_legacy_ctr = false");

    assert!(
        matches!(err, DemonParserError::LegacyCtrNotAllowed),
        "expected LegacyCtrNotAllowed, got: {err}"
    );
    assert!(registry.get(agent_id).await.is_none(), "rejected agent must not be registered");
}

#[tokio::test]
async fn parse_zero_ext_flags_init_rejected_when_allow_legacy_ctr_disabled() {
    // Extension flags present but zero — still counts as legacy mode and must be
    // rejected when allow_legacy_ctr = false.
    let registry = test_registry().await;
    let parser = DemonPacketParser::new(registry.clone());
    let agent_id = 0xEEEE_0002;
    let key = test_key(0xA2);
    let iv = test_iv(0xB2);
    let packet = build_init_packet_with_ext_flags(agent_id, key, iv, 0);

    let err = parser
        .parse_at(&packet, "10.0.0.61".to_owned(), datetime!(2026-03-30 00:00:00 UTC))
        .await
        .expect_err("zero ext_flags init must be rejected when allow_legacy_ctr = false");

    assert!(
        matches!(err, DemonParserError::LegacyCtrNotAllowed),
        "expected LegacyCtrNotAllowed, got: {err}"
    );
    assert!(registry.get(agent_id).await.is_none(), "rejected agent must not be registered");
}

#[tokio::test]
async fn parse_monotonic_ctr_init_succeeds_regardless_of_allow_legacy_ctr() {
    // INIT_EXT_MONOTONIC_CTR → not legacy → succeeds even when allow_legacy_ctr = false.
    let registry = test_registry().await;
    let parser = DemonPacketParser::new(registry.clone()); // allow_legacy_ctr = false
    let agent_id = 0xEEEE_0003;
    let key = test_key(0xA3);
    let iv = test_iv(0xB3);
    let packet = build_init_packet_with_ext_flags(agent_id, key, iv, INIT_EXT_MONOTONIC_CTR);

    parser
        .parse_at(&packet, "10.0.0.62".to_owned(), datetime!(2026-03-30 00:00:00 UTC))
        .await
        .expect("monotonic CTR init must succeed regardless of allow_legacy_ctr setting");

    assert!(registry.get(agent_id).await.is_some(), "monotonic CTR agent must be registered");
    assert!(
        !registry.legacy_ctr(agent_id).await.expect("legacy_ctr should be queryable"),
        "monotonic CTR agent must not be in legacy mode"
    );
}

#[tokio::test]
async fn specter_init_with_init_secret_registers_non_legacy_with_derived_keys() {
    let registry = test_registry().await;
    let init_secret = b"test-server-secret".to_vec();
    let parser = DemonPacketParser::with_init_secret(registry.clone(), Some(init_secret));
    let agent_id = 0xEEEE_5555;
    let key = test_key(0x91);
    let iv = test_iv(0xA2);
    let packet = build_init_packet_with_ext_flags(agent_id, key, iv, INIT_EXT_MONOTONIC_CTR);

    let parsed = parser
        .parse_at(&packet, "10.0.0.54".to_owned(), datetime!(2026-03-20 12:05:00 UTC))
        .await
        .expect("Specter init with init_secret should succeed");

    let ParsedDemonPacket::Init(init) = parsed else {
        panic!("expected init packet");
    };
    assert_eq!(init.agent.agent_id, agent_id);

    // Non-legacy CTR must be set.
    assert!(
        !registry.legacy_ctr(agent_id).await.expect("legacy_ctr"),
        "Specter init with init_secret must register non-legacy CTR"
    );

    // Session keys must be derived (not raw agent keys).
    assert_ne!(
        init.agent.encryption.aes_key.as_slice(),
        &key,
        "with init_secret, session key must differ from raw agent key"
    );
}

// ── Trailing-bytes rejection after extension flags ──────────────────────────

/// Helper: build an init packet whose encrypted metadata has `extra_bytes`
/// appended after the extension flags field.
fn build_init_packet_with_trailing_bytes(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    ext_flags: u32,
    extra: &[u8],
) -> Vec<u8> {
    let mut metadata = build_init_metadata_with_ext_flags(agent_id, ext_flags);
    metadata.extend_from_slice(extra);
    let encrypted =
        encrypt_agent_data(&key, &iv, &metadata).expect("metadata encryption should succeed");
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32_be(u32::from(DemonCommand::DemonInit)));
    payload.extend_from_slice(&u32_be(7));
    payload.extend_from_slice(&key);
    payload.extend_from_slice(&iv);
    payload.extend_from_slice(&encrypted);

    DemonEnvelope::new(agent_id, payload).expect("init envelope should be valid").to_bytes()
}

#[tokio::test]
async fn init_with_one_trailing_byte_after_ext_flags_is_rejected() {
    let registry = test_registry().await;
    let parser = DemonPacketParser::new(registry.clone());
    let agent_id = 0xDEAD_0001;
    let key = test_key(0xC1);
    let iv = test_iv(0xD1);
    let packet =
        build_init_packet_with_trailing_bytes(agent_id, key, iv, INIT_EXT_MONOTONIC_CTR, &[0xFF]);

    let err = parser
        .parse_at(&packet, "10.0.0.99".to_owned(), datetime!(2026-03-20 12:00:00 UTC))
        .await
        .expect_err("trailing byte after ext flags must be rejected");

    assert!(
        err.to_string().contains("trailing bytes"),
        "error should mention trailing bytes, got: {err}"
    );

    // Agent must not be registered.
    assert!(
        registry.get(agent_id).await.is_none(),
        "agent must not be registered after trailing-byte rejection"
    );
}

#[tokio::test]
async fn init_with_four_trailing_bytes_after_ext_flags_is_rejected() {
    let registry = test_registry().await;
    let parser = DemonPacketParser::new(registry.clone());
    let agent_id = 0xDEAD_0004;
    let key = test_key(0xC4);
    let iv = test_iv(0xD4);
    let packet = build_init_packet_with_trailing_bytes(
        agent_id,
        key,
        iv,
        INIT_EXT_MONOTONIC_CTR,
        &[0xAA, 0xBB, 0xCC, 0xDD],
    );

    let err = parser
        .parse_at(&packet, "10.0.0.99".to_owned(), datetime!(2026-03-20 12:00:00 UTC))
        .await
        .expect_err("4 trailing bytes after ext flags must be rejected");

    assert!(
        err.to_string().contains("trailing bytes"),
        "error should mention trailing bytes, got: {err}"
    );

    assert!(
        registry.get(agent_id).await.is_none(),
        "agent must not be registered after trailing-byte rejection"
    );
}

#[tokio::test]
async fn init_with_trailing_bytes_after_legacy_metadata_is_rejected() {
    // When there are no extension flags but extra bytes trail the working_hours
    // field, those bytes look like 1-3 leftover bytes (not enough for a u32
    // extension flag), so they should still be rejected.
    let registry = test_registry().await;
    let parser = DemonPacketParser::new(registry.clone());
    let agent_id = 0xDEAD_0003;
    let key = test_key(0xC3);
    let iv = test_iv(0xD3);

    // Build metadata without ext flags, then append 2 trailing bytes.
    let mut metadata = build_init_metadata(agent_id);
    metadata.extend_from_slice(&[0x01, 0x02]);
    let encrypted =
        encrypt_agent_data(&key, &iv, &metadata).expect("metadata encryption should succeed");
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32_be(u32::from(DemonCommand::DemonInit)));
    payload.extend_from_slice(&u32_be(7));
    payload.extend_from_slice(&key);
    payload.extend_from_slice(&iv);
    payload.extend_from_slice(&encrypted);
    let packet =
        DemonEnvelope::new(agent_id, payload).expect("init envelope should be valid").to_bytes();

    let err = parser
        .parse_at(&packet, "10.0.0.99".to_owned(), datetime!(2026-03-20 12:00:00 UTC))
        .await
        .expect_err("trailing bytes after legacy metadata must be rejected");

    assert!(
        err.to_string().contains("trailing bytes"),
        "error should mention trailing bytes, got: {err}"
    );

    assert!(
        registry.get(agent_id).await.is_none(),
        "agent must not be registered after trailing-byte rejection"
    );
}

// ── Seq-protected init test ─────────────────────────────────────────────────

#[tokio::test]
async fn seq_protected_init_sets_seq_protected_flag() {
    let agent_id = 0xA000_0001;
    let key = test_key(0xA1);
    let iv = test_iv(0xB1);
    let registry = test_registry().await;
    let parser = DemonPacketParser::new(registry.clone());
    let init = build_init_packet_with_ext_flags(
        agent_id,
        key,
        iv,
        INIT_EXT_SEQ_PROTECTED | INIT_EXT_MONOTONIC_CTR,
    );
    parser
        .parse_at(&init, "10.0.0.1".to_owned(), datetime!(2026-03-20 12:00:00 UTC))
        .await
        .expect("seq-protected init must succeed");
    assert!(
        registry.is_seq_protected(agent_id).await,
        "INIT_EXT_SEQ_PROTECTED must set seq_protected = true in the registry"
    );
}

// --- ECDH metadata parser focused tests ---

use crate::demon::parse_ecdh_agent_metadata;

#[test]
fn ecdh_metadata_rejects_reserved_agent_id_zero() {
    let metadata = build_init_metadata(0x0000_0000);
    let result =
        parse_ecdh_agent_metadata(&metadata, "10.0.0.1", datetime!(2026-01-01 00:00:00 UTC));
    assert!(
        matches!(result, Err(DemonParserError::InvalidInit(_))),
        "agent_id 0 must be rejected; got: {result:?}"
    );
}

#[test]
fn ecdh_metadata_rejects_trailing_bytes_after_standard_fields() {
    let mut metadata = build_init_metadata(0x1234_5678);
    metadata.push(0xFF);
    let result =
        parse_ecdh_agent_metadata(&metadata, "10.0.0.1", datetime!(2026-01-01 00:00:00 UTC));
    assert!(
        matches!(result, Err(DemonParserError::InvalidInit(_))),
        "trailing byte after standard fields must be rejected; got: {result:?}"
    );
}

#[test]
fn ecdh_metadata_rejects_trailing_bytes_after_ext_flags() {
    let mut metadata = build_init_metadata_with_ext_flags(0x1234_5678, INIT_EXT_MONOTONIC_CTR);
    metadata.push(0xDE);
    let result =
        parse_ecdh_agent_metadata(&metadata, "10.0.0.1", datetime!(2026-01-01 00:00:00 UTC));
    assert!(
        matches!(result, Err(DemonParserError::InvalidInit(_))),
        "trailing byte after ext_flags must be rejected; got: {result:?}"
    );
}

#[test]
fn ecdh_metadata_accepts_valid_ext_flags_monotonic_ctr() {
    let metadata = build_init_metadata_with_ext_flags(0x1234_5678, INIT_EXT_MONOTONIC_CTR);
    let result =
        parse_ecdh_agent_metadata(&metadata, "10.0.0.1", datetime!(2026-01-01 00:00:00 UTC));
    let (record, legacy_ctr, seq_protected) = result.expect("valid ECDH metadata must parse");
    assert_eq!(record.agent_id, 0x1234_5678);
    assert!(!legacy_ctr, "INIT_EXT_MONOTONIC_CTR must set legacy_ctr = false");
    assert!(!seq_protected);
}

#[test]
fn ecdh_metadata_accepts_valid_ext_flags_seq_protected() {
    let metadata = build_init_metadata_with_ext_flags(
        0x1234_5678,
        INIT_EXT_MONOTONIC_CTR | INIT_EXT_SEQ_PROTECTED,
    );
    let result =
        parse_ecdh_agent_metadata(&metadata, "10.0.0.1", datetime!(2026-01-01 00:00:00 UTC));
    let (record, legacy_ctr, seq_protected) = result.expect("valid ECDH metadata must parse");
    assert_eq!(record.agent_id, 0x1234_5678);
    assert!(!legacy_ctr);
    assert!(seq_protected, "INIT_EXT_SEQ_PROTECTED must set seq_protected = true");
}

#[test]
fn ecdh_metadata_accepts_valid_fields_without_ext_flags() {
    let metadata = build_init_metadata(0xDEAD_BEEF);
    let result =
        parse_ecdh_agent_metadata(&metadata, "203.0.113.5", datetime!(2026-01-01 00:00:00 UTC));
    let (record, legacy_ctr, seq_protected) =
        result.expect("valid ECDH metadata without ext flags must parse");
    assert_eq!(record.agent_id, 0xDEAD_BEEF);
    assert_eq!(record.external_ip, "203.0.113.5");
    assert!(legacy_ctr, "absence of ext flags must result in legacy_ctr = true");
    assert!(!seq_protected);
}
