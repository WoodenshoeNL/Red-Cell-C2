use red_cell_common::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len, encrypt_agent_data_at_offset,
};
use red_cell_common::demon::{DemonCommand, DemonEnvelope, DemonProtocolError};
use time::macros::datetime;

use super::{
    agent_with_raw_crypto, build_callback_packet, build_init_packet,
    build_init_packet_with_ext_flags, legacy_parser, temp_db_path, test_iv, test_key,
    test_registry, u32_be,
};
use crate::demon::callback::{parse_batched_callback_packages, parse_callback_packages};
use crate::demon::{
    DemonCallbackPackage, DemonPacketParser, DemonParserError, INIT_EXT_MONOTONIC_CTR,
    INIT_EXT_SEQ_PROTECTED, ParsedDemonPacket, build_init_ack,
};
use crate::{AgentRegistry, Database};

#[tokio::test]
async fn parse_decrypts_callback_packages_for_existing_agent() {
    let registry = test_registry().await;
    let parser = legacy_parser(registry.clone());
    let key = test_key(0x41);
    let iv = test_iv(0x24);
    let init_packet = build_init_packet(0x0102_0304, key, iv);
    parser
        .parse_at(&init_packet, "198.51.100.5".to_owned(), datetime!(2026-03-09 19:31:00 UTC))
        .await
        .expect("init should succeed");

    let _ack = build_init_ack(&registry, 0x0102_0304).await.expect("ack should build");
    // Legacy mode: CTR stays at 0 after init ACK.
    let callback_packet = build_callback_packet(0x0102_0304, key, iv, 0);
    let parsed = parser
        .parse_at(&callback_packet, "198.51.100.5".to_owned(), datetime!(2026-03-09 19:32:00 UTC))
        .await
        .expect("callback should parse");

    let ParsedDemonPacket::Callback { header, packages } = parsed else {
        panic!("expected callback packet");
    };

    assert_eq!(header.agent_id, 0x0102_0304);
    assert_eq!(packages.len(), 2);
    assert_eq!(packages[0].command_id, u32::from(DemonCommand::CommandCheckin));
    assert_eq!(packages[0].request_id, 42);
    assert_eq!(packages[0].payload, vec![0xaa, 0xbb, 0xcc]);
    assert_eq!(packages[1].command_id, u32::from(DemonCommand::CommandOutput));
    assert_eq!(packages[1].request_id, 99);
    assert_eq!(packages[1].payload, b"hello");
}

#[tokio::test]
async fn callback_after_registry_reload_uses_persisted_crypto_material() {
    let database =
        Database::connect(temp_db_path()).await.expect("temp database should initialize");
    let registry = AgentRegistry::new(database.clone());
    let parser = legacy_parser(registry);
    let key = test_key(0x57);
    let iv = test_iv(0x68);
    let agent_id: u32 = 0x2233_4455;

    let init_packet = build_init_packet(agent_id, key, iv);
    parser
        .parse_at(&init_packet, "10.0.0.5".to_owned(), datetime!(2026-03-09 19:47:00 UTC))
        .await
        .expect("init should succeed");

    let reloaded = AgentRegistry::load(database).await.expect("registry should reload");
    let parser = DemonPacketParser::new(reloaded);
    let callback_packet = build_callback_packet(agent_id, key, iv, 0);

    let parsed = parser
        .parse_at(&callback_packet, "10.0.0.5".to_owned(), datetime!(2026-03-09 19:48:00 UTC))
        .await
        .expect("callback should parse after reload");

    let ParsedDemonPacket::Callback { header, packages } = parsed else {
        panic!("expected callback packet");
    };

    assert_eq!(header.agent_id, agent_id);
    assert_eq!(packages.len(), 2);
    assert_eq!(packages[0].command_id, u32::from(DemonCommand::CommandCheckin));
    assert_eq!(packages[0].request_id, 42);
    assert_eq!(packages[0].payload, vec![0xaa, 0xbb, 0xcc]);
    assert_eq!(packages[1].command_id, u32::from(DemonCommand::CommandOutput));
    assert_eq!(packages[1].request_id, 99);
    assert_eq!(packages[1].payload, b"hello");
}

/// Build a callback packet whose encrypted payload decrypts to bytes that will fail
/// `parse_callback_packages` — simulating an adversary who sends a crafted packet with a
/// valid header but garbage payload (CTR desync attack).
fn build_garbage_callback_packet(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    ctr_offset: u64,
) -> Vec<u8> {
    // Encrypting a single byte: when decrypted, `read_length_prefixed_bytes_be` will attempt
    // to read a 4-byte u32 length prefix and fail with BufferTooShort.
    let garbage_plaintext = b"\xFF";
    let encrypted = encrypt_agent_data_at_offset(&key, &iv, ctr_offset, garbage_plaintext)
        .expect("garbage encryption should succeed");
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32_be(u32::from(DemonCommand::CommandCheckin)));
    payload.extend_from_slice(&u32_be(42));
    payload.extend_from_slice(&encrypted);

    DemonEnvelope::new(agent_id, payload)
        .expect("garbage callback envelope should be valid")
        .to_bytes()
}

#[tokio::test]
async fn garbage_callback_does_not_advance_ctr_offset() {
    // Reproduces the CTR desync attack: an adversary observes a valid agent_id from the
    // plaintext packet header, crafts a packet with the correct DEMON_MAGIC_VALUE and
    // agent_id, but encrypts garbage as the payload.  Before this fix, `decrypt_from_agent`
    // would advance the CTR offset unconditionally, permanently breaking the legitimate
    // agent's next callback.
    let registry = test_registry().await;
    let parser = legacy_parser(registry.clone());
    let agent_id = 0xDEAD_BEEF_u32;
    let key = test_key(0xAA);
    let iv = test_iv(0xBB);

    // Register the agent.
    let init_packet = build_init_packet(agent_id, key, iv);
    parser
        .parse_at(&init_packet, "203.0.113.50".to_owned(), datetime!(2026-03-15 10:00:00 UTC))
        .await
        .expect("init should succeed");

    // Switch to monotonic mode so CTR advances (this test validates desync protection).
    registry.set_legacy_ctr(agent_id, false).await.expect("set_legacy_ctr");

    // Advance the CTR offset by sending the init ack (simulates the server's normal response).
    let _ack = build_init_ack(&registry, agent_id).await.expect("ack should build");
    let offset_after_ack = registry.ctr_offset(agent_id).await.expect("offset should exist");
    assert_eq!(offset_after_ack, 1, "offset should be 1 after init ack");

    // Send a garbage callback packet at the current offset.
    let garbage_packet = build_garbage_callback_packet(agent_id, key, iv, offset_after_ack);
    let result = parser
        .parse_at(&garbage_packet, "203.0.113.50".to_owned(), datetime!(2026-03-15 10:00:01 UTC))
        .await;
    assert!(result.is_err(), "garbage callback must be rejected, got: {result:?}");

    // The CTR offset must NOT have advanced — the desync attack must fail.
    let offset_after_garbage = registry.ctr_offset(agent_id).await.expect("offset should exist");
    assert_eq!(
        offset_after_garbage, offset_after_ack,
        "CTR offset must not advance on a failed callback parse"
    );

    // The real agent's next callback at the correct offset must still succeed.
    let legitimate_packet = build_callback_packet(agent_id, key, iv, offset_after_ack);
    let parsed = parser
        .parse_at(&legitimate_packet, "203.0.113.50".to_owned(), datetime!(2026-03-15 10:00:02 UTC))
        .await
        .expect("legitimate callback must succeed after a rejected garbage packet");

    let ParsedDemonPacket::Callback { packages, .. } = parsed else {
        panic!("expected callback packet");
    };
    assert_eq!(packages[0].command_id, u32::from(DemonCommand::CommandCheckin));
    assert_eq!(packages[0].payload, vec![0xaa, 0xbb, 0xcc]);
}

#[tokio::test]
async fn specter_init_ctr_advances_on_callback() {
    let registry = test_registry().await;
    let parser = DemonPacketParser::new(registry.clone());
    let agent_id = 0xDDDD_4444;
    let key = test_key(0x71);
    let iv = test_iv(0x82);
    let packet = build_init_packet_with_ext_flags(agent_id, key, iv, INIT_EXT_MONOTONIC_CTR);

    parser
        .parse_at(&packet, "10.0.0.53".to_owned(), datetime!(2026-03-20 12:03:00 UTC))
        .await
        .expect("Specter init should succeed");

    assert!(
        !registry.legacy_ctr(agent_id).await.expect("legacy_ctr"),
        "agent should be non-legacy"
    );

    // Build init ack — advances the CTR offset.
    let _ack = build_init_ack(&registry, agent_id).await.expect("ack should build");
    let offset_after_ack = registry.ctr_offset(agent_id).await.expect("offset");
    assert_eq!(offset_after_ack, 1, "CTR should advance by 1 block after init ack");

    // A callback at the correct offset should parse and advance CTR.
    let callback_packet = build_callback_packet(agent_id, key, iv, offset_after_ack);
    let parsed = parser
        .parse_at(&callback_packet, "10.0.0.53".to_owned(), datetime!(2026-03-20 12:04:00 UTC))
        .await
        .expect("callback at correct offset should succeed");

    let ParsedDemonPacket::Callback { packages, .. } = parsed else {
        panic!("expected callback packet");
    };
    assert_eq!(packages[0].command_id, u32::from(DemonCommand::CommandCheckin));

    let offset_after_callback = registry.ctr_offset(agent_id).await.expect("offset");
    assert!(
        offset_after_callback > offset_after_ack,
        "monotonic CTR must advance after callback (was {offset_after_ack}, now {offset_after_callback})"
    );
}

// ── parse_callback_packages ──────────────────────────────────────────────

/// Build the raw decrypted buffer expected by `parse_callback_packages`.
///
/// The first entry in `packages` supplies the outer `(command_id, request_id)` returned
/// alongside the buffer; the remainder are inlined as additional `(cmd, req, len-prefixed
/// payload)` tuples that exercise the multi-package `while` loop.
fn build_raw_callback_decrypted(packages: &[(u32, u32, &[u8])]) -> (u32, u32, Vec<u8>) {
    assert!(!packages.is_empty(), "must supply at least one package");
    let (first_cmd, first_req, first_payload) = packages[0];
    let mut buf = Vec::new();
    buf.extend_from_slice(&u32_be(u32::try_from(first_payload.len()).expect("unwrap")));
    buf.extend_from_slice(first_payload);
    for &(cmd, req, payload) in &packages[1..] {
        buf.extend_from_slice(&u32_be(cmd));
        buf.extend_from_slice(&u32_be(req));
        buf.extend_from_slice(&u32_be(u32::try_from(payload.len()).expect("unwrap")));
        buf.extend_from_slice(payload);
    }
    (first_cmd, first_req, buf)
}

#[test]
fn parse_callback_packages_three_packages_all_present_in_order() {
    let (first_cmd, first_req, buf) = build_raw_callback_decrypted(&[
        (0x0000_0001, 0x1001, b"alpha"),
        (0x0000_0002, 0x2002, b"beta"),
        (0x0000_0003, 0x3003, b"gamma"),
    ]);

    let packages = parse_callback_packages(first_cmd, first_req, &buf)
        .expect("three-package payload should parse");

    assert_eq!(packages.len(), 3);
    assert_eq!(packages[0].command_id, 0x0000_0001);
    assert_eq!(packages[0].request_id, 0x1001);
    assert_eq!(packages[0].payload, b"alpha");
    assert_eq!(packages[1].command_id, 0x0000_0002);
    assert_eq!(packages[1].request_id, 0x2002);
    assert_eq!(packages[1].payload, b"beta");
    assert_eq!(packages[2].command_id, 0x0000_0003);
    assert_eq!(packages[2].request_id, 0x3003);
    assert_eq!(packages[2].payload, b"gamma");
}

#[test]
fn parse_callback_packages_single_package_loop_not_entered() {
    let (first_cmd, first_req, buf) =
        build_raw_callback_decrypted(&[(0x0000_0042, 0xDEAD_BEEF, b"only")]);

    let packages = parse_callback_packages(first_cmd, first_req, &buf)
        .expect("single-package payload should parse");

    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].command_id, 0x0000_0042);
    assert_eq!(packages[0].request_id, 0xDEAD_BEEF);
    assert_eq!(packages[0].payload, b"only");
}

#[test]
fn parse_callback_packages_empty_first_payload_followed_by_second() {
    let (first_cmd, first_req, buf) =
        build_raw_callback_decrypted(&[(0x0000_0010, 0x0001, b""), (0x0000_0020, 0x0002, b"data")]);

    let packages = parse_callback_packages(first_cmd, first_req, &buf)
        .expect("empty first payload should be valid");

    assert_eq!(packages.len(), 2);
    assert!(packages[0].payload.is_empty(), "first payload must be empty");
    assert_eq!(packages[1].payload, b"data");
}

#[test]
fn parse_callback_packages_truncated_command_id_in_loop_returns_error() {
    // First package is well-formed; then only 2 bytes follow (truncated command_id field).
    let (first_cmd, first_req, mut buf) =
        build_raw_callback_decrypted(&[(0x0000_0001, 0x0001, b"abcd")]);
    buf.extend_from_slice(&[0xDE, 0xAD]); // 2 of the 4 bytes needed for command_id

    let error = parse_callback_packages(first_cmd, first_req, &buf)
        .expect_err("truncated command_id must be rejected");

    assert!(
        matches!(error, DemonParserError::Protocol(_)),
        "expected Protocol error, got: {error:?}"
    );
}

#[test]
fn parse_callback_packages_truncated_payload_in_loop_returns_error() {
    // Second package's length field claims 10 bytes but the buffer only provides 2.
    let (first_cmd, first_req, mut buf) =
        build_raw_callback_decrypted(&[(0x0000_0001, 0x0001, b"abcd")]);
    buf.extend_from_slice(&u32_be(0x0000_0002)); // cmd_id
    buf.extend_from_slice(&u32_be(0x0002)); // req_id
    buf.extend_from_slice(&u32_be(10)); // claims 10-byte payload
    buf.extend_from_slice(&[0xAB, 0xCD]); // only 2 bytes available

    let error = parse_callback_packages(first_cmd, first_req, &buf)
        .expect_err("truncated payload must be rejected");

    assert!(
        matches!(error, DemonParserError::Protocol(_)),
        "expected Protocol error, got: {error:?}"
    );
}

// ── parse_callback_packages — first-callback truncation ─────────────────

#[test]
fn parse_callback_packages_empty_buffer_returns_error() {
    let buf: &[u8] = &[];
    let error = parse_callback_packages(1, 1, buf).expect_err("empty buffer must be rejected");

    assert!(
        matches!(error, DemonParserError::Protocol(_)),
        "expected Protocol error, got: {error:?}"
    );
}

#[test]
fn parse_callback_packages_first_length_prefix_truncated_returns_error() {
    // Only 2 bytes — not enough for the 4-byte length prefix of the first payload.
    let buf: &[u8] = &[0x00, 0x05];
    let error = parse_callback_packages(1, 1, buf)
        .expect_err("truncated first length prefix must be rejected");

    assert!(
        matches!(error, DemonParserError::Protocol(_)),
        "expected Protocol error, got: {error:?}"
    );
}

#[test]
fn parse_callback_packages_first_payload_exceeds_remaining_returns_error() {
    // Length prefix claims 100 bytes but buffer only has 4 (the prefix itself) + 2 data bytes.
    let mut buf = Vec::new();
    buf.extend_from_slice(&u32_be(100)); // first payload length = 100
    buf.extend_from_slice(&[0xAA, 0xBB]); // only 2 bytes available
    let error = parse_callback_packages(1, 1, &buf)
        .expect_err("oversized first payload length must be rejected");

    assert!(
        matches!(error, DemonParserError::Protocol(_)),
        "expected Protocol error, got: {error:?}"
    );
}

// ── DemonPacketParser COMMAND_CHECKIN truncated inner payload ────────────

/// Build a COMMAND_CHECKIN callback packet whose encrypted inner payload,
/// once decrypted, contains a length-prefix for the second sub-package that
/// claims more bytes than the buffer actually holds.
///
/// The outer envelope and AES encryption are well-formed so the packet
/// passes decryption; the parse error must come from the inner loop.
fn build_checkin_packet_with_truncated_inner_payload(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    ctr_offset: u64,
) -> Vec<u8> {
    // Inner decrypted bytes:
    //   [4] first_payload_len=3  [3] 0xaa 0xbb 0xcc   <- well-formed first package
    //   [4] second_cmd_id        [4] second_req_id
    //   [4] second_payload_len=100  [2] 0xAB 0xCD     <- truncated: only 2 bytes, not 100
    let mut decrypted = Vec::new();
    decrypted.extend_from_slice(&u32_be(3));
    decrypted.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
    decrypted.extend_from_slice(&u32_be(u32::from(DemonCommand::CommandOutput)));
    decrypted.extend_from_slice(&u32_be(77));
    decrypted.extend_from_slice(&u32_be(100)); // claims 100-byte payload
    decrypted.extend_from_slice(&[0xAB, 0xCD]); // only 2 bytes present

    let encrypted = encrypt_agent_data_at_offset(&key, &iv, ctr_offset, &decrypted)
        .expect("truncated-inner encryption should succeed");

    let mut payload = Vec::new();
    payload.extend_from_slice(&u32_be(u32::from(DemonCommand::CommandCheckin)));
    payload.extend_from_slice(&u32_be(42));
    payload.extend_from_slice(&encrypted);

    DemonEnvelope::new(agent_id, payload)
        .expect("truncated-inner callback envelope should be valid")
        .to_bytes()
}

/// A COMMAND_CHECKIN packet that decrypts successfully but whose inner
/// sub-package length-prefix exceeds the remaining buffer must return a
/// `DemonParserError` and must never panic.
#[tokio::test]
async fn parse_checkin_with_truncated_inner_payload_returns_parse_error() {
    let registry = test_registry().await;
    let parser = legacy_parser(registry.clone());
    let key = test_key(0x41);
    let iv = test_iv(0x24);
    let agent_id: u32 = 0x0A0B_0C0D;

    // Register the agent.
    let init_packet = build_init_packet(agent_id, key, iv);
    parser
        .parse_at(&init_packet, "198.51.100.7".to_owned(), datetime!(2026-03-15 10:00:00 UTC))
        .await
        .expect("init should succeed");

    // Advance the registry CTR offset by building (and discarding) the init ACK,
    // exactly as the real server would.  The ACK encrypts one u32 (4 bytes =
    // 1 AES-CTR block), so the next agent-to-server packet is decrypted starting
    // at block offset 1.
    let _ack = build_init_ack(&registry, agent_id).await.expect("ack should build");
    let ctr_offset = ctr_blocks_for_len(std::mem::size_of::<u32>());

    let bad_packet =
        build_checkin_packet_with_truncated_inner_payload(agent_id, key, iv, ctr_offset);

    let result = parser
        .parse_at(&bad_packet, "198.51.100.7".to_owned(), datetime!(2026-03-15 10:00:01 UTC))
        .await;

    assert!(
        matches!(result, Err(DemonParserError::Protocol(_))),
        "truncated inner payload must return a Protocol error, got: {result:?}"
    );
}

// ---- DemonCallbackPackage::command() tests ----

#[test]
fn callback_package_command_returns_known_variant() {
    let pkg = DemonCallbackPackage {
        command_id: u32::from(DemonCommand::CommandGetJob),
        request_id: 1,
        payload: Vec::new(),
    };

    assert_eq!(pkg.command(), Ok(DemonCommand::CommandGetJob));
}

#[test]
fn callback_package_command_returns_error_for_unknown_id() {
    let pkg = DemonCallbackPackage { command_id: 0xFFFF_FFFE, request_id: 0, payload: Vec::new() };

    let err = pkg.command().expect_err("unknown command ID must return Err");
    assert_eq!(
        err,
        DemonProtocolError::UnknownEnumValue { kind: "DemonCommand", value: 0xFFFF_FFFE }
    );
}

#[test]
fn callback_package_command_returns_error_for_zero_id() {
    let pkg = DemonCallbackPackage { command_id: 0, request_id: 0, payload: Vec::new() };

    // Zero is not a valid DemonCommand discriminant — the lowest is CommandGetJob = 1.
    let err = pkg.command().expect_err("zero command ID must return Err");
    assert_eq!(err, DemonProtocolError::UnknownEnumValue { kind: "DemonCommand", value: 0 });
}

// ---- InvalidStoredCryptoEncoding coverage (callback path) ----

#[tokio::test]
async fn callback_parse_returns_invalid_stored_crypto_for_bad_key() {
    let registry = test_registry().await;
    let agent_id: u32 = 0xBAD0_0004;
    // Insert agent with corrupted key directly — no init handshake needed.
    let agent = agent_with_raw_crypto(agent_id, vec![0xAA; 7], vec![0xBB; AGENT_IV_LENGTH]);
    registry.insert(agent).await.expect("insert should succeed");

    // Build a callback envelope — the ciphertext content does not matter because
    // the error fires before decryption, when the stored key fails length check.
    let dummy_key = test_key(0x55);
    let dummy_iv = test_iv(0x66);
    let callback_packet = build_callback_packet(agent_id, dummy_key, dummy_iv, 0);
    let parser = DemonPacketParser::new(registry);

    let error = parser
        .parse_at(&callback_packet, "10.0.0.99".to_owned(), datetime!(2026-03-10 14:01:00 UTC))
        .await
        .expect_err("callback with corrupted key must fail");

    match &error {
        DemonParserError::InvalidStoredCryptoEncoding { agent_id: err_id, field, .. } => {
            assert_eq!(*err_id, agent_id);
            assert_eq!(*field, "aes_key");
        }
        other => panic!("expected InvalidStoredCryptoEncoding for aes_key, got: {other}"),
    }
}

#[tokio::test]
async fn callback_parse_returns_invalid_stored_crypto_for_bad_iv() {
    let registry = test_registry().await;
    let agent_id: u32 = 0xBAD0_0005;
    let agent = agent_with_raw_crypto(agent_id, vec![0xCC; AGENT_KEY_LENGTH], vec![0xDD; 2]);
    registry.insert(agent).await.expect("insert should succeed");

    let dummy_key = test_key(0x57);
    let dummy_iv = test_iv(0x68);
    let callback_packet = build_callback_packet(agent_id, dummy_key, dummy_iv, 0);
    let parser = DemonPacketParser::new(registry);

    let error = parser
        .parse_at(&callback_packet, "10.0.0.99".to_owned(), datetime!(2026-03-10 14:01:00 UTC))
        .await
        .expect_err("callback with corrupted IV must fail");

    match &error {
        DemonParserError::InvalidStoredCryptoEncoding { agent_id: err_id, field, .. } => {
            assert_eq!(*err_id, agent_id);
            assert_eq!(*field, "aes_iv");
        }
        other => panic!("expected InvalidStoredCryptoEncoding for aes_iv, got: {other}"),
    }
}

#[tokio::test]
async fn callback_for_unregistered_agent_returns_not_found_without_creating_state() {
    let registry = test_registry().await;
    let parser = DemonPacketParser::new(registry.clone());
    let unregistered_id: u32 = 0xBADA_9E00;

    // Build a well-formed callback envelope targeting an agent ID the registry does not know.
    let dummy_key = test_key(0x41);
    let dummy_iv = test_iv(0x24);
    let callback_packet = build_callback_packet(unregistered_id, dummy_key, dummy_iv, 0);

    let error = parser
        .parse_at(&callback_packet, "198.51.100.99".to_owned(), datetime!(2026-03-15 12:00:00 UTC))
        .await
        .expect_err("callback for unregistered agent must fail");

    assert!(
        matches!(
            error,
            DemonParserError::Registry(crate::TeamserverError::AgentNotFound {
                agent_id: 0xBADA_9E00,
            })
        ),
        "expected AgentNotFound, got: {error}"
    );

    // No agent should have been inserted as a side effect.
    assert!(
        registry.get(unregistered_id).await.is_none(),
        "unregistered agent must not be inserted by a callback"
    );

    // No CTR state should have been created.
    assert!(
        registry.ctr_offset(unregistered_id).await.is_err(),
        "no CTR offset should exist for an unregistered agent"
    );
}

// ── Seq-protected callback tests ─────────────────────────────────────────

/// Build a seq-protected callback packet: the decrypted body starts with
/// an 8-byte LE seq number, then a normal Demon package stream.
fn build_seq_protected_callback(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    ctr_offset: u64,
    seq: u64,
) -> Vec<u8> {
    let mut decrypted = Vec::new();
    // 8-byte LE seq prefix
    decrypted.extend_from_slice(&seq.to_le_bytes());
    // One Demon package (first cmd + payload)
    decrypted.extend_from_slice(&u32_be(3)); // payload length prefix
    decrypted.extend_from_slice(b"out");
    // No additional packages
    let encrypted = encrypt_agent_data_at_offset(&key, &iv, ctr_offset, &decrypted)
        .expect("seq callback encryption must succeed");
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32_be(u32::from(DemonCommand::CommandOutput)));
    payload.extend_from_slice(&u32_be(1)); // request_id
    payload.extend_from_slice(&encrypted);
    DemonEnvelope::new(agent_id, payload).expect("seq callback envelope must be valid").to_bytes()
}

/// Register a seq-protected agent, parse the init, set seq_protected flag.
async fn register_seq_protected_agent(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> (AgentRegistry, DemonPacketParser) {
    let registry = test_registry().await;
    let parser = DemonPacketParser::new(registry.clone()); // allow_legacy_ctr = false
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
    (registry, parser)
}

#[tokio::test]
async fn seq_protected_callback_accepted_with_valid_seq() {
    let agent_id = 0xA000_0002;
    let key = test_key(0xA2);
    let iv = test_iv(0xB2);
    let (registry, parser) = register_seq_protected_agent(agent_id, key, iv).await;

    // Init ACK advances CTR by one block; callback must start at that offset.
    let ack = build_init_ack(&registry, agent_id).await.expect("build_init_ack must succeed");
    let offset = ctr_blocks_for_len(ack.len());

    let packet = build_seq_protected_callback(agent_id, key, iv, offset as u64, 1);
    let result =
        parser.parse_at(&packet, "10.0.0.1".to_owned(), datetime!(2026-03-20 12:01:00 UTC)).await;
    assert!(result.is_ok(), "valid seq-protected callback must be accepted: {result:?}");

    // last_seen_seq must have been advanced to 1.
    assert!(
        registry.check_callback_seq(agent_id, 1).await.is_err(),
        "seq=1 must now be rejected after being accepted"
    );
    assert!(
        registry.check_callback_seq(agent_id, 2).await.is_ok(),
        "seq=2 must still be acceptable"
    );
}

#[tokio::test]
async fn seq_protected_callback_rejects_replay() {
    let agent_id = 0xA000_0003;
    let key = test_key(0xA3);
    let iv = test_iv(0xB3);
    let (registry, parser) = register_seq_protected_agent(agent_id, key, iv).await;

    let ack = build_init_ack(&registry, agent_id).await.expect("build_init_ack must succeed");
    let offset = ctr_blocks_for_len(ack.len());

    // First packet with seq=1 — must be accepted.
    let packet1 = build_seq_protected_callback(agent_id, key, iv, offset as u64, 1);
    parser
        .parse_at(&packet1, "10.0.0.1".to_owned(), datetime!(2026-03-20 12:01:00 UTC))
        .await
        .expect("first seq-protected callback must succeed");

    // Re-use the same ciphertext (replay of seq=1) — must be rejected.
    // Build a new packet with seq=1 at the new offset.
    let next_offset = offset
        + ctr_blocks_for_len(
            // seq prefix + payload length: 8 + 4 + 3 = 15 bytes
            8 + 4 + 3,
        );
    let replay = build_seq_protected_callback(agent_id, key, iv, next_offset as u64, 1);
    let err = parser
        .parse_at(&replay, "10.0.0.1".to_owned(), datetime!(2026-03-20 12:02:00 UTC))
        .await
        .expect_err("replay of seq=1 must be rejected");
    assert!(
        matches!(err, DemonParserError::Registry(crate::TeamserverError::CallbackSeqReplay { .. })),
        "expected CallbackSeqReplay, got: {err:?}"
    );
}

#[tokio::test]
async fn seq_protected_callback_rejects_large_gap() {
    use red_cell_common::callback_seq::MAX_SEQ_GAP;
    let agent_id = 0xA000_0004;
    let key = test_key(0xA4);
    let iv = test_iv(0xB4);
    let (_registry, parser) = register_seq_protected_agent(agent_id, key, iv).await;

    let ack = build_init_ack(&_registry, agent_id).await.expect("build_init_ack must succeed");
    let offset = ctr_blocks_for_len(ack.len());

    let packet = build_seq_protected_callback(agent_id, key, iv, offset as u64, MAX_SEQ_GAP + 1);
    let err = parser
        .parse_at(&packet, "10.0.0.1".to_owned(), datetime!(2026-03-20 12:01:00 UTC))
        .await
        .expect_err("seq gap > MAX_SEQ_GAP must be rejected");
    assert!(
        matches!(
            err,
            DemonParserError::Registry(crate::TeamserverError::CallbackSeqGapTooLarge { .. })
        ),
        "expected CallbackSeqGapTooLarge, got: {err:?}"
    );
}

#[tokio::test]
async fn non_seq_protected_callback_not_checked_for_seq() {
    // Legacy Demon agent: seq_protected = false, no seq prefix in payload.
    let agent_id = 0xA000_0005;
    let key = test_key(0xA5);
    let iv = test_iv(0xB5);
    let registry = test_registry().await;
    let parser = legacy_parser(registry.clone());

    let init = build_init_packet(agent_id, key, iv);
    parser
        .parse_at(&init, "10.0.0.1".to_owned(), datetime!(2026-03-20 12:00:00 UTC))
        .await
        .expect("legacy init must succeed");

    // For a legacy agent, is_seq_protected must be false.
    assert!(!registry.is_seq_protected(agent_id).await, "legacy agent must not be seq-protected");

    // A normal (non-seq-prefixed) callback must still parse fine.
    let ack = build_init_ack(&registry, agent_id).await.expect("build_init_ack must succeed");
    let _ = ack; // legacy mode doesn't advance CTR

    let callback = build_callback_packet(agent_id, key, iv, 0);
    parser
        .parse_at(&callback, "10.0.0.1".to_owned(), datetime!(2026-03-20 12:01:00 UTC))
        .await
        .expect("legacy callback without seq prefix must still be accepted");
}

/// Build a seq-protected callback whose seq prefix is valid but whose package
/// stream is malformed (a payload length header that promises more bytes than
/// are present).  Used to verify that a parse failure leaves both
/// `last_seen_seq` and `ctr_block_offset` unchanged — the AES-CTR-has-no-AEAD
/// desync bug fixed in red-cell-c2-4mygg.
fn build_seq_protected_callback_with_malformed_packages(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    ctr_offset: u64,
    seq: u64,
) -> Vec<u8> {
    let mut decrypted = Vec::new();
    // Valid 8-byte LE seq prefix.
    decrypted.extend_from_slice(&seq.to_le_bytes());
    // First package claims a 0xFFFF_FFFF-byte payload but has zero bytes of
    // body after the length header — `parse_callback_packages` must fail with
    // BufferTooShort.
    decrypted.extend_from_slice(&u32_be(0xFFFF_FFFF));
    let encrypted = encrypt_agent_data_at_offset(&key, &iv, ctr_offset, &decrypted)
        .expect("encrypt must succeed");
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32_be(u32::from(DemonCommand::CommandOutput)));
    payload.extend_from_slice(&u32_be(1));
    payload.extend_from_slice(&encrypted);
    DemonEnvelope::new(agent_id, payload).expect("envelope must be valid").to_bytes()
}

#[tokio::test]
async fn seq_protected_malformed_packages_does_not_consume_seq_or_ctr() {
    // Regression for red-cell-c2-4mygg: when a seq-protected callback decrypts
    // cleanly and carries a valid seq prefix but the package stream that
    // follows is malformed, the parser must leave *both* `last_seen_seq` and
    // `ctr_block_offset` untouched so the real agent's next legitimate
    // callback at seq=N+1 still lines up with the stored keystream position.
    let agent_id = 0xA000_0006;
    let key = test_key(0xA6);
    let iv = test_iv(0xB6);
    let (registry, parser) = register_seq_protected_agent(agent_id, key, iv).await;

    let ack = build_init_ack(&registry, agent_id).await.expect("build_init_ack must succeed");
    let start_offset = ctr_blocks_for_len(ack.len()) as u64;

    // Sanity: confirm starting state.
    assert_eq!(
        registry.ctr_offset(agent_id).await.expect("ctr_offset must succeed"),
        start_offset,
        "ctr offset must equal init-ack block count before any callback"
    );
    assert!(
        registry.check_callback_seq(agent_id, 1).await.is_ok(),
        "seq=1 must be acceptable before any callback"
    );

    // Malformed-by-packages callback at seq=1 must be rejected.
    let bad =
        build_seq_protected_callback_with_malformed_packages(agent_id, key, iv, start_offset, 1);
    let err = parser
        .parse_at(&bad, "10.0.0.1".to_owned(), datetime!(2026-03-20 12:01:00 UTC))
        .await
        .expect_err("malformed-packages callback must be rejected");
    assert!(
        matches!(err, DemonParserError::Protocol(_)),
        "expected protocol parse error, got: {err:?}"
    );

    // (b) last_seen_seq must be unchanged — seq=1 must still be acceptable.
    assert!(
        registry.check_callback_seq(agent_id, 1).await.is_ok(),
        "last_seen_seq must be unchanged: seq=1 must remain acceptable after parse failure"
    );
    // (c) ctr_block_offset must be unchanged.
    assert_eq!(
        registry.ctr_offset(agent_id).await.expect("ctr_offset must succeed"),
        start_offset,
        "ctr offset must be unchanged after malformed-packages parse failure"
    );

    // (d) A subsequent legitimate callback at seq=1 must still be accepted —
    // which is only possible if the CTR keystream is still positioned at
    // `start_offset`, i.e. the failed packet did not desync it.
    let good = build_seq_protected_callback(agent_id, key, iv, start_offset, 1);
    parser
        .parse_at(&good, "10.0.0.1".to_owned(), datetime!(2026-03-20 12:02:00 UTC))
        .await
        .expect("subsequent legitimate callback at seq=1 must succeed");

    // And now seq=1 is consumed, seq=2 remains acceptable.
    assert!(
        registry.check_callback_seq(agent_id, 1).await.is_err(),
        "seq=1 must be rejected after legitimate callback commits it"
    );
    assert!(
        registry.check_callback_seq(agent_id, 2).await.is_ok(),
        "seq=2 must still be acceptable"
    );
}

// ── parse_batched_callback_packages (Demon/Archon GET_JOB format) ─────────

fn build_raw_batched_callback(packages: &[(u32, u32, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    for &(cmd, req, payload) in packages {
        buf.extend_from_slice(&u32_be(cmd));
        buf.extend_from_slice(&u32_be(req));
        buf.extend_from_slice(&u32_be(u32::try_from(payload.len()).expect("len")));
        buf.extend_from_slice(payload);
    }
    buf
}

#[test]
fn batched_callback_empty_body_returns_get_job_only() {
    let packages =
        parse_batched_callback_packages(0x99, &[]).expect("empty heartbeat body must be accepted");
    assert_eq!(packages.len(), 1);
    assert_eq!(packages[0].command_id, u32::from(DemonCommand::CommandGetJob));
    assert_eq!(packages[0].request_id, 0x99);
    assert!(packages[0].payload.is_empty());
}

#[test]
fn batched_callback_single_package() {
    let buf =
        build_raw_batched_callback(&[(u32::from(DemonCommand::CommandOutput), 0xABCD, b"hello")]);
    let packages =
        parse_batched_callback_packages(0, &buf).expect("single batched package should parse");
    assert_eq!(packages.len(), 2);
    assert_eq!(packages[0].command_id, u32::from(DemonCommand::CommandGetJob));
    assert_eq!(packages[1].command_id, u32::from(DemonCommand::CommandOutput));
    assert_eq!(packages[1].request_id, 0xABCD);
    assert_eq!(packages[1].payload, b"hello");
}

#[test]
fn batched_callback_multiple_packages() {
    let buf = build_raw_batched_callback(&[
        (u32::from(DemonCommand::CommandOutput), 0x01, b"first"),
        (u32::from(DemonCommand::CommandError), 0x02, b"second"),
        (u32::from(DemonCommand::CommandJob), 0x03, b"third"),
    ]);
    let packages =
        parse_batched_callback_packages(0, &buf).expect("three batched packages should parse");
    assert_eq!(packages.len(), 4);
    assert_eq!(packages[0].command_id, u32::from(DemonCommand::CommandGetJob));
    assert_eq!(packages[1].command_id, u32::from(DemonCommand::CommandOutput));
    assert_eq!(packages[1].payload, b"first");
    assert_eq!(packages[2].command_id, u32::from(DemonCommand::CommandError));
    assert_eq!(packages[2].payload, b"second");
    assert_eq!(packages[3].command_id, u32::from(DemonCommand::CommandJob));
    assert_eq!(packages[3].payload, b"third");
}

#[test]
fn batched_callback_truncated_command_id_returns_error() {
    let buf = &[0xDE, 0xAD]; // only 2 bytes, not enough for 4-byte command_id
    let error =
        parse_batched_callback_packages(0, buf).expect_err("truncated command_id must fail");
    assert!(matches!(error, DemonParserError::Protocol(_)));
}

#[test]
fn batched_callback_truncated_payload_returns_error() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&u32_be(u32::from(DemonCommand::CommandOutput)));
    buf.extend_from_slice(&u32_be(0x01));
    buf.extend_from_slice(&u32_be(100)); // claims 100 bytes
    buf.extend_from_slice(&[0xAA, 0xBB]); // only 2 available
    let error = parse_batched_callback_packages(0, &buf).expect_err("truncated payload must fail");
    assert!(matches!(error, DemonParserError::Protocol(_)));
}

// ── DemonPacketParser integration: Demon-style GET_JOB batched callback ───

fn build_demon_get_job_callback(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    ctr_offset: u64,
    sub_packages: &[(u32, u32, &[u8])],
) -> Vec<u8> {
    let decrypted = build_raw_batched_callback(sub_packages);
    let encrypted = encrypt_agent_data_at_offset(&key, &iv, ctr_offset, &decrypted)
        .expect("callback encryption should succeed");
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32_be(u32::from(DemonCommand::CommandGetJob)));
    payload.extend_from_slice(&u32_be(0)); // outer request_id
    payload.extend_from_slice(&encrypted);
    DemonEnvelope::new(agent_id, payload).expect("envelope").to_bytes()
}

#[tokio::test]
async fn parser_handles_demon_get_job_with_output() {
    let registry = test_registry().await;
    let parser = legacy_parser(registry.clone());
    let key = test_key(0x61);
    let iv = test_iv(0x62);
    let agent_id: u32 = 0xDEAD_0001;

    let init_packet = build_init_packet(agent_id, key, iv);
    parser
        .parse_at(&init_packet, "10.0.0.1".to_owned(), datetime!(2026-04-28 10:00:00 UTC))
        .await
        .expect("init should succeed");

    let _ack = build_init_ack(&registry, agent_id).await.expect("ack");

    let callback = build_demon_get_job_callback(
        agent_id,
        key,
        iv,
        0,
        &[
            (u32::from(DemonCommand::CommandOutput), 0x1234, b"whoami output"),
            (u32::from(DemonCommand::CommandError), 0x5678, b"err"),
        ],
    );
    let parsed = parser
        .parse_at(&callback, "10.0.0.1".to_owned(), datetime!(2026-04-28 10:01:00 UTC))
        .await
        .expect("demon GET_JOB callback should parse");

    let ParsedDemonPacket::Callback { header, packages } = parsed else {
        panic!("expected Callback variant");
    };
    assert_eq!(header.agent_id, agent_id);
    assert_eq!(packages.len(), 3);
    assert_eq!(packages[0].command_id, u32::from(DemonCommand::CommandGetJob));
    assert_eq!(packages[1].command_id, u32::from(DemonCommand::CommandOutput));
    assert_eq!(packages[1].request_id, 0x1234);
    assert_eq!(packages[1].payload, b"whoami output");
    assert_eq!(packages[2].command_id, u32::from(DemonCommand::CommandError));
    assert_eq!(packages[2].request_id, 0x5678);
    assert_eq!(packages[2].payload, b"err");
}

#[tokio::test]
async fn parser_handles_demon_empty_heartbeat() {
    let registry = test_registry().await;
    let parser = legacy_parser(registry.clone());
    let key = test_key(0x71);
    let iv = test_iv(0x72);
    let agent_id: u32 = 0xDEAD_0002;

    let init_packet = build_init_packet(agent_id, key, iv);
    parser
        .parse_at(&init_packet, "10.0.0.1".to_owned(), datetime!(2026-04-28 11:00:00 UTC))
        .await
        .expect("init should succeed");

    let _ack = build_init_ack(&registry, agent_id).await.expect("ack");

    let callback = build_demon_get_job_callback(agent_id, key, iv, 0, &[]);
    let parsed = parser
        .parse_at(&callback, "10.0.0.1".to_owned(), datetime!(2026-04-28 11:01:00 UTC))
        .await
        .expect("empty heartbeat GET_JOB should parse");

    let ParsedDemonPacket::Callback { header, packages } = parsed else {
        panic!("expected Callback variant");
    };
    assert_eq!(header.agent_id, agent_id);
    assert_eq!(packages.len(), 1, "empty heartbeat should yield only the synthetic GET_JOB");
    assert_eq!(packages[0].command_id, u32::from(DemonCommand::CommandGetJob));
}
