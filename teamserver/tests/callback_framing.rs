//! Callback/dispatch framing conformance tests.
//!
//! Each test covers one specific framing failure mode from a cycled bug.
//! All tests use hand-crafted byte sequences and run deterministically
//! without a live agent, HTTP listener, or operator WebSocket session.
//!
//! Bug classes covered:
//! - `38svz`: batched GET_JOB framing — multiple callbacks packed in one encrypted body
//! - `pa1wi`: Phantom ECDH callback batching — `DemonMessage` little-endian multi-package
//! - endianness: Demon/Archon wire format uses big-endian for the outer callback command_id

use red_cell::{AgentRegistry, Database, DemonPacketParser, ParsedDemonPacket};
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, encrypt_agent_data_at_offset};
use red_cell_common::demon::{DemonCommand, DemonEnvelope, DemonMessage, DemonPackage};
use red_cell_common::{AgentEncryptionInfo, AgentRecord};
use zeroize::Zeroizing;

// ── fixture helpers ────────────────────────────────────────────────

fn framing_key(seed: u8) -> [u8; AGENT_KEY_LENGTH] {
    core::array::from_fn(|i| seed.wrapping_add(i as u8))
}

fn framing_iv(seed: u8) -> [u8; AGENT_IV_LENGTH] {
    core::array::from_fn(|i| seed.wrapping_add(i as u8))
}

/// Build a minimal `AgentRecord` for framing tests; the key material is the
/// only field the parser actually inspects during a callback decode.
fn framing_agent(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
) -> AgentRecord {
    AgentRecord {
        agent_id,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: AgentEncryptionInfo {
            aes_key: Zeroizing::new(key.to_vec()),
            aes_iv: Zeroizing::new(iv.to_vec()),
            monotonic_ctr: false,
        },
        hostname: "framing-test".to_owned(),
        username: "test".to_owned(),
        domain_name: "TEST".to_owned(),
        external_ip: "127.0.0.1".to_owned(),
        internal_ip: "127.0.0.1".to_owned(),
        process_name: "test.exe".to_owned(),
        process_path: "C:\\test.exe".to_owned(),
        base_address: 0x0040_1000,
        process_pid: 100,
        process_tid: 101,
        process_ppid: 1,
        process_arch: "x64".to_owned(),
        elevated: false,
        os_version: "Test OS".to_owned(),
        os_build: 1,
        os_arch: "x64/AMD64".to_owned(),
        sleep_delay: 5,
        sleep_jitter: 0,
        kill_date: None,
        working_hours: None,
        first_call_in: "2026-05-01T00:00:00Z".to_owned(),
        last_call_in: "2026-05-01T00:00:00Z".to_owned(),
        archon_magic: None,
    }
}

/// Encode one sub-package in the batched GET_JOB wire format:
/// `(cmd_id BE u32)(req_id BE u32)(len BE u32)(payload)`.
fn batched_sub_package(cmd: DemonCommand, req_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&u32::from(cmd).to_be_bytes());
    buf.extend_from_slice(&req_id.to_be_bytes());
    buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Build a batched GET_JOB callback packet on the wire.
///
/// The outer command_id is `CommandGetJob` (BE u32).  The body — containing
/// zero or more sub-packages in the Demon batched format — is AES-CTR
/// encrypted at the given CTR block offset.
fn build_batched_get_job_packet(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    ctr_offset: u64,
    outer_request_id: u32,
    sub_packages: &[&[u8]],
) -> Vec<u8> {
    let body: Vec<u8> = sub_packages.iter().flat_map(|p| p.iter().copied()).collect();
    let encrypted = encrypt_agent_data_at_offset(&key, &iv, ctr_offset, &body)
        .expect("encryption must succeed");
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(DemonCommand::CommandGetJob).to_be_bytes());
    payload.extend_from_slice(&outer_request_id.to_be_bytes());
    payload.extend_from_slice(&encrypted);
    DemonEnvelope::new(agent_id, payload).expect("envelope must be valid").to_bytes()
}

/// Build a non-batched callback packet (standard Demon format).
///
/// The outer command_id / request_id are in the cleartext payload.
/// The body (first length-prefixed payload, followed by any additional
/// `(cmd_id BE)(req_id BE)(len BE)(payload)` triples) is AES-CTR encrypted.
fn build_callback_packet(
    agent_id: u32,
    key: [u8; AGENT_KEY_LENGTH],
    iv: [u8; AGENT_IV_LENGTH],
    ctr_offset: u64,
    outer_cmd: DemonCommand,
    outer_req_id: u32,
    body: &[u8],
) -> Vec<u8> {
    let encrypted =
        encrypt_agent_data_at_offset(&key, &iv, ctr_offset, body).expect("encryption must succeed");
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(outer_cmd).to_be_bytes());
    payload.extend_from_slice(&outer_req_id.to_be_bytes());
    payload.extend_from_slice(&encrypted);
    DemonEnvelope::new(agent_id, payload).expect("envelope must be valid").to_bytes()
}

// ── test 1 — 38svz: batched GET_JOB framing ───────────────────────

/// Multiple callbacks packed into one batched GET_JOB response must be split
/// at packet boundaries and returned in order (bug 38svz).
///
/// The parser reads `(cmd_id BE u32)(req_id BE u32)(len BE u32)(payload)` tuples
/// from the decrypted body.  An off-by-one or endianness error at any field
/// would cause either a silent truncation or a buffer-too-short parse error.
#[tokio::test]
async fn batched_get_job_splits_multiple_sub_packages_at_packet_boundaries() {
    const AGENT_ID: u32 = 0xCAFE_0001;
    let key = framing_key(0xA1);
    let iv = framing_iv(0xB1);

    let db = Database::connect_in_memory().await.expect("in-memory db");
    let registry = AgentRegistry::new(db);
    registry
        .insert_full(framing_agent(AGENT_ID, key, iv), "null", 0, true, false, false)
        .await
        .expect("agent insert must succeed");

    let parser = DemonPacketParser::new(registry).with_allow_legacy_ctr(true);

    // Build three sub-packages in BE batched format.
    let pkg1 = batched_sub_package(DemonCommand::CommandOutput, 0x0001, b"first result");
    let pkg2 = batched_sub_package(DemonCommand::CommandError, 0x0002, b"err");
    let pkg3 = batched_sub_package(DemonCommand::CommandCheckin, 0x0003, b"");

    let packet = build_batched_get_job_packet(AGENT_ID, key, iv, 0, 0xDEAD, &[&pkg1, &pkg2, &pkg3]);

    let parsed = parser
        .parse(&packet, "127.0.0.1")
        .await
        .expect("batched GET_JOB callback must parse without error");

    let ParsedDemonPacket::Callback { header, packages } = parsed else {
        panic!("expected Callback variant, got: {parsed:?}");
    };

    assert_eq!(header.agent_id, AGENT_ID, "agent_id field at offset 8 in Demon header mismatched");
    assert_eq!(
        packages.len(),
        4,
        "batched GET_JOB body with 3 sub-packages must yield 4 total packages \
         (synthetic GET_JOB sentinel + 3 sub-packages); parser split at wrong byte boundary"
    );

    // packages[0] is the synthetic GET_JOB sentinel with the outer request_id.
    assert_eq!(
        packages[0].command_id,
        u32::from(DemonCommand::CommandGetJob),
        "packages[0].command_id must be CommandGetJob sentinel"
    );
    assert_eq!(
        packages[0].request_id, 0xDEAD,
        "packages[0].request_id must carry the outer GET_JOB request_id"
    );
    assert!(packages[0].payload.is_empty(), "packages[0] sentinel must have empty payload");

    assert_eq!(
        packages[1].command_id,
        u32::from(DemonCommand::CommandOutput),
        "packages[1].command_id: wrong command at first sub-package boundary (byte offset 0)"
    );
    assert_eq!(
        packages[1].request_id, 0x0001,
        "packages[1].request_id: big-endian read at sub-package offset 4 returned wrong value"
    );
    assert_eq!(
        packages[1].payload, b"first result",
        "packages[1].payload: wrong bytes split at length boundary"
    );

    assert_eq!(
        packages[2].command_id,
        u32::from(DemonCommand::CommandError),
        "packages[2].command_id: parser advanced past first sub-package to wrong byte offset"
    );
    assert_eq!(
        packages[2].payload, b"err",
        "packages[2].payload: wrong bytes after second boundary"
    );

    assert_eq!(
        packages[3].command_id,
        u32::from(DemonCommand::CommandCheckin),
        "packages[3].command_id: wrong at third sub-package boundary"
    );
    assert_eq!(packages[3].request_id, 0x0003, "packages[3].request_id mismatch");
    assert!(packages[3].payload.is_empty(), "packages[3] must have empty payload");
}

// ── test 4 — pa1wi: Phantom ECDH callback batching ────────────────

/// Phantom encodes multiple callbacks in one `DemonMessage` session packet
/// (little-endian).  The teamserver's `parse_ecdh_session_payload` path calls
/// `DemonMessage::from_bytes` to split them.  This test verifies that
/// `DemonMessage` round-trips a multi-package payload without truncating or
/// reordering any package (bug pa1wi).
///
/// Unlike Demon/Archon (big-endian batched GET_JOB format), ECDH session
/// packages use the `DemonMessage` little-endian encoding.  A parser that
/// reads BE instead of LE (or vice-versa) would decode the wrong command_id
/// and request_id here.
#[test]
fn phantom_demon_message_from_bytes_parses_all_packages_in_batched_session_packet() {
    let packages_in = vec![
        DemonPackage::new(DemonCommand::CommandOutput, 0x1111, b"output-data".to_vec()),
        DemonPackage::new(DemonCommand::CommandCheckin, 0x2222, vec![]),
        DemonPackage::new(DemonCommand::CommandError, 0x3333, b"error-detail".to_vec()),
    ];

    let wire = DemonMessage::new(packages_in.clone())
        .to_bytes()
        .expect("DemonMessage serialization must succeed");

    let decoded = DemonMessage::from_bytes(&wire)
        .expect("DemonMessage::from_bytes must parse a valid multi-package payload");

    assert_eq!(
        decoded.packages.len(),
        3,
        "ECDH session payload with 3 packages must yield 3 decoded packages; \
         DemonMessage::from_bytes stopped early at byte offset {offset}",
        offset = decoded.packages.iter().map(DemonPackage::encoded_len).sum::<usize>()
    );

    for (i, (got, expected)) in decoded.packages.iter().zip(packages_in.iter()).enumerate() {
        assert_eq!(
            got.command_id,
            expected.command_id,
            "packages[{i}].command_id: little-endian decode returned wrong command at \
             package-stream offset {offset}",
            offset = packages_in[..i].iter().map(DemonPackage::encoded_len).sum::<usize>()
        );
        assert_eq!(
            got.request_id, expected.request_id,
            "packages[{i}].request_id: wrong value at byte 4 of package {i}"
        );
        assert_eq!(
            got.payload, expected.payload,
            "packages[{i}].payload: wrong bytes split at length boundary for package {i}"
        );
    }
}

// ── test 5 — endianness: callback command_id is big-endian ────────

/// Demon and Archon use big-endian for the outer callback command_id.
/// This test crafts a callback whose command_id is 0x0000005A (90 = CommandOutput)
/// encoded big-endian, registers an agent, and asserts the parser returns
/// CommandOutput — not the little-endian misread 0x5A000000.
///
/// If the parser read this field as little-endian, `u32::from_le_bytes([0,0,0,90])`
/// = `0x5A000000` (not a valid DemonCommand), which would cause a parse error or
/// a wrong command dispatch.
#[tokio::test]
async fn callback_command_id_wire_format_is_big_endian_matching_c_agent() {
    const AGENT_ID: u32 = 0xCAFE_0005;
    let key = framing_key(0xC1);
    let iv = framing_iv(0xD1);

    let db = Database::connect_in_memory().await.expect("in-memory db");
    let registry = AgentRegistry::new(db);
    registry
        .insert_full(framing_agent(AGENT_ID, key, iv), "null", 0, true, false, false)
        .await
        .expect("agent insert must succeed");

    let parser = DemonPacketParser::new(registry).with_allow_legacy_ctr(true);

    // Build a standard (non-batched) callback body.
    // format: [len BE u32][payload bytes]
    let payload_body = b"be-check";
    let mut body = Vec::new();
    body.extend_from_slice(&(payload_body.len() as u32).to_be_bytes()); // BE length prefix
    body.extend_from_slice(payload_body);

    // command_id = 90 (CommandOutput), encoded big-endian as the C agent sends it.
    let packet =
        build_callback_packet(AGENT_ID, key, iv, 0, DemonCommand::CommandOutput, 0xBEEF, &body);

    let parsed = parser
        .parse(&packet, "127.0.0.1")
        .await
        .expect("big-endian CommandOutput callback must parse without error");

    let ParsedDemonPacket::Callback { packages, .. } = parsed else {
        panic!("expected Callback variant, got: {parsed:?}");
    };

    assert!(!packages.is_empty(), "callback must yield at least one package");
    assert_eq!(
        packages[0].command_id,
        u32::from(DemonCommand::CommandOutput),
        "packages[0].command_id: outer payload offset 0 must decode as big-endian CommandOutput \
         ({}); a little-endian misread of the same bytes would give 0x{:08X} instead",
        u32::from(DemonCommand::CommandOutput),
        u32::from_le_bytes(u32::from(DemonCommand::CommandOutput).to_be_bytes()),
    );
    assert_eq!(
        packages[0].request_id, 0xBEEF,
        "packages[0].request_id: big-endian u32 at outer payload offset 4 must be 0xBEEF"
    );
    assert_eq!(
        packages[0].payload, payload_body,
        "packages[0].payload: body bytes must survive encrypt/decrypt round-trip"
    );
}
