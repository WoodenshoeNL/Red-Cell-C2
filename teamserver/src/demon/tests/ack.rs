use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, decrypt_agent_data_at_offset};
use red_cell_common::{AgentEncryptionInfo, AgentRecord};
use time::macros::datetime;
use zeroize::Zeroizing;

use super::{
    agent_with_raw_crypto, build_init_packet, legacy_parser, temp_db_path, test_iv, test_key,
    test_registry,
};
use crate::demon::{DemonParserError, build_init_ack, build_reconnect_ack};
use crate::{AgentRegistry, Database};

#[tokio::test]
async fn build_init_ack_encrypts_agent_identifier() {
    let registry = test_registry().await;
    let key = test_key(0x33);
    let iv = test_iv(0x44);
    let agent_id: u32 = 0xAABB_CCDD;

    let init_packet = build_init_packet(agent_id, key, iv);
    let parser = legacy_parser(registry.clone());
    parser
        .parse_at(&init_packet, "10.0.0.1".to_owned(), datetime!(2026-03-09 19:40:00 UTC))
        .await
        .expect("init should succeed");

    let ack = build_init_ack(&registry, agent_id).await.expect("ack should build");
    let decrypted = decrypt_agent_data_at_offset(&key, &iv, 0, &ack).expect("ack should decrypt");
    assert_eq!(decrypted, agent_id.to_le_bytes());
    // Legacy mode: CTR stays at 0.
    assert_eq!(registry.ctr_offset(agent_id).await.expect("offset"), 0);
}

#[tokio::test]
async fn build_init_ack_after_registry_reload_uses_persisted_crypto_material() {
    let database =
        Database::connect(temp_db_path()).await.expect("temp database should initialize");
    let registry = AgentRegistry::new(database.clone());
    let parser = legacy_parser(registry.clone());
    let key = test_key(0x55);
    let iv = test_iv(0x66);
    let agent_id: u32 = 0x1122_3344;

    let init_packet = build_init_packet(agent_id, key, iv);
    parser
        .parse_at(&init_packet, "10.0.0.3".to_owned(), datetime!(2026-03-09 19:45:00 UTC))
        .await
        .expect("init should succeed");

    let first_ack = build_init_ack(&registry, agent_id).await.expect("ack should build");

    let reloaded = AgentRegistry::load(database).await.expect("registry should reload");

    // Legacy mode: offset is still 0 after reload, so the ACK is byte-identical.
    let ack = build_init_ack(&reloaded, agent_id).await.expect("reconnect ack should build");
    let decrypted = decrypt_agent_data_at_offset(&key, &iv, 0, &ack).expect("ack should decrypt");
    assert_eq!(decrypted, agent_id.to_le_bytes());
    assert_eq!(first_ack, ack, "legacy mode ACKs at offset 0 must be identical across reloads");
}

#[tokio::test]
async fn build_reconnect_ack_uses_current_ctr_offset_without_advancing_registry_state() {
    let registry = test_registry().await;
    let key = test_key(0x56);
    let iv = test_iv(0x67);
    let agent_id: u32 = 0x5566_7788;

    let init_packet = build_init_packet(agent_id, key, iv);
    let parser = legacy_parser(registry.clone());
    parser
        .parse_at(&init_packet, "10.0.0.4".to_owned(), datetime!(2026-03-09 19:46:00 UTC))
        .await
        .expect("init should succeed");

    let _first_ack = build_init_ack(&registry, agent_id).await.expect("ack should build");
    let offset_before_reconnect = registry.ctr_offset(agent_id).await.expect("offset");

    let ack = build_reconnect_ack(&registry, agent_id).await.expect("reconnect ack");
    let decrypted = decrypt_agent_data_at_offset(&key, &iv, offset_before_reconnect, &ack)
        .expect("ack should decrypt");

    assert_eq!(decrypted, agent_id.to_le_bytes());
    assert_eq!(registry.ctr_offset(agent_id).await.expect("offset"), offset_before_reconnect);
}

#[tokio::test]
async fn successive_messages_use_same_keystream_in_legacy_mode() {
    let registry = test_registry().await;
    let parser = legacy_parser(registry.clone());
    let key = test_key(0x77);
    let iv = test_iv(0x88);
    let agent_id: u32 = 0xDEAD_BEEF;

    let init_packet = build_init_packet(agent_id, key, iv);
    parser
        .parse_at(&init_packet, "10.0.0.2".to_owned(), datetime!(2026-03-09 19:50:00 UTC))
        .await
        .expect("init should succeed");

    // Legacy mode: successive encryptions produce identical ciphertext (offset 0).
    let msg = b"same-payload-bytes";
    let ct1 = registry.encrypt_for_agent(agent_id, msg).await.expect("enc1");
    let ct2 = registry.encrypt_for_agent(agent_id, msg).await.expect("enc2");

    assert_eq!(ct1, ct2, "legacy mode must reuse the same keystream block");

    let pt1 = decrypt_agent_data_at_offset(&key, &iv, 0, &ct1).expect("dec1");
    assert_eq!(pt1, msg);
}

#[tokio::test]
async fn build_init_ack_rejects_zero_key_agent() {
    let registry = test_registry().await;
    let agent_id: u32 = 0x2468_ACED;
    let agent = AgentRecord {
        agent_id,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: AgentEncryptionInfo {
            aes_key: Zeroizing::new(vec![0; AGENT_KEY_LENGTH]),
            aes_iv: Zeroizing::new(vec![0; AGENT_IV_LENGTH]),
        },
        hostname: "wkstn-01".to_owned(),
        username: "operator".to_owned(),
        domain_name: "REDCELL".to_owned(),
        external_ip: "203.0.113.1".to_owned(),
        internal_ip: "10.0.0.10".to_owned(),
        process_name: "explorer.exe".to_owned(),
        process_path: "C:\\Windows\\explorer.exe".to_owned(),
        base_address: 0x401000,
        process_pid: 1337,
        process_tid: 1338,
        process_ppid: 512,
        process_arch: "x64".to_owned(),
        elevated: true,
        os_version: "Windows 11".to_owned(),
        os_build: 0,
        os_arch: "x64/AMD64".to_owned(),
        sleep_delay: 15,
        sleep_jitter: 20,
        kill_date: Some(1_893_456_000),
        working_hours: Some(0b101010),
        first_call_in: "2026-03-10T10:15:00Z".to_owned(),
        last_call_in: "2026-03-10T10:15:00Z".to_owned(),
        archon_magic: None,
    };
    registry.insert(agent).await.expect("agent insert should succeed");

    let error =
        build_init_ack(&registry, agent_id).await.expect_err("zero-key ack must be rejected");

    assert!(
        matches!(
            error,
            DemonParserError::Registry(crate::TeamserverError::InvalidAgentCrypto {
                agent_id: rejected_agent_id,
                ..
            }) if rejected_agent_id == agent_id
        ),
        "expected invalid zero-key agent crypto, got: {error}"
    );
}

// ── Round-trip wire-format verification for build_init_ack / build_reconnect_ack ──

#[tokio::test]
async fn build_init_ack_wire_format_is_exactly_four_le_bytes_of_agent_id() {
    let registry = test_registry().await;
    let key = test_key(0xA1);
    let iv = test_iv(0xB2);
    let agent_id: u32 = 0x1234_5678;

    let init_packet = build_init_packet(agent_id, key, iv);
    let parser = legacy_parser(registry.clone());
    parser
        .parse_at(&init_packet, "10.0.0.10".to_owned(), datetime!(2026-03-19 10:00:00 UTC))
        .await
        .expect("init should succeed");

    let ack = build_init_ack(&registry, agent_id).await.expect("ack should build");

    // CTR mode preserves plaintext length — the ciphertext must be exactly 4 bytes
    // (the LE-encoded agent_id with no framing, padding, or length prefix).
    assert_eq!(
        ack.len(),
        4,
        "init ACK ciphertext must be exactly 4 bytes (agent_id LE), got {}",
        ack.len()
    );

    // Decrypt at offset 0 (first encryption after init) and verify exact field layout.
    let plaintext = decrypt_agent_data_at_offset(&key, &iv, 0, &ack).expect("ack should decrypt");
    assert_eq!(plaintext.len(), 4, "plaintext must be exactly 4 bytes");

    // Verify each byte position matches the LE encoding of agent_id.
    let expected = agent_id.to_le_bytes();
    assert_eq!(plaintext[0], expected[0], "byte 0 mismatch");
    assert_eq!(plaintext[1], expected[1], "byte 1 mismatch");
    assert_eq!(plaintext[2], expected[2], "byte 2 mismatch");
    assert_eq!(plaintext[3], expected[3], "byte 3 mismatch");
}

#[tokio::test]
async fn build_init_ack_successive_calls_produce_identical_ciphertext_in_legacy_mode() {
    let registry = test_registry().await;
    let key = test_key(0xC3);
    let iv = test_iv(0xD4);
    let agent_id: u32 = 0xAAAA_BBBB;

    let init_packet = build_init_packet(agent_id, key, iv);
    let parser = legacy_parser(registry.clone());
    parser
        .parse_at(&init_packet, "10.0.0.11".to_owned(), datetime!(2026-03-19 10:01:00 UTC))
        .await
        .expect("init should succeed");

    // DEMON_INIT registers with legacy_ctr = true.
    assert!(registry.legacy_ctr(agent_id).await.expect("legacy_ctr"));

    let ack1 = build_init_ack(&registry, agent_id).await.expect("first ack");
    let ack2 = build_init_ack(&registry, agent_id).await.expect("second ack");

    // Legacy mode: both decrypt at offset 0 to the same plaintext.
    let pt1 = decrypt_agent_data_at_offset(&key, &iv, 0, &ack1).expect("decrypt ack1");
    let pt2 = decrypt_agent_data_at_offset(&key, &iv, 0, &ack2).expect("decrypt ack2");
    assert_eq!(pt1, agent_id.to_le_bytes());
    assert_eq!(pt2, agent_id.to_le_bytes());

    // Legacy mode: ciphertext is identical (same offset 0 keystream, same plaintext).
    assert_eq!(ack1, ack2, "legacy mode ACKs must be byte-identical");
    assert_eq!(registry.ctr_offset(agent_id).await.expect("offset"), 0);
}

#[tokio::test]
async fn build_reconnect_ack_wire_format_legacy_mode() {
    let registry = test_registry().await;
    let key = test_key(0xE5);
    let iv = test_iv(0xF6);
    let agent_id: u32 = 0xCCDD_EEFF;

    let init_packet = build_init_packet(agent_id, key, iv);
    let parser = legacy_parser(registry.clone());
    parser
        .parse_at(&init_packet, "10.0.0.12".to_owned(), datetime!(2026-03-19 10:02:00 UTC))
        .await
        .expect("init should succeed");

    // Legacy mode: CTR stays at 0 regardless of how many ACKs are sent.
    for _ in 0..3 {
        let _ = build_init_ack(&registry, agent_id).await.expect("ack should build");
    }
    assert_eq!(registry.ctr_offset(agent_id).await.expect("offset"), 0);

    // Reconnect ACK encrypts at offset 0 in legacy mode.
    let reconnect_ack = build_reconnect_ack(&registry, agent_id).await.expect("reconnect ack");
    assert_eq!(reconnect_ack.len(), 4);

    let plaintext = decrypt_agent_data_at_offset(&key, &iv, 0, &reconnect_ack)
        .expect("reconnect ack should decrypt at offset 0");
    assert_eq!(plaintext, agent_id.to_le_bytes());

    // A second reconnect ACK must produce identical ciphertext (same offset, same plaintext).
    let reconnect_ack2 =
        build_reconnect_ack(&registry, agent_id).await.expect("second reconnect ack");
    assert_eq!(
        reconnect_ack, reconnect_ack2,
        "repeated reconnect ACKs must be byte-identical in legacy mode"
    );
}

#[tokio::test]
async fn build_reconnect_ack_decrypting_at_wrong_offset_yields_garbage() {
    // Use a non-legacy agent to test that wrong-offset decryption fails.
    let registry = test_registry().await;
    let key = test_key(0x17);
    let iv = test_iv(0x28);
    let agent_id: u32 = 0x1111_2222;

    let init_packet = build_init_packet(agent_id, key, iv);
    let parser = legacy_parser(registry.clone());
    parser
        .parse_at(&init_packet, "10.0.0.13".to_owned(), datetime!(2026-03-19 10:03:00 UTC))
        .await
        .expect("init should succeed");

    // Switch to monotonic mode so CTR actually advances.
    registry.set_legacy_ctr(agent_id, false).await.expect("set_legacy_ctr");

    // Advance to offset 1.
    let _ = build_init_ack(&registry, agent_id).await.expect("ack");
    let offset = registry.ctr_offset(agent_id).await.expect("offset");
    assert_eq!(offset, 1);

    let reconnect_ack = build_reconnect_ack(&registry, agent_id).await.expect("reconnect ack");

    // Decrypting at the wrong offset (0 instead of 1) must NOT produce the agent_id.
    let wrong_plaintext = decrypt_agent_data_at_offset(&key, &iv, 0, &reconnect_ack)
        .expect("decryption itself succeeds");
    assert_ne!(
        wrong_plaintext,
        agent_id.to_le_bytes(),
        "decrypting reconnect ACK at wrong CTR offset must not yield the correct agent_id"
    );
}

// ---- InvalidStoredCryptoEncoding coverage (ack path) ----

#[tokio::test]
async fn build_init_ack_returns_invalid_stored_crypto_for_bad_key() {
    let registry = test_registry().await;
    let agent_id: u32 = 0xBAD0_0001;
    let agent = agent_with_raw_crypto(agent_id, vec![0xAA; 5], vec![0xBB; AGENT_IV_LENGTH]);
    registry.insert(agent).await.expect("insert should succeed");

    let error = build_init_ack(&registry, agent_id).await.expect_err("bad key must be rejected");

    match &error {
        DemonParserError::InvalidStoredCryptoEncoding { agent_id: err_id, field, .. } => {
            assert_eq!(*err_id, agent_id);
            assert_eq!(*field, "aes_key");
        }
        other => panic!("expected InvalidStoredCryptoEncoding for aes_key, got: {other}"),
    }
}

#[tokio::test]
async fn build_init_ack_returns_invalid_stored_crypto_for_bad_iv() {
    let registry = test_registry().await;
    let agent_id: u32 = 0xBAD0_0002;
    let agent = agent_with_raw_crypto(agent_id, vec![0xCC; AGENT_KEY_LENGTH], vec![0xDD; 3]);
    registry.insert(agent).await.expect("insert should succeed");

    let error = build_init_ack(&registry, agent_id).await.expect_err("bad IV must be rejected");

    match &error {
        DemonParserError::InvalidStoredCryptoEncoding { agent_id: err_id, field, .. } => {
            assert_eq!(*err_id, agent_id);
            assert_eq!(*field, "aes_iv");
        }
        other => panic!("expected InvalidStoredCryptoEncoding for aes_iv, got: {other}"),
    }
}

#[tokio::test]
async fn build_reconnect_ack_returns_invalid_stored_crypto_for_bad_key() {
    let registry = test_registry().await;
    let agent_id: u32 = 0xBAD0_0003;
    let agent = agent_with_raw_crypto(agent_id, vec![0xEE; 10], vec![0xFF; AGENT_IV_LENGTH]);
    registry.insert(agent).await.expect("insert should succeed");

    let error =
        build_reconnect_ack(&registry, agent_id).await.expect_err("bad key must be rejected");

    match &error {
        DemonParserError::InvalidStoredCryptoEncoding { agent_id: err_id, field, .. } => {
            assert_eq!(*err_id, agent_id);
            assert_eq!(*field, "aes_key");
        }
        other => panic!("expected InvalidStoredCryptoEncoding for aes_key, got: {other}"),
    }
}

#[tokio::test]
async fn build_reconnect_ack_returns_invalid_stored_crypto_for_bad_iv() {
    let registry = test_registry().await;
    let agent_id: u32 = 0xBAD0_0006;
    let agent = agent_with_raw_crypto(agent_id, vec![0xCC; AGENT_KEY_LENGTH], vec![0xDD; 2]);
    registry.insert(agent).await.expect("insert should succeed");

    let error =
        build_reconnect_ack(&registry, agent_id).await.expect_err("bad IV must be rejected");

    match &error {
        DemonParserError::InvalidStoredCryptoEncoding { agent_id: err_id, field, .. } => {
            assert_eq!(*err_id, agent_id);
            assert_eq!(*field, "aes_iv");
        }
        other => panic!("expected InvalidStoredCryptoEncoding for aes_iv, got: {other}"),
    }
}
