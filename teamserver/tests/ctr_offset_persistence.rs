//! Integration tests for AES-CTR block offset persistence and concurrency safety.
//!
//! Verifies that `AgentRegistry::load()` correctly reloads the per-agent CTR block
//! offset from SQLite, so that encryption after a restart continues from the correct
//! keystream position rather than silently resetting to block 0 (two-time-pad collision).
//!
//! Also verifies that concurrent `encrypt_for_agent` calls on the same agent never
//! produce overlapping keystream offsets (two-time-pad collision).

use std::collections::HashSet;
use std::sync::Arc;

use red_cell::database::TeamserverError;
use red_cell::{AgentRegistry, database::Database};
use red_cell_common::{
    AgentEncryptionInfo, AgentRecord,
    crypto::{
        AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len, decrypt_agent_data_at_offset,
        encrypt_agent_data_at_offset,
    },
};
use sqlx::Executor as _;
use zeroize::Zeroizing;

fn sample_agent_with_crypto(
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
        hostname: "wkstn-test".to_owned(),
        username: "testuser".to_owned(),
        domain_name: "TESTDOMAIN".to_owned(),
        external_ip: "203.0.113.1".to_owned(),
        internal_ip: "10.0.0.1".to_owned(),
        process_name: "test.exe".to_owned(),
        process_path: "C:\\test.exe".to_owned(),
        base_address: 0x400000,
        process_pid: 100,
        process_tid: 101,
        process_ppid: 4,
        process_arch: "x64".to_owned(),
        elevated: false,
        os_version: "Windows 10".to_owned(),
        os_build: 19041,
        os_arch: "x64".to_owned(),
        sleep_delay: 5,
        sleep_jitter: 0,
        kill_date: None,
        working_hours: None,
        first_call_in: "2026-01-01T00:00:00Z".to_owned(),
        last_call_in: "2026-01-01T00:00:01Z".to_owned(),
        archon_magic: None,
    }
}

/// Encrypting N messages with a fresh registry advances the CTR offset and persists it.
/// After dropping the registry and reloading it, the next encryption produces ciphertext
/// identical to encrypting from the persisted offset directly — confirming no keystream reuse.
#[tokio::test]
async fn ctr_offset_survives_registry_reload() -> Result<(), Box<dyn std::error::Error>> {
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F,
        0x90,
    ];
    let agent_id: u32 = 0xAB12_CD34;

    // Shared in-memory pool — both registry instances use the same SQLite data.
    let database = Database::connect_in_memory().await?;

    // --- Phase 1: register agent and advance the CTR offset via N encryptions ---
    let messages: &[&[u8]] = &[
        b"first encrypted message",
        b"second encrypted message, somewhat longer than the first one",
        b"third message to push the block counter past a single 16-byte block boundary",
    ];

    let expected_offset = {
        let registry = AgentRegistry::new(database.clone());
        let agent = sample_agent_with_crypto(agent_id, key, iv);
        registry.insert(agent).await?;

        let mut running_offset: u64 = 0;
        for msg in messages {
            registry.encrypt_for_agent(agent_id, msg).await?;
            running_offset += ctr_blocks_for_len(msg.len());
        }

        // Confirm the in-memory offset matches our manual calculation before reload.
        let stored = registry.ctr_offset(agent_id).await?;
        assert_eq!(
            stored, running_offset,
            "in-memory CTR offset should equal the sum of blocks consumed"
        );

        running_offset
        // registry is dropped here — simulated restart
    };

    // --- Phase 2: reload the registry from the shared database pool ---
    let reloaded_registry = AgentRegistry::load(database).await?;

    let reloaded_offset = reloaded_registry.ctr_offset(agent_id).await?;
    assert_eq!(
        reloaded_offset, expected_offset,
        "reloaded registry must restore CTR offset from SQLite (got {reloaded_offset}, \
         expected {expected_offset}); a reset to 0 would cause two-time-pad keystream collision"
    );

    // --- Phase 3: verify keystream continuity by comparing ciphertexts ---
    // Encrypt one more message with the reloaded registry and confirm it matches
    // a reference encryption starting from `expected_offset` — not from 0.
    let post_restart_plaintext = b"message sent after the simulated teamserver restart";

    let ciphertext_from_reloaded =
        reloaded_registry.encrypt_for_agent(agent_id, post_restart_plaintext).await?;

    let reference_ciphertext =
        encrypt_agent_data_at_offset(&key, &iv, expected_offset, post_restart_plaintext)?;

    assert_eq!(
        ciphertext_from_reloaded, reference_ciphertext,
        "post-restart ciphertext must match reference encryption from offset {expected_offset}; \
         a mismatch means the registry reset the counter to 0 (two-time-pad)"
    );

    // Sanity check: also confirm the reference ciphertext is NOT what offset-0 would produce.
    let offset_zero_ciphertext =
        encrypt_agent_data_at_offset(&key, &iv, 0, post_restart_plaintext)?;
    assert_ne!(
        ciphertext_from_reloaded, offset_zero_ciphertext,
        "test invariant violated: chosen test data produces identical ciphertext at offset 0 \
         and offset {expected_offset}; increase the number of pre-restart messages"
    );

    // Verify the post-restart ciphertext round-trips correctly when decrypted at the right offset.
    let decrypted =
        decrypt_agent_data_at_offset(&key, &iv, expected_offset, &ciphertext_from_reloaded)?;
    assert_eq!(
        decrypted, post_restart_plaintext,
        "post-restart ciphertext should decrypt back to the original plaintext"
    );

    Ok(())
}

/// Setting the CTR offset to a value above `i64::MAX` must fail because SQLite stores
/// the offset as a signed 64-bit integer. This tests the sign-conversion rejection
/// at the `set_ctr_offset` → `i64_from_u64` boundary.
#[tokio::test]
async fn set_ctr_offset_rejects_values_above_i64_max() -> Result<(), Box<dyn std::error::Error>> {
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E,
        0x3F, 0x40,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let agent_id: u32 = 0xBBBB_0001;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database);
    let agent = sample_agent_with_crypto(agent_id, key, iv);
    registry.insert(agent).await?;

    // i64::MAX + 1 is the first u64 value that cannot be stored in SQLite's INTEGER.
    let above_i64_max = i64::MAX as u64 + 1;
    let result = registry.set_ctr_offset(agent_id, above_i64_max).await;
    assert!(result.is_err(), "set_ctr_offset must reject values > i64::MAX");
    assert!(
        matches!(
            &result,
            Err(TeamserverError::InvalidPersistedValue { field, .. }) if *field == "ctr_block_offset"
        ),
        "expected InvalidPersistedValue for ctr_block_offset, got {result:?}"
    );

    // u64::MAX must also be rejected.
    let result = registry.set_ctr_offset(agent_id, u64::MAX).await;
    assert!(result.is_err(), "set_ctr_offset must reject u64::MAX");

    // The in-memory offset must remain at 0 (the initial value).
    let offset = registry.ctr_offset(agent_id).await?;
    assert_eq!(offset, 0, "offset must not change after rejected set_ctr_offset");

    Ok(())
}

/// The AES-CTR seek position is `block_offset * 16`. The maximum block offset where
/// this multiplication does not overflow u64 is `u64::MAX / 16`. This is the tightest
/// boundary — it is smaller than `i64::MAX` (the SQLite storage limit), so the crypto
/// layer rejects the offset before persistence is even attempted.
///
/// This test exercises the full `encrypt_for_agent` path at this boundary:
/// 1. Encryption at `u64::MAX / 16` succeeds (seek = `(u64::MAX / 16) * 16`, valid).
/// 2. The offset advances to `u64::MAX / 16 + 1`, which is persisted (< `i64::MAX`).
/// 3. The next encryption at `u64::MAX / 16 + 1` fails because the seek overflows u64.
/// 4. The in-memory offset is not modified on failure.
#[tokio::test]
async fn encrypt_for_agent_errors_at_crypto_seek_overflow_boundary()
-> Result<(), Box<dyn std::error::Error>> {
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E,
        0x5F, 0x60,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x11, 0x32, 0x53, 0x74, 0x95, 0xB6, 0xD7, 0xF8, 0x19, 0x3A, 0x5B, 0x7C, 0x9D, 0xBE, 0xDF,
        0xF0,
    ];
    let agent_id: u32 = 0xBBBB_0002;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database);
    let agent = sample_agent_with_crypto(agent_id, key, iv);
    registry.insert(agent).await?;

    // u64::MAX / 16 is the largest block offset where block_offset * 16 fits in u64.
    let max_safe_offset = u64::MAX / 16;
    registry.set_ctr_offset(agent_id, max_safe_offset).await?;
    assert_eq!(registry.ctr_offset(agent_id).await?, max_safe_offset);

    // Encryption at max_safe_offset succeeds — the seek is valid.
    let one_block = b"exactly-16-bytes";
    assert_eq!(one_block.len(), 16);
    let ciphertext = registry.encrypt_for_agent(agent_id, one_block).await?;
    assert!(!ciphertext.is_empty(), "encryption at max safe offset must succeed");

    // Offset is now max_safe_offset + 1, where (offset * 16) would overflow u64.
    let offset_after = registry.ctr_offset(agent_id).await?;
    assert_eq!(offset_after, max_safe_offset + 1);

    // Next encryption must fail because the seek position overflows.
    let result = registry.encrypt_for_agent(agent_id, one_block).await;
    assert!(
        result.is_err(),
        "encrypt_for_agent must fail when the CTR seek position would overflow u64"
    );

    // The in-memory offset must not have been modified.
    let offset_final = registry.ctr_offset(agent_id).await?;
    assert_eq!(
        offset_final,
        max_safe_offset + 1,
        "in-memory CTR offset must not change after a failed encrypt_for_agent"
    );

    Ok(())
}

/// When the CTR offset is at `i64::MAX` (the largest value storable in SQLite), the seek
/// position `i64::MAX * 16` overflows u64, so `encrypt_for_agent` must fail at the crypto
/// layer. This verifies the interaction between the two overflow boundaries: SQLite
/// persistence accepts `i64::MAX`, but the crypto seek rejects it.
#[tokio::test]
async fn encrypt_for_agent_errors_at_i64_max_offset() -> Result<(), Box<dyn std::error::Error>> {
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E,
        0x7F, 0x80,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x2A, 0x4B, 0x6C, 0x8D, 0xAE, 0xCF, 0xE0, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x10,
    ];
    let agent_id: u32 = 0xBBBB_0003;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database);
    let agent = sample_agent_with_crypto(agent_id, key, iv);
    registry.insert(agent).await?;

    // i64::MAX is storable in SQLite, but (i64::MAX * 16) overflows u64,
    // so the crypto seek will fail.
    let max_storable = i64::MAX as u64;
    registry.set_ctr_offset(agent_id, max_storable).await?;

    let result = registry.encrypt_for_agent(agent_id, b"payload").await;
    assert!(
        result.is_err(),
        "encrypt_for_agent at i64::MAX must fail because the seek position overflows u64"
    );

    // The in-memory offset must remain unchanged.
    let offset_after = registry.ctr_offset(agent_id).await?;
    assert_eq!(
        offset_after, max_storable,
        "in-memory CTR offset must not change after a failed encrypt_for_agent"
    );

    Ok(())
}

/// `decrypt_from_agent` must also fail at the crypto seek boundary, mirroring
/// `encrypt_for_agent` behavior. The decryption path advances the CTR offset
/// by the same block count, so it must hit the same overflow guard.
#[tokio::test]
async fn decrypt_from_agent_errors_at_crypto_seek_overflow_boundary()
-> Result<(), Box<dyn std::error::Error>> {
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
        0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E,
        0x9F, 0xA0,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x3B, 0x5C, 0x7D, 0x9E, 0xBF, 0xD0, 0xF1, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
        0x21,
    ];
    let agent_id: u32 = 0xBBBB_0004;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database);
    let agent = sample_agent_with_crypto(agent_id, key, iv);
    registry.insert(agent).await?;

    // Set offset one past the max safe value so the seek overflows.
    let past_safe = u64::MAX / 16 + 1;
    registry.set_ctr_offset(agent_id, past_safe).await?;

    // decrypt_from_agent must fail because the seek position overflows.
    let fake_ciphertext = vec![0xAA_u8; 32]; // 2 AES blocks
    let result = registry.decrypt_from_agent(agent_id, &fake_ciphertext).await;
    assert!(
        result.is_err(),
        "decrypt_from_agent must fail when the CTR seek position would overflow u64"
    );

    // The in-memory offset must remain unchanged.
    let offset_after = registry.ctr_offset(agent_id).await?;
    assert_eq!(
        offset_after, past_safe,
        "in-memory CTR offset must not change after a failed decrypt_from_agent"
    );

    Ok(())
}

/// `set_ctr_offset` accepts the largest offset that both the crypto layer and SQLite
/// can handle (`u64::MAX / 16`), and encryption at that offset succeeds. This confirms
/// there is no off-by-one in the boundary check.
#[tokio::test]
async fn encrypt_at_max_safe_offset_succeeds_and_roundtrips()
-> Result<(), Box<dyn std::error::Error>> {
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
        0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE,
        0xBF, 0xC0,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x4C, 0x6D, 0x8E, 0xAF, 0xC0, 0xE1, 0x02, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x10,
        0x32,
    ];
    let agent_id: u32 = 0xBBBB_0005;

    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database);
    let agent = sample_agent_with_crypto(agent_id, key, iv);
    registry.insert(agent).await?;

    let max_safe_offset = u64::MAX / 16;
    registry.set_ctr_offset(agent_id, max_safe_offset).await?;

    let plaintext = b"boundary test payload";
    let ciphertext = registry.encrypt_for_agent(agent_id, plaintext).await?;

    // Verify the ciphertext matches a direct encryption at the same offset.
    let reference = encrypt_agent_data_at_offset(&key, &iv, max_safe_offset, plaintext)?;
    assert_eq!(
        ciphertext, reference,
        "encryption at max safe offset must produce correct ciphertext"
    );

    // Verify the ciphertext decrypts back to the original plaintext.
    let decrypted = decrypt_agent_data_at_offset(&key, &iv, max_safe_offset, &ciphertext)?;
    assert_eq!(decrypted, plaintext, "round-trip at max safe offset must recover plaintext");

    Ok(())
}

/// A CTR offset of zero on reload means the DB either never stored the offset or stored 0.
/// This test registers an agent and immediately reloads it — confirming the initial offset
/// of 0 is also faithfully round-tripped (no off-by-one on first registration).
#[tokio::test]
async fn ctr_offset_zero_is_preserved_on_reload() -> Result<(), Box<dyn std::error::Error>> {
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
        0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE,
        0xDF, 0xE0,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x5D, 0x7E, 0x9F, 0xB0, 0xD1, 0xF2, 0x13, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x21,
        0x43,
    ];
    let agent_id: u32 = 0x0000_0001;

    let database = Database::connect_in_memory().await?;

    {
        let registry = AgentRegistry::new(database.clone());
        let agent = sample_agent_with_crypto(agent_id, key, iv);
        registry.insert(agent).await?;
        // No encryptions — offset stays at 0.
        let offset = registry.ctr_offset(agent_id).await?;
        assert_eq!(offset, 0, "freshly registered agent should start at CTR offset 0");
    }

    let reloaded = AgentRegistry::load(database).await?;
    let reloaded_offset = reloaded.ctr_offset(agent_id).await?;
    assert_eq!(reloaded_offset, 0, "reloaded offset should still be 0 when no messages were sent");

    Ok(())
}

/// Advancing the offset by exactly one block-boundary value (16 bytes) is preserved.
#[tokio::test]
async fn ctr_offset_exact_block_boundary_is_preserved() -> Result<(), Box<dyn std::error::Error>> {
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
        0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE,
        0xFF, 0x00,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x6E, 0x8F, 0xA0, 0xC1, 0xE2, 0x03, 0x24, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x32,
        0x54,
    ];
    let agent_id: u32 = 0x0000_0002;

    let database = Database::connect_in_memory().await?;

    // A 16-byte plaintext consumes exactly one AES block.
    let one_block = b"exactly-16-bytes";
    assert_eq!(one_block.len(), 16, "test data must be exactly one AES block");

    let expected_offset = {
        let registry = AgentRegistry::new(database.clone());
        let agent = sample_agent_with_crypto(agent_id, key, iv);
        registry.insert(agent).await?;
        registry.encrypt_for_agent(agent_id, one_block).await?;
        registry.ctr_offset(agent_id).await?
    };

    assert_eq!(expected_offset, 1, "one 16-byte message should advance offset by exactly 1 block");

    let reloaded = AgentRegistry::load(database).await?;
    assert_eq!(
        reloaded.ctr_offset(agent_id).await?,
        1,
        "reloaded offset must be 1 after one 16-byte message"
    );

    Ok(())
}

/// Concurrent `encrypt_for_agent` calls on the same agent must never reuse a CTR offset.
///
/// Spawns N tasks that each encrypt a payload for the same agent simultaneously.
/// Verifies:
/// 1. All returned ciphertexts are pairwise distinct (no two-time-pad collision).
/// 2. The final persisted CTR offset equals the sum of blocks consumed by all N calls.
#[tokio::test]
async fn concurrent_encrypt_for_agent_no_offset_collision() -> Result<(), Box<dyn std::error::Error>>
{
    const NUM_CONCURRENT: usize = 20;

    let key: [u8; AGENT_KEY_LENGTH] = [
        0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1,
        0xF0, 0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA, 0xE9, 0xE8, 0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2,
        0xE1, 0xE0,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x7F, 0x90, 0xB1, 0xD2, 0xF3, 0x14, 0x35, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x43,
        0x65,
    ];
    let agent_id: u32 = 0xC0C0_CAFE;

    let database = Database::connect_in_memory().await?;
    let registry = Arc::new(AgentRegistry::new(database));
    let agent = sample_agent_with_crypto(agent_id, key, iv);
    registry.insert(agent).await?;

    // Each task encrypts the same plaintext so that any keystream overlap would produce
    // identical ciphertext — making collision detection trivial.
    let payload = b"concurrent-test-payload-32-bytes!";
    let blocks_per_call = ctr_blocks_for_len(payload.len());

    // Spawn N concurrent encrypt tasks.
    let mut handles = Vec::with_capacity(NUM_CONCURRENT);
    for _ in 0..NUM_CONCURRENT {
        let reg = Arc::clone(&registry);
        let data = payload.to_vec();
        handles.push(tokio::spawn(async move { reg.encrypt_for_agent(agent_id, &data).await }));
    }

    // Collect all results.
    let mut ciphertexts = Vec::with_capacity(NUM_CONCURRENT);
    for handle in handles {
        ciphertexts.push(handle.await??);
    }

    // 1. All ciphertexts must be pairwise distinct.
    let unique: HashSet<&Vec<u8>> = ciphertexts.iter().collect();
    assert_eq!(
        unique.len(),
        NUM_CONCURRENT,
        "expected {NUM_CONCURRENT} distinct ciphertexts but got {}; \
         duplicate ciphertext means two calls shared the same CTR offset (two-time-pad)",
        unique.len(),
    );

    // 2. The final CTR offset must equal blocks_per_call * NUM_CONCURRENT.
    let expected_total_offset = blocks_per_call * NUM_CONCURRENT as u64;
    let final_offset = registry.ctr_offset(agent_id).await?;
    assert_eq!(
        final_offset, expected_total_offset,
        "final CTR offset should be {expected_total_offset} \
         ({blocks_per_call} blocks/call * {NUM_CONCURRENT} calls), got {final_offset}"
    );

    Ok(())
}

/// After a reload, `decrypt_from_agent` must decrypt ciphertext produced at the persisted CTR
/// offset and advance the offset correctly — proving the inbound decryption path also resumes
/// from the stored keystream position rather than resetting to block 0.
#[tokio::test]
async fn decrypt_from_agent_uses_persisted_ctr_offset_after_reload()
-> Result<(), Box<dyn std::error::Error>> {
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xDF, 0xCE, 0xBD, 0xAC, 0x9B, 0x8A, 0x79, 0x68, 0x57, 0x46, 0x35, 0x24, 0x13, 0x02, 0xF1,
        0xE0, 0xCF, 0xBE, 0xAD, 0x9C, 0x8B, 0x7A, 0x69, 0x58, 0x47, 0x36, 0x25, 0x14, 0x03, 0xF2,
        0xE1, 0xD0,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x80, 0xA1, 0xC2, 0xE3, 0x04, 0x25, 0x46, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x54,
        0x76,
    ];
    let agent_id: u32 = 0xDEC0_DE01;

    let database = Database::connect_in_memory().await?;

    // --- Phase 1: register agent and advance CTR offset with outbound encryptions ---
    let pre_messages: &[&[u8]] =
        &[b"outbound message one", b"outbound message two, a bit longer to push the block counter"];

    let offset_before_reload = {
        let registry = AgentRegistry::new(database.clone());
        let agent = sample_agent_with_crypto(agent_id, key, iv);
        registry.insert(agent).await?;

        let mut running_offset: u64 = 0;
        for msg in pre_messages {
            registry.encrypt_for_agent(agent_id, msg).await?;
            running_offset += ctr_blocks_for_len(msg.len());
        }

        let stored = registry.ctr_offset(agent_id).await?;
        assert_eq!(stored, running_offset, "pre-reload offset mismatch");
        running_offset
        // registry dropped — simulated restart
    };

    // --- Phase 2: prepare a ciphertext that the *agent* would send at the persisted offset ---
    // In the real protocol the agent encrypts from the same offset the teamserver expects.
    let inbound_plaintext = b"callback payload sent by agent after teamserver restart";
    let reference_ciphertext =
        encrypt_agent_data_at_offset(&key, &iv, offset_before_reload, inbound_plaintext)?;

    // --- Phase 3: reload the registry and decrypt the inbound ciphertext ---
    let reloaded = AgentRegistry::load(database).await?;

    // Sanity: the reloaded offset should match what was persisted.
    assert_eq!(
        reloaded.ctr_offset(agent_id).await?,
        offset_before_reload,
        "reloaded offset mismatch before decrypt"
    );

    let decrypted = reloaded.decrypt_from_agent(agent_id, &reference_ciphertext).await?;
    assert_eq!(
        decrypted, inbound_plaintext,
        "decrypt_from_agent after reload must recover the original plaintext; \
         failure means the inbound CTR offset was not restored from the database"
    );

    // --- Phase 4: verify the offset advanced by the correct number of blocks ---
    let expected_post_decrypt_offset =
        offset_before_reload + ctr_blocks_for_len(inbound_plaintext.len());
    let post_decrypt_offset = reloaded.ctr_offset(agent_id).await?;
    assert_eq!(
        post_decrypt_offset, expected_post_decrypt_offset,
        "after decrypt_from_agent the CTR offset should advance from {offset_before_reload} \
         to {expected_post_decrypt_offset}, got {post_decrypt_offset}"
    );

    // --- Phase 5: confirm that decrypting at offset 0 would NOT produce valid plaintext ---
    let wrong_plaintext = decrypt_agent_data_at_offset(&key, &iv, 0, &reference_ciphertext)?;
    assert_ne!(
        wrong_plaintext.as_slice(),
        inbound_plaintext,
        "test invariant violated: ciphertext at persisted offset is identical to offset 0; \
         increase pre-reload messages to push the offset further"
    );

    Ok(())
}

/// Calling `ctr_offset`, `encrypt_for_agent`, or `decrypt_from_agent` with an agent ID
/// that does not exist in the registry must return `Err(AgentNotFound)` — not `Ok` with
/// a default offset and not a panic. In the real protocol, a replay or late packet from
/// a dead/deleted agent could trigger a decryption call for an unknown ID; silently
/// returning offset 0 would produce garbage, and panicking would crash the teamserver.
#[tokio::test]
async fn ctr_operations_reject_unknown_agent_id() -> Result<(), Box<dyn std::error::Error>> {
    let database = Database::connect_in_memory().await?;
    let registry = AgentRegistry::new(database);

    let unknown_id: u32 = 0xDEAD_BEEF;

    // ctr_offset must return AgentNotFound.
    let result = registry.ctr_offset(unknown_id).await;
    assert!(
        matches!(
            &result,
            Err(TeamserverError::AgentNotFound { agent_id }) if *agent_id == unknown_id
        ),
        "ctr_offset on unknown agent must return AgentNotFound, got {result:?}"
    );

    // encrypt_for_agent must return AgentNotFound.
    let result = registry.encrypt_for_agent(unknown_id, b"data").await;
    assert!(
        matches!(
            &result,
            Err(TeamserverError::AgentNotFound { agent_id }) if *agent_id == unknown_id
        ),
        "encrypt_for_agent on unknown agent must return AgentNotFound, got {result:?}"
    );

    // decrypt_from_agent must return AgentNotFound.
    let result = registry.decrypt_from_agent(unknown_id, &[0u8; 16]).await;
    assert!(
        matches!(
            &result,
            Err(TeamserverError::AgentNotFound { agent_id }) if *agent_id == unknown_id
        ),
        "decrypt_from_agent on unknown agent must return AgentNotFound, got {result:?}"
    );

    Ok(())
}

/// If SQLite contains a negative `ctr_block_offset` (e.g., from DB corruption or a
/// botched migration), `AgentRegistry::load()` must return an explicit
/// `InvalidPersistedValue` error rather than silently converting the negative i64 to a
/// huge u64 (e.g., -1 → `u64::MAX`) and proceeding with a completely wrong keystream
/// position that would permanently desynchronise the Demon agent's CTR counter.
#[tokio::test]
async fn load_rejects_negative_ctr_block_offset_in_database()
-> Result<(), Box<dyn std::error::Error>> {
    let key: [u8; AGENT_KEY_LENGTH] = [
        0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
        0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE,
        0xCF, 0xD0,
    ];
    let iv: [u8; AGENT_IV_LENGTH] = [
        0x91, 0xA2, 0xB3, 0xC4, 0xD5, 0xE6, 0xF7, 0x08, 0x19, 0x2A, 0x3B, 0x4C, 0x5D, 0x6E, 0x7F,
        0x80,
    ];
    let agent_id: u32 = 0xDEAD_C0DE;

    // Shared in-memory pool — both the setup registry and AgentRegistry::load() use the
    // same SQLite data, so the corrupted row is visible on reload.
    let database = Database::connect_in_memory().await?;

    // Register the agent with a normal offset so the row exists.
    {
        let registry = AgentRegistry::new(database.clone());
        let agent = sample_agent_with_crypto(agent_id, key, iv);
        registry.insert(agent).await?;

        // Advance the offset to a non-zero value to ensure the corruption is detectable.
        registry.encrypt_for_agent(agent_id, b"some outbound data").await?;
        let offset = registry.ctr_offset(agent_id).await?;
        assert!(offset > 0, "sanity: offset must be non-zero before corruption");
    }

    // Directly corrupt the stored offset — simulating DB corruption, a botched migration,
    // or a direct SQL write that bypasses the Rust validation layer.
    let agent_id_i64 = i64::from(agent_id);
    database
        .pool()
        .execute(
            sqlx::query("UPDATE ts_agents SET ctr_block_offset = -1 WHERE agent_id = ?")
                .bind(agent_id_i64),
        )
        .await?;

    // AgentRegistry::load() must fail rather than silently accepting the corrupt value.
    let result = AgentRegistry::load(database).await;
    assert!(
        result.is_err(),
        "AgentRegistry::load() must return Err when a row contains a negative \
         ctr_block_offset; silent sign conversion to u64::MAX would cause permanent \
         CTR desynchronisation with the Demon agent"
    );
    assert!(
        matches!(
            &result,
            Err(TeamserverError::InvalidPersistedValue { field, .. }) if *field == "ctr_block_offset"
        ),
        "expected InvalidPersistedValue {{ field: \"ctr_block_offset\" }}, got {result:?}"
    );

    Ok(())
}
