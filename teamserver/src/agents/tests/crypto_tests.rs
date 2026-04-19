use red_cell_common::AgentEncryptionInfo;
use red_cell_common::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len, encrypt_agent_data_at_offset,
};
use zeroize::Zeroizing;

use super::super::AgentRegistry;
use super::{sample_agent, sample_agent_with_crypto, test_database, test_iv, test_key};
use crate::database::TeamserverError;

#[tokio::test]
async fn encryption_round_trips() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database.clone());
    let agent = sample_agent(0x1000_0007);
    let updated = AgentEncryptionInfo {
        aes_key: Zeroizing::new(b"new-key".to_vec()),
        aes_iv: Zeroizing::new(b"new-iv".to_vec()),
    };
    registry.insert(agent.clone()).await?;

    assert_eq!(registry.encryption(agent.agent_id).await?, agent.encryption);
    registry.set_encryption(agent.agent_id, updated.clone()).await?;
    assert_eq!(registry.encryption(agent.agent_id).await?, updated.clone());
    assert_eq!(
        database
            .agents()
            .get(agent.agent_id)
            .await?
            .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?
            .encryption,
        updated
    );

    Ok(())
}

#[tokio::test]
async fn encrypt_for_agent_advances_ctr_offset_per_message() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let key = test_key(0x31);
    let iv = test_iv(0x41);
    let agent = sample_agent_with_crypto(0x1000_0701, key, iv);
    let plaintext = b"first encrypted payload";

    registry.insert(agent.clone()).await?;

    assert_eq!(registry.ctr_offset(agent.agent_id).await?, 0);

    let first = registry.encrypt_for_agent(agent.agent_id, plaintext).await?;
    let second = registry.encrypt_for_agent(agent.agent_id, plaintext).await?;

    assert_eq!(first, encrypt_agent_data_at_offset(&key, &iv, 0, plaintext)?);
    assert_eq!(second, encrypt_agent_data_at_offset(&key, &iv, 2, plaintext)?);
    assert_ne!(first, second);
    assert_eq!(registry.ctr_offset(agent.agent_id).await?, 4);

    Ok(())
}

#[tokio::test]
async fn encrypt_and_decrypt_for_agent_round_trip() -> Result<(), TeamserverError> {
    let sender = AgentRegistry::new(test_database().await?);
    let receiver = AgentRegistry::new(test_database().await?);
    let agent = sample_agent_with_crypto(0x1000_0702, test_key(0x52), test_iv(0x62));
    let plaintext = b"callback payload requiring ctr synchronisation";

    sender.insert(agent.clone()).await?;
    receiver.insert(agent.clone()).await?;

    let ciphertext = sender.encrypt_for_agent(agent.agent_id, plaintext).await?;
    let decrypted = receiver.decrypt_from_agent(agent.agent_id, &ciphertext).await?;

    assert_eq!(decrypted, plaintext);
    assert_eq!(sender.ctr_offset(agent.agent_id).await?, ctr_blocks_for_len(plaintext.len()));
    assert_eq!(receiver.ctr_offset(agent.agent_id).await?, ctr_blocks_for_len(ciphertext.len()));

    Ok(())
}

#[tokio::test]
async fn encrypt_for_agent_empty_plaintext_returns_empty_and_preserves_ctr()
-> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let key = test_key(0xA1);
    let iv = test_iv(0xB1);
    let agent = sample_agent_with_crypto(0x1000_0E01, key, iv);

    registry.insert(agent.clone()).await?;
    assert_eq!(registry.ctr_offset(agent.agent_id).await?, 0);

    let ciphertext = registry.encrypt_for_agent(agent.agent_id, &[]).await?;

    assert!(ciphertext.is_empty(), "encrypting empty plaintext must produce empty ciphertext");
    assert_eq!(
        registry.ctr_offset(agent.agent_id).await?,
        0,
        "CTR offset must not advance for empty plaintext"
    );

    Ok(())
}

#[tokio::test]
async fn decrypt_from_agent_empty_ciphertext_returns_empty_and_preserves_ctr()
-> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let key = test_key(0xA2);
    let iv = test_iv(0xB2);
    let agent = sample_agent_with_crypto(0x1000_0E02, key, iv);

    registry.insert(agent.clone()).await?;
    assert_eq!(registry.ctr_offset(agent.agent_id).await?, 0);

    let plaintext = registry.decrypt_from_agent(agent.agent_id, &[]).await?;

    assert!(plaintext.is_empty(), "decrypting empty ciphertext must produce empty plaintext");
    assert_eq!(
        registry.ctr_offset(agent.agent_id).await?,
        0,
        "CTR offset must not advance for empty ciphertext"
    );

    Ok(())
}

#[tokio::test]
async fn encrypt_empty_then_non_empty_preserves_keystream_continuity() -> Result<(), TeamserverError>
{
    let registry = AgentRegistry::new(test_database().await?);
    let key = test_key(0xA3);
    let iv = test_iv(0xB3);
    let agent = sample_agent_with_crypto(0x1000_0E03, key, iv);
    let payload = b"payload after empty";

    registry.insert(agent.clone()).await?;

    // Encrypt empty — offset must stay at 0.
    let _ = registry.encrypt_for_agent(agent.agent_id, &[]).await?;
    assert_eq!(registry.ctr_offset(agent.agent_id).await?, 0);

    // Encrypt a real payload — must use offset 0 keystream.
    let ciphertext = registry.encrypt_for_agent(agent.agent_id, payload).await?;
    let expected = encrypt_agent_data_at_offset(&key, &iv, 0, payload)?;
    assert_eq!(
        ciphertext, expected,
        "empty encrypt must not shift the keystream for subsequent messages"
    );

    Ok(())
}

#[tokio::test]
async fn set_ctr_offset_changes_agent_transport_keystream() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let key = test_key(0x73);
    let iv = test_iv(0x83);
    let agent = sample_agent_with_crypto(0x1000_0703, key, iv);
    let starting_offset = 9;
    let plaintext = b"offset-aware encryption";

    registry.insert(agent.clone()).await?;
    registry.set_ctr_offset(agent.agent_id, starting_offset).await?;

    let ciphertext = registry.encrypt_for_agent(agent.agent_id, plaintext).await?;
    let expected_ciphertext = encrypt_agent_data_at_offset(&key, &iv, starting_offset, plaintext)?;

    assert_eq!(ciphertext, expected_ciphertext);
    assert_eq!(
        registry.ctr_offset(agent.agent_id).await?,
        starting_offset + ctr_blocks_for_len(plaintext.len())
    );

    Ok(())
}

#[tokio::test]
async fn encrypt_for_agent_without_advancing_keeps_ctr_unchanged() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let key = test_key(0x74);
    let iv = test_iv(0x84);
    let agent = sample_agent_with_crypto(0x1000_0705, key, iv);
    let starting_offset = 11;
    let plaintext = b"preview-only encryption";

    registry.insert(agent.clone()).await?;
    registry.set_ctr_offset(agent.agent_id, starting_offset).await?;

    let ciphertext =
        registry.encrypt_for_agent_without_advancing(agent.agent_id, plaintext).await?;
    let expected_ciphertext = encrypt_agent_data_at_offset(&key, &iv, starting_offset, plaintext)?;

    assert_eq!(ciphertext, expected_ciphertext);
    assert_eq!(registry.ctr_offset(agent.agent_id).await?, starting_offset);

    Ok(())
}

#[tokio::test]
async fn decrypt_from_agent_without_advancing_keeps_ctr_unchanged() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let key = test_key(0x75);
    let iv = test_iv(0x85);
    let agent = sample_agent_with_crypto(0x1000_0706, key, iv);
    let starting_offset = 7;
    let plaintext = b"decrypt-without-advance payload";

    registry.insert(agent.clone()).await?;
    registry.set_ctr_offset(agent.agent_id, starting_offset).await?;

    let ciphertext = encrypt_agent_data_at_offset(&key, &iv, starting_offset, plaintext)?;
    let decrypted =
        registry.decrypt_from_agent_without_advancing(agent.agent_id, &ciphertext).await?;

    assert_eq!(decrypted, plaintext);
    // Offset must NOT have advanced.
    assert_eq!(registry.ctr_offset(agent.agent_id).await?, starting_offset);

    Ok(())
}

#[tokio::test]
async fn advance_ctr_for_agent_commits_offset_correctly() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let key = test_key(0x76);
    let iv = test_iv(0x86);
    let agent = sample_agent_with_crypto(0x1000_0707, key, iv);
    let starting_offset = 3;
    let payload = b"advance-ctr test payload";

    registry.insert(agent.clone()).await?;
    registry.set_ctr_offset(agent.agent_id, starting_offset).await?;

    let ciphertext = encrypt_agent_data_at_offset(&key, &iv, starting_offset, payload)?;

    // Decrypt without advancing, then advance explicitly.
    let decrypted =
        registry.decrypt_from_agent_without_advancing(agent.agent_id, &ciphertext).await?;
    assert_eq!(decrypted, payload);
    assert_eq!(registry.ctr_offset(agent.agent_id).await?, starting_offset);

    registry.advance_ctr_for_agent(agent.agent_id, ciphertext.len()).await?;
    assert_eq!(
        registry.ctr_offset(agent.agent_id).await?,
        starting_offset + ctr_blocks_for_len(ciphertext.len())
    );

    Ok(())
}

#[tokio::test]
async fn decrypt_without_advancing_then_advance_matches_single_step_decrypt()
-> Result<(), TeamserverError> {
    // Verify that split decrypt+advance produces the same final offset as the normal
    // decrypt_from_agent (which advances atomically in one step).
    let registry_split = AgentRegistry::new(test_database().await?);
    let registry_atomic = AgentRegistry::new(test_database().await?);
    let key = test_key(0x77);
    let iv = test_iv(0x87);
    let agent = sample_agent_with_crypto(0x1000_0708, key, iv);
    let plaintext = b"split vs atomic ctr advance";

    registry_split.insert(agent.clone()).await?;
    registry_atomic.insert(agent.clone()).await?;

    let ciphertext = encrypt_agent_data_at_offset(&key, &iv, 0, plaintext)?;

    // Split path.
    let dec_split =
        registry_split.decrypt_from_agent_without_advancing(agent.agent_id, &ciphertext).await?;
    registry_split.advance_ctr_for_agent(agent.agent_id, ciphertext.len()).await?;

    // Atomic path.
    let dec_atomic = registry_atomic.decrypt_from_agent(agent.agent_id, &ciphertext).await?;

    assert_eq!(dec_split, plaintext);
    assert_eq!(dec_atomic, plaintext);
    assert_eq!(
        registry_split.ctr_offset(agent.agent_id).await?,
        registry_atomic.ctr_offset(agent.agent_id).await?
    );

    Ok(())
}

#[tokio::test]
async fn zero_key_agent_transport_is_rejected() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let agent =
        sample_agent_with_crypto(0x1000_0704, [0u8; AGENT_KEY_LENGTH], [0u8; AGENT_IV_LENGTH]);
    let plaintext = b"plaintext transport";

    registry.insert(agent.clone()).await?;

    assert!(matches!(
        registry.encrypt_for_agent(agent.agent_id, plaintext).await,
        Err(TeamserverError::InvalidAgentCrypto { agent_id, .. }) if agent_id == agent.agent_id
    ));
    assert!(matches!(
        registry.decrypt_from_agent(agent.agent_id, plaintext).await,
        Err(TeamserverError::InvalidAgentCrypto { agent_id, .. }) if agent_id == agent.agent_id
    ));
    assert_eq!(registry.ctr_offset(agent.agent_id).await?, 0);

    Ok(())
}

#[tokio::test]
async fn ctr_helpers_reject_unknown_agent_ids() {
    let registry = AgentRegistry::new(test_database().await.expect("db"));
    let missing_agent_id = 0x1000_07FF;

    assert!(matches!(
        registry.ctr_offset(missing_agent_id).await,
        Err(TeamserverError::AgentNotFound { agent_id }) if agent_id == missing_agent_id
    ));
    assert!(matches!(
        registry.set_ctr_offset(missing_agent_id, 4).await,
        Err(TeamserverError::AgentNotFound { agent_id }) if agent_id == missing_agent_id
    ));
    assert!(matches!(
        registry.encrypt_for_agent(missing_agent_id, b"abc").await,
        Err(TeamserverError::AgentNotFound { agent_id }) if agent_id == missing_agent_id
    ));
    assert!(matches!(
        registry.decrypt_from_agent(missing_agent_id, b"abc").await,
        Err(TeamserverError::AgentNotFound { agent_id }) if agent_id == missing_agent_id
    ));
}

/// Closing the pool simulates a SQLite write failure for set_ctr_offset.
/// The in-memory CTR offset must remain at its original value when the
/// persistence step fails.
#[tokio::test]
async fn set_ctr_offset_no_partial_mutation_on_db_failure() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database.clone());
    let agent = sample_agent(0x1000_F001);
    registry.insert(agent.clone()).await?;

    // Establish a known initial offset.
    registry.set_ctr_offset(agent.agent_id, 5).await?;
    assert_eq!(registry.ctr_offset(agent.agent_id).await?, 5);

    // Closing the pool causes any subsequent writes to fail.
    database.close().await;

    let result = registry.set_ctr_offset(agent.agent_id, 99).await;
    assert!(result.is_err(), "expected DB write to fail after pool close");

    // In-memory state must not have advanced.
    assert_eq!(
        registry.ctr_offset(agent.agent_id).await?,
        5,
        "in-memory ctr_block_offset must not mutate when persistence fails"
    );

    Ok(())
}

/// Closing the pool simulates a SQLite write failure for set_encryption.
/// The in-memory AES key/IV must remain at their original values when the
/// persistence step fails.
#[tokio::test]
async fn set_encryption_no_partial_mutation_on_db_failure() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database.clone());
    let agent = sample_agent_with_crypto(0x1000_F002, test_key(0xAA), test_iv(0xBB));
    registry.insert(agent.clone()).await?;

    let original_enc = registry.encryption(agent.agent_id).await?;

    // Closing the pool causes any subsequent writes to fail.
    database.close().await;

    let new_enc = AgentEncryptionInfo {
        aes_key: Zeroizing::new(vec![0xCC; AGENT_KEY_LENGTH]),
        aes_iv: Zeroizing::new(vec![0xDD; AGENT_IV_LENGTH]),
    };
    let result = registry.set_encryption(agent.agent_id, new_enc).await;
    assert!(result.is_err(), "expected DB write to fail after pool close");

    // In-memory encryption must not have changed.
    let current_enc = registry.encryption(agent.agent_id).await?;
    assert_eq!(
        current_enc, original_enc,
        "in-memory encryption must not mutate when persistence fails"
    );

    Ok(())
}

#[tokio::test]
async fn encrypt_for_agent_returns_agent_not_found_for_unknown_id() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let unknown_id: u32 = 0x1234;

    let result = registry.encrypt_for_agent(unknown_id, b"data").await;

    assert!(
        matches!(&result, Err(TeamserverError::AgentNotFound { agent_id }) if *agent_id == unknown_id),
        "expected AgentNotFound for 0x{unknown_id:08X}, got {result:?}"
    );

    Ok(())
}

#[tokio::test]
async fn decrypt_from_agent_returns_agent_not_found_for_unknown_id() -> Result<(), TeamserverError>
{
    let registry = AgentRegistry::new(test_database().await?);
    let unknown_id: u32 = 0x1234;

    let result = registry.decrypt_from_agent(unknown_id, b"data").await;

    assert!(
        matches!(&result, Err(TeamserverError::AgentNotFound { agent_id }) if *agent_id == unknown_id),
        "expected AgentNotFound for 0x{unknown_id:08X}, got {result:?}"
    );

    Ok(())
}

#[test]
fn next_ctr_offset_returns_error_on_u64_overflow() {
    // Place the offset near u64::MAX so adding even 1 block overflows.
    let near_max = u64::MAX;
    let result = super::super::crypto::next_ctr_offset(near_max, 16);
    assert!(result.is_err(), "adding 1 block at u64::MAX must overflow");
}

#[test]
fn next_ctr_offset_succeeds_at_maximum_non_overflowing_value() {
    // u64::MAX - 1 + 1 block = u64::MAX, which is representable.
    let result = super::super::crypto::next_ctr_offset(u64::MAX - 1, 16);
    assert_eq!(result.expect("unwrap"), u64::MAX);
}

#[test]
fn next_ctr_offset_zero_payload_does_not_advance() {
    let result = super::super::crypto::next_ctr_offset(u64::MAX, 0);
    assert_eq!(result.expect("unwrap"), u64::MAX, "zero-length payload must not advance");
}

#[tokio::test]
async fn advance_ctr_for_agent_errors_on_overflow_near_i64_max() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database);
    let agent = sample_agent_with_crypto(0x1000_FFFE, test_key(0xCC), test_iv(0xDD));
    registry.insert(agent.clone()).await?;

    // i64::MAX as u64 is the largest offset storable in SQLite.
    let max_storable = i64::MAX as u64;
    registry.set_ctr_offset(agent.agent_id, max_storable).await?;
    assert_eq!(registry.ctr_offset(agent.agent_id).await?, max_storable);

    // Advancing by 16 bytes (1 block) would push past i64::MAX, which
    // next_ctr_offset allows (it works in u64 space), but persistence will
    // reject the resulting value.  Either way the operation must fail.
    let result = registry.advance_ctr_for_agent(agent.agent_id, 16).await;
    assert!(result.is_err(), "advance past i64::MAX must fail on persist");

    // In-memory offset must remain unchanged after the failed advance.
    assert_eq!(
        registry.ctr_offset(agent.agent_id).await?,
        max_storable,
        "in-memory ctr_block_offset must not change on overflow"
    );

    Ok(())
}

#[tokio::test]
async fn advance_ctr_for_agent_succeeds_at_i64_max_boundary() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database);
    let agent = sample_agent_with_crypto(0x1000_FFFD, test_key(0xCC), test_iv(0xDD));
    registry.insert(agent.clone()).await?;

    // Set to (i64::MAX - 1) as u64, then advance by 1 block → i64::MAX as u64.
    let near_max = (i64::MAX - 1) as u64;
    registry.set_ctr_offset(agent.agent_id, near_max).await?;
    registry.advance_ctr_for_agent(agent.agent_id, 16).await?;

    assert_eq!(
        registry.ctr_offset(agent.agent_id).await?,
        i64::MAX as u64,
        "advance to exactly i64::MAX must succeed"
    );

    Ok(())
}

#[tokio::test]
async fn advance_ctr_for_agent_zero_len_at_max_does_not_advance() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database);
    let agent = sample_agent_with_crypto(0x1000_FFFC, test_key(0xCC), test_iv(0xDD));
    registry.insert(agent.clone()).await?;

    let max_storable = i64::MAX as u64;
    registry.set_ctr_offset(agent.agent_id, max_storable).await?;
    // Zero-length payload must not overflow even at the storage limit.
    registry.advance_ctr_for_agent(agent.agent_id, 0).await?;

    assert_eq!(registry.ctr_offset(agent.agent_id).await?, max_storable);

    Ok(())
}

/// Inserting an agent whose AES key is the wrong length (e.g. 16 bytes instead of 32)
/// causes `encrypt_for_agent` and `decrypt_from_agent` to return
/// `InvalidPersistedValue` from `decode_crypto_material` / `copy_fixed`.
#[tokio::test]
async fn encrypt_decrypt_reject_truncated_key_material() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let mut agent = sample_agent(0x1000_0D01);
    // 16-byte key instead of the required 32 (AGENT_KEY_LENGTH).
    agent.encryption = AgentEncryptionInfo {
        aes_key: Zeroizing::new(vec![0xAA; 16]),
        aes_iv: Zeroizing::new(vec![0xBB; AGENT_IV_LENGTH]),
    };
    registry.insert(agent.clone()).await?;

    let enc_result = registry.encrypt_for_agent(agent.agent_id, b"hello").await;
    assert!(
        matches!(
            &enc_result,
            Err(TeamserverError::InvalidPersistedValue { field, .. }) if *field == "aes_key"
        ),
        "expected InvalidPersistedValue for aes_key, got {enc_result:?}"
    );

    let dec_result = registry.decrypt_from_agent(agent.agent_id, b"hello").await;
    assert!(
        matches!(
            &dec_result,
            Err(TeamserverError::InvalidPersistedValue { field, .. }) if *field == "aes_key"
        ),
        "expected InvalidPersistedValue for aes_key, got {dec_result:?}"
    );

    // CTR offset must remain untouched because we never reached encryption.
    assert_eq!(registry.ctr_offset(agent.agent_id).await?, 0);

    Ok(())
}

/// Same as the above test but with a truncated IV instead of the key.
#[tokio::test]
async fn encrypt_decrypt_reject_truncated_iv_material() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let mut agent = sample_agent(0x1000_0D02);
    agent.encryption = AgentEncryptionInfo {
        aes_key: Zeroizing::new(vec![0xAA; AGENT_KEY_LENGTH]),
        aes_iv: Zeroizing::new(vec![0xBB; 8]), // 8 bytes instead of AGENT_IV_LENGTH (16)
    };
    registry.insert(agent.clone()).await?;

    let enc_result = registry.encrypt_for_agent(agent.agent_id, b"hello").await;
    assert!(
        matches!(
            &enc_result,
            Err(TeamserverError::InvalidPersistedValue { field, .. }) if *field == "aes_iv"
        ),
        "expected InvalidPersistedValue for aes_iv, got {enc_result:?}"
    );

    Ok(())
}

/// `advance_ctr_for_agent` must return `AgentNotFound` for a non-existent agent.
#[tokio::test]
async fn advance_ctr_for_agent_returns_agent_not_found_for_unknown_id() {
    let registry = AgentRegistry::new(test_database().await.expect("db"));
    let missing = 0x1000_0D03;

    assert!(matches!(
        registry.advance_ctr_for_agent(missing, 16).await,
        Err(TeamserverError::AgentNotFound { agent_id }) if agent_id == missing
    ));
}

/// After a successful `set_encryption`, both the in-memory value and the persisted
/// database row must reflect the new key material.
#[tokio::test]
async fn set_encryption_updates_both_memory_and_database() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database.clone());
    let agent = sample_agent_with_crypto(0x1000_0D04, test_key(0x11), test_iv(0x22));
    registry.insert(agent.clone()).await?;

    let new_enc = AgentEncryptionInfo {
        aes_key: Zeroizing::new(vec![0xCC; AGENT_KEY_LENGTH]),
        aes_iv: Zeroizing::new(vec![0xDD; AGENT_IV_LENGTH]),
    };
    registry.set_encryption(agent.agent_id, new_enc.clone()).await?;

    // In-memory value must match.
    assert_eq!(registry.encryption(agent.agent_id).await?, new_enc);

    // Database value must also match.
    let persisted = database
        .agents()
        .get(agent.agent_id)
        .await?
        .ok_or(TeamserverError::AgentNotFound { agent_id: agent.agent_id })?;
    assert_eq!(persisted.encryption, new_enc);

    Ok(())
}

#[tokio::test]
async fn legacy_ctr_encrypt_always_uses_offset_zero() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let key = test_key(0xC1);
    let iv = test_iv(0xD1);
    let agent = sample_agent_with_crypto(0x100A_0C01, key, iv);

    // Insert with legacy_ctr = true
    registry.insert_full(agent.clone(), "http-legacy", 0, true, false).await?;
    assert!(registry.legacy_ctr(agent.agent_id).await?);

    let plaintext = b"legacy demon callback data";
    let ct1 = registry.encrypt_for_agent(agent.agent_id, plaintext).await?;
    let ct2 = registry.encrypt_for_agent(agent.agent_id, plaintext).await?;

    // Both must be identical (same offset 0 keystream).
    // NOTE: identical ciphertext for the same plaintext is a known two-time-pad
    // weakness in legacy mode — documented in the security warning on `insert_full`.
    // This behaviour is preserved intentionally for Havoc Demon/Archon compatibility.
    assert_eq!(ct1, ct2, "legacy mode must produce identical ciphertext for same plaintext");
    // Offset must remain at 0
    assert_eq!(registry.ctr_offset(agent.agent_id).await?, 0);
    // Verify against direct offset-0 encryption
    assert_eq!(ct1, encrypt_agent_data_at_offset(&key, &iv, 0, plaintext)?);

    Ok(())
}

#[tokio::test]
async fn legacy_ctr_decrypt_always_uses_offset_zero() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let key = test_key(0xC2);
    let iv = test_iv(0xD2);
    let agent = sample_agent_with_crypto(0x100A_0C02, key, iv);

    registry.insert_full(agent.clone(), "http-legacy", 0, true, false).await?;

    let plaintext = b"response from demon agent";
    let ciphertext = encrypt_agent_data_at_offset(&key, &iv, 0, plaintext)?;

    // Decrypt twice — both should succeed and offset should not advance
    let dec1 = registry.decrypt_from_agent(agent.agent_id, &ciphertext).await?;
    let dec2 = registry.decrypt_from_agent(agent.agent_id, &ciphertext).await?;

    assert_eq!(&dec1[..], plaintext);
    assert_eq!(&dec2[..], plaintext);
    assert_eq!(registry.ctr_offset(agent.agent_id).await?, 0);

    Ok(())
}

#[tokio::test]
async fn legacy_ctr_advance_is_noop() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let agent = sample_agent_with_crypto(0x100A_0C03, test_key(0xC3), test_iv(0xD3));

    registry.insert_full(agent.clone(), "http-legacy", 0, true, false).await?;

    registry.advance_ctr_for_agent(agent.agent_id, 1024).await?;
    assert_eq!(
        registry.ctr_offset(agent.agent_id).await?,
        0,
        "advance must be a no-op in legacy mode"
    );

    Ok(())
}

#[tokio::test]
async fn set_legacy_ctr_toggles_mode_and_persists() -> Result<(), TeamserverError> {
    let database = test_database().await?;
    let registry = AgentRegistry::new(database.clone());
    let key = test_key(0xC4);
    let iv = test_iv(0xD4);
    let agent = sample_agent_with_crypto(0x100A_0C04, key, iv);
    let plaintext = b"mode switch test";

    // Start in legacy mode
    registry.insert_full(agent.clone(), "http-legacy", 0, true, false).await?;
    assert!(registry.legacy_ctr(agent.agent_id).await?);

    let ct_legacy = registry.encrypt_for_agent(agent.agent_id, plaintext).await?;

    // Switch to monotonic mode
    registry.set_legacy_ctr(agent.agent_id, false).await?;
    assert!(!registry.legacy_ctr(agent.agent_id).await?);

    let ct_mono1 = registry.encrypt_for_agent(agent.agent_id, plaintext).await?;
    let ct_mono2 = registry.encrypt_for_agent(agent.agent_id, plaintext).await?;

    // First monotonic encryption uses offset 0 (same as legacy), second must differ
    assert_eq!(ct_legacy, ct_mono1);
    assert_ne!(ct_mono1, ct_mono2, "monotonic mode must advance");
    assert!(registry.ctr_offset(agent.agent_id).await? > 0);

    // Verify persistence — reload from DB
    let persisted =
        database.agents().get_persisted(agent.agent_id).await?.expect("agent should exist");
    assert!(!persisted.legacy_ctr, "legacy_ctr=false must be persisted");

    Ok(())
}

#[tokio::test]
async fn legacy_ctr_persists_across_registry_reload() -> Result<(), TeamserverError> {
    let database = test_database().await?;

    // First registry: insert with legacy mode
    {
        let registry = AgentRegistry::new(database.clone());
        let agent = sample_agent_with_crypto(0x100A_0C05, test_key(0xC5), test_iv(0xD5));
        registry.insert_full(agent, "http-legacy", 0, true, false).await?;
    }

    // Second registry: reload from DB
    let registry = AgentRegistry::load(database).await?;
    assert!(registry.legacy_ctr(0x100A_0C05).await?, "legacy_ctr must survive registry reload");

    Ok(())
}

#[tokio::test]
async fn non_legacy_insert_defaults_to_monotonic_mode() -> Result<(), TeamserverError> {
    let registry = AgentRegistry::new(test_database().await?);
    let key = test_key(0xC6);
    let iv = test_iv(0xD6);
    let agent = sample_agent_with_crypto(0x100A_0C06, key, iv);
    let plaintext = b"specter monotonic test";

    // Default insert (non-legacy)
    registry.insert(agent.clone()).await?;
    assert!(!registry.legacy_ctr(agent.agent_id).await?);

    let ct1 = registry.encrypt_for_agent(agent.agent_id, plaintext).await?;
    let ct2 = registry.encrypt_for_agent(agent.agent_id, plaintext).await?;
    assert_ne!(ct1, ct2, "default insert must use monotonic mode");

    Ok(())
}
