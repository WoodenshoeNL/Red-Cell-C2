use cipher::InvalidLength;
use hex_literal::hex;

use super::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, AgentCryptoMaterial, CryptoError, ctr_blocks_for_len,
    decrypt_agent_data, decrypt_agent_data_at_offset, derive_session_keys,
    derive_session_keys_for_version, encrypt_agent_data, encrypt_agent_data_at_offset,
    generate_agent_crypto_material, hash_password_sha3, is_weak_aes_iv, is_weak_aes_key,
};

#[test]
fn is_weak_aes_key_detects_all_zero_key() {
    assert!(is_weak_aes_key(&[0u8; AGENT_KEY_LENGTH]));
}

#[test]
fn is_weak_aes_key_accepts_nonzero_key() {
    let mut key = [0u8; AGENT_KEY_LENGTH];
    key[0] = 1;
    assert!(!is_weak_aes_key(&key));
}

#[test]
fn is_weak_aes_key_rejects_empty_slice() {
    // An empty slice is not meaningfully "all-zero" — return false.
    assert!(!is_weak_aes_key(&[]));
}

#[test]
fn is_weak_aes_iv_rejects_empty_slice() {
    assert!(!is_weak_aes_iv(&[]));
}

#[test]
fn is_weak_aes_iv_detects_all_zero_iv() {
    assert!(is_weak_aes_iv(&[0u8; AGENT_IV_LENGTH]));
}

#[test]
fn is_weak_aes_iv_accepts_nonzero_iv() {
    let mut iv = [0u8; AGENT_IV_LENGTH];
    iv[AGENT_IV_LENGTH - 1] = 0xff;
    assert!(!is_weak_aes_iv(&iv));
}

#[test]
fn is_weak_aes_iv_empty_slice_is_not_weak() {
    assert!(!is_weak_aes_iv(&[]));
}

#[test]
fn is_weak_aes_key_detects_all_0xff() {
    assert!(is_weak_aes_key(&[0xFF; AGENT_KEY_LENGTH]));
}

#[test]
fn is_weak_aes_iv_detects_all_0xff() {
    assert!(is_weak_aes_iv(&[0xFF; AGENT_IV_LENGTH]));
}

#[test]
fn is_weak_aes_key_detects_single_repeating_byte() {
    assert!(is_weak_aes_key(&[0xAA; AGENT_KEY_LENGTH]));
    assert!(is_weak_aes_key(&[0x42; AGENT_KEY_LENGTH]));
}

#[test]
fn is_weak_aes_iv_detects_single_repeating_byte() {
    assert!(is_weak_aes_iv(&[0xAA; AGENT_IV_LENGTH]));
    assert!(is_weak_aes_iv(&[0x42; AGENT_IV_LENGTH]));
}

#[test]
fn is_weak_aes_key_detects_two_byte_repeating_pattern() {
    // [0xDE, 0xAD] repeated 16 times = 32 bytes
    let key: Vec<u8> = [0xDE, 0xAD].iter().copied().cycle().take(AGENT_KEY_LENGTH).collect();
    assert!(is_weak_aes_key(&key));
}

#[test]
fn is_weak_aes_iv_detects_two_byte_repeating_pattern() {
    let iv: Vec<u8> = [0xCA, 0xFE].iter().copied().cycle().take(AGENT_IV_LENGTH).collect();
    assert!(is_weak_aes_iv(&iv));
}

#[test]
fn is_weak_aes_key_detects_four_byte_repeating_pattern() {
    // [0xDE, 0xAD, 0xBE, 0xEF] repeated 8 times = 32 bytes
    let key: Vec<u8> =
        [0xDE, 0xAD, 0xBE, 0xEF].iter().copied().cycle().take(AGENT_KEY_LENGTH).collect();
    assert!(is_weak_aes_key(&key));
}

#[test]
fn is_weak_aes_iv_detects_four_byte_repeating_pattern() {
    let iv: Vec<u8> =
        [0xDE, 0xAD, 0xBE, 0xEF].iter().copied().cycle().take(AGENT_IV_LENGTH).collect();
    assert!(is_weak_aes_iv(&iv));
}

#[test]
fn is_weak_aes_key_detects_eight_byte_repeating_pattern() {
    // 8-byte pattern repeated 4 times = 32 bytes
    let key: Vec<u8> = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        .iter()
        .copied()
        .cycle()
        .take(AGENT_KEY_LENGTH)
        .collect();
    assert!(is_weak_aes_key(&key));
}

#[test]
fn is_weak_aes_iv_detects_eight_byte_repeating_pattern() {
    // 8-byte pattern repeated 2 times = 16 bytes
    let iv: Vec<u8> = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        .iter()
        .copied()
        .cycle()
        .take(AGENT_IV_LENGTH)
        .collect();
    assert!(is_weak_aes_iv(&iv));
}

#[test]
fn is_weak_aes_key_accepts_non_repeating_pattern() {
    // A key with genuine variety should not be flagged
    let key: [u8; AGENT_KEY_LENGTH] = [
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77,
        0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14,
        0xdf, 0xf4,
    ];
    assert!(!is_weak_aes_key(&key));
}

#[test]
fn is_weak_aes_key_accepts_nearly_repeating_pattern() {
    // A 4-byte pattern that almost repeats but differs in the last chunk
    let mut key: Vec<u8> =
        [0xDE, 0xAD, 0xBE, 0xEF].iter().copied().cycle().take(AGENT_KEY_LENGTH).collect();
    key[AGENT_KEY_LENGTH - 1] = 0x00; // break the pattern
    assert!(!is_weak_aes_key(&key));
}

#[test]
fn encrypt_agent_data_matches_reference_ciphertext() {
    let key = hex!(
        "603deb1015ca71be2b73aef0857d7781
         1f352c073b6108d72d9810a30914dff4"
    );
    let iv = hex!("000102030405060708090a0b0c0d0e0f");
    let plaintext = b"red-cell agent metadata";
    let expected_ciphertext = hex!(
        "c5da5e70975ce5b1b7919df285ba0f27
         1e2e93b8f2fd48"
    );

    let ciphertext =
        encrypt_agent_data(&key, &iv, plaintext).expect("reference encryption should succeed");

    assert_eq!(ciphertext, expected_ciphertext);
}

#[test]
fn decrypt_agent_data_recovers_reference_plaintext() {
    let key = hex!(
        "603deb1015ca71be2b73aef0857d7781
         1f352c073b6108d72d9810a30914dff4"
    );
    let iv = hex!("000102030405060708090a0b0c0d0e0f");
    let ciphertext = hex!(
        "c5da5e70975ce5b1b7919df285ba0f27
         1e2e93b8f2fd48"
    );

    let plaintext =
        decrypt_agent_data(&key, &iv, &ciphertext).expect("reference decryption should succeed");

    assert_eq!(plaintext, b"red-cell agent metadata");
}

#[test]
fn encrypt_and_decrypt_round_trip() {
    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    let plaintext = b"\x00\x01\x02demon-tasking";

    let ciphertext =
        encrypt_agent_data(&key, &iv, plaintext).expect("round-trip encryption should succeed");
    let decrypted =
        decrypt_agent_data(&key, &iv, &ciphertext).expect("round-trip decryption should succeed");

    assert_eq!(decrypted, plaintext);
    assert_ne!(ciphertext, plaintext);
}

#[test]
fn encrypt_and_decrypt_round_trip_multi_block() {
    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    // 80 bytes = 5 AES blocks (16 bytes each), verifying multi-block CTR.
    let plaintext: Vec<u8> = (0..80).collect();

    let ciphertext =
        encrypt_agent_data(&key, &iv, &plaintext).expect("multi-block encrypt should succeed");
    assert_eq!(ciphertext.len(), plaintext.len());
    assert_ne!(ciphertext, plaintext);

    let decrypted =
        decrypt_agent_data(&key, &iv, &ciphertext).expect("multi-block decrypt should succeed");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn decrypt_agent_data_rejects_invalid_iv_length() {
    let key = [0x11; AGENT_KEY_LENGTH];
    let ciphertext = [0x33; AGENT_IV_LENGTH];

    let error = decrypt_agent_data(&key, &[0x22; AGENT_IV_LENGTH - 1], &ciphertext)
        .expect_err("invalid IV length must fail decryption");

    assert!(matches!(
        error,
        CryptoError::InvalidIvLength { expected, actual }
            if expected == AGENT_IV_LENGTH && actual == AGENT_IV_LENGTH - 1
    ));
}

#[test]
fn encrypt_agent_data_rejects_invalid_key_length() {
    let error = encrypt_agent_data(&[0_u8; 31], &[0_u8; AGENT_IV_LENGTH], b"abc")
        .expect_err("invalid key length must fail encryption");

    assert!(matches!(
        error,
        CryptoError::InvalidKeyLength { expected, actual }
            if expected == AGENT_KEY_LENGTH && actual == AGENT_KEY_LENGTH - 1
    ));
}

#[test]
fn decrypt_agent_data_rejects_invalid_key_length() {
    let error = decrypt_agent_data(&[0x11; AGENT_KEY_LENGTH - 1], &[0x22; AGENT_IV_LENGTH], b"")
        .expect_err("invalid key length must fail decryption");

    assert!(matches!(
        error,
        CryptoError::InvalidKeyLength { expected, actual }
            if expected == AGENT_KEY_LENGTH && actual == AGENT_KEY_LENGTH - 1
    ));
}

#[test]
fn encrypt_agent_data_preserves_empty_plaintext() {
    let ciphertext = encrypt_agent_data(&[0x41; AGENT_KEY_LENGTH], &[0x24; AGENT_IV_LENGTH], b"")
        .expect("empty plaintext encryption should succeed");

    assert!(ciphertext.is_empty());
}

#[test]
fn generate_agent_crypto_material_returns_expected_sizes() {
    let material =
        generate_agent_crypto_material().expect("OS randomness should be available for tests");

    assert_eq!(material.key.len(), AGENT_KEY_LENGTH);
    assert_eq!(material.iv.len(), AGENT_IV_LENGTH);
    assert_ne!(material.key, [0_u8; AGENT_KEY_LENGTH]);
    assert_ne!(material.iv, [0_u8; AGENT_IV_LENGTH]);
    assert!(!is_weak_aes_iv(&material.iv));
}

#[test]
fn hash_password_sha3_produces_known_digest() {
    let digest = hash_password_sha3("password1234");
    assert_eq!(digest.len(), 64);
    assert_eq!(digest, "2f7d3e77d0786c5d305c0afadd4c1a2a6869a3210956c963ad2420c52e797022");
}

#[test]
fn hash_password_sha3_empty_input() {
    let digest = hash_password_sha3("");
    assert_eq!(digest.len(), 64);
    assert_eq!(digest, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
}

#[test]
fn hash_password_sha3_is_deterministic() {
    let first = hash_password_sha3("test-password");
    let second = hash_password_sha3("test-password");
    assert_eq!(first, second);
}

#[test]
fn hash_password_sha3_handles_non_ascii_unicode() {
    // Multi-byte UTF-8: CJK ideograph, emoji, accented chars — verified against
    // Python hashlib.sha3_256 reference digests.
    let digest_cjk = hash_password_sha3("密码");
    assert_eq!(
        digest_cjk, "66855cb24193f8e5b6a310b6ba67509a7e0dfd71dbdda86f281d0cd0d17439bf",
        "CJK digest must match independent Python reference"
    );

    let digest_mixed = hash_password_sha3("pässwörd☕");
    assert_eq!(
        digest_mixed, "70d79f7947244428870bc5e3cc0844598ea5524189996ad9b1cd27629459a2a2",
        "mixed accented/emoji digest must match independent Python reference"
    );

    let digest_emoji = hash_password_sha3("🔑secret🔒");
    assert_eq!(digest_emoji.len(), 64);

    let digest_accent = hash_password_sha3("contraseña");
    assert_eq!(digest_accent.len(), 64);

    // All four must be distinct from each other and from ASCII.
    let digest_ascii = hash_password_sha3("password");
    let all = [&digest_cjk, &digest_mixed, &digest_emoji, &digest_accent, &digest_ascii];
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "distinct inputs must produce distinct digests");
            }
        }
    }
}

/// Verifies that visually identical strings in NFC vs NFD normalization produce
/// different SHA3-256 digests.  This documents the expected behavior: `hash_password_sha3`
/// hashes raw UTF-8 bytes without normalizing, so clients and teamserver must agree on
/// normalization form (or skip it) to avoid locking out operators with Unicode passwords.
#[test]
fn hash_password_sha3_nfc_vs_nfd_produce_different_digests() {
    // U+00E4 'ä' (NFC, 2 UTF-8 bytes: c3 a4) vs U+0061 U+0308 'ä' (NFD, 3 UTF-8 bytes: 61 cc 88)
    let nfc = "\u{00E4}"; // ä precomposed
    let nfd = "\u{0061}\u{0308}"; // a + combining diaeresis

    // Sanity: both render as 'ä' but have different byte representations.
    assert_ne!(nfc.as_bytes(), nfd.as_bytes(), "NFC and NFD must have different byte sequences");

    let hash_nfc = hash_password_sha3(nfc);
    let hash_nfd = hash_password_sha3(nfd);

    // Verified against Python hashlib.sha3_256 reference values.
    assert_eq!(
        hash_nfc, "eeacc3cbcb4d927171c6a503cd9ad5f5a9c094b9464d7c73a1a5b9c0e00dc089",
        "NFC 'ä' digest must match Python reference"
    );
    assert_eq!(
        hash_nfd, "5c31be24bdfa8f8e858e0f86d97b225c7de45061d2f3373e24ed87df0c54c471",
        "NFD 'ä' digest must match Python reference"
    );

    assert_ne!(
        hash_nfc, hash_nfd,
        "NFC and NFD forms of the same visual character must produce different digests"
    );
}

#[test]
fn stateless_ctr_reuses_the_same_keystream_for_each_message() {
    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    let message = b"identical-message-body!!";

    let first = encrypt_agent_data(&key, &iv, message).expect("first encrypt");
    let second = encrypt_agent_data(&key, &iv, message).expect("second encrypt");

    assert_eq!(first, second, "Havoc resets AES-CTR with the base IV per message");
}

/// Reference vector for block offset 2, generated with Python's `cryptography`
/// library (AES-256-CTR, big-endian 128-bit counter):
///
/// ```python
/// from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
/// key = bytes([0x42] * 32)
/// iv  = bytes([0x01] * 16)
/// # Counter for block 2: IV interpreted as big-endian u128, incremented by 2
/// counter2 = (int.from_bytes(iv, 'big') + 2).to_bytes(16, 'big')
/// cipher = Cipher(algorithms.AES(key), modes.CTR(counter2))
/// enc = cipher.encryptor()
/// ciphertext = enc.update(b"block-offset-two") + enc.finalize()
/// # → da077ab4f03381afab09583c83b2b271
/// ```
#[test]
fn encrypt_agent_data_at_offset_matches_known_reference_at_block_two() {
    let key = [0x42_u8; AGENT_KEY_LENGTH];
    let iv = [0x01_u8; AGENT_IV_LENGTH];
    let plaintext = b"block-offset-two";
    // Pre-computed with an independent Python reference (see doc comment above).
    let expected = hex!("da077ab4f03381afab09583c83b2b271");

    let ciphertext = encrypt_agent_data_at_offset(&key, &iv, 2, plaintext)
        .expect("encryption at block offset 2 should succeed");

    assert_eq!(
        ciphertext, expected,
        "ciphertext at block offset 2 must match the independent reference vector"
    );
}

#[test]
fn decrypt_agent_data_at_offset_recovers_known_reference_at_block_two() {
    let key = [0x42_u8; AGENT_KEY_LENGTH];
    let iv = [0x01_u8; AGENT_IV_LENGTH];
    // Same reference ciphertext as encrypt_agent_data_at_offset_matches_known_reference_at_block_two.
    let ciphertext = hex!("da077ab4f03381afab09583c83b2b271");

    let plaintext = decrypt_agent_data_at_offset(&key, &iv, 2, &ciphertext)
        .expect("decryption at block offset 2 should succeed");

    assert_eq!(
        plaintext, b"block-offset-two",
        "decrypting the reference ciphertext at block offset 2 must recover the original plaintext"
    );
}

#[test]
fn encrypt_agent_data_at_offset_changes_the_keystream() {
    let key = [0x51; AGENT_KEY_LENGTH];
    let iv = [0x34; AGENT_IV_LENGTH];
    let plaintext = b"offset transport payload";

    let base = encrypt_agent_data_at_offset(&key, &iv, 0, plaintext).expect("offset zero");
    let advanced = encrypt_agent_data_at_offset(&key, &iv, 3, plaintext).expect("offset three");

    assert_ne!(base, advanced);
    assert_eq!(
        decrypt_agent_data_at_offset(&key, &iv, 3, &advanced).expect("offset decrypt"),
        plaintext
    );
}

#[test]
fn generate_agent_crypto_material_produces_unique_material_on_successive_calls() {
    let first = generate_agent_crypto_material().expect("first call should succeed");
    let second = generate_agent_crypto_material().expect("second call should succeed");

    assert_ne!(first.key, second.key, "two successive calls must not return the same session key");
    assert_ne!(first.iv, second.iv, "two successive calls must not return the same session IV");
}

#[test]
fn agent_crypto_material_debug_redacts_key_and_iv() {
    let material =
        AgentCryptoMaterial { key: [0xAA; AGENT_KEY_LENGTH], iv: [0xBB; AGENT_IV_LENGTH] };
    let debug_output = format!("{material:?}");

    assert!(
        debug_output.contains("[redacted]"),
        "Debug output must contain '[redacted]', got: {debug_output}"
    );
    assert!(!debug_output.contains("170"), "Debug output must not contain raw key byte values");
    assert!(!debug_output.contains("187"), "Debug output must not contain raw IV byte values");
    assert!(
        !debug_output.contains("0xAA") && !debug_output.contains("0xaa"),
        "Debug output must not contain hex key bytes"
    );
}

#[test]
fn encrypt_agent_data_at_offset_rejects_overflowing_block_offset() {
    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    // block_offset * 16 overflows u64
    let overflow_offset = u64::MAX / 16 + 1;

    let error = encrypt_agent_data_at_offset(&key, &iv, overflow_offset, b"data")
        .expect_err("overflowing block offset must return an error");

    assert!(
        matches!(error, CryptoError::InvalidCtrOffset { block_offset } if block_offset == overflow_offset),
        "expected InvalidCtrOffset, got {error:?}"
    );
}

#[test]
fn decrypt_agent_data_at_offset_rejects_overflowing_block_offset() {
    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    // block_offset * 16 overflows u64
    let overflow_offset = u64::MAX / 16 + 1;

    let error = decrypt_agent_data_at_offset(&key, &iv, overflow_offset, b"data")
        .expect_err("overflowing block offset must return an error");

    assert!(
        matches!(error, CryptoError::InvalidCtrOffset { block_offset } if block_offset == overflow_offset),
        "expected InvalidCtrOffset, got {error:?}"
    );
}

#[test]
fn ctr_blocks_for_len_rounds_up_to_full_blocks() {
    assert_eq!(ctr_blocks_for_len(0), 0);
    assert_eq!(ctr_blocks_for_len(1), 1);
    assert_eq!(ctr_blocks_for_len(16), 1);
    assert_eq!(ctr_blocks_for_len(17), 2);
    assert_eq!(ctr_blocks_for_len(32), 2);
}

#[test]
fn ctr_blocks_for_len_large_payload() {
    // 1 GiB payload = 2^30 bytes → 2^30 / 16 = 2^26 blocks.
    assert_eq!(ctr_blocks_for_len(1 << 30), 1 << 26);
    // Non-aligned: 2^30 + 1 byte rounds up.
    assert_eq!(ctr_blocks_for_len((1 << 30) + 1), (1 << 26) + 1);
}

#[cfg(target_pointer_width = "64")]
#[test]
fn ctr_blocks_for_len_near_usize_max() {
    // On 64-bit platforms `usize as u64` is lossless.
    // usize::MAX bytes → ceiling(usize::MAX / 16) blocks.
    let max_blocks = (u64::MAX).div_ceil(16);
    assert_eq!(ctr_blocks_for_len(usize::MAX), max_blocks);

    // usize::MAX - 15 is exactly aligned.
    let aligned = usize::MAX - 15;
    assert_eq!(ctr_blocks_for_len(aligned), aligned as u64 / 16);
}

#[test]
fn encrypt_at_max_valid_block_offset_succeeds() {
    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    // Maximum block offset whose seek position (offset * 16) fits in u64.
    let max_offset = u64::MAX / 16;
    let plaintext = b"near-limit";

    let result = encrypt_agent_data_at_offset(&key, &iv, max_offset, plaintext);
    assert!(result.is_ok(), "max valid block offset must succeed: {result:?}");

    let ciphertext = result.expect("unwrap");
    let decrypted = decrypt_agent_data_at_offset(&key, &iv, max_offset, &ciphertext)
        .expect("round-trip at max valid offset");
    assert_eq!(decrypted, plaintext);
}

/// AES-256-CTR is a stream cipher **without authentication**: decrypting with the
/// wrong key does not produce an error — it silently yields garbage.  This is a
/// fundamental property of CTR mode and is security-critical for the Demon protocol:
/// the protocol has no MAC or AEAD tag, so a key-agreement mismatch will not be
/// caught at the crypto layer.  Instead, the teamserver will receive structurally
/// invalid (garbled) agent data whose parser must reject it gracefully rather than
/// treating random bytes as valid commands.
#[test]
fn ctr_mode_silently_produces_wrong_plaintext_with_wrong_key() {
    let key_a = [0xAA; AGENT_KEY_LENGTH];
    let key_b = [0xBB; AGENT_KEY_LENGTH];
    let iv = [0x01; AGENT_IV_LENGTH];
    let plaintext = b"demon-init-metadata-payload";

    let ciphertext =
        encrypt_agent_data(&key_a, &iv, plaintext).expect("encryption with key A should succeed");

    // Decrypting with the wrong key must succeed (no error) …
    let wrong_plaintext = decrypt_agent_data(&key_b, &iv, &ciphertext)
        .expect("decryption with wrong key must not error");

    // … but the output must differ from the original plaintext.
    assert_ne!(
        wrong_plaintext.as_slice(),
        plaintext.as_slice(),
        "CTR decryption with the wrong key must produce different output, not the original plaintext"
    );

    // Sanity: the correct key still recovers the original.
    let correct_plaintext =
        decrypt_agent_data(&key_a, &iv, &ciphertext).expect("decryption with correct key");
    assert_eq!(correct_plaintext, plaintext);
}

#[test]
fn crypto_error_invalid_key_length_display() {
    let error = CryptoError::InvalidKeyLength { expected: 32, actual: 31 };
    let message = error.to_string();
    assert!(
        message.contains("expected 32 bytes") && message.contains("got 31"),
        "InvalidKeyLength display must contain key tokens, got: {message}"
    );
}

#[test]
fn crypto_error_invalid_iv_length_display() {
    let error = CryptoError::InvalidIvLength { expected: 16, actual: 8 };
    let message = error.to_string();
    assert!(
        message.contains("expected 16 bytes") && message.contains("got 8"),
        "InvalidIvLength display must contain key tokens, got: {message}"
    );
}

#[test]
fn crypto_error_invalid_ctr_offset_display() {
    let error = CryptoError::InvalidCtrOffset { block_offset: 999 };
    let message = error.to_string();
    assert!(
        message.contains("999") && message.contains("overflowed"),
        "InvalidCtrOffset display must contain the offset and 'overflowed', got: {message}"
    );
}

#[test]
fn crypto_error_cipher_construction_display() {
    let error = CryptoError::CipherConstruction(InvalidLength);
    let message = error.to_string();
    assert!(
        message.contains("cipher construction failed"),
        "CipherConstruction display must contain 'cipher construction failed', got: {message}"
    );
}

#[test]
fn crypto_error_random_generation_display() {
    let error = CryptoError::RandomGeneration("entropy source unavailable".to_string());
    let message = error.to_string();
    assert!(
        message.contains("entropy source unavailable"),
        "RandomGeneration display must contain the inner message, got: {message}"
    );
}

#[test]
fn encrypt_at_one_past_max_valid_block_offset_fails() {
    let key = [0x41; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    // One past the maximum valid offset: (u64::MAX / 16) + 1 overflows on seek.
    let overflow_offset = u64::MAX / 16 + 1;

    let error = encrypt_agent_data_at_offset(&key, &iv, overflow_offset, b"x")
        .expect_err("offset one past max must fail");
    assert!(
        matches!(error, CryptoError::InvalidCtrOffset { block_offset } if block_offset == overflow_offset),
    );
}

#[test]
fn derive_session_keys_matches_external_hkdf_reference_vectors() {
    // Generated independently with a standalone Python HKDF-SHA256 implementation.
    let key = hex!(
        "603deb1015ca71be2b73aef0857d7781
         1f352c073b6108d72d9810a30914dff4"
    );
    let iv = hex!("000102030405060708090a0b0c0d0e0f");
    let alpha = derive_session_keys(&key, &iv, b"test-server-secret").expect("alpha derivation");
    assert_eq!(alpha.key, hex!("7e65607a2ea7519b7242db07dd15c013c10de12d22e225e6f3df3cc37485dd87"));
    assert_eq!(alpha.iv, hex!("a1c6229d5cfd281f2f917bb8e237d0dc"));

    let bravo = derive_session_keys(&key, &iv, b"test-server-secret-v2").expect("bravo derivation");
    assert_eq!(bravo.key, hex!("f8c5042675c1f26038b082fb587dfb86afe67230f8909f4962576765018999ec"));
    assert_eq!(bravo.iv, hex!("65414dcb1c427ca093a8857368d2a214"));
}

#[test]
fn derive_session_keys_is_deterministic() {
    let key = [0x42; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    let secret = b"determinism-check";

    let first = derive_session_keys(&key, &iv, secret).expect("first derivation");
    let second = derive_session_keys(&key, &iv, secret).expect("second derivation");

    assert_eq!(first, second, "same inputs must produce identical output");
}

#[test]
fn derive_session_keys_different_secrets_produce_different_keys() {
    let key = [0x42; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];

    let derived_a = derive_session_keys(&key, &iv, b"secret-a").expect("derivation with secret A");
    let derived_b = derive_session_keys(&key, &iv, b"secret-b").expect("derivation with secret B");

    assert_ne!(
        derived_a.key, derived_b.key,
        "different server secrets must produce different keys"
    );
}

#[test]
fn derive_session_keys_different_agent_keys_produce_different_output() {
    let iv = [0x24; AGENT_IV_LENGTH];
    let secret = b"same-secret";

    let mut key_a = [0u8; AGENT_KEY_LENGTH];
    key_a[0] = 1;
    let mut key_b = [0u8; AGENT_KEY_LENGTH];
    key_b[0] = 2;

    let derived_a = derive_session_keys(&key_a, &iv, secret).expect("derivation A");
    let derived_b = derive_session_keys(&key_b, &iv, secret).expect("derivation B");

    assert_ne!(derived_a.key, derived_b.key);
}

#[test]
fn derive_session_keys_rejects_invalid_key_length() {
    let error = derive_session_keys(&[0u8; 16], &[0u8; AGENT_IV_LENGTH], b"secret")
        .expect_err("short key should be rejected");

    assert!(matches!(error, CryptoError::InvalidKeyLength { expected: 32, actual: 16 }));
}

#[test]
fn derive_session_keys_rejects_invalid_iv_length() {
    let error = derive_session_keys(&[0u8; AGENT_KEY_LENGTH], &[0u8; 8], b"secret")
        .expect_err("short IV should be rejected");

    assert!(matches!(error, CryptoError::InvalidIvLength { expected: 16, actual: 8 }));
}

#[test]
fn derive_session_keys_output_is_usable_for_encryption() {
    let key = [0x42; AGENT_KEY_LENGTH];
    let iv = [0x24; AGENT_IV_LENGTH];
    let secret = b"round-trip-secret";

    let derived = derive_session_keys(&key, &iv, secret).expect("derivation");
    let plaintext = b"hello from derived keys";

    let ciphertext =
        encrypt_agent_data(&derived.key, &derived.iv, plaintext).expect("encrypt with derived key");
    let recovered = decrypt_agent_data(&derived.key, &derived.iv, &ciphertext)
        .expect("decrypt with derived key");

    assert_eq!(recovered, plaintext);
}

#[test]
fn derive_session_keys_propagates_error_not_panics() {
    // Valid inputs must always succeed — this verifies that the replaced
    // `.expect()` calls are reachable and produce Ok results in the normal
    // case (i.e., no panic occurs and the result is properly returned).
    let key = [0x11; AGENT_KEY_LENGTH];
    let iv = [0x22; AGENT_IV_LENGTH];
    let secret = b"no-panic-check";

    let result = derive_session_keys(&key, &iv, secret);
    assert!(result.is_ok(), "valid inputs must succeed without panicking: {result:?}");
}

#[test]
fn crypto_error_hkdf_expand_display() {
    let error = CryptoError::HkdfExpand;
    let message = error.to_string();
    assert!(
        message.contains("HKDF expand failed"),
        "HkdfExpand display must contain 'HKDF expand failed', got: {message}"
    );
}

// ── derive_session_keys_for_version ─────────────────────────────────────

#[test]
fn derive_session_keys_for_version_returns_same_as_derive_session_keys() {
    let key = [0x11; AGENT_KEY_LENGTH];
    let iv = [0x22; AGENT_IV_LENGTH];
    let secret = b"sixteen-byte-sec";
    let secrets = vec![(1u8, secret.as_slice())];

    let versioned =
        derive_session_keys_for_version(&key, &iv, 1, &secrets).expect("version 1 must be found");
    let direct = derive_session_keys(&key, &iv, secret).expect("direct derive must succeed");

    assert_eq!(versioned.key, direct.key, "versioned key must match direct derivation");
    assert_eq!(versioned.iv, direct.iv, "versioned IV must match direct derivation");
}

#[test]
fn derive_session_keys_for_version_unknown_version_returns_error() {
    let key = [0x11; AGENT_KEY_LENGTH];
    let iv = [0x22; AGENT_IV_LENGTH];
    let secrets = vec![(1u8, b"sixteen-byte-sec".as_slice())];

    let result = derive_session_keys_for_version(&key, &iv, 2, &secrets);
    assert!(
        matches!(result, Err(CryptoError::UnknownSecretVersion { version: 2 })),
        "unknown version must return UnknownSecretVersion, got: {result:?}"
    );
}

#[test]
fn derive_session_keys_for_version_selects_correct_secret_from_list() {
    let key = [0x33; AGENT_KEY_LENGTH];
    let iv = [0x44; AGENT_IV_LENGTH];
    let secret1 = b"secret-version-1";
    let secret2 = b"secret-version-2";
    let secrets = vec![(1u8, secret1.as_slice()), (2u8, secret2.as_slice())];

    let derived1 =
        derive_session_keys_for_version(&key, &iv, 1, &secrets).expect("version 1 must succeed");
    let derived2 =
        derive_session_keys_for_version(&key, &iv, 2, &secrets).expect("version 2 must succeed");

    assert_ne!(
        derived1.key, derived2.key,
        "different secret versions must produce different session keys"
    );
}

#[test]
fn derive_session_keys_for_version_empty_list_returns_error() {
    let key = [0x55; AGENT_KEY_LENGTH];
    let iv = [0x66; AGENT_IV_LENGTH];

    let result = derive_session_keys_for_version(&key, &iv, 0, &[]);
    assert!(
        matches!(result, Err(CryptoError::UnknownSecretVersion { version: 0 })),
        "empty secrets list must return UnknownSecretVersion, got: {result:?}"
    );
}

#[test]
fn agent_crypto_material_zeroizes_on_drop() {
    use zeroize::Zeroize;

    let mut material =
        AgentCryptoMaterial { key: [0xAA; AGENT_KEY_LENGTH], iv: [0xBB; AGENT_IV_LENGTH] };

    // Explicit zeroize should clear the fields.
    material.zeroize();
    assert_eq!(material.key, [0u8; AGENT_KEY_LENGTH], "key must be zeroed after zeroize()");
    assert_eq!(material.iv, [0u8; AGENT_IV_LENGTH], "iv must be zeroed after zeroize()");
}

// ── CTR direction & continuity conformance tests ──────────────────────────────
//
// These tests verify the properties that distinguish correct Rust/C interop:
//
// 1. Counter is BIG-ENDIAN: Demon source (AesCrypt.c:230-239) increments the
//    highest-index byte first (index 15 = LSB of a 128-bit big-endian integer).
//    Rust uses Ctr128BE<Aes256> which matches this exactly.
//
// 2. Archon's AdvanceIvByBlocks (Package.c:238-271) treats the IV as two
//    big-endian 64-bit halves (bytes 0-7 = high, bytes 8-15 = low) and adds
//    the block count to the low half with carry to the high half. This is
//    identical to `cipher.seek(block_offset * 16)` on a Ctr128BE cipher.
//
// 3. Legacy CTR (Demon): each packet resets to offset 0 — produce the same
//    keystream regardless of how many prior packets were sent.
//
// 4. Monotonic CTR (Archon/Phantom/Specter): the counter advances across
//    packets; the N-th packet starts where the (N-1)-th left off.

/// Helper: compute what AdvanceIvByBlocks(iv, blocks) produces.
/// Replicates the C logic from agent/archon/src/core/Package.c:238-271
/// in order to verify the Rust `seek()` path produces the same result.
fn advance_iv_by_blocks_ref(iv: &[u8; AGENT_IV_LENGTH], blocks: u64) -> [u8; AGENT_IV_LENGTH] {
    if blocks == 0 {
        return *iv;
    }
    let lo = u64::from_be_bytes(iv[8..16].try_into().unwrap());
    let hi = u64::from_be_bytes(iv[0..8].try_into().unwrap());
    let new_lo = lo.wrapping_add(blocks);
    let new_hi = if new_lo < lo { hi.wrapping_add(1) } else { hi };
    let mut out = [0u8; AGENT_IV_LENGTH];
    out[0..8].copy_from_slice(&new_hi.to_be_bytes());
    out[8..16].copy_from_slice(&new_lo.to_be_bytes());
    out
}

#[test]
fn legacy_ctr_resets_keystream_per_call() {
    // Demon AesCrypt.c: AesInit is called before every AesXCryptBuffer, so
    // every packet starts from the same CTR counter value. Two identical
    // encrypt_agent_data calls with the same key/IV must produce the same
    // ciphertext — confirming that `encrypt_agent_data` is stateless/reset.
    let key = [0x11_u8; AGENT_KEY_LENGTH];
    let iv = [0x22_u8; AGENT_IV_LENGTH];
    let plaintext = b"demon-protocol-packet-payload-xx";

    let ct1 = encrypt_agent_data(&key, &iv, plaintext).expect("first encrypt");
    let ct2 = encrypt_agent_data(&key, &iv, plaintext).expect("second encrypt");

    assert_eq!(
        ct1, ct2,
        "legacy CTR must produce the same ciphertext on repeated calls (reset per packet)"
    );
}

#[test]
fn advance_iv_by_blocks_ref_matches_rust_seek() {
    // Archon Package.c AdvanceIvByBlocks must match Rust Ctr128BE seek().
    // For N offset blocks: encrypt_agent_data_at_offset(key, iv, N, pt) must
    // equal encrypt_agent_data(key, advance_iv_by_blocks_ref(iv, N), pt).
    let key = [0x33_u8; AGENT_KEY_LENGTH];
    let plaintext = b"conformance-test-payload-padding";

    for n in [0u64, 1, 2, 5, 10, 255, 256, 1000] {
        let iv: [u8; AGENT_IV_LENGTH] = {
            let mut v = [0x44_u8; AGENT_IV_LENGTH];
            v[15] = n.wrapping_mul(7) as u8; // vary IV to avoid trivial matches
            v
        };
        let advanced_iv = advance_iv_by_blocks_ref(&iv, n);

        let via_seek = encrypt_agent_data_at_offset(&key, &iv, n, plaintext)
            .unwrap_or_else(|e| panic!("seek encrypt at offset {n} failed: {e}"));
        let via_advance =
            encrypt_agent_data(&key, &advanced_iv, plaintext).expect("advance IV then encrypt");

        assert_eq!(
            via_seek, via_advance,
            "encrypt_at_offset({n}) and AdvanceIvByBlocks({n})+encrypt must produce the same ciphertext"
        );
    }
}

#[test]
fn ctr_counter_carries_into_high_half_on_low_half_overflow() {
    // Verify the big-endian carry: when the low 64 bits (bytes 8-15) overflow,
    // the carry propagates into the high 64 bits (bytes 0-7).
    // This exercises the `if new_lo < lo { hi++ }` branch in AdvanceIvByBlocks.
    let iv: [u8; AGENT_IV_LENGTH] = {
        let mut v = [0u8; AGENT_IV_LENGTH];
        // Set low half to u64::MAX so adding 1 causes overflow.
        v[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
        v
    };
    let advanced = advance_iv_by_blocks_ref(&iv, 1);

    // Low half wraps to 0; high half increments from 0 to 1.
    assert_eq!(&advanced[0..8], &1u64.to_be_bytes(), "high half must increment on carry");
    assert_eq!(&advanced[8..16], &0u64.to_be_bytes(), "low half must wrap to 0 on overflow");

    // Rust `encrypt_agent_data_at_offset` with seek through the carry must match.
    let key = [0x55_u8; AGENT_KEY_LENGTH];
    let plaintext = b"carry-test-payload-padding-xx-xx";
    let via_seek = encrypt_agent_data_at_offset(&key, &iv, 1, plaintext).expect("seek encrypt");
    let via_advance = encrypt_agent_data(&key, &advanced, plaintext).expect("advance encrypt");
    assert_eq!(via_seek, via_advance, "carry path: seek and advance must produce same ciphertext");
}

#[test]
fn big_endian_counter_direction_is_not_little_endian() {
    // If the counter were little-endian, a value of [0xFF, 0x00, ...] would
    // wrap byte 0 (LE LSB) and carry into byte 1.
    // With big-endian, [0x00, ..., 0xFF] wraps byte 15 (BE LSB) and carries
    // into byte 14. This test verifies the Rust implementation is BE by showing
    // that `encrypt_at_offset(1)` on an IV with byte 15 = 0xFF matches the
    // big-endian carry result, NOT the little-endian carry result.

    // IV with last byte = 0xFF: BE counter at offset 0.
    let iv_be_carry: [u8; AGENT_IV_LENGTH] = {
        let mut v = [0u8; AGENT_IV_LENGTH];
        v[15] = 0xFF;
        v
    };
    // Expected advanced IV (BE): byte 15 wraps to 0x00, byte 14 becomes 0x01.
    let be_advanced = advance_iv_by_blocks_ref(&iv_be_carry, 1);
    assert_eq!(be_advanced[14], 0x01, "BE carry: byte 14 must be 0x01");
    assert_eq!(be_advanced[15], 0x00, "BE carry: byte 15 must wrap to 0x00");

    let key = [0x66_u8; AGENT_KEY_LENGTH];
    let plaintext = b"be-direction-test-payload-xxxxxx";
    let via_seek =
        encrypt_agent_data_at_offset(&key, &iv_be_carry, 1, plaintext).expect("BE seek encrypt");
    let via_be_advance =
        encrypt_agent_data(&key, &be_advanced, plaintext).expect("BE advance encrypt");

    // Must match BE.
    assert_eq!(via_seek, via_be_advance, "CTR must match big-endian advance (BE carry)");

    // Must NOT match what a little-endian advance would produce.
    // LE advance of [0x00,...,0xFF, 0x00,...]: byte 0 = 0xFF → 0x00, byte 1 += 1.
    let mut le_advanced = iv_be_carry;
    // Simulate LE increment: start at index 0, carry up.
    for i in 0..AGENT_IV_LENGTH {
        if le_advanced[i] < 255 {
            le_advanced[i] += 1;
            break;
        }
        le_advanced[i] = 0;
    }
    let via_le_advance =
        encrypt_agent_data(&key, &le_advanced, plaintext).expect("LE advance encrypt");
    assert_ne!(
        via_seek, via_le_advance,
        "CTR must NOT match a little-endian advance — confirms Rust uses Ctr128BE, not Ctr128LE"
    );
}

#[test]
fn monotonic_ctr_two_packets_form_contiguous_keystream() {
    // When two packets are sent with the monotonic CTR protocol (Archon/Phantom),
    // packet 2 starts exactly where packet 1 left off. This means:
    //   encrypt_at_offset(0, pt1) || encrypt_at_offset(blocks(pt1), pt2)
    // must equal the corresponding slices of a single encrypt call:
    //   encrypt_at_offset(0, pt1 || pt2)[len(pt1)..]
    //
    // This is the core continuity invariant that prevents keystream overlap.
    let key = [0x77_u8; AGENT_KEY_LENGTH];
    let iv = [0x88_u8; AGENT_IV_LENGTH];

    let pt1 = b"first-packet-payload-xxxxxxxxxxx"; // 32 bytes = 2 blocks
    let pt2 = b"second-packet-payload-xxxxxxxxxx"; // 32 bytes = 2 blocks

    let pt1_blocks = ctr_blocks_for_len(pt1.len());
    assert_eq!(pt1_blocks, 2, "test setup: pt1 must consume exactly 2 blocks");

    let ct1 = encrypt_agent_data_at_offset(&key, &iv, 0, pt1).expect("packet 1");
    let ct2 = encrypt_agent_data_at_offset(&key, &iv, pt1_blocks, pt2).expect("packet 2");

    // Combined plaintext encrypted in one shot.
    let mut combined_pt = pt1.to_vec();
    combined_pt.extend_from_slice(pt2);
    let ct_combined =
        encrypt_agent_data_at_offset(&key, &iv, 0, &combined_pt).expect("combined encrypt");

    assert_eq!(&ct_combined[..pt1.len()], &ct1[..], "packet 1 ciphertext must equal combined[..N]");
    assert_eq!(&ct_combined[pt1.len()..], &ct2[..], "packet 2 ciphertext must equal combined[N..]");
}
