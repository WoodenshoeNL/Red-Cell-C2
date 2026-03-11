//! Agent transport cryptography helpers.

use aes::Aes256;
use cipher::{InvalidLength, KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use sha3::{Digest, Sha3_256};
use thiserror::Error;

/// Agent communication key length in bytes.
pub const AGENT_KEY_LENGTH: usize = 32;

/// Agent communication IV length in bytes.
pub const AGENT_IV_LENGTH: usize = 16;

/// Fresh AES key material assigned to an agent session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCryptoMaterial {
    /// AES-256 session key.
    pub key: [u8; AGENT_KEY_LENGTH],
    /// Initial CTR counter block.
    pub iv: [u8; AGENT_IV_LENGTH],
}

/// Errors returned by agent transport crypto helpers.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// The supplied AES key does not have the required 32-byte length.
    #[error("invalid AES-256 key length: expected {expected} bytes, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    /// The supplied IV does not have the required 16-byte length.
    #[error("invalid AES IV length: expected {expected} bytes, got {actual}")]
    InvalidIvLength { expected: usize, actual: usize },
    /// Randomness for new key material could not be obtained from the OS.
    #[error("failed to generate agent key material: {0}")]
    RandomGeneration(String),
}

impl From<InvalidLength> for CryptoError {
    fn from(_: InvalidLength) -> Self {
        unreachable!("length validation is performed before cipher construction")
    }
}

/// AES block size in bytes (128 bits).
const AES_BLOCK_LEN: usize = 16;

type AgentCtr = Ctr128BE<Aes256>;

/// Encrypt agent transport data with AES-256-CTR starting from the given IV.
///
/// Havoc uses a big-endian 128-bit counter on both the teamserver and Demon sides.
///
pub fn encrypt_agent_data(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    apply_agent_keystream(key, iv, plaintext)
}

/// Decrypt agent transport data with AES-256-CTR starting from the given IV.
pub fn decrypt_agent_data(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    apply_agent_keystream(key, iv, ciphertext)
}

/// Encrypt agent data while tracking the per-session CTR block offset.
///
/// The Demon C agent maintains a single AES-CTR context whose counter advances
/// after every encrypt/decrypt call.  This function replicates that behaviour:
/// it derives the effective IV by adding `block_offset` to `base_iv` (128-bit
/// big-endian addition), applies the keystream, and returns the ciphertext
/// together with the new block offset.
pub fn encrypt_agent_data_ctr(
    key: &[u8],
    base_iv: &[u8; AGENT_IV_LENGTH],
    block_offset: u64,
    plaintext: &[u8],
) -> Result<(Vec<u8>, u64), CryptoError> {
    let effective_iv = advance_iv(base_iv, block_offset);
    let ciphertext = apply_agent_keystream(key, &effective_iv, plaintext)?;
    let new_offset = block_offset.saturating_add(ctr_blocks_for_length(plaintext.len()));
    Ok((ciphertext, new_offset))
}

/// Decrypt agent data while tracking the per-session CTR block offset.
///
/// Mirror of [`encrypt_agent_data_ctr`] for the receive direction.  See its
/// documentation for details on counter tracking.
pub fn decrypt_agent_data_ctr(
    key: &[u8],
    base_iv: &[u8; AGENT_IV_LENGTH],
    block_offset: u64,
    ciphertext: &[u8],
) -> Result<(Vec<u8>, u64), CryptoError> {
    let effective_iv = advance_iv(base_iv, block_offset);
    let plaintext = apply_agent_keystream(key, &effective_iv, ciphertext)?;
    let new_offset = block_offset.saturating_add(ctr_blocks_for_length(ciphertext.len()));
    Ok((plaintext, new_offset))
}

/// Compute the number of AES blocks required to cover `data_len` bytes.
#[must_use]
pub fn ctr_blocks_for_length(data_len: usize) -> u64 {
    data_len.div_ceil(AES_BLOCK_LEN) as u64
}

/// Derive an effective IV by adding a block offset to the base IV.
///
/// The Demon agent increments its 128-bit counter (big-endian) in place after
/// each AES block.  This function replicates that by interpreting the IV as a
/// `u128` BE integer, adding the offset, and converting back.
#[must_use]
pub fn advance_iv(base_iv: &[u8; AGENT_IV_LENGTH], block_offset: u64) -> [u8; AGENT_IV_LENGTH] {
    let iv_val = u128::from_be_bytes(*base_iv);
    let advanced = iv_val.wrapping_add(u128::from(block_offset));
    advanced.to_be_bytes()
}

/// Generate fresh per-agent AES-256-CTR key material.
pub fn generate_agent_crypto_material() -> Result<AgentCryptoMaterial, CryptoError> {
    let mut key = [0_u8; AGENT_KEY_LENGTH];
    let mut iv = [0_u8; AGENT_IV_LENGTH];

    getrandom::fill(&mut key).map_err(|error| CryptoError::RandomGeneration(error.to_string()))?;
    getrandom::fill(&mut iv).map_err(|error| CryptoError::RandomGeneration(error.to_string()))?;

    Ok(AgentCryptoMaterial { key, iv })
}

/// Hash a password with SHA3-256 and return the lowercase hex digest.
///
/// This matches the Havoc operator protocol which sends `Password` as a SHA3-256 hex string.
#[must_use]
pub fn hash_password_sha3(password: &str) -> String {
    use std::fmt::Write;

    let mut hasher = Sha3_256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let mut hex_string = String::with_capacity(result.len() * 2);
    for byte in result {
        let _ = write!(hex_string, "{byte:02x}");
    }
    hex_string
}

fn apply_agent_keystream(key: &[u8], iv: &[u8], input: &[u8]) -> Result<Vec<u8>, CryptoError> {
    validate_key_and_iv(key, iv)?;

    let mut output = input.to_vec();
    let mut cipher = AgentCtr::new_from_slices(key, iv)?;
    cipher.apply_keystream(&mut output);

    Ok(output)
}

fn validate_key_and_iv(key: &[u8], iv: &[u8]) -> Result<(), CryptoError> {
    if key.len() != AGENT_KEY_LENGTH {
        return Err(CryptoError::InvalidKeyLength {
            expected: AGENT_KEY_LENGTH,
            actual: key.len(),
        });
    }

    if iv.len() != AGENT_IV_LENGTH {
        return Err(CryptoError::InvalidIvLength { expected: AGENT_IV_LENGTH, actual: iv.len() });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::{
        AGENT_IV_LENGTH, AGENT_KEY_LENGTH, CryptoError, advance_iv, ctr_blocks_for_length,
        decrypt_agent_data, decrypt_agent_data_ctr, encrypt_agent_data, encrypt_agent_data_ctr,
        generate_agent_crypto_material, hash_password_sha3,
    };

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

        let plaintext = decrypt_agent_data(&key, &iv, &ciphertext)
            .expect("reference decryption should succeed");

        assert_eq!(plaintext, b"red-cell agent metadata");
    }

    #[test]
    fn encrypt_and_decrypt_round_trip() {
        let key = [0x41; AGENT_KEY_LENGTH];
        let iv = [0x24; AGENT_IV_LENGTH];
        let plaintext = b"\x00\x01\x02demon-tasking";

        let ciphertext =
            encrypt_agent_data(&key, &iv, plaintext).expect("round-trip encryption should succeed");
        let decrypted = decrypt_agent_data(&key, &iv, &ciphertext)
            .expect("round-trip decryption should succeed");

        assert_eq!(decrypted, plaintext);
        assert_ne!(ciphertext, plaintext);
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
        let error =
            decrypt_agent_data(&[0x11; AGENT_KEY_LENGTH - 1], &[0x22; AGENT_IV_LENGTH], b"")
                .expect_err("invalid key length must fail decryption");

        assert!(matches!(
            error,
            CryptoError::InvalidKeyLength { expected, actual }
                if expected == AGENT_KEY_LENGTH && actual == AGENT_KEY_LENGTH - 1
        ));
    }

    #[test]
    fn encrypt_agent_data_preserves_empty_plaintext() {
        let ciphertext =
            encrypt_agent_data(&[0x41; AGENT_KEY_LENGTH], &[0x24; AGENT_IV_LENGTH], b"")
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
    fn advance_iv_adds_offset_to_base_iv() {
        let base = [0_u8; AGENT_IV_LENGTH];
        let advanced = advance_iv(&base, 1);
        let mut expected = [0_u8; AGENT_IV_LENGTH];
        expected[15] = 1;
        assert_eq!(advanced, expected);
    }

    #[test]
    fn advance_iv_wraps_on_overflow() {
        let base = [0xFF; AGENT_IV_LENGTH];
        let advanced = advance_iv(&base, 1);
        assert_eq!(advanced, [0_u8; AGENT_IV_LENGTH]);
    }

    #[test]
    fn advance_iv_with_zero_offset_is_identity() {
        let base = hex!("000102030405060708090a0b0c0d0e0f");
        assert_eq!(advance_iv(&base, 0), base);
    }

    #[test]
    fn ctr_blocks_for_length_rounds_up() {
        assert_eq!(ctr_blocks_for_length(0), 0);
        assert_eq!(ctr_blocks_for_length(1), 1);
        assert_eq!(ctr_blocks_for_length(16), 1);
        assert_eq!(ctr_blocks_for_length(17), 2);
        assert_eq!(ctr_blocks_for_length(32), 2);
        assert_eq!(ctr_blocks_for_length(33), 3);
    }

    #[test]
    fn ctr_round_trip_at_offset_zero_matches_plain() {
        let key = [0x41; AGENT_KEY_LENGTH];
        let iv = [0x24; AGENT_IV_LENGTH];
        let plaintext = b"hello from demon";

        let plain_ciphertext =
            encrypt_agent_data(&key, &iv, plaintext).expect("plain encryption should work");
        let (ctr_ciphertext, new_offset) =
            encrypt_agent_data_ctr(&key, &iv, 0, plaintext).expect("ctr encrypt should work");

        assert_eq!(plain_ciphertext, ctr_ciphertext);
        assert_eq!(new_offset, ctr_blocks_for_length(plaintext.len()));
    }

    #[test]
    fn ctr_successive_messages_produce_different_keystreams() {
        let key = [0x41; AGENT_KEY_LENGTH];
        let iv = [0x24; AGENT_IV_LENGTH];
        let message = b"identical-message-body!!";

        let (ct1, offset1) = encrypt_agent_data_ctr(&key, &iv, 0, message).expect("first encrypt");
        let (ct2, _offset2) =
            encrypt_agent_data_ctr(&key, &iv, offset1, message).expect("second encrypt");

        assert_ne!(ct1, ct2, "successive messages must use different keystreams");
    }

    #[test]
    fn ctr_encrypt_decrypt_round_trip_across_messages() {
        let key = [0x55; AGENT_KEY_LENGTH];
        let iv = [0x11; AGENT_IV_LENGTH];
        let msg1 = b"first-message-from-agent";
        let msg2 = b"second-callback-payload";
        let msg3 = b"third-response-from-ts!";

        let (ct1, off1) = encrypt_agent_data_ctr(&key, &iv, 0, msg1).expect("enc1");
        let (ct2, off2) = encrypt_agent_data_ctr(&key, &iv, off1, msg2).expect("enc2");
        let (ct3, _off3) = encrypt_agent_data_ctr(&key, &iv, off2, msg3).expect("enc3");

        let (pt1, dec_off1) = decrypt_agent_data_ctr(&key, &iv, 0, &ct1).expect("dec1");
        let (pt2, dec_off2) = decrypt_agent_data_ctr(&key, &iv, dec_off1, &ct2).expect("dec2");
        let (pt3, _dec_off3) = decrypt_agent_data_ctr(&key, &iv, dec_off2, &ct3).expect("dec3");

        assert_eq!(pt1, msg1);
        assert_eq!(pt2, msg2);
        assert_eq!(pt3, msg3);
    }

    #[test]
    fn ctr_matches_single_continuous_keystream() {
        let key = hex!(
            "603deb1015ca71be2b73aef0857d7781
             1f352c073b6108d72d9810a30914dff4"
        );
        let iv = hex!("000102030405060708090a0b0c0d0e0f");

        let part_a = b"sixteen-byte-blk";
        let part_b = b"another-sixteen!";
        let combined = [part_a.as_slice(), part_b.as_slice()].concat();

        let combined_ct =
            encrypt_agent_data(&key, &iv, &combined).expect("combined encryption should work");

        let (ct_a, offset_a) = encrypt_agent_data_ctr(&key, &iv, 0, part_a).expect("part a");
        let (ct_b, _offset_b) =
            encrypt_agent_data_ctr(&key, &iv, offset_a, part_b).expect("part b");

        let reassembled = [ct_a.as_slice(), ct_b.as_slice()].concat();
        assert_eq!(
            reassembled, combined_ct,
            "CTR offset tracking must produce the same keystream as a single continuous call"
        );
    }
}
