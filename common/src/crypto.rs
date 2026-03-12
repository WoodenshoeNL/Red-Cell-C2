//! Agent transport cryptography helpers.

use aes::Aes256;
use cipher::{InvalidLength, KeyIvInit, StreamCipher, StreamCipherSeek};
use ctr::Ctr128BE;
use sha3::{Digest, Sha3_256};
use thiserror::Error;

/// Agent communication key length in bytes.
pub const AGENT_KEY_LENGTH: usize = 32;

/// Agent communication IV length in bytes.
pub const AGENT_IV_LENGTH: usize = 16;
const AGENT_CTR_BLOCK_LEN: u64 = 16;

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
    /// The requested CTR block offset would overflow the cipher seek position.
    #[error("invalid AES-CTR block offset {block_offset}: seek position overflowed")]
    InvalidCtrOffset {
        /// The block offset that could not be represented safely.
        block_offset: u64,
    },
    /// Randomness for new key material could not be obtained from the OS.
    #[error("failed to generate agent key material: {0}")]
    RandomGeneration(String),
}

impl From<InvalidLength> for CryptoError {
    fn from(_: InvalidLength) -> Self {
        unreachable!("length validation is performed before cipher construction")
    }
}

type AgentCtr = Ctr128BE<Aes256>;

/// Encrypt agent transport data with AES-256-CTR starting from the given IV.
///
/// Havoc uses a big-endian 128-bit counter on both the teamserver and Demon sides.
///
pub fn encrypt_agent_data(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    encrypt_agent_data_at_offset(key, iv, 0, plaintext)
}

/// Encrypt agent transport data with AES-256-CTR starting from the given block offset.
pub fn encrypt_agent_data_at_offset(
    key: &[u8],
    iv: &[u8],
    block_offset: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    apply_agent_keystream(key, iv, block_offset, plaintext)
}

/// Decrypt agent transport data with AES-256-CTR starting from the given IV.
pub fn decrypt_agent_data(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    decrypt_agent_data_at_offset(key, iv, 0, ciphertext)
}

/// Decrypt agent transport data with AES-256-CTR starting from the given block offset.
pub fn decrypt_agent_data_at_offset(
    key: &[u8],
    iv: &[u8],
    block_offset: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    apply_agent_keystream(key, iv, block_offset, ciphertext)
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

/// Return the number of AES-CTR blocks consumed by `len` bytes of transport data.
#[must_use]
pub fn ctr_blocks_for_len(len: usize) -> u64 {
    if len == 0 {
        return 0;
    }

    (len as u64).div_ceil(AGENT_CTR_BLOCK_LEN)
}

fn apply_agent_keystream(
    key: &[u8],
    iv: &[u8],
    block_offset: u64,
    input: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    validate_key_and_iv(key, iv)?;

    let mut output = input.to_vec();
    let mut cipher = AgentCtr::new_from_slices(key, iv)?;
    let seek_pos = block_offset
        .checked_mul(AGENT_CTR_BLOCK_LEN)
        .ok_or(CryptoError::InvalidCtrOffset { block_offset })?;
    cipher.seek(seek_pos);
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
        AGENT_IV_LENGTH, AGENT_KEY_LENGTH, CryptoError, ctr_blocks_for_len, decrypt_agent_data,
        decrypt_agent_data_at_offset, encrypt_agent_data, encrypt_agent_data_at_offset,
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
    fn stateless_ctr_reuses_the_same_keystream_for_each_message() {
        let key = [0x41; AGENT_KEY_LENGTH];
        let iv = [0x24; AGENT_IV_LENGTH];
        let message = b"identical-message-body!!";

        let first = encrypt_agent_data(&key, &iv, message).expect("first encrypt");
        let second = encrypt_agent_data(&key, &iv, message).expect("second encrypt");

        assert_eq!(first, second, "Havoc resets AES-CTR with the base IV per message");
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

        assert_ne!(
            first.key, second.key,
            "two successive calls must not return the same session key"
        );
        assert_ne!(first.iv, second.iv, "two successive calls must not return the same session IV");
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
    fn ctr_blocks_for_len_rounds_up_to_full_blocks() {
        assert_eq!(ctr_blocks_for_len(0), 0);
        assert_eq!(ctr_blocks_for_len(1), 1);
        assert_eq!(ctr_blocks_for_len(16), 1);
        assert_eq!(ctr_blocks_for_len(17), 2);
        assert_eq!(ctr_blocks_for_len(32), 2);
    }
}
