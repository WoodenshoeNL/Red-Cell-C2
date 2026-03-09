//! Agent transport cryptography helpers.

use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cipher::block_padding::Pkcs7;
use cipher::{BlockDecryptMut, BlockEncryptMut, InvalidLength, KeyIvInit};
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
    /// CBC initialization vector.
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
    /// The ciphertext was not valid PKCS#7-padded AES-256-CBC data.
    #[error("failed to decrypt agent data")]
    DecryptionFailed,
    /// Randomness for new key material could not be obtained from the OS.
    #[error("failed to generate agent key material: {0}")]
    RandomGeneration(String),
}

impl From<InvalidLength> for CryptoError {
    fn from(_: InvalidLength) -> Self {
        unreachable!("length validation is performed before cipher construction")
    }
}

/// Encrypt agent transport data with AES-256-CBC and PKCS#7 padding.
///
/// Returns an empty buffer if the supplied key or IV length is invalid.
pub fn encrypt_agent_data(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Vec<u8> {
    if validate_key_and_iv(key, iv).is_err() {
        return Vec::new();
    }

    let cipher = match Encryptor::<Aes256>::new_from_slices(key, iv) {
        Ok(cipher) => cipher,
        Err(_) => return Vec::new(),
    };
    let mut buffer = vec![0_u8; plaintext.len() + AGENT_IV_LENGTH];
    buffer[..plaintext.len()].copy_from_slice(plaintext);

    match cipher.encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len()) {
        Ok(ciphertext) => ciphertext.to_vec(),
        Err(_) => Vec::new(),
    }
}

/// Decrypt agent transport data with AES-256-CBC and PKCS#7 padding.
pub fn decrypt_agent_data(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    validate_key_and_iv(key, iv)?;

    let cipher = Decryptor::<Aes256>::new_from_slices(key, iv)?;
    let mut buffer = ciphertext.to_vec();

    let plaintext = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| CryptoError::DecryptionFailed)?;

    Ok(plaintext.to_vec())
}

/// Generate fresh per-agent AES-256-CBC key material.
pub fn generate_agent_crypto_material() -> Result<AgentCryptoMaterial, CryptoError> {
    let mut key = [0_u8; AGENT_KEY_LENGTH];
    let mut iv = [0_u8; AGENT_IV_LENGTH];

    getrandom::fill(&mut key).map_err(|error| CryptoError::RandomGeneration(error.to_string()))?;
    getrandom::fill(&mut iv).map_err(|error| CryptoError::RandomGeneration(error.to_string()))?;

    Ok(AgentCryptoMaterial { key, iv })
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
        AGENT_IV_LENGTH, AGENT_KEY_LENGTH, CryptoError, decrypt_agent_data, encrypt_agent_data,
        generate_agent_crypto_material,
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
            "425075c7524208f3ca3143665f8dcd3a
             47a1eec602616042b47dc0f8f6d629fb"
        );

        let ciphertext = encrypt_agent_data(&key, &iv, plaintext);

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
            "425075c7524208f3ca3143665f8dcd3a
             47a1eec602616042b47dc0f8f6d629fb"
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

        let ciphertext = encrypt_agent_data(&key, &iv, plaintext);
        let decrypted = decrypt_agent_data(&key, &iv, &ciphertext)
            .expect("round-trip decryption should succeed");

        assert_eq!(decrypted, plaintext);
        assert_ne!(ciphertext, plaintext);
    }

    #[test]
    fn decrypt_agent_data_rejects_invalid_padding() {
        let key = [0x11; AGENT_KEY_LENGTH];
        let iv = [0x22; AGENT_IV_LENGTH];
        let ciphertext = [0x33; AGENT_IV_LENGTH];

        let error = decrypt_agent_data(&key, &iv, &ciphertext)
            .expect_err("invalid ciphertext must fail decryption");

        assert!(matches!(error, CryptoError::DecryptionFailed));
    }

    #[test]
    fn encrypt_agent_data_returns_empty_vec_for_invalid_key_length() {
        let ciphertext = encrypt_agent_data(&[0_u8; 31], &[0_u8; AGENT_IV_LENGTH], b"abc");

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
}
