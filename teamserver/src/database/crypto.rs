//! At-rest encryption for sensitive database columns.
//!
//! Agent session keys (AES-256 key + IV) are encrypted with AES-256-GCM before
//! being written to the `ts_agents` table.  Each row uses a fresh random 12-byte
//! nonce so that two rows with the same plaintext produce distinct ciphertexts.
//!
//! # Wire format
//!
//! `base64(nonce[12] || ciphertext || tag[16])`
//!
//! The nonce, ciphertext, and 16-byte authentication tag are concatenated and
//! then base64-encoded for storage as a TEXT column.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use thiserror::Error;
use zeroize::Zeroizing;

const NONCE_LEN: usize = 12;
/// Minimum encoded length: 12-byte nonce + 16-byte GCM tag (empty plaintext).
const MIN_CIPHERTEXT_LEN: usize = NONCE_LEN + 16;

/// Errors produced by [`DbMasterKey`] encrypt/decrypt operations.
#[derive(Debug, Error)]
pub enum DbCryptoError {
    /// AES-256-GCM encryption failed (should never happen in practice).
    #[error("database column encryption failed")]
    Encrypt,
    /// AES-256-GCM authentication / decryption failed.
    ///
    /// This means the ciphertext is corrupt, the wrong key was supplied, or the
    /// data was tampered with.
    #[error(
        "database column decryption failed — the master key may be wrong or the data is corrupt"
    )]
    Decrypt,
    /// Encoded blob is shorter than the minimum valid length.
    #[error("encrypted column too short: expected at least {min} bytes, got {got}")]
    TooShort {
        /// Minimum valid length.
        min: usize,
        /// Actual decoded length.
        got: usize,
    },
    /// Base64 decoding failed.
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    /// OS RNG was unavailable when generating a nonce.
    #[error("OS RNG unavailable: {0}")]
    Rng(#[from] getrandom::Error),
}

/// 256-bit master key used to protect per-row AES session keys in the database.
///
/// The key is held only in process memory and must never be written into the
/// SQLite database itself.  Typically it lives in a separate key file on disk
/// (see `load_or_create_master_key` in `main.rs`) so that exfiltrating the DB
/// file alone is not sufficient to read agent session keys.
///
/// Key material is zeroed on drop via the inner [`Zeroizing`] wrapper.
pub struct DbMasterKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for DbMasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbMasterKey").field("key", &"[redacted]").finish()
    }
}

impl DbMasterKey {
    /// Generate a fresh random 256-bit master key.
    pub fn random() -> Result<Self, DbCryptoError> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Construct from raw key bytes (e.g., loaded from a key file on disk).
    ///
    /// The caller must ensure `bytes` contains 32 bytes of high-entropy key
    /// material and that the source buffer is zeroized after this call.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Raw key bytes, for writing to a key file.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Encrypt `plaintext` and return a base64-encoded opaque blob.
    ///
    /// A fresh 12-byte nonce is generated for every call so that two invocations
    /// with the same plaintext produce distinct outputs.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<String, DbCryptoError> {
        let cipher = Aes256Gcm::new_from_slice(self.0.as_slice())
            .expect("DbMasterKey always holds a valid 32-byte key");
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes)?;
        let nonce = Nonce::from(nonce_bytes);
        let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|_| DbCryptoError::Encrypt)?;

        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(BASE64.encode(&out))
    }

    /// Decrypt a blob produced by [`DbMasterKey::encrypt`].
    ///
    /// The returned bytes are wrapped in [`Zeroizing`] so that plaintext key
    /// material is erased from the heap when the caller drops the value.
    pub fn decrypt(&self, encoded: &str) -> Result<Zeroizing<Vec<u8>>, DbCryptoError> {
        let raw = Zeroizing::new(BASE64.decode(encoded)?);
        if raw.len() < MIN_CIPHERTEXT_LEN {
            return Err(DbCryptoError::TooShort { min: MIN_CIPHERTEXT_LEN, got: raw.len() });
        }
        let nonce = Nonce::from_slice(&raw[..NONCE_LEN]);
        let cipher = Aes256Gcm::new_from_slice(self.0.as_slice())
            .expect("DbMasterKey always holds a valid 32-byte key");
        let plaintext =
            cipher.decrypt(nonce, &raw[NONCE_LEN..]).map_err(|_| DbCryptoError::Decrypt)?;
        Ok(Zeroizing::new(plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::DbMasterKey;

    #[test]
    fn encrypt_then_decrypt_roundtrip() {
        let key = DbMasterKey::random().expect("rng");
        let plaintext = b"secret-aes-key-bytes-here";
        let encrypted = key.encrypt(plaintext).expect("encrypt");
        let decrypted = key.decrypt(&encrypted).expect("decrypt");
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn same_plaintext_produces_different_ciphertexts() {
        let key = DbMasterKey::random().expect("rng");
        let c1 = key.encrypt(b"hello").expect("e1");
        let c2 = key.encrypt(b"hello").expect("e2");
        // Nonces differ, so outputs must differ.
        assert_ne!(c1, c2);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let key1 = DbMasterKey::random().expect("rng");
        let key2 = DbMasterKey::random().expect("rng");
        let encrypted = key1.encrypt(b"data").expect("encrypt");
        assert!(key2.decrypt(&encrypted).is_err(), "wrong key must fail");
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let key = DbMasterKey::random().expect("rng");
        let encrypted = key.encrypt(b"").expect("encrypt");
        let decrypted = key.decrypt(&encrypted).expect("decrypt");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn too_short_blob_returns_error() {
        let key = DbMasterKey::random().expect("rng");
        // Only 11 bytes decoded — shorter than the 28-byte minimum.
        let short = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0u8; 11]);
        assert!(key.decrypt(&short).is_err());
    }

    #[test]
    fn from_bytes_matches_random_key() {
        let key = DbMasterKey::random().expect("rng");
        let bytes = *key.as_bytes();
        let key2 = DbMasterKey::from_bytes(bytes);
        let plaintext = b"round-trip";
        let enc = key.encrypt(plaintext).expect("encrypt");
        let dec = key2.decrypt(&enc).expect("decrypt");
        assert_eq!(dec.as_slice(), plaintext);
    }

    #[test]
    fn debug_does_not_expose_key_material() {
        let key = DbMasterKey::random().expect("rng");
        let debug_str = format!("{key:?}");
        assert!(debug_str.contains("[redacted]"), "key must be redacted in Debug: {debug_str}");
        // Verify none of the actual key bytes appear as hex/base64 in the output.
        assert!(!debug_str.contains("DbMasterKey { key: [") || debug_str.contains("[redacted]"));
    }
}
