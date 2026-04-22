//! Agent transport cryptography helpers.
//!
//! # AES-256-CTR session design
//!
//! The Havoc Demon protocol assigns each agent a fixed key+IV pair at registration
//! time.  Red Cell's **running session** maintains a monotonically advancing per-agent
//! CTR block offset: `decrypt_from_agent` and `encrypt_for_agent` (in the teamserver)
//! each advance `ctr_block_offset` in both the in-memory session state and the
//! database after every message.  This means successive messages consume distinct
//! portions of the keystream and do **not** suffer from the two-time-pad attack.
//!
//! ## Init-handshake helpers vs. running-session functions
//!
//! [`encrypt_agent_data`] and [`decrypt_agent_data`] are **Havoc-compatibility
//! helpers** that always start at block offset zero.  They are used exclusively
//! during the `DEMON_INIT` handshake (`parse_init_agent`), where the Demon itself
//! sends the first message at offset zero before any session counter has been
//! established.  They must **not** be used for regular callback processing.
//!
//! For all post-registration traffic, use the offset-aware variants
//! ([`encrypt_agent_data_at_offset`] / [`decrypt_agent_data_at_offset`]) and keep the
//! `block_offset` advancing — or use an AEAD scheme (e.g. AES-256-GCM) for new
//! transports that do not need Havoc wire-format compatibility.
//!
//! ## Residual keystream-reuse risk
//!
//! If an adversary records two ciphertexts `C1` and `C2` encrypted at the **same**
//! offset (e.g. both at offset zero), `C1 ⊕ C2 = P1 ⊕ P2`.  The advancing-offset
//! design in the running session prevents this; the init message at offset zero is the
//! only deliberate reset and is constrained to the handshake phase.
//!
//! See [`docs/operator-security.md`](../../../docs/operator-security.md) for
//! deployment guidance.

mod primitives;
pub use primitives::{
    ctr_blocks_for_len, decrypt_agent_data, decrypt_agent_data_at_offset, encrypt_agent_data,
    encrypt_agent_data_at_offset, is_weak_aes_iv, is_weak_aes_key,
};

mod session;
pub use session::{
    derive_session_keys, derive_session_keys_for_version, generate_agent_crypto_material,
    hash_password_sha3,
};

use cipher::InvalidLength;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Agent communication key length in bytes.
pub const AGENT_KEY_LENGTH: usize = 32;

/// Agent communication IV length in bytes.
pub const AGENT_IV_LENGTH: usize = 16;
const AGENT_CTR_BLOCK_LEN: u64 = 16;

/// Fresh AES key material assigned to an agent session.
///
/// The [`Debug`] implementation deliberately redacts key and IV bytes to
/// prevent accidental exposure of key material in logs or error chains.
///
/// Key material is automatically zeroed when this struct is dropped
/// via [`ZeroizeOnDrop`], preventing residual secrets on the stack.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct AgentCryptoMaterial {
    /// AES-256 session key.
    pub key: [u8; AGENT_KEY_LENGTH],
    /// Initial CTR counter block.
    pub iv: [u8; AGENT_IV_LENGTH],
}

impl std::fmt::Debug for AgentCryptoMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentCryptoMaterial")
            .field("key", &"[redacted]")
            .field("iv", &"[redacted]")
            .finish()
    }
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
    /// The underlying cipher could not be constructed (unexpected key/IV length).
    #[error("cipher construction failed: {0}")]
    CipherConstruction(#[from] InvalidLength),
    /// HKDF expand step failed (output length too long for the hash function).
    #[error("HKDF expand failed: output length too long")]
    HkdfExpand,
    /// The version byte in a `DEMON_INIT` envelope does not match any configured secret.
    #[error("unknown init-secret version {version} — agent compiled with an unrecognised secret")]
    UnknownSecretVersion {
        /// The version byte the agent sent.
        version: u8,
    },
}

#[cfg(test)]
mod tests;
