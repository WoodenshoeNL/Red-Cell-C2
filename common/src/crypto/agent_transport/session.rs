//! Session-key derivation and password hashing.
//!
//! Extracted from `agent_transport` to keep that module under the 800-line threshold.
//! All public items are re-exported from the parent module so call-sites are unaffected.

use hkdf::Hkdf;
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use zeroize::Zeroizing;

use super::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, AgentCryptoMaterial, CryptoError};

/// Generate fresh per-agent AES-256-CTR key material.
pub fn generate_agent_crypto_material() -> Result<AgentCryptoMaterial, CryptoError> {
    let mut key = [0_u8; AGENT_KEY_LENGTH];
    let mut iv = [0_u8; AGENT_IV_LENGTH];

    getrandom::fill(&mut key).map_err(|error| CryptoError::RandomGeneration(error.to_string()))?;
    getrandom::fill(&mut iv).map_err(|error| CryptoError::RandomGeneration(error.to_string()))?;

    Ok(AgentCryptoMaterial { key, iv })
}

/// Derive session keys from agent-supplied key material and a server secret via HKDF-SHA256.
///
/// When a listener is configured with an `InitSecret`, the teamserver does not use the
/// agent-supplied AES key and IV directly for post-init session traffic.  Instead, the
/// raw agent material is mixed with the server secret through HKDF to produce the actual
/// session key and IV.  A compatible agent (Specter / Archon) must perform the same
/// derivation so both sides agree on the session keys.
///
/// This prevents an attacker who can reach the listener from choosing their own session
/// keys: without knowing the server secret they cannot derive the correct session material
/// and subsequent encrypted traffic will be unintelligible.
///
/// The HKDF extraction step uses the server secret as salt and the agent key as input
/// keying material.  Two separate `expand` calls with distinct `info` tags produce the
/// 32-byte session key and 16-byte session IV.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKeyLength`] if the agent-supplied key is not
/// [`AGENT_KEY_LENGTH`] bytes, or [`CryptoError::InvalidIvLength`] if the IV is not
/// [`AGENT_IV_LENGTH`] bytes.
pub fn derive_session_keys(
    agent_key: &[u8],
    agent_iv: &[u8],
    server_secret: &[u8],
) -> Result<AgentCryptoMaterial, CryptoError> {
    if agent_key.len() != AGENT_KEY_LENGTH {
        return Err(CryptoError::InvalidKeyLength {
            expected: AGENT_KEY_LENGTH,
            actual: agent_key.len(),
        });
    }
    if agent_iv.len() != AGENT_IV_LENGTH {
        return Err(CryptoError::InvalidIvLength {
            expected: AGENT_IV_LENGTH,
            actual: agent_iv.len(),
        });
    }

    // Concatenate agent key + IV as the input keying material so both values
    // contribute entropy to the derived output.  Use Zeroizing so the heap
    // allocation is wiped on drop, consistent with the zeroize discipline used
    // elsewhere in this module.
    let mut ikm = Zeroizing::new(Vec::with_capacity(AGENT_KEY_LENGTH + AGENT_IV_LENGTH));
    ikm.extend_from_slice(agent_key);
    ikm.extend_from_slice(agent_iv);

    let hk = Hkdf::<Sha256>::new(Some(server_secret), &ikm);

    let mut derived_key = [0u8; AGENT_KEY_LENGTH];
    hk.expand(b"red-cell-session-key", &mut derived_key).map_err(|_| CryptoError::HkdfExpand)?;

    let mut derived_iv = [0u8; AGENT_IV_LENGTH];
    hk.expand(b"red-cell-session-iv", &mut derived_iv).map_err(|_| CryptoError::HkdfExpand)?;

    Ok(AgentCryptoMaterial { key: derived_key, iv: derived_iv })
}

/// Derive session keys using a versioned server secret from a pre-shared list.
///
/// Looks up `version` in `secrets` (a slice of `(version_byte, secret_bytes)` pairs)
/// and calls [`derive_session_keys`] with the matching secret.
///
/// This is the multi-secret variant used for zero-downtime rotation: agents emit
/// a 1-byte version field in the `DEMON_INIT` envelope so the teamserver can select
/// the correct secret without requiring simultaneous recompilation.
///
/// # Errors
///
/// Returns [`CryptoError::UnknownSecretVersion`] if no entry in `secrets` matches
/// `version`.  Returns the same errors as [`derive_session_keys`] otherwise.
pub fn derive_session_keys_for_version(
    agent_key: &[u8],
    agent_iv: &[u8],
    version: u8,
    secrets: &[(u8, &[u8])],
) -> Result<AgentCryptoMaterial, CryptoError> {
    let secret = secrets
        .iter()
        .find(|(v, _)| *v == version)
        .map(|(_, s)| *s)
        .ok_or(CryptoError::UnknownSecretVersion { version })?;
    derive_session_keys(agent_key, agent_iv, secret)
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
