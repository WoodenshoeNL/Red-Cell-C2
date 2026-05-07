//! ECDH key exchange and session encryption for Phantom and Specter agents.
//!
//! ## Wire format
//!
//! ### Registration packet (agent → teamserver)
//! ```text
//! [ephemeral_pubkey: 32] | [nonce: 12] | [ciphertext] | [tag: 16]
//! ```
//! Where plaintext = `[timestamp_be: 8] | [metadata]`
//! Minimum size: 32 + 12 + 8 + 16 = 68 bytes
//!
//! ### Registration response (teamserver → agent)
//! ```text
//! [connection_id: 16] | [nonce: 12] | [ciphertext] | [tag: 16]
//! ```
//! Where plaintext = `[agent_id_le: 4]` and AES-GCM AAD = `connection_id` (16 bytes).
//! The `connection_id` is bound as additional authenticated data so in-path tampering
//! of the cleartext routing token invalidates the AEAD tag.
//! Minimum size: 16 + 12 + 4 + 16 = 48 bytes
//!
//! ### Session packet (agent → teamserver)
//! ```text
//! [connection_id: 16] | [nonce: 12] | [ciphertext] | [tag: 16]
//! ```
//! Minimum size: 16 + 12 + 1 + 16 = 45 bytes
//!
//! ### Session response (teamserver → agent)
//! ```text
//! [nonce: 12] | [ciphertext] | [tag: 16]
//! ```
//! Minimum size: 12 + 0 + 16 = 28 bytes (empty payload allowed)

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use getrandom::fill as getrandom_fill;
use hkdf::Hkdf;
use sha2::Sha256;

mod handshake;
mod session;
mod types;

#[cfg(test)]
mod tests;

pub use handshake::{
    ParsedRegistration, build_registration_packet, build_registration_response,
    open_registration_packet, parse_registration_response,
};
pub use session::{
    extract_connection_id_candidate, open_session_packet, open_session_response,
    perform_registration, seal_session_packet, seal_session_response, send_session_packet,
};
pub use types::{
    AgentTransport, CONNECTION_ID_LEN, ConnectionId, ECDH_REG_FINGERPRINT_LEN, ECDH_REG_MIN_LEN,
    ECDH_REG_RESP_MIN_LEN, ECDH_SESSION_MIN_LEN, ECDH_SESSION_RESP_MIN_LEN, EcdhError, EcdhSession,
    ListenerKeypair, decode_listener_pub_key,
};

#[cfg(feature = "test-utils")]
pub use handshake::build_registration_packet_from_parts;

/// HKDF info string for session key derivation.
const HKDF_INFO_SESSION_KEY: &[u8] = b"red-cell-ecdh-session-key-v1";

fn derive_session_key_from_secret(shared_secret: &[u8; 32]) -> Result<[u8; 32], EcdhError> {
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret);
    let mut session_key = [0u8; 32];
    hkdf.expand(HKDF_INFO_SESSION_KEY, &mut session_key).map_err(|_| EcdhError::HkdfExpand)?;
    Ok(session_key)
}

/// Seal plaintext with AES-256-GCM using a random nonce.
///
/// Returns `nonce(12) | ciphertext | tag(16)`.
fn aes_gcm_seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, EcdhError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    getrandom_fill(&mut nonce_bytes).map_err(|e| EcdhError::Rng(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext).map_err(|_| EcdhError::AeadFailure)?;
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open an AES-256-GCM sealed blob of the form `nonce(12) | ciphertext | tag(16)`.
fn aes_gcm_open(key: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, EcdhError> {
    if sealed.len() < ECDH_SESSION_RESP_MIN_LEN {
        return Err(EcdhError::PacketTooShort);
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&sealed[..12]);
    cipher.decrypt(nonce, &sealed[12..]).map_err(|_| EcdhError::AeadFailure)
}

/// Seal plaintext with AES-256-GCM using a random nonce and caller-supplied AAD.
///
/// Returns `nonce(12) | ciphertext | tag(16)`.  The tag covers both the plaintext
/// and `aad`, so any mutation of `aad` after sealing will fail authentication.
fn aes_gcm_seal_aad(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, EcdhError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut nonce_bytes = [0u8; 12];
    getrandom_fill(&mut nonce_bytes).map_err(|e| EcdhError::Rng(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|_| EcdhError::AeadFailure)?;
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open an AES-256-GCM sealed blob of the form `nonce(12) | ciphertext | tag(16)`
/// with caller-supplied AAD.  Fails with [`EcdhError::AeadFailure`] if either the
/// ciphertext or the AAD has been tampered with.
fn aes_gcm_open_aad(key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, EcdhError> {
    if sealed.len() < ECDH_SESSION_RESP_MIN_LEN {
        return Err(EcdhError::PacketTooShort);
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&sealed[..12]);
    cipher.decrypt(nonce, Payload { msg: &sealed[12..], aad }).map_err(|_| EcdhError::AeadFailure)
}

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn hex_short(bytes: &[u8]) -> String {
    bytes.iter().take(8).map(|b| format!("{b:02x}")).collect::<String>() + "..."
}
