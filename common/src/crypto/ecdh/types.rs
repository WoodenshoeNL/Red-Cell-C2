use getrandom::fill as getrandom_fill;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use super::hex_short;

/// Minimum bytes for a valid registration packet.
pub const ECDH_REG_MIN_LEN: usize = 32 + 12 + 8 + 16;
/// Minimum bytes for a valid session packet.
pub const ECDH_SESSION_MIN_LEN: usize = 16 + 12 + 1 + 16;
/// Minimum bytes for a valid session response.
pub const ECDH_RESP_MIN_LEN: usize = 12 + 16;
/// Length of a connection ID (random token returned at registration).
pub const CONNECTION_ID_LEN: usize = 16;
/// Length of the replay-detection fingerprint for a registration packet.
///
/// The fingerprint is the first 44 bytes of the wire packet:
/// `ephemeral_pubkey[32] || aes_gcm_nonce[12]`. Because the ephemeral key is
/// generated fresh for every legitimate registration, this value is unique per
/// attempt; an attacker replaying a captured packet will present the same 44
/// bytes.
pub const ECDH_REG_FINGERPRINT_LEN: usize = 32 + 12;

#[derive(Debug, Error)]
pub enum EcdhError {
    #[error("packet too short")]
    PacketTooShort,
    #[error("HKDF expand failed")]
    HkdfExpand,
    #[error("AES-GCM seal/open failed")]
    AeadFailure,
    #[error("replay protection: timestamp outside allowed window")]
    ReplayDetected,
    #[error("invalid connection ID")]
    InvalidConnectionId,
    #[error("RNG failure: {0}")]
    Rng(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("base64 decode error: {0}")]
    Base64(String),
    #[error("invalid key length: expected 32 bytes")]
    InvalidKeyLength,
}

/// Live ECDH session after a successful registration handshake.
#[derive(Debug, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct EcdhSession {
    pub connection_id: ConnectionId,
    pub session_key: [u8; 32],
    pub agent_id: u32,
}

/// Decode a base64-encoded listener public key (standard or URL-safe, with or without padding).
pub fn decode_listener_pub_key(encoded: &str) -> Result<[u8; 32], EcdhError> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(encoded.trim())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded.trim()))
        .map_err(|e| EcdhError::Base64(e.to_string()))?;
    bytes.try_into().map_err(|_| EcdhError::InvalidKeyLength)
}

/// Transport abstraction for ECDH helper functions — implemented by each agent's HTTP transport.
pub trait AgentTransport: Send + Sync {
    fn send(
        &self,
        packet: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>, String>> + Send;
}

/// A listener's X25519 keypair — the secret half never leaves the teamserver.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct ListenerKeypair {
    pub secret_bytes: [u8; 32],
    pub public_bytes: [u8; 32],
}

impl ListenerKeypair {
    /// Generate a fresh random X25519 keypair for a listener.
    pub fn generate() -> Result<Self, EcdhError> {
        let mut secret_bytes = [0u8; 32];
        getrandom_fill(&mut secret_bytes).map_err(|e| EcdhError::Rng(e.to_string()))?;
        let secret = StaticSecret::from(secret_bytes);
        let public = PublicKey::from(&secret);
        Ok(Self { secret_bytes: secret.to_bytes(), public_bytes: public.to_bytes() })
    }

    /// Restore a keypair from persisted bytes.
    pub fn from_bytes(secret: [u8; 32]) -> Self {
        let static_secret = StaticSecret::from(secret);
        let public = PublicKey::from(&static_secret);
        Self { secret_bytes: static_secret.to_bytes(), public_bytes: public.to_bytes() }
    }
}

impl std::fmt::Debug for ListenerKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListenerKeypair")
            .field("public_bytes", &hex_short(&self.public_bytes))
            .finish_non_exhaustive()
    }
}

/// A random 16-byte token returned to the agent after successful registration.
///
/// Used as a routing key for subsequent session packets. Contains no information
/// about the agent identity.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, zeroize::Zeroize)]
pub struct ConnectionId(pub [u8; CONNECTION_ID_LEN]);

impl ConnectionId {
    pub fn generate() -> Result<Self, EcdhError> {
        let mut buf = [0u8; CONNECTION_ID_LEN];
        getrandom_fill(&mut buf).map_err(|e| EcdhError::Rng(e.to_string()))?;
        Ok(Self(buf))
    }
}

impl AsRef<[u8]> for ConnectionId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
