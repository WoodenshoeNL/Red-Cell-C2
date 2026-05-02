use getrandom::fill as getrandom_fill;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use super::{
    ConnectionId, ECDH_REG_MIN_LEN, EcdhError, ListenerKeypair, aes_gcm_open, aes_gcm_seal,
    current_unix_secs, derive_session_key_from_secret,
};

fn build_registration_packet_from_parts_impl(
    listener_public_key: &[u8; 32],
    ephemeral_secret_bytes: [u8; 32],
    timestamp_unix_secs: u64,
    metadata: &[u8],
) -> Result<(Vec<u8>, [u8; 32]), EcdhError> {
    let ephemeral_secret = StaticSecret::from(ephemeral_secret_bytes);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    let listener_pub = PublicKey::from(*listener_public_key);
    let mut shared = ephemeral_secret.diffie_hellman(&listener_pub).to_bytes();
    let session_key = derive_session_key_from_secret(&shared)?;
    shared.zeroize();

    let mut plaintext = Vec::with_capacity(8 + metadata.len());
    plaintext.extend_from_slice(&timestamp_unix_secs.to_be_bytes());
    plaintext.extend_from_slice(metadata);

    let sealed = aes_gcm_seal(&session_key, &plaintext)?;

    let mut packet = Vec::with_capacity(32 + sealed.len());
    packet.extend_from_slice(ephemeral_public.as_bytes());
    packet.extend_from_slice(&sealed);

    Ok((packet, session_key))
}

/// Build a registration packet from caller-supplied ephemeral secret and timestamp.
///
/// Returns `(packet_bytes, session_key)`. Use this variant when deterministic
/// output is required — for example when generating corpus fixtures for replay
/// tests. The caller must ensure `ephemeral_secret_bytes` are freshly generated
/// and never reused across registrations in production code.
///
/// For normal agent use, prefer [`build_registration_packet`] which generates
/// both the ephemeral secret and timestamp automatically.
///
/// # Arguments
/// - `listener_public_key` — 32-byte X25519 public key compiled into the agent.
/// - `ephemeral_secret_bytes` — caller-supplied ephemeral X25519 secret.
/// - `timestamp_unix_secs` — Unix timestamp to embed in the plaintext.
/// - `metadata` — arbitrary agent metadata bytes.
///
/// # Feature gate
/// This function is only available when the `test-utils` Cargo feature is
/// enabled. It must not be called from production code.
#[cfg(feature = "test-utils")]
pub fn build_registration_packet_from_parts(
    listener_public_key: &[u8; 32],
    ephemeral_secret_bytes: [u8; 32],
    timestamp_unix_secs: u64,
    metadata: &[u8],
) -> Result<(Vec<u8>, [u8; 32]), EcdhError> {
    build_registration_packet_from_parts_impl(
        listener_public_key,
        ephemeral_secret_bytes,
        timestamp_unix_secs,
        metadata,
    )
}

/// Build a registration packet to send to the teamserver.
///
/// Returns `(packet_bytes, session_key)`. The session key must be stored for
/// encrypting subsequent session packets, after the teamserver returns a
/// [`ConnectionId`].
///
/// # Arguments
/// - `listener_public_key` — 32-byte X25519 public key compiled into the agent.
/// - `metadata` — arbitrary agent metadata bytes (agent info, OS details, etc.).
pub fn build_registration_packet(
    listener_public_key: &[u8; 32],
    metadata: &[u8],
) -> Result<(Vec<u8>, [u8; 32]), EcdhError> {
    // Generate a fresh ephemeral keypair. StaticSecret is used here (not
    // EphemeralSecret) because x25519-dalek v2 requires a RNG trait object for
    // EphemeralSecret; we supply our own randomness via getrandom and immediately
    // discard the secret after the ECDH step.
    let mut ephemeral_secret_bytes = [0u8; 32];
    getrandom_fill(&mut ephemeral_secret_bytes).map_err(|e| EcdhError::Rng(e.to_string()))?;
    build_registration_packet_from_parts_impl(
        listener_public_key,
        ephemeral_secret_bytes,
        current_unix_secs(),
        metadata,
    )
}

/// Parse a registration response from the teamserver.
///
/// Returns `(connection_id, agent_id_le)`.
///
/// Response format: `[connection_id: 16] | [nonce: 12] | [ciphertext] | [tag: 16]`
pub fn parse_registration_response(
    session_key: &[u8; 32],
    response: &[u8],
) -> Result<(ConnectionId, u32), EcdhError> {
    if response.len() < 16 + 12 + 4 + 16 {
        return Err(EcdhError::PacketTooShort);
    }
    let connection_id =
        ConnectionId(response[..16].try_into().map_err(|_| EcdhError::PacketTooShort)?);
    let plaintext = aes_gcm_open(session_key, &response[16..])?;
    if plaintext.len() < 4 {
        return Err(EcdhError::PacketTooShort);
    }
    let agent_id =
        u32::from_le_bytes(plaintext[..4].try_into().map_err(|_| EcdhError::PacketTooShort)?);
    Ok((connection_id, agent_id))
}

/// Parsed result of a valid ECDH registration packet.
pub struct ParsedRegistration {
    /// Derived session key — store this and associate it with the agent.
    pub session_key: [u8; 32],
    /// Decrypted metadata bytes (starts with timestamp which has already been validated).
    pub metadata: Vec<u8>,
}

/// Attempt to open an ECDH registration packet received by the teamserver.
///
/// Returns [`ParsedRegistration`] on success. Fails if the packet is too short,
/// the AEAD tag is invalid (wrong listener key), or the timestamp is outside
/// `replay_window_secs`.
///
/// Packet format: `[ephemeral_pubkey: 32] | [nonce: 12] | [ciphertext] | [tag: 16]`
pub fn open_registration_packet(
    keypair: &ListenerKeypair,
    replay_window_secs: u64,
    packet: &[u8],
) -> Result<ParsedRegistration, EcdhError> {
    if packet.len() < ECDH_REG_MIN_LEN {
        return Err(EcdhError::PacketTooShort);
    }

    let ephemeral_pub_bytes: [u8; 32] =
        packet[..32].try_into().map_err(|_| EcdhError::PacketTooShort)?;
    let ephemeral_pub = PublicKey::from(ephemeral_pub_bytes);
    let listener_secret = StaticSecret::from(keypair.secret_bytes);

    let mut shared = listener_secret.diffie_hellman(&ephemeral_pub).to_bytes();
    let session_key = derive_session_key_from_secret(&shared)?;
    shared.zeroize();

    let plaintext = aes_gcm_open(&session_key, &packet[32..])?;

    if plaintext.len() < 8 {
        return Err(EcdhError::PacketTooShort);
    }

    let agent_ts =
        u64::from_be_bytes(plaintext[..8].try_into().map_err(|_| EcdhError::PacketTooShort)?);
    let now = current_unix_secs();
    let delta = now.abs_diff(agent_ts);
    if delta > replay_window_secs {
        return Err(EcdhError::ReplayDetected);
    }

    Ok(ParsedRegistration { session_key, metadata: plaintext[8..].to_vec() })
}

/// Build a registration response to send to the agent.
///
/// Returns `[connection_id: 16] | [nonce: 12] | [ciphertext] | [tag: 16]`.
pub fn build_registration_response(
    connection_id: &ConnectionId,
    session_key: &[u8; 32],
    agent_id: u32,
) -> Result<Vec<u8>, EcdhError> {
    let sealed = aes_gcm_seal(session_key, &agent_id.to_le_bytes())?;
    let mut out = Vec::with_capacity(super::CONNECTION_ID_LEN + sealed.len());
    out.extend_from_slice(&connection_id.0);
    out.extend_from_slice(&sealed);
    Ok(out)
}
