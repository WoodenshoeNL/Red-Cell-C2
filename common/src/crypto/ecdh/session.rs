use super::{
    AgentTransport, CONNECTION_ID_LEN, ConnectionId, ECDH_SESSION_MIN_LEN, EcdhError, EcdhSession,
    aes_gcm_open, aes_gcm_seal,
};
use crate::crypto::ecdh::{build_registration_packet, parse_registration_response};

/// Perform the ECDH registration handshake with the teamserver and return the negotiated session.
pub async fn perform_registration<T: AgentTransport>(
    transport: &T,
    listener_pub_key: &[u8; 32],
    metadata: &[u8],
) -> Result<EcdhSession, EcdhError> {
    let (packet, session_key) = build_registration_packet(listener_pub_key, metadata)?;

    let response = transport.send(&packet).await.map_err(EcdhError::Transport)?;

    let (connection_id, agent_id) = parse_registration_response(&session_key, &response)?;

    Ok(EcdhSession { connection_id, session_key, agent_id })
}

/// Encrypt a payload with the session key, send it, and return the decrypted response.
pub async fn send_session_packet<T: AgentTransport>(
    transport: &T,
    session: &EcdhSession,
    payload: &[u8],
) -> Result<Vec<u8>, EcdhError> {
    let packet = seal_session_packet(&session.connection_id, &session.session_key, payload)?;

    let response = transport.send(&packet).await.map_err(EcdhError::Transport)?;

    if response.is_empty() {
        return Ok(Vec::new());
    }

    open_session_response(&session.session_key, &response)
}

/// Encrypt an agent → teamserver session payload.
///
/// Returns `[connection_id: 16] | [nonce: 12] | [ciphertext] | [tag: 16]`.
pub fn seal_session_packet(
    connection_id: &ConnectionId,
    session_key: &[u8; 32],
    payload: &[u8],
) -> Result<Vec<u8>, EcdhError> {
    let sealed = aes_gcm_seal(session_key, payload)?;
    let mut out = Vec::with_capacity(CONNECTION_ID_LEN + sealed.len());
    out.extend_from_slice(&connection_id.0);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Decrypt a teamserver → agent session response.
///
/// Response format: `[nonce: 12] | [ciphertext] | [tag: 16]`
pub fn open_session_response(
    session_key: &[u8; 32],
    response: &[u8],
) -> Result<Vec<u8>, EcdhError> {
    aes_gcm_open(session_key, response)
}

/// Open an agent → teamserver session packet.
///
/// The caller must first strip the leading `connection_id` (16 bytes) and look
/// up the associated session key; this function decrypts what remains.
///
/// Remaining format: `[nonce: 12] | [ciphertext] | [tag: 16]`
pub fn open_session_packet(
    session_key: &[u8; 32],
    packet_body: &[u8],
) -> Result<Vec<u8>, EcdhError> {
    aes_gcm_open(session_key, packet_body)
}

/// Build a teamserver → agent session response.
///
/// Returns `[nonce: 12] | [ciphertext] | [tag: 16]`.
pub fn seal_session_response(session_key: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>, EcdhError> {
    aes_gcm_seal(session_key, payload)
}

/// Classify an incoming non-legacy HTTP body.
///
/// Returns the leading 16 bytes interpreted as a potential `ConnectionId`,
/// so the caller can look it up in the session table. If the packet is too
/// short to be a session packet but long enough for registration, the caller
/// should try `open_registration_packet`.
#[must_use]
pub fn extract_connection_id_candidate(packet: &[u8]) -> Option<[u8; CONNECTION_ID_LEN]> {
    if packet.len() >= ECDH_SESSION_MIN_LEN {
        packet[..CONNECTION_ID_LEN].try_into().ok()
    } else {
        None
    }
}
