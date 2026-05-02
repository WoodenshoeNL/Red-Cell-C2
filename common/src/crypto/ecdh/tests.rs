use super::*;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use std::sync::Mutex;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Mock transport that returns a pre-configured response or an error.
struct MockTransport {
    /// Bytes to return from `send`, or `Err(msg)` if `None`.
    response: Option<Vec<u8>>,
    /// Captures every packet passed to `send` for inspection.
    sent: Mutex<Vec<Vec<u8>>>,
}

impl MockTransport {
    fn ok(response: Vec<u8>) -> Self {
        Self { response: Some(response), sent: Mutex::new(Vec::new()) }
    }

    fn error() -> Self {
        Self { response: None, sent: Mutex::new(Vec::new()) }
    }

    fn sent_packets(&self) -> Vec<Vec<u8>> {
        self.sent.lock().expect("lock").clone()
    }
}

impl AgentTransport for MockTransport {
    fn send(
        &self,
        packet: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>, String>> + Send {
        self.sent.lock().expect("lock").push(packet.to_vec());
        let result = match &self.response {
            Some(r) => Ok(r.clone()),
            None => Err("mock transport error".to_string()),
        };
        std::future::ready(result)
    }
}

/// Server-side ECDH transport: opens the registration packet and returns a valid encrypted response.
struct RegistrationServerTransport {
    keypair: ListenerKeypair,
    conn_id: ConnectionId,
    agent_id: u32,
    sent: Mutex<Vec<Vec<u8>>>,
}

impl AgentTransport for RegistrationServerTransport {
    fn send(
        &self,
        packet: &[u8],
    ) -> impl std::future::Future<Output = Result<Vec<u8>, String>> + Send {
        self.sent.lock().expect("lock").push(packet.to_vec());
        let parsed =
            open_registration_packet(&self.keypair, 300, packet).map_err(|e| e.to_string());
        let conn_id = self.conn_id;
        let agent_id = self.agent_id;
        std::future::ready(parsed.and_then(|p| {
            build_registration_response(&conn_id, &p.session_key, agent_id)
                .map_err(|e| e.to_string())
        }))
    }
}

#[tokio::test]
async fn perform_registration_calls_transport_and_parses_session() {
    let kp = ListenerKeypair::generate().expect("keypair");
    let conn_id = ConnectionId::generate().expect("conn_id");
    let agent_id = 0xDEAD_BEEFu32;
    let metadata = b"test-metadata";

    let transport = RegistrationServerTransport {
        keypair: kp,
        conn_id,
        agent_id,
        sent: Mutex::new(Vec::new()),
    };

    let session = perform_registration(&transport, &transport.keypair.public_bytes, metadata)
        .await
        .expect("registration");

    assert_eq!(transport.sent.lock().expect("lock").len(), 1);
    assert!(transport.sent.lock().expect("lock")[0].len() >= ECDH_REG_MIN_LEN);
    assert_eq!(session.agent_id, agent_id);
    assert_eq!(session.connection_id, conn_id);
    assert_ne!(session.session_key, [0u8; 32]);
}

#[tokio::test]
async fn send_session_packet_encrypts_and_decrypts_response() {
    let kp = ListenerKeypair::generate().expect("keypair");
    let (_, session_key) = build_registration_packet(&kp.public_bytes, b"meta").expect("build");
    let conn_id = ConnectionId::generate().expect("conn_id");
    let session = EcdhSession { connection_id: conn_id, session_key, agent_id: 1 };

    let response_payload = b"server-reply";
    let server_response =
        seal_session_response(&session.session_key, response_payload).expect("seal");

    let transport = MockTransport::ok(server_response);

    let decrypted =
        send_session_packet(&transport, &session, b"agent-payload").await.expect("send");

    assert_eq!(transport.sent_packets().len(), 1);
    assert_eq!(&transport.sent_packets()[0][..16], &conn_id.0);
    assert_eq!(decrypted, response_payload);
}

#[tokio::test]
async fn send_session_packet_propagates_transport_error() {
    let kp = ListenerKeypair::generate().expect("keypair");
    let (_, session_key) = build_registration_packet(&kp.public_bytes, b"meta").expect("build");
    let conn_id = ConnectionId::generate().expect("conn_id");
    let session = EcdhSession { connection_id: conn_id, session_key, agent_id: 1 };

    let transport = MockTransport::error();

    let err = send_session_packet(&transport, &session, b"payload").await.unwrap_err();
    assert!(matches!(err, EcdhError::Transport(_)));
}

fn test_listener_keypair() -> ListenerKeypair {
    ListenerKeypair::generate().expect("keypair")
}

#[test]
fn generate_keypair_is_valid() {
    let kp = test_listener_keypair();
    assert_ne!(kp.public_bytes, [0u8; 32]);
    assert_ne!(kp.secret_bytes, [0u8; 32]);
}

#[test]
fn from_bytes_round_trips() {
    let kp = test_listener_keypair();
    let kp2 = ListenerKeypair::from_bytes(kp.secret_bytes);
    assert_eq!(kp.public_bytes, kp2.public_bytes);
}

#[test]
fn connection_id_generate_is_nonzero() {
    let id = ConnectionId::generate().expect("id");
    assert_ne!(id.0, [0u8; 16]);
}

#[test]
fn registration_round_trip() {
    let kp = test_listener_keypair();
    let metadata = b"agent-metadata-bytes";

    let (packet, session_key) =
        build_registration_packet(&kp.public_bytes, metadata).expect("build");

    assert!(packet.len() >= ECDH_REG_MIN_LEN);

    let parsed = open_registration_packet(&kp, 300, &packet).expect("open");

    assert_eq!(parsed.session_key, session_key);
    assert_eq!(parsed.metadata, metadata.as_slice());
}

#[test]
fn registration_response_round_trip() {
    let kp = test_listener_keypair();
    let (_, session_key) = build_registration_packet(&kp.public_bytes, b"meta").expect("build");

    let conn_id = ConnectionId::generate().expect("conn_id");
    let agent_id = 0x1234_5678_u32;

    let response = build_registration_response(&conn_id, &session_key, agent_id).expect("response");

    let (parsed_conn_id, parsed_agent_id) =
        parse_registration_response(&session_key, &response).expect("parse");

    assert_eq!(parsed_conn_id, conn_id);
    assert_eq!(parsed_agent_id, agent_id);
}

#[test]
fn session_packet_round_trip() {
    let kp = test_listener_keypair();
    let (_, session_key) = build_registration_packet(&kp.public_bytes, b"meta").expect("build");

    let conn_id = ConnectionId::generate().expect("conn_id");
    let payload = b"task-response-data";

    let packet = seal_session_packet(&conn_id, &session_key, payload).expect("seal");
    assert!(packet.len() >= ECDH_SESSION_MIN_LEN);
    assert_eq!(&packet[..16], &conn_id.0);

    let decrypted = open_session_packet(&session_key, &packet[16..]).expect("open");
    assert_eq!(decrypted, payload);
}

#[test]
fn session_response_round_trip() {
    let kp = test_listener_keypair();
    let (_, session_key) = build_registration_packet(&kp.public_bytes, b"meta").expect("build");

    let payload = b"teamserver-response";
    let sealed = seal_session_response(&session_key, payload).expect("seal");
    let opened = open_session_response(&session_key, &sealed).expect("open");
    assert_eq!(opened, payload);
}

#[test]
fn wrong_listener_key_fails_decryption() {
    let kp_correct = test_listener_keypair();
    let kp_wrong = test_listener_keypair();

    let (packet, _) = build_registration_packet(&kp_correct.public_bytes, b"meta").expect("build");

    let result = open_registration_packet(&kp_wrong, 300, &packet);
    assert!(result.is_err());
}

#[test]
fn tampered_packet_fails_authentication() {
    let kp = test_listener_keypair();
    let (mut packet, _) = build_registration_packet(&kp.public_bytes, b"meta").expect("build");

    let last = packet.len() - 1;
    packet[last] ^= 0xFF;

    let result = open_registration_packet(&kp, 300, &packet);
    assert!(result.is_err());
}

#[test]
fn short_packet_is_rejected() {
    let kp = test_listener_keypair();
    let result = open_registration_packet(&kp, 300, &[0u8; 60]);
    assert!(matches!(result, Err(EcdhError::PacketTooShort)));
}

#[test]
fn extract_connection_id_returns_first_16_bytes() {
    let packet = (0u8..45).collect::<Vec<u8>>();
    let candidate = extract_connection_id_candidate(&packet).expect("candidate");
    assert_eq!(candidate, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
}

#[test]
fn extract_connection_id_returns_none_for_short_packet() {
    let packet = [0u8; 44];
    assert!(extract_connection_id_candidate(&packet).is_none());
}

#[test]
fn replay_protection_rejects_stale_timestamp() {
    let kp = test_listener_keypair();

    let mut ephemeral_secret_bytes = [0u8; 32];
    getrandom::fill(&mut ephemeral_secret_bytes).expect("rng");
    let ephemeral_secret = StaticSecret::from(ephemeral_secret_bytes);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let listener_pub = PublicKey::from(kp.public_bytes);
    let mut shared = ephemeral_secret.diffie_hellman(&listener_pub).to_bytes();
    let session_key = derive_session_key_from_secret(&shared).expect("key");
    shared.zeroize();

    let stale_ts: u64 = current_unix_secs().saturating_sub(400);
    let mut plaintext = Vec::with_capacity(8 + 4);
    plaintext.extend_from_slice(&stale_ts.to_be_bytes());
    plaintext.extend_from_slice(b"meta");

    let sealed = aes_gcm_seal(&session_key, &plaintext).expect("seal");
    let mut packet = Vec::with_capacity(32 + sealed.len());
    packet.extend_from_slice(ephemeral_public.as_bytes());
    packet.extend_from_slice(&sealed);

    let result = open_registration_packet(&kp, 300, &packet);
    assert!(matches!(result, Err(EcdhError::ReplayDetected)));
}

/// Golden vector: known X25519 shared secret → HKDF-SHA256 session key.
///
/// Uses the RFC 7748 §6.1 shared secret as HKDF input and verifies
/// `derive_session_key_from_secret` against an independent reference that
/// manually steps through RFC 5869 using raw HMAC-SHA256 (without the `hkdf`
/// crate's API), catching any mismatch in the info string, salt, or expand
/// logic.
///
/// Expected output computed with this reference and independently verified
/// against Python's `cryptography` library:
/// `1b3fc6e8d68f2ef35a497116cc09ed333874052611804a8d80460b6317bc5279`
#[test]
fn ecdh_hkdf_session_key_derivation_golden_vector() {
    use hmac::Mac as HmacMac;

    let shared_secret: [u8; 32] = [
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f,
        0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16,
        0x17, 0x42,
    ];

    type HmacSha256 = hmac::Hmac<sha2::Sha256>;
    let salt = [0u8; 32];
    let mut mac = <HmacSha256 as HmacMac>::new_from_slice(&salt).expect("hmac init");
    mac.update(&shared_secret);
    let prk = mac.finalize().into_bytes();

    let info = b"red-cell-ecdh-session-key-v1";
    let mut mac2 = <HmacSha256 as HmacMac>::new_from_slice(&prk).expect("hmac init");
    mac2.update(info);
    mac2.update(&[0x01u8]);
    let reference_key: [u8; 32] = mac2.finalize().into_bytes().into();

    let derived = derive_session_key_from_secret(&shared_secret).expect("derive");

    assert_eq!(
        derived, reference_key,
        "derive_session_key_from_secret must match RFC 5869 HKDF-SHA256 reference"
    );

    let expected: [u8; 32] =
        hex::decode("1b3fc6e8d68f2ef35a497116cc09ed333874052611804a8d80460b6317bc5279")
            .expect("hex")
            .try_into()
            .expect("32 bytes");
    assert_eq!(derived, expected, "HKDF session key must match Python reference vector");
}

#[test]
fn aes256gcm_cross_implementation_with_c_archon() {
    let key_bytes: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let nonce_bytes: [u8; 12] =
        [0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88];
    let plaintext = b"ECDH session test payload for Archon";

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let rust_ct = cipher.encrypt(nonce, plaintext.as_slice()).expect("encrypt");

    let c_ct_tag = hex::decode(
        "cfe0e46e8a092a68356232b35b69ec4c7900b030a67505152aff621ecca924\
         8dce38ae280061e5aae17e2647dc3565d9dd90c9dc",
    )
    .expect("hex");

    assert_eq!(
        rust_ct, c_ct_tag,
        "Rust aes-gcm and C AesGcm.c must produce identical ciphertext+tag"
    );
}

#[test]
fn x25519_cross_implementation_rfc7748() {
    let alice_priv: [u8; 32] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];
    let bob_pub: [u8; 32] = [
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35,
        0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88,
        0x2b, 0x4f,
    ];
    let expected_shared: [u8; 32] = [
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f,
        0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16,
        0x17, 0x42,
    ];

    let alice_secret = StaticSecret::from(alice_priv);
    let bob_public = PublicKey::from(bob_pub);
    let shared = alice_secret.diffie_hellman(&bob_public).to_bytes();
    assert_eq!(shared, expected_shared, "x25519-dalek must match RFC 7748 §6.1");
}
