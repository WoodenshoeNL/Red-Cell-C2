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
//! Where plaintext = `[agent_id_le: 4]`
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

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use getrandom::fill as getrandom_fill;
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Minimum bytes for a valid registration packet.
pub const ECDH_REG_MIN_LEN: usize = 32 + 12 + 8 + 16;
/// Minimum bytes for a valid session packet.
pub const ECDH_SESSION_MIN_LEN: usize = 16 + 12 + 1 + 16;
/// Minimum bytes for a valid session response.
pub const ECDH_RESP_MIN_LEN: usize = 12 + 16;
/// Length of a connection ID (random token returned at registration).
pub const CONNECTION_ID_LEN: usize = 16;

/// HKDF info string for session key derivation.
const HKDF_INFO_SESSION_KEY: &[u8] = b"red-cell-ecdh-session-key-v1";

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

/// Derive the AES-256-GCM session key from a shared X25519 secret.
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
    if sealed.len() < 12 + 16 {
        return Err(EcdhError::PacketTooShort);
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&sealed[..12]);
    cipher.decrypt(nonce, &sealed[12..]).map_err(|_| EcdhError::AeadFailure)
}

// ─── Agent-side helpers ───────────────────────────────────────────────────────

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
    let ephemeral_secret = StaticSecret::from(ephemeral_secret_bytes);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // Perform ECDH with the listener's static public key.
    let listener_pub = PublicKey::from(*listener_public_key);
    let mut shared = ephemeral_secret.diffie_hellman(&listener_pub).to_bytes();
    let session_key = derive_session_key_from_secret(&shared)?;
    shared.zeroize();

    // Build plaintext: timestamp(8 BE) | metadata.
    let timestamp = current_unix_secs();
    let mut plaintext = Vec::with_capacity(8 + metadata.len());
    plaintext.extend_from_slice(&timestamp.to_be_bytes());
    plaintext.extend_from_slice(metadata);

    // Encrypt with the session key.
    let sealed = aes_gcm_seal(&session_key, &plaintext)?;

    // Wire format: ephemeral_pubkey(32) | nonce(12) | ciphertext | tag(16).
    let mut packet = Vec::with_capacity(32 + sealed.len());
    packet.extend_from_slice(ephemeral_public.as_bytes());
    packet.extend_from_slice(&sealed);

    Ok((packet, session_key))
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
    let connection_id = ConnectionId(response[..16].try_into().expect("16 bytes"));
    let plaintext = aes_gcm_open(session_key, &response[16..])?;
    if plaintext.len() < 4 {
        return Err(EcdhError::PacketTooShort);
    }
    let agent_id = u32::from_le_bytes(plaintext[..4].try_into().expect("4 bytes"));
    Ok((connection_id, agent_id))
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

// ─── Teamserver-side helpers ──────────────────────────────────────────────────

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

    let ephemeral_pub_bytes: [u8; 32] = packet[..32].try_into().expect("32 bytes");
    let ephemeral_pub = PublicKey::from(ephemeral_pub_bytes);
    let listener_secret = StaticSecret::from(keypair.secret_bytes);

    let mut shared = listener_secret.diffie_hellman(&ephemeral_pub).to_bytes();
    let session_key = derive_session_key_from_secret(&shared)?;
    shared.zeroize();

    let plaintext = aes_gcm_open(&session_key, &packet[32..])?;

    if plaintext.len() < 8 {
        return Err(EcdhError::PacketTooShort);
    }

    // Validate timestamp for replay protection.
    let agent_ts = u64::from_be_bytes(plaintext[..8].try_into().expect("8 bytes"));
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
    let mut out = Vec::with_capacity(CONNECTION_ID_LEN + sealed.len());
    out.extend_from_slice(&connection_id.0);
    out.extend_from_slice(&sealed);
    Ok(out)
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
        Some(packet[..CONNECTION_ID_LEN].try_into().expect("16 bytes"))
    } else {
        None
    }
}

fn current_unix_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn hex_short(bytes: &[u8]) -> String {
    bytes.iter().take(8).map(|b| format!("{b:02x}")).collect::<String>() + "..."
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

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

    /// Transport that simulates the server side of the registration handshake.
    ///
    /// On `send` it opens the registration packet with the listener keypair, derives
    /// the session key, and returns a properly encrypted registration response — the
    /// same bytes a real teamserver would produce.
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

        // Transport was called exactly once.
        assert_eq!(transport.sent.lock().expect("lock").len(), 1);
        // The sent packet is long enough to be a registration packet.
        assert!(transport.sent.lock().expect("lock")[0].len() >= ECDH_REG_MIN_LEN);

        // Session fields match what the mock server put in the response.
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

        // Transport was called exactly once.
        assert_eq!(transport.sent_packets().len(), 1);
        // The packet starts with the connection_id.
        assert_eq!(&transport.sent_packets()[0][..16], &conn_id.0);

        // The decrypted response matches what the server encrypted.
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

        let response =
            build_registration_response(&conn_id, &session_key, agent_id).expect("response");

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

        let (packet, _) =
            build_registration_packet(&kp_correct.public_bytes, b"meta").expect("build");

        let result = open_registration_packet(&kp_wrong, 300, &packet);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_packet_fails_authentication() {
        let kp = test_listener_keypair();
        let (mut packet, _) = build_registration_packet(&kp.public_bytes, b"meta").expect("build");

        // Flip a bit in the ciphertext region.
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

        // Build a registration packet but manually craft one with a very old timestamp.
        let mut ephemeral_secret_bytes = [0u8; 32];
        getrandom_fill(&mut ephemeral_secret_bytes).expect("rng");
        let ephemeral_secret = StaticSecret::from(ephemeral_secret_bytes);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);
        let listener_pub = PublicKey::from(kp.public_bytes);
        let mut shared = ephemeral_secret.diffie_hellman(&listener_pub).to_bytes();
        let session_key = derive_session_key_from_secret(&shared).expect("key");
        shared.zeroize();

        // Old timestamp: current time minus replay_window + 1.
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
}
