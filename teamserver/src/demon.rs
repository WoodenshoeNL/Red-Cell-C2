//! Incoming Havoc Demon transport parsing for the teamserver.

use std::borrow::Cow;

use red_cell_common::crypto::{
    AGENT_IV_LENGTH, AGENT_KEY_LENGTH, CryptoError, decrypt_agent_data, is_weak_aes_iv,
    is_weak_aes_key,
};
use red_cell_common::demon::{DemonCommand, DemonEnvelope, DemonHeader, DemonProtocolError};
use red_cell_common::{AgentEncryptionInfo, AgentRecord};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::warn;
use zeroize::Zeroizing;

use crate::dispatch::util::{
    basename, process_arch_label, windows_arch_label, windows_version_label,
};
use crate::{AgentRegistry, TeamserverError};

/// A decrypted Demon callback package parsed from an agent request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemonCallbackPackage {
    /// Raw command identifier.
    pub command_id: u32,
    /// Request identifier correlated with the originating task.
    pub request_id: u32,
    /// Raw package payload bytes.
    pub payload: Vec<u8>,
}

impl DemonCallbackPackage {
    /// Return the typed command identifier if it matches a known Havoc constant.
    pub fn command(&self) -> Result<DemonCommand, DemonProtocolError> {
        self.command_id.try_into()
    }
}

/// Parsed registration payload for a new Demon agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDemonInit {
    /// Outer transport header.
    pub header: DemonHeader,
    /// Request identifier supplied by the implant.
    pub request_id: u32,
    /// Fully parsed agent metadata, including the stored transport key/IV.
    pub agent: AgentRecord,
}

/// Normalized result of parsing a Demon request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedDemonPacket {
    /// First-time registration with metadata and session key material.
    Init(Box<ParsedDemonInit>),
    /// Reconnect probe from an already-registered agent.
    Reconnect {
        /// Outer transport header.
        header: DemonHeader,
        /// Request identifier supplied by the implant.
        request_id: u32,
    },
    /// One or more decrypted callback packages from an existing agent.
    Callback {
        /// Outer transport header.
        header: DemonHeader,
        /// Parsed callback packages in transmission order.
        packages: Vec<DemonCallbackPackage>,
    },
}

/// Errors returned while parsing incoming Demon traffic.
#[derive(Debug, Error)]
pub enum DemonParserError {
    /// The envelope or command stream did not match the Havoc wire format.
    #[error("invalid demon protocol data: {0}")]
    Protocol(#[from] DemonProtocolError),
    /// Stored or transmitted AES material could not be used.
    #[error("invalid agent crypto material: {0}")]
    Crypto(#[from] CryptoError),
    /// The parser could not update the shared agent registry.
    #[error("agent registry operation failed: {0}")]
    Registry(#[from] TeamserverError),
    /// Base64 decoding failed for a persisted key or IV.
    #[error("invalid base64 in stored {field} for agent 0x{agent_id:08X}: {message}")]
    InvalidStoredCryptoEncoding {
        /// Agent identifier associated with the invalid value.
        agent_id: u32,
        /// Stored field name.
        field: &'static str,
        /// Decoder error message.
        message: String,
    },
    /// The parser found malformed or incomplete metadata in a `DEMON_INIT` request.
    #[error("invalid demon init payload: {0}")]
    InvalidInit(&'static str),
}

/// Parser for incoming Demon transport packets backed by the teamserver agent registry.
#[derive(Clone, Debug)]
pub struct DemonPacketParser {
    registry: AgentRegistry,
}

impl DemonPacketParser {
    /// Create a packet parser that resolves agent session keys from the provided registry.
    #[must_use]
    pub fn new(registry: AgentRegistry) -> Self {
        Self { registry }
    }

    /// Parse an incoming Demon request and update the registry for newly registered agents.
    pub async fn parse(
        &self,
        bytes: &[u8],
        external_ip: impl Into<String>,
    ) -> Result<ParsedDemonPacket, DemonParserError> {
        self.parse_for_listener(bytes, external_ip, "null").await
    }

    /// Parse an incoming Demon request and retain the listener that accepted it.
    pub async fn parse_for_listener(
        &self,
        bytes: &[u8],
        external_ip: impl Into<String>,
        listener_name: &str,
    ) -> Result<ParsedDemonPacket, DemonParserError> {
        let now = OffsetDateTime::now_utc();
        self.parse_at_for_listener(bytes, external_ip.into(), listener_name, now).await
    }

    #[cfg(test)]
    async fn parse_at(
        &self,
        bytes: &[u8],
        external_ip: String,
        now: OffsetDateTime,
    ) -> Result<ParsedDemonPacket, DemonParserError> {
        self.parse_at_for_listener(bytes, external_ip, "null", now).await
    }

    async fn parse_at_for_listener(
        &self,
        bytes: &[u8],
        external_ip: String,
        listener_name: &str,
        now: OffsetDateTime,
    ) -> Result<ParsedDemonPacket, DemonParserError> {
        let envelope = DemonEnvelope::from_bytes(bytes)?;
        let mut offset = 0_usize;
        let command_id = read_u32_be(&envelope.payload, &mut offset, "top-level command id")?;
        let request_id = read_u32_be(&envelope.payload, &mut offset, "top-level request id")?;
        let remaining = &envelope.payload[offset..];

        if command_id == u32::from(DemonCommand::DemonInit) {
            if envelope.header.agent_id == 0 {
                warn!(listener_name, "rejecting DEMON_INIT with reserved agent_id 0x00000000");
                return Err(DemonParserError::InvalidInit(
                    "agent_id 0 is reserved and not allowed",
                ));
            }

            if remaining.is_empty() {
                return Ok(ParsedDemonPacket::Reconnect { header: envelope.header, request_id });
            }

            if self.registry.get(envelope.header.agent_id).await.is_some() {
                warn!(
                    agent_id = format_args!("0x{:08X}", envelope.header.agent_id),
                    listener_name,
                    "rejecting duplicate full DEMON_INIT for an already-registered agent"
                );
                return Err(DemonParserError::InvalidInit(
                    "agent is already registered; reconnect probe required",
                ));
            }

            let agent = parse_init_agent(envelope.header.agent_id, remaining, &external_ip, now)?;
            self.registry
                .insert_with_listener_and_ctr_offset(agent.clone(), listener_name, 0)
                .await?;

            return Ok(ParsedDemonPacket::Init(Box::new(ParsedDemonInit {
                header: envelope.header,
                request_id,
                agent,
            })));
        }

        // Decrypt without advancing the CTR offset first.  AES-CTR has no authentication tag, so
        // decryption always "succeeds" regardless of whether the ciphertext is genuine.  If we
        // advanced the offset unconditionally and the Demon protocol parse below then failed (e.g.
        // because an attacker sent a crafted packet with a valid agent_id but garbage payload),
        // the stored offset would be permanently desynced and the real agent's next legitimate
        // callback would be decrypted at the wrong keystream position — breaking the session.
        //
        // By deferring the advance until after a successful parse we ensure the offset is only
        // committed when we have confirmed the payload was valid Demon data.
        let decrypted = self
            .registry
            .decrypt_from_agent_without_advancing(envelope.header.agent_id, remaining)
            .await
            .map_err(|e| lift_crypto_encoding_error(envelope.header.agent_id, e))?;
        let packages = parse_callback_packages(command_id, request_id, &decrypted)?;

        // Parse succeeded: advance the offset now that we know the payload was genuine.
        self.registry.advance_ctr_for_agent(envelope.header.agent_id, remaining.len()).await?;

        Ok(ParsedDemonPacket::Callback { header: envelope.header, packages })
    }
}

/// Build the encrypted acknowledgement body returned after a Demon init request.
pub async fn build_init_ack(
    registry: &crate::AgentRegistry,
    agent_id: u32,
) -> Result<Vec<u8>, DemonParserError> {
    let payload = agent_id.to_le_bytes();
    registry
        .encrypt_for_agent(agent_id, &payload)
        .await
        .map_err(|e| lift_crypto_encoding_error(agent_id, e))
}

/// Build the encrypted acknowledgement body returned for a reconnect probe.
///
/// # Protocol design intent — reconnect ACK is **not counter-consuming**
///
/// A reconnect probe (`DEMON_INIT` with an empty payload) carries no encrypted data, so the
/// agent does not advance its CTR block counter when sending it.  The reconnect ACK response
/// is the one piece of traffic where server and agent diverge from the usual rule "every
/// encrypted message advances both counters by `ctr_blocks_for_len(len)` blocks":
///
/// - **Server side**: the ACK is encrypted at the *current* stored CTR offset, and that
///   offset is **not advanced** afterwards (hence `encrypt_for_agent_without_advancing`).
/// - **Agent side**: the agent must treat the reconnect ACK as a synchronisation marker and
///   also **not advance** its local counter after receiving it.
///
/// The result is that after a reconnect handshake both parties remain at the same offset
/// they held before the reconnect, and the very next agent callback/response pair continues
/// from that position without any skipped or replayed keystream blocks.
///
/// If an agent implementation incorrectly advances its counter by one block after receiving
/// the reconnect ACK (mirroring the init-ACK handling), its next outbound message will be
/// encrypted at `offset + 1` while the server will attempt to decrypt it at `offset`,
/// causing a permanent session desync.  The end-to-end test
/// `reconnect_then_subsequent_callback_remains_synchronised` in
/// `teamserver/tests/mock_demon_agent_checkin.rs` exercises this contract explicitly.
pub async fn build_reconnect_ack(
    registry: &crate::AgentRegistry,
    agent_id: u32,
) -> Result<Vec<u8>, DemonParserError> {
    let payload = agent_id.to_le_bytes();
    registry
        .encrypt_for_agent_without_advancing(agent_id, &payload)
        .await
        .map_err(|e| lift_crypto_encoding_error(agent_id, e))
}

/// Lift a [`TeamserverError::InvalidPersistedValue`] for AES key/IV fields into the
/// more specific [`DemonParserError::InvalidStoredCryptoEncoding`] variant, preserving
/// the originating agent identifier.  All other errors pass through as
/// [`DemonParserError::Registry`].
fn lift_crypto_encoding_error(agent_id: u32, error: TeamserverError) -> DemonParserError {
    match error {
        TeamserverError::InvalidPersistedValue { field, message }
            if field == "aes_key" || field == "aes_iv" =>
        {
            DemonParserError::InvalidStoredCryptoEncoding { agent_id, field, message }
        }
        other => DemonParserError::Registry(other),
    }
}

fn parse_callback_packages(
    first_command_id: u32,
    first_request_id: u32,
    decrypted: &[u8],
) -> Result<Vec<DemonCallbackPackage>, DemonParserError> {
    let mut offset = 0_usize;
    let first_payload =
        read_length_prefixed_bytes_be(decrypted, &mut offset, "first callback payload")?;
    let mut packages = vec![DemonCallbackPackage {
        command_id: first_command_id,
        request_id: first_request_id,
        payload: first_payload,
    }];

    while offset < decrypted.len() {
        let command_id = read_u32_be(decrypted, &mut offset, "callback command id")?;
        let request_id = read_u32_be(decrypted, &mut offset, "callback request id")?;
        let payload = read_length_prefixed_bytes_be(decrypted, &mut offset, "callback payload")?;
        packages.push(DemonCallbackPackage { command_id, request_id, payload });
    }

    Ok(packages)
}

fn parse_init_agent(
    agent_id: u32,
    payload: &[u8],
    external_ip: &str,
    now: OffsetDateTime,
) -> Result<AgentRecord, DemonParserError> {
    let mut offset = 0_usize;
    let key = read_fixed::<AGENT_KEY_LENGTH>(payload, &mut offset, "init AES key")?;
    let iv = read_fixed::<AGENT_IV_LENGTH>(payload, &mut offset, "init AES IV")?;
    let encrypted = &payload[offset..];

    if is_weak_aes_key(&key) {
        warn!(
            agent_id = format_args!("0x{agent_id:08X}"),
            "rejecting DEMON_INIT with degenerate AES key"
        );
        return Err(DemonParserError::InvalidInit("degenerate AES key is not allowed"));
    }

    if is_weak_aes_iv(&iv) {
        warn!(
            agent_id = format_args!("0x{agent_id:08X}"),
            "rejecting DEMON_INIT with degenerate AES IV"
        );
        return Err(DemonParserError::InvalidInit("degenerate AES IV is not allowed"));
    }

    let decrypted = Cow::Owned(decrypt_agent_data(&key, &iv, encrypted)?);

    let mut decrypted_offset = 0_usize;
    let parsed_agent_id = read_u32_be(&decrypted, &mut decrypted_offset, "init agent id")?;
    if parsed_agent_id != agent_id {
        return Err(DemonParserError::InvalidInit("decrypted agent id does not match header"));
    }

    let hostname = read_length_prefixed_string_be(&decrypted, &mut decrypted_offset, "hostname")?;
    let username = read_length_prefixed_string_be(&decrypted, &mut decrypted_offset, "username")?;
    let domain_name =
        read_length_prefixed_string_be(&decrypted, &mut decrypted_offset, "domain name")?;
    let internal_ip =
        read_length_prefixed_string_be(&decrypted, &mut decrypted_offset, "internal ip")?;
    let process_path =
        read_length_prefixed_utf16_be(&decrypted, &mut decrypted_offset, "process path")?;
    let process_pid = read_u32_be(&decrypted, &mut decrypted_offset, "process pid")?;
    let process_tid = read_u32_be(&decrypted, &mut decrypted_offset, "process tid")?;
    let process_ppid = read_u32_be(&decrypted, &mut decrypted_offset, "process ppid")?;
    let process_arch = read_u32_be(&decrypted, &mut decrypted_offset, "process arch")?;
    let elevated = read_u32_be(&decrypted, &mut decrypted_offset, "elevated")? != 0;
    let base_address = read_u64_be(&decrypted, &mut decrypted_offset, "base address")?;
    let os_major = read_u32_be(&decrypted, &mut decrypted_offset, "os major")?;
    let os_minor = read_u32_be(&decrypted, &mut decrypted_offset, "os minor")?;
    let os_product_type = read_u32_be(&decrypted, &mut decrypted_offset, "os product type")?;
    let os_service_pack = read_u32_be(&decrypted, &mut decrypted_offset, "os service pack")?;
    let os_build = read_u32_be(&decrypted, &mut decrypted_offset, "os build")?;
    let os_arch = read_u32_be(&decrypted, &mut decrypted_offset, "os arch")?;
    let sleep_delay = read_u32_be(&decrypted, &mut decrypted_offset, "sleep delay")?;
    let sleep_jitter = read_u32_be(&decrypted, &mut decrypted_offset, "sleep jitter")?;
    let kill_date = read_u64_be(&decrypted, &mut decrypted_offset, "kill date")?;
    let working_hours =
        i32::from_be_bytes(read_fixed::<4>(&decrypted, &mut decrypted_offset, "working hours")?);
    let timestamp =
        now.format(&Rfc3339).map_err(|_| DemonParserError::InvalidInit("invalid timestamp"))?;
    let kill_date = parse_kill_date(kill_date)?;

    Ok(AgentRecord {
        agent_id: parsed_agent_id,
        active: true,
        reason: String::new(),
        note: String::new(),
        encryption: AgentEncryptionInfo {
            aes_key: Zeroizing::new(key.to_vec()),
            aes_iv: Zeroizing::new(iv.to_vec()),
        },
        hostname,
        username,
        domain_name,
        external_ip: external_ip.to_owned(),
        internal_ip,
        process_name: basename(&process_path),
        process_path,
        base_address,
        process_pid,
        process_tid,
        process_ppid,
        process_arch: process_arch_label(process_arch).to_owned(),
        elevated,
        os_version: windows_version_label(
            os_major,
            os_minor,
            os_product_type,
            os_service_pack,
            os_build,
        ),
        os_build,
        os_arch: windows_arch_label(os_arch).to_owned(),
        sleep_delay,
        sleep_jitter,
        kill_date,
        working_hours: (working_hours != 0).then_some(working_hours),
        first_call_in: timestamp.clone(),
        last_call_in: timestamp,
    })
}

fn parse_kill_date(kill_date: u64) -> Result<Option<i64>, DemonParserError> {
    if kill_date == 0 {
        return Ok(None);
    }

    let parsed = i64::try_from(kill_date)
        .map_err(|_| DemonParserError::InvalidInit("kill date exceeds i64 range"))?;
    Ok(Some(parsed))
}

fn read_fixed<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
    context: &'static str,
) -> Result<[u8; N], DemonParserError> {
    let remaining = bytes.len().saturating_sub(*offset);
    if remaining < N {
        return Err(
            DemonProtocolError::BufferTooShort { context, expected: N, actual: remaining }.into()
        );
    }

    let value: [u8; N] = bytes[*offset..*offset + N].try_into().map_err(|_| {
        DemonProtocolError::BufferTooShort { context, expected: N, actual: remaining }
    })?;
    *offset += N;
    Ok(value)
}

fn read_u32_be(
    bytes: &[u8],
    offset: &mut usize,
    context: &'static str,
) -> Result<u32, DemonParserError> {
    Ok(u32::from_be_bytes(read_fixed::<4>(bytes, offset, context)?))
}

fn read_u64_be(
    bytes: &[u8],
    offset: &mut usize,
    context: &'static str,
) -> Result<u64, DemonParserError> {
    Ok(u64::from_be_bytes(read_fixed::<8>(bytes, offset, context)?))
}

fn read_length_prefixed_bytes_be(
    bytes: &[u8],
    offset: &mut usize,
    context: &'static str,
) -> Result<Vec<u8>, DemonParserError> {
    let len = usize::try_from(read_u32_be(bytes, offset, context)?)
        .map_err(|_| DemonParserError::InvalidInit("length conversion overflow"))?;
    let remaining = bytes.len().saturating_sub(*offset);
    if remaining < len {
        return Err(DemonProtocolError::BufferTooShort {
            context,
            expected: len,
            actual: remaining,
        }
        .into());
    }

    let value = bytes[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(value)
}

fn read_length_prefixed_string_be(
    bytes: &[u8],
    offset: &mut usize,
    context: &'static str,
) -> Result<String, DemonParserError> {
    let raw = read_length_prefixed_bytes_be(bytes, offset, context)?;
    Ok(String::from_utf8_lossy(&raw).trim_end_matches('\0').to_owned())
}

fn read_length_prefixed_utf16_be(
    bytes: &[u8],
    offset: &mut usize,
    context: &'static str,
) -> Result<String, DemonParserError> {
    let raw = read_length_prefixed_bytes_be(bytes, offset, context)?;
    if raw.len() % 2 != 0 {
        return Err(DemonParserError::InvalidInit("utf16 field length must be even"));
    }

    let words: Vec<u16> =
        raw.chunks_exact(2).map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]])).collect();
    Ok(String::from_utf16_lossy(&words).trim_end_matches('\0').to_owned())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use red_cell_common::crypto::{
        AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len, decrypt_agent_data_at_offset,
        encrypt_agent_data, encrypt_agent_data_at_offset,
    };
    use red_cell_common::demon::{
        DEMON_MAGIC_VALUE, DemonCommand, DemonEnvelope, DemonProtocolError,
    };
    use red_cell_common::{AgentEncryptionInfo, AgentRecord};
    use time::macros::datetime;
    use uuid::Uuid;
    use zeroize::Zeroizing;

    use super::{
        DemonCallbackPackage, DemonPacketParser, DemonParserError, ParsedDemonPacket,
        build_init_ack, build_reconnect_ack,
    };
    use crate::{AgentRegistry, Database};

    /// Generate a non-degenerate test key from a seed byte.
    /// Each byte differs, so no repeating-pattern check will flag it.
    fn test_key(seed: u8) -> [u8; AGENT_KEY_LENGTH] {
        core::array::from_fn(|i| seed.wrapping_add(i as u8))
    }

    /// Generate a non-degenerate test IV from a seed byte.
    fn test_iv(seed: u8) -> [u8; AGENT_IV_LENGTH] {
        core::array::from_fn(|i| seed.wrapping_add(i as u8))
    }

    fn u32_be(value: u32) -> [u8; 4] {
        value.to_be_bytes()
    }

    fn u64_be(value: u64) -> [u8; 8] {
        value.to_be_bytes()
    }

    fn add_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(&u32_be(u32::try_from(bytes.len()).expect("test data fits in u32")));
        buf.extend_from_slice(bytes);
    }

    fn add_str(buf: &mut Vec<u8>, value: &str) {
        add_bytes(buf, value.as_bytes());
    }

    fn add_utf16(buf: &mut Vec<u8>, value: &str) {
        let utf16: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
        add_bytes(buf, &utf16);
    }

    async fn test_registry() -> AgentRegistry {
        let database = Database::connect_in_memory().await.expect("in-memory db should work");
        AgentRegistry::new(database)
    }

    fn temp_db_path() -> PathBuf {
        std::env::temp_dir().join(format!("red-cell-demon-parser-{}.sqlite", Uuid::new_v4()))
    }

    fn build_init_metadata(agent_id: u32) -> Vec<u8> {
        build_init_metadata_with_kill_date_and_working_hours(agent_id, 1_893_456_000, 0b101010)
    }

    fn build_init_metadata_with_working_hours(agent_id: u32, working_hours: i32) -> Vec<u8> {
        build_init_metadata_with_kill_date_and_working_hours(agent_id, 1_893_456_000, working_hours)
    }

    fn build_init_metadata_with_kill_date_and_working_hours(
        agent_id: u32,
        kill_date: u64,
        working_hours: i32,
    ) -> Vec<u8> {
        let mut metadata = Vec::new();
        metadata.extend_from_slice(&u32_be(agent_id));
        add_str(&mut metadata, "wkstn-01");
        add_str(&mut metadata, "operator");
        add_str(&mut metadata, "REDCELL");
        add_str(&mut metadata, "10.0.0.25");
        add_utf16(&mut metadata, "C:\\Windows\\explorer.exe");
        metadata.extend_from_slice(&u32_be(1337));
        metadata.extend_from_slice(&u32_be(1338));
        metadata.extend_from_slice(&u32_be(512));
        metadata.extend_from_slice(&u32_be(2));
        metadata.extend_from_slice(&u32_be(1));
        metadata.extend_from_slice(&u64_be(0x401000));
        metadata.extend_from_slice(&u32_be(10));
        metadata.extend_from_slice(&u32_be(0));
        metadata.extend_from_slice(&u32_be(1));
        metadata.extend_from_slice(&u32_be(0));
        metadata.extend_from_slice(&u32_be(22000));
        metadata.extend_from_slice(&u32_be(9));
        metadata.extend_from_slice(&u32_be(15));
        metadata.extend_from_slice(&u32_be(20));
        metadata.extend_from_slice(&u64_be(kill_date));
        metadata.extend_from_slice(&working_hours.to_be_bytes());
        metadata
    }

    fn build_init_packet(
        agent_id: u32,
        key: [u8; AGENT_KEY_LENGTH],
        iv: [u8; AGENT_IV_LENGTH],
    ) -> Vec<u8> {
        build_init_packet_with_working_hours(agent_id, key, iv, 0b101010)
    }

    fn build_init_packet_with_working_hours(
        agent_id: u32,
        key: [u8; AGENT_KEY_LENGTH],
        iv: [u8; AGENT_IV_LENGTH],
        working_hours: i32,
    ) -> Vec<u8> {
        let metadata = build_init_metadata_with_working_hours(agent_id, working_hours);
        let encrypted =
            encrypt_agent_data(&key, &iv, &metadata).expect("metadata encryption should succeed");
        let mut payload = Vec::new();
        payload.extend_from_slice(&u32_be(u32::from(DemonCommand::DemonInit)));
        payload.extend_from_slice(&u32_be(7));
        payload.extend_from_slice(&key);
        payload.extend_from_slice(&iv);
        payload.extend_from_slice(&encrypted);

        DemonEnvelope::new(agent_id, payload).expect("init envelope should be valid").to_bytes()
    }

    fn build_init_packet_with_kill_date_and_working_hours(
        agent_id: u32,
        key: [u8; AGENT_KEY_LENGTH],
        iv: [u8; AGENT_IV_LENGTH],
        kill_date: u64,
        working_hours: i32,
    ) -> Vec<u8> {
        let metadata = build_init_metadata_with_kill_date_and_working_hours(
            agent_id,
            kill_date,
            working_hours,
        );
        let encrypted =
            encrypt_agent_data(&key, &iv, &metadata).expect("metadata encryption should succeed");
        let mut payload = Vec::new();
        payload.extend_from_slice(&u32_be(u32::from(DemonCommand::DemonInit)));
        payload.extend_from_slice(&u32_be(7));
        payload.extend_from_slice(&key);
        payload.extend_from_slice(&iv);
        payload.extend_from_slice(&encrypted);

        DemonEnvelope::new(agent_id, payload).expect("init envelope should be valid").to_bytes()
    }

    fn build_plaintext_zero_key_init_packet(agent_id: u32) -> Vec<u8> {
        let metadata = build_init_metadata(agent_id);
        let mut payload = Vec::new();
        payload.extend_from_slice(&u32_be(u32::from(DemonCommand::DemonInit)));
        payload.extend_from_slice(&u32_be(7));
        payload.extend_from_slice(&[0; AGENT_KEY_LENGTH]);
        payload.extend_from_slice(&[0; AGENT_IV_LENGTH]);
        payload.extend_from_slice(&metadata);

        DemonEnvelope::new(agent_id, payload).expect("init envelope should be valid").to_bytes()
    }

    fn build_plaintext_zero_iv_init_packet(agent_id: u32) -> Vec<u8> {
        let metadata = build_init_metadata(agent_id);
        let mut payload = Vec::new();
        payload.extend_from_slice(&u32_be(u32::from(DemonCommand::DemonInit)));
        payload.extend_from_slice(&u32_be(7));
        payload.extend_from_slice(&test_key(0xAB));
        payload.extend_from_slice(&[0; AGENT_IV_LENGTH]);
        payload.extend_from_slice(&metadata);

        DemonEnvelope::new(agent_id, payload).expect("init envelope should be valid").to_bytes()
    }

    /// Build a callback packet encrypted at the given CTR block offset,
    /// simulating the Demon agent's counter-advancing AES context.
    fn build_callback_packet(
        agent_id: u32,
        key: [u8; AGENT_KEY_LENGTH],
        iv: [u8; AGENT_IV_LENGTH],
        ctr_offset: u64,
    ) -> Vec<u8> {
        let mut decrypted = Vec::new();
        decrypted.extend_from_slice(&u32_be(3));
        decrypted.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        decrypted.extend_from_slice(&u32_be(u32::from(DemonCommand::CommandOutput)));
        decrypted.extend_from_slice(&u32_be(99));
        decrypted.extend_from_slice(&u32_be(5));
        decrypted.extend_from_slice(b"hello");

        let encrypted = encrypt_agent_data_at_offset(&key, &iv, ctr_offset, &decrypted)
            .expect("callback encryption should succeed");
        let mut payload = Vec::new();
        payload.extend_from_slice(&u32_be(u32::from(DemonCommand::CommandCheckin)));
        payload.extend_from_slice(&u32_be(42));
        payload.extend_from_slice(&encrypted);

        DemonEnvelope::new(agent_id, payload).expect("callback envelope should be valid").to_bytes()
    }

    #[tokio::test]
    async fn parse_registers_new_agent_from_demon_init() {
        let registry = test_registry().await;
        let parser = DemonPacketParser::new(registry.clone());
        let key = test_key(0x41);
        let iv = test_iv(0x24);
        let packet = build_init_packet(0x1234_5678, key, iv);

        let parsed = parser
            .parse_at(&packet, "203.0.113.10".to_owned(), datetime!(2026-03-09 19:30:00 UTC))
            .await
            .expect("init packet should parse");

        let ParsedDemonPacket::Init(init) = parsed else {
            panic!("expected init packet");
        };

        assert_eq!(init.header.magic, DEMON_MAGIC_VALUE);
        assert_eq!(init.request_id, 7);
        assert_eq!(init.agent.agent_id, 0x1234_5678);
        assert_eq!(init.agent.hostname, "wkstn-01");
        assert_eq!(init.agent.process_name, "explorer.exe");
        assert_eq!(init.agent.process_path, "C:\\Windows\\explorer.exe");
        assert_eq!(init.agent.os_version, "Windows 11");
        assert_eq!(init.agent.os_arch, "x64/AMD64");
        assert_eq!(init.agent.external_ip, "203.0.113.10");
        assert_eq!(init.agent.sleep_delay, 15);
        assert_eq!(init.agent.kill_date, Some(1_893_456_000));
        assert_eq!(init.agent.working_hours, Some(0b101010));
        assert_eq!(registry.get(0x1234_5678).await, Some(init.agent));

        assert_eq!(registry.ctr_offset(0x1234_5678).await.expect("offset should be set"), 0);
    }

    #[tokio::test]
    async fn parse_preserves_signed_working_hours_bitmask_from_demon_init() {
        let registry = test_registry().await;
        let parser = DemonPacketParser::new(registry);
        let key = test_key(0x41);
        let iv = test_iv(0x24);
        let working_hours = i32::MIN | 0x2A;
        let packet = build_init_packet_with_working_hours(0x1234_5678, key, iv, working_hours);

        let parsed = parser
            .parse_at(&packet, "203.0.113.10".to_owned(), datetime!(2026-03-09 19:30:00 UTC))
            .await
            .expect("init packet should parse");

        let ParsedDemonPacket::Init(init) = parsed else {
            panic!("expected init packet");
        };

        assert_eq!(init.agent.working_hours, Some(working_hours));
    }

    #[tokio::test]
    async fn parse_stores_no_kill_date_when_init_kill_date_is_zero() {
        let registry = test_registry().await;
        let parser = DemonPacketParser::new(registry);
        let key = test_key(0x51);
        let iv = test_iv(0x34);
        let packet =
            build_init_packet_with_kill_date_and_working_hours(0x1234_5678, key, iv, 0, 0b101010);

        let parsed = parser
            .parse_at(&packet, "203.0.113.10".to_owned(), datetime!(2026-03-09 19:30:00 UTC))
            .await
            .expect("init packet should parse");

        let ParsedDemonPacket::Init(init) = parsed else {
            panic!("expected init packet");
        };

        assert_eq!(init.agent.kill_date, None);
    }

    #[tokio::test]
    async fn parse_for_listener_persists_accepting_listener_name() {
        let registry = test_registry().await;
        let parser = DemonPacketParser::new(registry.clone());
        let packet = build_init_packet(0x2233_4455, test_key(0x31), test_iv(0x42));

        parser
            .parse_for_listener(&packet, "203.0.113.20", "http-main")
            .await
            .expect("init packet should parse");

        assert_eq!(registry.listener_name(0x2233_4455).await.as_deref(), Some("http-main"));
    }

    #[tokio::test]
    async fn parse_decrypts_callback_packages_for_existing_agent() {
        let registry = test_registry().await;
        let parser = DemonPacketParser::new(registry.clone());
        let key = test_key(0x41);
        let iv = test_iv(0x24);
        let init_packet = build_init_packet(0x0102_0304, key, iv);
        parser
            .parse_at(&init_packet, "198.51.100.5".to_owned(), datetime!(2026-03-09 19:31:00 UTC))
            .await
            .expect("init should succeed");

        let _ack = build_init_ack(&registry, 0x0102_0304).await.expect("ack should build");
        let callback_packet = build_callback_packet(
            0x0102_0304,
            key,
            iv,
            ctr_blocks_for_len(std::mem::size_of::<u32>()),
        );
        let parsed = parser
            .parse_at(
                &callback_packet,
                "198.51.100.5".to_owned(),
                datetime!(2026-03-09 19:32:00 UTC),
            )
            .await
            .expect("callback should parse");

        let ParsedDemonPacket::Callback { header, packages } = parsed else {
            panic!("expected callback packet");
        };

        assert_eq!(header.agent_id, 0x0102_0304);
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].command_id, u32::from(DemonCommand::CommandCheckin));
        assert_eq!(packages[0].request_id, 42);
        assert_eq!(packages[0].payload, vec![0xaa, 0xbb, 0xcc]);
        assert_eq!(packages[1].command_id, u32::from(DemonCommand::CommandOutput));
        assert_eq!(packages[1].request_id, 99);
        assert_eq!(packages[1].payload, b"hello");
    }

    #[tokio::test]
    async fn parse_returns_reconnect_for_existing_agent_init_probe() {
        let registry = test_registry().await;
        let parser = DemonPacketParser::new(registry.clone());
        let key = test_key(0x41);
        let iv = test_iv(0x24);
        let init_packet = build_init_packet(0x1111_2222, key, iv);
        parser
            .parse_at(&init_packet, "192.0.2.10".to_owned(), datetime!(2026-03-09 19:33:00 UTC))
            .await
            .expect("init should succeed");

        let payload =
            [u32_be(u32::from(DemonCommand::DemonInit)).as_slice(), u32_be(123).as_slice()]
                .concat();
        let reconnect = DemonEnvelope::new(0x1111_2222, payload)
            .expect("reconnect envelope should be valid")
            .to_bytes();

        let parsed = parser
            .parse_at(&reconnect, "192.0.2.10".to_owned(), datetime!(2026-03-09 19:34:00 UTC))
            .await
            .expect("reconnect should parse");

        assert_eq!(
            parsed,
            ParsedDemonPacket::Reconnect {
                header: red_cell_common::demon::DemonHeader {
                    size: 16,
                    magic: DEMON_MAGIC_VALUE,
                    agent_id: 0x1111_2222,
                },
                request_id: 123,
            }
        );
    }

    #[tokio::test]
    async fn parse_rejects_duplicate_full_init_without_mutating_registered_agent() {
        let registry = test_registry().await;
        let parser = DemonPacketParser::new(registry.clone());
        let agent_id = 0x1111_2222;
        let first_key = test_key(0x41);
        let first_iv = test_iv(0x24);
        let first_packet = build_init_packet(agent_id, first_key, first_iv);
        parser
            .parse_for_listener(&first_packet, "192.0.2.10", "http-main")
            .await
            .expect("initial init should succeed");

        let stored_before = registry.get(agent_id).await.expect("agent should be registered");
        let listener_before =
            registry.listener_name(agent_id).await.expect("listener should exist");
        let ctr_before = registry.ctr_offset(agent_id).await.expect("ctr offset should exist");

        let duplicate_packet = build_init_packet(agent_id, test_key(0x99), test_iv(0x55));
        let error = parser
            .parse_for_listener(&duplicate_packet, "198.51.100.99", "smb-secondary")
            .await
            .expect_err("duplicate full init must be rejected");

        assert!(matches!(
            error,
            DemonParserError::InvalidInit("agent is already registered; reconnect probe required")
        ));
        assert_eq!(registry.get(agent_id).await, Some(stored_before));
        assert_eq!(
            registry.listener_name(agent_id).await.as_deref(),
            Some(listener_before.as_str())
        );
        assert_eq!(
            registry.ctr_offset(agent_id).await.expect("ctr offset should exist"),
            ctr_before
        );
    }

    #[tokio::test]
    async fn build_init_ack_encrypts_agent_identifier() {
        let registry = test_registry().await;
        let key = test_key(0x33);
        let iv = test_iv(0x44);
        let agent_id: u32 = 0xAABB_CCDD;

        let init_packet = build_init_packet(agent_id, key, iv);
        let parser = DemonPacketParser::new(registry.clone());
        parser
            .parse_at(&init_packet, "10.0.0.1".to_owned(), datetime!(2026-03-09 19:40:00 UTC))
            .await
            .expect("init should succeed");

        let ack = build_init_ack(&registry, agent_id).await.expect("ack should build");
        let decrypted =
            decrypt_agent_data_at_offset(&key, &iv, 0, &ack).expect("ack should decrypt");
        assert_eq!(decrypted, agent_id.to_le_bytes());
        assert_eq!(registry.ctr_offset(agent_id).await.expect("offset"), 1);
    }

    #[tokio::test]
    async fn build_init_ack_after_registry_reload_uses_persisted_crypto_material() {
        let database =
            Database::connect(temp_db_path()).await.expect("temp database should initialize");
        let registry = AgentRegistry::new(database.clone());
        let parser = DemonPacketParser::new(registry.clone());
        let key = test_key(0x55);
        let iv = test_iv(0x66);
        let agent_id: u32 = 0x1122_3344;

        let init_packet = build_init_packet(agent_id, key, iv);
        parser
            .parse_at(&init_packet, "10.0.0.3".to_owned(), datetime!(2026-03-09 19:45:00 UTC))
            .await
            .expect("init should succeed");

        let _first_ack = build_init_ack(&registry, agent_id).await.expect("ack should build");

        let reloaded = AgentRegistry::load(database).await.expect("registry should reload");

        let ack = build_init_ack(&reloaded, agent_id).await.expect("reconnect ack should build");
        let decrypted =
            decrypt_agent_data_at_offset(&key, &iv, 1, &ack).expect("ack should decrypt");
        assert_eq!(decrypted, agent_id.to_le_bytes());
    }

    #[tokio::test]
    async fn callback_after_registry_reload_uses_persisted_crypto_material() {
        let database =
            Database::connect(temp_db_path()).await.expect("temp database should initialize");
        let registry = AgentRegistry::new(database.clone());
        let parser = DemonPacketParser::new(registry);
        let key = test_key(0x57);
        let iv = test_iv(0x68);
        let agent_id: u32 = 0x2233_4455;

        let init_packet = build_init_packet(agent_id, key, iv);
        parser
            .parse_at(&init_packet, "10.0.0.5".to_owned(), datetime!(2026-03-09 19:47:00 UTC))
            .await
            .expect("init should succeed");

        let reloaded = AgentRegistry::load(database).await.expect("registry should reload");
        let parser = DemonPacketParser::new(reloaded);
        let callback_packet = build_callback_packet(agent_id, key, iv, 0);

        let parsed = parser
            .parse_at(&callback_packet, "10.0.0.5".to_owned(), datetime!(2026-03-09 19:48:00 UTC))
            .await
            .expect("callback should parse after reload");

        let ParsedDemonPacket::Callback { header, packages } = parsed else {
            panic!("expected callback packet");
        };

        assert_eq!(header.agent_id, agent_id);
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].command_id, u32::from(DemonCommand::CommandCheckin));
        assert_eq!(packages[0].request_id, 42);
        assert_eq!(packages[0].payload, vec![0xaa, 0xbb, 0xcc]);
        assert_eq!(packages[1].command_id, u32::from(DemonCommand::CommandOutput));
        assert_eq!(packages[1].request_id, 99);
        assert_eq!(packages[1].payload, b"hello");
    }

    /// Build a callback packet whose encrypted payload decrypts to bytes that will fail
    /// `parse_callback_packages` — simulating an adversary who sends a crafted packet with a
    /// valid header but garbage payload (CTR desync attack).
    fn build_garbage_callback_packet(
        agent_id: u32,
        key: [u8; AGENT_KEY_LENGTH],
        iv: [u8; AGENT_IV_LENGTH],
        ctr_offset: u64,
    ) -> Vec<u8> {
        // Encrypting a single byte: when decrypted, `read_length_prefixed_bytes_be` will attempt
        // to read a 4-byte u32 length prefix and fail with BufferTooShort.
        let garbage_plaintext = b"\xFF";
        let encrypted = encrypt_agent_data_at_offset(&key, &iv, ctr_offset, garbage_plaintext)
            .expect("garbage encryption should succeed");
        let mut payload = Vec::new();
        payload.extend_from_slice(&u32_be(u32::from(DemonCommand::CommandCheckin)));
        payload.extend_from_slice(&u32_be(42));
        payload.extend_from_slice(&encrypted);

        DemonEnvelope::new(agent_id, payload)
            .expect("garbage callback envelope should be valid")
            .to_bytes()
    }

    #[tokio::test]
    async fn garbage_callback_does_not_advance_ctr_offset() {
        // Reproduces the CTR desync attack: an adversary observes a valid agent_id from the
        // plaintext packet header, crafts a packet with the correct DEMON_MAGIC_VALUE and
        // agent_id, but encrypts garbage as the payload.  Before this fix, `decrypt_from_agent`
        // would advance the CTR offset unconditionally, permanently breaking the legitimate
        // agent's next callback.
        let registry = test_registry().await;
        let parser = DemonPacketParser::new(registry.clone());
        let agent_id = 0xDEAD_BEEF_u32;
        let key = test_key(0xAA);
        let iv = test_iv(0xBB);

        // Register the agent.
        let init_packet = build_init_packet(agent_id, key, iv);
        parser
            .parse_at(&init_packet, "203.0.113.50".to_owned(), datetime!(2026-03-15 10:00:00 UTC))
            .await
            .expect("init should succeed");

        // Advance the CTR offset by sending the init ack (simulates the server's normal response).
        let _ack = build_init_ack(&registry, agent_id).await.expect("ack should build");
        let offset_after_ack = registry.ctr_offset(agent_id).await.expect("offset should exist");
        assert_eq!(offset_after_ack, 1, "offset should be 1 after init ack");

        // Send a garbage callback packet at the current offset.
        let garbage_packet = build_garbage_callback_packet(agent_id, key, iv, offset_after_ack);
        let result = parser
            .parse_at(
                &garbage_packet,
                "203.0.113.50".to_owned(),
                datetime!(2026-03-15 10:00:01 UTC),
            )
            .await;
        assert!(result.is_err(), "garbage callback must be rejected, got: {result:?}");

        // The CTR offset must NOT have advanced — the desync attack must fail.
        let offset_after_garbage =
            registry.ctr_offset(agent_id).await.expect("offset should exist");
        assert_eq!(
            offset_after_garbage, offset_after_ack,
            "CTR offset must not advance on a failed callback parse"
        );

        // The real agent's next callback at the correct offset must still succeed.
        let legitimate_packet = build_callback_packet(agent_id, key, iv, offset_after_ack);
        let parsed = parser
            .parse_at(
                &legitimate_packet,
                "203.0.113.50".to_owned(),
                datetime!(2026-03-15 10:00:02 UTC),
            )
            .await
            .expect("legitimate callback must succeed after a rejected garbage packet");

        let ParsedDemonPacket::Callback { packages, .. } = parsed else {
            panic!("expected callback packet");
        };
        assert_eq!(packages[0].command_id, u32::from(DemonCommand::CommandCheckin));
        assert_eq!(packages[0].payload, vec![0xaa, 0xbb, 0xcc]);
    }

    #[tokio::test]
    async fn build_reconnect_ack_uses_current_ctr_offset_without_advancing_registry_state() {
        let registry = test_registry().await;
        let key = test_key(0x56);
        let iv = test_iv(0x67);
        let agent_id: u32 = 0x5566_7788;

        let init_packet = build_init_packet(agent_id, key, iv);
        let parser = DemonPacketParser::new(registry.clone());
        parser
            .parse_at(&init_packet, "10.0.0.4".to_owned(), datetime!(2026-03-09 19:46:00 UTC))
            .await
            .expect("init should succeed");

        let _first_ack = build_init_ack(&registry, agent_id).await.expect("ack should build");
        let offset_before_reconnect = registry.ctr_offset(agent_id).await.expect("offset");

        let ack = build_reconnect_ack(&registry, agent_id).await.expect("reconnect ack");
        let decrypted = decrypt_agent_data_at_offset(&key, &iv, offset_before_reconnect, &ack)
            .expect("ack should decrypt");

        assert_eq!(decrypted, agent_id.to_le_bytes());
        assert_eq!(registry.ctr_offset(agent_id).await.expect("offset"), offset_before_reconnect);
    }

    #[tokio::test]
    async fn successive_messages_advance_the_keystream() {
        let registry = test_registry().await;
        let parser = DemonPacketParser::new(registry.clone());
        let key = test_key(0x77);
        let iv = test_iv(0x88);
        let agent_id: u32 = 0xDEAD_BEEF;

        let init_packet = build_init_packet(agent_id, key, iv);
        parser
            .parse_at(&init_packet, "10.0.0.2".to_owned(), datetime!(2026-03-09 19:50:00 UTC))
            .await
            .expect("init should succeed");

        let msg = b"same-payload-bytes";
        let ct1 = registry.encrypt_for_agent(agent_id, msg).await.expect("enc1");
        let ct2 = registry.encrypt_for_agent(agent_id, msg).await.expect("enc2");

        assert_ne!(ct1, ct2, "registry should advance the stored CTR block offset");

        let pt1 = decrypt_agent_data_at_offset(&key, &iv, 0, &ct1).expect("dec1");
        let pt2 = decrypt_agent_data_at_offset(&key, &iv, ctr_blocks_for_len(msg.len()), &ct2)
            .expect("dec2");
        assert_eq!(pt1, msg);
        assert_eq!(pt2, msg);
    }

    #[tokio::test]
    async fn parse_rejects_init_with_mismatched_agent_id() {
        let registry = test_registry().await;
        let parser = DemonPacketParser::new(registry);
        let mut packet = build_init_packet(0x9999_AAAA, test_key(0x41), test_iv(0x24));
        let start = 12 + 8 + AGENT_KEY_LENGTH + AGENT_IV_LENGTH;
        packet[start..start + 4].copy_from_slice(&u32_be(0x1111_2222));

        let error = parser
            .parse_at(&packet, "203.0.113.1".to_owned(), datetime!(2026-03-09 19:35:00 UTC))
            .await
            .expect_err("mismatched init should fail");

        assert!(matches!(error, DemonParserError::Crypto(_) | DemonParserError::InvalidInit(_)));
    }

    #[tokio::test]
    async fn parse_rejects_plaintext_zero_key_init() {
        let registry = test_registry().await;
        let parser = DemonPacketParser::new(registry.clone());
        let packet = build_plaintext_zero_key_init_packet(0x1357_9BDF);

        let error = parser
            .parse_at(&packet, "203.0.113.77".to_owned(), datetime!(2026-03-10 10:15:00 UTC))
            .await
            .expect_err("zero-key init must be rejected");

        assert!(
            matches!(error, DemonParserError::InvalidInit("degenerate AES key is not allowed")),
            "expected degenerate-key init rejection, got: {error}"
        );
        assert!(registry.get(0x1357_9BDF).await.is_none(), "rejected init must not register");
    }

    #[tokio::test]
    async fn parse_rejects_plaintext_zero_iv_init() {
        let registry = test_registry().await;
        let parser = DemonPacketParser::new(registry.clone());
        let packet = build_plaintext_zero_iv_init_packet(0x1357_9BDF);

        let error = parser
            .parse_at(&packet, "203.0.113.77".to_owned(), datetime!(2026-03-10 10:15:00 UTC))
            .await
            .expect_err("zero-IV init must be rejected");

        assert!(
            matches!(error, DemonParserError::InvalidInit("degenerate AES IV is not allowed")),
            "expected degenerate-IV init rejection, got: {error}"
        );
        assert!(registry.get(0x1357_9BDF).await.is_none(), "rejected init must not register");
    }

    #[tokio::test]
    async fn parse_rejects_init_with_kill_date_exceeding_i64_range() {
        let registry = test_registry().await;
        let parser = DemonPacketParser::new(registry.clone());
        let agent_id = 0x1357_9BDF;
        let key = test_key(0x21);
        let iv = test_iv(0x31);
        let packet = build_init_packet_with_kill_date_and_working_hours(
            agent_id,
            key,
            iv,
            u64::MAX,
            0b101010,
        );

        let error = parser
            .parse_at(&packet, "203.0.113.77".to_owned(), datetime!(2026-03-10 10:15:00 UTC))
            .await
            .expect_err("overflowing kill date init must be rejected");

        assert!(matches!(error, DemonParserError::InvalidInit("kill date exceeds i64 range")));
        assert!(registry.get(agent_id).await.is_none(), "rejected init must not register");
    }

    #[tokio::test]
    async fn parse_rejects_init_when_registry_limit_is_reached() {
        let database =
            Database::connect(temp_db_path()).await.expect("temp database should initialize");
        let registry = AgentRegistry::with_max_registered_agents(database, 1);
        let parser = DemonPacketParser::new(registry.clone());

        parser
            .parse_at(
                &build_init_packet(0x1357_9BDF, test_key(0x21), test_iv(0x31)),
                "203.0.113.77".to_owned(),
                datetime!(2026-03-10 10:15:00 UTC),
            )
            .await
            .expect("first init should succeed");

        let error = parser
            .parse_at(
                &build_init_packet(0x2468_ACED, test_key(0x22), test_iv(0x32)),
                "203.0.113.78".to_owned(),
                datetime!(2026-03-10 10:16:00 UTC),
            )
            .await
            .expect_err("second init must be rejected");

        assert!(matches!(
            error,
            DemonParserError::Registry(crate::TeamserverError::MaxRegisteredAgentsExceeded {
                max_registered_agents: 1,
                registered: 1,
            })
        ));
        assert!(registry.get(0x2468_ACED).await.is_none(), "rejected init must not register");
    }

    #[tokio::test]
    async fn build_init_ack_rejects_zero_key_agent() {
        let registry = test_registry().await;
        let agent_id: u32 = 0x2468_ACED;
        let agent = AgentRecord {
            agent_id,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: AgentEncryptionInfo {
                aes_key: Zeroizing::new(vec![0; AGENT_KEY_LENGTH]),
                aes_iv: Zeroizing::new(vec![0; AGENT_IV_LENGTH]),
            },
            hostname: "wkstn-01".to_owned(),
            username: "operator".to_owned(),
            domain_name: "REDCELL".to_owned(),
            external_ip: "203.0.113.1".to_owned(),
            internal_ip: "10.0.0.10".to_owned(),
            process_name: "explorer.exe".to_owned(),
            process_path: "C:\\Windows\\explorer.exe".to_owned(),
            base_address: 0x401000,
            process_pid: 1337,
            process_tid: 1338,
            process_ppid: 512,
            process_arch: "x64".to_owned(),
            elevated: true,
            os_version: "Windows 11".to_owned(),
            os_build: 0,
            os_arch: "x64/AMD64".to_owned(),
            sleep_delay: 15,
            sleep_jitter: 20,
            kill_date: Some(1_893_456_000),
            working_hours: Some(0b101010),
            first_call_in: "2026-03-10T10:15:00Z".to_owned(),
            last_call_in: "2026-03-10T10:15:00Z".to_owned(),
        };
        registry.insert(agent).await.expect("agent insert should succeed");

        let error =
            build_init_ack(&registry, agent_id).await.expect_err("zero-key ack must be rejected");

        assert!(
            matches!(
                error,
                DemonParserError::Registry(crate::TeamserverError::InvalidAgentCrypto {
                    agent_id: rejected_agent_id,
                    ..
                }) if rejected_agent_id == agent_id
            ),
            "expected invalid zero-key agent crypto, got: {error}"
        );
    }

    /// Regression test for red-cell-c2-1a5: a header `agent_id = 0` must NOT
    /// bypass the identity mismatch check.
    #[tokio::test]
    async fn parse_rejects_init_with_zero_header_id_and_different_payload_id() {
        let registry = test_registry().await;
        let parser = DemonPacketParser::new(registry);
        let key = test_key(0x55);
        let iv = test_iv(0x66);
        let spoofed_id: u32 = 0xAAAA_BBBB;

        let metadata = build_init_metadata(spoofed_id);
        let encrypted =
            encrypt_agent_data(&key, &iv, &metadata).expect("metadata encryption should succeed");

        let mut payload = Vec::new();
        payload.extend_from_slice(&u32_be(u32::from(DemonCommand::DemonInit)));
        payload.extend_from_slice(&u32_be(1));
        payload.extend_from_slice(&key);
        payload.extend_from_slice(&iv);
        payload.extend_from_slice(&encrypted);

        let packet = DemonEnvelope::new(0, payload).expect("envelope should be valid").to_bytes();

        let error = parser
            .parse_at(&packet, "203.0.113.99".to_owned(), datetime!(2026-03-10 12:00:00 UTC))
            .await
            .expect_err("zero-header spoofed init must be rejected");

        assert!(
            matches!(error, DemonParserError::InvalidInit(_)),
            "expected InvalidInit error, got: {error}"
        );
    }

    /// Regression test for red-cell-c2-4rsi: a DEMON_INIT where both the
    /// transport header `agent_id` *and* the encrypted metadata `agent_id` are
    /// zero must be rejected.  Previously the header/payload mismatch check
    /// passed (both equal) and the zero-id agent was registered.
    #[tokio::test]
    async fn parse_rejects_init_with_zero_agent_id_in_both_header_and_payload() {
        let registry = test_registry().await;
        let parser = DemonPacketParser::new(registry);
        let key = test_key(0x55);
        let iv = test_iv(0x66);

        // Build a fully well-formed init packet with agent_id=0 everywhere.
        let packet = build_init_packet(0, key, iv);

        let error = parser
            .parse_at(&packet, "203.0.113.99".to_owned(), datetime!(2026-03-16 10:00:00 UTC))
            .await
            .expect_err("zero agent_id init must be rejected");

        assert!(
            matches!(error, DemonParserError::InvalidInit(_)),
            "expected InvalidInit error, got: {error}"
        );
    }

    // ── parse_callback_packages ──────────────────────────────────────────────

    /// Build the raw decrypted buffer expected by `parse_callback_packages`.
    ///
    /// The first entry in `packages` supplies the outer `(command_id, request_id)` returned
    /// alongside the buffer; the remainder are inlined as additional `(cmd, req, len-prefixed
    /// payload)` tuples that exercise the multi-package `while` loop.
    fn build_raw_callback_decrypted(packages: &[(u32, u32, &[u8])]) -> (u32, u32, Vec<u8>) {
        assert!(!packages.is_empty(), "must supply at least one package");
        let (first_cmd, first_req, first_payload) = packages[0];
        let mut buf = Vec::new();
        buf.extend_from_slice(&u32_be(u32::try_from(first_payload.len()).unwrap()));
        buf.extend_from_slice(first_payload);
        for &(cmd, req, payload) in &packages[1..] {
            buf.extend_from_slice(&u32_be(cmd));
            buf.extend_from_slice(&u32_be(req));
            buf.extend_from_slice(&u32_be(u32::try_from(payload.len()).unwrap()));
            buf.extend_from_slice(payload);
        }
        (first_cmd, first_req, buf)
    }

    #[test]
    fn parse_callback_packages_three_packages_all_present_in_order() {
        let (first_cmd, first_req, buf) = build_raw_callback_decrypted(&[
            (0x0000_0001, 0x1001, b"alpha"),
            (0x0000_0002, 0x2002, b"beta"),
            (0x0000_0003, 0x3003, b"gamma"),
        ]);

        let packages = super::parse_callback_packages(first_cmd, first_req, &buf)
            .expect("three-package payload should parse");

        assert_eq!(packages.len(), 3);
        assert_eq!(packages[0].command_id, 0x0000_0001);
        assert_eq!(packages[0].request_id, 0x1001);
        assert_eq!(packages[0].payload, b"alpha");
        assert_eq!(packages[1].command_id, 0x0000_0002);
        assert_eq!(packages[1].request_id, 0x2002);
        assert_eq!(packages[1].payload, b"beta");
        assert_eq!(packages[2].command_id, 0x0000_0003);
        assert_eq!(packages[2].request_id, 0x3003);
        assert_eq!(packages[2].payload, b"gamma");
    }

    #[test]
    fn parse_callback_packages_single_package_loop_not_entered() {
        let (first_cmd, first_req, buf) =
            build_raw_callback_decrypted(&[(0x0000_0042, 0xDEAD_BEEF, b"only")]);

        let packages = super::parse_callback_packages(first_cmd, first_req, &buf)
            .expect("single-package payload should parse");

        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].command_id, 0x0000_0042);
        assert_eq!(packages[0].request_id, 0xDEAD_BEEF);
        assert_eq!(packages[0].payload, b"only");
    }

    #[test]
    fn parse_callback_packages_empty_first_payload_followed_by_second() {
        let (first_cmd, first_req, buf) = build_raw_callback_decrypted(&[
            (0x0000_0010, 0x0001, b""),
            (0x0000_0020, 0x0002, b"data"),
        ]);

        let packages = super::parse_callback_packages(first_cmd, first_req, &buf)
            .expect("empty first payload should be valid");

        assert_eq!(packages.len(), 2);
        assert!(packages[0].payload.is_empty(), "first payload must be empty");
        assert_eq!(packages[1].payload, b"data");
    }

    #[test]
    fn parse_callback_packages_truncated_command_id_in_loop_returns_error() {
        // First package is well-formed; then only 2 bytes follow (truncated command_id field).
        let (first_cmd, first_req, mut buf) =
            build_raw_callback_decrypted(&[(0x0000_0001, 0x0001, b"abcd")]);
        buf.extend_from_slice(&[0xDE, 0xAD]); // 2 of the 4 bytes needed for command_id

        let error = super::parse_callback_packages(first_cmd, first_req, &buf)
            .expect_err("truncated command_id must be rejected");

        assert!(
            matches!(error, super::DemonParserError::Protocol(_)),
            "expected Protocol error, got: {error:?}"
        );
    }

    #[test]
    fn parse_callback_packages_truncated_payload_in_loop_returns_error() {
        // Second package's length field claims 10 bytes but the buffer only provides 2.
        let (first_cmd, first_req, mut buf) =
            build_raw_callback_decrypted(&[(0x0000_0001, 0x0001, b"abcd")]);
        buf.extend_from_slice(&u32_be(0x0000_0002)); // cmd_id
        buf.extend_from_slice(&u32_be(0x0002)); // req_id
        buf.extend_from_slice(&u32_be(10)); // claims 10-byte payload
        buf.extend_from_slice(&[0xAB, 0xCD]); // only 2 bytes available

        let error = super::parse_callback_packages(first_cmd, first_req, &buf)
            .expect_err("truncated payload must be rejected");

        assert!(
            matches!(error, super::DemonParserError::Protocol(_)),
            "expected Protocol error, got: {error:?}"
        );
    }

    // ── parse_callback_packages — first-callback truncation ─────────────────

    #[test]
    fn parse_callback_packages_empty_buffer_returns_error() {
        let buf: &[u8] = &[];
        let error =
            super::parse_callback_packages(1, 1, buf).expect_err("empty buffer must be rejected");

        assert!(
            matches!(error, super::DemonParserError::Protocol(_)),
            "expected Protocol error, got: {error:?}"
        );
    }

    #[test]
    fn parse_callback_packages_first_length_prefix_truncated_returns_error() {
        // Only 2 bytes — not enough for the 4-byte length prefix of the first payload.
        let buf: &[u8] = &[0x00, 0x05];
        let error = super::parse_callback_packages(1, 1, buf)
            .expect_err("truncated first length prefix must be rejected");

        assert!(
            matches!(error, super::DemonParserError::Protocol(_)),
            "expected Protocol error, got: {error:?}"
        );
    }

    #[test]
    fn parse_callback_packages_first_payload_exceeds_remaining_returns_error() {
        // Length prefix claims 100 bytes but buffer only has 4 (the prefix itself) + 2 data bytes.
        let mut buf = Vec::new();
        buf.extend_from_slice(&u32_be(100)); // first payload length = 100
        buf.extend_from_slice(&[0xAA, 0xBB]); // only 2 bytes available
        let error = super::parse_callback_packages(1, 1, &buf)
            .expect_err("oversized first payload length must be rejected");

        assert!(
            matches!(error, super::DemonParserError::Protocol(_)),
            "expected Protocol error, got: {error:?}"
        );
    }

    // ── DemonPacketParser COMMAND_CHECKIN truncated inner payload ────────────

    /// Build a COMMAND_CHECKIN callback packet whose encrypted inner payload,
    /// once decrypted, contains a length-prefix for the second sub-package that
    /// claims more bytes than the buffer actually holds.
    ///
    /// The outer envelope and AES encryption are well-formed so the packet
    /// passes decryption; the parse error must come from the inner loop.
    fn build_checkin_packet_with_truncated_inner_payload(
        agent_id: u32,
        key: [u8; AGENT_KEY_LENGTH],
        iv: [u8; AGENT_IV_LENGTH],
        ctr_offset: u64,
    ) -> Vec<u8> {
        // Inner decrypted bytes:
        //   [4] first_payload_len=3  [3] 0xaa 0xbb 0xcc   <- well-formed first package
        //   [4] second_cmd_id        [4] second_req_id
        //   [4] second_payload_len=100  [2] 0xAB 0xCD     <- truncated: only 2 bytes, not 100
        let mut decrypted = Vec::new();
        decrypted.extend_from_slice(&u32_be(3));
        decrypted.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        decrypted.extend_from_slice(&u32_be(u32::from(DemonCommand::CommandOutput)));
        decrypted.extend_from_slice(&u32_be(77));
        decrypted.extend_from_slice(&u32_be(100)); // claims 100-byte payload
        decrypted.extend_from_slice(&[0xAB, 0xCD]); // only 2 bytes present

        let encrypted = encrypt_agent_data_at_offset(&key, &iv, ctr_offset, &decrypted)
            .expect("truncated-inner encryption should succeed");

        let mut payload = Vec::new();
        payload.extend_from_slice(&u32_be(u32::from(DemonCommand::CommandCheckin)));
        payload.extend_from_slice(&u32_be(42));
        payload.extend_from_slice(&encrypted);

        DemonEnvelope::new(agent_id, payload)
            .expect("truncated-inner callback envelope should be valid")
            .to_bytes()
    }

    /// A COMMAND_CHECKIN packet that decrypts successfully but whose inner
    /// sub-package length-prefix exceeds the remaining buffer must return a
    /// `DemonParserError` and must never panic.
    #[tokio::test]
    async fn parse_checkin_with_truncated_inner_payload_returns_parse_error() {
        let registry = test_registry().await;
        let parser = DemonPacketParser::new(registry.clone());
        let key = test_key(0x41);
        let iv = test_iv(0x24);
        let agent_id: u32 = 0x0A0B_0C0D;

        // Register the agent.
        let init_packet = build_init_packet(agent_id, key, iv);
        parser
            .parse_at(&init_packet, "198.51.100.7".to_owned(), datetime!(2026-03-15 10:00:00 UTC))
            .await
            .expect("init should succeed");

        // Advance the registry CTR offset by building (and discarding) the init ACK,
        // exactly as the real server would.  The ACK encrypts one u32 (4 bytes =
        // 1 AES-CTR block), so the next agent-to-server packet is decrypted starting
        // at block offset 1.
        let _ack = build_init_ack(&registry, agent_id).await.expect("ack should build");
        let ctr_offset = ctr_blocks_for_len(std::mem::size_of::<u32>());

        let bad_packet =
            build_checkin_packet_with_truncated_inner_payload(agent_id, key, iv, ctr_offset);

        let result = parser
            .parse_at(&bad_packet, "198.51.100.7".to_owned(), datetime!(2026-03-15 10:00:01 UTC))
            .await;

        assert!(
            matches!(result, Err(DemonParserError::Protocol(_))),
            "truncated inner payload must return a Protocol error, got: {result:?}"
        );
    }

    // ── windows_version_label ────────────────────────────────────────────────

    const SERVER: u32 = 2; // any value != VER_NT_WORKSTATION (1)
    const WS: u32 = crate::dispatch::util::VER_NT_WORKSTATION;

    #[test]
    fn windows_version_label_win11() {
        assert_eq!(super::windows_version_label(10, 0, WS, 0, 22_000), "Windows 11");
        assert_eq!(super::windows_version_label(10, 0, WS, 0, 22_621), "Windows 11");
    }

    #[test]
    fn windows_version_label_win10() {
        assert_eq!(super::windows_version_label(10, 0, WS, 0, 19_045), "Windows 10");
    }

    #[test]
    fn windows_version_label_win2022() {
        assert_eq!(
            super::windows_version_label(10, 0, SERVER, 0, 20_348),
            "Windows 2022 Server 22H2"
        );
    }

    #[test]
    fn windows_version_label_win2019() {
        assert_eq!(super::windows_version_label(10, 0, SERVER, 0, 17_763), "Windows 2019 Server");
    }

    #[test]
    fn windows_version_label_win2016() {
        // Any server build that is not 20348 or 17763 maps to 2016
        assert_eq!(super::windows_version_label(10, 0, SERVER, 0, 14_393), "Windows 2016 Server");
    }

    #[test]
    fn windows_version_label_win81() {
        assert_eq!(super::windows_version_label(6, 3, WS, 0, 9_600), "Windows 8.1");
    }

    #[test]
    fn windows_version_label_win_server_2012_r2() {
        assert_eq!(super::windows_version_label(6, 3, SERVER, 0, 9_600), "Windows Server 2012 R2");
    }

    #[test]
    fn windows_version_label_win8() {
        assert_eq!(super::windows_version_label(6, 2, WS, 0, 9_200), "Windows 8");
    }

    #[test]
    fn windows_version_label_win_server_2012() {
        assert_eq!(super::windows_version_label(6, 2, SERVER, 0, 9_200), "Windows Server 2012");
    }

    #[test]
    fn windows_version_label_win7() {
        assert_eq!(super::windows_version_label(6, 1, WS, 0, 7_601), "Windows 7");
    }

    #[test]
    fn windows_version_label_win_server_2008_r2() {
        assert_eq!(super::windows_version_label(6, 1, SERVER, 0, 7_601), "Windows Server 2008 R2");
    }

    #[test]
    fn windows_version_label_unknown() {
        assert_eq!(super::windows_version_label(5, 1, WS, 0, 2_600), "Unknown");
    }

    #[test]
    fn windows_version_label_service_pack_suffix() {
        assert_eq!(super::windows_version_label(6, 1, WS, 1, 7_601), "Windows 7 Service Pack 1");
        assert_eq!(
            super::windows_version_label(6, 1, SERVER, 2, 7_601),
            "Windows Server 2008 R2 Service Pack 2"
        );
    }

    #[test]
    fn windows_version_label_no_service_pack_when_zero() {
        // service_pack == 0 must not append the suffix
        let label = super::windows_version_label(6, 1, WS, 0, 7_601);
        assert!(!label.contains("Service Pack"), "unexpected suffix: {label}");
    }

    // ── truncated DEMON_INIT error-path coverage ──────────────────────────────

    /// Build an init packet whose inner payload (key + IV + encrypted metadata)
    /// is truncated to `inner_payload_len` bytes.  The envelope size field is set
    /// consistently so that `DemonEnvelope::from_bytes` accepts the packet and
    /// the truncation is only visible to `parse_init_agent`.
    fn build_truncated_init_packet(
        agent_id: u32,
        key: [u8; AGENT_KEY_LENGTH],
        iv: [u8; AGENT_IV_LENGTH],
        inner_payload_len: usize,
    ) -> Vec<u8> {
        let metadata = build_init_metadata(agent_id);
        let encrypted =
            encrypt_agent_data(&key, &iv, &metadata).expect("metadata encryption should succeed");

        let mut full_inner =
            Vec::with_capacity(AGENT_KEY_LENGTH + AGENT_IV_LENGTH + encrypted.len());
        full_inner.extend_from_slice(&key);
        full_inner.extend_from_slice(&iv);
        full_inner.extend_from_slice(&encrypted);

        let truncated_inner = &full_inner[..inner_payload_len];

        let mut payload = Vec::new();
        payload.extend_from_slice(&u32_be(u32::from(DemonCommand::DemonInit)));
        payload.extend_from_slice(&u32_be(7));
        payload.extend_from_slice(truncated_inner);

        DemonEnvelope::new(agent_id, payload).expect("init envelope should be valid").to_bytes()
    }

    /// Truncating an otherwise valid DEMON_INIT payload at several offsets must
    /// always return a `BufferTooShort` protocol error and must never register
    /// the agent in the registry.
    #[tokio::test]
    async fn parse_returns_buffer_too_short_for_truncated_demon_init_payload() {
        let agent_id: u32 = 0xCAFE_BABE;
        let key = test_key(0x41);
        let iv = test_iv(0x24);

        // (label, inner_payload_len)
        // inner_payload_len is the number of bytes of (key ++ iv ++ encrypted_metadata)
        // to include in the envelope payload after the 8-byte command/request prefix.
        let truncation_cases: &[(&str, usize)] = &[
            // 16 of 32 key bytes present — read_fixed::<32> fails immediately.
            ("mid-key", AGENT_KEY_LENGTH / 2),
            // Full key + 8 of 16 IV bytes — read_fixed::<16> fails.
            ("mid-IV", AGENT_KEY_LENGTH + AGENT_IV_LENGTH / 2),
            // Full key + full IV + zero encrypted bytes — decrypt_agent_data returns
            // empty plaintext; the subsequent read_u32_be for the agent-id field fails.
            ("no-encrypted-bytes", AGENT_KEY_LENGTH + AGENT_IV_LENGTH),
            // Full key + full IV + 6 encrypted bytes — decrypts to 6 bytes of plaintext.
            // The agent-id (4 bytes) reads OK; the hostname length-prefix read (4 bytes)
            // fails because only 2 bytes remain.
            ("mid-hostname-length-prefix-in-decrypted", AGENT_KEY_LENGTH + AGENT_IV_LENGTH + 6),
        ];

        for &(label, inner_payload_len) in truncation_cases {
            let registry = test_registry().await;
            let parser = DemonPacketParser::new(registry.clone());
            let packet = build_truncated_init_packet(agent_id, key, iv, inner_payload_len);

            let result = parser
                .parse_at(&packet, "203.0.113.1".to_owned(), datetime!(2026-03-14 00:00:00 UTC))
                .await;

            assert!(
                matches!(
                    result,
                    Err(DemonParserError::Protocol(DemonProtocolError::BufferTooShort { .. }))
                ),
                "truncation '{label}' (inner_payload_len={inner_payload_len}) must return \
                 BufferTooShort, got: {result:?}"
            );
            assert!(
                registry.get(agent_id).await.is_none(),
                "truncation '{label}' must not register the agent in the registry"
            );
        }
    }

    // ---- DemonCallbackPackage::command() tests ----

    #[test]
    fn callback_package_command_returns_known_variant() {
        let pkg = DemonCallbackPackage {
            command_id: u32::from(DemonCommand::CommandGetJob),
            request_id: 1,
            payload: Vec::new(),
        };

        assert_eq!(pkg.command(), Ok(DemonCommand::CommandGetJob));
    }

    #[test]
    fn callback_package_command_returns_error_for_unknown_id() {
        let pkg =
            DemonCallbackPackage { command_id: 0xFFFF_FFFE, request_id: 0, payload: Vec::new() };

        let err = pkg.command().expect_err("unknown command ID must return Err");
        assert_eq!(
            err,
            DemonProtocolError::UnknownEnumValue { kind: "DemonCommand", value: 0xFFFF_FFFE }
        );
    }

    #[test]
    fn callback_package_command_returns_error_for_zero_id() {
        let pkg = DemonCallbackPackage { command_id: 0, request_id: 0, payload: Vec::new() };

        // Zero is not a valid DemonCommand discriminant — the lowest is CommandGetJob = 1.
        let err = pkg.command().expect_err("zero command ID must return Err");
        assert_eq!(err, DemonProtocolError::UnknownEnumValue { kind: "DemonCommand", value: 0 });
    }

    // ---- InvalidStoredCryptoEncoding coverage ----

    /// Build an [`AgentRecord`] whose encryption material has arbitrary raw bytes.
    /// Passing wrong-length vectors simulates what happens when persisted base64
    /// decodes to an unexpected number of bytes (i.e. database corruption).
    fn agent_with_raw_crypto(agent_id: u32, aes_key: Vec<u8>, aes_iv: Vec<u8>) -> AgentRecord {
        AgentRecord {
            agent_id,
            active: true,
            reason: String::new(),
            note: String::new(),
            encryption: AgentEncryptionInfo {
                aes_key: Zeroizing::new(aes_key),
                aes_iv: Zeroizing::new(aes_iv),
            },
            hostname: "wkstn-corrupt".to_owned(),
            username: "operator".to_owned(),
            domain_name: "REDCELL".to_owned(),
            external_ip: "198.51.100.1".to_owned(),
            internal_ip: "10.0.0.50".to_owned(),
            process_name: "svchost.exe".to_owned(),
            process_path: "C:\\Windows\\svchost.exe".to_owned(),
            base_address: 0x401000,
            process_pid: 2000,
            process_tid: 2001,
            process_ppid: 800,
            process_arch: "x64".to_owned(),
            elevated: false,
            os_version: "Windows 11".to_owned(),
            os_build: 22000,
            os_arch: "x64/AMD64".to_owned(),
            sleep_delay: 10,
            sleep_jitter: 5,
            kill_date: None,
            working_hours: None,
            first_call_in: "2026-03-10T12:00:00Z".to_owned(),
            last_call_in: "2026-03-10T12:00:00Z".to_owned(),
        }
    }

    #[tokio::test]
    async fn build_init_ack_returns_invalid_stored_crypto_for_bad_key() {
        let registry = test_registry().await;
        let agent_id: u32 = 0xBAD0_0001;
        let agent = agent_with_raw_crypto(agent_id, vec![0xAA; 5], vec![0xBB; AGENT_IV_LENGTH]);
        registry.insert(agent).await.expect("insert should succeed");

        let error =
            build_init_ack(&registry, agent_id).await.expect_err("bad key must be rejected");

        match &error {
            DemonParserError::InvalidStoredCryptoEncoding { agent_id: err_id, field, .. } => {
                assert_eq!(*err_id, agent_id);
                assert_eq!(*field, "aes_key");
            }
            other => panic!("expected InvalidStoredCryptoEncoding for aes_key, got: {other}"),
        }
    }

    #[tokio::test]
    async fn build_init_ack_returns_invalid_stored_crypto_for_bad_iv() {
        let registry = test_registry().await;
        let agent_id: u32 = 0xBAD0_0002;
        let agent = agent_with_raw_crypto(agent_id, vec![0xCC; AGENT_KEY_LENGTH], vec![0xDD; 3]);
        registry.insert(agent).await.expect("insert should succeed");

        let error = build_init_ack(&registry, agent_id).await.expect_err("bad IV must be rejected");

        match &error {
            DemonParserError::InvalidStoredCryptoEncoding { agent_id: err_id, field, .. } => {
                assert_eq!(*err_id, agent_id);
                assert_eq!(*field, "aes_iv");
            }
            other => panic!("expected InvalidStoredCryptoEncoding for aes_iv, got: {other}"),
        }
    }

    #[tokio::test]
    async fn build_reconnect_ack_returns_invalid_stored_crypto_for_bad_key() {
        let registry = test_registry().await;
        let agent_id: u32 = 0xBAD0_0003;
        let agent = agent_with_raw_crypto(agent_id, vec![0xEE; 10], vec![0xFF; AGENT_IV_LENGTH]);
        registry.insert(agent).await.expect("insert should succeed");

        let error =
            build_reconnect_ack(&registry, agent_id).await.expect_err("bad key must be rejected");

        match &error {
            DemonParserError::InvalidStoredCryptoEncoding { agent_id: err_id, field, .. } => {
                assert_eq!(*err_id, agent_id);
                assert_eq!(*field, "aes_key");
            }
            other => panic!("expected InvalidStoredCryptoEncoding for aes_key, got: {other}"),
        }
    }

    #[tokio::test]
    async fn callback_parse_returns_invalid_stored_crypto_for_bad_key() {
        let registry = test_registry().await;
        let agent_id: u32 = 0xBAD0_0004;
        // Insert agent with corrupted key directly — no init handshake needed.
        let agent = agent_with_raw_crypto(agent_id, vec![0xAA; 7], vec![0xBB; AGENT_IV_LENGTH]);
        registry.insert(agent).await.expect("insert should succeed");

        // Build a callback envelope — the ciphertext content does not matter because
        // the error fires before decryption, when the stored key fails length check.
        let dummy_key = test_key(0x55);
        let dummy_iv = test_iv(0x66);
        let callback_packet = build_callback_packet(agent_id, dummy_key, dummy_iv, 0);
        let parser = DemonPacketParser::new(registry);

        let error = parser
            .parse_at(&callback_packet, "10.0.0.99".to_owned(), datetime!(2026-03-10 14:01:00 UTC))
            .await
            .expect_err("callback with corrupted key must fail");

        match &error {
            DemonParserError::InvalidStoredCryptoEncoding { agent_id: err_id, field, .. } => {
                assert_eq!(*err_id, agent_id);
                assert_eq!(*field, "aes_key");
            }
            other => panic!("expected InvalidStoredCryptoEncoding for aes_key, got: {other}"),
        }
    }

    #[tokio::test]
    async fn callback_parse_returns_invalid_stored_crypto_for_bad_iv() {
        let registry = test_registry().await;
        let agent_id: u32 = 0xBAD0_0005;
        let agent = agent_with_raw_crypto(agent_id, vec![0xCC; AGENT_KEY_LENGTH], vec![0xDD; 2]);
        registry.insert(agent).await.expect("insert should succeed");

        let dummy_key = test_key(0x57);
        let dummy_iv = test_iv(0x68);
        let callback_packet = build_callback_packet(agent_id, dummy_key, dummy_iv, 0);
        let parser = DemonPacketParser::new(registry);

        let error = parser
            .parse_at(&callback_packet, "10.0.0.99".to_owned(), datetime!(2026-03-10 14:01:00 UTC))
            .await
            .expect_err("callback with corrupted IV must fail");

        match &error {
            DemonParserError::InvalidStoredCryptoEncoding { agent_id: err_id, field, .. } => {
                assert_eq!(*err_id, agent_id);
                assert_eq!(*field, "aes_iv");
            }
            other => panic!("expected InvalidStoredCryptoEncoding for aes_iv, got: {other}"),
        }
    }

    #[tokio::test]
    async fn callback_for_unregistered_agent_returns_not_found_without_creating_state() {
        let registry = test_registry().await;
        let parser = DemonPacketParser::new(registry.clone());
        let unregistered_id: u32 = 0xBADA_9E00;

        // Build a well-formed callback envelope targeting an agent ID the registry does not know.
        let dummy_key = test_key(0x41);
        let dummy_iv = test_iv(0x24);
        let callback_packet = build_callback_packet(unregistered_id, dummy_key, dummy_iv, 0);

        let error = parser
            .parse_at(
                &callback_packet,
                "198.51.100.99".to_owned(),
                datetime!(2026-03-15 12:00:00 UTC),
            )
            .await
            .expect_err("callback for unregistered agent must fail");

        assert!(
            matches!(
                error,
                DemonParserError::Registry(crate::TeamserverError::AgentNotFound {
                    agent_id: 0xBADA_9E00,
                })
            ),
            "expected AgentNotFound, got: {error}"
        );

        // No agent should have been inserted as a side effect.
        assert!(
            registry.get(unregistered_id).await.is_none(),
            "unregistered agent must not be inserted by a callback"
        );

        // No CTR state should have been created.
        assert!(
            registry.ctr_offset(unregistered_id).await.is_err(),
            "no CTR offset should exist for an unregistered agent"
        );
    }

    // ── Round-trip wire-format verification for build_init_ack / build_reconnect_ack ──

    #[tokio::test]
    async fn build_init_ack_wire_format_is_exactly_four_le_bytes_of_agent_id() {
        let registry = test_registry().await;
        let key = test_key(0xA1);
        let iv = test_iv(0xB2);
        let agent_id: u32 = 0x1234_5678;

        let init_packet = build_init_packet(agent_id, key, iv);
        let parser = DemonPacketParser::new(registry.clone());
        parser
            .parse_at(&init_packet, "10.0.0.10".to_owned(), datetime!(2026-03-19 10:00:00 UTC))
            .await
            .expect("init should succeed");

        let ack = build_init_ack(&registry, agent_id).await.expect("ack should build");

        // CTR mode preserves plaintext length — the ciphertext must be exactly 4 bytes
        // (the LE-encoded agent_id with no framing, padding, or length prefix).
        assert_eq!(
            ack.len(),
            4,
            "init ACK ciphertext must be exactly 4 bytes (agent_id LE), got {}",
            ack.len()
        );

        // Decrypt at offset 0 (first encryption after init) and verify exact field layout.
        let plaintext =
            decrypt_agent_data_at_offset(&key, &iv, 0, &ack).expect("ack should decrypt");
        assert_eq!(plaintext.len(), 4, "plaintext must be exactly 4 bytes");

        // Verify each byte position matches the LE encoding of agent_id.
        let expected = agent_id.to_le_bytes();
        assert_eq!(plaintext[0], expected[0], "byte 0 mismatch");
        assert_eq!(plaintext[1], expected[1], "byte 1 mismatch");
        assert_eq!(plaintext[2], expected[2], "byte 2 mismatch");
        assert_eq!(plaintext[3], expected[3], "byte 3 mismatch");
    }

    #[tokio::test]
    async fn build_init_ack_successive_calls_produce_different_ciphertext() {
        let registry = test_registry().await;
        let key = test_key(0xC3);
        let iv = test_iv(0xD4);
        let agent_id: u32 = 0xAAAA_BBBB;

        let init_packet = build_init_packet(agent_id, key, iv);
        let parser = DemonPacketParser::new(registry.clone());
        parser
            .parse_at(&init_packet, "10.0.0.11".to_owned(), datetime!(2026-03-19 10:01:00 UTC))
            .await
            .expect("init should succeed");

        let ack1 = build_init_ack(&registry, agent_id).await.expect("first ack");
        let ack2 = build_init_ack(&registry, agent_id).await.expect("second ack");

        // Both decrypt to the same plaintext (agent_id LE)…
        let pt1 = decrypt_agent_data_at_offset(&key, &iv, 0, &ack1).expect("decrypt ack1");
        let pt2 = decrypt_agent_data_at_offset(&key, &iv, 1, &ack2).expect("decrypt ack2");
        assert_eq!(pt1, agent_id.to_le_bytes());
        assert_eq!(pt2, agent_id.to_le_bytes());

        // …but the ciphertext differs because each call advances the CTR offset.
        assert_ne!(ack1, ack2, "successive ACKs must use different keystream blocks");
        assert_eq!(registry.ctr_offset(agent_id).await.expect("offset"), 2);
    }

    #[tokio::test]
    async fn build_reconnect_ack_wire_format_at_various_ctr_offsets() {
        let registry = test_registry().await;
        let key = test_key(0xE5);
        let iv = test_iv(0xF6);
        let agent_id: u32 = 0xCCDD_EEFF;

        let init_packet = build_init_packet(agent_id, key, iv);
        let parser = DemonPacketParser::new(registry.clone());
        parser
            .parse_at(&init_packet, "10.0.0.12".to_owned(), datetime!(2026-03-19 10:02:00 UTC))
            .await
            .expect("init should succeed");

        // Advance CTR offset to 3 by sending three init ACKs.
        for _ in 0..3 {
            let _ = build_init_ack(&registry, agent_id).await.expect("ack should build");
        }
        let offset = registry.ctr_offset(agent_id).await.expect("offset");
        assert_eq!(offset, 3);

        // Now send a reconnect ACK — it should encrypt at offset 3 without advancing.
        let reconnect_ack = build_reconnect_ack(&registry, agent_id).await.expect("reconnect ack");

        // Wire format: exactly 4 bytes of ciphertext, no framing.
        assert_eq!(
            reconnect_ack.len(),
            4,
            "reconnect ACK ciphertext must be exactly 4 bytes, got {}",
            reconnect_ack.len()
        );

        // Decrypt at the pre-reconnect offset.
        let plaintext = decrypt_agent_data_at_offset(&key, &iv, offset, &reconnect_ack)
            .expect("reconnect ack should decrypt at current offset");
        assert_eq!(plaintext, agent_id.to_le_bytes());

        // CTR offset must not have changed.
        assert_eq!(
            registry.ctr_offset(agent_id).await.expect("offset after reconnect"),
            offset,
            "reconnect ACK must not advance CTR offset"
        );

        // A second reconnect ACK at the same offset must produce identical ciphertext
        // (same keystream block, same plaintext → same output).
        let reconnect_ack2 =
            build_reconnect_ack(&registry, agent_id).await.expect("second reconnect ack");
        assert_eq!(
            reconnect_ack, reconnect_ack2,
            "repeated reconnect ACKs at the same offset must be byte-identical"
        );
    }

    #[tokio::test]
    async fn build_reconnect_ack_decrypting_at_wrong_offset_yields_garbage() {
        let registry = test_registry().await;
        let key = test_key(0x17);
        let iv = test_iv(0x28);
        let agent_id: u32 = 0x1111_2222;

        let init_packet = build_init_packet(agent_id, key, iv);
        let parser = DemonPacketParser::new(registry.clone());
        parser
            .parse_at(&init_packet, "10.0.0.13".to_owned(), datetime!(2026-03-19 10:03:00 UTC))
            .await
            .expect("init should succeed");

        // Advance to offset 1.
        let _ = build_init_ack(&registry, agent_id).await.expect("ack");
        let offset = registry.ctr_offset(agent_id).await.expect("offset");
        assert_eq!(offset, 1);

        let reconnect_ack = build_reconnect_ack(&registry, agent_id).await.expect("reconnect ack");

        // Decrypting at the wrong offset (0 instead of 1) must NOT produce the agent_id.
        let wrong_plaintext = decrypt_agent_data_at_offset(&key, &iv, 0, &reconnect_ack)
            .expect("decryption itself succeeds");
        assert_ne!(
            wrong_plaintext,
            agent_id.to_le_bytes(),
            "decrypting reconnect ACK at wrong CTR offset must not yield the correct agent_id"
        );
    }
}
