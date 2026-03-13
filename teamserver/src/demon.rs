//! Incoming Havoc Demon transport parsing for the teamserver.

use std::borrow::Cow;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use red_cell_common::crypto::{AGENT_IV_LENGTH, AGENT_KEY_LENGTH, CryptoError, decrypt_agent_data};
use red_cell_common::demon::{DemonCommand, DemonEnvelope, DemonHeader, DemonProtocolError};
use red_cell_common::{AgentEncryptionInfo, AgentRecord};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::warn;

use crate::{AgentRegistry, TeamserverError};

const PROCESS_ARCH_X86: u32 = 1;
const PROCESS_ARCH_X64: u32 = 2;
const PROCESS_ARCH_IA64: u32 = 3;
const VER_NT_WORKSTATION: u32 = 0x0000_0001;

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

        let decrypted =
            self.registry.decrypt_from_agent(envelope.header.agent_id, remaining).await?;
        let packages = parse_callback_packages(command_id, request_id, &decrypted)?;

        Ok(ParsedDemonPacket::Callback { header: envelope.header, packages })
    }
}

/// Build the encrypted acknowledgement body returned after a Demon init request.
pub async fn build_init_ack(
    registry: &crate::AgentRegistry,
    agent_id: u32,
) -> Result<Vec<u8>, DemonParserError> {
    let payload = agent_id.to_le_bytes();
    Ok(registry.encrypt_for_agent(agent_id, &payload).await?)
}

/// Build the encrypted acknowledgement body returned for a reconnect probe.
pub async fn build_reconnect_ack(
    registry: &crate::AgentRegistry,
    agent_id: u32,
) -> Result<Vec<u8>, DemonParserError> {
    let payload = agent_id.to_le_bytes();
    Ok(registry.encrypt_for_agent_without_advancing(agent_id, &payload).await?)
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

    if key.iter().all(|byte| *byte == 0) {
        warn!(
            agent_id = format_args!("0x{agent_id:08X}"),
            "rejecting DEMON_INIT with all-zero AES key"
        );
        return Err(DemonParserError::InvalidInit("all-zero AES key is not allowed"));
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
            aes_key: BASE64_STANDARD.encode(key),
            aes_iv: BASE64_STANDARD.encode(iv),
        },
        hostname,
        username,
        domain_name,
        external_ip: external_ip.to_owned(),
        internal_ip,
        process_name: basename(&process_path),
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

fn basename(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_owned()
}

fn process_arch_label(value: u32) -> &'static str {
    match value {
        PROCESS_ARCH_X64 => "x64",
        PROCESS_ARCH_X86 => "x86",
        PROCESS_ARCH_IA64 => "IA64",
        _ => "Unknown",
    }
}

fn windows_arch_label(value: u32) -> &'static str {
    match value {
        0 => "x86",
        9 => "x64/AMD64",
        5 => "ARM",
        12 => "ARM64",
        6 => "Itanium-based",
        _ => "Unknown",
    }
}

fn windows_version_label(
    major: u32,
    minor: u32,
    product_type: u32,
    service_pack: u32,
    build: u32,
) -> String {
    let mut version =
        if major == 10 && minor == 0 && product_type != VER_NT_WORKSTATION && build == 20_348 {
            "Windows 2022 Server 22H2".to_owned()
        } else if major == 10 && minor == 0 && product_type != VER_NT_WORKSTATION && build == 17_763
        {
            "Windows 2019 Server".to_owned()
        } else if major == 10
            && minor == 0
            && product_type == VER_NT_WORKSTATION
            && (22_000..=22_621).contains(&build)
        {
            "Windows 11".to_owned()
        } else if major == 10 && minor == 0 && product_type != VER_NT_WORKSTATION {
            "Windows 2016 Server".to_owned()
        } else if major == 10 && minor == 0 && product_type == VER_NT_WORKSTATION {
            "Windows 10".to_owned()
        } else if major == 6 && minor == 3 && product_type != VER_NT_WORKSTATION {
            "Windows Server 2012 R2".to_owned()
        } else if major == 6 && minor == 3 && product_type == VER_NT_WORKSTATION {
            "Windows 8.1".to_owned()
        } else if major == 6 && minor == 2 && product_type != VER_NT_WORKSTATION {
            "Windows Server 2012".to_owned()
        } else if major == 6 && minor == 2 && product_type == VER_NT_WORKSTATION {
            "Windows 8".to_owned()
        } else if major == 6 && minor == 1 && product_type != VER_NT_WORKSTATION {
            "Windows Server 2008 R2".to_owned()
        } else if major == 6 && minor == 1 && product_type == VER_NT_WORKSTATION {
            "Windows 7".to_owned()
        } else {
            "Unknown".to_owned()
        };

    if service_pack != 0 {
        version.push_str(" Service Pack ");
        version.push_str(&service_pack.to_string());
    }

    version
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

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use red_cell_common::crypto::{
        AGENT_IV_LENGTH, AGENT_KEY_LENGTH, ctr_blocks_for_len, decrypt_agent_data_at_offset,
        encrypt_agent_data, encrypt_agent_data_at_offset,
    };
    use red_cell_common::demon::{DEMON_MAGIC_VALUE, DemonCommand, DemonEnvelope};
    use red_cell_common::{AgentEncryptionInfo, AgentRecord};
    use time::macros::datetime;
    use uuid::Uuid;

    use super::{
        DemonPacketParser, DemonParserError, ParsedDemonPacket, build_init_ack, build_reconnect_ack,
    };
    use crate::{AgentRegistry, Database};

    fn u32_be(value: u32) -> [u8; 4] {
        value.to_be_bytes()
    }

    fn u64_be(value: u64) -> [u8; 8] {
        value.to_be_bytes()
    }

    fn add_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
        buf.extend_from_slice(&u32_be(u32::try_from(bytes.len()).unwrap_or_default()));
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
        let key = [0x41; AGENT_KEY_LENGTH];
        let iv = [0x24; AGENT_IV_LENGTH];
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
        let key = [0x41; AGENT_KEY_LENGTH];
        let iv = [0x24; AGENT_IV_LENGTH];
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
        let key = [0x51; AGENT_KEY_LENGTH];
        let iv = [0x34; AGENT_IV_LENGTH];
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
        let packet =
            build_init_packet(0x2233_4455, [0x31; AGENT_KEY_LENGTH], [0x42; AGENT_IV_LENGTH]);

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
        let key = [0x41; AGENT_KEY_LENGTH];
        let iv = [0x24; AGENT_IV_LENGTH];
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
        let key = [0x41; AGENT_KEY_LENGTH];
        let iv = [0x24; AGENT_IV_LENGTH];
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
        let first_key = [0x41; AGENT_KEY_LENGTH];
        let first_iv = [0x24; AGENT_IV_LENGTH];
        let first_packet = build_init_packet(agent_id, first_key, first_iv);
        parser
            .parse_for_listener(&first_packet, "192.0.2.10", "http-main")
            .await
            .expect("initial init should succeed");

        let stored_before = registry.get(agent_id).await.expect("agent should be registered");
        let listener_before =
            registry.listener_name(agent_id).await.expect("listener should exist");
        let ctr_before = registry.ctr_offset(agent_id).await.expect("ctr offset should exist");

        let duplicate_packet =
            build_init_packet(agent_id, [0x99; AGENT_KEY_LENGTH], [0x55; AGENT_IV_LENGTH]);
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
        let key = [0x33; AGENT_KEY_LENGTH];
        let iv = [0x44; AGENT_IV_LENGTH];
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
        let key = [0x55; AGENT_KEY_LENGTH];
        let iv = [0x66; AGENT_IV_LENGTH];
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
        let key = [0x57; AGENT_KEY_LENGTH];
        let iv = [0x68; AGENT_IV_LENGTH];
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

    #[tokio::test]
    async fn build_reconnect_ack_uses_current_ctr_offset_without_advancing_registry_state() {
        let registry = test_registry().await;
        let key = [0x56; AGENT_KEY_LENGTH];
        let iv = [0x67; AGENT_IV_LENGTH];
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
        let key = [0x77; AGENT_KEY_LENGTH];
        let iv = [0x88; AGENT_IV_LENGTH];
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
        let mut packet =
            build_init_packet(0x9999_AAAA, [0x41; AGENT_KEY_LENGTH], [0x24; AGENT_IV_LENGTH]);
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
            matches!(error, DemonParserError::InvalidInit("all-zero AES key is not allowed")),
            "expected zero-key init rejection, got: {error}"
        );
        assert!(registry.get(0x1357_9BDF).await.is_none(), "rejected init must not register");
    }

    #[tokio::test]
    async fn parse_rejects_init_with_kill_date_exceeding_i64_range() {
        let registry = test_registry().await;
        let parser = DemonPacketParser::new(registry.clone());
        let agent_id = 0x1357_9BDF;
        let key = [0x21; AGENT_KEY_LENGTH];
        let iv = [0x31; AGENT_IV_LENGTH];
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
                &build_init_packet(0x1357_9BDF, [0x21; AGENT_KEY_LENGTH], [0x31; AGENT_IV_LENGTH]),
                "203.0.113.77".to_owned(),
                datetime!(2026-03-10 10:15:00 UTC),
            )
            .await
            .expect("first init should succeed");

        let error = parser
            .parse_at(
                &build_init_packet(0x2468_ACED, [0x22; AGENT_KEY_LENGTH], [0x32; AGENT_IV_LENGTH]),
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
                aes_key: BASE64_STANDARD.encode([0; AGENT_KEY_LENGTH]),
                aes_iv: BASE64_STANDARD.encode([0; AGENT_IV_LENGTH]),
            },
            hostname: "wkstn-01".to_owned(),
            username: "operator".to_owned(),
            domain_name: "REDCELL".to_owned(),
            external_ip: "203.0.113.1".to_owned(),
            internal_ip: "10.0.0.10".to_owned(),
            process_name: "explorer.exe".to_owned(),
            base_address: 0x401000,
            process_pid: 1337,
            process_tid: 1338,
            process_ppid: 512,
            process_arch: "x64".to_owned(),
            elevated: true,
            os_version: "Windows 11".to_owned(),
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
        let key = [0x55; AGENT_KEY_LENGTH];
        let iv = [0x66; AGENT_IV_LENGTH];
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
}
