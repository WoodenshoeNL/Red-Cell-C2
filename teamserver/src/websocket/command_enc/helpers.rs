//! Low-level parse and binary-writing helpers used by the payload encoders.

use red_cell_common::demon::DemonInjectWay;
use uuid::Uuid;

use super::AgentCommandError;

// ── Parse helpers ───────────────────────────────────────────────────────────

pub fn parse_injection_way(value: &str) -> Result<DemonInjectWay, AgentCommandError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "inject" => Ok(DemonInjectWay::Inject),
        "spawn" => Ok(DemonInjectWay::Spawn),
        _ => Err(AgentCommandError::UnsupportedInjectionWay { way: value.to_owned() }),
    }
}

pub fn parse_memory_protection(value: &str) -> Result<u32, AgentCommandError> {
    match value.to_ascii_uppercase().as_str() {
        "PAGE_NOACCESS" => Ok(0x01),
        "PAGE_READONLY" => Ok(0x02),
        "PAGE_READWRITE" => Ok(0x04),
        "PAGE_WRITECOPY" => Ok(0x08),
        "PAGE_EXECUTE" => Ok(0x10),
        "PAGE_EXECUTE_READ" => Ok(0x20),
        "PAGE_EXECUTE_READWRITE" => Ok(0x40),
        "PAGE_EXECUTE_WRITECOPY" => Ok(0x80),
        "PAGE_GUARD" => Ok(0x100),
        _ => Err(AgentCommandError::InvalidNumericField {
            field: "MemoryProtection".to_owned(),
            value: value.to_owned(),
        }),
    }
}

pub fn parse_injection_technique(value: &str) -> Result<u32, AgentCommandError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "default" => Ok(0),
        "createremotethread" => Ok(1),
        "ntcreatethreadex" => Ok(2),
        "ntqueueapcthread" => Ok(3),
        _ => Err(AgentCommandError::UnsupportedInjectionTechnique { technique: value.to_owned() }),
    }
}

pub fn arch_to_flag(value: &str) -> Result<u32, AgentCommandError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "x86" => Ok(0),
        "x64" => Ok(1),
        _ => Err(AgentCommandError::UnsupportedArchitecture { arch: value.to_owned() }),
    }
}

pub fn parse_bool_field(field: &str, value: &str) -> Result<bool, AgentCommandError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => Err(AgentCommandError::InvalidBooleanField {
            field: field.to_owned(),
            value: value.to_owned(),
        }),
    }
}

pub fn parse_u32_field(field: &str, value: &str) -> Result<u32, AgentCommandError> {
    value.trim().parse::<u32>().map_err(|_| AgentCommandError::InvalidNumericField {
        field: field.to_owned(),
        value: value.to_owned(),
    })
}

pub fn parse_hex_u32(value: &str) -> Result<u32, AgentCommandError> {
    let trimmed = value.trim();
    let trimmed =
        trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")).unwrap_or(trimmed);
    u32::from_str_radix(trimmed, 16).map_err(|_| AgentCommandError::InvalidNumericField {
        field: "hex".to_owned(),
        value: value.to_owned(),
    })
}

pub fn ipv4_to_u32(value: &str) -> Result<u32, AgentCommandError> {
    let address = value.trim().parse::<std::net::Ipv4Addr>().map_err(|_| {
        AgentCommandError::InvalidNumericField { field: "ip".to_owned(), value: value.to_owned() }
    })?;
    Ok(u32::from_le_bytes(address.octets()))
}

// ── Binary writing helpers ──────────────────────────────────────────────────

pub fn write_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

pub fn write_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_le_bytes());
}

pub fn write_len_prefixed_bytes(
    buf: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), crate::TeamserverError> {
    let len = u32::try_from(value.len())
        .map_err(|_| crate::TeamserverError::PayloadTooLarge { length: value.len() })?;
    write_u32(buf, len);
    buf.extend_from_slice(value);
    Ok(())
}

pub fn random_u32() -> u32 {
    let bytes = *Uuid::new_v4().as_bytes();
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

pub fn encode_utf16(value: &str) -> Vec<u8> {
    let mut encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
    encoded.extend_from_slice(&[0, 0]);
    encoded
}
