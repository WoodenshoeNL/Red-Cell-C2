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

#[cfg(test)]
mod tests {
    use super::*;
    use red_cell_common::demon::DemonInjectWay;

    // ── parse_injection_way ──────────────────────────────────────────────────

    #[test]
    fn parse_injection_way_inject() {
        assert_eq!(parse_injection_way("inject").unwrap(), DemonInjectWay::Inject);
    }

    #[test]
    fn parse_injection_way_spawn() {
        assert_eq!(parse_injection_way("spawn").unwrap(), DemonInjectWay::Spawn);
    }

    #[test]
    fn parse_injection_way_case_insensitive() {
        assert_eq!(parse_injection_way("INJECT").unwrap(), DemonInjectWay::Inject);
        assert_eq!(parse_injection_way("SPAWN").unwrap(), DemonInjectWay::Spawn);
    }

    #[test]
    fn parse_injection_way_unknown() {
        let err = parse_injection_way("execute").unwrap_err();
        assert!(matches!(err, AgentCommandError::UnsupportedInjectionWay { .. }));
    }

    // ── parse_memory_protection ──────────────────────────────────────────────

    #[test]
    fn parse_memory_protection_known_constants() {
        let cases = [
            ("PAGE_NOACCESS", 0x01u32),
            ("PAGE_READONLY", 0x02),
            ("PAGE_READWRITE", 0x04),
            ("PAGE_WRITECOPY", 0x08),
            ("PAGE_EXECUTE", 0x10),
            ("PAGE_EXECUTE_READ", 0x20),
            ("PAGE_EXECUTE_READWRITE", 0x40),
            ("PAGE_EXECUTE_WRITECOPY", 0x80),
            ("PAGE_GUARD", 0x100),
        ];
        for (input, expected) in cases {
            assert_eq!(parse_memory_protection(input).unwrap(), expected, "failed for {input}");
        }
    }

    #[test]
    fn parse_memory_protection_case_insensitive() {
        assert_eq!(parse_memory_protection("page_readwrite").unwrap(), 0x04);
    }

    #[test]
    fn parse_memory_protection_unknown() {
        let err = parse_memory_protection("PAGE_UNKNOWN").unwrap_err();
        assert!(matches!(err, AgentCommandError::InvalidNumericField { .. }));
    }

    // ── parse_injection_technique ────────────────────────────────────────────

    #[test]
    fn parse_injection_technique_known_values() {
        let cases = [
            ("default", 0u32),
            ("createremotethread", 1),
            ("ntcreatethreadex", 2),
            ("ntqueueapcthread", 3),
        ];
        for (input, expected) in cases {
            assert_eq!(parse_injection_technique(input).unwrap(), expected, "failed for {input}");
        }
    }

    #[test]
    fn parse_injection_technique_case_insensitive() {
        assert_eq!(parse_injection_technique("CreateRemoteThread").unwrap(), 1);
    }

    #[test]
    fn parse_injection_technique_unknown() {
        let err = parse_injection_technique("earlybird").unwrap_err();
        assert!(matches!(err, AgentCommandError::UnsupportedInjectionTechnique { .. }));
    }

    // ── arch_to_flag ─────────────────────────────────────────────────────────

    #[test]
    fn arch_to_flag_x86() {
        assert_eq!(arch_to_flag("x86").unwrap(), 0);
    }

    #[test]
    fn arch_to_flag_x64() {
        assert_eq!(arch_to_flag("x64").unwrap(), 1);
    }

    #[test]
    fn arch_to_flag_case_insensitive() {
        assert_eq!(arch_to_flag("X86").unwrap(), 0);
        assert_eq!(arch_to_flag("X64").unwrap(), 1);
    }

    #[test]
    fn arch_to_flag_unknown() {
        let err = arch_to_flag("arm64").unwrap_err();
        assert!(matches!(err, AgentCommandError::UnsupportedArchitecture { .. }));
    }

    // ── parse_bool_field ─────────────────────────────────────────────────────

    #[test]
    fn parse_bool_field_truthy_values() {
        assert!(parse_bool_field("enabled", "1").unwrap());
        assert!(parse_bool_field("enabled", "true").unwrap());
        assert!(parse_bool_field("enabled", "TRUE").unwrap());
    }

    #[test]
    fn parse_bool_field_falsy_values() {
        assert!(!parse_bool_field("enabled", "0").unwrap());
        assert!(!parse_bool_field("enabled", "false").unwrap());
        assert!(!parse_bool_field("enabled", "FALSE").unwrap());
    }

    #[test]
    fn parse_bool_field_invalid() {
        let err = parse_bool_field("enabled", "yes").unwrap_err();
        assert!(matches!(err, AgentCommandError::InvalidBooleanField { .. }));
    }

    // ── parse_u32_field ──────────────────────────────────────────────────────

    #[test]
    fn parse_u32_field_valid() {
        assert_eq!(parse_u32_field("timeout", "42").unwrap(), 42u32);
        assert_eq!(parse_u32_field("timeout", "0").unwrap(), 0);
        assert_eq!(parse_u32_field("timeout", "4294967295").unwrap(), u32::MAX);
    }

    #[test]
    fn parse_u32_field_trims_whitespace() {
        assert_eq!(parse_u32_field("timeout", "  7  ").unwrap(), 7);
    }

    #[test]
    fn parse_u32_field_invalid() {
        let err = parse_u32_field("timeout", "abc").unwrap_err();
        assert!(matches!(err, AgentCommandError::InvalidNumericField { .. }));
    }

    #[test]
    fn parse_u32_field_overflow() {
        let err = parse_u32_field("timeout", "4294967296").unwrap_err();
        assert!(matches!(err, AgentCommandError::InvalidNumericField { .. }));
    }

    // ── parse_hex_u32 ────────────────────────────────────────────────────────

    #[test]
    fn parse_hex_u32_with_prefix() {
        assert_eq!(parse_hex_u32("0xDEADBEEF").unwrap(), 0xDEAD_BEEF);
        assert_eq!(parse_hex_u32("0XDEADBEEF").unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn parse_hex_u32_without_prefix() {
        assert_eq!(parse_hex_u32("DEADBEEF").unwrap(), 0xDEAD_BEEF);
        assert_eq!(parse_hex_u32("deadbeef").unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn parse_hex_u32_trims_whitespace() {
        assert_eq!(parse_hex_u32("  0xff  ").unwrap(), 0xFF);
    }

    #[test]
    fn parse_hex_u32_invalid() {
        let err = parse_hex_u32("0xGGGG").unwrap_err();
        assert!(matches!(err, AgentCommandError::InvalidNumericField { .. }));
    }

    #[test]
    fn parse_hex_u32_overflow() {
        let err = parse_hex_u32("0x1FFFFFFFF").unwrap_err();
        assert!(matches!(err, AgentCommandError::InvalidNumericField { .. }));
    }

    // ── ipv4_to_u32 ──────────────────────────────────────────────────────────

    #[test]
    fn ipv4_to_u32_valid() {
        // 127.0.0.1 → little-endian bytes [127, 0, 0, 1]
        let expected = u32::from_le_bytes([127, 0, 0, 1]);
        assert_eq!(ipv4_to_u32("127.0.0.1").unwrap(), expected);
    }

    #[test]
    fn ipv4_to_u32_broadcast() {
        let expected = u32::from_le_bytes([255, 255, 255, 255]);
        assert_eq!(ipv4_to_u32("255.255.255.255").unwrap(), expected);
    }

    #[test]
    fn ipv4_to_u32_trims_whitespace() {
        let expected = u32::from_le_bytes([10, 0, 0, 1]);
        assert_eq!(ipv4_to_u32("  10.0.0.1  ").unwrap(), expected);
    }

    #[test]
    fn ipv4_to_u32_invalid() {
        let err = ipv4_to_u32("not-an-ip").unwrap_err();
        assert!(matches!(err, AgentCommandError::InvalidNumericField { .. }));
    }

    #[test]
    fn ipv4_to_u32_out_of_range_octet() {
        let err = ipv4_to_u32("256.0.0.1").unwrap_err();
        assert!(matches!(err, AgentCommandError::InvalidNumericField { .. }));
    }
}
