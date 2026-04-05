//! Strongly typed agent identifiers for CLI and session boundaries.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Canonical agent identifier used throughout the CLI.
///
/// The teamserver wire format uses a numeric `u32`, while the CLI surface uses
/// uppercase hexadecimal. This wrapper keeps both representations tied together
/// so callers cannot accidentally pass an arbitrary string where an agent ID is
/// required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentId(u32);

impl AgentId {
    /// Create an [`AgentId`] from its wire-format value.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Return the wire-format numeric identifier.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Format the agent identifier as uppercase hexadecimal.
    #[must_use]
    pub fn format_hex(self, prefix: bool) -> String {
        if prefix { format!("0x{:08X}", self.0) } else { self.to_string() }
    }

    fn parse_decimal(input: &str) -> Result<Self, ParseAgentIdError> {
        input
            .parse::<u32>()
            .map(Self)
            .map_err(|_| ParseAgentIdError::InvalidDecimal(input.to_owned()))
    }

    fn parse_hex(input: &str, original: &str) -> Result<Self, ParseAgentIdError> {
        u32::from_str_radix(input, 16)
            .map(Self)
            .map_err(|_| ParseAgentIdError::InvalidHex(original.to_owned()))
    }
}

impl From<u32> for AgentId {
    fn from(value: u32) -> Self {
        Self::new(value)
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08X}", self.0)
    }
}

/// Parse failure for [`AgentId`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseAgentIdError {
    Empty,
    Ambiguous(String),
    InvalidDecimal(String),
    InvalidHex(String),
}

impl fmt::Display for ParseAgentIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "agent id cannot be empty"),
            Self::Ambiguous(value) => write!(
                f,
                "ambiguous agent id '{value}': use 0x<hex> for hexadecimal, bare hex with A-F, or dec:<u32> for decimal"
            ),
            Self::InvalidDecimal(value) => {
                write!(f, "invalid decimal agent id '{value}'")
            }
            Self::InvalidHex(value) => write!(f, "invalid hexadecimal agent id '{value}'"),
        }
    }
}

impl std::error::Error for ParseAgentIdError {}

impl FromStr for AgentId {
    type Err = ParseAgentIdError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(ParseAgentIdError::Empty);
        }

        if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
            if hex.is_empty() {
                return Err(ParseAgentIdError::InvalidHex(trimmed.to_owned()));
            }
            return Self::parse_hex(hex, trimmed);
        }

        if let Some(decimal) = trimmed
            .strip_prefix("dec:")
            .or_else(|| trimmed.strip_prefix("DEC:"))
            .or_else(|| trimmed.strip_prefix("decimal:"))
            .or_else(|| trimmed.strip_prefix("DECIMAL:"))
        {
            if decimal.is_empty() {
                return Err(ParseAgentIdError::InvalidDecimal(trimmed.to_owned()));
            }
            return Self::parse_decimal(decimal);
        }

        if trimmed.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ParseAgentIdError::Ambiguous(trimmed.to_owned()));
        }

        if trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Self::parse_hex(trimmed, trimmed);
        }

        Err(ParseAgentIdError::InvalidHex(trimmed.to_owned()))
    }
}

impl Serialize for AgentId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for AgentId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AgentIdVisitor;

        impl Visitor<'_> for AgentIdVisitor {
            type Value = AgentId;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a u32 agent id or a hexadecimal agent id string")
            }

            fn visit_u32<E>(self, value: u32) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(AgentId::new(value))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let value =
                    u32::try_from(value).map_err(|_| E::custom("agent id exceeds u32 range"))?;
                Ok(AgentId::new(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                let value =
                    u32::try_from(value).map_err(|_| E::custom("agent id must be non-negative"))?;
                Ok(AgentId::new(value))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                AgentId::from_str(value).map_err(E::custom)
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_str(&value)
            }
        }

        deserializer.deserialize_any(AgentIdVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_zero_padded_upper_hex() {
        assert_eq!(AgentId::new(0xABC123).to_string(), "00ABC123");
    }

    #[test]
    fn format_hex_can_add_prefix() {
        assert_eq!(AgentId::new(0xDEADBEEF).format_hex(true), "0xDEADBEEF");
    }

    #[test]
    fn parses_prefixed_hex() {
        assert_eq!("0xdeadbeef".parse::<AgentId>().expect("parse"), AgentId::new(0xDEADBEEF));
    }

    #[test]
    fn parses_bare_hex_when_unambiguous() {
        assert_eq!("abc123".parse::<AgentId>().expect("parse"), AgentId::new(0xABC123));
    }

    #[test]
    fn parses_explicit_decimal_string() {
        assert_eq!("dec:42".parse::<AgentId>().expect("parse"), AgentId::new(42));
    }

    #[test]
    fn rejects_ambiguous_digit_only_string() {
        let err = "1234".parse::<AgentId>().expect_err("must reject ambiguous digits");
        assert_eq!(err, ParseAgentIdError::Ambiguous("1234".to_owned()));
    }

    #[test]
    fn serde_accepts_numeric_wire_value() {
        let id: AgentId = serde_json::from_value(serde_json::json!(3735928559u32)).expect("json");
        assert_eq!(id, AgentId::new(0xDEADBEEF));
    }

    #[test]
    fn serde_accepts_hex_string() {
        let id: AgentId = serde_json::from_value(serde_json::json!("DEADBEEF")).expect("json");
        assert_eq!(id, AgentId::new(0xDEADBEEF));
    }

    #[test]
    fn serde_rejects_ambiguous_string() {
        let err = serde_json::from_value::<AgentId>(serde_json::json!("1234")).expect_err("json");
        assert!(err.to_string().contains("ambiguous agent id '1234'"));
    }

    #[test]
    fn serializes_as_upper_hex_string() {
        let value = serde_json::to_value(AgentId::new(0xDEADBEEF)).expect("json");
        assert_eq!(value, serde_json::json!("DEADBEEF"));
    }
}
