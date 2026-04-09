//! Flexible serde deserializers for numeric and boolean fields.
//!
//! The Havoc protocol and HCL profile format represent values inconsistently —
//! sometimes as JSON numbers, sometimes as strings.  These helpers accept both
//! representations so that a single Rust struct can deserialise from either
//! source without manual pre-processing.

use serde::de;
use serde::{Deserialize, Deserializer};

// ── Helper enums for `#[serde(untagged)]` type coercion ────────────────────

#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum StringOrU64 {
    String(String),
    Number(u64),
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum StringOrI64 {
    String(String),
    Number(i64),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum StringOrBoolOrU64 {
    String(String),
    Bool(bool),
    Number(u64),
}

// ── Boolean ────────────────────────────────────────────────────────────────

pub(super) fn deserialize_bool_from_any<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = StringOrBoolOrU64::deserialize(deserializer)?;

    match raw {
        StringOrBoolOrU64::Bool(value) => Ok(value),
        StringOrBoolOrU64::Number(value) => match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(de::Error::custom(format!("invalid boolean number `{value}`"))),
        },
        StringOrBoolOrU64::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" => Ok(true),
            "false" | "0" | "" => Ok(false),
            other => Err(de::Error::custom(format!("invalid boolean value `{other}`"))),
        },
    }
}

// ── Unsigned integers ──────────────────────────────────────────────────────

pub(super) fn deserialize_u16_from_any<'de, D>(deserializer: D) -> Result<u16, D::Error>
where
    D: Deserializer<'de>,
{
    let value = deserialize_u64_from_any(deserializer)?;
    u16::try_from(value)
        .map_err(|_| de::Error::custom(format!("integer `{value}` does not fit in u16")))
}

pub(super) fn deserialize_optional_u16_from_any<'de, D>(
    deserializer: D,
) -> Result<Option<u16>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = deserialize_optional_u64_from_any(deserializer)?;
    value
        .map(|value| {
            u16::try_from(value)
                .map_err(|_| de::Error::custom(format!("integer `{value}` does not fit in u16")))
        })
        .transpose()
}

pub(super) fn deserialize_u32_from_any<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let value = deserialize_u64_from_any(deserializer)?;
    u32::try_from(value)
        .map_err(|_| de::Error::custom(format!("integer `{value}` does not fit in u32")))
}

pub(super) fn deserialize_u64_from_any<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = StringOrU64::deserialize(deserializer)?;

    match raw {
        StringOrU64::String(value) => value
            .trim()
            .parse::<u64>()
            .map_err(|_| de::Error::custom(format!("invalid unsigned integer value `{value}`"))),
        StringOrU64::Number(value) => Ok(value),
    }
}

// ── Optional unsigned integers ─────────────────────────────────────────────

pub(super) fn deserialize_optional_u64_from_any<'de, D>(
    deserializer: D,
) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Option::<StringOrU64>::deserialize(deserializer)?;

    raw.map(|value| match value {
        StringOrU64::String(string) if string.trim().is_empty() => Ok(None),
        StringOrU64::String(string) => {
            string.trim().parse::<u64>().map(Some).map_err(|_| {
                de::Error::custom(format!("invalid unsigned integer value `{string}`"))
            })
        }
        StringOrU64::Number(value) => Ok(Some(value)),
    })
    .transpose()
    .map(Option::flatten)
}

// ── Optional signed integers ───────────────────────────────────────────────

pub(super) fn deserialize_optional_i64_from_any<'de, D>(
    deserializer: D,
) -> Result<Option<i64>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Option::<StringOrI64>::deserialize(deserializer)?;

    raw.map(|value| match value {
        StringOrI64::String(string) if string.trim().is_empty() => Ok(None),
        StringOrI64::String(string) => string
            .trim()
            .parse::<i64>()
            .map(Some)
            .map_err(|_| de::Error::custom(format!("invalid signed integer value `{string}`"))),
        StringOrI64::Number(value) => Ok(Some(value)),
    })
    .transpose()
    .map(Option::flatten)
}

pub(super) fn deserialize_optional_i32_from_any<'de, D>(
    deserializer: D,
) -> Result<Option<i32>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = deserialize_optional_i64_from_any(deserializer)?;
    value
        .map(|value| {
            i32::try_from(value)
                .map_err(|_| de::Error::custom(format!("integer `{value}` does not fit in i32")))
        })
        .transpose()
}
