//! JSON config parsing helpers and Demon value-encoding utilities.
//!
//! These are pure functions that extract typed values from `serde_json::Map`
//! entries and map Demon-specific configuration strings to their integer
//! protocol equivalents.  The buffer helpers (`add_u32`, `add_bytes`, …)
//! serialise values into the little-endian, length-prefixed wire format
//! expected by the Demon agent.

use red_cell_common::HttpListenerProxyConfig;
use serde_json::{Map, Value};

use super::PayloadBuildError;

// ---------------------------------------------------------------------------
// JSON map accessors
// ---------------------------------------------------------------------------

pub(super) fn required_object<'a>(
    config: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Map<String, Value>, PayloadBuildError> {
    config
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| PayloadBuildError::InvalidRequest { message: format!("{key} is undefined") })
}

pub(super) fn required_string<'a>(
    config: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, PayloadBuildError> {
    optional_string(config, key)
        .ok_or_else(|| PayloadBuildError::InvalidRequest { message: format!("{key} is undefined") })
}

pub(super) fn optional_string<'a>(config: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    config
        .get(key)
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub(super) fn optional_bool(config: &Map<String, Value>, key: &str) -> Option<bool> {
    config.get(key).and_then(Value::as_bool)
}

pub(super) fn required_u32(
    config: &Map<String, Value>,
    key: &str,
) -> Result<u32, PayloadBuildError> {
    match config.get(key) {
        Some(Value::String(value)) => value.trim().parse::<u32>().map_err(|_| {
            PayloadBuildError::InvalidRequest { message: format!("{key} must be a valid integer") }
        }),
        Some(Value::Number(value)) => {
            value.as_u64().and_then(|value| u32::try_from(value).ok()).ok_or_else(|| {
                PayloadBuildError::InvalidRequest { message: format!("{key} must fit in u32") }
            })
        }
        _ => Err(PayloadBuildError::InvalidRequest { message: format!("{key} is undefined") }),
    }
}

// ---------------------------------------------------------------------------
// Demon config value mappers
// ---------------------------------------------------------------------------

pub(super) fn injection_mode(
    config: &Map<String, Value>,
    key: &str,
) -> Result<u32, PayloadBuildError> {
    Ok(match optional_string(config, key).unwrap_or_default() {
        "Win32" => 1,
        "Native/Syscall" => 2,
        _ => 0,
    })
}

pub(super) fn sleep_obfuscation_value(value: &str) -> u32 {
    match value {
        "Foliage" => 3,
        "Ekko" => 1,
        "Zilean" => 2,
        _ => 0,
    }
}

pub(super) fn sleep_jump_bypass(
    obfuscation: u32,
    value: Option<&str>,
) -> Result<u32, PayloadBuildError> {
    if obfuscation == 0 {
        return Ok(0);
    }
    Ok(match value.unwrap_or_default() {
        "jmp rax" => 1,
        "jmp rbx" => 2,
        _ => 0,
    })
}

pub(super) fn proxy_loading_value(value: Option<&str>) -> u32 {
    match value.unwrap_or("None (LdrLoadDll)") {
        "RtlRegisterWait" => 1,
        "RtlCreateTimer" => 2,
        "RtlQueueWorkItem" => 3,
        _ => 0,
    }
}

pub(super) fn amsi_patch_value(value: Option<&str>) -> u32 {
    match value.unwrap_or_default() {
        // Legacy GUI values (Havoc-compatible)
        "Hardware breakpoints" => 1,
        "Memory" => 2,
        // ARC-01 canonical profile keys: AmsiEtw = 'hwbp' | 'patch' | 'none'
        "hwbp" => 1,
        "patch" => 2,
        "none" => 0,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Date / time parsers
// ---------------------------------------------------------------------------

pub(super) fn parse_kill_date(value: Option<&str>) -> Result<u64, PayloadBuildError> {
    let Some(raw) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(0);
    };
    let epoch = red_cell_common::parse_kill_date_to_epoch(raw)
        .map_err(|err| PayloadBuildError::InvalidRequest { message: err.to_string() })?;
    u64::try_from(epoch).map_err(|_| PayloadBuildError::InvalidRequest {
        message: format!("KillDate `{raw}` must be a non-negative unix timestamp"),
    })
}

pub(super) fn parse_working_hours(value: Option<&str>) -> Result<i32, PayloadBuildError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(0);
    };

    let (start, end) = value.split_once('-').ok_or_else(|| PayloadBuildError::InvalidRequest {
        message: "WorkingHours must use `HH:MM-HH:MM`".to_owned(),
    })?;
    let (start_hour, start_minute) = parse_hour_minute(start)?;
    let (end_hour, end_minute) = parse_hour_minute(end)?;
    if end_hour < start_hour || (end_hour == start_hour && end_minute <= start_minute) {
        return Err(PayloadBuildError::InvalidRequest {
            message: "WorkingHours end must be after the start".to_owned(),
        });
    }

    let mut packed = 0_i32;
    packed |= 1 << 22;
    packed |= (i32::from(start_hour) & 0b01_1111) << 17;
    packed |= (i32::from(start_minute) & 0b11_1111) << 11;
    packed |= (i32::from(end_hour) & 0b01_1111) << 6;
    packed |= i32::from(end_minute) & 0b11_1111;
    Ok(packed)
}

pub(super) fn parse_hour_minute(value: &str) -> Result<(u8, u8), PayloadBuildError> {
    let (hour, minute) =
        value.split_once(':').ok_or_else(|| PayloadBuildError::InvalidRequest {
            message: "WorkingHours must use `HH:MM-HH:MM`".to_owned(),
        })?;
    let hour = hour.trim().parse::<u8>().map_err(|_| PayloadBuildError::InvalidRequest {
        message: format!("invalid working-hours hour `{hour}`"),
    })?;
    let minute = minute.trim().parse::<u8>().map_err(|_| PayloadBuildError::InvalidRequest {
        message: format!("invalid working-hours minute `{minute}`"),
    })?;
    if hour > 23 || minute > 59 {
        return Err(PayloadBuildError::InvalidRequest {
            message: "WorkingHours contains an out-of-range hour or minute".to_owned(),
        });
    }
    Ok((hour, minute))
}

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

pub(super) fn proxy_url(proxy: &HttpListenerProxyConfig) -> String {
    let scheme = proxy.proxy_type.as_deref().unwrap_or("http");
    format!("{scheme}://{}:{}", proxy.host, proxy.port)
}

// ---------------------------------------------------------------------------
// Binary buffer writers (little-endian, length-prefixed)
// ---------------------------------------------------------------------------

pub(super) fn add_u32(buffer: &mut Vec<u8>, value: u32) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

pub(super) fn add_u64(buffer: &mut Vec<u8>, value: u64) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

pub(super) fn add_bytes(buffer: &mut Vec<u8>, value: &[u8]) -> Result<(), PayloadBuildError> {
    let len = u32::try_from(value.len()).map_err(|_| PayloadBuildError::InvalidRequest {
        message: format!("byte slice length {} exceeds u32::MAX", value.len()),
    })?;
    add_u32(buffer, len);
    buffer.extend_from_slice(value);
    Ok(())
}

pub(super) fn add_wstring(buffer: &mut Vec<u8>, value: &str) -> Result<(), PayloadBuildError> {
    let mut utf16: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
    utf16.extend_from_slice(&[0, 0]);
    add_bytes(buffer, &utf16)
}
