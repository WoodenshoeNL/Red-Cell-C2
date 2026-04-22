pub(super) use super::super::pe_patch::parse_header_u32_field;
pub(super) use super::*;
pub(super) use red_cell_common::HttpListenerProxyConfig as DomainHttpListenerProxyConfig;
pub(super) use red_cell_common::config::{DemonConfig, JobExecutionMode};
pub(super) use serde_json::{Map, Value, json};
pub(super) use zeroize::Zeroizing;

mod agent_format;
mod listener;
mod profile;
mod validation;

// ── Cursor / binary reader helpers ──────────────────────────────────

pub(super) fn read_u32(cursor: &mut &[u8]) -> Result<u32, PayloadBuildError> {
    let bytes = take(cursor, 4)?;
    let array: [u8; 4] = bytes.try_into().map_err(|_| PayloadBuildError::InvalidRequest {
        message: "test parser failed to decode u32".to_owned(),
    })?;
    Ok(u32::from_le_bytes(array))
}

pub(super) fn read_u64(cursor: &mut &[u8]) -> Result<u64, PayloadBuildError> {
    let bytes = take(cursor, 8)?;
    let array: [u8; 8] = bytes.try_into().map_err(|_| PayloadBuildError::InvalidRequest {
        message: "test parser failed to decode u64".to_owned(),
    })?;
    Ok(u64::from_le_bytes(array))
}

pub(super) fn read_wstring(cursor: &mut &[u8]) -> Result<String, PayloadBuildError> {
    let byte_len =
        usize::try_from(read_u32(cursor)?).map_err(|_| PayloadBuildError::InvalidRequest {
            message: "test parser string length overflow".to_owned(),
        })?;
    let bytes = take(cursor, byte_len)?;
    if bytes.len() < 2 || bytes[bytes.len() - 2..] != [0, 0] {
        return Err(PayloadBuildError::InvalidRequest {
            message: "test parser missing UTF-16 terminator".to_owned(),
        });
    }

    let units = bytes[..bytes.len() - 2]
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&units).map_err(|error| PayloadBuildError::InvalidRequest {
        message: format!("test parser invalid UTF-16: {error}"),
    })
}

/// Read a length-prefixed raw byte slice (as written by `add_bytes`).
pub(super) fn read_bytes<'a>(cursor: &mut &'a [u8]) -> Result<&'a [u8], PayloadBuildError> {
    let byte_len =
        usize::try_from(read_u32(cursor)?).map_err(|_| PayloadBuildError::InvalidRequest {
            message: "test parser byte-slice length overflow".to_owned(),
        })?;
    take(cursor, byte_len)
}

pub(super) fn take<'a>(cursor: &mut &'a [u8], len: usize) -> Result<&'a [u8], PayloadBuildError> {
    if cursor.len() < len {
        return Err(PayloadBuildError::InvalidRequest {
            message: "test parser reached end of buffer".to_owned(),
        });
    }
    let (head, tail) = cursor.split_at(len);
    *cursor = tail;
    Ok(head)
}

// ── Listener constructor helpers ────────────────────────────────────

pub(super) fn minimal_config_json() -> Map<String, Value> {
    serde_json::from_value::<Map<String, Value>>(json!({
        "Sleep": "5",
        "Jitter": "0",
        "Sleep Technique": "WaitForSingleObjectEx",
        "Injection": {
            "Alloc": "Win32",
            "Execute": "Win32",
            "Spawn64": "a",
            "Spawn32": "b"
        }
    }))
    .expect("valid test json")
}

pub(super) fn http_listener_with_method(method: Option<&str>) -> ListenerConfig {
    ListenerConfig::Http(Box::new(HttpListenerConfig {
        name: "http".to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["localhost:80".to_owned()],
        host_bind: "0.0.0.0".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: 80,
        port_conn: None,
        method: method.map(str::to_owned),
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: None,
        headers: Vec::new(),
        uris: Vec::new(),
        host_header: None,
        secure: false,
        cert: None,
        response: None,
        proxy: None,
        ja3_randomize: None,
        doh_domain: None,
        doh_provider: None,
        legacy_mode: true,
        suppress_opsec_warnings: true,
    }))
}

/// Helper: build a minimal HTTPS listener with an optional `ja3_randomize` override.
pub(super) fn https_listener_with_ja3(ja3_randomize: Option<bool>) -> ListenerConfig {
    ListenerConfig::Http(Box::new(HttpListenerConfig {
        name: "https".to_owned(),
        kill_date: None,
        working_hours: None,
        hosts: vec!["localhost:443".to_owned()],
        host_bind: "0.0.0.0".to_owned(),
        host_rotation: "round-robin".to_owned(),
        port_bind: 443,
        port_conn: None,
        method: None,
        behind_redirector: false,
        trusted_proxy_peers: Vec::new(),
        user_agent: None,
        headers: Vec::new(),
        uris: Vec::new(),
        host_header: None,
        secure: true,
        cert: None,
        response: None,
        proxy: None,
        ja3_randomize,
        doh_domain: None,
        doh_provider: None,
        legacy_mode: true,
        suppress_opsec_warnings: true,
    }))
}
