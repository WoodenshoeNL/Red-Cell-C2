//! Wire-format codec helpers and pipe error type for SMB pivot.
//!
//! All integers use **little-endian** byte order, matching the teamserver's
//! `CallbackParser`.

// ─── Serialisation helpers ──────────────────────────────────────────────────

/// Extract the child agent's Demon ID from its init packet.
///
/// The init packet wire layout (big-endian) is:
/// `[size: u32][magic: u32][agent_id: u32][...]`
///
/// We skip size (4 bytes) and magic (4 bytes), then read the agent ID.
pub(super) fn parse_demon_id_from_init(data: &[u8]) -> u32 {
    if data.len() < 12 {
        return 0;
    }
    u32::from_be_bytes([data[8], data[9], data[10], data[11]])
}

pub(super) fn parse_u32_le(buf: &[u8], offset: &mut usize) -> Result<u32, &'static str> {
    if buf.len() < *offset + 4 {
        return Err("buffer too short for u32");
    }
    let v = u32::from_le_bytes(buf[*offset..*offset + 4].try_into().unwrap_or([0; 4]));
    *offset += 4;
    Ok(v)
}

pub(super) fn parse_bytes_le(buf: &[u8], offset: &mut usize) -> Result<Vec<u8>, &'static str> {
    let len = parse_u32_le(buf, offset)? as usize;
    if buf.len() < *offset + len {
        return Err("buffer too short for bytes payload");
    }
    let v = buf[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(v)
}

pub(super) fn decode_utf16le_null(bytes: &[u8]) -> String {
    let words: Vec<u16> = bytes.chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
    String::from_utf16_lossy(&words).trim_end_matches('\0').to_string()
}

pub(super) fn write_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

pub(super) fn write_bytes_le(buf: &mut Vec<u8>, data: &[u8]) {
    #[allow(clippy::cast_possible_truncation)]
    let len = data.len() as u32;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(data);
}

pub(super) fn write_utf16le(buf: &mut Vec<u8>, s: &str) {
    let utf16: Vec<u8> =
        s.encode_utf16().chain(std::iter::once(0u16)).flat_map(|c| c.to_le_bytes()).collect();
    write_bytes_le(buf, &utf16);
}

// ─── Pipe error type ────────────────────────────────────────────────────────

/// Platform-agnostic pipe error.
#[derive(Debug, Clone)]
pub struct PipeError {
    code: u32,
    message: String,
    broken_pipe: bool,
}

impl PipeError {
    pub(crate) fn new(code: u32, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), broken_pipe: false }
    }

    #[cfg(windows)]
    pub(crate) fn broken_pipe(code: u32, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), broken_pipe: true }
    }

    /// Whether this error indicates the pipe is broken (child disconnected).
    pub fn is_broken_pipe(&self) -> bool {
        self.broken_pipe
    }

    /// The raw Win32 error code (or 0 on non-Windows).
    pub fn raw_os_error(&self) -> u32 {
        self.code
    }
}

impl std::fmt::Display for PipeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}
