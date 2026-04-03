//! Little-endian / big-endian payload helpers for Demon task and callback bodies.

// ─── Payload parsing helpers (server → agent, little-endian) ─────────────────

/// Parse a `u32` in little-endian byte order from `buf[*offset..]`.
pub(crate) fn parse_u32_le(buf: &[u8], offset: &mut usize) -> Result<u32, &'static str> {
    if buf.len() < *offset + 4 {
        return Err("buffer too short for u32 LE");
    }
    let val = u32::from_le_bytes(
        buf[*offset..*offset + 4].try_into().map_err(|_| "slice-to-array conversion failed")?,
    );
    *offset += 4;
    Ok(val)
}

/// Parse a `u64` in little-endian byte order from `buf[*offset..]`.
pub(crate) fn parse_u64_le(buf: &[u8], offset: &mut usize) -> Result<u64, &'static str> {
    if buf.len() < *offset + 8 {
        return Err("buffer too short for u64 LE");
    }
    let val = u64::from_le_bytes(
        buf[*offset..*offset + 8].try_into().map_err(|_| "slice-to-array conversion failed")?,
    );
    *offset += 8;
    Ok(val)
}

/// Parse a length-prefixed byte slice: `[u32 LE length][bytes…]`.
pub(crate) fn parse_bytes_le(buf: &[u8], offset: &mut usize) -> Result<Vec<u8>, &'static str> {
    let len = parse_u32_le(buf, offset)? as usize;
    if buf.len() < *offset + len {
        return Err("buffer too short for payload bytes");
    }
    let bytes = buf[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(bytes)
}

/// Decode a UTF-16LE byte slice to a `String`, stripping trailing NUL characters.
pub(crate) fn decode_utf16le_null(bytes: &[u8]) -> String {
    let words: Vec<u16> = bytes.chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
    String::from_utf16_lossy(&words).trim_end_matches('\0').to_string()
}

// ─── Payload serialisation helpers (agent → server, big-endian, always) ──────
//
// Used by the FS download OPEN header and download chunk packets, which must
// use big-endian encoding to match the original Demon `PackageAdd*` functions.

/// Append a `u32` in big-endian byte order (non-test, always compiled).
pub(crate) fn write_u32_be_always(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Encode `s` as UTF-16LE with a NUL terminator and append `[u32 BE length][bytes…]`.
///
/// Matches the Demon's `PackageAddWString`: big-endian length prefix, UTF-16LE payload.
pub(crate) fn write_wstring_be(buf: &mut Vec<u8>, s: &str) {
    let utf16: Vec<u8> =
        s.encode_utf16().chain(std::iter::once(0u16)).flat_map(|c| c.to_le_bytes()).collect();
    #[allow(clippy::cast_possible_truncation)]
    let len = utf16.len() as u32;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&utf16);
}

// ─── Payload serialisation helpers (agent → server, big-endian, test-only) ───
//
// Used by the existing Sleep, Fs, and Exec callbacks which pre-date the LE fix.

/// Append a `u32` in big-endian byte order.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn write_u32_be(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Append a length-prefixed byte slice: `[u32 BE length][bytes…]`.
#[cfg(test)]
pub(crate) fn write_bytes_be(buf: &mut Vec<u8>, data: &[u8]) {
    #[allow(clippy::cast_possible_truncation)]
    let len = data.len() as u32;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
}

/// Append a `u64` pointer in big-endian byte order (8 bytes).
#[cfg(test)]
pub(crate) fn write_ptr_be(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Encode `s` as UTF-16LE with a NUL terminator and append `[u32 BE length][bytes…]`.
#[cfg(test)]
pub(crate) fn write_utf16le_be(buf: &mut Vec<u8>, s: &str) {
    let utf16: Vec<u8> =
        s.encode_utf16().chain(std::iter::once(0u16)).flat_map(|c| c.to_le_bytes()).collect();
    write_bytes_be(buf, &utf16);
}

// ─── Payload serialisation helpers (agent → server, little-endian) ───────────
//
// Used by the process callbacks (CommandProcList / CommandProc) whose fields
// are parsed by the Rust teamserver's `CallbackParser` which reads LE.

/// Append a `u32` in little-endian byte order.
pub(crate) fn write_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// Append a length-prefixed byte slice: `[u32 LE length][bytes…]`.
pub(crate) fn write_bytes_le(buf: &mut Vec<u8>, data: &[u8]) {
    #[allow(clippy::cast_possible_truncation)]
    let len = data.len() as u32;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(data);
}

/// Append a `u64` pointer in little-endian byte order (8 bytes).
///
/// Used for base-address fields; the Rust teamserver's `CallbackParser::read_u64` reads 8 bytes LE.
pub(crate) fn write_ptr_le(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// Encode `s` as UTF-16LE with a NUL terminator and append `[u32 LE length][bytes…]`.
pub(crate) fn write_utf16le(buf: &mut Vec<u8>, s: &str) {
    let utf16: Vec<u8> =
        s.encode_utf16().chain(std::iter::once(0u16)).flat_map(|c| c.to_le_bytes()).collect();
    write_bytes_le(buf, &utf16);
}
