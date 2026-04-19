//! Shared network utility helpers used across dispatch submodules.

/// Converts a little-endian `u32` to a dotted-decimal IPv4 string.
pub fn int_to_ipv4(value: u32) -> String {
    let bytes = value.to_le_bytes();
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}
