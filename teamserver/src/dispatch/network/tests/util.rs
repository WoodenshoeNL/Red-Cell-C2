//! Tests for `int_to_ipv4`.

use super::super::util::int_to_ipv4;

#[test]
fn int_to_ipv4_zero_is_all_zeros() {
    assert_eq!(int_to_ipv4(0x0000_0000), "0.0.0.0");
}

#[test]
fn int_to_ipv4_little_endian_192_168_1_1() {
    // LE bytes of 0x0101A8C0: C0 A8 01 01 → 192.168.1.1
    assert_eq!(int_to_ipv4(0x0101_A8C0), "192.168.1.1");
}

#[test]
fn int_to_ipv4_localhost() {
    // LE bytes of 0x0100007F: 7F 00 00 01 → 127.0.0.1
    assert_eq!(int_to_ipv4(0x0100_007F), "127.0.0.1");
}

#[test]
fn int_to_ipv4_broadcast() {
    // LE bytes of 0xFFFFFFFF: FF FF FF FF → 255.255.255.255
    assert_eq!(int_to_ipv4(0xFFFF_FFFF), "255.255.255.255");
}

/// Pin byte-order: 0xC0A8_0101 under `to_le_bytes()` yields [0x01, 0x01, 0xA8, 0xC0],
/// i.e. "1.1.168.192". If someone swaps to `to_be_bytes()` this would become
/// "192.168.1.1" — the test catches the regression.
#[test]
fn int_to_ipv4_byte_order_pinned() {
    assert_eq!(int_to_ipv4(0xC0A8_0101), "1.1.168.192");
}
