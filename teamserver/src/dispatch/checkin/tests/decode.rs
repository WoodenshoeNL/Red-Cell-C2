use super::super::decode_working_hours;

#[test]
fn decode_working_hours_zero_returns_none() {
    assert_eq!(decode_working_hours(0u32), None);
}

#[test]
fn decode_working_hours_nonzero_returns_some() {
    assert_eq!(decode_working_hours(0b101010u32), Some(42i32));
}

#[test]
fn decode_working_hours_high_bit_set_preserves_sign() {
    // 0x8000_0000 as u32 → i32::MIN when reinterpreted via big-endian bytes.
    assert_eq!(decode_working_hours(0x8000_0000u32), Some(i32::MIN));
}
