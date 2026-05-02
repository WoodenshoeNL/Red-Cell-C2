//! Shared test helpers for HTTP listener test modules.
//!
//! These are only compiled in `#[cfg(test)]` contexts; the file is gated by
//! the `#[cfg(test)] mod test_helpers;` declaration in `mod.rs`.

fn put_u32_be(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn put_u64_be(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn put_str_be(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    put_u32_be(buf, u32::try_from(bytes.len()).expect("str len fits in u32"));
    buf.extend_from_slice(bytes);
}

fn put_utf16_be(buf: &mut Vec<u8>, s: &str) {
    let utf16: Vec<u16> = s.encode_utf16().collect();
    let nbytes = utf16.len() * 2;
    put_u32_be(buf, u32::try_from(nbytes).expect("utf16 len fits in u32"));
    for unit in utf16 {
        buf.extend_from_slice(&unit.to_be_bytes());
    }
}

/// Build a minimal but valid ECDH init metadata blob.
///
/// Callers supply the fields that differ between test scenarios; all other
/// fields use the fixed values shared by both the handler and ecdh_dispatch
/// test suites.
pub(super) fn build_ecdh_metadata(
    agent_id: u32,
    hostname: &str,
    ip: &str,
    pid: u32,
    tid: u32,
    elevated: u32,
    ext_flags: u32,
) -> Vec<u8> {
    let mut m = Vec::new();
    put_u32_be(&mut m, agent_id);
    put_str_be(&mut m, hostname);
    put_str_be(&mut m, "operator");
    put_str_be(&mut m, "REDCELL");
    put_str_be(&mut m, ip);
    put_utf16_be(&mut m, "C:\\Windows\\explorer.exe");
    put_u32_be(&mut m, pid);
    put_u32_be(&mut m, tid);
    put_u32_be(&mut m, 512); // ppid
    put_u32_be(&mut m, 2); // arch
    put_u32_be(&mut m, elevated);
    put_u64_be(&mut m, 0x0040_1000); // base_address
    put_u32_be(&mut m, 10); // os_major
    put_u32_be(&mut m, 0); // os_minor
    put_u32_be(&mut m, 1); // os_product_type
    put_u32_be(&mut m, 0); // os_service_pack
    put_u32_be(&mut m, 22000); // os_build
    put_u32_be(&mut m, 9); // os_arch
    put_u32_be(&mut m, 15); // sleep_delay
    put_u32_be(&mut m, 20); // sleep_jitter
    put_u64_be(&mut m, 1_893_456_000); // kill_date
    m.extend_from_slice(&0_i32.to_be_bytes()); // working_hours
    put_u32_be(&mut m, ext_flags);
    m
}
