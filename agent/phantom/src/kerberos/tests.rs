use super::ccache::{CCache, parse_ccache};
use super::format::{
    enctype_name, format_keytabs, format_klist, format_timestamp, ticket_flags_str,
};
use super::keytab::parse_keytab;
use super::ops::build_ccache_blob;

/// Build a minimal ccache v4 binary blob for testing.
pub(super) fn make_test_ccache() -> Vec<u8> {
    let mut buf = Vec::new();
    // Version 0x0504
    buf.extend_from_slice(&0x0504u16.to_be_bytes());
    // Header length: 0
    buf.extend_from_slice(&0u16.to_be_bytes());
    // Default principal: name_type=1, 1 component, realm="EXAMPLE.COM", component="testuser"
    buf.extend_from_slice(&1u32.to_be_bytes()); // name_type
    buf.extend_from_slice(&1u32.to_be_bytes()); // num_components
    buf.extend_from_slice(&11u32.to_be_bytes()); // realm length
    buf.extend_from_slice(b"EXAMPLE.COM");
    buf.extend_from_slice(&8u32.to_be_bytes()); // component length
    buf.extend_from_slice(b"testuser");

    // One credential entry
    // Client principal
    buf.extend_from_slice(&1u32.to_be_bytes());
    buf.extend_from_slice(&1u32.to_be_bytes());
    buf.extend_from_slice(&11u32.to_be_bytes());
    buf.extend_from_slice(b"EXAMPLE.COM");
    buf.extend_from_slice(&8u32.to_be_bytes());
    buf.extend_from_slice(b"testuser");
    // Server principal: krbtgt/EXAMPLE.COM@EXAMPLE.COM
    buf.extend_from_slice(&1u32.to_be_bytes());
    buf.extend_from_slice(&2u32.to_be_bytes());
    buf.extend_from_slice(&11u32.to_be_bytes());
    buf.extend_from_slice(b"EXAMPLE.COM");
    buf.extend_from_slice(&6u32.to_be_bytes());
    buf.extend_from_slice(b"krbtgt");
    buf.extend_from_slice(&11u32.to_be_bytes());
    buf.extend_from_slice(b"EXAMPLE.COM");
    // Keyblock: enctype=18 (AES256), key length=0
    buf.extend_from_slice(&18u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    // Times: auth=1000, start=1000, end=37000, renew=73000
    buf.extend_from_slice(&1000u32.to_be_bytes());
    buf.extend_from_slice(&1000u32.to_be_bytes());
    buf.extend_from_slice(&37000u32.to_be_bytes());
    buf.extend_from_slice(&73000u32.to_be_bytes());
    // is_skey=0
    buf.push(0);
    // ticket_flags: forwardable + renewable + pre_authent = 0x40a0_0000
    buf.extend_from_slice(&0x40a0_0000u32.to_be_bytes());
    // Addresses: 0
    buf.extend_from_slice(&0u32.to_be_bytes());
    // Auth data: 0
    buf.extend_from_slice(&0u32.to_be_bytes());
    // Ticket: 4 bytes of dummy data
    buf.extend_from_slice(&4u32.to_be_bytes());
    buf.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    // Second ticket: 0
    buf.extend_from_slice(&0u32.to_be_bytes());

    buf
}

/// Build a minimal keytab v2 binary blob for testing.
pub(super) fn make_test_keytab() -> Vec<u8> {
    let mut buf = Vec::new();
    // Version 0x0502
    buf.extend_from_slice(&0x0502u16.to_be_bytes());

    // One entry — compute length first, then prepend.
    let mut entry = Vec::new();
    // num_components (u16) = 2
    entry.extend_from_slice(&2u16.to_be_bytes());
    // realm
    entry.extend_from_slice(&11u32.to_be_bytes());
    entry.extend_from_slice(b"EXAMPLE.COM");
    // component 1: "host"
    entry.extend_from_slice(&4u32.to_be_bytes());
    entry.extend_from_slice(b"host");
    // component 2: "server1.example.com"
    entry.extend_from_slice(&19u32.to_be_bytes());
    entry.extend_from_slice(b"server1.example.com");
    // name_type = 1
    entry.extend_from_slice(&1u32.to_be_bytes());
    // timestamp = 1700000000
    entry.extend_from_slice(&1_700_000_000u32.to_be_bytes());
    // kvno (u8) = 3
    entry.push(3);
    // enctype = 18 (AES256)
    entry.extend_from_slice(&18u16.to_be_bytes());
    // key length = 4
    entry.extend_from_slice(&4u16.to_be_bytes());
    // key data
    entry.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
    // trailing u32 kvno = 5 (overrides the u8 kvno)
    entry.extend_from_slice(&5u32.to_be_bytes());

    // Write entry length + entry
    buf.extend_from_slice(&(entry.len() as i32).to_be_bytes());
    buf.extend_from_slice(&entry);

    buf
}

#[test]
fn parse_ccache_v4_roundtrip() {
    let data = make_test_ccache();
    let cc = parse_ccache(&data, "/tmp/test_ccache").expect("parse failed");

    assert_eq!(cc.principal.realm, "EXAMPLE.COM");
    assert_eq!(cc.principal.components, vec!["testuser"]);
    assert_eq!(cc.source_path, "/tmp/test_ccache");
    assert_eq!(cc.credentials.len(), 1);

    let cred = &cc.credentials[0];
    assert_eq!(cred.client.to_string(), "testuser@EXAMPLE.COM");
    assert_eq!(cred.server.to_string(), "krbtgt/EXAMPLE.COM@EXAMPLE.COM");
    assert_eq!(cred.encryption_type, 18);
    assert_eq!(cred.auth_time, 1000);
    assert_eq!(cred.start_time, 1000);
    assert_eq!(cred.end_time, 37000);
    assert_eq!(cred.renew_till, 73000);
    assert_eq!(cred.ticket, vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn parse_ccache_rejects_wrong_version() {
    let mut data = make_test_ccache();
    // Change version to 0x0503
    data[0] = 0x05;
    data[1] = 0x03;
    assert!(parse_ccache(&data, "test").is_err());
}

#[test]
fn parse_ccache_empty_credentials() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0x0504u16.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    // Principal with 0 components
    buf.extend_from_slice(&1u32.to_be_bytes()); // name_type
    buf.extend_from_slice(&0u32.to_be_bytes()); // 0 components
    buf.extend_from_slice(&4u32.to_be_bytes()); // realm length
    buf.extend_from_slice(b"TEST");

    let cc = parse_ccache(&buf, "empty").expect("parse failed");
    assert_eq!(cc.principal.realm, "TEST");
    assert!(cc.credentials.is_empty());
}

#[test]
fn parse_keytab_v2_roundtrip() {
    let data = make_test_keytab();
    let kt = parse_keytab(&data, "/etc/krb5.keytab").expect("parse failed");

    assert_eq!(kt.entries.len(), 1);
    let e = &kt.entries[0];
    assert_eq!(e.principal.to_string(), "host/server1.example.com@EXAMPLE.COM");
    assert_eq!(e.kvno, 5); // trailing u32 overrides u8
    assert_eq!(e.enctype, 18);
    assert_eq!(e.timestamp, 1_700_000_000);
}

#[test]
fn parse_keytab_rejects_wrong_version() {
    let mut data = make_test_keytab();
    data[1] = 0x01; // 0x0501 instead of 0x0502
    assert!(parse_keytab(&data, "test").is_err());
}

#[test]
fn format_klist_no_caches() {
    let output = format_klist(&[]);
    assert!(output.contains("No Kerberos credential caches found"));
}

#[test]
fn format_klist_with_credentials() {
    let data = make_test_ccache();
    let cc = parse_ccache(&data, "/tmp/krb5cc_1000").expect("parse");
    let output = format_klist(&[cc]);

    assert!(output.contains("Credential cache: /tmp/krb5cc_1000"));
    assert!(output.contains("Default principal: testuser@EXAMPLE.COM"));
    assert!(output.contains("krbtgt/EXAMPLE.COM@EXAMPLE.COM"));
    assert!(output.contains("AES256_CTS_HMAC_SHA1_96"));
}

#[test]
fn format_keytabs_with_entries() {
    let data = make_test_keytab();
    let kt = parse_keytab(&data, "/etc/krb5.keytab").expect("parse");
    let output = format_keytabs(&[kt]);

    assert!(output.contains("Keytab: /etc/krb5.keytab"));
    assert!(output.contains("host/server1.example.com@EXAMPLE.COM"));
    assert!(output.contains("KVNO: 5"));
}

#[test]
fn build_ccache_blob_roundtrip() {
    let ticket = vec![0x30, 0x82, 0x01, 0x00]; // Dummy ASN.1
    let blob = build_ccache_blob(&ticket, "admin@CORP.LOCAL").expect("build");
    let cc = parse_ccache(&blob, "injected").expect("parse roundtrip");

    assert_eq!(cc.principal.realm, "CORP.LOCAL");
    assert_eq!(cc.principal.components, vec!["admin"]);
    assert_eq!(cc.credentials.len(), 1);
    assert_eq!(cc.credentials[0].ticket, ticket);
}

#[test]
fn build_ccache_blob_multi_component_principal() {
    let ticket = vec![0x01];
    let blob = build_ccache_blob(&ticket, "host/web.corp@CORP.LOCAL").expect("build");
    let cc = parse_ccache(&blob, "test").expect("parse");

    assert_eq!(cc.principal.components, vec!["host", "web.corp"]);
    assert_eq!(cc.principal.realm, "CORP.LOCAL");
}

#[test]
fn build_ccache_blob_rejects_no_realm() {
    assert!(build_ccache_blob(&[1], "admin").is_err());
}

#[test]
fn ticket_flags_str_covers_known_flags() {
    let flags = 0x40a0_0000; // forwardable + renewable + pre_authent
    let s = ticket_flags_str(flags);
    assert!(s.contains("forwardable"));
    assert!(s.contains("renewable"));
    assert!(s.contains("pre_authent"));
}

#[test]
fn ticket_flags_str_empty_flags() {
    let s = ticket_flags_str(0);
    assert!(s.contains("0x00000000"));
}

#[test]
fn enctype_name_known() {
    assert_eq!(enctype_name(18), "AES256_CTS_HMAC_SHA1_96");
    assert_eq!(enctype_name(23), "RC4_HMAC");
    assert_eq!(enctype_name(999), "UNKNOWN");
}

#[test]
fn format_timestamp_zero() {
    assert_eq!(format_timestamp(0), "(never)");
}

#[test]
fn format_timestamp_nonzero() {
    let s = format_timestamp(1_700_000_000);
    assert!(s.contains("2023")); // Nov 2023
    assert!(s.contains("UTC"));
}

#[test]
fn parse_keytab_with_deleted_entry() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&0x0502u16.to_be_bytes());

    // Deleted entry (negative length = -8)
    buf.extend_from_slice(&(-8i32).to_be_bytes());
    buf.extend_from_slice(&[0u8; 8]); // 8 bytes of hole

    // Real entry
    let mut entry = Vec::new();
    entry.extend_from_slice(&1u16.to_be_bytes()); // 1 component
    entry.extend_from_slice(&4u32.to_be_bytes());
    entry.extend_from_slice(b"TEST");
    entry.extend_from_slice(&4u32.to_be_bytes());
    entry.extend_from_slice(b"user");
    entry.extend_from_slice(&1u32.to_be_bytes()); // name_type
    entry.extend_from_slice(&0u32.to_be_bytes()); // timestamp
    entry.push(1); // kvno u8
    entry.extend_from_slice(&17u16.to_be_bytes()); // enctype
    entry.extend_from_slice(&0u16.to_be_bytes()); // key length

    buf.extend_from_slice(&(entry.len() as i32).to_be_bytes());
    buf.extend_from_slice(&entry);

    let kt = parse_keytab(&buf, "test").expect("parse");
    assert_eq!(kt.entries.len(), 1);
    assert_eq!(kt.entries[0].principal.to_string(), "user@TEST");
    assert_eq!(kt.entries[0].kvno, 1); // no trailing u32
}
