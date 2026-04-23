/// Percent-encode a query-parameter value.
///
/// Safe characters (RFC 3986 unreserved plus `:` for ISO 8601 timestamps)
/// are left unchanged; everything else is `%XX`-encoded.
pub(crate) fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b':' => {
                out.push(byte as char)
            }
            b => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0xf) as usize] as char);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::percent_encode;

    #[test]
    fn percent_encode_leaves_safe_chars_unchanged() {
        assert_eq!(percent_encode("abc123-_.~:"), "abc123-_.~:");
    }

    #[test]
    fn percent_encode_encodes_space() {
        assert_eq!(percent_encode("hello world"), "hello%20world");
    }

    #[test]
    fn percent_encode_encodes_ampersand_and_equals() {
        assert_eq!(percent_encode("a=b&c=d"), "a%3Db%26c%3Dd");
    }

    #[test]
    fn percent_encode_iso8601_timestamp_unchanged() {
        assert_eq!(percent_encode("2026-03-21T12:00:00Z"), "2026-03-21T12:00:00Z");
    }

    #[test]
    fn percent_encode_until_timestamp_unchanged() {
        assert_eq!(percent_encode("2026-03-22T23:59:59Z"), "2026-03-22T23:59:59Z");
    }

    #[test]
    fn percent_encode_at_sign_in_operator_name() {
        let encoded = percent_encode("alice@example.com");
        assert!(encoded.contains('%'));
        assert!(!encoded.contains('@'));
    }
}
