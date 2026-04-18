//! Operator WebSocket frame integrity (HMAC-SHA256 over sequence + payload).

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Wire format for an HMAC-protected operator WebSocket frame.
///
/// The envelope wraps the original JSON payload with a monotonic sequence
/// number and an HMAC-SHA256 tag so that:
///
/// * **Integrity** – any tampering with `seq` or `payload` invalidates the tag.
/// * **Replay prevention** – the receiver rejects any frame whose `seq` is not
///   strictly greater than the last accepted `seq`.
///
/// # Wire encoding
///
/// ```json
/// { "seq": 0, "payload": "<base64 JSON>", "hmac": "<hex HMAC-SHA256>" }
/// ```
///
/// The HMAC input is the ASCII string `"{seq}:{payload}"` where `{payload}`
/// is the base64-encoded inner JSON.  Binding both fields to the tag prevents
/// an attacker from substituting a different `seq` value on a captured frame.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WsEnvelope {
    /// Monotonically increasing frame counter (per direction).
    pub seq: u64,
    /// Base64-encoded inner JSON message.
    pub payload: String,
    /// Lowercase hex HMAC-SHA256 over `"{seq}:{payload}"`.
    pub hmac: String,
}

/// Errors returned when opening (verifying) a [`WsEnvelope`].
#[derive(Debug)]
pub enum WsHmacError {
    /// The HMAC tag did not match the recomputed value.
    BadHmac,
    /// The frame's `seq` is not strictly greater than the last accepted `seq`.
    ReplayedSeq,
    /// The `payload` field is not valid standard base64.
    Base64Decode,
}

impl std::fmt::Display for WsHmacError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadHmac => write!(f, "HMAC tag mismatch"),
            Self::ReplayedSeq => write!(f, "replayed or out-of-order sequence number"),
            Self::Base64Decode => write!(f, "payload base64 decode failed"),
        }
    }
}

impl std::error::Error for WsHmacError {}

/// Derive the 32-byte per-session HMAC key from a session token string.
///
/// Uses HKDF-SHA256 with the fixed info label `b"red-cell-ws-hmac-v1"`.
#[must_use]
pub fn derive_ws_hmac_key(session_token: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, session_token.as_bytes());
    let mut key = [0u8; 32];
    // HKDF-SHA256 supports up to 255 × 32 = 8160 bytes output; 32 is always valid.
    let Ok(()) = hk.expand(b"red-cell-ws-hmac-v1", &mut key) else {
        unreachable!("HKDF-SHA256 expand to 32 bytes cannot fail");
    };
    key
}

/// Wrap `message_json` in a [`WsEnvelope`] protected by HMAC-SHA256.
#[must_use]
pub fn seal_ws_frame(key: &[u8; 32], seq: u64, message_json: &str) -> WsEnvelope {
    let payload = BASE64_STANDARD.encode(message_json.as_bytes());
    let input = format!("{seq}:{payload}");
    // HMAC accepts any key length — new_from_slice is infallible for Hmac<T>.
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        unreachable!("HMAC-SHA256 accepts any key length");
    };
    mac.update(input.as_bytes());
    let tag = mac.finalize().into_bytes();
    let hmac = tag.iter().fold(String::with_capacity(64), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    });
    WsEnvelope { seq, payload, hmac }
}

/// Verify and unwrap a [`WsEnvelope`], returning the inner JSON string.
///
/// `last_seen_seq` is the sequence number of the most recently accepted
/// frame in this direction.  Pass `None` if no frame has been accepted yet.
///
/// # Errors
///
/// Returns [`WsHmacError::BadHmac`] on tag mismatch, [`WsHmacError::ReplayedSeq`]
/// if the sequence number is not strictly increasing, or [`WsHmacError::Base64Decode`]
/// if the `payload` field is not valid base64.
pub fn open_ws_frame(
    key: &[u8; 32],
    envelope: &WsEnvelope,
    last_seen_seq: Option<u64>,
) -> Result<String, WsHmacError> {
    // Replay check first — cheapest.
    if let Some(last) = last_seen_seq {
        if envelope.seq <= last {
            return Err(WsHmacError::ReplayedSeq);
        }
    }

    // Recompute HMAC.
    let input = format!("{}:{}", envelope.seq, envelope.payload);
    // HMAC accepts any key length — new_from_slice is infallible for Hmac<T>.
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        unreachable!("HMAC-SHA256 accepts any key length");
    };
    mac.update(input.as_bytes());
    let expected = mac.finalize().into_bytes();

    // Decode provided tag — returns BadHmac for wrong length or non-hex chars.
    let provided = decode_hex_tag(&envelope.hmac)?;

    // Constant-time compare via `subtle` to prevent timing side-channels.
    if !bool::from(expected.ct_eq(&provided[..])) {
        return Err(WsHmacError::BadHmac);
    }

    // Decode payload.
    BASE64_STANDARD
        .decode(envelope.payload.as_bytes())
        .map_err(|_| WsHmacError::Base64Decode)
        .and_then(|b| String::from_utf8(b).map_err(|_| WsHmacError::Base64Decode))
}

/// Decode a lowercase hex string into a fixed 32-byte HMAC tag.
///
/// Returns [`WsHmacError::BadHmac`] if `hex` is not exactly 64 characters long
/// or contains any character outside `[0-9a-fA-F]`.
fn decode_hex_tag(hex: &str) -> Result<[u8; 32], WsHmacError> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return Err(WsHmacError::BadHmac);
    }
    let mut out = [0u8; 32];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        let hi = hex_nibble(pair[0]).ok_or(WsHmacError::BadHmac)?;
        let lo = hex_nibble(pair[1]).ok_or(WsHmacError::BadHmac)?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

/// Convert an ASCII hex digit to its numeric value.
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{WsHmacError, decode_hex_tag, open_ws_frame, seal_ws_frame};

    #[test]
    fn decode_hex_tag_accepts_valid_64_char_lowercase_hex() {
        let tag = "a".repeat(64);
        let result = decode_hex_tag(&tag);
        assert!(result.is_ok(), "valid 64-char hex must decode successfully");
        assert_eq!(result.unwrap(), [0xaa; 32]);
    }

    #[test]
    fn decode_hex_tag_accepts_uppercase_hex() {
        let tag = "A".repeat(64);
        let result = decode_hex_tag(&tag);
        assert!(result.is_ok(), "uppercase hex digits must be accepted");
        assert_eq!(result.unwrap(), [0xaa; 32]);
    }

    #[test]
    fn decode_hex_tag_rejects_string_too_short() {
        let tag = "ab".repeat(31); // 62 chars
        assert!(
            matches!(decode_hex_tag(&tag), Err(WsHmacError::BadHmac)),
            "63-char hex must be rejected"
        );
    }

    #[test]
    fn decode_hex_tag_rejects_string_too_long() {
        let tag = "ab".repeat(33); // 66 chars
        assert!(
            matches!(decode_hex_tag(&tag), Err(WsHmacError::BadHmac)),
            "66-char hex must be rejected"
        );
    }

    #[test]
    fn decode_hex_tag_rejects_non_hex_character() {
        // 'g' is not a valid hex digit
        let mut tag = "a".repeat(64);
        tag.replace_range(10..11, "g");
        assert!(
            matches!(decode_hex_tag(&tag), Err(WsHmacError::BadHmac)),
            "tag containing 'g' must be rejected"
        );
    }

    #[test]
    fn decode_hex_tag_rejects_non_ascii_bytes() {
        // Build a string that is 64 bytes but contains a non-ASCII character
        // by embedding a 2-byte UTF-8 sequence.  We do this at the byte level
        // so the length check (64 *chars*) still passes — but a non-hex byte
        // is present, which should trigger BadHmac rather than a panic.
        let mut bytes = b"ab".repeat(31).to_vec(); // 62 bytes of valid hex
        bytes.push(0xc3); // first byte of a 2-byte UTF-8 sequence (non-ASCII)
        bytes.push(0xa9); // second byte: together they form 'é' (U+00E9)
        // Total: 64 bytes, but bytes[62] and [63] are not ASCII hex digits.
        let tag = String::from_utf8(bytes).expect("valid UTF-8 for test string");
        assert_eq!(tag.len(), 64, "test precondition: tag is 64 bytes");
        assert!(
            matches!(decode_hex_tag(&tag), Err(WsHmacError::BadHmac)),
            "non-hex non-ASCII bytes must be rejected"
        );
    }

    #[test]
    fn seal_then_open_roundtrip() {
        let key = [0x42u8; 32];
        let msg = r#"{"type":"ping"}"#;
        let envelope = seal_ws_frame(&key, 1, msg);
        let recovered = open_ws_frame(&key, &envelope, None)
            .expect("valid sealed frame must open successfully");
        assert_eq!(recovered, msg);
    }

    #[test]
    fn open_ws_frame_rejects_tampered_hmac_non_hex() {
        let key = [0x42u8; 32];
        let mut envelope = seal_ws_frame(&key, 1, r#"{"type":"ping"}"#);
        // Replace the first two hex chars with 'zz' — non-hex, same length
        envelope.hmac.replace_range(0..2, "zz");
        assert!(
            matches!(open_ws_frame(&key, &envelope, None), Err(WsHmacError::BadHmac)),
            "non-hex tag must be rejected with BadHmac"
        );
    }

    #[test]
    fn open_ws_frame_rejects_truncated_hmac() {
        let key = [0x42u8; 32];
        let mut envelope = seal_ws_frame(&key, 1, r#"{"type":"ping"}"#);
        envelope.hmac.truncate(32); // only 32 chars instead of 64
        assert!(
            matches!(open_ws_frame(&key, &envelope, None), Err(WsHmacError::BadHmac)),
            "truncated tag must be rejected with BadHmac"
        );
    }

    #[test]
    fn open_ws_frame_rejects_replayed_seq() {
        let key = [0x42u8; 32];
        let envelope = seal_ws_frame(&key, 5, r#"{"type":"ping"}"#);
        assert!(
            matches!(open_ws_frame(&key, &envelope, Some(5)), Err(WsHmacError::ReplayedSeq)),
            "seq not strictly increasing must be rejected"
        );
    }

    #[test]
    fn open_ws_frame_rejects_wrong_key() {
        let key_a = [0x01u8; 32];
        let key_b = [0x02u8; 32];
        let envelope = seal_ws_frame(&key_a, 1, r#"{"type":"ping"}"#);
        assert!(
            matches!(open_ws_frame(&key_b, &envelope, None), Err(WsHmacError::BadHmac)),
            "wrong key must produce BadHmac"
        );
    }
}
