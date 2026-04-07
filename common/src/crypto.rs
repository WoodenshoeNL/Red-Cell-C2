//! Agent transport cryptography helpers.
//!
//! # AES-256-CTR session design
//!
//! The Havoc Demon protocol assigns each agent a fixed key+IV pair at registration
//! time.  Red Cell's **running session** maintains a monotonically advancing per-agent
//! CTR block offset: `decrypt_from_agent` and `encrypt_for_agent` (in the teamserver)
//! each advance `ctr_block_offset` in both the in-memory session state and the
//! database after every message.  This means successive messages consume distinct
//! portions of the keystream and do **not** suffer from the two-time-pad attack.
//!
//! ## Init-handshake helpers vs. running-session functions
//!
//! [`encrypt_agent_data`] and [`decrypt_agent_data`] are **Havoc-compatibility
//! helpers** that always start at block offset zero.  They are used exclusively
//! during the `DEMON_INIT` handshake (`parse_init_agent`), where the Demon itself
//! sends the first message at offset zero before any session counter has been
//! established.  They must **not** be used for regular callback processing.
//!
//! For all post-registration traffic, use the offset-aware variants
//! ([`encrypt_agent_data_at_offset`] / [`decrypt_agent_data_at_offset`]) and keep the
//! `block_offset` advancing — or use an AEAD scheme (e.g. AES-256-GCM) for new
//! transports that do not need Havoc wire-format compatibility.
//!
//! ## Residual keystream-reuse risk
//!
//! If an adversary records two ciphertexts `C1` and `C2` encrypted at the **same**
//! offset (e.g. both at offset zero), `C1 ⊕ C2 = P1 ⊕ P2`.  The advancing-offset
//! design in the running session prevents this; the init message at offset zero is the
//! only deliberate reset and is constrained to the handshake phase.
//!
//! See [`docs/operator-security.md`](../../../docs/operator-security.md) for
//! deployment guidance.

use aes::Aes256;
use cipher::{InvalidLength, KeyIvInit, StreamCipher, StreamCipherSeek};
use ctr::Ctr128BE;
use hkdf::Hkdf;
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Agent communication key length in bytes.
pub const AGENT_KEY_LENGTH: usize = 32;

/// Agent communication IV length in bytes.
pub const AGENT_IV_LENGTH: usize = 16;
const AGENT_CTR_BLOCK_LEN: u64 = 16;

/// Fresh AES key material assigned to an agent session.
///
/// The [`Debug`] implementation deliberately redacts key and IV bytes to
/// prevent accidental exposure of key material in logs or error chains.
///
/// Key material is automatically zeroed when this struct is dropped
/// via [`ZeroizeOnDrop`], preventing residual secrets on the stack.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct AgentCryptoMaterial {
    /// AES-256 session key.
    pub key: [u8; AGENT_KEY_LENGTH],
    /// Initial CTR counter block.
    pub iv: [u8; AGENT_IV_LENGTH],
}

impl std::fmt::Debug for AgentCryptoMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentCryptoMaterial")
            .field("key", &"[redacted]")
            .field("iv", &"[redacted]")
            .finish()
    }
}

/// Errors returned by agent transport crypto helpers.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// The supplied AES key does not have the required 32-byte length.
    #[error("invalid AES-256 key length: expected {expected} bytes, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    /// The supplied IV does not have the required 16-byte length.
    #[error("invalid AES IV length: expected {expected} bytes, got {actual}")]
    InvalidIvLength { expected: usize, actual: usize },
    /// The requested CTR block offset would overflow the cipher seek position.
    #[error("invalid AES-CTR block offset {block_offset}: seek position overflowed")]
    InvalidCtrOffset {
        /// The block offset that could not be represented safely.
        block_offset: u64,
    },
    /// Randomness for new key material could not be obtained from the OS.
    #[error("failed to generate agent key material: {0}")]
    RandomGeneration(String),
    /// The underlying cipher could not be constructed (unexpected key/IV length).
    #[error("cipher construction failed: {0}")]
    CipherConstruction(#[from] InvalidLength),
    /// HKDF expand step failed (output length too long for the hash function).
    #[error("HKDF expand failed: output length too long")]
    HkdfExpand,
    /// The version byte in a `DEMON_INIT` envelope does not match any configured secret.
    #[error("unknown init-secret version {version} — agent compiled with an unrecognised secret")]
    UnknownSecretVersion {
        /// The version byte the agent sent.
        version: u8,
    },
}

type AgentCtr = Ctr128BE<Aes256>;

/// Encrypt agent transport data with AES-256-CTR starting from the given IV.
///
/// Havoc uses a big-endian 128-bit counter on both the teamserver and Demon sides.
///
/// # Security — keystream reuse
///
/// This function **always** resets the AES-CTR counter to zero before encrypting.
/// When the same `key`+`iv` pair is used for multiple messages — as it is in the
/// Havoc Demon protocol — every message is encrypted with an **identical keystream**.
/// Two ciphertexts produced with the same key and IV satisfy `C1 ⊕ C2 = P1 ⊕ P2`,
/// so an adversary who can cause the agent to encrypt a known value can recover other
/// plaintexts (two-time-pad attack).
///
/// This limitation is **inherited from Havoc** and is preserved here for wire-format
/// compatibility.  When operating custom implants that do not need Havoc
/// compatibility, prefer [`encrypt_agent_data_at_offset`] with a monotonically
/// increasing `block_offset`, or use an AEAD scheme instead.  See the module-level
/// documentation for guidance.
pub fn encrypt_agent_data(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    encrypt_agent_data_at_offset(key, iv, 0, plaintext)
}

/// Encrypt agent transport data with AES-256-CTR starting from the given block offset.
pub fn encrypt_agent_data_at_offset(
    key: &[u8],
    iv: &[u8],
    block_offset: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    apply_agent_keystream(key, iv, block_offset, plaintext)
}

/// Decrypt agent transport data with AES-256-CTR starting from the given IV.
///
/// # Security — keystream reuse
///
/// Symmetric to [`encrypt_agent_data`]: the counter is reset to zero for every
/// call.  See that function's documentation for the two-time-pad limitation that
/// applies when decrypting Havoc Demon messages.
pub fn decrypt_agent_data(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    decrypt_agent_data_at_offset(key, iv, 0, ciphertext)
}

/// Decrypt agent transport data with AES-256-CTR starting from the given block offset.
pub fn decrypt_agent_data_at_offset(
    key: &[u8],
    iv: &[u8],
    block_offset: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    apply_agent_keystream(key, iv, block_offset, ciphertext)
}

/// Returns `true` if `key` exhibits a degenerate pattern indicating broken or
/// uninitialized key material.
///
/// Detected patterns:
/// - All-zero (uninitialized memory)
/// - All-0xFF
/// - Single repeating byte (e.g. `0xAA` repeated 32 times)
/// - Short repeating pattern of 2, 4, or 8 bytes (e.g. `[0xDE, 0xAD]` repeated)
///
/// The Demon agent generates keys via OS CSPRNG, so a degenerate key from a
/// legitimate agent indicates a broken RNG.  Both the DemonInit parser and the
/// COMMAND_CHECKIN handler use this predicate to reject such material before
/// it can be installed as a live session key.
#[must_use]
pub fn is_weak_aes_key(key: &[u8]) -> bool {
    has_short_repeating_pattern(key)
}

/// Returns `true` if `iv` exhibits a degenerate pattern indicating broken or
/// uninitialized key material.
///
/// Detected patterns are the same as [`is_weak_aes_key`]: all-zero, all-0xFF,
/// single repeating byte, or short repeating patterns of 2, 4, or 8 bytes.
///
/// Both the DemonInit parser and the COMMAND_CHECKIN handler reject this
/// condition for the same reason as [`is_weak_aes_key`].
#[must_use]
pub fn is_weak_aes_iv(iv: &[u8]) -> bool {
    has_short_repeating_pattern(iv)
}

/// Returns `true` if `data` consists entirely of a short repeating pattern,
/// indicating degenerate key or IV material.
///
/// Checked pattern lengths: 1, 2, 4, and 8 bytes.  The data length must be
/// at least twice the pattern length (i.e. the pattern must repeat at least
/// once) for it to be considered degenerate.
fn has_short_repeating_pattern(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }

    for pattern_len in [1, 2, 4, 8] {
        if data.len() < pattern_len * 2 || data.len() % pattern_len != 0 {
            continue;
        }
        let pattern = &data[..pattern_len];
        if data.chunks_exact(pattern_len).all(|chunk| chunk == pattern) {
            return true;
        }
    }

    false
}

/// Generate fresh per-agent AES-256-CTR key material.
pub fn generate_agent_crypto_material() -> Result<AgentCryptoMaterial, CryptoError> {
    let mut key = [0_u8; AGENT_KEY_LENGTH];
    let mut iv = [0_u8; AGENT_IV_LENGTH];

    getrandom::fill(&mut key).map_err(|error| CryptoError::RandomGeneration(error.to_string()))?;
    getrandom::fill(&mut iv).map_err(|error| CryptoError::RandomGeneration(error.to_string()))?;

    Ok(AgentCryptoMaterial { key, iv })
}

/// Derive session keys from agent-supplied key material and a server secret via HKDF-SHA256.
///
/// When a listener is configured with an `InitSecret`, the teamserver does not use the
/// agent-supplied AES key and IV directly for post-init session traffic.  Instead, the
/// raw agent material is mixed with the server secret through HKDF to produce the actual
/// session key and IV.  A compatible agent (Specter / Archon) must perform the same
/// derivation so both sides agree on the session keys.
///
/// This prevents an attacker who can reach the listener from choosing their own session
/// keys: without knowing the server secret they cannot derive the correct session material
/// and subsequent encrypted traffic will be unintelligible.
///
/// The HKDF extraction step uses the server secret as salt and the agent key as input
/// keying material.  Two separate `expand` calls with distinct `info` tags produce the
/// 32-byte session key and 16-byte session IV.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKeyLength`] if the agent-supplied key is not
/// [`AGENT_KEY_LENGTH`] bytes, or [`CryptoError::InvalidIvLength`] if the IV is not
/// [`AGENT_IV_LENGTH`] bytes.
pub fn derive_session_keys(
    agent_key: &[u8],
    agent_iv: &[u8],
    server_secret: &[u8],
) -> Result<AgentCryptoMaterial, CryptoError> {
    if agent_key.len() != AGENT_KEY_LENGTH {
        return Err(CryptoError::InvalidKeyLength {
            expected: AGENT_KEY_LENGTH,
            actual: agent_key.len(),
        });
    }
    if agent_iv.len() != AGENT_IV_LENGTH {
        return Err(CryptoError::InvalidIvLength {
            expected: AGENT_IV_LENGTH,
            actual: agent_iv.len(),
        });
    }

    // Concatenate agent key + IV as the input keying material so both values
    // contribute entropy to the derived output.  Use Zeroizing so the heap
    // allocation is wiped on drop, consistent with the zeroize discipline used
    // elsewhere in this module.
    let mut ikm = Zeroizing::new(Vec::with_capacity(AGENT_KEY_LENGTH + AGENT_IV_LENGTH));
    ikm.extend_from_slice(agent_key);
    ikm.extend_from_slice(agent_iv);

    let hk = Hkdf::<Sha256>::new(Some(server_secret), &ikm);

    let mut derived_key = [0u8; AGENT_KEY_LENGTH];
    hk.expand(b"red-cell-session-key", &mut derived_key).map_err(|_| CryptoError::HkdfExpand)?;

    let mut derived_iv = [0u8; AGENT_IV_LENGTH];
    hk.expand(b"red-cell-session-iv", &mut derived_iv).map_err(|_| CryptoError::HkdfExpand)?;

    Ok(AgentCryptoMaterial { key: derived_key, iv: derived_iv })
}

/// Derive session keys using a versioned server secret from a pre-shared list.
///
/// Looks up `version` in `secrets` (a slice of `(version_byte, secret_bytes)` pairs)
/// and calls [`derive_session_keys`] with the matching secret.
///
/// This is the multi-secret variant used for zero-downtime rotation: agents emit
/// a 1-byte version field in the `DEMON_INIT` envelope so the teamserver can select
/// the correct secret without requiring simultaneous recompilation.
///
/// # Errors
///
/// Returns [`CryptoError::UnknownSecretVersion`] if no entry in `secrets` matches
/// `version`.  Returns the same errors as [`derive_session_keys`] otherwise.
pub fn derive_session_keys_for_version(
    agent_key: &[u8],
    agent_iv: &[u8],
    version: u8,
    secrets: &[(u8, Vec<u8>)],
) -> Result<AgentCryptoMaterial, CryptoError> {
    let secret = secrets
        .iter()
        .find(|(v, _)| *v == version)
        .map(|(_, s)| s.as_slice())
        .ok_or(CryptoError::UnknownSecretVersion { version })?;
    derive_session_keys(agent_key, agent_iv, secret)
}

/// Hash a password with SHA3-256 and return the lowercase hex digest.
///
/// This matches the Havoc operator protocol which sends `Password` as a SHA3-256 hex string.
#[must_use]
pub fn hash_password_sha3(password: &str) -> String {
    use std::fmt::Write;

    let mut hasher = Sha3_256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    let mut hex_string = String::with_capacity(result.len() * 2);
    for byte in result {
        let _ = write!(hex_string, "{byte:02x}");
    }
    hex_string
}

// ── WebSocket frame HMAC helpers ─────────────────────────────────────────────

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use hmac::{Hmac, Mac};
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
    hk.expand(b"red-cell-ws-hmac-v1", &mut key)
        .expect("HKDF expand with 32-byte output must succeed");
    key
}

/// Wrap `message_json` in a [`WsEnvelope`] protected by HMAC-SHA256.
#[must_use]
pub fn seal_ws_frame(key: &[u8; 32], seq: u64, message_json: &str) -> WsEnvelope {
    let payload = BASE64_STANDARD.encode(message_json.as_bytes());
    let input = format!("{seq}:{payload}");
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
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
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(input.as_bytes());
    let expected = mac.finalize().into_bytes();

    // Decode provided tag — returns BadHmac for wrong length or non-hex chars.
    let provided = decode_hex_tag(&envelope.hmac)?;

    // Constant-time compare.
    if !constant_time_eq(&expected, &provided) {
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

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Return the number of AES-CTR blocks consumed by `len` bytes of transport data.
#[must_use]
pub fn ctr_blocks_for_len(len: usize) -> u64 {
    if len == 0 {
        return 0;
    }

    (len as u64).div_ceil(AGENT_CTR_BLOCK_LEN)
}

fn apply_agent_keystream(
    key: &[u8],
    iv: &[u8],
    block_offset: u64,
    input: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    validate_key_and_iv(key, iv)?;

    let mut output = input.to_vec();
    let mut cipher = AgentCtr::new_from_slices(key, iv)?;
    let seek_pos = block_offset
        .checked_mul(AGENT_CTR_BLOCK_LEN)
        .ok_or(CryptoError::InvalidCtrOffset { block_offset })?;
    cipher.seek(seek_pos);
    cipher.apply_keystream(&mut output);

    Ok(output)
}

fn validate_key_and_iv(key: &[u8], iv: &[u8]) -> Result<(), CryptoError> {
    if key.len() != AGENT_KEY_LENGTH {
        return Err(CryptoError::InvalidKeyLength {
            expected: AGENT_KEY_LENGTH,
            actual: key.len(),
        });
    }

    if iv.len() != AGENT_IV_LENGTH {
        return Err(CryptoError::InvalidIvLength { expected: AGENT_IV_LENGTH, actual: iv.len() });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use cipher::InvalidLength;
    use hex_literal::hex;

    use super::{
        AGENT_IV_LENGTH, AGENT_KEY_LENGTH, AgentCryptoMaterial, CryptoError, ctr_blocks_for_len,
        decrypt_agent_data, decrypt_agent_data_at_offset, derive_session_keys,
        derive_session_keys_for_version, encrypt_agent_data, encrypt_agent_data_at_offset,
        generate_agent_crypto_material, hash_password_sha3, is_weak_aes_iv, is_weak_aes_key,
    };

    #[test]
    fn is_weak_aes_key_detects_all_zero_key() {
        assert!(is_weak_aes_key(&[0u8; AGENT_KEY_LENGTH]));
    }

    #[test]
    fn is_weak_aes_key_accepts_nonzero_key() {
        let mut key = [0u8; AGENT_KEY_LENGTH];
        key[0] = 1;
        assert!(!is_weak_aes_key(&key));
    }

    #[test]
    fn is_weak_aes_key_rejects_empty_slice() {
        // An empty slice is not meaningfully "all-zero" — return false.
        assert!(!is_weak_aes_key(&[]));
    }

    #[test]
    fn is_weak_aes_iv_rejects_empty_slice() {
        assert!(!is_weak_aes_iv(&[]));
    }

    #[test]
    fn is_weak_aes_iv_detects_all_zero_iv() {
        assert!(is_weak_aes_iv(&[0u8; AGENT_IV_LENGTH]));
    }

    #[test]
    fn is_weak_aes_iv_accepts_nonzero_iv() {
        let mut iv = [0u8; AGENT_IV_LENGTH];
        iv[AGENT_IV_LENGTH - 1] = 0xff;
        assert!(!is_weak_aes_iv(&iv));
    }

    #[test]
    fn is_weak_aes_iv_empty_slice_is_not_weak() {
        assert!(!is_weak_aes_iv(&[]));
    }

    #[test]
    fn is_weak_aes_key_detects_all_0xff() {
        assert!(is_weak_aes_key(&[0xFF; AGENT_KEY_LENGTH]));
    }

    #[test]
    fn is_weak_aes_iv_detects_all_0xff() {
        assert!(is_weak_aes_iv(&[0xFF; AGENT_IV_LENGTH]));
    }

    #[test]
    fn is_weak_aes_key_detects_single_repeating_byte() {
        assert!(is_weak_aes_key(&[0xAA; AGENT_KEY_LENGTH]));
        assert!(is_weak_aes_key(&[0x42; AGENT_KEY_LENGTH]));
    }

    #[test]
    fn is_weak_aes_iv_detects_single_repeating_byte() {
        assert!(is_weak_aes_iv(&[0xAA; AGENT_IV_LENGTH]));
        assert!(is_weak_aes_iv(&[0x42; AGENT_IV_LENGTH]));
    }

    #[test]
    fn is_weak_aes_key_detects_two_byte_repeating_pattern() {
        // [0xDE, 0xAD] repeated 16 times = 32 bytes
        let key: Vec<u8> = [0xDE, 0xAD].iter().copied().cycle().take(AGENT_KEY_LENGTH).collect();
        assert!(is_weak_aes_key(&key));
    }

    #[test]
    fn is_weak_aes_iv_detects_two_byte_repeating_pattern() {
        let iv: Vec<u8> = [0xCA, 0xFE].iter().copied().cycle().take(AGENT_IV_LENGTH).collect();
        assert!(is_weak_aes_iv(&iv));
    }

    #[test]
    fn is_weak_aes_key_detects_four_byte_repeating_pattern() {
        // [0xDE, 0xAD, 0xBE, 0xEF] repeated 8 times = 32 bytes
        let key: Vec<u8> =
            [0xDE, 0xAD, 0xBE, 0xEF].iter().copied().cycle().take(AGENT_KEY_LENGTH).collect();
        assert!(is_weak_aes_key(&key));
    }

    #[test]
    fn is_weak_aes_iv_detects_four_byte_repeating_pattern() {
        let iv: Vec<u8> =
            [0xDE, 0xAD, 0xBE, 0xEF].iter().copied().cycle().take(AGENT_IV_LENGTH).collect();
        assert!(is_weak_aes_iv(&iv));
    }

    #[test]
    fn is_weak_aes_key_detects_eight_byte_repeating_pattern() {
        // 8-byte pattern repeated 4 times = 32 bytes
        let key: Vec<u8> = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
            .iter()
            .copied()
            .cycle()
            .take(AGENT_KEY_LENGTH)
            .collect();
        assert!(is_weak_aes_key(&key));
    }

    #[test]
    fn is_weak_aes_iv_detects_eight_byte_repeating_pattern() {
        // 8-byte pattern repeated 2 times = 16 bytes
        let iv: Vec<u8> = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
            .iter()
            .copied()
            .cycle()
            .take(AGENT_IV_LENGTH)
            .collect();
        assert!(is_weak_aes_iv(&iv));
    }

    #[test]
    fn is_weak_aes_key_accepts_non_repeating_pattern() {
        // A key with genuine variety should not be flagged
        let key: [u8; AGENT_KEY_LENGTH] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        assert!(!is_weak_aes_key(&key));
    }

    #[test]
    fn is_weak_aes_key_accepts_nearly_repeating_pattern() {
        // A 4-byte pattern that almost repeats but differs in the last chunk
        let mut key: Vec<u8> =
            [0xDE, 0xAD, 0xBE, 0xEF].iter().copied().cycle().take(AGENT_KEY_LENGTH).collect();
        key[AGENT_KEY_LENGTH - 1] = 0x00; // break the pattern
        assert!(!is_weak_aes_key(&key));
    }

    #[test]
    fn encrypt_agent_data_matches_reference_ciphertext() {
        let key = hex!(
            "603deb1015ca71be2b73aef0857d7781
             1f352c073b6108d72d9810a30914dff4"
        );
        let iv = hex!("000102030405060708090a0b0c0d0e0f");
        let plaintext = b"red-cell agent metadata";
        let expected_ciphertext = hex!(
            "c5da5e70975ce5b1b7919df285ba0f27
             1e2e93b8f2fd48"
        );

        let ciphertext =
            encrypt_agent_data(&key, &iv, plaintext).expect("reference encryption should succeed");

        assert_eq!(ciphertext, expected_ciphertext);
    }

    #[test]
    fn decrypt_agent_data_recovers_reference_plaintext() {
        let key = hex!(
            "603deb1015ca71be2b73aef0857d7781
             1f352c073b6108d72d9810a30914dff4"
        );
        let iv = hex!("000102030405060708090a0b0c0d0e0f");
        let ciphertext = hex!(
            "c5da5e70975ce5b1b7919df285ba0f27
             1e2e93b8f2fd48"
        );

        let plaintext = decrypt_agent_data(&key, &iv, &ciphertext)
            .expect("reference decryption should succeed");

        assert_eq!(plaintext, b"red-cell agent metadata");
    }

    #[test]
    fn encrypt_and_decrypt_round_trip() {
        let key = [0x41; AGENT_KEY_LENGTH];
        let iv = [0x24; AGENT_IV_LENGTH];
        let plaintext = b"\x00\x01\x02demon-tasking";

        let ciphertext =
            encrypt_agent_data(&key, &iv, plaintext).expect("round-trip encryption should succeed");
        let decrypted = decrypt_agent_data(&key, &iv, &ciphertext)
            .expect("round-trip decryption should succeed");

        assert_eq!(decrypted, plaintext);
        assert_ne!(ciphertext, plaintext);
    }

    #[test]
    fn encrypt_and_decrypt_round_trip_multi_block() {
        let key = [0x41; AGENT_KEY_LENGTH];
        let iv = [0x24; AGENT_IV_LENGTH];
        // 80 bytes = 5 AES blocks (16 bytes each), verifying multi-block CTR.
        let plaintext: Vec<u8> = (0..80).collect();

        let ciphertext =
            encrypt_agent_data(&key, &iv, &plaintext).expect("multi-block encrypt should succeed");
        assert_eq!(ciphertext.len(), plaintext.len());
        assert_ne!(ciphertext, plaintext);

        let decrypted =
            decrypt_agent_data(&key, &iv, &ciphertext).expect("multi-block decrypt should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_agent_data_rejects_invalid_iv_length() {
        let key = [0x11; AGENT_KEY_LENGTH];
        let ciphertext = [0x33; AGENT_IV_LENGTH];

        let error = decrypt_agent_data(&key, &[0x22; AGENT_IV_LENGTH - 1], &ciphertext)
            .expect_err("invalid IV length must fail decryption");

        assert!(matches!(
            error,
            CryptoError::InvalidIvLength { expected, actual }
                if expected == AGENT_IV_LENGTH && actual == AGENT_IV_LENGTH - 1
        ));
    }

    #[test]
    fn encrypt_agent_data_rejects_invalid_key_length() {
        let error = encrypt_agent_data(&[0_u8; 31], &[0_u8; AGENT_IV_LENGTH], b"abc")
            .expect_err("invalid key length must fail encryption");

        assert!(matches!(
            error,
            CryptoError::InvalidKeyLength { expected, actual }
                if expected == AGENT_KEY_LENGTH && actual == AGENT_KEY_LENGTH - 1
        ));
    }

    #[test]
    fn decrypt_agent_data_rejects_invalid_key_length() {
        let error =
            decrypt_agent_data(&[0x11; AGENT_KEY_LENGTH - 1], &[0x22; AGENT_IV_LENGTH], b"")
                .expect_err("invalid key length must fail decryption");

        assert!(matches!(
            error,
            CryptoError::InvalidKeyLength { expected, actual }
                if expected == AGENT_KEY_LENGTH && actual == AGENT_KEY_LENGTH - 1
        ));
    }

    #[test]
    fn encrypt_agent_data_preserves_empty_plaintext() {
        let ciphertext =
            encrypt_agent_data(&[0x41; AGENT_KEY_LENGTH], &[0x24; AGENT_IV_LENGTH], b"")
                .expect("empty plaintext encryption should succeed");

        assert!(ciphertext.is_empty());
    }

    #[test]
    fn generate_agent_crypto_material_returns_expected_sizes() {
        let material =
            generate_agent_crypto_material().expect("OS randomness should be available for tests");

        assert_eq!(material.key.len(), AGENT_KEY_LENGTH);
        assert_eq!(material.iv.len(), AGENT_IV_LENGTH);
        assert_ne!(material.key, [0_u8; AGENT_KEY_LENGTH]);
        assert_ne!(material.iv, [0_u8; AGENT_IV_LENGTH]);
        assert!(!is_weak_aes_iv(&material.iv));
    }

    #[test]
    fn hash_password_sha3_produces_known_digest() {
        let digest = hash_password_sha3("password1234");
        assert_eq!(digest.len(), 64);
        assert_eq!(digest, "2f7d3e77d0786c5d305c0afadd4c1a2a6869a3210956c963ad2420c52e797022");
    }

    #[test]
    fn hash_password_sha3_empty_input() {
        let digest = hash_password_sha3("");
        assert_eq!(digest.len(), 64);
        assert_eq!(digest, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    }

    #[test]
    fn hash_password_sha3_is_deterministic() {
        let first = hash_password_sha3("test-password");
        let second = hash_password_sha3("test-password");
        assert_eq!(first, second);
    }

    #[test]
    fn hash_password_sha3_handles_non_ascii_unicode() {
        // Multi-byte UTF-8: CJK ideograph, emoji, accented chars — verified against
        // Python hashlib.sha3_256 reference digests.
        let digest_cjk = hash_password_sha3("密码");
        assert_eq!(
            digest_cjk, "66855cb24193f8e5b6a310b6ba67509a7e0dfd71dbdda86f281d0cd0d17439bf",
            "CJK digest must match independent Python reference"
        );

        let digest_mixed = hash_password_sha3("pässwörd☕");
        assert_eq!(
            digest_mixed, "70d79f7947244428870bc5e3cc0844598ea5524189996ad9b1cd27629459a2a2",
            "mixed accented/emoji digest must match independent Python reference"
        );

        let digest_emoji = hash_password_sha3("🔑secret🔒");
        assert_eq!(digest_emoji.len(), 64);

        let digest_accent = hash_password_sha3("contraseña");
        assert_eq!(digest_accent.len(), 64);

        // All four must be distinct from each other and from ASCII.
        let digest_ascii = hash_password_sha3("password");
        let all = [&digest_cjk, &digest_mixed, &digest_emoji, &digest_accent, &digest_ascii];
        for (i, a) in all.iter().enumerate() {
            for (j, b) in all.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "distinct inputs must produce distinct digests");
                }
            }
        }
    }

    /// Verifies that visually identical strings in NFC vs NFD normalization produce
    /// different SHA3-256 digests.  This documents the expected behavior: `hash_password_sha3`
    /// hashes raw UTF-8 bytes without normalizing, so clients and teamserver must agree on
    /// normalization form (or skip it) to avoid locking out operators with Unicode passwords.
    #[test]
    fn hash_password_sha3_nfc_vs_nfd_produce_different_digests() {
        // U+00E4 'ä' (NFC, 2 UTF-8 bytes: c3 a4) vs U+0061 U+0308 'ä' (NFD, 3 UTF-8 bytes: 61 cc 88)
        let nfc = "\u{00E4}"; // ä precomposed
        let nfd = "\u{0061}\u{0308}"; // a + combining diaeresis

        // Sanity: both render as 'ä' but have different byte representations.
        assert_ne!(
            nfc.as_bytes(),
            nfd.as_bytes(),
            "NFC and NFD must have different byte sequences"
        );

        let hash_nfc = hash_password_sha3(nfc);
        let hash_nfd = hash_password_sha3(nfd);

        // Verified against Python hashlib.sha3_256 reference values.
        assert_eq!(
            hash_nfc, "eeacc3cbcb4d927171c6a503cd9ad5f5a9c094b9464d7c73a1a5b9c0e00dc089",
            "NFC 'ä' digest must match Python reference"
        );
        assert_eq!(
            hash_nfd, "5c31be24bdfa8f8e858e0f86d97b225c7de45061d2f3373e24ed87df0c54c471",
            "NFD 'ä' digest must match Python reference"
        );

        assert_ne!(
            hash_nfc, hash_nfd,
            "NFC and NFD forms of the same visual character must produce different digests"
        );
    }

    #[test]
    fn stateless_ctr_reuses_the_same_keystream_for_each_message() {
        let key = [0x41; AGENT_KEY_LENGTH];
        let iv = [0x24; AGENT_IV_LENGTH];
        let message = b"identical-message-body!!";

        let first = encrypt_agent_data(&key, &iv, message).expect("first encrypt");
        let second = encrypt_agent_data(&key, &iv, message).expect("second encrypt");

        assert_eq!(first, second, "Havoc resets AES-CTR with the base IV per message");
    }

    /// Reference vector for block offset 2, generated with Python's `cryptography`
    /// library (AES-256-CTR, big-endian 128-bit counter):
    ///
    /// ```python
    /// from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    /// key = bytes([0x42] * 32)
    /// iv  = bytes([0x01] * 16)
    /// # Counter for block 2: IV interpreted as big-endian u128, incremented by 2
    /// counter2 = (int.from_bytes(iv, 'big') + 2).to_bytes(16, 'big')
    /// cipher = Cipher(algorithms.AES(key), modes.CTR(counter2))
    /// enc = cipher.encryptor()
    /// ciphertext = enc.update(b"block-offset-two") + enc.finalize()
    /// # → da077ab4f03381afab09583c83b2b271
    /// ```
    #[test]
    fn encrypt_agent_data_at_offset_matches_known_reference_at_block_two() {
        let key = [0x42_u8; AGENT_KEY_LENGTH];
        let iv = [0x01_u8; AGENT_IV_LENGTH];
        let plaintext = b"block-offset-two";
        // Pre-computed with an independent Python reference (see doc comment above).
        let expected = hex!("da077ab4f03381afab09583c83b2b271");

        let ciphertext = encrypt_agent_data_at_offset(&key, &iv, 2, plaintext)
            .expect("encryption at block offset 2 should succeed");

        assert_eq!(
            ciphertext, expected,
            "ciphertext at block offset 2 must match the independent reference vector"
        );
    }

    #[test]
    fn decrypt_agent_data_at_offset_recovers_known_reference_at_block_two() {
        let key = [0x42_u8; AGENT_KEY_LENGTH];
        let iv = [0x01_u8; AGENT_IV_LENGTH];
        // Same reference ciphertext as encrypt_agent_data_at_offset_matches_known_reference_at_block_two.
        let ciphertext = hex!("da077ab4f03381afab09583c83b2b271");

        let plaintext = decrypt_agent_data_at_offset(&key, &iv, 2, &ciphertext)
            .expect("decryption at block offset 2 should succeed");

        assert_eq!(
            plaintext, b"block-offset-two",
            "decrypting the reference ciphertext at block offset 2 must recover the original plaintext"
        );
    }

    #[test]
    fn encrypt_agent_data_at_offset_changes_the_keystream() {
        let key = [0x51; AGENT_KEY_LENGTH];
        let iv = [0x34; AGENT_IV_LENGTH];
        let plaintext = b"offset transport payload";

        let base = encrypt_agent_data_at_offset(&key, &iv, 0, plaintext).expect("offset zero");
        let advanced = encrypt_agent_data_at_offset(&key, &iv, 3, plaintext).expect("offset three");

        assert_ne!(base, advanced);
        assert_eq!(
            decrypt_agent_data_at_offset(&key, &iv, 3, &advanced).expect("offset decrypt"),
            plaintext
        );
    }

    #[test]
    fn generate_agent_crypto_material_produces_unique_material_on_successive_calls() {
        let first = generate_agent_crypto_material().expect("first call should succeed");
        let second = generate_agent_crypto_material().expect("second call should succeed");

        assert_ne!(
            first.key, second.key,
            "two successive calls must not return the same session key"
        );
        assert_ne!(first.iv, second.iv, "two successive calls must not return the same session IV");
    }

    #[test]
    fn agent_crypto_material_debug_redacts_key_and_iv() {
        let material =
            AgentCryptoMaterial { key: [0xAA; AGENT_KEY_LENGTH], iv: [0xBB; AGENT_IV_LENGTH] };
        let debug_output = format!("{material:?}");

        assert!(
            debug_output.contains("[redacted]"),
            "Debug output must contain '[redacted]', got: {debug_output}"
        );
        assert!(!debug_output.contains("170"), "Debug output must not contain raw key byte values");
        assert!(!debug_output.contains("187"), "Debug output must not contain raw IV byte values");
        assert!(
            !debug_output.contains("0xAA") && !debug_output.contains("0xaa"),
            "Debug output must not contain hex key bytes"
        );
    }

    #[test]
    fn encrypt_agent_data_at_offset_rejects_overflowing_block_offset() {
        let key = [0x41; AGENT_KEY_LENGTH];
        let iv = [0x24; AGENT_IV_LENGTH];
        // block_offset * 16 overflows u64
        let overflow_offset = u64::MAX / 16 + 1;

        let error = encrypt_agent_data_at_offset(&key, &iv, overflow_offset, b"data")
            .expect_err("overflowing block offset must return an error");

        assert!(
            matches!(error, CryptoError::InvalidCtrOffset { block_offset } if block_offset == overflow_offset),
            "expected InvalidCtrOffset, got {error:?}"
        );
    }

    #[test]
    fn decrypt_agent_data_at_offset_rejects_overflowing_block_offset() {
        let key = [0x41; AGENT_KEY_LENGTH];
        let iv = [0x24; AGENT_IV_LENGTH];
        // block_offset * 16 overflows u64
        let overflow_offset = u64::MAX / 16 + 1;

        let error = decrypt_agent_data_at_offset(&key, &iv, overflow_offset, b"data")
            .expect_err("overflowing block offset must return an error");

        assert!(
            matches!(error, CryptoError::InvalidCtrOffset { block_offset } if block_offset == overflow_offset),
            "expected InvalidCtrOffset, got {error:?}"
        );
    }

    #[test]
    fn ctr_blocks_for_len_rounds_up_to_full_blocks() {
        assert_eq!(ctr_blocks_for_len(0), 0);
        assert_eq!(ctr_blocks_for_len(1), 1);
        assert_eq!(ctr_blocks_for_len(16), 1);
        assert_eq!(ctr_blocks_for_len(17), 2);
        assert_eq!(ctr_blocks_for_len(32), 2);
    }

    #[test]
    fn ctr_blocks_for_len_large_payload() {
        // 1 GiB payload = 2^30 bytes → 2^30 / 16 = 2^26 blocks.
        assert_eq!(ctr_blocks_for_len(1 << 30), 1 << 26);
        // Non-aligned: 2^30 + 1 byte rounds up.
        assert_eq!(ctr_blocks_for_len((1 << 30) + 1), (1 << 26) + 1);
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn ctr_blocks_for_len_near_usize_max() {
        // On 64-bit platforms `usize as u64` is lossless.
        // usize::MAX bytes → ceiling(usize::MAX / 16) blocks.
        let max_blocks = (u64::MAX).div_ceil(16);
        assert_eq!(ctr_blocks_for_len(usize::MAX), max_blocks);

        // usize::MAX - 15 is exactly aligned.
        let aligned = usize::MAX - 15;
        assert_eq!(ctr_blocks_for_len(aligned), aligned as u64 / 16);
    }

    #[test]
    fn encrypt_at_max_valid_block_offset_succeeds() {
        let key = [0x41; AGENT_KEY_LENGTH];
        let iv = [0x24; AGENT_IV_LENGTH];
        // Maximum block offset whose seek position (offset * 16) fits in u64.
        let max_offset = u64::MAX / 16;
        let plaintext = b"near-limit";

        let result = encrypt_agent_data_at_offset(&key, &iv, max_offset, plaintext);
        assert!(result.is_ok(), "max valid block offset must succeed: {result:?}");

        let ciphertext = result.expect("unwrap");
        let decrypted = decrypt_agent_data_at_offset(&key, &iv, max_offset, &ciphertext)
            .expect("round-trip at max valid offset");
        assert_eq!(decrypted, plaintext);
    }

    /// AES-256-CTR is a stream cipher **without authentication**: decrypting with the
    /// wrong key does not produce an error — it silently yields garbage.  This is a
    /// fundamental property of CTR mode and is security-critical for the Demon protocol:
    /// the protocol has no MAC or AEAD tag, so a key-agreement mismatch will not be
    /// caught at the crypto layer.  Instead, the teamserver will receive structurally
    /// invalid (garbled) agent data whose parser must reject it gracefully rather than
    /// treating random bytes as valid commands.
    #[test]
    fn ctr_mode_silently_produces_wrong_plaintext_with_wrong_key() {
        let key_a = [0xAA; AGENT_KEY_LENGTH];
        let key_b = [0xBB; AGENT_KEY_LENGTH];
        let iv = [0x01; AGENT_IV_LENGTH];
        let plaintext = b"demon-init-metadata-payload";

        let ciphertext = encrypt_agent_data(&key_a, &iv, plaintext)
            .expect("encryption with key A should succeed");

        // Decrypting with the wrong key must succeed (no error) …
        let wrong_plaintext = decrypt_agent_data(&key_b, &iv, &ciphertext)
            .expect("decryption with wrong key must not error");

        // … but the output must differ from the original plaintext.
        assert_ne!(
            wrong_plaintext.as_slice(),
            plaintext.as_slice(),
            "CTR decryption with the wrong key must produce different output, not the original plaintext"
        );

        // Sanity: the correct key still recovers the original.
        let correct_plaintext =
            decrypt_agent_data(&key_a, &iv, &ciphertext).expect("decryption with correct key");
        assert_eq!(correct_plaintext, plaintext);
    }

    #[test]
    fn crypto_error_invalid_key_length_display() {
        let error = CryptoError::InvalidKeyLength { expected: 32, actual: 31 };
        let message = error.to_string();
        assert!(
            message.contains("expected 32 bytes") && message.contains("got 31"),
            "InvalidKeyLength display must contain key tokens, got: {message}"
        );
    }

    #[test]
    fn crypto_error_invalid_iv_length_display() {
        let error = CryptoError::InvalidIvLength { expected: 16, actual: 8 };
        let message = error.to_string();
        assert!(
            message.contains("expected 16 bytes") && message.contains("got 8"),
            "InvalidIvLength display must contain key tokens, got: {message}"
        );
    }

    #[test]
    fn crypto_error_invalid_ctr_offset_display() {
        let error = CryptoError::InvalidCtrOffset { block_offset: 999 };
        let message = error.to_string();
        assert!(
            message.contains("999") && message.contains("overflowed"),
            "InvalidCtrOffset display must contain the offset and 'overflowed', got: {message}"
        );
    }

    #[test]
    fn crypto_error_cipher_construction_display() {
        let error = CryptoError::CipherConstruction(InvalidLength);
        let message = error.to_string();
        assert!(
            message.contains("cipher construction failed"),
            "CipherConstruction display must contain 'cipher construction failed', got: {message}"
        );
    }

    #[test]
    fn crypto_error_random_generation_display() {
        let error = CryptoError::RandomGeneration("entropy source unavailable".to_string());
        let message = error.to_string();
        assert!(
            message.contains("entropy source unavailable"),
            "RandomGeneration display must contain the inner message, got: {message}"
        );
    }

    #[test]
    fn encrypt_at_one_past_max_valid_block_offset_fails() {
        let key = [0x41; AGENT_KEY_LENGTH];
        let iv = [0x24; AGENT_IV_LENGTH];
        // One past the maximum valid offset: (u64::MAX / 16) + 1 overflows on seek.
        let overflow_offset = u64::MAX / 16 + 1;

        let error = encrypt_agent_data_at_offset(&key, &iv, overflow_offset, b"x")
            .expect_err("offset one past max must fail");
        assert!(
            matches!(error, CryptoError::InvalidCtrOffset { block_offset } if block_offset == overflow_offset),
        );
    }

    #[test]
    fn derive_session_keys_matches_external_hkdf_reference_vectors() {
        // Generated independently with a standalone Python HKDF-SHA256 implementation.
        let key = hex!(
            "603deb1015ca71be2b73aef0857d7781
             1f352c073b6108d72d9810a30914dff4"
        );
        let iv = hex!("000102030405060708090a0b0c0d0e0f");
        let alpha =
            derive_session_keys(&key, &iv, b"test-server-secret").expect("alpha derivation");
        assert_eq!(
            alpha.key,
            hex!("7e65607a2ea7519b7242db07dd15c013c10de12d22e225e6f3df3cc37485dd87")
        );
        assert_eq!(alpha.iv, hex!("a1c6229d5cfd281f2f917bb8e237d0dc"));

        let bravo =
            derive_session_keys(&key, &iv, b"test-server-secret-v2").expect("bravo derivation");
        assert_eq!(
            bravo.key,
            hex!("f8c5042675c1f26038b082fb587dfb86afe67230f8909f4962576765018999ec")
        );
        assert_eq!(bravo.iv, hex!("65414dcb1c427ca093a8857368d2a214"));
    }

    #[test]
    fn derive_session_keys_is_deterministic() {
        let key = [0x42; AGENT_KEY_LENGTH];
        let iv = [0x24; AGENT_IV_LENGTH];
        let secret = b"determinism-check";

        let first = derive_session_keys(&key, &iv, secret).expect("first derivation");
        let second = derive_session_keys(&key, &iv, secret).expect("second derivation");

        assert_eq!(first, second, "same inputs must produce identical output");
    }

    #[test]
    fn derive_session_keys_different_secrets_produce_different_keys() {
        let key = [0x42; AGENT_KEY_LENGTH];
        let iv = [0x24; AGENT_IV_LENGTH];

        let derived_a =
            derive_session_keys(&key, &iv, b"secret-a").expect("derivation with secret A");
        let derived_b =
            derive_session_keys(&key, &iv, b"secret-b").expect("derivation with secret B");

        assert_ne!(
            derived_a.key, derived_b.key,
            "different server secrets must produce different keys"
        );
    }

    #[test]
    fn derive_session_keys_different_agent_keys_produce_different_output() {
        let iv = [0x24; AGENT_IV_LENGTH];
        let secret = b"same-secret";

        let mut key_a = [0u8; AGENT_KEY_LENGTH];
        key_a[0] = 1;
        let mut key_b = [0u8; AGENT_KEY_LENGTH];
        key_b[0] = 2;

        let derived_a = derive_session_keys(&key_a, &iv, secret).expect("derivation A");
        let derived_b = derive_session_keys(&key_b, &iv, secret).expect("derivation B");

        assert_ne!(derived_a.key, derived_b.key);
    }

    #[test]
    fn derive_session_keys_rejects_invalid_key_length() {
        let error = derive_session_keys(&[0u8; 16], &[0u8; AGENT_IV_LENGTH], b"secret")
            .expect_err("short key should be rejected");

        assert!(matches!(error, CryptoError::InvalidKeyLength { expected: 32, actual: 16 }));
    }

    #[test]
    fn derive_session_keys_rejects_invalid_iv_length() {
        let error = derive_session_keys(&[0u8; AGENT_KEY_LENGTH], &[0u8; 8], b"secret")
            .expect_err("short IV should be rejected");

        assert!(matches!(error, CryptoError::InvalidIvLength { expected: 16, actual: 8 }));
    }

    #[test]
    fn derive_session_keys_output_is_usable_for_encryption() {
        let key = [0x42; AGENT_KEY_LENGTH];
        let iv = [0x24; AGENT_IV_LENGTH];
        let secret = b"round-trip-secret";

        let derived = derive_session_keys(&key, &iv, secret).expect("derivation");
        let plaintext = b"hello from derived keys";

        let ciphertext = encrypt_agent_data(&derived.key, &derived.iv, plaintext)
            .expect("encrypt with derived key");
        let recovered = decrypt_agent_data(&derived.key, &derived.iv, &ciphertext)
            .expect("decrypt with derived key");

        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn derive_session_keys_propagates_error_not_panics() {
        // Valid inputs must always succeed — this verifies that the replaced
        // `.expect()` calls are reachable and produce Ok results in the normal
        // case (i.e., no panic occurs and the result is properly returned).
        let key = [0x11; AGENT_KEY_LENGTH];
        let iv = [0x22; AGENT_IV_LENGTH];
        let secret = b"no-panic-check";

        let result = derive_session_keys(&key, &iv, secret);
        assert!(result.is_ok(), "valid inputs must succeed without panicking: {result:?}");
    }

    #[test]
    fn crypto_error_hkdf_expand_display() {
        let error = CryptoError::HkdfExpand;
        let message = error.to_string();
        assert!(
            message.contains("HKDF expand failed"),
            "HkdfExpand display must contain 'HKDF expand failed', got: {message}"
        );
    }

    // ── derive_session_keys_for_version ─────────────────────────────────────

    #[test]
    fn derive_session_keys_for_version_returns_same_as_derive_session_keys() {
        let key = [0x11; AGENT_KEY_LENGTH];
        let iv = [0x22; AGENT_IV_LENGTH];
        let secret = b"sixteen-byte-sec".to_vec();
        let secrets = vec![(1u8, secret.clone())];

        let versioned = derive_session_keys_for_version(&key, &iv, 1, &secrets)
            .expect("version 1 must be found");
        let direct = derive_session_keys(&key, &iv, &secret).expect("direct derive must succeed");

        assert_eq!(versioned.key, direct.key, "versioned key must match direct derivation");
        assert_eq!(versioned.iv, direct.iv, "versioned IV must match direct derivation");
    }

    #[test]
    fn derive_session_keys_for_version_unknown_version_returns_error() {
        let key = [0x11; AGENT_KEY_LENGTH];
        let iv = [0x22; AGENT_IV_LENGTH];
        let secrets = vec![(1u8, b"sixteen-byte-sec".to_vec())];

        let result = derive_session_keys_for_version(&key, &iv, 2, &secrets);
        assert!(
            matches!(result, Err(CryptoError::UnknownSecretVersion { version: 2 })),
            "unknown version must return UnknownSecretVersion, got: {result:?}"
        );
    }

    #[test]
    fn derive_session_keys_for_version_selects_correct_secret_from_list() {
        let key = [0x33; AGENT_KEY_LENGTH];
        let iv = [0x44; AGENT_IV_LENGTH];
        let secret1 = b"secret-version-1".to_vec();
        let secret2 = b"secret-version-2".to_vec();
        let secrets = vec![(1u8, secret1.clone()), (2u8, secret2.clone())];

        let derived1 = derive_session_keys_for_version(&key, &iv, 1, &secrets)
            .expect("version 1 must succeed");
        let derived2 = derive_session_keys_for_version(&key, &iv, 2, &secrets)
            .expect("version 2 must succeed");

        assert_ne!(
            derived1.key, derived2.key,
            "different secret versions must produce different session keys"
        );
    }

    #[test]
    fn derive_session_keys_for_version_empty_list_returns_error() {
        let key = [0x55; AGENT_KEY_LENGTH];
        let iv = [0x66; AGENT_IV_LENGTH];

        let result = derive_session_keys_for_version(&key, &iv, 0, &[]);
        assert!(
            matches!(result, Err(CryptoError::UnknownSecretVersion { version: 0 })),
            "empty secrets list must return UnknownSecretVersion, got: {result:?}"
        );
    }

    #[test]
    fn agent_crypto_material_zeroizes_on_drop() {
        use zeroize::Zeroize;

        let mut material =
            AgentCryptoMaterial { key: [0xAA; AGENT_KEY_LENGTH], iv: [0xBB; AGENT_IV_LENGTH] };

        // Explicit zeroize should clear the fields.
        material.zeroize();
        assert_eq!(material.key, [0u8; AGENT_KEY_LENGTH], "key must be zeroed after zeroize()");
        assert_eq!(material.iv, [0u8; AGENT_IV_LENGTH], "iv must be zeroed after zeroize()");
    }

    // --- decode_hex_tag / open_ws_frame / seal_ws_frame tests ---

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
