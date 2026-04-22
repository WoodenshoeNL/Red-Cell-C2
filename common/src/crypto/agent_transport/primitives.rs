//! AES-256-CTR encrypt/decrypt primitives for Demon agent transport.
//!
//! Low-level functions used by the Havoc-compatible init-handshake and the
//! offset-aware running-session path.  All callers outside this crate should go
//! through the re-exports in the parent [`agent_transport`] module.

use aes::Aes256;
use cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use ctr::Ctr128BE;

use super::{AGENT_CTR_BLOCK_LEN, AGENT_IV_LENGTH, AGENT_KEY_LENGTH, CryptoError};

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

/// Return the number of AES-CTR blocks consumed by `len` bytes of transport data.
#[must_use]
pub fn ctr_blocks_for_len(len: usize) -> u64 {
    if len == 0 {
        return 0;
    }

    (len as u64).div_ceil(AGENT_CTR_BLOCK_LEN)
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
