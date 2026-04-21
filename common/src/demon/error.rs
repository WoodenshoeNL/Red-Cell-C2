//! Error type for the Demon binary protocol.

use thiserror::Error;

/// Errors returned while encoding or decoding Demon protocol values.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DemonProtocolError {
    /// The provided byte buffer does not contain enough data for the requested field.
    #[error("buffer too short while reading {context}: expected {expected} bytes, got {actual}")]
    BufferTooShort {
        /// Description of the field being decoded.
        context: &'static str,
        /// Minimum number of bytes needed.
        expected: usize,
        /// Actual remaining bytes.
        actual: usize,
    },
    /// The provided packet length exceeds what fits in the 32-bit wire format.
    #[error("length overflow while encoding {context}: {length} bytes")]
    LengthOverflow {
        /// Description of the field being encoded.
        context: &'static str,
        /// Length that could not fit in `u32`.
        length: usize,
    },
    /// The Demon transport magic value did not match the Havoc protocol constant.
    #[error("invalid Demon magic value: expected 0x{expected:08x}, got 0x{actual:08x}")]
    InvalidMagic {
        /// Expected magic value.
        expected: u32,
        /// Observed magic value.
        actual: u32,
    },
    /// The declared packet size did not match the provided byte buffer.
    #[error("invalid Demon packet size: declared {declared} bytes, actual {actual} bytes")]
    SizeMismatch {
        /// Declared size from the header.
        declared: u32,
        /// Actual size from the buffer.
        actual: usize,
    },
    /// An integer value did not map to a known Havoc enum discriminant.
    #[error("unknown {kind} value: {value}")]
    UnknownEnumValue {
        /// Protocol enum type.
        kind: &'static str,
        /// Unknown raw wire value.
        value: u32,
    },
}
