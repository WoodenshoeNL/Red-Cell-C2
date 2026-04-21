//! Havoc Demon binary protocol types and serializers.

mod commands;
mod envelope;
mod error;
mod package;

pub use commands::*;
pub use envelope::*;
pub use error::*;
pub use package::*;

/// Transport magic value used by Havoc Demon packets.
pub const DEMON_MAGIC_VALUE: u32 = 0xDEAD_BEEF;

/// Minimum number of bytes required to parse a [`DemonEnvelope`].
///
/// A valid envelope must contain the full 12-byte [`DemonHeader`]
/// (size, magic, and agent_id fields).  Buffers shorter than this are
/// rejected by [`DemonEnvelope::from_bytes`] before any further
/// decoding is attempted.
pub const MIN_ENVELOPE_SIZE: usize = 12;
