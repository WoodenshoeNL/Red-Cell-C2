//! Incoming Havoc Demon transport parsing for the teamserver.

mod ack;
pub(crate) mod callback;
mod init;
mod parser;

pub use ack::{build_init_ack, build_reconnect_ack};
pub use parser::DemonPacketParser;

use red_cell_common::AgentRecord;
use red_cell_common::crypto::CryptoError;
use red_cell_common::demon::{DemonCommand, DemonHeader, DemonProtocolError};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::TeamserverError;

/// Extension flags appended after the standard DEMON_INIT metadata fields.
///
/// When an agent appends a trailing `u32` (big-endian) after the `working_hours` field
/// in the encrypted init metadata, it is interpreted as a bitmask of extension flags.
/// Legacy Demon agents omit this field entirely, and the parser defaults to legacy mode.
///
/// Bit 0: request monotonic (non-legacy) AES-CTR mode.  When set, the teamserver
/// registers the agent with `legacy_ctr = false`, meaning the CTR block offset
/// advances across packets rather than resetting to 0 for each message.
pub const INIT_EXT_MONOTONIC_CTR: u32 = 1 << 0;

/// Bit 1: callback sequence-number protection.  When set, the agent prefixes every
/// encrypted callback payload with an 8-byte little-endian monotonically increasing
/// sequence number.  The teamserver enforces strict ordering and rejects replays.
///
/// Demon and Archon agents do not set this flag (frozen wire format).
/// Specter agents set this flag during `DEMON_INIT`.
pub const INIT_EXT_SEQ_PROTECTED: u32 = 1 << 1;

/// Server-secret configuration for HKDF session key derivation in `DEMON_INIT`.
///
/// This enum captures the three possible modes:
///
/// - **`None`** — no HKDF; raw agent keys are stored directly (Demon / legacy mode).
/// - **`Unversioned`** — a single secret; no version byte in the `DEMON_INIT` packet.
///   Used when the profile specifies `Demon { InitSecret = "..." }`.
/// - **`Versioned`** — a list of `(version, secret)` pairs; agents emit a 1-byte version
///   field in `DEMON_INIT` so the teamserver can select the correct secret for rotation.
///   Used when the profile specifies `Demon { InitSecrets = [...] }`.
///
/// Legacy Demon agents (C/ASM, frozen wire format) can only work with `None` or
/// `Unversioned`.  Versioned mode requires agent-side support (Specter / Archon).
#[derive(Clone, Debug)]
pub enum DemonInitSecretConfig {
    /// No HKDF — raw agent keys stored directly.
    None,
    /// Single unversioned secret — no version byte in `DEMON_INIT`.
    Unversioned(Zeroizing<Vec<u8>>),
    /// Multiple versioned secrets — requires 1-byte version field in `DEMON_INIT`.
    Versioned(Vec<(u8, Zeroizing<Vec<u8>>)>),
}

/// A decrypted Demon callback package parsed from an agent request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemonCallbackPackage {
    /// Raw command identifier.
    pub command_id: u32,
    /// Request identifier correlated with the originating task.
    pub request_id: u32,
    /// Raw package payload bytes.
    pub payload: Vec<u8>,
}

impl DemonCallbackPackage {
    /// Return the typed command identifier if it matches a known Havoc constant.
    pub fn command(&self) -> Result<DemonCommand, DemonProtocolError> {
        self.command_id.try_into()
    }
}

/// Parsed registration payload for a new Demon agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDemonInit {
    /// Outer transport header.
    pub header: DemonHeader,
    /// Request identifier supplied by the implant.
    pub request_id: u32,
    /// Fully parsed agent metadata, including the stored transport key/IV.
    pub agent: AgentRecord,
}

/// Normalized result of parsing a Demon request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedDemonPacket {
    /// First-time registration with metadata and session key material.
    Init(Box<ParsedDemonInit>),
    /// Re-registration from an already-known agent (same agent_id, fresh metadata).
    ///
    /// Occurs when a Demon agent restarts after a crash or kill-date reset and sends a
    /// full `DEMON_INIT` with the same `agent_id`.  The existing DB record is updated
    /// in-place rather than creating a duplicate row.
    ReInit(Box<ParsedDemonInit>),
    /// Reconnect probe from an already-registered agent.
    Reconnect {
        /// Outer transport header.
        header: DemonHeader,
        /// Request identifier supplied by the implant.
        request_id: u32,
    },
    /// One or more decrypted callback packages from an existing agent.
    Callback {
        /// Outer transport header.
        header: DemonHeader,
        /// Parsed callback packages in transmission order.
        packages: Vec<DemonCallbackPackage>,
    },
}

/// Errors returned while parsing incoming Demon traffic.
#[derive(Debug, Error)]
pub enum DemonParserError {
    /// The envelope or command stream did not match the Havoc wire format.
    #[error("invalid demon protocol data: {0}")]
    Protocol(#[from] DemonProtocolError),
    /// Stored or transmitted AES material could not be used.
    #[error("invalid agent crypto material: {0}")]
    Crypto(#[from] CryptoError),
    /// The parser could not update the shared agent registry.
    #[error("agent registry operation failed: {0}")]
    Registry(#[from] TeamserverError),
    /// Base64 decoding failed for a persisted key or IV.
    #[error("invalid base64 in stored {field} for agent 0x{agent_id:08X}: {message}")]
    InvalidStoredCryptoEncoding {
        /// Agent identifier associated with the invalid value.
        agent_id: u32,
        /// Stored field name.
        field: &'static str,
        /// Decoder error message.
        message: String,
    },
    /// The parser found malformed or incomplete metadata in a `DEMON_INIT` request.
    #[error("invalid demon init payload: {0}")]
    InvalidInit(&'static str),
    /// The agent negotiated legacy CTR mode but the operator has not opted in.
    ///
    /// Set `AllowLegacyCtr = true` in the `Demon` section of your profile to accept
    /// legacy Demon/Archon sessions, accepting the two-time-pad risk.
    #[error(
        "DEMON_INIT rejected: agent requires legacy CTR mode (no INIT_EXT_MONOTONIC_CTR flag) \
         and AllowLegacyCtr is not enabled in the profile — \
         set AllowLegacyCtr = true in the Demon block to accept insecure sessions"
    )]
    LegacyCtrNotAllowed,
    /// A `DEMON_INIT` re-registration was rejected because the supplied key material
    /// does not match the session keys on file for this agent.
    ///
    /// This prevents an attacker who knows a valid `agent_id` from injecting arbitrary
    /// key material to hijack an existing session.  A legitimate agent restart will
    /// present the same compiled-in (or HKDF-derived) key material.
    #[error(
        "DEMON_INIT re-registration rejected for agent 0x{agent_id:08X}: \
         key material does not match the existing session — possible key-rotation hijack"
    )]
    KeyMismatchOnReInit {
        /// The agent identifier that attempted the re-registration.
        agent_id: u32,
    },
}

#[cfg(test)]
mod tests;
