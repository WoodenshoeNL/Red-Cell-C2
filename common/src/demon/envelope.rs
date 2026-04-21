//! Demon and Archon transport headers and envelopes.

use super::{DEMON_MAGIC_VALUE, DemonProtocolError, MIN_ENVELOPE_SIZE};

/// Fixed-size Demon transport header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DemonHeader {
    /// Packet size excluding the size field itself.
    pub size: u32,
    /// Protocol magic value.
    pub magic: u32,
    /// Agent identifier.
    pub agent_id: u32,
}

impl DemonHeader {
    /// Serialized header length in bytes.
    pub const SERIALIZED_LEN: usize = 12;

    /// Construct a header for the provided payload length.
    pub fn new(agent_id: u32, payload_len: usize) -> Result<Self, DemonProtocolError> {
        let size = payload_len.checked_add(8).ok_or(DemonProtocolError::LengthOverflow {
            context: "Demon header payload",
            length: payload_len,
        })?;
        let size = u32::try_from(size).map_err(|_| DemonProtocolError::LengthOverflow {
            context: "Demon header payload",
            length: payload_len,
        })?;

        Ok(Self { size, magic: DEMON_MAGIC_VALUE, agent_id })
    }

    /// Construct a header from raw field values without validating the magic constant.
    ///
    /// Used internally when converting from an [`ArchonHeader`] so the rest of the
    /// parsing pipeline can use the same `DemonHeader`-based API.
    #[must_use]
    pub fn from_raw(size: u32, magic: u32, agent_id: u32) -> Self {
        Self { size, magic, agent_id }
    }

    /// Serialize the header to its big-endian wire format.
    pub fn to_bytes(self) -> [u8; Self::SERIALIZED_LEN] {
        let mut bytes = [0_u8; Self::SERIALIZED_LEN];
        bytes[..4].copy_from_slice(&self.size.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.magic.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.agent_id.to_be_bytes());
        bytes
    }

    /// Parse a header from its big-endian wire format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DemonProtocolError> {
        if bytes.len() < Self::SERIALIZED_LEN {
            return Err(DemonProtocolError::BufferTooShort {
                context: "Demon header",
                expected: Self::SERIALIZED_LEN,
                actual: bytes.len(),
            });
        }

        let size = u32::from_be_bytes(bytes[0..4].try_into().map_err(|_| {
            DemonProtocolError::BufferTooShort {
                context: "Demon packet size",
                expected: 4,
                actual: bytes.len(),
            }
        })?);
        let magic = u32::from_be_bytes(bytes[4..8].try_into().map_err(|_| {
            DemonProtocolError::BufferTooShort {
                context: "Demon packet magic",
                expected: 4,
                actual: bytes.len().saturating_sub(4),
            }
        })?);
        if magic != DEMON_MAGIC_VALUE {
            return Err(DemonProtocolError::InvalidMagic {
                expected: DEMON_MAGIC_VALUE,
                actual: magic,
            });
        }

        let agent_id = u32::from_be_bytes(bytes[8..12].try_into().map_err(|_| {
            DemonProtocolError::BufferTooShort {
                context: "Demon packet agent id",
                expected: 4,
                actual: bytes.len().saturating_sub(8),
            }
        })?);

        Ok(Self { size, magic, agent_id })
    }
}

/// Full transport packet consisting of a big-endian header and raw payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemonEnvelope {
    /// Fixed transport header.
    pub header: DemonHeader,
    /// Raw packet payload following the 12-byte header.
    pub payload: Vec<u8>,
}

impl DemonEnvelope {
    /// Create a transport packet for an agent and payload.
    pub fn new(agent_id: u32, payload: Vec<u8>) -> Result<Self, DemonProtocolError> {
        let header = DemonHeader::new(agent_id, payload.len())?;
        Ok(Self { header, payload })
    }

    /// Serialize the packet to the wire format used by the Demon transport.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(DemonHeader::SERIALIZED_LEN + self.payload.len());
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    /// Parse a transport packet from the wire format used by the Demon transport.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DemonProtocolError> {
        if bytes.len() < MIN_ENVELOPE_SIZE {
            return Err(DemonProtocolError::BufferTooShort {
                context: "DemonEnvelope",
                expected: MIN_ENVELOPE_SIZE,
                actual: bytes.len(),
            });
        }
        let header = DemonHeader::from_bytes(bytes)?;
        let declared =
            usize::try_from(header.size).map_err(|_| DemonProtocolError::SizeMismatch {
                declared: header.size,
                actual: bytes.len().saturating_sub(4),
            })?;
        let actual = bytes.len().saturating_sub(4);
        if declared != actual {
            return Err(DemonProtocolError::SizeMismatch { declared: header.size, actual });
        }

        Ok(Self { header, payload: bytes[DemonHeader::SERIALIZED_LEN..].to_vec() })
    }
}

/// Fixed-size Archon transport header with the new field order.
///
/// The Archon wire layout differs from Demon's to eliminate the shared
/// `0xDEADBEEF` fingerprint: agent\_id is placed before magic so the teamserver
/// can look up the expected per-agent magic before decrypting the payload.
///
/// ```text
/// offset  size  field
/// 0       4     size      — packet length excluding this field (big-endian u32)
/// 4       4     agent_id  — Archon session identifier (big-endian u32)
/// 8       4     magic     — per-build random value, never 0xDEADBEEF (big-endian u32)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchonHeader {
    /// Packet size excluding the size field itself.
    pub size: u32,
    /// Agent identifier (at bytes 4–7, before magic).
    pub agent_id: u32,
    /// Per-build magic value (at bytes 8–11).
    pub magic: u32,
}

impl ArchonHeader {
    /// Serialized header length in bytes.
    pub const SERIALIZED_LEN: usize = 12;

    /// Serialize the header to its big-endian wire format.
    pub fn to_bytes(self) -> [u8; Self::SERIALIZED_LEN] {
        let mut bytes = [0_u8; Self::SERIALIZED_LEN];
        bytes[..4].copy_from_slice(&self.size.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.agent_id.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.magic.to_be_bytes());
        bytes
    }

    /// Parse a header from its big-endian wire format.
    ///
    /// The magic value is read but **not** validated against any constant here —
    /// per-agent magic validation is the caller's responsibility.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DemonProtocolError> {
        if bytes.len() < Self::SERIALIZED_LEN {
            return Err(DemonProtocolError::BufferTooShort {
                context: "Archon header",
                expected: Self::SERIALIZED_LEN,
                actual: bytes.len(),
            });
        }
        let size = u32::from_be_bytes(bytes[0..4].try_into().map_err(|_| {
            DemonProtocolError::BufferTooShort {
                context: "Archon packet size",
                expected: 4,
                actual: bytes.len(),
            }
        })?);
        let agent_id = u32::from_be_bytes(bytes[4..8].try_into().map_err(|_| {
            DemonProtocolError::BufferTooShort {
                context: "Archon packet agent_id",
                expected: 4,
                actual: bytes.len().saturating_sub(4),
            }
        })?);
        let magic = u32::from_be_bytes(bytes[8..12].try_into().map_err(|_| {
            DemonProtocolError::BufferTooShort {
                context: "Archon packet magic",
                expected: 4,
                actual: bytes.len().saturating_sub(8),
            }
        })?);
        Ok(Self { size, agent_id, magic })
    }

    /// Return `true` if the magic matches the expected per-agent value.
    #[must_use]
    pub fn magic_matches(&self, expected: u32) -> bool {
        self.magic == expected
    }
}

/// Full Archon transport packet: header + raw payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchonEnvelope {
    /// Fixed transport header.
    pub header: ArchonHeader,
    /// Raw packet payload following the 12-byte header.
    pub payload: Vec<u8>,
}

impl ArchonEnvelope {
    /// Parse a transport packet from the Archon wire format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DemonProtocolError> {
        if bytes.len() < ArchonHeader::SERIALIZED_LEN {
            return Err(DemonProtocolError::BufferTooShort {
                context: "ArchonEnvelope",
                expected: ArchonHeader::SERIALIZED_LEN,
                actual: bytes.len(),
            });
        }
        let header = ArchonHeader::from_bytes(bytes)?;
        let declared =
            usize::try_from(header.size).map_err(|_| DemonProtocolError::SizeMismatch {
                declared: header.size,
                actual: bytes.len().saturating_sub(4),
            })?;
        let actual = bytes.len().saturating_sub(4);
        if declared != actual {
            return Err(DemonProtocolError::SizeMismatch { declared: header.size, actual });
        }
        Ok(Self { header, payload: bytes[ArchonHeader::SERIALIZED_LEN..].to_vec() })
    }

    /// Serialize the packet to the Archon wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ArchonHeader::SERIALIZED_LEN + self.payload.len());
        bytes.extend_from_slice(&self.header.to_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }

    /// Construct an Archon envelope for an agent.
    ///
    /// The `magic` parameter must be the per-build magic injected into the
    /// Archon binary at compile time.
    pub fn new(agent_id: u32, magic: u32, payload: Vec<u8>) -> Result<Self, DemonProtocolError> {
        let size = payload.len().checked_add(8).ok_or(DemonProtocolError::LengthOverflow {
            context: "Archon envelope payload",
            length: payload.len(),
        })?;
        let size = u32::try_from(size).map_err(|_| DemonProtocolError::LengthOverflow {
            context: "Archon envelope payload",
            length: payload.len(),
        })?;
        Ok(Self { header: ArchonHeader { size, agent_id, magic }, payload })
    }
}
