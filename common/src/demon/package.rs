//! Demon package encoding and message parsing.

use super::{DemonCommand, DemonProtocolError};

/// A single task or callback unit encoded inside a Demon message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemonPackage {
    /// Raw top-level command identifier.
    pub command_id: u32,
    /// Request identifier associated with the command.
    pub request_id: u32,
    /// Raw payload bytes for the command.
    pub payload: Vec<u8>,
}

impl DemonPackage {
    /// Construct a package for a typed command.
    pub fn new(command: DemonCommand, request_id: u32, payload: Vec<u8>) -> Self {
        Self { command_id: command.into(), request_id, payload }
    }

    /// Return the typed command identifier if the raw ID is known.
    pub fn command(&self) -> Result<DemonCommand, DemonProtocolError> {
        self.command_id.try_into()
    }

    /// Total encoded size of the package in bytes.
    pub fn encoded_len(&self) -> usize {
        12 + self.payload.len()
    }

    /// Validate that a payload length fits in the wire format's `u32` field.
    fn checked_payload_len(len: usize) -> Result<u32, DemonProtocolError> {
        u32::try_from(len).map_err(|_| DemonProtocolError::LengthOverflow {
            context: "Demon package payload",
            length: len,
        })
    }

    /// Serialize the package using Havoc's little-endian package format.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DemonProtocolError> {
        let payload_len = Self::checked_payload_len(self.payload.len())?;

        let mut bytes = Vec::with_capacity(self.encoded_len());
        bytes.extend_from_slice(&self.command_id.to_le_bytes());
        bytes.extend_from_slice(&self.request_id.to_le_bytes());
        bytes.extend_from_slice(&payload_len.to_le_bytes());
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }

    /// Parse a single package from bytes, requiring an exact-length buffer.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DemonProtocolError> {
        let (package, consumed) = Self::parse_from(bytes)?;
        if consumed != bytes.len() {
            return Err(DemonProtocolError::SizeMismatch {
                declared: u32::try_from(consumed).unwrap_or(u32::MAX),
                actual: bytes.len(),
            });
        }
        Ok(package)
    }

    pub(super) fn parse_from(bytes: &[u8]) -> Result<(Self, usize), DemonProtocolError> {
        let mut offset = 0_usize;
        let command_id = read_u32_le(bytes, &mut offset, "Demon package command id")?;
        let request_id = read_u32_le(bytes, &mut offset, "Demon package request id")?;
        let payload_len_u32 = read_u32_le(bytes, &mut offset, "Demon package payload length")?;
        let payload_len =
            usize::try_from(payload_len_u32).map_err(|_| DemonProtocolError::BufferTooShort {
                context: "Demon package payload",
                expected: usize::MAX,
                actual: bytes.len().saturating_sub(offset),
            })?;
        let payload = read_vec(bytes, &mut offset, payload_len, "Demon package payload")?;

        Ok((Self { command_id, request_id, payload }, offset))
    }
}

/// Sequence of little-endian packages carried by a single Demon request or response body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DemonMessage {
    /// Packages encoded in transmission order.
    pub packages: Vec<DemonPackage>,
}

impl DemonMessage {
    /// Construct a message from pre-built packages.
    pub fn new(packages: Vec<DemonPackage>) -> Self {
        Self { packages }
    }

    /// Serialize the message to the Havoc package stream format.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DemonProtocolError> {
        let total_len = self.packages.iter().map(DemonPackage::encoded_len).sum();
        let mut bytes = Vec::with_capacity(total_len);
        for package in &self.packages {
            bytes.extend_from_slice(&package.to_bytes()?);
        }
        Ok(bytes)
    }

    /// Parse a package stream until the buffer is exhausted.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DemonProtocolError> {
        let mut offset = 0_usize;
        let mut packages = Vec::new();

        while offset < bytes.len() {
            let (package, consumed) = DemonPackage::parse_from(&bytes[offset..])?;
            packages.push(package);
            offset += consumed;
        }

        Ok(Self { packages })
    }
}

fn read_u32_le(
    bytes: &[u8],
    offset: &mut usize,
    context: &'static str,
) -> Result<u32, DemonProtocolError> {
    let remaining = bytes.len().saturating_sub(*offset);
    if remaining < 4 {
        return Err(DemonProtocolError::BufferTooShort { context, expected: 4, actual: remaining });
    }

    let value = u32::from_le_bytes(bytes[*offset..*offset + 4].try_into().map_err(|_| {
        DemonProtocolError::BufferTooShort { context, expected: 4, actual: remaining }
    })?);
    *offset += 4;
    Ok(value)
}

fn read_vec(
    bytes: &[u8],
    offset: &mut usize,
    len: usize,
    context: &'static str,
) -> Result<Vec<u8>, DemonProtocolError> {
    let remaining = bytes.len().saturating_sub(*offset);
    if remaining < len {
        return Err(DemonProtocolError::BufferTooShort {
            context,
            expected: len,
            actual: remaining,
        });
    }

    let value = bytes[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{DemonPackage, DemonProtocolError};

    #[test]
    fn demon_package_to_bytes_rejects_payload_length_overflow() {
        let overflow_len = u32::MAX as usize + 1;
        let error = DemonPackage::checked_payload_len(overflow_len)
            .expect_err("payload length exceeding u32::MAX must fail");

        assert_eq!(
            error,
            DemonProtocolError::LengthOverflow {
                context: "Demon package payload",
                length: overflow_len,
            }
        );
    }

    #[test]
    fn demon_package_checked_payload_len_accepts_max_u32() {
        let len = u32::MAX as usize;
        let result = DemonPackage::checked_payload_len(len);
        assert_eq!(result.expect("unwrap"), u32::MAX);
    }
}
