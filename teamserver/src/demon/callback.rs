//! Callback package decoding and binary read helpers for Demon transport.

use red_cell_common::demon::{DemonCommand, DemonProtocolError};

use super::{DemonCallbackPackage, DemonParserError};

pub(crate) fn parse_callback_packages(
    first_command_id: u32,
    first_request_id: u32,
    decrypted: &[u8],
) -> Result<Vec<DemonCallbackPackage>, DemonParserError> {
    let mut offset = 0_usize;
    let first_payload =
        read_length_prefixed_bytes_be(decrypted, &mut offset, "first callback payload")?;
    let mut packages = vec![DemonCallbackPackage {
        command_id: first_command_id,
        request_id: first_request_id,
        payload: first_payload,
    }];

    while offset < decrypted.len() {
        let command_id = read_u32_be(decrypted, &mut offset, "callback command id")?;
        let request_id = read_u32_be(decrypted, &mut offset, "callback request id")?;
        let payload = read_length_prefixed_bytes_be(decrypted, &mut offset, "callback payload")?;
        packages.push(DemonCallbackPackage { command_id, request_id, payload });
    }

    Ok(packages)
}

/// Parse the Demon/Archon batched callback format used by `DEMON_COMMAND_GET_JOB`.
///
/// In this format every sub-package carries its own `(command_id, request_id,
/// length-prefixed payload)` triple — including the first one.  An empty body
/// (heartbeat with no queued output) is valid.
///
/// A synthetic `CommandGetJob` package with `outer_request_id` and an empty
/// payload is always prepended so the dispatcher knows to dequeue pending
/// tasks for the agent — this mirrors the role the outer GET_JOB header plays
/// in the original Havoc protocol.
pub(crate) fn parse_batched_callback_packages(
    outer_request_id: u32,
    decrypted: &[u8],
) -> Result<Vec<DemonCallbackPackage>, DemonParserError> {
    let mut packages = vec![DemonCallbackPackage {
        command_id: GET_JOB_COMMAND_ID,
        request_id: outer_request_id,
        payload: Vec::new(),
    }];
    let mut offset = 0_usize;
    while offset < decrypted.len() {
        let command_id = read_u32_be(decrypted, &mut offset, "batched callback command id")?;
        let request_id = read_u32_be(decrypted, &mut offset, "batched callback request id")?;
        let payload =
            read_length_prefixed_bytes_be(decrypted, &mut offset, "batched callback payload")?;
        packages.push(DemonCallbackPackage { command_id, request_id, payload });
    }
    Ok(packages)
}

const GET_JOB_COMMAND_ID: u32 = DemonCommand::CommandGetJob as u32;

pub(crate) fn read_fixed<const N: usize>(
    bytes: &[u8],
    offset: &mut usize,
    context: &'static str,
) -> Result<[u8; N], DemonParserError> {
    let remaining = bytes.len().saturating_sub(*offset);
    if remaining < N {
        return Err(
            DemonProtocolError::BufferTooShort { context, expected: N, actual: remaining }.into()
        );
    }

    let value: [u8; N] = bytes[*offset..*offset + N].try_into().map_err(|_| {
        DemonProtocolError::BufferTooShort { context, expected: N, actual: remaining }
    })?;
    *offset += N;
    Ok(value)
}

pub(crate) fn read_u32_be(
    bytes: &[u8],
    offset: &mut usize,
    context: &'static str,
) -> Result<u32, DemonParserError> {
    Ok(u32::from_be_bytes(read_fixed::<4>(bytes, offset, context)?))
}

pub(crate) fn read_u64_be(
    bytes: &[u8],
    offset: &mut usize,
    context: &'static str,
) -> Result<u64, DemonParserError> {
    Ok(u64::from_be_bytes(read_fixed::<8>(bytes, offset, context)?))
}

pub(crate) fn read_length_prefixed_bytes_be(
    bytes: &[u8],
    offset: &mut usize,
    context: &'static str,
) -> Result<Vec<u8>, DemonParserError> {
    let len = usize::try_from(read_u32_be(bytes, offset, context)?)
        .map_err(|_| DemonParserError::InvalidInit("length conversion overflow"))?;
    let remaining = bytes.len().saturating_sub(*offset);
    if remaining < len {
        return Err(DemonProtocolError::BufferTooShort {
            context,
            expected: len,
            actual: remaining,
        }
        .into());
    }

    let value = bytes[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(value)
}

pub(crate) fn read_length_prefixed_string_be(
    bytes: &[u8],
    offset: &mut usize,
    context: &'static str,
) -> Result<String, DemonParserError> {
    let raw = read_length_prefixed_bytes_be(bytes, offset, context)?;
    Ok(String::from_utf8_lossy(&raw).trim_end_matches('\0').to_owned())
}

pub(crate) fn read_length_prefixed_utf16_be(
    bytes: &[u8],
    offset: &mut usize,
    context: &'static str,
) -> Result<String, DemonParserError> {
    let raw = read_length_prefixed_bytes_be(bytes, offset, context)?;
    if raw.len() % 2 != 0 {
        return Err(DemonParserError::InvalidInit("utf16 field length must be even"));
    }

    let words: Vec<u16> =
        raw.chunks_exact(2).map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]])).collect();
    Ok(String::from_utf16_lossy(&words).trim_end_matches('\0').to_owned())
}
