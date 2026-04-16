//! PE binary patching helpers for Demon payloads.
//!
//! Applies Havoc-compatible transformations to a freshly-compiled PE image:
//!   - MZ magic byte overrides
//!   - PE file header timestamp (`CompileTime`)
//!   - PE optional header `SizeOfImage`
//!   - Null-padded in-place string replacements

use red_cell_common::config::BinaryConfig;

use super::PayloadBuildError;
use super::formats::Architecture;

pub(super) fn patch_payload(
    mut bytes: Vec<u8>,
    architecture: Architecture,
    binary_patch: &BinaryConfig,
) -> Result<Vec<u8>, PayloadBuildError> {
    // Validate PE structure before applying any patches.  A failed build step
    // may produce an ELF, error output, or a truncated file; writing PE header
    // fields into such a binary would silently corrupt it with no diagnostic.
    const MZ_MAGIC: [u8; 2] = [0x4D, 0x5A];
    if bytes.len() < 2 || bytes[..2] != MZ_MAGIC {
        return Err(PayloadBuildError::InvalidRequest {
            message: "payload does not start with MZ magic bytes — not a valid PE binary"
                .to_owned(),
        });
    }
    // pe_offsets validates the PE\0\0 signature at the DOS header pointer (0x3C).
    pe_offsets(&bytes)?;

    let header = binary_patch.header.as_ref();
    let magic = match architecture {
        Architecture::X64 => header.and_then(|header| header.magic_mz_x64.as_deref()),
        Architecture::X86 => header.and_then(|header| header.magic_mz_x86.as_deref()),
    };
    if let Some(magic) = magic {
        let patch = magic.as_bytes();
        if patch.len() > bytes.len() {
            return Err(PayloadBuildError::InvalidRequest {
                message: "binary patch header is larger than the payload".to_owned(),
            });
        }
        bytes[..patch.len()].copy_from_slice(patch);
    }

    if let Some(header) = &binary_patch.header {
        if let Some(compile_time) = header.compile_time.as_deref() {
            let timestamp = parse_header_u32_field("CompileTime", compile_time)?;
            write_pe_file_header_timestamp(&mut bytes, timestamp)?;
        }

        let image_size = match architecture {
            Architecture::X64 => header.image_size_x64,
            Architecture::X86 => header.image_size_x86,
        };
        if let Some(image_size) = image_size {
            write_pe_optional_header_image_size(&mut bytes, image_size)?;
        }
    }

    let replacements = match architecture {
        Architecture::X64 => &binary_patch.replace_strings_x64,
        Architecture::X86 => &binary_patch.replace_strings_x86,
    };
    for (old, new) in replacements {
        let mut replacement = new.as_bytes().to_vec();
        if replacement.len() > old.len() {
            return Err(PayloadBuildError::InvalidRequest {
                message: format!("replacement value `{new}` is longer than search string `{old}`"),
            });
        }
        replacement.resize(old.len(), 0);
        bytes = replace_all(bytes, old.as_bytes(), &replacement);
    }

    Ok(bytes)
}

pub(super) fn parse_header_u32_field(
    field_name: &str,
    value: &str,
) -> Result<u32, PayloadBuildError> {
    let trimmed = value.trim();
    let parsed =
        if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
            u32::from_str_radix(hex, 16)
        } else {
            trimmed.parse::<u32>()
        };

    parsed.map_err(|_| PayloadBuildError::InvalidRequest {
        message: format!("{field_name} `{trimmed}` must be a valid u32 value"),
    })
}

fn pe_offsets(bytes: &[u8]) -> Result<(usize, usize), PayloadBuildError> {
    const DOS_HEADER_PE_POINTER_OFFSET: usize = 0x3C;
    const PE_SIGNATURE_SIZE: usize = 4;
    const FILE_HEADER_SIZE: usize = 20;

    if bytes.len() < DOS_HEADER_PE_POINTER_OFFSET + 4 {
        return Err(PayloadBuildError::InvalidRequest {
            message: "payload is too small to contain a PE header".to_owned(),
        });
    }

    let pe_offset = u32::from_le_bytes(
        bytes[DOS_HEADER_PE_POINTER_OFFSET..DOS_HEADER_PE_POINTER_OFFSET + 4].try_into().map_err(
            |_| PayloadBuildError::InvalidRequest {
                message: "payload is too small to contain a PE header".to_owned(),
            },
        )?,
    );
    let pe_offset = usize::try_from(pe_offset).map_err(|_| PayloadBuildError::InvalidRequest {
        message: "payload PE header offset does not fit in memory".to_owned(),
    })?;

    if bytes.len() < pe_offset + PE_SIGNATURE_SIZE + FILE_HEADER_SIZE {
        return Err(PayloadBuildError::InvalidRequest {
            message: "payload PE header is truncated".to_owned(),
        });
    }

    if bytes[pe_offset..pe_offset + PE_SIGNATURE_SIZE] != *b"PE\0\0" {
        return Err(PayloadBuildError::InvalidRequest {
            message: "payload does not contain a valid PE signature".to_owned(),
        });
    }

    let optional_header_offset = pe_offset + PE_SIGNATURE_SIZE + FILE_HEADER_SIZE;
    if bytes.len() < optional_header_offset + 60 {
        return Err(PayloadBuildError::InvalidRequest {
            message: "payload PE optional header is truncated".to_owned(),
        });
    }

    Ok((pe_offset, optional_header_offset))
}

fn write_pe_file_header_timestamp(
    bytes: &mut [u8],
    timestamp: u32,
) -> Result<(), PayloadBuildError> {
    let (pe_offset, _) = pe_offsets(bytes)?;
    let timestamp_offset = pe_offset + 8;
    bytes[timestamp_offset..timestamp_offset + 4].copy_from_slice(&timestamp.to_le_bytes());
    Ok(())
}

fn write_pe_optional_header_image_size(
    bytes: &mut [u8],
    image_size: u32,
) -> Result<(), PayloadBuildError> {
    let (_, optional_header_offset) = pe_offsets(bytes)?;
    let image_size_offset = optional_header_offset + 56;
    bytes[image_size_offset..image_size_offset + 4].copy_from_slice(&image_size.to_le_bytes());
    Ok(())
}

pub(super) fn replace_all(mut haystack: Vec<u8>, needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return haystack;
    }

    let mut offset = 0;
    while let Some(position) =
        haystack[offset..].windows(needle.len()).position(|window| window == needle)
    {
        let start = offset + position;
        haystack[start..start + needle.len()].copy_from_slice(replacement);
        offset = start + replacement.len();
    }
    haystack
}
