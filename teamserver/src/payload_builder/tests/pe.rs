use super::*;
use red_cell_common::config::BinaryConfig;

fn sample_pe_payload() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x80 + 24 + 60];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3C..0x40].copy_from_slice(&(0x80_u32).to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    bytes
}

#[test]
fn patch_payload_updates_pe_header_fields() -> Result<(), Box<dyn std::error::Error>> {
    let patched = patch_payload(
        sample_pe_payload(),
        Architecture::X64,
        &BinaryConfig {
            header: Some(red_cell_common::config::HeaderConfig {
                magic_mz_x64: Some("MZ".to_owned()),
                magic_mz_x86: None,
                compile_time: Some("0x12345678".to_owned()),
                image_size_x64: Some(0x2000),
                image_size_x86: None,
            }),
            replace_strings_x64: std::collections::BTreeMap::new(),
            replace_strings_x86: std::collections::BTreeMap::new(),
        },
    )?;

    let pe_offset = 0x80;
    assert_eq!(&patched[..2], b"MZ");
    assert_eq!(u32::from_le_bytes(patched[pe_offset + 8..pe_offset + 12].try_into()?), 0x1234_5678);
    let optional_header_offset = pe_offset + 24;
    assert_eq!(
        u32::from_le_bytes(
            patched[optional_header_offset + 56..optional_header_offset + 60].try_into()?
        ),
        0x2000
    );
    Ok(())
}

#[test]
fn patch_payload_rejects_invalid_compile_time() {
    let error = patch_payload(
        sample_pe_payload(),
        Architecture::X64,
        &BinaryConfig {
            header: Some(red_cell_common::config::HeaderConfig {
                magic_mz_x64: None,
                magic_mz_x86: None,
                compile_time: Some("not-a-number".to_owned()),
                image_size_x64: None,
                image_size_x86: None,
            }),
            replace_strings_x64: std::collections::BTreeMap::new(),
            replace_strings_x86: std::collections::BTreeMap::new(),
        },
    )
    .expect_err("invalid compile time should fail");

    assert!(matches!(error, PayloadBuildError::InvalidRequest { .. }));
}

#[test]
fn patch_payload_rejects_truncated_pe_header() {
    let error = patch_payload(
        vec![0_u8; 8],
        Architecture::X64,
        &BinaryConfig {
            header: Some(red_cell_common::config::HeaderConfig {
                magic_mz_x64: None,
                magic_mz_x86: None,
                compile_time: Some("1".to_owned()),
                image_size_x64: None,
                image_size_x86: None,
            }),
            replace_strings_x64: std::collections::BTreeMap::new(),
            replace_strings_x86: std::collections::BTreeMap::new(),
        },
    )
    .expect_err("truncated pe should fail");

    assert!(matches!(error, PayloadBuildError::InvalidRequest { .. }));
}

#[test]
fn patch_payload_rejects_non_mz_magic() {
    // ELF magic — a non-PE binary that a failed cross-compile might produce.
    let mut elf_bytes = vec![0_u8; 0x80 + 24 + 60];
    elf_bytes[..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    let error = patch_payload(
        elf_bytes,
        Architecture::X64,
        &BinaryConfig {
            header: Some(red_cell_common::config::HeaderConfig {
                magic_mz_x64: None,
                magic_mz_x86: None,
                compile_time: Some("1".to_owned()),
                image_size_x64: None,
                image_size_x86: None,
            }),
            replace_strings_x64: std::collections::BTreeMap::new(),
            replace_strings_x86: std::collections::BTreeMap::new(),
        },
    )
    .expect_err("non-PE binary should be rejected");

    assert!(
        matches!(&error, PayloadBuildError::InvalidRequest { message }
            if message.contains("MZ magic")),
        "unexpected error: {error}"
    );
}

#[test]
fn patch_payload_rejects_empty_binary() {
    let error = patch_payload(
        vec![],
        Architecture::X64,
        &BinaryConfig {
            header: Some(red_cell_common::config::HeaderConfig {
                magic_mz_x64: None,
                magic_mz_x86: None,
                compile_time: Some("1".to_owned()),
                image_size_x64: None,
                image_size_x86: None,
            }),
            replace_strings_x64: std::collections::BTreeMap::new(),
            replace_strings_x86: std::collections::BTreeMap::new(),
        },
    )
    .expect_err("empty binary should be rejected");

    assert!(matches!(error, PayloadBuildError::InvalidRequest { .. }));
}

#[test]
fn patch_payload_rejects_invalid_pe_signature() {
    // MZ magic present but PE\0\0 signature is wrong.
    let mut bytes = vec![0_u8; 0x80 + 24 + 60];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3C..0x40].copy_from_slice(&(0x80_u32).to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"NE\0\0"); // wrong signature
    let error = patch_payload(
        bytes,
        Architecture::X64,
        &BinaryConfig {
            header: Some(red_cell_common::config::HeaderConfig {
                magic_mz_x64: None,
                magic_mz_x86: None,
                compile_time: Some("1".to_owned()),
                image_size_x64: None,
                image_size_x86: None,
            }),
            replace_strings_x64: std::collections::BTreeMap::new(),
            replace_strings_x86: std::collections::BTreeMap::new(),
        },
    )
    .expect_err("invalid PE signature should be rejected");

    assert!(matches!(error, PayloadBuildError::InvalidRequest { .. }));
}
