use super::*;

#[test]
fn output_format_parses_staged_shellcode() {
    let fmt = OutputFormat::parse("Windows Shellcode Staged")
        .expect("should parse Windows Shellcode Staged");
    assert_eq!(fmt, OutputFormat::StagedShellcode);
    assert_eq!(fmt.file_extension(), ".exe");
}

#[test]
fn output_format_parses_raw_shellcode() {
    let fmt =
        OutputFormat::parse("Windows Raw Shellcode").expect("should parse Windows Raw Shellcode");
    assert_eq!(fmt, OutputFormat::RawShellcode);
    assert_eq!(fmt.file_extension(), ".bin");
}

#[test]
fn output_format_parse_rejects_unknown_format() {
    let err = OutputFormat::parse("Windows Invalid Format")
        .expect_err("unknown format should be rejected");
    assert!(
        matches!(&err, PayloadBuildError::InvalidRequest { message }
            if message.contains("Windows Invalid Format")),
        "unexpected error: {err}"
    );
}
