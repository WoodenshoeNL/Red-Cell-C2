use super::super::PayloadBuildError;

/// Format a byte slice as a comma-separated list of hex literals suitable for
/// embedding in a C array initialiser via a `-D` define.
pub(in super::super) fn format_config_bytes(bytes: &[u8]) -> String {
    // No shell escaping needed: the compiler is invoked via Command::args() which
    // passes arguments directly to execvp, so commas do not need backslash-escaping.
    bytes.iter().map(|byte| format!("0x{byte:02x}")).collect::<Vec<_>>().join(",")
}

/// Validates a compiler `-D` define string before it is passed to the compiler.
///
/// A valid define has the form `NAME` or `NAME=value` where:
/// - `NAME` contains only ASCII alphanumeric characters and underscores and begins
///   with a letter or underscore.
/// - The entire string contains no whitespace (a space-containing define would be
///   embedded as one argument but is almost certainly a bug or injection attempt).
/// - The entire string does not begin with `-` to prevent injecting extra compiler
///   flags.
pub(in super::super) fn validate_define(define: &str) -> Result<(), PayloadBuildError> {
    if define.is_empty() {
        return Err(PayloadBuildError::InvalidRequest {
            message: "compiler define must not be empty".to_owned(),
        });
    }
    if define.starts_with('-') {
        return Err(PayloadBuildError::InvalidRequest {
            message: format!("compiler define `{define}` must not begin with `-`"),
        });
    }
    if define.chars().any(|c| c.is_whitespace()) {
        return Err(PayloadBuildError::InvalidRequest {
            message: format!("compiler define `{define}` must not contain whitespace"),
        });
    }
    let name = define.split_once('=').map_or(define, |(n, _)| n);
    if name.is_empty()
        || !name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(PayloadBuildError::InvalidRequest {
            message: format!(
                "compiler define name `{name}` must contain only ASCII alphanumeric characters \
                 and underscores and begin with a letter or underscore"
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_define_accepts_bare_name() {
        assert!(validate_define("SHELLCODE").is_ok());
        assert!(validate_define("TRANSPORT_HTTP").is_ok());
        assert!(validate_define("_PRIVATE").is_ok());
    }

    #[test]
    fn validate_define_accepts_name_equals_value() {
        assert!(validate_define("FOO=bar").is_ok());
        assert!(validate_define("CONFIG_BYTES={0x00,0x01}").is_ok());
        assert!(validate_define("LEVEL=1").is_ok());
    }

    #[test]
    fn validate_define_rejects_empty() {
        let err = validate_define("");
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message.contains("must not be empty")
        ));
    }

    #[test]
    fn validate_define_rejects_leading_dash() {
        let err = validate_define("-o /tmp/evil");
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message.contains("must not begin with `-`")
        ));
    }

    #[test]
    fn validate_define_rejects_whitespace_in_value() {
        let err = validate_define("FOO=bar baz");
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message.contains("must not contain whitespace")
        ));
    }

    #[test]
    fn validate_define_rejects_whitespace_in_name() {
        let err = validate_define("FOO BAR=1");
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message.contains("must not contain whitespace")
        ));
    }

    #[test]
    fn validate_define_rejects_name_starting_with_digit() {
        let err = validate_define("1FOO=1");
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message.contains("alphanumeric characters and underscores")
        ));
    }

    #[test]
    fn validate_define_rejects_name_with_hyphen() {
        let err = validate_define("FOO-BAR=1");
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message.contains("alphanumeric characters and underscores")
        ));
    }

    #[test]
    fn validate_define_rejects_embedded_flag_injection() {
        // Value contains a space followed by a flag — rejected due to whitespace rule
        let err = validate_define("FOO=1 -o /tmp/evil");
        assert!(matches!(
            err,
            Err(PayloadBuildError::InvalidRequest { message })
                if message.contains("must not contain whitespace")
        ));
    }

    #[test]
    fn format_config_bytes_formats_correctly() {
        assert_eq!(format_config_bytes(&[0x00, 0xFF, 0x42]), "0x00,0xff,0x42");
    }

    #[test]
    fn format_config_bytes_empty_input() {
        assert_eq!(format_config_bytes(&[]), "");
    }

    #[test]
    fn format_config_bytes_single_byte() {
        assert_eq!(format_config_bytes(&[0xAB]), "0xab");
    }
}
