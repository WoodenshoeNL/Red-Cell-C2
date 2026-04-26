//! Error types and exit-code constants for `red-cell-cli`.
//!
//! Exit codes follow the documented contract:
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0    | Success |
//! | 1    | General / argument error |
//! | 2    | Not found |
//! | 3    | Auth failure (bad token, insufficient role) |
//! | 4    | Server unreachable |
//! | 5    | Timeout |
//! | 6    | Rate limited (HTTP 429) |

use thiserror::Error;

/// Process exit code: success.
pub const EXIT_SUCCESS: i32 = 0;
/// Process exit code: general / argument error.
pub const EXIT_GENERAL: i32 = 1;
/// Process exit code: resource not found.
pub const EXIT_NOT_FOUND: i32 = 2;
/// Process exit code: authentication or authorisation failure.
pub const EXIT_AUTH_FAILURE: i32 = 3;
/// Process exit code: server unreachable.
pub const EXIT_SERVER_UNREACHABLE: i32 = 4;
/// Process exit code: request timed out.
pub const EXIT_TIMEOUT: i32 = 5;
/// Process exit code: rate limited by the server (HTTP 429).
pub const EXIT_RATE_LIMITED: i32 = 6;

/// Machine-readable error codes emitted on stderr.
pub const ERROR_CODE_GENERAL: &str = "ERROR";
/// Machine-readable error code for missing/unknown resource.
pub const ERROR_CODE_NOT_FOUND: &str = "NOT_FOUND";
/// Machine-readable error code for authentication/authorisation failure.
pub const ERROR_CODE_AUTH_FAILURE: &str = "AUTH_FAILURE";
/// Machine-readable error code for connectivity failure.
pub const ERROR_CODE_UNREACHABLE: &str = "UNREACHABLE";
/// Machine-readable error code for timeout.
pub const ERROR_CODE_TIMEOUT: &str = "TIMEOUT";
/// Machine-readable error code for invalid argument combination.
pub const ERROR_CODE_INVALID_ARGS: &str = "INVALID_ARGS";
/// Machine-readable error code for unexpected server-side errors.
pub const ERROR_CODE_SERVER_ERROR: &str = "SERVER_ERROR";
/// Machine-readable error code for features not yet available.
pub const ERROR_CODE_UNSUPPORTED: &str = "UNSUPPORTED";
/// Machine-readable error code for an in-process serialization failure (serde_json).
pub const ERROR_CODE_SERIALIZE_FAILED: &str = "SERIALIZE_FAILED";
/// Machine-readable error code for a write failure on stdout/stderr (e.g. broken pipe).
pub const ERROR_CODE_IO_WRITE_FAILED: &str = "IO_WRITE_FAILED";
/// Machine-readable error code for server-side rate limiting (HTTP 429).
pub const ERROR_CODE_RATE_LIMITED: &str = "RATE_LIMITED";
/// Machine-readable error code for an unknown session-mode `cmd` (local validation).
pub const ERROR_CODE_UNKNOWN_COMMAND: &str = "UNKNOWN_COMMAND";
/// Machine-readable error code for a profile that fails local validation.
pub const ERROR_CODE_PROFILE_INVALID: &str = "PROFILE_INVALID";

/// All errors that a CLI command can produce.
#[derive(Debug, Error)]
pub enum CliError {
    /// The server returned 401 or 403.
    #[error("auth failure: {0}")]
    AuthFailure(String),

    /// The server could not be reached (connection refused, DNS failure, etc.).
    #[error("server unreachable: {0}")]
    ServerUnreachable(String),

    /// The requested resource does not exist on the server.
    #[error("not found: {0}")]
    NotFound(String),

    /// The request exceeded the configured timeout.
    #[error("timeout: {0}")]
    Timeout(String),

    /// Invalid combination of flags or arguments supplied by the caller.
    #[error("invalid arguments: {0}")]
    InvalidArgs(String),

    /// Unknown `cmd` in `red-cell-cli session` (rejected before forwarding).
    #[error("unknown command `{0}`")]
    UnknownSessionCommand(String),

    /// An unexpected 5xx response was returned by the teamserver.
    #[error("server error: {0}")]
    ServerError(String),

    /// Configuration error (missing server URL, missing token, parse failure).
    #[error("configuration error: {0}")]
    Config(#[from] crate::config::ConfigError),

    /// The requested feature is not yet supported by the teamserver.
    #[error("unsupported: {0}")]
    #[allow(dead_code)]
    Unsupported(String),

    /// The CLI could not serialize a response envelope to JSON.
    #[error("serialize failed: {0}")]
    SerializeFailed(String),

    /// A write to stdout or stderr failed (e.g. broken pipe).
    #[error("I/O write failed: {0}")]
    Io(String),

    /// The server returned 429 Too Many Requests.
    ///
    /// `retry_after_secs` is populated when the server includes a numeric
    /// `Retry-After` header; callers should sleep for that duration before
    /// retrying.  When absent, a sensible default (e.g. 10 s) is appropriate.
    #[error("rate limited by server (retry after {retry_after_secs:?}s)")]
    RateLimited {
        /// Seconds to wait before retrying, parsed from the `Retry-After`
        /// response header.  `None` when the header is absent or non-numeric.
        retry_after_secs: Option<u64>,
    },

    /// A YAOTL profile failed local validation.
    #[error("profile validation failed: {message}")]
    ProfileInvalid {
        /// Human-readable summary.
        message: String,
        /// Individual validation error messages.
        errors: Vec<String>,
    },

    /// Any other error not covered above.
    #[error("{0}")]
    General(String),
}

/// Convert a [`clap::Error`] from [`clap::Parser::try_parse`] into [`CliError`].
///
/// Callers must handle [`clap::error::ErrorKind::DisplayHelp`] and
/// [`clap::error::ErrorKind::DisplayVersion`] separately (typically `clap::Error::print()` and
/// exit `0`), because those are not API failures.
#[must_use]
pub(crate) fn cli_error_from_clap_parse(e: &clap::Error) -> CliError {
    use clap::error::ErrorKind;
    match e.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => CliError::General(
            "internal: DisplayHelp/DisplayVersion must be handled before mapping".to_owned(),
        ),
        ErrorKind::Io | ErrorKind::Format => CliError::General(format!("invalid arguments: {e}")),
        _ => CliError::InvalidArgs(normalize_clap_message(e)),
    }
}

fn normalize_clap_message(e: &clap::Error) -> String {
    let s = e.to_string();
    s.strip_prefix("error: ").map(|rest| rest.trim_start().to_owned()).unwrap_or(s)
}

impl CliError {
    /// Return the process exit code that corresponds to this error.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::AuthFailure(_) => EXIT_AUTH_FAILURE,
            CliError::ServerUnreachable(_) => EXIT_SERVER_UNREACHABLE,
            CliError::NotFound(_) => EXIT_NOT_FOUND,
            CliError::Timeout(_) => EXIT_TIMEOUT,
            CliError::RateLimited { .. } => EXIT_RATE_LIMITED,
            CliError::InvalidArgs(_) => EXIT_GENERAL,
            CliError::UnknownSessionCommand(_) => EXIT_GENERAL,
            CliError::ServerError(_) => EXIT_GENERAL,
            CliError::Unsupported(_) => EXIT_GENERAL,
            CliError::SerializeFailed(_) => EXIT_GENERAL,
            CliError::Io(_) => EXIT_GENERAL,
            CliError::ProfileInvalid { .. } => EXIT_GENERAL,
            CliError::Config(crate::config::ConfigError::MissingToken) => EXIT_AUTH_FAILURE,
            CliError::Config(_) => EXIT_GENERAL,
            CliError::General(_) => EXIT_GENERAL,
        }
    }

    /// Return the stable machine-readable error code string.
    #[must_use]
    pub fn error_code(&self) -> &'static str {
        match self {
            CliError::AuthFailure(_) => ERROR_CODE_AUTH_FAILURE,
            CliError::ServerUnreachable(_) => ERROR_CODE_UNREACHABLE,
            CliError::NotFound(_) => ERROR_CODE_NOT_FOUND,
            CliError::Timeout(_) => ERROR_CODE_TIMEOUT,
            CliError::RateLimited { .. } => ERROR_CODE_RATE_LIMITED,
            CliError::InvalidArgs(_) => ERROR_CODE_INVALID_ARGS,
            CliError::UnknownSessionCommand(_) => ERROR_CODE_UNKNOWN_COMMAND,
            CliError::ServerError(_) => ERROR_CODE_SERVER_ERROR,
            CliError::Unsupported(_) => ERROR_CODE_UNSUPPORTED,
            CliError::SerializeFailed(_) => ERROR_CODE_SERIALIZE_FAILED,
            CliError::Io(_) => ERROR_CODE_IO_WRITE_FAILED,
            CliError::ProfileInvalid { .. } => ERROR_CODE_PROFILE_INVALID,
            CliError::Config(crate::config::ConfigError::MissingToken) => ERROR_CODE_AUTH_FAILURE,
            CliError::Config(_) => ERROR_CODE_GENERAL,
            CliError::General(_) => ERROR_CODE_GENERAL,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_failure_has_correct_exit_code() {
        let err = CliError::AuthFailure("401".to_owned());
        assert_eq!(err.exit_code(), EXIT_AUTH_FAILURE);
        assert_eq!(err.error_code(), ERROR_CODE_AUTH_FAILURE);
    }

    #[test]
    fn server_unreachable_has_correct_exit_code() {
        let err = CliError::ServerUnreachable("refused".to_owned());
        assert_eq!(err.exit_code(), EXIT_SERVER_UNREACHABLE);
        assert_eq!(err.error_code(), ERROR_CODE_UNREACHABLE);
    }

    #[test]
    fn invalid_args_exits_1_with_correct_code() {
        let err = CliError::InvalidArgs("--foo and --bar are mutually exclusive".to_owned());
        assert_eq!(err.exit_code(), EXIT_GENERAL);
        assert_eq!(err.error_code(), ERROR_CODE_INVALID_ARGS);
    }

    #[test]
    fn unknown_session_command_exits_1_with_unknown_command_code() {
        let err = CliError::UnknownSessionCommand("agent.lst".to_owned());
        assert_eq!(err.exit_code(), EXIT_GENERAL);
        assert_eq!(err.error_code(), ERROR_CODE_UNKNOWN_COMMAND);
        assert!(err.to_string().contains("agent.lst"));
    }

    #[test]
    fn server_error_exits_1_with_correct_code() {
        let err = CliError::ServerError("500 Internal Server Error".to_owned());
        assert_eq!(err.exit_code(), EXIT_GENERAL);
        assert_eq!(err.error_code(), ERROR_CODE_SERVER_ERROR);
    }

    #[test]
    fn not_found_has_correct_exit_code() {
        let err = CliError::NotFound("agent x".to_owned());
        assert_eq!(err.exit_code(), EXIT_NOT_FOUND);
        assert_eq!(err.error_code(), ERROR_CODE_NOT_FOUND);
    }

    #[test]
    fn timeout_has_correct_exit_code() {
        let err = CliError::Timeout("30s".to_owned());
        assert_eq!(err.exit_code(), EXIT_TIMEOUT);
        assert_eq!(err.error_code(), ERROR_CODE_TIMEOUT);
    }

    #[test]
    fn unsupported_exits_general_with_unsupported_error_code() {
        let err = CliError::Unsupported("agent output not available via REST".to_owned());
        assert_eq!(err.exit_code(), EXIT_GENERAL);
        assert_eq!(err.error_code(), ERROR_CODE_UNSUPPORTED);
    }

    #[test]
    fn serialize_failed_exits_general_with_serialize_failed_error_code() {
        let err = CliError::SerializeFailed("boom".to_owned());
        assert_eq!(err.exit_code(), EXIT_GENERAL);
        assert_eq!(err.error_code(), ERROR_CODE_SERIALIZE_FAILED);
    }

    #[test]
    fn general_has_correct_exit_code() {
        let err = CliError::General("oops".to_owned());
        assert_eq!(err.exit_code(), EXIT_GENERAL);
        assert_eq!(err.error_code(), ERROR_CODE_GENERAL);
    }

    #[test]
    fn rate_limited_with_retry_after_has_correct_exit_and_code() {
        let err = CliError::RateLimited { retry_after_secs: Some(30) };
        assert_eq!(err.exit_code(), EXIT_RATE_LIMITED);
        assert_eq!(err.error_code(), ERROR_CODE_RATE_LIMITED);
    }

    #[test]
    fn rate_limited_without_retry_after_has_correct_exit_and_code() {
        let err = CliError::RateLimited { retry_after_secs: None };
        assert_eq!(err.exit_code(), EXIT_RATE_LIMITED);
        assert_eq!(err.error_code(), ERROR_CODE_RATE_LIMITED);
    }

    #[test]
    fn rate_limited_exit_code_is_distinct_from_timeout_and_unreachable() {
        let rl = CliError::RateLimited { retry_after_secs: None };
        assert_ne!(rl.exit_code(), EXIT_TIMEOUT);
        assert_ne!(rl.exit_code(), EXIT_SERVER_UNREACHABLE);
        assert_eq!(rl.exit_code(), EXIT_RATE_LIMITED);
    }

    #[test]
    fn profile_invalid_exits_general_with_profile_invalid_code() {
        let err = CliError::ProfileInvalid {
            message: "Host must not be empty".to_owned(),
            errors: vec!["Host must not be empty".to_owned()],
        };
        assert_eq!(err.exit_code(), EXIT_GENERAL);
        assert_eq!(err.error_code(), ERROR_CODE_PROFILE_INVALID);
        assert!(err.to_string().contains("Host must not be empty"));
    }

    #[test]
    fn config_missing_token_exits_auth_failure() {
        let err: CliError = crate::config::ConfigError::MissingToken.into();
        assert_eq!(err.exit_code(), EXIT_AUTH_FAILURE);
        assert_eq!(err.error_code(), ERROR_CODE_AUTH_FAILURE);
    }

    #[test]
    fn config_missing_server_exits_general() {
        let err: CliError = crate::config::ConfigError::MissingServer.into();
        assert_eq!(err.exit_code(), EXIT_GENERAL);
        assert_eq!(err.error_code(), ERROR_CODE_GENERAL);
    }

    #[test]
    fn config_read_error_exits_general() {
        let err: CliError = crate::config::ConfigError::ReadError {
            path: std::path::PathBuf::from("/tmp/config.toml"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "no such file"),
        }
        .into();
        assert_eq!(err.exit_code(), EXIT_GENERAL);
        assert_eq!(err.error_code(), ERROR_CODE_GENERAL);
    }

    #[test]
    fn config_parse_error_exits_general() {
        let source: toml::de::Error =
            toml::from_str::<toml::Value>("not = [valid @@@@").unwrap_err();
        let err: CliError = crate::config::ConfigError::ParseError {
            path: std::path::PathBuf::from("/tmp/config.toml"),
            source,
        }
        .into();
        assert_eq!(err.exit_code(), EXIT_GENERAL);
        assert_eq!(err.error_code(), ERROR_CODE_GENERAL);
    }

    #[test]
    fn clap_unknown_subcommand_maps_to_invalid_args() {
        use clap::Parser;
        let e = match crate::cli::Cli::try_parse_from(["red-cell-cli", "xyzzy-plugh"]) {
            Ok(_) => panic!("expected parse failure"),
            Err(e) => e,
        };
        let err = super::cli_error_from_clap_parse(&e);
        assert!(matches!(err, CliError::InvalidArgs(_)));
        assert_eq!(err.error_code(), ERROR_CODE_INVALID_ARGS);
        assert!(err.to_string().to_lowercase().contains("subcommand"));
    }

    #[test]
    fn clap_missing_required_args_maps_to_invalid_args() {
        use clap::Parser;
        let e = match crate::cli::Cli::try_parse_from(["red-cell-cli", "agent", "exec"]) {
            Ok(_) => panic!("expected parse failure"),
            Err(e) => e,
        };
        let err = super::cli_error_from_clap_parse(&e);
        assert!(matches!(err, CliError::InvalidArgs(_)));
        assert_eq!(err.error_code(), ERROR_CODE_INVALID_ARGS);
        assert!(err.to_string().to_lowercase().contains("required"));
    }
}
