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
    ///
    /// Used by downstream command modules — not yet constructed in this crate.
    #[allow(dead_code)]
    #[error("invalid arguments: {0}")]
    InvalidArgs(String),

    /// An unexpected 5xx response was returned by the teamserver.
    #[error("server error: {0}")]
    ServerError(String),

    /// Configuration error (missing server URL, missing token, parse failure).
    #[error("configuration error: {0}")]
    Config(#[from] crate::config::ConfigError),

    /// The requested feature is not yet supported by the teamserver.
    ///
    /// Used for commands that are part of the documented CLI surface but
    /// cannot be fulfilled because the teamserver does not expose the
    /// necessary endpoint (e.g. agent output retrieval, file transfer).
    #[error("unsupported: {0}")]
    #[allow(dead_code)] // Part of the public error API for future commands.
    Unsupported(String),

    /// Any other error not covered above.
    #[error("{0}")]
    General(String),
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
            CliError::InvalidArgs(_) => EXIT_GENERAL,
            CliError::ServerError(_) => EXIT_GENERAL,
            CliError::Unsupported(_) => EXIT_GENERAL,
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
            CliError::InvalidArgs(_) => ERROR_CODE_INVALID_ARGS,
            CliError::ServerError(_) => ERROR_CODE_SERVER_ERROR,
            CliError::Unsupported(_) => ERROR_CODE_UNSUPPORTED,
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
    fn general_has_correct_exit_code() {
        let err = CliError::General("oops".to_owned());
        assert_eq!(err.exit_code(), EXIT_GENERAL);
        assert_eq!(err.error_code(), ERROR_CODE_GENERAL);
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
}
