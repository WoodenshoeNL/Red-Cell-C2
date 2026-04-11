//! Typed errors for the operator client (`src/` modules and `main`).
//!
//! Library-style paths (`app`, `bootstrap`, TLS, etc.) return [`ClientError`]. The binary entry
//! point also returns `Result<(), ClientError>` so failures stay typed end-to-end (no `anyhow`).

use thiserror::Error;

/// Errors produced by client bootstrap, TLS resolution, and related setup.
#[derive(Debug, Error)]
pub(crate) enum ClientError {
    /// Certificate fingerprint has the wrong length for SHA-256 hex.
    #[error(
        "invalid certificate fingerprint from {fingerprint_source}: expected 64 hex characters \
         (SHA-256 digest), got {got} characters"
    )]
    InvalidFingerprintLength {
        /// Where the value came from (e.g. `--cert-fingerprint`).
        fingerprint_source: String,
        got: usize,
    },
    /// Certificate fingerprint contains non-hexadecimal characters.
    #[error(
        "invalid certificate fingerprint from {fingerprint_source}: contains non-hex characters"
    )]
    InvalidFingerprintNonHex {
        /// Where the value came from (e.g. `config file`).
        fingerprint_source: String,
    },
    /// Failed to persist the known-servers store.
    #[error(transparent)]
    KnownServersSave(#[from] crate::known_servers::SaveError),
    /// Native window / egui failed to start (`eframe::Error` is not `Send`/`Sync`; keep text only).
    #[error("failed to start egui application: {0}")]
    EguiStartup(String),
}

#[cfg(test)]
mod tests {
    use super::ClientError;

    #[test]
    fn invalid_fingerprint_length_display_mentions_source_and_length() {
        let err =
            ClientError::InvalidFingerprintLength { fingerprint_source: "test".to_owned(), got: 6 };
        let s = err.to_string();
        assert!(s.contains("test"), "{s}");
        assert!(s.contains("6 characters"), "{s}");
    }

    #[test]
    fn invalid_fingerprint_non_hex_display_mentions_source() {
        let err =
            ClientError::InvalidFingerprintNonHex { fingerprint_source: "config file".to_owned() };
        let s = err.to_string();
        assert!(s.contains("config file"), "{s}");
        assert!(s.contains("non-hex"), "{s}");
    }

    #[test]
    fn client_error_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ClientError>();
    }
}
