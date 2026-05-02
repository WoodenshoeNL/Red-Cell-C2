//! Public configuration types and resolution errors for `red-cell-cli` config.

use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

/// Which certificate in the TLS handshake to match when using fingerprint pinning.
///
/// **Leaf** pinning binds to the server's end-entity certificate: it is the
/// strictest check, but you must update the pin whenever that certificate is
/// renewed. **Chain** pinning matches the fingerprint against any certificate
/// the server presents (leaf plus intermediates); use it to pin an
/// intermediate CA so leaf rotation does not require a new pin. Chain pinning
/// is weaker in the sense that any presented cert in the chain with that
/// fingerprint satisfies the check—prefer leaf pinning when you can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FingerprintPinMode {
    /// Match only the end-entity (leaf) certificate (default).
    #[default]
    Leaf,
    /// Match the fingerprint against any certificate in the presented chain.
    Chain,
}

/// TLS fingerprint pinning parameters (`--cert-fingerprint` / `--pin-intermediate`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintTls {
    /// SHA-256 fingerprint of the certificate to pin (lowercase hex, 64 chars).
    pub sha256_hex: String,
    /// Whether to require a match on the leaf only or anywhere in the chain.
    pub pin_mode: FingerprintPinMode,
}

/// Controls how the CLI verifies the teamserver's TLS certificate.
#[derive(Debug, Clone, Default)]
pub enum TlsMode {
    /// Verify against the system/webpki root CAs (default, secure).
    #[default]
    SystemRoots,
    /// Verify against a single custom CA certificate loaded from a PEM file.
    /// Built-in root CAs are disabled so only this CA is trusted.
    CustomCa(PathBuf),
    /// Pin against a SHA-256 certificate fingerprint. Overrides `--ca-cert`
    /// when both are supplied.
    Fingerprint(FingerprintTls),
}

/// Raw values loaded from a TOML config file.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct FileConfig {
    /// Teamserver base URL (e.g. `https://teamserver:40056`).
    pub server: Option<String>,
    /// API authentication token.
    pub token: Option<String>,
    /// Request timeout in seconds.
    pub timeout: Option<u64>,
    /// SHA-256 certificate fingerprint for TLS pinning (lowercase hex, 64 chars).
    pub cert_fingerprint: Option<String>,
}

/// Final resolved configuration ready for use by command handlers.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    /// Teamserver base URL (scheme + host + port, no trailing slash).
    pub server: String,
    /// API authentication token.
    pub token: String,
    /// Request timeout in seconds.
    pub timeout: u64,
    /// How the HTTP client should verify the teamserver's TLS certificate.
    pub tls_mode: TlsMode,
}

/// Errors that can occur during configuration resolution.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// No server URL was found in any source.
    #[error(
        "missing server URL — provide --server, set RC_SERVER, or add `server` to a config file"
    )]
    MissingServer,

    /// No auth token was found in any source.
    #[error("missing auth token — provide --token, set RC_TOKEN, or add `token` to a config file")]
    MissingToken,

    /// `--pin-intermediate` was set without `--cert-fingerprint`.
    #[error("--pin-intermediate requires --cert-fingerprint")]
    PinIntermediateWithoutFingerprint,

    /// A config file existed but could not be read.
    #[error("failed to read config file {path}: {source}")]
    ReadError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// A config file existed but contained invalid TOML.
    #[error("failed to parse config file {path}: {source}")]
    ParseError {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    /// A config file could not be written.
    #[error("failed to write config file {path}: {source}")]
    #[allow(dead_code)] // Public API for future config-writing commands.
    WriteError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}
