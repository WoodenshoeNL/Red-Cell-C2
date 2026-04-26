//! Merge CLI flags, environment, and TOML file values into a [`ResolvedConfig`](super::types::ResolvedConfig).

use std::path::PathBuf;

use super::discovery::{find_config_file, global_config_path};
use super::file::load_config_file;
use super::types::{
    ConfigError, FileConfig, FingerprintPinMode, FingerprintTls, ResolvedConfig, TlsMode,
};

/// Resolve the final configuration from all sources.
///
/// `cli_server` and `cli_token` already incorporate both CLI flags and
/// environment variables because clap handles both via `#[arg(env = "…")]`.
///
/// `cli_timeout` is `Some(secs)` when the user explicitly passed `--timeout`,
/// or `None` when the flag was omitted.  An explicit value always wins over the
/// config file; when absent the config file's `timeout` is used, falling back
/// to the built-in default of 30 seconds.
///
/// `ca_cert` comes from `--ca-cert` (CLI-only).
/// `cert_fingerprint` comes from `--cert-fingerprint` / `RC_CERT_FINGERPRINT`
/// env var (handled by clap) and falls back to the config file's
/// `cert_fingerprint` field.  When both `ca_cert` and `cert_fingerprint` are
/// supplied, `cert_fingerprint` wins.
///
/// `pin_intermediate` maps to [`FingerprintPinMode::Chain`] when
/// `cert_fingerprint` is set; it is an error without a fingerprint.
pub fn resolve(
    cli_server: Option<String>,
    cli_token: Option<String>,
    cli_timeout: Option<u64>,
    ca_cert: Option<PathBuf>,
    cert_fingerprint: Option<String>,
    pin_intermediate: bool,
) -> Result<ResolvedConfig, ConfigError> {
    // Pay the I/O cost of loading files when any value that can come from the
    // config file is absent from the CLI/env.  Timeout and cert_fingerprint are
    // included so that `--server X --token Y` (no `--timeout`) still picks up
    // `timeout` / `cert_fingerprint` from the config file instead of silently
    // falling back to defaults.
    let need_file = cli_server.is_none()
        || cli_token.is_none()
        || cli_timeout.is_none()
        || cert_fingerprint.is_none();

    let file_config: Option<FileConfig> = if need_file {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let path = find_config_file(&cwd).or_else(global_config_path);
        match path {
            Some(p) => Some(load_config_file(&p)?),
            None => None,
        }
    } else {
        None
    };

    let server = cli_server
        .or_else(|| file_config.as_ref().and_then(|c| c.server.clone()))
        .ok_or(ConfigError::MissingServer)?;

    let token = cli_token
        .or_else(|| file_config.as_ref().and_then(|c| c.token.clone()))
        .ok_or(ConfigError::MissingToken)?;

    // Timeout: explicit CLI flag always wins; when absent, fall back to the
    // config file value, then to the built-in default of 30 seconds.
    let timeout =
        cli_timeout.or_else(|| file_config.as_ref().and_then(|c| c.timeout)).unwrap_or(30);

    let cert_fingerprint =
        cert_fingerprint.or_else(|| file_config.as_ref().and_then(|c| c.cert_fingerprint.clone()));

    if pin_intermediate && cert_fingerprint.is_none() {
        return Err(ConfigError::PinIntermediateWithoutFingerprint);
    }

    // TLS mode: fingerprint wins over CA cert.
    let tls_mode = match (ca_cert, cert_fingerprint) {
        (_, Some(fp)) => TlsMode::Fingerprint(FingerprintTls {
            sha256_hex: fp,
            pin_mode: if pin_intermediate {
                FingerprintPinMode::Chain
            } else {
                FingerprintPinMode::Leaf
            },
        }),
        (Some(path), None) => TlsMode::CustomCa(path),
        (None, None) => TlsMode::SystemRoots,
    };

    Ok(ResolvedConfig { server: server.trim_end_matches('/').to_owned(), token, timeout, tls_mode })
}
