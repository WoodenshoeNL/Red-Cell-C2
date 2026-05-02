//! Auth and configuration resolution for `red-cell-cli`.
//!
//! Resolution order (first wins):
//! 1. `--server` / `--token` / `--cert-fingerprint` CLI flags
//! 2. `RC_SERVER` / `RC_TOKEN` / `RC_CERT_FINGERPRINT` environment variables (handled by clap)
//! 3. `.red-cell-cli.toml` walked up from the current working directory
//! 4. `~/.config/red-cell-cli/config.toml`

mod discovery;
mod file;
mod permissions;
mod resolve;
mod types;

pub use discovery::{global_config_path, is_unconfigured, resolve_server_only};

// `find_config_file` / `load_config_file` are the stable `crate::config::*` entry points; some
// call sites are only in `#[cfg(test)]` modules in other files, so the re-export is not always
// referenced from this crate’s non-test build graph.
#[allow(unused_imports)]
pub use discovery::find_config_file;

#[allow(unused_imports)]
pub use file::load_config_file;
pub use file::write_config_file;
pub(crate) use resolve::resolve_with_global;
pub use types::{
    ConfigError, FileConfig, FingerprintPinMode, FingerprintTls, ResolvedConfig, TlsMode,
};

#[cfg(test)]
mod tests;
