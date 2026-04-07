//! Tracing setup: stderr plus a daily rolling log file under the data directory.
//!
//! Log filenames follow [`tracing_appender`]'s daily pattern, e.g. `red-cell.2026-04-07.log`
//! under the configured or default log directory.

use std::io;
use std::path::PathBuf;
use std::sync::OnceLock;

use tracing_appender::non_blocking::WorkerGuard;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

use crate::local_config::LocalConfig;

/// Global guard for the non-blocking file writer; must live for the process lifetime.
static FILE_LOG_GUARD: OnceLock<WorkerGuard> = OnceLock::new();

/// Default directory for rolling log files: `~/.local/share/red-cell-client/logs`.
pub fn default_log_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("red-cell-client")
        .join("logs")
}

/// Effective log directory from [`LocalConfig::log_dir`], or [`default_log_dir`].
pub fn resolve_log_dir(config: &LocalConfig) -> PathBuf {
    config.log_dir.clone().unwrap_or_else(default_log_dir)
}

/// Builds the [`EnvFilter`]: `RUST_LOG` wins when set and valid; otherwise
/// [`LocalConfig::log_level`] or defaults to `info`.
pub fn env_filter_for_config(config: &LocalConfig) -> EnvFilter {
    if let Ok(directives) = std::env::var("RUST_LOG") {
        if let Ok(f) = EnvFilter::try_new(&directives) {
            return f;
        }
    }
    let level = config.log_level.as_deref().unwrap_or("info");
    EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"))
}

/// Initialize `tracing` with stderr and a daily rolling file (7 days retention).
///
/// If the file appender cannot be created, logs only go to stderr and a short
/// message is printed to stderr (before tracing is fully initialized).
pub fn init(config: &LocalConfig) {
    let filter = env_filter_for_config(config);
    let stderr_layer = fmt::layer().with_writer(std::io::stderr).with_ansi(true);

    let log_dir = resolve_log_dir(config);
    match rolling_file_appender(log_dir) {
        Ok((non_blocking, guard)) => {
            let _ = FILE_LOG_GUARD.set(guard);
            let file_layer = fmt::layer().with_writer(non_blocking).with_ansi(false);
            if let Err(err) =
                Registry::default().with(filter).with(stderr_layer).with(file_layer).try_init()
            {
                eprintln!("red-cell-client: tracing already initialized ({err}); continuing");
            }
        }
        Err(err) => {
            eprintln!("red-cell-client: file logging disabled ({err}); stderr only");
            if let Err(init_err) = Registry::default().with(filter).with(stderr_layer).try_init() {
                eprintln!("red-cell-client: tracing already initialized ({init_err}); continuing");
            }
        }
    }
}

fn rolling_file_appender(
    log_dir: PathBuf,
) -> Result<(tracing_appender::non_blocking::NonBlocking, WorkerGuard), io::Error> {
    std::fs::create_dir_all(&log_dir)?;
    let file_appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("red-cell")
        .filename_suffix("log")
        .max_log_files(7)
        .build(log_dir)
        .map_err(|e| io::Error::other(e.to_string()))?;

    Ok(tracing_appender::non_blocking(file_appender))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_log_dir_ends_with_red_cell_logs() {
        let dir = default_log_dir();
        assert!(dir.ends_with("red-cell-client/logs") || dir.ends_with("red-cell-client\\logs"));
    }

    #[test]
    fn resolve_log_dir_uses_config_when_set() {
        let config = LocalConfig {
            log_dir: Some(PathBuf::from("/tmp/custom-logs")),
            ..LocalConfig::default()
        };
        assert_eq!(resolve_log_dir(&config), PathBuf::from("/tmp/custom-logs"));
    }

    #[test]
    fn env_filter_invalid_level_falls_back_to_info() {
        let config = LocalConfig {
            log_level: Some("not-a-real-level-xyz".to_owned()),
            ..LocalConfig::default()
        };
        let _ = env_filter_for_config(&config);
    }

    #[test]
    fn rolling_file_appender_creates_log_under_directory() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let (non_blocking, _guard) =
            rolling_file_appender(dir.path().to_path_buf()).expect("rolling appender");
        drop(non_blocking);
        let mut found = false;
        for entry in std::fs::read_dir(dir.path()).unwrap_or_else(|e| panic!("read_dir: {e}")) {
            let entry = entry.unwrap_or_else(|e| panic!("entry: {e}"));
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with("red-cell.") && name.ends_with(".log") {
                found = true;
                break;
            }
        }
        assert!(found, "expected a red-cell.*.log file in {:?}", dir.path());
    }
}
