use std::env;
use std::path::PathBuf;

use red_cell_common::config::{LogFormat, LogRotation, Profile};
use thiserror::Error;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

#[derive(Debug)]
pub struct LoggingGuard {
    pub(super) _file_guard: Option<WorkerGuard>,
    #[cfg(feature = "otel")]
    pub(super) _otel_provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ResolvedLoggingConfig {
    pub(super) filter_directive: String,
    pub(super) format: LogFormat,
    pub(super) file: Option<ResolvedFileLoggingConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ResolvedFileLoggingConfig {
    pub(super) directory: PathBuf,
    pub(super) prefix: String,
    pub(super) rotation: LogRotation,
}

#[derive(Debug, Error)]
pub enum LoggingInitError {
    #[error("failed to configure tracing filter `{directive}`: {message}")]
    InvalidFilter { directive: String, message: String },
    #[error("failed to create log directory `{path}`: {source}")]
    CreateLogDirectory { path: PathBuf, source: std::io::Error },
    #[error("failed to initialize tracing subscriber: {message}")]
    InitializeSubscriber { message: String },
    #[cfg(feature = "otel")]
    #[error("failed to initialize OpenTelemetry tracer: {message}")]
    OpenTelemetry { message: String },
}

pub(super) fn resolve_logging_config(
    profile: Option<&Profile>,
    debug_logging: bool,
) -> ResolvedLoggingConfig {
    let rust_log_override =
        env::var(EnvFilter::DEFAULT_ENV).ok().filter(|value| !value.trim().is_empty());
    resolve_logging_config_with_override(profile, debug_logging, rust_log_override)
}

pub(super) fn resolve_logging_config_with_override(
    profile: Option<&Profile>,
    debug_logging: bool,
    rust_log_override: Option<String>,
) -> ResolvedLoggingConfig {
    let profile_logging = profile.and_then(|profile| profile.teamserver.logging.as_ref());
    let filter_directive = rust_log_override
        .filter(|value| !value.trim().is_empty())
        .or_else(|| profile_logging.and_then(|logging| logging.level.clone()))
        .unwrap_or_else(|| if debug_logging { "debug".to_owned() } else { "info".to_owned() });
    let format = profile_logging.and_then(|logging| logging.format).unwrap_or(if debug_logging {
        LogFormat::Pretty
    } else {
        LogFormat::Json
    });
    let file = profile_logging.and_then(|logging| {
        logging.file.as_ref().map(|file| ResolvedFileLoggingConfig {
            directory: PathBuf::from(&file.directory),
            prefix: file.prefix.clone(),
            rotation: file.rotation.unwrap_or(LogRotation::Daily),
        })
    });

    ResolvedLoggingConfig { filter_directive, format, file }
}
