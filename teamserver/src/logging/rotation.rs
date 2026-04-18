use std::fs;

use red_cell_common::config::LogRotation;
use tracing_appender::non_blocking::WorkerGuard;

use super::config::{LoggingInitError, ResolvedFileLoggingConfig};

pub(super) fn file_writer(
    config: &ResolvedFileLoggingConfig,
) -> Result<(tracing_appender::non_blocking::NonBlocking, WorkerGuard), LoggingInitError> {
    fs::create_dir_all(&config.directory).map_err(|source| {
        LoggingInitError::CreateLogDirectory { path: config.directory.clone(), source }
    })?;

    let appender = tracing_appender::rolling::RollingFileAppender::new(
        map_rotation(config.rotation),
        &config.directory,
        &config.prefix,
    );
    Ok(tracing_appender::non_blocking(appender))
}

pub(super) fn map_rotation(rotation: LogRotation) -> tracing_appender::rolling::Rotation {
    match rotation {
        LogRotation::Never => tracing_appender::rolling::Rotation::NEVER,
        LogRotation::Hourly => tracing_appender::rolling::Rotation::HOURLY,
        LogRotation::Daily => tracing_appender::rolling::Rotation::DAILY,
        LogRotation::Minutely => tracing_appender::rolling::Rotation::MINUTELY,
    }
}
