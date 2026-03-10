use std::env;
use std::fs;
use std::path::PathBuf;

use red_cell_common::config::{LogFormat, LogRotation, Profile};
use thiserror::Error;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, registry};

#[derive(Debug)]
pub struct LoggingGuard {
    _file_guard: Option<WorkerGuard>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedLoggingConfig {
    filter_directive: String,
    format: LogFormat,
    file: Option<ResolvedFileLoggingConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedFileLoggingConfig {
    directory: PathBuf,
    prefix: String,
    rotation: LogRotation,
}

#[derive(Debug, Error)]
pub enum LoggingInitError {
    #[error("failed to configure tracing filter `{directive}`: {message}")]
    InvalidFilter { directive: String, message: String },
    #[error("failed to create log directory `{path}`: {source}")]
    CreateLogDirectory { path: PathBuf, source: std::io::Error },
    #[error("failed to initialize tracing subscriber: {message}")]
    InitializeSubscriber { message: String },
}

pub fn init_tracing(
    profile: Option<&Profile>,
    debug_logging: bool,
) -> Result<LoggingGuard, LoggingInitError> {
    let ResolvedLoggingConfig { filter_directive, format, file } =
        resolve_logging_config(profile, debug_logging);
    let filter = EnvFilter::try_new(filter_directive.clone()).map_err(|error| {
        LoggingInitError::InvalidFilter {
            directive: filter_directive.clone(),
            message: error.to_string(),
        }
    })?;

    match (format, file) {
        (LogFormat::Pretty, None) => {
            registry()
                .with(filter)
                .with(
                    fmt::layer().pretty().with_target(false).with_file(true).with_line_number(true),
                )
                .try_init()
                .map_err(|error| LoggingInitError::InitializeSubscriber {
                    message: error.to_string(),
                })?;

            Ok(LoggingGuard { _file_guard: None })
        }
        (LogFormat::Json, None) => {
            registry()
                .with(filter)
                .with(fmt::layer().json().with_target(false))
                .try_init()
                .map_err(|error| LoggingInitError::InitializeSubscriber {
                    message: error.to_string(),
                })?;

            Ok(LoggingGuard { _file_guard: None })
        }
        (LogFormat::Pretty, Some(file)) => {
            let (writer, guard) = file_writer(&file)?;
            registry()
                .with(filter)
                .with(
                    fmt::layer().pretty().with_target(false).with_file(true).with_line_number(true),
                )
                .with(fmt::layer().pretty().with_ansi(false).with_target(false).with_writer(writer))
                .try_init()
                .map_err(|error| LoggingInitError::InitializeSubscriber {
                    message: error.to_string(),
                })?;

            Ok(LoggingGuard { _file_guard: Some(guard) })
        }
        (LogFormat::Json, Some(file)) => {
            let (writer, guard) = file_writer(&file)?;
            registry()
                .with(filter)
                .with(fmt::layer().json().with_target(false))
                .with(fmt::layer().json().with_target(false).with_writer(writer))
                .try_init()
                .map_err(|error| LoggingInitError::InitializeSubscriber {
                    message: error.to_string(),
                })?;

            Ok(LoggingGuard { _file_guard: Some(guard) })
        }
    }
}

fn resolve_logging_config(profile: Option<&Profile>, debug_logging: bool) -> ResolvedLoggingConfig {
    let rust_log_override =
        env::var(EnvFilter::DEFAULT_ENV).ok().filter(|value| !value.trim().is_empty());
    resolve_logging_config_with_override(profile, debug_logging, rust_log_override)
}

fn resolve_logging_config_with_override(
    profile: Option<&Profile>,
    debug_logging: bool,
    rust_log_override: Option<String>,
) -> ResolvedLoggingConfig {
    let profile_logging = profile.and_then(|profile| profile.teamserver.logging.as_ref());
    let filter_directive = rust_log_override
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

fn file_writer(
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

fn map_rotation(rotation: LogRotation) -> tracing_appender::rolling::Rotation {
    match rotation {
        LogRotation::Never => tracing_appender::rolling::Rotation::NEVER,
        LogRotation::Hourly => tracing_appender::rolling::Rotation::HOURLY,
        LogRotation::Daily => tracing_appender::rolling::Rotation::DAILY,
        LogRotation::Minutely => tracing_appender::rolling::Rotation::MINUTELY,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use red_cell_common::config::{LogFormat, LogRotation, Profile};

    use super::resolve_logging_config_with_override;

    #[test]
    fn debug_mode_defaults_to_pretty_debug_logging() {
        let resolved = resolve_logging_config_with_override(None, true, None);

        assert_eq!(resolved.filter_directive, "debug");
        assert_eq!(resolved.format, LogFormat::Pretty);
        assert_eq!(resolved.file, None);
    }

    #[test]
    fn profile_logging_is_used_when_env_override_is_absent() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              Logging {
                Level = "red_cell=trace"
                Format = "Json"
                File {
                  Directory = "logs"
                  Prefix = "teamserver.log"
                  Rotation = "Hourly"
                }
              }
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        let resolved = resolve_logging_config_with_override(Some(&profile), false, None);

        assert_eq!(resolved.filter_directive, "red_cell=trace");
        assert_eq!(resolved.format, LogFormat::Json);
        let file = resolved.file.expect("file logging should be resolved");
        assert_eq!(file.directory, PathBuf::from("logs"));
        assert_eq!(file.prefix, "teamserver.log");
        assert_eq!(file.rotation, LogRotation::Hourly);
    }

    #[test]
    fn rust_log_env_overrides_profile_level() {
        let profile = Profile::parse(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              Logging {
                Level = "info"
              }
            }

            Operators {
              user "neo" {
                Password = "password1234"
              }
            }

            Demon {}
            "#,
        )
        .expect("profile should parse");

        let resolved = resolve_logging_config_with_override(
            Some(&profile),
            false,
            Some("warn,red_cell=debug".to_owned()),
        );

        assert_eq!(resolved.filter_directive, "warn,red_cell=debug");
    }
}
