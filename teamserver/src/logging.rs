use std::env;
use std::fs;
use std::path::PathBuf;

use red_cell_common::config::{LogFormat, LogRotation, Profile};
#[cfg(feature = "otel")]
use red_cell_common::config::ObservabilityConfig;
use thiserror::Error;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, registry};

#[derive(Debug)]
pub struct LoggingGuard {
    _file_guard: Option<WorkerGuard>,
    #[cfg(feature = "otel")]
    _otel_provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
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
    #[cfg(feature = "otel")]
    #[error("failed to initialize OpenTelemetry tracer: {message}")]
    OpenTelemetry { message: String },
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

    // Resolve optional OTel provider (only compiled in when the `otel` feature is active).
    #[cfg(feature = "otel")]
    let otel_config = profile.and_then(|p| p.teamserver.observability.as_ref());
    #[cfg(feature = "otel")]
    let otel_provider = build_otel_provider(otel_config)?;
    #[cfg(feature = "otel")]
    let otel_layer = otel_layer_from_provider(&otel_provider);

    // Build the base subscriber with the OTel layer positioned directly on the
    // registry so that `OpenTelemetryLayer<Registry, T>` matches its `Layer<Registry>`
    // impl.  The OTel layer is `Option<_>`, so it no-ops when absent.
    let base = registry();
    #[cfg(feature = "otel")]
    let base = base.with(otel_layer);

    let init_err = |error: tracing_subscriber::util::TryInitError| {
        LoggingInitError::InitializeSubscriber { message: error.to_string() }
    };

    match (format, file) {
        (LogFormat::Pretty, None) => {
            base.with(filter)
                .with(
                    fmt::layer().pretty().with_target(false).with_file(true).with_line_number(true),
                )
                .try_init()
                .map_err(init_err)?;

            Ok(LoggingGuard {
                _file_guard: None,
                #[cfg(feature = "otel")]
                _otel_provider: otel_provider,
            })
        }
        (LogFormat::Json, None) => {
            base.with(filter)
                .with(fmt::layer().json().with_target(false))
                .try_init()
                .map_err(init_err)?;

            Ok(LoggingGuard {
                _file_guard: None,
                #[cfg(feature = "otel")]
                _otel_provider: otel_provider,
            })
        }
        (LogFormat::Pretty, Some(file)) => {
            let (writer, guard) = file_writer(&file)?;
            base.with(filter)
                .with(
                    fmt::layer().pretty().with_target(false).with_file(true).with_line_number(true),
                )
                .with(fmt::layer().pretty().with_ansi(false).with_target(false).with_writer(writer))
                .try_init()
                .map_err(init_err)?;

            Ok(LoggingGuard {
                _file_guard: Some(guard),
                #[cfg(feature = "otel")]
                _otel_provider: otel_provider,
            })
        }
        (LogFormat::Json, Some(file)) => {
            let (writer, guard) = file_writer(&file)?;
            base.with(filter)
                .with(fmt::layer().json().with_target(false))
                .with(fmt::layer().json().with_target(false).with_writer(writer))
                .try_init()
                .map_err(init_err)?;

            Ok(LoggingGuard {
                _file_guard: Some(guard),
                #[cfg(feature = "otel")]
                _otel_provider: otel_provider,
            })
        }
    }
}

/// Build an OpenTelemetry tracer provider when the `otel` feature is active.
///
/// Returns `None` when no OTLP endpoint is configured.  The caller creates
/// the tracing layer from the returned provider so that the subscriber type
/// parameter `S` is inferred at the call site.
#[cfg(feature = "otel")]
fn build_otel_provider(
    config: Option<&ObservabilityConfig>,
) -> Result<Option<opentelemetry_sdk::trace::SdkTracerProvider>, LoggingInitError> {
    let Some(cfg) = config else {
        return Ok(None);
    };
    let Some(ref endpoint) = cfg.otlp_endpoint else {
        return Ok(None);
    };

    use opentelemetry_otlp::WithExportConfig as _;
    use opentelemetry_sdk::Resource;
    use opentelemetry_sdk::trace::SdkTracerProvider;

    let service_name = cfg
        .service_name
        .as_deref()
        .unwrap_or("red-cell-teamserver");

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .map_err(|e: opentelemetry::trace::TraceError| LoggingInitError::OpenTelemetry {
            message: e.to_string(),
        })?;

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            Resource::builder()
                .with_service_name(service_name.to_owned())
                .build(),
        )
        .build();

    Ok(Some(provider))
}

/// Create a `tracing_opentelemetry` layer from an optional provider.
///
/// Returns `None` when no provider is supplied, keeping the subscriber
/// unmodified (the `Option<Layer>` no-ops in `tracing-subscriber`).
#[cfg(feature = "otel")]
fn otel_layer_from_provider(
    provider: &Option<opentelemetry_sdk::trace::SdkTracerProvider>,
) -> Option<tracing_opentelemetry::OpenTelemetryLayer<tracing_subscriber::Registry, opentelemetry_sdk::trace::Tracer>> {
    use opentelemetry::trace::TracerProvider as _;
    provider.as_ref().map(|p| {
        let tracer = p.tracer("red-cell-teamserver");
        tracing_opentelemetry::layer().with_tracer(tracer)
    })
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
    use std::env;
    use std::path::PathBuf;
    use std::process::Command;

    use red_cell_common::config::{LogFormat, LogRotation, Profile};
    use tempfile::TempDir;

    use super::{
        LoggingInitError, init_tracing, map_rotation, resolve_logging_config_with_override,
    };

    const SUBPROCESS_TEST_ENV: &str = "RED_CELL_LOGGING_TEST_CASE";
    const SUBPROCESS_LOG_DIR_ENV: &str = "RED_CELL_LOGGING_TEST_LOG_DIR";
    const SUBPROCESS_FILTER_ENV: &str = "RED_CELL_LOGGING_TEST_FILTER";
    const SUBPROCESS_DEBUG_ENV: &str = "RED_CELL_LOGGING_TEST_DEBUG";

    fn parse_profile(input: &str) -> Profile {
        match Profile::parse(input) {
            Ok(profile) => profile,
            Err(error) => panic!("profile should parse: {error}"),
        }
    }

    fn run_init_tracing_subprocess(case: &str, envs: &[(&str, &str)]) -> std::process::Output {
        let current_exe = match env::current_exe() {
            Ok(path) => path,
            Err(error) => panic!("current test binary path should resolve: {error}"),
        };

        let mut command = Command::new(current_exe);
        command.arg("--exact").arg("logging::tests::subprocess_entrypoint").arg("--nocapture");
        command.env(SUBPROCESS_TEST_ENV, case);
        for (key, value) in envs {
            command.env(key, value);
        }

        match command.output() {
            Ok(output) => output,
            Err(error) => panic!("subprocess should run: {error}"),
        }
    }

    #[test]
    fn subprocess_entrypoint() {
        let Ok(case) = env::var(SUBPROCESS_TEST_ENV) else {
            return;
        };

        match case.as_str() {
            "file_logging_happy_path" => {
                let log_dir = match env::var(SUBPROCESS_LOG_DIR_ENV) {
                    Ok(path) => path,
                    Err(error) => panic!("log directory should be set: {error}"),
                };
                let profile = parse_profile(&format!(
                    r#"
                    Teamserver {{
                      Host = "127.0.0.1"
                      Port = 40056
                      Logging {{
                        Level = "info"
                        Format = "Json"
                        File {{
                          Directory = "{log_dir}"
                          Prefix = "teamserver.log"
                          Rotation = "Never"
                        }}
                      }}
                    }}

                    Operators {{
                      user "neo" {{
                        Password = "password1234"
                      }}
                    }}

                    Demon {{}}
                    "#
                ));

                if let Err(error) = init_tracing(Some(&profile), false) {
                    panic!("file logging init should succeed: {error}");
                }
            }
            "json_file_format" => {
                let log_dir = match env::var(SUBPROCESS_LOG_DIR_ENV) {
                    Ok(path) => path,
                    Err(error) => panic!("log directory should be set: {error}"),
                };
                let profile = parse_profile(&format!(
                    r#"
                    Teamserver {{
                      Host = "127.0.0.1"
                      Port = 40056
                      Logging {{
                        Level = "info"
                        Format = "Json"
                        File {{
                          Directory = "{log_dir}"
                          Prefix = "teamserver.log"
                          Rotation = "Never"
                        }}
                      }}
                    }}

                    Operators {{
                      user "neo" {{
                        Password = "password1234"
                      }}
                    }}

                    Demon {{}}
                    "#
                ));

                let guard = match init_tracing(Some(&profile), false) {
                    Ok(guard) => guard,
                    Err(error) => panic!("json file logging init should succeed: {error}"),
                };
                tracing::info!(marker = "json_file_format_test", "hello from json test");
                drop(guard);
            }
            "pretty_file_format" => {
                let log_dir = match env::var(SUBPROCESS_LOG_DIR_ENV) {
                    Ok(path) => path,
                    Err(error) => panic!("log directory should be set: {error}"),
                };
                let profile = parse_profile(&format!(
                    r#"
                    Teamserver {{
                      Host = "127.0.0.1"
                      Port = 40056
                      Logging {{
                        Level = "info"
                        Format = "Pretty"
                        File {{
                          Directory = "{log_dir}"
                          Prefix = "teamserver.log"
                          Rotation = "Never"
                        }}
                      }}
                    }}

                    Operators {{
                      user "neo" {{
                        Password = "password1234"
                      }}
                    }}

                    Demon {{}}
                    "#
                ));

                let guard = match init_tracing(Some(&profile), false) {
                    Ok(guard) => guard,
                    Err(error) => panic!("pretty file logging init should succeed: {error}"),
                };
                tracing::info!(marker = "pretty_file_format_test", "hello from pretty test");
                drop(guard);
            }
            "invalid_filter" => {
                let filter = match env::var(SUBPROCESS_FILTER_ENV) {
                    Ok(filter) => filter,
                    Err(error) => panic!("filter should be set: {error}"),
                };
                let profile = parse_profile(&format!(
                    r#"
                    Teamserver {{
                      Host = "127.0.0.1"
                      Port = 40056
                      Logging {{
                        Level = "{filter}"
                      }}
                    }}

                    Operators {{
                      user "neo" {{
                        Password = "password1234"
                      }}
                    }}

                    Demon {{}}
                    "#
                ));

                match init_tracing(Some(&profile), false) {
                    Err(LoggingInitError::InvalidFilter { directive, .. }) => {
                        assert_eq!(directive, filter);
                    }
                    Err(error) => panic!("expected invalid filter error, got {error}"),
                    Ok(_) => panic!("invalid filter should not initialize tracing"),
                }
            }
            "create_log_dir_error" => {
                let log_dir = match env::var(SUBPROCESS_LOG_DIR_ENV) {
                    Ok(path) => path,
                    Err(error) => panic!("log directory should be set: {error}"),
                };
                let profile = parse_profile(&format!(
                    r#"
                    Teamserver {{
                      Host = "127.0.0.1"
                      Port = 40056
                      Logging {{
                        Level = "info"
                        Format = "Json"
                        File {{
                          Directory = "{log_dir}"
                          Prefix = "teamserver.log"
                          Rotation = "Never"
                        }}
                      }}
                    }}

                    Operators {{
                      user "neo" {{
                        Password = "password1234"
                      }}
                    }}

                    Demon {{}}
                    "#
                ));

                match init_tracing(Some(&profile), false) {
                    Err(LoggingInitError::CreateLogDirectory { path, .. }) => {
                        assert_eq!(path, PathBuf::from(&log_dir));
                    }
                    Err(error) => panic!("expected CreateLogDirectory error, got {error}"),
                    Ok(_) => panic!("init_tracing should fail for uncreatable directory"),
                }
            }
            "default_config_once" => {
                let debug_logging = match env::var(SUBPROCESS_DEBUG_ENV) {
                    Ok(value) => value == "1",
                    Err(error) => panic!("debug flag should be set: {error}"),
                };

                if let Err(error) = init_tracing(None, debug_logging) {
                    panic!("default init should succeed: {error}");
                }
            }
            "double_init" => {
                // First init should succeed.
                if let Err(error) = init_tracing(None, false) {
                    panic!("first init should succeed: {error}");
                }

                // Second init in the same process must fail with InitializeSubscriber.
                match init_tracing(None, false) {
                    Err(LoggingInitError::InitializeSubscriber { .. }) => {}
                    Err(error) => panic!("expected InitializeSubscriber error, got {error}"),
                    Ok(_) => panic!("second init_tracing call should fail"),
                }
            }
            other => panic!("unexpected subprocess case: {other}"),
        }
    }

    #[test]
    fn debug_mode_defaults_to_pretty_debug_logging() {
        let resolved = resolve_logging_config_with_override(None, true, None);

        assert_eq!(resolved.filter_directive, "debug");
        assert_eq!(resolved.format, LogFormat::Pretty);
        assert_eq!(resolved.file, None);
    }

    #[test]
    fn non_debug_defaults_to_json_info_logging() {
        let resolved = resolve_logging_config_with_override(None, false, None);

        assert_eq!(resolved.filter_directive, "info");
        assert_eq!(resolved.format, LogFormat::Json);
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

    #[test]
    fn whitespace_only_override_falls_back_to_profile_level() {
        let profile = parse_profile(
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
        );

        let resolved =
            resolve_logging_config_with_override(Some(&profile), false, Some("  ".to_owned()));

        assert_eq!(resolved.filter_directive, "info");
        assert_eq!(resolved.format, LogFormat::Json);
    }

    #[test]
    fn no_profile_with_rust_log_override_uses_override_and_json_format() {
        let resolved = resolve_logging_config_with_override(None, false, Some("trace".to_owned()));

        assert_eq!(resolved.filter_directive, "trace");
        assert_eq!(resolved.format, LogFormat::Json);
        assert_eq!(resolved.file, None);
    }

    #[test]
    fn init_tracing_succeeds_with_file_logging_enabled() {
        let temp_dir = match TempDir::new() {
            Ok(dir) => dir,
            Err(error) => panic!("tempdir should be created: {error}"),
        };
        let log_dir = temp_dir.path().join("logs");
        let log_dir_str = log_dir.to_string_lossy().into_owned();

        let output = run_init_tracing_subprocess(
            "file_logging_happy_path",
            &[(SUBPROCESS_LOG_DIR_ENV, log_dir_str.as_str())],
        );

        assert!(
            output.status.success(),
            "subprocess should succeed, stdout: {}, stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(log_dir.is_dir(), "log directory should be created");
        let mut entries = match std::fs::read_dir(&log_dir) {
            Ok(entries) => entries,
            Err(error) => panic!("log directory should be readable: {error}"),
        };
        assert!(entries.next().is_some(), "log file should be created");
    }

    #[test]
    fn init_tracing_rejects_invalid_filter_directive() {
        let output =
            run_init_tracing_subprocess("invalid_filter", &[(SUBPROCESS_FILTER_ENV, "[invalid")]);

        assert!(
            output.status.success(),
            "subprocess should succeed, stdout: {}, stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn init_tracing_returns_create_log_directory_error_for_uncreatable_path() {
        let temp_dir = match TempDir::new() {
            Ok(dir) => dir,
            Err(error) => panic!("tempdir should be created: {error}"),
        };
        // Create a regular file; using it as a directory makes create_dir_all fail.
        let blocker = temp_dir.path().join("not_a_dir");
        std::fs::write(&blocker, b"").expect("blocker file should be created");
        let impossible_dir = blocker.join("logs");
        let impossible_dir_str = impossible_dir.to_string_lossy().into_owned();

        let output = run_init_tracing_subprocess(
            "create_log_dir_error",
            &[(SUBPROCESS_LOG_DIR_ENV, impossible_dir_str.as_str())],
        );

        assert!(
            output.status.success(),
            "subprocess should succeed, stdout: {}, stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn init_tracing_succeeds_once_per_process_without_profile_in_debug_mode() {
        let output =
            run_init_tracing_subprocess("default_config_once", &[(SUBPROCESS_DEBUG_ENV, "1")]);

        assert!(
            output.status.success(),
            "subprocess should succeed, stdout: {}, stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn file_rotation_defaults_to_daily_when_omitted() {
        let profile = parse_profile(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              Logging {
                Level = "info"
                Format = "Json"
                File {
                  Directory = "logs"
                  Prefix = "teamserver.log"
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
        );

        let resolved = resolve_logging_config_with_override(Some(&profile), false, None);

        let file = resolved.file.expect("file logging should be resolved");
        assert_eq!(file.rotation, LogRotation::Daily);
    }

    #[test]
    fn file_rotation_preserves_minutely_when_configured() {
        let profile = parse_profile(
            r#"
            Teamserver {
              Host = "127.0.0.1"
              Port = 40056
              Logging {
                Level = "info"
                Format = "Json"
                File {
                  Directory = "logs"
                  Prefix = "teamserver.log"
                  Rotation = "Minutely"
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
        );

        let resolved = resolve_logging_config_with_override(Some(&profile), false, None);

        let file = resolved.file.expect("file logging should be resolved");
        assert_eq!(file.rotation, LogRotation::Minutely);
    }

    #[test]
    fn init_tracing_returns_initialize_subscriber_error_on_double_init() {
        let output = run_init_tracing_subprocess("double_init", &[]);

        assert!(
            output.status.success(),
            "subprocess should succeed, stdout: {}, stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn map_rotation_maps_never_to_appender_never() {
        assert_eq!(map_rotation(LogRotation::Never), tracing_appender::rolling::Rotation::NEVER);
    }

    #[test]
    fn map_rotation_maps_hourly_to_appender_hourly() {
        assert_eq!(map_rotation(LogRotation::Hourly), tracing_appender::rolling::Rotation::HOURLY);
    }

    #[test]
    fn map_rotation_maps_daily_to_appender_daily() {
        assert_eq!(map_rotation(LogRotation::Daily), tracing_appender::rolling::Rotation::DAILY);
    }

    #[test]
    fn map_rotation_maps_minutely_to_appender_minutely() {
        assert_eq!(
            map_rotation(LogRotation::Minutely),
            tracing_appender::rolling::Rotation::MINUTELY
        );
    }

    #[test]
    fn init_tracing_succeeds_once_per_process_without_profile_in_non_debug_mode() {
        let output =
            run_init_tracing_subprocess("default_config_once", &[(SUBPROCESS_DEBUG_ENV, "0")]);

        assert!(
            output.status.success(),
            "subprocess should succeed, stdout: {}, stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Read all log file contents from a log directory, concatenated.
    fn read_log_contents(log_dir: &std::path::Path) -> String {
        let mut contents = String::new();
        let entries = match std::fs::read_dir(log_dir) {
            Ok(entries) => entries,
            Err(error) => panic!("log directory should be readable: {error}"),
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => panic!("directory entry should be readable: {error}"),
            };
            match std::fs::read_to_string(entry.path()) {
                Ok(text) => contents.push_str(&text),
                Err(error) => panic!("log file should be readable: {error}"),
            }
        }
        contents
    }

    #[test]
    fn init_tracing_writes_json_records_to_log_file() {
        let temp_dir = match TempDir::new() {
            Ok(dir) => dir,
            Err(error) => panic!("tempdir should be created: {error}"),
        };
        let log_dir = temp_dir.path().join("logs");
        let log_dir_str = log_dir.to_string_lossy().into_owned();

        let output = run_init_tracing_subprocess(
            "json_file_format",
            &[(SUBPROCESS_LOG_DIR_ENV, log_dir_str.as_str())],
        );

        assert!(
            output.status.success(),
            "subprocess should succeed, stdout: {}, stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let contents = read_log_contents(&log_dir);
        assert!(!contents.is_empty(), "log file should not be empty");

        // Each non-empty line should be a valid JSON object.
        let mut found_marker = false;
        for line in contents.lines().filter(|l| !l.trim().is_empty()) {
            let parsed: serde_json::Value = match serde_json::from_str(line) {
                Ok(value) => value,
                Err(error) => panic!(
                    "every log line should be valid JSON, but got parse error: {error}\nline: {line}"
                ),
            };
            let obj = parsed.as_object().expect("JSON log line should be an object");
            // tracing JSON output includes standard fields.
            assert!(obj.contains_key("timestamp"), "JSON record should have 'timestamp' field");
            assert!(obj.contains_key("level"), "JSON record should have 'level' field");
            assert!(obj.contains_key("fields"), "JSON record should have 'fields' field");
            if let Some(fields) = obj.get("fields").and_then(|f| f.as_object()) {
                if fields.get("marker").and_then(|m| m.as_str()) == Some("json_file_format_test") {
                    found_marker = true;
                    let message = fields.get("message").and_then(|m| m.as_str());
                    assert_eq!(
                        message,
                        Some("hello from json test"),
                        "JSON record should contain the emitted message"
                    );
                }
            }
        }
        assert!(found_marker, "log file should contain the marker record");
    }

    #[test]
    fn init_tracing_writes_pretty_records_to_log_file() {
        let temp_dir = match TempDir::new() {
            Ok(dir) => dir,
            Err(error) => panic!("tempdir should be created: {error}"),
        };
        let log_dir = temp_dir.path().join("logs");
        let log_dir_str = log_dir.to_string_lossy().into_owned();

        let output = run_init_tracing_subprocess(
            "pretty_file_format",
            &[(SUBPROCESS_LOG_DIR_ENV, log_dir_str.as_str())],
        );

        assert!(
            output.status.success(),
            "subprocess should succeed, stdout: {}, stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let contents = read_log_contents(&log_dir);
        assert!(!contents.is_empty(), "log file should not be empty");

        // Pretty format should contain the message as human-readable text, not JSON.
        assert!(
            contents.contains("hello from pretty test"),
            "pretty log file should contain the emitted message, got: {contents}"
        );
        assert!(
            contents.contains("pretty_file_format_test"),
            "pretty log file should contain the marker field, got: {contents}"
        );

        // The pretty output must NOT be valid JSON on any single line containing the marker.
        for line in contents.lines() {
            if line.contains("pretty_file_format_test") {
                assert!(
                    serde_json::from_str::<serde_json::Value>(line).is_err(),
                    "pretty log lines should not be valid JSON, got: {line}"
                );
            }
        }
    }
}
