//! Async command dispatch and synchronous `help` routing.

use std::io::Write as _;

use crate::PayloadCommands;
use crate::cli::{Cli, Commands, ProfileCommands};
use crate::client;
use crate::commands;
use crate::config;
use crate::error::{CliError, EXIT_GENERAL, EXIT_SUCCESS};
use crate::output;

/// Print a human-readable setup guide to stderr when no configuration exists.
fn print_setup_hint() {
    write_setup_hint(&mut std::io::stderr()).ok();
}

fn write_setup_hint<W: std::io::Write>(out: &mut W) -> std::io::Result<()> {
    let global_path = config::global_config_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "~/.config/red-cell-cli/config.toml".to_owned());

    writeln!(
        out,
        "\
red-cell-cli: no configuration found

Set up the CLI with environment variables:

  export RC_SERVER=\"https://<teamserver-host>:40056\"
  export RC_TOKEN=\"<your-api-token>\"

Or create a config file at {global_path}:

  server = \"https://<teamserver-host>:40056\"
  token  = \"<your-api-token>\"

For self-signed teamservers, also set the certificate fingerprint:

  export RC_CERT_FINGERPRINT=\"<sha256-hex>\"   # env var
  cert_fingerprint = \"<sha256-hex>\"            # config file

Run `red-cell-cli --help` for all options."
    )
}

/// Print help for the given subcommand name, or top-level help if `None`.
///
/// Returns the appropriate process exit code.
pub(crate) fn handle_help(command: Option<&str>) -> i32 {
    use clap::CommandFactory;
    let mut root = Cli::command();
    match command {
        None => {
            if root.print_help().is_err() || writeln!(std::io::stdout()).is_err() {
                return EXIT_GENERAL;
            }
            EXIT_SUCCESS
        }
        Some(name) => {
            if let Some(sub) = root.find_subcommand_mut(name) {
                if sub.print_long_help().is_err() || writeln!(std::io::stdout()).is_err() {
                    return EXIT_GENERAL;
                }
                EXIT_SUCCESS
            } else {
                output::print_error(&CliError::InvalidArgs(format!("unknown command '{name}'")))
                    .ok();
                root.print_help().ok();
                writeln!(std::io::stdout()).ok();
                EXIT_GENERAL
            }
        }
    }
}

/// Run the parsed CLI command and return a process exit code.
pub async fn dispatch(cli: Cli) -> i32 {
    // Capture output format before partial moves.
    let fmt = cli.output.clone();

    // `payload inspect` reads a local file — no server config needed.
    if let Some(Commands::Payload { action: PayloadCommands::Inspect { ref file } }) = cli.command {
        return commands::payload::inspect_local(file, &fmt);
    }

    // `profile validate` reads a local file — no server config needed.
    if let Some(Commands::Profile { action: ProfileCommands::Validate { ref path } }) = cli.command
    {
        return commands::profile::validate_local(path, &fmt);
    }

    // `profile show` requires a server connection — falls through to normal config resolution.

    // `login` brings its own server/token — bypass normal config resolution.
    if let Some(Commands::Login { ref server, ref token, ref cert_fingerprint }) = cli.command {
        return commands::login::run(server, token, cert_fingerprint.as_deref(), &fmt).await;
    }

    // Resolve configuration (CLI flags + env vars were already absorbed by
    // clap; this step adds the file-based fallbacks).
    let resolved = match config::resolve(
        cli.server,
        cli.token,
        cli.timeout,
        cli.ca_cert,
        cli.cert_fingerprint,
        cli.pin_intermediate,
    ) {
        Ok(cfg) => cfg,
        Err(config::ConfigError::MissingServer | config::ConfigError::MissingToken)
            if config::is_unconfigured() =>
        {
            print_setup_hint();
            return EXIT_GENERAL;
        }
        Err(e) => {
            let err: CliError = e.into();
            output::print_error(&err).ok();
            return err.exit_code();
        }
    };

    // Build the shared API client.
    let api_client = match client::ApiClient::new(&resolved) {
        Ok(c) => c,
        Err(e) => {
            output::print_error(&e).ok();
            return e.exit_code();
        }
    };

    let Some(command) = cli.command else {
        // Unreachable: bare invocation is handled in main().
        return EXIT_SUCCESS;
    };

    match command {
        Commands::Status => match commands::status::run(&api_client).await {
            Ok(data) => match output::print_success(&fmt, &data) {
                Ok(()) => EXIT_SUCCESS,
                Err(e) => {
                    output::print_error(&e).ok();
                    e.exit_code()
                }
            },
            Err(e) => {
                output::print_error(&e).ok();
                e.exit_code()
            }
        },

        Commands::Agent { action } => commands::agent::run(&api_client, &fmt, action).await,

        Commands::Listener { action } => commands::listener::run(&api_client, &fmt, action).await,

        Commands::Payload { action } => commands::payload::run(&api_client, &fmt, action).await,

        Commands::Loot { action } => commands::loot::run(&api_client, &fmt, action).await,

        Commands::Audit { action } => commands::audit::run(&api_client, &fmt, action).await,

        Commands::Session { agent } => commands::session::run(&resolved, agent).await,

        Commands::Operator { action } => commands::operator::run(&api_client, &fmt, action).await,

        Commands::Profile { action: ProfileCommands::Show } => {
            match commands::profile::show_server(&api_client).await {
                Ok(data) => match output::print_success(&fmt, &data) {
                    Ok(()) => EXIT_SUCCESS,
                    Err(e) => {
                        output::print_error(&e).ok();
                        e.exit_code()
                    }
                },
                Err(e) => {
                    output::print_error(&e).ok();
                    e.exit_code()
                }
            }
        }

        // Handled above before config resolution; these arms are for exhaustiveness.
        Commands::Login { .. } => EXIT_SUCCESS,
        Commands::Profile { action: ProfileCommands::Validate { .. } } => EXIT_SUCCESS,

        // Handled synchronously in main() before the runtime is started;
        // these arms exist only for exhaustiveness.
        Commands::Completion { .. } => EXIT_SUCCESS,
        Commands::Help { .. } => EXIT_SUCCESS,
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::dispatch;
    use crate::cli::{Cli, Commands};
    use crate::error::EXIT_SUCCESS;
    use crate::output::OutputFormat;

    /// Regression: `Commands::Status` must keep calling [`crate::commands::status::run`].
    /// Exercised at the dispatch layer (no subprocess) so refactors cannot strand the handler.
    #[tokio::test]
    async fn dispatch_status_wires_through_to_status_run() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"version": "v1"})),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v1/health"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "ok",
                "uptime_secs": 1u64,
                "agents": { "active": 0, "total": 0 },
                "listeners": { "running": 0, "stopped": 0 },
                "database": "ok",
                "plugins": { "loaded": 0, "failed": 0, "disabled": 0 },
                "plugin_health": [],
            })))
            .mount(&server)
            .await;

        let cli = Cli {
            server: Some(server.uri()),
            token: Some("tok".into()),
            output: OutputFormat::Json,
            timeout: None,
            ca_cert: None,
            cert_fingerprint: None,
            pin_intermediate: false,
            command: Some(Commands::Status),
        };

        let code = dispatch(cli).await;
        assert_eq!(code, EXIT_SUCCESS);
    }

    #[test]
    fn write_setup_hint_contains_key_instructions() {
        let mut buf = Vec::new();
        super::write_setup_hint(&mut buf).expect("write");
        let output = String::from_utf8(buf).expect("utf-8");

        assert!(output.contains("no configuration found"), "should state the problem");
        assert!(output.contains("RC_SERVER"), "should mention RC_SERVER env var");
        assert!(output.contains("RC_TOKEN"), "should mention RC_TOKEN env var");
        assert!(output.contains("RC_CERT_FINGERPRINT"), "should mention cert fingerprint");
        assert!(output.contains(".toml"), "should mention a config file path");
        assert!(output.contains("red-cell-cli --help"), "should point to --help");
    }

    #[tokio::test]
    async fn dispatch_returns_general_error_when_server_missing() {
        let cli = Cli {
            server: None,
            token: Some("tok".into()),
            output: OutputFormat::Json,
            timeout: None,
            ca_cert: None,
            cert_fingerprint: None,
            pin_intermediate: false,
            command: Some(Commands::Status),
        };

        let code = dispatch(cli).await;
        assert_eq!(code, crate::error::EXIT_GENERAL);
    }

    /// `payload inspect` must work without server/token config — it operates
    /// on a local file and should be intercepted before config resolution.
    #[tokio::test]
    async fn dispatch_payload_inspect_does_not_require_server_config() {
        use crate::PayloadCommands;
        use red_cell_common::payload_manifest::{PayloadManifest, encode_manifest};

        let manifest = PayloadManifest {
            agent_type: "Demon".to_owned(),
            arch: "x64".to_owned(),
            format: "exe".to_owned(),
            hosts: vec!["10.0.0.1".to_owned()],
            port: Some(443),
            secure: true,
            callback_url: Some("https://10.0.0.1:443/".to_owned()),
            sleep_ms: Some(5000),
            jitter: Some(20),
            init_secret_hash: None,
            kill_date: None,
            working_hours_mask: None,
            listener_name: "http1".to_owned(),
            export_name: None,
            built_at: "2026-04-25T00:00:00Z".to_owned(),
        };

        let mut payload = vec![0u8; 64];
        payload.extend_from_slice(&encode_manifest(&manifest).expect("encode"));

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("agent.exe");
        std::fs::write(&path, &payload).expect("write");

        let cli = Cli {
            server: None,
            token: None,
            output: OutputFormat::Json,
            timeout: None,
            ca_cert: None,
            cert_fingerprint: None,
            pin_intermediate: false,
            command: Some(Commands::Payload {
                action: PayloadCommands::Inspect { file: path.to_str().expect("path").to_owned() },
            }),
        };

        let code = dispatch(cli).await;
        assert_eq!(code, EXIT_SUCCESS, "payload inspect must succeed without server config");
    }

    /// `profile validate` must work without server/token config — it operates
    /// on a local file and should be intercepted before config resolution.
    #[tokio::test]
    async fn dispatch_profile_validate_does_not_require_server_config() {
        use std::io::Write as _;

        use crate::cli::ProfileCommands;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("good.yaotl");
        let mut f = std::fs::File::create(&path).expect("create");
        write!(
            f,
            r#"
Teamserver {{
    Host = "0.0.0.0"
    Port = 40056
}}

Operators {{
    user "admin" {{
        Password = "secret123"
    }}
}}

Listeners {{}}

Demon {{
    Sleep  = 2
    Jitter = 10
}}
"#
        )
        .expect("write");
        drop(f);

        let cli = Cli {
            server: None,
            token: None,
            output: OutputFormat::Json,
            timeout: None,
            ca_cert: None,
            cert_fingerprint: None,
            pin_intermediate: false,
            command: Some(Commands::Profile {
                action: ProfileCommands::Validate { path: path.clone() },
            }),
        };

        let code = dispatch(cli).await;
        assert_eq!(code, EXIT_SUCCESS, "profile validate must succeed without server config");
    }

    /// `profile show` wires through to the profile endpoint on the running server.
    #[tokio::test]
    async fn dispatch_profile_show_wires_through() {
        use crate::cli::ProfileCommands;

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/api/v1/profile"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "path": "profiles/test.yaotl",
                "host": "127.0.0.1",
                "port": 40056,
                "operators": [{"name": "admin", "role": "Admin", "has_password": true}],
                "api_keys": [],
                "api_rate_limit_per_minute": null,
                "listeners": {"http": [], "smb": [], "dns": [], "external": []},
                "demon": {"sleep": 5, "jitter": 20, "indirect_syscall": false, "stack_duplication": false, "sleep_technique": null},
                "service_configured": false,
                "webhook": null
            })))
            .mount(&server)
            .await;

        let cli = Cli {
            server: Some(server.uri()),
            token: Some("tok".into()),
            output: OutputFormat::Json,
            timeout: None,
            ca_cert: None,
            cert_fingerprint: None,
            pin_intermediate: false,
            command: Some(Commands::Profile { action: ProfileCommands::Show }),
        };

        let code = dispatch(cli).await;
        assert_eq!(code, EXIT_SUCCESS);
    }
}
