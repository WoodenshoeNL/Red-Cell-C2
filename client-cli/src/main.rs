mod agent_id;
mod backoff;
mod bootstrap;
mod cli;
mod client;
mod commands;
mod config;
mod defaults;
mod dispatch;
mod error;
mod output;
mod tls;
mod util;

pub(crate) use agent_id::AgentId;
pub(crate) use cli::{
    AgentCommands, AuditCommands, ListenerCommands, LootCommands, OperatorCommands, PayloadCommands,
};

fn main() {
    bootstrap::run();
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use crate::AgentId;
    use crate::cli::{
        AgentCommands, AuditCommands, Cli, Commands, ListenerCommands, OperatorCommands,
        PayloadCommands,
    };
    use crate::dispatch::handle_help;
    use crate::error::{self, CliError, EXIT_GENERAL, EXIT_SUCCESS};
    use crate::output::OutputFormat;

    // ── top-level help content ───────────────────────────────────────────────

    #[test]
    fn top_level_help_contains_rc_server() {
        let help = Cli::command().render_long_help().to_string();
        assert!(help.contains("RC_SERVER"), "top-level help must mention RC_SERVER");
    }

    #[test]
    fn top_level_help_contains_rc_token() {
        let help = Cli::command().render_long_help().to_string();
        assert!(help.contains("RC_TOKEN"), "top-level help must mention RC_TOKEN");
    }

    #[test]
    fn top_level_help_contains_rc_cert_fingerprint() {
        let help = Cli::command().render_long_help().to_string();
        assert!(
            help.contains("RC_CERT_FINGERPRINT"),
            "top-level help must mention RC_CERT_FINGERPRINT"
        );
    }

    #[test]
    fn top_level_help_contains_examples_section() {
        let help = Cli::command().render_long_help().to_string();
        assert!(help.contains("Examples:"), "top-level help must have an Examples section");
        assert!(
            help.contains("red-cell-cli status"),
            "top-level help examples must include 'red-cell-cli status'"
        );
        assert!(
            help.contains("red-cell-cli agent list"),
            "top-level help examples must include 'red-cell-cli agent list'"
        );
    }

    #[test]
    fn top_level_help_contains_environment_section() {
        let help = Cli::command().render_long_help().to_string();
        assert!(help.contains("Environment:"), "top-level help must have an Environment section");
    }

    // ── per-subcommand examples ──────────────────────────────────────────────

    /// Every direct child of the root command must have "Examples:" in its long help.
    #[test]
    fn every_top_level_subcommand_has_examples() {
        let mut cmd = Cli::command();
        for sub in cmd.get_subcommands_mut() {
            let name = sub.get_name().to_owned();
            let help = sub.render_long_help().to_string();
            assert!(
                help.contains("Examples:"),
                "subcommand '{name}' help is missing an Examples section"
            );
        }
    }

    /// Spot-check a selection of second-level subcommands for examples.
    #[test]
    fn nested_subcommands_have_examples() {
        let mut cmd = Cli::command();

        // agent → exec
        let agent_exec_help = cmd
            .find_subcommand_mut("agent")
            .expect("agent subcommand")
            .find_subcommand_mut("exec")
            .expect("agent exec subcommand")
            .render_long_help()
            .to_string();
        assert!(agent_exec_help.contains("Examples:"), "agent exec help missing Examples");

        // listener → create
        let mut cmd2 = Cli::command();
        let listener_create_help = cmd2
            .find_subcommand_mut("listener")
            .expect("listener subcommand")
            .find_subcommand_mut("create")
            .expect("listener create subcommand")
            .render_long_help()
            .to_string();
        assert!(
            listener_create_help.contains("Examples:"),
            "listener create help missing Examples"
        );

        // log → list
        let mut cmd3 = Cli::command();
        let log_list_help = cmd3
            .find_subcommand_mut("log")
            .expect("log subcommand")
            .find_subcommand_mut("list")
            .expect("log list subcommand")
            .render_long_help()
            .to_string();
        assert!(log_list_help.contains("Examples:"), "log list help missing Examples");
    }

    #[test]
    fn agent_output_help_describes_numeric_since_cursor() {
        let mut cmd = Cli::command();
        let help = cmd
            .find_subcommand_mut("agent")
            .expect("agent subcommand")
            .find_subcommand_mut("output")
            .expect("agent output subcommand")
            .render_long_help()
            .to_string();

        assert!(
            help.contains("numeric output entry id"),
            "agent output help must describe --since as a numeric output entry id"
        );
        assert!(
            help.contains("--since 42"),
            "agent output help must show a numeric --since example"
        );
        assert!(
            help.contains("cursor_reset"),
            "agent output help must mention cursor_reset stderr warning"
        );
    }

    // ── help subcommand parsing ───────────────────────────────────────────────

    #[test]
    fn bare_invocation_yields_none_command() {
        let cli = Cli::try_parse_from(["red-cell-cli"]).expect("parse bare invocation");
        assert!(cli.command.is_none());
    }

    #[test]
    fn help_subcommand_parses_with_no_arg() {
        let cli = Cli::try_parse_from(["red-cell-cli", "help"]).expect("parse 'help'");
        assert!(matches!(cli.command, Some(Commands::Help { command: None })));
    }

    #[test]
    fn help_subcommand_parses_with_agent_arg() {
        let cli =
            Cli::try_parse_from(["red-cell-cli", "help", "agent"]).expect("parse 'help agent'");
        assert!(
            matches!(&cli.command, Some(Commands::Help { command: Some(c) }) if c == "agent"),
            "expected Help {{ command: Some(\"agent\") }}"
        );
    }

    #[test]
    fn help_subcommand_parses_with_listener_arg() {
        let cli = Cli::try_parse_from(["red-cell-cli", "help", "listener"])
            .expect("parse 'help listener'");
        assert!(
            matches!(&cli.command, Some(Commands::Help { command: Some(c) }) if c == "listener")
        );
    }

    // ── unknown command handling ──────────────────────────────────────────────

    #[test]
    fn unknown_command_fails_to_parse_without_panic() {
        let result = Cli::try_parse_from(["red-cell-cli", "frobnicator"]);
        assert!(result.is_err(), "unknown command must fail to parse");
    }

    #[test]
    fn handle_help_unknown_returns_exit_general() {
        let code = handle_help(Some("totally-unknown-command"));
        assert_eq!(code, EXIT_GENERAL);
    }

    /// Unknown-command error uses INVALID_ARGS code so parsers see structured JSON.
    #[test]
    fn unknown_command_error_uses_invalid_args_code() {
        let err = CliError::InvalidArgs("unknown command 'bogus'".to_owned());
        assert_eq!(err.error_code(), error::ERROR_CODE_INVALID_ARGS);
        let envelope = serde_json::json!({
            "ok": false,
            "error": err.error_code(),
            "message": err.to_string(),
        });
        assert_eq!(envelope["ok"], false);
        assert_eq!(envelope["error"], "INVALID_ARGS");
        assert!(envelope["message"].as_str().unwrap_or("").contains("unknown command"));
    }

    /// Runtime-build error uses ERROR code so parsers see structured JSON.
    #[test]
    fn runtime_build_error_uses_general_code() {
        let err =
            CliError::General("failed to build async runtime: out of file descriptors".to_owned());
        assert_eq!(err.error_code(), error::ERROR_CODE_GENERAL);
        let envelope = serde_json::json!({
            "ok": false,
            "error": err.error_code(),
            "message": err.to_string(),
        });
        assert_eq!(envelope["ok"], false);
        assert_eq!(envelope["error"], "ERROR");
        assert!(envelope["message"].as_str().unwrap_or("").contains("async runtime"));
    }

    #[test]
    fn handle_help_none_returns_exit_success() {
        let code = handle_help(None);
        assert_eq!(code, EXIT_SUCCESS);
    }

    #[test]
    fn handle_help_known_command_returns_exit_success() {
        let code = handle_help(Some("agent"));
        assert_eq!(code, EXIT_SUCCESS);
    }

    // ── log command name ──────────────────────────────────────────────────────

    #[test]
    fn audit_variant_is_exposed_as_log_command() {
        // The CLI name must be "log", not "audit".
        let cli =
            Cli::try_parse_from(["red-cell-cli", "log", "list"]).expect("'log list' must parse");
        assert!(matches!(cli.command, Some(Commands::Audit { .. })));
    }

    #[test]
    fn log_list_until_flag_parses() {
        let cli = Cli::try_parse_from([
            "red-cell-cli",
            "log",
            "list",
            "--since",
            "2026-03-21T00:00:00Z",
            "--until",
            "2026-03-22T00:00:00Z",
        ])
        .expect("log list --since --until must parse");
        match cli.command {
            Some(Commands::Audit { action: AuditCommands::List { since, until, .. } }) => {
                assert_eq!(since.as_deref(), Some("2026-03-21T00:00:00Z"));
                assert_eq!(until.as_deref(), Some("2026-03-22T00:00:00Z"));
            }
            _ => panic!("expected log list"),
        }
    }

    #[test]
    fn log_list_until_is_optional() {
        let cli =
            Cli::try_parse_from(["red-cell-cli", "log", "list", "--since", "2026-01-01T00:00:00Z"])
                .expect("log list --since only must parse");
        match cli.command {
            Some(Commands::Audit { action: AuditCommands::List { until, .. } }) => {
                assert!(until.is_none(), "--until should default to None");
            }
            _ => panic!("expected log list"),
        }
    }

    #[test]
    fn log_tail_follow_default_max_failures_is_five() {
        let cli = Cli::try_parse_from(["red-cell-cli", "log", "tail", "--follow"]).expect("parse");
        match cli.command {
            Some(Commands::Audit { action: AuditCommands::Tail { follow, max_failures } }) => {
                assert!(follow);
                assert_eq!(max_failures, crate::defaults::AUDIT_TAIL_FOLLOW_MAX_FAILURES_DEFAULT);
            }
            _ => panic!("expected log tail --follow"),
        }
    }

    #[test]
    fn log_tail_follow_parses_max_failures() {
        let cli =
            Cli::try_parse_from(["red-cell-cli", "log", "tail", "--follow", "--max-failures", "7"])
                .expect("parse");
        match cli.command {
            Some(Commands::Audit { action: AuditCommands::Tail { follow, max_failures } }) => {
                assert!(follow);
                assert_eq!(max_failures, 7);
            }
            _ => panic!("expected log tail --follow"),
        }
    }

    // ── global flag round-trips ───────────────────────────────────────────────

    #[test]
    fn server_flag_is_captured() {
        let cli = Cli::try_parse_from(["red-cell-cli", "--server", "https://ts.example.com:40056"])
            .expect("--server flag must parse");
        assert_eq!(cli.server.as_deref(), Some("https://ts.example.com:40056"));
    }

    #[test]
    fn token_flag_is_captured() {
        let cli = Cli::try_parse_from(["red-cell-cli", "--token", "secret-token-abc"])
            .expect("--token flag must parse");
        assert_eq!(cli.token.as_deref(), Some("secret-token-abc"));
    }

    #[test]
    fn output_flag_json_is_captured() {
        let cli = Cli::try_parse_from(["red-cell-cli", "--output", "json"])
            .expect("--output json must parse");
        assert!(matches!(cli.output, OutputFormat::Json));
    }

    #[test]
    fn output_flag_text_is_captured() {
        let cli = Cli::try_parse_from(["red-cell-cli", "--output", "text"])
            .expect("--output text must parse");
        assert!(matches!(cli.output, OutputFormat::Text));
    }

    #[test]
    fn default_output_format_is_json() {
        let cli = Cli::try_parse_from(["red-cell-cli"]).expect("bare invocation must parse");
        assert!(matches!(cli.output, OutputFormat::Json), "default --output must be json");
    }

    #[test]
    fn timeout_flag_is_captured() {
        let cli = Cli::try_parse_from(["red-cell-cli", "--timeout", "60"])
            .expect("--timeout flag must parse");
        assert_eq!(cli.timeout, Some(60));
    }

    #[test]
    fn default_timeout_is_none_when_omitted() {
        let cli = Cli::try_parse_from(["red-cell-cli"]).expect("bare invocation must parse");
        assert!(cli.timeout.is_none(), "omitting --timeout must yield None, not a sentinel");
    }

    #[test]
    fn server_and_token_and_timeout_together() {
        let cli = Cli::try_parse_from([
            "red-cell-cli",
            "--server",
            "https://ts:40056",
            "--token",
            "tok",
            "--timeout",
            "120",
            "status",
        ])
        .expect("combined global flags with subcommand must parse");
        assert_eq!(cli.server.as_deref(), Some("https://ts:40056"));
        assert_eq!(cli.token.as_deref(), Some("tok"));
        assert_eq!(cli.timeout, Some(120));
        assert!(matches!(cli.command, Some(Commands::Status)));
    }

    // ── invalid flags produce errors ──────────────────────────────────────────

    #[test]
    fn invalid_flag_returns_error() {
        let result = Cli::try_parse_from(["red-cell-cli", "--invalid-flag"]);
        assert!(result.is_err(), "unknown flag must return an error");
    }

    #[test]
    fn invalid_output_value_returns_error() {
        let result = Cli::try_parse_from(["red-cell-cli", "--output", "yaml"]);
        assert!(result.is_err(), "invalid --output value must return an error");
    }

    #[test]
    fn non_numeric_timeout_returns_error() {
        let result = Cli::try_parse_from(["red-cell-cli", "--timeout", "notanumber"]);
        assert!(result.is_err(), "non-numeric --timeout must return an error");
    }

    // ── payload build --agent flag ───────────────────────────────────────────

    #[test]
    fn payload_build_agent_defaults_to_demon() {
        let cli = Cli::try_parse_from([
            "red-cell-cli",
            "payload",
            "build",
            "--listener",
            "http1",
            "--arch",
            "x64",
            "--format",
            "exe",
        ])
        .expect("payload build must parse without --agent");
        match cli.command {
            Some(Commands::Payload { action: PayloadCommands::Build { agent, .. } }) => {
                assert_eq!(agent, "demon", "--agent must default to 'demon'")
            }
            other => panic!("expected Payload::Build, got {other:?}"),
        }
    }

    #[test]
    fn payload_build_agent_flag_is_captured() {
        let cli = Cli::try_parse_from([
            "red-cell-cli",
            "payload",
            "build",
            "--listener",
            "http1",
            "--arch",
            "x64",
            "--format",
            "bin",
            "--agent",
            "phantom",
        ])
        .expect("payload build --agent phantom must parse");
        match cli.command {
            Some(Commands::Payload { action: PayloadCommands::Build { agent, .. } }) => {
                assert_eq!(agent, "phantom")
            }
            other => panic!("expected Payload::Build, got {other:?}"),
        }
    }

    // ── --wait-timeout flags ─────────────────────────────────────────────────

    #[test]
    fn agent_exec_wait_timeout_is_captured() {
        let cli = Cli::try_parse_from([
            "red-cell-cli",
            "agent",
            "exec",
            "abc123",
            "--cmd",
            "whoami",
            "--wait",
            "--wait-timeout",
            "120",
        ])
        .expect("agent exec --wait --wait-timeout must parse");
        match cli.command {
            Some(Commands::Agent { action: AgentCommands::Exec { wait_timeout, .. } }) => {
                assert_eq!(wait_timeout, Some(120));
            }
            other => panic!("expected Agent::Exec, got {other:?}"),
        }
    }

    #[test]
    fn agent_exec_wait_timeout_defaults_to_none_when_omitted() {
        let cli = Cli::try_parse_from([
            "red-cell-cli",
            "agent",
            "exec",
            "abc123",
            "--cmd",
            "whoami",
            "--wait",
        ])
        .expect("agent exec --wait without --wait-timeout must parse");
        match cli.command {
            Some(Commands::Agent { action: AgentCommands::Exec { wait_timeout, .. } }) => {
                assert!(
                    wait_timeout.is_none(),
                    "omitting --wait-timeout must yield None (default applied in handler)"
                );
            }
            other => panic!("expected Agent::Exec, got {other:?}"),
        }
    }

    #[test]
    fn agent_show_rejects_ambiguous_digit_only_id() {
        let err = Cli::try_parse_from(["red-cell-cli", "agent", "show", "1234"])
            .expect_err("ambiguous digit-only id must be rejected");
        let rendered = err.to_string();
        assert!(rendered.contains("ambiguous agent id '1234'"));
        assert!(rendered.contains("0x<hex>"));
    }

    #[test]
    fn session_accepts_explicit_decimal_default_agent() {
        let cli = Cli::try_parse_from(["red-cell-cli", "session", "--agent", "dec:42"])
            .expect("explicit decimal default agent must parse");
        match cli.command {
            Some(Commands::Session { agent }) => assert_eq!(agent, Some(AgentId::new(42))),
            other => panic!("expected Session, got {other:?}"),
        }
    }

    #[test]
    fn agent_exec_help_mentions_default_wait_timeout() {
        let mut cmd = Cli::command();
        let help = cmd
            .find_subcommand_mut("agent")
            .expect("agent subcommand")
            .find_subcommand_mut("exec")
            .expect("agent exec subcommand")
            .render_long_help()
            .to_string();

        assert!(help.contains("default: 60"), "agent exec help must mention the default timeout");
        assert!(help.contains("--wait-timeout"), "agent exec help must mention the override flag");
    }

    #[test]
    fn payload_build_wait_timeout_is_captured() {
        let cli = Cli::try_parse_from([
            "red-cell-cli",
            "payload",
            "build",
            "--listener",
            "http1",
            "--arch",
            "x86_64",
            "--format",
            "exe",
            "--wait",
            "--wait-timeout",
            "600",
        ])
        .expect("payload build --wait --wait-timeout must parse");
        match cli.command {
            Some(Commands::Payload { action: PayloadCommands::Build { wait_timeout, .. } }) => {
                assert_eq!(wait_timeout, Some(600));
            }
            other => panic!("expected Payload::Build, got {other:?}"),
        }
    }

    #[test]
    fn payload_build_wait_timeout_defaults_to_none_when_omitted() {
        let cli = Cli::try_parse_from([
            "red-cell-cli",
            "payload",
            "build",
            "--listener",
            "http1",
            "--arch",
            "x86_64",
            "--format",
            "exe",
        ])
        .expect("payload build without --wait-timeout must parse");
        match cli.command {
            Some(Commands::Payload { action: PayloadCommands::Build { wait_timeout, .. } }) => {
                assert!(
                    wait_timeout.is_none(),
                    "omitting --wait-timeout must yield None (default applied in handler)"
                );
            }
            other => panic!("expected Payload::Build, got {other:?}"),
        }
    }

    #[test]
    fn payload_build_help_mentions_default_wait_timeout() {
        let mut cmd = Cli::command();
        let help = cmd
            .find_subcommand_mut("payload")
            .expect("payload subcommand")
            .find_subcommand_mut("build")
            .expect("payload build subcommand")
            .render_long_help()
            .to_string();

        assert!(
            help.contains("default: 300"),
            "payload build help must mention the default timeout"
        );
        assert!(
            help.contains("--wait-timeout"),
            "payload build help must mention the override flag"
        );
    }

    #[test]
    fn audit_tail_help_mentions_default_poll_interval() {
        let mut cmd = Cli::command();
        let help = cmd
            .find_subcommand_mut("log")
            .expect("log subcommand")
            .find_subcommand_mut("tail")
            .expect("log tail subcommand")
            .render_long_help()
            .to_string();

        assert!(
            help.contains("default: 1"),
            "log tail help must mention the default poll interval"
        );
        assert!(help.contains("Polls every 1 second"), "log tail help must mention polling");
        assert!(help.contains("--max-failures"), "log tail help must mention --max-failures");
        assert!(
            help.contains("default: 5"),
            "log tail help must mention the default max consecutive HTTP timeouts"
        );
    }

    #[test]
    fn log_server_tail_help_mentions_examples() {
        let mut cmd = Cli::command();
        let help = cmd
            .find_subcommand_mut("log")
            .expect("log subcommand")
            .find_subcommand_mut("server-tail")
            .expect("log server-tail subcommand")
            .render_long_help()
            .to_string();

        assert!(help.contains("Examples:"), "log server-tail help missing Examples");
        assert!(help.contains("--lines"), "log server-tail help must mention --lines");
    }

    #[test]
    fn rbac_agent_groups_subcommands_parse() {
        let g = Cli::try_parse_from(["red-cell-cli", "agent", "groups", "DEADBEEF"])
            .expect("agent groups");
        assert!(matches!(
            g.command,
            Some(Commands::Agent { action: AgentCommands::Groups { .. } })
        ));

        let s = Cli::try_parse_from([
            "red-cell-cli",
            "agent",
            "set-groups",
            "AABBCCDD",
            "--group",
            "g1",
            "--group",
            "g2",
        ])
        .expect("agent set-groups");
        match s.command {
            Some(Commands::Agent { action: AgentCommands::SetGroups { id, group } }) => {
                assert_eq!(id, AgentId::new(0xAABBCCDD));
                assert_eq!(group, vec!["g1", "g2"]);
            }
            other => panic!("expected Agent::SetGroups, got {other:?}"),
        }
    }

    #[test]
    fn rbac_operator_agent_groups_subcommands_parse() {
        let show = Cli::try_parse_from(["red-cell-cli", "operator", "show-agent-groups", "alice"])
            .expect("show-agent-groups");
        assert!(matches!(
            show.command,
            Some(Commands::Operator { action: OperatorCommands::ShowAgentGroups { .. } })
        ));

        let set = Cli::try_parse_from([
            "red-cell-cli",
            "operator",
            "set-agent-groups",
            "bob",
            "--group",
            "tier1",
        ])
        .expect("set-agent-groups");
        match set.command {
            Some(Commands::Operator {
                action: OperatorCommands::SetAgentGroups { username, group },
            }) => {
                assert_eq!(username, "bob");
                assert_eq!(group, vec!["tier1"]);
            }
            other => panic!("expected Operator::SetAgentGroups, got {other:?}"),
        }
    }

    #[test]
    fn rbac_listener_access_subcommands_parse() {
        let a =
            Cli::try_parse_from(["red-cell-cli", "listener", "access", "http1"]).expect("access");
        assert!(matches!(
            a.command,
            Some(Commands::Listener { action: ListenerCommands::Access { .. } })
        ));

        let s = Cli::try_parse_from([
            "red-cell-cli",
            "listener",
            "set-access",
            "dns1",
            "--allow-operator",
            "u1",
            "--allow-operator",
            "u2",
        ])
        .expect("set-access");
        match s.command {
            Some(Commands::Listener {
                action: ListenerCommands::SetAccess { name, allow_operator },
            }) => {
                assert_eq!(name, "dns1");
                assert_eq!(allow_operator, vec!["u1", "u2"]);
            }
            other => panic!("expected Listener::SetAccess, got {other:?}"),
        }
    }

    // ── payload inspect ─────────────────────────────────────────────────────

    #[test]
    fn payload_inspect_parses_file_argument() {
        let cli = Cli::try_parse_from(["red-cell-cli", "payload", "inspect", "./agent.exe"])
            .expect("payload inspect must parse");
        match cli.command {
            Some(Commands::Payload { action: PayloadCommands::Inspect { file } }) => {
                assert_eq!(file, "./agent.exe")
            }
            other => panic!("expected Payload::Inspect, got {other:?}"),
        }
    }

    #[test]
    fn payload_inspect_rejects_missing_file_argument() {
        let result = Cli::try_parse_from(["red-cell-cli", "payload", "inspect"]);
        assert!(result.is_err(), "payload inspect without file arg must fail");
    }
}
