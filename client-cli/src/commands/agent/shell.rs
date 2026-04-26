//! `agent shell <id> --unsafe-tty` — interactive REPL against a connected agent.
//!
//! Gated behind `--unsafe-tty` because it uses interactive readline I/O and
//! writes raw command output to stdout, violating the JSON envelope contract.
//! For machine-consumable agent interaction, use `session --agent <id>`.

use std::io::Write as _;

use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use tokio::task;
use tracing::warn;

use serde::Serialize;

use red_cell_common::demon::{COMMAND_SLEEP_ID, format_sleep_payload_base64};

use crate::AgentId;
use crate::client::ApiClient;
use crate::defaults::AGENT_EXEC_WAIT_TIMEOUT_SECS;
use crate::error::{CliError, EXIT_GENERAL, EXIT_SUCCESS};

use super::exec::exec_wait;
use super::show::show;
use super::transfer::{download, upload};
use super::types::AgentDetail;
use super::wire::TaskQueuedResponse;

const HISTORY_FILE_NAME: &str = "shell_history";
const DEFAULT_MAX_UPLOAD_MB: u64 = 100;

/// Resolve the history file path: `~/.config/red-cell-cli/shell_history`.
fn history_path() -> Option<std::path::PathBuf> {
    dirs::config_dir().map(|d| d.join("red-cell-cli").join(HISTORY_FILE_NAME))
}

/// Print the connection banner to stderr.
fn print_banner(detail: &AgentDetail) {
    let user = detail.username.as_deref().unwrap_or("?");
    eprintln!(
        "Connected to agent {} on {} ({}).  User: {user}\n\
         Type help for built-ins, exit to leave.",
        detail.id, detail.hostname, detail.os
    );
}

/// Print the built-in command help to stderr.
fn print_help(local_shell_enabled: bool) {
    let local_shell_line = if local_shell_enabled {
        "  !<cmd>                 Run <cmd> on the OPERATOR HOST (not the agent) [enabled]"
    } else {
        "  !<cmd>                 (disabled — pass --enable-local-shell to allow)"
    };
    eprintln!(
        "\
Built-in commands:
  help                   Show this message
  exit / quit            Leave the shell
{local_shell_line}
  upload <src> <dst>     Upload a local file to the agent
  download <src> <dst>   Download a file from the agent to local disk
  sleep <secs> [jitter%] Change the agent sleep interval (jitter default: 0)

All other input is sent as a shell command to the remote agent."
    );
}

/// Categorised result of parsing a single input line.
enum BuiltIn<'a> {
    Help,
    Exit,
    LocalExec(&'a str),
    Upload { src: &'a str, dst: &'a str },
    Download { src: &'a str, dst: &'a str },
    Sleep { delay: u32, jitter: u32 },
    UsageError(&'static str),
    AgentCmd(&'a str),
}

/// Parse a trimmed, non-empty input line into a [`BuiltIn`] variant.
fn parse_builtin(line: &str) -> BuiltIn<'_> {
    if line == "exit" || line == "quit" {
        return BuiltIn::Exit;
    }
    if line == "help" {
        return BuiltIn::Help;
    }
    if let Some(local_cmd) = line.strip_prefix('!') {
        return BuiltIn::LocalExec(local_cmd.trim());
    }
    if let Some(rest) = line.strip_prefix("upload").filter(|r| r.is_empty() || r.starts_with(' ')) {
        let rest = rest.trim();
        if let Some((src, dst)) = rest.split_once(' ') {
            return BuiltIn::Upload { src: src.trim(), dst: dst.trim() };
        }
        return BuiltIn::UsageError("Usage: upload <local-src> <remote-dst>");
    }
    if let Some(rest) = line.strip_prefix("download").filter(|r| r.is_empty() || r.starts_with(' '))
    {
        let rest = rest.trim();
        if let Some((src, dst)) = rest.split_once(' ') {
            return BuiltIn::Download { src: src.trim(), dst: dst.trim() };
        }
        return BuiltIn::UsageError("Usage: download <remote-src> <local-dst>");
    }
    if let Some(rest) = line.strip_prefix("sleep").filter(|r| r.is_empty() || r.starts_with(' ')) {
        let rest = rest.trim();
        if !rest.is_empty() {
            let mut parts = rest.split_whitespace();
            if let Some(Ok(delay)) = parts.next().map(|s| s.parse::<u32>()) {
                let jitter = parts.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
                return BuiltIn::Sleep { delay, jitter };
            }
        }
        return BuiltIn::UsageError("Usage: sleep <secs> [jitter%]");
    }
    BuiltIn::AgentCmd(line)
}

/// Run the interactive agent shell REPL.
///
/// Fetches agent details for the banner, then enters a read-eval-print loop.
/// Each non-builtin line is dispatched via `exec_wait`. Ctrl+C during a
/// running command cancels the wait; Ctrl+C at the prompt is a no-op.
/// Ctrl+D (EOF) exits cleanly.
pub(crate) async fn run(
    client: &ApiClient,
    id: AgentId,
    timeout: Option<u64>,
    enable_local_shell: bool,
    operator: &str,
) -> i32 {
    let timeout_secs = timeout.unwrap_or(AGENT_EXEC_WAIT_TIMEOUT_SECS);

    let detail = match show(client, id).await {
        Ok(d) => d,
        Err(e) => {
            crate::output::print_error(&e).ok();
            return e.exit_code();
        }
    };

    print_banner(&detail);

    let mut editor = match DefaultEditor::new() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("Failed to initialise readline: {e}");
            return EXIT_GENERAL;
        }
    };

    if let Some(path) = history_path() {
        let _ = editor.load_history(&path);
    }

    let prompt = format!("{}> ", detail.hostname);

    loop {
        let p = prompt.clone();
        let (ed, result) = match task::spawn_blocking(move || {
            let res = editor.readline(&p);
            (editor, res)
        })
        .await
        {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("readline task failed: {e}");
                return EXIT_GENERAL;
            }
        };
        editor = ed;

        let line = match result {
            Ok(l) => l,
            Err(ReadlineError::Interrupted) => continue,
            Err(ReadlineError::Eof) => break,
            Err(e) => {
                eprintln!("readline error: {e}");
                break;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let _ = editor.add_history_entry(trimmed);

        match parse_builtin(trimmed) {
            BuiltIn::Exit => break,
            BuiltIn::Help => print_help(enable_local_shell),

            BuiltIn::LocalExec(cmd) => {
                if !enable_local_shell {
                    eprintln!(
                        "Local shell execution is disabled. \
                         Pass --enable-local-shell or set enable_local_shell = true \
                         in the config file to allow !<cmd>."
                    );
                    continue;
                }
                if cmd.is_empty() {
                    eprintln!("Usage: !<command>");
                    continue;
                }
                warn!(
                    audit_event = "local_exec",
                    command = cmd,
                    agent_id = %id,
                    operator = operator,
                    "operator executing local shell command"
                );
                let success = handle_local_exec(cmd).await;
                let audit_client = client.clone();
                let audit_operator = operator.to_owned();
                let audit_cmd = cmd.to_owned();
                tokio::spawn(async move {
                    forward_local_exec_audit(
                        &audit_client,
                        &audit_operator,
                        &audit_cmd,
                        id,
                        success,
                    )
                    .await;
                });
            }

            BuiltIn::Upload { src, dst } => {
                match upload(client, id, src, dst, DEFAULT_MAX_UPLOAD_MB).await {
                    Ok(r) => {
                        let jid = r.job_id.as_deref().unwrap_or("?");
                        eprintln!("Upload queued: job {jid}");
                    }
                    Err(e) => eprintln!("Upload failed: {e}"),
                }
            }

            BuiltIn::Download { src, dst } => match download(client, id, src, dst).await {
                Ok(r) => eprintln!("Downloaded to {}", r.local_path),
                Err(e) => eprintln!("Download failed: {e}"),
            },

            BuiltIn::Sleep { delay, jitter } => {
                match sleep_submit(client, id, delay, jitter).await {
                    Ok(_) => {
                        eprintln!("Sleep set to {delay}s (jitter {jitter}%)");
                    }
                    Err(e) => eprintln!("Sleep failed: {e}"),
                }
            }

            BuiltIn::UsageError(msg) => eprintln!("{msg}"),

            BuiltIn::AgentCmd(cmd) => {
                run_agent_command(client, id, cmd, timeout_secs).await;
            }
        }
    }

    save_history(&mut editor);
    EXIT_SUCCESS
}

/// Execute a command on the agent, with Ctrl+C cancellation.
async fn run_agent_command(client: &ApiClient, id: AgentId, cmd: &str, timeout_secs: u64) {
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    tokio::select! {
        biased;
        _ = &mut ctrl_c => {
            eprintln!("\nCommand cancelled.");
        }
        result = exec_wait(client, id, cmd, timeout_secs) => {
            match result {
                Ok(exec_result) => {
                    print!("{}", exec_result.output);
                    std::io::stdout().flush().ok();
                }
                Err(CliError::Timeout(msg)) => {
                    eprintln!("Timed out: {msg}");
                }
                Err(e) => {
                    eprintln!("Error: {e}");
                }
            }
        }
    }
}

/// Submit a `CommandSleep` task to change the agent's check-in interval.
async fn sleep_submit(
    client: &ApiClient,
    id: AgentId,
    delay: u32,
    jitter: u32,
) -> Result<(), CliError> {
    #[derive(Serialize)]
    struct Body<'a> {
        #[serde(rename = "CommandLine")]
        command_line: String,
        #[serde(rename = "CommandID")]
        command_id: &'static str,
        #[serde(rename = "DemonID")]
        demon_id: &'a str,
        #[serde(rename = "TaskID")]
        task_id: &'static str,
        #[serde(rename = "PayloadBase64")]
        payload_base64: String,
    }

    let demon_id = id.to_string();
    let _resp: TaskQueuedResponse = client
        .post(
            &format!("/agents/{id}/task"),
            &Body {
                command_line: format!("sleep {delay} {jitter}"),
                command_id: COMMAND_SLEEP_ID,
                demon_id: &demon_id,
                task_id: "",
                payload_base64: format_sleep_payload_base64(delay, jitter),
            },
        )
        .await?;
    Ok(())
}

/// POST a `local_exec` audit event to the teamserver.
///
/// Fails open: a warning is logged if the request fails but execution is not
/// blocked.
async fn forward_local_exec_audit(
    client: &ApiClient,
    operator: &str,
    cmd: &str,
    agent_id: AgentId,
    success: bool,
) {
    #[derive(Serialize)]
    struct AuditBody<'a> {
        action: &'a str,
        target_kind: &'a str,
        target_id: Option<&'a str>,
        agent_id: Option<u32>,
        command: Option<&'a str>,
        parameters: Option<serde_json::Value>,
        result_status: &'a str,
    }

    #[derive(serde::Deserialize)]
    struct AuditResponse {
        #[allow(dead_code)]
        id: i64,
    }

    let body = AuditBody {
        action: "operator.local_exec",
        target_kind: "agent",
        target_id: None,
        agent_id: Some(agent_id.as_u32()),
        command: Some(cmd),
        parameters: Some(serde_json::json!({
            "operator": operator,
            "raw_command": cmd,
        })),
        result_status: if success { "success" } else { "failure" },
    };

    if let Err(e) = client.post::<AuditBody<'_>, AuditResponse>("/audit", &body).await {
        warn!(
            %e,
            "failed to forward local_exec audit event to teamserver"
        );
    }
}

/// Execute a command on the local host (operator machine).
async fn handle_local_exec(cmd: &str) -> bool {
    let cmd = cmd.to_owned();
    let result =
        task::spawn_blocking(move || std::process::Command::new("sh").arg("-c").arg(&cmd).status())
            .await;

    match result {
        Ok(Ok(status)) => {
            if !status.success() {
                if let Some(code) = status.code() {
                    eprintln!("[local exit {code}]");
                } else {
                    eprintln!("[local process terminated by signal]");
                }
            }
            status.success()
        }
        Ok(Err(e)) => {
            eprintln!("local exec failed: {e}");
            false
        }
        Err(e) => {
            eprintln!("local exec task failed: {e}");
            false
        }
    }
}

/// Persist readline history to disk.
fn save_history(editor: &mut DefaultEditor) {
    if let Some(path) = history_path() {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = editor.save_history(&path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_exit() {
        assert!(matches!(parse_builtin("exit"), BuiltIn::Exit));
        assert!(matches!(parse_builtin("quit"), BuiltIn::Exit));
    }

    #[test]
    fn parse_help() {
        assert!(matches!(parse_builtin("help"), BuiltIn::Help));
    }

    #[test]
    fn parse_local_exec() {
        match parse_builtin("!ls -la") {
            BuiltIn::LocalExec(cmd) => assert_eq!(cmd, "ls -la"),
            other => panic!("expected LocalExec, got {}", builtin_name(&other)),
        }
    }

    #[test]
    fn parse_local_exec_empty() {
        match parse_builtin("!") {
            BuiltIn::LocalExec(cmd) => assert_eq!(cmd, ""),
            other => panic!("expected LocalExec, got {}", builtin_name(&other)),
        }
    }

    #[test]
    fn parse_upload() {
        match parse_builtin("upload /tmp/payload.exe C:\\Windows\\Temp\\p.exe") {
            BuiltIn::Upload { src, dst } => {
                assert_eq!(src, "/tmp/payload.exe");
                assert_eq!(dst, "C:\\Windows\\Temp\\p.exe");
            }
            other => panic!("expected Upload, got {}", builtin_name(&other)),
        }
    }

    #[test]
    fn parse_upload_missing_dst_returns_usage_error() {
        assert!(matches!(parse_builtin("upload /tmp/payload.exe"), BuiltIn::UsageError(_)));
    }

    #[test]
    fn parse_upload_no_args_returns_usage_error() {
        assert!(matches!(parse_builtin("upload"), BuiltIn::UsageError(_)));
        assert!(matches!(parse_builtin("upload  "), BuiltIn::UsageError(_)));
    }

    #[test]
    fn parse_download_missing_dst_returns_usage_error() {
        assert!(matches!(parse_builtin("download C:\\secret.txt"), BuiltIn::UsageError(_)));
    }

    #[test]
    fn parse_download_no_args_returns_usage_error() {
        assert!(matches!(parse_builtin("download"), BuiltIn::UsageError(_)));
        assert!(matches!(parse_builtin("download  "), BuiltIn::UsageError(_)));
    }

    #[test]
    fn parse_download() {
        match parse_builtin("download C:\\secret.txt ./loot.txt") {
            BuiltIn::Download { src, dst } => {
                assert_eq!(src, "C:\\secret.txt");
                assert_eq!(dst, "./loot.txt");
            }
            other => panic!("expected Download, got {}", builtin_name(&other)),
        }
    }

    #[test]
    fn parse_regular_command() {
        match parse_builtin("whoami") {
            BuiltIn::AgentCmd(cmd) => assert_eq!(cmd, "whoami"),
            other => panic!("expected AgentCmd, got {}", builtin_name(&other)),
        }
    }

    #[test]
    fn parse_sleep_delay_only() {
        match parse_builtin("sleep 30") {
            BuiltIn::Sleep { delay, jitter } => {
                assert_eq!(delay, 30);
                assert_eq!(jitter, 0);
            }
            other => panic!("expected Sleep, got {}", builtin_name(&other)),
        }
    }

    #[test]
    fn parse_sleep_delay_and_jitter() {
        match parse_builtin("sleep 60 15") {
            BuiltIn::Sleep { delay, jitter } => {
                assert_eq!(delay, 60);
                assert_eq!(jitter, 15);
            }
            other => panic!("expected Sleep, got {}", builtin_name(&other)),
        }
    }

    #[test]
    fn parse_sleep_non_numeric_shows_usage() {
        assert!(matches!(parse_builtin("sleep abc"), BuiltIn::UsageError(_)));
    }

    #[test]
    fn parse_sleep_bare_shows_usage() {
        assert!(matches!(parse_builtin("sleep"), BuiltIn::UsageError(_)));
    }

    #[test]
    fn parse_sleep_whitespace_only_shows_usage() {
        assert!(matches!(parse_builtin("sleep   "), BuiltIn::UsageError(_)));
    }

    #[test]
    fn history_path_contains_expected_components() {
        if let Some(p) = history_path() {
            let s = p.to_string_lossy();
            assert!(s.contains("red-cell-cli"), "path should contain red-cell-cli: {s}");
            assert!(
                s.ends_with(HISTORY_FILE_NAME),
                "path should end with {HISTORY_FILE_NAME}: {s}"
            );
        }
    }

    #[test]
    fn help_with_local_shell_enabled_does_not_panic() {
        print_help(true);
    }

    #[test]
    fn help_with_local_shell_disabled_does_not_panic() {
        print_help(false);
    }

    fn builtin_name(b: &BuiltIn<'_>) -> &'static str {
        match b {
            BuiltIn::Help => "Help",
            BuiltIn::Exit => "Exit",
            BuiltIn::LocalExec(_) => "LocalExec",
            BuiltIn::Upload { .. } => "Upload",
            BuiltIn::Download { .. } => "Download",
            BuiltIn::Sleep { .. } => "Sleep",
            BuiltIn::UsageError(_) => "UsageError",
            BuiltIn::AgentCmd(_) => "AgentCmd",
        }
    }

    fn test_client(uri: &str) -> ApiClient {
        let cfg = crate::config::ResolvedConfig {
            server: uri.to_owned(),
            token: "tok".to_owned(),
            timeout: 5,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        ApiClient::new(&cfg).expect("test client")
    }

    #[tokio::test]
    async fn forward_local_exec_audit_posts_to_teamserver() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/audit"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": 42
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = test_client(&server.uri());
        let agent_id = AgentId::new(0xDEAD);

        forward_local_exec_audit(&client, "alice", "whoami", agent_id, true).await;
    }

    #[tokio::test]
    async fn forward_local_exec_audit_sends_failure_status() {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/audit"))
            .and(body_string_contains(r#""result_status":"failure""#))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": 43
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = test_client(&server.uri());
        let agent_id = AgentId::new(0xDEAD);

        forward_local_exec_audit(&client, "alice", "false", agent_id, false).await;
    }

    #[tokio::test]
    async fn forward_local_exec_audit_fails_open_on_server_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/audit"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;

        let client = test_client(&server.uri());
        let agent_id = AgentId::new(0xBEEF);

        // Must not panic — fails open.
        forward_local_exec_audit(&client, "bob", "id", agent_id, true).await;
    }

    #[tokio::test]
    async fn forward_local_exec_audit_fails_open_on_unreachable() {
        let cfg = crate::config::ResolvedConfig {
            server: "http://127.0.0.1:1".to_owned(),
            token: "tok".to_owned(),
            timeout: 1,
            tls_mode: crate::config::TlsMode::SystemRoots,
        };
        let client = ApiClient::new(&cfg).expect("test client");
        let agent_id = AgentId::new(0xCAFE);

        // Must not panic — fails open.
        forward_local_exec_audit(&client, "charlie", "ls", agent_id, true).await;
    }
}
