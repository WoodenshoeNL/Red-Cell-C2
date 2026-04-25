//! `agent shell <id>` — interactive REPL against a connected agent.

use std::io::Write as _;

use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use tokio::task;

use crate::AgentId;
use crate::client::ApiClient;
use crate::defaults::AGENT_EXEC_WAIT_TIMEOUT_SECS;
use crate::error::{CliError, EXIT_GENERAL, EXIT_SUCCESS};

use super::exec::exec_wait;
use super::show::show;
use super::transfer::{download, upload};
use super::types::AgentDetail;

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
fn print_help() {
    eprintln!(
        "\
Built-in commands:
  help                   Show this message
  exit / quit            Leave the shell
  !<cmd>                 Execute <cmd> on the local host
  upload <src> <dst>     Upload a local file to the agent
  download <src> <dst>   Download a file from the agent to local disk
  sleep <secs>           Change the agent sleep interval

All other input is sent as a shell command to the agent."
    );
}

/// Categorised result of parsing a single input line.
enum BuiltIn<'a> {
    Help,
    Exit,
    LocalExec(&'a str),
    Upload { src: &'a str, dst: &'a str },
    Download { src: &'a str, dst: &'a str },
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
    if let Some(rest) = line.strip_prefix("upload ") {
        let rest = rest.trim();
        if let Some((src, dst)) = rest.split_once(' ') {
            return BuiltIn::Upload { src: src.trim(), dst: dst.trim() };
        }
    }
    if let Some(rest) = line.strip_prefix("download ") {
        let rest = rest.trim();
        if let Some((src, dst)) = rest.split_once(' ') {
            return BuiltIn::Download { src: src.trim(), dst: dst.trim() };
        }
    }
    BuiltIn::AgentCmd(line)
}

/// Run the interactive agent shell REPL.
///
/// Fetches agent details for the banner, then enters a read-eval-print loop.
/// Each non-builtin line is dispatched via `exec_wait`. Ctrl+C during a
/// running command cancels the wait; Ctrl+C at the prompt is a no-op.
/// Ctrl+D (EOF) exits cleanly.
pub(crate) async fn run(client: &ApiClient, id: AgentId, timeout: Option<u64>) -> i32 {
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
            BuiltIn::Help => print_help(),

            BuiltIn::LocalExec(cmd) => {
                if cmd.is_empty() {
                    eprintln!("Usage: !<command>");
                    continue;
                }
                handle_local_exec(cmd).await;
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

/// Execute a command on the local host (operator machine).
async fn handle_local_exec(cmd: &str) {
    let cmd = cmd.to_owned();
    let result = task::spawn_blocking(move || {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(&cmd)
            .status()
    })
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
        }
        Ok(Err(e)) => eprintln!("local exec failed: {e}"),
        Err(e) => eprintln!("local exec task failed: {e}"),
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
    fn parse_upload_missing_dst_falls_through() {
        assert!(matches!(parse_builtin("upload /tmp/payload.exe"), BuiltIn::AgentCmd(_)));
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
    fn parse_sleep_is_agent_command() {
        match parse_builtin("sleep 30") {
            BuiltIn::AgentCmd(cmd) => assert_eq!(cmd, "sleep 30"),
            other => panic!("expected AgentCmd, got {}", builtin_name(&other)),
        }
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

    fn builtin_name(b: &BuiltIn<'_>) -> &'static str {
        match b {
            BuiltIn::Help => "Help",
            BuiltIn::Exit => "Exit",
            BuiltIn::LocalExec(_) => "LocalExec",
            BuiltIn::Upload { .. } => "Upload",
            BuiltIn::Download { .. } => "Download",
            BuiltIn::AgentCmd(_) => "AgentCmd",
        }
    }
}
