//! Compiler invocation, diagnostic parsing, and source file discovery.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use red_cell_common::operator::CompilerDiagnostic;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc;

use super::formats::Architecture;
use super::{BuildProgress, MAX_STDERR_TAIL_LINES, PayloadBuildError};

/// Tag identifying which stream a line originated from.
enum StreamTag {
    Stdout,
    Stderr,
}

/// Spawn a compiler command, stream its output via `progress`, and collect
/// stderr for diagnostic parsing on failure.
pub(super) async fn run_command<F>(
    program: &Path,
    args: &[OsString],
    cwd: &Path,
    progress: &mut F,
) -> Result<(), PayloadBuildError>
where
    F: FnMut(BuildProgress),
{
    let command_line = std::iter::once(program.display().to_string())
        .chain(args.iter().map(|arg| arg.to_string_lossy().into_owned()))
        .collect::<Vec<_>>()
        .join(" ");
    progress(BuildProgress { level: "Info".to_owned(), message: command_line.clone() });

    let mut command = Command::new(program);
    command.args(args).current_dir(cwd).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| PayloadBuildError::Io(std::io::Error::other("missing child stdout")))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| PayloadBuildError::Io(std::io::Error::other("missing child stderr")))?;

    // Use a tagged channel so stdout and stderr lines can be handled differently.
    // Stderr lines are collected for diagnostic parsing on failure.
    let (sender, mut receiver) = mpsc::unbounded_channel::<(StreamTag, String)>();
    let stdout_sender = sender.clone();
    let stderr_sender = sender;

    let stdout_task = tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        while let Some(line) = lines.next_line().await? {
            let _ = stdout_sender.send((StreamTag::Stdout, line));
        }
        Ok::<(), std::io::Error>(())
    });
    let stderr_task = tokio::spawn(async move {
        let mut lines = BufReader::new(stderr).lines();
        while let Some(line) = lines.next_line().await? {
            let _ = stderr_sender.send((StreamTag::Stderr, line));
        }
        Ok::<(), std::io::Error>(())
    });

    let mut stderr_lines: Vec<String> = Vec::new();
    while let Some((tag, line)) = receiver.recv().await {
        if line.trim().is_empty() {
            continue;
        }
        match tag {
            StreamTag::Stdout => {
                progress(BuildProgress { level: "Info".to_owned(), message: line });
            }
            StreamTag::Stderr => {
                stderr_lines.push(line.clone());
                // Forward stderr as a warning so the operator sees it in real time.
                progress(BuildProgress { level: "Warning".to_owned(), message: line });
            }
        }
    }

    let status = child.wait().await?;
    stdout_task.await.map_err(|source| PayloadBuildError::Io(std::io::Error::other(source)))??;
    stderr_task.await.map_err(|source| PayloadBuildError::Io(std::io::Error::other(source)))??;

    if status.success() {
        Ok(())
    } else {
        let diagnostics =
            stderr_lines.iter().filter_map(|l| parse_compiler_diagnostic(l)).collect();
        let stderr_tail: Vec<String> =
            stderr_lines.into_iter().take(MAX_STDERR_TAIL_LINES).collect();
        Err(PayloadBuildError::CommandFailed { command: command_line, diagnostics, stderr_tail })
    }
}

/// Try to parse a single line of GCC or NASM compiler output as a structured diagnostic.
///
/// Handles the common format used by both compilers on Linux:
/// - `filename:line:col: severity: message`
/// - `filename:line: severity: message`
///
/// The optional flag that GCC appends at the end of warnings (`[-Wfoo]`) is
/// extracted as `error_code` when present.
pub fn parse_compiler_diagnostic(line: &str) -> Option<CompilerDiagnostic> {
    let line = line.trim_start();

    // Find the first colon that terminates the filename. On Linux, source paths
    // do not contain colons, so the first colon reliably marks the boundary.
    let first_colon = line.find(':')?;
    let filename = &line[..first_colon];
    if filename.is_empty() {
        return None;
    }

    // After the first colon: line-number[:col]: severity: message
    let after_filename = &line[first_colon + 1..];
    let second_colon = after_filename.find(':')?;
    let line_num: u32 = after_filename[..second_colon].trim().parse().ok()?;

    // What follows the line number colon may be either a column number or the severity.
    let after_line = &after_filename[second_colon + 1..];
    let (column, severity_text) = {
        if let Some(next_colon) = after_line.find(':') {
            let candidate = after_line[..next_colon].trim();
            if let Ok(col) = candidate.parse::<u32>() {
                (Some(col), after_line[next_colon + 1..].trim_start())
            } else {
                (None, after_line.trim_start())
            }
        } else {
            (None, after_line.trim_start())
        }
    };

    // Severity is one of the known GCC/NASM severity labels.
    const SEVERITIES: &[&str] = &["fatal error", "error", "warning", "note"];
    let (severity, rest_after_severity) = SEVERITIES
        .iter()
        .find_map(|&sev| severity_text.strip_prefix(sev).map(|rest| (sev, rest)))?;

    // After the severity there must be a `: message`.
    let message_raw = rest_after_severity.trim_start().strip_prefix(':')?.trim();
    if message_raw.is_empty() {
        return None;
    }

    // GCC appends the triggering flag in brackets at the end of warnings, e.g.
    // `unused variable 'x' [-Wunused-variable]`.  Extract it as error_code.
    let (message, error_code) = extract_gcc_flag(message_raw);

    Some(CompilerDiagnostic {
        filename: filename.to_owned(),
        line: line_num,
        column,
        severity: severity.to_owned(),
        error_code,
        message,
    })
}

/// Extract a trailing GCC diagnostic flag from a message, if present.
///
/// GCC appends flags in the form `[-Wfoo]` or `[-Werror=foo]` at the end of
/// warning/error messages.  Returns `(message_without_flag, Some(flag))` when
/// the pattern is matched, or `(message, None)` otherwise.
fn extract_gcc_flag(message: &str) -> (String, Option<String>) {
    let trimmed = message.trim();
    if trimmed.ends_with(']') {
        if let Some(bracket_start) = trimmed.rfind('[') {
            let flag = &trimmed[bracket_start + 1..trimmed.len() - 1];
            if flag.starts_with('-') {
                let msg = trimmed[..bracket_start].trim().to_owned();
                return (msg, Some(flag.to_owned()));
            }
        }
    }
    (trimmed.to_owned(), None)
}

/// Collect all `.c` source files from the standard Demon agent directories.
pub(super) fn c_sources(source_root: &Path) -> Result<Vec<PathBuf>, PayloadBuildError> {
    let mut sources = Vec::new();
    for dir in ["src/core", "src/crypt", "src/inject", "src/asm"] {
        let mut entries = std::fs::read_dir(source_root.join(dir))?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("c"))
            .collect::<Vec<_>>();
        entries.sort();
        sources.extend(entries);
    }
    Ok(sources)
}

/// Collect architecture-specific `.asm` source files from the Demon agent tree.
pub(super) fn asm_sources(
    source_root: &Path,
    architecture: Architecture,
) -> Result<Vec<PathBuf>, PayloadBuildError> {
    let suffix = match architecture {
        Architecture::X64 => ".x64.asm",
        Architecture::X86 => ".x86.asm",
    };
    let mut entries = std::fs::read_dir(source_root.join("src/asm"))?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|name| name.contains(suffix))
        })
        .collect::<Vec<_>>();
    entries.sort();
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_compiler_diagnostic_gcc_with_column() {
        let diag = parse_compiler_diagnostic(
            "src/core/Inject.c:42:8: error: 'foo' undeclared (first use in this function)",
        )
        .expect("should parse GCC error with column");

        assert_eq!(diag.filename, "src/core/Inject.c");
        assert_eq!(diag.line, 42);
        assert_eq!(diag.column, Some(8));
        assert_eq!(diag.severity, "error");
        assert_eq!(diag.error_code, None);
        assert_eq!(diag.message, "'foo' undeclared (first use in this function)");
    }

    #[test]
    fn parse_compiler_diagnostic_gcc_warning_with_flag() {
        let diag = parse_compiler_diagnostic(
            "src/Demon.c:10:3: warning: unused variable 'x' [-Wunused-variable]",
        )
        .expect("should parse GCC warning with flag");

        assert_eq!(diag.filename, "src/Demon.c");
        assert_eq!(diag.line, 10);
        assert_eq!(diag.column, Some(3));
        assert_eq!(diag.severity, "warning");
        assert_eq!(diag.error_code.as_deref(), Some("-Wunused-variable"));
        assert_eq!(diag.message, "unused variable 'x'");
    }

    #[test]
    fn parse_compiler_diagnostic_gcc_fatal_error_no_column() {
        let diag = parse_compiler_diagnostic(
            "src/Demon.c:1: fatal error: windows.h: No such file or directory",
        )
        .expect("should parse GCC fatal error without column");

        assert_eq!(diag.filename, "src/Demon.c");
        assert_eq!(diag.line, 1);
        assert_eq!(diag.column, None);
        assert_eq!(diag.severity, "fatal error");
        assert_eq!(diag.error_code, None);
        assert!(diag.message.contains("No such file or directory"));
    }

    #[test]
    fn parse_compiler_diagnostic_nasm_error() {
        let diag = parse_compiler_diagnostic(
            "src/asm/HookDetect.x64.asm:55: error: symbol `_start' undefined",
        )
        .expect("should parse NASM error");

        assert_eq!(diag.filename, "src/asm/HookDetect.x64.asm");
        assert_eq!(diag.line, 55);
        assert_eq!(diag.column, None);
        assert_eq!(diag.severity, "error");
        assert_eq!(diag.message, "symbol `_start' undefined");
    }

    #[test]
    fn parse_compiler_diagnostic_nasm_warning() {
        let diag = parse_compiler_diagnostic(
            "src/asm/Sleep.x64.asm:12: warning: uninitialized space declared in non-BSS section",
        )
        .expect("should parse NASM warning");

        assert_eq!(diag.severity, "warning");
        assert_eq!(diag.line, 12);
    }

    #[test]
    fn parse_compiler_diagnostic_returns_none_for_plain_text() {
        assert!(parse_compiler_diagnostic("stub compiler error").is_none());
        assert!(parse_compiler_diagnostic("In file included from foo.c:").is_none());
        assert!(parse_compiler_diagnostic("").is_none());
    }

    #[test]
    fn parse_compiler_diagnostic_returns_none_for_context_line() {
        // GCC indented caret/context lines should not be treated as diagnostics.
        assert!(parse_compiler_diagnostic("   10 |   int x = foo;").is_none());
        assert!(parse_compiler_diagnostic("      |           ^^^").is_none());
    }

    #[test]
    fn extract_gcc_flag_strips_trailing_bracket_flag() {
        let (msg, code) = extract_gcc_flag("unused variable 'x' [-Wunused-variable]");
        assert_eq!(msg, "unused variable 'x'");
        assert_eq!(code.as_deref(), Some("-Wunused-variable"));
    }

    #[test]
    fn extract_gcc_flag_strips_werror_flag() {
        let (msg, code) =
            extract_gcc_flag("deprecated declaration [-Werror=deprecated-declarations]");
        assert_eq!(code.as_deref(), Some("-Werror=deprecated-declarations"));
        assert_eq!(msg, "deprecated declaration");
    }

    #[test]
    fn extract_gcc_flag_no_flag_returns_message_unchanged() {
        let (msg, code) = extract_gcc_flag("'foo' undeclared");
        assert_eq!(msg, "'foo' undeclared");
        assert!(code.is_none());
    }
}
