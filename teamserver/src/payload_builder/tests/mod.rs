use std::path::{Path, PathBuf};

use super::cache::CacheKey;
use super::config_values::{
    add_bytes, add_wstring, amsi_patch_value, injection_mode, parse_hour_minute, parse_kill_date,
    parse_working_hours, proxy_loading_value, proxy_url, required_u32, sleep_jump_bypass,
    sleep_obfuscation_value,
};
use super::*;
use red_cell_common::HttpListenerConfig;

mod build;
mod cache;
mod config;
mod constructor;
mod pe;
mod util;

// ── Shared test helpers ──────────────────────────────────────────────────

pub(super) fn create_payload_assets(repo_root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let payload_root = repo_root.join("agent/demon/payloads");
    std::fs::create_dir_all(payload_root.join("Demon"))?;
    std::fs::write(payload_root.join("Shellcode.x64.bin"), [0x90, 0x90])?;
    std::fs::write(payload_root.join("Shellcode.x86.bin"), [0x90, 0x90])?;
    std::fs::write(payload_root.join("DllLdr.x64.bin"), [0x55, 0x48])?;
    let templates_dir = repo_root.join("payloads/templates");
    std::fs::create_dir_all(&templates_dir)?;
    std::fs::write(templates_dir.join("MainStager.c"), "int main(void){return 0;}")?;
    Ok(())
}

/// Write a fake executable that prints `output` on stdout then exits 0.
pub(super) fn write_fake_executable_with_output(
    path: &Path,
    output: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, format!("#!/bin/sh\nprintf '%s\\n' '{}'\nexit 0\n", output))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(path.to_path_buf())
}

/// Write a fake MinGW GCC that reports version 12.2.0.
pub(super) fn write_fake_gcc(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    write_fake_executable_with_output(
        path,
        "x86_64-w64-mingw32-gcc (GCC) 12.2.0 20220819 (Release)",
    )
}

/// Write a fake NASM that reports version 2.16.01.
pub(super) fn write_fake_nasm(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    write_fake_executable_with_output(path, "NASM version 2.16.01 compiled on Jan  1 2023")
}

/// Read the version output embedded in a fake shell script created by
/// [`write_fake_executable_with_output`] without spawning a subprocess.
///
/// The script format is:
/// ```text
/// #!/bin/sh
/// printf '%s\n' '<output>'
/// exit 0
/// ```
pub(super) fn read_fake_script_output(path: &Path) -> Result<String, PayloadBuildError> {
    let content =
        std::fs::read_to_string(path).map_err(|err| PayloadBuildError::ToolchainUnavailable {
            message: format!("failed to read fake script `{}`: {err}", path.display()),
        })?;
    // The script format is: printf '%s\n' '<output>'
    // Skip the first two single-quoted segments (format string) and extract
    // the second quoted string which contains the actual version output.
    let err = || PayloadBuildError::ToolchainUnavailable {
        message: format!("no quoted output in fake script `{}`", path.display()),
    };
    let first_quote = content.find('\'').ok_or_else(err)? + 1;
    let after_format = content[first_quote..].find('\'').ok_or_else(err)? + first_quote + 1;
    let value_start = content[after_format..].find('\'').ok_or_else(err)? + after_format + 1;
    let value_end = content[value_start..].find('\'').ok_or_else(err)? + value_start;
    Ok(content[value_start..value_end].to_owned())
}
