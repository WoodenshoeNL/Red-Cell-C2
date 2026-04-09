//! Toolchain discovery and version verification for cross-compilation.
//!
//! Resolves MinGW-w64 (GCC) and NASM executables from the PATH or
//! well-known install locations and verifies that their versions meet
//! the minimum requirements for Demon payload compilation.

use std::path::{Path, PathBuf};

use super::PayloadBuildError;

/// Parsed semantic version reported by a toolchain binary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolchainVersion {
    /// Major version component.
    pub major: u32,
    /// Minor version component.
    pub minor: u32,
    /// Patch version component.
    pub patch: u32,
    /// Raw version string as extracted from the tool's output.
    pub raw: String,
}

impl std::fmt::Display for ToolchainVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.raw)
    }
}

/// Minimum version requirement (major.minor) for a toolchain binary.
pub(super) struct VersionRequirement {
    pub(super) major: u32,
    pub(super) minor: u32,
}

impl VersionRequirement {
    pub(super) fn is_satisfied_by(&self, version: &ToolchainVersion) -> bool {
        (version.major, version.minor) >= (self.major, self.minor)
    }
}

/// Minimum GCC version required for MinGW cross-compilation (10.0+).
pub(super) const GCC_MIN_VERSION: VersionRequirement = VersionRequirement { major: 10, minor: 0 };

/// Minimum NASM version required for Win32/Win64 object output (2.14+).
pub(super) const NASM_MIN_VERSION: VersionRequirement = VersionRequirement { major: 2, minor: 14 };

#[derive(Clone, Debug)]
pub(super) struct Toolchain {
    pub(super) compiler_x64: PathBuf,
    // Version fields are used by the tracing log at startup and in tests; the
    // dead_code lint does not track macro-argument usage.
    #[allow(dead_code)]
    pub(super) compiler_x64_version: ToolchainVersion,
    pub(super) compiler_x86: PathBuf,
    #[allow(dead_code)]
    pub(super) compiler_x86_version: ToolchainVersion,
    pub(super) nasm: PathBuf,
    #[allow(dead_code)]
    pub(super) nasm_version: ToolchainVersion,
}

/// Resolve an executable path from an optional configured value or a fallback
/// program name looked up via PATH and well-known locations.
pub(super) fn resolve_executable(
    configured: Option<&str>,
    fallback_name: &str,
    repo_root: Option<&Path>,
) -> Result<PathBuf, PayloadBuildError> {
    let candidate = configured
        .map(|path| {
            let path = PathBuf::from(path);
            if path.is_relative() {
                repo_root.map_or(path.clone(), |repo_root| repo_root.join(path))
            } else {
                path
            }
        })
        .or_else(|| find_in_path_or_common_locations(fallback_name))
        .ok_or_else(|| PayloadBuildError::ToolchainUnavailable {
            message: format!(
                "required executable `{fallback_name}` was not found in PATH or common \
                 toolchain locations (/usr/bin, /usr/local/bin, /opt/mingw)"
            ),
        })?;

    if candidate.is_file() {
        candidate.canonicalize().map_err(|source| PayloadBuildError::ToolchainUnavailable {
            message: format!("failed to resolve {}: {source}", candidate.display()),
        })
    } else {
        Err(PayloadBuildError::ToolchainUnavailable {
            message: format!("executable does not exist: {}", candidate.display()),
        })
    }
}

fn find_in_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|dir| dir.join(program)).find(|candidate| candidate.is_file())
}

/// Search PATH then well-known toolchain install locations for `program`.
///
/// Checked directories beyond PATH: `/usr/bin`, `/usr/local/bin`, `/opt/mingw/bin`,
/// `/opt/mingw64/bin`, `/usr/x86_64-w64-mingw32/bin`, `/usr/i686-w64-mingw32/bin`.
pub(super) fn find_in_path_or_common_locations(program: &str) -> Option<PathBuf> {
    if let Some(found) = find_in_path(program) {
        return Some(found);
    }
    const EXTRA_DIRS: &[&str] = &[
        "/usr/bin",
        "/usr/local/bin",
        "/opt/mingw/bin",
        "/opt/mingw64/bin",
        "/usr/x86_64-w64-mingw32/bin",
        "/usr/i686-w64-mingw32/bin",
    ];
    EXTRA_DIRS.iter().map(|dir| std::path::Path::new(dir).join(program)).find(|p| p.is_file())
}

/// Parse `major.minor.patch` triples from a version token.
fn parse_version_triple(token: &str) -> Option<(u32, u32, u32)> {
    let mut parts = token.splitn(3, '.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    let patch = parts.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    Some((major, minor, patch))
}

/// Extract a version from GCC `--version` output.
///
/// GCC emits a first line like:
/// `x86_64-w64-mingw32-gcc (GCC) 12.2.0 20220819 (Release)`
pub(super) fn parse_gcc_version(
    output: &str,
    path: &Path,
) -> Result<ToolchainVersion, PayloadBuildError> {
    let first_line = output.lines().next().unwrap_or("").trim();
    let token = first_line
        .split_whitespace()
        .find(|t| t.chars().next().is_some_and(|c| c.is_ascii_digit()) && t.contains('.'))
        .ok_or_else(|| PayloadBuildError::ToolchainUnavailable {
            message: format!(
                "could not parse version from `{} --version` output: {:?}",
                path.display(),
                first_line
            ),
        })?;
    let (major, minor, patch) =
        parse_version_triple(token).ok_or_else(|| PayloadBuildError::ToolchainUnavailable {
            message: format!(
                "invalid version string `{token}` from `{} --version`",
                path.display()
            ),
        })?;
    Ok(ToolchainVersion { major, minor, patch, raw: token.to_owned() })
}

/// Extract a version from NASM `--version` output.
///
/// NASM emits a first line like: `NASM version 2.16.01 compiled on ...`
pub(super) fn parse_nasm_version(
    output: &str,
    path: &Path,
) -> Result<ToolchainVersion, PayloadBuildError> {
    let first_line = output.lines().next().unwrap_or("").trim();
    let token = first_line
        .split_whitespace()
        .find(|t| t.chars().next().is_some_and(|c| c.is_ascii_digit()) && t.contains('.'))
        .ok_or_else(|| PayloadBuildError::ToolchainUnavailable {
            message: format!(
                "could not parse version from `{} --version` output: {:?}",
                path.display(),
                first_line
            ),
        })?;
    let (major, minor, patch) =
        parse_version_triple(token).ok_or_else(|| PayloadBuildError::ToolchainUnavailable {
            message: format!(
                "invalid version string `{token}` from `{} --version`",
                path.display()
            ),
        })?;
    Ok(ToolchainVersion { major, minor, patch, raw: token.to_owned() })
}

/// Obtain `--version` output by spawning the tool binary.
pub(super) fn run_version_command(path: &Path) -> Result<String, PayloadBuildError> {
    let output = std::process::Command::new(path).arg("--version").output().map_err(|err| {
        PayloadBuildError::ToolchainUnavailable {
            message: format!("failed to run `{} --version`: {err}", path.display()),
        }
    })?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Run `path --version` (or obtain the version string via `output_fn`),
/// parse with `parse_fn`, and enforce `requirement`.
pub(super) fn verify_tool_version_with(
    path: &Path,
    parse_fn: fn(&str, &Path) -> Result<ToolchainVersion, PayloadBuildError>,
    requirement: &VersionRequirement,
    output_fn: fn(&Path) -> Result<String, PayloadBuildError>,
) -> Result<ToolchainVersion, PayloadBuildError> {
    let stdout = output_fn(path)?;
    let version = parse_fn(&stdout, path)?;
    if requirement.is_satisfied_by(&version) {
        Ok(version)
    } else {
        Err(PayloadBuildError::ToolchainUnavailable {
            message: format!(
                "`{}` version {} is below the minimum required {}.{}",
                path.display(),
                version,
                requirement.major,
                requirement.minor,
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_gcc_version_extracts_version_triple() -> Result<(), Box<dyn std::error::Error>> {
        let output = "x86_64-w64-mingw32-gcc (GCC) 12.2.0 20220819 (Release)\n";
        let path = Path::new("/usr/bin/x86_64-w64-mingw32-gcc");
        let ver = parse_gcc_version(output, path)?;
        assert_eq!(
            ver,
            ToolchainVersion { major: 12, minor: 2, patch: 0, raw: "12.2.0".to_owned() }
        );
        Ok(())
    }

    #[test]
    fn parse_nasm_version_extracts_version_triple() -> Result<(), Box<dyn std::error::Error>> {
        let output = "NASM version 2.16.01 compiled on Jan  1 2023\n";
        let path = Path::new("/usr/bin/nasm");
        let ver = parse_nasm_version(output, path)?;
        assert_eq!(
            ver,
            ToolchainVersion { major: 2, minor: 16, patch: 1, raw: "2.16.01".to_owned() }
        );
        Ok(())
    }

    #[test]
    fn parse_gcc_version_rejects_unparseable_output() {
        let path = Path::new("/usr/bin/gcc");
        let err = parse_gcc_version("not a version string", path)
            .expect_err("unparseable output should be rejected");
        assert!(matches!(err, PayloadBuildError::ToolchainUnavailable { .. }));
    }

    #[test]
    fn find_in_path_or_common_locations_returns_none_for_missing_program() {
        // A program with this name cannot plausibly exist anywhere.
        let found = find_in_path_or_common_locations("__red_cell_nonexistent_tool_zzz__");
        assert_eq!(found, None);
    }

    #[test]
    fn find_in_path_or_common_locations_finds_sh_from_path() {
        // /bin/sh is present on every POSIX system and in PATH; confirms that
        // PATH search works without mutating the global environment.
        let found = find_in_path_or_common_locations("sh");
        assert!(found.is_some(), "sh should be discoverable via PATH");
    }

    #[test]
    fn parse_version_triple_full() {
        assert_eq!(parse_version_triple("12.2.0"), Some((12, 2, 0)));
    }

    #[test]
    fn parse_version_triple_major_only() {
        assert_eq!(parse_version_triple("10"), Some((10, 0, 0)));
    }

    #[test]
    fn parse_version_triple_major_minor_only() {
        assert_eq!(parse_version_triple("2.16"), Some((2, 16, 0)));
    }

    #[test]
    fn parse_version_triple_rejects_empty() {
        assert_eq!(parse_version_triple(""), None);
    }

    #[test]
    fn parse_version_triple_rejects_non_numeric() {
        assert_eq!(parse_version_triple("abc"), None);
    }

    #[test]
    fn version_requirement_satisfied_by_exact_match() {
        let req = VersionRequirement { major: 10, minor: 0 };
        let ver = ToolchainVersion { major: 10, minor: 0, patch: 0, raw: "10.0.0".to_owned() };
        assert!(req.is_satisfied_by(&ver));
    }

    #[test]
    fn version_requirement_satisfied_by_higher_version() {
        let req = VersionRequirement { major: 10, minor: 0 };
        let ver = ToolchainVersion { major: 12, minor: 2, patch: 0, raw: "12.2.0".to_owned() };
        assert!(req.is_satisfied_by(&ver));
    }

    #[test]
    fn version_requirement_not_satisfied_by_lower_version() {
        let req = VersionRequirement { major: 10, minor: 0 };
        let ver = ToolchainVersion { major: 9, minor: 99, patch: 0, raw: "9.99.0".to_owned() };
        assert!(!req.is_satisfied_by(&ver));
    }
}
