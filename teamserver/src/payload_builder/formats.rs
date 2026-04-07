//! Output format and target architecture types for the payload builder.

use super::PayloadBuildError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Architecture {
    X64,
    X86,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum OutputFormat {
    Exe,
    ServiceExe,
    Dll,
    ReflectiveDll,
    Shellcode,
    /// Small HTTP(S) downloader EXE that fetches and executes the Demon
    /// shellcode payload at run time rather than embedding it directly.
    StagedShellcode,
    /// Position-independent shellcode produced by prepending `DllLdr.x64.bin`
    /// to the Demon DLL (x64 only; the DllLdr binary has no x86 counterpart).
    RawShellcode,
}

impl Architecture {
    pub(super) fn parse(value: &str) -> Result<Self, PayloadBuildError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "x64" => Ok(Self::X64),
            "x86" => Ok(Self::X86),
            other => Err(PayloadBuildError::InvalidRequest {
                message: format!("unsupported architecture `{other}`"),
            }),
        }
    }

    pub(super) const fn nasm_format(self) -> &'static str {
        match self {
            Self::X64 => "win64",
            Self::X86 => "win32",
        }
    }

    pub(super) const fn suffix(self) -> &'static str {
        match self {
            Self::X64 => ".x64",
            Self::X86 => ".x86",
        }
    }
}

impl OutputFormat {
    pub(super) fn parse(value: &str) -> Result<Self, PayloadBuildError> {
        match value.trim() {
            "Windows Exe" => Ok(Self::Exe),
            "Windows Service Exe" => Ok(Self::ServiceExe),
            "Windows Dll" => Ok(Self::Dll),
            "Windows Reflective Dll" => Ok(Self::ReflectiveDll),
            "Windows Shellcode" => Ok(Self::Shellcode),
            "Windows Shellcode Staged" => Ok(Self::StagedShellcode),
            "Windows Raw Shellcode" => Ok(Self::RawShellcode),
            other => Err(PayloadBuildError::InvalidRequest {
                message: format!("unsupported output format `{other}`"),
            }),
        }
    }

    pub(super) const fn file_extension(self) -> &'static str {
        match self {
            Self::Exe | Self::ServiceExe | Self::StagedShellcode => ".exe",
            Self::Dll | Self::ReflectiveDll => ".dll",
            Self::Shellcode | Self::RawShellcode => ".bin",
        }
    }

    /// Unique per-variant tag used in cache key computation.
    ///
    /// Unlike [`file_extension`](Self::file_extension), this returns a distinct
    /// value for every variant so that formats sharing the same extension
    /// (e.g. `Exe` vs `ServiceExe`) never collide in the payload cache.
    pub(super) const fn cache_tag(self) -> &'static str {
        match self {
            Self::Exe => "exe",
            Self::ServiceExe => "service-exe",
            Self::Dll => "dll",
            Self::ReflectiveDll => "reflective-dll",
            Self::Shellcode => "shellcode",
            Self::StagedShellcode => "staged-shellcode",
            Self::RawShellcode => "raw-shellcode",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Architecture::parse tests ─────────────────────────────────────────

    #[test]
    fn architecture_parse_accepts_x64_case_insensitive() {
        assert_eq!(Architecture::parse("x64").expect("unwrap"), Architecture::X64);
        assert_eq!(Architecture::parse("X64").expect("unwrap"), Architecture::X64);
        assert_eq!(Architecture::parse(" x64 ").expect("unwrap"), Architecture::X64);
    }

    #[test]
    fn architecture_parse_accepts_x86_case_insensitive() {
        assert_eq!(Architecture::parse("x86").expect("unwrap"), Architecture::X86);
        assert_eq!(Architecture::parse("X86").expect("unwrap"), Architecture::X86);
    }

    #[test]
    fn architecture_parse_rejects_unknown() {
        let err = Architecture::parse("arm64").expect_err("arm64 should be rejected");
        assert!(matches!(err, PayloadBuildError::InvalidRequest { message }
            if message.contains("arm64")));
    }

    #[test]
    fn architecture_suffix_and_nasm_format() {
        assert_eq!(Architecture::X64.suffix(), ".x64");
        assert_eq!(Architecture::X86.suffix(), ".x86");
        assert_eq!(Architecture::X64.nasm_format(), "win64");
        assert_eq!(Architecture::X86.nasm_format(), "win32");
    }

    // ── OutputFormat::parse comprehensive tests ───────────────────────────

    #[test]
    fn output_format_parses_all_known_formats() {
        let cases = [
            ("Windows Exe", OutputFormat::Exe, ".exe"),
            ("Windows Service Exe", OutputFormat::ServiceExe, ".exe"),
            ("Windows Dll", OutputFormat::Dll, ".dll"),
            ("Windows Reflective Dll", OutputFormat::ReflectiveDll, ".dll"),
            ("Windows Shellcode", OutputFormat::Shellcode, ".bin"),
            ("Windows Shellcode Staged", OutputFormat::StagedShellcode, ".exe"),
            ("Windows Raw Shellcode", OutputFormat::RawShellcode, ".bin"),
        ];
        for (input, expected_variant, expected_ext) in cases {
            let parsed =
                OutputFormat::parse(input).unwrap_or_else(|_| panic!("should parse `{input}`"));
            assert_eq!(parsed, expected_variant, "variant mismatch for `{input}`");
            assert_eq!(parsed.file_extension(), expected_ext, "extension mismatch for `{input}`");
        }
    }

    #[test]
    fn output_format_cache_tags_are_all_unique() {
        use std::collections::HashSet;
        let tags: Vec<&str> = vec![
            OutputFormat::Exe.cache_tag(),
            OutputFormat::ServiceExe.cache_tag(),
            OutputFormat::Dll.cache_tag(),
            OutputFormat::ReflectiveDll.cache_tag(),
            OutputFormat::Shellcode.cache_tag(),
            OutputFormat::StagedShellcode.cache_tag(),
            OutputFormat::RawShellcode.cache_tag(),
        ];
        let unique: HashSet<&str> = tags.iter().copied().collect();
        assert_eq!(
            unique.len(),
            tags.len(),
            "all cache tags must be unique to prevent cache collisions"
        );
    }
}
