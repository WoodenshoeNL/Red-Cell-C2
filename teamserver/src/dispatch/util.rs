//! Shared helpers used by both the initial Demon INIT parser (`demon.rs`) and
//! the per-command dispatch handlers (`dispatch/`).

/// Windows product-type constant: workstation SKU.
pub(crate) const VER_NT_WORKSTATION: u32 = 0x0000_0001;

/// Numeric constants for the Demon `process_arch` field.
pub(crate) const PROCESS_ARCH_X86: u32 = 1;
pub(crate) const PROCESS_ARCH_X64: u32 = 2;
pub(crate) const PROCESS_ARCH_IA64: u32 = 3;

/// Return a human-readable Windows version string for the given OS fields.
///
/// The mapping matches the original Havoc teamserver logic exactly so that
/// agent records produced by both the initial INIT path and subsequent
/// CHECKIN path agree on version strings.
pub(crate) fn windows_version_label(
    major: u32,
    minor: u32,
    product_type: u32,
    service_pack: u32,
    build: u32,
) -> String {
    let mut version =
        if major == 10 && minor == 0 && product_type != VER_NT_WORKSTATION && build == 20_348 {
            "Windows 2022 Server 22H2".to_owned()
        } else if major == 10 && minor == 0 && product_type != VER_NT_WORKSTATION && build == 17_763
        {
            "Windows 2019 Server".to_owned()
        } else if major == 10
            && minor == 0
            && product_type == VER_NT_WORKSTATION
            && (22_000..=22_621).contains(&build)
        {
            "Windows 11".to_owned()
        } else if major == 10 && minor == 0 && product_type != VER_NT_WORKSTATION {
            "Windows 2016 Server".to_owned()
        } else if major == 10 && minor == 0 && product_type == VER_NT_WORKSTATION {
            "Windows 10".to_owned()
        } else if major == 6 && minor == 3 && product_type != VER_NT_WORKSTATION {
            "Windows Server 2012 R2".to_owned()
        } else if major == 6 && minor == 3 && product_type == VER_NT_WORKSTATION {
            "Windows 8.1".to_owned()
        } else if major == 6 && minor == 2 && product_type != VER_NT_WORKSTATION {
            "Windows Server 2012".to_owned()
        } else if major == 6 && minor == 2 && product_type == VER_NT_WORKSTATION {
            "Windows 8".to_owned()
        } else if major == 6 && minor == 1 && product_type != VER_NT_WORKSTATION {
            "Windows Server 2008 R2".to_owned()
        } else if major == 6 && minor == 1 && product_type == VER_NT_WORKSTATION {
            "Windows 7".to_owned()
        } else {
            "Unknown".to_owned()
        };

    if service_pack != 0 {
        version.push_str(" Service Pack ");
        version.push_str(&service_pack.to_string());
    }

    version
}

/// Strip the directory prefix from a Windows (or POSIX) path, returning only
/// the file name component.
pub(crate) fn basename(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_owned()
}

/// Map the Demon `process_arch` field to a human-readable architecture label.
pub(crate) fn process_arch_label(value: u32) -> &'static str {
    match value {
        PROCESS_ARCH_X64 => "x64",
        PROCESS_ARCH_X86 => "x86",
        PROCESS_ARCH_IA64 => "IA64",
        _ => "Unknown",
    }
}

/// Map the Windows `wProcessorArchitecture` field to a human-readable label.
pub(crate) fn windows_arch_label(value: u32) -> &'static str {
    match value {
        0 => "x86",
        9 => "x64/AMD64",
        5 => "ARM",
        12 => "ARM64",
        6 => "Itanium-based",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_empty_string() {
        assert_eq!(basename(""), "");
    }

    #[test]
    fn basename_bare_filename() {
        assert_eq!(basename("cmd.exe"), "cmd.exe");
    }

    #[test]
    fn basename_windows_backslash_path() {
        assert_eq!(basename("C:\\Windows\\system32\\cmd.exe"), "cmd.exe");
    }

    #[test]
    fn basename_posix_forward_slash_path() {
        assert_eq!(basename("/usr/bin/ls"), "ls");
    }

    #[test]
    fn basename_mixed_separators() {
        assert_eq!(basename("C:\\path/to\\file.exe"), "file.exe");
    }

    #[test]
    fn basename_trailing_separator() {
        assert_eq!(basename("C:\\Windows\\"), "");
    }

    #[test]
    fn basename_trailing_forward_slash() {
        assert_eq!(basename("/usr/bin/"), "");
    }

    #[test]
    fn basename_single_separator() {
        assert_eq!(basename("\\"), "");
    }

    #[test]
    fn basename_root_forward_slash() {
        assert_eq!(basename("/"), "");
    }

    /// Table-driven tests for `windows_version_label` covering every branch.
    ///
    /// Each entry is (major, minor, product_type, service_pack, build, expected).
    const VERSION_CASES: &[(u32, u32, u32, u32, u32, &str)] = &[
        // Windows Server 2022 22H2 — exact build 20348, non-workstation
        (10, 0, 3, 0, 20_348, "Windows 2022 Server 22H2"),
        // Windows Server 2019 — exact build 17763, non-workstation
        (10, 0, 3, 0, 17_763, "Windows 2019 Server"),
        // Windows 11 — workstation, build in [22000, 22621]
        (10, 0, VER_NT_WORKSTATION, 0, 22_000, "Windows 11"),
        (10, 0, VER_NT_WORKSTATION, 0, 22_621, "Windows 11"),
        (10, 0, VER_NT_WORKSTATION, 0, 22_300, "Windows 11"),
        // Windows 2016 Server fallback — non-workstation, build != 20348/17763
        (10, 0, 3, 0, 14_393, "Windows 2016 Server"),
        // Windows 10 — workstation, build outside Win11 range
        (10, 0, VER_NT_WORKSTATION, 0, 19_045, "Windows 10"),
        (10, 0, VER_NT_WORKSTATION, 0, 21_999, "Windows 10"),
        (10, 0, VER_NT_WORKSTATION, 0, 22_622, "Windows 10"),
        // Windows Server 2012 R2
        (6, 3, 3, 0, 0, "Windows Server 2012 R2"),
        // Windows 8.1
        (6, 3, VER_NT_WORKSTATION, 0, 0, "Windows 8.1"),
        // Windows Server 2012
        (6, 2, 3, 0, 0, "Windows Server 2012"),
        // Windows 8
        (6, 2, VER_NT_WORKSTATION, 0, 0, "Windows 8"),
        // Windows Server 2008 R2
        (6, 1, 3, 0, 0, "Windows Server 2008 R2"),
        // Windows 7
        (6, 1, VER_NT_WORKSTATION, 0, 0, "Windows 7"),
        // Unknown fallback
        (5, 1, VER_NT_WORKSTATION, 0, 0, "Unknown"),
        (0, 0, 0, 0, 0, "Unknown"),
    ];

    #[test]
    fn windows_version_label_all_branches() {
        for &(major, minor, pt, sp, build, expected) in VERSION_CASES {
            let got = windows_version_label(major, minor, pt, sp, build);
            assert_eq!(
                got, expected,
                "windows_version_label({major}, {minor}, {pt}, {sp}, {build}) = {got:?}, expected {expected:?}"
            );
        }
    }

    #[test]
    fn windows_version_label_service_pack_appended() {
        let got = windows_version_label(6, 1, VER_NT_WORKSTATION, 2, 0);
        assert_eq!(got, "Windows 7 Service Pack 2");
    }

    #[test]
    fn windows_version_label_service_pack_zero_omitted() {
        let got = windows_version_label(6, 1, VER_NT_WORKSTATION, 0, 0);
        assert_eq!(got, "Windows 7");
        assert!(!got.contains("Service Pack"));
    }

    #[test]
    fn windows_version_label_service_pack_on_server() {
        let got = windows_version_label(6, 1, 3, 1, 0);
        assert_eq!(got, "Windows Server 2008 R2 Service Pack 1");
    }

    #[test]
    fn windows_version_label_service_pack_on_unknown() {
        let got = windows_version_label(5, 1, VER_NT_WORKSTATION, 3, 0);
        assert_eq!(got, "Unknown Service Pack 3");
    }

    // ── process_arch_label ──────────────────────────────────────────

    #[test]
    fn process_arch_label_known_values() {
        assert_eq!(process_arch_label(PROCESS_ARCH_X86), "x86");
        assert_eq!(process_arch_label(PROCESS_ARCH_X64), "x64");
        assert_eq!(process_arch_label(PROCESS_ARCH_IA64), "IA64");
    }

    #[test]
    fn process_arch_label_unknown_fallback() {
        for value in [0, 4, 99, u32::MAX] {
            assert_eq!(
                process_arch_label(value),
                "Unknown",
                "process_arch_label({value}) should be Unknown"
            );
        }
    }

    // ── windows_arch_label ──────────────────────────────────────────

    const WINDOWS_ARCH_CASES: &[(u32, &str)] =
        &[(0, "x86"), (9, "x64/AMD64"), (5, "ARM"), (12, "ARM64"), (6, "Itanium-based")];

    #[test]
    fn windows_arch_label_known_values() {
        for &(value, expected) in WINDOWS_ARCH_CASES {
            assert_eq!(
                windows_arch_label(value),
                expected,
                "windows_arch_label({value}) = expected {expected:?}"
            );
        }
    }

    #[test]
    fn windows_arch_label_unknown_fallback() {
        for value in [1, 2, 3, 4, 7, 8, 10, 11, 99, u32::MAX] {
            assert_eq!(
                windows_arch_label(value),
                "Unknown",
                "windows_arch_label({value}) should be Unknown"
            );
        }
    }
}
