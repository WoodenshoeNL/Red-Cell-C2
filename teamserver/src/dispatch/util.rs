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
