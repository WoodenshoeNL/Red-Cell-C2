//! Linux host metadata helpers for Demon-compatible [`AgentMetadata`](crate::protocol::AgentMetadata) collection.

use std::fs;
use std::path::PathBuf;

/// Return trimmed file contents, if the file exists and is readable.
pub(crate) fn read_trimmed(path: impl Into<PathBuf>) -> Option<String> {
    let path = path.into();
    fs::read_to_string(path).ok().map(|value| value.trim().to_string())
}

/// Return the NIS/YP domain name from the kernel, or `"WORKGROUP"` as fallback.
///
/// On Linux the kernel exposes the domain name via `/proc/sys/kernel/domainname`.
/// This returns `"(none)"` when no domain is configured, in which case we fall
/// back to `"WORKGROUP"` to match Windows-style Demon metadata semantics.
pub(crate) fn domain_name() -> String {
    read_trimmed("/proc/sys/kernel/domainname")
        .filter(|d| !d.is_empty() && d != "(none)")
        .unwrap_or_else(|| String::from("WORKGROUP"))
}

/// Determine the primary non-loopback IPv4 address by connecting a UDP socket.
///
/// Connecting a UDP socket does not send any data — it only causes the kernel
/// to select the appropriate source address for the given destination.  We use
/// a well-known public address (`8.8.8.8:80`) solely to trigger route lookup.
pub(crate) fn local_ip() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|sock| {
            sock.connect("8.8.8.8:80")?;
            sock.local_addr()
        })
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|_| String::from("127.0.0.1"))
}

/// Return the TID of the calling thread by reading `Pid:` from `/proc/self/status`.
///
/// On Linux the `Pid:` field in `/proc/self/status` is the thread ID (TID) of
/// the thread reading it — for the main thread this equals the process PID.
pub(crate) fn thread_id() -> u32 {
    read_trimmed("/proc/self/status")
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                line.strip_prefix("Pid:\t").and_then(|v| v.trim().parse::<u32>().ok())
            })
        })
        .unwrap_or(0)
}

/// Return the base load address of the running executable.
///
/// Parses `/proc/self/maps` to find the first mapping with execute permission,
/// which is the virtual address at which the ELF text segment was loaded.
pub(crate) fn base_address() -> u64 {
    fs::read_to_string("/proc/self/maps")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                // Format: "addr_start-addr_end perms offset dev ino pathname"
                let mut cols = line.splitn(6, ' ');
                let range = cols.next()?;
                let perms = cols.next()?;
                if !perms.contains('x') {
                    return None;
                }
                let addr_start = range.split('-').next()?;
                u64::from_str_radix(addr_start, 16).ok()
            })
        })
        .unwrap_or(0)
}

/// Parse the Linux kernel version string from `/proc/version`.
///
/// Returns `(major, minor, patch)` extracted from the version triple (e.g.
/// `"Linux version 6.8.0-50-generic ..."` → `(6, 8, 0)`).
pub(crate) fn kernel_version() -> (u32, u32, u32) {
    let raw = fs::read_to_string("/proc/version").unwrap_or_default();
    // Third whitespace-separated token is the version string, e.g. "6.8.0-50-generic".
    let ver = raw.split_whitespace().nth(2).unwrap_or("");
    let mut parts = ver.split('.');
    let major = parts.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    // Third component may be "0-50-generic"; take only the numeric prefix.
    let patch = parts
        .next()
        .and_then(|s| s.split('-').next())
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    (major, minor, patch)
}

pub(crate) fn parent_pid() -> u32 {
    read_trimmed("/proc/self/status")
        .and_then(|contents| {
            contents
                .lines()
                .find_map(|line| line.strip_prefix("PPid:\t"))
                .and_then(|value| value.trim().parse::<u32>().ok())
        })
        .unwrap_or_default()
}

pub(crate) fn is_elevated() -> bool {
    read_trimmed("/proc/self/status").and_then(|contents| {
        contents.lines().find_map(|line| {
            line.strip_prefix("Uid:\t").and_then(|value| {
                value.split_whitespace().next().and_then(|first| first.parse::<u32>().ok())
            })
        })
    }) == Some(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_trimmed_trims_and_reads_file() {
        let path = std::env::temp_dir().join("phantom_metadata_read_trimmed_test");
        let _ = std::fs::write(&path, "  hello world \n");
        assert_eq!(read_trimmed(&path).as_deref(), Some("hello world"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_trimmed_missing_file_returns_none() {
        let path = std::env::temp_dir().join("phantom_metadata_no_such_file_xyz");
        let _ = std::fs::remove_file(&path);
        assert!(read_trimmed(&path).is_none());
    }

    #[test]
    fn domain_name_is_non_empty_on_linux() {
        let name = domain_name();
        assert!(!name.is_empty());
    }

    #[test]
    fn local_ip_is_non_loopback_placeholder() {
        let ip = local_ip();
        assert!(!ip.is_empty());
        assert_ne!(ip, "0.0.0.0");
    }

    #[test]
    fn thread_id_is_positive_in_test_process() {
        assert!(thread_id() > 0);
    }

    #[test]
    fn kernel_version_major_plausible_on_linux() {
        let (major, _, _) = kernel_version();
        assert!(major >= 4, "expected Linux kernel major >= 4, got {major}");
    }

    #[test]
    fn parent_pid_matches_status_ppid_line() {
        let ppid = parent_pid();
        let from_proc = read_trimmed("/proc/self/status")
            .and_then(|contents| {
                contents
                    .lines()
                    .find_map(|line| line.strip_prefix("PPid:\t"))
                    .and_then(|value| value.trim().parse::<u32>().ok())
            })
            .unwrap_or(0);
        assert_eq!(ppid, from_proc);
    }

    #[test]
    fn is_elevated_matches_status_uid_line() {
        let elevated = is_elevated();
        let from_proc = read_trimmed("/proc/self/status")
            .and_then(|contents| {
                contents.lines().find_map(|line| {
                    line.strip_prefix("Uid:\t").and_then(|value| {
                        value.split_whitespace().next().and_then(|first| first.parse::<u32>().ok())
                    })
                })
            })
            .map(|u| u == 0)
            .unwrap_or(false);
        assert_eq!(elevated, from_proc);
    }

    #[test]
    fn base_address_zero_or_plausible_user_mapping() {
        let addr = base_address();
        assert!(addr == 0 || (0x1000..0x0000_7fff_ffff_ffff).contains(&addr));
    }
}
