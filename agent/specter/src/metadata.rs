//! Host metadata collection helpers used by the agent init handshake.

use std::time::{SystemTime, UNIX_EPOCH};

/// Return the current UTC time as a Unix timestamp (seconds since 1970-01-01).
pub(crate) fn current_unix_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Get the hostname of the current machine via platform-native API.
pub(crate) fn hostname() -> String {
    crate::platform::hostname()
}

/// Get the current username via platform-native API.
pub(crate) fn username() -> String {
    crate::platform::username()
}

/// Get the domain name (or "WORKGROUP") via platform-native API.
pub(crate) fn domain_name() -> String {
    crate::platform::domain_name()
}

/// Get the local IP address via the OS routing table.
pub(crate) fn local_ip() -> String {
    crate::platform::local_ip()
}

/// Get the current thread ID via platform-native API.
pub(crate) fn process_tid() -> u32 {
    crate::platform::process_tid()
}

/// Get the parent process ID via platform-native API.
pub(crate) fn process_ppid() -> u32 {
    crate::platform::process_ppid()
}

/// Return whether the current process is running elevated via platform-native API.
pub(crate) fn is_elevated() -> bool {
    crate::platform::is_elevated()
}

/// Get the base address of the current process image via platform-native API.
pub(crate) fn base_address() -> u64 {
    crate::platform::base_address()
}

/// Get the OS major version via `RtlGetVersion` (Windows) or returns 0 elsewhere.
pub(crate) fn os_major() -> u32 {
    crate::platform::os_version().0
}

/// Get the OS minor version via `RtlGetVersion` (Windows) or returns 0 elsewhere.
pub(crate) fn os_minor() -> u32 {
    crate::platform::os_version().1
}

/// Get the OS build number via `RtlGetVersion` (Windows) or returns 0 elsewhere.
pub(crate) fn os_build() -> u32 {
    crate::platform::os_version().2
}

/// Get the OS service pack major version via `RtlGetVersion` (Windows) or returns 0 elsewhere.
pub(crate) fn os_service_pack() -> u16 {
    crate::platform::os_version().3
}
