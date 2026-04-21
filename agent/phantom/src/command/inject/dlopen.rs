//! Locate libc and resolve `__libc_dlopen_mode` in a target process.

use std::fs;

/// Find the base address of libc in a target process by parsing `/proc/<pid>/maps`.
pub(crate) fn find_libc_base(pid: u32) -> Option<u64> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    for line in maps.lines() {
        if (line.contains("libc.so") || line.contains("libc-")) && line.contains("r-xp") {
            let addr_str = line.split('-').next()?;
            return u64::from_str_radix(addr_str, 16).ok();
        }
    }
    None
}

/// Resolve the address of `__libc_dlopen_mode` in the target process.
///
/// We find the offset in our own libc and combine it with the target's libc
/// base address. This works because both processes load the same libc version
/// (same system).
pub(crate) fn resolve_dlopen_in_target(target_libc_base: u64) -> Option<u64> {
    // Find our own libc base.
    let our_libc_base = find_libc_base(std::process::id())?;

    // Resolve __libc_dlopen_mode in our own process.
    let sym_name = std::ffi::CString::new("__libc_dlopen_mode").ok()?;
    // SAFETY: dlsym with RTLD_DEFAULT to search all loaded libraries.
    let sym_addr = unsafe { libc::dlsym(libc::RTLD_DEFAULT, sym_name.as_ptr()) };
    if sym_addr.is_null() {
        // Fall back to dlopen as a symbol name.
        let sym_name2 = std::ffi::CString::new("dlopen").ok()?;
        // SAFETY: dlsym with RTLD_DEFAULT.
        let sym_addr2 = unsafe { libc::dlsym(libc::RTLD_DEFAULT, sym_name2.as_ptr()) };
        if sym_addr2.is_null() {
            return None;
        }
        let offset = (sym_addr2 as u64).wrapping_sub(our_libc_base);
        return Some(target_libc_base.wrapping_add(offset));
    }

    let offset = (sym_addr as u64).wrapping_sub(our_libc_base);
    Some(target_libc_base.wrapping_add(offset))
}
