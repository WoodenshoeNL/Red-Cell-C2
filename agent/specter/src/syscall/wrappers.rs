//! Safe Rust wrappers around NT syscalls (Windows) and no-op stubs (non-Windows).

// ── Windows NT wrappers ───────────────────────────────────────────────────────

#[cfg(all(windows, target_arch = "x86_64"))]
mod windows_impl {
    use std::ffi::c_void;

    use super::super::invoke::{
        get_entry, sys_invoke_4, sys_invoke_5, sys_invoke_6, sys_invoke_11, sys_set_config,
    };
    use super::super::{STATUS_NOT_SUPPORTED, SyscallEntry, table};

    /// `NtAllocateVirtualMemory` via indirect syscall.
    ///
    /// Allocates a region of virtual memory in the address space of the
    /// specified process.
    ///
    /// | Arg | NT param              |
    /// |-----|-----------------------|
    /// | 1   | ProcessHandle         |
    /// | 2   | *BaseAddress          |
    /// | 3   | ZeroBits              |
    /// | 4   | *RegionSize           |
    /// | 5   | AllocationType        |
    /// | 6   | Protect               |
    pub fn nt_allocate_virtual_memory(
        process: isize,
        base_address: *mut *mut c_void,
        zero_bits: usize,
        region_size: *mut usize,
        alloc_type: u32,
        protect: u32,
    ) -> i32 {
        let tbl = match table() {
            Some(t) => t,
            None => return STATUS_NOT_SUPPORTED,
        };
        let entry = match get_entry(&tbl.nt_allocate_virtual_memory) {
            Some(e) => e,
            None => return STATUS_NOT_SUPPORTED,
        };
        unsafe {
            sys_set_config(entry as *const SyscallEntry);
            sys_invoke_6(
                process as usize,
                base_address as usize,
                zero_bits,
                region_size as usize,
                alloc_type as usize,
                protect as usize,
            )
        }
    }

    /// `NtWriteVirtualMemory` via indirect syscall.
    pub fn nt_write_virtual_memory(
        process: isize,
        base_address: *const c_void,
        buffer: *const c_void,
        bytes_to_write: usize,
        bytes_written: *mut usize,
    ) -> i32 {
        let tbl = match table() {
            Some(t) => t,
            None => return STATUS_NOT_SUPPORTED,
        };
        let entry = match get_entry(&tbl.nt_write_virtual_memory) {
            Some(e) => e,
            None => return STATUS_NOT_SUPPORTED,
        };
        unsafe {
            sys_set_config(entry as *const SyscallEntry);
            sys_invoke_5(
                process as usize,
                base_address as usize,
                buffer as usize,
                bytes_to_write,
                bytes_written as usize,
            )
        }
    }

    /// `NtReadVirtualMemory` via indirect syscall.
    pub fn nt_read_virtual_memory(
        process: isize,
        base_address: *const c_void,
        buffer: *mut c_void,
        bytes_to_read: usize,
        bytes_read: *mut usize,
    ) -> i32 {
        let tbl = match table() {
            Some(t) => t,
            None => return STATUS_NOT_SUPPORTED,
        };
        let entry = match get_entry(&tbl.nt_read_virtual_memory) {
            Some(e) => e,
            None => return STATUS_NOT_SUPPORTED,
        };
        unsafe {
            sys_set_config(entry as *const SyscallEntry);
            sys_invoke_5(
                process as usize,
                base_address as usize,
                buffer as usize,
                bytes_to_read,
                bytes_read as usize,
            )
        }
    }

    /// `NtFreeVirtualMemory` via indirect syscall.
    pub fn nt_free_virtual_memory(
        process: isize,
        base_address: *mut *mut c_void,
        region_size: *mut usize,
        free_type: u32,
    ) -> i32 {
        let tbl = match table() {
            Some(t) => t,
            None => return STATUS_NOT_SUPPORTED,
        };
        let entry = match get_entry(&tbl.nt_free_virtual_memory) {
            Some(e) => e,
            None => return STATUS_NOT_SUPPORTED,
        };
        unsafe {
            sys_set_config(entry as *const SyscallEntry);
            sys_invoke_4(
                process as usize,
                base_address as usize,
                region_size as usize,
                free_type as usize,
            )
        }
    }

    /// `NtProtectVirtualMemory` via indirect syscall.
    pub fn nt_protect_virtual_memory(
        process: isize,
        base_address: *mut *mut c_void,
        region_size: *mut usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32 {
        let tbl = match table() {
            Some(t) => t,
            None => return STATUS_NOT_SUPPORTED,
        };
        let entry = match get_entry(&tbl.nt_protect_virtual_memory) {
            Some(e) => e,
            None => return STATUS_NOT_SUPPORTED,
        };
        unsafe {
            sys_set_config(entry as *const SyscallEntry);
            sys_invoke_5(
                process as usize,
                base_address as usize,
                region_size as usize,
                new_protect as usize,
                old_protect as usize,
            )
        }
    }

    /// `NtCreateThreadEx` via indirect syscall.
    #[allow(clippy::too_many_arguments)]
    pub fn nt_create_thread_ex(
        thread_handle: *mut isize,
        desired_access: u32,
        object_attributes: *mut c_void,
        process: isize,
        start_routine: *const c_void,
        argument: *const c_void,
        create_flags: u32,
        zero_bits: usize,
        stack_size: usize,
        maximum_stack_size: usize,
        attribute_list: *mut c_void,
    ) -> i32 {
        let tbl = match table() {
            Some(t) => t,
            None => return STATUS_NOT_SUPPORTED,
        };
        let entry = match get_entry(&tbl.nt_create_thread_ex) {
            Some(e) => e,
            None => return STATUS_NOT_SUPPORTED,
        };
        unsafe {
            sys_set_config(entry as *const SyscallEntry);
            sys_invoke_11(
                thread_handle as usize,
                desired_access as usize,
                object_attributes as usize,
                process as usize,
                start_routine as usize,
                argument as usize,
                create_flags as usize,
                zero_bits,
                stack_size,
                maximum_stack_size,
                attribute_list as usize,
            )
        }
    }

    /// `NtOpenProcess` via indirect syscall.
    pub fn nt_open_process(
        process_handle: *mut isize,
        desired_access: u32,
        object_attributes: *mut c_void,
        client_id: *mut c_void,
    ) -> i32 {
        let tbl = match table() {
            Some(t) => t,
            None => return STATUS_NOT_SUPPORTED,
        };
        let entry = match get_entry(&tbl.nt_open_process) {
            Some(e) => e,
            None => return STATUS_NOT_SUPPORTED,
        };
        unsafe {
            sys_set_config(entry as *const SyscallEntry);
            sys_invoke_4(
                process_handle as usize,
                desired_access as usize,
                object_attributes as usize,
                client_id as usize,
            )
        }
    }

    /// `NtTerminateProcess` via indirect syscall.
    pub fn nt_terminate_process(process: isize, exit_status: i32) -> i32 {
        let tbl = match table() {
            Some(t) => t,
            None => return STATUS_NOT_SUPPORTED,
        };
        let entry = match get_entry(&tbl.nt_terminate_process) {
            Some(e) => e,
            None => return STATUS_NOT_SUPPORTED,
        };
        unsafe {
            sys_set_config(entry as *const SyscallEntry);
            // 4-arg variant: 2 used + 2 shadow (unused but required by ABI).
            sys_invoke_4(process as usize, exit_status as usize, 0, 0)
        }
    }

    /// `NtClose` via indirect syscall.
    pub fn nt_close(handle: isize) -> i32 {
        let tbl = match table() {
            Some(t) => t,
            None => return STATUS_NOT_SUPPORTED,
        };
        let entry = match get_entry(&tbl.nt_close) {
            Some(e) => e,
            None => return STATUS_NOT_SUPPORTED,
        };
        unsafe {
            sys_set_config(entry as *const SyscallEntry);
            sys_invoke_4(handle as usize, 0, 0, 0)
        }
    }

    /// `NtWaitForSingleObject` via indirect syscall.
    pub fn nt_wait_for_single_object(handle: isize, alertable: bool, timeout: *mut i64) -> i32 {
        let tbl = match table() {
            Some(t) => t,
            None => return STATUS_NOT_SUPPORTED,
        };
        let entry = match get_entry(&tbl.nt_wait_for_single_object) {
            Some(e) => e,
            None => return STATUS_NOT_SUPPORTED,
        };
        unsafe {
            sys_set_config(entry as *const SyscallEntry);
            sys_invoke_4(handle as usize, alertable as usize, timeout as usize, 0)
        }
    }
}

// ── Non-Windows stubs ─────────────────────────────────────────────────────────

#[cfg(not(all(windows, target_arch = "x86_64")))]
mod stubs {
    use std::ffi::c_void;

    use super::super::STATUS_NOT_SUPPORTED;

    pub fn nt_allocate_virtual_memory(
        _process: isize,
        _base: *mut *mut c_void,
        _zero_bits: usize,
        _region_size: *mut usize,
        _alloc_type: u32,
        _protect: u32,
    ) -> i32 {
        STATUS_NOT_SUPPORTED
    }
    pub fn nt_write_virtual_memory(
        _process: isize,
        _base: *const c_void,
        _buf: *const c_void,
        _n: usize,
        _written: *mut usize,
    ) -> i32 {
        STATUS_NOT_SUPPORTED
    }
    pub fn nt_read_virtual_memory(
        _process: isize,
        _base: *const c_void,
        _buf: *mut c_void,
        _n: usize,
        _read: *mut usize,
    ) -> i32 {
        STATUS_NOT_SUPPORTED
    }
    pub fn nt_free_virtual_memory(
        _process: isize,
        _base: *mut *mut c_void,
        _size: *mut usize,
        _free_type: u32,
    ) -> i32 {
        STATUS_NOT_SUPPORTED
    }
    pub fn nt_protect_virtual_memory(
        _process: isize,
        _base: *mut *mut c_void,
        _size: *mut usize,
        _new: u32,
        _old: *mut u32,
    ) -> i32 {
        STATUS_NOT_SUPPORTED
    }
    #[allow(clippy::too_many_arguments)]
    pub fn nt_create_thread_ex(
        _handle: *mut isize,
        _access: u32,
        _attrs: *mut c_void,
        _process: isize,
        _start: *const c_void,
        _arg: *const c_void,
        _flags: u32,
        _zero_bits: usize,
        _stack_size: usize,
        _max_stack: usize,
        _attr_list: *mut c_void,
    ) -> i32 {
        STATUS_NOT_SUPPORTED
    }
    pub fn nt_open_process(
        _handle: *mut isize,
        _access: u32,
        _attrs: *mut c_void,
        _client_id: *mut c_void,
    ) -> i32 {
        STATUS_NOT_SUPPORTED
    }
    pub fn nt_terminate_process(_process: isize, _status: i32) -> i32 {
        STATUS_NOT_SUPPORTED
    }
    pub fn nt_close(_handle: isize) -> i32 {
        STATUS_NOT_SUPPORTED
    }
    pub fn nt_wait_for_single_object(_handle: isize, _alertable: bool, _timeout: *mut i64) -> i32 {
        STATUS_NOT_SUPPORTED
    }
}

// ── Re-exports ────────────────────────────────────────────────────────────────

#[cfg(all(windows, target_arch = "x86_64"))]
pub use windows_impl::{
    nt_allocate_virtual_memory, nt_close, nt_create_thread_ex, nt_free_virtual_memory,
    nt_open_process, nt_protect_virtual_memory, nt_read_virtual_memory, nt_terminate_process,
    nt_wait_for_single_object, nt_write_virtual_memory,
};

#[cfg(not(all(windows, target_arch = "x86_64")))]
pub use stubs::{
    nt_allocate_virtual_memory, nt_close, nt_create_thread_ex, nt_free_virtual_memory,
    nt_open_process, nt_protect_virtual_memory, nt_read_virtual_memory, nt_terminate_process,
    nt_wait_for_single_object, nt_write_virtual_memory,
};
