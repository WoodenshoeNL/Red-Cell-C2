# COFF Loader: REL32 Relocation Addend Fix

**Date:** 2026-07-21  
**Commit:** `ab5ae197`  
**Agent:** Desktop (Anvil)  
**Component:** `agent/specter/src/coffeeldr.rs`

## Problem

Every BOF executed through Specter's COFF loader crashed with
`STATUS_ACCESS_VIOLATION` (0xC0000005) the moment the BOF's `go()` entry
point was called. This affected all BOFs with global/static variables —
essentially every non-trivial BOF.

The crash occurred despite the entire loading pipeline succeeding:
- COFF header parsed ✓
- External imports resolved ✓
- Relocations applied ✓
- Memory protections set ✓
- Entry point found ✓
- → CRASH at `func(bof_arg_data, bof_arg_len)` call

## Root Cause

The `IMAGE_REL_AMD64_REL32` relocation handler was **overwriting** the
existing 4-byte displacement at each patch site instead of **adding to it**.

### Background: How REL32 Works with Section Symbols

In COFF object files, when code references a global/static variable, the
compiler emits a RIP-relative instruction and creates a relocation entry
pointing to the **section symbol** (e.g. `.data`), not the individual
variable. The variable's offset within the section is encoded as the
existing `disp32` value in the instruction itself.

Example from `whoami.x64.o`:
```asm
.text+0x179:  add rdx, QWORD PTR [rip+0x10]  ; 0x10 = offset of 'output' in .data
```

Relocation entry:
```
VA=0x17C  Type=REL32  Symbol=.data (value=0)
```

The `0x10` displacement is the ONLY thing identifying the specific variable
(`output` at `.data+0x10`, vs `currentoutsize` at `.data+0x8`, vs `trash`
at `.data+0x0`).

### The Bug

The old code:
```rust
let rip = patch_addr as u64 + 4;
let delta = target_addr.wrapping_sub(rip) as i32;
unsafe { std::ptr::copy_nonoverlapping(delta.to_le_bytes().as_ptr(), patch_addr, 4); }
```

This computed `delta = section_base - rip` and **overwrote** the existing
`0x10` value. After relocation, the instruction became:
```asm
add rdx, QWORD PTR [rip+<delta_to_.data_base>]  ; now points to .data+0x0
```

The instruction now reads from `.data+0x0` (the `trash` variable — garbage)
instead of `.data+0x10` (the HeapAlloc'd output buffer pointer). The BOF
uses this garbage value as a memory address and tries to write to it →
access violation.

### Impact

50 out of 98 REL32 relocations in `whoami.x64.o` had non-zero existing
displacements. Every one was silently corrupted.

## Diagnosis

### Step 1: Vectored Exception Handler (VEH)

Added a VEH to capture crash details (see `agent/specter/src/coffeeldr.rs`,
`crash_veh` module). The VEH captures:
- Exception code
- Faulting instruction address
- For access violations: read/write/execute type + target VA

Crash output:
```
BOF_CRASH_VEH: code=0xC0000005 fault_addr=0x2903F270191 type=write target=0x2903EF7B040
```

### Step 2: Decode with objdump

The faulting instruction at `.text+0x191`:
```asm
191:  rep movs BYTE PTR es:[rdi], BYTE PTR ds:[rsi]
```

The destination `rdi` was computed from `[rip+0x10]` (the corrupted
relocation site). The `target=0x2903EF7B040` was the garbage value read
from `.data+0x0` instead of the real output buffer pointer at `.data+0x10`.

### Step 3: Confirm with relocation analysis

Parsed the BOF's relocation table: 50/98 REL32 relocations had non-zero
existing displacements (8, 16, 60, etc.), all referencing section symbols
with `value=0`.

## Fix

```rust
// Read the existing disp32 (addend) before overwriting
let addend = unsafe { ptr_read_i32(patch_addr) } as u64;
// Add the addend to the target address
let delta = target_addr.wrapping_add(addend).wrapping_sub(rip) as i32;
```

Helper function:
```rust
unsafe fn ptr_read_i32(addr: *mut u8) -> i32 {
    unsafe { i32::from_le_bytes([*addr, *addr.add(1), *addr.add(2), *addr.add(3)]) }
}
```

Applied to both `REL32` (type 4) and `REL32_1..REL32_5` (types 5-9).

### Why This Is Always Safe

| Symbol type | Existing addend | Effect |
|---|---|---|
| Section symbol (`.data`, `.rdata`) | Variable offset (non-zero) | Corrected — now points to right variable |
| Import (`__imp_*`) | 0 | No change — was already correct |
| External function | 0 | No change — was already correct |

## Verification

**Before fix** (commit `061799ce`):
```
BOF: calling entry point go() ep="0x2903f2709a3"
BOF_CRASH_VEH: code=0xC0000005 type=write target=0x2903ef7b040
→ process DEAD
```

**After fix** (commit `ab5ae197`):
```
BOF: calling entry point go() ep="0x210210d09a3"
BOF: execution completed output_len=5312
→ agent ALIVE, continues beaconing
```

**Test setup:**
- BOF: `whoami.x64.o` (6903 bytes, CS-Situational-Awareness-BOF)
- Agent: Specter `2BEED883` on Windows test VM (192.168.50.15, Windows 10 x64 build 26200)
- C2: Red-Cell-C2 teamserver (192.168.50.48:40056 API + :19100 HTTP listener)
- Delivery: MemFile upload + InlineExecute task via REST API

**Also added in this commit:**
- VEH crash diagnostics module (`crash_veh`) — captures exception details
  for any future BOF crashes. Uses correct `AddVectoredExceptionHandler`
  API (the prior session's attempt used a non-existent doubled-Handler
  name and was dead code).
- `Win32_System_Kernel` feature in `agent/specter/Cargo.toml` (required
  for VEH API and `EXCEPTION_POINTERS` struct).
- Post-execution trace (`output_len`) to confirm BOF output capture.

## Related Files

- `agent/specter/src/coffeeldr.rs` — the fix + VEH module
- `agent/specter/src/beacon_api.rs` — Beacon API implementations (unchanged)
- `agent/specter/src/bof_context.rs` — `DataParser` / `datap` struct (unchanged)
