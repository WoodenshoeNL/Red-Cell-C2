# VEH Crash Handler: Evolution and Limitations

**Date:** 2026-07-21  
**Commits:** `4c36f718`, `b2a0307f`, `3f1b9d3b`  
**Agent:** Desktop (Anvil)  
**Component:** `agent/specter/src/coffeeldr.rs` — `crash_veh` module

## Overview

The Vectored Exception Handler (VEH) captures hardware exceptions during BOF
execution, providing diagnostic output (exception code, faulting address, AV
type/target) to stderr. It was iteratively refined across 3 commits to improve
crash survival during batch BOF testing.

## Evolution

### Commit 4c36f718 — CONTINUE_EXECUTION (initial crash-survival)

Changed the VEH return value from `EXCEPTION_CONTINUE_SEARCH` (0, let process
die) to `EXCEPTION_CONTINUE_EXECUTION` (-1, suppress and continue). This allows
the agent to survive BOF crashes — one crashing BOF no longer kills the entire
agent process.

### Commit b2a0307f — AV-only guard

**Problem:** Returning CONTINUE_EXECUTION for `STATUS_BREAKPOINT` (0x80000003)
caused an infinite loop — the breakpoint instruction re-triggers on every
re-execution.

**Fix:** The VEH now only suppresses `ACCESS_VIOLATION` (0xC0000005) and returns
`CONTINUE_SEARCH` for all other exceptions (breakpoints, single-step, etc.).

### Commit 3f1b9d3b — RIP advancement

**Problem:** CONTINUE_EXECUTION alone re-executes the faulting instruction,
which triggers the same AV again (infinite loop for NULL reads — the instruction
reads from address 0, gets suppressed, re-executes, reads from 0 again, ...).

**Fix:** Before returning CONTINUE_EXECUTION, the VEH modifies the CONTEXT
record to advance RIP by 1 byte and clear RAX. This skips the faulting
instruction instead of re-executing it.

```rust
if !ep.ContextRecord.is_null() {
    let ctx = unsafe { &mut *ep.ContextRecord };
    ctx.Rax = 0;
    ctx.Rip = ctx.Rip.wrapping_add(1);
}
-1 // EXCEPTION_CONTINUE_EXECUTION
```

## Limitations

The 1-byte RIP skip is fundamentally limited. When the VEH suppresses an AV
and skips 1 byte, it may land mid-instruction, producing garbage opcodes that
trigger cascading exceptions:

```
14B6  read  target=0x0          ← original NULL read (AV, suppressed, RIP+1)
14B7  write target=0xE70162...  ← mid-instruction write (AV, suppressed, RIP+1)
14B8  write target=0xE70162...  ← still mid-instruction (AV, suppressed, RIP+1)
14BF  read  target=0x0          ← cascading through garbage (AV, suppressed)
14C0  0xC000001D                ← ILLEGAL_INSTRUCTION — NOT an AV, process dies
```

Other non-AV exceptions observed after RIP-skip cascades:
- `0xC000001D` — ILLEGAL_INSTRUCTION
- `0xC0000096` — PRIVILEGED_INSTRUCTION

Since the VEH only handles 0xC0000005, these non-AV exceptions return
CONTINUE_SEARCH and the process terminates.

## Root Cause of Crashes

All crashing BOFs dereference NULL pointers from Windows APIs that return NULL
on the test VM (workgroup, no domain controller, no LanmanServer service):
- NetSessionEnum, NetGroupEnum, NetUserEnum, etc. → NULL return → NULL deref
- LSA APIs, RPC-dependent calls → same pattern

This is NOT a loader bug. The COFF loader (after the REL32 addend fix) loads
and executes BOFs correctly. The crashes are BOF-specific: the BOFs don't
check API return values before dereferencing.

## Future Work: Sacrificial Child-Process Execution

The only robust solution for crash immunity is running each BOF in a separate
child process. If the BOF crashes, only the child dies — the parent agent
survives and continues. This would allow testing ALL BOFs (including the 42
that currently crash) in a single batch run without agent restarts.

## Verification

All 3 VEH fixes verified via ad-hoc scripts:
- `/tmp/hermes-verify-veh-survival.sh` — commit 4c36f718
- `/tmp/hermes-verify-veh-av-only.sh` — commit b2a0307f
- `/tmp/hermes-verify-final-veh-state.sh` — commit 3f1b9d3b (12/12 PASS)

Runtime verified: 17/64 SA BOFs produce real output. The 42 crashing BOFs
all hit the RIP-skip cascade limit documented above.
