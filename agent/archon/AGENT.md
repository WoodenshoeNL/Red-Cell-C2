# Archon (Enhanced C Agent)

Fork of the Havoc Demon agent with intentional divergence. Same C/ASM codebase,
different capabilities. Always maintains byte-for-byte wire compatibility with the
Red Cell teamserver (same Demon binary protocol: 0xDEADBEEF magic, AES-256-CTR).

## Current State

Archon is a clean fork of Demon. It compiles and behaves identically. The parity
milestone is complete. All future changes are tracked in the backlog below.

## Build

Same toolchain as Demon — see `makefile` and `CMakeLists.txt`.

```bash
cd agent/archon
make
```

Cross-compilation requires `mingw-w64` and `nasm`.

---

## What Demon Already Has (Do Not Re-implement)

Before adding anything, read `agent/demon/src/` to understand the baseline:

| Feature | Demon files | Notes |
|---------|-------------|-------|
| Sleep obfuscation: Ekko, Zilean, Foliage | `src/core/Obf.c`, `include/core/SleepObf.h` | APC/timer ROP chains, RC4 encrypt during sleep |
| Indirect syscalls | `src/core/Syscalls.c`, `src/asm/Syscall.x64.asm` | Resolves SSN + nearest `syscall` instr |
| Return-address spoofing | `src/core/Spoof.c`, `src/asm/Spoof.x64.asm` | Trampoline gadget (`jmp [rbx]`) |
| AMSI bypass (HwBp + memory patch) | `src/core/HwBpExceptions.c`, `src/core/Dotnet.c` | Applied only during .NET inline exec |
| ETW bypass (HwBp `NtTraceEvent`) | `src/core/HwBpExceptions.c`, `src/core/Dotnet.c` | Applied only during .NET inline exec |
| Hardware breakpoint engine | `src/core/HwBpEngine.c` | Per-thread HWBP slots |

---

## Enhancement Backlog

Issues are filed in beads and labelled `zone:archon`. Work them in priority order.
**Do not start coding an enhancement before its beads issue exists.**

### P1 — High Value, Low Risk

#### ARC-01: Persistent process-wide AMSI/ETW bypass

**What**: Demon only patches AMSI (`AmsiScanBuffer`) and ETW (`NtTraceEvent`) on the
thread executing inline .NET. Archon should patch them once at initialization and
keep them patched for the lifetime of the implant.

**How**: Memory-patch the function prologue with a `ret` (x64: `0xC3`) immediately
after resolving the addresses in `Runtime.c`. This is simpler and more reliable than
HwBp for persistent suppression. Leave HwBp mode available as an opt-in for
scenarios where memory patching is too loud.

**Profile key** (new): `AmsiEtw = "patch" | "hwbp" | "none"` (default: `"patch"`)

**Files to touch**: `src/core/Runtime.c`, `Demon.h` (config struct), profile parser.

**Beads issue**: file before starting.

---

#### ARC-02: Synthetic call-stack frames during WaitForSingleObject / sleep

**What**: Demon spoofs the return address on the calling thread but does not
synthesize a realistic call stack. EDR products that walk the full stack during a
sleep will see a suspicious chain. Archon should unwind back to a plausible
`kernel32!BaseThreadInitThunk → ntdll!RtlUserThreadStart` chain by building
synthetic frames on the stack before blocking.

**How**: Before each sleep/wait, allocate a shadow stack area and write fake
`CONTEXT`-compatible return addresses pointing into `kernel32.dll` and `ntdll.dll`
image bases (resolved at runtime via LDR walk). Restore original RSP after wakeup.

**Reference**: `src/core/Spoof.c` (existing gadget infra), `src/core/Obf.c` (ROP chain setup).

**Files to touch**: `src/core/Spoof.c`, `src/asm/Spoof.x64.asm`, `include/core/Spoof.h`.

**Beads issue**: file before starting.

---

#### ARC-03: Timer-callback sleep obfuscation (Cronos-style, no suspended thread)

**What**: Ekko and Foliage use `NtQueueApcThread` on a suspended thread. This is
detectable because the thread is in `WaitForSingleObjectEx` with an alertable wait
and the APC queue is non-empty during the sleep window. Archon should add a fourth
sleep-obfuscation mode that uses `NtSetTimer2` (thread-pool timer callback) so no
thread is explicitly suspended and there is no APC queue to inspect.

**Profile key**: `SleepObf = 0x4` (new constant: `SLEEPOBF_CRONOS`).

**Files to touch**: `src/core/Obf.c`, `include/core/SleepObf.h`, `src/asm/` (new ROP stubs if needed).

**Beads issue**: file before starting.

---

### P2 — Meaningful Uplift, Moderate Complexity

#### ARC-04: Heap encryption during sleep

**What**: Demon encrypts its image sections during sleep via the ROP chain but leaves
heap allocations in plaintext. Archon should walk the process heap during the sleep
ROP chain and XOR/RC4-encrypt all Archon-owned heap blocks, restoring them on wakeup.

**How**: Tag all `HeapAlloc` calls in `MiniStd.c` with a sentinel header. During
the Obf ROP chain, walk the sentinel list and encrypt each block in-place before
calling `WaitForSingleObjectEx`, decrypt on resume.

**Files to touch**: `src/core/MiniStd.c`, `src/core/Obf.c`, `Demon.h`.

**Beads issue**: file before starting.

---

#### ARC-05: Module-stomping loader for reflective injection

**What**: When Archon is injected as a DLL via the teamserver's inject path, it loads
into a freshly allocated `MEM_PRIVATE` region, which is trivially flagged by scanners.
Archon should provide an optional loader that stomps an existing, already-mapped DLL
(e.g., a rarely-used system DLL loaded into every process) and loads itself into
that backing memory instead.

**How**: Implement a new entry in `src/inject/` analogous to the existing
`Inject.c` that: (1) finds a suitable victim DLL via LDR walk, (2) verifies its
mapped size is sufficient, (3) uses `NtProtectVirtualMemory` + `NtWriteVirtualMemory`
(indirect syscalls) to stomp it, (4) jumps to the stomped image's entry point.

**Files to touch**: new `src/inject/Stomp.c`, `include/inject/Stomp.h`, wired into `src/core/Command.c`.

**Beads issue**: file before starting.

---

#### ARC-06: JA3/JA3S fingerprint randomization for TLS

**What**: Demon's HTTPS listener uses a fixed TLS client-hello sequence determined
by the WinHTTP/Schannel stack. JA3 fingerprinting can identify the implant even when
traffic is encrypted. Archon should randomize the cipher suite order and TLS
extension list on each new connection.

**How**: Hook or replace the Schannel `SslEmptyCache` / `InitializeSecurityContext`
call path to inject a randomized `SCHANNEL_CRED` cipher list before each connection
is established. Only applies to the HTTP transport path (`src/core/TransportHttp.c`).

**Profile key**: `JA3Randomize = true | false` (default: `true` when transport is HTTPS).

**Files to touch**: `src/core/TransportHttp.c`, `include/core/TransportHttp.h`.

**Beads issue**: file before starting.

---

#### ARC-07: Stomped PE header (MZ/PE signature erasure)

**What**: When Archon is running as a loaded module, the MZ/PE header at its base
address is a reliable detection artefact. Archon should zero its own PE header
immediately after the reflective loader resolves all imports and relocations.

**How**: After `RuntimeInit()` completes in `src/main/MainDll.c`, call
`NtProtectVirtualMemory` to make the first page `PAGE_READWRITE`, zero the MZ/DOS/PE
headers, then restore `PAGE_EXECUTE_READ`. Store the module base before zeroing in
`Instance->Session.ModuleBase` (already used by Obf.c for section sizes).

**Files to touch**: `src/main/MainDll.c`, `src/core/Runtime.c`.

**Beads issue**: file before starting.

---

### P3 — Nice-to-Have, Higher Complexity

#### ARC-08: DNS-over-HTTPS (DoH) fallback transport

**What**: Add a second transport mode that tunnels C2 traffic over HTTPS queries to
a public DoH resolver, bypassing DNS-based network controls without requiring a
dedicated DNS listener.

**Profile key**: `Transport = "doh"` with `DoHProvider = "https://..."`.

**Files to touch**: new `src/core/TransportDoH.c`, wired into `src/core/Transport.c`.

**Beads issue**: file before starting.

---

#### ARC-09: Thread-pool execution for post-ex commands

**What**: Demon spawns a new thread for each post-exploitation job. Archon should
offer an option to queue jobs onto the native NT thread pool (`TpAllocWork` /
`TpPostWork`) so no new threads are created and thread-count anomaly detection
is harder to trigger.

**Profile key**: `JobExecution = "thread" | "threadpool"` (default: `"thread"` for
compatibility).

**Files to touch**: `src/core/Jobs.c`, `include/core/Jobs.h`.

**Beads issue**: file before starting.

---

## Compatibility Invariants

These must hold for every Archon change, no exceptions:

1. **Wire protocol**: Archon packets must pass the teamserver's `DemonInit` and
   `DemonCommand` parsers unchanged. Do not alter packet structure, magic bytes,
   command IDs, or AES key exchange.
2. **Profile format**: Archon reads the same `.yaotl` profile as Demon. New keys are
   additive; existing keys must behave identically.
3. **Toolchain**: `mingw-w64` + `nasm`, same `CMakeLists.txt` structure. Do not
   introduce new build-time dependencies without updating `docs/build-deps.md`.
4. **32-bit stubs**: All new ASM must provide both `x64` and `x86` variants or
   be guarded with `#if _WIN64`.

---

## Implementation Order

Work enhancements in this order to maximise early payoff and minimise churn:

1. ARC-07 (PE header erasure) — trivial, immediate win
2. ARC-01 (persistent AMSI/ETW) — high value, contained change
3. ARC-02 (synthetic call-stack) — hardest ASM work, do early while context is fresh
4. ARC-03 (Cronos sleep) — extends existing Obf.c patterns
5. ARC-04 (heap encryption) — depends on sentinel tagging in MiniStd
6. ARC-05 (module stomping) — new inject path, self-contained
7. ARC-06 (JA3 randomization) — transport layer, isolated
8. ARC-08 (DoH transport) — new transport, significant scope
9. ARC-09 (thread pool exec) — lowest priority, compatibility risk

Each item must be a separate beads issue, a separate commit, and must pass
`cargo clippy`/`cargo fmt` (Rust workspace) and the C build (`make`) before merge.
