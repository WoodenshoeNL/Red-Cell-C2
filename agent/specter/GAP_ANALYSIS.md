# Specter Gap Analysis — Demon Protocol Parity

**Date:** 2026-04-03
**Issue:** red-cell-c2-lmgs5

## Summary

Specter implements **all 22 dispatchable command types** from the Demon protocol,
plus two agent-specific extensions (Persist, Harvest). The `CommandSocket` and
`CommandPivot` commands are intercepted by the agent run-loop before dispatch.
All previously identified gaps (NetComputer/DcList, PE stomp, DoH transport,
BOF spawn context) have been closed.

Overall status: **~100% protocol parity** — Specter is a full-featured Windows
agent with comprehensive Demon-compatible capabilities and additional evasion
features (indirect syscalls, sleep obfuscation, ETW/AMSI bypass, return-address
spoofing, PE header stomping).

---

## Inventory

### Legend

| Status | Meaning |
|--------|---------|
| ✅ Implemented | Full implementation with Windows-native APIs |
| 🔶 Partial | Dispatched but with known limitations |
| ❌ Missing | Not dispatched; falls through to generic error |
| ➖ N/A | Not a task command (callback/control-plane only) |

---

### Registration & Control Flow

| Command | ID | Status | Notes |
|---------|---:|--------|-------|
| DemonInit | 99 | ✅ Implemented | Full host metadata: hostname, user, domain, IP, PID/PPID/TID, arch, OS version, sleep config. Progressive CTR mode. |
| CommandCheckin | 100 | ✅ Implemented | Heartbeat callback, advances CTR offset |
| CommandGetJob | 1 | ✅ Implemented | Two-request pattern (checkin then get-job) |
| CommandNoJob | 10 | ✅ Implemented | No-op |
| CommandExit | 92 | ✅ Implemented | Immediate termination with exit callback |
| CommandKillDate | 93 | ✅ Implemented | Dynamic set/disable, checked in main loop |

### Sleep & Jitter

| Command | ID | Status | Notes |
|---------|---:|--------|-------|
| CommandSleep | 11 | ✅ Implemented | Dynamic delay/jitter. Three obfuscation modes: plain (0), Cronos timer-callback with .rdata XOR (1), Cronos + heap encryption (2). Working hours bitmask enforcement. |

### Process Operations

| Command | ID | Sub-cmd | Status | Notes |
|---------|---:|---------|--------|-------|
| CommandProcList | 12 | — | ✅ Implemented | Toolhelp32 snapshot: PID, PPID, name, user, arch (x86/x64), session |
| CommandProc | 0x1010 | Create (4) | ✅ Implemented | CreateProcess with piped I/O, verbose flag, state control |
| CommandProc | 0x1010 | Kill (7) | ✅ Implemented | TerminateProcess by PID |
| CommandProc | 0x1010 | Grep (3) | ✅ Implemented | Case-insensitive process name search |
| CommandProc | 0x1010 | Modules (2) | ✅ Implemented | Module32 enumeration of loaded DLLs |
| CommandProc | 0x1010 | Memory (6) | ✅ Implemented | VirtualQueryEx memory region enumeration |
| CommandProcPpidSpoof | 27 | — | ✅ Implemented | PROC_THREAD_ATTRIBUTE_PARENT_PROCESS spoofing |

### File System Operations

| Command | ID | Sub-cmd | Status | Notes |
|---------|---:|---------|--------|-------|
| CommandFs | 15 | Dir (1) | ✅ Implemented | Recursive listing with filters (starts-with, contains, ends-with) |
| CommandFs | 15 | Download (2) | ✅ Implemented | Chunked download with 512 KiB chunks, file ID tracking |
| CommandFs | 15 | Upload (3) | ✅ Implemented | Via MemFile buffer, writes to disk on completion |
| CommandFs | 15 | Cd (4) | ✅ Implemented | Change working directory |
| CommandFs | 15 | Remove (5) | ✅ Implemented | File or directory deletion |
| CommandFs | 15 | Mkdir (6) | ✅ Implemented | Recursive directory creation |
| CommandFs | 15 | Copy (7) | ✅ Implemented | File copy |
| CommandFs | 15 | Move (8) | ✅ Implemented | File rename/move |
| CommandFs | 15 | GetPwd (9) | ✅ Implemented | Return current directory |
| CommandFs | 15 | Cat (10) | ✅ Implemented | Read file contents |

### Code Injection

| Command | ID | Status | Notes |
|---------|---:|--------|-------|
| CommandInjectShellcode | 24 | ✅ Implemented | Three modes: inject into PID (NtAllocate/NtWrite/NtCreateThreadEx), spawn with PPID spoof + inject, in-process local execution. All via indirect syscalls. |
| CommandInjectDll | 22 | ✅ Implemented | Reflective DLL injection into target process |
| CommandSpawnDll | 26 | ✅ Implemented | Spawn child with configured spawn path + reflective DLL injection |
| CommandInlineExecute (BOF) | 20 | ✅ Implemented | Full COFF/BOF loader with Beacon API compatibility (see BOF section below) |

### Token & Impersonation

| Command | ID | Sub-cmd | Status | Notes |
|---------|---:|---------|--------|-------|
| CommandToken | 40 | Impersonate (1) | ✅ Implemented | Set thread token from vault entry |
| CommandToken | 40 | Steal (2) | ✅ Implemented | OpenProcessToken + DuplicateTokenEx from target PID |
| CommandToken | 40 | List (3) | ✅ Implemented | Enumerate vault entries |
| CommandToken | 40 | Privs (4) | ✅ Implemented | AdjustTokenPrivileges — enumerate/enable/disable |
| CommandToken | 40 | Make (5) | ✅ Implemented | LogonUserW network logon (domain\user + password) |
| CommandToken | 40 | GetUid (6) | ✅ Implemented | GetTokenInformation(TokenUser) — identity + elevation |
| CommandToken | 40 | Revert (7) | ✅ Implemented | Revert to original process token |
| CommandToken | 40 | Remove (8) | ✅ Implemented | Remove vault entry |
| CommandToken | 40 | Clear (9) | ✅ Implemented | Clear all tokens |
| CommandToken | 40 | FindTokens (10) | ✅ Implemented | System-wide token enumeration via handle table scan |

### .NET & PowerShell

| Command | ID | Status | Notes |
|---------|---:|--------|-------|
| CommandAssemblyInlineExecute | 0x2001 | ✅ Implemented | In-process .NET CLR hosting via mscoree.dll, console output capture |
| CommandAssemblyListVersions | 0x2003 | ✅ Implemented | Enumerate installed CLR versions |
| CommandPsImport | 0x1011 | ✅ Implemented | PowerShell script staging via MemFile |

### Job Management

| Command | ID | Sub-cmd | Status | Notes |
|---------|---:|---------|--------|-------|
| CommandJob | 21 | List (1) | ✅ Implemented | Enumerate background jobs with ID, type, state |
| CommandJob | 21 | Suspend (2) | ✅ Implemented | Suspend job thread |
| CommandJob | 21 | Resume (3) | ✅ Implemented | Resume suspended job |
| CommandJob | 21 | Kill (4) | ✅ Implemented | Terminate and remove job |

### Network Discovery

| Command | ID | Sub-cmd | Status | Notes |
|---------|---:|---------|--------|-------|
| CommandNet | 2100 | Domain (1) | ✅ Implemented | GetComputerNameExW domain enumeration |
| CommandNet | 2100 | Logons (2) | ✅ Implemented | NetWkstaUserEnum logon sessions |
| CommandNet | 2100 | Sessions (3) | ✅ Implemented | NetSessionEnum network sessions |
| CommandNet | 2100 | Computer (4) | ✅ Implemented | NetServerEnum SV_TYPE_ALL — enumerate domain computers |
| CommandNet | 2100 | DcList (5) | ✅ Implemented | NetServerEnum SV_TYPE_DOMAIN_CTRL — list domain controllers |
| CommandNet | 2100 | Share (6) | ✅ Implemented | NetShareEnum network shares |
| CommandNet | 2100 | LocalGroup (7) | ✅ Implemented | NetLocalGroupEnum local groups |
| CommandNet | 2100 | Group (8) | ✅ Implemented | NetGroupEnum domain groups |
| CommandNet | 2100 | Users (9) | ✅ Implemented | NetUserEnum domain users |

### Screenshot

| Command | ID | Status | Notes |
|---------|---:|--------|-------|
| CommandScreenshot | 2510 | ✅ Implemented | GDI desktop capture (BitBlt) |

### Configuration

| Command | ID | Sub-cmd | Status | Notes |
|---------|---:|---------|--------|-------|
| CommandConfig | 2500 | SleepMask (1) | ✅ Implemented | Enable/disable sleep obfuscation |
| CommandConfig | 2500 | SpfThreadAddr (3) | ✅ Implemented | Thread start address spoofing |
| CommandConfig | 2500 | Verbose (4) | ✅ Implemented | Verbose logging toggle |
| CommandConfig | 2500 | SleepTechnique (5) | ✅ Implemented | Obfuscation technique (0/1/2) |
| CommandConfig | 2500 | CoffeeThreaded (6) | ✅ Implemented | BOF threaded execution toggle |
| CommandConfig | 2500 | CoffeeVeh (7) | ✅ Implemented | BOF VEH exception handler toggle |
| CommandConfig | 2500 | MemoryAlloc (101) | ✅ Implemented | Memory allocation method |
| CommandConfig | 2500 | MemoryExecute (102) | ✅ Implemented | Memory execution method |
| CommandConfig | 2500 | InjectTechnique (150) | ✅ Implemented | DLL injection technique |
| CommandConfig | 2500 | InjectSpoofAddr (151) | ✅ Implemented | Injection spoof address |
| CommandConfig | 2500 | Spawn64 (152) | ✅ Implemented | x64 spawn-to process path |
| CommandConfig | 2500 | Spawn32 (153) | ✅ Implemented | x86 spawn-to process path |
| CommandConfig | 2500 | KillDate (154) | ✅ Implemented | Kill date (Unix timestamp) |
| CommandConfig | 2500 | WorkingHours (155) | ✅ Implemented | Working hours bitmask |

### Pivot & Lateral Movement

| Command | ID | Sub-cmd | Status | Notes |
|---------|---:|---------|--------|-------|
| CommandPivot | 2520 | List (1) | ✅ Implemented | Enumerate active pivot connections |
| CommandPivot | 2520 | SmbConnect (10) | ✅ Implemented | Named-pipe connection to child agent |
| CommandPivot | 2520 | SmbDisconnect (11) | ✅ Implemented | Tear down pivot |
| CommandPivot | 2520 | SmbCommand (12) | ✅ Implemented | Forward Demon packets through pipe |

Note: CommandPivot is intercepted by the agent run-loop (`agent.rs`) before
`dispatch()` and routed directly to `PivotState::handle_command()`.

### Socket & Port Forwarding

| Command | ID | Sub-cmd | Status | Notes |
|---------|---:|---------|--------|-------|
| CommandSocket | 2540 | RPortFwd Add (0) | ✅ Implemented | Bind listener, relay through C2 |
| CommandSocket | 2540 | RPortFwd AddLocal (1) | ✅ Implemented | Bind listener, forward locally |
| CommandSocket | 2540 | RPortFwd List (2) | ✅ Implemented | List active port forwards |
| CommandSocket | 2540 | RPortFwd Clear (3) | ✅ Implemented | Clear all listeners |
| CommandSocket | 2540 | RPortFwd Remove (4) | ✅ Implemented | Remove specific listener |
| CommandSocket | 2540 | SOCKS5 Add (5) | ✅ Implemented | Full SOCKS5 proxy (no-auth) |
| CommandSocket | 2540 | SOCKS5 List (6) | ✅ Implemented | List proxies |
| CommandSocket | 2540 | SOCKS5 Remove (7) | ✅ Implemented | Remove proxy |
| CommandSocket | 2540 | SOCKS5 Clear (8) | ✅ Implemented | Clear all |
| CommandSocket | 2540 | Open/Read/Write/Close/Connect | ✅ Implemented | Full socket lifecycle (0x10–0x14) |

Note: CommandSocket is intercepted by the agent run-loop (`agent.rs`) before
`dispatch()` and handled via `SocketState::handle_command()` for async I/O.

### Kerberos

| Command | ID | Sub-cmd | Status | Notes |
|---------|---:|---------|--------|-------|
| CommandKerberos | 2550 | LUID (0) | ✅ Implemented | GetTokenInformation(TokenStatistics) |
| CommandKerberos | 2550 | Klist (1) | ✅ Implemented | Full LSA ticket enumeration with principal names, realms, encryption types, flags, ticket data |
| CommandKerberos | 2550 | Purge (2) | ✅ Implemented | Clear tickets for specific LUID |
| CommandKerberos | 2550 | PTT (3) | ✅ Implemented | KERB_SUBMIT_TKT_REQUEST ticket injection |

### File Transfer Management

| Command | ID | Sub-cmd | Status | Notes |
|---------|---:|---------|--------|-------|
| CommandTransfer | 2530 | List (0) | ✅ Implemented | Active transfer enumeration |
| CommandTransfer | 2530 | Stop (1) | ✅ Implemented | Pause transfer |
| CommandTransfer | 2530 | Resume (2) | ✅ Implemented | Resume paused transfer |
| CommandTransfer | 2530 | Remove (3) | ✅ Implemented | Remove transfer |

### Memory File

| Command | ID | Status | Notes |
|---------|---:|--------|-------|
| CommandMemFile | 2560 | ✅ Implemented | In-memory file buffer (create/write/close) for uploads |
| CommandPackageDropped | 2570 | ✅ Implemented | Handle in-flight download removal |

### Specter-Only Extensions (not in Demon)

| Command | ID | Status | Notes |
|---------|---:|--------|-------|
| CommandPersist | 3000 | ✅ Implemented | Windows persistence: Registry RunKey, Startup folder, PowerShell profile (install/remove) |
| CommandHarvest | 2580 | ✅ Implemented | DPAPI credential extraction |

### Callback-Only Commands (no dispatch needed)

| Command | ID | Notes |
|---------|---:|-------|
| DemonInfo | 89 | Informational callback — not a task |
| CommandOutput | 90 | Output callback |
| CommandError | 91 | Error callback |
| BeaconOutput | 94 | Legacy Beacon output |

---

## Specter-Specific Focus Areas

### BOF Loading and Execution

**Status: ✅ Full implementation** (`coffeeldr.rs`)

- COFF object file parser and executor with section mapping, import resolution,
  and relocation processing
- Full Beacon API compatibility:
  - Data parsing: `BeaconDataParse`, `BeaconDataInt`, `BeaconDataShort`,
    `BeaconDataExtract`, `BeaconDataLength`
  - Output: `BeaconOutput`, `BeaconPrintf` (via C variadic shim in `csrc/bof_printf.c`)
  - Spawn: `BeaconGetSpawnTo`, `BeaconSpawnTemporaryProcess`, `BeaconInjectProcess`,
    `BeaconInjectTemporaryProcess`, `BeaconInformation`
  - Token: `BeaconUseToken`, `BeaconRevertToken`, `BeaconIsAdmin`
  - Formatting: `BeaconFormatAlloc`, `BeaconFormatFree`, `BeaconFormatAppend`,
    `BeaconFormatPrintf`, `BeaconFormatToString`, `BeaconFormatInt`, `BeaconFormatReset`
- Threaded and non-threaded execution modes (configurable via `COMMAND_CONFIG`)
- VEH (Vectored Exception Handler) crash protection
- Background BOF threads feed output via `Arc<Mutex<Vec>>` queue
- BOF spawn context correctly propagated to worker threads (fixed in red-cell-c2-7nmhu)

### Process Injection Techniques

**Status: ✅ Full implementation** (`dispatch.rs`, `syscall.rs`)

Three injection paths, all using indirect syscalls:

1. **Shellcode injection** (`CommandInjectShellcode`):
   - Inject mode: NtAllocateVirtualMemory → NtWriteVirtualMemory → NtProtectVirtualMemory → NtCreateThreadEx in target PID
   - Spawn mode: Create child process with PPID spoofing, then inject
   - Local mode: In-process RWX allocation and execution

2. **Reflective DLL injection** (`CommandInjectDll`):
   - DLL payload with optional parameters into target process

3. **Spawn + DLL** (`CommandSpawnDll`):
   - Spawn child with configured spawn path, then reflective inject

### Windows Token / Impersonation Operations

**Status: ✅ Full implementation** (`token.rs`)

- Token vault with sparse-list storage
- All 10 Demon token sub-commands implemented
- System-wide token discovery via handle table enumeration
- Full privilege manipulation (enumerate/enable/disable)

### SMB/TCP Pivot Listeners

**Status: ✅ Full implementation** (`pivot.rs`, `socket.rs`)

- SMB named-pipe pivot chains with 30-packet poll throttle
- Full SOCKS5 proxy (no-auth) with bidirectional relay
- Reverse port forwarding (teamserver relay and local forward modes)
- All 14 socket sub-commands dispatched

---

## Evasion Features (beyond Demon baseline)

| Feature | Module | Status | Notes |
|---------|--------|--------|-------|
| Indirect syscalls | `syscall.rs` | ✅ | Runtime SSN resolution, gadget dispatch, hook detection, 15 NT functions |
| Return-address spoofing | `spoof.rs` | ✅ | AceLdr technique: `jmp [rbx]` gadget scan, stack trampoline |
| Sleep obfuscation | `sleep_obf.rs` | ✅ | Cronos timer-callback: .rdata XOR + PE header zeroing during sleep |
| Heap encryption at rest | `sleep_obf.rs` | ✅ | Technique 2: Cronos + heap block XOR during sleep |
| PE header stomping | `pe_stomp.rs` | ✅ | One-shot DOS header zeroing at startup |
| ETW bypass | `bypass.rs` | ✅ | In-memory EtwEventWrite patch |
| AMSI bypass | `bypass.rs` | ✅ | In-memory AmsiScanBuffer patch |
| PPID spoofing | `dispatch.rs` | ✅ | PROC_THREAD_ATTRIBUTE_PARENT_PROCESS for spawned processes |
| DoH fallback transport | `doh_transport.rs` | ✅ | Base32 TXT encoding via Cloudflare/Google DoH |
| TLS certificate pinning | `transport.rs` | ✅ | Compile-time or env-var PEM pinning |

---

## Protocol & Transport Verification

| Aspect | Status | Notes |
|--------|--------|-------|
| 0xDEADBEEF magic | ✅ | Correct |
| AES-256-CTR encryption | ✅ | Per-agent session keys |
| Progressive CTR mode | ✅ | Counter advances across packets (not per-packet reset) |
| HKDF session key derivation | ✅ | From listener init secret |
| HTTP(S) transport | ✅ | reqwest + rustls, optional cert pinning |
| DoH fallback transport | ✅ | Base32 TXT queries via public DoH resolvers |
| Chunked file transfer | ✅ | 512 KiB chunks with file ID tracking |
| Callback wire format | ✅ | Binary-compatible with Demon (BE header, LE payload) |
| Endianness | ✅ | Server→agent LE, agent→server BE envelope + LE content |

---

## Gap Summary

**No protocol gaps remain.** All 22 Demon command types are dispatched and
implemented with full Windows-native APIs. All previously identified issues
have been closed:

| Former Issue | Description | Resolution |
|---|---|---|
| red-cell-c2-5la4k | NetComputer/NetDcList stubs | Closed — implemented via NetServerEnum |
| red-cell-c2-9aq7r | PE stomp + heap encryption | Closed — pe_stomp.rs + sleep technique 2 |
| red-cell-c2-s79pa | DoH fallback transport | Closed — doh_transport.rs |
| red-cell-c2-7nmhu | BOF spawn context | Closed — spawn_ctx propagated to worker threads |

**No new issues to file.**
