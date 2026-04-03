# Phantom Gap Analysis — Demon Protocol Parity

**Date:** 2026-04-03
**Issue:** red-cell-c2-9uocv

## Summary

Phantom implements **20 of 22 dispatchable command types** from the Demon protocol.
The remaining 2 commands (`CommandProcPpidSpoof`, `CommandKerberos`) are not handled
and fall through to a generic "not implemented" error. Six additional commands are
correctly stubbed as Windows-only with explicit error messages.

Overall status: **~95% protocol parity** — Phantom is production-grade for Linux C2
operations with comprehensive Linux-native adaptations.

---

## Inventory

### Legend

| Status | Meaning |
|--------|---------|
| ✅ Implemented | Full implementation with Linux-native adaptation where needed |
| 🔶 Windows-only stub | Explicitly returns "not supported on Linux" — correct behavior |
| ❌ Missing | Not dispatched; falls through to generic error |
| ➖ N/A | Not a task command (callback/control-plane only) |

---

### Registration & Control Flow

| Command | ID | Status | Notes |
|---------|---:|--------|-------|
| DemonInit | 99 | ✅ Implemented | Full host metadata: hostname, user, domain, IP, PID/PPID/TID, arch, kernel version, sleep config. Sends monotonic CTR extension flag. |
| CommandCheckin | 100 | ✅ Implemented | Heartbeat callback, advances CTR offset |
| CommandGetJob | 1 | ✅ Implemented | Two-request pattern (checkin then get-job) |
| CommandNoJob | 10 | ✅ Implemented | No-op |
| CommandExit | 92 | ✅ Implemented | Graceful shutdown with exit callback |
| CommandKillDate | 93 | ✅ Implemented | Dynamic set/disable, checked in main loop |

### Sleep & Jitter

| Command | ID | Status | Notes |
|---------|---:|--------|-------|
| CommandSleep | 11 | ✅ Implemented | Dynamic sleep_delay_ms + jitter percentage. Two obfuscation modes: mprotect (marks heap PROT_NONE during sleep) and plain nanosleep. Working hours bitmask enforcement. |

### Process Operations

| Command | ID | Sub-cmd | Status | Notes |
|---------|---:|---------|--------|-------|
| CommandProcList | 12 | — | ✅ Implemented | Full /proc enumeration: PID, PPID, session, threads, name, user, WoW64 detection |
| CommandProc | 0x1010 | Create (4) | ✅ Implemented | /bin/sh -c or binary spawn, piped stdout/stderr, verbose flag |
| CommandProc | 0x1010 | Kill (7) | ✅ Implemented | SIGKILL by PID |
| CommandProc | 0x1010 | Grep (3) | ✅ Implemented | Case-insensitive process name search |
| CommandProc | 0x1010 | Modules (2) | ✅ Implemented | Enumerates shared libraries via /proc/pid/maps |
| CommandProc | 0x1010 | Memory (6) | ✅ Implemented | Memory region enumeration with protection filters |
| CommandProcPpidSpoof | 27 | — | ❌ Missing | Not dispatched. Windows concept (CreateProcess with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS). No direct Linux equivalent — should be added to Windows-only stub list. |

### File System Operations

| Command | ID | Sub-cmd | Status | Notes |
|---------|---:|---------|--------|-------|
| CommandFs | 15 | Dir (1) | ✅ Implemented | Recursive listing with filters |
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
| CommandInjectShellcode | 24 | ✅ Implemented | Three modes: ptrace into existing PID, spawn+inject, in-process RWX mmap. Yama ptrace check. |
| CommandInjectDll | 22 | ✅ Implemented | Linux adaptation: .so injection via /dev/shm + ptrace + __libc_dlopen_mode stub |
| CommandSpawnDll | 26 | ✅ Implemented | Linux adaptation: fork child with LD_PRELOAD |
| CommandInlineExecute (BOF) | 20 | 🔶 Windows-only stub | COFF/BOF requires Windows PE loader. Returns error. |

### Token & Impersonation

| Command | ID | Status | Notes |
|---------|---:|--------|-------|
| CommandToken | 40 | 🔶 Windows-only stub | Windows token impersonation/vault. No Linux equivalent (Linux uses UID/capabilities). Returns error. |

### .NET & PowerShell

| Command | ID | Status | Notes |
|---------|---:|--------|-------|
| CommandAssemblyInlineExecute | 0x2001 | 🔶 Windows-only stub | .NET CLR injection. Returns error. |
| CommandAssemblyListVersions | 0x2003 | 🔶 Windows-only stub | .NET framework enumeration. Returns error. |
| CommandPsImport | 0x1011 | 🔶 Windows-only stub | PowerShell import. Returns error. |

### Job Management

| Command | ID | Status | Notes |
|---------|---:|--------|-------|
| CommandJob | 21 | 🔶 Windows-only stub | Windows job objects (list/suspend/resume/kill). Returns error. Could potentially manage background tasks on Linux but not required for protocol parity. |

### Network Discovery

| Command | ID | Status | Notes |
|---------|---:|--------|-------|
| CommandNet | 2100 | ✅ Implemented | Linux adaptation: network interfaces (IP/netmask/MAC), routing table, active TCP/UDP connections. Replaces Demon's Windows NetApi32 calls (domain, logons, sessions, shares, groups). |

### Screenshot

| Command | ID | Status | Notes |
|---------|---:|--------|-------|
| CommandScreenshot | 2510 | ✅ Implemented | X11 + Wayland support with black-image fallback |

### Configuration

| Command | ID | Sub-cmd | Status | Notes |
|---------|---:|---------|--------|-------|
| CommandConfig | 2500 | KillDate (154) | ✅ Implemented | Dynamic kill date |
| CommandConfig | 2500 | WorkingHours (155) | ✅ Implemented | Bitmask time window |
| CommandConfig | 2500 | SpfThread/Verbose/SleepTech/Coffee/Memory/Inject | 🔶 Windows-only stub | Returns error for all Windows-specific config keys |

### Pivot & Lateral Movement

| Command | ID | Sub-cmd | Status | Notes |
|---------|---:|---------|--------|-------|
| CommandPivot | 2520 | List (1) | ✅ Implemented | Enumerate active pivot connections |
| CommandPivot | 2520 | SmbConnect (10) | ✅ Implemented | Unix domain sockets (replaces Windows named pipes) |
| CommandPivot | 2520 | SmbDisconnect (11) | ✅ Implemented | Close pivot to agent |
| CommandPivot | 2520 | SmbCommand (12) | ✅ Implemented | Forward raw Demon packets through pivot |

### Socket & Port Forwarding

| Command | ID | Sub-cmd | Status | Notes |
|---------|---:|---------|--------|-------|
| CommandSocket | 2540 | RPortFwd Add (0) | ✅ Implemented | Bind listener, relay through C2 or forward locally |
| CommandSocket | 2540 | RPortFwd List (2) | ✅ Implemented | List active port forwards |
| CommandSocket | 2540 | RPortFwd Remove (4) | ✅ Implemented | Remove specific listener |
| CommandSocket | 2540 | RPortFwd Clear (3) | ✅ Implemented | Clear all listeners |
| CommandSocket | 2540 | SOCKS5 Add (5) | ✅ Implemented | Full SOCKS5 proxy (no-auth) |
| CommandSocket | 2540 | SOCKS5 List (6) | ✅ Implemented | List proxies |
| CommandSocket | 2540 | SOCKS5 Remove (7) | ✅ Implemented | Remove proxy |
| CommandSocket | 2540 | SOCKS5 Clear (8) | ✅ Implemented | Clear all |
| CommandSocket | 2540 | Open/Read/Write/Close/Connect | ✅ Implemented | Full socket lifecycle |

### Kerberos

| Command | ID | Status | Notes |
|---------|---:|--------|-------|
| CommandKerberos | 2550 | ❌ Missing | Not dispatched. Demon uses Windows LSA for LUID/klist/purge/PTT. Linux has Kerberos via krb5 (ccache, keytab) which is useful on AD-joined hosts. Should be added to Windows-only stubs or given a Linux implementation. |

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

### Phantom-Only Extensions (not in Demon)

| Command | ID | Status | Notes |
|---------|---:|--------|-------|
| CommandPersist | 3000 | ✅ Implemented | Linux persistence: cron, systemd user unit, shell RC (install/remove) |
| CommandHarvest | 2580 | ✅ Implemented | Linux credential harvesting: SSH keys, browser cookies/passwords, AWS/Docker/K8s creds, /etc/shadow, .netrc |

### Callback-Only Commands (no dispatch needed)

| Command | ID | Notes |
|---------|---:|-------|
| DemonInfo | 89 | Informational callback — not a task |
| CommandOutput | 90 | Output callback |
| CommandError | 91 | Error callback |
| BeaconOutput | 94 | Legacy Beacon output |

---

## Gap Summary

### Issues to File

1. **CommandProcPpidSpoof (27)** — Not handled in dispatch. PPID spoofing is a Windows
   `CreateProcess` concept with no direct Linux equivalent. Should be added to the
   Windows-only stub list so the teamserver gets a clean "not supported" error instead
   of a generic "not implemented" message.

2. **CommandKerberos (2550)** — Not handled in dispatch. While Demon's implementation
   uses Windows LSA, Linux Kerberos operations (ccache enumeration, ticket purge, keytab
   operations) are valuable on AD-joined Linux hosts. Two options:
   - Minimal: add to Windows-only stub list
   - Full: implement Linux krb5 operations (klist via ccache, purge, keytab injection)

---

## Protocol & Transport Verification

| Aspect | Status | Notes |
|--------|--------|-------|
| 0xDEADBEEF magic | ✅ | Correct |
| AES-256-CTR encryption | ✅ | Per-agent session keys |
| Monotonic CTR mode | ✅ | Shared offset across packets |
| HKDF session key derivation | ✅ | From listener init secret |
| HTTP(S) transport | ✅ | reqwest + rustls, optional cert pinning |
| Chunked file transfer | ✅ | 512 KiB chunks with file ID tracking |
| Callback wire format | ✅ | Binary-compatible with Demon |
