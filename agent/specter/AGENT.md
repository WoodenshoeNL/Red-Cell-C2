# Specter (Rust Agent)

Ground-up Rust rewrite of the Demon agent. Targets full protocol and feature
parity with the original C/ASM Demon, while leveraging Rust for safety and
modern tooling.

## Status

~100% feature-complete (Demon protocol parity). Do not re-implement existing
functionality — read this file and the source before adding new code.
See `GAP_ANALYSIS.md` for the full command-by-command inventory.

### What is implemented

- **Protocol** (`protocol.rs`): full Demon binary framing — 0xDEADBEEF magic,
  AES-256-CTR with progressive counter offsets (see note below), init handshake.
- **Transport** (`transport.rs`): HTTP/HTTPS polling transport.
- **Dispatch** (`dispatch.rs`): ~48 command handlers covering:
  - `COMMAND_SLEEP` — jitter + kill-date enforcement
  - `COMMAND_FS` — pwd, cd, dir, download (chunked), upload
  - `COMMAND_MEMFILE` — in-memory file staging
  - `COMMAND_TRANSFER` — list/stop/resume/remove in-flight downloads
  - `COMMAND_PROC` — create, modules, grep, memory scan, kill
  - `COMMAND_PROC_LIST` — full process snapshot
  - `COMMAND_PROC_PPID_SPOOF` — parent-PID spoofing
  - `COMMAND_NET` — domain, logons, sessions, name-list, shares, groups,
    users, Computer (NetServerEnum), DcList (NetServerEnum)
  - `COMMAND_TOKEN` — impersonate, steal, list, privs, make, getuid, revert,
    remove, clear, find
  - `COMMAND_KERBEROS` — luid, klist, purge, ptt
  - `COMMAND_CONFIG` — all config keys (u32, bool, addr, spawn, kill-date)
  - `COMMAND_INJECT_SHELLCODE` / `COMMAND_INJECT_DLL` / `COMMAND_SPAWN_DLL`
  - `COMMAND_INLINE_EXECUTE` — BOF loader (`coffeeldr.rs`)
  - `COMMAND_JOB` — async job tracking
  - `COMMAND_PS_IMPORT` / `COMMAND_ASSEMBLY_INLINE_EXECUTE` /
    `COMMAND_ASSEMBLY_LIST_VERSIONS` — .NET / PowerShell execution
  - `COMMAND_SCREENSHOT`
  - `COMMAND_PACKAGE_DROPPED`
  - `COMMAND_EXIT`
- **Sleep obfuscation** (`sleep_obf.rs`): Cronos-style timer-callback
  obfuscation (technique 1); plain sleep fallback (technique 0).
- **Token vault** (`token.rs`): stolen-token storage and impersonation.
- **Kerberos** (`kerberos.rs`): ticket enumeration, purge, pass-the-ticket.
- **Pivot / socket** (`pivot.rs`, `socket.rs`): SMB named-pipe and TCP pivot
  channels.
- **BOF / .NET loaders** (`coffeeldr.rs`, `dotnet.rs`): in-process execution.
- **Syscall layer** (`syscall.rs`): indirect syscall stubs.
- **Bypass / spoof** (`bypass.rs`, `spoof.rs`): ETW/AMSI bypass, stack spoof.

### Known gaps (open issues)

None — all previously identified gaps have been resolved. See `GAP_ANALYSIS.md`
for the full audit (red-cell-c2-lmgs5).

### AES-CTR model note

Specter uses a **progressive** AES-CTR model: after the init ACK the
send/receive counter offsets advance across packets rather than resetting to
zero per packet.  This differs from the frozen Havoc Demon in `agent/demon/`,
which reinitializes AES-CTR for each packet.  The Red Cell teamserver
(`teamserver/`) is implemented to match Specter's progressive model.

## Build

```bash
cargo build -p specter
```
