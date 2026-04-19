# Agent Capability Matrix

This document tracks which commands each agent variant supports. Update it as
agent implementations progress.

Status legend: ✅ implemented · 🔨 in progress · ☐ planned · — not applicable

---

## Command support by agent

| Command / Feature          | Demon (C/ASM) | Archon (C/ASM) | Phantom (Rust/Linux) | Specter (Rust/Win) |
|----------------------------|:-------------:|:--------------:|:--------------------:|:------------------:|
| **Checkin / beacon**       | ✅            | ✅             | ✅                   | ✅                 |
| **Shell exec**             | ✅            | ✅             | ✅                   | ✅                 |
| **File upload**            | ✅            | ✅             | ✅                   | ✅                 |
| **File download**          | ✅            | ✅             | ✅                   | ✅                 |
| **Directory listing**      | ✅            | ✅             | ✅                   | ✅                 |
| **Process list**           | ✅            | ✅             | ✅                   | ✅                 |
| **Process kill**           | ✅            | ✅             | ✅                   | ✅                 |
| **Screenshot**             | ✅            | ✅             | ✅                   | ✅                 |
| **Kerberos (ask TGT)**     | ✅            | ✅             | — ¹                  | ✅                 |
| **Kerberos (ask ST)**      | ✅            | ✅             | — ¹                  | ✅                 |
| **Kerberos klist**         | —             | —              | ✅                   | —                  |
| **Kerberos purge**         | —             | —              | ✅                   | —                  |
| **Kerberos PTT**           | —             | —              | ✅                   | —                  |
| **Pivot dispatch**         | ✅            | ✅             | ✅                   | ✅                 |
| **Token impersonation**    | ✅            | ✅             | —                    | ✅                 |
| **Memory injection**       | ✅            | ✅             | ✅                   | ✅                 |
| **Sleep / jitter control** | ✅            | ✅             | ✅                   | ✅                 |
| **Self-destruct / exit**   | ✅            | ✅             | ✅                   | ✅                 |
| **Net enumeration**        | ✅            | ✅             | ✅                   | ✅                 |
| **SOCKS / socket relay**   | ✅            | ✅             | ✅                   | ✅                 |
| **In-memory file staging** | ✅            | ✅             | ✅                   | ✅                 |
| **Persist** ²              | —             | —              | ✅                   | —                  |
| **Harvest** ³              | —             | —              | ✅                   | —                  |

### Archon-specific enhancements

| Enhancement                              | Archon | Notes                                          |
|------------------------------------------|:------:|------------------------------------------------|
| **ARC-01: Persistent AMSI/ETW bypass**   | ✅     | Patches AMSI/ETW in-process at init and re-applies after each job |
| **ARC-02: Synthetic call-stack frames**  | ✅     | Spoofs return addresses to look like legitimate call chains |
| **ARC-03: Cronos timer-callback sleep**  | ✅     | Sleep via NtSetTimer2/timer callbacks instead of NtDelayExecution |
| **ARC-04: Heap encryption during sleep** | ✅     | Encrypts heap segments while sleeping to foil memory scanners |
| **ARC-05: Module-stomping loader**       | ✅     | Loads reflective DLL into a legitimate module's memory region |
| **ARC-06: JA3 fingerprint randomization**| ✅     | Randomizes TLS cipher-suite order per connection |
| **ARC-07: PE header erasure**            | ✅     | Zeroes DOS/PE headers in-memory after load |
| **ARC-08: DNS-over-HTTPS fallback**      | ✅     | Falls back to DoH (Cloudflare/Google) when direct DNS is blocked |
| **ARC-09: Thread-pool post-ex execution**| ✅     | Dispatches post-ex jobs via the system thread pool to avoid suspicious thread creation |

Notes:
- Phantom **Screenshot** uses best-effort Linux tooling (`import`, `scrot`, `gnome-screenshot`).
- ¹ Linux has no LSA/TGT-request API. Phantom implements Linux Kerberos via ccache/keytab
  (`klist`, `purge`, `PTT`) rather than Windows-style TGT/ST requests.
- ² Phantom **Persist** supports install/remove via cron, systemd user units, and shell RC files
  (`~/.bashrc`, `~/.zshrc`, etc.).
- ³ Phantom **Harvest** collects SSH private keys, browser cookies/passwords (Chrome, Firefox),
  `/etc/shadow` (when readable), `.netrc`, and git credential cache — without spawning
  subprocesses.

---

## Protocol compliance

All agents must implement the core binary protocol to interoperate with the
teamserver:

| Protocol requirement              | Demon | Archon | Phantom | Specter |
|-----------------------------------|:-----:|:------:|:-------:|:-------:|
| Magic bytes (`0xDEADBEEF`)        | ✅    | ✅     | ✅      | ✅      |
| AES-256-CTR encryption            | ✅    | ✅     | ✅      | ✅      |
| Per-agent key derivation          | ✅    | ✅     | ✅      | ✅      |
| DEMON_INIT (cmd 99) handshake     | ✅    | ✅     | ✅      | ✅      |
| CHECKIN (cmd 100) registration    | ✅    | ✅     | ✅      | ✅      |
| GET_JOB (cmd 1) poll loop         | ✅    | ✅     | ✅      | ✅      |

See `teamserver/src/protocol/` for the full specification and
`teamserver/tests/` for integration tests that agents must pass.

---

## Platform targets

| Agent   | Windows x64 | Windows x86 | Linux x64 | Linux aarch64 |
|---------|:-----------:|:-----------:|:---------:|:-------------:|
| Demon   | ✅          | ✅          | —         | —             |
| Archon  | ✅          | ✅          | —         | —             |
| Phantom | —           | —           | ✅        | ☐             |
| Specter | ✅          | ☐           | —         | —             |

---

*Last updated: 2026-04-19. Update this file as agent work progresses.*
