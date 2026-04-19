# Agent Capability Matrix

This document tracks which commands each agent variant supports. Update it as
agent implementations progress.

Status legend: ✅ implemented · 🔨 in progress · ☐ planned · — not applicable

---

## Command support by agent

| Command / Feature          | Demon (C/ASM) | Archon (C/ASM) | Phantom (Rust/Linux) | Specter (Rust/Win) |
|----------------------------|:-------------:|:--------------:|:--------------------:|:------------------:|
| **Checkin / beacon**       | ✅            | ☐              | ✅                   | ✅                 |
| **Shell exec**             | ✅            | ☐              | ✅                   | ✅                 |
| **File upload**            | ✅            | ☐              | ✅                   | ✅                 |
| **File download**          | ✅            | ☐              | ✅                   | ✅                 |
| **Directory listing**      | ✅            | ☐              | ✅                   | ✅                 |
| **Process list**           | ✅            | ☐              | ✅                   | ✅                 |
| **Process kill**           | ✅            | ☐              | ✅                   | ✅                 |
| **Screenshot**             | ✅            | ☐              | ✅                   | ✅                 |
| **Kerberos (ask TGT)**     | ✅            | ☐              | — ¹                  | ✅                 |
| **Kerberos (ask ST)**      | ✅            | ☐              | — ¹                  | ✅                 |
| **Kerberos klist**         | —             | —              | ✅                   | —                  |
| **Kerberos purge**         | —             | —              | ✅                   | —                  |
| **Kerberos PTT**           | —             | —              | ✅                   | —                  |
| **Pivot dispatch**         | ✅            | ☐              | ✅                   | ✅                 |
| **Token impersonation**    | ✅            | ☐              | —                    | ✅                 |
| **Memory injection**       | ✅            | ☐              | ✅                   | ✅                 |
| **Sleep / jitter control** | ✅            | ☐              | ✅                   | ✅                 |
| **Self-destruct / exit**   | ✅            | ☐              | ✅                   | ✅                 |
| **Net enumeration**        | ✅            | ☐              | ✅                   | ✅                 |
| **SOCKS / socket relay**   | ✅            | ☐              | ✅                   | ✅                 |
| **In-memory file staging** | ✅            | ☐              | ✅                   | ✅                 |
| **Persist** ²              | —             | —              | ✅                   | —                  |
| **Harvest** ³              | —             | —              | ✅                   | —                  |

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
| Magic bytes (`0xDEADBEEF`)        | ✅    | ☐      | ✅      | ✅      |
| AES-256-CTR encryption            | ✅    | ☐      | ✅      | ✅      |
| Per-agent key derivation          | ✅    | ☐      | ✅      | ✅      |
| DEMON_INIT (cmd 99) handshake     | ✅    | ☐      | ✅      | ✅      |
| CHECKIN (cmd 100) registration    | ✅    | ☐      | ✅      | ✅      |
| GET_JOB (cmd 1) poll loop         | ✅    | ☐      | ✅      | ✅      |

See `teamserver/src/protocol/` for the full specification and
`teamserver/tests/` for integration tests that agents must pass.

---

## Platform targets

| Agent   | Windows x64 | Windows x86 | Linux x64 | Linux aarch64 |
|---------|:-----------:|:-----------:|:---------:|:-------------:|
| Demon   | ✅          | ✅          | —         | —             |
| Archon  | ☐           | ☐           | —         | —             |
| Phantom | —           | —           | ✅        | ☐             |
| Specter | ✅          | ☐           | —         | —             |

---

*Last updated: 2026-04-19. Update this file as agent work progresses.*
