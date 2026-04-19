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
| **Kerberos (ask TGT)**     | ✅            | ☐              | —                    | ✅                 |
| **Kerberos (ask ST)**      | ✅            | ☐              | —                    | ✅                 |
| **Pivot dispatch**         | ✅            | ☐              | ✅                   | ✅                 |
| **Token impersonation**    | ✅            | ☐              | —                    | ✅                 |
| **Memory injection**       | ✅            | ☐              | ✅                   | ✅                 |
| **Sleep / jitter control** | ✅            | ☐              | ✅                   | ✅                 |
| **Self-destruct / exit**   | ✅            | ☐              | ✅                   | ✅                 |
| **Net enumeration**        | ✅            | ☐              | ✅                   | ✅                 |
| **SOCKS / socket relay**   | ✅            | ☐              | ✅                   | ✅                 |
| **In-memory file staging** | ✅            | ☐              | ✅                   | ✅                 |

Notes:
- Phantom **Screenshot** uses best-effort Linux tooling (`import`, `scrot`, `gnome-screenshot`).

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
