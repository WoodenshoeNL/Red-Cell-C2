# Agent Compatibility Notes

This directory contains three agent variants with different compatibility
constraints:

| Agent | Status | AES-CTR packet behavior | Compatibility with current Red Cell teamserver |
|---|---|---|---|
| `demon/` | Frozen upstream Havoc copy | Resets CTR to block 0 for every packet | Incompatible after `DEMON_INIT` |
| `archon/` | Mutable C/ASM fork | Currently inherits Demon per-packet CTR reset | Incompatible after `DEMON_INIT` unless its transport/crypto path changes |
| `specter/` | Rust rewrite | Tracks progressive CTR offsets across the init ACK and later callbacks | Compatible with the current Red Cell teamserver design |

## Why legacy Demon/Archon break

The current Red Cell teamserver/common implementation stores a progressive
AES-256-CTR block offset per agent. After `DEMON_INIT`, the init ACK consumes
one 16-byte CTR block, so the server expects the next agent callback to start at
CTR block 1.

The original Havoc Demon packet builder reinitializes AES-CTR for each packet,
which restarts the stream at block 0 every time. Red Cell then decrypts the next
callback with the wrong counter value and the session breaks.

Reference points in this repository:

- `agent/demon/src/core/Package.c`: callback encryption reinitializes AES with
  the base IV before each packet.
- `agent/archon/src/core/Package.c`: same per-packet CTR reset behavior today.
- `agent/specter/src/agent.rs`: tracks `send_ctr_offset`/`recv_ctr_offset`
  progressively after the init ACK.

## Current expectation

Until the teamserver/common layers gain a legacy compatibility mode, use
`agent/specter/` when testing against the current Red Cell server
implementation.
