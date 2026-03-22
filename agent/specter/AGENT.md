# Specter (Rust Agent)

Ground-up Rust rewrite of the Demon agent. Targets full protocol and feature
parity with the original C/ASM Demon, while leveraging Rust for safety and
modern tooling.

## Status

Skeleton — not yet functional.

The current implementation follows the Red Cell teamserver's progressive
AES-CTR model: after the init ACK, Specter advances its send/receive counter
offsets for later packets instead of resetting CTR to zero per packet.

This differs from the frozen Havoc Demon implementation in `agent/demon/`,
which reinitializes AES-CTR for each packet. As a result, Specter currently
matches the Red Cell server behavior more closely than the legacy Demon binary
does.

## Build

```bash
cargo build -p specter
```
