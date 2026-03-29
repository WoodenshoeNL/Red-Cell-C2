# Archon Agent

Archon is a C/ASM Windows implant that is a fork of the Havoc Demon agent.
It is protocol-compatible with Demon: same magic bytes (0xDEADBEEF), same
AES-256-CTR handshake, same command set.  Archon diverges from Demon
intentionally in later phases; the initial state is a byte-for-byte build
equivalent.

## Directory Layout

```
src/asm/       — Assembly stubs (return-address stack spoofing)
src/core/      — Core C2 logic (transport, commands, tokens, pivots, …)
src/crypt/     — AES encryption helpers
src/inject/    — Injection utilities
src/main/      — PE/DLL/service entry points
include/       — Shared headers
scripts/       — Build helper scripts
CMakeLists.txt — CLion/CMake project file (IDE reference only, do not use to build)
makefile       — Invoke `make` here to build
```

## Toolchain Requirements

| Tool | Minimum version | Purpose |
|------|----------------|---------|
| `x86_64-w64-mingw32-gcc` | 10.0 | C cross-compiler (Windows x64) |
| `i686-w64-mingw32-gcc` | 10.0 | C cross-compiler (Windows x86) |
| `nasm` | 2.14 | Assembles the ASM stubs |

On Ubuntu/Debian:

```bash
sudo apt-get install mingw-w64 nasm
```

## Build

```bash
cd agent/archon
make
```

The `makefile` mirrors the one in `agent/demon/`.  The compiled output lands in
`Build/` with the name `Archon` (instead of `Demon`).

The teamserver uses the same build pipeline for Archon as it does for Demon —
it cross-compiles the source tree with the embedded C2 configuration injected
as preprocessor defines.  You do not normally build Archon by hand; the
teamserver builds it on demand when an operator requests an Archon payload.

## Protocol Compatibility

Archon checks in to the teamserver identically to Demon:

- Magic header: `0xDEADBEEF`
- Encryption: AES-256-CTR with per-agent session keys
- Command IDs: identical to Demon

Any teamserver that speaks the Demon protocol will accept an Archon agent
without modification.

## CMakeLists.txt Note

`CMakeLists.txt` is an IDE project file for CLion only.  It is **not** the
authoritative build system.  Use `make` to build.
