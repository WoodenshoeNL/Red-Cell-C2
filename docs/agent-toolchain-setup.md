# Agent Build Toolchain Setup

Each agent variant has its own build toolchain requirements. This document
covers what is needed to build each agent and how to install the prerequisites.

The quick path:

```bash
sudo ./install.sh --agents   # installs Rust cross-compile targets
sudo ./install.sh --teamserver   # installs nasm + MinGW (needed for Archon)
```

---

## Agent overview

| Agent   | Language | Target OS     | Toolchain needed |
|---------|----------|---------------|------------------|
| Demon   | C / ASM  | Windows x64   | nasm, MinGW-w64 cross-compiler (installed by `--teamserver`) |
| Archon  | C / ASM  | Windows x64   | nasm, MinGW-w64 cross-compiler (same as Demon) |
| Phantom | Rust     | Linux (musl)  | Rust + `x86_64-unknown-linux-musl` / `aarch64-unknown-linux-musl` targets |
| Specter | Rust     | Windows x64   | Rust + `x86_64-pc-windows-gnu` target + MinGW-w64 linker |

---

## Demon / Archon (C / ASM — Windows)

Both Demon and Archon are built with the same toolchain.

### Requirements

- **nasm** ≥ 2.15 — assembler
- **MinGW-w64 cross-compilers** — `x86_64-w64-mingw32-gcc` and `i686-w64-mingw32-gcc`

### Install

These are installed automatically by `install.sh --teamserver`:

```bash
sudo ./install.sh --teamserver
```

The MinGW compilers are downloaded from [musl.cc](https://musl.cc/) into
`data/x86_64-w64-mingw32-cross/` and `data/i686-w64-mingw32-cross/`.

### Build Archon

```bash
cd archon
make          # builds archon.exe (x64) and archon32.exe (x86)
make clean    # remove build artefacts
```

---

## Phantom (Rust — Linux, musl)

Phantom targets hardened Linux environments and compiles to statically-linked
musl binaries for maximum portability.

### Requirements

- **Rust** (stable toolchain)
- Rust targets: `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`
- **musl-gcc** wrapper: `musl-tools` package on Ubuntu

### Install

```bash
sudo ./install.sh --agents
```

Or manually:

```bash
# Install musl libc wrapper
sudo apt-get install -y musl-tools

# Add Rust targets
rustup target add x86_64-unknown-linux-musl
rustup target add aarch64-unknown-linux-musl
```

For aarch64 cross-compilation you also need the cross-linker:

```bash
sudo apt-get install -y gcc-aarch64-linux-gnu
```

### Build Phantom

```bash
cd phantom
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target aarch64-unknown-linux-musl
```

---

## Specter (Rust — Windows, MinGW)

Specter targets Windows and links against the MinGW runtime already installed
for the Demon/Archon toolchain.

### Requirements

- **Rust** (stable toolchain)
- Rust target: `x86_64-pc-windows-gnu`
- **MinGW-w64 linker** — `x86_64-w64-mingw32-gcc` (installed by `--teamserver`)

### Install

```bash
sudo ./install.sh --agents   # adds the Rust target
# MinGW linker is installed by --teamserver (already present if you ran that)
```

Or manually:

```bash
rustup target add x86_64-pc-windows-gnu
```

Then configure `.cargo/config.toml` to point at the musl.cc linker:

```toml
[target.x86_64-pc-windows-gnu]
linker = "data/x86_64-w64-mingw32-cross/bin/x86_64-w64-mingw32-gcc"
```

This is already configured in `specter/.cargo/config.toml`.

### Build Specter

```bash
cd specter
cargo build --release --target x86_64-pc-windows-gnu
```

---

## Verifying your toolchains

```bash
# nasm
nasm --version          # NASM version 2.15.xx or later

# MinGW
data/x86_64-w64-mingw32-cross/bin/x86_64-w64-mingw32-gcc --version

# musl-gcc
musl-gcc --version

# Rust targets
rustup target list --installed | grep -E 'musl|windows-gnu'
```

---

## CI note

The test harness does **not** build agents — it expects pre-built binaries in
`target/` (workspace) or agent `target/` subdirectories. Run `cargo build` or
`make` in each agent directory before launching a test run that deploys agents.
