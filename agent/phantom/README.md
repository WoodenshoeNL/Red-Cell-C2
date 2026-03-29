# Phantom — Linux Rust Agent

Phantom is a Linux implant for Red Cell C2. It implements the Havoc Demon binary protocol
over HTTP, allowing it to check in to a running Red Cell teamserver and receive tasks.

## Protocol compatibility

Phantom uses the same Demon wire framing as the original Havoc agent:

- `0xDEADBEEF` magic value in every packet header
- AES-256-CTR encryption with per-agent session keys
- `DEMON_INIT` (command ID 99) registration handshake
- `COMMAND_GET_JOB` (1) polling loop
- `COMMAND_CHECKIN` (100) metadata report
- Monotonic CTR mode — the counter advances across packets rather than resetting

## Build

### Prerequisites

```bash
rustup target add x86_64-unknown-linux-gnu
```

### Debug build

```bash
cargo build -p phantom
```

### Release build (statically linked, x86_64 Linux)

```bash
cargo build --release -p phantom --target x86_64-unknown-linux-gnu
```

The resulting binary is at:

```
target/x86_64-unknown-linux-gnu/release/phantom
```

### Cross-compile from macOS / Windows

Install a Linux cross-linker (`aarch64-linux-gnu-gcc` or equivalent) and set the
`CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER` environment variable before building.

## Usage

```
phantom [OPTIONS]

Options:
  --server   <URL>        Teamserver callback URL  [env: PHANTOM_SERVER]
  --sleep    <ms>         Callback interval in milliseconds  [env: PHANTOM_SLEEP, default: 5000]
  --jitter   <pct>        Sleep jitter percentage 0-100  [env: PHANTOM_JITTER, default: 0]
  --kill-date <timestamp> Unix timestamp after which the agent exits  [env: PHANTOM_KILL_DATE]
  --cert-pin <PEM>        PEM-encoded server certificate for TLS pinning  [env: PHANTOM_CERT_PIN]
  -h, --help              Print this help message
```

Environment variables take precedence over defaults; CLI flags take precedence over
environment variables.

### Minimal example

```bash
./phantom --server http://192.168.1.10:40056/havoc
```

The agent registers once (`DEMON_INIT`), then polls for jobs at the configured interval.
On first checkin the agent will appear in the Red Cell client agent list.

## Architecture

```
main.rs           entry point — logging init, config load, run loop
config.rs         PhantomConfig — CLI + env var resolution
agent.rs          PhantomAgent — registration → poll → dispatch loop
protocol.rs       Demon packet builders and response parsers
transport.rs      HTTP transport backed by reqwest (rustls, optional cert pinning)
command.rs        task dispatch handlers (exec, exit, fs, process, network, …)
parser.rs         little-endian task payload parser helpers
error.rs          PhantomError type
```

## Tests

```bash
# unit and integration tests (no network required)
cargo test -p phantom

# end-to-end tests against a live teamserver (requires --features integration)
cargo test -p phantom --features integration
```
