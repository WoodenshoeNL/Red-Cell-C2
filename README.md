# Red Cell C2

A Rust rewrite of the [Havoc C2 framework](https://github.com/HavocFramework/Havoc) — teamserver and operator client. The original Demon agent (C/ASM) is preserved as-is; full binary protocol compatibility is maintained.

> **Status**: Planning complete, implementation in progress. See [issue tracker](#issue-tracker) for current state.

> **This is a vibe-coded hobby project.** The entire codebase is written by AI agent
> loops (Claude, Codex, Cursor) with human direction. It is not production-grade
> software — use it for learning, experimentation, and authorized security testing
> only.

## Disclaimer

This software is provided for **authorized security testing, research, and educational
purposes only**. It is intended for use by security professionals in controlled
environments with proper authorization.

- Do not use this tool against systems you do not own or have explicit written
  permission to test.
- The authors assume no liability for misuse or damage caused by this software.
- Users are solely responsible for compliance with all applicable local, state,
  national, and international laws.

By using this software you agree to these terms.

---

## Overview

| Component | Language | Status |
|---|---|---|
| **Teamserver** | Rust (Axum + Tokio) | In development |
| **Operator client** | Rust (egui) | In development |
| **Demon agent** | C + x86/x64 ASM | Unchanged — `./agent/demon` |

See [HAVOC_ATTRIBUTION.md](HAVOC_ATTRIBUTION.md) for Havoc-derived files and licensing.

---

## Architecture

| Concern | Decision |
|---|---|
| Repo structure | Cargo workspace: `./teamserver`, `./client`, `./common` at repo root |
| Binaries | `red-cell` (teamserver), `red-cell-client` (operator GUI) |
| Rust edition | 2024, latest stable |
| Teamserver framework | Axum |
| Database | SQLite via sqlx |
| Config format | HCL/YAOTL (same `.yaotl` profile format as Havoc) |
| Operator protocol | JSON over WebSocket |
| Agent protocol | Demon binary protocol — unchanged (0xDEADBEEF, AES-256-CTR) |
| Client UI | egui |
| Plugin system | Python via PyO3 |
| New features | RBAC, REST API, DNS listener, structured audit logging |
| Testing | Unit + integration (mock Demon agent) + E2E |

---

## Requirements

### Development tools

- **Rust** (2024 edition, latest stable) — [install](https://rustup.rs)
- **Python 3.12** shared library — required for PyO3 embedding. Run `sudo ./install.sh`
  to set up automatically, or install `libpython3.12-dev` manually.
  See [docs/pyo3-embedding.md](docs/pyo3-embedding.md) for details.
- **br** (beads_rust issue tracker):
  ```bash
  curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/beads_rust/main/install.sh" | bash
  ```

### Agent loop tools (optional, for autonomous development)

- **Claude Code CLI** — for the Claude dev and QA loops
- **Codex CLI** — for the Codex dev loop
- **Cursor Agent CLI** (`agent`) — for the Cursor dev loop

---

## Getting Started

## CI Policy

This repository does not use GitHub Actions or any other hosted CI.
Builds, tests, linting, and end-to-end validation must run on the VM where the
repo is checked out.

Use the local dev/QA/arch loops and the VM-hosted test harness for validation.
If a GitHub Actions workflow or other external CI config is added, remove it
instead of extending it.

### First time on a new machine

```bash
git clone git@github.com:WoodenshoeNL/Red-Cell-C2.git
cd Red-Cell-C2
./setup.sh
```

`setup.sh` checks required tools, enforces the correct `br` issue prefix, and builds the local beads DB from the committed JSONL.

On the first run it also downloads the musl.cc MinGW-w64 cross-compilers into `data/` so Havoc-compatible payload builds can use the default profile paths.

### Switching between machines during the day

Run `setup.sh` at the start of every session — it is idempotent and safe to run repeatedly:

```bash
./setup.sh
```

It will:
1. Check required tools
2. `git pull --ff-only` to fetch work committed on another VM (skips if you have uncommitted changes)
3. Enforce `br issue_prefix = red-cell-c2`
4. Download and extract the musl.cc MinGW-w64 toolchains into `data/` when they are missing
5. Rebuild the beads DB from the updated JSONL
6. Warn about any `in_progress` tasks left running on another VM
7. Print the agent loop commands for this machine

### Payload toolchain bootstrap

If you only need the payload build toolchains without the rest of the session bootstrap, run:

```bash
./scripts/install-toolchains.sh
```

The installer is idempotent. It ensures these default Havoc-compatible compiler paths exist:

- `data/x86_64-w64-mingw32-cross/bin/x86_64-w64-mingw32-gcc`
- `data/i686-w64-mingw32-cross/bin/i686-w64-mingw32-gcc`

### Build (once crates exist)

```bash
cargo build --workspace
cargo test --workspace
```

---

## Agent Loop System

This project uses autonomous AI agent loops for development. Three loops are available — run them in any combination depending on what tools you have available.

### Loops at a glance

| Script | Agent | Role | Cadence |
|---|---|---|---|
| `./codex_loop.sh` | Codex | Development | Continuous |
| `./claude_dev_loop.sh` | Claude | Development | Continuous |
| `./cursor_loop.sh` | Cursor Agent | Development | Continuous |
| `./claude_loop.sh` | Claude | QA review | Every 20 min |
| `./claude_arch_loop.sh` | Claude | Architecture review | Every 45–90 min |

### Development loops (`codex_loop.sh`, `claude_dev_loop.sh`, `cursor_loop.sh`)

Pick the highest-priority unblocked task from the issue tracker, implement it, run tests, commit, push, and close the issue — then repeat.

```bash
# Run forever
./codex_loop.sh
./claude_dev_loop.sh
./cursor_loop.sh

# Run exactly N loops then exit
./codex_loop.sh 5
./claude_dev_loop.sh 3
./cursor_loop.sh 3
```

Logs: `logs/codex_dev.log`, `logs/claude_dev.log`, `logs/cursor_dev.log`

### QA review loop (`claude_loop.sh`)

Runs every 20 minutes. Reviews commits since the last QA checkpoint, checks build health, verifies architecture compliance, and creates beads issues for any problems found. Does not write code.

```bash
./claude_loop.sh
```

Log: `logs/claude_qa.log`

### QA review loop (`codex_qa_loop.sh`)

Runs every 20 minutes. Same QA workflow as the Claude loop, but executed by Codex.
Reviews commits since the last QA checkpoint, checks build health, verifies architecture
compliance, and creates beads issues for any problems found. Does not write code.

```bash
./codex_qa_loop.sh
```

Log: `logs/codex_qa.log`

### Architecture review loop (`claude_arch_loop.sh`)

Runs every 45–90 minutes (randomised interval). Reads the **entire codebase from scratch** — not just recent commits. Looks for security issues, architectural drift, missing test coverage, protocol correctness, and stubbed-out code that silently does nothing. Files beads issues for all findings. Does not write code.

```bash
# Run forever
./claude_arch_loop.sh

# Run exactly N reviews then exit
./claude_arch_loop.sh 3
```

Logs: `logs/claude_arch.log` (loop control), `logs/arch_review_YYYYMMDD_HHMMSS.log` (per run)

### Architecture review loop (`codex_arch_loop.sh`)

Runs every 45–90 minutes (randomised interval). Same architecture review workflow as the
Claude loop, but executed by Codex. Reads the entire codebase from scratch, looks for
security issues, architectural drift, missing coverage, protocol correctness problems, and
stubbed-out behavior that silently does nothing.

```bash
# Run forever
./codex_arch_loop.sh

# Run exactly N reviews then exit
./codex_arch_loop.sh 3
```

Logs: `logs/codex_arch.log` (loop control), `logs/codex_arch_review_YYYYMMDD_HHMMSS.log` (per run)

### Stopping a loop

Create a `.stop` file in the repo root. Each loop checks for it before starting the next pass:

```bash
touch .stop          # stop local loops after the current pass
rm .stop             # resume
```

To stop a remote agent (e.g. Codex running in the cloud):

```bash
touch .stop && git add .stop && git commit -m "chore: stop dev loop" && git push
```

### Typical multi-agent setup (single machine)

```bash
./codex_loop.sh &           # Codex doing dev work
./cursor_loop.sh &          # Cursor Agent doing dev work
./claude_loop.sh &          # Claude QA running every 10 min
./claude_arch_loop.sh       # Claude deep architecture review in foreground
```

### Running on multiple VMs in parallel

Both dev loops are safe to run simultaneously across machines. Each loop claims a task by immediately pushing a git commit — if two agents select the same task at the same moment, the one whose push lands second detects the conflict, releases the claim, and picks a different task.

Each agent identifies itself as `<hostname>-claude`, `<hostname>-codex`, or `<hostname>-cursor` in git commit messages and log lines, so it is always clear which machine did what.

**On each VM, start with:**
```bash
./setup.sh          # pull latest, sync DB, check config
```

**Then start loops:**

```bash
# VM 1
./codex_loop.sh &
./claude_dev_loop.sh

# VM 2
./codex_loop.sh &
./claude_dev_loop.sh
```

The QA loop (`claude_loop.sh`) and architecture loop (`claude_arch_loop.sh`) only need to run on one machine.

Codex QA and architecture loops are alternatives to the Claude review loops, not companions.
Run one QA loop and one architecture loop total.

### Prompt files

Each loop has a corresponding prompt file that controls agent behaviour:

| Prompt | Used by |
|---|---|
| `CODEX_PROMPT.md` | `codex_loop.sh` |
| `CLAUDE_DEV_PROMPT.md` | `claude_dev_loop.sh` |
| `CURSOR_PROMPT.md` | `cursor_loop.sh` |
| `CLAUDE_PROMPT.md` | `claude_loop.sh` |
| `CLAUDE_ARCH_PROMPT.md` | `claude_arch_loop.sh` |
| `CODEX_QA_PROMPT.md` | `codex_qa_loop.sh` |
| `CODEX_ARCH_PROMPT.md` | `codex_arch_loop.sh` |

---

## Issue Tracker

This project uses [beads_rust](https://github.com/Dicklesworthstone/beads_rust) (`br`) for issue tracking. Issues are stored in `.beads/issues.jsonl` and synced via git — no external service required.

```bash
br ready                    # show unblocked work
br show <id>                # full issue details
br stats                    # project statistics

br create \
  --title="..." \
  --description="..." \
  --type=task \
  --priority=2              # 0=critical, 1=high, 2=medium, 3=low, 4=backlog

br update <id> --status=in_progress
br close <id> --reason="done"
```

### Syncing across machines

After changes to issues, sync back to git:

```bash
br sync --flush-only
git add .beads/issues.jsonl
git commit -m "chore: sync issues"
git push
```

On another machine, `./setup.sh` pulls and rebuilds the DB in one step.

---

## Project Structure

```
Red-Cell-C2/
├── teamserver/              # Axum-based C2 server (red-cell binary)
├── client/                  # egui operator client (red-cell-client binary)
├── common/                  # Shared types: protocol, crypto, config
├── agent/                   # Agent source: demon/, archon/, phantom/, specter/
├── logs/                    # Agent loop log output (gitignored)
├── .beads/                  # Issue tracker database
│   └── issues.jsonl         # Issues — committed to git for sync
├── AGENTS.md                # Agent instructions and architecture decisions
├── CLAUDE_PROMPT.md         # QA reviewer prompt
├── CLAUDE_DEV_PROMPT.md     # Claude developer prompt
├── CLAUDE_ARCH_PROMPT.md    # Architecture reviewer prompt
├── CODEX_PROMPT.md          # Codex developer prompt
├── CURSOR_PROMPT.md         # Cursor Agent developer prompt
├── claude_loop.sh           # QA review loop (every 20 min)
├── claude_dev_loop.sh       # Claude development loop
├── claude_arch_loop.sh      # Architecture review loop (every 45–90 min)
├── codex_loop.sh            # Codex development loop
├── cursor_loop.sh           # Cursor Agent development loop
└── setup.sh                 # Session start / machine onboarding script
```

---

## Status

This is a vibe-coded personal hobby project — built entirely by AI agent loops with
human direction. It is not open for contributions. Feel free to follow along or use
it as inspiration, but please do not open pull requests.
