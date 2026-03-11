# Red Cell C2

A Rust rewrite of the [Havoc C2 framework](https://github.com/HavocFramework/Havoc) — teamserver and operator client. The original Demon agent (C/ASM) is preserved as-is; full binary protocol compatibility is maintained.

> **Status**: Planning complete, implementation in progress. See [issue tracker](#issue-tracker) for current state.

---

## Overview

| Component | Language | Status |
|---|---|---|
| **Teamserver** | Rust (Axum + Tokio) | In development |
| **Operator client** | Rust (egui) | In development |
| **Demon agent** | C + x86/x64 ASM | Unchanged — `./src/Havoc` |

The original Havoc source lives at `./src/Havoc` and serves as the reference implementation. It is not modified.

---

## Architecture

| Concern | Decision |
|---|---|
| Repo structure | Cargo workspace: `crates/teamserver`, `crates/client`, `crates/common` |
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

### First time on a new machine

```bash
git clone git@github.com:WoodenshoeNL/Red-Cell-C2.git
cd Red-Cell-C2
./setup.sh
```

`setup.sh` checks required tools, enforces the correct `br` issue prefix, and builds the local beads DB from the committed JSONL.

### Switching between machines during the day

Run `setup.sh` at the start of every session — it is idempotent and safe to run repeatedly:

```bash
./setup.sh
```

It will:
1. Check required tools
2. `git pull --ff-only` to fetch work committed on another VM (skips if you have uncommitted changes)
3. Enforce `br issue_prefix = red-cell-c2`
4. Rebuild the beads DB from the updated JSONL
5. Warn about any `in_progress` tasks left running on another VM
6. Print the agent loop commands for this machine

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
| `./claude_loop.sh` | Claude | QA review | Every 15 min |
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

Runs every 15 minutes. Reviews commits since the last QA checkpoint, checks build health, verifies architecture compliance, and creates beads issues for any problems found. Does not write code.

```bash
./claude_loop.sh
```

Log: `logs/claude_qa.log`

### Architecture review loop (`claude_arch_loop.sh`)

Runs every 45–90 minutes (randomised interval). Reads the **entire codebase from scratch** — not just recent commits. Looks for security issues, architectural drift, missing test coverage, protocol correctness, and stubbed-out code that silently does nothing. Files beads issues for all findings. Does not write code.

```bash
# Run forever
./claude_arch_loop.sh

# Run exactly N reviews then exit
./claude_arch_loop.sh 3
```

Logs: `logs/claude_arch.log` (loop control), `logs/arch_review_YYYYMMDD_HHMMSS.log` (per run)

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

### Prompt files

Each loop has a corresponding prompt file that controls agent behaviour:

| Prompt | Used by |
|---|---|
| `CODEX_PROMPT.md` | `codex_loop.sh` |
| `CLAUDE_DEV_PROMPT.md` | `claude_dev_loop.sh` |
| `CURSOR_PROMPT.md` | `cursor_loop.sh` |
| `CLAUDE_PROMPT.md` | `claude_loop.sh` |
| `CLAUDE_ARCH_PROMPT.md` | `claude_arch_loop.sh` |

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
├── crates/                  # Rust workspace (created during implementation)
│   ├── common/              # Shared types: protocol, crypto, config
│   ├── teamserver/          # Axum-based C2 server (red-cell binary)
│   └── client/              # egui operator client (red-cell-client binary)
├── src/
│   └── Havoc/               # Original Havoc source — reference only, do not modify
├── profiles/                # HCL/YAOTL profile examples (from Havoc)
├── logs/                    # Agent loop log output (gitignored)
├── .beads/                  # Issue tracker database
│   └── issues.jsonl         # Issues — committed to git for sync
├── AGENTS.md                # Agent instructions and architecture decisions
├── CLAUDE_PROMPT.md         # QA reviewer prompt
├── CLAUDE_DEV_PROMPT.md     # Claude developer prompt
├── CLAUDE_ARCH_PROMPT.md    # Architecture reviewer prompt
├── CODEX_PROMPT.md          # Codex developer prompt
├── CURSOR_PROMPT.md         # Cursor Agent developer prompt
├── claude_loop.sh           # QA review loop (every 10 min)
├── claude_dev_loop.sh       # Claude development loop
├── claude_arch_loop.sh      # Architecture review loop (every 45–90 min)
├── codex_loop.sh            # Codex development loop
├── cursor_loop.sh           # Cursor Agent development loop
└── setup.sh                 # Session start / machine onboarding script
```

---

## Status

This is a personal hobby project and is not open for contributions. Feel free to follow along or use it as inspiration, but please do not open pull requests.
