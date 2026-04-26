# Red Cell C2

A Rust rewrite of the [Havoc C2 framework](https://github.com/HavocFramework/Havoc) —
teamserver, operator GUI client, and AI-agent CLI client. The original Demon agent (C/ASM)
is preserved as-is; full binary protocol compatibility is maintained.

> **This is a vibe-coded hobby project.** The entire codebase is written by AI agent
> loops (Claude, Codex, Cursor) with human direction. It is not production-grade
> software — use it for learning, experimentation, and authorized security testing only.

## Disclaimer

This software is provided for **authorized security testing, research, and educational
purposes only**. It is intended for use by security professionals in controlled
environments with proper authorization.

- Do not use this tool against systems you do not own or have explicit written permission to test.
- The authors assume no liability for misuse or damage caused by this software.
- Users are solely responsible for compliance with all applicable local, state, national,
  and international laws.

By using this software you agree to these terms.

---

## Overview

| Component | Language | Binary | Status |
|---|---|---|---|
| **Teamserver** | Rust (Axum + Tokio) | `red-cell` | In development |
| **Operator client** | Rust (egui) | `red-cell-client` | In development |
| **AI-agent CLI client** | Rust | `red-cell-cli` | In development |
| **Demon agent** | C + x86/x64 ASM | — | Frozen — `./agent/demon` |
| **Archon agent** | C + x86/x64 ASM | — | In development — `./agent/archon` |
| **Phantom agent** | Rust | — | In development — `./agent/phantom` |
| **Specter agent** | Rust | — | In development — `./agent/specter` |

See [HAVOC_ATTRIBUTION.md](HAVOC_ATTRIBUTION.md) for Havoc-derived files and licensing.

---

## Architecture

| Concern | Decision |
|---|---|
| Repo structure | Cargo workspace: `./teamserver`, `./client`, `./client-cli`, `./common` at repo root |
| Binaries | `red-cell` (teamserver), `red-cell-client` (operator GUI), `red-cell-cli` (AI-agent CLI) |
| Rust edition | 2024, latest stable |
| Teamserver framework | Axum + Tokio |
| Database | SQLite via sqlx — runtime `sqlx::query()` with `.bind()` |
| Config format | HCL/YAOTL (same `.yaotl` profile format as Havoc) |
| Operator protocol | JSON over WebSocket |
| Agent protocol | Demon binary protocol — unchanged (0xDEADBEEF magic, AES-256-CTR, per-agent keys) |
| Client UI | egui (pure Rust, immediate-mode) |
| Plugin system | Python via PyO3 (client + teamserver) |
| New features | RBAC, REST API, DNS listener, structured audit logging |
| Agent builds | Demon/Archon: `mingw-w64` + `nasm`; Phantom: Linux Rust; Specter: Windows cross-compiled Rust |
| Testing | Unit + integration + E2E automated harness (`automatic-test/`) + manual test plan (`docs/test-plan.md`) |

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

- **Claude Code CLI** — for Claude dev, QA, arch, quality, coverage, and feature loops
- **Codex CLI** — for Codex dev loops
- **Cursor Agent CLI** (`agent`) — for Cursor dev loops

---

## Getting Started

### CI Policy

This repository does not use GitHub Actions or any other hosted CI.
Builds, tests, linting, and end-to-end validation must run on the VM where the repo is
checked out. If a GitHub Actions workflow is added, remove it instead of extending it.

### First time on a new machine

```bash
git clone git@github.com:WoodenshoeNL/Red-Cell-C2.git
cd Red-Cell-C2
./setup.sh
```

`setup.sh` checks required tools, enforces the correct `br` issue prefix, and builds the
local beads DB from the committed JSONL. On the first run it also downloads the musl.cc
MinGW-w64 cross-compilers into `data/` for Havoc-compatible payload builds.

### Switching between machines

Run `setup.sh` at the start of every session — it is idempotent and safe to run repeatedly:

```bash
./setup.sh
```

It will:
1. Check required tools
2. `git pull --ff-only` to fetch work committed on another VM
3. Enforce `br issue_prefix = red-cell-c2`
4. Download MinGW-w64 toolchains into `data/` when missing
5. Rebuild the beads DB from the updated JSONL
6. Warn about any `in_progress` tasks left running on another VM
7. Print the agent loop commands for this machine

### Build

```bash
cargo build --workspace
cargo test --workspace
```

---

## Agent Loop System

All loops are driven by a single entry point:

```bash
./loop.sh [--service] --agent <agent> --loop <type> [options]
```

`loop.sh` is a thin wrapper around `loop.py`. Without `--service` it runs in the
foreground. With `--service` it launches as a transient systemd user service that survives
terminal close and oomd kill (see [Service mode](#service-mode) below).

### Loop types

| Loop | Role | Default cadence |
|---|---|---|
| `dev` | Claims beads tasks, implements them, then runs a lite QA pass | Continuous |
| `qa` | Reviews recent commits, checks build health, files issues | Every 20 min |
| `arch` | Deep full-codebase review: security, drift, test gaps, stubs | Every 120 min |
| `quality` | Evaluates quality of existing tests | Every 30 min |
| `coverage` | Finds untested public functions | Every 30 min |
| `maintenance` | Disk, git, and process health checks | Every 60 min |
| `feature` | Feature completeness + integration gap analysis per zone | 1 run (default) |

### Agents

| Agent | `--agent` value |
|---|---|
| Claude Code | `claude` |
| Codex | `codex` |
| Cursor | `cursor` |

### Common options

```
--zone ZONE [ZONE ...]   Restrict to one or more zones (see Zone system below)
--iterations N           Max iterations before exit; 0 = run forever
--sleep N                Minutes to sleep between iterations
--jitter N               ±N minutes of random jitter on --sleep
--pre-sleep N            Sleep N minutes before the first run
--model MODEL            Claude model override (claude agent only)
--node-id ID             Override machine identifier used in commit tags
--dev-light              Dev loop only: skip the lite QA pass (original single-call behaviour)
--service                Run as a systemd user service (survives terminal close)
```

### Examples

```bash
# Development
./loop.sh --agent claude --loop dev
./loop.sh --agent claude --loop dev --zone client-cli
./loop.sh --agent codex  --loop dev --zone teamserver
./loop.sh --agent cursor --loop dev --zone client-cli client
./loop.sh --agent claude --loop dev --dev-light          # skip lite QA

# QA and review
./loop.sh --agent claude --loop qa
./loop.sh --agent claude --loop arch
./loop.sh --agent claude --loop arch --zone teamserver
./loop.sh --agent claude --loop quality --zone teamserver
./loop.sh --agent claude --loop coverage --zone common

# Feature completeness review (runs once and reports)
./loop.sh --agent claude --loop feature --zone teamserver client-cli
./loop.sh --agent claude --loop feature --zone teamserver phantom
./loop.sh --agent claude --loop feature --zone teamserver  # single zone

# Maintenance
./loop.sh --loop maintenance

# Run as background service
./loop.sh --service --agent claude --loop dev --zone teamserver
./loop.sh --service --agent claude --loop qa
```

### Loop descriptions

#### `dev` — Development loop

Claims the highest-priority unblocked task from the issue tracker, implements it, commits,
pushes, and closes the issue. After each completed task it runs a **lite QA pass** — a
second, read-only agent call that reviews the code quality of the changes just made and
files follow-up issues. Use `--dev-light` to skip the lite QA and get the original
single-agent-call behaviour.

Logs: `logs/claude_dev.log`, `logs/codex_dev.log`, `logs/cursor_dev.log`

#### `qa` — QA review loop

Runs every 20 minutes. Reviews commits since the last QA checkpoint, runs `cargo check`
and `cargo nextest`, verifies architecture compliance, and files beads issues for any
problems found. Updates `AGENT_SCORECARD.md` with per-agent quality metrics. Does not
write code.

Log: `logs/claude_qa.log`

#### `arch` — Architecture review loop

Runs every 120 minutes. Reads the **entire codebase from scratch** — not just recent
commits. Checks security, protocol correctness, error handling, architectural drift,
test coverage blindspots, oversized files, and unimplemented stubs. Files beads issues
for all findings. Updates `AGENT_SCORECARD.md`. Does not write code.

Logs: `logs/claude_arch.log` + per-run `logs/claude_arch_YYYYMMDD_HHMMSS.log`

#### `quality` — Test quality loop

Reviews the quality of existing tests — are they testing the right things, covering error
paths, and structured correctly? Files issues for weak or missing tests.

Logs: `logs/claude_quality.log` + per-run timestamped log

#### `coverage` — Test coverage loop

Scans for public functions and types that have no test coverage at all. Files issues for
each gap. Complementary to `quality` — `coverage` finds what's missing, `quality` reviews
what's there.

Logs: `logs/claude_coverage.log` + per-run timestamped log

#### `feature` — Feature completeness loop

Runs once by default (`--iterations 1`). Analyses one or more zones against the project
spec (AGENTS.md) and beads issues to answer: *what was planned, what exists, and what's
missing?* When multiple zones are given it also analyses integration gaps between them —
interface contracts, missing glue, end-to-end flow breaks. Can flag problems with the spec
or roadmap itself for human review. Files actionable beads issues for all gaps. Does not
write code or run tests.

Logs: `logs/claude_feature.log` + per-run timestamped log

#### `maintenance` — Maintenance loop

Runs every 60 minutes. Checks disk space, stale cargo processes, old git stashes, and
orphaned worktrees. Cleans up build artifacts. Does not write code or file issues.

Log: `logs/maintenance.log`

### Service mode

With `--service`, `loop.sh` launches `loop.py` as a transient systemd user service. This
protects the loop from being killed when the terminal closes or when systemd-oomd reclaims
memory under the terminal's cgroup.

```bash
# Start
./loop.sh --service --agent claude --loop dev --zone teamserver

# Monitor
journalctl --user -u loop-claude-dev-teamserver -f

# Stop
systemctl --user stop loop-claude-dev-teamserver

# List running loops
systemctl --user list-units 'loop-*.service'
```

### Zone system

Loops can be scoped to one or more zones so multiple agents can work in parallel without
file conflicts. Each zone maps to a workspace crate or directory.

| Zone | Paths |
|---|---|
| `teamserver` | `teamserver/` |
| `client` | `client/` |
| `client-cli` | `client-cli/` |
| `common` | `common/` |
| `archon` | `agent/archon/` |
| `phantom` | `agent/phantom/` |
| `specter` | `agent/specter/` |
| `autotest` | `automatic-test/` |

A dev agent in a zone is strictly prohibited from modifying files outside it. If work in
another zone is needed, the agent creates a beads issue labelled `zone:<name>` for a
future session.

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

### Typical multi-agent setup

```bash
# Two dev agents covering different zones
./loop.sh --service --agent claude --loop dev --zone teamserver
./loop.sh --service --agent codex  --loop dev --zone client-cli

# QA and arch review (one of each is enough)
./loop.sh --service --agent claude --loop qa
./loop.sh --service --agent claude --loop arch

# Feature completeness check on demand
./loop.sh --agent claude --loop feature --zone teamserver client-cli
```

### Running on multiple VMs in parallel

Dev loops are safe to run simultaneously across machines. Each loop claims a task by
pushing a git commit immediately — if two agents select the same task at the same moment,
the one whose push lands second detects the conflict, releases the claim, and picks a
different task.

Each agent identifies itself as `<node-id>-<agent>` in commit messages and log lines
(e.g. `ubuntu-c2-dev01-a3kx-claude`), so it is always clear which machine did what. The
node ID is auto-generated on first run and stored in `.node-id`.

### Prompt files

All prompts live in `prompts/`:

| Prompt | Used by |
|---|---|
| `prompts/CLAUDE_DEV_PROMPT.md` | `dev` loop (Claude) |
| `prompts/CODEX_PROMPT.md` | `dev` loop (Codex) |
| `prompts/CURSOR_PROMPT.md` | `dev` loop (Cursor) |
| `prompts/DEV_LITEQA_PROMPT.md` | lite QA pass after each dev task |
| `prompts/CLAUDE_PROMPT.md` | `qa` loop |
| `prompts/CLAUDE_ARCH_PROMPT.md` | `arch` loop |
| `prompts/CLAUDE_TEST_PROMPT.md` | `quality` loop |
| `prompts/CODEX_TEST_PROMPT.md` | `coverage` loop |
| `prompts/CLAUDE_FEATURE_PROMPT.md` | `feature` loop |
| `prompts/CLAUDE_AUTOTEST_PROMPT.md` | `autotest` loop |

---

## Issue Tracker

This project uses [beads_rust](https://github.com/Dicklesworthstone/beads_rust) (`br`)
for issue tracking. Issues are stored in `.beads/issues.jsonl` and synced via git — no
external service required.

```bash
br ready                    # show unblocked work
br show <id>                # full issue details
br list --status=open       # all open issues
br search "keyword"         # full-text search

br create \
  --title="..." \
  --description="..." \
  --type=task \
  --priority=2              # 0=critical, 1=high, 2=medium, 3=low, 4=backlog

br update <id> --status=in_progress
br close <id> --reason="done"
```

### Syncing across machines

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
├── client-cli/              # AI-agent CLI client (red-cell-cli binary)
├── common/                  # Shared types: protocol, crypto, config
├── agent/
│   ├── demon/               # Original Havoc Demon — frozen, do not modify
│   ├── archon/              # Fork of Demon — C/ASM, Phase 2a
│   ├── phantom/             # Linux Rust agent — Phase 2b
│   └── specter/             # Windows Rust agent — Phase 2c
├── automatic-test/          # E2E test harness (Python)
│   ├── test.py              # Main runner: --scenario all|01|02|...
│   ├── config/              # env.toml (committed), targets.toml (gitignored)
│   ├── scenarios/           # Per-scenario test scripts
│   └── lib/                 # CLI wrapper, SSH helpers, poll helpers
├── profiles/                # Teamserver profiles (.yaotl + TLS certs)
├── docs/                    # Documentation and test plans
├── prompts/                 # Agent loop prompt files
├── logs/                    # Agent loop log output (gitignored)
├── .beads/
│   └── issues.jsonl         # Issue tracker — committed to git for sync
├── loop.py                  # Unified agent loop runner
├── loop.sh                  # Wrapper: foreground or --service mode
├── AGENTS.md                # Agent instructions and architecture decisions
├── AGENT_SCORECARD.md       # Per-agent quality metrics
└── setup.sh                 # Session start / machine onboarding script
```

---

## Status

This is a vibe-coded personal hobby project — built entirely by AI agent loops with
human direction. It is not open for contributions. Feel free to follow along or use it
as inspiration, but please do not open pull requests.
