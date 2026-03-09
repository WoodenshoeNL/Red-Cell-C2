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
| Agent protocol | Demon binary protocol — unchanged (0xDEADBEEF, AES-256-CBC) |
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

---

## Getting Started

### 1. Clone

```bash
git clone git@github.com:WoodenshoeNL/Red-Cell-C2.git
cd Red-Cell-C2
```

`br` will auto-import all issues from `.beads/issues.jsonl` on first use.

### 2. Verify issue tracker

```bash
br ready    # shows available work
br stats    # shows overall project state
```

### 3. Build (once crates exist)

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
| `./claude_loop.sh` | Claude | QA review | Every 10 min |

### Development loops (`codex_loop.sh`, `claude_dev_loop.sh`)

Pick the highest-priority unblocked task from the issue tracker, implement it, run tests, commit, push, and close the issue — then repeat.

```bash
# Run forever
./codex_loop.sh
./claude_dev_loop.sh

# Run exactly N loops then exit
./codex_loop.sh 5
./claude_dev_loop.sh 3
```

Logs: `logs/codex_dev.log`, `logs/claude_dev.log`

### QA review loop (`claude_loop.sh`)

Runs every 10 minutes. Reviews recent commits, checks build health, verifies architecture compliance, and creates beads issues for any problems found. Does not write code.

```bash
./claude_loop.sh
```

Log: `logs/claude_qa.log`

### Typical multi-agent setup

```bash
./codex_loop.sh &          # Codex doing dev work in background
./claude_dev_loop.sh 2 &   # Claude doing 2 dev tasks in background
./claude_loop.sh           # Claude QA in foreground
```

### Prompt files

Each loop has a corresponding prompt file that controls agent behavior:

| Prompt | Used by |
|---|---|
| `CODEX_PROMPT.md` | `codex_loop.sh` |
| `CLAUDE_DEV_PROMPT.md` | `claude_dev_loop.sh` |
| `CLAUDE_PROMPT.md` | `claude_loop.sh` |

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

On another machine, `git pull` is sufficient — `br` auto-imports from the updated JSONL.

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
├── CODEX_PROMPT.md          # Codex developer prompt
├── claude_loop.sh           # QA review loop
├── claude_dev_loop.sh       # Claude development loop
└── codex_loop.sh            # Codex development loop
```

---

## Contributing

This project is primarily developed by autonomous AI agents. Human contributions are welcome — use the issue tracker to coordinate:

1. Check `br ready` for available work
2. Claim a task: `br update <id> --status=in_progress`
3. Implement, test, commit, push
4. Close: `br close <id>`

See `AGENTS.md` for full workflow details and architecture decisions.
