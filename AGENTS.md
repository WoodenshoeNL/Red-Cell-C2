# Agent Instructions

## Goal

Rewrite of the [Havoc C2 framework](./src/Havoc) in Rust — teamserver and operator client. The original Demon agent (C/ASM) is kept as-is; protocol compatibility is maintained.

## Onboarding (new VM setup)

1. **Install `br`** (beads_rust issue tracker):
   ```bash
   curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/beads_rust/main/install.sh" | bash
   ```
2. **Clone the repo** (or `git pull` if already cloned) — `br` auto-imports issues from `.beads/issues.jsonl` on first use.
3. **Verify**: `br ready` should show available work.

## Architecture Decisions

| Concern | Decision |
|---|---|
| **Repo structure** | Cargo workspace: `./teamserver`, `./client`, `./client-cli`, `./common` at repo root. Agent source in `./agent/`. Profiles in `./profiles/`. |
| **Binaries** | `red-cell` (teamserver), `red-cell-client` (operator GUI), `red-cell-cli` (AI-agent CLI) |
| **Rust edition** | 2024, latest stable |
| **Teamserver framework** | Axum + Tokio |
| **Database** | SQLite via sqlx |
| **Config format** | HCL/YAOTL (same as Havoc `.yaotl` profiles) |
| **Operator protocol** | JSON over WebSocket (same structure as Havoc) |
| **Agent protocol** | Demon binary protocol — unchanged (0xDEADBEEF magic, AES-256-CTR, per-agent keys) |
| **Client UI** | egui (pure Rust, immediate-mode) |
| **Plugin system** | Python via PyO3 (client + teamserver) |
| **New features** | RBAC, REST API, DNS listener, structured audit logging |
| **Testing** | Full suite: unit + integration (mock Demon agent) + E2E |

## client-cli Design Spec (`red-cell-cli`)

An AI-agent-optimized CLI client that lives alongside the GUI client. Every design decision
optimises for machine consumption, not human aesthetics.

### Non-negotiable rules

| Rule | Rationale |
|---|---|
| JSON on stdout by default | Agents parse output — no guessing at table formats |
| Structured errors on stderr | Agents can redirect stdout/stderr independently |
| Zero interactive prompts | Dev loops cannot respond to prompts; everything via flags/env vars |
| Exit codes are documented and stable | Agents branch on exit code, not string matching |
| `--help` everywhere includes examples | Agents discover usage without docs |
| Bare invocation prints all commands | First thing an agent tries when exploring a new tool |

### Output contract

```
stdout (success): {"ok": true, "data": <payload>}
stderr (failure): {"ok": false, "error": "ERROR_CODE", "message": "human text"}
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General / argument error |
| 2 | Not found (agent/listener/operator does not exist) |
| 3 | Auth failure (bad token, insufficient role) |
| 4 | Server unreachable |
| 5 | Timeout (--timeout exceeded) |

### Auth resolution order (first wins)

1. `--server` / `--token` CLI flags
2. `RC_SERVER` / `RC_TOKEN` environment variables
3. `.red-cell-cli.toml` in current or any parent directory
4. `~/.config/red-cell-cli/config.toml`

### Command surface

```
red-cell-cli [--server URL] [--token TOKEN] [--output json|text] [--timeout N]

  status                              Server health check
  agent list                          List all active agents
  agent show <id>                     Full agent details
  agent exec <id> --cmd <cmd>         Execute command [--wait] [--timeout N]
  agent output <id>                   Fetch pending output [--watch to stream]
  agent kill <id>                     Terminate agent [--wait]
  agent upload <id> --src --dst       Upload file to agent
  agent download <id> --src --dst     Download file from agent
  listener list                       List all listeners
  listener show <name>                Show listener config + status
  listener create --name --type ...   Create listener (http/dns/smb/external)
  listener start/stop/delete <name>   Lifecycle management
  operator list/create/delete         RBAC operator management
  payload build/list/download         Payload building
  log list/tail                       Audit log (--watch to stream)
  session [--agent <id>]              Persistent JSON pipe (see below)
```

### Session mode

For long-running agent interactions, `session` keeps a single WebSocket connection open and
reads newline-delimited JSON from stdin, writing responses to stdout:

```json
→ {"cmd": "agent.exec", "id": "abc123", "command": "whoami", "wait": true}
← {"ok": true, "cmd": "agent.exec", "data": {"output": "DOMAIN\\user", "exit_code": 0}}
→ {"cmd": "ping"}
← {"ok": true, "data": {"pong": true}}
→ {"cmd": "exit"}
```

Commands mirror the CLI surface (`agent.list`, `agent.exec`, `listener.list`, etc.).
EOF on stdin or `{"cmd": "exit"}` terminates cleanly.

### Architecture compliance (QA checklist)

- Binary crate in `./client-cli/`, workspace member
- No egui / GUI dependencies
- Shares code with `./common` — never duplicates teamserver types
- All async via Tokio (no async-std)
- Errors via `thiserror` (not `anyhow` in library code)
- No `unwrap()`/`expect()` in non-test code
- Every public function has a unit test

---

## Zone System

Dev loops can be scoped to a **zone** so multiple agents can run in parallel without file conflicts.
Each zone maps to a workspace crate. Issues carry a `zone:<name>` beads label.

| Zone | Paths | Beads label |
|------|-------|-------------|
| `teamserver` | `teamserver/` | `zone:teamserver` |
| `client-cli` | `client-cli/` | `zone:client-cli` |
| `client` | `client/` | `zone:client` |
| `common` | `common/` | `zone:common` |
| `agent` | `agent/` | `zone:agent` |

### Running a zone-scoped dev loop

```bash
# Single zone
./loop.py --agent claude --loop dev --zone client-cli
./loop.py --agent codex  --loop dev --zone teamserver

# Multiple zones on one agent
./loop.py --agent cursor --loop dev --zone client-cli client

# No --zone = all zones (default behaviour, unchanged)
./loop.py --agent claude --loop dev
```

### Zone rules for dev agents

When `--zone` is set, the loop injects a strict constraint into the prompt:

- **Only modify files inside the allowed zone paths.**
- If work in another zone is needed, **create a beads issue** for it and label it:
  ```bash
  br create --title="..." --description="..." --type=task --priority=<N>
  br update <new-id> --add-label zone:<zone>
  ```
- Never reach across zone boundaries yourself.

### Labelling new issues

When creating issues, always add the correct zone label:
```bash
br create --title="fix: ..." --type=bug --priority=2
br update <id> --add-label zone:teamserver
```

The QA and arch loops review all zones and are not zone-scoped.

---

The original Havoc source lives in `./src/Havoc` as reference only — **do not modify it, do not stage it, do not delete it**. It is committed to git for cross-machine sync, but it is **read-only**. Agents must never edit, create, or delete any file under `./src/`. It is there purely so the code can be read as a reference implementation.

### Profiles

Teamserver profiles live in `./profiles/` (`.yaotl` config files + TLS certs). This is the canonical location — use `--profile profiles/havoc.yaotl` when running the teamserver.

### Agent Variants (`./agent/`)

| Directory | Name | Language | Policy |
|-----------|------|----------|--------|
| `agent/demon/` | **Demon** | C/ASM | **Frozen** — pristine copy of the Havoc Demon. Do not modify. Replace with upstream to update. |
| `agent/archon/` | **Archon** | C/ASM | **Mutable** — enhanced fork of Demon. Changes and improvements welcome. |
| `agent/specter/` | **Specter** | Rust | **New** — ground-up Rust rewrite targeting full Demon protocol/feature parity. |

## Stopping a Dev Loop

Both the Claude and Codex dev loops check for a `.stop` file at the repo root before each
pass. If the file exists the agent halts cleanly without claiming new work.

**To stop a locally running loop:**
```bash
touch .stop
```

**To stop a remote/cloud loop (e.g. Codex):**
```bash
touch .stop && git add .stop && git commit -m "chore: stop dev loop" && git push
```

**To resume after stopping:**
```bash
rm .stop && git add .stop && git commit -m "chore: resume dev loop" && git push
# or locally:
rm .stop
```

The `.stop` file is intentionally not gitignored so it can be pushed to stop remote agents.

<!-- br-agent-instructions-v1 -->

---

## Beads Workflow Integration

This project uses [beads_rust](https://github.com/Dicklesworthstone/beads_rust) (`br`/`bd`) for issue tracking. Issues are stored in `.beads/` and tracked in git.

### Essential Commands

```bash
# View ready issues (unblocked, not deferred)
br ready              # or: bd ready

# List and search
br list --status=open # All open issues
br show <id>          # Full issue details with dependencies
br search "keyword"   # Full-text search

# Create and update
br create --title="..." --description="..." --type=task --priority=2
br update <id> --status=in_progress
br close <id> --reason="Completed"
br close <id1> <id2>  # Close multiple issues at once

# Sync with git
br sync --flush-only  # Export DB to JSONL
br sync --status      # Check sync status
```

### Workflow Pattern

1. **Start**: Run `br ready` to find actionable work
2. **Claim**: Use `br update <id> --status=in_progress`
3. **Work**: Implement the task
4. **Complete**: Use `br close <id>`
5. **Sync**: Always run `br sync --flush-only` at session end

### Key Concepts

- **Dependencies**: Issues can block other issues. `br ready` shows only unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers 0-4, not words)
- **Types**: task, bug, feature, epic, chore, docs, question
- **Blocking**: `br dep add <issue> <depends-on>` to add dependencies

### Session Protocol

**Before ending any session, run this checklist:**

```bash
git status              # Check what changed
git add <files>         # Stage code changes
br sync --flush-only    # Export beads changes to JSONL
git commit -m "..."     # Commit everything
git push                # Push to remote
```

### Best Practices

- Check `br ready` at session start to find available work
- Update status as you work (in_progress → closed)
- Create new issues with `br create` when you discover tasks
- Use descriptive titles and set appropriate priority/type
- Always sync before ending session

<!-- end-br-agent-instructions -->

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd sync
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
