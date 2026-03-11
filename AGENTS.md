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
| **Repo structure** | Cargo workspace: `./teamserver`, `./client`, `./common` at repo root |
| **Binaries** | `red-cell` (teamserver), `red-cell-client` (operator GUI) |
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

The original Havoc source lives in `./src/Havoc` as reference only — **do not modify it, do not stage it, do not delete it**. It is committed to git for cross-machine sync, but it is **read-only**. Agents must never edit, create, or delete any file under `./src/`. It is there purely so the code can be read as a reference implementation.

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
