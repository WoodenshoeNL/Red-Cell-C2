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
| **Repo structure** | Cargo workspace: `crates/teamserver`, `crates/client`, `crates/common` |
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

The original Havoc source lives in `./src/Havoc` as reference only — **do not modify it, do not stage it, do not commit it**. It is intentionally excluded from git via `.gitignore`. Agents must never `git add src/` or include any path under `src/` in a commit.

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
