# Agent Instructions

## Goal

**Phase 1 — Complete.** Rust rewrite of the [Havoc C2 framework](./src/Havoc):
teamserver, operator GUI client (`red-cell-client`), and AI-agent CLI client
(`red-cell-cli`). The original Demon agent (C/ASM) is kept as-is; Demon protocol
compatibility is maintained.

**Phase 2 — Active.** Two objectives running in parallel:
1. **Testing** — manual operator test plan + automated end-to-end harness
   (`automatic-test/`) exercising the full `red-cell-cli → teamserver → agent`
   flow on real Ubuntu Desktop and Windows 11 targets.
2. **Additional agents** — implement Archon, Phantom, and Specter in sequence
   (see *Agent Variants* below). Archon first (C/ASM fork of Demon, compile +
   test parity), then Phantom (Rust, Linux), then Specter (Rust, Windows).

## Onboarding (new VM setup)

1. **Install `br`** (beads_rust issue tracker):
   ```bash
   curl -fsSL "https://raw.githubusercontent.com/Dicklesworthstone/beads_rust/main/install.sh" | bash
   ```
2. **Clone the repo** (or `git pull` if already cloned) — `br` auto-imports issues from `.beads/issues.jsonl` on first use.
3. **Verify**: `br ready` should show available work.

## CI Policy

Do not use GitHub Actions for this repository.

- Do not add or keep files under `.github/workflows/`.
- Do not rely on any hosted CI system for builds, tests, linting, or reviews.
- Run all validation on the VM where this repo is checked out.
- Use the local agent loops and the VM-hosted automated/manual test flows instead.

## Architecture Decisions

| Concern | Decision |
|---|---|
| **Repo structure** | Cargo workspace: `./teamserver`, `./client`, `./client-cli`, `./common` at repo root. Agent source in `./agent/`. Profiles in `./profiles/`. Automated test harness in `./automatic-test/`. Docs in `./docs/`. |
| **Binaries** | `red-cell` (teamserver), `red-cell-client` (operator GUI), `red-cell-cli` (AI-agent CLI) |
| **Rust edition** | 2024, latest stable |
| **Teamserver framework** | Axum + Tokio |
| **Database** | SQLite via sqlx — runtime-checked `sqlx::query()` with parameterized `.bind()` calls; `QueryBuilder` for dynamic filters. Compile-time `sqlx::query!()` macros are not used. |
| **Config format** | HCL/YAOTL (same as Havoc `.yaotl` profiles) |
| **Operator protocol** | JSON over WebSocket (same structure as Havoc) |
| **Agent protocol** | Demon binary protocol — unchanged (0xDEADBEEF magic, AES-256-CTR, per-agent keys) |
| **Client UI** | egui (pure Rust, immediate-mode) |
| **Plugin system** | Python via PyO3 (client + teamserver) |
| **New features** | RBAC, REST API, DNS listener, structured audit logging |
| **Agent builds** | Demon and Archon: cross-compiled C/ASM via `mingw-w64` + `nasm` (same toolchain as Demon). Phantom and Specter: `cargo build --target x86_64-unknown-linux-gnu` / `x86_64-pc-windows-gnu`. |
| **Testing** | Unit + integration (mock Demon agent) + E2E automated harness (`automatic-test/test.py`) + manual test plan (see `docs/test-plan.md`). |

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
| 6 | Rate limited (HTTP 429; stderr `error`: `RATE_LIMITED`) |

Long-running **polling** loops (for example `--watch` streams) should retry with backoff or respect `Retry-After` instead of surfacing exit code 6 to the outer caller when recovery is possible.

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
| `archon` | `agent/archon/` | `zone:archon` |
| `phantom` | `agent/phantom/` | `zone:phantom` |
| `specter` | `agent/specter/` | `zone:specter` |
| `autotest` | `automatic-test/` | `zone:autotest` |

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

The QA, arch, quality, and coverage loops review all zones by default, but can be zone-scoped with `--zone`.

---

The original Havoc source lives in `./src/Havoc` as reference only — **do not modify it, do not stage it, do not delete it**. It is committed to git for cross-machine sync, but it is **read-only**. Agents must never edit, create, or delete any file under `./src/`. It is there purely so the code can be read as a reference implementation.

### Profiles

Teamserver profiles live in `./profiles/` (`.yaotl` config files + TLS certs). This is the canonical location — use `--profile profiles/havoc.yaotl` when running the teamserver.

### Agent Variants (`./agent/`)

| Directory | Name | Language | Status | Policy |
|-----------|------|----------|--------|--------|
| `agent/demon/` | **Demon** | C/ASM | ✅ Production | **Frozen** — pristine Havoc Demon copy. Do not modify. Replace with upstream to update. |
| `agent/archon/` | **Archon** | C/ASM | 🔨 Phase 2a | **Fork of Demon.** Initially identical to Demon — compile + test parity first. Enhancements in a later phase. Build: same toolchain as Demon (`mingw-w64` + `nasm`). |
| `agent/phantom/` | **Phantom** | Rust | 🔨 Phase 2b | **Linux Rust agent.** Demon-compatible transport. Linux-specific capabilities. Build: `cargo build --target x86_64-unknown-linux-gnu`. |
| `agent/specter/` | **Specter** | Rust | 🔨 Phase 2c | **Windows Rust agent.** Full Demon protocol/feature parity. Build: `cargo build --target x86_64-pc-windows-gnu`. |

### Agent build commands

```bash
# Demon / Archon (C/ASM, cross-compiled for Windows)
cd agent/archon
make          # uses the same Makefile structure as agent/demon

# Phantom (Rust, Linux)
cd agent/phantom
cargo build --release --target x86_64-unknown-linux-gnu

# Specter (Rust, Windows cross-compile from Linux)
cd agent/specter
cargo build --release --target x86_64-pc-windows-gnu
```

## Phase 2: Real-World Testing

### Automated test harness (`automatic-test/`)

The harness drives the full `red-cell-cli → teamserver → agent` flow against real
target machines. All interaction goes through `red-cell-cli` (JSON output, stable
exit codes) so AI agents can run it unattended and file bugs for failures.

```
automatic-test/
  test.py                     # main runner: --scenario all|01|02|...
  config/
    env.toml                  # teamserver URL + operator credentials (commit safe)
    targets.toml              # test-machine SSH details — GITIGNORED
    targets.toml.example      # template with placeholders
  scenarios/
    01_auth.py                # login, token expiry, RBAC enforcement
    02_listeners.py           # HTTP/DNS/SMB create/start/stop/delete
    03_payload_build.py       # all format × arch combos, PE validation
    04_agent_linux.py         # deploy → checkin → command suite on Ubuntu
    05_agent_windows.py       # deploy → checkin → command suite on Windows 11
    06_file_transfer.py       # upload + download round-trip
    07_process_ops.py         # list, kill, inject
    08_screenshot.py          # screenshot capture + loot entry
    09_kerberos.py            # token operations
    10_pivot.py               # pivot chain dispatch
    11_loot_audit.py          # loot entries, audit log completeness
    12_rbac.py                # role enforcement across all endpoints
  lib/
    cli.py                    # subprocess wrapper for red-cell-cli
    deploy.py                 # SSH/SCP helpers (Linux + Windows)
    wait.py                   # poll helpers: wait_for_agent, wait_for_output
  PROMPTS/
    AGENT_TEST_PROMPT.md      # prompt for AI-agent-driven test runs
```

**Running the harness:**
```bash
cd automatic-test
# Run all scenarios against both targets
python3 test.py --scenario all

# Run a single scenario
python3 test.py --scenario 04

# Dry-run (validate config only, no actual deployment)
python3 test.py --dry-run
```

### Target machines

| Target | OS | Deploy method |
|--------|----|---------------|
| `linux-test` | Ubuntu Desktop (latest LTS) | SSH + SCP |
| `windows-test` | Windows 11 | SSH (OpenSSH for Windows) |

Connection details live in `automatic-test/config/targets.toml` (gitignored).
See `automatic-test/config/targets.toml.example` for the required fields.

For Windows SSH setup, see `docs/win11-ssh-setup.md`.

### Manual test plan

A checklist-style test plan for operator-driven validation lives in
`docs/test-plan.md`. It covers every layer: auth, listeners, payload generation,
agent commands, events, loot, plugins, and the REST API.

### Zone for test harness work

Use `--zone autotest` when running a dev loop against `automatic-test/`:
```bash
./loop.py --agent claude --loop dev --zone autotest
```

---

## Large Task Policy

**Never attempt a refactor or file split larger than ~300 lines in a single session.**

Splitting a 5k–11k-line file requires 100–150 turns. Sessions are capped at ~150 turns.
Hitting the cap mid-split leaves the codebase in a broken intermediate state and forces
the next session to spend turns just understanding where to resume.

### Rule: measure first, split the issue before touching code

```bash
wc -l <file>            # > 300 lines? split the issue.
```

If the file is large, create **one sub-issue per logical module** before writing any code:

```bash
br create \
  --title="refactor(<scope>): extract <module> from <file>" \
  --description="Functions/structs to move: ...\nWhy: reduces file from Nk to ~Mk lines" \
  --type=task --priority=<same as parent>
br update <new-id> --add-label zone:<zone>
br dep add <new-id> <parent-id>
br close <parent-id> --reason="split into: <id1>, <id2>, ..."
br sync --flush-only && git add .beads/issues.jsonl
git commit -m "chore: split <parent-id> into sub-issues" && git push
```

Then pick the **first** sub-issue and implement only that module in this session.
**One session = one logical module moved.**

---

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
