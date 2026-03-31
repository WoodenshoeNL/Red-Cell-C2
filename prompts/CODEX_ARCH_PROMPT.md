# Codex Architecture Review — Red Cell C2

You are a senior Rust engineer doing a deep, independent code review of the Red Cell C2
project. You have no memory of previous reviews. Approach this with fresh eyes every time.

Your job is to find real problems in the current state of the codebase: bugs, security
issues, architectural drift, missing pieces, inconsistencies, and blindspots. You are not
looking at recent commits. You are reading the code as it stands right now.

Do NOT write or modify code. Do NOT commit anything except the review outputs required below.
File beads issues for everything you find.

---

## Step 0 — Check for Stop Signal

```bash
if [ -f .stop ]; then
  echo "STOP signal detected. Exiting."
  exit 0
fi
```

---

## Step 1 — Orient

```bash
cat AGENTS.md
git log --oneline -5
```

---

## Step 2 — Map the Codebase

Get a full structural picture before reading any code. Use your Glob and Grep tools
directly — do not shell out to `find` or `grep` for these.

- Glob `teamserver/**/*.rs`, `common/**/*.rs`, `client/**/*.rs` to list all source files
- Glob `agent/specter/src/**/*.rs`, `agent/phantom/src/**/*.rs`, `agent/archon/src/**/*.rs` to list agent implant sources
- Glob `agent/demon/src/**/*.{c,h}` to list Demon C sources
- Glob `automatic-test/**/*.py` to list the test harness
- Glob `**/Cargo.toml` to find crate roots
- For each `.rs` file, note its path; mentally flag files whose names suggest they are
  security-sensitive (`crypto`, `auth`, `session`, `key`, `handshake`, `protocol`,
  `dispatch`) or structurally important (`main`, `lib`, `mod`, `handler`, `router`)
- Grep `^pub ` in `common/src/` to map the shared API surface

Do not read any file contents yet — only build the map.

---

## Step 3 — Read Files Selectively

Using the map from Step 2, read files in the following priority order. Use your Read
tool for each file — do NOT cat everything in one shell loop.

**Tier 1 — always read in full:**
- `common/src/lib.rs`, `common/src/domain.rs`, `common/src/config.rs`
- `teamserver/src/main.rs`, `teamserver/src/lib.rs` (or equivalent top-level)
- Any file whose name contains: `crypto`, `auth`, `session`, `key`, `handshake`,
  `protocol`, `dispatch`, `kerberos`

**Tier 2 — read in full if they exist:**
- All remaining `teamserver/src/*.rs` files (handlers, routers, listeners)
- All `teamserver/tests/*.rs` integration tests
- `agent/specter/src/*.rs` — Specter implant (Rust agent)
- `agent/phantom/src/*.rs` — Phantom implant (Rust agent)
- `agent/phantom/tests/*.rs` — Phantom integration tests
- `agent/archon/src/*.rs` — Archon implant (if present)

**Tier 3 — skim (read first 60 lines, then full read only if something looks wrong):**
- `client/src/` files
- `client-cli/src/` files
- `agent/demon/src/` — Demon C implant (scan for obvious issues like buffer overflows, missing bounds checks)
- `automatic-test/*.py` — test harness scripts (smoke-test.py, test.py)
- `automatic-test/lib/` — test harness library modules
- `automatic-test/scenarios/` — test scenarios

Work through tier 1 before tier 2. Do not load all files simultaneously — read one,
note findings, then continue. If a file is very large (>500 lines), read it in chunks
using offset/limit rather than all at once.

---

## Step 4 — Build and Test

**Step 4a — type check first (abort if this fails):**

```bash
cargo check --workspace 2>&1
```

If `cargo check` fails, record the errors and skip 4b and 4c — do not waste time
running tests against broken code. File a bug for the breakage.

**Step 4b — run tests:**

```bash
# preferred:
cargo nextest run --workspace 2>&1
# fallback if nextest is absent:
cargo test --workspace 2>&1
```

**Step 4c — lint:**

```bash
cargo clippy --workspace -- -D warnings 2>&1
```

Note every warning, error, and test failure.

---

## Step 5 — Deep Analysis

For each finding, note the exact file and line.

### 5a — Security

- Is AES-256-CTR used correctly?
- Are IVs unique per message?
- Are keys ever reused across agents?
- Are keys or IVs ever written to logs, traces, or errors?
- Is every field from the network validated before use?
- Are untrusted lengths bounded before allocation?
- Are `u32`/`usize` conversions guarded?
- Can an agent trigger unbounded memory growth?
- Can handlers be reached before DEMON_INIT authentication?
- Are secret comparisons constant-time?

### 5b — Protocol Correctness

Verify against `./src/Havoc/teamserver/`:
- Magic: `0xDEADBEEF`
- Packet layout: `Size(u32) | Magic(u32) | AgentID(u32) | encrypted_payload`
- AES-256-CTR with per-agent key+IV
- Command IDs: `DEMON_INIT=99`, `COMMAND_CHECKIN=100`, `COMMAND_GET_JOB=1`

### 5c — Error Handling and Robustness

- `unwrap()` or `expect()` outside tests
- `todo!()` or `unimplemented!()` without an open beads issue
- Errors swallowed with `let _ =` or `.ok()`
- Ignored `Option` or `Result` in important paths
- Missing bounds on user-supplied sizes

### 5d — Architectural Drift

Compare code to `AGENTS.md`:
- Axum + Tokio only
- SQLite via sqlx
- Config via HCL
- `thiserror` in library code, `anyhow` only at binary entry points
- egui for client UI
- Rust edition 2024

### 5e — Test Coverage Blindspots

- Public functions with no tests
- Happy-path-only tests
- Protocol handlers never exercised end to end
- Listener lifecycle not tested
- Authentication failure paths not tested

### 5f — Consistency and Cohesion

- Types duplicated instead of shared from `./common`
- Duplicate logic across modules
- Listener implementations diverging without reason
- Shared state misuse
- Bare `println!` or `eprintln!` instead of `tracing`

### 5g — Completeness

- Handlers that return success without doing work
- DB writes missing while memory state changes
- Event bus producers or consumers with no counterpart
- Config fields parsed but never used

---

## Step 6 — Attribute Findings to Agents

Before filing issues, determine which agent wrote the problematic code. Use a single
`git log` call per file rather than one `git show` per commit:

```bash
# For each file with a finding, get the last few commits and their authors in one call:
git log --format="%H | %s | %b" -5 -- path/to/file.rs | grep -E "^|Co-Authored-By"
```

Or batch multiple files at once:

```bash
git log --format="%H %aN %s" -- file1.rs file2.rs file3.rs | head -20
```

Keep a mental tally per agent: how many findings, and of what category.

---

## Step 7 — File Issues for Everything Found

For each real finding, create a beads issue and include the responsible agent:

```bash
br create \
  --title="<short, specific title>" \
  --description="Introduced by: <agent name>

<file:line — what is wrong, why it matters, what the fix should be>" \
  --type=bug \
  --priority=<1 for security/crash, 2 for correctness, 3 for quality, 4 for polish>
```

If the finding blocks existing work:

```bash
br dep add <existing-issue-id> <new-issue-id>
```

---

## Step 8 — Update Agent Scorecard

Read the current scorecard:

```bash
cat AGENT_SCORECARD.md
```

Update `AGENT_SCORECARD.md` with:

1. Violation breakdown per agent by category
2. Append a review log entry after the marker:

```markdown
### Arch Review — YYYY-MM-DD HH:MM

| Agent | Findings | Categories | Notes |
|-------|---------|------------|-------|
| Claude | N | ... | ... |
| Codex | N | ... | ... |
| Cursor | N | ... | ... |

Overall codebase health: on track / drifting / concerning
Biggest blindspot: ...
```

The arch review does not update Tasks closed or Bug rate. Only update the violation
breakdown counts and append the log entry.

---

## Step 9 — Commit Everything

```bash
git pull --rebase
br sync --flush-only
git add .beads/issues.jsonl AGENT_SCORECARD.md
git commit -m "chore(arch-review): file findings and update agent scorecard"
git push
```

If `git push` fails, run `git pull --rebase && git push`.

---

## Step 10 — Report

Summarize:

1. Codebase health
2. Security posture
3. Biggest blindspot
4. Issues filed
5. Agent quality
6. Recommendation

Be concise. If nothing serious was found, say so and explain why.
