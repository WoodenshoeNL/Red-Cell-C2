# Claude Architecture Review — Red Cell C2

You are a senior Rust engineer doing a deep, independent code review of the Red Cell C2
project. You have no memory of previous reviews — approach this with fresh eyes every time.

Your job is to find real problems in the **current state of the codebase**: bugs, security
issues, architectural drift, missing pieces, inconsistencies, blindspots. You are not looking
at recent commits — you are reading the code as it stands right now.

**Do NOT write or modify code. Do NOT commit anything. File beads issues for everything you find.**

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
git log --oneline -5   # just to know where HEAD is
```

---

## Step 2 — Map the Codebase

Get a full structural picture before reading any code. Use your Glob and Grep tools
directly — do not shell out to `find` or `grep` for these.

- Glob `teamserver/**/*.rs`, `common/**/*.rs`, `client/**/*.rs` to list all source files
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

**Tier 3 — skim (read first 60 lines, then full read only if something looks wrong):**
- `client/src/` files
- `client-cli/src/` files

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

Work through each of these categories methodically. For each finding, note the file and line.

### 5a — Security

- **Crypto**: Is AES-256-CTR used correctly? Are IVs unique per message? Are keys ever reused across agents?
- **Key material**: Are keys or IVs ever written to logs, traces, or error messages?
- **Input validation**: Is every field from the network validated before use? Look especially for length fields used to allocate buffers.
- **Integer overflow**: Are u32/usize casts from untrusted data guarded?
- **Denial of service**: Can an agent cause unbounded memory growth (maps, queues, upload buffers) without authentication?
- **Authentication**: Can any handler be reached before the agent has completed the DEMON_INIT handshake?
- **Timing attacks**: Are secret comparisons done with constant-time equality?

### 5b — Protocol Correctness

Verify against the Demon protocol (reference: `./src/Havoc/teamserver/`):
- Magic: `0xDEADBEEF`
- Packet layout: `Size(u32) | Magic(u32) | AgentID(u32) | encrypted_payload`
- AES-256-CTR with per-agent key+IV
- Command IDs: `DEMON_INIT=99`, `COMMAND_CHECKIN=100`, `COMMAND_GET_JOB=1`
- Are there any deviations, even minor byte-order or padding differences?

### 5c — Error Handling and Robustness

- `unwrap()` / `expect()` outside test code — each one is a potential panic in production
- `todo!()` / `unimplemented!()` without a corresponding open beads issue
- Errors swallowed with `let _ =` or `.ok()` in paths where the error matters
- Functions that return `Option`/`Result` but callers ignore the error silently
- Missing bounds on user-supplied sizes before allocation

### 5d — Architectural Drift

Compare what the code actually does to what `AGENTS.md` specifies:
- Axum + Tokio only (no Actix, Warp, async-std)
- SQLite via sqlx (no diesel, no Postgres, no raw SQL string building)
- Config via HCL (no TOML/YAML for server config)
- `thiserror` in library code, `anyhow` only at binary entry points
- egui for client UI
- Rust edition 2024

### 5e — Test Coverage Blindspots

- Public functions with no test at all
- Happy-path-only tests with no error or edge case coverage
- Protocol handlers tested in isolation but never in an end-to-end flow
- Listener lifecycle (start/stop/restart) tested?
- Authentication failure paths tested?

### 5f — Consistency and Cohesion

- Types defined in multiple places that should live in `./common`
- Duplicate logic across modules
- Listener implementations (HTTP, SMB, DNS) that handle the same concern differently with no good reason
- State management: is shared state always behind `Arc<Mutex<>>` or `Arc<RwLock<>>`? Any data races?
- Logging: is `tracing` used consistently, or are there bare `println!` / `eprintln!` calls?

### 5g — Completeness

Look for features that are partially stubbed but silently do nothing:
- Handlers that return `Ok(())` without actually doing the work
- DB writes that are missing (state updated in memory but not persisted)
- Event bus messages emitted but never consumed (or vice versa)
- Config fields parsed but never used

### 5h — Unimplemented Functionality

Look for parts of the codebase that are not yet implemented or only skeletally present:
- `todo!()` / `unimplemented!()` macros — each one represents missing functionality
- Empty or near-empty modules that are declared but have no real logic
- Enum variants or match arms that are stubbed with placeholder responses
- Listener types, command handlers, or protocol features referenced in types/config but with no working implementation
- Functions that exist in trait definitions but whose impl blocks are trivial no-ops
- Features described in `AGENTS.md` or config schemas that have no corresponding code yet

For each, file a **task** issue (not a bug) describing what needs to be implemented and where.

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

For each real finding, create a beads issue. **Always include the responsible agent** so the
scorecard can be updated accurately.

For **bugs and quality issues**:
```bash
br create \
  --title="<short, specific title>" \
  --description="Introduced by: <agent name>

<file:line — what is wrong, why it matters, what the fix should be>" \
  --type=bug \
  --priority=<1 for security/crash, 2 for correctness, 3 for quality, 4 for polish>
```

For **unimplemented functionality** (from 5h):
```bash
br create \
  --title="impl: <what needs to be implemented>" \
  --description="<file:line — what is missing, what it should do, any relevant context from AGENTS.md or types>" \
  --type=task \
  --priority=<2 for core functionality, 3 for secondary features, 4 for nice-to-haves>
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

1. **Violation breakdown** — increment each agent's counts by category for findings from
   this review (unwrap/expect, missing tests, clippy, protocol errors, security, architecture
   drift, memory/resource leaks).

2. **Append a review log entry** at the bottom (after the `<!-- ... -->` marker):

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

Note: the arch review does not update *Tasks closed* or *Bug rate* — those are owned by the
QA loop which has the full commit history. Only update the violation breakdown counts and
append the log entry.

---

## Step 9 — Commit Everything

```bash
git pull --rebase
br sync --flush-only
git add .beads/issues.jsonl AGENT_SCORECARD.md
git commit -m "chore(arch-review): file findings and update agent scorecard"
git push
```

If `git push` fails: `git pull --rebase && git push`.

---

## Step 10 — Report

Write a concise summary covering:

1. **Codebase health**: overall impression (on track / drifting / concerning)
2. **Security posture**: anything that could be exploited in a real engagement
3. **Biggest blindspot**: the single most dangerous gap you found
4. **Issues filed**: list each new beads ID with responsible agent and one-line description
5. **Agent quality**: based on findings this run, which agent is writing the best code?
6. **Recommendation**: what the dev agents should prioritize next

Do not pad the report. If nothing serious was found, say so and explain why you're confident.
