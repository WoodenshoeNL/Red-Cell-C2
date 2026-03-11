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

```bash
find teamserver common client -name '*.rs' | sort
find teamserver common client -name 'Cargo.toml' | xargs grep -l '^\[package\]' | sort
find teamserver common client -name '*.rs' | xargs wc -l | sort -rn | head -30
grep -rn '^pub ' common/src/ | grep -v '^\s*//' | head -60
```

---

## Step 3 — Read the Core Files in Full

```bash
cat common/src/lib.rs
cat common/src/domain.rs
cat common/src/config.rs
cat teamserver/src/main.rs
cat teamserver/src/lib.rs
```

Then read every teamserver module and integration test:

```bash
find teamserver/src -name '*.rs' | sort | while read f; do
  echo "====== $f ======"
  cat "$f"
done

find teamserver/tests -name '*.rs' 2>/dev/null | while read f; do
  echo "====== $f ======"
  cat "$f"
done
```

---

## Step 4 — Build and Test

```bash
cargo check --workspace 2>&1
cargo clippy --workspace -- -D warnings 2>&1
cargo test --workspace 2>&1
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

For each finding, determine which agent wrote the code:

```bash
git log --format="%H %s" -- path/to/file.rs | head -5 | while read hash title; do
  agent=$(git show "$hash" --no-patch --format="%b" \
    | grep "Co-Authored-By:" | sed 's/Co-Authored-By: //' | head -1)
  echo "$hash | ${agent:-unknown} | $title"
done
```

Keep a tally per agent by category.

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
