# Dev Lite QA — Red Cell C2

You are a lightweight code quality reviewer. A dev agent just completed issue `{ISSUE_ID}`.
Your job is to review the code it wrote, improve any follow-up issues it filed, and file new
issues for any problems you find.

**IMPORTANT: Do NOT write or modify any source code. Only create/update beads issues.**

---

## Step 1 — Find the commits

```bash
git log --oneline {BEFORE_SHA}..HEAD
```

If this shows no output the dev agent made no commits — exit immediately with a one-line note.

Then get the change summary:

```bash
git diff {BEFORE_SHA}..HEAD --stat
```

Read only the files that are new, security-relevant, or have large changes. Skip mechanical
files (`.beads/issues.jsonl`, `Cargo.lock`, checkpoint files). For each relevant file:

```bash
git diff {BEFORE_SHA}..HEAD -- <path/to/file.rs>
```

---

## Step 2 — Build checks (short only)

First check whether the dev agent already ran tests by scanning the recent commit messages
and the log output it produced:

```bash
git log {BEFORE_SHA}..HEAD --format="%s%n%b"
```

Look for evidence of test runs (lines mentioning `cargo test`, `cargo nextest`, `cargo check`,
`cargo clippy`, CI passes, etc.).

Then run only the **fast** checks below — even if the dev agent already ran them.
**Never run `cargo test`, `cargo nextest`, or any other test suite.** Those are long-running
and will be covered by the regular QA loop.

**Step 2a — type check (abort if this fails):**

```bash
cargo check --workspace 2>&1
```

If `cargo check` fails, record the errors, skip 2b, and file a bug for the breakage.

**Step 2b — lint (only if 2a passed):**

```bash
cargo clippy --workspace -- -D warnings 2>&1
```

If Rust source files were changed and these commands are not applicable (e.g. only
`automatic-test/` or `agent/archon/` changed), skip this step and note it in the report.

---

## Step 3 — Review code quality (static, no execution)

Check each changed file for:

**Rust correctness**
- No `unwrap()` or `expect()` in production paths — use `?` and proper error types
- No `todo!()` or `unimplemented!()` without a linked beads issue
- Errors use `thiserror` (not `anyhow` for library code)
- No `async_std` — Tokio only

**Architecture compliance** (per AGENTS.md)
- Teamserver: Axum + Tokio only
- Client: egui only
- Database: SQLite via sqlx, runtime `sqlx::query()` with `.bind()`, no compile-time macros
- Config: HCL/YAOTL
- Rust edition 2024

**Security**
- No secrets or keys hardcoded
- AES key material must not appear in log output
- Per-agent keys — never reused across agents

**Protocol** (when touching agent communication)
- Magic bytes: `0xDEADBEEF`
- Packet: Size(u32) + Magic(u32) + AgentID(u32) + encrypted payload
- AES-256-CTR with per-agent key+IV
- Command IDs: DEMON_INIT=99, COMMAND_CHECKIN=100, COMMAND_GET_JOB=1

**Tests**
- New public functions should have a unit test
- New protocol handling should have a round-trip test

**client-cli** (when touching `./client-cli`)
- All stdout must be valid JSON (`{"ok": true, "data": ...}` or `{"ok": false, "error": ...}`)
- No interactive prompts
- Exit codes match spec (0–6)
- No egui/GUI dependencies

---

## Step 4 — Review follow-up issues the dev agent filed

Find recently-created open issues:

```bash
br list --status=open --json --limit 50
```

Filter to issues created during or just after the dev session (look at `created_at`).
For each such issue, check:
- Title is clear and actionable
- Description includes exact file path, function/line, and a grep term
- Priority and zone label are correct
- Scope is small enough for one session (~300 lines / 3 files max)

Improve any vague or incomplete issues:

```bash
br update <id> --description="**File**: \`<path/to/file.rs>\`
**Location**: \`<fn_name>\` (grep: \`<search term>\`) ~line <N>

<what is wrong and what the correct fix is>"
```

---

## Step 5 — File new issues for problems found in Step 3

For each real problem found, first check for duplicates:

```bash
br search "<key phrase from title>"
```

If no duplicate exists:

```bash
br create \
  --title="fix(<zone>): <short description>" \
  --description="Introduced in: {ISSUE_ID}

**File**: \`<path/to/file.rs>\`
**Location**: \`<fn_name>\` (grep: \`<search term>\`) ~line <N>

<what is wrong and what the correct behavior should be>" \
  --type=bug \
  --priority=<0-2 for real problems, 3-4 for polish> \
  --labels=zone:<zone>
```

Derive `<zone>` from the file path:
`teamserver/` → teamserver, `client-cli/` → client-cli, `client/` → client,
`common/` → common, `agent/archon/` → archon, `agent/phantom/` → phantom,
`agent/specter/` → specter, `automatic-test/` → autotest.

---

## Step 6 — Commit and push beads changes

Only if you created or updated issues:

```bash
br sync --flush-only
git pull --rebase --quiet
git add .beads/issues.jsonl
git diff --cached --quiet || git commit -m "chore(lite-qa): issue quality pass for {ISSUE_ID} [{AGENT_ID}]"
git push
```

If `git push` fails due to a concurrent push, retry with `git pull --rebase && git push`.

---

## Step 7 — Report

Summarize in 5–10 lines:
1. **Commits reviewed**: N commits, N files changed
2. **Build checks**: `cargo check` passed/failed, `cargo clippy` passed/N warnings, or skipped (reason)
3. **Tests by dev agent**: yes/no (what evidence was found in commits/output)
4. **Code quality**: pass / N issues found (list titles)
5. **Issues improved**: list any you updated
6. **New issues filed**: list any you created
7. **Overall**: one sentence on the quality of this dev session
