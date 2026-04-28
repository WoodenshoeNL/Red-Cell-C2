# Claude Autotest — Red Cell C2

You are a QA agent. Your job is to run the full automatic-test suite end-to-end
against both target VMs (Linux + Windows), classify every failure, file beads
issues for everything that warrants one, and commit the results so the dev loop
can pick them up.

**Unlike the qa/arch/quality review loops, you ARE allowed to write code — but
only for small, blocking test-process fixes.** Anything bigger goes to a beads
issue. See "Inline fixes vs beads" below for the boundary.

---

## Step 0 — Dual-mode setup (loop vs manual)

`loop.py --loop autotest` does the compile, teamserver start, and orphan-payload
cleanup before invoking you, then signals the result via env vars. Manual
invocations (`claude --prompt prompts/CLAUDE_AUTOTEST_PROMPT.md`) have none of
those set, so you do the preflight yourself.

```bash
if [ -f .stop ]; then echo "STOP signal detected. Exiting."; exit 0; fi

if [ -n "$RC_AUTOTEST_BUILD_OK" ]; then
    # Loop mode — trust loop's compile + teamserver start.
    echo "[loop mode] build_ok=$RC_AUTOTEST_BUILD_OK ts_ok=$RC_AUTOTEST_TEAMSERVER_OK"
    echo "[loop mode] config_dir=$RC_AUTOTEST_CONFIG_DIR profile=$RC_AUTOTEST_PROFILE"

    if [ "$RC_AUTOTEST_BUILD_OK" != "1" ]; then
        # Compile failed. Do NOT run scenarios. Read the build log, identify
        # the root cause, file ONE P1 bead with the gcc/rustc error excerpt,
        # commit, push, exit.
        echo "[loop mode] compile failed — switching to troubleshooting"
        echo "[loop mode] build log: $RC_AUTOTEST_BUILD_LOG"
        # Read tail of $RC_AUTOTEST_BUILD_LOG, extract the first 'error[' or
        # 'error:' line + 30 lines of context, file the bead, exit clean.
        # Skip directly to Step 8 (Land the plane).
        AUTOTEST_MODE=build_failed
    elif [ "$RC_AUTOTEST_TEAMSERVER_OK" != "1" ]; then
        # Build OK but teamserver did not start. Diagnose: port already taken
        # by another process? profiles/autotest.yaotl missing or invalid?
        # File a bead, do not run scenarios.
        echo "[loop mode] teamserver did not start — switching to troubleshooting"
        AUTOTEST_MODE=teamserver_failed
    else
        echo "[loop mode] proceeding to scenario run"
        AUTOTEST_MODE=run
    fi
else
    # Manual mode — do the full self-contained preflight in Step 3.
    echo "[manual mode] no RC_AUTOTEST_BUILD_OK set; doing full preflight"
    AUTOTEST_MODE=run
    # Use the regular test profile + config when invoked outside the loop.
    export RC_AUTOTEST_CONFIG_DIR="${RC_AUTOTEST_CONFIG_DIR:-automatic-test/config}"
    export RC_AUTOTEST_PROFILE="${RC_AUTOTEST_PROFILE:-profiles/test.yaotl}"
    export RC_AUTOTEST_PORT="${RC_AUTOTEST_PORT:-40056}"
fi
```

If `AUTOTEST_MODE=build_failed` or `teamserver_failed`, **skip Steps 3–5 and
go straight to Step 7 (file the bead) and Step 8 (commit + push)**. Do not
attempt scenarios; the test infrastructure isn't in a runnable state.

---

## CRITICAL: Concurrent dev agent

A dev agent may be running in this same repository with uncommitted changes.

**Never run any of the following:**
- `git reset --hard` / `git reset --mixed`
- `git checkout -- .` / `git restore .` / `git restore --staged`
- `git clean -f` / `git clean -fd`
- `git stash drop` / `git stash clear`

If `git pull --rebase` fails because of unstaged changes, stash with `--`
specifying only the file you intend to keep aside:
`git stash push -m "wip" -- automatic-test/config/env.toml`. Pull, push,
`git stash pop`. Never blanket-stash.

---

## Step 1 — Orient

```bash
cat AGENTS.md
cat automatic-test/README.md
cat automatic-test/PROMPTS/AGENT_TEST_PROMPT.md   # canonical workflow doc
cat automatic-test/KNOWN_FAILURES.md              # diagnostic shortcuts
br ready                                           # what is the dev loop working on?
```

**Internalize `KNOWN_FAILURES.md` before classifying anything in Step 5.**
Each row maps an error-message substring to either an open bead or a
resolved fix. Matching a row lets you skip an investigation cycle entirely
— file the bead reference instead of re-deriving the same conclusion.

---

## Step 2 — Environment context

Hard-coded values for this VM. Verify they still apply before relying on them.

- Linux target: `192.168.213.159` (user `rctest`)
- Windows target: `192.168.213.160` (user `rctest`)
- Dev-box callback IP: `192.168.213.157`
- SSH key: `~/.ssh/red_cell_test`
- Teamserver: `$RC_AUTOTEST_PROFILE` on `127.0.0.1:$RC_AUTOTEST_PORT`
  (loop mode: `profiles/autotest.yaotl` on `:40156`;
   manual mode: `profiles/test.yaotl` on `:40056`)
- Harness config dir: `$RC_AUTOTEST_CONFIG_DIR`
  (loop mode: `automatic-test/config-autotest`;
   manual mode: `automatic-test/config`)
- Test operator: `test-operator` / api_key `changeme-api-key`

`$RC_AUTOTEST_CONFIG_DIR/env.toml` and `targets.toml` are **gitignored** —
host-specific. `[server].callback_host` must be set to the dev-box IP above;
otherwise Demon/Archon `CONFIG_BYTES` bake `127.0.0.1` and agents on the VMs
call their own loopback.

---

## Step 3 — Preflight (fail loud, do not paper over)

In **loop mode** the loop already compiled, started the teamserver, and ran
orphan-payload cleanup; you only need to verify SSH reachability and put the
CLI on PATH. In **manual mode** you do everything.

```bash
git pull --rebase

if [ "$AUTOTEST_MODE" != "build_failed" ] && [ "$AUTOTEST_MODE" != "teamserver_failed" ]; then

  if [ -z "$RC_AUTOTEST_BUILD_OK" ]; then
    # Manual mode: rebuild only when source changed; (re)start teamserver if stale.
    if [ -f target/release/red-cell ] && [ -f target/release/red-cell-cli ]; then
      CHANGED=$(git log --since="$(stat -c %y target/release/red-cell)" --oneline \
                  -- teamserver agent client-cli common 2>/dev/null | wc -l)
    else
      CHANGED=999
    fi
    if [ "$CHANGED" != "0" ]; then
      echo "Rebuilding (source changed since last release build)"
      cargo build --release --workspace
    fi

    TS_PID=$(pgrep -af "target/release/red-cell --profile $RC_AUTOTEST_PROFILE" \
              | grep -v grep | awk '{print $1}' | head -1)
    if [ -z "$TS_PID" ]; then
      pkill -f "target/release/red-cell --profile $RC_AUTOTEST_PROFILE" || true
      sleep 2
      ./target/release/red-cell --profile "$RC_AUTOTEST_PROFILE" \
          > logs/teamserver.log 2>&1 &
      sleep 5
      tail -3 logs/teamserver.log
    fi
  fi

  # Verify teamserver is listening (both modes — fast sanity check)
  ss -ltn "sport = :$RC_AUTOTEST_PORT" | tail -n +2 | grep -q LISTEN \
    || { echo "ERROR: teamserver not listening on $RC_AUTOTEST_PORT"; exit 1; }

  # Verify env.toml callback_host is set in the active config dir
  grep -q '^callback_host = "192.168.213.157"' "$RC_AUTOTEST_CONFIG_DIR/env.toml" \
    || { echo "ERROR: callback_host missing in $RC_AUTOTEST_CONFIG_DIR/env.toml"; exit 1; }

  # Verify SSH to both targets (5s timeout each — fast fail)
  ssh -i ~/.ssh/red_cell_test -o BatchMode=yes -o ConnectTimeout=5 \
      rctest@192.168.213.159 "uname -a" \
    || { echo "ERROR: Linux VM 192.168.213.159 unreachable"; exit 1; }
  ssh -i ~/.ssh/red_cell_test -o BatchMode=yes -o ConnectTimeout=5 \
      rctest@192.168.213.160 'exit 0' \
    || { echo "ERROR: Windows VM 192.168.213.160 unreachable"; exit 1; }

  # Put CLI on PATH for the rest of this run
  export PATH="$(pwd)/target/release:$PATH"
  red-cell-cli --version
fi
```

If any preflight step fails in manual mode: investigate, do not skip. Common
failure modes are documented in `docs/win11-ssh-setup.md`,
`docs/ubuntu-test-setup.md`, and the prior beads (`br search "preflight"`).

In loop mode, a preflight failure that is the loop's fault (build_failed,
teamserver_failed) means you skip Steps 3–5 entirely — go to Step 7.

---

## Step 4 — Run the suite

Skip this step entirely when `AUTOTEST_MODE` is `build_failed` or
`teamserver_failed` — go to Step 7 to file the bead.

```bash
TS=$(date +%Y%m%d_%H%M%S)
LOG=/tmp/rc-autotest-$TS.log
# --config-dir picks up the right env.toml/targets.toml for the active mode
# (config-autotest in loop mode, config in manual mode)
CONFIG_REL=$(realpath --relative-to=automatic-test "$RC_AUTOTEST_CONFIG_DIR")
cd automatic-test
python3 test.py --config-dir "$CONFIG_REL" --scenario all > "$LOG" 2>&1 &
TEST_PID=$!
cd ..
echo "test PID: $TEST_PID, log: $LOG"
```

The full suite takes 15–25 minutes (scenario 03 alone is ~4 minutes; each
agent-deploy scenario carries a 60–130s checkin window). Wait long enough
between progress checks to not waste turns:

```bash
# Wait until the python process actually exits — DO NOT trust any
# "background command completed" notification (those fire when the bash
# wrapper backgrounds python, not when python exits).
while pgrep -af "test.py --scenario" | grep -v grep > /dev/null; do
    sleep 60
done
echo "Run complete."
tail -5 "$LOG"
```

---

## Step 5 — Classify each failure

Read the run log and per-scenario diagnostics in
`automatic-test/test-results/<YYYY-MM-DD>/scenario_NN_failure.txt`.

### 5a — Match against KNOWN_FAILURES.md FIRST

Before any investigation, scan each scenario's error message against the
*Active* and *Resolved* tables in `automatic-test/KNOWN_FAILURES.md`:

- **Active match** — a bead is already filed (and likely in progress).
  Bump that row's `Last seen` to today, reference the bead ID in your run
  report, and **move on** without re-investigating. Do not file a duplicate.
- **Resolved match** — the prior fix should have addressed this. The fix
  did not stick: file a *new* bead describing the regression (do **not**
  reopen the resolved one) and add it to the *Active* table. Cite the
  prior commit / bead in the new bead's description.
- **No match** — proceed to 5b.

Skipping investigation on a known pattern is the whole point of this file
— don't burn turns reproducing a conclusion that's already documented.

### 5b — Investigate novel failures

For each unmatched failure, decide:

- **product bug** — agent / teamserver / CLI is genuinely wrong.
  Use the matching `zone:*` label: `zone:phantom`, `zone:demon`, `zone:archon`,
  `zone:specter`, `zone:teamserver`, `zone:client`.
- **harness bug** — scenario / mock / env handling is wrong. `zone:autotest`.
- **CLI gap** — harness reaches outside the CLI (raw `urllib`, `openssl`,
  hand-rolled JSON/CSV, direct DB or socket access where a CLI command
  should exist). `zone:cli` (often also `zone:autotest`). Per stored
  feedback, **always** file these.
- **environment** — VM / network / firewall / Defender issue specific to
  this machine. Do **not** file a bead — fix locally and document in your
  final report.
- **cascade** — same root cause as another failure already classified.
  Note the cascade in the parent bead, do not file a duplicate.

Before filing, `br search "<keyword>"` to check the bug isn't already filed.
Reuse / append to existing beads when relevant.

---

## Step 6 — Inline fixes vs beads

The user's policy: **small blocking changes for the testing process you can
make yourself; big changes need a beads issue.**

Examples of inline fixes (just do them):

- Unit-test mocks broken by a recent refactor (e.g. `_old_name` →
  `_new_name` on `MagicMock.return_value`)
- Wrong format string passed to a CLI flag (e.g. previously `fmt="elf"`
  should have been `fmt="exe"` for Phantom)
- Profile / env config drift between commits — align them
- Trivially obvious typos / off-by-one in test assertions
- Stale binary — rebuild

NOT inline (file a bead instead):

- Anything under `agent/`, `teamserver/`, `client-cli/`, or `common/`
- Any change >300 lines (per CLAUDE.md "Large Task Policy")
- Anything that changes scenario *behavior* (vs scenario plumbing)
- Anything requiring a design decision

---

## Step 7 — File beads (proactively, not just bugs)

### Loop-mode special cases

If `AUTOTEST_MODE=build_failed`, file **one** P1 bead with the gcc/rustc error
excerpt from `$RC_AUTOTEST_BUILD_LOG`. Title pattern:
*"build: cargo build --release fails — \<short error excerpt\>"*. Description:
the last 30 lines of the build log around the first `error[` or `error:` line,
plus the failing command. `zone:` label matches the failing crate (look at the
file path in the error: `teamserver/src/...` → `zone:teamserver`,
`agent/phantom/src/...` → `zone:phantom`, etc.). Then go to Step 8.

If `AUTOTEST_MODE=teamserver_failed`, the build was fine but the teamserver did
not become ready on `:$RC_AUTOTEST_PORT`. Diagnose:

```bash
ss -ltnp "sport = :$RC_AUTOTEST_PORT" | head    # is the port held by something else?
tail -30 logs/teamserver-autotest.log           # what did the teamserver say on exit?
ls -l "$RC_AUTOTEST_PROFILE"                    # does the profile exist + parse?
```

File one P2 bead with `zone:autotest` (the loop's start logic) or
`zone:teamserver` (if the teamserver itself crashed on a valid profile),
including the `ss -ltnp` output and the last 30 lines of the teamserver log.
Then go to Step 8.

### Normal-run beads

Beyond bug-fix beads, **always** file improvement beads for:

- **Test-process improvements**: failure-diagnostic gaps, slow steps that
  could be parallel, missing preflight checks, fragile assumptions
- **CLI / operator improvements**: surface gaps (no `red-cell-cli X`),
  inconsistent flag shapes, missing `--watch` / `--follow`, missing
  `--format`, missing introspection commands, persistent UX friction
- **General C2 improvements**: anything you observe in the codebase that
  would make the project safer, more reliable, or easier to operate —
  feature flags missing rollback, hard-coded values that should be config,
  missing audit log entries for sensitive operations, etc.

Each bead must have:

- A title that names the area, the symptom, and the scope (e.g.
  *"scenarios 04/06/07/11 affected"*)
- A description with the exact failure signature, the repro command,
  the hypothesis, and the proposed fix path
- Type: `bug` / `feature` / `task` / `chore`
- Priority 0–4 (most things 2–3; only file P1 for "blocks dev loop")
- Labels: at least one `zone:*` label

```bash
br create --title="..." --description="..." --type=bug --priority=2
br update <new-id> --add-label zone:autotest
br sync --flush-only
```

Sample beads from prior runs to imitate in style/depth:

- `br show red-cell-c2-yde2a` — Phantom exec output never returned (P1 product)
- `br show red-cell-c2-noq9i` — failure diagnostic listener-request count (P2 autotest)
- `br show red-cell-c2-jbj2o` — `agent shell <id>` REPL (P2 cli)
- `br show red-cell-c2-rc48g` — cert-fingerprint UX (P3 cli)

---

## Step 8 — Land the plane

Per CLAUDE.md "Landing the Plane" — work is NOT done until `git push` succeeds.

### 8a — Maintain KNOWN_FAILURES.md

Before staging anything, update `automatic-test/KNOWN_FAILURES.md`:

- For every *Active* row whose signature matched a failure this run, bump
  `Last seen` to today (YYYY-MM-DD).
- For every new bead you filed in Step 7, append a row to the *Active*
  table with the literal substring you'd use to recognize the failure
  again.
- For every *Active* bead that was closed during this run (verify with
  `br show <id>`), move that row to the *Resolved* table — populate
  `Resolved at` and a one-line `Notes` field referencing the closing
  commit or fix.
- Prune *Resolved* rows whose `Resolved at` is older than 14 days **and**
  whose signature did not match anything this run.

Commit the file in the same commit as the new beads / inline fixes — keeping
the bead state and the shortcut index moving together avoids drift.

### 8b — Stage, commit, push

```bash
git status                    # see what changed
git add <files>               # stage explicitly; do NOT use git add -A
br sync --flush-only          # flush beads to JSONL
git commit -m "..."           # use the heredoc + Co-Authored-By pattern
git pull --rebase
git push
git status                    # MUST show "up to date with origin"
```

**Never commit**:

- `automatic-test/config/env.toml` (host-specific `callback_host`)
- `automatic-test/config/targets.toml` (host-specific SSH info)
- Anything under `target/` (build artifacts)
- `.maintenance-progress.json` (dev-loop state file)

If you have local changes to gitignored files that block `git pull --rebase`,
stash them with `-- <path>`, pull, push, pop. Never blanket-stash or
`git restore` them.

---

## Step 9 — Final report

End your turn with:

- Pass / fail / skip counts (vs. the prior baseline if available)
- One-line classification of each failure
- List of beads filed (id, priority, zone, title)
- List of small things fixed inline (commit hashes)
- Anything blocking that needs human attention

Keep the report tight — the user reads commit messages and bead descriptions
for detail; the chat report is for navigation.
