# Claude Autotest — Red Cell C2

You are a QA agent. Your job is to run the full automatic-test suite end-to-end
against both target VMs (Linux + Windows), classify every failure, file beads
issues for everything that warrants one, and commit the results so the dev loop
can pick them up.

**Unlike the qa/arch/quality review loops, you ARE allowed to write code — but
only for small, blocking test-process fixes.** Anything bigger goes to a beads
issue. See "Inline fixes vs beads" below for the boundary.

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

## Step 0 — Stop signal

```bash
if [ -f .stop ]; then echo "STOP signal detected. Exiting."; exit 0; fi
```

---

## Step 1 — Orient

```bash
cat AGENTS.md
cat automatic-test/README.md
cat automatic-test/PROMPTS/AGENT_TEST_PROMPT.md   # canonical workflow doc
br ready                                           # what is the dev loop working on?
```

---

## Step 2 — Environment context

Hard-coded values for this VM. Verify they still apply before relying on them.

- Linux target: `192.168.213.159` (user `rctest`)
- Windows target: `192.168.213.160` (user `rctest`)
- Dev-box callback IP: `192.168.213.157`
- SSH key: `~/.ssh/red_cell_test`
- Teamserver profile: `profiles/test.yaotl` (canonical test profile;
  do **not** use `havoc.yaotl` — operator names and ports differ from `env.toml`)
- Teamserver port: `127.0.0.1:40056`
- Test operator: `test-operator` / api_key `changeme-api-key`

`automatic-test/config/env.toml` and `targets.toml` are **both gitignored** —
host-specific. If either is missing, the harness auto-seeds `env.toml` from
`env.toml.example` on first run, but `[server].callback_host` must be set
manually to the dev-box IP above; otherwise Demon/Archon `CONFIG_BYTES` bake
`127.0.0.1` and agents on the VMs call their own loopback.

---

## Step 3 — Preflight (fail loud, do not paper over)

```bash
git pull --rebase

# Rebuild only when source has changed since target/release/red-cell was built.
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

# Teamserver: restart if not running, or if running an older binary.
TS_PID=$(pgrep -af 'target/release/red-cell --profile' | grep -v grep | awk '{print $1}' | head -1)
RESTART=0
if [ -z "$TS_PID" ]; then
  RESTART=1
elif [ "$(stat -c %Y target/release/red-cell)" -gt "$(ps -o lstart= -p $TS_PID | xargs -I{} date -d "{}" +%s)" ]; then
  RESTART=1
fi
if [ "$RESTART" = "1" ]; then
  pkill -f 'target/release/red-cell' || true
  sleep 2
  ./target/release/red-cell --profile profiles/test.yaotl > logs/teamserver.log 2>&1 &
  sleep 5
  tail -3 logs/teamserver.log
fi

# Verify teamserver is listening
ss -ltn 'sport = :40056' | tail -n +2 | grep -q LISTEN \
  || { echo "ERROR: teamserver not listening on 40056"; exit 1; }

# Verify env.toml callback_host is set
grep -q '^callback_host = "192.168.213.157"' automatic-test/config/env.toml \
  || { echo "ERROR: callback_host missing in env.toml"; exit 1; }

# Verify SSH to both targets (5s timeout each — fast fail)
ssh -i ~/.ssh/red_cell_test -o BatchMode=yes -o ConnectTimeout=5 \
    rctest@192.168.213.159 "uname -a" \
  || { echo "ERROR: Linux VM 192.168.213.159 unreachable"; exit 1; }
ssh -i ~/.ssh/red_cell_test -o BatchMode=yes -o ConnectTimeout=5 \
    rctest@192.168.213.160 'powershell -Command "ver"' \
  || { echo "ERROR: Windows VM 192.168.213.160 unreachable"; exit 1; }

# Put CLI on PATH for the rest of this run
export PATH="$(pwd)/target/release:$PATH"
red-cell-cli --version
```

If any preflight step fails: investigate, do not skip. Common failure modes
are documented in `docs/win11-ssh-setup.md`, `docs/ubuntu-test-setup.md`, and
the prior beads (`br search "preflight"`).

---

## Step 4 — Run the suite

```bash
TS=$(date +%Y%m%d_%H%M%S)
LOG=/tmp/rc-autotest-$TS.log
cd automatic-test
python3 test.py --scenario all > "$LOG" 2>&1 &
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

For each ✗ FAILED scenario decide:

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
