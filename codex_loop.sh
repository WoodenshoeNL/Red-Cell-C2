#!/bin/bash
# Codex development loop — picks up beads tasks and implements them
#
# Safe to run on multiple VMs simultaneously. Uses optimistic git locking to
# prevent two agents from claiming the same task.
#
# Usage:
#   ./codex_loop.sh          # run forever
#   ./codex_loop.sh 5        # run exactly 5 loops then exit

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
LOG_FILE="$LOG_DIR/codex_dev.log"
CODEX_PROMPT_FILE="$SCRIPT_DIR/CODEX_PROMPT.md"
RUNTIME_PROMPT_DIR="/tmp"
CLAIM_LOCK_FILE="$SCRIPT_DIR/.agent-claim.lock"
SLEEP_ON_NO_WORK=60   # seconds to wait when no tasks are ready
SLEEP_BETWEEN_TASKS=15 # seconds between task iterations
STALE_THRESHOLD=7200  # seconds before an in_progress task is considered stuck (2h)

# Unique identity for this agent instance — used in git commit messages and logs
# so it is always clear which machine/agent did what.
AGENT_ID="${HOSTNAME:-unknown}-codex"

MAX_LOOPS="${1:-0}"   # 0 = run forever
LOOP_COUNT=0

mkdir -p "$LOG_DIR"
exec 9>"$CLAIM_LOCK_FILE"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$AGENT_ID] $*" | tee -a "$LOG_FILE"
}

# Detect DB schema drift (e.g. missing columns added in newer br versions)
# and rebuild from JSONL if needed.
repair_db_if_needed() {
    local test_output
    test_output=$(br stats --json 2>&1)
    if echo "$test_output" | grep -q '"code": "DATABASE_ERROR"'; then
        log "DB schema error detected — rebuilding from JSONL"
        local db_path="$SCRIPT_DIR/.beads/beads.db"
        rm -f "$db_path" "$db_path-wal" "$db_path-shm" 2>/dev/null
        if br sync --import-only --rename-prefix --quiet 2>/dev/null; then
            log "DB rebuilt successfully"
        else
            log "WARNING: DB rebuild failed"
        fi
    fi
}

issue_status() {
    local task_id="$1"

    br show "$task_id" --json 2>/dev/null | python3 -c '
import json
import sys

try:
    issues = json.load(sys.stdin)
    if issues:
        print(issues[0].get("status", ""))
except Exception:
    pass
'
}

issue_status_from_jsonl() {
    local task_id="$1"

    CLAIM_TASK_ID="$task_id" CLAIM_JSONL="$SCRIPT_DIR/.beads/issues.jsonl" \
        python3 -c "
import json, os
tid = os.environ['CLAIM_TASK_ID']
last = None
try:
    with open(os.environ['CLAIM_JSONL']) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    e = json.loads(line)
                    if e.get('id') == tid:
                        last = e
                except Exception:
                    pass
    print((last or {}).get('status', ''))
except Exception:
    pass
" 2>/dev/null
}

# Claim a task with optimistic git locking.
# Immediately pushes the claim commit so other agents see it.
# Returns 0 on success, 1 if another agent beat us to it.
claim_task() {
    local task_id="$1"
    local head_before
    local claim_commit
    local claim_status

    head_before=$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null) || return 1

    # Pre-claim check: read the raw JSONL directly to detect stale beads DB.
    # br sync --import-only can miss another agent's claim (their in_progress
    # entry is in issues.jsonl after git pull, but the local SQLite DB still
    # shows open). br update would then write a new entry with a fresh
    # updated_at timestamp, making git diff --quiet pass despite no real
    # status change — causing a double-claim. Bypass the DB entirely here.
    local pre_status
    pre_status=$(issue_status_from_jsonl "$task_id")
    if [ "$pre_status" = "in_progress" ]; then
        log "CLAIM SKIP: $task_id already in_progress in JSONL (stale DB) — forcing DB rebuild"
        # br sync --import-only skips when the JSONL hash is cached as current,
        # leaving the DB/JSONL mismatch intact. Delete and rebuild to fix it.
        local db_path="$SCRIPT_DIR/.beads/beads.db"
        rm -f "$db_path" "$db_path-wal" "$db_path-shm" 2>/dev/null
        br sync --import-only --rename-prefix --quiet 2>/dev/null || true
        return 1
    fi

    br update "$task_id" --status=in_progress 2>/dev/null || return 1
    br sync --flush-only 2>/dev/null || return 1

    if git -C "$SCRIPT_DIR" diff --quiet -- .beads/issues.jsonl; then
        log "CLAIM SKIP: $task_id produced no issue change locally; refreshing issue state"
        br sync --import-only --rename-prefix --quiet 2>/dev/null || true
        return 1
    fi

    git -C "$SCRIPT_DIR" add .beads/issues.jsonl
    if ! git -C "$SCRIPT_DIR" commit -m "chore: claim $task_id [$AGENT_ID]" --quiet; then
        log "CLAIM SKIP: failed to create claim commit for $task_id"
        git -C "$SCRIPT_DIR" restore --staged .beads/issues.jsonl 2>/dev/null || true
        git -C "$SCRIPT_DIR" checkout -- .beads/issues.jsonl 2>/dev/null || true
        br sync --import-only --rename-prefix --quiet 2>/dev/null || true
        return 1
    fi
    claim_commit=$(git -C "$SCRIPT_DIR" rev-parse HEAD 2>/dev/null) || return 1

    if git -C "$SCRIPT_DIR" push --quiet 2>/dev/null; then
        if ! git -C "$SCRIPT_DIR" pull --ff-only --quiet 2>/dev/null; then
            log "CLAIM VERIFY FAILED: could not refresh git state after claiming $task_id"
            return 1
        fi

        br sync --import-only --rename-prefix --quiet 2>/dev/null || true

        if ! git -C "$SCRIPT_DIR" merge-base --is-ancestor "$claim_commit" HEAD 2>/dev/null; then
            log "CLAIM VERIFY FAILED: claim commit for $task_id is no longer on the current branch"
            return 1
        fi

        claim_status=$(issue_status "$task_id")
        if [ "$claim_status" != "in_progress" ]; then
            log "CLAIM VERIFY FAILED: expected $task_id to be in_progress after claim, found '${claim_status:-unknown}'"
            return 1
        fi

        return 0
    fi

    # Push failed — another agent pushed first. Undo our commit and restore
    # the remote state so the next iteration starts clean.
    log "CLAIM CONFLICT: another agent claimed $task_id first — releasing"
    git -C "$SCRIPT_DIR" reset "$head_before" --mixed --quiet
    git -C "$SCRIPT_DIR" checkout -- .beads/issues.jsonl
    git -C "$SCRIPT_DIR" pull --ff-only --quiet 2>/dev/null || true
    br sync --import-only --rename-prefix --quiet 2>/dev/null || true
    return 1
}

# Reset any tasks that have been stuck in_progress longer than STALE_THRESHOLD
reset_stuck_tasks() {
    local stuck
    stuck=$(br list --status=in_progress --json 2>/dev/null | python3 -c "
import sys, json
from datetime import datetime, timezone

threshold = $STALE_THRESHOLD
now = datetime.now(timezone.utc)
try:
    issues = json.load(sys.stdin)
    for issue in issues:
        ts = issue.get('updated_at') or issue.get('created_at', '')
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                if (now - dt).total_seconds() > threshold:
                    print(issue['id'])
            except ValueError:
                pass
except Exception:
    pass
" 2>/dev/null || true)

    if [ -n "$stuck" ]; then
        for stuck_id in $stuck; do
            log "SAFEGUARD: $stuck_id stuck in_progress for >${STALE_THRESHOLD}s — resetting to open"
            br update "$stuck_id" --status=open \
                2>/dev/null \
                && log "SAFEGUARD: $stuck_id reset to open" \
                || log "WARNING: failed to reset $stuck_id"
        done
    fi
}

if [ ! -f "$CODEX_PROMPT_FILE" ]; then
    log "ERROR: $CODEX_PROMPT_FILE not found. Exiting."
    exit 1
fi

if [ "$MAX_LOOPS" -gt 0 ] 2>/dev/null; then
    log "========================================================"
    log "  Codex development loop starting (max $MAX_LOOPS loops)"
    log "  Agent ID: $AGENT_ID"
    log "  Prompt template: $CODEX_PROMPT_FILE"
    log "  Log: $LOG_FILE"
    log "========================================================"
else
    log "========================================================"
    log "  Codex development loop starting (unlimited)"
    log "  Agent ID: $AGENT_ID"
    log "  Prompt template: $CODEX_PROMPT_FILE"
    log "  Log: $LOG_FILE"
    log "========================================================"
fi

while true; do
    # ── Stop signal ────────────────────────────────────────────────────────────
    if [ -f "$SCRIPT_DIR/.stop" ]; then
        log "STOP signal detected (.stop file exists). Exiting."
        exit 0
    fi

    # ── Loop limit ─────────────────────────────────────────────────────────────
    if [ "$MAX_LOOPS" -gt 0 ] 2>/dev/null; then
        if [ "$LOOP_COUNT" -ge "$MAX_LOOPS" ]; then
            log "Reached max loops ($MAX_LOOPS). Exiting."
            exit 0
        fi
        log "=== Codex loop iteration $((LOOP_COUNT + 1)) of $MAX_LOOPS ==="
    else
        log "=== Starting Codex loop iteration $((LOOP_COUNT + 1)) ==="
    fi
    LOOP_COUNT=$((LOOP_COUNT + 1))

    if ! flock -x 9; then
        log "WARNING: failed to acquire local claim lock"
        sleep "$SLEEP_ON_NO_WORK"
        continue
    fi

    # ── Pull latest ────────────────────────────────────────────────────────────
    if git -C "$SCRIPT_DIR" pull --ff-only --quiet 2>/dev/null; then
        log "git pull --ff-only: ok"
    else
        log "WARNING: git pull --ff-only failed; skipping iteration until repo state is synced"
        flock -u 9
        sleep "$SLEEP_ON_NO_WORK"
        continue
    fi

    # Import any new issues from JSONL (picks up claims by other agents).
    # --rename-prefix normalises any red-xxx IDs from other VMs to red-cell-c2-xxx.
    br sync --import-only --rename-prefix --quiet 2>/dev/null \
        && log "br sync import: ok" \
        || log "WARNING: br sync import failed, continuing"

    # If --rename-prefix renamed IDs, the DB is now ahead of JSONL and the
    # Stale DB Guard will block every subsequent flush.  Detect this by
    # attempting a normal flush; if it fails with CONFIG_ERROR, force-flush
    # and commit so the JSONL is normalised once and for all.
    if ! br sync --flush-only --quiet 2>/dev/null; then
        if br sync --flush-only --force --quiet 2>/dev/null; then
            if ! git -C "$SCRIPT_DIR" diff --quiet -- .beads/issues.jsonl; then
                git -C "$SCRIPT_DIR" add .beads/issues.jsonl
                git -C "$SCRIPT_DIR" commit -m "chore: normalize issue IDs to red-cell-c2 prefix [$AGENT_ID]" --quiet \
                    && git -C "$SCRIPT_DIR" push --quiet 2>/dev/null \
                    && log "Normalized issue IDs in JSONL and pushed" \
                    || log "WARNING: could not push normalized JSONL"
            fi
        fi
    fi

    # Heal DB schema drift (new br version may require columns not yet in DB)
    repair_db_if_needed

    # ── Reset stuck tasks ──────────────────────────────────────────────────────
    reset_stuck_tasks

    # ── Pick next task ─────────────────────────────────────────────────────────
    READY_CANDIDATES=$(br ready --json 2>/dev/null | python3 -c "
import sys, json
try:
    issues = json.load(sys.stdin)
    tasks = [i for i in issues if i.get('issue_type', 'task') not in ('epic',)]
    pool = tasks if tasks else issues
    for issue in pool[:20]:
        print(issue['id'])
except Exception:
    pass
" 2>/dev/null || true)

    if [ -z "$READY_CANDIDATES" ]; then
        log "No ready work found. Sleeping ${SLEEP_ON_NO_WORK}s..."
        flock -u 9
        sleep "$SLEEP_ON_NO_WORK"
        continue
    fi

    # ── Claim with optimistic locking ──────────────────────────────────────────
    NEXT_ID=""
    while IFS= read -r candidate_id; do
        [ -n "$candidate_id" ] || continue

        if [ "$(issue_status_from_jsonl "$candidate_id")" = "in_progress" ]; then
            log "Skipping candidate already in_progress in JSONL: $candidate_id"
            continue
        fi

        log "Selected task: $candidate_id"
        if claim_task "$candidate_id"; then
            NEXT_ID="$candidate_id"
            break
        fi
    done << EOF
$READY_CANDIDATES
EOF

    if [ -z "$NEXT_ID" ]; then
        flock -u 9
        log "Could not claim any ready task — retrying after backoff"
        sleep $((5 + RANDOM % 20))
        continue
    fi
    flock -u 9

    log "Claimed $NEXT_ID"

    # ── Build runtime prompt ───────────────────────────────────────────────────
    TASK_DETAILS=$(br show "$NEXT_ID" 2>/dev/null || echo "See issue ID: $NEXT_ID")
    READY_LIST=$(br ready 2>/dev/null | head -15 || echo "Unable to fetch ready list")
    IN_PROGRESS=$(br list --status=in_progress 2>/dev/null || echo "None")

    RUNTIME_PROMPT="$RUNTIME_PROMPT_DIR/red_cell_codex_$(date +%s)_$$.md"

    cat > "$RUNTIME_PROMPT" << HEREDOC
$(cat "$CODEX_PROMPT_FILE")

---

## Your Current Task

**Issue ID**: \`$NEXT_ID\`
**Agent**: \`$AGENT_ID\`

$TASK_DETAILS

---

## Current Beads State

### Ready to Work (unblocked, top 15)
$READY_LIST

### Currently In Progress
$IN_PROGRESS

---

**IMPORTANT**: This task has already been claimed by the loop script.
Do NOT run \`br update $NEXT_ID --status=in_progress\` — it is already \`in_progress\`.
Start directly with understanding the task and implementing it.
HEREDOC

    log "Running Codex on task $NEXT_ID..."

    codex exec \
        --dangerously-bypass-approvals-and-sandbox \
        < "$RUNTIME_PROMPT" \
        2>&1 | tee -a "$LOG_FILE"

    CODEX_EXIT=${PIPESTATUS[0]}
    if [ "$CODEX_EXIT" -ne 0 ]; then
        log "WARNING: Codex exited with code $CODEX_EXIT for task $NEXT_ID"
    else
        log "Codex completed task $NEXT_ID"
    fi

    rm -f "$RUNTIME_PROMPT"
    log "========================LOOP========================="
    sleep "$SLEEP_BETWEEN_TASKS"
done
