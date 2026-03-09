#!/bin/bash
# Claude development loop — picks up beads tasks and implements them using Claude
#
# Usage:
#   ./claude_dev_loop.sh         # run forever
#   ./claude_dev_loop.sh 5       # run exactly 5 loops then exit

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
LOG_FILE="$LOG_DIR/claude_dev.log"
DEV_PROMPT_FILE="$SCRIPT_DIR/CLAUDE_DEV_PROMPT.md"
RUNTIME_PROMPT_DIR="/tmp"
SLEEP_ON_NO_WORK=60   # seconds to wait when no tasks are ready
SLEEP_BETWEEN_TASKS=15 # seconds between task iterations

MAX_LOOPS="${1:-0}"   # 0 = run forever
LOOP_COUNT=0

mkdir -p "$LOG_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

if [ ! -f "$DEV_PROMPT_FILE" ]; then
    log "ERROR: $DEV_PROMPT_FILE not found. Exiting."
    exit 1
fi

if [ "$MAX_LOOPS" -gt 0 ] 2>/dev/null; then
    log "========================================================"
    log "  Claude development loop starting (max $MAX_LOOPS loops)"
    log "  Prompt template: $DEV_PROMPT_FILE"
    log "  Log: $LOG_FILE"
    log "========================================================"
else
    log "========================================================"
    log "  Claude development loop starting (unlimited)"
    log "  Prompt template: $DEV_PROMPT_FILE"
    log "  Log: $LOG_FILE"
    log "========================================================"
fi

while true; do
    # Check loop limit
    if [ "$MAX_LOOPS" -gt 0 ] 2>/dev/null; then
        if [ "$LOOP_COUNT" -ge "$MAX_LOOPS" ]; then
            log "Reached max loops ($MAX_LOOPS). Exiting."
            exit 0
        fi
        log "=== Claude dev loop iteration $((LOOP_COUNT + 1)) of $MAX_LOOPS ==="
    else
        log "=== Starting Claude dev loop iteration $((LOOP_COUNT + 1)) ==="
    fi

    # Pull latest before picking up work
    git -C "$SCRIPT_DIR" pull --rebase --quiet 2>/dev/null \
        && log "git pull: ok" \
        || log "WARNING: git pull failed, continuing with local state"

    # Import any new issues from JSONL (in case another agent pushed changes)
    br sync --import-only --quiet 2>/dev/null \
        && log "br sync import: ok" \
        || log "WARNING: br sync import failed, continuing"

    # Find the next task: prefer non-epic tasks, highest priority first
    NEXT_ID=$(br ready --json 2>/dev/null | python3 -c "
import sys, json
try:
    issues = json.load(sys.stdin)
    # Prefer actionable task types over epics
    tasks = [i for i in issues if i.get('issue_type', 'task') not in ('epic',)]
    pool = tasks if tasks else issues
    if pool:
        print(pool[0]['id'])
except Exception:
    pass
" 2>/dev/null || true)

    if [ -z "$NEXT_ID" ]; then
        log "No ready work found. Sleeping ${SLEEP_ON_NO_WORK}s..."
        sleep "$SLEEP_ON_NO_WORK"
        continue
    fi

    log "Next task: $NEXT_ID"

    # Get full task details
    TASK_DETAILS=$(br show "$NEXT_ID" 2>/dev/null || echo "See issue ID: $NEXT_ID")

    # Get ready list for context (top 15)
    READY_LIST=$(br ready 2>/dev/null | head -15 || echo "Unable to fetch ready list")

    # Get in-progress list
    IN_PROGRESS=$(br list --status=in_progress 2>/dev/null || echo "None")

    # Build runtime prompt
    RUNTIME_PROMPT="$RUNTIME_PROMPT_DIR/red_cell_claude_dev_$(date +%s)_$$.md"

    cat > "$RUNTIME_PROMPT" << HEREDOC
$(cat "$DEV_PROMPT_FILE")

---

## Your Current Task

**Issue ID**: \`$NEXT_ID\`

$TASK_DETAILS

---

## Current Beads State

### Ready to Work (unblocked, top 15)
$READY_LIST

### Currently In Progress
$IN_PROGRESS

---

Start by claiming this task:

\`\`\`bash
br update $NEXT_ID --status=in_progress
\`\`\`

Then implement it fully following the workflow in this prompt.
HEREDOC

    log "Running Claude on task $NEXT_ID..."

    cat "$RUNTIME_PROMPT" | claude -p \
        --dangerously-skip-permissions \
        --verbose \
        2>&1 | tee -a "$LOG_FILE"

    CLAUDE_EXIT=${PIPESTATUS[0]}
    if [ "$CLAUDE_EXIT" -ne 0 ]; then
        log "WARNING: Claude exited with code $CLAUDE_EXIT for task $NEXT_ID"
    else
        log "Claude completed task $NEXT_ID"
    fi

    # Clean up runtime prompt
    rm -f "$RUNTIME_PROMPT"

    LOOP_COUNT=$((LOOP_COUNT + 1))
    log "========================LOOP========================="
    sleep "$SLEEP_BETWEEN_TASKS"
done
