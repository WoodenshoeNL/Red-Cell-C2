#!/bin/bash
# Codex development loop — picks up beads tasks and implements them
# Runs continuously, one task per iteration

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
LOG_FILE="$LOG_DIR/codex_dev.log"
CODEX_PROMPT_FILE="$SCRIPT_DIR/CODEX_PROMPT.md"
RUNTIME_PROMPT_DIR="/tmp"
SLEEP_ON_NO_WORK=60   # seconds to wait when no tasks are ready
SLEEP_BETWEEN_TASKS=15 # seconds between task iterations

mkdir -p "$LOG_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

if [ ! -f "$CODEX_PROMPT_FILE" ]; then
    log "ERROR: $CODEX_PROMPT_FILE not found. Exiting."
    exit 1
fi

log "========================================================"
log "  Codex development loop starting"
log "  Prompt template: $CODEX_PROMPT_FILE"
log "  Log: $LOG_FILE"
log "========================================================"

while true; do
    log "=== Starting Codex loop iteration ==="

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
    RUNTIME_PROMPT="$RUNTIME_PROMPT_DIR/red_cell_codex_$(date +%s)_$$.md"

    cat > "$RUNTIME_PROMPT" << HEREDOC
$(cat "$CODEX_PROMPT_FILE")

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

    # Clean up runtime prompt
    rm -f "$RUNTIME_PROMPT"

    log "========================LOOP========================="
    sleep "$SLEEP_BETWEEN_TASKS"
done
