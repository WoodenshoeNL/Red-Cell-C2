#!/bin/bash
# Claude QA review loop — runs every 20 minutes
# Checks Codex's work, enforces quality, creates beads issues for problems

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
LOG_FILE="$LOG_DIR/claude_qa.log"
PROMPT_FILE="$SCRIPT_DIR/CLAUDE_PROMPT.md"
SLEEP_INTERVAL=1200  # 20 minutes

mkdir -p "$LOG_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

if [ ! -f "$PROMPT_FILE" ]; then
    log "ERROR: $PROMPT_FILE not found. Exiting."
    exit 1
fi

log "========================================================"
log "  Claude QA loop starting"
log "  Prompt: $PROMPT_FILE"
log "  Log:    $LOG_FILE"
log "  Sleep:  ${SLEEP_INTERVAL}s between reviews"
log "========================================================"

while true; do
    log "=== Starting Claude QA review ==="

    # Pull latest before reviewing
    git -C "$SCRIPT_DIR" pull --rebase --quiet 2>/dev/null \
        && log "git pull: ok" \
        || log "WARNING: git pull failed, reviewing local state"

    # Run Claude QA review
    cat "$PROMPT_FILE" | claude -p \
        --dangerously-skip-permissions \
        --verbose \
        2>&1 | tee -a "$LOG_FILE"

    CLAUDE_EXIT=${PIPESTATUS[0]}
    if [ "$CLAUDE_EXIT" -ne 0 ]; then
        log "WARNING: Claude exited with code $CLAUDE_EXIT"
    else
        log "Claude review completed successfully"
    fi

    echo "" | tee -a "$LOG_FILE"
    log "========================LOOP========================="
    echo "" | tee -a "$LOG_FILE"
    log "Next review in ${SLEEP_INTERVAL}s ($(date -d "+${SLEEP_INTERVAL} seconds" '+%H:%M:%S' 2>/dev/null || date -v+${SLEEP_INTERVAL}S '+%H:%M:%S' 2>/dev/null || echo '10 minutes'))..."

    sleep "$SLEEP_INTERVAL"
done
