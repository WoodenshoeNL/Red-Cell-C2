#!/bin/bash
# Codex QA review loop — runs every 20 minutes
# Reviews recent commits, checks build health, files beads issues, updates scorecard

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
LOG_FILE="$LOG_DIR/codex_qa.log"
PROMPT_FILE="$SCRIPT_DIR/CODEX_QA_PROMPT.md"
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
log "  Codex QA loop starting"
log "  Prompt: $PROMPT_FILE"
log "  Log:    $LOG_FILE"
log "  Sleep:  ${SLEEP_INTERVAL}s between reviews"
log "========================================================"

while true; do
    if [ -f "$SCRIPT_DIR/.stop" ]; then
        log "STOP signal detected (.stop file exists). Exiting."
        exit 0
    fi

    log "=== Starting Codex QA review ==="

    git -C "$SCRIPT_DIR" pull --rebase --quiet 2>/dev/null \
        && log "git pull: ok" \
        || log "WARNING: git pull failed, reviewing local state"

    codex exec \
        --dangerously-bypass-approvals-and-sandbox \
        < "$PROMPT_FILE" \
        2>&1 | tee -a "$LOG_FILE"

    CODEX_EXIT=${PIPESTATUS[0]}
    if [ "$CODEX_EXIT" -ne 0 ]; then
        log "WARNING: Codex exited with code $CODEX_EXIT"
    else
        log "Codex QA review completed successfully"
    fi

    echo "" | tee -a "$LOG_FILE"
    log "========================LOOP========================="
    echo "" | tee -a "$LOG_FILE"
    log "Next review in ${SLEEP_INTERVAL}s ($(date -d "+${SLEEP_INTERVAL} seconds" '+%H:%M:%S' 2>/dev/null || date -v+${SLEEP_INTERVAL}S '+%H:%M:%S' 2>/dev/null || echo '20 minutes'))..."

    sleep "$SLEEP_INTERVAL"
done
