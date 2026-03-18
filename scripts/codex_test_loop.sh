#!/bin/bash
# Codex test coverage loop — runs every 30 minutes
# Systematically scans public API surface for untested functions.
# Creates beads issues for coverage gaps — does NOT write test code itself.
#
# Usage:
#   ./codex_test_loop.sh          # run forever
#   ./codex_test_loop.sh 3        # run exactly 3 reviews then exit

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
LOOP_LOG="$LOG_DIR/codex_test.log"
PROMPT_FILE="$SCRIPT_DIR/CODEX_TEST_PROMPT.md"
SLEEP_INTERVAL=1800  # 30 minutes

MAX_LOOPS="${1:-0}"   # 0 = run forever
LOOP_COUNT=0

mkdir -p "$LOG_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOOP_LOG"
}

if [ ! -f "$PROMPT_FILE" ]; then
    log "ERROR: $PROMPT_FILE not found. Exiting."
    exit 1
fi

if [ "$MAX_LOOPS" -gt 0 ] 2>/dev/null; then
    log "========================================================"
    log "  Codex test coverage loop starting (max $MAX_LOOPS runs)"
    log "  Prompt:   $PROMPT_FILE"
    log "  Loop log: $LOOP_LOG"
    log "  Interval: ${SLEEP_INTERVAL}s"
    log "========================================================"
else
    log "========================================================"
    log "  Codex test coverage loop starting (unlimited)"
    log "  Prompt:   $PROMPT_FILE"
    log "  Loop log: $LOOP_LOG"
    log "  Interval: ${SLEEP_INTERVAL}s"
    log "========================================================"
fi

while true; do
    if [ -f "$SCRIPT_DIR/.stop" ]; then
        log "STOP signal detected (.stop file exists). Exiting."
        exit 0
    fi

    if [ "$MAX_LOOPS" -gt 0 ] 2>/dev/null; then
        if [ "$LOOP_COUNT" -ge "$MAX_LOOPS" ]; then
            log "Reached max runs ($MAX_LOOPS). Exiting."
            exit 0
        fi
        log "=== Test coverage review run $((LOOP_COUNT + 1)) of $MAX_LOOPS ==="
    else
        log "=== Test coverage review run $((LOOP_COUNT + 1)) ==="
    fi

    git -C "$SCRIPT_DIR" pull --rebase --quiet 2>/dev/null \
        && log "git pull: ok" \
        || log "WARNING: git pull failed, reviewing local state"

    RUN_TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"
    RUN_LOG="$LOG_DIR/codex_test_review_${RUN_TIMESTAMP}.log"
    log "Run log: $RUN_LOG"

    codex exec \
        --dangerously-bypass-approvals-and-sandbox \
        < "$PROMPT_FILE" \
        2>&1 | tee "$RUN_LOG" | tee -a "$LOOP_LOG"

    CODEX_EXIT="${PIPESTATUS[0]}"
    if [ "$CODEX_EXIT" -ne 0 ]; then
        log "WARNING: Codex exited with code $CODEX_EXIT"
    else
        log "Test coverage review completed successfully"
    fi

    LOOP_COUNT=$((LOOP_COUNT + 1))

    if [ -f "$SCRIPT_DIR/.stop" ]; then
        log "STOP signal detected after review. Exiting."
        exit 0
    fi

    NEXT_RUN="$(date -d "+${SLEEP_INTERVAL} seconds" '+%H:%M:%S' 2>/dev/null \
        || date -v+${SLEEP_INTERVAL}S '+%H:%M:%S' 2>/dev/null \
        || echo "30 minutes from now")"

    log "========================LOOP========================="
    log "Next review in 30m (at ${NEXT_RUN})"
    log ""

    sleep "$SLEEP_INTERVAL"
done
