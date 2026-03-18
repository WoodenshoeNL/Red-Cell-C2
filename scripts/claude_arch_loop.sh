#!/bin/bash
# Claude architecture review loop
#
# Runs a deep, independent code analysis every ~1 hour (with jitter).
# Does not look at recent commits — reads the project as it stands.
# Files beads issues for anything found.
#
# Usage:
#   ./claude_arch_loop.sh          # run forever
#   ./claude_arch_loop.sh 3        # run exactly 3 reviews then exit

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
LOOP_LOG="$LOG_DIR/claude_arch.log"
PROMPT_FILE="$SCRIPT_DIR/CLAUDE_ARCH_PROMPT.md"

# Interval jitter: sleep a random number of seconds between MIN and MAX
INTERVAL_MIN=6300   # 105 minutes
INTERVAL_MAX=8100   # 135 minutes

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

log "========================================================"
log "  Claude architecture review loop starting"
log "  Prompt:   $PROMPT_FILE"
log "  Loop log: $LOOP_LOG"
log "  Interval: ${INTERVAL_MIN}s–${INTERVAL_MAX}s (random)"
if [ "$MAX_LOOPS" -gt 0 ] 2>/dev/null; then
    log "  Max runs: $MAX_LOOPS"
else
    log "  Max runs: unlimited"
fi
log "========================================================"

while true; do
    # ── Stop signal ────────────────────────────────────────────────────────────
    if [ -f "$SCRIPT_DIR/.stop" ]; then
        log "STOP signal detected (.stop file exists). Exiting."
        exit 0
    fi

    # ── Loop limit ─────────────────────────────────────────────────────────────
    if [ "$MAX_LOOPS" -gt 0 ] 2>/dev/null; then
        if [ "$LOOP_COUNT" -ge "$MAX_LOOPS" ]; then
            log "Reached max runs ($MAX_LOOPS). Exiting."
            exit 0
        fi
        log "=== Architecture review run $((LOOP_COUNT + 1)) of $MAX_LOOPS ==="
    else
        log "=== Architecture review run $((LOOP_COUNT + 1)) ==="
    fi

    # ── Pull latest ────────────────────────────────────────────────────────────
    git -C "$SCRIPT_DIR" pull --rebase --quiet 2>/dev/null \
        && log "git pull: ok" \
        || log "WARNING: git pull failed, reviewing local state"

    # ── Per-run log file ───────────────────────────────────────────────────────
    RUN_TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"
    RUN_LOG="$LOG_DIR/arch_review_${RUN_TIMESTAMP}.log"
    log "Run log: $RUN_LOG"

    # ── Run Claude ─────────────────────────────────────────────────────────────
    cat "$PROMPT_FILE" | claude -p \
        --dangerously-skip-permissions \
        --verbose \
        2>&1 | tee "$RUN_LOG" | tee -a "$LOOP_LOG"

    CLAUDE_EXIT="${PIPESTATUS[0]}"
    if [ "$CLAUDE_EXIT" -ne 0 ]; then
        log "WARNING: Claude exited with code $CLAUDE_EXIT"
    else
        log "Architecture review completed successfully"
    fi

    LOOP_COUNT=$((LOOP_COUNT + 1))

    # ── Check stop signal again before sleeping ────────────────────────────────
    if [ -f "$SCRIPT_DIR/.stop" ]; then
        log "STOP signal detected after review. Exiting."
        exit 0
    fi

    # ── Random sleep interval ──────────────────────────────────────────────────
    SLEEP_SECS=$(( INTERVAL_MIN + RANDOM % (INTERVAL_MAX - INTERVAL_MIN) ))
    SLEEP_MINS=$(( SLEEP_SECS / 60 ))
    NEXT_RUN="$(date -d "+${SLEEP_SECS} seconds" '+%H:%M:%S' 2>/dev/null \
        || date -v+${SLEEP_SECS}S '+%H:%M:%S' 2>/dev/null \
        || echo "~${SLEEP_MINS} minutes from now")"

    log "========================LOOP========================="
    log "Next review in ${SLEEP_MINS}m (at ${NEXT_RUN})"
    log ""

    sleep "$SLEEP_SECS"
done
