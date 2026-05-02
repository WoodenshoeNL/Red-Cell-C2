#!/bin/bash
# Maintenance loop — keeps the dev VM healthy.
#
# Runs hourly checks:
#   - disk space
#   - git pull/push state
#   - stale cargo / loop processes
#   - /tmp/red-cell-agent-registry-*.sqlite cleanup (autotest leaves ~5/sec)
#   - /tmp/red-cell-* / qa-target-* stranded scratch dirs
#   - .beads/issues.jsonl uncommitted sweeps
#
# Safe to run alongside dev/qa/arch/autotest loops — that is its design point.
#
# Usage:
#   ./scripts/claude_maintenance_loop.sh      # run forever, 60-min interval
#   ./scripts/claude_maintenance_loop.sh 5    # run exactly 5 cycles then exit

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MAX_ITERS="${1:-0}"

exec "$SCRIPT_DIR/loop.py" --loop maintenance --iterations "$MAX_ITERS"
