#!/bin/bash
# Wrapper for loop.py that protects the process from systemd-oomd.
# Usage: ./loop.sh [loop.py args...]
#
# Runs loop.py inside a transient systemd scope with ManagedOOMPreference=avoid
# so oomd will not kill it during cargo builds, without needing a service file
# or sudo. Falls back to running loop.py directly if systemd-run is unavailable.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$(uv python find --managed-python 3.12 2>/dev/null || echo python3)"

if command -v systemd-run &>/dev/null; then
    exec systemd-run --user --scope -p ManagedOOMPreference=avoid -- \
        "$PYTHON" "$SCRIPT_DIR/loop.py" "$@"
else
    exec "$PYTHON" "$SCRIPT_DIR/loop.py" "$@"
fi
