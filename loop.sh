#!/bin/bash
# Wrapper for loop.py that runs it as a transient systemd *user service*
# (--unit, NOT --scope) so the loop survives the launching terminal being
# closed or OOM-killed by systemd-oomd. Also marks the unit
# ManagedOOMPreference=avoid so oomd itself won't pick it as a victim.
#
# Background: a --scope is parented under the calling terminal's
# vte-spawn-<uuid>.scope cgroup. When oomd kills the terminal scope under
# memory pressure, every --scope inside it dies too. A --unit is parented
# directly under user@.service and is independent of any terminal.
#
# Output:
#   - file:    logs/<agent>_<loop>.log (loop.py writes this directly)
#   - journal: journalctl --user -u <unit> -f
#
# Manage:
#   list:  systemctl --user list-units 'loop-*.service'
#   stop:  systemctl --user stop <unit>
#
# Falls back to running loop.py directly if systemd-run is unavailable.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$(uv python find --managed-python 3.12 2>/dev/null || echo python3)"

# Derive a unit name from --agent / --loop / --zone so concurrent loops don't
# collide. Example: --agent claude --loop dev --zone teamserver
#               -> loop-claude-dev-teamserver.service
suffix=""
prev=""
for arg in "$@"; do
    case "$prev" in
        --agent|--loop|--zone) suffix="${suffix}-${arg}" ;;
    esac
    prev="$arg"
done
unit="loop${suffix:--$(date +%H%M%S)}"

if ! command -v systemd-run &>/dev/null; then
    exec "$PYTHON" "$SCRIPT_DIR/loop.py" "$@"
fi

if systemctl --user is-active --quiet "${unit}.service"; then
    echo "ERROR: ${unit}.service is already running." >&2
    echo "  stop:  systemctl --user stop ${unit}" >&2
    echo "  logs:  journalctl --user -u ${unit} -f" >&2
    exit 1
fi

systemd-run --user --quiet \
    --unit="${unit}" \
    --description="Red-Cell-C2 ${unit}" \
    --working-directory="${SCRIPT_DIR}" \
    -p ManagedOOMPreference=avoid \
    --collect \
    -- "$PYTHON" "$SCRIPT_DIR/loop.py" "$@"

cat <<EOF
Started ${unit}.service — tailing its journal below.
  Ctrl-C stops the tail only; the loop keeps running.
  resume tail:  journalctl --user -u ${unit} -f
  stop loop:    systemctl --user stop ${unit}
----
EOF
exec journalctl --user -u "${unit}" -n 100 -f
