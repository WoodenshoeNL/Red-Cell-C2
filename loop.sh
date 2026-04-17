#!/bin/bash
# Wrapper for loop.py.
#
# Default (no --service):
#   Runs loop.py in the foreground in the current terminal. Output is live.
#   Closing the terminal or oomd killing the terminal scope kills the loop.
#
# With --service:
#   Runs loop.py as a transient systemd *user service* (--unit, NOT --scope)
#   so it survives the launching terminal being closed or OOM-killed by
#   systemd-oomd. Marks the unit ManagedOOMPreference=avoid. After starting,
#   tails the unit's journal — Ctrl-C stops only the tail, not the loop.
#
#   Background: a --scope is parented under the calling terminal's
#   vte-spawn-<uuid>.scope cgroup; when oomd kills that scope under memory
#   pressure, every --scope inside it dies too. A --unit is parented directly
#   under user@.service and is independent of any terminal.
#
#   Service mode commands:
#     list:  systemctl --user list-units 'loop-*.service'
#     stop:  systemctl --user stop <unit>
#     tail:  journalctl --user -u <unit> -f

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="$(uv python find --managed-python 3.12 2>/dev/null || echo python3)"

# Strip our own --service flag from args before passing them to loop.py.
service_mode=0
args=()
for arg in "$@"; do
    case "$arg" in
        --service) service_mode=1 ;;
        *) args+=("$arg") ;;
    esac
done
if [[ "${#args[@]}" -gt 0 ]]; then
    set -- "${args[@]}"
else
    set --
fi

if [[ "$service_mode" -eq 0 ]]; then
    exec "$PYTHON" "$SCRIPT_DIR/loop.py" "$@"
fi

# --- service mode below ---

if ! command -v systemd-run &>/dev/null; then
    echo "ERROR: --service requires systemd-run, not found in PATH" >&2
    exit 1
fi

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
