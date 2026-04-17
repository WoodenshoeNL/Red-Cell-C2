#!/bin/bash
# Install a logrotate config for the Red-Cell-C2 loop logs.
# Run once per VM with sudo. Idempotent.
#
# Background: loop.py appends forever to logs/<agent>_<loop>.log. Long-running
# loops (claude_dev in particular) can grow these to hundreds of MB. This
# config rotates them daily or at 50 MB, keeps 7 compressed backups, and uses
# copytruncate so the file handle loop.py holds open during a single iteration
# (cargo builds can take 30+ min) keeps writing to the same inode.
#
# Picked up automatically by Ubuntu's stock /etc/cron.daily/logrotate — no
# timer or extra cron entry needed.

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[ok]${NC}    $*"; }
warn() { echo -e "${YELLOW}[warn]${NC}  $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGS_DIR="${SCRIPT_DIR}/logs"

# Detect the repo owner BEFORE re-execing under sudo, so we don't end up
# reading "root" from a sudo-owned environment.
REPO_USER="$(stat -c '%U' "$SCRIPT_DIR")"
REPO_GROUP="$(stat -c '%G' "$SCRIPT_DIR")"

if [[ "$EUID" -ne 0 ]]; then
    echo "Re-running with sudo..."
    exec sudo REPO_USER="$REPO_USER" REPO_GROUP="$REPO_GROUP" "$0" "$@"
fi

DROPIN="/etc/logrotate.d/red-cell-c2-loops"
# `su` directive is required because the repo dir is group-writable (typical
# for a user clone); without it logrotate refuses to touch the logs.
#
# Glob `*[!0-9].log` matches the rolling per-loop logs (claude_dev.log,
# codex_arch.log, maintenance.log, …) but skips the per-run timestamped logs
# (codex_arch_20260414_210118.log, …) which already self-rotate by name.
WANT=$(cat <<EOF
${LOGS_DIR}/*[!0-9].log {
    su ${REPO_USER} ${REPO_GROUP}
    daily
    size 50M
    rotate 7
    compress
    delaycompress
    copytruncate
    missingok
    notifempty
    nocreate
}
EOF
)

if [[ -f "$DROPIN" ]] && [[ "$(cat "$DROPIN")" == "$WANT" ]]; then
    ok "logrotate config already installed at $DROPIN"
else
    warn "Writing logrotate config to $DROPIN..."
    printf '%s\n' "$WANT" > "$DROPIN"
    chmod 0644 "$DROPIN"
    ok "logrotate config installed ($DROPIN)"
fi

# Validate: --debug parses the config without rotating.
if logrotate --debug "$DROPIN" >/dev/null 2>&1; then
    ok "logrotate config parses cleanly"
else
    warn "logrotate --debug reported errors:"
    logrotate --debug "$DROPIN" || true
    exit 1
fi

ok "done — Ubuntu's daily cron will run rotations automatically"
echo "  test now: sudo logrotate -f $DROPIN"
