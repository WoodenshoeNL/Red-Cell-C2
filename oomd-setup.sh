#!/bin/bash
# Raise the systemd-oomd memory-pressure kill threshold from 50% to 90%
# and protect gnome-terminal sessions from being killed by oomd.
# Run once per VM with sudo. Idempotent.
#
# Background: cargo builds push user-slice memory pressure past oomd's default
# 50% threshold for >20s, causing it to kill terminal scopes and eventually
# gnome-shell itself. Two layers of protection:
#   1. Raise the per-unit threshold on user@.service from 50% → 90%
#      (the oomd.conf DefaultMemoryPressureLimit is ignored when a per-unit
#       ManagedOOMMemoryPressureLimit is set, which Ubuntu ships at 50%)
#   2. Mark gnome-terminal scopes with ManagedOOMPreference=avoid so oomd
#      deprioritises them even when pressure exceeds the threshold

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[ok]${NC}    $*"; }
warn() { echo -e "${YELLOW}[warn]${NC}  $*"; }

if [[ "$EUID" -ne 0 ]]; then
    echo "Re-running with sudo..."
    exec sudo "$0" "$@"
fi

CHANGED=0

# --- 1. Raise DefaultMemoryPressureLimit (belt-and-suspenders) ----------------
OOMD_DROPIN="/etc/systemd/oomd.conf.d/dev-threshold.conf"
if [[ -f "$OOMD_DROPIN" ]] && grep -q "DefaultMemoryPressureLimit=90%" "$OOMD_DROPIN" 2>/dev/null; then
    ok "oomd default threshold already 90%"
else
    warn "Setting oomd default threshold to 90%..."
    mkdir -p "$(dirname "$OOMD_DROPIN")"
    cat > "$OOMD_DROPIN" <<'EOF'
[OOM]
DefaultMemoryPressureLimit=90%
EOF
    CHANGED=1
    ok "oomd default threshold set to 90% ($OOMD_DROPIN)"
fi

# --- 2. Override the per-unit 50% limit on user@.service ---------------------
USER_DROPIN="/etc/systemd/system/user@.service.d/oomd-dev-threshold.conf"
if [[ -f "$USER_DROPIN" ]] && grep -q "ManagedOOMMemoryPressureLimit=90%" "$USER_DROPIN" 2>/dev/null; then
    ok "user@.service threshold already 90%"
else
    warn "Overriding user@.service oomd threshold to 90%..."
    mkdir -p "$(dirname "$USER_DROPIN")"
    cat > "$USER_DROPIN" <<'EOF'
[Service]
ManagedOOMMemoryPressureLimit=90%
EOF
    CHANGED=1
    ok "user@.service threshold set to 90% ($USER_DROPIN)"
fi

# --- 3. Protect gnome-terminal from oomd via user-level drop-in ---------------
GT_DROPIN_DIR="/etc/systemd/user/gnome-terminal-server.service.d"
GT_DROPIN="$GT_DROPIN_DIR/oomd-avoid.conf"
if [[ -f "$GT_DROPIN" ]] && grep -q "ManagedOOMPreference=avoid" "$GT_DROPIN" 2>/dev/null; then
    ok "gnome-terminal already protected from oomd"
else
    warn "Protecting gnome-terminal from oomd..."
    mkdir -p "$GT_DROPIN_DIR"
    cat > "$GT_DROPIN" <<'EOF'
[Service]
ManagedOOMPreference=avoid
EOF
    CHANGED=1
    ok "gnome-terminal marked ManagedOOMPreference=avoid ($GT_DROPIN)"
fi

# --- Apply changes -----------------------------------------------------------
if [[ "$CHANGED" -eq 1 ]]; then
    systemctl daemon-reload
    systemctl restart systemd-oomd
    ok "oomd restarted with new settings"
else
    ok "nothing to change"
fi
