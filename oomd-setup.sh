#!/bin/bash
# Raise the systemd-oomd memory-pressure kill threshold from 50% to 90%.
# Run once per VM with sudo. Idempotent.
#
# Background: cargo builds push user-slice memory pressure past oomd's default
# 50% threshold for >20s, causing it to kill the terminal scope running loop.py.

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[ok]${NC}    $*"; }
warn() { echo -e "${YELLOW}[warn]${NC}  $*"; }

OOMD_DROPIN="/etc/systemd/oomd.conf.d/dev-threshold.conf"

if [[ "$EUID" -ne 0 ]]; then
    echo "Re-running with sudo..."
    exec sudo "$0" "$@"
fi

if [[ -f "$OOMD_DROPIN" ]] && grep -q "DefaultMemoryPressureLimit=90%" "$OOMD_DROPIN" 2>/dev/null; then
    ok "oomd threshold already set to 90% — nothing to do"
    exit 0
fi

warn "Setting oomd memory-pressure threshold to 90%..."
mkdir -p "$(dirname "$OOMD_DROPIN")"
cat > "$OOMD_DROPIN" <<'EOF'
[OOM]
DefaultMemoryPressureLimit=90%
EOF

systemctl restart systemd-oomd
ok "oomd threshold set to 90% (drop-in: $OOMD_DROPIN)"
