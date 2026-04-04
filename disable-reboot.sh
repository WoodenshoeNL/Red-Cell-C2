#!/usr/bin/env bash
# disable-reboot.sh — prevent Ubuntu from autonomously rebooting this VM
# Run as root (sudo ./disable-reboot.sh)
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo $0" >&2
    exit 1
fi

echo "==> Disabling apt automatic update/upgrade timers and services"
systemctl disable --now unattended-upgrades.service 2>/dev/null || true
systemctl disable --now apt-daily.timer 2>/dev/null || true
systemctl disable --now apt-daily-upgrade.timer 2>/dev/null || true
systemctl disable --now apt-daily.service 2>/dev/null || true
systemctl disable --now apt-daily-upgrade.service 2>/dev/null || true

echo "==> Disabling update-notifier timers"
systemctl disable --now update-notifier-download.timer 2>/dev/null || true
systemctl disable --now update-notifier-motd.timer 2>/dev/null || true

echo "==> Disabling fwupd automatic refresh"
systemctl disable --now fwupd-refresh.timer 2>/dev/null || true
systemctl disable --now fwupd-refresh.service 2>/dev/null || true

echo "==> Configuring unattended-upgrades to never auto-reboot (belt-and-suspenders)"
APT_CONF=/etc/apt/apt.conf.d/99disable-autoreboot
cat > "$APT_CONF" <<'EOF'
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Unattended-Upgrade "0";
APT::Periodic::Download-Upgradeable-Packages "0";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
EOF
echo "    Wrote $APT_CONF"

echo "==> Holding snap-store and firmware-updater refresh indefinitely"
HOLD_DATE=$(date --date='5 years' +%Y-%m-%dT%H:%M:%S+00:00)
snap set snap-store refresh.hold="$HOLD_DATE" 2>/dev/null && echo "    snap-store held" || echo "    snap-store not found, skipping"
snap set firmware-updater refresh.hold="$HOLD_DATE" 2>/dev/null && echo "    firmware-updater held" || echo "    firmware-updater not found, skipping"

echo "==> Removing /var/run/reboot-required if present (clears pending-reboot flag)"
rm -f /var/run/reboot-required /var/run/reboot-required.pkgs

echo ""
echo "Done. The following still work normally:"
echo "  - 'sudo apt update && sudo apt upgrade'  (manual updates)"
echo "  - 'sudo snap refresh'                    (manual snap updates)"
echo "  - 'sudo reboot'                          (manual reboots)"
