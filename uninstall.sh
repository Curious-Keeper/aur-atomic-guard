#!/usr/bin/env bash
# uninstall.sh — remove aur-atomic-guard. Leaves the scan log in place unless
# you pass --purge.

set -euo pipefail
BIN="$HOME/.local/bin"
SHARE="${XDG_DATA_HOME:-$HOME/.local/share}/aur-atomic"
UNITS="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
STATE="${XDG_STATE_HOME:-$HOME/.local/state}/aur-atomic-scan"

systemctl --user disable --now aur-atomic-scan.timer 2>/dev/null || true
rm -f "$UNITS/aur-atomic-scan.timer" "$UNITS/aur-atomic-scan.service"
systemctl --user daemon-reload 2>/dev/null || true

# Only remove our makepkg shadow, never the real one.
if [ -f "$BIN/makepkg" ] && grep -q 'makepkg-wrapper' "$BIN/makepkg" 2>/dev/null; then
    rm -f "$BIN/makepkg"
fi
rm -f "$BIN/aur-atomic-scan.sh" "$BIN/aur-prebuild-check"
rm -rf "$SHARE"

if [ "${1:-}" = "--purge" ]; then
    rm -rf "$STATE"
    echo "Removed (including scan log/state at $STATE)."
else
    echo "Removed. Scan log kept at $STATE (re-run with --purge to delete it)."
fi
