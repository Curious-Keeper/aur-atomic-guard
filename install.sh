#!/usr/bin/env bash
# install.sh — install aur-atomic-guard for the current user (no root needed).
# Idempotent: safe to re-run to update.

set -euo pipefail
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$HOME/.local/bin"
SHARE="${XDG_DATA_HOME:-$HOME/.local/share}/aur-atomic"
UNITS="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"

command -v pacman >/dev/null 2>&1 || {
    echo "This tool targets Arch Linux (pacman not found). Aborting." >&2
    exit 1; }

echo "Installing to:"
echo "  scripts : $BIN"
echo "  iocs    : $SHARE"
echo "  units   : $UNITS"
mkdir -p "$BIN" "$SHARE" "$UNITS"

install -m 0644 "$SRC/share/iocs.sh"             "$SHARE/iocs.sh"
install -m 0755 "$SRC/bin/aur-atomic-scan.sh"    "$BIN/aur-atomic-scan.sh"
install -m 0755 "$SRC/bin/aur-prebuild-check"    "$BIN/aur-prebuild-check"
install -m 0755 "$SRC/wrappers/makepkg"          "$BIN/makepkg"
install -m 0644 "$SRC/systemd/aur-atomic-scan.service" "$UNITS/"
install -m 0644 "$SRC/systemd/aur-atomic-scan.timer"   "$UNITS/"

# The makepkg gate only works if ~/.local/bin precedes /usr/bin in PATH.
case ":$PATH:" in
    *":$BIN:"*)
        before="$(awk -v b="$BIN" -v u="/usr/bin" 'BEGIN{
            n=split(ENVIRON["PATH"],a,":"); for(i=1;i<=n;i++){
                if(a[i]==b&&!ub)bb=i; if(a[i]==u&&!ub)ub=i }
            print (bb&&ub&&bb<ub)?"yes":"no" }')"
        [ "$before" = "yes" ] || cat >&2 <<EOF

WARNING: $BIN does not appear before /usr/bin in PATH.
The makepkg pre-build gate will NOT intercept builds until it does.
Fix by putting ~/.local/bin first in your shell PATH, then re-login.
EOF
        ;;
    *) echo >&2 "WARNING: $BIN is not in PATH; add it so the gate works." ;;
esac

systemctl --user daemon-reload
systemctl --user enable --now aur-atomic-scan.timer

echo
echo "Installed. The scanner runs every 2h; the makepkg gate is active."
echo "Run a scan now:   aur-atomic-scan.sh ; echo exit=\$?"
echo "Optional list:    curl -fsSL <package_list_url> -o $SHARE/../../state/aur-atomic-scan/package_list.txt"
echo "Uninstall:        $SRC/uninstall.sh"
