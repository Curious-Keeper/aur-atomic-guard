#!/usr/bin/env bash
# aur-atomic-scan.sh — read-only IOC sweep for the "Atomic Arch" AUR
# supply-chain attack (June 2026). Covers BOTH waves:
#   wave 1: npm install atomic-lockfile -> src/hooks/deps ELF + eBPF rootkit
#   wave 2: bun install js-digest       -> embedded ELF (evades npm signature)
# plus the second-stage Monero cryptominer. Read-only; makes NO changes.
# Exit 0 = clean, 2 = indicators found.

set -uo pipefail
H="$HOME"
STATE="${XDG_STATE_HOME:-$H/.local/state}/aur-atomic-scan"
LOG="$STATE/scan.log"
PKGLIST="$STATE/package_list.txt"   # optional: drop the community list here
mkdir -p "$STATE"

HITS=0
ts()   { date '+%Y-%m-%dT%H:%M:%S%z'; }
hit()  { HITS=$((HITS + 1)); echo "[$(ts)] HIT: $*" | tee -a "$LOG" >&2; }
note() { echo "[$(ts)] $*" >>"$LOG"; }

# --- IOCs (single source of truth, shared with aur-prebuild-check) -----------
IOCS="${XDG_DATA_HOME:-$H/.local/share}/aur-atomic/iocs.sh"
if ! . "$IOCS" 2>/dev/null; then
    note "ERROR — IOC file $IOCS missing; scan skipped this run"
    exit 0
fi

note "scan start"

# Optional self-expiry: set AUR_ATOMIC_EXPIRE=YYYYMMDD (env or the systemd
# unit) to auto-disable the timer once the incident window closes. Unset by
# default — the scanner runs until you uninstall it.
EXPIRE="${AUR_ATOMIC_EXPIRE:-}"
if [ -n "$EXPIRE" ] && [ "$(date +%Y%m%d)" -ge "$EXPIRE" ]; then
    note "past expiry $EXPIRE — disabling timer, no further scans"
    command -v notify-send >/dev/null 2>&1 \
        && notify-send "AUR malware scan" "Expired ($EXPIRE) — auto-disabled."
    systemctl --user disable --now aur-atomic-scan.timer 2>/dev/null
    exit 0
fi

# 1. Malicious npm/bun packages & payload on disk
while IFS= read -r f; do hit "package/payload artifact: $f"; done < <(
    find "$H" /usr/lib/node_modules /usr/local/lib/node_modules -maxdepth 7 \
        \( -name atomic-lockfile -o -name js-digest \) 2>/dev/null
    find "$H" /tmp /var/tmp -path '*hooks/deps' 2>/dev/null
)

# 2. IOC strings in AUR build dirs, bun/npm caches, shell history.
#    Scoped to where malware actually leaves traces — NOT all of ~/.config,
#    which produces false positives from editor local-history of these very
#    scripts. systemd-unit persistence is covered separately by check 4.
while IFS= read -r f; do hit "IOC string in: $f"; done < <(
    grep -rIlsE "$SOURCE_RE" \
        "$H/.cache/yay" "$H/.cache/paru" "$H/.bun" "$H/.cache/bun" \
        "$H/.npm" "$H/.bash_history" "$H/.zsh_history" 2>/dev/null
)

# 3. eBPF rootkit pinned maps
for m in hidden_pids hidden_names hidden_inodes; do
    [ -e "/sys/fs/bpf/$m" ] && hit "eBPF map /sys/fs/bpf/$m"
done

# 4. Malware-style systemd persistence (Restart=always + /var/lib/<random>)
while IFS= read -r u; do
    grep -qi "Restart=always" "$u" 2>/dev/null \
        && grep -qiE "ExecStart=.*/var/lib/[A-Za-z0-9]{6,}" "$u" 2>/dev/null \
        && hit "suspicious unit: $u"
done < <(grep -rilsE "RestartSec=30" /etc/systemd/system \
    "$H/.config/systemd/user" 2>/dev/null)

# 5. Recently-dropped executables at /var/lib top level
while IFS= read -r f; do hit "dropped exec: $f"; done < <(
    find /var/lib -maxdepth 1 -type f -executable -size +500k 2>/dev/null
)

# 6. Second stage: Monero cryptominer
for p in /usr/bin/monero-wallet-gui /usr/local/bin/monero-wallet-gui \
         "$H/.local/bin/monero-wallet-gui"; do
    [ -e "$p" ] && ! pacman -Qo "$p" >/dev/null 2>&1 \
        && hit "unowned monero-wallet-gui (possible miner): $p"
done
if command -v pgrep >/dev/null 2>&1; then
    while IFS= read -r line; do hit "miner process: $line"; done < <(
        pgrep -a -iE "xmrig|monerod|minerd|stratum" 2>/dev/null)
fi

# 7. C2 / exfil / mining egress
if command -v ss >/dev/null 2>&1; then
    while IFS= read -r line; do hit "suspicious egress: $line"; done < <(
        ss -tnp 2>/dev/null \
            | grep -iE "$ONION|temp\.sh|:3333|:4444|:5555|:7777|:14444|:14433")
fi

# 8. Hash match across likely drop dirs (size-prefiltered for speed)
while IFS= read -r f; do
    s="$(sha256sum "$f" 2>/dev/null | awk '{print $1}')"
    grep -qx "$s" <<<"$HASHES" && hit "payload hash match: $f"
done < <(find "$H/.cache" "$H/.npm" "$H/.bun" /tmp /var/tmp /var/lib \
    -type f -size +2900k -size -3100k 2>/dev/null)

# 9. Cross-reference installed foreign packages vs the compromised list
#    (only if a local copy of the list has been provided at $PKGLIST)
if [ -s "$PKGLIST" ]; then
    while IFS= read -r p; do
        grep -qxF "$p" "$PKGLIST" && hit "installed pkg on compromised list: $p"
    done < <(pacman -Qmq 2>/dev/null)
else
    note "no $PKGLIST present — package-name cross-reference skipped"
fi

if [ "$HITS" -gt 0 ]; then
    note "scan end — $HITS INDICATOR(S) FOUND"
    command -v notify-send >/dev/null 2>&1 \
        && notify-send -u critical "AUR malware scan" \
            "$HITS indicator(s) found — see $LOG"
    exit 2
fi

note "scan end — clean"
exit 0
