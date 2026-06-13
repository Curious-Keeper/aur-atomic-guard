# aur-atomic-guard

Detection **and prevention** for the June 2026 *"Atomic Arch"* AUR supply-chain
attack, in which a malicious actor adopted ~1,500 orphaned [AUR](https://aur.archlinux.org/)
packages and modified their `PKGBUILD`s to silently run `npm install
atomic-lockfile` (wave 1) or `bun install js-digest` (wave 2) — pulling a Linux
credential stealer with an optional eBPF rootkit and a second-stage Monero
cryptominer.

This is a small, dependency-free, user-level (no root) toolkit for Arch Linux.
It does two things:

| Layer | Tool | What it does |
|-------|------|--------------|
| **Prevent** | `makepkg` wrapper → `aur-prebuild-check` | Scans a package's `PKGBUILD`/`.install`/`.SRCINFO` *before* `makepkg` runs any of its code. Aborts the build on a confirmed campaign IOC. |
| **Detect** | `aur-atomic-scan.sh` (systemd timer) | Read-only sweep for on-disk artifacts, persistence, the miner, C2 egress, and known payload hashes. Runs every 2h. |

Both share one IOC definition file (`share/iocs.sh`) so they never drift apart.

## What it checks

**Pre-build gate** (`aur-prebuild-check`) — two tiers:
- **Block** (aborts the build) on unambiguous campaign IOCs: the malicious npm/bun
  package names, the `src/hooks/deps` payload path, the onion C2, the attacker
  accounts (`herbsobering`, `krisztinavarga`, `custodiatover`, `veramagalhaes`,
  `PLYSHKA`, `fardewoalk`), and the exact injected installer lines.
- **Warn** (build proceeds) on generic supply-chain shapes (`npm install …`,
  `curl … | sh`, `.onion`, …) so legitimate node-based packages aren't blocked.

**Background scanner** (`aur-atomic-scan.sh`):
1. Malicious npm/bun packages & `hooks/deps` payload on disk
2. IOC strings in AUR build dirs, npm/bun caches, shell history
3. eBPF rootkit pinned maps (`/sys/fs/bpf/hidden_*`)
4. Malware-style systemd persistence (`Restart=always` + `/var/lib/<random>`)
5. Dropped executables at `/var/lib` top level
6. Second-stage Monero miner (unowned `monero-wallet-gui`, `xmrig`/stratum procs)
7. C2 / exfil / mining egress
8. Known payload SHA256 matches
9. Installed packages vs the compromised list (optional, see below)

## Install

```sh
git clone https://github.com/Curious-Keeper/aur-atomic-guard
cd aur-atomic-guard
./install.sh
```

Installs to `~/.local/bin`, `~/.local/share/aur-atomic`, and
`~/.config/systemd/user` (all user-level, no root). The `makepkg` gate requires
`~/.local/bin` to **precede** `/usr/bin` in your `PATH`; `install.sh` warns if it
doesn't.

Run a scan immediately:
```sh
aur-atomic-scan.sh ; echo "exit=$?"   # 0 = clean, 2 = indicators found
```

## Optional: package-name cross-reference

Drop a copy of the community compromised-package list to enable check #9:
```sh
curl -fsSL <list-url> -o ~/.local/state/aur-atomic-scan/package_list.txt
```

## Optional: auto-expiry

The scanner can disable itself once the incident window closes. Set a date
(`YYYYMMDD`) via the environment or the systemd unit — it's **off by default**:
```ini
# ~/.config/systemd/user/aur-atomic-scan.service
Environment=AUR_ATOMIC_EXPIRE=20260620
```

## Uninstall

```sh
./uninstall.sh           # keeps the scan log
./uninstall.sh --purge   # also removes the log/state
```
Removing `~/.local/bin/makepkg` restores normal builds; the real
`/usr/bin/makepkg` is never touched.

## Limitations (read these)

- **Signature-based, not heuristic.** Every string/hash/account/onion is keyed to
  *this* campaign as currently reported. A renamed payload, new C2, or fresh
  account evades the string/hash checks. The behavioral checks (eBPF maps,
  persistence units, `/var/lib` droppers, miner processes) are more resilient.
- **Local artifacts only.** It inspects your machine; it does not query the AUR
  or vet packages you haven't built.
- **The gate assumes `paru`/`yay` call `makepkg` by name** (their default). An
  absolute `--makepkg` path bypasses it.
- IOC hashes are transcribed from community reports and may carry noise; names,
  paths, and accounts are the primary signal.

This is a stop-gap for one incident, not a substitute for not rebuilding AUR
packages until Arch confirms the purge is complete.

## Sources & credits

- Arch `aur-general` mailing-list report thread
- [ioctl.fail — preliminary analysis of AUR malware](https://ioctl.fail/preliminary-analysis-of-aur-malware/)
- [Sonatype — "Atomic Arch" analysis](https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency)
- [lenucksi/aur-malware-check](https://github.com/lenucksi/aur-malware-check) (consolidated IOCs / package list)

## License

MIT — see [LICENSE](LICENSE).
