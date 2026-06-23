# iocs.sh — single source of truth for AUR supply-chain IOCs. Sourced by
# aur-atomic-scan.sh and aur-prebuild-check. Shell fragment only: defines
# variables, runs nothing. Covers three 2026-era AUR campaigns:
#   1. "Atomic Arch" — npm/bun infostealer (atomic-lockfile / js-digest / …)
#   2. Chaos RAT      — fake "patched browser" packages (account danikpapas)
#   3. Russian spam   — shell-rc spam/profanity injection (non-weaponized)

# Onion C2: stable prefix only (sources disagree on later chars).
ONION="olrh4mibs62l6kkuvvjyc5lrer"

# npm/bun publisher + AUR maintainer + git commit-author strings.
# Synced 2026-06-23 with lenucksi/aur-malware-check data/iocs (fixed custodiatovar
# and fardewoak spellings; added confirmed wave-1 maintainers franziskaweber,
# tobiaswesterburg, ellenmyklebust). Excludes arojas (impersonated, legit) and
# monitoring-only accounts ivonahruskova/simongeisler (no malicious commits yet).
ACCOUNTS="herbsobering|krisztinavarga|custodiatovar|veramagalhaes|PLYSHKA|fardewoak|franziskaweber|tobiaswesterburg|ellenmyklebust"

# Injected-installer signatures (the exact lines added to trojaned PKGBUILDs).
# Campaign now also uses `bun add` and pnpm/yarn — match the family broadly.
INSTALLERS="(npm|bun|pnpm|yarn) (install|add|i) .*(atomic-lockfile|js-digest|lockfile-js|nextfile-js)"

# Malicious package names and on-disk payload path. Names expand as the
# campaign evolves (aur-general thread DWY3WBOI…): atomic-lockfile, js-digest,
# lockfile-js, nextfile-js.
PKGNAMES="atomic-lockfile|js-digest|lockfile-js|nextfile-js"
PAYLOAD_PATH="src/hooks/deps"

# Payload SHA256s (community IOCs; secondary — may carry transcription noise).
HASHES="6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b
7883bda1ff15425f2dbe622c45a3ae105ddfa6175009bbf0b0cad9bf5c79b316
47893d9badc38c54b71321263ce8178c1abb10396e0aadf9793e61ec8829e204"

# --- Chaos RAT campaign (distinct incident; fake "patched browser" packages) -
# Account `danikpapas` uploaded firefox-patch-bin / librewolf-fix-bin /
# zen-browser-patched-bin (and similar) whose PKGBUILD pulled a malicious
# `patches` git source from github.com/danikpapas/* (e.g. zenbrowser-patch.git),
# running Chaos RAT during the build. Package names are caught by the scanner's
# compromised-list cross-reference (check 9); this string catches the source-side
# IOC in a PKGBUILD before it ever builds.
CHAOS_RE="danikpapas|zenbrowser-patch"

# --- Russian-spam campaign (June 2026; shell-rc injection, non-weaponized) ----
# ~144 packages whose PKGBUILD/.install appended Russian/profanity echo lines to
# the user's personal shell rc files at install time. A package build
# redirecting into a user's rc file is the signature — legitimate builds never
# do this. Block-grade for the pre-build gate ONLY (kept out of SOURCE_RE so the
# scanner's shell-history grep, where such redirections are normal user
# activity, does not false-positive).
SPAM_RC_RE='(>>?|tee( -a)?)[[:space:]]*"?(~|\$HOME|\$\{HOME\}|/home/[^/[:space:]]+)/\.(bashrc|bash_profile|zshrc|zprofile|zshenv|profile)|(>>?|tee( -a)?)[[:space:]]*"?[^"[:space:]]*/\.config/fish/(config\.fish|conf\.d)'

# HARD-BLOCK regex for source review: any hit is an unambiguous campaign IOC.
SOURCE_RE="${PKGNAMES}|${PAYLOAD_PATH}|${ONION}|${ACCOUNTS}|${INSTALLERS}|${CHAOS_RE}"

# Pre-build gate block set = SOURCE_RE plus the shell-rc-injection shape. Used
# only by aur-prebuild-check (scans PKGBUILD/.install/.SRCINFO), never by the
# scanner's cache/history grep.
BUILD_BLOCK_RE="${SOURCE_RE}|${SPAM_RC_RE}"

# WARN regex: generic supply-chain-injection shapes. Legit packages sometimes
# match (e.g. real npm builds), so these warn rather than block.
GENERIC_RE='(npm|bun|pnpm|yarn) (install|add|i)\b|npx |bunx |curl [^|]*\|[[:space:]]*(ba)?sh|wget [^|]*\|[[:space:]]*(ba)?sh|base64 -d[^|]*\|[[:space:]]*(ba)?sh|\.onion'
