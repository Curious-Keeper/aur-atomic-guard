# iocs.sh — single source of truth for the "Atomic Arch" AUR supply-chain
# attack (June 2026). Sourced by aur-atomic-scan.sh and aur-prebuild-check.
# Shell fragment only: defines variables, runs nothing.

# Onion C2: stable prefix only (sources disagree on later chars).
ONION="olrh4mibs62l6kkuvvjyc5lrer"

# npm/bun publisher + AUR maintainer + git commit-author strings.
ACCOUNTS="herbsobering|krisztinavarga|custodiatover|veramagalhaes|PLYSHKA|fardewoalk"

# Injected-installer signatures (the exact lines added to trojaned PKGBUILDs).
INSTALLERS="npm install .*atomic-lockfile|bun install .*js-digest"

# Malicious package names and on-disk payload path.
PKGNAMES="atomic-lockfile|js-digest"
PAYLOAD_PATH="src/hooks/deps"

# Payload SHA256s (community IOCs; secondary — may carry transcription noise).
HASHES="6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b
7883bda1ff15425f2dbe622c45a3ae105ddfa6175009bbf0b0cad9bf5c79b316
47893d9badc38c54b71321263ce8178c1abb10396e0aadf9793e61ec8829e204"

# HARD-BLOCK regex for source review: any hit is an unambiguous campaign IOC.
SOURCE_RE="${PKGNAMES}|${PAYLOAD_PATH}|${ONION}|${ACCOUNTS}|${INSTALLERS}"

# WARN regex: generic supply-chain-injection shapes. Legit packages sometimes
# match (e.g. real npm builds), so these warn rather than block.
GENERIC_RE='(npm|bun|pnpm|yarn) (install|add|i)\b|npx |bunx |curl [^|]*\|[[:space:]]*(ba)?sh|wget [^|]*\|[[:space:]]*(ba)?sh|base64 -d[^|]*\|[[:space:]]*(ba)?sh|\.onion'
