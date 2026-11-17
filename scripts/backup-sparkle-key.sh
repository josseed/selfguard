#!/bin/bash
# Back up the Sparkle EdDSA private key (login Keychain) into Bitwarden, then verify it.
#
#   scripts/backup-sparkle-key.sh
#
# Needs `bw` logged in (it asks for the master password to unlock) and Sparkle's tools
# (macos/.build/artifacts, created by `swift build` in macos/). The key only touches disk for a
# moment, in a private temporary folder that is always removed, and is never printed.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GEN="$ROOT/macos/.build/artifacts/sparkle/Sparkle/bin/generate_keys"
NAME="selfguard · Sparkle EdDSA private key"
PUBLIC="$(tr -d '[:space:]' < "$ROOT/macos/sparkle-public-key.txt")"
[[ -x "$GEN" ]] || { echo "Sparkle's tools are missing: run 'swift build' in macos/ first" >&2; exit 1; }

D="$(mktemp -d)"
cleanup() { rm -rf "$D"; bw lock >/dev/null 2>&1 || true; }
trap cleanup EXIT

# 1. Export from the Keychain (generate_keys refuses a file that already exists).
"$GEN" -x "$D/key" >/dev/null
KEY="$(tr -d '[:space:]' < "$D/key")"
rm -f "$D/key"
if [[ ! "$KEY" =~ ^([A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{86}==)$ ]]; then
  echo "✗ the export doesn't look like an EdDSA key: nothing was saved" >&2
  exit 1
fi
# The Keychain key must be the one the app trusts.
[[ "$("$GEN" -p 2>/dev/null | tr -d '[:space:]')" == "$PUBLIC" ]] || { echo "✗ the Keychain key doesn't match macos/sparkle-public-key.txt" >&2; exit 1; }

# 2. Unlock Bitwarden (asks for the master password).
BW_SESSION="$(bw unlock --raw)"
export BW_SESSION
bw sync >/dev/null

NOTES="Signs selfguard.app updates (secret SPARKLE_ED_PRIVATE_KEY in the macos-release environment).
Public key: $PUBLIC

$KEY"

# 3. Update the existing item, or create it.
ID="$(bw list items --search "$NAME" | jq -r --arg n "$NAME" 'map(select(.name == $n)) | .[0].id // empty')"
if [[ -n "$ID" ]]; then
  bw get item "$ID" | jq --arg notes "$NOTES" '.notes = $notes' | bw encode | bw edit item "$ID" >/dev/null
else
  ID="$(bw get template item | jq --arg n "$NAME" --arg notes "$NOTES" \
    '.type = 2 | .secureNote = {type: 0} | .login = null | .name = $n | .notes = $notes' \
    | bw encode | bw create item | jq -r .id)"
fi

# 4. Verify: read it back from the server copy and compare (prints only the result).
bw sync >/dev/null
if [[ "$(bw get notes "$ID" | tail -n 1 | tr -d '[:space:]')" == "$KEY" ]]; then
  echo "✓ backup saved and verified: \"$NAME\" in Bitwarden"
else
  echo "✗ the saved note doesn't match the key" >&2
  exit 1
fi
