#!/bin/bash
# Notarize a Developer ID-signed selfguard.app (scripts/build-app.sh with SIGN_IDENTITY) and
# package it as a notarized, stapled DMG: macos/build/selfguard-<version>-<arch>.dmg.
#
# Needs an App Store Connect API key (Users and Access → Integrations → Team Keys, role
# "Developer"):
#   APPLE_API_KEY_PATH  the .p8 file     APPLE_API_KEY_ID  its key ID
#   APPLE_API_ISSUER    the issuer ID    SIGN_IDENTITY     same identity as the build
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/macos/build"
APP="$OUT/selfguard.app"
: "${APPLE_API_KEY_PATH:?}" "${APPLE_API_KEY_ID:?}" "${APPLE_API_ISSUER:?}" "${SIGN_IDENTITY:?}"
[[ -d "$APP" ]] || { echo "build the app first: scripts/build-app.sh" >&2; exit 1; }

VERSION="$(plutil -extract CFBundleShortVersionString raw "$APP/Contents/Info.plist")"
case "$(lipo -archs "$APP/Contents/MacOS/selfguard")" in
  arm64) ARCH=arm64 ;;
  x86_64) ARCH=x64 ;;
  *) echo "unexpected architecture" >&2; exit 1 ;;
esac
DMG="$OUT/selfguard-$VERSION-$ARCH.dmg"
NOTARY=(xcrun notarytool submit --key "$APPLE_API_KEY_PATH" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_ISSUER" --wait --timeout 30m)

# Refuse anything that isn't signed for distribution with the hardened runtime.
codesign --verify --strict --deep "$APP"
for bin in "$APP/Contents/MacOS/selfguard" "$APP/Contents/Resources/engine/node"; do
  # Captured first: `codesign | grep -q` fails under pipefail when grep exits early (SIGPIPE).
  info="$(codesign -d --verbose=2 "$bin" 2>&1)"
  grep -q "flags=.*runtime" <<<"$info" || { echo "$bin: no hardened runtime" >&2; exit 1; }
  grep -q "^Authority=Developer ID Application" <<<"$info" || { echo "$bin: not Developer ID signed" >&2; exit 1; }
done

# 1. Notarize the app, then staple the ticket so it opens offline too.
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
ditto -c -k --keepParent "$APP" "$WORK/selfguard.zip"
"${NOTARY[@]}" "$WORK/selfguard.zip"
xcrun stapler staple "$APP"

# 2. The DMG: the app and a link to /Applications in a window laid out for dragging one onto
# the other (scripts/dmg/: background, icon positions), signed, notarized and stapled.
python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' || { echo "dmgbuild needs Python 3.11+" >&2; exit 1; }
python3 -m venv "$WORK/venv"
"$WORK/venv/bin/pip" install --quiet --disable-pip-version-check --require-hashes --only-binary :all: \
  -r "$ROOT/scripts/dmg/requirements.txt"
rm -f "$DMG"
"$WORK/venv/bin/dmgbuild" -s "$ROOT/scripts/dmg/settings.py" -D app="$APP" -D root="$ROOT" \
  "selfguard $VERSION" "$DMG" >/dev/null
codesign --force --timestamp --sign "$SIGN_IDENTITY" "$DMG"
"${NOTARY[@]}" "$DMG"
xcrun stapler staple "$DMG"

spctl --assess --type open --context context:primary-signature --verbose=2 "$DMG"
spctl --assess --type execute --verbose=2 "$APP"
shasum -a 256 "$DMG"
echo "Notarized $DMG"
