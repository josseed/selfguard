#!/bin/bash
# Build selfguard.app: the Swift menu bar app plus the engine (this package's dist/ and a
# pinned Node.js from macos/node.lock). The result is macos/build/selfguard.app.
#
#   scripts/build-app.sh            this Mac's architecture
#   ARCH=x64 scripts/build-app.sh   Intel build on Apple Silicon (arm64 | x64)
#
# Signing: always with the hardened runtime and macos/node.entitlements, so local builds behave
# like releases. Ad-hoc by default (runs on this Mac only); SIGN_IDENTITY="Developer ID
# Application: …" signs for distribution (then scripts/notarize-app.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MAC="$ROOT/macos"
OUT="$MAC/build"
APP="$OUT/selfguard.app"
CACHE="$MAC/.build/node"

case "${ARCH:-$(uname -m)}" in
  arm64) ARCH=arm64; SWIFT_ARCH=arm64 ;;
  x64 | x86_64) ARCH=x64; SWIFT_ARCH=x86_64 ;;
  *) echo "unsupported architecture: ${ARCH:-$(uname -m)}" >&2; exit 1 ;;
esac

NODE_VERSION="$(awk '$1 == "version" { print $2 }' "$MAC/node.lock")"
NODE_SHA="$(awk -v a="darwin-$ARCH" '$1 == "sha256" && $2 == a { print $3 }' "$MAC/node.lock")"
[[ "$NODE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$NODE_SHA" =~ ^[0-9a-f]{64}$ ]] || {
  echo "macos/node.lock has no valid entry for darwin-$ARCH" >&2
  exit 1
}
VERSION="$(node -p 'require(process.argv[1]).version' "$ROOT/package.json")"

# 1. Node.js, verified against the pinned checksum (never against a file from the same server).
NODE_DIR="node-v$NODE_VERSION-darwin-$ARCH"
TARBALL="$CACHE/$NODE_DIR.tar.gz"
mkdir -p "$CACHE"
if [[ ! -f "$TARBALL" ]] || ! echo "$NODE_SHA  $TARBALL" | shasum -a 256 -c --status; then
  echo "Downloading Node.js $NODE_VERSION ($ARCH)…"
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    -o "$TARBALL.part" "https://nodejs.org/dist/v$NODE_VERSION/$NODE_DIR.tar.gz"
  echo "$NODE_SHA  $TARBALL.part" | shasum -a 256 -c --status || {
    rm -f "$TARBALL.part"
    echo "Node.js tarball checksum mismatch: refusing it" >&2
    exit 1
  }
  mv "$TARBALL.part" "$TARBALL"
fi
EXTRACT="$(mktemp -d)"
trap 'rm -rf "$EXTRACT"' EXIT
tar -xzf "$TARBALL" -C "$EXTRACT" "$NODE_DIR/bin/node" "$NODE_DIR/LICENSE"

# 2. The engine and the Swift app.
echo "Building the engine…"
(cd "$ROOT" && npm run build --silent)
echo "Building the app ($SWIFT_ARCH)…"
(cd "$MAC" && swift build -c release --arch "$SWIFT_ARCH" >/dev/null)
BIN_DIR="$(cd "$MAC" && swift build -c release --arch "$SWIFT_ARCH" --show-bin-path)"
BIN="$BIN_DIR/Selfguard"

# 3. Assemble the bundle.
rm -rf "$APP"
ENGINE="$APP/Contents/Resources/engine"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Frameworks" "$ENGINE/bin"
cp "$BIN" "$APP/Contents/MacOS/selfguard"
# Sparkle (auto-update). Its XPC services are only for sandboxed apps; this one isn't.
ditto "$BIN_DIR/Sparkle.framework" "$APP/Contents/Frameworks/Sparkle.framework"
rm -rf "$APP/Contents/Frameworks/Sparkle.framework/Versions/B/XPCServices" "$APP/Contents/Frameworks/Sparkle.framework/XPCServices"
cp "$ROOT/src/assets/selfguard.icns" "$APP/Contents/Resources/selfguard.icns"
# Bastion's menu bar helmets (his scenes ship with the engine, in dist/ui/static/mascot).
cp -R "$MAC/Resources/mascot" "$APP/Contents/Resources/mascot"
cp "$EXTRACT/$NODE_DIR/bin/node" "$ENGINE/node"
cp "$EXTRACT/$NODE_DIR/LICENSE" "$ENGINE/NODE-LICENSE"
cp -R "$ROOT/dist" "$ENGINE/dist"
cp "$ROOT/package.json" "$ROOT/LICENSE" "$ENGINE/"
cat > "$ENGINE/bin/selfguard" <<'SH'
#!/bin/sh
# The selfguard CLI of selfguard.app, with the Node bundled in the app.
here="$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)"
exec "$here/node" "$here/dist/cli.js" "$@"
SH
chmod 755 "$ENGINE/bin/selfguard" "$ENGINE/node"
sed -e "s/@VERSION@/$VERSION/g" "$MAC/Info.plist.in" > "$APP/Contents/Info.plist"
# Updates: the latest release's appcast for this architecture, signed with the EdDSA key whose
# public half is macos/sparkle-public-key.txt (no key: no updater, e.g. a fork's build).
ED_KEY="$(tr -d '[:space:]' < "$MAC/sparkle-public-key.txt" 2>/dev/null || true)"
if [[ "$ED_KEY" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
  PLIST="$APP/Contents/Info.plist"
  plutil -insert SUFeedURL -string "https://github.com/josseed/selfguard/releases/latest/download/appcast-$ARCH.xml" "$PLIST"
  plutil -insert SUPublicEDKey -string "$ED_KEY" "$PLIST"
  plutil -insert SURequireSignedFeed -bool true "$PLIST"
  plutil -insert SUVerifyUpdateBeforeExtraction -bool true "$PLIST"
  plutil -insert SUEnableAutomaticChecks -bool true "$PLIST"
fi
plutil -lint -s "$APP/Contents/Info.plist"

# 4. Signature, inside-out: the Node binary (only allow-jit), Sparkle's helpers and framework,
# then the bundle.
IDENTITY="${SIGN_IDENTITY:--}"
SIGN=(codesign --force --options runtime --sign "$IDENTITY")
[[ "$IDENTITY" != "-" ]] && SIGN+=(--timestamp)
"${SIGN[@]}" --entitlements "$MAC/node.entitlements" "$ENGINE/node"
SPARKLE="$APP/Contents/Frameworks/Sparkle.framework"
"${SIGN[@]}" "$SPARKLE/Versions/B/Autoupdate"
"${SIGN[@]}" "$SPARKLE/Versions/B/Updater.app"
"${SIGN[@]}" "$SPARKLE"
if [[ "$IDENTITY" == "-" ]]; then
  # Ad-hoc signatures carry no Team ID, so the hardened runtime's library validation would
  # refuse to load Sparkle.framework. Local builds only: Developer ID builds keep it on.
  ADHOC_ENT="$EXTRACT/adhoc.entitlements"
  cat > "$ADHOC_ENT" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.cs.disable-library-validation</key><true/></dict></plist>
PLIST
  "${SIGN[@]}" --entitlements "$ADHOC_ENT" "$APP"
else
  "${SIGN[@]}" "$APP"
fi
codesign --verify --strict --deep "$APP"
# The signed engine must still run (it can't on another architecture without Rosetta).
if [[ "$SWIFT_ARCH" == "$(uname -m)" ]]; then
  "$ENGINE/bin/selfguard" --version >/dev/null || { echo "the signed engine doesn't run" >&2; exit 1; }
fi

echo "Built $APP ($VERSION, $ARCH, Node $NODE_VERSION, signed: ${SIGN_IDENTITY:-ad-hoc})"
