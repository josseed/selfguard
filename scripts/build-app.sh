#!/bin/bash
# Build selfguard.app: the Swift menu bar app plus the engine (this package's dist/ and a
# pinned Node.js from macos/node.lock). The result is macos/build/selfguard.app.
#
#   scripts/build-app.sh            this Mac's architecture
#   ARCH=x64 scripts/build-app.sh   Intel build on Apple Silicon (arm64 | x64)
#
# Signing: ad-hoc by default (runs on this Mac only). Release signing and notarization are
# done in CI.
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
BIN="$(cd "$MAC" && swift build -c release --arch "$SWIFT_ARCH" --show-bin-path)/Selfguard"

# 3. Assemble the bundle.
rm -rf "$APP"
ENGINE="$APP/Contents/Resources/engine"
mkdir -p "$APP/Contents/MacOS" "$ENGINE/bin"
cp "$BIN" "$APP/Contents/MacOS/selfguard"
cp "$ROOT/src/assets/selfguard.icns" "$APP/Contents/Resources/selfguard.icns"
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
plutil -lint -s "$APP/Contents/Info.plist"

# 4. Ad-hoc signature, inside-out (release builds are signed in CI).
codesign --force --sign - "$ENGINE/node"
codesign --force --sign - "$APP"
codesign --verify --strict "$APP"

echo "Built $APP ($VERSION, $ARCH, Node $NODE_VERSION)"
