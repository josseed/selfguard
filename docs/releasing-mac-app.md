# Releasing the Mac app (maintainers)

Every GitHub release `vX.Y.Z` also builds the Mac app: one DMG per architecture (Apple Silicon
and Intel), signed with a **Developer ID Application** certificate, **notarized** by Apple and
**stapled**, attached to the release with its SHA-256. The job (`macos-app` in
`.github/workflows/release.yml`) runs in the `macos-release` environment, which needs a
maintainer's approval, like the npm release.

## Updates (Sparkle)

The app updates itself with [Sparkle 2](https://sparkle-project.org) (pinned in
`macos/Package.swift` and `Package.resolved`). For each architecture the job also writes
`appcast-<arch>.xml` (`scripts/appcast.mjs`, release notes from the CHANGELOG) and attaches it
to the release; the app reads `releases/latest/download/appcast-<arch>.xml`. An update is
installed only if all three hold:

- the **feed** is signed with the Sparkle EdDSA key (`SURequireSignedFeed`);
- the **DMG** carries a valid EdDSA signature in the feed, checked before it is opened
  (`SUVerifyUpdateBeforeExtraction`);
- the new app is signed with the **same Developer ID** as the running one (Sparkle checks it).

The public key is `macos/sparkle-public-key.txt`, baked into `Info.plist` by
`scripts/build-app.sh` (a build without it has no updater). The private key is the
`SPARKLE_ED_PRIVATE_KEY` secret of `macos-release`, with a backup in the maintainer's
password manager (GitHub secrets can't be read back, so that backup is the only recoverable
copy). The login Keychain may hold it too, for signing locally.

The first version with the updater is 0.13.0: Macs on 0.12.0 or earlier install it by hand once.

## What is signed, and how

- `Contents/Resources/engine/node`: the Node.js from `macos/node.lock` (checksum-verified),
  re-signed with the **hardened runtime** and a single entitlement, `allow-jit`
  (`macos/node.entitlements`). Node's own release carries more (library validation off,
  unsigned executable memory, `get-task-allow`) for native addons and debuggers; selfguard has
  neither, and Apple refuses `get-task-allow` in notarized apps.
- The Swift app and the bundle: hardened runtime, no entitlements, no sandbox (the engine reads
  repos anywhere on the disk, as the CLI does).
- The DMG: signed, notarized and stapled too, so it opens offline without warnings.

## The DMG window

Opening the DMG shows a window laid out for installing: selfguard.app on the left, a link to
Applications on the right, and Bastion on the castle wall with an arrow between them. It's
built with [dmgbuild](https://github.com/dmgbuild/dmgbuild), pinned by hash in
`scripts/dmg/requirements.txt` and installed in a throwaway venv (needs Python 3.11+).

- `scripts/dmg/settings.py`: window size, icon size and positions.
- `scripts/dmg/background.html`: the background. After changing it (or Bastion), run
  `node scripts/dmg/render.mjs` (Google Chrome) and commit `macos/Resources/dmg/background*.png`.
  Its window size and icon centers must match `settings.py`.

`scripts/notarize-app.sh` refuses an app whose binaries lack the hardened runtime or a
Developer ID signature, then checks the result with `spctl` (Gatekeeper).

## One-time setup

Only the **Account Holder** of the Apple Developer team can create Developer ID certificates.
The team's name is what macOS shows as the app's developer ("Developer ID Application: <team>").

1. **Certificate.** In Keychain Access → Certificate Assistant → *Request a Certificate From a
   Certificate Authority* (saved to disk). On developer.apple.com → Certificates → **+** →
   *Developer ID Application* (G2 Sub-CA), upload the request, download the certificate and
   open it. In Keychain Access, export the certificate **with its private key** as a `.p12`
   with a strong password.
2. **API key for notarization.** App Store Connect → Users and Access → Integrations → App Store
   Connect API → Team Keys → **+**, role *Developer*. Download the `.p8` (only once) and note
   its **Key ID** and the **Issuer ID** shown above the list.
3. **GitHub environment.** The `macos-release` environment exists with a required reviewer and
   only `v*` tags can deploy to it. Add its secrets from your terminal (they never appear in
   a file or the shell history):

   ```sh
   base64 -i DeveloperID.p12 | gh secret set MACOS_CERT_P12 --env macos-release
   gh secret set MACOS_CERT_PASSWORD --env macos-release          # prompts
   gh secret set APPLE_API_KEY_P8 --env macos-release < AuthKey_XXXXXXXXXX.p8
   gh secret set APPLE_API_KEY_ID --env macos-release             # prompts
   gh secret set APPLE_API_ISSUER --env macos-release             # prompts
   ```

   Then delete the `.p12` and `.p8` copies you don't need; keep backups in a password
   manager.

## Try it locally before a release

```sh
SIGN_IDENTITY="Developer ID Application: <team> (<TEAMID>)" scripts/build-app.sh
APPLE_API_KEY_PATH=~/AuthKey_XXXXXXXXXX.p8 APPLE_API_KEY_ID=XXXXXXXXXX \
APPLE_API_ISSUER=<issuer-uuid> SIGN_IDENTITY="Developer ID Application: <team> (<TEAMID>)" \
  scripts/notarize-app.sh
```

`security find-identity -v -p codesigning` lists the identity's exact name. Notarization takes
a few minutes; `xcrun notarytool log <id> --key … --key-id … --issuer …` explains a rejection.

## Rotating or revoking

- Sparkle key: **back it up**. With the key in the login Keychain (Sparkle's `generate_keys`,
  in `macos/.build/artifacts/sparkle/Sparkle/bin`) and the Bitwarden CLI logged in,
  `scripts/backup-sparkle-key.sh` exports it, checks it matches `macos/sparkle-public-key.txt`,
  saves it as a secure note and reads it back to verify. The key is never printed and only
  touches disk for a moment in a private temporary folder. (`generate_keys -x` needs a path to
  a new file: `/dev/stdout` doesn't work.) To sign locally again, import it with
  `generate_keys -f <file>`.
  If it is lost or leaked, generate a new pair, update `macos/sparkle-public-key.txt` and the
  secret, and release: apps already installed trust only the old key, so the release that
  switches keys must still be signed with the old one (or users reinstall by hand).

- Certificate: create a new one, update `MACOS_CERT_P12` and `MACOS_CERT_PASSWORD`, then revoke
  the old one. Revoking it doesn't break apps already notarized with it.
- API key: revoke it in App Store Connect and add a new one; it only notarizes.
