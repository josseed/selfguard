# Design: selfguard for Mac

Status (2026-11-16): phase 1 done, and from phase 2 the summary file, "new since you looked",
the login item, the Dock icon while the window is open and Check/Sync result notifications.
Phase 3 (signing and notarization in CI) is done: releases from v0.11.0 attach notarized
DMGs (docs/releasing-mac-app.md). Phase 4's auto-update is done from v0.13.0 (Sparkle 2, signed
feed per architecture on the GitHub release); the Homebrew cask is still pending. Pending: native notifications for findings, adopting the services,
the CLI link, phases 4–5.

## Goal

A native macOS app that makes selfguard visible and self-maintaining, while the CLI stays the
engine and keeps working on its own:

- a **menu bar icon** that always shows the state (clean, findings, malicious, a service down);
- a **window** with the existing dashboard;
- **native notifications** with the selfguard icon, which open the right page when clicked;
- **automatic updates** of the app *and* the engine, signed and notarized;
- **no prerequisites**: no Node.js or npm needed.

Decisions taken: SwiftUI shell + the existing web dashboard; Node bundled in the app; Developer
ID signing, notarization and auto-update; "updates" means selfguard updating itself.

Out of scope for now: outdated (non-vulnerable) dependencies, the Mac App Store (the sandbox
can't read repos across the disk), Windows and Linux.

## What exists today and is reused

| Piece | Today | In the app |
|---|---|---|
| Engine | `dist/cli.js` on the user's Node | same code, run by the bundled Node |
| Dashboard | `selfguard ui`: 127.0.0.1, random port, per-session token, `ui.json` | loaded in a WKWebView |
| Services | launchd agents (`watch`, `sync`, `discover`, `share`, `remote`) built from `process.execPath` + `cliEntry()` | the same agents, pointing to the bundled engine |
| Alerts | `osascript` banners and a blocking dialog | `UNUserNotificationCenter` and an `NSAlert` from the app |
| Updates | daily npm check, shows `npm i -g …` | Sparkle |
| Launcher | `selfguard app install` generates a script-only `.app` | replaced by the real app |

## Architecture

```
selfguard.app/Contents/
  MacOS/selfguard                 Swift app (menu bar + window), LSUIElement
  Resources/engine/node           pinned Node, signed with the app
  Resources/engine/dist/…         the npm package's dist/, same version as the app
  Resources/engine/bin/selfguard  shell wrapper: exec node dist/cli.js "$@"
  Frameworks/Sparkle.framework
```

### The Swift app (new `macos/` folder in this repo)

- **Menu bar** (`MenuBarExtra`): status icon in four states, last check and sync times, the
  repos with findings, "Open dashboard", "Check now", "Sync now", service health, "Check for
  updates", "Quit".
- **Window**: a `WKWebView` on `http://127.0.0.1:<port>/#t=<token>`. Navigation outside that
  origin is blocked; osv.dev and GitHub links open in the default browser. No other content is
  ever loaded.
- **Dashboard process**: reuses the running instance from `ui.json` if it answers `/api/ping`
  with the same version, otherwise starts `engine/node dist/cli.js ui --serve --no-open` as a
  child process and restarts it if it dies.
- **State for the menu**: `~/.selfguard/menubar.json`, rewritten by the engine after every scan
  with news, `sync`, `dismiss` and `forget`, and by `selfguard menubar` (the app runs it at
  launch, after Check Now / Sync and every 15 minutes for service health). The app checks the
  file's date every 3 s. No server is needed for the menu: polling one kept a ~700 MB dashboard
  process alive for good (measured), so the server only runs while the window is used.
- **Icon**: changes for findings that are new since the menu was last opened, a malicious
  package, or a service that is off. The backlog (repos that need attention) is listed in the
  menu but doesn't change the icon: with real data it never empties, and an icon that never
  changes is ignored.
- **Bastion, the mascot**: a pixel-art castle guard whose visor shows his eyes and takes the
  color of the alert. The menu bar icon is his helmet (a template while watching, asleep when
  monitoring is off, amber/red/magenta for news, critical news and malicious packages). The
  engine's alerts (new findings, fixes, the reminder, malicious packages) are shown by a small
  floating panel (`MascotPanel`, non-activating, top-right) where he plays the scene twice and
  closes; malicious packages stay until dismissed, jump the queue and offer the advisory, and a
  click opens the repo. "Bastion Alerts" in the menu turns the panel off.
- **One alert, not two** (`src/appalerts.ts`, `AppAlerts.swift`): the engine still decides
  what to say; the app only decides how. While the app runs it keeps `~/.selfguard/app.json`
  fresh (`{ pid, at, alerts }`, every 30 s and when the toggle changes; removed on quit). If
  that heartbeat is under 75 s old, its process is alive and alerts are on, `deliver()` writes
  each alert to `~/.selfguard/app-alerts/` instead of calling osascript, and the app shows and
  deletes it. Anything else (no app, a crashed or sleeping one, alerts off) falls back to the
  macOS banner and dialog, so alerts never stop. Update, sharing and "find my projects"
  notices stay banners. The art has one source,
  `scripts/mascot/bastion.html`; `scripts/mascot/export.mjs` writes the sprite strips the
  dashboard and the app share (`src/ui/static/mascot/`, shipped in the engine) and the menu
  bar helmets (`macos/Resources/mascot/`). `--mascot-demo <scene>` shows the panel.
- **Notifications**: the app watches `events.jsonl` and posts native notifications. Malicious
  findings open an `NSAlert` that can't be missed, like today's dialog. While the app is
  running, the engine leaves alerts to it (a `notifier: app` setting plus a heartbeat file the
  app updates); if the app isn't running, `osascript` is used as today, so alerts never stop.
- **Login item**: `SMAppService.mainApp`, on by default, with a switch in settings.
- **Swift files follow the 300-line rule**; `test/layout.test.ts` covers `macos/**/*.swift`.

### The engine inside the app

- **Node**: an exact Node LTS version, downloaded in CI from nodejs.org and verified against
  `SHASUMS256.txt` (and its GPG signature). Its version is recorded in the app's About window.
- **Services follow the binary that installs them.** Because the plists are built from
  `process.execPath` + `cliEntry()`, running `setup` from the app points them to
  `/Applications/selfguard.app/Contents/Resources/engine/…`. Sparkle replaces the app in place,
  so the paths stay valid across updates. On first launch the app offers to "adopt" the
  existing services: same config and state in `~/.selfguard`, no migration.
- **Terminal CLI**: "Install command line tool" links `/usr/local/bin/selfguard` (or
  `~/.local/bin`) to `engine/bin/selfguard`. If an npm global install also exists, the app and
  `selfguard status` say which one owns the services and suggest removing the other.
- **The shell hook** already stores absolute paths. After adoption it is rewritten to use the
  bundled engine.
- **Update check**: with `SELFGUARD_RUNTIME=app`, `update.ts` skips the npm check and says
  "updated by the app".

## Security

selfguard is a security tool, so the app must not widen its attack surface:

- **Hardened runtime** on every binary. Node needs `com.apple.security.cs.allow-jit` (V8), and
  only that. No sandbox: the engine must read repos anywhere on the disk, as the CLI does today.
- **Signing**: Developer ID Application certificate. The bundled `node` binary, the Swift app,
  Sparkle and the bundle are signed inside-out. Then the app is notarized with `notarytool`
  and stapled.
- **WebView**: one origin only (127.0.0.1:port), the token check and Host check stay as today,
  no JavaScript bridge to Swift. The menu uses the HTTP API with the token, like the browser.
- **Sparkle 2**: EdDSA-signed appcast over HTTPS, and the update must also pass Apple's code
  signature check, so a stolen EdDSA key alone can't ship an update.
- **Releases need approval, like npm**: the macOS job runs in a GitHub environment
  `macos-release` with a required reviewer. The Apple certificate (`.p12`), its password, the
  App Store Connect API key and the Sparkle private key are secrets of that environment only.
- **Supply chain**: Node is pinned and checksum-verified; Sparkle is pinned by version and
  checksum through SwiftPM `Package.resolved`; actions are pinned to SHAs (selfguard
  checks its own workflows).

## Release pipeline

Same GitHub release `vX.Y.Z` as npm, with one more job in `release.yml`:

1. `macos-14` runner: `npm ci`, typecheck, test, build.
2. Download Node `darwin-arm64` and `darwin-x64`, verify them, and merge them with `lipo` (or
   ship two DMGs; see open questions).
3. `swift build -c release --arch arm64 --arch x86_64`, then assemble the bundle.
4. Sign → `notarytool submit --wait` → `stapler staple` → `selfguard-X.Y.Z.dmg`.
5. Sign the DMG with Sparkle's EdDSA key, upload it to the GitHub release and update
   `appcast.xml` (GitHub Pages or a release asset).
6. Homebrew: a cask in a `josseed/homebrew-tap` tap (`brew install --cask josseed/tap/selfguard`).

## Phases

| Phase | Result | Needs from the user |
|---|---|---|
| 0. Prereqs | Apple Developer account, Developer ID Application certificate, App Store Connect API key, Sparkle key pair | Enroll (USD 99/year); create the certificate and key |
| 1. App shell (done) | Menu bar + window + bundled engine + `/api/menubar`, built locally with `scripts/build-app.sh` (unsigned, ad-hoc) | Nothing; Xcode is optional (Command Line Tools are enough for SwiftPM) |
| 2. Engine integration | Native notifications, adoption of the services, CLI tool link, `SELFGUARD_RUNTIME=app` | — |
| 3. Signed releases | CI signs, notarizes and publishes the DMG on every release | Add the secrets to the `macos-release` environment |
| 4. Auto-update | Sparkle appcast, "Check for updates", Homebrew cask | Create the tap repo |
| 5. Docs and migration | `docs/mac-app.md`, README, the old `selfguard app install` points to the real app | — |

Phases 1 and 2 can start right away and don't depend on the Apple account.

## Open questions

- **Size**: the Node binary for macOS is about 100 MB per architecture. A universal binary
  (~200 MB uncompressed, ~70 MB DMG) is the simplest; two DMGs (arm64 and Intel, ~35 MB each)
  are lighter. Proposal: arm64 + Intel DMGs, with the appcast choosing per architecture.
- **Minimum macOS**: 13 (Ventura), for `MenuBarExtra` and `SMAppService`.
- **Name and icon**: reuse `selfguard.icns`; a monochrome template image is needed for the
  menu bar.
- **npm users**: the npm package stays the main channel for Linux and for people who prefer
  it; the app is optional.
