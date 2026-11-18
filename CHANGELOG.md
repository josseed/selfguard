# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- **A new menu bar panel.** The menu is now a panel, always dark on the system's glass: Bastion
  and the status, the time since the last check (↻ checks now), one notice when something needs
  you (a service off, an update), what's new since you last looked (or the counts by
  severity), Open Dashboard (⌘D), three live stats, Settings… (⌘,) and Quit (⌘Q). It has
  nothing to configure: Open at Login, Bastion Alerts and the terminal command move to the
  dashboard's Settings, in "This Mac".
- **Sharper icons.** The menu bar helmet is drawn at the screen's resolution (36×36 on Retina),
  in color in every state: cyan eyes when all is well, muted with "zz" when monitoring is off,
  the alert's color otherwise. The app icon is now Bastion's helmet.
- Times read in full words ("1 hour ago").
- **Dashboard redesign.** Every page now follows the menu bar panel's style: always dark,
  borderless cards with uppercase section titles, severity pills, hairline dividers and the
  helmet in the sidebar and header. The Overview opens with a status headline ("Watching N
  projects · checked … ago"), one dismissible notice when something needs a decision (for
  example the lockfile watcher being off), four severity tiles, the repos that need attention
  and recent activity. Settings are grouped cards (Watching, Alerts, This Mac, Projects, Other
  machines, Updates, About) with switches and presets (reminder daily, weekly or off; active
  window 7, 30, 90 days or 1 year). Sync now has a shortcut (⌘S). Times and counts are written
  out in full words ("5 minutes ago", not "5 min ago").

### Fixed

- The Mac app quit at launch, silently, when macOS hid its menu bar icon (System Settings →
  Menu Bar, or ⌘-dragging it out), so it never showed up there to be allowed again. It now
  keeps running; opening it again shows the dashboard.
- The dashboard's "Check for updates" switch had no effect (the settings route dropped it).

### Security

- The terminal command installer only replaces a link that belongs to selfguard.app.

## [0.16.0] - 2026-11-17

### Added

- **The Mac app works on its own; the command line is optional.** On first launch the app asks
  once whether to watch your projects in the background (the launchd agents, run by the engine
  inside the app), so nothing else needs installing. If the agents were set up by an npm
  install, it offers to move them to the app (same folders, settings and results; the sync
  interval is kept). The menu has "Install Terminal Command…", which links `selfguard` in
  `~/.local/bin` to the app's engine (and never replaces a command that isn't the app's).
  Settings → Background watching says which one runs the agents. `selfguard schedule on`
  without `--every` now keeps the installed interval.

### Changed

- **Much less memory.** A repo's record is now two files: a small one with what listings
  need (findings, lockfile fingerprint, package count) and `<id>.deps.json` with the full
  dependency list, read only when rescanning it or on the Packages page. Old records keep
  working and split on their next save (the next sync). Every engine process runs with a
  smaller V8 young generation. With ~900 tracked repos, the peak of the menu summary and of the
  dashboard's status went from ~340 MB to ~165 MB, and they take half the time. Older
  versions can't read the new records: if you also have selfguard from npm, update it to this
  version too (or let the app run the background agents).
- **The Mac app no longer starts the engine every 15 minutes.** It reads the background agents'
  status (`launchctl print`) and the last check and sync times itself; the engine still rewrites
  the menu summary whenever something changes.

## [0.15.0] - 2026-11-17

### Changed

- **"Ignore folder" now pauses the folder instead of banning it.** Projects inside stay out of
  tracking and alerts while nothing changes, but when a project there has activity (its lockfile
  or `package.json` is updated, or new commits) it comes back by itself and is scanned again; the
  rest of the folder stays paused. Paused folders are listed under Folders → "Ignored folders"
  with "Include again". Ignoring a folder on another machine and `selfguard forget` are
  unchanged (permanent).

## [0.14.0] - 2026-11-17

### Added

- **Ignore a whole folder from the Repos page.** In the "By folder" view, each folder has an
  "Ignore folder" button: everything inside stops being tracked, scanned, alerted and
  discovered, including projects created there later (on this Mac or on another machine). It
  is the same exclusion as `selfguard forget <folder>`. "Include again" under Folders or
  Machines now brings the projects back right away instead of waiting for the next discovery.

### Changed

- **The dashboard no longer has a web server.** There are now two things: the CLI (the engine)
  and the Mac app, the only visual part. The dashboard page is shown only inside the app's
  window: it is served from a custom `selfguard://dashboard/` scheme and its API goes through
  the app to a new internal command, `selfguard bridge` (newline-delimited JSON over stdio).
  Nothing listens on `127.0.0.1` anymore, and there is no session token or `ui.json`. The CSP is
  now `connect-src 'none'`. See the [security model](docs/security-model.md#dashboard).
- `selfguard ui` opens the Mac app's dashboard (`--repo` and `--page` pick where). Without the
  app it says where to download it. **On Linux there is no visual dashboard**; the CLI is
  complete there (`status`, `report`, `--json`).
- `selfguard app install` no longer generates a script launcher: it points to the Mac app.
  `setup` no longer offers it. The Mac app's dashboard checks for updates through the app only
  (no "restart the dashboard" banner).

### Removed

- `selfguard ui --no-open`, `--port` and `--serve`, the `/api/restart` and `/api/app`
  endpoints, and the dashboard's Settings entry for the launcher.
- `selfguard app uninstall` still removes the old script launcher (it checks the bundle id, so
  it never deletes the real app). A dashboard server left running from an older version is
  not stopped by this version: quit it (`pkill -f "selfguard.*ui --serve"`).

### Fixed

- Excluding a folder with `forget` now refreshes the menu bar summary even when the folder
  itself wasn't a tracked project.

## [0.13.0] - 2026-11-16

### Added

- **The Mac app updates itself** ([Sparkle 2](https://sparkle-project.org)): it checks once a
  day and offers the new version with its release notes; "Check for Updates…" in the menu
  checks now. An update installs only if the feed and the DMG carry valid EdDSA signatures
  (the feed is signed too, and the DMG is verified before it is opened) and the new app is
  signed with the same Developer ID. Each release attaches `appcast-arm64.xml` and
  `appcast-x64.xml`. Macs on 0.12.0 or earlier install 0.13.0 by hand once.

### Changed

- Inside the Mac app, "a new version is available" (menu, dashboard banner, notification) points
  to "Check for Updates…" instead of an `npm i -g` command, which updated a different copy.

### Fixed

- Two alerts handed to the Mac app in the same millisecond could be shown out of order.

## [0.12.0] - 2026-11-16

### Added

- **Bastion, the mascot**: a 16-bit castle guard brought up to date (his visor is a screen that
  shows his eyes in the color of the alert). On the dashboard's Overview he patrols when all is
  clear and acts out what is new since you last looked: he jumps at a high finding, sounds the
  horn for a critical one, fights off a malicious package and celebrates a fix (once, then he
  settles; still frames under reduced motion). In the Mac app his helmet is the menu bar icon,
  and a small floating panel plays the scene when serious findings or fixes arrive (malicious
  packages stay until dismissed; "Bastion Alerts" in the menu turns it off). While the app runs
  it shows the engine's alerts itself instead of the macOS banner and dialog, so a finding is
  announced **once**; when the app isn't running, alerts are banners as before. The art is drawn
  once in `scripts/mascot/bastion.html` and exported as indexed-PNG sprite strips (about 25 KB
  for every scene) by `scripts/mascot/export.mjs`.

## [0.11.0] - 2026-11-16

### Added

- **Mac app** (DMGs for Apple Silicon and Intel attached to the GitHub release; `macos/`): a
  menu bar icon that changes for what is **new since you last looked** (and for malicious
  packages or monitoring that is off), not for the standing backlog; the latest findings and
  fixes; the repos that need attention, with their branch; "Check Now" and "Sync Everything"
  with a notification of the result; "Open at Login"; and the dashboard in a window locked to
  its own `127.0.0.1` address, with a Dock icon while it is open. The menu reads a file, so the
  dashboard server only runs while the window is used. The app bundles a pinned,
  checksum-verified Node.js, so it needs nothing installed. See
  [docs/design/mac-app.md](docs/design/mac-app.md).
- **Signed and notarized** (Developer ID, see
  [docs/releasing-mac-app.md](docs/releasing-mac-app.md)): the DMGs come with their SHA-256 and
  are built in the approval-gated `macos-release` environment. Every binary runs with the
  hardened runtime; the bundled Node.js keeps only the `allow-jit` entitlement.
- `selfguard menubar` and `~/.selfguard/menubar.json` (also `GET /api/menubar`): the summary
  the app shows, rewritten after every scan with news, `sync`, `dismiss` and `forget`.

### Changed

- **Each repo is judged by one checkout: the one on its default branch** (`origin/HEAD`, else
  `main` or `master`; without one, the active main clone). Its findings are the repo's in
  `status`, the dashboard, reminders, the menu bar and MCP. Other worktrees and clones are
  still scanned and listed, but they only alert, and only appear in the activity feed, for
  malicious packages: the fix is made once, on the default branch.
- **Copies without git are grouped with the project they copy**: a folder without git whose
  manifest has the same name as a tracked project and at least 60% of the same dependency
  names (agents' snapshots, unpacked archives, "evidence" folders). They never represent the
  repo. On real data: repos needing attention went from 298 to 40, and repo status got faster.
- The repo page marks the checkout that counts ("default branch"), copies, and packages
  "only in other checkouts".

### Fixed

- Dashboard: "Copy markdown" works in Safari (and the Mac app). WebKit refuses a clipboard
  write that starts after the markdown request; the write now starts during the click.
- Two `selfguard ui` started at the same moment no longer start two dashboard servers.

## [0.10.1] - 2026-11-16

### Fixed

- **`selfguard check` no longer walks every repo.** Since 0.10.0, each check (and so each
  lockfile change seen by the watcher) searched every tracked repo for composite `action.yml`
  files, which took tens of seconds with a few hundred repos. Check now stats what the last
  scan recorded: the workflow and agent config files, and the folders new ones appear in
  (`.github/workflows`, `.github/actions`, the composite actions' folders). Only when one of
  those folders changed are that repo's files listed again; a repo without workflows yet is
  probed by reading `.github/workflows` alone. `sync` and `scan` still search the whole repo.
- **The lockfile watcher could stay unloaded after an update.** Reloading it while its own
  check was running raced with launchd (`bootout` returns before the job has exited), so
  `bootstrap` failed and the watcher showed "not running". selfguard now retries for a few
  seconds, checks the agent is loaded, and reports a clear error otherwise.
- **"Already running" for five minutes after a killed run.** A lock whose process no longer
  exists is reclaimed at once, and locks are released when selfguard is stopped by SIGTERM or
  SIGINT.

## [0.10.0] - 2026-11-16

### Added

- **GitHub Actions workflows.** Actions referenced in `.github/workflows` and composite
  `action.yml` files are checked against OSV's GitHub Actions advisories (for example the
  compromised `tj-actions/changed-files`). Action names never leave the machine: selfguard
  keeps a local index of OSV's GitHub Actions advisories (the public `modified_id.csv` list,
  refreshed every 6 hours, only changed advisories downloaded again) and matches names
  case-insensitively, as GitHub does (`azure/setup-kubectl` gets `Azure/setup-kubectl`'s
  advisories). Ranges are evaluated locally: an exact tag is confirmed, `@v4` "may be
  affected"; a bare SHA lists every advisory with its fix, a branch only those that affect the
  latest release. Warnings, without the network, for actions not
  pinned to a SHA, `pull_request_target` workflows that check out the PR head, and untrusted
  event text interpolated into `run:` scripts.
- **MCP servers of AI agents.** Servers configured for Claude Code, Claude Desktop, Cursor,
  VS Code, Windsurf, Codex and Gemini CLI (on this machine and in each repo) and launched with
  npx, bunx, pnpm/yarn dlx, uvx or pipx are checked as npm or PyPI packages; unpinned ones are
  warned about, with the version last run from the npx cache. An unpinned server is still
  checked by name (malicious advisories always apply); it lists advisories without a fix and
  those affecting the version last run. Only names and versions are kept: secrets in those
  configs are never stored or sent.
- Sources are quiet by default: a source's first check is a baseline (only malicious findings
  notify), the watcher only asks OSV when a file's references changed or a day has passed,
  an offline check is retried, and `forget` also drops the repo's CI and agent config results.
- `selfguard tools [dir]`, the `selfguard_sources` MCP tool, an Agent tools card and a sources
  section per repo in the dashboard. A malicious action or MCP server raises the same alert as
  a malicious package. `selfguard where` also finds actions and MCP servers.

## [0.9.0] - 2026-11-16

### Added

- **Python, Rust and Go projects.** selfguard now reads `uv.lock`, `poetry.lock` (with
  `pyproject.toml` for direct and dev dependencies), `Cargo.lock` and `go.mod`, and checks them
  against OSV's PyPI, crates.io and Go databases. Discovery, the shell hook, the lockfile
  watcher, other machines, alerts, the dashboard, markdown reports, `where` and the MCP tools
  handle them like JavaScript projects. Nothing from those ecosystems needs to be installed, and
  no Python, Cargo or Go tool is ever run.
- PyPI versions are compared with PEP 440 ordering and names PEP 503-normalized. Go versions are
  stored without their leading `v`, as OSV lists them. Packages carry an `ecosystem` field in
  JSON, MCP and API output (absent in records stored by earlier versions, meaning npm).
- `selfguard where <package> --ecosystem npm|PyPI|crates.io|Go`, and an `ecosystem` argument for
  the `selfguard_where` MCP tool (case-insensitive; unknown values are an error).
- Advisories without a severity label (PYSEC, GO, RUSTSEC) take it from their CVSS v3 vector or
  from an alias that has one. Copies of an advisory under several ids are collapsed even when
  only one of them lists the other, keeping the copy with a known severity.
- RustSec informational notices (unmaintained, unsound) are not reported as vulnerabilities.

### Changed

- A folder with lockfiles of several ecosystems is one project, checked through the first of:
  JavaScript, uv, Poetry, Cargo, Go, whichever subfolder you enter it from.
- Discovery skips `testdata` folders (fixtures, ignored by the go tool) and Go module caches
  wherever `GOPATH` is. A `package.json` (or `Cargo.toml`, `pyproject.toml`) below a
  lockfile of another ecosystem no longer resolves to it.
- SSH readers installed by earlier versions keep working but only list JavaScript lockfiles:
  reinstall them (`selfguard machines install <name>`) to include Python, Rust and Go.

## [0.8.2] - 2026-11-16

### Fixed

- Adding a machine over SSH when SSH is off there (for example, a Mac with Remote Login off)
  used to fall through to "install the reader by hand", and the copied script could never be
  used. selfguard now checks the SSH port first. If the machine refuses, nothing is saved or
  installed, and the dashboard and CLI say that Remote Login (SSH) is off there. They explain
  how to turn it on, or offer selfguard sharing for a Mac on the tailnet (or **Connect** when
  sharing already answers). The Add a machine dialog warns as soon as you pick such a machine,
  and **Verify** and **Sync now** give the same explanation. A machine saved over SSH whose SSH
  was turned off later is pointed to **Switch to sharing** instead of a bare "Connection refused".

## [0.8.1] - 2026-11-16

### Fixed

- After updating, a dashboard left running from the previous version could serve the new page,
  which calls endpoints the old server doesn't have ("no such endpoint", for example on
  Machines). Each dashboard now serves the page files of its own version, and `selfguard ui`
  (or selfguard.app) replaces a dashboard of an older version through its own restart, at the
  same address and with the same session.

## [0.8.0] - 2026-11-16

### Added

- selfguard sharing: add your other Macs from the dashboard without SSH. On the machine to
  watch, "Let my other machines see this one" (`selfguard share on`) starts a small read-only
  service (launchd agent, systemd user unit on Linux). It listens only on that machine's
  Tailscale addresses and answers the same reader requests as the SSH reader (`reader.ts`, a
  byte-identical TypeScript port), with the same limits and a folder scope.
- Pairing: press **Connect** and both screens show the same 6-digit code, derived from an X25519
  exchange. You approve on the other machine and choose the folder it may read. The credential
  is sealed for the requester only, stored there as a hash, bound to its Tailscale node ID (a
  mismatch revokes it), and limited by default to machines of your own Tailscale user. Requests
  are rate limited, accesses logged, and `share off` stops answering at once. **Machines that
  can see this one** lists paired machines with their last connection and **Revoke**
  (`selfguard share list | revoke <name>`).
- Machines page: **On your tailnet** lists every peer with its state (online, last seen) and
  what it can do (selfguard sharing, SSH, Tailscale SSH), probed in parallel. Each one gets the
  right next step: Connect, Turn on sharing there (with automatic retry), or Add with SSH. The
  long manual install script is now behind "Advanced". There are clear messages when Tailscale
  is missing or stopped.
- Machines gain a `transport` (`ssh` or `share`; configs without it stay `ssh`).
  `selfguard machines add <peer>` picks sharing when available (`--via share|ssh`), and
  `selfguard machines migrate <name> --via share|ssh` keeps history and folders.
  `selfguard machines peers` shows capabilities.
- MCP: `selfguard_machines_peers`. The agent guide documents the share transport.

### Security

- The restricted SSH reader now also confines git facts to its granted folder: a parent repo's
  remote URL (which may embed a token) is no longer reported for a narrower grant.

## [0.7.1] - 2026-11-15

### Added

- Update notice: once a day, selfguard asks the npm registry for its latest version, sending
  only the package name. You can turn this off with `--update-check off` or
  `SELFGUARD_NO_UPDATE_CHECK=1`. Each new version gets one notification. The dashboard shows a
  banner with the release notes, the npm provenance status and the safe command to copy
  (`npm i -g selfguard@<version> --ignore-scripts`). `selfguard status` mentions it too.
  selfguard never installs anything by itself.
- After an update, the dashboard notices that the code on disk is newer and offers **Restart
  dashboard**: it restarts on the same address and the page reloads.
- `selfguard update`: check now and show how to update.

## [0.7.0] - 2026-11-15

### Added

- Dismiss a repo: `selfguard dismiss [dir]`, **Dismiss** on a repo's page in the dashboard, or
  `selfguard_dismiss` over MCP. The repo stays tracked but is treated as inactive (no reminders,
  alerts only for malicious packages) until any of its checkouts has git activity again; then it
  turns back on by itself. `selfguard undismiss` and `dismiss --list`, a **Dismissed** filter on
  Repos, and `dismissedAt` on repos in `status --json`.
- Find my projects: `selfguard discover --everywhere`, **Find my projects** on the dashboard's
  Folders page, and a new first question in `selfguard setup`. It searches the whole home folder
  read-only and skips:
  - dependencies, build output and caches (anywhere);
  - hidden, system and media folders;
  - cloud drives, other disks and symlinks;
  - whatever a repo's own `.gitignore` marks as disposable;
  - zones that burn through their budget without a project.

  Worktrees that tools keep in hidden folders (`~/.t3/worktrees`, `.worktrees`) are found from
  their repo's `.git/worktrees`. Samples inside repos (`examples/`, `fixtures/`…) and copies
  (`evidence/`, `backups/`…) are marked and don't decide anything. Results come as a handful of
  places to approve, with folders that have active repos pre-selected; unchecked ones are
  excluded.
- Automatic discovery: once a week, while `schedule on` is active, selfguard runs the same
  search and starts watching new places with active repos, with a notification and an Activity
  entry ("Now watching …"). Folders you remove are never added back. On macOS, the background
  pass only enters Desktop, Documents and Downloads once a watched folder lives there, so no
  privacy prompts appear out of nowhere. Turn it off with `selfguard settings --auto-discover off`
  or in Settings.

## [0.6.0] - 2026-11-15

### Added

- Other machines: `selfguard machines add <host>` watches repos on dev servers over SSH. By
  default it uses a dedicated key that the machine accepts only for a small read-only reader
  (`authorized_keys` `restrict,command=…`, pinned to this Mac's tailnet address). The reader is
  limited to one folder, so even a leaked key can't open a shell or read anything but
  lockfiles. It is installed once with your SSH access, or by hand
  (`selfguard machines setup`). `--mode ssh` uses your own access instead. Lockfiles are
  scanned locally, and only changed ones are transferred. See the security model.
- `selfguard machines` (list, peers, test, add, setup, install, verify, roots, sync, remove), and
  a 15-minute background check of other machines while `schedule on` is active.
- Dashboard: **Machines** page (add from your tailnet, browse remote folders, sync, status) and a
  machine filter on Repos. Repos, alerts, reminders and markdown name the machine.
- MCP: `selfguard_machines` and `selfguard_machines_sync`; repos and projects carry `machine`.

## [0.5.0] - 2026-11-15

### Added

- Dashboard: repos are grouped by folder automatically (the first folder under each watched
  folder), with collapsible groups and a **Flat** view. The API returns `folder` per repo group.
- Dashboard: **Copy markdown** and **Preview** on a repo's page copy its vulnerabilities as
  markdown: serious packages first, the fixed version, bump vs override,
  and how to refresh the lockfile with install scripts disabled. Advisory text is cleaned and
  marked as data.
- `selfguard report <dir> --markdown` (`-m`) prints the same markdown.

## [0.4.0] - 2026-11-15

### Added

- Redesigned dashboard with a sidebar and six pages: Overview (with "Fix first": serious
  packages ranked by how many repos they affect), Repos, Packages (vulnerable packages across
  all repos, per-version fixes), Activity, Folders and Settings.
- Manage watched folders from the dashboard: folder browser to add one, depth stepper, remove,
  look for new projects, include excluded paths again.
- Turn background watching and selfguard.app on or off from the dashboard's Settings.

## [0.3.0] - 2026-11-15

### Added

- `selfguard app install | uninstall | status` (macOS): a launcher app in `~/Applications` to
  open the dashboard from Spotlight, Launchpad or the Dock. Generated locally, so it needs no
  Apple signature. Offered by `setup`, refreshed by `schedule on`.

## [0.2.1] - 2026-11-15

### Fixed

- A sync no longer announces new worktrees or clones of a known repo as new findings. Other
  checkouts scanned in the same run now count with what they already had.

## [0.2.0] - 2026-11-15

### Added

- `selfguard ui`: a local dashboard in the browser with the repos that need attention, fixes per
  package and branch, an activity feed and alert settings. Served on 127.0.0.1 with a
  per-session token and a strict CSP; no dependencies.
- Daily reminder (configurable: `selfguard settings --remind daily|weekly|off`) of serious open
  issues in active repos: malicious packages, critical vulnerabilities outside dev dependencies
  and high ones in direct dependencies. `selfguard remind` sends it on demand.
- "✓ fixed" notifications when a scan on the same branch no longer has a vulnerable package.
- Lockfile watcher (launchd `dev.selfguard.watch`, installed by `schedule on`): `git pull`,
  installs and merges are checked within seconds, without a terminal. New `selfguard check`.
- Active checkouts: only checkouts with git activity in the last 30 days alert
  (`--active-days`); others are listed but quiet, except for malicious packages.
  `status` hides inactive repos and checkouts unless `--all`.
- Activity log (`~/.selfguard/events.jsonl`).
- MCP tools `selfguard_attention` and `selfguard_check`.

### Changed

- New findings are no longer announced again when you switch branches back and forth, or when a
  new worktree or clone has the same findings as another checkout of the repo.
- Repo-level counts in `status` (and `--json`) cover active checkouts.

### Fixed

- Worktrees whose main repository was deleted are shown as "(orphaned worktree)" instead of
  being grouped under a bogus "worktrees" repo.

## [0.1.0] - 2026-11-14

First release.

### Added

- Lockfile scanning against OSV.dev (GitHub advisories, CVEs, OpenSSF malicious packages) with
  one upgrade target per vulnerable package.
- Lockfile support: npm (`package-lock.json` v1–v3, `npm-shrinkwrap.json`), pnpm
  (`pnpm-lock.yaml` v5, v6, v9), yarn (classic v1 and berry v2+), bun (`bun.lock`).
- zsh hook that registers projects on `cd` and re-scans in the background when the lockfile
  changes.
- `setup` wizard to choose code folders, and bounded recursive discovery in those folders.
- `sync` to re-check every project, discover new clones and prune removed folders.
- Grouping of git worktrees and clones of the same repository in `status`.
- macOS notifications naming the repo and the fix, and a persistent dialog for malicious
  packages.
- Scheduled background sync via launchd (`schedule on|off|status`).
- `where`, `vuln`, `report`, `roots`, `discover`, `forget` and `unexclude` commands.
- MCP server (`selfguard mcp`), `--json` output on every command, and `selfguard guide` for
  AI agents.
- Releases with npm Trusted Publishing, provenance and staged publishing.

[Unreleased]: https://github.com/josseed/selfguard/compare/v0.16.0...HEAD
[0.16.0]: https://github.com/josseed/selfguard/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/josseed/selfguard/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/josseed/selfguard/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/josseed/selfguard/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/josseed/selfguard/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/josseed/selfguard/compare/v0.10.1...v0.11.0
[0.10.1]: https://github.com/josseed/selfguard/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/josseed/selfguard/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/josseed/selfguard/compare/v0.8.2...v0.9.0
[0.8.2]: https://github.com/josseed/selfguard/compare/v0.8.1...v0.8.2
[0.8.1]: https://github.com/josseed/selfguard/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/josseed/selfguard/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/josseed/selfguard/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/josseed/selfguard/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/josseed/selfguard/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/josseed/selfguard/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/josseed/selfguard/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/josseed/selfguard/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/josseed/selfguard/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/josseed/selfguard/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/josseed/selfguard/releases/tag/v0.1.0
