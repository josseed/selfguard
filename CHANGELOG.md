# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
  the `selfguard_where` MCP tool.

### Changed

- A folder with lockfiles of several ecosystems is one project, checked through the first of:
  JavaScript, uv, Poetry, Cargo, Go. A `package.json` (or `Cargo.toml`, `pyproject.toml`) below a
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

[Unreleased]: https://github.com/josseed/selfguard/compare/v0.8.2...HEAD
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
