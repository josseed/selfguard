# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/josseed/selfguard/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/josseed/selfguard/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/josseed/selfguard/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/josseed/selfguard/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/josseed/selfguard/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/josseed/selfguard/releases/tag/v0.1.0
