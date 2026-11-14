# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/josseed/selfguard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/josseed/selfguard/releases/tag/v0.1.0
