# Contributing to selfguard

Thanks for helping! Bug reports, ideas, documentation fixes and code are all welcome.

- **Bugs and features:** open an [issue](https://github.com/josseed/selfguard/issues/new/choose).
- **Security vulnerabilities:** please **don't** open a public issue; see [SECURITY.md](SECURITY.md).
- **Larger changes:** open an issue first so we can agree on the approach before you spend time
  on it.

## Development setup

Requires Node.js **22.18+** for development (the tests run the TypeScript sources directly with
Node's type stripping). The published CLI supports Node 20.10+.

```sh
git clone https://github.com/josseed/selfguard.git
cd selfguard
npm ci --ignore-scripts
npm test            # node:test, runs src/ directly
npm run typecheck   # tsc --noEmit
npm run build       # emits dist/
node dist/cli.js --help
```

Try your changes without touching your real state by pointing selfguard at a scratch directory:

```sh
SELFGUARD_HOME=$(mktemp -d) SELFGUARD_NO_NOTIFY=1 node dist/cli.js scan ~/some/project
```

## Project layout

```text
src/
  cli.ts, cli/      command-line entry point and one module per command group (human output)
  api.ts, api/      structured operations shared by the CLI (--json), MCP and dashboard
  mcp.ts, mcp/      MCP server over stdio; tool definitions in mcp/tools.ts
  guide.ts          guide for AI agents (selfguard guide / MCP instructions)
  scan.ts           lockfile → OSV → findings; findings.ts collapses advisory aliases
  osv.ts            OSV.dev client and advisory cache
  match.ts          OSV range evaluation and severity (cvss.ts scores CVSS v3 vectors)
  versions.ts       versions per ecosystem: semver.ts (SemVer 2.0), pep440.ts (Python)
  lockfile/         detection and parsers (npm, pnpm, yarn, bun, uv, Poetry, Cargo, go.mod;
                    YAML and TOML subsets)
  discover.ts       bounded project discovery in watched folders
  everywhere.ts, everywhere/  "find my projects" in the whole home folder
  repoid.ts         repository identity for grouping worktrees and clones
  hook.ts           zsh hook and background scans
  activity.ts       which checkouts are active (recent git activity)
  alerts.ts         what to notify (pure); announce.ts logs events and delivers via notify.ts
  events.ts         activity log; state.ts small runtime state (last reminder, sync…)
  schedule.ts, schedule/  launchd agents: periodic sync, lockfile watcher, sharing
  remote.ts, remote/      other machines over SSH: reader script, transport, answer parsers
  reader.ts         the same reader in TypeScript, for sharing
  machines.ts, machines/  other machines: config, pairing, sync
  share.ts, share/  selfguard ↔ selfguard sharing over the tailnet
  ui/               local dashboard: server.ts and its modules (HTTP + JSON API), and
                    static/ (HTML, CSS and ES modules, listed in ui/assets.ts)
  app.ts            macOS launcher app (~/Applications/selfguard.app); icon in assets/
  setup.ts, tui.ts  interactive setup wizard
  store.ts, config.ts, paths.ts, fsutil.ts, sanitize.ts, report.ts
macos/              the Mac app (SwiftUI menu bar + the dashboard in a window); node.lock
                    pins the Node.js bundled in it; scripts/build-app.sh assembles the app
test/               node:test suites and fixtures
docs/               user documentation; docs/design/ for proposals
```

A module that grows past **300 lines** is split by responsibility into a folder next to it,
keeping the original file as the entry point that re-exports its API. `test/layout.test.ts`
enforces the limit for everything under `src/` and `macos/Sources/`.

### The Mac app

`scripts/build-app.sh` builds `macos/build/selfguard.app` for this Mac's architecture
(`ARCH=x64` for Intel). It needs the Xcode Command Line Tools; Xcode itself is optional. Try it
on scratch state:

```sh
scripts/build-app.sh
SELFGUARD_HOME=$(mktemp -d) SELFGUARD_NO_NOTIFY=1 macos/build/selfguard.app/Contents/MacOS/selfguard --dashboard
```

The app adds no logic of its own: it reads `/api/menubar` and shows the dashboard. To update
the bundled Node, change `macos/node.lock` with the checksums from that release's
`SHASUMS256.txt` (verify its signature first).

## Ground rules

These keep selfguard trustworthy. Pull requests that break them can't be merged:

1. **No runtime dependencies.** Use Node built-ins. CI fails if `dependencies` is non-empty.
2. **Never execute anything from a scanned project.** No package managers, `npm ls`, git
   commands, project scripts or config loading. Read files as data.
3. **Treat every external string as hostile.** Sanitize anything printed, notified or returned
   to an AI with `clean()` from `src/sanitize.ts`. Never interpolate untrusted text into
   commands or scripts; pass it as arguments. In the dashboard, use `textContent`, never
   `innerHTML`, and keep the CSP strict (no inline scripts or styles).
4. **Only package names and versions may leave the machine.**
5. **`api.ts` returns data, `cli.ts` renders it.** New features should be available through
   `--json` and, where it makes sense, as an MCP tool (`src/mcp/tools.ts`), documented in
   `src/guide.ts` and `docs/`.

## Tests

- Every bug fix should come with a test that fails without it.
- **Lockfile changes:** add a fixture generated by the real package manager
  (`--lockfile-only` / `--ignore-scripts`, never running install scripts) to
  `test/fixtures/real/`. The cross-manager test requires every parser to agree.
- **Fixture naming:** fixtures that contain vulnerable versions must **not** be named
  `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` or `bun.lock`. Use `*.fixture.*` so
  GitHub's dependency graph and selfguard's own discovery don't report them. `copyFixture()` in
  `test/helpers.ts` materializes them in a temp folder.
- Tests must not touch your real `~/.selfguard`, `~/.zshrc` or launchd. Use `SELFGUARD_HOME`,
  `HOME` and `SELFGUARD_NO_NOTIFY=1` in temp folders. Network calls go to a local fake OSV
  server (see `test/scan.test.ts`).

## Pull requests

- Keep each PR focused on one change. Explain the *why* in the description.
- `npm run typecheck && npm test` must pass. CI runs on macOS and Linux with Node 22 and 24,
  and smoke-tests the built CLI on Node 20.
- Update `docs/` and `CHANGELOG.md` (under "Unreleased") when behavior changes.
- Use clear commit messages: an imperative summary line, then a body explaining the reason.

## Releasing (maintainers)

1. Update `version` in `package.json` and `src/version.ts`, and move the "Unreleased" changelog
   entries under the new version.
2. Merge to `main` and wait for CI.
3. Create a GitHub release with tag `vX.Y.Z`. The `release` workflow waits for approval in
   the `npm` environment.
4. Approve the deploy. The workflow tests, builds and **stages** the version on npm with
   provenance.
5. Approve the staged version on npmjs.com with 2FA, or with
   `npx npm@12 stage approve <stage-id>` (the ID is in the workflow log).
6. Verify: `npm view selfguard@X.Y.Z dist.attestations`.

## Code of conduct

Be kind and constructive. Harassment or discrimination of any kind isn't tolerated. Maintainers
may remove comments or block contributors who don't follow this.
