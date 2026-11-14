# selfguard

A local-first guard for the dependencies of **every** JavaScript repo you work on.

- **Hands-off**: `cd` into a project and selfguard registers it and scans it in the background.
  Run `npm install` and it notices that the lockfile changed and re-scans.
- **Reverse alerts**: `selfguard sync` (or the scheduled job) re-checks all your projects against
  new advisories. You get a macOS notification when a repo you haven't opened in months becomes vulnerable.
- **Malicious packages first**: OSV includes the OpenSSF malicious-packages feed (`MAL-*`), so
  compromised releases (Shai-Hulud style) are flagged above any CVE.
- **Incident response**: `selfguard where <pkg>` answers "do I use this anywhere?" in one command.

## Install

```sh
npm install -g selfguard
selfguard setup
```

`setup` is a small terminal UI: pick the folders where you keep your repos (it suggests
`~/repository`, `~/code`, `~/dev`… and shows how many projects each has), then it scans them and
offers to install the shell hook and the background sync.

```
Where do you keep your code?
selfguard only looks inside the folders you pick, nothing else on your disk.

  [x] ~/repository                     205 projects   depth 3
› [x] ~/code                             12 projects   depth 2
  + add another folder…

↑/↓ move · space select · ←/→ depth · a add folder · enter continue · q quit
```

## How projects are found

selfguard **never crawls your whole disk**. A project gets tracked in one of three ways:

1. **Your folders** (`setup` / `roots add`): a recursive search of every subfolder (depth-limited,
   default 5) that only skips dependency/generated folders: `node_modules`, `bower_components`,
   `vendor`, `Pods`, `venv`, `target`, `__pycache__`, hidden folders (`.git`, `.next`, `.cache`…),
   and symlinks. It also looks inside projects, so monorepos with several lockfiles are covered.
   `sync` re-runs it, so a fresh `git clone` gets watched even if you never open it.
2. **The shell hook**: `cd` anywhere and the enclosing project is registered.
3. **By hand**: `selfguard scan <dir>`.

Test fixtures, examples or archived repos you don't care about: `selfguard forget <dir>` stops
tracking them and excludes them from discovery (undo with `selfguard unexclude <dir>`).

## Use it with AI (MCP)

selfguard ships an MCP server, so assistants like Claude Code or Cursor can triage and manage it:

```sh
claude mcp add selfguard -- selfguard mcp
```

Then ask things like *"which of my projects have critical vulnerabilities and how do I fix them?"*,
*"is `@ctrl/tinycolor` used anywhere?"* or *"stop tracking the test fixtures in ~/code/shop"*.

| Tool | Purpose |
|---|---|
| `selfguard_status` | All projects with risk summary |
| `selfguard_project_report` | Vulnerable packages of a project, with `upgradeTo` |
| `selfguard_scan` / `selfguard_sync` | Re-check one project / everything |
| `selfguard_where` | Which projects use a package |
| `selfguard_vulnerability` | Advisory details + which of your projects it affects |
| `selfguard_roots_*`, `selfguard_discover` | Manage watched folders |
| `selfguard_forget` / `selfguard_unexclude` | Stop tracking / re-include |

The MCP tools never run package managers or project code. Fixes are proposed for the user to apply.
Advisory text is marked as third-party data so the model treats it as data, not instructions.

Without MCP, every command accepts `--json` (one JSON document on stdout, errors as
`{"error":{"code","message"}}`, exit codes 0/1/2), and `selfguard guide` prints a guide written
for agents.

## Commands

Run `selfguard --help` for everything. The main ones:

| Command | What it does |
|---|---|
| `selfguard setup` | Interactive: choose your code folders, scan, install hook + sync |
| `selfguard status [--vulnerable]` | All tracked projects, riskiest first |
| `selfguard scan [dir] [-v]` | Scan a project now (exit code 1 if anything is found) |
| `selfguard report [dir] [-v]` | Last results for a project, no network |
| `selfguard sync` | Find new repos in your folders, re-check everything, notify about news |
| `selfguard where <pkg>` | Which projects use a package, and which versions |
| `selfguard vuln <id>` | Advisory details and which of your projects it affects |
| `selfguard roots [add <dir> [--depth N] \| remove <dir>]` | Manage your code folders |
| `selfguard discover [--dry-run]` | Register new projects found in your folders |
| `selfguard forget [dir]` / `unexclude <dir>` | Stop tracking + exclude / re-include |
| `selfguard schedule on\|off\|status` | Periodic sync via launchd (macOS) |
| `selfguard mcp` / `selfguard guide` | MCP server / guide for AI agents |

## Security model

selfguard is a security tool, so it holds itself to a stricter standard:

- **Never executes anything from your projects.** Lockfiles are parsed as data. No `npm ls`, no
  lifecycle scripts, no `.npmrc`. Entering a hostile repo is safe.
- **Zero runtime dependencies.** Only Node built-ins. CI fails if a runtime dependency is added.
- **Minimal data leaves your machine**: only `name` + `version` pairs go to
  [OSV.dev](https://osv.dev). No paths, repo names, or file contents.
- **Untrusted text is sanitized** before it reaches your terminal or a notification: no terminal
  escape injection and no bidi spoofing. Notification text goes to AppleScript as arguments, never as code.
- **Local state is private**: `~/.selfguard` is created `0700` and its files `0600`.
- **Releases use npm Trusted Publishing with provenance**, so no long-lived publish token exists.

## How it works

```
cd ──► zsh hook (pure shell: walk up for package.json, stat lockfile on each prompt)
         │ only when the project or lockfile changes
         ▼
   selfguard hook-enter ──► cached summary on stderr
         │ lockfile changed / never scanned / >24h
         ▼
   detached background scan ──► parse lockfile ──► OSV querybatch ──► ~/.selfguard
                                                                    └─► macOS notification on new findings
```

Supported today: `package-lock.json` / `npm-shrinkwrap.json` (v1, v2, v3). pnpm, yarn and bun
lockfiles are detected but not parsed yet.

## Development

```sh
npm ci --ignore-scripts
npm test          # node:test runs the TypeScript sources directly (Node >= 22.18)
npm run build     # emits dist/
```

## License

MIT
