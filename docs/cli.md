# CLI reference

```text
selfguard <command> [options]
```

Every command accepts `--json` to print a single JSON document on stdout instead of
human-readable output (see [AI and automation](ai-and-automation.md#json-output)).

- [Setup](#setup): `setup`, `init`, `schedule`
- [Dashboard and alerts](#dashboard-and-alerts): `ui`, `remind`, `settings`
- [Projects](#projects): `status`, `scan`, `report`, `sync`, `check`, `where`, `vuln`
- [Folders](#folders): `roots`, `discover`, `forget`, `unexclude`
- [AI and automation](#ai-and-automation): `mcp`, `guide`
- [Exit codes](#exit-codes) · [Environment variables](#environment-variables) · [Files](#files)

---

## Setup

### `selfguard setup`

Interactive wizard. Choose the folders where you keep code, scan the projects found there,
then optionally install the zsh hook and the background sync. Requires an interactive terminal.
Use `roots add` + `discover` in scripts.

### `selfguard init zsh`

Prints the zsh hook. Add it to `~/.zshrc`:

```sh
eval "$(selfguard init zsh)"
```

The hook is plain zsh, so most prompts cost nothing. It only calls selfguard when you enter a
different project, or when that project's lockfile changes. Scans that need the network always
run in a detached background process, so your prompt never waits. Only zsh is supported for now.

### `selfguard schedule on [--every <interval>] | off | status`

macOS only. Installs two per-user launchd agents:

- `dev.selfguard.sync` runs `selfguard sync --background` periodically and once at login. It
  discovers new projects, re-checks everything against new advisories, and sends the reminder
  when it is due.
- `dev.selfguard.watch` runs `selfguard check --background` when the lockfile or folder of an
  active checkout changes (at most every 15 seconds). It watches up to 200 paths, most recently
  active first, and is refreshed after each sync.

| Option | Default | |
|---|---|---|
| `--every` | `6h` | Interval like `30m`, `6h`, `1d`. Minimum `15m`. |

The agent stores the absolute path of the Node.js binary that ran `schedule on`. If you change
Node versions (nvm, fnm, Homebrew upgrade), run `selfguard schedule on` again.

---

## Dashboard and alerts

### `selfguard ui [--no-open] [--port N]`

Opens the local dashboard in your browser. It is served on `127.0.0.1` by a background process
that stops after 30 minutes without use. If one is already running, it is reused. The URL
carries a per-session token. See the [security model](security-model.md#dashboard).

| Option | |
|---|---|
| `--no-open` | Print the URL without opening a browser. |
| `--port` | Port to listen on (default: a random free port). |

### `selfguard remind [--dry-run]`

Lists the serious open issues in your active repos and sends the reminder notification now.
"Serious" means malicious packages, critical vulnerabilities outside dev dependencies, and high
ones in direct dependencies. Each repo is judged by its main checkout (or its most recently
active one). `--dry-run` only prints. The scheduled reminder uses the same list.

### `selfguard settings [--remind daily|weekly|off] [--active-days N]`

Shows or changes alert settings.

| Option | Default | |
|---|---|---|
| `--remind` | `daily` | How often to send the reminder. It is only sent between 09:00 and 21:00, and only if something serious is open. |
| `--active-days` | `30` | Checkouts without git activity (commits, checkouts, pulls, `git status`) for longer are inactive. They are listed but only alert for malicious packages. |

---

## Projects

### `selfguard status [--vulnerable] [--flat] [--all]`

Tracked projects, riskiest first. Git worktrees and clones of the same repository are grouped
under one entry, with each checkout's branch. The headline shows the main checkout and mentions
a branch that is worse. Inactive repos and checkouts are hidden unless you pass `--all`.

| Option | |
|---|---|
| `--vulnerable` | Only show repos with findings. |
| `--flat` | One line per folder instead of grouping by repository. |

Reads local state only (no network).

### `selfguard scan [dir] [-v|--verbose]`

Scans the project containing `dir` (default: current directory) against OSV.dev now, and starts
tracking it if it is new. The project is the nearest folder with a lockfile, so running it
inside a monorepo package scans the monorepo root.

| Option | |
|---|---|
| `-v`, `--verbose` | List every advisory, not just the first three per package. |

Exits with code `1` if any vulnerability is found, which makes it usable as a CI gate.

### `selfguard report [dir] [-v|--verbose]`

Same output as `scan`, but from the last stored scan, with no network. Exits `1` if the last scan
found vulnerabilities, `2` if the project is not tracked.

### `selfguard sync`

1. Stops tracking folders that no longer exist (for example, removed worktrees).
2. Discovers new projects in your watched folders.
3. Re-checks every tracked project against OSV.dev in a single batched query.
4. Reports and notifies (macOS) only about **findings that are new** since the previous check.

All dependencies across all projects are de-duplicated before querying, so syncing hundreds of
projects takes seconds.

### `selfguard check`

Re-scans only the tracked projects whose lockfile changed since their last scan. It is fast
(a `stat` per project), and it is what the lockfile watcher runs.

### `selfguard where <package>`

Lists the tracked projects that depend on `<package>` (direct or transitive), with the installed
versions. Vulnerable versions are highlighted. Exact npm package names only, e.g. `lodash` or
`@scope/name`. No network.

### `selfguard vuln <id>`

Shows an advisory (`GHSA-…`, `CVE-…`, `MAL-…`): severity, summary, affected ranges, and which of
your tracked projects it affects, with the fixed version for each.

---

## Folders

### `selfguard roots [list]`
### `selfguard roots add <dir> [--depth N]`
### `selfguard roots remove <dir>`

Manage the folders where projects are discovered. `--depth` is how many directory levels below
the folder to search (default `5`, max `10`). Removing a folder doesn't stop tracking projects
already registered from it. Use `forget` for that.

### `selfguard discover [--dry-run]`

Searches the watched folders for projects that aren't tracked yet, then registers and scans them.
With `--dry-run`, only lists what it would add. `sync` runs the same discovery automatically.

### `selfguard forget [dir] [--keep-discoverable]`

Stops tracking the project containing `dir` (default: current directory). By default it also
**excludes** that path from discovery, along with every project below it, so it doesn't come back.

| Option | |
|---|---|
| `--keep-discoverable` | Only stop tracking. The next `sync` may register it again. |

### `selfguard unexclude <dir>`

Removes a path from the exclusion list so discovery can find it again.

---

## AI and automation

### `selfguard mcp`

Runs the [MCP](https://modelcontextprotocol.io) server over stdio. See
[AI and automation](ai-and-automation.md#mcp-server) for client setup and the tool list.

### `selfguard guide`

Prints a concise usage guide written for AI agents. The MCP server also sends it to clients as
its instructions.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. |
| `1` | `scan` / `report` found at least one vulnerability. |
| `2` | Usage error or runtime error. With `--json`, stdout contains `{"error":{"code","message"}}`. |

Error codes in JSON mode: `usage`, `not_found`, `no_project`, `not_tracked`, `no_roots`,
`invalid`, `busy`, `error`.

## Environment variables

| Variable | |
|---|---|
| `SELFGUARD_HOME` | State directory. Default `~/.selfguard`. |
| `SELFGUARD_NO_NOTIFY=1` | Disable notifications and dialogs (useful in tests and CI). |
| `SELFGUARD_OSV_API` | OSV API base URL. Default `https://api.osv.dev/v1`. For mirrors and tests. |
| `SELFGUARD_NO_LAUNCHD=1` | Never install or change launchd agents (tests). |
| `NO_COLOR` | Disable colored output ([no-color.org](https://no-color.org)). Color is also off when stdout isn't a terminal. |

## Files

| Path | |
|---|---|
| `~/.selfguard/config.json` | Watched folders (`roots`), exclusions (`exclude`), `remind` and `activeDays`. |
| `~/.selfguard/state.json` | When the last reminder, sync and check ran. |
| `~/.selfguard/events.jsonl` | Activity log shown in the dashboard (new findings, fixes, reminders). Capped. |
| `~/.selfguard/ui.json` | Port, PID and token of the running dashboard. Removed when it stops. |
| `~/.selfguard/repos/*.json` | One record per tracked project: dependencies, findings, last scan. |
| `~/.selfguard/cache/vulns/*.json` | Cached advisories, refreshed when OSV reports a change. |
| `~/.selfguard/selfguard.log` | Log of background scans and syncs. |
| `~/Library/LaunchAgents/dev.selfguard.sync.plist` | macOS scheduled sync (`schedule on`). |
| `~/Library/LaunchAgents/dev.selfguard.watch.plist` | macOS lockfile watcher (`schedule on`). |

The state directory is created with mode `0700` and its files with `0600`.
