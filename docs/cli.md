# CLI reference

```text
selfguard <command> [options]
```

Every command accepts `--json` to print a single JSON document on stdout instead of
human-readable output (see [AI and automation](ai-and-automation.md#json-output)).

- [Setup](#setup): `setup`, `init`, `schedule`
- [Projects](#projects): `status`, `scan`, `report`, `sync`, `where`, `vuln`
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

macOS only. Installs a per-user launchd agent (`~/Library/LaunchAgents/dev.selfguard.sync.plist`)
that runs `selfguard sync --background` periodically and once at login.

| Option | Default | |
|---|---|---|
| `--every` | `6h` | Interval like `30m`, `6h`, `1d`. Minimum `15m`. |

The agent stores the absolute path of the Node.js binary that ran `schedule on`. If you change
Node versions (nvm, fnm, Homebrew upgrade), run `selfguard schedule on` again.

---

## Projects

### `selfguard status [--vulnerable] [--flat]`

All tracked projects, riskiest first. Git worktrees and clones of the same repository are
grouped under one entry, with each checkout's branch. The headline shows the main checkout and
mentions a branch that is worse.

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
| `NO_COLOR` | Disable colored output ([no-color.org](https://no-color.org)). Color is also off when stdout isn't a terminal. |

## Files

| Path | |
|---|---|
| `~/.selfguard/config.json` | Watched folders (`roots`) and exclusions (`exclude`). |
| `~/.selfguard/repos/*.json` | One record per tracked project: dependencies, findings, last scan. |
| `~/.selfguard/cache/vulns/*.json` | Cached advisories, refreshed when OSV reports a change. |
| `~/.selfguard/selfguard.log` | Log of background scans and syncs. |
| `~/Library/LaunchAgents/dev.selfguard.sync.plist` | macOS scheduled sync (`schedule on`). |

The state directory is created with mode `0700` and its files with `0600`.
