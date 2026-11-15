# CLI reference

```text
selfguard <command> [options]
```

Every command accepts `--json` to print a single JSON document on stdout instead of
human-readable output (see [AI and automation](ai-and-automation.md#json-output)).

- [Setup](#setup): `setup`, `init`, `schedule`
- [Dashboard and alerts](#dashboard-and-alerts): `ui`, `app`, `remind`, `settings`
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

### `selfguard app install | uninstall | status`

macOS only. Creates `~/Applications/selfguard.app`, a launcher for the dashboard, so you can
open it from Spotlight (<kbd>⌘</kbd>+<kbd>Space</kbd> → "selfguard"), Launchpad or the Dock.

The app is generated on your machine, not downloaded, so macOS doesn't quarantine it and it
needs no Apple signature. It contains an icon, an `Info.plist` and a two-line shell script that
runs `selfguard ui` with the absolute paths of your Node.js and selfguard. `status` tells you if
it points at a different Node.js (after switching versions); `install` again to fix it.
`schedule on` also refreshes it.

Notifications still come from Script Editor (see [troubleshooting](troubleshooting.md#i-dont-see-notifications)),
so clicking one doesn't open the dashboard.

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

### `selfguard report [dir] [-v|--verbose] [-m|--markdown]`

Same output as `scan`, but from the last stored scan, with no network. Exits `1` if the last scan
found vulnerabilities, `2` if the project is not tracked.

With `--markdown`, it prints a markdown report instead: every vulnerable package
(serious first), the version that fixes it, whether to bump package.json or override a
transitive dependency, and how to refresh the lockfile with install scripts disabled. Copy it with
`selfguard report -m | pbcopy`. The dashboard's **Copy markdown**
button produces the same text.

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

## Other machines

Watch dev servers from this machine over SSH. By default selfguard uses a dedicated key that
the machine accepts only for a small read-only *reader*, limited to one folder. Lockfiles are
scanned here. See [Other machines](security-model.md#other-machines) in the security model.

### `selfguard machines [list]`

Machines, their folders, how many projects each has and how the last sync went.

### `selfguard machines peers`

Machines on your tailnet (`tailscale status`), to pick a host from.

### `selfguard machines test <host>`

Checks that `ssh <host>` works without prompts and prints the remote OS and home folder.

### `selfguard machines add <host> [options]`

`<host>` is anything `ssh` accepts as a destination: an alias, a tailnet name or `user@host`.

| Option | |
|---|---|
| `--name N` | Name shown everywhere. Default: the first label of the host (`devbox.tail123.ts.net` → `devbox`). |
| `--scope DIR` | Restricted mode: the only folder the reader allows. Default `~`. |
| `--root DIR` (repeatable), `--depth N` | Folders to watch (inside the scope). Absolute or `~/…`. |
| `--port N` | SSH port. |
| `--manual` | Don't install the reader now; see `setup`. |
| `--mode ssh` | Use your own SSH access (keys or Tailscale SSH) instead of a restricted key. |

In restricted mode it creates the key and installs the reader with your SSH access, which must
work without prompts. If it can't, the machine is saved and `setup` shows what to paste on it.

```sh
selfguard machines add devbox.tail123.ts.net --scope ~/code --root ~/code --depth 4
```

### `selfguard machines setup <name>`

Prints the install command for a restricted machine: the reader, the `authorized_keys` line
and where they go. Paste it in a terminal on the machine, then run `verify`.

### `selfguard machines install <name>` / `verify <name>`

`install` (re)installs the reader with your SSH access, for example after a selfguard update
reports it outdated. `verify` checks that the machine answers through the restricted key.

### `selfguard machines roots <name> add <dir> [--depth N] | remove <dir>`

Manage the folders watched on a machine.

### `selfguard machines sync [name]`

Lists projects on the machines (one SSH session each). It fetches only lockfiles that changed
and scans new and changed projects. `selfguard sync` also re-checks every remote project against
new advisories, reusing the dependencies it already parsed. A machine that doesn't answer keeps
its last results and shows the error. The first sync of a machine is logged but doesn't notify.

### `selfguard machines remove <name> [--keep-remote]`

Forgets the machine, its results and its key. In restricted mode it also removes the key line
(and the reader, if no other selfguard key uses it) from the machine with your SSH access,
unless `--keep-remote`.

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
| `SELFGUARD_SSH` | ssh client to use for other machines. Default `ssh` from `PATH`. |
| `NO_COLOR` | Disable colored output ([no-color.org](https://no-color.org)). Color is also off when stdout isn't a terminal. |

## Files

| Path | |
|---|---|
| `~/.selfguard/config.json` | Watched folders (`roots`), exclusions (`exclude`), `remind`, `activeDays` and other `machines`. |
| `~/.selfguard/state.json` | When the last reminder, sync and check ran. |
| `~/.selfguard/events.jsonl` | Activity log shown in the dashboard (new findings, fixes, reminders). Capped. |
| `~/.selfguard/ui.json` | Port, PID and token of the running dashboard. Removed when it stops. |
| `~/.selfguard/repos/*.json` | One record per tracked project: dependencies, findings, last scan. |
| `~/.selfguard/machines/<name>/` | Records and last sync status of another machine. |
| `~/.selfguard/ssh/<name>_ed25519` | Restricted key for that machine (only runs its reader). |
| `~/.selfguard-reader/reader.sh` (on the machine) | The read-only reader, run by sshd for the restricted key. |
| `~/.selfguard/cache/vulns/*.json` | Cached advisories, refreshed when OSV reports a change. |
| `~/.selfguard/selfguard.log` | Log of background scans and syncs. |
| `~/Library/LaunchAgents/dev.selfguard.sync.plist` | macOS scheduled sync (`schedule on`). |
| `~/Library/LaunchAgents/dev.selfguard.watch.plist` | macOS lockfile watcher (`schedule on`). |
| `~/Library/LaunchAgents/dev.selfguard.remote.plist` | Checks other machines every 15 minutes (`schedule on`, when you have machines). |
| `~/Applications/selfguard.app` | macOS launcher for the dashboard (`app install`). |

The state directory is created with mode `0700` and its files with `0600`.
