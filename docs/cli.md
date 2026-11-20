# CLI reference

```text
selfguard <command> [options]
```

Every command accepts `--json` to print a single JSON document on stdout instead of
human-readable output (see [AI and automation](ai-and-automation.md#json-output)).

- [Setup](#setup): `setup`, `init`, `schedule`
- [Alerts and the Mac app](#alerts-and-the-mac-app): `remind`, `update`, `settings`, internal `menubar`, `bridge`
- [Projects](#projects): `status`, `scan`, `report`, `sync`, `check`, `where`, `vuln`
- [Folders](#folders): `roots`, `discover`, `forget`, `unexclude`, `dismiss`, `undismiss`
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

## Alerts and the Mac app

The CLI is for the terminal. The dashboard exists only inside the selfguard Mac app (menu bar →
Open Dashboard, [latest release](https://github.com/josseed/selfguard/releases/latest)); no CLI
command opens it. The commands below marked internal are what the app's bundled engine runs.

### `selfguard menubar [--json]` (internal)

Rewrites `~/.selfguard/menubar.json` and prints it: the summary the Mac app shows in its menu
bar (state, repos that need attention, latest findings and fixes, services, last check and
sync). selfguard also rewrites it after every scan that finds or fixes something, and after
`dismiss`, `undismiss`, `forget` and `sync`. Local only, no network.

### `selfguard bridge` (internal)

Used by the Mac app, not by people: serves the dashboard's JSON API over stdio, one JSON object
per line each way.

```text
{"id": 1, "method": "GET", "path": "/api/overview", "query": {"key": "…"}, "body": {…}}
{"id": 1, "status": 200, "data": {…}}
{"id": 1, "status": 404, "error": {"code": "not_found", "message": "…"}}
```

Requests run concurrently and answers carry the `id`. `method` is `GET` or `POST`, `path`
starts with `/api/`. A malformed line gets an answer with `"id": null`; lines over 1 MB are
refused. It exits when stdin closes. Nothing but the protocol is written to stdout. To try it:
`printf '{"id":1,"method":"GET","path":"/api/ping"}\n' | selfguard bridge`.

### `selfguard remind [--dry-run]`

Lists the serious open issues in your active repos and sends the reminder notification now.
"Serious" means malicious packages, critical vulnerabilities outside dev dependencies, and high
ones in direct dependencies. Each repo is judged by its main checkout (or its most recently
active one). `--dry-run` only prints. The scheduled reminder uses the same list.

### `selfguard update`

Asks npm for the latest selfguard right away. If a newer one exists, it prints the release notes
link, whether the release has npm provenance, and the command to install it
(`npm i -g selfguard@<version> --ignore-scripts`). selfguard never installs anything by itself.
Otherwise this check runs at most once a day from the background sync. Each new version gets one
notification and a banner in the dashboard. `status` also mentions it, from the cache, with no
network call. After you update, the dashboard offers **Restart dashboard**.

### `selfguard settings [--remind daily|weekly|off] [--active-days N] [--auto-discover on|off] [--update-check on|off]`

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

Exits with code `1` if any vulnerability is found, which makes it usable as a CI gate. The
repo's GitHub Actions workflows and agent configs are checked in the same pass; when they have
findings or warnings, one line points to `selfguard tools <dir>` (they don't change the exit
code).

### `selfguard tools [dir] [-v|--verbose]`

Last results for what runs beside your lockfiles: this machine's **agent tools** (MCP servers
from Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Codex and Gemini CLI configs) and
each repo's **GitHub Actions** workflows and project agent configs, plus **This machine**:
launch items, shell startup files, package manager and git config, plaintext credential files
and Python startup hooks (also in each repo's virtualenvs), high warnings first. With `dir`,
only the git repo around it. Shows findings with their certainty (confirmed, may be affected,
version unknown), file and line, and warnings such as unpinned actions or MCP servers. Reads
local state only; `scan`, `sync` and `check` refresh it. See
[CI workflows and agent tools](ci-and-agent-tools.md) and [This machine](host.md).

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

### `selfguard where <package> [--ecosystem <name>]`

Lists the tracked projects that depend on `<package>` (direct or transitive), with the installed
versions and their ecosystem, including actions in CI workflows and MCP servers in agent configs
(marked as such). Vulnerable versions are highlighted. Use exact names: npm
(`lodash`, `@scope/name`), PyPI (`requests`; compared PEP 503-normalized, so `Django` and
`django` match), crates.io (`serde`), a Go module path (`golang.org/x/net`) or a GitHub action
(`tj-actions/changed-files`, any case). By default every ecosystem is searched;
`--ecosystem npm|PyPI|crates.io|Go|"GitHub Actions"` narrows it. No network.

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

### `selfguard discover --everywhere [--dry-run] [--yes]`

Searches your whole home folder (read-only, a minute or two; see
[How it works](how-it-works.md#finding-projects) for what it skips) and lists the **places**
it would watch: folders with their project count, active repos and depth. Recommended places,
those with active repos, are checked.

- **In a terminal:** asks before watching the checked places.
- **With `--yes`:** watches them without asking.
- **With `--dry-run`, or `--json` without `--yes`:** only lists them.

With `--background`, it is the weekly automatic pass. Settings decides whether it runs
(`--auto-discover`), and it only searches when the last search is a week old.

### `selfguard forget [dir] [--keep-discoverable]`

Stops tracking the project containing `dir` (default: current directory). By default it also
**excludes** that path from discovery, along with every project below it, so it doesn't come back.
It works on a whole folder too (for example `~/code/old-clients`): the folder and every project
inside stop being tracked, scanned and alerted, including projects created there later. (The
dashboard's "Ignore folder" button is gentler: the folder is only paused, and a project inside
comes back by itself when its lockfile, `package.json` or git log changes. `selfguard unexclude`
clears both.)

| Option | |
|---|---|
| `--keep-discoverable` | Only stop tracking. The next `sync` may register it again. |

### `selfguard unexclude <dir>`

Removes a path from the exclusion list so discovery can find it again. (The dashboard's
"Include again" also searches that folder right away; from the CLI run `selfguard discover`.)

### `selfguard dismiss [dir|key] [--list]`

Turns off the repo containing `dir` (default: current directory), or the repo with that key
(as shown by `status --json` or `dismiss --list`, useful for other machines). Every checkout of
the repo counts as inactive (no reminders, alerts only for malicious packages, hidden from
`status` without `--all`) until one of them has git activity again: then it turns back on by
itself. Dismissing again restarts the clock. `--list` shows the dismissed repos.

### `selfguard undismiss [dir|key]`

Turns a dismissed repo back on now.

---

## Other machines

Watch the repos of your other machines. Machines that run selfguard connect through
**selfguard sharing** over Tailscale (paired once, approved over there, no SSH). Servers
without it use SSH with a dedicated key that only runs a small read-only *reader*. Either way,
lockfiles are scanned here. See [Other machines](security-model.md#other-machines) in the
security model.

### `selfguard machines [list]`

Machines, their folders, how many projects each has and how the last sync went.

### `selfguard machines peers`

Machines on your tailnet, each with what it can do (about 1.5 s of probing). Online or offline
and last seen, selfguard sharing on, SSH port open, Tailscale SSH, already added. It also
prints the recommended next step. `--json` returns all of it.

### `selfguard machines add <peer> --via share`

Pairs with a tailnet machine that has selfguard sharing on. It shows a 6-digit code, then waits
up to 5 minutes for you to approve it on that machine (its dashboard, or
`selfguard share approve`). The folders it suggests are added. Without `--via`,
`machines add` uses sharing when the machine answers and SSH otherwise. SSH-only options
(`--mode`, `--root`, `--depth`, `--scope`, `--port`, `--manual`) always mean SSH, as before 0.8.
`--name` must not belong to another machine. To pair an existing machine again, use `migrate`.

### `selfguard machines migrate <name> --via share|ssh`

Switches how an existing machine is reached and keeps its name, history and folders. `share`
pairs with it. `ssh` installs the restricted reader with your SSH access.

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

## Sharing

Let your other machines see this one, over Tailscale, without SSH.

### `selfguard share on | off | status [--port N] [--allow-other-users]`

`on` starts the sharing service: a launchd agent on macOS, or a systemd user unit
(`selfguard-share.service`) on Linux. It listens only on this machine's Tailscale addresses,
port 47821 by default. Pairing is limited to your own Tailscale user unless
`--allow-other-users`. `off` stops answering at once. `status` shows addresses, pending
requests and paired machines.

### `selfguard share requests`, `approve <id> [--scope DIR] [--root DIR]...`, `reject <id>`

Pending pairing requests, with the code to compare with the other screen. `approve` grants
read access to lockfiles under `--scope` (default `~`) and suggests `--root` folders (default:
this machine's watched folders).

### `selfguard share list`, `revoke <name>`

Machines that can see this one (last connection, folder), and how to cut one off.

### `selfguard share serve`

The service itself (what the agent runs). It waits for a Tailscale address and follows
address changes.

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
| `SELFGUARD_SYSTEM_ROOT` | Folder that stands for `/` when reading `/Library/LaunchAgents` and `/Library/LaunchDaemons` (tests). |
| `SELFGUARD_SSH` | ssh client to use for other machines. Default `ssh` from `PATH`. |
| `SELFGUARD_TAILSCALE` | Path of the `tailscale` CLI (default: the usual install locations). |
| `SELFGUARD_NO_UPDATE_CHECK=1` | Never ask npm for a newer selfguard. |
| `SELFGUARD_NPM_REGISTRY` | Registry for the update check. Default `https://registry.npmjs.org`. |
| `NO_COLOR` | Disable colored output ([no-color.org](https://no-color.org)). Color is also off when stdout isn't a terminal. |

## Files

| Path | |
|---|---|
| `~/.selfguard/config.json` | Watched folders (`roots`), exclusions (`exclude`), `remind`, `activeDays` and other `machines`. |
| `~/.selfguard/state.json` | When the last reminder, sync and check ran. |
| `~/.selfguard/events.jsonl` | Activity log shown in the dashboard (new findings, fixes, reminders). Capped. |
| `~/.selfguard/repos/*.json` | One record per tracked project: dependencies, findings, last scan. |
| `~/.selfguard/machines/<name>/` | Records and last sync status of another machine. |
| `~/.selfguard/machines/<name>/share.json` | Credential for a machine paired through sharing (mode `0600`). |
| `~/.selfguard/share/` | Sharing on this machine: grants (credential hashes), pending requests, access log. |
| `~/Library/LaunchAgents/dev.selfguard.share.plist` | Sharing service (`share on`); on Linux `~/.config/systemd/user/selfguard-share.service`. |
| `~/.selfguard/ssh/<name>_ed25519` | Restricted key for that machine (only runs its reader). |
| `~/.selfguard-reader/reader.sh` (on the machine) | The read-only reader, run by sshd for the restricted key. |
| `~/.selfguard/cache/vulns/*.json` | Cached advisories, refreshed when OSV reports a change. |
| `~/.selfguard/selfguard.log` | Log of background scans and syncs. |
| `~/Library/LaunchAgents/dev.selfguard.sync.plist` | macOS scheduled sync (`schedule on`). |
| `~/Library/LaunchAgents/dev.selfguard.watch.plist` | macOS lockfile watcher (`schedule on`). |
| `~/Library/LaunchAgents/dev.selfguard.discover.plist` | Weekly "find my projects" in the background (`schedule on`, unless `--auto-discover off`). |
| `~/Library/LaunchAgents/dev.selfguard.remote.plist` | Checks other machines every 15 minutes (`schedule on`, when you have machines). |

The state directory is created with mode `0700` and its files with `0600`.
