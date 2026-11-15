# Getting started

## Requirements

- **Node.js 20.10 or newer.** `node --version` to check.
- **macOS or Linux.** Everything works on both, except native notifications and the scheduled
  background sync, which are macOS-only for now. On Linux you can schedule `sync` with cron
  instead (see [below](#linux-schedule-with-cron)).
- **zsh** for the automatic shell hook (the default shell on macOS). Other shells can still use
  every command; only the automatic "register on `cd`" behavior needs zsh.

## Install

```sh
npm install -g selfguard
selfguard --version
```

selfguard has no runtime dependencies and no install scripts. You can check that the package
you installed was built by this repository's GitHub Actions and not tampered with:

```sh
npm audit signatures   # run inside any project that depends on selfguard
npm view selfguard dist.attestations
```

## Set up

```sh
selfguard setup
```

The setup wizard walks you through these steps:

1. **Choose your code folders.** selfguard suggests common locations that exist on your machine
   (`~/code`, `~/dev`, `~/projects`, `~/repository`, `~/Documents/GitHub`…) and counts the
   projects in each as you browse. Use <kbd>space</kbd> to select, <kbd>←</kbd>/<kbd>→</kbd> to
   change how deep it looks (default 5 levels, max 10), and <kbd>a</kbd> to add any other
   folder.
2. **Scan the projects it found.** This sends only package names and versions to OSV.dev and
   prints a summary of what is vulnerable.
3. **Install the shell hook.** It adds one line to `~/.zshrc` so projects are tracked when you
   `cd` into them.
4. **Enable background watching** (macOS). A lockfile watcher re-checks a repo seconds after its
   lockfile changes, a full sync runs every 6 hours, and a daily reminder sums up what is still
   open and serious.
5. **Add selfguard.app** (macOS) to open the dashboard from Spotlight or the Dock.

Each step asks first, and you can re-run `selfguard setup` at any time to change your folders.

### Non-interactive setup

For dotfiles, provisioning scripts or AI agents, the same can be done without the wizard:

```sh
selfguard roots add ~/code --depth 5   # watch a folder
selfguard discover                     # register and scan its projects
echo 'eval "$(selfguard init zsh)"' >> ~/.zshrc
selfguard schedule on --every 6h       # macOS
```

## Daily use

Once set up, you mostly don't have to do anything. selfguard notifies you when:

| What happened | Notification |
|---|---|
| A new advisory affects a repo you work on, or you install a vulnerable version | `selfguard: acme/web` · `2 vulnerable packages · worst: HIGH` · `axios → 1.20.0, …` |
| You fixed something (upgrade, `git pull` of a fix, merge) | `selfguard: acme/web ✓` · `17 vulnerable packages fixed` |
| Once a day (09:00–21:00), if serious issues are still open | `selfguard: 3 repos need attention` · `worst: CRITICAL` |
| A malicious package appears anywhere | A dialog that stays on screen, with remediation steps |

"Serious" means malicious packages, critical vulnerabilities outside dev dependencies, and high
ones in direct dependencies. Everything else is in the dashboard, not in your notifications.
Only **active** checkouts (git activity in the last 30 days) alert you; see
[how it works](how-it-works.md#alerts). Change the reminder with
`selfguard settings --remind weekly` (or `off`).

### Dashboard

```sh
selfguard ui
```

Opens a local page in your browser (served from `127.0.0.1` only, with a per-session token):

- **Overview**: whether anything needs attention, counts by severity, and **Fix first**: the
  serious packages ranked by how many repos they affect.
- **Repos**: every repo with its worst severity, serious and vulnerable counts, checkouts and
  last activity. A repo's page lists its vulnerable packages on the main checkout (or all
  checkouts) with the version that fixes each one, which branches have it and the advisories.
  Re-scan or ignore a checkout from there.
- **Packages**: vulnerable packages across all your repos, each installed version with its fix,
  and the repos that have it. "Upgrading `next` fixes 5 repos."
- **Activity**: what appeared, what got fixed and which reminders were sent.
- **Folders**: add folders to watch with a folder browser, change how deep to look, remove them,
  look for new projects, and include excluded paths again.
- **Settings**: reminder frequency, the active window, background watching on/off and
  selfguard.app.

The dashboard runs in the background and stops by itself after 30 minutes without use. Running
`selfguard ui` again reopens it.

On macOS, `selfguard app install` (also offered by `setup`) adds **selfguard.app** to
`~/Applications`, so you can open the dashboard from Spotlight (<kbd>⌘</kbd>+<kbd>Space</kbd> →
"selfguard") or keep it in the Dock.

### In the terminal

- **Entering a project** prints a one-line reminder if it has known vulnerabilities:
  ```text
  selfguard 3 vulnerable package(s) (1 critical, 4 high, 4 moderate) → selfguard scan
  ```
- **Installing or updating dependencies** changes the lockfile. selfguard notices on your next
  prompt and re-scans in the background.
- **New advisories** published for packages you already have are picked up by the scheduled
  sync. You get a notification naming the repo and the version to upgrade to.
- **Pulling a fix** (`git pull`, merging a dependency PR) is noticed by the lockfile watcher
  within seconds, even if you never open a terminal in that repo.

Useful commands:

```sh
selfguard ui                    # dashboard
selfguard remind                # what is serious and still open, right now
selfguard status                # active repos, riskiest first (--all for everything)
selfguard scan                  # full report for the current project
selfguard where @ctrl/tinycolor # "is this compromised package anywhere on my machine?"
selfguard vuln GHSA-35jh-r3h4-6jhm
```

See the [CLI reference](cli.md) for every command.

## Fixing what selfguard finds

For each vulnerable package selfguard tells you:

- **Direct or transitive.** A direct dependency is declared in your `package.json`. A
  transitive one is pulled in by another package.
- **`upgrade to X or later`.** The lowest version that fixes every advisory with a published fix.

Typical fixes:

- **Direct dependency:** bump it in `package.json` to at least the suggested version and
  reinstall.
- **Transitive dependency:** upgrade the direct dependency that pulls it in. If no compatible
  release exists, force the fixed version with your package manager's overrides:
  [npm `overrides`](https://docs.npmjs.com/cli/configuring-npm/package-json#overrides),
  [pnpm `overrides`](https://pnpm.io/package_json#pnpmoverrides) or
  [yarn `resolutions`](https://yarnpkg.com/configuration/manifest#resolutions).
- **Malicious package:** remove it immediately, reinstall from a clean state, and **rotate any
  credentials** the machine or CI could reach (npm tokens, cloud keys, SSH keys, `.env`
  secrets). Upgrading is not enough: the damage happens at install time.

After reinstalling, the lockfile watcher re-scans within seconds and confirms the fix with a
"✓ fixed" notification. You can also run `selfguard scan` to verify.

## Ignoring projects

Test fixtures, examples and archived repos often pin old versions on purpose. Stop tracking
them and keep them out of future discovery:

```sh
selfguard forget ~/code/shop/test/fixtures   # also hides everything below it
selfguard unexclude ~/code/shop/test/fixtures  # undo
```

## Linux: schedule with cron

`selfguard schedule` uses launchd and is macOS-only. On Linux, add a cron entry instead
(`crontab -e`), using the absolute paths printed by `command -v node` and `command -v selfguard`:

```cron
0 */6 * * * /usr/bin/node /usr/local/bin/selfguard sync --background >> "$HOME/.selfguard/selfguard.log" 2>&1
```

Desktop notifications and the lockfile watcher are not implemented on Linux yet. New findings
are recorded and shown by `selfguard ui`, `selfguard status` and the shell hook.

## Uninstall

```sh
selfguard schedule off                 # macOS: remove the launchd agents
selfguard app uninstall                # macOS: remove ~/Applications/selfguard.app
npm uninstall -g selfguard
rm -rf ~/.selfguard                    # all local state
```

Then delete the `eval "$(selfguard init zsh)"` line (and the comment above it) from `~/.zshrc`.
If you registered the MCP server, remove it too (`claude mcp remove selfguard`).
