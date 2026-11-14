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

The setup wizard walks you through four steps:

1. **Choose your code folders.** selfguard suggests common locations that exist on your machine
   (`~/code`, `~/dev`, `~/projects`, `~/repository`, `~/Documents/GitHub`…) and counts the
   projects in each as you browse. Use <kbd>space</kbd> to select, <kbd>←</kbd>/<kbd>→</kbd> to
   change how deep it looks (default 5 levels, max 10), and <kbd>a</kbd> to add any other
   folder.
2. **Scan the projects it found.** This sends only package names and versions to OSV.dev and
   prints a summary of what is vulnerable.
3. **Install the shell hook.** It adds one line to `~/.zshrc` so projects are tracked when you
   `cd` into them.
4. **Enable the background sync** (macOS). selfguard checks everything every 6 hours and sends a
   notification when something new turns up.

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

Once set up, you mostly don't have to do anything:

- **Entering a project** prints a one-line reminder if it has known vulnerabilities:
  ```text
  selfguard 3 vulnerable package(s) (1 critical, 4 high, 4 moderate) → selfguard scan
  ```
- **Installing or updating dependencies** changes the lockfile. selfguard notices on your next
  prompt and re-scans in the background.
- **New advisories** published for packages you already have are picked up by the scheduled
  sync. You get a notification naming the repo and the version to upgrade to.

Useful commands:

```sh
selfguard status                # everything, riskiest first
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

After reinstalling, selfguard re-scans on your next prompt, or run `selfguard scan` to verify.

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

Desktop notifications are not implemented on Linux yet. New findings are recorded and shown by
`selfguard status` and by the shell hook.

## Uninstall

```sh
selfguard schedule off                 # macOS: remove the launchd agent
npm uninstall -g selfguard
rm -rf ~/.selfguard                    # all local state
```

Then delete the `eval "$(selfguard init zsh)"` line (and the comment above it) from `~/.zshrc`.
If you registered the MCP server, remove it too (`claude mcp remove selfguard`).
