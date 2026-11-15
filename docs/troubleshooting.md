# Troubleshooting

## I don't see notifications

selfguard delivers macOS notifications through `osascript`, so macOS lists them under
**Script Editor**.

1. Open **System Settings → Notifications → Script Editor** and make sure notifications are
   allowed, with the alert style set to **Banners** or **Alerts**. If Script Editor isn't listed
   yet, trigger one notification first:
   ```sh
   osascript -e 'display notification "test" with title "selfguard"'
   ```
2. Check that **Focus / Do Not Disturb** isn't on.
3. Banners disappear after a few seconds. Look in **Notification Center** (click the date in the
   menu bar) for ones you missed.

Malicious-package alerts also open a dialog that stays on screen, so they can't be missed.

## I don't get alerts on my own

- Check `selfguard schedule status`. It should say `enabled` and show a lockfile watcher. If not,
  run `selfguard schedule on`.
- Alerts are about **changes** (new findings, fixes) plus the daily reminder. If nothing changed
  and the reminder already went out today, you won't hear from selfguard. Run `selfguard remind`
  to see what the reminder covers and send it now.
- Only active checkouts alert (git activity in the last 30 days). Check `selfguard status --all`
  and raise the window with `selfguard settings --active-days 90` if needed.

## Too many reminders

- Switch to weekly: `selfguard settings --remind weekly`, or `off`.
- Ignore folders you don't care about (fixtures, probes, experiments) from the dashboard or with
  `selfguard forget <dir>`.
- Dev-only findings and transitive high-severity findings never trigger the reminder. They are in
  the dashboard.

## The dashboard doesn't open

- Run `selfguard ui --no-open` and open the printed URL yourself.
- selfguard.app does nothing after switching Node versions: `selfguard app status` says
  "outdated". Run `selfguard app install` again.
- "Not connected": the dashboard stopped after 30 idle minutes. Run `selfguard ui` again.
- Errors are logged to `~/.selfguard/selfguard.log`.

## The shell hook doesn't do anything

- Check that `~/.zshrc` contains `eval "$(selfguard init zsh)"`, then open a **new** terminal.
- `command -v selfguard` must print a path inside an interactive shell. If you use nvm or fnm,
  make sure they are initialized **before** the selfguard line in `~/.zshrc`.
- The hook only reacts to folders inside a project: it looks for `package.json` or a lockfile
  while walking up, and stops at the git root or your home folder.
- Only zsh is supported. In bash or fish, run `selfguard scan` manually or use the scheduled sync.

## Background scans don't seem to run

Background scans and scheduled syncs write to `~/.selfguard/selfguard.log`:

```sh
tail -n 20 ~/.selfguard/selfguard.log
```

Lines like `could not reach OSV` mean the network was unavailable. The previous findings are kept
and the next run retries.

## The scheduled sync stopped after upgrading Node

The launchd agent stores the absolute path of the Node binary that ran `schedule on`. After
switching or upgrading Node (nvm, fnm, Homebrew), re-create it:

```sh
selfguard schedule on
selfguard schedule status
```

## "bun.lockb (binary) is not supported"

selfguard reads the text lockfile `bun.lock`. Convert the project once:

```sh
bun install --save-text-lockfile
```

## "no lockfile found"

selfguard checks what is actually installed, and that lives in the lockfile. Run your package
manager's install once (`npm install`, `pnpm install`, `yarn`, `bun install`) and commit the
lockfile. With only a `package.json`, versions are ranges and can't be matched precisely.

## Some dependencies are "skipped"

Git (`github:user/repo`), `file:`, `link:` and tarball dependencies aren't published to a
registry, so advisory databases don't cover them. They are counted as skipped rather than
reported as safe.

## Too many results from fixtures, examples or old branches

- Exclude folders you don't care about: `selfguard forget <dir>`. It also hides everything below
  it from future discovery.
- Worktrees and clones of the same repo are already grouped in `selfguard status`. Use
  `status --flat` to see each folder separately.
- Removed worktrees are dropped automatically on the next `sync`.
- Old clones and worktrees without recent git activity are inactive: hidden from `status` (use
  `--all`) and quiet, except for malicious packages.

## The MCP server doesn't start in a desktop app

Desktop apps don't load your shell profile, so they may not find Node or selfguard. Use absolute
paths in the client config. See
[AI and automation](ai-and-automation.md#mcp-server).

## A machine shows "reader not installed"

The restricted key reached the machine, but the selfguard reader didn't answer:

- The install never happened. Run `selfguard machines install <name>` (it uses your own SSH
  access), or `selfguard machines setup <name>` and paste the command on the machine yourself.
- **Tailscale SSH is on for that machine.** It authorizes by tailnet policy and ignores
  `authorized_keys`, so the forced reader never runs. Turn it off there with
  `tailscale set --ssh=false` so the regular `sshd` answers over the tailnet, or add the
  machine with `--mode ssh`.
- "reader outdated": selfguard was updated and the protocol changed. Run
  `selfguard machines install <name>`.

## A machine shows "unreachable" or "SSH login failed"

selfguard connects with `ssh -o BatchMode=yes`, so anything that would prompt fails instead:

1. Run `ssh <host> true` yourself. It must finish without asking anything. Accept the host key
   once if it is new, and load your key into the agent or use a key without a passphrase
   prompt.
2. Tailscale SSH in "check" mode asks you to re-authenticate in the browser from time to time.
   Run `ssh <host> true` once to do it, or use an "accept" rule in your tailnet policy for
   your own devices.
3. `selfguard machines test <host>` shows the exact error. Background runs use the same `ssh`
   from `/usr/bin`. If you rely on a different client or config, set `SELFGUARD_SSH`.

A machine that doesn't answer keeps its last results. The next sync updates it.

## Reset everything

```sh
selfguard schedule off
rm -rf ~/.selfguard
selfguard setup
```
