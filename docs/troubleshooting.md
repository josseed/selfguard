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

## The menu bar icon doesn't show

macOS can hide a menu bar icon: when the menu bar is full (behind the notch), or when the app
isn't allowed there. Open **System Settings → Menu Bar** and turn on selfguard under "Allow in
the Menu Bar" (selfguard has to be running to be listed). selfguard keeps running while its
icon is hidden, so alerts still arrive; opening the app again (Spotlight, Finder) shows the
dashboard. A menu bar manager (Bartender, Ice) can also be hiding it.

## The dashboard doesn't open

The dashboard is the selfguard Mac app's window ([download](https://github.com/josseed/selfguard/releases/latest));
there is no browser page.

- Open it from the menu bar icon ("Open Dashboard"). There is no CLI command that opens it;
  without the app, use `selfguard status` / `report` in the terminal.
- "Not connected" or an error in the window: the app talks to the engine through a background
  process (`selfguard bridge`) that it restarts on the next request. Quit selfguard from the
  menu bar and open it again.
- An old `~/Applications/selfguard.app` that is a script launcher (from `selfguard app install`
  before 0.14, a command that no longer exists): drag it to the Trash and install the real app.
- Errors are logged to `~/.selfguard/selfguard.log`.

## The shell hook doesn't do anything

- Check that `~/.zshrc` contains `eval "$(selfguard init zsh)"`, then open a **new** terminal.
- `command -v selfguard` must print a path inside an interactive shell. If you use nvm or fnm,
  make sure they are initialized **before** the selfguard line in `~/.zshrc`.
- The hook only reacts to folders inside a project: it looks for `package.json`,
  `pyproject.toml`, `Cargo.toml` or a lockfile (`go.mod` included) while walking up, and stops at
  the git root or your home folder.
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

Python and Rust projects without a lockfile aren't registered: `requirements.txt`,
`pyproject.toml` or `Cargo.toml` alone don't pin what is installed. Create one with `uv lock`,
`poetry lock` or `cargo generate-lockfile`. Go projects are read from `go.mod` directly.

## A Python, Rust or Go project shows fewer packages than expected

- **Skipped entries** are git, path, URL and editable dependencies, and crates from registries
  other than crates.io. They can't be matched against OSV.
- **Go:** for modules that declare `go 1.16` or older, `go.mod` may not list every indirect
  dependency. Run `go mod tidy` with a recent Go to record them. The Go standard library isn't
  checked (`go.mod` only states the minimum Go version, not the toolchain you build with).
- **Mixed folders:** a folder with both `package-lock.json` and `uv.lock` (or `Cargo.lock`) is
  checked through its JavaScript lockfile only. Move the other ecosystem to its own folder
  (`api/`, `src-tauri/`) to have it checked too.
- **Other machines over SSH:** readers installed by an older selfguard only list JavaScript
  lockfiles. Reinstall it with `selfguard machines install <name>`; with sharing, update
  selfguard on that machine.

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

## My other Mac doesn't show "Connect"

"On your tailnet" offers **Connect** when the other machine answers with selfguard sharing:

- Turn it on there: selfguard → Settings → **Let my other machines see this one**, or
  `selfguard share on`. `selfguard share status` should say it is answering on its Tailscale
  address.
- Both machines must be logged in to Tailscale with the **same Tailscale user** (pairing with
  other users is refused unless `selfguard share on --allow-other-users`).
- The peer must be online in Tailscale. Press **Refresh**: the page probes each machine for
  about 1.5 s.
- A firewall on that machine may block incoming connections to node. Allow it, or check that
  `curl http://<its-tailnet-ip>:47821/hello` answers from this machine.

## A shared machine says "pair again"

The other machine revoked this one, re-paired with it (which replaces the old credential), or
saw the credential used from a different Tailscale node and revoked it. Press **Pair again** on
its card, or run `selfguard machines add <peer> --via share`.

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

## "Remote Login (SSH) is off there"

Before installing anything over SSH, selfguard checks that the machine's SSH port takes
connections. If the port refuses them, SSH is off on that machine, so nothing is saved or
installed and selfguard says so. Pick one:

- **Your own Mac running selfguard:** skip SSH. On that machine, open Settings → **Let my other
  machines see this one** → **Turn on** (or run `selfguard share on`). Then press **Connect** here.
- **SSH:** turn it on there. On macOS, go to System Settings → General → Sharing → **Remote Login**.
  On Linux, run `sudo systemctl enable --now ssh`. Then add the machine again.

Hosts behind a `ProxyJump` or `ProxyCommand` in `~/.ssh/config` aren't checked. selfguard
uses `ssh -G` to find the real host name and port.

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
