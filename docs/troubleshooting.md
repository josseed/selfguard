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

## The MCP server doesn't start in a desktop app

Desktop apps don't load your shell profile, so they may not find Node or selfguard. Use absolute
paths in the client config. See
[AI and automation](ai-and-automation.md#mcp-server).

## Reset everything

```sh
selfguard schedule off
rm -rf ~/.selfguard
selfguard setup
```
