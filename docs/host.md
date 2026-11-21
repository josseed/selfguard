# This machine: persistence and credentials

Malware that reaches a developer machine through a package or a fake installer does two things:
it makes sure it runs again (a launch item, a line in `~/.zshrc`, a Python `.pth` file) and it
reads the tokens lying around in plain text. selfguard checks for both, on this machine and in
each repo's virtualenvs. Real cases this is built for:

- **LiteLLM on PyPI** (March and October 2026): a `.pth` file in site-packages ran a stealer on
  every Python start, and a `sitecustomize.py` did the same.
- **ClickFix fake Homebrew pages**: a pasted command installed a LaunchAgent disguised as an
  updater (Cuckoo, MacSync and SHub stealers).
- **Shai-Hulud and s1ngularity** (npm): read npm, GitHub and AWS tokens from plaintext files;
  s1ngularity also drove local AI agents with `claude --dangerously-skip-permissions`,
  `gemini --yolo` and `q --trust-all-tools`.

These are **warnings** (source kind `host`): practices and items to review, never counted as
vulnerable packages. Nothing is executed, nothing is sent: these checks make no network request
at all. Results appear in `selfguard tools` (a "This machine" section), `selfguard tools --json`
and the `selfguard_sources` MCP tool (records with `"kind": "host"`), and the dashboard's
**This machine** card. Warnings marked **N** below carry `notify: true`: when one appears after
the first check (the baseline), it is news even if it isn't high.

## Launch items

| Files read | |
| --- | --- |
| macOS | `~/Library/LaunchAgents/*.plist`, `/Library/LaunchAgents/*.plist`, `/Library/LaunchDaemons/*.plist` |
| Linux | `~/.config/systemd/user/*.service` (`ExecStart=`), `~/.config/autostart/*.desktop` (`Exec=`) |

Only those folders, one level, at most 100 items each. Plists are read as data, XML or binary
(`bplist00`, with a small bounded reader); an unreadable one is still listed, as "could not be
read".

| Rule | Severity | When |
| --- | --- | --- |
| `launch-item` | low, N | Every item, keyed by its label: a new item is announced once after the baseline. selfguard's own agents (`dev.selfguard.sync`, `.watch`, `.remote`, `.discover`, `.share`) are left out unless they look suspicious. |
| `suspicious-launch-item` | high, N | The program (or the script an interpreter runs) lives in `/tmp`, `/private/tmp`, `/var/tmp`, `/Users/Shared`, a hidden folder or `Downloads`; an interpreter runs inline code (`sh`/`bash`/`zsh -c`, `python -c`, `osascript -e`, `node -e`); `curl`, `wget` or `base64` appear in its arguments; a `com.apple.*` label outside `/System`; its program is missing. Runtimes in a version manager's versions folder (`~/.nvm/versions`, volta, fnm, mise, asdf, pyenv, rbenv, `~/.bun/bin`, `~/.deno/bin`, `~/.cargo/bin`) don't count as hidden. |

Messages name the label and the program's basename only: arguments may hold tokens and are
never shown or stored.

## Shell startup files

`~/.zshrc`, `~/.zprofile`, `~/.zshenv`, `~/.zlogin`, `~/.bashrc`, `~/.bash_profile`,
`~/.bash_login`, `~/.profile`, `~/.config/fish/config.fish`. Comment lines are skipped.
Warnings give the line number, never the line.

| Rule | Severity | When |
| --- | --- | --- |
| `shell-fetch-exec` | high, N | A download run at startup: `curl`/`wget` piped to a shell or interpreter, `eval "$(curl …)"`, `source <(curl …)`, `bash -c "$(curl …)"`, `base64 -d \| sh`. |
| `shell-code-injection` | high, N | Sets `DYLD_INSERT_LIBRARIES`, `LD_PRELOAD`, `NODE_OPTIONS` with `--require`/`--import`/`--loader`, or `PYTHONSTARTUP`. Keyed by the variable. |
| `agent-permissions-bypassed` | moderate | An alias, function or line runs `claude --dangerously-skip-permissions`, `gemini --yolo`/`-y`, `q`/`kiro --trust-all-tools`, or `codex --dangerously-bypass-approvals-and-sandbox`/`--yolo`. |

The usual init lines (`eval "$(brew shellenv)"`, `starship init`, nvm, pyenv, rbenv, direnv,
zoxide, fnm, mise, completions) don't fetch anything and aren't flagged.

## Package manager and git config

| File | Rule | Severity | When |
| --- | --- | --- | --- |
| `~/.npmrc` | `custom-registry` | moderate, N | `registry=` isn't registry.npmjs.org (scoped `@corp:registry=` lines are fine). |
| `~/.config/pip/pip.conf`, `~/.pip/pip.conf`, `~/Library/Application Support/pip/pip.conf` | `pip-extra-index` | moderate, N | `extra-index-url` is set: a public package named like a private one can win (dependency confusion). |
| same | `custom-registry` | moderate, N | `index-url` isn't pypi.org. |
| `~/.gitconfig`, `~/.config/git/config` | `git-global-hooks` | moderate, N | `core.hooksPath`: those hooks run in every repo. |
| same | `git-command-config` | moderate, N (high and urgent when it downloads or decodes code) | A global setting that runs a program other than the usual tools, see [Git config and hooks](#git-config-and-hooks). |
| same | `git-config-include`, `git-url-rewrite`, `git-safe-directory` | moderate N, moderate N, low | See below. |

Messages name a registry's host only (URLs can embed credentials).

## Git config and hooks

A cloned repo can't ship `.git/config` or `.git/hooks`, but malware already running on the
machine (a postinstall, a stealer) can plant them, and they run on normal git use: persistence
that survives deleting `node_modules`. `.gitmodules` *is* part of a repo, so a malicious one
arrives with the clone (the CVE-2024-32002 family). selfguard reads, as data and never through
git, per repo: `.git/config` (and a worktree's `config.worktree`), the hooks, and `.gitmodules`.
Files are never opened through a link that leaves the repo: a `.git/config`, `.gitmodules` or hook that is such a link is recorded as the link itself (its target text is hashed, the target is not read) and reported (`git-config-command` key `config:link`, `suspicious-submodule` key `.gitmodules:link`, `git-hook`). Machine-scope files such as `~/.zshrc` are still followed into a dotfiles repo. Linked worktrees and submodules (`.git` is a file `gitdir: ...`) are followed only into
`.git/worktrees/...` or `.git/modules/...`, and `commondir` only to a `.git` folder; a pointer
anywhere else is ignored. Messages name the key and at most a sanitized program name, never the
value (it may hold a token) and never a URL.

Repo scope:

| Rule | Severity | When |
| --- | --- | --- |
| `git-config-command` | high, N (urgent: see below) | `.git/config` sets a key that runs a program other than the usual tools for it. Key = the config key (`core.pager`, `filter.x.clean`...). |
| `git-config-include` | moderate N (low inside the repo) | `include.path` / `includeIf.*.path` pointing outside `.git`: outside the repo or in a temporary or shared folder is moderate; a file inside the work tree (`../.gitconfig`) is low and silent. |
| `git-hooks-path` | moderate, N | `core.hooksPath` in `.git/config` points outside the repo, by its spelling or by where it really leads: a tracked `.githooks` that is a link to `/tmp/payload` counts. Inside the repo (husky's `.husky/_`) is fine: those hooks are read like `.git/hooks`. |
| `git-hook` | low, N | An executable, non-`.sample` hook with a known git hook name in `.git/hooks` (or the in-repo `core.hooksPath` folder), or a hook that is a link out of the repo. Key = hook name. |
| `suspicious-git-hook` | high, urgent | `.git/hooks` itself replaced by a link to a folder outside the repo (key `hooks`); or a hook line that pipes a download to a shell, evals or sources one, decodes base64 into a shell or interpreter, opens `/dev/tcp`, runs a file from `/tmp`, or is longer than 4000 characters; or a compiled hook in a folder whose other hooks are scripts. Comment lines are ignored. |
| `suspicious-submodule` | high, N (urgent for `ext::`, `fd::` and a leading `-` in the URL) | `.gitmodules` URL using `ext::`, `fd::` or another `name::` transport, or starting with `-`; a path or a submodule name containing `..`, starting with `-`, absolute, or pointing into `.git` (case and NTFS spellings included). |

What `git-config-command` looks at: `core.fsmonitor` (when not a boolean), `core.sshCommand`,
`core.pager`, `core.editor`, `core.askPass`, `sequence.editor`, `diff.external`,
`diff.<x>.textconv`/`command`, `merge.<x>.driver`, `filter.<x>.clean`/`smudge`/`process`,
`credential.helper` (starting with `!`, or an absolute path), `gpg.program` and
`gpg.<x>.program`, `uploadpack.packObjectsHook`, and aliases starting with `!`.

**Allowlist** (the program's basename, every command of a pipeline): editors (vim, nvim, emacs,
nano, code, cursor, subl, zed, JetBrains launchers...), pagers (less, bat, delta, diff-so-fancy,
cat...), `ssh`/`autossh`/`plink` for `core.sshCommand`, `*askpass*` programs, `gpg`/`gpg2`/
`gpgsm`/`smimesign`/`ssh-keygen`/`op-ssh-sign` for the gpg keys, `git-lfs`/`git-crypt`/
`git-annex`/`cat`/`sed`/`tr`/`iconv` for filters (a normal lfs setup is silent), difftastic and
friends for `diff.external`, common converters (exiftool, pdftotext, jq, plutil...) for
`textconv`, `mergiraf`/`npm-merge-driver` for merge drivers, `watchman`-style hooks for
`core.fsmonitor`, and `git-credential-*` helpers. Aliases and `!` credential helpers are free-form
shell, so only their shape is judged: they are flagged only for the fetch-and-run shapes below or
a program in a temporary folder. A hidden folder alone (`~/.cargo/bin/delta`) doesn't make a
known tool unusual.

**Arguments that run code.** An allowed program is also flagged (high in a repo, moderate globally) when its arguments make it run something else: `ssh -o ProxyCommand=…`, `LocalCommand=…` or `KnownHostsCommand=…` (also `-oProxyCommand=`, any case), sed's `e` command or `s///e` flag, `vim`/`nvim` with `-S`, `-c`, `--cmd`, `-u`, `-s` or `+cmd` (not `+10`), `emacs --eval`/`--load`. Legitimate `ProxyCommand` setups (a cloudflared or bastion hop) are flagged too: review and dismiss. The temporary-folder and hidden-folder checks look at every token of the value, not only the program, so `vim -S ~/.cache/x.vim` or `ssh -o LocalCommand=/tmp/x` is urgent in a repo; `ssh -i ~/.ssh/key` is fine.

**Urgent** (alerts on the first check and in inactive repos, like a malicious package): the value
downloads or decodes code (`curl`/`wget`, `base64 -d`, `sh -c`, inline `python -c`, `osascript`,
`/dev/tcp`; a download piped to a shell anywhere, aliases included), runs a program from `/tmp`,
`/var/tmp`, `/Users/Shared` or Downloads, or runs an unknown program from a hidden folder.

**Hooks and noise.** husky, lefthook and pre-commit install hooks into `.git/hooks` (or
`.husky/_`) on setup: with the baseline, the first check of a repo announces nothing, and each
new hook after that is announced once (low). Expect one notice after you add one of those tools
to a repo you already track, or when `pre-commit install` runs. A hook file that isn't
executable is ignored (git skips it); a `chmod +x` alone isn't noticed until the file changes.
Only the known hook names are read, one level, regular files or links, 100 per folder, 256 KB of
text each; hooks named like husky's `h` helper are never listed.

Machine scope (`~/.gitconfig`, `~/.config/git/config`), in addition to `git-global-hooks`:

| Rule | Severity | When |
| --- | --- | --- |
| `git-command-config` | moderate, N; high and urgent when it fetches or decodes code | The same command keys as above, same allowlists (`core.sshCommand` and `core.fsmonitor` were already covered). |
| `git-config-include` | moderate, N | `include.path` / `includeIf.*.path` outside your home folder or in a temporary or shared folder (a profile under `~` is normal). |
| `git-url-rewrite` | moderate, N | `url.<base>.insteadOf` / `pushInsteadOf` sends github.com, gitlab.com, bitbucket.org, ghcr.io or a package registry host to another host (same-host rewrites such as `https://` to `git@github.com:` are fine). The message names the two hosts only. |
| `git-safe-directory` | low | `safe.directory = *`. |

## Plaintext credentials

Rule `plaintext-credential`, moderate, one warning per file, keyed by the file. **Presence
only**: the message says what kind of credential sits where and the safer alternative.

| File | Looked for | Safer |
| --- | --- | --- |
| `~/.npmrc` | `_authToken`, `_auth`, `_password` (not `${NPM_TOKEN}` references) | a token from an environment variable |
| `~/.aws/credentials` | `aws_secret_access_key` | `aws sso login`, `credential_process` |
| `~/.config/gh/hosts.yml` | `oauth_token` | `gh auth login` with its default (keychain) |
| `~/.docker/config.json` | `auths.*.auth` without `credsStore`/`credHelpers` | a credential store |
| `~/.netrc` | `password` | credential helpers |
| `~/.git-credentials` | a URL with a password | a keychain credential helper |
| `~/.pypirc` | `password` | keyring, trusted publishing |
| `~/.kube/config` | `token:`, `client-key-data:`, `password:` | an exec credential plugin |
| `~/.config/gcloud/application_default_credentials.json` | `refresh_token`, `private_key` | revoke when unused, impersonation |

## Python startup hooks

Python runs the lines of a `.pth` file that start with `import`, and imports
`sitecustomize.py`/`usercustomize.py`, at every start. selfguard lists the site-packages folder
itself (never the packages inside it) of:

- each repo's virtualenvs: `<repo>/.venv`, `venv`, `env` (`lib/python3*/site-packages`);
- uv tools: `~/.local/share/uv/tools/*/lib/python3*/site-packages`;
- pipx apps: `~/.local/pipx/venvs/*/…`, `~/.local/share/pipx/venvs/*/…`;
- the user site: `~/Library/Python/3.*/lib/python/site-packages`, `~/.local/lib/python3*/site-packages`.

| Rule | Severity | When |
| --- | --- | --- |
| `python-startup-hook` | moderate, N | A `.pth` with `import` lines that isn't a known one, or a `sitecustomize.py`/`usercustomize.py`. |
| `malicious-looking-startup-hook` | high, N | Its code uses `exec`, `eval`, `compile`, `base64`/`b64decode`, `zlib`, `marshal`, `subprocess`, `os.system`, `urllib`, `socket`, `__import__`…, or a line is longer than 1000 characters. |

Keyed by the file name. Known hooks are recognised by name **and** by the shape of every
`import` line, so a stealer reusing a familiar name is still flagged: `distutils-precedence.pth`,
`_virtualenv.pth`, `__editable__*.pth` finders, setuptools `*-nspkg.pth` namespace lines,
`pywin32.pth`, coverage's `a1_coverage.pth`, older pytest-cov, `easy-install.pth`. Lines
without `import` are paths and never run.

Repo virtualenv results are a per-repo record, shown with the repo (`selfguard tools <dir>`, the
repo page). At most 40 hooks per site-packages folder and 100 environments per tool folder are
read.

## Editor extensions

VS Code extensions run with your user's full rights, and attackers know it: **GlassWorm**
(Open VSX and the VS Code Marketplace, October 2025 onwards) hid its loader in invisible Unicode
inside extension code and spread through hijacked publishers; fake Solidity and crypto
extensions dropped ScreenConnect and stealers; the **Nx Console 18.95.0** release (May 2026)
stole GitHub tokens within minutes of being published.

| Files read | |
| --- | --- |
| Lists | `extensions/extensions.json` in `~/.vscode`, `~/.vscode-insiders`, `~/.vscode-oss` (VSCodium), `~/.vscode-server`, `~/.cursor`, `~/.windsurf`, `~/.kiro`, `~/.antigravity` (macOS and Linux) |
| Code | for each listed extension, the `main` and `browser` files named by its `package.json` |

Everything is read as data: nothing is loaded, executed or fetched. Extensions installed behind
the editor's back (not in `extensions.json`) are not listed.

| Rule | Severity | When |
| --- | --- | --- |
| `malicious-extension` | high, urgent | The id (any case) is on the bundled list of publicly reported malicious or compromised extensions (`src/sources/host/extensions-editor-denylist.ts`, each group with its source URL). Some entries name only the compromised releases (Nx Console 18.95.0, the hijacked `oorzc.*` versions). The list has 50 ids: Datadog (MUT-9332), Checkmarx, Socket (GlassWorm clusters, hijacked publisher, activated April 2026 extensions), The Hacker News (first GlassWorm wave, Solidity Pro), the Nx postmortem and GHSA-c9j4-9m59-847w. Socket's unactivated "sleeper" extensions are left out. |
| `hidden-unicode` | high, urgent | The entry point has Unicode tag characters, bidirectional controls, or invisible characters (zero-width, variation selectors) in long runs or encoding text, as `agentguard` judges them: emoji and scripts that need these characters are fine. |
| `sideloaded-extension` | moderate, N | `extensions.json` says it was installed from a `.vsix` file or a URL, not a marketplace. |
| `editor-extension` | low, N | Every extension except built-in ones, so a new one is announced once after the baseline. |

All are keyed by the extension id, so an update of an extension (new version, new folder) is
not news. Messages show the id (checked against a strict pattern), the version and the editor's
name, never a path.

Limits: every entry of `extensions.json` is checked against the denylist, the other rules apply to the first 400; of an entry point the first 5 MB are scanned, and the last 1 MB too when it is bigger (padding can't hide a payload at either end; the middle of a file over 6 MB is not read); about 64 MB in total per check, shared fairly (each extension gets its turn's share of what is left, at least 128 KB, so early ones can't use it all up); a `main` that is absolute, uses `..`, is a symlink leading out of the
extension's folder, or is not a regular file is ignored. The code is scanned when
`extensions.json` changes (an install, update or removal), not on every check.

## Browser extensions

Extensions run inside every page you visit, and a hijacked one reads sessions and wallets. This
module lists what is installed and flags the dangerous ones. Real cases: the **Cyberhaven**
extension and ~30 more hijacked by phishing the developers' Web Store accounts (December 2024),
**Trust Wallet 2.68** (December 2025), and fake VPN, AI and crypto extensions stealing wallets.

| Browser | Profiles read (at most 12 each) | File read |
| --- | --- | --- |
| Chrome, Brave, Edge, Arc, Chromium, Vivaldi (macOS: `~/Library/Application Support/Google/Chrome`, `BraveSoftware/Brave-Browser`, `Microsoft Edge`, `Arc/User Data`, `Chromium`, `Vivaldi`; Linux: `~/.config/google-chrome`, `chromium`, `BraveSoftware/Brave-Browser`, `microsoft-edge`) | `Default`, `Profile N` | `Secure Preferences` (where Chromium keeps `extensions.settings`), or `Preferences` if it doesn't exist |
| Firefox (`~/Library/Application Support/Firefox/Profiles/*`, `~/.mozilla/firefox/*`, snap and Flatpak) | each profile folder | `extensions.json` |

Read-only, as data. Only each extension's id, name, version, install kind and granted
permissions are taken; nothing else in those files (they hold browsing-related settings) is kept,
shown or sent. Names come from the profile (`__MSG_x__` names from the extension's own locale
file) and are sanitized and truncated. Built-in components (Chromium location 5 and 10, Firefox
`app-builtin`/`app-system-*`), themes and leftovers of removed extensions are skipped.

| Rule | Severity | When |
| --- | --- | --- |
| `malicious-browser-extension` | high, N, urgent | The id is in the bundled denylist (`src/sources/host/extensions-browser-data.ts`, one public source per entry). Hijacked-then-repaired extensions match only the malicious versions. Alerts even on the first check. |
| `unpacked-browser-extension` | moderate, N | Chromium: loaded unpacked (location 4, developer mode) or from the command line (8), or `from_webstore: false` (not Edge, whose store doesn't set it). Firefox: loaded temporarily, or `signedState` 0 or lower. |
| `powerful-browser-extension` | moderate | An enabled extension with `debugger` (controls any tab), `nativeMessaging` (talks to a program on this machine), `proxy` (reroutes traffic), `webRequestBlocking` plus all sites, or `cookies` plus all sites (`<all_urls>`, `*://*/*`, `http(s)://*/*`). |
| `browser-extension` | low, N | Every extension, so a new one is announced once after the baseline. |

Warnings are keyed by browser, profile and extension id, so they stay stable across updates. Every extension of a profile is checked against the denylist; the other rules apply to the first 150.

**False positives.** Password managers (Bitwarden, 1Password) use `nativeMessaging` for their
desktop apps and often `cookies`, and developer tools use `debugger`: they are flagged
`powerful-browser-extension` by design, at moderate and without notification, so you review
them once and dismiss. The set leaves out `tabs`, `history`, `storage`, `webRequest` alone and
ordinary content-script hosts, which almost every extension has. Disabled extensions are not
checked for powers (their permissions aren't in use).

**Cost.** Preferences files are rewritten by the browser in every session, so they are not
markers and not watched: `check` re-lists profiles only when a browser folder, a profile's
`Extensions` folder (install, update, removal) or a profile without a data file changes, and the
watcher wakes only for `Extensions` folders and Firefox's `extensions.json`. When the data file
itself changed, `check` reads it once (bounded by the 16 MB source cap) and rescans the host
record. An unpacked extension, which leaves nothing in `Extensions`, is therefore noticed by the
next `check` that sees the changed file or by `sync`, not instantly.

Not covered: extension *updates* are not diffed (a hijacked update is caught only if its id and
version are in the denylist), Safari, Windows, extensions installed by policy are listed but not
judged, and the denylist is only as current as the release.

## Exposed local services

A developer service that listens on all interfaces (`0.0.0.0`, `::`) or on a LAN address, not on
`127.0.0.1`/`::1`, can be reached by anyone on the same Wi-Fi (and, for some, by a web page through
DNS rebinding). Real cases: the MCP Inspector RCE (CVE-2025-49596, ports 6274/6277), Ollama
(11434) left open, Chrome/Electron remote debugging (9222, full browser takeover), the Node.js
inspector (9229, code execution), Jupyter, Docker's API without TLS (2375).

| | |
| --- | --- |
| macOS | `/usr/sbin/lsof -nP -iTCP -sTCP:LISTEN +c 0 -F pcn` (machine-readable: pid, command, address; chosen over `netstat -anv`, which doesn't give the command reliably). It only sees your own user's processes, which is what you run. |
| Linux | `/proc/net/tcp` and `/proc/net/tcp6` (state `0A`); process names from `/proc/<pid>/fd` and `comm` for the processes you may read (at most 600 processes, 512 descriptors each). |

`lsof` is run with an absolute path, fixed arguments, a 3 s timeout and a 4 MB output cap; nothing
from a project is executed. Only the port, the process's basename and the *kind* of address
(loopback, all interfaces, LAN, tailnet) are kept: never an address, and never a peer. Tailscale
addresses (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`) count as private: that network is
authenticated (selfguard's own share server listens there). `SELFGUARD_NO_SOCKETS=1` turns the
check off.

| Rule | Severity | When |
| --- | --- | --- |
| `exposed-dev-service` | high, N (urgent for 9222, 9229, 6277, 2375) | A known risky port on a non-loopback address: 9222 Chrome/Electron debugging, 9229 Node inspector, 6277 MCP Inspector proxy, 6274 MCP Inspector, 2375 Docker API, 11434 Ollama, 8888 Jupyter, 8265 Ray dashboard, 6379 Redis, 5432 PostgreSQL, 3306 MySQL, 27017 MongoDB, 9200 Elasticsearch, 11211 memcached. Any process name. Keyed by `port/process`. |
| `exposed-local-service` | low | Another developer process on all interfaces or a LAN address: `node`, `bun`, `deno`, `python*`, `uvicorn`, `gunicorn`, `ruby`, `puma`, `java`, `php`, `ollama`, `jupyter*`, `ray*`, `vite`, `webpack`, `docker-proxy`… A vite or webpack dev server started with `--host` shows up here. |

The message names the process and port, what it is, and how to bind it to 127.0.0.1 (for example
`OLLAMA_HOST=127.0.0.1`, `--inspect=127.0.0.1:9229`, `bind 127.0.0.1 -::1` in redis.conf).

Loopback listeners don't count toward the 2000-listener cap, so a crowd of them can't hide an exposed one. Left alone: loopback listeners, and system or desktop daemons (`launchd`, `rapportd`,
`ControlCenter`, `sharingd`, `identityservicesd`, `AirPlay*`, `mDNSResponder`, `netbiosd`, `cupsd`,
`sshd`, `smbd`, `systemd*`, `avahi-daemon`, `tailscaled`, and a few more; `SYSTEM_PROCESSES` in
`src/sources/host/exposed.ts`), except on any port in the risky list above, so a process can't hide there
under a system name (a binary called `sharingd` on `0.0.0.0:6379` is reported). Unknown processes on ordinary ports are not reported.

Unlike files, this is a live snapshot, taken **only by `selfguard sync` (and the scheduled
sync)**, at most once per sync (about 50 ms; 3 s at worst). `check` and the watcher never run it:
they keep the last snapshot's warnings, so a service stopped between syncs is noticed at the next
sync, and a failed `lsof` keeps the last result instead of reporting everything as fixed, for 7 days since the last good snapshot at most. `lsof` exiting with status 1 (it does when some process can't be inspected) is read normally if it printed anything. With `SELFGUARD_NO_SOCKETS=1` or on a system with no reader the result is empty, so old exposure warnings resolve. The
first sync is the baseline: only urgent exposures are news then. After an upgrade, new rules
start from a baseline too.

## What is never read or sent

- Credential values, command lines and shell lines are never stored, printed, logged, returned
  to an AI or sent anywhere. A test writes fake tokens in every credential file, a launch item
  and a shell file and checks that none reaches the record, events, `--json`, CLI or MCP output.
- Records keep, per file, its path, size, modification time and a SHA-256 of its content, only
  to notice changes, as for every source.
- No network request: no OSV query is made for host checks.
- Not read: Login Items added through System Settings (`SMAppService`/BTM database), cron jobs,
  `/etc` files, Windows, JetBrains plugins, keychains.

## Limits

A source record keeps at most 1000 warnings: the urgent ones first, then high, moderate, low; one low `truncated` warning says how many were left out. At most 200 files are read per source and kind, shared fairly between the checks (a folder with 100 launch items can't push the extension lists out); if some were left out, a `truncated` warning says how many.

## When they are checked

- `selfguard sync` (and the scheduled sync): this machine's host record and every tracked
  repo's virtualenvs.
- `selfguard check` and the watcher: only what changed. Check compares the files of the last
  scan and the folders new ones appear in (the launch item folders, the editors' `extensions` folders, site-packages folders and
  their parents); the watcher also wakes up when a launch item folder, a shell startup file,
  a package manager config or a site-packages folder (up to 20) changes. A rewrite of an already known, allowlisted `.pth` in place
  is caught by check as a changed file. For git, check stats `.git/config`, `.gitmodules` and the
  hooks folders (not `.git` itself, which changes on every git command).
- The first check is the baseline: N warnings are news only when they appear afterwards, except
  `malicious-looking-startup-hook`, `malicious-extension`, `malicious-browser-extension`, the
  extension `hidden-unicode`, `suspicious-git-hook`, `suspicious-submodule` (`ext::`, `fd::`,
  leading `-`) and urgent `git-config-command` warnings, which alert even on the first check.

`SELFGUARD_SYSTEM_ROOT` moves `/Library/…` under another folder (tests only).
