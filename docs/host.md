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
| `suspicious-launch-item` | high, N | The program (or the script an interpreter runs) lives in `/tmp`, `/private/tmp`, `/var/tmp`, `/Users/Shared`, a hidden folder or `Downloads`; an interpreter runs inline code (`sh`/`bash`/`zsh -c`, `python -c`, `osascript -e`, `node -e`); `curl`, `wget` or `base64` appear in its arguments; a `com.apple.*` label outside `/System`; its program is missing. |

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
| same | `git-command-config` | moderate, N | `core.sshCommand` runs something other than `ssh`, or `core.fsmonitor` is a command (not true/false). |

Messages name a registry's host only (URLs can embed credentials).

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

Left alone: loopback listeners, and system or desktop daemons (`launchd`, `rapportd`,
`ControlCenter`, `sharingd`, `identityservicesd`, `AirPlay*`, `mDNSResponder`, `netbiosd`, `cupsd`,
`sshd`, `smbd`, `systemd*`, `avahi-daemon`, `tailscaled`, and a few more; `SYSTEM_PROCESSES` in
`src/sources/host/exposed.ts`), except on the four urgent ports, so a process can't hide there
under a system name. Unknown processes on ordinary ports are not reported.

Unlike files, this is a live snapshot, taken **only by `selfguard sync` (and the scheduled
sync)**, at most once per sync (about 50 ms; 3 s at worst). `check` and the watcher never run it:
they keep the last snapshot's warnings, so a service stopped between syncs is noticed at the next
sync, and a failed `lsof` keeps the last result instead of reporting everything as fixed. The
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
  `/etc` files, Windows, browser extensions, keychains.

## When they are checked

- `selfguard sync` (and the scheduled sync): this machine's host record and every tracked
  repo's virtualenvs.
- `selfguard check` and the watcher: only what changed. Check compares the files of the last
  scan and the folders new ones appear in (the launch item folders, site-packages folders and
  their parents); the watcher also wakes up when a launch item folder, a shell startup file,
  a package manager config or a site-packages folder (up to 20) changes. A rewrite of an already known, allowlisted `.pth` in place
  is caught by check as a changed file.
- The first check is the baseline: N warnings are news only when they appear afterwards, except
  `malicious-looking-startup-hook`, which is urgent and alerts even on the first check.

`SELFGUARD_SYSTEM_ROOT` moves `/Library/…` under another folder (tests only).
