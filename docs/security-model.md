# Security model

selfguard runs on developer machines and reads untrusted input every time you open a project, so
it holds itself to a stricter standard than a typical CLI. This page explains what it trusts,
what it sends, and how it is built and released. To report a vulnerability, see
[SECURITY.md](../SECURITY.md).

## Threats considered

| Threat | Mitigation |
|---|---|
| A hostile repository runs code when you `cd` into it or scan it | Lockfiles, `package.json`, `pyproject.toml` and `go.mod` are parsed as data by selfguard's own parsers. No package manager (`npm`, `pip`, `uv`, `poetry`, `cargo`, `go`), lifecycle or build script, `.npmrc` or project config is ever executed or loaded. |
| A crafted lockfile crashes or abuses the parser | Lockfiles over 100 MB are refused. The YAML reader supports only the subset lockfiles use: no anchors, aliases or tags, so no "billion laughs". The TOML reader (Cargo.lock, uv.lock, poetry.lock, pyproject.toml) has no evaluation features either. Nesting depth is bounded and objects have no prototype, so keys like `__proto__` are plain data. |
| Package names or advisory text inject terminal escape sequences | Everything printed is stripped of C0/C1 control characters and bidirectional overrides ("Trojan Source"), and truncated. |
| Notification text injects AppleScript | Text is passed to `osascript` as arguments to an `on run` handler, never interpolated into script source. The dialog's button only opens `https://osv.dev/vulnerability/<id>` URLs built by selfguard. |
| A website talks to the local dashboard | There is nothing to talk to: the dashboard has no HTTP server, no port and no token. The page runs inside the Mac app's WKWebView under a custom scheme, and its API is reachable only through the app's message handler. See [Dashboard](#dashboard). |
| Prompt injection through the MCP server | Tool descriptions and the agent guide label advisory text and package names as third-party data. No MCP tool can run commands, install packages or edit files. |
| selfguard's own dependencies get compromised | Zero runtime dependencies, enforced in CI. Dev tooling updates go through Dependabot with a 7-day cooldown and review. |
| A compromised CI or stolen token publishes a malicious selfguard | See [Releases](#releases). |

## Finding projects on your disk

The whole-home search ("find my projects") only lists folders and reads a few small files:
`.gitignore` and `.git/worktrees/*/gitdir`, each capped at 64 KB. It never opens your other
files or runs anything. It stays inside your home folder, on the same disk, doesn't follow
symlinks, and skips cloud drives, because listing them can trigger downloads. Results stay in
`~/.selfguard`. On macOS, the weekly background pass doesn't enter Desktop, Documents or
Downloads unless you already watch a folder there, so it never shows a privacy prompt on its own.

## CI workflows and agent configs

selfguard also reads, as data, each tracked repo's `.github/workflows/*.yml` and composite
`action.yml` files, and the MCP server definitions of AI agents: `~/.claude.json`, Claude
Desktop's, Cursor's, VS Code's, Windsurf's, Codex's and Gemini CLI's config files, and their
per-repo counterparts (`.mcp.json`, `.cursor/mcp.json`, …). These configs often hold secrets.
From each server only the agent, server name, launcher, package name, version or pin, file
and line are kept; environment variables, headers, URLs, tokens and other arguments are never
stored, logged, printed, returned to an AI or sent anywhere. Remote MCP servers are recorded by
host only. Nothing is executed, and GitHub is never queried to resolve commit SHAs. See
[CI workflows and agent tools](ci-and-agent-tools.md).

## What leaves your machine

Calls to the OSV.dev API at `https://api.osv.dev/v1` and to OSV's public data bucket, plus the
daily update check described below:

- `POST /querybatch` with `{ "package": { "ecosystem": …, "name": … }, "version": … }` for
  each unique dependency. The ecosystem is `npm`, `PyPI`, `crates.io` or `Go`; Go module paths
  (`github.com/org/module`) are public names, sent like any package name. MCP servers without
  an exact version are sent without `version`;
- `GET /vulns/{id}` for advisory details not already cached;
- when a repo has GitHub Actions workflows, at most every 6 hours,
  `GET https://osv-vulnerabilities.storage.googleapis.com/GitHub%20Actions/modified_id.csv`:
  the public list of every GitHub Actions advisory (id and last change), followed by
  `GET /vulns/{id}` for the ones that are new or changed. The same request for every user:
  **no action name is sent**. Actions are matched locally against that index. The list is
  size-capped (1 MB, 10,000 lines) and its ids validated.

Requests carry the `User-Agent: selfguard/<version>` header. No file paths, project or repo
names, git remotes, source code or identifiers are sent. Redirects are refused, responses are
size-capped, and requests time out.

OSV can infer which open-source packages and versions you use, but not who you are or what you
build. If even that is too much, point `SELFGUARD_OSV_API` (and `SELFGUARD_OSV_BUCKET` for the
GitHub Actions list) at a mirror you control.

**Update check.** At most once a day, selfguard sends `GET https://registry.npmjs.org/selfguard/latest`
to learn whether a newer selfguard exists. The request has the same safeguards (no redirects,
timeout, size cap) and carries nothing about your projects: npm only sees that someone asked
about selfguard, as with any `npm view`. The answer is used only if it holds a valid version,
and it is never executed. selfguard **never installs or updates itself**. It shows the command
(`npm i -g selfguard@<version> --ignore-scripts`), the release notes, and whether the release
carries an npm provenance attestation, meaning it was built and signed by the project's GitHub
Actions. Turn the check off with `selfguard settings --update-check off` or
`SELFGUARD_NO_UPDATE_CHECK=1`.

Inside the Mac app, updates are installed by the app itself (Sparkle, see [Releases](#releases)), not by this check.

## Local state

`~/.selfguard` (or `SELFGUARD_HOME`) holds the list of your projects, their dependencies,
findings and an activity log. It is created with mode `0700` and its files with `0600`. Writes are atomic (temporary
file plus rename), and concurrent scans are serialized with lock files.

To identify repositories, selfguard reads `.git/HEAD`, `.git/config`, `.git/commondir` and the
worktree pointer file, each capped at 64 KB. It never runs `git`.

## Other machines

`selfguard machines add` lets this machine also watch the repos of your other machines. The
goal is that neither side can hurt the other: a compromised machine can't attack this one, and
someone in control of selfguard here can't use it to get into the others. There are two ways
to reach a machine: **selfguard sharing** (both run selfguard, nothing but Tailscale needed) and
**SSH** (servers without selfguard).

### selfguard sharing (machines that run selfguard)

On the machine to be watched (B), "Let my other machines see this one" (`selfguard share on`)
starts a small HTTP service (a launchd agent, or a systemd user unit on Linux):

- **Tailnet only.** It listens only on B's own Tailscale addresses (from `tailscale status`),
  never on `0.0.0.0`, the LAN or localhost. Without a Tailscale address it doesn't listen at
  all. Unlike enabling Remote Login, it opens no port outside the tailnet and needs no SSH.
  Each address is bound on its own, so one that can't be bound (an IPv6 address on a host
  without IPv6) doesn't take the others down.
- **Not reachable from web pages.** It answers only requests whose `Host` is its own address
  and port, and the pairing endpoints accept only `application/json`. A page in a browser,
  even one that re-points its own domain at this address (DNS rebinding), can't talk to it.
- **Read-only, same reader.** It answers the same requests as the SSH reader (list, fetch,
  browse, ping; `reader.ts` produces byte-identical answers) with the same limits: lockfile,
  `package.json` and `pyproject.toml` names only, no symlinked files, 50 MB per file, at most 1,000 files and 64
  folders per request, nothing outside the granted folder (paths resolved with `realpath`, so
  symlinks and `..` can't escape). Git facts (branch, remote URL, activity) also come only from
  a `.git` and a common git dir inside the granted folder. A narrower grant never reveals a
  parent repo's remote URL, which may embed a token. It has no endpoint that writes files or runs
  anything from a project.
- **Pairing, approved over there.** Machine A sends `POST /pair/request` with its name and an
  ephemeral X25519 public key. B identifies the caller with `tailscale whois`: it must be a
  machine of the tailnet and, by default, of **the same Tailscale user**
  (`--allow-other-users` widens that on purpose). The request waits 5 minutes, with a
  notification and a card in B's dashboard. Both screens show the same 6-digit code, derived
  from both public keys, so you can check that you approve the request you sent. On approval,
  B chooses the folder A may read, creates a random 256-bit credential, keeps only its SHA-256
  and seals the credential for A with the X25519 shared secret (HKDF-SHA256, AES-256-GCM).
  Only the machine that holds the ephemeral private key can open it. A stores it in
  `~/.selfguard/machines/<name>/share.json` (mode `0600`).
- **Bound to the machine.** Every request needs the credential (compared in constant time)
  **and** has to come from the Tailscale node it was issued to, checked with `whois`. A
  credential confirmed to be used from another node is revoked on the spot. When `whois` can't
  answer (tailscaled restarting, a timeout), the request is refused for now and retried later,
  never treated as a mismatch. Only confirmed answers are cached. Pending or rejected requests
  can't read anything. Moving a machine from sharing to SSH, or removing it, drops its grant
  over there and deletes the credential here.
- **Limits and logs.** Pairing requests are rate limited (5 per address every 10 minutes),
  failed credentials too. Every access is logged in `~/.selfguard/share/access.log` (capped).
  B's dashboard lists "Machines that can see this one" with their last connection and
  **Revoke**, and `selfguard share list | revoke <name>` does the same. `share off` stops
  answering at once, before the service is even unloaded.

What this doesn't protect against: someone already in control of B's account can serve
anything (the answer is untrusted on A, as with SSH), and someone in control of A can read what
A was granted on B, and nothing more.

### Restricted mode (default): a key that can only read lockfiles

1. selfguard creates an ed25519 key just for that machine in `~/.selfguard/ssh/<name>_ed25519`
   (mode `0600`).
2. Using your own SSH access **once**, it installs two things on the machine:
   - `~/.selfguard-reader/reader.sh`, the *reader*: about 150 lines of POSIX `sh`. You can
     read it with `selfguard machines setup <name>`, or install it by hand with the same
     command.
   - one line in `~/.ssh/authorized_keys`:
     ```
     restrict,command="/bin/sh .selfguard-reader/reader.sh",from="<this Mac's tailnet IPs>" ssh-ed25519 AAAA… selfguard:<name>@<this-mac>
     ```
3. From then on, every connection uses only that key: `IdentitiesOnly`, no agent, no password.

What the key can do on the machine:

- **Only the reader.** sshd runs the forced command whatever command is requested. `restrict`
  turns off the shell (no PTY) and agent, X11 and port forwarding. If the key leaked, it would
  not open a shell, copy files or reach other hosts.
- **Only inside one folder.** The reader is installed for one folder (`--scope`, default `~`).
  It resolves every requested path with `pwd -P` and refuses anything outside, including
  through symlinks or `..`. The dashboard's folder picker stops at that folder.
- **Only lockfiles.** Answers contain lockfile names, sizes and dates, the bytes of files
  named like a lockfile (`go.mod` included), `package.json` or `pyproject.toml` (never symlinks, at most 50 MB each), and a few git
  facts: branch, worktree pointer, remote URL and last activity. No `.env`, keys or source
  files.
- **Only from this Mac.** When the machine is on your tailnet, the line is pinned to this Mac's
  Tailscale addresses (`from=`).
- **Requests are data.** The reader reads a request (`SGREQ1 list` plus folder lines) from
  stdin with `read -r` and never evaluates it.

Removing the machine (`selfguard machines remove`) deletes the key here and, with your SSH
access, its line and the reader there. If that cleanup can't connect, the line left behind
can't be used without the deleted private key.

Tailscale SSH authorizes connections with tailnet policy and ignores `authorized_keys`.
Restricted mode therefore needs the machine's regular `sshd` (reachable over the tailnet). With
Tailscale SSH enabled on the machine, the reader isn't reached and selfguard reports it.

### ssh mode: your own access

`--mode ssh` (or "My SSH access" in the dashboard) uses your own keys or Tailscale SSH. It pipes
the same read-only functions into `ssh -T -a -x -o BatchMode=yes -- <host> /bin/sh -s`, with
folder paths passed as single-quoted literals. It installs nothing, but anyone in control of
selfguard on this Mac would have your full shell access there. Prefer the restricted mode.

### Both modes

- The remote side only uses `find`, `stat`, `sed`, `sort`, `head`, `wc`, `cat` and `gzip`. It
  never runs `git`, a package manager or anything from a project. Apart from installing and
  removing the reader, it never writes.
- ssh never prompts (`BatchMode`) and never disables host key verification. Host names are
  validated (no leading `-`, no shell characters) and come after `--`.
- **The answer is untrusted.** It is size-capped (16 MB per listing, 200 MB per transfer) and
  time-limited, then parsed strictly: absolute paths only, no `..`, expected file names only.
  Text is cleaned like any advisory text. A compromised machine can still hide its own
  vulnerabilities, and no design can prevent that.
- Lockfiles are parsed and checked here, so OSV only sees package names and versions,
  de-duplicated across machines. Git remotes are stored as `host/owner/repo`, so credentials
  embedded in a URL are dropped.
- Results live in `~/.selfguard/machines/<name>/`.

## Dashboard

selfguard has no HTTP server for the dashboard: **no listening socket, no port on localhost, no
token, no `ui.json`**. (The only network listener in selfguard is the opt-in
[tailnet sharing](#other-machines) service, which is a different thing.) The dashboard exists only
inside the selfguard Mac app:

- **The page** (`src/ui/static`, shipped in the app's bundled engine, not in the npm package) is served to the app's WKWebView by a
  `WKURLSchemeHandler` for the custom scheme `selfguard://dashboard/`. It serves only files
  named in `dist/ui/static/files.json`, generated at build time from the allowlist in
  `src/ui/assets.ts`; the lookup is an exact match on the URL path, never a path join, so
  there is no traversal. Everything else is a 404.
- **Navigation** is limited to `selfguard://dashboard/…`. https links (osv.dev advisories,
  GitHub) open in your default browser; any other scheme is cancelled. Website data is kept in
  memory only.
- **CSP** on every response: `default-src 'none'`, scripts, styles and images only from the
  page's own origin, `connect-src 'none'` (the page cannot make requests at all),
  `form-action 'none'`, `frame-ancestors 'none'`. No inline scripts or styles, no third-party
  resources.
- **The API** is reachable only through a script message handler (`selfguard`, page world
  only) that the app registers. It accepts calls from the dashboard's own main frame, checks
  that the method is GET or POST, the path starts with `/api/` and the body is a JSON object,
  and forwards them to `selfguard bridge`, a child process of the app that speaks
  newline-delimited JSON over stdio. The bridge validates again (and refuses lines over 1 MB),
  then runs the same code the CLI uses. The bridge's stdout carries only the protocol. It starts
  with the first request, stops a minute after the window closes, and exits if the app dies
  (its stdin closes).
- untrusted text (package names, advisory summaries, paths) is inserted with `textContent`,
  never as HTML;
- actions (re-scan, ignore) only accept projects selfguard already tracks; links only go to
  `osv.dev` advisory pages;
- the folder browser lists only the names of visible subfolders (no files, no contents), and
  adding a folder only changes `config.json`. Discovery still reads lockfiles as data and never
  runs anything.

Compared with the previous local web server, other users of the Mac and other websites have
nothing to connect to or guess (no port, no token in process arguments or on disk), and a
compromised web page cannot reach the engine except through requests the app validates. Any
process running as you could still start `selfguard bridge` itself, but it could just as well
run the CLI, which exposes the same operations.

On Linux and on machines without the app there is no dashboard; the CLI is complete there.

## Old launcher app

Before 0.14, `selfguard app install` generated a script-only `~/Applications/selfguard.app`
that started the dashboard server. It no longer exists, and neither do `selfguard app` and
`selfguard ui`: the CLI never launches or opens anything. If an old launcher is still in
`~/Applications`, drag it to the Trash.

## Releases

Every published version is:

1. **Built in GitHub Actions** from a tagged commit. Actions are pinned to full commit SHAs, the
   checkout keeps no credentials, and the tag must match `package.json`.
2. **Published with npm Trusted Publishing (OIDC).** No long-lived npm token exists anywhere.
3. **Signed with provenance.** A [SLSA provenance](https://slsa.dev) attestation, recorded in
   the public Sigstore transparency log, links the package to the exact repository, workflow
   and commit.
4. **Staged, not published.** The trusted publisher is only allowed to *stage* a version. A
   maintainer must approve it on npmjs.com with 2FA before anyone can install it. The deploy
   job itself also requires a maintainer's approval in GitHub.

The Mac app is built in the same workflow, in a job that requires a maintainer's approval and
is the only place the Apple and Sparkle keys exist. Each DMG is signed with Developer ID,
notarized, given a GitHub artifact attestation (SLSA provenance) and published with its
checksum. Sparkle updates are accepted only with a valid EdDSA signature of both the feed and
the DMG. Each release also carries a CycloneDX SBOM with its own attestation.

Verify an installed copy:

```sh
npm audit signatures
npm view selfguard@<version> dist.attestations
gh attestation verify selfguard-<version>-<arch>.dmg --repo josseed/selfguard
```

All the commands, for the CLI, the DMG and the SBOM, are in [Verify your download](verify.md).
The repository is also checked continuously by OpenSSF Scorecard, CodeQL and zizmor.

## Known limitations

- Advisory data is only as complete and timely as OSV.dev. A malicious package that hasn't been
  reported yet won't be flagged.
- Git, file, link and tarball dependencies are skipped. They aren't in registry advisory
  databases.
- Matching is by package name. A package from a private registry that shares its name with a
  public package is checked against the public package's advisories.
- macOS notifications appear as "Script Editor" because they are delivered through `osascript`.
