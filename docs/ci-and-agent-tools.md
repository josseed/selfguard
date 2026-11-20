# CI workflows and agent tools

Besides lockfiles, selfguard checks two things that run with your credentials (CI secrets,
tokens, source code) without being in any project lockfile:

- **GitHub Actions** referenced by each repo's workflows.
- **MCP servers** configured for AI agents, on this machine and in each repo.

Files are read as data: nothing is executed, GitHub is never called, and only MCP server
package names (and exact versions) are sent to OSV. Action names never leave the machine: they
are matched against a local index of OSV's GitHub Actions advisories. Results appear in
`selfguard tools`, `selfguard where`, the `selfguard_sources` MCP tool, the dashboard (an
**Agent tools** card and a section on each repo's page) and the usual alerts: a malicious
action or MCP server opens the same dialog as a malicious package. Repo status counts cover
lockfiles only; sources are shown separately.

## Findings and warnings

- **Findings** come from OSV advisories, each with a `certainty`:
  - `confirmed`: the exact version written is affected.
  - `may-be-affected`: a mutable tag such as `@v4`; some release of that line is affected.
  - `version-unknown`: the version can't be known from the file.
    - A commit SHA without a version comment is fixed but unknown: every advisory of the
      package is listed, with the version that fixes it so you can check your SHA.
    - A branch (`@main`), a tag such as `@latest`, or an unpinned package runs the latest
      release: only advisories without a fix (they affect the latest release) are listed, plus,
      for an unpinned npx package, those affecting the version last run (from the npx cache,
      as `may-be-affected` with "last run … is affected").

  Malicious advisories (`MAL-*`) always apply, whatever the version.
- **Warnings** are risky practices found without the network. They are never counted as
  vulnerable packages. High-severity ones (and those whose rule asks for it) notify you when
  they appear after the first scan; `selfguard dismiss --warning <id>` silences one you put
  there on purpose. See [alerts](how-it-works.md#alerts).

## GitHub Actions

### Files read

- `.github/workflows/*.yml` and `*.yaml` at the git root of each tracked repo. Subfolders are
  not read.
- `action.yml` and `action.yaml` of composite actions anywhere in the repo, up to 6 levels
  deep. Dependency, build, hidden (except `.github`) and symlinked folders are skipped.

The lockfile watcher also watches each `.github/workflows` folder and the folders of the
composite actions found.

### References

| Written as | Checked as |
|---|---|
| `owner/repo@ref`, `owner/repo/path@ref`, reusable `owner/repo/.github/workflows/x.yml@ref` | action `owner/repo` |
| `@v4.1.0`, `@4.1.0` | exact version |
| `@v4`, `@v4.1` | release line: may be affected |
| 40-character SHA with a `# v4.1.0` (or `# tag=…`, `# pin@…`, `# ratchet:…@…`) comment | that version |
| SHA without a version comment, or a branch | version unknown |
| `./local` | through that folder's `action.yml` |
| `docker://…`, values with `${{ }}` | skipped and counted |

Action names are matched **case-insensitively**, as GitHub resolves them: `azure/setup-kubectl`
gets the advisories OSV stores as `Azure/setup-kubectl`. OSV's API matches names
case-sensitively and doesn't match versions for this ecosystem, so actions are **never sent to
OSV**. Instead selfguard keeps a local index of the whole GitHub Actions ecosystem (64
advisories on 2026-11-16):

- it downloads OSV's public list `GitHub%20Actions/modified_id.csv` from
  `osv-vulnerabilities.storage.googleapis.com` (at most every 6 hours, when actions are
  checked), then the details of the advisories that are new or changed since the last time;
- names are compared lowercased, and the advisory ranges are evaluated locally, including
  partial versions such as `fixed: 41`.

Offline, the last index is used. Without any index yet, the source shows "could not refresh
the GitHub Actions advisory index" and keeps its previous results; it is never reported clean.
The index is stored in `~/.selfguard/cache/github-actions-index.json`.

### Warnings

| Rule | Severity | When |
|---|---|---|
| `unpinned-action` | moderate | A third-party action isn't pinned to a full commit SHA (`actions/*` and `github/*` are exempt). |
| `pr-target-checkout` | high | A `pull_request_target` or `workflow_run` workflow checks out the pull request head with `actions/checkout`. |
| `script-injection` | high | Untrusted event text (issue, PR, comment and review titles and bodies, head ref, commit messages, page names…) is interpolated with `${{ }}` into a `run:` script. Passing it through `env:` is the safe form and isn't flagged. |

Limits: flow mappings (`- { uses: x }`), anchors, multi-line quoted scalars and expressions
split across lines aren't interpreted; a checkout done with `run: git …`, or untrusted text
passed through an intermediate `env:` or step output, isn't detected.

## MCP servers of AI agents

### Files read

| Agent | This machine | In each repo |
|---|---|---|
| Claude Code | `~/.claude.json` (`mcpServers`, and per-project entries) | `.mcp.json` |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json`, `~/.config/Claude/claude_desktop_config.json` | — |
| Cursor | `~/.cursor/mcp.json` | `.cursor/mcp.json` |
| VS Code (and Insiders) | user `mcp.json` (`servers`) | `.vscode/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | — |
| Codex | `~/.codex/config.toml` (`[mcp_servers.*]`) | — |
| Gemini CLI | `~/.gemini/settings.json` | `.gemini/settings.json` |

JSON with comments and trailing commas is accepted. A file that can't be parsed gives an
`unreadable-agent-config` warning that never quotes its content.

### Launchers

| Launcher | Checked as |
|---|---|
| `npx` (`-y`, `-p`/`--package`), `bunx`, `pnpm dlx`, `pnpx`, `yarn dlx`, `npm exec` | npm package |
| `uvx`, `uv tool run` (`--from`), `pipx run` (`--spec`) | PyPI package |
| absolute paths to those, `cmd /c …`, a whole command in one string | as above |
| `docker`, `node`, `python`, other binaries, git URLs, tarballs, local paths | skipped and counted |

Only an exact version (`@1.2.3`, `==1.2.3`) is pinned. Tags and ranges (`@latest`, `^1`) are a
version-unknown reference plus an `unpinned-mcp-server` warning (moderate): the server runs
whatever is latest when the agent starts. For an unpinned npx package, the copy in the npx cache
(`~/.npm/_npx`) gives the version last run, shown in the warning. It doesn't make the reference
exact: the package is still asked by name (so malicious advisories always apply), and the
version last run only adds the advisories that affect it.

### Privacy

Agent configs often hold secrets. From each server selfguard keeps only the agent, server name,
launcher, package name, version or pin, file and line. Environment variables, headers, URLs,
tokens and other arguments are never stored, printed, logged, returned to an AI or sent. Remote
servers (`url`, `httpUrl`, `serverUrl`, HTTP/SSE types) aren't checked; a low
`remote-mcp-server` warning names the host only. A test puts secrets in every one of those
places and checks that none reaches records, events, logs, CLI and MCP output or OSV requests.

Limits: line numbers are best effort; changes to the npx cache don't trigger a rescan; VS Code's
`settings.json` (`mcp.servers`), Windows paths, `CLAUDE_CONFIG_DIR`/`CODEX_HOME` overrides,
managed configs and the bunx, pnpm and uv caches aren't read.

## When they are checked

- `selfguard scan <dir>`: the repo's workflows and agent configs, in the same OSV request as its
  lockfile. A one-line summary points to `selfguard tools <dir>` when something needs a look.
- `selfguard sync` and the scheduled sync: every tracked repo's sources and this machine's
  agent configs. `selfguard check` and the watcher: sources whose files changed. Check doesn't
  search the repos: it compares the files of the last scan (size and modification time, then
  content) and the folders new ones appear in (`.github/workflows`, `.github`,
  `.github/actions`, the composite actions' folders); a repo is searched again only when one
  of those folders changed. A repo without results yet is picked up by check once it has a
  workflow in `.github/workflows`; composite actions elsewhere are found by the next sync or
  scan. A changed file is read again, but OSV is only asked when its references changed or its last successful
  check is more than 24 hours old (`~/.claude.json` changes all the time). When OSV can't be
  reached, the previous results are kept and the next check retries.
- A source checked for the first time is a baseline: its findings don't notify, except
  malicious ones.
- `selfguard forget` also forgets the CI and agent config results of the project's git repo
  when no other tracked project lives in it.
- Other machines: not yet. Their reader would need to serve workflow and agent config files,
  which widens what a restricted key can read; that needs its own review.

Records are stored in `~/.selfguard/sources/`, separate from lockfile records.
