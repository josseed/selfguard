# CI workflows and agent tools

Besides lockfiles, selfguard checks two things that run with your credentials (CI secrets,
tokens, source code) without being in any project lockfile:

- **GitHub Actions** referenced by each repo's workflows.
- **MCP servers** configured for AI agents, on this machine and in each repo.

Files are read as data: nothing is executed, GitHub is never called, and only package or
action names (and exact versions where OSV supports them) are sent to OSV. Results appear in
`selfguard tools`, `selfguard where`, the `selfguard_sources` MCP tool, the dashboard (an
**Agent tools** card and a section on each repo's page) and the usual alerts: a malicious
action or MCP server opens the same dialog as a malicious package. Repo status counts cover
lockfiles only; sources are shown separately.

## Findings and warnings

- **Findings** come from OSV advisories, each with a `certainty`:
  - `confirmed`: the exact version written is affected.
  - `may-be-affected`: a mutable tag such as `@v4`; some release of that line is affected.
  - `version-unknown`: a branch, a SHA without a version comment, or an unpinned package.
    Every advisory of the package is listed.

  Malicious advisories (`MAL-*`) always apply, whatever the version.
- **Warnings** are risky practices found without the network. They are never counted as
  vulnerable packages.

## GitHub Actions

### Files read

- `.github/workflows/*.yml` and `*.yaml` at the git root of each tracked repo. Subfolders are
  not read.
- `action.yml` and `action.yaml` of composite actions anywhere in the repo, up to 6 levels
  deep. Dependency, build, hidden (except `.github`) and symlinked folders are skipped.

The lockfile watcher also watches each `.github/workflows` folder.

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

Action names keep the case they are written in. OSV stores GitHub's own spelling and matches
it case-sensitively (`Azure/setup-kubectl` has advisories, `azure/setup-kubectl` none), so an
action written in another case than its advisory isn't matched. `selfguard where` ignores case.

OSV doesn't match versions for this ecosystem server-side: a query for
`tj-actions/changed-files` at `45.0.7` returns nothing (checked on 2026-11-16). Every action is
therefore queried **by name only**, and the advisory ranges are evaluated locally, including
partial versions such as `fixed: 41`.

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
(`~/.npm/_npx`) gives the version last run, shown in the warning and checked as that version.

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
  agent configs. `selfguard check` and the watcher: sources whose files changed.
- Other machines: not yet. Their reader would need to serve workflow and agent config files,
  which widens what a restricted key can read; that needs its own review.

Records are stored in `~/.selfguard/sources/`, separate from lockfile records.
