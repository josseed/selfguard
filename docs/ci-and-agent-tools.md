# CI workflows and agent tools

Status: **proposed; not implemented**. This document designs two new sources for selfguard:
GitHub Actions workflows and the MCP servers configured for AI agents. Both run with the
developer's credentials (CI secrets, tokens, source code) outside any project lockfile, and
neither is checked by the current scans.

## Goals

- Report actions and MCP servers that match a known advisory, especially malicious ones
  (`MAL-*`), with the same alerts, dashboard and MCP tools as dependencies.
- Flag risky practices that need no network: mutable references and unpinned packages.
- Keep the security model: files are read as data, nothing is executed, and only package
  names, versions and ecosystems are sent to OSV.

Non-goals: secret scanning, container images, a full workflow linter, editing files.

## 1. GitHub Actions workflows

### Inputs

`.github/workflows/*.yml` and `*.yaml` at the git root of each tracked repo, and `action.yml`
or `action.yaml` of composite actions anywhere in the repo. Workflows belong to the repo, not
to a lockfile folder, so they are scanned once per git root, even if the root also has a
lockfile.

### Extraction

The YAML reader used for pnpm skips sequence items, and workflows are mostly sequences
(`steps:`). Extraction is therefore a line scanner for `uses:` values, not a YAML parser:

| `uses:` value | Result |
|---|---|
| `owner/repo@ref`, `owner/repo/path@ref` | action `owner/repo` (path dropped) at `ref` |
| `owner/repo/.github/workflows/x.yml@ref` | reusable workflow `owner/repo` at `ref` |
| `./path` | local action: read its `action.yml` instead |
| `docker://image` | skipped and counted (out of scope) |

Quoted values, trailing comments and `${{ }}` expressions are handled; a value with an
expression is skipped. Each result keeps the file and line for the report.

### Versions

Checked against OSV on 2026-11-16: advisories in the `GitHub Actions` ecosystem use
`ECOSYSTEM` ranges with release numbers (`introduced: 0`, `fixed: 46.0.1`, sometimes partial
like `fixed: 41`), and OSV does **not** match them server-side: a query for
`tj-actions/changed-files` at `45.0.7` (or `v45.0.7`) returns nothing, while the same query
without a version returns both advisories. So:

- Every action is queried **by name only**, and the ranges are evaluated locally (as
  `match.ts` already does), with a SemVer comparison that accepts partial versions
  (`41` = `41.0.0`) and a leading `v`.
- **Version tag** (`@v4.1.0`): evaluated with that version.
- **Major or minor tag** (`@v4`, `@v4.1`): the exact release is unknown offline. Reported as
  affected when any release of that major (or minor) line is in a range, marked "mutable
  reference: may be affected".
- **Commit SHA** (`@8f4b7f8…`): if the line carries the `# v4.1.0` comment that Dependabot and
  Renovate write, that version is used; otherwise every advisory of the action is listed as
  "version unknown". Resolving a SHA through the GitHub API is not done: it would reveal which
  repos you use.
- **Branch** (`@main`): mutable; listed like an unknown version.

Malicious advisories apply whatever the version, so a compromised action is always reported.

### Practice checks (no network)

Shown as warnings, not counted as vulnerable packages:

1. Third-party action not pinned to a full commit SHA (actions from `actions/*` and
   `github/*` can be exempted by a setting).
2. `pull_request_target` or `workflow_run` workflows that check out the pull request head.
3. `${{ github.event.* }}` text fields (titles, bodies, branch names) interpolated directly
   into `run:` scripts.

Each warning cites the file and line. Further checks need their own design.

## 2. MCP servers and agent tools

### Inputs

Configuration files of common agents, read only for their server definitions:

| Agent | Machine-wide | Per project |
|---|---|---|
| Claude Code | `~/.claude.json` (`mcpServers`, and per-project entries) | `.mcp.json` |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` | — |
| Cursor | `~/.cursor/mcp.json` | `.cursor/mcp.json` |
| VS Code | user `mcp.json` | `.vscode/mcp.json` (`servers`) |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | — |
| Codex | `~/.codex/config.toml` (`[mcp_servers.*]`) | — |
| Gemini CLI | `~/.gemini/settings.json` | `.gemini/settings.json` |

Paths and keys must be verified against each tool's current documentation during
implementation; the list is data, so adding an agent is one entry.

### Privacy

These files can hold secrets (`env`, `headers`, API keys in arguments). selfguard keeps only
the launcher, package name and version of each server. It never stores, prints, logs or sends
environment variables, headers, URLs with credentials, or other arguments. Remote servers
(`url` / `httpUrl`) are listed by host only and not checked.

### Extraction

From `command` and `args`:

| Launcher | Package and version |
|---|---|
| `npx` (`-y`, `--yes`, `-p`/`--package`), `bunx`, `pnpm dlx`, `yarn dlx` | npm `name@version` |
| `uvx` (`--from`), `pipx run` (`--spec`) | PyPI `name==version` |
| `docker run`, `node /path`, `python /path`, other binaries | skipped and listed as "not checked" |

A server without an exact version is **unpinned**: it runs whatever is latest when the agent
starts. For npx, the version actually run may be recoverable from the npx cache
(`~/.npm/_npx/*/package-lock.json`); this is to be confirmed. Otherwise the package is queried
by name only: malicious advisories are reported, and other advisories are summarized as "N
advisories exist for some versions; pin a version to check it."

### Where it shows

- Machine-wide servers appear as an **Agent tools** item: dashboard section, `selfguard tools`
  command and MCP tool, with the agent and config file each server comes from.
- Per-project servers (`.mcp.json`, `.cursor/mcp.json`, …) are attached to their repo, like
  workflows.
- A malicious server raises the same blocking dialog as a malicious package.

## Shared implementation

- **Sources beside the lockfile.** A record now has one lockfile. Workflows and project MCP
  configs become additional sources of a repo, stored in their own records keyed by git root
  and kind (`ci`, `agents`), so the one-lockfile-per-folder model and existing records are
  untouched. Machine-wide agent configs get one record of kind `agents`.
- **Change detection.** Size and mtime of each source file, hashed when they change, as with
  lockfiles. The launchd watcher also watches `.github/workflows` and the agent config files.
- **Scanning.** Extracted references become dependencies with an ecosystem (`GitHub Actions`,
  `npm`, `PyPI`) and go through the same deduplicated OSV batch. A name-only query is a
  query without `version`; OSV then returns every advisory of the package, so local range
  evaluation decides which ones apply (and must handle partial versions).
- **Remote machines.** Phase 2: the reader would need to list and serve workflow and agent
  config files, which widens what a restricted key can read; it needs its own review.
- **Output.** Findings carry their source (`lockfile`, `workflow`, `agent-config`) and, for
  workflows, file and line. JSON, MCP, markdown and the dashboard show them.

## Phases

1. Workflows: `uses:` extraction, OSV check, mutable-reference warning.
2. Agent configs: Claude Code, Cursor, VS Code and Claude Desktop; npx and uvx launchers.
3. Remaining agents and launchers, workflow practice checks 2 and 3, npx cache resolution.
4. Remote machines, after a review of the reader's scope.

## Acceptance criteria

- Fixtures for every `uses:` form and every launcher, including quoting, comments,
  expressions, SHAs with and without version comments, and unknown commands.
- A test that config secrets (`env`, headers, keys in arguments) never appear in records,
  logs, JSON output or OSV requests.
- Mocked OSV tests: a malicious action and a malicious npx server raise malicious findings
  whatever the reference; version tags are matched locally against `ECOSYSTEM` ranges
  (including partial versions such as `fixed: 41`); name-only results are never reported as
  confirmed when the version is unknown.
- A live check (manual, not in CI) that `tj-actions/changed-files@v45.0.7` is reported and
  `@v46.0.1` is not.
- Existing lockfile records and outputs are unchanged.
- README, how-it-works, security model (new files read, what leaves the machine), CLI, MCP
  guide and changelog updated before the planned label is removed.
