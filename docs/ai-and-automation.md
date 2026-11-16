# AI and automation

selfguard is designed to be driven by people, scripts and AI assistants alike:

- an **MCP server** so assistants can query and manage it directly;
- **`--json`** on every command, with stable shapes and structured errors;
- **`selfguard guide`**, a short usage guide written for agents.

## MCP server

`selfguard mcp` runs a [Model Context Protocol](https://modelcontextprotocol.io) server over
stdio. Add it to your client:

**Claude Code**

```sh
claude mcp add selfguard -- selfguard mcp
```

**Claude Desktop, Cursor, VS Code and other clients** (JSON config):

```json
{
  "mcpServers": {
    "selfguard": {
      "command": "selfguard",
      "args": ["mcp"]
    }
  }
}
```

> Desktop apps don't load your shell profile, so they may not find `selfguard` or `node` when
> they are installed through nvm, fnm or similar. If the server fails to start, use absolute
> paths. `command -v node` and `command -v selfguard` print them:
>
> ```json
> { "command": "/Users/you/.nvm/versions/node/v24.12.0/bin/node",
>   "args": ["/Users/you/.nvm/versions/node/v24.12.0/bin/selfguard", "mcp"] }
> ```

Then ask things like:

- *"Which of my projects have critical vulnerabilities, and how do I fix them?"*
- *"Is `@ctrl/tinycolor` used anywhere on my machine?"*
- *"Explain GHSA-35jh-r3h4-6jhm and tell me which of my repos it affects."*
- *"Stop tracking the test fixtures in ~/code/shop."*
- *"Watch ~/work too, and register what's in there."*

### Tools

| Tool | Read-only | Network | Purpose |
|---|---|---|---|
| `selfguard_status` | ✅ | | Overview: repos (grouped checkouts, with `active` flags) and projects with risk summary. Start here. |
| `selfguard_attention` | ✅ | | The short list reminders are about: serious findings per repo, on its representative checkout. |
| `selfguard_project_report` | ✅ | | Vulnerable packages of one project with `upgradeTo` and advisory IDs. |
| `selfguard_scan` | | ✅ | Scan one project now. |
| `selfguard_sync` | | ✅ | Discover new projects and re-check everything; returns only what's new. |
| `selfguard_check` | | ✅ | Re-scan only projects whose lockfile changed. Use it to verify a fix. |
| `selfguard_machines` | ✅ | | Other machines (dev servers): folders, projects, last sync or error. |
| `selfguard_machines_sync` | | ✅ | Check other machines now over SSH (read-only there). Use it to verify a fix on a server. |
| `selfguard_where` | ✅ | | Which projects use a package (any ecosystem, or `ecosystem` to narrow), which versions, whether vulnerable. |
| `selfguard_vulnerability` | ✅ | ✅ | Advisory details plus the user's affected projects. |
| `selfguard_roots_list` | ✅ | | Watched folders and exclusions. |
| `selfguard_roots_add` / `selfguard_roots_remove` | | | Manage watched folders. |
| `selfguard_discover` | | ✅ | List (default) or register new projects in watched folders. |
| `selfguard_forget` | | | Stop tracking and exclude a path. Marked destructive. |
| `selfguard_unexclude` | | | Re-include an excluded path. |

Each tool declares MCP annotations (`readOnlyHint`, `destructiveHint`, `openWorldHint`), so
clients can decide what to auto-approve. Results come as `structuredContent` and as JSON text.

### Safety

- **No tool runs package managers, project scripts or shell commands.** Assistants propose fixes
  and you apply them.
- **Advisory text and package names are third-party data.** Tool descriptions and the agent
  guide tell the model to treat them as data, never as instructions (prompt-injection
  hardening). All such text is also stripped of control and bidirectional characters.
- **`selfguard_forget` is marked destructive**, and the guide asks the assistant to confirm with
  you first.

## JSON output

Add `--json` to any command. stdout receives exactly one JSON document. Errors exit with code `2`
and print:

```json
{ "error": { "code": "not_tracked", "message": "/path is not tracked yet; scan it first" } }
```

Main shapes (abridged):

**`status --json`**

```json
{
  "repos": [
    {
      "key": "github.com/acme/web",
      "label": "acme/web",
      "active": true,
      "worstSeverity": "critical",
      "vulnerablePackages": 41,
      "inactiveCheckouts": 1,
      "checkouts": [
        { "path": "/Users/you/code/web", "branch": "main", "worktree": false, "orphaned": false,
          "exists": true, "active": true, "lastActivity": "2026-11-15T10:02:11.000Z",
          "worstSeverity": "critical", "vulnerablePackages": 31, "advisories": 83, "error": null }
      ]
    }
  ],
  "projects": [ { "path": "…", "lockType": "pnpm", "packages": 1520, "worstSeverity": "critical",
                  "vulnerablePackages": 31, "advisories": 83, "bySeverity": { "critical": 2 },
                  "scannedAt": "2026-11-14T19:20:24.875Z", "error": null, "repo": { "…": "…" } } ]
}
```

**`scan --json`** / **`report --json`**: a project summary plus `vulnerable`:

```json
{
  "path": "/Users/you/code/web",
  "vulnerable": [
    {
      "name": "lodash", "version": "4.17.20", "direct": true, "dev": false,
      "worstSeverity": "high", "upgradeTo": "4.18.0", "advisoriesWithoutFix": 0,
      "advisories": [
        { "id": "GHSA-35jh-r3h4-6jhm", "aliases": ["CVE-2021-23337"], "severity": "high",
          "summary": "Command Injection in lodash", "fixedIn": "4.17.21",
          "url": "https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm" }
      ]
    }
  ]
}
```

`scan --json` wraps it as `{ "project": …, "firstScan": false, "newAdvisories": 0 }`.

**`sync --json`**

```json
{
  "projects": 42,
  "discovered": ["/Users/you/code/new-clone"],
  "pruned": [],
  "news": [ { "path": "…", "packages": [ { "name": "axios", "version": "0.21.0",
              "worstSeverity": "high", "advisories": ["GHSA-…"] } ] } ],
  "errors": []
}
```

Repo-level `worstSeverity` and `vulnerablePackages` cover active checkouts only (all of them if
none is active).

**`remind --dry-run --json`**: `{ "sent", "notification": { "title", "subtitle", "body" } | null, "repos": [{ "repo", "packages": [{ "name", "version", "worstSeverity", "upgradeTo", "direct" }] }] }`

**`check --json`**: `{ "rescanned": ["/path"], "errors": [{ "path", "error" }] }`

**`settings --json`**: `{ "remind", "activeDays", "lastReminder", "lastSync", "lastCheck" }`

**`where <pkg> --json`**: `{ "package", "usedIn": [{ "path", "versions": [{ "version", "direct", "dev", "vulnerable" }] }] }`

**`vuln <id> --json`**: `{ "id", "aliases", "severity", "summary", "details", "published", "modified", "affected", "references", "url", "affectsYourProjects": [{ "path", "package", "version", "fixedIn" }] }`

Field values are stable within a major version. New fields may be added.

## Scripting and CI

`selfguard scan` exits with `1` when anything is found, so it works as a CI gate:

```yaml
- run: npx -y selfguard@0.1.0 scan . --json > selfguard.json
  env:
    SELFGUARD_NO_NOTIFY: "1"
```

Pin the version you vetted rather than using `latest`. Fail only on serious findings with `jq`:

```sh
selfguard scan --json | jq -e '[.project.vulnerable[] | select(.worstSeverity == "malicious" or .worstSeverity == "critical")] | length == 0'
```

Find every project using a compromised version across your machine:

```sh
selfguard where event-stream --json | jq -r '.usedIn[] | "\(.path) \(.versions | map(.version) | join(","))"'
```
