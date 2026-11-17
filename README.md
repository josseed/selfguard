# selfguard

[![npm](https://img.shields.io/npm/v/selfguard)](https://www.npmjs.com/package/selfguard)
[![CI](https://github.com/josseed/selfguard/actions/workflows/ci.yml/badge.svg)](https://github.com/josseed/selfguard/actions/workflows/ci.yml)
[![provenance](https://img.shields.io/badge/npm-provenance-blue)](https://www.npmjs.com/package/selfguard#provenance)
[![license](https://img.shields.io/npm/l/selfguard)](LICENSE)

**A local-first guard for the dependencies of every JavaScript, Python, Rust and Go repo on your machine.**

Most dependency scanners only check a project when you remember to run them, or only for repos
hosted on a platform. selfguard tracks every project on your machine and checks their lockfiles
against [OSV.dev](https://osv.dev). It tells you when one of them is affected by a new
vulnerability or a malicious package, including repos you haven't opened in months.

```text
$ selfguard status
CRITICAL acme/storefront  31 vulnerable pkg(s) on main · 82 on feat/checkout  3 checkouts
   ├ main  31 vulnerable  ~/code/storefront
   ├ fix/query-perf worktree  30 vulnerable  ~/code/storefront-query-perf
   └ feat/checkout worktree  82 vulnerable  ~/code/storefront-feat-checkout
HIGH     acme/payments-api  3 vulnerable pkg(s)  ~/code/payments-api
✓        acme/docs-site  clean  ~/code/docs-site
```

## Features

- **It tells you on its own.** A background watcher re-checks a repo seconds after its lockfile
  changes (`git pull`, installs, merges), a scheduled sync catches newly published advisories,
  and a daily reminder lists what is still open and serious. When you fix something, you get a
  "✓ fixed" notification too.
- **A dashboard, not just a terminal.** The Mac app shows every repo, what needs attention,
  how to fix it, and a feed of what changed, in its own window (`selfguard ui` opens it). There
  is no web server and no browser involved. On Linux the CLI is complete: `selfguard status`,
  `report`, `--json`.
- **Bastion, a guard who tells you.** A 16-bit castle guard, brought up to date, acts out what
  changed on the dashboard and, in the Mac app, in a small panel: he sounds the horn for a
  critical vulnerability, fights off a malicious package and celebrates your fixes. With the
  app open, each alert arrives once, from him.
- **Your other machines too.** Your other Macs connect over Tailscale with selfguard sharing.
  You press Connect, check that both screens show the same code and approve it over there: no
  SSH, no Remote Login, nothing listening outside your tailnet. Servers without selfguard use
  SSH with a dedicated key that only runs a small read-only reader. The scan runs locally, and
  alerts and the dashboard name the machine.
- **Signal over noise.** Only checkouts with recent git activity alert you. Old clones and
  abandoned worktrees stay listed but quiet (except for malicious packages), and a new worktree
  of a known repo isn't reported as news.
- **Hands-off.** `cd` into a project and it is registered and scanned in the background. New
  clones in your code folders are picked up automatically.
- **Finds your projects even if you don't keep them in one place.** "Find my projects" searches
  your home folder and skips dependencies, caches, cloud drives and copies. It finds agent
  worktrees through their repos and proposes a few folders to watch. A weekly pass picks up new
  ones on its own.
- **Malicious packages first.** OSV includes the OpenSSF malicious-packages feed (`MAL-*`).
  Compromised releases, like the Shai-Hulud npm worm, outrank any CVE and open a dialog that
  stays on screen until you dismiss it.
- **Actionable output.** One upgrade target per vulnerable package ("upgrade lodash to 4.18.0"),
  not a wall of advisories.
- **JavaScript, Python, Rust and Go.** npm, pnpm, yarn (classic and berry) and bun lockfiles,
  `uv.lock` and `poetry.lock`, `Cargo.lock`, and `go.mod`. See
  [supported ecosystems](docs/multi-ecosystem.md) for what each one covers.
- **CI workflows and AI agent tools.** GitHub Actions used by your workflows (compromised
  actions, unpinned references, script injection) and the MCP servers configured for Claude,
  Cursor, VS Code, Codex and other agents, without ever reading their secrets. See
  [CI workflows and agent tools](docs/ci-and-agent-tools.md).
- **Repo-aware.** Git worktrees and clones of the same repo are grouped, each with its branch.
- **Incident response.** `selfguard where <package>` answers "do I use this anywhere?" in one
  command.
- **AI-ready.** A built-in MCP server, `--json` output on every command, and a guide for agents.
- **Safe by design.** It never executes code from your projects, has zero runtime dependencies,
  and only sends package names and versions over the network.

## Quick start

Requires **Node.js 20.10+**. Works on **macOS** and **Linux**. Native notifications and
scheduling are macOS-only for now.

```sh
npm install -g selfguard
selfguard setup
```

`setup` is a small terminal UI. Pick the folders where you keep your code, and selfguard scans
them. It then offers to install the shell hook and background watching with notifications.
You don't need the command line on a Mac: the selfguard app (below) bundles everything, asks
whether to watch in the background, and has an optional "Install Terminal Command…" in its menu.
Then open the dashboard (the selfguard Mac app, from the
[latest release](https://github.com/josseed/selfguard/releases/latest)):

```sh
selfguard ui
```

```text
Where do you keep your code?
selfguard only looks inside the folders you pick, nothing else on your disk.

  [x] ~/code                          42 projects    depth 5
› [ ] ~/work                          17 projects    depth 5
  + add another folder…

↑/↓ move · space select · ←/→ depth · a add folder · enter continue · q quit
```

Or scan a single project without setting anything up:

```text
$ selfguard scan
~/code/payments-api  412 packages
  3 vulnerable package(s), 9 advisories: 1 critical, 4 high, 4 moderate

  CRITICAL minimist@1.2.5 (transitive)
    → upgrade to 1.2.6 or later
    • GHSA-xvch-5gv4-984h critical Prototype Pollution in minimist

  HIGH axios@0.21.0 (direct)
    → upgrade to 0.33.0 or later
    • GHSA-cph5-m8f7-6c5x high axios Inefficient Regular Expression Complexity vulnerability
    …
```

## Documentation

| | |
|---|---|
| [Getting started](docs/getting-started.md) | Install, setup, dashboard, alerts, uninstall |
| [CLI reference](docs/cli.md) | Every command and flag, exit codes, environment variables |
| [Supported ecosystems](docs/multi-ecosystem.md) | JavaScript, Python, Rust and Go: files read, what is checked, limitations |
| [CI workflows and agent tools](docs/ci-and-agent-tools.md) | GitHub Actions in workflows and MCP servers of AI agents: what is read, checks, privacy |
| [How it works](docs/how-it-works.md) | Discovery, lockfile parsing, repo grouping, OSV, caching, alerts |
| [AI and automation](docs/ai-and-automation.md) | MCP server setup, tools, JSON output, scripting and CI |
| [Security model](docs/security-model.md) | What selfguard trusts, what it sends, how it is released |
| [Troubleshooting](docs/troubleshooting.md) | Notifications, hook, scheduling, unsupported lockfiles |

## How it compares

| | selfguard | `npm audit` | osv-scanner | Dependabot |
|---|---|---|---|---|
| Watches every project on your machine | ✅ | ❌ one project, on demand | ❌ on demand | ❌ hosted repos only |
| Alerts when a new advisory hits an old project | ✅ | ❌ | ❌ | ✅ |
| Local-only (no repo hosting required) | ✅ | ✅ | ✅ | ❌ |
| npm, pnpm, yarn, bun | ✅ | npm only | ✅ | ✅ |
| uv, Poetry, Cargo, Go modules | ✅ | ❌ | ✅ | ✅ |
| Malicious package feed | ✅ via OSV | ❌ | ✅ via OSV | partial |
| Opens PRs with fixes | ❌ | ❌ (`npm audit fix` locally) | guided remediation | ✅ |
| Ecosystems | JavaScript, Python, Rust, Go | JavaScript | many | many |

selfguard complements these tools rather than replacing them. Keep Dependabot or Renovate for
automated fix PRs, and use selfguard to know what is vulnerable on your machine right now.

## Privacy

selfguard sends only the ecosystem, `name` and `version` of your locked dependencies to the OSV.dev API.
No file paths, repo names or source code ever leave your machine. All state lives in
`~/.selfguard`, readable only by your user. See the [security model](docs/security-model.md).

## Contributing

Bug reports, ideas and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).
Please report security issues privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
