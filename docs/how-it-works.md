# How it works

```text
               ┌──────────── you cd into a project ────────────┐
               ▼                                               │
   zsh hook (pure shell: find a project file, stat lockfile)   │
               │ only when the project or its lockfile changed │
               ▼                                               │
   selfguard hook-enter ──► one-line reminder from the last scan
               │ new project / lockfile changed / last scan > 24h
               ▼
   detached background scan
      parse lockfile ──► OSV.dev querybatch ──► ~/.selfguard ──► notification if something is new

   scheduled sync (launchd, every 6h)
      prune removed folders ──► discover new projects ──► re-check everything ──► notify on news
```

## Finding projects

A **project** is a folder with a lockfile (or a `package.json` at the root of a git repo that has
no lockfile yet). selfguard never crawls your whole disk on its own, and it never leaves your home
folder. A project gets tracked in one of four ways:

1. **Watched folders.** These are folders you chose in `setup` or added with `roots add`.
   Discovery is breadth-first and depth-limited (default 5 levels). It doesn't follow symlinks
   and has a hard budget of 50,000 directories per folder. It descends into every subfolder,
   including inside projects, so a repo with `frontend/` and `backend/` lockfiles yields two
   projects. It skips:
   - dependency and build-cache folders: `node_modules`, `bower_components`, `jspm_packages`,
     `vendor`, `Pods`, `venv`, `__pycache__`, `target`;
   - hidden folders (`.git`, `.next`, `.cache`, `.turbo`, `.yarn`…);
   - when a watched folder is your home directory: `Library`, `Applications`, `Movies`,
     `Music`, `Pictures`, `Public`;
   - anything you excluded with `forget`.
2. **Find my projects** (`selfguard discover --everywhere`, the dashboard's Folders page, and
   weekly in the background). This is for code that isn't all in one folder. It walks the
   whole home folder read-only, with no depth limit, but prunes hard:
   - dependency, build and cache folders anywhere: `node_modules`, `vendor`, `target`, `dist`,
     `build`, `out`, `coverage`, `venv`, `__pycache__`, `DerivedData`…;
   - every hidden folder: dotfiles, tool caches, the trash;
   - in the home: `Library` (which also holds iCloud and `CloudStorage` drives, where listing
     files can download them), `Applications`, media folders and `go/pkg`;
   - other disks and network mounts (it never crosses filesystems) and symlinks;
   - inside a repo, the folder names its own `.gitignore` ignores;
   - a top-level folder that goes through 40,000 folders without a single project is cut
     short and reported.

   Worktrees that tools keep in hidden folders (`~/.t3/worktrees`, `~/repo/.worktrees`) are
   found from their main repo's `.git/worktrees/*/gitdir`, not by walking hidden folders.
   Projects under `examples/`, `fixtures/`, `templates/`, `test/`… of a repo, and copies under
   `evidence/`, `artifacts/`, `backups/`, `archive/`… anywhere, are marked as samples. Like
   projects without git, they never decide what gets watched.

   What's found is grouped into **places**: usually the folder right below the home (or the
   hidden folder holding worktrees), with the depth that covers its projects. Places with repos
   active in the last 30 days are recommended. Approved places become watched folders; the
   others are excluded. The weekly background pass watches new recommended places by itself,
   notifies you, and never re-adds a folder you removed. On macOS, it only enters Desktop,
   Documents and Downloads once a watched folder lives there.
3. **The shell hook.** When you `cd` into a folder, selfguard walks up to the nearest folder
   with a lockfile, stopping at the git root or your home directory, and registers it.
4. **Explicitly**, with `selfguard scan <dir>`.

## Reading lockfiles

Lockfiles are read as **data**. selfguard never runs a package manager, `npm ls`, `pip`, `uv`,
`poetry`, `cargo`, `go`, lifecycle scripts, or anything else from the project, so entering a
hostile repository is safe. None of those tools needs to be installed.

| Package manager | Files | Versions | OSV ecosystem |
|---|---|---|---|
| npm | `package-lock.json`, `npm-shrinkwrap.json` | lockfile v1, v2, v3 | npm |
| pnpm | `pnpm-lock.yaml` | v5.x, v6.x, v9.x | npm |
| yarn | `yarn.lock` | classic (v1) and berry (v2+) | npm |
| bun | `bun.lock` | text lockfile | npm |
| uv | `uv.lock` | v1 | PyPI |
| Poetry | `poetry.lock` (+ `pyproject.toml`) | lock 1.x and 2.x | PyPI |
| Cargo | `Cargo.lock` | v1 to v4 | crates.io |
| Go modules | `go.mod` | Go 1.17+ module files | Go |

A folder holds one project: when it has lockfiles of several ecosystems, the JavaScript one
wins, then uv, Poetry, Cargo and Go. Projects in different folders of the same repo (for example
`web/package-lock.json` and `api/uv.lock`) are separate projects, each fully checked. The
[supported ecosystems](multi-ecosystem.md) page details what each format provides.

The binary `bun.lockb` can't be read. `bun install --save-text-lockfile` converts it.

For every installed package selfguard records:

- **name and version.** Aliases such as `"my-pad": "npm:left-pad@1.3.0"` resolve to the real
  package.
- **direct or transitive.** Direct means declared in the `package.json` of the project or one of
  its workspaces (Python: by the project or its workspace members, or in `pyproject.toml` for
  Poetry; Rust: by a workspace member; Go: a requirement without `// indirect`).
- **dev or production.** A package is "dev" only if it is reachable *exclusively* through
  `devDependencies`. When the lockfile doesn't say (pnpm 9, yarn, bun), selfguard works it out by
  walking the dependency graph from the production dependencies.

Git, file, link, path, URL and tarball dependencies, and crates from registries other than
crates.io, can't be matched against a registry advisory database, so they are counted as skipped.

The test suite includes lockfiles generated by real npm, pnpm, yarn 1, yarn 4 and bun for the
same `package.json`, and requires all five parsers to produce exactly the same result. Python,
Rust and Go parsers are tested with fixtures covering workspaces, dev groups, extras, git and
path sources, alternate registries, `replace` directives and pseudo-versions.

## Matching vulnerabilities

selfguard uses the [OSV.dev](https://osv.dev) API. OSV aggregates the GitHub Advisory Database,
CVEs from NVD, and the [OpenSSF malicious packages](https://github.com/ossf/malicious-packages)
feed, all in one schema.

1. All `ecosystem:name@version` triples from all scanned projects are **de-duplicated** and
   sent to `POST /v1/querybatch` in batches of 1,000. A package of the same name and version in
   two ecosystems is two separate queries. PyPI names are sent PEP 503-normalized.
2. Advisory details come from `GET /v1/vulns/{id}` and are **cached** locally. An advisory is
   downloaded again only when OSV reports it was modified.
3. Each advisory's affected ranges are evaluated locally: `SEMVER` ranges (npm, crates.io, Go)
   with a SemVer 2.0 implementation, PyPI `ECOSYSTEM` ranges with PEP 440 ordering. That
   gives the **lowest fixed version** above the installed one. Per package, selfguard reports
   `upgradeTo`, the smallest version that fixes every advisory that has a fix.
4. Duplicates published under several IDs (GHSA and CVE aliases) are collapsed. Withdrawn
   advisories are ignored.

If OSV can't be reached, the previous findings are kept and the project is marked with an error,
so a network problem never looks like "all clear".

### Severity

`malicious` > `critical` > `high` > `moderate` > `low` > `unknown`.
Anything with an `MAL-` ID is `malicious`. Other severities come from the advisory's
database-specific rating (GitHub's `LOW`/`MODERATE`/`HIGH`/`CRITICAL`), or else from its CVSS v3
base score (9+ critical, 7+ high, 4+ moderate). When an advisory has copies under several ids,
the finding takes the worst severity any copy states. RustSec informational notices
(unmaintained or unsound crates) are not reported.

## Grouping repositories

To group checkouts, selfguard reads a few small files under `.git`. It doesn't run `git`.

- A **linked worktree** has a `.git` *file* pointing to `<main repo>/.git/worktrees/<name>`.
  selfguard follows it back to the main repository.
- **Separate clones** are matched by their `origin` remote. SSH, HTTPS and `scp`-style URLs are
  normalized, so `git@github.com:acme/web.git` and `https://github.com/acme/web` are the same repo.
- **Monorepo subprojects** keep their own group (`acme/web/frontend` ≠ `acme/web`), shared across
  worktrees.

- **Copies without git** (an agent's snapshot of a repo, an unpacked archive, an "evidence"
  folder) join the project they copy: a folder without git counts as a copy when its manifest
  has the same name as a tracked project (`package.json` `name`, `pyproject.toml`,
  `Cargo.toml`, `go.mod` `module`) and at least 60% of the same dependency names. Among
  folders without git, the shallowest one is the original. Checkouts of other machines are
  never merged with local ones.

### The checkout that counts

A repo's vulnerabilities are fixed once, on its default branch; worktrees, other clones and
copies get the fix when they merge or update. So each repo is judged by **one checkout**:

1. the one on the **default branch**: what `origin/HEAD` points to, else `main` or `master`;
2. without one, the main clone if it is active, else the most recently active checkout.

That checkout's findings are the repo's in `status`, the dashboard's repo list, reminders, the
Mac app's menu and the `selfguard_attention` MCP tool. It is marked "default branch" on the
repo's page, where **All checkouts** still lists every checkout's findings and marks those
"only in other checkouts". The repo counts as active if any of its own checkouts (not copies)
has recent git activity, even when the default branch checkout itself is idle.

## Active checkouts

People accumulate clones and worktrees. Alerting about all of them is noise, so selfguard tells
apart the ones you are working on. A checkout is **active** if its own git files (`HEAD`,
`index`, the reflog) changed in the last 30 days (`selfguard settings --active-days N`). Commits,
checkouts, pulls and even `git status` count. Projects outside git are always active, and
orphaned worktrees never are.

Inactive checkouts are still scanned and listed (`status --all`, the dashboard's Inactive tab),
but they only alert for malicious packages.

### Dismissed repos

Sometimes a repo is recent but you don't care about it right now (a repo you cloned to read, a
spike you parked). `selfguard dismiss [dir]` (or **Dismiss** on the repo's page in the
dashboard) turns the whole repo off, every checkout included: it is treated like an inactive
checkout from that moment. It comes back by itself as soon as any of its checkouts has git
activity after the dismissal (the same signal as above: a commit, checkout, pull or `git
status`), so you never have to remember to turn it back on. `selfguard undismiss` does it right
away. Dismissals live in `~/.selfguard/config.json`; the next `sync` or `check` cleans up the
ones that came back.

## Alerts

- **New findings.** A finding is news when it appears in the checkout that counts for its
  repo (see above), wasn't in that checkout's previous scan, wasn't seen there in the last 180
  days (so switching branches back and forth doesn't re-alert), and no other checkout of the
  same repo already has it. The first scan of a brand-new repo is news. Other worktrees, clones
  and copies only alert, and only appear in the activity feed, for malicious packages.
- **Fixes.** When a scan on the **same branch** no longer has a vulnerable package, you get a
  "✓ fixed" notification with what is left. Switching to a branch that happens to be clean
  isn't a fix.
- **New risks.** Warnings of [CI workflows and agent tools](ci-and-agent-tools.md) (and any
  other source: a repo's agent configs, this machine's own config) alert when they appear and
  are either high severity or flagged by their rule as worth telling. A warning's identity is
  its kind, rule, file and the rule's own key (a hook event, a plist label), not its line or
  text, so edits around it don't re-alert. They are grouped per source in one notification
  ("3 new risks in acme/api (agent tools)"; a single one shows its message). A high risk
  weighs like a high vulnerability: a banner, Bastion sounds the horn, never the
  malicious-package dialog. Same rules as findings: active repos only (this machine's own
  config always counts), one alert per repo even with several checkouts, not again for a
  warning seen there in the last 180 days. Baseline: a source's first scan never alerts, and
  after an upgrade adds rules, a new warning only alerts if its file is new or changed since
  the last scan (otherwise the rule is new, not the risk). A risk that goes away gets a quiet
  "✓ resolved". `selfguard dismiss --warning <id>` silences one you put there on purpose.
- **Reminders.** Once a day by default (`settings --remind daily|weekly|off`), between 09:00
  and 21:00, if serious issues are still open in active repos: malicious packages, critical
  vulnerabilities outside dev dependencies, and high ones in direct dependencies. Each repo is
  judged by the checkout that counts for it (see above). Open high risks (not dismissed) follow
  the vulnerabilities.

How they are delivered:

- **macOS banner** with the repository, the number of vulnerable packages, the worst severity and
  the versions to upgrade to. It also stays in Notification Center.
- **Critical dialog** for malicious packages. It stays on screen until dismissed (it closes
  itself after 30 minutes) and lists the remediation steps. Its "Open advisory" button can only
  open `osv.dev` pages built by selfguard.
- **Shell reminder** when you enter a project with known findings.

Notifications are delivered through `osascript`, so macOS shows them as coming from
**Script Editor**. See [troubleshooting](troubleshooting.md#i-dont-see-notifications) if they
don't appear.

## The dashboard

The engine is the CLI; the Mac app is the only visual part, and the two never meet over a
network. The app's window shows the dashboard page (`dist/ui/static`, served to its WKWebView
under `selfguard://dashboard/`). When the page needs data it calls the app, which writes the
request as one JSON line to a `selfguard bridge` child process and returns the answer. The
bridge runs the same code as the CLI (`api.ts`), starts with the first request and stops a
minute after the window closes. The menu bar reads `~/.selfguard/menubar.json` and needs no
process at all. Without the app (Linux, servers) everything is in the CLI.

## When things are re-checked

| Trigger | What happens |
|---|---|
| Entering a project for the first time | Registered and scanned in the background. |
| Lockfile changed (checked on every prompt by the hook) | Re-scanned in the background. |
| Lockfile of an active checkout changed, terminal or not (`git pull`, installs, merges) | The launchd watcher runs `selfguard check` within seconds (macOS). |
| Entering a project whose last scan is older than 24 hours | Re-scanned in the background. |
| Scheduled `sync` | Every tracked project is re-checked and new projects are discovered, on this machine and on [other machines](security-model.md#other-machines). |
| Every 15 minutes, when you added other machines | `selfguard machines check`: one SSH listing per machine. Changed lockfiles are fetched and re-scanned, and new projects are added. |
| `selfguard scan` | Immediately, in the foreground. |
