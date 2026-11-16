# Supported ecosystems

selfguard checks JavaScript, Python, Rust and Go projects. Each one is read from the file that
records the exact versions in use, parsed as data by selfguard's own parsers. No package manager
or language toolchain is run, and none needs to be installed: Node.js is the only requirement.

| Language | Files read | OSV ecosystem | Checked |
|---|---|---|---|
| JavaScript | `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock` (+ `package.json`) | `npm` | Every installed registry package |
| Python | `uv.lock`; `poetry.lock` (+ `pyproject.toml`) | `PyPI` | Every locked package from a package index |
| Rust | `Cargo.lock` | `crates.io` | Every locked crate from crates.io |
| Go | `go.mod` | `Go` | Every module requirement, after `replace` directives |

## What each format provides

### Python: uv

- **Packages:** every `[[package]]` whose `source` is a `registry`. Git, URL, path and directory
  sources are counted as skipped. Workspace members (`editable` or `virtual` sources) are your
  own code and aren't listed.
- **Direct:** the dependencies, extras and dependency groups of the workspace members.
- **Dev:** packages reachable only through dependency groups (`[package.dev-dependencies]`), not
  through regular dependencies or extras. Every extra counts as runtime.

### Python: Poetry

- **Packages:** every `[[package]]`, except those whose `[package.source]` is `git`,
  `directory`, `file` or `url` (skipped). Private indexes (`legacy`) are checked against PyPI.
- **Direct:** names declared in `pyproject.toml`: `[tool.poetry.dependencies]`, its groups and
  `dev-dependencies`, `[project] dependencies` and `optional-dependencies`, and
  `[dependency-groups]`.
- **Dev:** from the lockfile when it says so (`groups` in Poetry 2, `category` before 1.5);
  otherwise packages not reachable from the runtime dependencies of `pyproject.toml`. Without a
  readable `pyproject.toml`, nothing is marked direct or dev.

### Rust: Cargo

- **Packages:** crates from crates.io (`registry+https://github.com/rust-lang/crates.io-index`
  or `sparse+https://index.crates.io/`). Git crates and crates from other registries are
  skipped. Workspace members (no `source`) are your own code.
- **Direct:** dependencies of any workspace member.
- **Dev:** not recorded in `Cargo.lock`, so every crate counts as runtime.

### Go modules

- **Packages:** every `require`, with `replace` applied (a version-specific replacement wins
  over a module-wide one). A module replaced by a local folder is skipped. Versions are stored
  without the leading `v`, like OSV (`v1.2.3` → `1.2.3`); pseudo-versions and `+incompatible`
  are supported.
- **Direct:** requirements without `// indirect`.
- **Dev:** Go has no dev dependencies; every module counts as runtime.
- `go.sum` is not read: it is a checksum history, not the list of versions in use.

## Matching and fixes

- Queries carry the ecosystem, so the same name and version in two ecosystems (an npm package
  and a crate both called `smallvec`) are separate queries and findings.
- PyPI names are compared PEP 503-normalized (`PyYAML` = `pyyaml`, `zope.interface` =
  `zope-interface`), and versions with PEP 440 ordering (`1.0rc1` < `1.0` < `1.0.post1`).
  npm, crates.io and Go versions use SemVer 2.0.
- `upgradeTo` is the smallest version that fixes every advisory with a published fix. For Go,
  add the `v` back when upgrading: `go get <module>@v<version>`.
- Markdown reports name the right manifest and refresh command per project: `uv lock
  --upgrade-package`, `poetry update --lock`, `cargo update -p … --precise …`, `go get … && go
  mod tidy`. Python resolvers may build source distributions of packages without wheels, which
  runs their build code; the report says so.

## Discovery, hook and other machines

- **Discovery** recognizes the new lockfiles and skips Python environments (`venv`,
  `site-packages`, `__pypackages__`), Cargo's `target`, Go's module cache (`…/pkg/mod`, wherever
  `GOPATH` is) and `testdata` folders.
- **The shell hook** reacts to `pyproject.toml`, `Cargo.toml` and the new lockfiles while walking
  up, so a crate inside a Cargo workspace resolves to the workspace's `Cargo.lock`. Above a
  `package.json`, `Cargo.toml` or `pyproject.toml`, only a folder with a lockfile of the same
  ecosystem counts: a JavaScript folder inside a Go module isn't that module. A folder found that
  way is the same project as when entered directly. In a Python or Rust folder without a
  lockfile, the hook watches the folder and registers the project once `uv lock`, `poetry lock`
  or `cargo generate-lockfile` creates one.
- **Severity:** RustSec and PYSEC advisories often have no severity label; selfguard uses their
  CVSS v3 vector or the GHSA copy of the same advisory. RustSec informational notices aren't
  findings.
- **Watchers and `check`** re-scan when the lockfile (or `go.mod`) changes.
- **Other machines** list and fetch the new lockfiles, and `pyproject.toml` for Poetry projects.
  SSH readers installed by an earlier selfguard keep working with JavaScript only; reinstall
  them with `selfguard machines install <name>`. With sharing, update selfguard on that machine.
- **Output:** findings, packages and `where` results carry `ecosystem`. Records stored by earlier
  versions have none, which means npm; they need no migration.

## Limitations

- **One lockfile per folder.** When a folder holds lockfiles of several ecosystems, the first
  of JavaScript, uv, Poetry, Cargo and Go is checked. Lockfiles in separate folders of the same
  repo are separate projects and are all checked.
- **Projects without a lockfile** are registered only for JavaScript (`package.json` in a git
  repo). `requirements.txt`, Pipenv (`Pipfile.lock`) and PDM (`pdm.lock`) aren't read yet.
- **Go:** modules declaring `go 1.16` or older may not list every indirect dependency in
  `go.mod`. The Go standard library isn't checked: `go.mod` doesn't say which toolchain builds
  the project.
- **Platform markers** (`sys_platform == 'win32'`, Cargo target-specific crates) aren't
  evaluated: every locked package is checked, whatever platform it is for.
- **Dev classification** is conservative: when the data doesn't say, a package counts as
  runtime, so its findings are never hidden as dev-only.
