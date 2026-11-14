# Security model

selfguard runs on developer machines and reads untrusted input every time you open a project, so
it holds itself to a stricter standard than a typical CLI. This page explains what it trusts,
what it sends, and how it is built and released. To report a vulnerability, see
[SECURITY.md](../SECURITY.md).

## Threats considered

| Threat | Mitigation |
|---|---|
| A hostile repository runs code when you `cd` into it or scan it | Lockfiles and `package.json` are parsed as data by selfguard's own parsers. No package manager, `npm ls`, lifecycle script, `.npmrc` or project config is ever executed or loaded. |
| A crafted lockfile crashes or abuses the parser | Lockfiles over 100 MB are refused. The YAML reader supports only the subset lockfiles use: no anchors, aliases or tags, so no "billion laughs". Nesting depth is bounded and objects have no prototype, so keys like `__proto__` are plain data. |
| Package names or advisory text inject terminal escape sequences | Everything printed is stripped of C0/C1 control characters and bidirectional overrides ("Trojan Source"), and truncated. |
| Notification text injects AppleScript | Text is passed to `osascript` as arguments to an `on run` handler, never interpolated into script source. The dialog's button only opens `https://osv.dev/vulnerability/<id>` URLs built by selfguard. |
| Prompt injection through the MCP server | Tool descriptions and the agent guide label advisory text and package names as third-party data. No MCP tool can run commands, install packages or edit files. |
| selfguard's own dependencies get compromised | Zero runtime dependencies, enforced in CI. Dev tooling updates go through Dependabot with a 7-day cooldown and review. |
| A compromised CI or stolen token publishes a malicious selfguard | See [Releases](#releases). |

## What leaves your machine

Only calls to the OSV.dev API at `https://api.osv.dev/v1`:

- `POST /querybatch` with `{ "package": { "ecosystem": "npm", "name": … }, "version": … }` for
  each unique dependency;
- `GET /vulns/{id}` for advisory details not already cached.

Requests carry the `User-Agent: selfguard/<version>` header. No file paths, project or repo
names, git remotes, source code or identifiers are sent. Redirects are refused, responses are
size-capped, and requests time out.

OSV can infer which open-source packages and versions you use, but not who you are or what you
build. If even that is too much, point `SELFGUARD_OSV_API` at a mirror you control.

## Local state

`~/.selfguard` (or `SELFGUARD_HOME`) holds the list of your projects, their dependencies and
findings. It is created with mode `0700` and its files with `0600`. Writes are atomic (temporary
file plus rename), and concurrent scans are serialized with lock files.

To identify repositories, selfguard reads `.git/HEAD`, `.git/config`, `.git/commondir` and the
worktree pointer file, each capped at 64 KB. It never runs `git`.

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

Verify an installed copy:

```sh
npm audit signatures
npm view selfguard@<version> dist.attestations
```

## Known limitations

- Advisory data is only as complete and timely as OSV.dev. A malicious package that hasn't been
  reported yet won't be flagged.
- Git, file, link and tarball dependencies are skipped. They aren't in registry advisory
  databases.
- Matching is by package name. A package from a private registry that shares its name with a
  public package is checked against the public package's advisories.
- macOS notifications appear as "Script Editor" because they are delivered through `osascript`.
