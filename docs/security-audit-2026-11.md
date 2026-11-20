# Security audit, November 2026

An internal review of selfguard 0.18.2 (commit `d3a4c4c`), done before asking for an
independent audit. It was carried out by the maintainer with automated tooling and AI-assisted
code review. It is **not** a third-party audit. Every finding below was reproduced with a proof
of concept against temporary state before it was fixed, and every fix has a regression test that
fails without it.

Result: **no critical or high findings**, 6 medium, 15 low, and a few informational ones. All are
fixed in the release that follows 0.18.2. The [security model](security-model.md) was updated
where it no longer matched the code.

## Scope

- Lockfile, manifest, YAML, TOML and JSONC parsers, and the text cleaner.
- selfguard sharing: pairing, the share service, and the client on the other machine.
- The two remote readers: the POSIX `sh` reader installed over SSH, and `reader.ts`.
- The Mac app: the WKWebView dashboard and its bridge, how the app starts its engine, Sparkle.
- The MCP server and its tools.
- Secret handling and local state: agent configs, credentials, the state folder.
- The GitHub Actions and MCP-server scanners.

## Method

- **Fuzzing.** A new mutation fuzzer (`test/fuzz.test.ts`) mutates the real fixtures
  (lockfiles, workflows, agent configs, answers from other machines) and checks every parser and
  extractor for exceptions other than parse errors, hangs, stack overflows, prototype pollution
  and control characters in shown text. It runs on every `npm test`. For this audit it also ran
  with several seeds and 3,000 to 4,000 iterations per target, about 360,000 inputs in total.
- **Focused review** of each area above, by four reviewers working in parallel. Each looked for
  ways to break a claim of the security model and wrote a proof of concept for what it found.
- **A second review** of the combined fixes, which found five more issues (listed as F-17 to
  F-21 below) that were fixed before release.

Reproduce the fuzzing:

```sh
SELFGUARD_FUZZ_SEED=1 SELFGUARD_FUZZ_ITERATIONS=4000 node --test test/fuzz.test.ts
```

## Findings

| ID | Severity | Area | Finding | Fix |
|---|---|---|---|---|
| F-01 | Medium | Mac app | `open --env NODE_OPTIONS=--require… -a selfguard`, or the `SELFGUARD_APP_NODE`/`SELFGUARD_APP_CLI` overrides, made the app run another program with the privacy permissions macOS gave the app. Needs code already running as the user. | The engine gets a filtered environment (no `NODE_*`, `DYLD_*`, system `PATH`); overrides only in debug builds. |
| F-02 | Medium | Scanning | A cloned repo with `package.json` or a lockfile committed as a symlink to `/dev/zero` grew the scan to gigabytes; a FIFO hung it while holding the project lock. | Manifests and lockfiles must be regular files, opened without blocking, read up to a cap. |
| F-03 | Medium | MCP | `selfguard_forget` with `/` or `~` excluded every project, switching selfguard off. One call from a prompt-injected agent was enough. | Excluding `/`, the home folder, a watched folder or a folder above one is refused everywhere. Alert-reducing tools are marked destructive. Urgent warnings can't be dismissed over MCP. |
| F-04 | Medium | Agent configs | In `npx --_authToken npm_… -y pkg`, the token was taken for the package name, sent to OSV and stored, and the real package went unchecked. `--loglevel x evil-pkg` hid a package the same way. | Known npm, uv and pipx options are read correctly; an unknown one before the package skips the server with a warning. |
| F-05 | Medium | Sharing | A paired machine could make the share service read and hold gigabytes: one 49 KB `/read` request naming a 2 MB lockfile 500 times used about 2 GB. | Each file answered once, at most 64 MB of files per answer, answers streamed. Same limits in the SSH reader. |
| F-06 | Medium | CI scanner | `uses:` forms that GitHub runs were missed with no warning: flow style, a value on the next line, explicit keys. YAML escapes (`"tj-actions/…"`) gave a wrong action name. | Those forms are read; YAML escapes are decoded; what still can't be read gives a `workflow-not-parsed` warning. |
| F-07 | Low | Sharing | Any two tagged Tailscale devices counted as "the same user" (Tailscale reports them all as `tagged-devices`). A human still had to approve the pairing. | Tagged devices have no user; pairing with one needs `--allow-other-users`. |
| F-08 | Low | Readers | Symlinked `HEAD`, `commondir` or `config` inside a `.git` folder were followed, leaking a parent repo's remote URL or another file's first line outside a grant. Needs such symlinks to already exist on the shared machine. | Both readers refuse to read those files through a symlink. |
| F-09 | Low | SSH reader | A folder name containing a newline made the `sh` reader list lockfile names, sizes and dates outside its folder. | Names with control characters are skipped, and every listed folder is checked against the scope. |
| F-10 | Low | Sharing client | Replies from other machines (`/hello`, pairing) were read whole before the 256 KB limit was checked; a peer could stream gigabytes. | Read as a stream, stopped at the cap. |
| F-11 | Low | SSH machines | Removing a machine's key with `grep -v -F` also removed another Mac's line whose name contained it (`dev@mac` and `dev@mac-2`). | The marker is matched as a whole, at the end of the line. |
| F-12 | Low | Report | Links and images in advisory summaries or repo names survived into the "Copy markdown" report, which is meant to be pasted into issues or AI agents. | They are escaped. |
| F-13 | Low | CI scanner | `script-injection` missed `github.event['issue']['title']`, other letter cases, and `actions/github-script`'s `script:` input. | Expressions are normalised before matching; `script:` is scanned. |
| F-14 | Low | CI scanner | `pr-target-checkout` missed `merge_commit_sha` and a checkout of the PR's head repository. | Both are detected. |
| F-15 | Low | Local state | JSON lockfile parse errors quoted about 20 characters of the file in stored and printed messages, which could include a credential. | "invalid JSON at line N", never a quote. |
| F-16 | Low | Parsers | Found by the fuzzer: a `go.mod` with a no-break space hung the parser; long runs of spaces made the text cleaner quadratic; a `run:` line of repeated `${{` took 149 s for 2 MB in the CI checks. | All linear now, with regression tests. |
| F-17 | Low | SSH reader | Readers installed by an older selfguard kept the old behaviour, and nothing said so. | Readers report a revision; an older one shows "reader outdated" until reinstalled. |
| F-18 | Low | Mac app | Background agents run the app's engine with launchd's environment, so `launchctl setenv` could still choose another `ssh` or set `NODE_OPTIONS`. | From the app's bundle the engine ignores those variables, and agents get an empty `NODE_OPTIONS`. |
| F-19 | Low | MCP | `selfguard_forget` on a repo dropped its urgent warnings along with it, getting around the new dismissal rule. | Refused over MCP while the repo has an urgent warning. |
| F-20 | Low | Dashboard | The place picker could exclude a folder holding a watched one, bypassing the rule from F-03. | Same rule applied there. |
| F-21 | Low | Agent configs | After the F-04 fix, a server skipped because of an unknown option produced no warning, so a hidden package still came out clean. | New low `unparsed-mcp-server` warning. |

Informational, also fixed:

- Responses from OSV, npm and the GitHub Actions advisory list were size-capped only after the
  full download. The download now stops at the cap.
- The update check stored the registry's version untrimmed (`"\n9.9.9"` would break the shown
  `npm i -g … --ignore-scripts` command). Only an exact `x.y.z` is accepted.
- Cached advisories weren't checked against their id (on a case-insensitive disk, two ids could
  share a file).
- The whole-home search followed worktree pointers outside the home folder.
- The dashboard opened any https URL a script asked for. Only osv.dev advisories and
  selfguard's GitHub page open now.
- The security model said images load only from the page's origin; the CSP also allows `data:`.
  The document now matches.

## What was checked and holds

Among others: the share service listens only on Tailscale addresses and checks `Host` (no DNS
rebinding); pairing crypto (X25519, HKDF-SHA256, AES-256-GCM, a code derived from both keys);
credentials compared in constant time and bound to the Tailscale node; rate limits; the access
log can't be injected; the `sh` reader never evaluates requests and quotes every value; the
`authorized_keys` line can't be injected; ssh never prompts and keeps host key checks; the
dashboard has no server or port, a strict CSP, no `innerHTML` and a validated bridge;
notifications pass text to `osascript` as arguments; Sparkle requires a signed feed and
update; agent-config secrets never reach records, logs, output or OSV; state files are `0600`
in a `0700` folder, written atomically, loaded from an allowlist of keys.

## Remaining limits

- This was an internal review. An independent audit is still planned.
- Package names from private registries (including Go modules on company hosts) are sent to
  OSV like any other name; `GOPRIVATE` isn't consulted. Use an OSV mirror if that matters.
- The workflow scanner understands the YAML that GitHub workflows use, not all of YAML. What it
  can't read is reported (`workflow-not-parsed`), never passed silently. See
  [CI workflows and agent tools](ci-and-agent-tools.md#github-actions).
- The Mac app looks for `tailscale` in its usual install locations, including Homebrew's,
  which the user can write to. Code already running as the user could replace that binary.

To report a vulnerability, see [SECURITY.md](../SECURITY.md).
