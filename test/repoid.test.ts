import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { activityOf } from "../src/activity.ts";
import { normalizeRemote, remoteFromConfig, repoIdentity } from "../src/repoid.ts";

test("normalizes remotes so ssh/https/scp forms match", () => {
  const want = "github.com/acme/web";
  for (const u of ["git@github.com:acme/web.git", "https://github.com/acme/web", "ssh://git@GitHub.com/acme/web.git", "https://user@github.com/acme/web.git/"]) {
    assert.equal(normalizeRemote(u), want, u);
  }
  assert.equal(normalizeRemote("git@gitlab.com:group/sub/admin.git"), "gitlab.com/group/sub/admin");
});

test("reads origin from git config, else the first remote", () => {
  assert.equal(remoteFromConfig('[core]\n\tbare = false\n[remote "upstream"]\n\turl = git@x:a/b.git\n[remote "origin"]\n\turl = git@x:me/b.git\n'), "git@x:me/b.git");
  assert.equal(remoteFromConfig('[remote "upstream"]\n\turl = git@x:a/b.git\n'), "git@x:a/b.git");
});

test("main clone, linked worktree and a second clone share one key; subfolders don't", () => {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "sg-repo-")));
  // main clone with a frontend subproject
  const main = join(base, "web");
  mkdirSync(join(main, ".git", "worktrees", "web-feat"), { recursive: true });
  mkdirSync(join(main, "frontend"), { recursive: true });
  writeFileSync(join(main, ".git", "config"), '[remote "origin"]\n\turl = git@github.com:acme/web.git\n');
  writeFileSync(join(main, ".git", "HEAD"), "ref: refs/heads/main\n");
  // linked worktree
  const wt = join(base, "web-feat");
  mkdirSync(join(wt, "frontend"), { recursive: true });
  writeFileSync(join(wt, ".git"), `gitdir: ${join(main, ".git", "worktrees", "web-feat")}\n`);
  writeFileSync(join(main, ".git", "worktrees", "web-feat", "commondir"), "../..\n");
  writeFileSync(join(main, ".git", "worktrees", "web-feat", "HEAD"), "ref: refs/heads/feat/x\n");
  // separate clone over https
  const clone = join(base, "web-copy");
  mkdirSync(join(clone, ".git"), { recursive: true });
  writeFileSync(join(clone, ".git", "config"), '[remote "origin"]\n\turl = https://github.com/acme/web\n');
  writeFileSync(join(clone, ".git", "HEAD"), "0123456789abcdef0123456789abcdef01234567\n");

  const a = repoIdentity(main)!;
  const b = repoIdentity(wt)!;
  const c = repoIdentity(clone)!;
  assert.equal(a.key, "github.com/acme/web");
  assert.equal(b.key, a.key);
  assert.equal(c.key, a.key);
  assert.deepEqual([a.branch, b.branch, c.branch], ["main", "feat/x", "01234567"]);
  assert.deepEqual([a.worktree, b.worktree], [false, true]);
  assert.equal(a.label, "acme/web");

  const fa = repoIdentity(join(main, "frontend"))!;
  const fb = repoIdentity(join(wt, "frontend"))!;
  assert.equal(fa.key, "github.com/acme/web#frontend");
  assert.equal(fb.key, fa.key, "same subfolder groups across worktrees");
  assert.notEqual(fa.key, a.key, "subprojects stay separate from the repo root");
  assert.equal(fa.label, "acme/web/frontend");
});

test("not a git repo: no identity", () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "sg-nogit-")));
  assert.equal(repoIdentity(dir), null);
});

test("a worktree whose main repo was deleted is reported as orphaned, not grouped", () => {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "sg-orphan-")));
  const wt = join(base, "leftover");
  mkdirSync(wt, { recursive: true });
  writeFileSync(join(wt, ".git"), `gitdir: ${join(base, "gone.git", "worktrees", "leftover")}\n`);
  const id = repoIdentity(wt)!;
  assert.equal(id.orphaned, true);
  assert.equal(id.label, "leftover (orphaned worktree)");
  assert.equal(id.key, `orphan:${wt}`);
});

test("activity comes from the checkout's own git files; old checkouts are inactive", () => {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "sg-activity-")));
  const repo = join(base, "web");
  mkdirSync(join(repo, ".git", "logs"), { recursive: true });
  writeFileSync(join(repo, ".git", "HEAD"), "ref: refs/heads/main\n");
  writeFileSync(join(repo, ".git", "index"), "");
  writeFileSync(join(repo, ".git", "logs", "HEAD"), "");
  const old = new Date(Date.now() - 90 * 86_400_000);
  for (const f of ["HEAD", "index", join("logs", "HEAD")]) utimesSync(join(repo, ".git", f), old, old);

  const id = repoIdentity(repo)!;
  assert.ok(Math.abs(Date.parse(id.lastActivity!) - old.getTime()) < 2000);
  assert.equal(activityOf(id, 30).active, false);
  assert.equal(activityOf(id, 120).active, true);

  utimesSync(join(repo, ".git", "index"), new Date(), new Date()); // e.g. git status, commit
  assert.equal(activityOf(repoIdentity(repo), 30).active, true);
  assert.equal(activityOf(null, 30).active, true, "non-git projects always count");
  assert.equal(activityOf({ ...id, orphaned: true }, 30).active, false);
});
