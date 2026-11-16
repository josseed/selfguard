import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { placeCheckouts, type Checkout } from "../src/canonical.ts";
import { defaultBranchOf, type RepoIdentity } from "../src/repoid.ts";
import type { Finding, RepoRecord } from "../src/store.ts";

process.env.SELFGUARD_HOME = mkdtempSync(join(tmpdir(), "sg-canonical-"));

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.parse("2026-11-16T12:00:00Z");
const ago = (days: number) => new Date(NOW - days * DAY).toISOString();

function rec(path: string, deps: string[] = [], findings: Finding[] = [], extra: Partial<RepoRecord> = {}): RepoRecord {
  return {
    schema: 1, path, lockfile: join(path, "package-lock.json"), lockType: "npm", lockHash: null, lockMtimeMs: null, lockSize: null,
    registeredAt: "", scannedAt: null, deps: deps.map((name) => ({ name, version: "1.0.0", direct: true, dev: false })), skipped: 0, findings, ...extra,
  };
}

function git(key: string, branch: string, opts: { worktree?: boolean; lastActivity?: string | null; defaultBranch?: string | null } = {}): RepoIdentity {
  return { key, label: key.split("/").slice(1).join("/"), branch, worktree: opts.worktree ?? false, lastActivity: opts.lastActivity ?? ago(1), defaultBranch: opts.defaultBranch === undefined ? "main" : opts.defaultBranch };
}

const place = (checkouts: Checkout[]) => placeCheckouts(checkouts, 14, new Map(), NOW);

test("the checkout on the default branch represents the repo, even a worktree", () => {
  const p = place([
    { rec: rec("/r/web"), repo: git("github.com/acme/web", "feat/x") },
    { rec: rec("/r/web-main"), repo: git("github.com/acme/web", "main", { worktree: true }) },
    { rec: rec("/r/web-fix"), repo: git("github.com/acme/web", "fix/y", { worktree: true }) },
  ]);
  assert.equal(p.get("/r/web-main")?.representative, true);
  assert.equal(p.get("/r/web-main")?.role, "default-branch");
  assert.equal(p.get("/r/web")?.representative, false);
  assert.equal(p.get("/r/web")?.role, "branch");
  assert.equal(new Set([...p.values()].map((x) => x.key)).size, 1);
});

test("an inactive default-branch clone still represents a repo whose worktrees are active", () => {
  const p = place([
    { rec: rec("/r/api"), repo: git("github.com/acme/api", "main", { lastActivity: ago(90) }) },
    { rec: rec("/r/api-wt"), repo: git("github.com/acme/api", "feat", { worktree: true, lastActivity: ago(0) }) },
  ]);
  assert.equal(p.get("/r/api")?.representative, true);
  assert.equal(p.get("/r/api")?.active, false);
  assert.equal(p.get("/r/api-wt")?.active, true);
});

test("default branch unknown: the active main clone, else the most recently active checkout", () => {
  const none = { defaultBranch: null };
  let p = place([
    { rec: rec("/r/a"), repo: git("local:/r/a/.git", "dev", { ...none, lastActivity: ago(3) }) },
    { rec: rec("/r/a-wt"), repo: git("local:/r/a/.git", "x", { ...none, worktree: true, lastActivity: ago(0) }) },
  ]);
  assert.equal(p.get("/r/a")?.representative, true);
  p = place([
    { rec: rec("/r/a"), repo: git("local:/r/a/.git", "dev", { ...none, lastActivity: ago(60) }) },
    { rec: rec("/r/a-wt1"), repo: git("local:/r/a/.git", "x", { ...none, worktree: true, lastActivity: ago(5) }) },
    { rec: rec("/r/a-wt2"), repo: git("local:/r/a/.git", "y", { ...none, worktree: true, lastActivity: ago(1) }) },
  ]);
  assert.equal(p.get("/r/a-wt2")?.representative, true);
});

function project(dir: string, name: string): string {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name }));
  return dir;
}

test("a folder without git with the same name and dependencies is a copy of the repo", () => {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "sg-copies-")));
  const deps = ["express", "zod", "pg", "lodash", "dayjs"];
  const original = project(join(base, "core"), "@acme/core");
  const snapshot = project(join(base, "plans", "run-1", "reference-source", "core"), "@acme/core");
  const drifted = project(join(base, "evidence", "old", "core"), "@acme/core");
  const other = project(join(base, "tools", "core"), "@acme/core");
  const unrelated = project(join(base, "playground"), "playground");
  const p = place([
    { rec: rec(original, deps), repo: git("gitlab.com/acme/core", "master", { defaultBranch: "master" }) },
    { rec: rec(snapshot, deps), repo: null },
    { rec: rec(drifted, [...deps.slice(0, 4), "uuid"]), repo: null },
    { rec: rec(other, ["react", "vite"]), repo: null },
    { rec: rec(unrelated, deps), repo: null },
  ]);
  assert.equal(p.get(snapshot)?.role, "copy");
  assert.equal(p.get(snapshot)?.key, "gitlab.com/acme/core");
  assert.equal(p.get(snapshot)?.label, "acme/core");
  assert.equal(p.get(snapshot)?.representative, false);
  assert.equal(p.get(drifted)?.role, "copy", "4 of 6 dependency names in common");
  assert.equal(p.get(other)?.role, "folder", "same name, different project");
  assert.equal(p.get(unrelated)?.role, "folder", "same dependencies, different name");
  assert.equal(p.get(unrelated)?.representative, true);
  assert.equal(p.get(original)?.representative, true);
});

test("copies of a project without git join the shallowest one", () => {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "sg-copies-")));
  const deps = ["next", "react", "zod"];
  const app = project(join(base, "next-app"), "next-app");
  const nested = project(join(base, "next-app", "evidence", "run-b", "runtime-next"), "next-app");
  const sibling = project(join(base, "form-http", "frontend"), "next-app");
  const p = place([
    { rec: rec(nested, deps), repo: null },
    { rec: rec(sibling, deps), repo: null },
    { rec: rec(app, deps), repo: null },
  ]);
  assert.equal(p.get(app)?.representative, true);
  assert.equal(p.get(nested)?.role, "copy");
  assert.equal(p.get(sibling)?.role, "copy");
  assert.equal(p.get(nested)?.key, `path:${app}`);
});

test("remote checkouts are never folded into local ones", () => {
  const p = place([
    { rec: rec("/r/core", ["a", "b"]), repo: git("gitlab.com/acme/core", "main") },
    { rec: rec("/home/me/core", ["a", "b"], [], { machine: "devbox" }), repo: null },
  ]);
  assert.equal(p.get("devbox:/home/me/core")?.role, "folder");
  assert.equal(p.get("devbox:/home/me/core")?.key, "devbox|path:/home/me/core");
});

test("default branch: origin/HEAD, else a local main or master (loose or packed)", () => {
  const dir = mkdtempSync(join(tmpdir(), "sg-defbranch-"));
  assert.equal(defaultBranchOf(dir), null);
  writeFileSync(join(dir, "packed-refs"), "# pack-refs with: peeled\n0123 refs/heads/master\n");
  assert.equal(defaultBranchOf(dir), "master");
  mkdirSync(join(dir, "refs", "heads"), { recursive: true });
  writeFileSync(join(dir, "refs", "heads", "main"), "0123\n");
  assert.equal(defaultBranchOf(dir), "main");
  mkdirSync(join(dir, "refs", "remotes", "origin"), { recursive: true });
  writeFileSync(join(dir, "refs", "remotes", "origin", "HEAD"), "ref: refs/remotes/origin/develop\n");
  assert.equal(defaultBranchOf(dir), "develop");
});
