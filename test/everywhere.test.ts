import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { before, test } from "node:test";
import { discoverEverywhere, gitignoredNames, groupPlaces } from "../src/everywhere.ts";

const home = realpathSync(mkdtempSync(join(tmpdir(), "sg-home-everywhere-")));
const H = (...p: string[]): string => join(home, ...p);

function project(dir: string, opts: { git?: boolean; lock?: string } = {}): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "package.json"), "{}");
  writeFileSync(join(dir, opts.lock ?? "package-lock.json"), "{}");
  if (opts.git) {
    mkdirSync(join(dir, ".git"), { recursive: true });
    writeFileSync(join(dir, ".git", "HEAD"), "ref: refs/heads/main\n"); // fresh mtime: active
  }
}

before(() => {
  project(H("repository", "acme", "api"), { git: true });
  writeFileSync(H("repository", "acme", "api", ".gitignore"), "generated/\n/scratch\n*.log\n!keep\n");
  project(H("repository", "acme", "api", "examples", "demo"));
  project(H("repository", "acme", "api", "dist", "bundle"));
  project(H("repository", "acme", "api", "generated", "client"));
  project(H("repository", "acme", "api", "scratch", "x"));
  project(H("repository", "acme", "api", "packages", "scratch"), { lock: "pnpm-lock.yaml" }); // "/scratch" only at the repo root
  project(H("Desktop", "cliente", "web"), { git: true, lock: "pnpm-lock.yaml" });
  project(H("Downloads", "curso-react"));
  project(H("work", "evidence", "copy-of-api"));
  project(H("node_modules", "pkg"));
  project(H("Library", "Caches", "x"));
  project(H(".cache", "tool", "x"));
  project(H("go", "pkg", "mod", "x"));
  // A worktree of acme/api kept in a hidden tool folder, registered in the repo's .git.
  project(H(".t3", "worktrees", "api", "feat"));
  mkdirSync(H("repository", "acme", "api", ".git", "worktrees", "feat"), { recursive: true });
  writeFileSync(H("repository", "acme", "api", ".git", "worktrees", "feat", "gitdir"), `${H(".t3", "worktrees", "api", "feat", ".git")}\n`);
  writeFileSync(H(".t3", "worktrees", "api", "feat", ".git"), `gitdir: ${H("repository", "acme", "api", ".git", "worktrees", "feat")}\n`);
  writeFileSync(H("repository", "acme", "api", ".git", "worktrees", "feat", "HEAD"), "ref: refs/heads/feat\n");
  // A zone with many folders and no project, and a symlink loop.
  for (let i = 0; i < 60; i++) mkdirSync(H("bigzone", `d${i}`, "x"), { recursive: true });
  symlinkSync(home, H("loop"));
});

const rel = (p: string): string => p.slice(home.length + 1);

test(".gitignore: plain folder names only, rooted ones only at the repo root", () => {
  const r = gitignoredNames("# c\ndist\n/build/\n*.log\nsrc/gen\n!dist\ncache/\n");
  assert.deepEqual([...r.anywhere].sort(), ["cache"]);
  assert.deepEqual([...r.atRoot], ["build"]);
});

test("finds projects anywhere in the home, skipping what can't be yours", async () => {
  const r = await discoverEverywhere({ home, emptyZoneBudget: 30 });
  const found = r.projects.map((p) => rel(p.root)).sort();
  assert.deepEqual(found, [
    ".t3/worktrees/api/feat",
    "Desktop/cliente/web",
    "Downloads/curso-react",
    "repository/acme/api",
    "repository/acme/api/examples/demo",
    "repository/acme/api/packages/scratch",
    "work/evidence/copy-of-api",
  ]);
  const by = new Map(r.projects.map((p) => [rel(p.root), p]));
  assert.equal(by.get("repository/acme/api/examples/demo")!.secondary, true, "samples inside a repo");
  assert.equal(by.get("work/evidence/copy-of-api")!.secondary, true, "copies/dumps anywhere");
  assert.equal(by.get("Downloads/curso-react")!.gitRoot, null);
  assert.equal(by.get(".t3/worktrees/api/feat")!.worktreeRoot, H(".t3", "worktrees", "api", "feat"));
  assert.deepEqual(r.heavy, [H("bigzone")]);
});

test("protected folders can be skipped (background runs on macOS)", async () => {
  const r = await discoverEverywhere({ home, skipProtected: true });
  assert.ok(!r.projects.some((p) => p.root.startsWith(H("Desktop"))));
  assert.deepEqual(r.skipped.sort(), [H("Desktop"), H("Documents"), H("Downloads")].filter((p) => p !== H("Documents")));
});

test("places: a few folders to approve, active ones recommended", async () => {
  const r = await discoverEverywhere({ home });
  const places = groupPlaces(r.projects, home, [], 30);
  const by = new Map(places.map((p) => [rel(p.path), p]));
  assert.deepEqual([...by.keys()].sort(), [".t3/worktrees", "Desktop", "Downloads", "repository", "work"]);
  assert.equal(by.get("repository")!.recommended, true);
  assert.equal(by.get("repository")!.depth, 4, "covers acme/api/packages/scratch; samples don't count");
  assert.equal(by.get(".t3/worktrees")!.recommended, true);
  assert.equal(by.get("Desktop")!.recommended, true);
  assert.equal(by.get("Downloads")!.recommended, false, "no git: not recommended");
  assert.equal(by.get("work")!.recommended, false, "only copies");
  // Already watched (deep enough) → not recommended again; a hidden folder below a root isn't covered.
  const watched = groupPlaces(r.projects, home, [{ path: H("repository"), depth: 5 }, { path: home, depth: 6 }], 30);
  const w = new Map(watched.map((p) => [rel(p.path), p]));
  assert.equal(w.get("repository")!.watched, true);
  assert.equal(w.get(".t3/worktrees")!.watched, false);
  // A dismissed repo doesn't make its folder worth watching.
  const { repoIdentity } = await import("../src/repoid.ts");
  const key = repoIdentity(H("Desktop", "cliente", "web"))!.key;
  const d = groupPlaces(r.projects, home, [], 30, Date.now(), new Map([[key, new Date(Date.now() + 60_000).toISOString()]]));
  assert.equal(d.find((p) => rel(p.path) === "Desktop")!.recommended, false);
});

test("automatic weekly pass: adds new active places once, respects removals", async () => {
  process.env.HOME = home;
  process.env.SELFGUARD_HOME = mkdtempSync(join(tmpdir(), "sg-state-everywhere-"));
  process.env.SELFGUARD_NO_NOTIFY = "1";
  process.env.SELFGUARD_NO_LAUNCHD = "1";
  process.env.SELFGUARD_OSV_API = "http://127.0.0.1:9/v1"; // offline: scans record the error
  const api = await import("../src/api.ts");
  const first = await api.autoDiscover();
  assert.equal(first.ran, true);
  // On macOS the background pass doesn't enter Desktop/Documents/Downloads until a watched
  // folder lives there (no privacy prompts from a background process).
  const expected = process.platform === "darwin" ? [".t3/worktrees", "repository"] : [".t3/worktrees", "Desktop", "repository"];
  assert.deepEqual(first.added.map((a) => rel(a.path)).sort(), expected);
  assert.ok(api.getStatus().projects.length >= 3);
  const events = readFileSync(join(process.env.SELFGUARD_HOME, "events.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.deepEqual(events.filter((e) => e.kind === "watching").map((e) => rel(e.path)).sort(), expected);

  assert.equal((await api.autoDiscover()).ran, false, "at most once a week");
  assert.deepEqual((await api.autoDiscover({ force: true })).added, [], "already watched");
  api.removeRoot(H(".t3", "worktrees"));
  assert.ok(!api.listRoots().roots.some((r) => r.path === H(".t3", "worktrees")));
  assert.deepEqual((await api.autoDiscover({ force: true })).added, [], "removed by the user: not added back");
  api.updateSettings({ autoDiscover: false });
  assert.equal((await api.autoDiscover()).reason, "automatic discovery is off");
});
