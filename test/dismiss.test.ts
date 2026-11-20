import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, utimesSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { activityOf } from "../src/activity.ts";
import { liveDismissals, pruneDismissals } from "../src/dismiss.ts";
import type { Config } from "../src/config.ts";
import { copyFixture } from "./helpers.ts";

const HOUR = 3_600_000;
const iso = (ms: number): string => new Date(ms).toISOString();

test("a dismissed checkout is inactive until git activity after the dismissal", () => {
  const now = Date.now();
  const id = { key: "github.com/acme/web", label: "acme/web", branch: "main", worktree: false, lastActivity: iso(now - 2 * HOUR) };
  assert.deepEqual(activityOf(id, 30, now), { active: true, lastActivity: id.lastActivity, dismissed: false });
  assert.deepEqual(activityOf(id, 30, now, iso(now - HOUR)), { active: false, lastActivity: id.lastActivity, dismissed: true });
  // A commit after the dismissal brings it back.
  const later = { ...id, lastActivity: iso(now - HOUR / 2) };
  assert.deepEqual(activityOf(later, 30, now, iso(now - HOUR)), { active: true, lastActivity: later.lastActivity, dismissed: false });
  // Without git activity info there's nothing to bring it back: it stays dismissed.
  assert.equal(activityOf(null, 30, now, iso(now - HOUR)).dismissed, true);
});

test("activity in any checkout of the repo ends the dismissal; prune drops it", () => {
  const now = Date.now();
  const dismissed = [
    { key: "a", label: "a", at: iso(now - HOUR) },
    { key: "b", label: "b", at: iso(now - HOUR) },
    { key: "gone", label: "gone", at: iso(now - HOUR) },
  ];
  const checkouts = [
    { key: "a", lastActivity: iso(now - 2 * HOUR) },
    { key: "a", lastActivity: iso(now - HOUR / 2) }, // a worktree of "a" got a commit
    { key: "b", lastActivity: iso(now - 2 * HOUR) },
    { key: "b", lastActivity: null },
  ];
  assert.deepEqual([...liveDismissals(dismissed, checkouts).keys()], ["b", "gone"]);
  const cfg = { dismissed: [...dismissed] } as Config;
  assert.deepEqual(pruneDismissals(cfg, checkouts), ["a"]);
  assert.deepEqual(cfg.dismissed.map((d) => d.key), ["b", "gone"], "repos not tracked right now keep their dismissal");
});

// ---------- end to end through the API ----------

const read = (req: IncomingMessage) => new Promise<string>((r) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => r(b)); });
const osv = createServer(async (req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url === "/v1/querybatch") {
    const body = JSON.parse(await read(req));
    res.end(JSON.stringify({ results: body.queries.map((q: any) => (q.package.name === "lodash" && q.version === "4.17.20" ? { vulns: [{ id: "GHSA-lodash", modified: "2026-01-01T00:00:00Z" }] } : {})) }));
    return;
  }
  if (req.url === "/v1/vulns/GHSA-lodash") {
    res.end(JSON.stringify({ id: "GHSA-lodash", modified: "2026-01-01T00:00:00Z", summary: "Prototype pollution", database_specific: { severity: "CRITICAL" },
      affected: [{ package: { ecosystem: "npm", name: "lodash" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }] }));
    return;
  }
  res.statusCode = 404;
  res.end("{}");
});

let api: typeof import("../src/api.ts");
let home: string;

before(async () => {
  await new Promise<void>((r) => osv.listen(0, "127.0.0.1", r));
  process.env.SELFGUARD_OSV_API = `http://127.0.0.1:${(osv.address() as AddressInfo).port}/v1`;
  home = mkdtempSync(join(tmpdir(), "sg-dismiss-"));
  process.env.SELFGUARD_HOME = home;
  process.env.HOME = mkdtempSync(join(tmpdir(), "sg-dismiss-user-")); // agent configs: never the real home
  process.env.SELFGUARD_SYSTEM_ROOT = process.env.HOME; // host checks: never the real /Library
  process.env.SELFGUARD_NO_NOTIFY = "1";
  process.env.SELFGUARD_NO_LAUNCHD = "1";
  api = await import("../src/api.ts");
});
after(() => osv.close());

function gitRepo(dir: string, activity: Date): void {
  mkdirSync(join(dir, ".git", "logs"), { recursive: true });
  writeFileSync(join(dir, ".git", "HEAD"), "ref: refs/heads/main\n");
  writeFileSync(join(dir, ".git", "config"), '[remote "origin"]\n\turl = git@github.com:acme/web.git\n');
  writeFileSync(join(dir, ".git", "index"), "");
  writeFileSync(join(dir, ".git", "logs", "HEAD"), "");
  for (const f of ["HEAD", "index", join("logs", "HEAD")]) utimesSync(join(dir, ".git", f), activity, activity);
}

test("dismiss turns a repo off until its next git activity", async () => {
  const repo = join(realpathSync(mkdtempSync(join(tmpdir(), "sg-dismiss-code-"))), "web");
  copyFixture("v3", repo);
  gitRepo(repo, new Date(Date.now() - HOUR));
  await api.scanPath(repo);
  const key = "github.com/acme/web";
  assert.equal(api.getAttention().length, 1, "critical lodash on an active repo needs attention");

  assert.equal(api.resolveRepoKey(join(repo, "src")), key, "a path inside the checkout finds its repo");
  const d = api.dismissRepo(key);
  assert.equal(d.label, "acme/web");
  const g = api.getStatus().repos.find((x) => x.key === key)!;
  assert.equal(g.active, false);
  assert.equal(g.dismissedAt, d.dismissedAt);
  assert.equal(api.getStatus().projects[0]!.dismissed, true);
  assert.deepEqual(api.getAttention(), [], "no reminders for a dismissed repo");
  assert.deepEqual(api.listDismissed().map((x) => x.key), [key]);
  assert.deepEqual(api.watchTargets(), []);
  await api.check();
  assert.equal(JSON.parse(readFileSync(join(home, "config.json"), "utf8")).dismissed.length, 1, "no activity: still dismissed");

  // A commit (or checkout, pull...) brings it back by itself.
  const soon = new Date(Date.now() + 1000);
  utimesSync(join(repo, ".git", "index"), soon, soon);
  assert.equal(api.getStatus().repos.find((x) => x.key === key)!.dismissedAt, null);
  assert.equal(api.getStatus().repos.find((x) => x.key === key)!.active, true);
  assert.equal(api.getAttention().length, 1);
  assert.deepEqual(api.listDismissed(), []);
  await api.check();
  assert.deepEqual(JSON.parse(readFileSync(join(home, "config.json"), "utf8")).dismissed, [], "the stale dismissal is cleaned up");

  // Manual undo.
  api.dismissRepo(key);
  assert.equal(api.undismissRepo(key).removed, true);
  assert.equal(api.undismissRepo(key).removed, false);
  assert.throws(() => api.dismissRepo("nope"), /unknown repo/);
});
