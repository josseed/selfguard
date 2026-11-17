import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

process.env.SELFGUARD_HOME = mkdtempSync(join(tmpdir(), "sg-menubar-"));
process.env.SELFGUARD_NO_NOTIFY = "1";
process.env.SELFGUARD_NO_LAUNCHD = "1";
process.env.SELFGUARD_NO_UPDATE_CHECK = "1";

test("menu bar state: malicious, then serious findings, then a service down", async () => {
  const { menuBarState } = await import("../src/menubar.ts");
  const zero = { malicious: 0, critical: 0, high: 0, moderate: 0, low: 0, unknown: 0 };
  const up = { sync: true, watcher: true };
  assert.equal(menuBarState({ ...zero, malicious: 1 }, 0, { sync: false, watcher: false }), "malicious");
  assert.equal(menuBarState({ ...zero, high: 2 }, 1, { sync: false, watcher: true }), "attention");
  assert.equal(menuBarState({ ...zero, moderate: 3 }, 0, { sync: true, watcher: false }), "degraded");
  assert.equal(menuBarState({ ...zero, low: 3 }, 0, up), "clean");
  assert.equal(menuBarState(zero, 0, null), "clean", "unknown services (not macOS) aren't a problem");
});

test("GET /api/menubar returns the summary", async () => {
  const { handleLine } = await import("../src/bridge.ts");
  const r = await handleLine('{"id":1,"method":"GET","path":"/api/menubar"}');
  assert.equal(r.status, 200);
  const m = r.data as any;
  assert.equal(typeof m.version, "string");
  // Services come from this machine's launchd: off on a CI runner, maybe on here.
  const expected = m.services && (!m.services.sync || !m.services.watcher) ? "degraded" : "clean";
  assert.equal(m.state, expected);
  assert.deepEqual(m.repos, []);
  assert.equal(m.moreRepos, 0);
  assert.deepEqual(Object.keys(m.update).sort(), ["available", "latest"]);
  assert.deepEqual(m.events, []);
  const file = JSON.parse(readFileSync(join(process.env.SELFGUARD_HOME!, "menubar.json"), "utf8"));
  assert.equal(file.state, expected, "the endpoint also refreshes the file the app reads");
});

test("the summary lists the repos' news (not first scans) and the repos that need attention", async () => {
  const { appendEvents } = await import("../src/events.ts");
  const { writeMenuBar } = await import("../src/menubar.ts");
  const base = { repoKey: "github.com/acme/web", path: "/x", branch: "main", active: true, total: 1 };
  appendEvents([
    { ...base, at: "2026-11-16T10:00:00.000Z", kind: "new", repo: "acme/web", firstScan: true, packages: [{ name: "a", version: "1", severity: "high" }] },
    { ...base, at: "2026-11-16T11:00:00.000Z", kind: "new", repo: "acme/web", packages: [{ name: "b", version: "1", severity: "moderate" }, { name: "c", version: "1", severity: "critical" }] },
    { ...base, at: "2026-11-16T12:00:00.000Z", kind: "new", repo: "acme/old", active: false, packages: [{ name: "d", version: "1", severity: "high" }] },
    { ...base, at: "2026-11-16T13:00:00.000Z", kind: "resolved", repo: "acme/web", packages: [{ name: "b", version: "1", severity: "moderate" }] },
  ]);
  const m = writeMenuBar()!;
  assert.deepEqual(m.events.map((e) => [e.kind, e.repo, e.severity]), [["resolved", "acme/web", "moderate"], ["new", "acme/web", "critical"]]);
});
