import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, beforeEach, test } from "node:test";

const home = mkdtempSync(join(tmpdir(), "sg-appalerts-"));
process.env.SELFGUARD_HOME = home;
delete process.env.SELFGUARD_NO_NOTIFY;
const { appAlert, appHandlesAlerts, queueForApp } = await import("../src/appalerts.ts");
const { buildAlert, buildResolvedAlert } = await import("../src/alerts.ts");
after(() => rmSync(home, { recursive: true, force: true }));
beforeEach(() => rmSync(join(home, "app.json"), { force: true }));

const beat = (over: Record<string, unknown> = {}) =>
  writeFileSync(join(home, "app.json"), JSON.stringify({ pid: process.pid, at: new Date().toISOString(), alerts: true, ...over }));
const vuln = (severity: string, id = "GHSA-1") => ({ id, name: "lodash", version: "4.17.20", severity, direct: true, dev: false }) as never;

test("the app handles alerts only with a fresh heartbeat, a live process and alerts on", () => {
  assert.equal(appHandlesAlerts(Date.now(), "darwin"), false, "no heartbeat");
  beat();
  assert.equal(appHandlesAlerts(Date.now(), "darwin"), true);
  assert.equal(appHandlesAlerts(Date.now(), "linux"), false, "not macOS");
  assert.equal(appHandlesAlerts(Date.now() + 120_000, "darwin"), false, "stale: the app stopped beating");
  beat({ alerts: false });
  assert.equal(appHandlesAlerts(Date.now(), "darwin"), false, "Bastion Alerts off");
  beat({ pid: 2 ** 22 + 12345 });
  assert.equal(appHandlesAlerts(Date.now(), "darwin"), false, "the app's process is gone");
});

test("alerts carry the mascot scene and the repo to open", () => {
  const repo = { key: "github.com/acme/web", label: "acme/web" };
  const high = buildAlert([{ path: "/c/web", newFindings: [vuln("high")], repo }]);
  assert.deepEqual(appAlert(high as never, new Date(0)), {
    at: "1970-01-01T00:00:00.000Z", scene: "high", title: "acme/web", subtitle: "1 vulnerable package · worst: HIGH", body: "lodash (no fix yet)", repoKey: repo.key,
  });
  assert.equal((buildAlert([{ path: "/c/web", newFindings: [vuln("critical")], repo }]) as { scene: string }).scene, "crit");
  const mal = appAlert(buildAlert([{ path: "/c/web", newFindings: [vuln("malicious", "MAL-2026-1")], repo }]) as never) as Record<string, unknown>;
  assert.equal(mal.scene, "mal");
  assert.equal(mal.url, "https://osv.dev/vulnerability/MAL-2026-1");
  assert.match(String(mal.details), /Rotate credentials/);
  const fixed = buildResolvedAlert([{ path: "/c/web", newFindings: [], resolvedFindings: [vuln("high")], findings: [], repo }]);
  assert.equal((fixed as { scene: string }).scene, "fixed");
});

test("queued alerts are one file each, in order, and only while the app handles them", { skip: process.platform !== "darwin" }, () => {
  const alert = buildAlert([{ path: "/c/web", newFindings: [vuln("high")] }]);
  assert.equal(queueForApp(alert), false, "no app: osascript");
  beat();
  assert.equal(queueForApp(alert), true);
  assert.equal(queueForApp(buildResolvedAlert([{ path: "/c/web", newFindings: [], resolvedFindings: [vuln("high")], findings: [] }])), true);
  const files = readdirSync(join(home, "app-alerts")).sort();
  assert.equal(files.length, 2);
  assert.deepEqual(files.map((f) => JSON.parse(readFileSync(join(home, "app-alerts", f), "utf8")).scene), ["high", "fixed"]);
});
