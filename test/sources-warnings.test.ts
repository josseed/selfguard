// Source warnings end to end: scan outcomes, events, menu bar, dismissals and the reminder.
// Synthetic rules ("test-rule"…) through fake extractors: the real rules don't matter here.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { FAKE_AGENTS, FAKE_CI, osv, startOsv } from "./sources-helpers.ts";

let server: Server;
let sources: typeof import("../src/sources.ts");
let news: typeof import("../src/sources/news.ts");
let api: typeof import("../src/api.ts");
let announce: typeof import("../src/announce.ts");
let menubar: typeof import("../src/menubar.ts");
let events: typeof import("../src/events.ts");
let alerts: typeof import("../src/riskalerts.ts");

before(async () => {
  server = await startOsv();
  process.env.SELFGUARD_HOME = mkdtempSync(join(tmpdir(), "sg-home-"));
  process.env.HOME = mkdtempSync(join(tmpdir(), "sg-user-"));
  process.env.SELFGUARD_NO_NOTIFY = "1";
  sources = await import("../src/sources.ts");
  news = await import("../src/sources/news.ts");
  api = await import("../src/api.ts");
  announce = await import("../src/announce.ts");
  menubar = await import("../src/menubar.ts");
  events = await import("../src/events.ts");
  alerts = await import("../src/riskalerts.ts");
  sources.resetSourceExtractors();
  sources.registerSourceExtractor(FAKE_CI);
  sources.registerSourceExtractor(FAKE_AGENTS);
});
after(() => server.close());

const W = (o: Record<string, unknown>) => ({ rule: "test-rule", message: "Something risky", line: 2, severity: "low", ...o });
const write = (root: string, warnings: unknown[]) => writeFileSync(join(root, "fake-ci.json"), JSON.stringify({ refs: [], warnings, skipped: 0 }));

function repo(warnings: unknown[]): string {
  const root = mkdtempSync(join(tmpdir(), "sg-warn-"));
  mkdirSync(join(root, ".git"));
  write(root, warnings);
  return root;
}

async function scan(root: string) {
  const [o] = await sources.scanSources([{ kind: "ci", target: sources.repoTarget(root) }]);
  sources.saveSource(o!.record);
  return o!;
}

test("scan outcomes: first scan is a baseline, then new and resolved warnings; key and notify are kept", async () => {
  const root = repo([W({ severity: "moderate" })]);
  const first = await scan(root);
  assert.ok(first.firstScan);
  assert.deepEqual([first.newWarnings, first.resolvedWarnings], [[], []]);
  assert.ok(first.record.warningsBy);

  write(root, [
    W({ severity: "moderate", line: 9 }),
    W({ rule: "test-hook", key: "SessionStart\u001b[2J", message: "Hook fetches and runs a script", severity: "high" }),
    W({ rule: "test-flag", message: "New autorun task", notify: true }),
  ]);
  const second = await scan(root);
  assert.deepEqual(second.newWarnings.map((w) => [w.rule, w.key ?? null, w.notify ?? false]), [["test-hook", "SessionStart[2J", false], ["test-flag", null, true]]);
  assert.deepEqual(second.resolvedWarnings, []);

  write(root, [W({ severity: "moderate" })]);
  const third = await scan(root);
  assert.deepEqual(third.newWarnings, []);
  assert.deepEqual(third.resolvedWarnings.map((w) => w.rule).sort(), ["test-flag", "test-hook"]);
});

test("warnings are news even when OSV can't be reached", async () => {
  const root = repo([]);
  await scan(root);
  // With a reference to look up, so that the OSV error path is taken.
  writeFileSync(join(root, "fake-ci.json"), JSON.stringify({ refs: [{ ecosystem: "npm", name: "lodash", version: "4.17.20", versionKind: "exact", line: 1 }], warnings: [W({ severity: "high" })], skipped: 0 }));
  osv.fail = true;
  try {
    const [o] = await sources.scanSources([{ kind: "ci", target: sources.repoTarget(root) }]);
    assert.ok(o!.record.error);
    assert.equal(o!.newWarnings.length, 1);
  } finally {
    osv.fail = false;
  }
});

test("announce logs risk events, the menu bar counts them; dismissing one silences it", async () => {
  const root = repo([]);
  await scan(root);
  write(root, [W({ rule: "test-hook", key: "PreToolUse", message: "Hook runs curl | sh", severity: "high" }), W({ rule: "test-low" })]);
  const o = await scan(root);
  await announce.announce([], { notify: false, sources: [o] });
  const risk = events.readEvents(10).find((e) => e.kind === "risk" && e.path === root);
  assert.ok(risk, "a risk event");
  assert.equal(risk!.total, 1, "only warnings that alert are logged");
  assert.deepEqual(risk!.risks, [{ rule: "test-hook", message: "Hook runs curl | sh", severity: "high" }]);
  const m = menubar.getMenuBar();
  assert.ok(m.risks.high >= 1);
  assert.equal(m.state, "attention");
  assert.ok(m.events.some((e) => e.kind === "risk" && e.severity === "high"));

  const report = api.getSources({ path: root }).repos[0]!;
  const hook = report.warnings.find((w) => w.rule === "test-hook")!;
  assert.equal(hook.alerts, true);
  assert.equal(hook.dismissed, false);
  assert.equal(report.warnings.find((w) => w.rule === "test-low")!.alerts, false);

  const before = api.riskCounts().high;
  const d = api.dismissWarning(hook.id);
  assert.equal(d.key, hook.warningKey);
  assert.equal(api.getSources({ path: root }).repos[0]!.warnings.find((w) => w.rule === "test-hook")!.dismissed, true, "still listed, marked");
  assert.equal(api.riskCounts().high, before - 1);
  assert.deepEqual(api.listDismissedWarnings().map((x) => x.id), [hook.id]);
  // A dismissed warning is no news, and its going away isn't either.
  const dismissed = new Set([hook.warningKey]);
  assert.deepEqual(news.riskNews([o], 30, new Map(), dismissed)[0]!.newWarnings.map((w) => w.rule), ["test-low"]);
  assert.throws(() => api.dismissWarning("nope"), /unknown warning/);
  // Show in Finder only takes the id of a known warning, never a path.
  assert.throws(() => api.revealWarning("nope"), process.platform === "darwin" ? /unknown warning/ : /macOS-only/);
  assert.throws(() => api.revealWarning("/etc/passwd"), process.platform === "darwin" ? /unknown warning/ : /macOS-only/);

  assert.deepEqual(api.undismissWarning(hook.id), { key: hook.warningKey, removed: true });
  assert.equal(api.undismissWarning(hook.id).removed, false);
  assert.equal(api.riskCounts().high, before);
});

test("the same new risk in another checkout of the repo is news once", async () => {
  const clone = (): string => {
    const root = repo([]);
    writeFileSync(join(root, ".git", "config"), '[remote "origin"]\n\turl = https://github.com/acme/api.git\n');
    return root;
  };
  const [a, b, c] = [clone(), clone(), clone()];
  for (const r of [a, b, c]) await scan(r);
  const risky = [W({ rule: "test-hook", key: "Stop", severity: "high" })];
  write(a, risky);
  const oa = await scan(a);
  assert.equal(news.riskNews([oa], 30, new Map())[0]!.newWarnings.length, 1);
  // Pulled later into another clone: already known in the repo.
  write(b, risky);
  const ob = await scan(b);
  assert.equal(news.riskNews([ob], 30, new Map())[0]!.newWarnings.length, 0);
  // Two clones getting it in the same run: one alert, not two.
  write(c, [...risky, W({ rule: "test-other", severity: "high" })]);
  const d = repo([]);
  writeFileSync(join(d, ".git", "config"), '[remote "origin"]\n\turl = https://github.com/acme/api.git\n');
  await scan(d);
  write(d, [W({ rule: "test-other", severity: "high" })]);
  const both = [await scan(c), await scan(d)];
  const n = news.riskNews(both, 30, new Map());
  assert.deepEqual(n.map((x) => x.newWarnings.map((w) => w.rule)), [["test-other"], ["test-other"]]);
  const alert = alerts.buildRiskAlert(n);
  assert.equal(alert.kind === "banner" && alert.title, "selfguard: new risk in acme/api (CI workflows)");
});

test("machine scope: baseline first, then always active; the reminder includes open high risks", async () => {
  const file = join(process.env.HOME!, "fake-agents.json");
  writeFileSync(file, JSON.stringify({ refs: [], warnings: [], skipped: 0 }));
  const input = { kind: "agents" as const, target: sources.machineTarget() };
  const [first] = await sources.scanSources([input]);
  sources.saveSource(first!.record);
  writeFileSync(file, JSON.stringify({ refs: [], warnings: [W({ rule: "test-persistence", message: "New LaunchAgent runs a script from /tmp", severity: "high", key: "com.evil.agent" })], skipped: 0 }));
  const [o] = await sources.scanSources([input]);
  sources.saveSource(o!.record);
  const [n] = news.riskNews([o!], 30, new Map());
  assert.equal(n!.scope, "machine");
  assert.equal(n!.active, true);
  assert.equal(n!.newWarnings.length, 1);

  assert.ok(api.openRiskGroups().some((g) => g.label === "Agent tools"));
  assert.equal(await announce.maybeRemind([], { force: true }), true);
  const reminder = events.readEvents(5).find((e) => e.kind === "reminder");
  assert.ok(reminder && reminder.total >= 1);
  assert.match(readFileSync(join(process.env.SELFGUARD_HOME!, "events.jsonl"), "utf8"), /"kind":"reminder"/);
});

test("a long warning message is kept whole (up to 600 characters)", async () => {
  const long = `${"A credential sits in plain text. ".repeat(14)}Safer: use a helper.`;
  assert.ok(long.length > 300 && long.length < 600);
  const root = repo([W({ message: long })]);
  const o = await scan(root);
  assert.equal(o.record.warnings[0]!.message, long);
  const huge = repo([W({ message: "x".repeat(2000) })]);
  assert.equal((await scan(huge)).record.warnings[0]!.message.length, 600, "still bounded");
});
