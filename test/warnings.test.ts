// Source warnings as alerts ("risks"): identity, baseline and what to notify. Pure.
import assert from "node:assert/strict";
import { test } from "node:test";
import { buildRiskAlert, buildRiskResolvedAlert, withRisks, type RiskNews } from "../src/riskalerts.ts";
import { alertWorthy, diffWarnings, warningId, warningKey } from "../src/sources/warnings.ts";
import type { SourceRecord, SourceWarning } from "../src/sources/types.ts";

const ROOT = "/r/acme";
const FILE = `${ROOT}/.claude/settings.json`;
const T0 = "2026-11-01T00:00:00.000Z";
const T1 = "2026-11-02T00:00:00.000Z";

const warn = (o: Partial<SourceWarning> = {}): SourceWarning => ({ rule: "test-rule", message: "Hook runs curl | sh", file: FILE, line: 3, severity: "high", ...o });

function rec(warnings: SourceWarning[], o: Partial<SourceRecord> = {}): SourceRecord {
  return {
    schema: 1, kind: "agents", scope: "repo", path: ROOT, registeredAt: T0, scannedAt: T0,
    files: [{ path: FILE, size: 1, mtimeMs: 1, hash: "h1" }], refs: [], findings: [], warnings, skipped: 0,
    warningsBy: "9.9.9", ...o,
  };
}

const fresh = (warnings: SourceWarning[], hash = "h1") => ({ kind: "agents" as const, warnings, files: [{ path: FILE, size: 1, mtimeMs: 2, hash }] });

test("warningKey: kind, rule, file and key; not line or message", () => {
  const a = warningKey("agents", warn());
  assert.equal(a, `agents|test-rule|${FILE}|`);
  assert.equal(warningKey("agents", warn({ line: 99, message: "other" })), a);
  assert.notEqual(warningKey("agents", warn({ key: "PreToolUse" })), a);
  assert.notEqual(warningKey("ci", warn()), a);
  assert.match(warningId(a), /^[0-9a-f]{12}$/);
  assert.equal(alertWorthy(warn()), true);
  assert.equal(alertWorthy(warn({ severity: "low" })), false);
  assert.equal(alertWorthy(warn({ severity: "low", notify: true })), true);
});

test("diffWarnings: first scan is a baseline; later, new and resolved by key", () => {
  const first = diffWarnings(fresh([warn()]), null, T1, "9.9.9");
  assert.deepEqual([first.newWarnings, first.resolvedWarnings], [[], []]);
  assert.ok(Object.hasOwn(first.warningSeen, warningKey("agents", warn())));

  const hook = warn({ key: "SessionStart", message: "SessionStart hook downloads and runs a script" });
  const d = diffWarnings(fresh([warn({ line: 7 }), hook], "h2"), rec([warn(), warn({ rule: "gone-rule" })]), T1, "9.9.9");
  assert.deepEqual(d.newWarnings, [hook], "a moved line is the same warning");
  assert.deepEqual(d.resolvedWarnings.map((w) => w.rule), ["gone-rule"]);
});

test("diffWarnings: a warning seen recently that comes back isn't news", () => {
  const prev = rec([], { warningSeen: { [warningKey("agents", warn())]: T0 } });
  assert.deepEqual(diffWarnings(fresh([warn()], "h2"), prev, T1, "9.9.9").newWarnings, []);
});

test("diffWarnings: after an upgrade, a new rule on unchanged files is baseline; changed files are news", () => {
  const prev = rec([], { warningsBy: "1.0.0" });
  // Same content: the rule is new, not the risk.
  assert.deepEqual(diffWarnings(fresh([warn()], "h1"), prev, T1, "2.0.0").newWarnings, []);
  // Records from before warnings were tracked behave the same.
  const legacy = rec([]);
  delete legacy.warningsBy;
  assert.deepEqual(diffWarnings(fresh([warn()], "h1"), legacy, T1, "2.0.0").newWarnings, []);
  // The file changed: what it says now is news, whatever the rule.
  assert.equal(diffWarnings(fresh([warn()], "h2"), prev, T1, "2.0.0").newWarnings.length, 1);
  // Once this version scanned the record, every rule was evaluated there: new is new.
  assert.equal(diffWarnings(fresh([warn()], "h1"), rec([], { warningsBy: "2.0.0" }), T1, "2.0.0").newWarnings.length, 1);
});

const news = (o: Partial<RiskNews> = {}): RiskNews => ({
  key: "github.com/acme/api", label: "acme/api (agent tools)", path: ROOT, scope: "repo", branch: "main", active: true,
  newWarnings: [], resolvedWarnings: [], warnings: [], ...o,
});

test("buildRiskAlert: one risk says its message; several are grouped per source", () => {
  const one = buildRiskAlert([news({ newWarnings: [warn({ message: "Hook runs curl\u001b[31m | sh" })] })]);
  assert.equal(one.kind, "banner");
  if (one.kind !== "banner") return;
  assert.equal(one.title, "selfguard: new risk in acme/api (agent tools)");
  assert.equal(one.body, "Hook runs curl[31m | sh", "sanitized");
  assert.equal(one.scene, "crit", "high risk: the horn");
  assert.equal(one.repoKey, "github.com/acme/api");

  const three = buildRiskAlert([news({ newWarnings: [warn(), warn({ key: "a" }), warn({ key: "b", severity: "moderate", notify: true })] })]);
  assert.equal(three.kind === "banner" && three.title, "selfguard: 3 new risks in acme/api (agent tools)");

  const two = buildRiskAlert([news({ newWarnings: [warn()] }), news({ key: "sources:agents:machine", label: "Agent tools", scope: "machine", path: "/home/u", newWarnings: [warn({ file: "/home/u/x" })] })]);
  assert.equal(two.kind === "banner" && two.title, "selfguard: 2 new risks in 2 places");
  assert.equal(two.kind === "banner" && two.repoKey, undefined);
});

test("buildRiskAlert: only high or notify; inactive repos stay quiet; machine scope has no repo to open", () => {
  assert.equal(buildRiskAlert([news({ newWarnings: [warn({ severity: "moderate" })] })]).kind, "none");
  const flagged = buildRiskAlert([news({ newWarnings: [warn({ severity: "low", notify: true })] })]);
  assert.equal(flagged.kind === "banner" && flagged.scene, "high", "notify without high severity: a jump, not the horn");
  assert.equal(buildRiskAlert([news({ active: false, newWarnings: [warn()] })]).kind, "none");
  const machine = buildRiskAlert([news({ key: "sources:host:machine", label: "This Mac", scope: "machine", newWarnings: [warn()] })]);
  assert.equal(machine.kind, "banner");
  assert.equal(machine.kind === "banner" && machine.repoKey, undefined);
  // Checkouts of the same repo merge: one risk, not two.
  const twice = buildRiskAlert([news({ newWarnings: [warn()] }), news({ path: "/r/acme-wt", newWarnings: [warn({ file: "/r/acme-wt/.claude/settings.json" })] })]);
  assert.equal(twice.kind === "banner" && twice.title, "selfguard: new risk in acme/api (agent tools)");
});

test("buildRiskResolvedAlert: a quiet ✓ for risks that would have alerted", () => {
  assert.equal(buildRiskResolvedAlert([news({ resolvedWarnings: [warn({ severity: "low" })] })]).kind, "none");
  const done = buildRiskResolvedAlert([news({ resolvedWarnings: [warn()] })]);
  assert.equal(done.kind === "banner" && done.scene, "fixed");
  assert.equal(done.kind === "banner" && done.body, "No open risks left.");
  assert.equal(buildRiskResolvedAlert([news({ active: false, resolvedWarnings: [warn()] })]).kind, "none");
});

test("withRisks: open high risks come after the vulnerabilities in the reminder", () => {
  const vulns = { kind: "banner" as const, title: "selfguard: web needs attention", subtitle: "1 critical", body: "lodash → 4.17.21", scene: "crit" as const };
  const both = withRisks(vulns, [{ label: "acme/api (agent tools)", warnings: [warn()] }]);
  assert.equal(both.kind === "banner" && both.body, "lodash → 4.17.21 · also 1 high risk: acme/api (agent tools) (1)");
  assert.equal(withRisks(vulns, [{ label: "x", warnings: [warn({ severity: "moderate", notify: true })] }]), vulns, "only high risks remind");
  const alone = withRisks({ kind: "none" }, [{ label: "acme/api (agent tools)", warnings: [warn()] }]);
  assert.equal(alone.kind === "banner" && alone.title, "selfguard: acme/api (agent tools) needs attention");
  assert.equal(alone.kind === "banner" && alone.body, "Hook runs curl | sh");
  assert.equal(withRisks({ kind: "none" }, []).kind, "none");
});
