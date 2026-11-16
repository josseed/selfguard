import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, utimesSync, writeFileSync } from "node:fs";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { FAKE_AGENTS, FAKE_CI, osv, startOsv } from "./sources-helpers.ts";

let server: Server;
let sources: typeof import("../src/sources.ts");
let alerts: typeof import("../src/alerts.ts");
let news: typeof import("../src/sources/news.ts");
let api: typeof import("../src/api.ts");

before(async () => {
  server = await startOsv();
  process.env.SELFGUARD_HOME = mkdtempSync(join(tmpdir(), "sg-home-"));
  process.env.HOME = mkdtempSync(join(tmpdir(), "sg-user-"));
  process.env.SELFGUARD_NO_NOTIFY = "1";
  sources = await import("../src/sources.ts");
  alerts = await import("../src/alerts.ts");
  news = await import("../src/sources/news.ts");
  api = await import("../src/api.ts");
  sources.resetSourceExtractors();
  sources.registerSourceExtractor(FAKE_CI);
  sources.registerSourceExtractor(FAKE_AGENTS);
});
after(() => server.close());

const ref = (o: Record<string, unknown>) => ({ ecosystem: "GitHub Actions", version: null, line: 3, ...o });

function repo(content: unknown): string {
  const root = mkdtempSync(join(tmpdir(), "sg-src-"));
  mkdirSync(join(root, ".git"));
  writeFileSync(join(root, "fake-ci.json"), JSON.stringify(content));
  return root;
}

const CONTENT = {
  refs: [
    ref({ name: "tj-actions/changed-files", version: "v45.0.7", versionKind: "exact", line: 10 }),
    ref({ name: "tj-actions/changed-files", versionKind: "line", lineOf: "v45", pin: "v45", line: 11 }),
    ref({ name: "tj-actions/changed-files", versionKind: "line", lineOf: "47", pin: "v47", line: 12 }),
    ref({ name: "tj-actions/changed-files", version: "46.0.1", versionKind: "exact", line: 13 }),
    ref({ name: "evil/action", versionKind: "unknown", pin: "main\u001b[31m", line: 14 }),
    { ecosystem: "npm", name: "lodash", version: "4.17.20", versionKind: "exact", line: 15, agent: "Claude Code", server: "docs", launcher: "npx" },
    { ecosystem: "Maven", name: "junk", version: "1", versionKind: "exact", line: 1 },
    { ecosystem: "npm", name: "", versionKind: "exact", line: 1 },
  ],
  warnings: [
    { rule: "unpinned-action", message: "Pin tj-actions/changed-files to a commit SHA\u001b]0;x\u0007", line: 11, severity: "moderate" },
    { rule: "", message: "no rule: dropped", line: 1, severity: "high" },
  ],
  skipped: 2,
};

test("scanSources: name-only queries for actions, local evaluation, certainty, warnings apart", async () => {
  const root = repo(CONTENT);
  osv.bodies.length = 0;
  const [o] = await sources.scanSources([{ kind: "ci", target: sources.repoTarget(root) }]);
  assert.equal(osv.bodies.length, 1, "one batch");
  // Actions are matched in the local index, never sent: only the npm package is asked.
  assert.deepEqual(osv.bodies[0].queries, [{ package: { ecosystem: "npm", name: "lodash" }, version: "4.17.20" }]);

  const rec = o!.record;
  assert.equal(rec.refs.length, 6, "invalid ecosystems and empty names dropped");
  assert.equal(rec.skipped, 2);
  assert.equal(rec.files.length, 1);
  const summary = rec.findings.map((f) => [f.id, f.version, f.certainty ?? "confirmed", f.fixedIn ?? null]);
  assert.deepEqual(summary, [
    ["MAL-2026-7", "main[31m", "version-unknown", null],
    ["GHSA-aaaa-bbbb-cccc", "4.17.20", "confirmed", "4.17.21"],
    ["GHSA-mrrh-fwg8-r2c3", "45.0.7", "confirmed", "46.0.1"],
    ["GHSA-mrrh-fwg8-r2c3", "45.x", "may-be-affected", "46.0.1"],
  ]);
  const mal = rec.findings[0]!;
  assert.equal(mal.severity, "malicious");
  assert.doesNotMatch(mal.pin ?? "", /\u001b/, "external strings are cleaned");
  assert.deepEqual(rec.findings[2]!.locations, [{ file: join(root, "fake-ci.json"), line: 10 }]);
  assert.equal(rec.refs.find((r) => r.name === "lodash")?.agent, "Claude Code");

  assert.equal(rec.warnings.length, 1);
  assert.equal(rec.warnings[0]!.rule, "unpinned-action");
  assert.doesNotMatch(rec.warnings[0]!.message, /[\u0000-\u001f]/);
  // A first scan is a baseline: only the malicious finding is news (no burst of notifications).
  assert.deepEqual(o!.newFindings.map((f) => f.id), ["MAL-2026-7"]);
  assert.ok(o!.firstScan);

  // The malicious action raises the same blocking dialog as a malicious package.
  const alert = alerts.buildAlert(news.sourceNews([o!], 30, new Map()));
  assert.equal(alert.kind, "critical");
  assert.match(alert.kind === "critical" ? alert.dialogMessage : "", /evil\/action/);
});

test("records: round trip, change detection, new and resolved findings", async () => {
  const root = repo(CONTENT);
  const input = { kind: "ci" as const, target: sources.repoTarget(root) };
  const [first] = await sources.scanSources([input]);
  sources.saveSource(first!.record);
  const loaded = sources.loadSource("ci", "repo", root);
  assert.deepEqual(loaded, JSON.parse(JSON.stringify(first!.record)));
  assert.equal(sources.loadSource("agents", "repo", root), null, "keyed by kind");
  const file = join(root, "fake-ci.json");
  assert.equal(sources.sourceChanged(loaded, [file]), false);
  // Same content, new mtime: the hash says nothing changed.
  utimesSync(file, new Date(), new Date(Date.now() + 5000));
  assert.equal(sources.sourceChanged(loaded, [file]), false);
  assert.equal(sources.sourceChanged(loaded, []), true, "file gone");

  writeFileSync(file, JSON.stringify({ refs: [ref({ name: "tj-actions/changed-files", version: "46.0.1", versionKind: "exact" })], warnings: [], skipped: 0 }));
  assert.equal(sources.sourceChanged(loaded, [file]), true);
  const [second] = await sources.scanSources([input]);
  assert.equal(second!.record.findings.length, 0);
  assert.equal(second!.resolvedFindings.length, 4);
  assert.equal(second!.newFindings.length, 0);
  assert.equal(second!.record.registeredAt, first!.record.registeredAt);
  assert.equal(second!.firstScan, false);
});

test("network errors keep the previous findings", async () => {
  const root = repo(CONTENT);
  const input = { kind: "ci" as const, target: sources.repoTarget(root) };
  const [ok] = await sources.scanSources([input]);
  sources.saveSource(ok!.record);
  osv.fail = true;
  try {
    const file = join(root, "fake-ci.json");
    writeFileSync(file, JSON.stringify({ ...CONTENT, refs: CONTENT.refs.slice(5, 6) }));
    const [o] = await sources.scanSources([input]);
    assert.match(o!.record.error ?? "", /could not reach OSV/);
    assert.deepEqual(o!.record.findings, ok!.record.findings);
    assert.equal(o!.record.scannedAt, ok!.record.scannedAt);
    assert.deepEqual([o!.newFindings, o!.resolvedFindings], [[], []]);
    // The previous file states are kept, so the next check sees the change and retries.
    assert.deepEqual(o!.record.files, ok!.record.files);
    sources.saveSource(o!.record);
    assert.equal(sources.sourceChanged(sources.loadSource("ci", "repo", root), [file]), true);
  } finally {
    osv.fail = false;
  }
});

test("api: machine-wide agent tools and repo sources; warnings are never vulnerable packages", async () => {
  writeFileSync(join(process.env.HOME!, "fake-agents.json"), JSON.stringify({
    refs: [{ ecosystem: "npm", name: "lodash", version: null, versionKind: "unknown", unknownKind: "tracks-latest", lastRun: "4.17.20", pin: "latest", line: 4, agent: "Cursor", server: "x", launcher: "npx" }],
    warnings: [{ rule: "unpinned-server", message: "Pin a version", line: 4, severity: "high" }],
    skipped: 0,
  }));
  const onlyWarnings = repo({ refs: [], warnings: [{ rule: "unpinned-action", message: "Pin it", line: 2, severity: "high" }], skipped: 0 });
  const outcomes = await sources.scanSources([
    { kind: "agents", target: sources.machineTarget() },
    { kind: "ci", target: sources.repoTarget(onlyWarnings) },
  ]);
  for (const o of outcomes) sources.saveSource(o.record);

  const all = api.getSources();
  assert.deepEqual(all.kinds.sort(), ["agents", "ci"]);
  assert.equal(all.machine.length, 1);
  const machine = all.machine[0]!;
  assert.equal(machine.label, "Agent tools");
  assert.equal(machine.repoKey, null);
  // Unpinned: the fixed advisory applies only because the version last run is affected.
  assert.deepEqual(machine.findings.map((f) => [f.id, f.certainty, f.version, f.lastRun, f.fixedIn]), [["GHSA-aaaa-bbbb-cccc", "may-be-affected", "latest", "4.17.20", "4.17.21"]]);
  assert.equal(machine.references[0]!.agent, "Cursor");

  const scoped = api.getSources({ path: join(onlyWarnings, ".git") });
  assert.equal(scoped.machine.length, 0);
  assert.equal(scoped.repos.length, 1);
  assert.equal(scoped.repos[0]!.warnings.length, 1);
  assert.equal(scoped.repos[0]!.vulnerableReferences, 0, "warnings are not vulnerabilities");
  assert.equal(scoped.repos[0]!.worstSeverity, null);
  assert.equal(api.getStatus().projects.length, 0, "sources are not projects");
});
