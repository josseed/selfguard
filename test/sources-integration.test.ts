import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, test } from "node:test";
import { FAKE_CI, osv, startOsv } from "./sources-helpers.ts";

let server: Server;
let sources: typeof import("../src/sources.ts");
let api: typeof import("../src/api.ts");
let store: typeof import("../src/store.ts");

before(async () => {
  server = await startOsv();
  process.env.SELFGUARD_HOME = mkdtempSync(join(tmpdir(), "sg-home-"));
  process.env.HOME = realpathSync(mkdtempSync(join(tmpdir(), "sg-user-")));
  process.env.SELFGUARD_NO_NOTIFY = "1";
  sources = await import("../src/sources.ts");
  api = await import("../src/api.ts");
  store = await import("../src/store.ts");
});
after(() => server.close());

/** A git repo (recent activity) with a vulnerable lockfile and a fake CI file. */
function project(): string {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "sg-int-")));
  mkdirSync(join(root, ".git"));
  writeFileSync(join(root, ".git", "HEAD"), "ref: refs/heads/main\n");
  writeFileSync(join(root, "package.json"), JSON.stringify({ name: "app", dependencies: { lodash: "4.17.20" } }));
  writeFileSync(
    join(root, "package-lock.json"),
    JSON.stringify({ lockfileVersion: 3, packages: { "": { dependencies: { lodash: "4.17.20" } }, "node_modules/lodash": { version: "4.17.20" } } }),
  );
  writeCi(root, "evil/action");
  return root;
}

function writeCi(root: string, name: string, extra: Record<string, unknown> = {}): void {
  const ref = { ecosystem: "GitHub Actions", name, version: null, versionKind: "unknown", pin: "main", line: 7, ...extra };
  writeFileSync(join(root, "fake-ci.json"), JSON.stringify({ refs: [ref], warnings: [], skipped: 0 }));
}

test("without extractors, scanning is exactly the lockfile scan", async () => {
  sources.resetSourceExtractors();
  const root = project();
  osv.bodies.length = 0;
  const r = await api.scanPath(root);
  assert.equal(osv.bodies.length, 1);
  assert.deepEqual(osv.bodies[0].queries, [{ package: { ecosystem: "npm", name: "lodash" }, version: "4.17.20" }]);
  assert.deepEqual(r.project.vulnerable.map((p) => [p.name, p.advisories.map((a) => a.id)]), [["lodash", ["GHSA-aaaa-bbbb-cccc"]]]);
  assert.equal(store.loadRepo(root)!.findings[0]!.certainty, undefined, "lockfile findings carry no certainty");
  assert.deepEqual(sources.listSources(), []);
  assert.deepEqual(api.watchTargets().filter((p) => p.startsWith(root)), [root, join(root, "package-lock.json")]);
});

test("with an extractor: one batch for lockfile and sources; check re-scans changed sources", async () => {
  sources.resetSourceExtractors();
  sources.registerSourceExtractor(FAKE_CI);
  const root = project();
  osv.bodies.length = 0;
  const r = await api.scanPath(root);
  assert.equal(osv.bodies.length, 1, "lockfile and CI references share one scan");
  // Actions are matched in the local index: their names are never sent.
  assert.deepEqual(osv.bodies[0].queries, [{ package: { ecosystem: "npm", name: "lodash" }, version: "4.17.20" }]);
  // The lockfile report is unchanged by sources.
  assert.equal(r.project.vulnerablePackages, 1);
  assert.equal(r.newAdvisories, 1);
  const rec = sources.loadSource("ci", "repo", root)!;
  assert.deepEqual(rec.findings.map((f) => [f.id, f.severity, f.certainty]), [["MAL-2026-7", "malicious", "version-unknown"]]);
  const listed = api.getSources({ path: root });
  assert.equal(listed.repos[0]!.findings[0]!.locations[0]!.line, 7);
  assert.equal(api.getStatus().projects[0]!.advisories, 1, "status counts stay lockfile-only");

  // Watcher: the extractor's watch paths come with the checkout.
  const targets = api.watchTargets();
  assert.ok(targets.includes(join(root, "fake-ci.json")));
  assert.ok(targets.includes(join(root, ".github")));

  // The first test's repo has CI files but no source record yet: check picks it up once.
  await api.check();
  osv.bodies.length = 0;
  assert.deepEqual(await api.check(), { rescanned: [], errors: [] });
  assert.equal(osv.bodies.length, 0, "nothing changed: no network");

  writeCi(root, "TJ-Actions/changed-files", { pin: "0123456789ab", unknownKind: "fixed-unknown" });
  const c = await api.check();
  assert.deepEqual(c.rescanned, [], "the lockfile didn't change");
  assert.equal(osv.bodies.length, 0, "actions are not sent");
  const after = sources.loadSource("ci", "repo", root)!;
  assert.deepEqual(after.findings.map((f) => [f.id, f.version, f.certainty, f.fixedIn]), [["GHSA-mrrh-fwg8-r2c3", "0123456789ab", "version-unknown", "46.0.1"]]);

  // The file changes but its references don't (a moved line): no lookup, findings relocated.
  const csv = osv.csv;
  const details = osv.details.length;
  writeCi(root, "TJ-Actions/changed-files", { pin: "0123456789ab", unknownKind: "fixed-unknown", line: 9 });
  await api.check();
  assert.deepEqual([osv.bodies.length, osv.csv, osv.details.length], [0, csv, details], "no network");
  const moved = sources.loadSource("ci", "repo", root)!;
  assert.equal(moved.scannedAt, after.scannedAt);
  assert.deepEqual(moved.findings[0]!.locations, [{ file: join(root, "fake-ci.json"), line: 9 }]);
  assert.equal(sources.sourceChanged(moved, [join(root, "fake-ci.json")]), false, "file states updated");
});

test("selfguard tools --json: a stable document with the built-in kinds, empty before any scan", () => {
  const home = realpathSync(mkdtempSync(join(tmpdir(), "sg-cli-")));
  const env = { ...process.env, HOME: home, SELFGUARD_HOME: join(home, ".sg"), SELFGUARD_NO_NOTIFY: "1", NO_COLOR: "1" };
  const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
  const json = JSON.parse(execFileSync(process.execPath, [cli, "tools", "--json"], { env, encoding: "utf8" }));
  assert.deepEqual(Object.keys(json).sort(), ["kinds", "machine", "repos"]);
  assert.ok(json.kinds.includes("ci") && json.kinds.includes("agents"), "both built-in extractors ship");
  assert.deepEqual({ machine: json.machine, repos: json.repos }, { machine: [], repos: [] });
  const text = execFileSync(process.execPath, [cli, "tools"], { env, encoding: "utf8" });
  assert.match(text, /Agent tools on this machine\n\s+none found/);
});
