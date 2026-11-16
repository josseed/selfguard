// GitHub Actions advisories: a local index of the whole ecosystem, matched case-insensitively.
// Action names are never sent to OSV.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { osv, startOsv, VULNS } from "./sources-helpers.ts";

const GHA = "GitHub Actions" as const;
let server: Server;
let lookup: typeof import("../src/scan/lookup.ts");
let index: typeof import("../src/scan/gha-index.ts");
let sources: typeof import("../src/sources.ts");
let paths: typeof import("../src/paths.ts");

before(async () => {
  server = await startOsv();
  process.env.SELFGUARD_HOME = mkdtempSync(join(tmpdir(), "sg-home-"));
  process.env.HOME = realpathSync(mkdtempSync(join(tmpdir(), "sg-user-")));
  process.env.SELFGUARD_NO_NOTIFY = "1";
  lookup = await import("../src/scan/lookup.ts");
  index = await import("../src/scan/gha-index.ts");
  sources = await import("../src/sources.ts");
  paths = await import("../src/paths.ts");
});
after(() => server.close());

const reset = () => {
  osv.bodies.length = 0;
  osv.details.length = 0;
  osv.csv = 0;
};
const age = (ms: number) => {
  const file = paths.ghaIndexFile();
  const idx = JSON.parse(readFileSync(file, "utf8"));
  writeFileSync(file, JSON.stringify({ ...idx, fetchedAt: new Date(Date.now() - ms).toISOString() }));
};

test("actions are matched in the local index, case-insensitively, and never sent to OSV", async () => {
  reset();
  const actions = [
    { name: "TJ-Actions/Changed-Files", ecosystem: GHA },
    { name: "tj-actions/changed-files", ecosystem: GHA },
    { name: "Evil/Action", ecosystem: GHA },
    { name: "actions/checkout", ecosystem: GHA },
  ];
  const found = await lookup.lookup([...actions, { name: "lodash", version: "4.17.20", ecosystem: "npm" }]);
  assert.equal(found.error, undefined);
  assert.equal(found.ghaError, undefined);
  assert.deepEqual(osv.bodies.flatMap((b) => b.queries), [{ package: { ecosystem: "npm", name: "lodash" }, version: "4.17.20" }]);
  assert.doesNotMatch(JSON.stringify(osv.bodies), /actions|Action/i, "no action name in any querybatch body");
  assert.deepEqual(actions.map((q) => found.refs.get(lookup.queryKey(q))), [["GHSA-mrrh-fwg8-r2c3"], ["GHSA-mrrh-fwg8-r2c3"], ["MAL-2026-7"], []]);
  assert.ok(found.vulns.has("GHSA-mrrh-fwg8-r2c3") && found.vulns.has("MAL-2026-7"));
  assert.equal(osv.csv, 1);

  // Fresh index: no network for actions at all.
  reset();
  await lookup.lookup(actions);
  assert.deepEqual([osv.bodies.length, osv.csv, osv.details.length], [0, 0, 0]);
});

test("a stale index is refreshed, and only changed advisories are downloaded again", async () => {
  age(7 * 60 * 60 * 1000);
  const mal = VULNS["MAL-2026-7"] as { modified: string };
  const before = mal.modified;
  mal.modified = "2026-02-02T00:00:00.123456789Z";
  try {
    reset();
    const found = await lookup.lookup([{ name: "evil/action", ecosystem: GHA }]);
    assert.equal(osv.csv, 1);
    assert.deepEqual(osv.details, ["MAL-2026-7"], "the unchanged advisory comes from the cache");
    assert.equal(found.vulns.get("MAL-2026-7")?.modified, mal.modified);
  } finally {
    mal.modified = before;
  }
});

test("offline: the cached index is used; without one the source gets an error, never a clean result", async () => {
  age(7 * 60 * 60 * 1000);
  osv.failBucket = true;
  try {
    reset();
    const stale = await lookup.lookup([{ name: "tj-actions/changed-files", ecosystem: GHA }]);
    assert.equal(stale.ghaError, undefined);
    assert.deepEqual(stale.refs.get(lookup.queryKey({ name: "tj-actions/changed-files", ecosystem: GHA })), ["GHSA-mrrh-fwg8-r2c3"]);

    rmSync(paths.ghaIndexFile());
    const none = await lookup.lookup([{ name: "tj-actions/changed-files", ecosystem: GHA }, { name: "lodash", version: "4.17.20", ecosystem: "npm" }]);
    assert.match(none.ghaError ?? "", /could not refresh the GitHub Actions advisory index/);
    assert.equal(none.error, undefined, "other ecosystems are unaffected");

    const root = realpathSync(mkdtempSync(join(tmpdir(), "sg-gha-")));
    mkdirSync(join(root, ".git"));
    mkdirSync(join(root, ".github", "workflows"), { recursive: true });
    writeFileSync(join(root, ".github", "workflows", "ci.yml"), "jobs:\n  a:\n    steps:\n      - uses: tj-actions/changed-files@v45.0.7\n");
    sources.resetSourceExtractors();
    sources.registerBuiltinExtractors();
    const [o] = await sources.scanSources([{ kind: "ci", target: sources.repoTarget(root) }]);
    assert.match(o!.record.error ?? "", /GitHub Actions advisory index/);
    assert.equal(o!.record.scannedAt, null);
  } finally {
    osv.failBucket = false;
  }
});

test("the advisory list is parsed defensively", () => {
  const ok = "2026-01-01T00:00:00Z,GHSA-aaaa-bbbb-cccc\n\njunk\n2026-01-01T00:00:00Z,../../etc/passwd\nnot-a-date,GHSA-x\n2026-11-11T02:57:10.295103665Z,GHSA-6f4g-xm8v-pgv6\r\n";
  assert.deepEqual(index.parseModifiedCsv(ok), [
    { id: "GHSA-aaaa-bbbb-cccc", modified: "2026-01-01T00:00:00Z" },
    { id: "GHSA-6f4g-xm8v-pgv6", modified: "2026-11-11T02:57:10.295103665Z" },
  ]);
  // The list and the advisory write the same instant differently: still a cache hit.
  assert.ok(index.sameInstant("2026-11-10T16:15:04.76005653Z", "2026-11-10T16:15:04.760056530Z"));
  assert.ok(index.sameInstant("2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00Z"));
  assert.ok(!index.sameInstant("2026-01-01T00:00:00.1Z", "2026-01-01T00:00:00Z"));
  assert.throws(() => index.parseModifiedCsv("2026-01-01T00:00:00Z,GHSA-a\n".repeat(10_001)), /too long/);
  assert.deepEqual(index.actionNames({ id: "X", affected: [{ package: { ecosystem: GHA, name: "Azure/setup-kubectl" } }, { package: { ecosystem: "npm", name: "azure/x" } }] }), ["azure/setup-kubectl"]);
});
