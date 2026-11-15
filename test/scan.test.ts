import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { copyFixture } from "./helpers.ts";

// Fake OSV API: lodash@4.17.20 is vulnerable (GHSA + CVE alias), left-pad@1.3.0 is "malicious".
const VULNS: Record<string, unknown> = {
  "GHSA-aaaa-bbbb-cccc": {
    id: "GHSA-aaaa-bbbb-cccc", modified: "2026-01-01T00:00:00Z", aliases: ["CVE-2021-23337"],
    summary: "Command injection in lodash\u001b[31m", database_specific: { severity: "HIGH" },
    affected: [{ package: { ecosystem: "npm", name: "lodash" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }],
  },
  "CVE-2021-23337": {
    id: "CVE-2021-23337", modified: "2026-01-01T00:00:00Z", aliases: ["GHSA-aaaa-bbbb-cccc"],
    affected: [{ package: { ecosystem: "npm", name: "lodash" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }],
  },
  "MAL-2026-42": {
    id: "MAL-2026-42", modified: "2026-01-01T00:00:00Z", summary: "Malicious code in left-pad",
    affected: [{ package: { ecosystem: "npm", name: "left-pad" }, versions: ["1.3.0"] }],
  },
};
const MATCHES: Record<string, string[]> = {
  "lodash@4.17.20": ["GHSA-aaaa-bbbb-cccc", "CVE-2021-23337"],
  "left-pad@1.3.0": ["MAL-2026-42"],
};

let batchCalls = 0;
let detailCalls = 0;
let lastBody: any;
const read = (req: IncomingMessage) =>
  new Promise<string>((r) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => r(b)); });

const server = createServer(async (req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.method === "POST" && req.url === "/v1/querybatch") {
    batchCalls++;
    lastBody = JSON.parse(await read(req));
    const results = lastBody.queries.map((q: any) => {
      const ids = MATCHES[`${q.package.name}@${q.version}`] ?? [];
      return ids.length ? { vulns: ids.map((id) => ({ id, modified: "2026-01-01T00:00:00Z" })) } : {};
    });
    res.end(JSON.stringify({ results }));
    return;
  }
  const m = /^\/v1\/vulns\/(.+)$/.exec(req.url ?? "");
  if (m && VULNS[decodeURIComponent(m[1]!)]) {
    detailCalls++;
    res.end(JSON.stringify(VULNS[decodeURIComponent(m[1]!)]));
    return;
  }
  res.statusCode = 404;
  res.end("{}");
});

let scan: typeof import("../src/scan.ts");
let store: typeof import("../src/store.ts");
let project: import("../src/lockfile/detect.ts").Project;

before(async () => {
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  process.env.SELFGUARD_OSV_API = `http://127.0.0.1:${(server.address() as AddressInfo).port}/v1`;
  process.env.SELFGUARD_HOME = mkdtempSync(join(tmpdir(), "sg-home-"));
  scan = await import("../src/scan.ts");
  store = await import("../src/store.ts");
  const dir = mkdtempSync(join(tmpdir(), "sg-proj-"));
  copyFixture("v3", dir);
  project = { root: dir, lockfile: join(dir, "package-lock.json"), lockType: "npm" };
});
after(() => server.close());

test("first scan finds, dedupes aliases, classifies and sanitizes", async () => {
  const [o] = await scan.scanProjects([project]);
  const rec = o!.record;
  assert.equal(rec.error, undefined);
  assert.equal(o!.firstScan, true);
  // only name+version are sent
  assert.deepEqual(Object.keys(lastBody.queries[0]).sort(), ["package", "version"]);
  assert.deepEqual(rec.findings.map((f) => `${f.severity}:${f.id}:${f.name}@${f.version}`), [
    "malicious:MAL-2026-42:left-pad@1.3.0",
    "high:GHSA-aaaa-bbbb-cccc:lodash@4.17.20",
  ]);
  assert.equal(rec.findings[1]!.fixedIn, "4.17.21");
  assert.equal(rec.findings[1]!.summary.includes("\u001b"), false);
  assert.equal(o!.newFindings.length, 2);
  store.saveRepo(rec);
});

test("rescan uses advisory cache and reports nothing new", async () => {
  const detailsBefore = detailCalls;
  const [o] = await scan.scanProjects([project]);
  assert.equal(detailCalls, detailsBefore, "advisories served from local cache");
  assert.equal(o!.newFindings.length, 0);
  assert.equal(o!.firstScan, false);
  assert.equal(scan.lockChanged(o!.record, project), false);
});

test("fixing a dependency is detected as a lockfile change and clears the finding", async () => {
  const lock = JSON.parse(readFileSync(project.lockfile!, "utf8"));
  lock.packages["node_modules/lodash"].version = "4.17.21";
  writeFileSync(project.lockfile!, JSON.stringify(lock));
  assert.equal(scan.lockChanged(store.loadRepo(project.root)!, project), true);
  const [o] = await scan.scanProjects([project]);
  assert.deepEqual(o!.record.findings.map((f) => f.id), ["MAL-2026-42"]);
});

test("a fix on the same branch is reported as resolved; switching branches is not", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sg-branch-"));
  copyFixture("v3", dir);
  mkdirSync(join(dir, ".git"));
  const head = (b: string) => writeFileSync(join(dir, ".git", "HEAD"), `ref: refs/heads/${b}\n`);
  const setLodash = (v: string) => {
    const lock = JSON.parse(readFileSync(join(dir, "package-lock.json"), "utf8"));
    lock.packages["node_modules/lodash"].version = v;
    writeFileSync(join(dir, "package-lock.json"), JSON.stringify(lock));
  };
  const p = { root: dir, lockfile: join(dir, "package-lock.json"), lockType: "npm" as const };
  const run = async () => {
    const [o] = await scan.scanProjects([p]);
    store.saveRepo(o!.record);
    return o!;
  };

  head("main");
  await run();
  // switch to an old branch that has the fix "undone"... and an upgraded lodash on main
  head("feature");
  setLodash("4.17.21");
  const switched = await run();
  assert.deepEqual(switched.resolvedFindings, [], "branch switch is not a fix");
  // back to main with the vulnerable version: seen before, so not "new"
  head("main");
  setLodash("4.17.20");
  const back = await run();
  assert.deepEqual(back.newFindings, [], "known findings don't re-alert after switching back");
  // a real fix on main
  setLodash("4.17.21");
  const fixed = await run();
  assert.deepEqual(fixed.resolvedFindings.map((f) => f.id), ["GHSA-aaaa-bbbb-cccc"]);
  assert.equal(fixed.record.branch, "main");
});

test("network failure keeps the last known findings", async () => {
  const prevApi = process.env.SELFGUARD_OSV_API;
  server.close();
  const [o] = await scan.scanProjects([project]);
  assert.match(o!.record.error ?? "", /could not reach OSV/);
  assert.equal(o!.record.findings.length, 2, "previous findings retained");
  process.env.SELFGUARD_OSV_API = prevApi;
});
