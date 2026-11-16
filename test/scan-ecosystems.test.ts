import assert from "node:assert/strict";
import { copyFileSync, mkdtempSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, test } from "node:test";

// Fake OSV: one advisory per ecosystem, and "smallvec" also exists (clean) on npm.
const VULNS: Record<string, unknown> = {
  "PYSEC-2021-142": {
    id: "PYSEC-2021-142", modified: "2026-01-01T00:00:00Z", summary: "Arbitrary code execution in PyYAML",
    database_specific: { severity: "CRITICAL" },
    affected: [{ package: { ecosystem: "PyPI", name: "pyyaml" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "5.4" }] }] }],
  },
  "RUSTSEC-2021-0003": {
    id: "RUSTSEC-2021-0003", modified: "2026-01-01T00:00:00Z", summary: "Buffer overflow in SmallVec::insert_many",
    affected: [{ package: { ecosystem: "crates.io", name: "smallvec" }, ranges: [{ type: "SEMVER", events: [{ introduced: "1.6.0" }, { fixed: "1.6.1" }] }] }],
  },
  "GO-2021-0238": {
    id: "GO-2021-0238", modified: "2026-01-01T00:00:00Z", summary: "Infinite loop in golang.org/x/net/html",
    affected: [{ package: { ecosystem: "Go", name: "golang.org/x/net" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "0.0.0-20210520170846-37e1c6afe023" }] }] }],
  },
};
const MATCHES: Record<string, string[]> = {
  "PyPI:pyyaml@5.3.1": ["PYSEC-2021-142"],
  "crates.io:smallvec@1.6.0": ["RUSTSEC-2021-0003"],
  "Go:golang.org/x/net@0.0.0-20210226172049-e18ecbb05110": ["GO-2021-0238"],
};

const bodies: any[] = [];
const read = (req: IncomingMessage) =>
  new Promise<string>((r) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => r(b)); });
const server = createServer(async (req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.method === "POST" && req.url === "/v1/querybatch") {
    const body = JSON.parse(await read(req));
    bodies.push(body);
    const results = body.queries.map((q: any) => {
      const ids = MATCHES[`${q.package.ecosystem}:${q.package.name}@${q.version}`] ?? [];
      return ids.length ? { vulns: ids.map((id) => ({ id, modified: "2026-01-01T00:00:00Z" })) } : {};
    });
    res.end(JSON.stringify({ results }));
    return;
  }
  const m = /^\/v1\/vulns\/(.+)$/.exec(req.url ?? "");
  if (m && VULNS[decodeURIComponent(m[1]!)]) {
    res.end(JSON.stringify(VULNS[decodeURIComponent(m[1]!)]));
    return;
  }
  res.statusCode = 404;
  res.end("{}");
});

const fixture = (name: string) => fileURLToPath(new URL(`./fixtures/multi/${name}`, import.meta.url));
let scan: typeof import("../src/scan.ts");
let report: typeof import("../src/report.ts");
let markdown: typeof import("../src/markdown.ts");

function project(file: string, as: string, type: "uv" | "cargo" | "gomod" | "npm") {
  const dir = mkdtempSync(join(tmpdir(), `sg-${type}-`));
  copyFileSync(fixture(file), join(dir, as));
  return { root: dir, lockfile: join(dir, as), lockType: type };
}

before(async () => {
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  process.env.SELFGUARD_OSV_API = `http://127.0.0.1:${(server.address() as AddressInfo).port}/v1`;
  process.env.SELFGUARD_HOME = mkdtempSync(join(tmpdir(), "sg-home-"));
  scan = await import("../src/scan.ts");
  report = await import("../src/report.ts");
  markdown = await import("../src/markdown.ts");
});
after(() => server.close());

test("Python, Rust and Go projects are scanned in one batch, each with its ecosystem", async () => {
  const py = project("uv.fixture.lock", "uv.lock", "uv");
  const rs = project("cargo.fixture.lock", "Cargo.lock", "cargo");
  const go = project("gomod.fixture.mod", "go.mod", "gomod");
  // A JS project with a package named like a crate: must stay a separate npm query.
  const js = mkdtempSync(join(tmpdir(), "sg-npm-"));
  writeFileSync(
    join(js, "package-lock.json"),
    JSON.stringify({ lockfileVersion: 3, packages: { "": { dependencies: { smallvec: "1.6.0" } }, "node_modules/smallvec": { version: "1.6.0" } } }),
  );
  const jsp = { root: js, lockfile: join(js, "package-lock.json"), lockType: "npm" as const };

  const outcomes = await scan.scanProjects([py, rs, go, jsp]);
  assert.equal(bodies.length, 1, "one deduplicated batch for every ecosystem");
  const queries = bodies[0].queries as Array<{ package: { ecosystem: string; name: string }; version: string }>;
  const sent = new Set(queries.map((q) => `${q.package.ecosystem}:${q.package.name}@${q.version}`));
  assert.ok(sent.has("PyPI:pyyaml@5.3.1"));
  assert.ok(sent.has("crates.io:smallvec@1.6.0"));
  assert.ok(sent.has("npm:smallvec@1.6.0"), "same name and version, other ecosystem: its own query");
  assert.ok(sent.has("Go:golang.org/x/net@0.0.0-20210226172049-e18ecbb05110"), "Go versions without v");
  assert.ok(queries.every((q) => Object.keys(q).sort().join() === "package,version"), "only name, ecosystem and version are sent");

  const [pyRec, rsRec, goRec, jsRec] = outcomes.map((o) => o.record);
  for (const r of [pyRec, rsRec, goRec, jsRec]) assert.equal(r!.error, undefined);
  assert.deepEqual(pyRec!.findings.map((f) => [f.id, f.name, f.ecosystem, f.fixedIn, f.severity, f.direct]), [
    ["PYSEC-2021-142", "pyyaml", "PyPI", "5.4", "critical", true],
  ]);
  assert.deepEqual(rsRec!.findings.map((f) => [f.id, f.name, f.version, f.ecosystem, f.fixedIn]), [
    ["RUSTSEC-2021-0003", "smallvec", "1.6.0", "crates.io", "1.6.1"],
  ]);
  assert.deepEqual(goRec!.findings.map((f) => [f.id, f.ecosystem, f.direct, f.fixedIn]), [
    ["GO-2021-0238", "Go", false, "0.0.0-20210520170846-37e1c6afe023"],
  ]);
  assert.deepEqual(jsRec!.findings, [], "the npm smallvec is not the crate");
  assert.equal(rsRec!.skipped, 2);

  const groups = report.groupByPackage(goRec!.findings);
  assert.equal(groups[0]!.ecosystem, "Go");
  assert.equal(groups[0]!.upgradeTo, "0.0.0-20210520170846-37e1c6afe023");

  const md = markdown.renderMarkdown({
    label: "svc",
    checkouts: [{ path: go.root, branch: null, lockfile: go.lockfile, lockType: "gomod", scannedAt: null }],
    packages: groups.map((g) => ({
      name: g.name, version: g.version, ecosystem: g.ecosystem, direct: g.direct, dev: g.dev, worstSeverity: g.worst,
      upgradeTo: g.upgradeTo ?? null, advisoriesWithoutFix: g.unfixed, advisories: [],
    })),
  });
  assert.match(md, /golang\.org\/x\/net@v0\.0\.0-20210226172049-e18ecbb05110/, "Go versions shown with v");
  assert.match(md, /go get <module>@v<version>/);
  assert.doesNotMatch(md, /package\.json/);
});

test("an unparseable lockfile is reported, not treated as clean", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sg-bad-"));
  writeFileSync(join(dir, "Cargo.lock"), "[[package]\nname = ");
  const [o] = await scan.scanProjects([{ root: dir, lockfile: join(dir, "Cargo.lock"), lockType: "cargo" }]);
  assert.match(o!.record.error ?? "", /could not parse lockfile/);
});
