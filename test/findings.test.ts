import assert from "node:assert/strict";
import { test } from "node:test";
import { cvss3Score } from "../src/cvss.ts";
import { eventPackages } from "../src/events.ts";
import { buildFindings } from "../src/findings.ts";
import { parseEcosystem } from "../src/lockfile/types.ts";
import { evaluate, severityOf } from "../src/match.ts";
import type { OsvVuln } from "../src/osv.ts";

test("evaluate: PyPI ECOSYSTEM ranges use PEP 440 and normalized names", () => {
  const v: OsvVuln = {
    id: "PYSEC-1",
    affected: [{ package: { ecosystem: "PyPI", name: "PyYAML" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "5.4" }] }] }],
  };
  assert.deepEqual(evaluate(v, "pyyaml", "5.3.1", "PyPI"), { affected: true, fixedIn: "5.4" });
  assert.equal(evaluate(v, "pyyaml", "5.4", "PyPI").affected, false);
  assert.equal(evaluate(v, "pyyaml", "5.4rc1", "PyPI").affected, true, "rc sorts before the final release");
  assert.equal(evaluate(v, "pyyaml", "5.3.1", "npm").affected, false, "same name in another ecosystem");
  const listed: OsvVuln = { id: "X", affected: [{ package: { ecosystem: "PyPI", name: "a" }, versions: ["1.0"] }] };
  assert.equal(evaluate(listed, "a", "1.0.0", "PyPI").affected, true, "equivalent PEP 440 spelling");
});

test("evaluate: Go and crates.io SEMVER ranges", () => {
  const go: OsvVuln = {
    id: "GO-2022-0236",
    affected: [{ package: { ecosystem: "Go", name: "golang.org/x/net" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "0.0.0-20211209124913-491a49abca63" }] }] }],
  };
  assert.deepEqual(evaluate(go, "golang.org/x/net", "0.0.0-20210226172049-e18ecbb05110", "Go"), {
    affected: true,
    fixedIn: "0.0.0-20211209124913-491a49abca63",
  });
  assert.equal(evaluate(go, "golang.org/x/net", "0.1.0", "Go").affected, false);
  const crate: OsvVuln = {
    id: "RUSTSEC-2021-0003",
    affected: [{ package: { ecosystem: "crates.io", name: "smallvec" }, ranges: [{ type: "SEMVER", events: [{ introduced: "1.6.0" }, { fixed: "1.6.1" }] }] }],
  };
  assert.deepEqual(evaluate(crate, "smallvec", "1.6.0", "crates.io"), { affected: true, fixedIn: "1.6.1" });
  assert.equal(evaluate(crate, "smallvec", "0.6.13", "crates.io").affected, false);
});

test("CVSS v3 base scores and severity from a vector", () => {
  assert.equal(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
  assert.equal(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10);
  assert.equal(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1);
  assert.equal(cvss3Score("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"), 5.5);
  assert.equal(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0);
  assert.equal(cvss3Score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"), null);
  assert.equal(cvss3Score("CVSS:3.1/AV:N"), null);
  const v = (score: string): OsvVuln => ({ id: "PYSEC-1", severity: [{ type: "CVSS_V3", score }] });
  assert.equal(severityOf(v("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")), "critical");
  assert.equal(severityOf(v("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")), "moderate");
  assert.equal(severityOf({ id: "GO-1" }), "unknown");
});

const fixed = (eco: string, name: string, fix: string) => [{ package: { ecosystem: eco, name }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: fix }] }] }];
const dep = { name: "pyyaml", version: "5.3.1", direct: true, dev: false, ecosystem: "PyPI" as const };
const run = (ids: string[], vulns: OsvVuln[]) =>
  buildFindings([dep], new Map([["PyPI:pyyaml@5.3.1", ids]]), new Map(vulns.map((v) => [v.id, v])), null, "2026-01-01T00:00:00Z");

test("aliases collapse in either direction and keep the known severity, whatever the order", () => {
  const pysec: OsvVuln = { id: "PYSEC-2021-142", aliases: ["CVE-2020-14343", "GHSA-8q59-q68h-6hv4"], summary: "From PYSEC", affected: fixed("PyPI", "pyyaml", "5.4") };
  const ghsa: OsvVuln = { id: "GHSA-8q59-q68h-6hv4", aliases: ["CVE-2020-14343"], database_specific: { severity: "CRITICAL" }, affected: fixed("PyPI", "PyYAML", "5.4") };
  for (const order of [["PYSEC-2021-142", "GHSA-8q59-q68h-6hv4"], ["GHSA-8q59-q68h-6hv4", "PYSEC-2021-142"]]) {
    const f = run(order, [pysec, ghsa]);
    assert.equal(f.length, 1, order.join());
    assert.equal(f[0]!.id, "GHSA-8q59-q68h-6hv4");
    assert.equal(f[0]!.severity, "critical");
    assert.equal(f[0]!.fixedIn, "5.4");
    assert.ok(f[0]!.aliases.includes("PYSEC-2021-142"));
  }
  // GO-* lists its GHSA, the GHSA doesn't list GO-*: still one finding.
  const go: OsvVuln = { id: "GO-2021-0001", aliases: ["GHSA-aaaa"] };
  const gh: OsvVuln = { id: "GHSA-aaaa", database_specific: { severity: "HIGH" } };
  const f = run(["GO-2021-0001", "GHSA-aaaa"], [go, gh]);
  assert.deepEqual(f.map((x) => [x.id, x.severity]), [["GHSA-aaaa", "high"]]);
});

test("RustSec informational notices are not findings", () => {
  const notice: OsvVuln = { id: "RUSTSEC-2024-0375", affected: [{ package: { ecosystem: "crates.io", name: "pyyaml" }, database_specific: { informational: "unmaintained" } }] };
  const vuln: OsvVuln = { id: "RUSTSEC-2021-0003" };
  assert.deepEqual(run(["RUSTSEC-2024-0375", "RUSTSEC-2021-0003"], [notice, vuln]).map((f) => f.id), ["RUSTSEC-2021-0003"]);
});

test("ecosystem names are matched case-insensitively and unknown ones rejected", () => {
  assert.equal(parseEcosystem("pypi"), "PyPI");
  assert.equal(parseEcosystem(" Crates.IO "), "crates.io");
  assert.equal(parseEcosystem("maven"), null);
});

test("events keep the ecosystem of non-npm packages", () => {
  const base = { aliases: [], summary: "", direct: true, dev: false, firstSeen: "", severity: "high" as const };
  const { packages } = eventPackages([
    { ...base, id: "A", name: "smallvec", version: "1.0.0" },
    { ...base, id: "B", name: "smallvec", version: "1.0.0", ecosystem: "crates.io" },
  ]);
  assert.deepEqual(packages.map((p) => p.ecosystem ?? "npm").sort(), ["crates.io", "npm"]);
});
