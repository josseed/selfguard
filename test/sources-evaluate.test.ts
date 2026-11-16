import assert from "node:assert/strict";
import { test } from "node:test";
import { evaluate } from "../src/match.ts";
import type { OsvVuln } from "../src/osv.ts";
import { evaluateRef, lineAffected } from "../src/sources/evaluate.ts";
import { queryFor, refVersion } from "../src/sources/findings.ts";
import { compareVersions, completeSemver, isValidVersion } from "../src/versions.ts";

const GHA = "GitHub Actions" as const;

// Shaped like the real tj-actions/changed-files advisories: ECOSYSTEM ranges, partial versions.
const CHANGED_FILES: OsvVuln = {
  id: "GHSA-mrrh-fwg8-r2c3",
  summary: "tj-actions/changed-files compromised",
  database_specific: { severity: "HIGH" },
  affected: [{ package: { ecosystem: GHA, name: "tj-actions/changed-files" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "46.0.1" }] }] }],
};
const OLD: OsvVuln = {
  id: "GHSA-old",
  affected: [{ package: { ecosystem: GHA, name: "tj-actions/changed-files" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "41" }] }] }],
};
const MAL: OsvVuln = {
  id: "MAL-2026-1",
  summary: "Malicious code in evil/action",
  affected: [{ package: { ecosystem: GHA, name: "evil/action" }, versions: ["1.0.0"] }],
};

test("GitHub Actions versions: leading v and partial versions", () => {
  assert.equal(completeSemver("41"), "41.0.0");
  assert.equal(completeSemver("v4.1"), "v4.1.0");
  assert.equal(completeSemver("v4.1.2"), "v4.1.2");
  assert.equal(completeSemver("main"), "main");
  assert.equal(compareVersions(GHA, "41", "41.0.0"), 0);
  assert.equal(compareVersions(GHA, "v4.1", "4.1.0"), 0);
  assert.ok(compareVersions(GHA, "v45.0.7", "46.0.1") < 0);
  assert.ok(compareVersions(GHA, "41", "40.9.9") > 0);
  assert.equal(isValidVersion(GHA, "main"), false);
  assert.equal(isValidVersion(GHA, "8f4b7f84864484a7bf31766abe9204da3cbe65b3"), false);
  // npm keeps strict SemVer: partial versions stay invalid there.
  assert.equal(isValidVersion("npm", "41"), false);
});

test("exact action versions are matched locally, including partial fixes", () => {
  assert.deepEqual(evaluate(CHANGED_FILES, "tj-actions/changed-files", "v45.0.7", GHA), { affected: true, fixedIn: "46.0.1" });
  assert.equal(evaluate(CHANGED_FILES, "tj-actions/changed-files", "v46.0.1", GHA).affected, false);
  assert.equal(evaluate(OLD, "tj-actions/changed-files", "40.2.0", GHA).affected, true);
  assert.equal(evaluate(OLD, "tj-actions/changed-files", "41", GHA).affected, false);
  const ref = { ecosystem: GHA, name: "tj-actions/changed-files", version: "v45.0.7", versionKind: "exact" as const };
  assert.deepEqual(evaluateRef(CHANGED_FILES, ref, false), { applies: true, certainty: "confirmed", fixedIn: "46.0.1" });
  assert.equal(evaluateRef(CHANGED_FILES, { ...ref, version: "46.0.1" }, false).applies, false);
});

test("a release line is affected when any of its versions is in a range", () => {
  const name = "tj-actions/changed-files";
  assert.deepEqual(lineAffected(CHANGED_FILES, GHA, name, "45"), { affected: true, fixedIn: "46.0.1" });
  assert.equal(lineAffected(CHANGED_FILES, GHA, name, "46").affected, true, "46.0.0 is affected");
  assert.equal(lineAffected(CHANGED_FILES, GHA, name, "47").affected, false);
  assert.equal(lineAffected(OLD, GHA, name, "41").affected, false, "fixed: 41 means 41.0.0 is safe");
  assert.equal(lineAffected(OLD, GHA, name, "40").affected, true);
  assert.equal(lineAffected(OLD, GHA, name, "40.9").affected, true);
  // Ranges entirely inside a line, last_affected and limits.
  const inner: OsvVuln = {
    id: "X",
    affected: [{ package: { ecosystem: GHA, name: "a/b" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "4.2.0" }, { last_affected: "4.2.3" }] }] }],
  };
  assert.equal(lineAffected(inner, GHA, "a/b", "4").affected, true);
  assert.equal(lineAffected(inner, GHA, "a/b", "4.2").affected, true);
  assert.equal(lineAffected(inner, GHA, "a/b", "4.1").affected, false);
  assert.equal(lineAffected(inner, GHA, "a/b", "4.3").affected, false);
  assert.equal(lineAffected(inner, GHA, "a/b", "5").affected, false);
  const fromFive: OsvVuln = {
    id: "Y",
    affected: [{ package: { ecosystem: GHA, name: "a/b" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "5.0.0" }] }] }],
  };
  assert.equal(lineAffected(fromFive, GHA, "a/b", "4").affected, false);
  assert.equal(lineAffected(fromFive, GHA, "a/b", "7").affected, true, "open range");
  assert.equal(lineAffected(CHANGED_FILES, GHA, "other/action", "45").affected, false, "other package");
  const listed: OsvVuln = { id: "Z", affected: [{ package: { ecosystem: "npm", name: "x" }, versions: ["2.3.1"] }] };
  assert.equal(lineAffected(listed, "npm", "x", "2").affected, true);
  assert.equal(lineAffected(listed, "npm", "x", "3").affected, false);
  const py: OsvVuln = { id: "P", affected: [{ package: { ecosystem: "PyPI", name: "pkg" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.1" }] }] }] };
  assert.equal(lineAffected(py, "PyPI", "pkg", "2").affected, true);
  assert.equal(lineAffected(py, "PyPI", "pkg", "2.1").affected, false);
});

test("line and unknown references: certainty, and malicious advisories always apply", () => {
  const line = { ecosystem: GHA, name: "tj-actions/changed-files", version: null, versionKind: "line" as const, lineOf: "45" };
  assert.deepEqual(evaluateRef(CHANGED_FILES, line, false), { applies: true, certainty: "may-be-affected", fixedIn: "46.0.1" });
  assert.equal(evaluateRef(CHANGED_FILES, { ...line, lineOf: "47" }, false).applies, false);

  const unknown = { ecosystem: GHA, name: "tj-actions/changed-files", version: null, versionKind: "unknown" as const, unknownKind: "fixed-unknown" as const };
  assert.deepEqual(evaluateRef(CHANGED_FILES, unknown, false), { applies: true, certainty: "version-unknown", fixedIn: "46.0.1" });
  assert.equal(evaluateRef(CHANGED_FILES, { ...unknown, name: "someone/else" }, false).applies, false, "only its own advisories");

  const evil = { ecosystem: GHA, name: "evil/action" };
  assert.deepEqual(evaluateRef(MAL, { ...evil, version: "1.0.0", versionKind: "exact" }, false), { applies: true, certainty: "confirmed" });
  assert.deepEqual(evaluateRef(MAL, { ...evil, version: "9.9.9", versionKind: "exact" }, false), { applies: true, certainty: "may-be-affected" });
  assert.deepEqual(evaluateRef(MAL, { ...evil, version: null, versionKind: "line", lineOf: "3" }, false), { applies: true, certainty: "may-be-affected" });
  assert.deepEqual(evaluateRef(MAL, { ...evil, version: null, versionKind: "unknown" }, false), { applies: true, certainty: "version-unknown" });
});

test("unknown versions: a bare SHA lists everything with the fix; tracking the latest, only what affects it or the last run", () => {
  const sha = { ecosystem: GHA, name: "TJ-Actions/Changed-Files", version: null, versionKind: "unknown" as const, unknownKind: "fixed-unknown" as const };
  // Names are compared case-insensitively (GitHub ignores case; OSV keeps the repo's spelling).
  assert.deepEqual(evaluateRef(OLD, sha, false), { applies: true, certainty: "version-unknown", fixedIn: "41" });
  const branch = { ...sha, unknownKind: "tracks-latest" as const };
  assert.deepEqual(evaluateRef(CHANGED_FILES, branch, false), { applies: false, certainty: "version-unknown", fixedIn: "46.0.1" }, "fixed: the latest isn't affected");
  const open = (events: object[]): OsvVuln => ({ id: "GHSA-open", affected: [{ package: { ecosystem: GHA, name: "tj-actions/changed-files" }, ranges: [{ type: "ECOSYSTEM", events }] }] });
  assert.deepEqual(evaluateRef(open([{ introduced: "40" }, { fixed: "41" }, { introduced: "45" }]), branch, false), { applies: true, certainty: "version-unknown", fixedIn: "41" }, "open range");
  assert.equal(evaluateRef(open([{ introduced: "0" }, { last_affected: "45" }]), branch, false).applies, false, "closed by last_affected");
  assert.equal(evaluateRef(MAL, { ...branch, name: "evil/action" }, false).applies, true, "malicious always");

  const npx = { ecosystem: "npm" as const, name: "lodash", version: null, versionKind: "unknown" as const, unknownKind: "tracks-latest" as const };
  const LODASH: OsvVuln = { id: "GHSA-l", affected: [{ package: { ecosystem: "npm", name: "lodash" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }] };
  assert.equal(evaluateRef(LODASH, npx, false).applies, false, "unpinned: a fixed advisory doesn't apply");
  assert.deepEqual(evaluateRef(LODASH, { ...npx, lastRun: "4.17.20" }, false), { applies: true, certainty: "may-be-affected", lastRun: "4.17.20", fixedIn: "4.17.21" });
  assert.equal(evaluateRef(LODASH, { ...npx, lastRun: "4.17.21" }, false).applies, false, "the last run is fixed");
});

test("queries: actions and inexact references by name only; exact npm/PyPI by version", () => {
  const base = { file: "/x", line: 1 };
  assert.deepEqual(queryFor({ ...base, ecosystem: GHA, name: "a/b", version: "4.1.0", versionKind: "exact" }), { name: "a/b", ecosystem: GHA });
  assert.deepEqual(queryFor({ ...base, ecosystem: "npm", name: "srv", version: "1.2.3", versionKind: "exact" }), { name: "srv", version: "1.2.3", ecosystem: "npm" });
  assert.deepEqual(queryFor({ ...base, ecosystem: "npm", name: "srv", version: null, versionKind: "unknown" }), { name: "srv", ecosystem: "npm" });
  assert.equal(refVersion({ version: null, versionKind: "line", lineOf: "4" }), "4.x");
  assert.equal(refVersion({ version: null, versionKind: "unknown", pin: "main" }), "main");
  assert.equal(refVersion({ version: null, versionKind: "unknown" }), "*");
});
