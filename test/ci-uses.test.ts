import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { extractActions } from "../src/sources/ci/extractor.ts";
import { scalar, splitLines } from "../src/sources/ci/lines.ts";
import { commentVersion, tagVersion } from "../src/sources/ci/uses.ts";

const fixture = (name: string): string => readFileSync(new URL(`./fixtures/ci/${name}`, import.meta.url), "utf8");
const brief = (r: any): string =>
  `${r.line} ${r.name} ${r.versionKind}${r.version ? ` ${r.version}` : ""}${r.lineOf ? ` line ${r.lineOf}` : ""} pin=${r.pin}`;

test("every uses: form of a workflow", () => {
  const res = extractActions(fixture("uses-forms.fixture.yml"));
  assert.deepEqual(res.refs.map(brief), [
    "7 actions/checkout line line 4 pin=v4",
    "9 actions/setup-node exact v4.1.0 pin=v4.1.0",
    "10 tj-actions/changed-files exact v45.0.7 pin=v45.0.7",
    "11 tj-actions/changed-files exact 46.0.1 pin=46.0.1",
    "12 Azure/setup-kubectl line line 3.2 pin=v3.2",
    "13 github/codeql-action line line 3 pin=v3",
    "14 tj-actions/changed-files exact v45.0.7 pin=0123456789ab",
    "15 owner/one exact v1.2.3 pin=0123456789ab",
    "16 owner/two line line 2 pin=0123456789ab",
    "17 owner/three unknown pin=0123456789ab",
    "18 owner/four unknown pin=0123456789ab",
    "19 owner/five unknown pin=main",
    "28 owner/six line line 6 pin=v6",
    "30 octo-org/shared exact v2.0.0 pin=v2.0.0",
  ]);
  assert.ok(res.refs.every((r) => r.ecosystem === "GitHub Actions"));
  // docker://, ${{ }} and a value that isn't owner/repo@ref; local actions aren't counted.
  assert.equal(res.skipped, 3);
});

test("ref versions: tags, lines, SHAs with and without version comments", () => {
  assert.deepEqual(tagVersion("v4.1.0"), { version: "v4.1.0", versionKind: "exact" });
  assert.deepEqual(tagVersion("1.2.3-beta.1"), { version: "1.2.3-beta.1", versionKind: "exact" });
  assert.deepEqual(tagVersion("v4"), { version: null, versionKind: "line", lineOf: "4" });
  assert.deepEqual(tagVersion("4.1"), { version: null, versionKind: "line", lineOf: "4.1" });
  for (const branch of ["main", "release/v4", "v4-beta", "latest"]) assert.equal(tagVersion(branch), null, branch);

  assert.deepEqual(commentVersion("v4.1.0"), { version: "v4.1.0", versionKind: "exact" });
  assert.deepEqual(commentVersion("4.1.0"), { version: "4.1.0", versionKind: "exact" });
  assert.deepEqual(commentVersion("tag=v4.1.0"), { version: "v4.1.0", versionKind: "exact" });
  assert.deepEqual(commentVersion("pin@v4.1.0"), { version: "v4.1.0", versionKind: "exact" });
  assert.deepEqual(commentVersion("ratchet:actions/checkout@v4"), { version: null, versionKind: "line", lineOf: "4" });
  assert.deepEqual(commentVersion("v4.1.0 (2024-01-01)"), { version: "v4.1.0", versionKind: "exact" });
  assert.deepEqual(commentVersion("v4"), { version: null, versionKind: "line", lineOf: "4" });
  for (const c of ["", "2", "4.1", "2024-01-01", "see PR 12", "v4-beta", "pinned", "v4.1.0.1"]) assert.equal(commentVersion(c), null, c);
});

test("quoting and comments of scalar values", () => {
  assert.deepEqual(scalar(` "a/b@v1" # c`), { value: "a/b@v1", comment: "c", quoted: true });
  assert.deepEqual(scalar(` 'it''s' `), { value: "it's", comment: "", quoted: true });
  assert.deepEqual(scalar(` "a\\"b"`), { value: 'a"b', comment: "", quoted: true });
  assert.deepEqual(scalar(` a/b@v1#x # real`), { value: "a/b@v1#x", comment: "real", quoted: false });
  assert.deepEqual(scalar(` "unterminated`), { value: "", comment: "", quoted: true });
  assert.deepEqual(scalar(`# only a comment`), { value: "", comment: "only a comment", quoted: false });
});

test("block scalars hide their content from the scanner", () => {
  const lines = splitLines(["a:", "  run: |", "    uses: x/y@v1", "", "    more", "  uses: real/one@v1", "b: >-", "  - uses: no/no@v1", "c: 1"].join("\n"));
  assert.deepEqual(lines.map((l) => l.blockOf), [-1, -1, 1, 1, 1, -1, -1, 6, -1]);
  assert.deepEqual(extractActions(lines.map((l) => l.raw).join("\n")).refs.map((r) => r.name), ["real/one"]);
});

test("a composite action's steps", () => {
  const res = extractActions(fixture("composite-action.fixture.yml"));
  assert.deepEqual(res.refs.map(brief), ["9 actions/setup-node line line 4 pin=v4", "10 tj-actions/changed-files line line 45 pin=v45"]);
  assert.equal(res.skipped, 0);
  assert.deepEqual(res.warnings.map((w) => `${w.line} ${w.rule}`), ["10 unpinned-action"]);
});

test("malformed input never throws", () => {
  for (const text of ["", "\0\0", "uses:", "- uses: |", "uses: '", "- - - uses: a/b@", ":::", "x".repeat(100_000), "\n".repeat(60_000) + "uses: a/b@v1"]) {
    const res = extractActions(text);
    assert.ok(Array.isArray(res.refs) && Array.isArray(res.warnings) && typeof res.skipped === "number");
  }
  assert.deepEqual(extractActions(undefined as unknown as string), { refs: [], warnings: [], skipped: 0 });
  assert.deepEqual(extractActions("- uses: a/b@v1\r\n- uses: c/d@v2\r\n").refs.map((r) => r.pin), ["v1", "v2"]);
});
