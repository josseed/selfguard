import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, before, test } from "node:test";
import { osv, startOsv } from "./sources-helpers.ts";

let server: Server;
let sources: typeof import("../src/sources.ts");
let ci: typeof import("../src/sources/ci/extractor.ts");

before(async () => {
  server = await startOsv();
  process.env.SELFGUARD_HOME = mkdtempSync(join(tmpdir(), "sg-home-"));
  process.env.HOME = realpathSync(mkdtempSync(join(tmpdir(), "sg-user-")));
  process.env.SELFGUARD_NO_NOTIFY = "1";
  sources = await import("../src/sources.ts");
  ci = await import("../src/sources/ci/extractor.ts");
});
after(() => server.close());

const SHA = "0123456789abcdef0123456789abcdef01234567";

function put(root: string, rel: string, text: string): string {
  const file = join(root, rel);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, text);
  return file;
}

function repo(): string {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "sg-ci-")));
  mkdirSync(join(root, ".git"));
  return root;
}

test("files(): workflows and action files, bounded, no dependency folders or symlinks", () => {
  const root = repo();
  const wf = put(root, ".github/workflows/ci.yml", "on: push\n");
  const wf2 = put(root, ".github/workflows/release.yaml", "on: push\n");
  put(root, ".github/workflows/notes.txt", "x");
  put(root, ".github/workflows/old/nested.yml", "on: push\n");
  const local = put(root, ".github/actions/setup/action.yml", "runs: {}\n");
  const sub = put(root, "tools/lint/action.yaml", "runs: {}\n");
  put(root, "node_modules/some-action/action.yml", "runs: {}\n");
  put(root, "vendor/x/action.yml", "runs: {}\n");
  put(root, ".cache/x/action.yml", "runs: {}\n");
  put(root, "a/b/c/d/e/f/g/action.yml", "runs: {}\n");
  const outside = realpathSync(mkdtempSync(join(tmpdir(), "sg-ci-out-")));
  put(outside, "action.yml", "runs: {}\n");
  symlinkSync(outside, join(root, "linked"));

  const t = sources.repoTarget(root);
  assert.deepEqual(ci.GITHUB_ACTIONS.files(t), [wf, wf2, local, sub]);
  // The watcher also watches the folders of the composite actions found (no walk of its own).
  const found = ci.GITHUB_ACTIONS.files(t);
  assert.deepEqual(ci.GITHUB_ACTIONS.watch!(t, found), [join(root, ".github", "workflows"), dirname(local), dirname(sub)]);
  assert.deepEqual(ci.GITHUB_ACTIONS.watch!(t, []), [join(root, ".github", "workflows")]);
  // Check's markers: where a new workflow or action appears, never the git root itself.
  assert.deepEqual(ci.GITHUB_ACTIONS.markers!(t, found), [
    join(root, ".github", "workflows"), join(root, ".github"), join(root, ".github", "actions"), dirname(local), dirname(sub), join(root, "tools"),
  ]);
  assert.deepEqual(ci.GITHUB_ACTIONS.probe!(t), [wf, wf2]);
  assert.deepEqual(ci.GITHUB_ACTIONS.files(sources.machineTarget()), []);
  assert.deepEqual(ci.GITHUB_ACTIONS.watch!(sources.machineTarget(), []), []);
  const bare = repo();
  assert.deepEqual([ci.GITHUB_ACTIONS.files(sources.repoTarget(bare)), ci.GITHUB_ACTIONS.watch!(sources.repoTarget(bare), [])], [[], []]);
});

test("scanSources: tags matched locally, lines may be affected, bare SHAs unknown, malicious always", async () => {
  sources.resetSourceExtractors();
  sources.registerBuiltinExtractors();
  assert.deepEqual(sources.activeKinds().includes("ci"), true);
  const root = repo();
  const wf = put(
    root,
    ".github/workflows/ci.yml",
    [
      "on: [push]",
      "jobs:",
      "  a:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: tj-actions/changed-files@v45.0.7",
      "      - uses: tj-actions/changed-files@v46.0.1",
      "      - uses: tj-actions/changed-files@v45",
      `      - uses: tj-actions/changed-files@${SHA}`,
      `      - uses: tj-actions/changed-files@${SHA} # v46.0.1`,
      "      - uses: evil/action@v9.9.9",
      "      - uses: actions/checkout@v4",
      "      - uses: docker://alpine:3",
      "      - run: echo '${{ github.event.issue.title }}'",
    ].join("\n"),
  );
  const action = put(root, ".github/actions/setup/action.yml", "runs:\n  using: composite\n  steps:\n    - uses: tj-actions/changed-files@v45.0.7\n");

  osv.bodies.length = 0;
  const [out] = await sources.scanSources([{ kind: "ci", target: sources.repoTarget(root) }]);
  const rec = out!.record;
  assert.equal(rec.error, undefined);
  assert.deepEqual(rec.files.map((f) => f.path), [wf, action]);
  assert.equal(rec.skipped, 1, "the docker image");

  // Actions are never sent: they are matched in the local index of the ecosystem.
  assert.deepEqual(osv.bodies, [], "no querybatch for actions");

  const got = rec.findings.map((f) => `${f.id} ${f.name}@${f.version} ${f.certainty ?? "confirmed"} ${f.locations.map((l) => `${l.file === action ? "action" : "wf"}:${l.line}`).join(",")}`);
  assert.deepEqual(got.sort(), [
    "GHSA-mrrh-fwg8-r2c3 tj-actions/changed-files@0123456789ab version-unknown wf:9", // bare SHA: listed, with the fix
    "GHSA-mrrh-fwg8-r2c3 tj-actions/changed-files@45.0.7 confirmed wf:6,action:4",
    "GHSA-mrrh-fwg8-r2c3 tj-actions/changed-files@45.x may-be-affected wf:8",
    "MAL-2026-7 evil/action@9.9.9 may-be-affected wf:11",
  ]);
  const confirmed = rec.findings.find((f) => f.version === "45.0.7")!;
  assert.equal(confirmed.fixedIn, "46.0.1");
  assert.equal(rec.findings.find((f) => f.version === "0123456789ab")!.fixedIn, "46.0.1", "a bare SHA gets the fix to compare with");
  assert.equal(rec.findings.find((f) => f.id === "MAL-2026-7")!.severity, "malicious");
  assert.equal(rec.findings.find((f) => f.version === "45.x")!.pin, "v45");

  assert.deepEqual(
    rec.warnings.map((w) => `${w.rule} ${w.file === action ? "action" : "wf"}:${w.line}`),
    [
      "unpinned-action wf:6",
      "unpinned-action wf:7",
      "unpinned-action wf:8",
      "unpinned-action wf:11",
      "script-injection wf:14",
      "unpinned-action action:4",
    ],
  );
});

test("scanSources: a SHA's version comment is evaluated like the tag", async () => {
  sources.resetSourceExtractors();
  sources.registerSourceExtractor(ci.GITHUB_ACTIONS); // builtins register once per process
  const root = repo();
  put(root, ".github/workflows/a.yml", `jobs:\n  a:\n    steps:\n      - uses: tj-actions/changed-files@${SHA} # v45.0.7\n      - uses: tj-actions/changed-files@${SHA} # tag=v46.0.1\n`);
  const [out] = await sources.scanSources([{ kind: "ci", target: sources.repoTarget(root) }]);
  assert.deepEqual(out!.record.findings.map((f) => [f.version, f.certainty ?? "confirmed", f.locations[0]!.line]), [["45.0.7", "confirmed", 4]]);
  assert.deepEqual(out!.record.warnings, []);
  assert.deepEqual(out!.record.refs.map((r) => r.pin), ["0123456789ab", "0123456789ab"]);
});

test("where finds actions in workflows, case-insensitively, and says they come from CI", async () => {
  const root = repo();
  put(root, ".github/workflows/a.yml", "jobs:\n  a:\n    steps:\n      - uses: tj-actions/changed-files@v45.0.7\n");
  const [out] = await sources.scanSources([{ kind: "ci", target: sources.repoTarget(root) }]);
  sources.saveSource(out!.record);
  const api = await import("../src/api.ts");
  const r = api.whereUsed("TJ-Actions/Changed-Files");
  const hit = r.usedIn.find((u) => u.path === root)!;
  assert.equal(hit.source, "ci");
  assert.deepEqual(hit.versions, [{ version: "45.0.7", ecosystem: "GitHub Actions", direct: true, dev: false, vulnerable: true }]);
  assert.equal(api.whereUsed("tj-actions/changed-files", "npm").usedIn.length, 0);
});

test("the fixtures directory isn't read as workflows of this repo", () => {
  const here = realpathSync(join(dirname(new URL(import.meta.url).pathname), ".."));
  const files = ci.GITHUB_ACTIONS.files(sources.repoTarget(here));
  assert.ok(files.every((f) => !f.includes(join("test", "fixtures"))), files.join("\n"));
});
