// `check` (run by the watcher on every lockfile change) must not walk repos: it stats what the
// source records hold (files and markers) and lists files again only when a marker moved.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, before, beforeEach, test } from "node:test";
import { startOsv } from "./sources-helpers.ts";

let server: Server;
let sources: typeof import("../src/sources.ts");
let api: typeof import("../src/api.ts");
/** files() calls of the GitHub Actions extractor, per git root. */
const calls: string[] = [];

before(async () => {
  server = await startOsv();
  process.env.SELFGUARD_HOME = mkdtempSync(join(tmpdir(), "sg-home-"));
  process.env.HOME = realpathSync(mkdtempSync(join(tmpdir(), "sg-user-")));
  process.env.SELFGUARD_NO_NOTIFY = "1";
  process.env.SELFGUARD_NO_LAUNCHD = "1";
  sources = await import("../src/sources.ts");
  api = await import("../src/api.ts");
  const { GITHUB_ACTIONS } = await import("../src/sources/ci/extractor.ts");
  sources.resetSourceExtractors();
  sources.registerSourceExtractor({
    ...GITHUB_ACTIONS,
    files: (t) => {
      calls.push(t.root);
      return GITHUB_ACTIONS.files(t);
    },
  });
});
after(() => server.close());
beforeEach(() => {
  calls.length = 0;
});

function put(root: string, rel: string, text: string): string {
  const file = join(root, rel);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, text);
  return file;
}

const WORKFLOW = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n";

/** A git repo with a lockfile, some depth and (optionally) a workflow. */
function repo(workflow = true): string {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "sg-chk-")));
  put(root, ".git/HEAD", "ref: refs/heads/main\n");
  put(root, "package.json", JSON.stringify({ name: "app", dependencies: { lodash: "4.17.21" } }));
  put(root, "package-lock.json", JSON.stringify({ lockfileVersion: 3, packages: { "": { dependencies: { lodash: "4.17.21" } }, "node_modules/lodash": { version: "4.17.21" } } }));
  mkdirSync(join(root, "src", "a", "b"), { recursive: true });
  if (workflow) put(root, ".github/workflows/ci.yml", WORKFLOW);
  return root;
}

const ciRecord = (root: string) => sources.loadSource("ci", "repo", root);

test("nothing changed: check lists no files (no walk)", async () => {
  const root = repo();
  await api.scanPath(root);
  assert.ok(ciRecord(root)!.markers!.some((m) => m.path === join(root, ".github", "workflows")), "markers recorded");
  calls.length = 0;
  assert.deepEqual(await api.check(), { rescanned: [], errors: [] });
  assert.deepEqual(await api.check(), { rescanned: [], errors: [] });
  assert.deepEqual(calls, []);
});

test("a new workflow is seen through the folder's mtime, and only that repo is listed again", async () => {
  const root = repo();
  const other = repo();
  await api.scanPath(root);
  await api.scanPath(other);
  calls.length = 0;
  put(root, ".github/workflows/release.yml", "jobs:\n  a:\n    steps:\n      - uses: actions/cache@v4\n");
  await api.check();
  assert.deepEqual(calls, [root]);
  const rec = ciRecord(root)!;
  assert.equal(rec.files.length, 2);
  assert.ok(rec.refs.some((r) => r.name === "actions/cache"));
  calls.length = 0;
  await api.check();
  assert.deepEqual(calls, [], "markers updated: no listing on the next check");
});

test("an edited workflow is re-read from the record without listing files", async () => {
  const root = repo();
  await api.scanPath(root);
  calls.length = 0;
  put(root, ".github/workflows/ci.yml", "jobs:\n  a:\n    steps:\n      - uses: actions/setup-node@v4.0.0\n");
  await api.check();
  assert.deepEqual(calls, []);
  assert.deepEqual(ciRecord(root)!.refs.map((r) => r.name), ["actions/setup-node"]);
});

test("a removed workflow is noticed", async () => {
  const root = repo();
  const extra = put(root, ".github/workflows/extra.yml", WORKFLOW);
  await api.scanPath(root);
  assert.equal(ciRecord(root)!.files.length, 2);
  rmSync(extra);
  await api.check();
  assert.equal(ciRecord(root)!.files.length, 1);
});

test("a marker that moved without a file change lists once, then not again", async () => {
  const root = repo();
  await api.scanPath(root);
  calls.length = 0;
  put(root, ".github/dependabot.yml", "version: 2\n"); // `.github` changes, no workflow added
  await api.check();
  assert.deepEqual(calls, [root]);
  calls.length = 0;
  await api.check();
  assert.deepEqual(calls, []);
});

test("without a record: a repo's first workflow is probed cheaply; no workflows, no listing", async () => {
  const root = repo(false);
  await api.scanPath(root);
  assert.equal(ciRecord(root), null);
  calls.length = 0;
  await api.check();
  assert.deepEqual(calls, [], "no workflow file: nothing listed");
  put(root, ".github/workflows/ci.yml", WORKFLOW);
  await api.check();
  assert.deepEqual(calls, [root]);
  assert.equal(ciRecord(root)!.files.length, 1);
});

test("a record from 0.10.0 (no markers) is listed once, then gets markers", async () => {
  const root = repo();
  await api.scanPath(root);
  const { markers: _m, ...old } = ciRecord(root)!;
  sources.saveSource(old);
  calls.length = 0;
  await api.check();
  assert.deepEqual(calls, [root]);
  assert.ok(ciRecord(root)!.markers);
  calls.length = 0;
  await api.check();
  assert.deepEqual(calls, []);
});
