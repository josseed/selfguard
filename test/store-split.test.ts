// Records are stored in two files: a small head that listings read, and the dependency list.
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { before, test } from "node:test";

let store: typeof import("../src/store.ts");
let dir: string;
const rec = (path: string) => ({
  schema: 1 as const, path, lockfile: `${path}/package-lock.json`, lockType: "npm" as const, lockHash: "h", lockMtimeMs: 1, lockSize: 2,
  registeredAt: "2026-01-01T00:00:00Z", scannedAt: null, skipped: 0, findings: [],
  deps: [{ name: "a", version: "1.0.0", direct: true, dev: false }, { name: "b", version: "2.0.0", direct: false, dev: false }],
  seen: { "X|npm:a@1.0.0": "2026-01-01T00:00:00Z" },
});

before(async () => {
  process.env.SELFGUARD_HOME = mkdtempSync(join(tmpdir(), "sg-store-"));
  store = await import("../src/store.ts");
  dir = join(process.env.SELFGUARD_HOME, "repos");
});

test("the head has no dependency list; it's read only when used", () => {
  store.saveRepo(rec("/code/a") as never);
  const files = readdirSync(dir).sort();
  assert.equal(files.length, 2);
  const head = JSON.parse(readFileSync(join(dir, files.find((f) => !f.endsWith(".deps.json"))!), "utf8"));
  assert.equal(head.deps, undefined);
  assert.equal(head.seen, undefined);
  assert.equal(head.packages, 2);
  const [r] = store.listRepos();
  assert.equal(store.packagesOf(r!), 2);
  assert.deepEqual(Object.keys(r!).includes("deps"), false, "not loaded by listing");
  assert.equal(r!.deps.length, 2);
  assert.deepEqual(r!.seen, { "X|npm:a@1.0.0": "2026-01-01T00:00:00Z" });
  assert.equal(store.listRepos().length, 1, "the body file isn't a record");
});

test("saving keeps an unread body, and a spread copy doesn't lose it", () => {
  const r = store.loadRepo("/code/a")!;
  r.findings = [];
  store.saveRepo(r); // body never read
  store.saveRepo({ ...store.loadRepo("/code/a")!, branch: "main" }); // `deps` not copied
  const again = store.loadRepo("/code/a")!;
  assert.equal(again.branch, "main");
  assert.equal(again.deps.length, 2);
  assert.ok(again.seen);
});

test("records of the old single-file format load as they are and split on save", () => {
  const old = rec("/code/old");
  const file = join(dir, `${createHash("sha256").update("/code/old").digest("hex").slice(0, 40)}.json`);
  writeFileSync(file, JSON.stringify(old));
  const r = store.loadRepo("/code/old")!;
  assert.equal(r.deps.length, 2);
  store.saveRepo(r);
  assert.equal(JSON.parse(readFileSync(file, "utf8")).deps, undefined);
  assert.ok(existsSync(file.replace(/\.json$/, ".deps.json")));
  assert.equal(store.loadRepo("/code/old")!.deps.length, 2);
  assert.ok(store.forgetRepo("/code/old"));
  assert.ok(!existsSync(file.replace(/\.json$/, ".deps.json")), "forget removes both files");
});
