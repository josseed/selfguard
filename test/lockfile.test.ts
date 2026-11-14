import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { findProject } from "../src/lockfile/detect.ts";
import { parseNpmLockfile } from "../src/lockfile/npm.ts";
import type { Dependency } from "../src/lockfile/types.ts";

const fixture = (p: string) => readFileSync(new URL(`./fixtures/${p}`, import.meta.url), "utf8");
const byKey = (deps: Dependency[]) =>
  Object.fromEntries(deps.map((d) => [`${d.name}@${d.version}`, d]));

test("lockfile v3: aliases, workspaces, nesting, dev, git deps", () => {
  const { deps, skipped } = parseNpmLockfile(fixture("v3/lockfile.fixture.json"));
  const m = byKey(deps);
  assert.deepEqual(Object.keys(m).sort(), [
    "left-pad@1.3.0", "lodash@4.17.20", "lodash@4.17.21", "loose-envify@1.4.0", "minimist@1.2.5", "react@18.2.0",
  ]);
  assert.equal(m["left-pad@1.3.0"]!.direct, true, "alias resolves to real name and stays direct");
  assert.equal(m["lodash@4.17.20"]!.direct, true);
  assert.equal(m["lodash@4.17.21"]!.direct, false, "nested copy is transitive");
  assert.equal(m["react@18.2.0"]!.direct, true, "workspace deps are direct");
  assert.equal(m["loose-envify@1.4.0"]!.direct, false);
  assert.equal(m["minimist@1.2.5"]!.dev, true);
  assert.equal(skipped, 2, "git dep + non-semver version");
});

test("lockfile v1: nested deps, aliases, direct from package.json", () => {
  const manifest = JSON.parse(fixture("v1/manifest.fixture.json"));
  const { deps, skipped } = parseNpmLockfile(fixture("v1/lockfile.fixture.json"), manifest);
  const m = byKey(deps);
  assert.deepEqual(Object.keys(m).sort(), ["debug@2.6.8", "express@4.16.0", "mocha@5.0.0", "qs@6.11.0", "qs@6.5.1"]);
  assert.equal(m["express@4.16.0"]!.direct, true);
  assert.equal(m["qs@6.11.0"]!.direct, false);
  assert.equal(m["mocha@5.0.0"]!.dev, true);
  assert.equal(skipped, 1);
});

test("rejects garbage and is not fooled by __proto__ keys", () => {
  assert.throws(() => parseNpmLockfile("[]"));
  assert.throws(() => parseNpmLockfile("{}"));
  const evil = '{"lockfileVersion":3,"packages":{"node_modules/__proto__":{"version":"1.0.0"}}}';
  const { deps } = parseNpmLockfile(evil);
  assert.equal(deps[0]?.name, "__proto__");
  assert.equal(({} as Record<string, unknown>).version, undefined);
});

test("findProject prefers nearest lockfile, stops at git root and home", () => {
  const base = mkdtempSync(join(tmpdir(), "sg-detect-"));
  const repo = join(base, "home", "mono");
  const pkg = join(repo, "packages", "ui", "src");
  mkdirSync(pkg, { recursive: true });
  mkdirSync(join(repo, ".git"));
  writeFileSync(join(repo, "package.json"), "{}");
  writeFileSync(join(repo, "package-lock.json"), "{}");
  writeFileSync(join(repo, "packages", "ui", "package.json"), "{}");
  // a lockfile above the git root must not be picked up
  writeFileSync(join(base, "home", "package-lock.json"), "{}");

  const home = join(base, "home");
  assert.deepEqual(findProject(pkg, home), { root: repo, lockfile: join(repo, "package-lock.json"), lockType: "npm" });

  const lone = join(home, "lone");
  mkdirSync(join(lone, ".git"), { recursive: true });
  writeFileSync(join(lone, "package.json"), "{}");
  assert.deepEqual(findProject(lone, home), { root: lone, lockfile: null, lockType: null });
  assert.equal(findProject(home, home), null);
});
