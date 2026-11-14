import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { discover } from "../src/discover.ts";

function tree(): string {
  const root = mkdtempSync(join(tmpdir(), "sg-disc-"));
  const file = (p: string, body = "{}") => {
    mkdirSync(join(root, p, ".."), { recursive: true });
    writeFileSync(join(root, p), body);
  };
  file("app/package-lock.json");
  file("app/package.json");
  file("app/packages/ui/package.json"); // monorepo package: belongs to app
  file("app/node_modules/dep/package-lock.json");
  file("clients/acme/web/pnpm-lock.yaml");
  file("lib-no-lock/package.json");
  mkdirSync(join(root, "lib-no-lock/.git"));
  file("scratch/package.json"); // no lockfile, not a git root: not a project
  file("tool/examples/demo/package-lock.json");
  file(".hidden/x/package-lock.json");
  file("a/b/c/d/deep/package-lock.json");
  symlinkSync(join(root, "app"), join(root, "link-to-app"));
  return root;
}

test("descends everywhere except dependency dirs, hidden dirs and symlinks", async () => {
  const root = tree();
  const found = (await discover(root, { depth: 5 })).map((p) => p.root.slice(root.length + 1)).sort();
  assert.deepEqual(found, ["a/b/c/d/deep", "app", "clients/acme/web", "lib-no-lock", "tool/examples/demo"]);
});

test("finds nested projects inside a project and honors excludes", async () => {
  const root = tree();
  writeFileSync(join(root, "app/packages/ui/package-lock.json"), "{}"); // independent sub-project
  const found = (await discover(root, { depth: 5, exclude: [join(root, "tool")] })).map((p) => p.root.slice(root.length + 1));
  assert.ok(found.includes("app") && found.includes("app/packages/ui"));
  assert.ok(!found.includes("tool/examples/demo"), "excluded subtree");
});

test("depth limits how far it looks", async () => {
  const root = tree();
  const shallow = await discover(root, { depth: 1 });
  assert.equal(shallow.some((p) => p.root.endsWith("clients/acme/web")), false);
  const deep = await discover(root, { depth: 6 });
  assert.equal(deep.some((p) => p.root.endsWith("a/b/c/d/deep")), true);
});

test("respects the directory budget", async () => {
  const root = tree();
  assert.ok((await discover(root, { depth: 5, maxDirs: 2 })).length <= 1);
  // a project inside node_modules never shows up
  assert.ok(!(await discover(root, { depth: 6 })).some((p) => p.root.includes("node_modules")));
});
