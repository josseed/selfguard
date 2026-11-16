import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { STATIC } from "../src/ui/assets.ts";

const SRC = fileURLToPath(new URL("../src/", import.meta.url));
const MAC = fileURLToPath(new URL("../macos/Sources/", import.meta.url));
const MAX_LINES = 300;

function files(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? files(join(dir, e.name)) : /\.(ts|js|mjs|css|html|swift)$/.test(e.name) ? [join(dir, e.name)] : [],
  );
}

test(`source files stay under ${MAX_LINES} lines (split modules by responsibility)`, () => {
  const long = [...files(SRC), ...files(MAC)]
    .map((f) => ({ f: relative(join(SRC, ".."), f), n: readFileSync(f, "utf8").split("\n").length - 1 }))
    .filter(({ n }) => n > MAX_LINES)
    .map(({ f, n }) => `${f} (${n})`);
  assert.deepEqual(long, []);
});

test("every dashboard file is in the server's allowlist (anything else is a 404)", () => {
  const served = new Set(Object.values(STATIC).map((a) => a.file));
  const onDisk = files(join(SRC, "ui", "static")).map((f) => relative(join(SRC, "ui", "static"), f));
  assert.deepEqual(onDisk.filter((f) => !served.has(f)), []);
});
