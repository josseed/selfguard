import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { parseCargoLockfile } from "../src/lockfile/cargo.ts";
import { parseGoMod } from "../src/lockfile/gomod.ts";
import { parseLockfile, parseManifest } from "../src/lockfile/index.ts";
import { parsePoetryLockfile, parseUvLockfile, pyprojectDeps } from "../src/lockfile/python.ts";
import { parseToml } from "../src/lockfile/toml.ts";
import type { Dependency } from "../src/lockfile/types.ts";
import { compareVersions, isValidVersion } from "../src/versions.ts";

const fixture = (p: string) => readFileSync(new URL(`./fixtures/multi/${p}`, import.meta.url), "utf8");
const byKey = (deps: Dependency[]) => Object.fromEntries(deps.map((d) => [`${d.name}@${d.version}`, d]));

// ---------- TOML ----------

test("toml: tables, arrays of tables, inline tables, strings and comments", () => {
  const doc = parseToml(`
# comment
title = "a \\"quoted\\" \\u00e9" # trailing
lit = 'C:\\path'
multi = """
line1 \\
  line2"""
n = 1_000
f = 1.5
yes = true
date = 1979-05-27T07:32:00Z
arr = [ 1, [2, 3], "x", ] # trailing comma
"quoted.key" = 1
a.b.c = "dotted"
[[pkg]]
name = "one"
src = { registry = "https://x", n = 2 }
[pkg.sub]
k = "v"
[[pkg]]
name = "two"
deps = [
  { name = "x" }, # comment inside an array
  { name = "y", marker = "os == 'nt'" },
]
`);
  assert.equal(doc.title, 'a "quoted" é');
  assert.equal(doc.lit, "C:\\path");
  assert.equal(doc.multi, "line1 line2");
  assert.equal(doc.n, 1000);
  assert.equal(doc.f, 1.5);
  assert.equal(doc.yes, true);
  assert.equal(doc.date, "1979-05-27T07:32:00Z");
  assert.deepEqual(doc.arr, [1, [2, 3], "x"]);
  assert.equal(doc["quoted.key"], 1);
  assert.equal(((doc.a as any).b as any).c, "dotted");
  const pkg = doc.pkg as any[];
  assert.equal(pkg.length, 2);
  assert.equal(pkg[0].src.registry, "https://x");
  assert.equal(pkg[0].sub.k, "v");
  assert.equal(pkg[1].deps[1].marker, "os == 'nt'");
});

test("toml: malformed input throws, __proto__ is plain data", () => {
  assert.throws(() => parseToml('a = "unterminated'));
  assert.throws(() => parseToml("[table"));
  assert.throws(() => parseToml("a = [1, 2"));
  assert.throws(() => parseToml("= 1"));
  assert.throws(() => parseToml(`${"a = ".repeat(1)}${"[".repeat(200)}`));
  const doc = parseToml('__proto__ = "x"\n[constructor]\nprototype = 1');
  assert.equal(({} as any).prototype, undefined);
  assert.equal(Object.getPrototypeOf(doc), null);
});

// ---------- versions ----------

test("PEP 440 ordering", () => {
  const ordered = ["1.0.dev0", "1.0a1", "1.0a2.dev1", "1.0a2", "1.0b1", "1.0rc1", "1.0", "1.0+local.1", "1.0.post1.dev0", "1.0.post1", "1.0.1", "1!0.1"];
  for (let i = 1; i < ordered.length; i++) {
    assert.equal(compareVersions("PyPI", ordered[i - 1]!, ordered[i]!), -1, `${ordered[i - 1]} < ${ordered[i]}`);
  }
  assert.equal(compareVersions("PyPI", "1.0", "1.0.0"), 0);
  assert.equal(compareVersions("PyPI", "1.0RC1", "1.0rc1"), 0);
  assert.equal(compareVersions("PyPI", "2023.7.22", "2023.11.17"), -1);
  assert.equal(isValidVersion("PyPI", "not a version"), false);
  assert.equal(isValidVersion("PyPI", "1.0-1"), true, "implicit post release");
});

test("Go pseudo-versions and +incompatible are SemVer", () => {
  assert.equal(compareVersions("Go", "0.0.0-20210226172049-e18ecbb05110", "0.0.0-20211209124913-491a49abca63"), -1);
  assert.equal(compareVersions("Go", "0.0.0-20210226172049-e18ecbb05110", "0.1.0"), -1);
  assert.equal(isValidVersion("Go", "2.0.0+incompatible"), true);
});

// ---------- parsers ----------

test("uv.lock: registry packages, direct/dev from the project, git source skipped", () => {
  const { deps, skipped } = parseUvLockfile(fixture("uv.fixture.lock"));
  const m = byKey(deps);
  assert.deepEqual(Object.keys(m).sort(), [
    "certifi@2023.7.22", "iniconfig@2.0.0", "pytest@7.4.0", "pyyaml@5.3.1", "requests@2.31.0", "urllib3@1.26.5",
  ]);
  assert.equal(skipped, 1, "git dependency");
  assert.ok(deps.every((d) => d.ecosystem === "PyPI"));
  assert.equal(m["requests@2.31.0"]!.direct, true);
  assert.equal(m["requests@2.31.0"]!.dev, false);
  assert.equal(m["pyyaml@5.3.1"]!.direct, true, "extras are direct");
  assert.equal(m["pyyaml@5.3.1"]!.dev, false);
  assert.equal(m["urllib3@1.26.5"]!.direct, false);
  assert.equal(m["urllib3@1.26.5"]!.dev, false);
  assert.equal(m["pytest@7.4.0"]!.direct, true);
  assert.equal(m["pytest@7.4.0"]!.dev, true);
  assert.equal(m["iniconfig@2.0.0"]!.dev, true, "only reachable from dev groups");
});

test("poetry.lock + pyproject.toml: direct and dev from groups, directory source skipped", () => {
  const manifest = parseManifest("poetry", fixture("pyproject.fixture.toml"));
  const { deps, skipped } = parsePoetryLockfile(fixture("poetry.fixture.lock"), manifest);
  const m = byKey(deps);
  assert.deepEqual(Object.keys(m).sort(), ["Django@3.2.0", "asgiref@3.7.2", "black@22.1.0", "click@8.1.7", "pytz@2023.3", "sqlparse@0.4.1"]);
  assert.equal(skipped, 1);
  assert.equal(m["Django@3.2.0"]!.direct, true, "names compare PEP 503-normalized");
  assert.equal(m["sqlparse@0.4.1"]!.direct, false);
  assert.equal(m["sqlparse@0.4.1"]!.dev, false);
  assert.equal(m["black@22.1.0"]!.dev, true);
  assert.equal(m["click@8.1.7"]!.dev, true);
  // Without pyproject.toml: nothing is direct, nothing is assumed dev.
  const bare = byKey(parsePoetryLockfile(fixture("poetry.fixture.lock")).deps);
  assert.equal(bare["black@22.1.0"]!.dev, false);
  assert.equal(bare["Django@3.2.0"]!.direct, false);
});

test("poetry.lock: Poetry 2 groups and old categories", () => {
  const lock = `[[package]]\nname = "a"\nversion = "1.0"\ngroups = ["dev"]\n\n[[package]]\nname = "b"\nversion = "2.0"\ncategory = "main"\n`;
  const m = byKey(parsePoetryLockfile(lock).deps);
  assert.equal(m["a@1.0"]!.dev, true);
  assert.equal(m["b@2.0"]!.dev, false);
});

test("pyproject.toml: PEP 621, optional deps and dependency groups", () => {
  const { prod, dev } = pyprojectDeps(
    parseToml(`[project]\ndependencies = ["Requests[socks] >=2; python_version<'3.8'", "attrs"]\n[project.optional-dependencies]\nfast = ["ujson"]\n[dependency-groups]\ntest = ["PyTest>=7"]\n`),
  );
  assert.deepEqual([...prod].sort(), ["attrs", "requests", "ujson"]);
  assert.deepEqual([...dev], ["pytest"]);
});

test("Cargo.lock: crates.io only, workspace members' deps are direct", () => {
  const { deps, skipped } = parseCargoLockfile(fixture("cargo.fixture.lock"));
  const m = byKey(deps);
  assert.deepEqual(Object.keys(m).sort(), ["aho-corasick@0.7.18", "memchr@2.4.1", "regex@1.5.4", "smallvec@0.6.13", "smallvec@1.6.0"]);
  assert.equal(skipped, 2, "git crate and alternate registry");
  assert.ok(deps.every((d) => d.ecosystem === "crates.io" && d.dev === false));
  assert.equal(m["regex@1.5.4"]!.direct, true);
  assert.equal(m["smallvec@1.6.0"]!.direct, true);
  assert.equal(m["smallvec@0.6.13"]!.direct, true, "direct dep of another workspace member");
  assert.equal(m["memchr@2.4.1"]!.direct, false);
});

test("go.mod: require blocks, indirect, replace and versions without v", () => {
  const { deps, skipped } = parseGoMod(fixture("gomod.fixture.mod"));
  const m = byKey(deps);
  assert.deepEqual(Object.keys(m).sort(), [
    "github.com/gin-gonic/gin@1.7.0",
    "github.com/new/thing@1.3.0",
    "github.com/quoted/mod@0.3.1",
    "github.com/single/line@2.0.0+incompatible",
    "golang.org/x/net@0.0.0-20210226172049-e18ecbb05110",
  ]);
  assert.equal(skipped, 1, "replaced by a local folder");
  assert.equal(m["github.com/gin-gonic/gin@1.7.0"]!.direct, true);
  assert.equal(m["golang.org/x/net@0.0.0-20210226172049-e18ecbb05110"]!.direct, false);
  assert.equal(m["github.com/quoted/mod@0.3.1"]!.direct, false);
  assert.ok(deps.every((d) => d.ecosystem === "Go"));
  assert.throws(() => parseGoMod("require x v1.0.0\n"), /module/);
});

test("garbage is rejected by every new parser", () => {
  for (const type of ["uv", "poetry", "cargo"] as const) {
    assert.throws(() => parseLockfile(type, "this is [not toml"), type);
    assert.throws(() => parseLockfile(type, "[something]\nx = 1\n"), type);
  }
  assert.throws(() => parseLockfile("gomod", "{}"));
});
