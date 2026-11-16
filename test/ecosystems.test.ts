import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { findProject } from "../src/lockfile/detect.ts";
import { parseCargoLockfile } from "../src/lockfile/cargo.ts";
import { parseGoMod } from "../src/lockfile/gomod.ts";
import { parseLockfile, parseManifest } from "../src/lockfile/index.ts";
import { parsePoetryLockfile, parseUvLockfile, pyprojectDeps } from "../src/lockfile/python.ts";
import { parseToml } from "../src/lockfile/toml.ts";
import type { Dependency } from "../src/lockfile/types.ts";
import { evaluate } from "../src/match.ts";
import type { OsvVuln } from "../src/osv.ts";
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

// ---------- detection ----------

test("findProject: new lockfiles, nested crates resolve to the workspace, a JS package is not a Go module", () => {
  const root = mkdtempSync(join(tmpdir(), "sg-eco-"));
  mkdirSync(join(root, ".git"));
  writeFileSync(join(root, "go.mod"), "module x\n");
  mkdirSync(join(root, "web"));
  writeFileSync(join(root, "web", "package.json"), "{}");
  assert.equal(findProject(join(root, "web"))?.lockType, null, "package.json without a lockfile, not the go.mod above");
  assert.equal(findProject(root)?.lockType, "gomod");

  const ws = mkdtempSync(join(tmpdir(), "sg-cargo-"));
  writeFileSync(join(ws, "Cargo.lock"), "version = 3\n");
  mkdirSync(join(ws, "crates", "core"), { recursive: true });
  writeFileSync(join(ws, "crates", "core", "Cargo.toml"), "[package]\nname='core'\n");
  assert.deepEqual(findProject(join(ws, "crates", "core")), { root: ws, lockfile: join(ws, "Cargo.lock"), lockType: "cargo" });

  const py = mkdtempSync(join(tmpdir(), "sg-py-"));
  writeFileSync(join(py, "uv.lock"), "version = 1\n");
  writeFileSync(join(py, "package-lock.json"), "{}");
  assert.equal(findProject(py)?.lockType, "npm", "JavaScript first when a folder has both");
});

// ---------- matching ----------

test("evaluate: PyPI ECOSYSTEM ranges use PEP 440 and normalized names", () => {
  const v: OsvVuln = {
    id: "PYSEC-1",
    affected: [{ package: { ecosystem: "PyPI", name: "PyYAML" }, ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "5.4" }] }] }],
  };
  assert.deepEqual(evaluate(v, "pyyaml", "5.3.1", "PyPI"), { affected: true, fixedIn: "5.4" });
  assert.equal(evaluate(v, "pyyaml", "5.4", "PyPI").affected, false);
  assert.equal(evaluate(v, "pyyaml", "5.4rc1", "PyPI").affected, true, "rc sorts before the final release");
  assert.equal(evaluate(v, "pyyaml", "5.3.1", "npm").affected, false, "same name in another ecosystem");
  const listed: OsvVuln = { id: "X", affected: [{ package: { ecosystem: "PyPI", name: "a" }, versions: ["1.0"] }] };
  assert.equal(evaluate(listed, "a", "1.0.0", "PyPI").affected, true, "equivalent PEP 440 spelling");
});

test("evaluate: Go and crates.io SEMVER ranges", () => {
  const go: OsvVuln = {
    id: "GO-2022-0236",
    affected: [{ package: { ecosystem: "Go", name: "golang.org/x/net" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "0.0.0-20211209124913-491a49abca63" }] }] }],
  };
  assert.deepEqual(evaluate(go, "golang.org/x/net", "0.0.0-20210226172049-e18ecbb05110", "Go"), {
    affected: true,
    fixedIn: "0.0.0-20211209124913-491a49abca63",
  });
  assert.equal(evaluate(go, "golang.org/x/net", "0.1.0", "Go").affected, false);
  const crate: OsvVuln = {
    id: "RUSTSEC-2021-0003",
    affected: [{ package: { ecosystem: "crates.io", name: "smallvec" }, ranges: [{ type: "SEMVER", events: [{ introduced: "1.6.0" }, { fixed: "1.6.1" }] }] }],
  };
  assert.deepEqual(evaluate(crate, "smallvec", "1.6.0", "crates.io"), { affected: true, fixedIn: "1.6.1" });
  assert.equal(evaluate(crate, "smallvec", "0.6.13", "crates.io").affected, false);
});

test("discover finds Python, Rust and Go projects and skips Go's module cache and site-packages", async () => {
  const { discover } = await import("../src/discover.ts");
  const root = mkdtempSync(join(tmpdir(), "sg-disc-"));
  const put = (rel: string, body = "") => {
    mkdirSync(join(root, rel, ".."), { recursive: true });
    writeFileSync(join(root, rel), body);
  };
  put("api/uv.lock");
  put("site/poetry.lock");
  put("cli/Cargo.lock");
  put("svc/go.mod", "module svc\n");
  put("go/pkg/mod/github.com/x/y@v1.0.0/go.mod", "module y\n");
  put("venv2/lib/python3.12/site-packages/pkg/uv.lock");
  const found = (await discover(root, { depth: 8 })).map((p) => [p.root.slice(root.length + 1), p.lockType]).sort();
  assert.deepEqual(found, [["api", "uv"], ["cli", "cargo"], ["site", "poetry"], ["svc", "gomod"]]);
});

test("the reader lists new lockfiles and serves pyproject.toml, but not Go's module cache", async () => {
  const { answerReader } = await import("../src/reader.ts");
  const { parseFetch, parseList } = await import("../src/remote.ts");
  const home = mkdtempSync(join(tmpdir(), "sg-rhome-"));
  mkdirSync(join(home, "code", "site"), { recursive: true });
  mkdirSync(join(home, "code", "pkg", "mod", "m"), { recursive: true });
  writeFileSync(join(home, "code", "site", "poetry.lock"), "[metadata]\n");
  writeFileSync(join(home, "code", "site", "pyproject.toml"), "[project]\n");
  writeFileSync(join(home, "code", "pkg", "mod", "m", "go.mod"), "module m\n");
  const ctx = { scope: home, home };
  const list = parseList(await answerReader(`SGREQ1 list\n3\t${home}/code\n`, ctx), { host: "x", transport: "share" } as any);
  assert.deepEqual(list.projects.map((p) => [p.root.split("/code/")[1], p.lockType]), [["site", "poetry"]]);
  const t = { host: "x", transport: "share" } as any;
  const file = `${list.projects[0]!.root}/pyproject.toml`;
  const fetched = parseFetch(await answerReader(`SGREQ1 fetch\n${file}\n`, ctx), t);
  assert.equal(fetched.get(file)?.toString(), "[project]\n");
});
