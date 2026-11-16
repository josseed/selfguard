import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { findProject } from "../src/lockfile/detect.ts";

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

test("findProject: a folder is the same project from any subfolder (hook, scan and check agree)", () => {
  const r = mkdtempSync(join(tmpdir(), "sg-mixed-"));
  mkdirSync(join(r, ".git"));
  writeFileSync(join(r, "package-lock.json"), "{}");
  writeFileSync(join(r, "Cargo.lock"), "version = 3\n");
  mkdirSync(join(r, "crates", "foo"), { recursive: true });
  writeFileSync(join(r, "crates", "foo", "Cargo.toml"), "[package]\n");
  const fromRoot = findProject(r);
  assert.equal(fromRoot?.lockType, "npm");
  assert.deepEqual(findProject(join(r, "crates", "foo")), fromRoot);
});

test("discover and the home search skip Go testdata and module caches outside ~/go", async () => {
  const { discover } = await import("../src/discover.ts");
  const { discoverEverywhere } = await import("../src/everywhere.ts");
  const home = mkdtempSync(join(tmpdir(), "sg-evhome-"));
  const put = (rel: string, body = "module x\n") => {
    mkdirSync(join(home, rel, ".."), { recursive: true });
    writeFileSync(join(home, rel), body);
  };
  put("code/svc/.git/HEAD", "ref: refs/heads/main\n");
  put("code/svc/go.mod");
  put("code/svc/testdata/old/go.mod");
  put("dev/gopath/pkg/mod/github.com/x/y@v1.0.0/go.mod");
  put("code/py/__pypackages__/3.12/lib/uv.lock", "version = 1\n");
  const local = (await discover(home, { depth: 10 })).map((p) => p.root.slice(home.length + 1));
  assert.deepEqual(local, ["code/svc"]);
  const everywhere = (await discoverEverywhere({ home })).projects.map((p) => p.root.slice(home.length + 1));
  assert.deepEqual(everywhere, ["code/svc"]);
});

test("hook: a Python or Rust folder without a lockfile is watched until one appears", () => {
  const dir = mkdtempSync(join(tmpdir(), "sg-hookpy-"));
  writeFileSync(join(dir, "pyproject.toml"), "[project]\n");
  const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
  const env = { ...process.env, SELFGUARD_HOME: mkdtempSync(join(tmpdir(), "sg-hh-")) };
  const run = () => execFileSync(process.execPath, [cli, "hook-enter", "--dir", dir], { env, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
  assert.equal(run(), dir, "watches the folder itself");
  writeFileSync(join(dir, "uv.lock"), "version = 1\n");
  assert.equal(run(), join(dir, "uv.lock"), "then the new lockfile");
});
