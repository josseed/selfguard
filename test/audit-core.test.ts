// Security audit regressions: hostile project files (devices, FIFOs, symlinks, huge files),
// exclusions that would switch selfguard off, alert-reducing MCP tools, npm/uv/pipx flag values
// taken for package names, parse errors quoting lockfiles, and worktree pointers leaving home.
import assert from "node:assert/strict";
import { execFile, execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import type { SourceWarning } from "../src/sources/types.ts";
import { copyFixture } from "./helpers.ts";
import { osv, startOsv } from "./sources-helpers.ts";

const CLI = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
const src = (f: string): string => new URL(`../src/${f}`, import.meta.url).href;
const run = promisify(execFile);

const tmp = (prefix: string): string => realpathSync(mkdtempSync(join(tmpdir(), prefix)));
const home = tmp("sg-audit-home-");
const state = join(home, ".sg-state");
process.env.HOME = home;
process.env.SELFGUARD_HOME = state;
process.env.SELFGUARD_NO_NOTIFY = "1";
process.env.SELFGUARD_NO_LAUNCHD = "1";

let server: Server;
let api: typeof import("../src/api.ts");
let scan: typeof import("../src/scan.ts");
let tools: typeof import("../src/mcp/tools.ts");
let launchers: typeof import("../src/sources/agents/launchers.ts");
let store: typeof import("../src/sources/store.ts");
let warnings: typeof import("../src/sources/warnings.ts");
let everywhere: typeof import("../src/everywhere.ts");

before(async () => {
  server = await startOsv();
  api = await import("../src/api.ts");
  scan = await import("../src/scan.ts");
  tools = await import("../src/mcp/tools.ts");
  launchers = await import("../src/sources/agents/launchers.ts");
  store = await import("../src/sources/store.ts");
  warnings = await import("../src/sources/warnings.ts");
  everywhere = await import("../src/everywhere.ts");
});
after(() => server.close());

/** A project dir with the v3 fixture; `swap` replaces one of its files (a symlink, a FIFO…). */
function project(swap?: { file: "package.json" | "package-lock.json"; make: (path: string) => void }): string {
  const dir = mkdtempSync(join(home, "proj-"));
  copyFixture("v3", dir);
  if (swap) {
    rmSync(join(dir, swap.file));
    swap.make(join(dir, swap.file));
  }
  return dir;
}
const fifo = (p: string): void => void execFileSync("mkfifo", [p]);
const devZero = (p: string): void => symlinkSync("/dev/zero", p);

/**
 * Scan (no network: prepareProjects) and read manifest names in a child that is killed after
 * `ms`, so a hang (FIFO) or an endless read (/dev/zero) fails the test instead of the run.
 */
function scanInChild(dirs: string[], ms: number): Array<{ error: string | null; deps: number; name: string | null }> {
  const code = `
    import { prepareProjects } from ${JSON.stringify(src("scan.ts"))};
    import { manifestName } from ${JSON.stringify(src("canonical.ts"))};
    const dirs = ${JSON.stringify(dirs)};
    const { inventories } = prepareProjects(dirs.map((root) => ({ root, lockfile: root + "/package-lock.json", lockType: "npm" })));
    console.log(JSON.stringify(inventories.map(({ record }) => ({ error: record.error ?? null, deps: record.deps.length, name: manifestName(record) }))));
  `;
  const r = spawnSync(process.execPath, ["--input-type=module", "-e", code], { env: process.env, encoding: "utf8", timeout: ms });
  assert.equal(r.signal, null, `the scan hung or ran away (killed after ${ms} ms)`);
  assert.equal(r.status, 0, r.stderr);
  return JSON.parse(r.stdout);
}

test("scan: a manifest or lockfile that is /dev/zero never streams forever", { timeout: 20_000 }, () => {
  const [manifest, lock] = scanInChild([project({ file: "package.json", make: devZero }), project({ file: "package-lock.json", make: devZero })], 4_000);
  assert.equal(manifest!.error, null, "the lockfile is still scanned");
  assert.ok(manifest!.deps > 0);
  assert.equal(manifest!.name, null, "copy detection reads no name from it");
  assert.match(lock!.error ?? "", /lockfile unreadable, too large \(over 50 MB\) or not a regular file/);
});

test("scan: a FIFO manifest or lockfile can't hang the scan (and its project lock)", { timeout: 30_000 }, () => {
  const [manifest, lock] = scanInChild([project({ file: "package.json", make: fifo }), project({ file: "package-lock.json", make: fifo })], 10_000);
  assert.equal(manifest!.error, null);
  assert.ok(manifest!.deps > 0);
  assert.equal(manifest!.name, null);
  assert.match(lock!.error ?? "", /not a regular file/);
});

test("scan: symlinked and oversized lockfiles are refused; the whole-home walk's small reads skip FIFOs", async () => {
  const real = project();
  const linked = project({ file: "package-lock.json", make: (p) => symlinkSync(join(real, "package-lock.json"), p) });
  const huge = project();
  truncateSync(join(huge, "package-lock.json"), scan.MAX_LOCKFILE_BYTES + 1); // sparse: no disk used
  const { inventories } = scan.prepareProjects([real, linked, huge].map((root) => ({ root, lockfile: join(root, "package-lock.json"), lockType: "npm" as const })));
  const [ok, link, big] = inventories.map((i) => i.record);
  assert.equal(ok!.error, undefined);
  assert.match(link!.error ?? "", /not a regular file/, "symlinks are refused, as discovery and the remote readers do");
  assert.match(big!.error ?? "", /too large/);
  assert.equal(scan.lockState(join(linked, "package-lock.json")), null);
  assert.equal(scan.MAX_LOCKFILE_BYTES, 50 * 1024 * 1024, "same cap as a file fetched from another machine");

  const { readSmall } = await import("../src/everywhere/rules.ts");
  const pipe = join(home, "gitignore-fifo");
  fifo(pipe);
  assert.equal(readSmall(pipe), null);
  assert.equal(readSmall("/dev/zero"), null);
});

test("parse errors: the line of a JSON error, never a quote of the lockfile", async () => {
  const dir = project();
  const lock = [
    "{",
    '  "name": "x",',
    '  "lockfileVersion": 3,',
    '  "packages": {',
    '    "node_modules/a": { "version": "1.0.0", "resolved": https://u:SECRET_TOKEN_1@registry.example/a.tgz }',
    "  }",
    "}",
  ].join("\n");
  writeFileSync(join(dir, "package-lock.json"), lock);
  const rec = scan.prepareProjects([{ root: dir, lockfile: join(dir, "package-lock.json"), lockType: "npm" }]).inventories[0]!.record;
  assert.equal(rec.error, "could not parse lockfile: invalid JSON at line 5");

  // Every V8 message form: with a position, quoting the start, the middle or the end, the end of input.
  const msg = (text: string): string => {
    try {
      JSON.parse(text);
    } catch (e) {
      const m = scan.parseErrorMessage(e, text);
      assert.doesNotMatch(m, /SECRET|tok/);
      return m;
    }
    throw new Error("parsed");
  };
  assert.equal(msg('{\n"a": 1\n"tok": "SECRET_2"}'), "invalid JSON at line 3");
  assert.equal(msg('{"a": tok_SECRET_3456789012345,\n"b": 1}'), "invalid JSON at line 1");
  assert.equal(msg('{\n\n\n"a": 1,\n"b": "x",\n"c": tok_SECRET_4}'), "invalid JSON at line 6");
  assert.equal(msg('{\n"a": [1,\n2,\n'), "invalid JSON at line 4");
  assert.equal(msg("[tok_SECRET]"), "invalid JSON", "short input: V8 quotes all of it, no position");
  assert.equal(scan.parseErrorMessage(new Error("TOML line 3: expected ="), ""), "TOML line 3: expected =", "our parsers' messages are kept");

  // bun.lock: trailing commas are blanked, not removed, so the line still matches the file.
  const bunDir = project();
  const entries = Array.from({ length: 400 }, (_, i) => `    "p${i}": ["p${i}@1.0.0", "", {},],`);
  writeFileSync(join(bunDir, "bun.lock"), ["{", '  "lockfileVersion": 1,', '  "packages": {', ...entries, '    "bad": tok_SECRET_5,', "  },", "}"].join("\n"));
  const bunRec = scan.prepareProjects([{ root: bunDir, lockfile: join(bunDir, "bun.lock"), lockType: "bun" }]).inventories[0]!.record;
  assert.equal(bunRec.error, `could not parse lockfile: invalid JSON at line ${entries.length + 4}`);
  // Node 20 and 22 report only "at position N" for some errors: positions must match the file.
  const { stripTrailingCommas } = await import("../src/lockfile/bun.ts");
  const withCommas = readFileSync(join(bunDir, "bun.lock"), "utf8");
  assert.equal(stripTrailingCommas(withCommas).length, withCommas.length);
});

test("forget refuses to exclude /, the home folder, a watched folder or a folder above one", async () => {
  const code = join(home, "code");
  copyFixture("v3", join(code, "app"));
  api.addRoot(code);
  const before = api.listRoots().exclude;
  for (const path of ["/", home, `${home}/`, dirname(home), "~", code]) {
    assert.throws(() => api.forget(path), (e: any) => e.code === "invalid" && /refusing to exclude/.test(e.message), path);
  }
  const deeper = join(home, "nested", "code");
  mkdirSync(deeper, { recursive: true });
  api.addRoot(deeper);
  assert.throws(() => api.forget(join(home, "nested")), /contains the watched folder/);
  assert.deepEqual(api.listRoots().exclude, before, "nothing was excluded");

  // Forgetting without excluding is harmless; inside a watched folder it works as before.
  assert.equal(api.forget(home, { exclude: false }).excluded, false);
  const r = api.forget(join(code, "app"));
  assert.equal(r.excluded, true);
  assert.deepEqual(api.listRoots().exclude, [...before, join(code, "app")]);
  api.unexclude(join(code, "app"));

  // The MCP tool and the CLI go through the same check.
  const forget = tools.TOOLS.find((t) => t.name === "selfguard_forget")!;
  assert.throws(() => forget.run({ path: "/" }), /refusing to exclude/);
  const env = { ...process.env, NO_COLOR: "1" };
  const cli = spawnSync(process.execPath, [CLI, "forget", "/", "--json"], { env, encoding: "utf8" });
  assert.equal(cli.status, 2);
  assert.equal(JSON.parse(cli.stdout).error.code, "invalid");
  assert.ok(!api.listRoots().exclude.includes("/"));
});

test("the dashboard's place picker never excludes a folder holding a watched one", async () => {
  const parent = join(home, "places");
  const watched = join(parent, "work");
  const other = join(parent, "old");
  mkdirSync(watched, { recursive: true });
  mkdirSync(other, { recursive: true });
  api.addRoot(watched);
  const r = await api.applyPlaces([], [parent, home, "/", other]);
  assert.deepEqual(r.excluded, [other]);
  assert.ok(!api.listRoots().exclude.includes(parent));
  api.unexclude(other);
  api.removeRoot(watched);
});

test("forget on another machine refuses /, its home and its watched folders too", async () => {
  const config = await import("../src/config.ts");
  const machines = await import("../src/machines/core.ts");
  const cfg = config.loadConfig();
  const m = { name: "devbox", host: "devbox", mode: "restricted" as const, scope: "~", transport: "ssh" as const, roots: [{ path: "~/code", depth: 3 }, { path: "/srv/apps", depth: 2 }], exclude: [] };
  config.saveConfig({ ...cfg, machines: [...cfg.machines, m] });
  machines.saveMachineStatus("devbox", { home: "/home/me" });
  for (const path of ["/", "/home", "/home/me", "/home/me/code", "/srv", "/srv/apps"]) {
    assert.throws(() => api.excludeOnMachine("devbox", path), (e: any) => e.code === "invalid" && /refusing to exclude/.test(e.message), path);
  }
  assert.deepEqual(machines.getMachine("devbox").exclude, [], "nothing was excluded");
  assert.equal(api.excludeOnMachine("devbox", "/home/me/code/old").path, "/home/me/code/old");
  assert.deepEqual(machines.getMachine("devbox").exclude, ["/home/me/code/old"]);
});

test("MCP: every tool that makes selfguard watch or alert less is destructive", () => {
  const reducing = ["selfguard_forget", "selfguard_roots_remove", "selfguard_dismiss", "selfguard_dismiss_warning"];
  for (const name of reducing) {
    const t = tools.TOOLS.find((x) => x.name === name);
    assert.ok(t, name);
    assert.equal(t.annotations.destructiveHint, true, name);
    assert.equal(t.annotations.readOnlyHint, false, name);
  }
});

test("MCP: an urgent warning can't be dismissed by an agent; the user still can", () => {
  const repo = tmp("sg-audit-repo-");
  const file = join(repo, ".vscode", "tasks.json");
  const urgent: SourceWarning = { rule: "autorun-task", message: "A task runs when the folder is opened.", file, line: 3, severity: "high", urgent: true };
  const plain: SourceWarning = { rule: "unpinned-mcp-server", message: "runs x unpinned", file: join(repo, ".mcp.json"), line: 2, severity: "moderate" };
  store.saveSource({ schema: 1, kind: "agents", scope: "repo", path: repo, registeredAt: new Date().toISOString(), scannedAt: new Date().toISOString(), files: [], refs: [], findings: [], warnings: [urgent, plain], skipped: 0 });
  const id = (w: SourceWarning) => warnings.warningId(warnings.warningKey("agents", w));
  const key = warnings.warningKey("agents", urgent);
  const dismiss = tools.TOOLS.find((t) => t.name === "selfguard_dismiss_warning")!;

  assert.throws(() => dismiss.run({ warning: id(urgent) }), (e: any) => e.code === "invalid" && /urgent/.test(e.message));
  assert.throws(() => dismiss.run({ warning: key }), /urgent/, "by its full key too");
  assert.equal(api.listDismissedWarnings().length, 0);
  assert.equal((dismiss.run({ warning: id(plain) }) as { id: string }).id, id(plain), "other warnings as before");
  assert.equal(api.dismissWarning(id(urgent)).id, id(urgent), "the CLI and the app call the API directly");
  api.undismissWarning(id(urgent));
  api.undismissWarning(id(plain));

  // Forgetting the repo would drop its warnings: refused over MCP too, for the repo or a folder in it.
  const forget = tools.TOOLS.find((t) => t.name === "selfguard_forget")!;
  for (const path of [repo, join(repo, ".vscode")]) assert.throws(() => forget.run({ path }), /urgent warning/, path);
  assert.ok(store.listSources({ scope: "repo" }).some((r) => r.path === repo), "the record and its warnings are kept");
  assert.equal(api.forget(repo).excluded, true, "the user still can");
  assert.ok(!store.listSources({ scope: "repo" }).some((r) => r.path === repo));
  api.unexclude(repo);
});

/** "launcher ecosystem:name@version|pin" per package, or null. */
function launch(command: string, args: string[] = []): string[] | null {
  const l = launchers.parseLaunch(command, args);
  if (l?.ambiguous) assert.equal(l.packages.length, 0);
  return l && !l.ambiguous ? l.packages.map((p) => `${l.launcher} ${p.ecosystem}:${p.name}@${p.version ?? `?${p.pin ?? ""}`}`) : null;
}

test("launchers: a flag's value before the package is never taken for the package", () => {
  // Unknown flag + plain word: npx's argv pass reads a value, npm's parser a package. Skipped.
  assert.equal(launch("npx", ["--_authToken", "npm_SECRET123", "-y", "@modelcontextprotocol/server-github"]), null);
  assert.equal(launch("npx", ["--token", "ghp_SECRET", "pkg@1.0.0"]), null);
  assert.equal(launch("npx", ["-yq", "pkg"]), null);
  assert.equal(launch("npx -y --api-key SECRET pkg"), null);
  assert.equal(launch("bunx", ["--auth", "SECRET", "pkg"]), null);
  assert.equal(launch("pnpm", ["dlx", "--token", "SECRET", "pkg"]), null);
  assert.equal(launch("npm", ["--token", "SECRET", "exec", "pkg"]), null, "global flags before the subcommand too");
  assert.equal(launch("npm", ["--unknown", "exec", "exec", "evil"]), null);
  // Known flags with values, switches and negations: the real package.
  assert.deepEqual(launch("npx", ["--loglevel", "silent", "-y", "evil-mcp-server@1.0.0"]), ["npx npm:evil-mcp-server@1.0.0"]);
  assert.deepEqual(launch("npx", ["--_auth", "SECRET", "--userconfig", "/x/.npmrc", "pkg@1.0.0"]), ["npx npm:pkg@1.0.0"]);
  assert.deepEqual(launch("npx", ["--prefer-offline", "--no-audit", "-q", "pkg@1.0.0"]), ["npx npm:pkg@1.0.0"]);
  assert.deepEqual(launch("npx", ["--_authToken=SECRET", "pkg@1.0.0"]), ["npx npm:pkg@1.0.0"], "--flag=value is one token");
  assert.deepEqual(launch("npx", ["--unknown", "-y", "pkg@1.0.0"]), ["npx npm:pkg@1.0.0"], "no plain word after it: not ambiguous");
  assert.deepEqual(launch("npm", ["--loglevel", "silent", "exec", "--", "pkg@1.0.0"]), ["npm exec npm:pkg@1.0.0"]);
  assert.deepEqual(launch("pnpm", ["--dir", "/x", "dlx", "pkg@1.0.0"]), ["pnpm dlx npm:pkg@1.0.0"]);
});

test("launchers: uvx, uv tool run and pipx run follow the same rule", () => {
  assert.equal(launch("uvx", ["--token", "SECRET", "mcp-server-fetch"]), null);
  assert.equal(launch("uv", ["tool", "run", "--auth", "SECRET", "pkg"]), null);
  assert.equal(launch("uv", ["--token", "SECRET", "tool", "run", "pkg"]), null);
  assert.equal(launch("pipx", ["run", "--auth", "SECRET", "pkg"]), null);
  assert.equal(launch("pipx", ["run", "--sp", "evil", "good"]), null, "argparse abbreviations are unknown flags");
  assert.deepEqual(launch("uvx", ["--index-url", "https://u:SECRET@pypi.example/simple", "pkg==1.0.0"]), ["uvx PyPI:pkg@1.0.0"]);
  assert.deepEqual(launch("uvx", ["--compile-bytecode", "--no-cache", "pkg==1.0.0"]), ["uvx PyPI:pkg@1.0.0"]);
  assert.deepEqual(launch("uv", ["--directory", "/x", "tool", "--offline", "run", "pkg==1.0.0"]), ["uvx PyPI:pkg@1.0.0"]);
  assert.deepEqual(launch("pipx", ["--verbose", "run", "--pip-args=--no-deps", "--no-cache", "pkg==1.0.0"]), ["pipx run PyPI:pkg@1.0.0"]);
});

test("agent configs: secrets placed before the package never reach OSV, state or output", async () => {
  const user = tmp("sg-audit-user-");
  const sgState = join(user, ".sg-state");
  const servers = {
    gh: { command: "npx", args: ["--_authToken", "npm_FAKESECRETabc123", "-y", "@modelcontextprotocol/server-github"] },
    lv: { command: "npx", args: ["--loglevel", "silent", "-y", "lodash@4.17.20"] },
    uv: { command: "uvx", args: ["--token", "SECRET_UV_1", "mcp-server-fetch"] },
    px: { command: "pipx", args: ["run", "--auth", "SECRET_PIPX_2", "pkg"] },
    idx: { command: "uvx", args: ["--index-url", "https://u:SECRET_IDX_3@pypi.example/simple", "mcp-server-fetch==2025.4.7"] },
  };
  writeFileSync(join(user, ".claude.json"), JSON.stringify({ mcpServers: servers }, null, 2));
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: user, SELFGUARD_HOME: sgState, SELFGUARD_SYSTEM_ROOT: user, NO_COLOR: "1" };
  delete env.npm_config_cache;
  osv.bodies.length = 0;
  const sync = await run(process.execPath, [CLI, "sync", "--json"], { env });
  const out = await run(process.execPath, [CLI, "tools", "--json"], { env });

  const machine = JSON.parse(out.stdout).machine[0];
  const refs = machine.references.map((r: any) => `${r.server}|${r.name}@${r.version ?? "?"}`).sort();
  assert.deepEqual(refs, ["idx|mcp-server-fetch@2025.4.7", "lv|lodash@4.17.20"], "the real package behind --loglevel is checked");
  assert.equal(machine.skippedReferences, 3, "ambiguous servers are counted as not checked");
  const unparsed = machine.warnings.filter((w: any) => w.rule === "unparsed-mcp-server").map((w: any) => /"(\w+)"/.exec(w.message)?.[1]).sort();
  assert.deepEqual(unparsed, ["gh", "px", "uv"], "and each one is a low warning, so a hidden package never comes out clean");
  assert.ok(machine.findings.some((f: any) => f.name === "lodash"));

  const SECRET = /SECRET|npm_FAKE/;
  for (const text of [sync.stdout, sync.stderr, out.stdout, out.stderr]) assert.doesNotMatch(text, SECRET);
  const files = (dir: string): string[] => readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? files(join(dir, e.name)) : [join(dir, e.name)]));
  for (const f of files(sgState)) assert.doesNotMatch(readFileSync(f, "utf8"), SECRET, basename(f));
  assert.doesNotMatch(JSON.stringify(osv.bodies), SECRET);
  assert.deepEqual(
    osv.bodies.flatMap((b) => b.queries.map((q: any) => `${q.package.name}@${q.version ?? "*"}`)).sort(),
    ["lodash@4.17.20", "mcp-server-fetch@2025.4.7"],
  );
});

test("whole-home search: worktree pointers stay inside the home, on its disk, out of pruned folders", async () => {
  const h = tmp("sg-audit-everywhere-");
  const outside = tmp("sg-audit-outside-");
  const put = (dir: string): void => {
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, "package.json"), "{}");
    writeFileSync(join(dir, "package-lock.json"), "{}");
  };
  const repo = join(h, "repository", "api");
  put(repo);
  mkdirSync(join(repo, ".git"));
  writeFileSync(join(repo, ".git", "HEAD"), "ref: refs/heads/main\n");
  const pointer = (name: string, worktree: string): void => {
    put(worktree);
    mkdirSync(join(repo, ".git", "worktrees", name), { recursive: true });
    writeFileSync(join(repo, ".git", "worktrees", name, "gitdir"), `${join(worktree, ".git")}\n`);
  };
  pointer("ok", join(h, ".t3", "worktrees", "feat"));
  pointer("out", join(outside, "wt"));
  symlinkSync(outside, join(h, "link"));
  pointer("via-link", join(h, "link", "wt2"));
  pointer("library", join(h, "Library", "wt"));
  pointer("desktop", join(h, "Desktop", "wt"));
  mkdirSync(join(repo, ".git", "worktrees", "dots"), { recursive: true });
  writeFileSync(join(repo, ".git", "worktrees", "dots", "gitdir"), `${h}/../${basename(outside)}/wt/.git\n`);

  const found = async (skipProtected: boolean): Promise<string[]> =>
    (await everywhere.discoverEverywhere({ home: h, skipProtected })).projects.map((p) => p.root);
  const all = await found(false);
  assert.ok(all.includes(join(h, ".t3", "worktrees", "feat")), "a worktree in a hidden tool folder is still found");
  assert.ok(all.includes(join(h, "Desktop", "wt")));
  for (const p of all) assert.ok(p.startsWith(`${h}/`), `left the home: ${p}`);
  assert.ok(!all.includes(join(h, "link", "wt2")), "nor through a symlink out of it");
  assert.ok(!all.some((p) => p.includes(`${h}/Library/`)), "pruned folders stay pruned");
  assert.ok(!(await found(true)).includes(join(h, "Desktop", "wt")), "protected folders stay skipped");

  // A home reached through a symlink: git writes the worktree pointer with the real path.
  const realH = tmp("sg-audit-realhome-");
  const linkH = join(tmp("sg-audit-homelink-"), "me");
  symlinkSync(realH, linkH);
  const repo2 = join(realH, "code", "api");
  put(repo2);
  mkdirSync(join(repo2, ".git", "worktrees", "feat"), { recursive: true });
  writeFileSync(join(repo2, ".git", "HEAD"), "ref: refs/heads/main\n");
  put(join(realH, ".t3", "worktrees", "feat"));
  writeFileSync(join(repo2, ".git", "worktrees", "feat", "gitdir"), `${join(realH, ".t3", "worktrees", "feat", ".git")}\n`);
  const viaLink = (await everywhere.discoverEverywhere({ home: linkH, skipProtected: false })).projects.map((p) => p.root);
  assert.ok(viaLink.some((p) => p.endsWith("/.t3/worktrees/feat")), `worktree under the real home is found: ${viaLink.join(", ")}`);
});
