import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

process.env.SELFGUARD_HOME = mkdtempSync(join(tmpdir(), "sg-bridge-"));
process.env.SELFGUARD_NO_NOTIFY = "1";
process.env.SELFGUARD_NO_LAUNCHD = "1";
process.env.SELFGUARD_NO_UPDATE_CHECK = "1";

const { handleLine, MAX_LINE } = await import("../src/bridge.ts");

const ask = (req: unknown) => handleLine(JSON.stringify(req));
const get = (path: string, query?: Record<string, string>) => ask({ id: 1, method: "GET", path, query });
const post = (path: string, body: unknown) => ask({ id: 2, method: "POST", path, body });

test("ping returns the version", async () => {
  const r = await get("/api/ping");
  assert.equal(r.id, 1);
  assert.equal(r.status, 200);
  assert.match((r.data as { version: string }).version, /^\d+\.\d+\.\d+/);
  assert.equal((r.data as { ok: boolean }).ok, true);
});

test("GET overview, and the query reaches the route", async () => {
  const r = await get("/api/overview");
  assert.equal(r.status, 200);
  const o = r.data as { repos: unknown[]; settings: { remind: string }; app?: unknown };
  assert.deepEqual(o.repos, []);
  assert.equal(o.settings.remind, "daily");
  assert.equal(o.app, undefined, "the old script launcher is gone");
  assert.equal((await get("/api/repo", { key: "nope" })).status, 404);
  assert.equal((await ask({ id: "a", method: "GET", path: "/api/repo?key=nope" })).status, 404, "a query in the path works too");
});

test("the mascot manifest is served through the API (the page can't fetch)", async () => {
  const r = await get("/api/mascot");
  assert.equal(r.status, 200);
  assert.deepEqual(Object.keys((r.data as { scenes: object }).scenes).sort(), ["crit", "fixed", "high", "idle", "mal"]);
});

test("a POST with a body; validation errors map to statuses", async () => {
  const ok = await post("/api/settings", { remind: "weekly" });
  assert.equal(ok.status, 200);
  assert.equal((ok.data as { remind: string }).remind, "weekly");
  const bad = await post("/api/settings", { activeDays: -1 });
  assert.equal(bad.status, 400);
  assert.equal(bad.error?.code, "invalid");
  assert.equal((await ask({ id: 3, method: "POST", path: "/api/settings" })).status, 200, "no body means {}");
});

test("only tracked projects and configured machines are acted on", async () => {
  const untracked = await post("/api/scan", { path: "/etc" });
  assert.equal(untracked.status, 404);
  assert.equal(untracked.error?.code, "not_tracked");
  assert.equal((await post("/api/scan", { path: "/x", machine: "nope" })).status, 404);
  assert.equal((await post("/api/machines/add", { host: "-oProxyCommand=id" })).status, 400);
  assert.equal((await get("/api/machines/fs", { name: "nope" })).status, 404);
  assert.equal((await post("/api/unexclude", { path: "/x" })).status, 404);
});

test("unknown routes, and the endpoints that went away with the server, are 404", async () => {
  for (const [method, path] of [["GET", "/api/nope"], ["POST", "/api/restart"], ["POST", "/api/app"], ["GET", "/api/overview/x"]]) {
    const r = await ask({ id: 5, method, path, body: {} });
    assert.equal(r.status, 404, path);
    assert.deepEqual(r.error, { code: "not_found", message: "no such endpoint" });
  }
});

test("update status and tailnet endpoints: validation, only configured things", async () => {
  const st = (await get("/api/update")).data as { enabled: boolean; restartNeeded?: unknown };
  assert.equal(st.enabled, false);
  assert.equal(st.restartNeeded, undefined, "no dashboard process to restart anymore");
  process.env.SELFGUARD_TAILSCALE = "/nonexistent/tailscale";
  try {
    const peers = (await get("/api/machines/peers")).data as { tailscale: { ok: boolean; reason: string }; peers: unknown[] };
    assert.equal(peers.tailscale.reason, "not_installed");
    assert.deepEqual(peers.peers, []);
    assert.equal(((await post("/api/share", { enabled: true })).data as { enabled: boolean }).enabled, true);
    assert.equal(((await post("/api/share", { enabled: false })).data as { enabled: boolean }).enabled, false);
    assert.equal((await post("/api/share/approve", { id: "nope" })).status, 404);
    assert.equal((await get("/api/pair/status", { job: "nope" })).status, 404);
    assert.equal((await post("/api/pair/start", { peer: "nobody" })).status, 404);
  } finally {
    delete process.env.SELFGUARD_TAILSCALE;
  }
});

test("folders: browse, add, change depth, remove", async () => {
  const dir = mkdtempSync(join(tmpdir(), "sg-bridge-code-"));
  mkdirSync(join(dir, "web"));
  writeFileSync(join(dir, "web", "package.json"), "{}");
  mkdirSync(join(dir, ".hidden"));
  mkdirSync(join(dir, "node_modules"));
  const fs = (await get("/api/fs", { path: dir })).data as { dirs: Array<{ name: string; isProject: boolean }> };
  assert.deepEqual(fs.dirs.map((d) => [d.name, d.isProject]), [["web", true]]);
  assert.equal((await get("/api/fs", { path: join(dir, "nope") })).status, 404);
  assert.equal((await post("/api/folders/add", { path: dir, depth: 3 })).status, 200);
  assert.equal(((await get("/api/folders")).data as { roots: Array<{ depth: number }> }).roots[0]!.depth, 3);
  assert.equal((await post("/api/folders/remove", { path: dir })).status, 200);
});

test("malformed requests get an answer, never a crash", async () => {
  assert.deepEqual(await handleLine("{nope"), { id: null, status: 400, error: { code: "invalid", message: "request is not valid JSON" } });
  assert.equal((await handleLine("[1]")).status, 400);
  assert.equal((await handleLine('{"method":"GET","path":"/api/ping"}')).id, null, "no id");
  assert.equal((await handleLine('{"id":{},"method":"GET","path":"/api/ping"}')).id, null);
  for (const req of [
    { id: 1, method: "DELETE", path: "/api/ping" },
    { id: 1, method: "GET", path: "/etc/passwd" },
    { id: 1, method: "GET", path: "api/ping" },
    { id: 1, method: "GET", path: 7 },
    { id: 1, method: "GET", path: "/api/ping", query: "x" },
    { id: 1, method: "POST", path: "/api/settings", body: [1] },
  ]) {
    const r = await ask(req);
    assert.equal(r.status, 400, JSON.stringify(req));
    assert.equal(r.id, 1);
  }
});

// ---- the process ----

const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));

function bridge() {
  const child = spawn(process.execPath, [cli, "bridge"], { env: { ...process.env, SELFGUARD_HOME: mkdtempSync(join(tmpdir(), "sg-bridge-p-")) } });
  let out = "";
  child.stdout.setEncoding("utf8").on("data", (c) => (out += c));
  const lines = () => out.split("\n").filter(Boolean).map((l) => JSON.parse(l));
  const waitFor = async (n: number) => {
    for (let i = 0; i < 200 && lines().length < n; i++) await new Promise((r) => setTimeout(r, 50));
    return lines();
  };
  const exited = new Promise<number | null>((resolve) => child.on("close", (code) => resolve(code)));
  return { child, waitFor, exited, lines, raw: () => out };
}

test("the process answers lines concurrently by id, survives garbage, and exits 0 when stdin closes", async () => {
  const b = bridge();
  b.child.stdin.write('{"id":1,"method":"GET","path":"/api/ping"}\n');
  b.child.stdin.write("garbage\n");
  b.child.stdin.write('{"id":"x","method":"GET","path":"/api/overview"}\n{"id":3,"method":"GET","path":"/api/nope"}\n');
  b.child.stdin.write('{"id":4,"method":"GET","path":"/api/ping"}'); // no trailing newline: still answered at EOF
  const early = await b.waitFor(4);
  assert.equal(early.length, 4);
  b.child.stdin.end();
  assert.equal(await b.exited, 0);
  const all = b.lines();
  assert.equal(all.length, 5);
  const byId = new Map(all.map((r) => [r.id, r]));
  assert.equal(byId.get(1).status, 200);
  assert.equal(byId.get("x").status, 200);
  assert.equal(byId.get(3).status, 404);
  assert.equal(byId.get(4).status, 200);
  assert.equal(byId.get(null).status, 400);
  assert.ok(b.raw().split("\n").filter(Boolean).every((l) => l.startsWith('{"id"')), "stdout is protocol only");
});

test("an oversized line is refused and the next one still works", async () => {
  const b = bridge();
  b.child.stdin.write(`{"id":1,"method":"POST","path":"/api/settings","body":{"x":"${"a".repeat(MAX_LINE + 10)}"}}\n`);
  b.child.stdin.write('{"id":2,"method":"GET","path":"/api/ping"}\n');
  const out = await b.waitFor(2);
  assert.equal(out.find((r) => r.id === null).status, 413);
  assert.equal(out.find((r) => r.id === 2).status, 200);
  b.child.stdin.end();
  assert.equal(await b.exited, 0);
});

test("stdin closed straight away: exit 0 and no output", async () => {
  const b = bridge();
  b.child.stdin.end();
  assert.equal(await b.exited, 0);
  assert.equal(b.raw(), "");
});
