import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { copyFixture } from "./helpers.ts";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("../src/cli.ts", import.meta.url));

function sandbox() {
  const home = realpathSync(mkdtempSync(join(tmpdir(), "sg-agent-")));
  const code = join(home, "code");
  copyFixture("v3", join(code, "app"));
  const env = { ...process.env, HOME: home, SELFGUARD_HOME: join(home, ".sg"), SELFGUARD_NO_NOTIFY: "1", NO_COLOR: "1" };
  return { home, code, env };
}

function cli(env: NodeJS.ProcessEnv, ...args: string[]): { code: number; json: any } {
  try {
    return { code: 0, json: JSON.parse(execFileSync(process.execPath, [CLI, ...args], { env, encoding: "utf8" })) };
  } catch (e: any) {
    return { code: e.status, json: JSON.parse(e.stdout) };
  }
}

test("--json: stable documents and structured errors with exit code 2", () => {
  const { code, env } = sandbox();
  assert.deepEqual(cli(env, "status", "--json"), { code: 0, json: { repos: [], projects: [] } });
  const added = cli(env, "roots", "add", code, "--depth", "2", "--json");
  assert.deepEqual(added.json.roots, [{ path: code, depth: 2 }]);
  const dry = cli(env, "discover", "--dry-run", "--json");
  assert.deepEqual(dry.json.found, [{ path: join(code, "app"), lockType: "npm" }]);
  const bad = cli(env, "report", "/definitely/not/here", "--json");
  assert.equal(bad.code, 2);
  assert.equal(bad.json.error.code, "not_found");
  const unknown = cli(env, "nope", "--json");
  assert.equal(unknown.json.error.code, "usage");
});

test("settings and reminder preview are available as JSON", () => {
  const { env } = sandbox();
  const s = cli(env, "settings", "--json").json;
  assert.equal(s.remind, "daily");
  assert.equal(s.activeDays, 30);
  const changed = cli(env, "settings", "--remind", "weekly", "--active-days", "14", "--json").json;
  assert.deepEqual([changed.remind, changed.activeDays], ["weekly", 14]);
  const bad = cli(env, "settings", "--remind", "hourly", "--json");
  assert.equal(bad.code, 2);
  assert.equal(bad.json.error.code, "invalid");
  assert.deepEqual(cli(env, "remind", "--dry-run", "--json").json, { sent: false, notification: null, repos: [] });
  assert.deepEqual(cli(env, "check", "--json").json, { rescanned: [], errors: [] });
});

test("forget excludes a path so discovery never brings it back", () => {
  const { code, env } = sandbox();
  cli(env, "roots", "add", code, "--json");
  const r = cli(env, "forget", join(code, "app"), "--json");
  assert.equal(r.json.excluded, true);
  assert.deepEqual(cli(env, "discover", "--dry-run", "--json").json.found, []);
  cli(env, "unexclude", join(code, "app"), "--json");
  assert.equal(cli(env, "discover", "--dry-run", "--json").json.found.length, 1);
});

test("MCP server: initialize, list tools, call a tool, report tool errors", async () => {
  const { code, env } = sandbox();
  const child = spawn(process.execPath, [CLI, "mcp"], { env, stdio: ["pipe", "pipe", "inherit"] });
  const lines: any[] = [];
  let buf = "";
  child.stdout.on("data", (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      lines.push(JSON.parse(buf.slice(0, i)));
      buf = buf.slice(i + 1);
    }
  });
  const send = (m: object) => child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", ...m })}\n`);
  const waitFor = async (id: number) => {
    for (let t = 0; t < 100; t++) {
      const hit = lines.find((l) => l.id === id);
      if (hit) return hit;
      await new Promise((r) => setTimeout(r, 50));
    }
    throw new Error(`no response for ${id}`);
  };

  send({ id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } });
  const init = await waitFor(1);
  assert.equal(init.result.protocolVersion, "2025-06-18");
  assert.equal(init.result.serverInfo.name, "selfguard");
  assert.match(init.result.instructions, /guide for AI agents/);
  send({ method: "notifications/initialized" });

  send({ id: 2, method: "tools/list" });
  const names = (await waitFor(2)).result.tools.map((t: any) => t.name);
  for (const n of ["selfguard_status", "selfguard_attention", "selfguard_check", "selfguard_project_report", "selfguard_scan", "selfguard_where", "selfguard_forget", "selfguard_machines", "selfguard_machines_sync", "selfguard_machines_peers"]) {
    assert.ok(names.includes(n), n);
  }

  send({ id: 3, method: "tools/call", params: { name: "selfguard_roots_add", arguments: { path: code } } });
  const call = await waitFor(3);
  assert.equal(call.result.isError, false);
  assert.equal(call.result.structuredContent.roots[0].path, code);

  send({ id: 4, method: "tools/call", params: { name: "selfguard_project_report", arguments: { path: "/nope" } } });
  const failed = await waitFor(4);
  assert.equal(failed.result.isError, true);
  assert.match(failed.result.content[0].text, /not_found/);

  send({ id: 5, method: "does/not/exist" });
  assert.equal((await waitFor(5)).error.code, -32601);

  child.stdin.end();
  await new Promise((r) => child.on("close", r));
});
