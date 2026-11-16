// Agent configs hold secrets (env, headers, URLs, arguments): none may leave the config file.
import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { after, before, test } from "node:test";
import { osv, startOsv } from "./sources-helpers.ts";

const CLI = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
const SECRETS = fileURLToPath(new URL("./fixtures/agents/secrets.fixture.json", import.meta.url));
const SECRET = /SECRET_|user:|Bearer|\?key=|acme\/x|registry\.example/;
const run = promisify(execFile);

let server: Server;
let home: string;
let state: string;
let env: NodeJS.ProcessEnv;

before(async () => {
  server = await startOsv();
  home = realpathSync(mkdtempSync(join(tmpdir(), "sg-privacy-user-")));
  state = join(home, ".sg-state");
  const text = readFileSync(SECRETS, "utf8");
  mkdirSync(join(home, ".cursor"));
  writeFileSync(join(home, ".cursor", "mcp.json"), text);
  writeFileSync(join(home, ".claude.json"), text);
  // The npx cache ran lodash 4.17.20; its lockfile holds a credential that must not be copied.
  const npx = join(home, ".npm", "_npx", "0123abcd");
  mkdirSync(npx, { recursive: true });
  writeFileSync(join(npx, "package.json"), JSON.stringify({ _npx: { packages: ["lodash"] } }));
  const resolved = "https://user:SECRET_NPX_12@registry.example.com/lodash.tgz";
  writeFileSync(join(npx, "package-lock.json"), JSON.stringify({ packages: { "node_modules/lodash": { version: "4.17.20", resolved } } }));
  env = { ...process.env, HOME: home, SELFGUARD_HOME: state, SELFGUARD_NO_NOTIFY: "1", SELFGUARD_NO_LAUNCHD: "1", NO_COLOR: "1" };
  delete env.npm_config_cache;
});
after(() => server.close());

function allFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? allFiles(join(dir, e.name)) : [join(dir, e.name)]));
}

async function mcpSources(): Promise<string> {
  const child = spawn(process.execPath, [CLI, "mcp"], { env, stdio: ["pipe", "pipe", "pipe"] });
  let out = "";
  let err = "";
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => (err += d));
  const send = (m: object) => child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", ...m })}\n`);
  send({ id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } });
  send({ method: "notifications/initialized" });
  send({ id: 2, method: "tools/call", params: { name: "selfguard_sources", arguments: {} } });
  for (let t = 0; t < 200 && !out.includes('"id":2'); t++) await new Promise((r) => setTimeout(r, 25));
  child.kill();
  assert.match(out, /"id":2/);
  return out + err;
}

test("secrets in env, headers, URLs and arguments never reach records, logs, outputs or OSV", async () => {
  osv.bodies.length = 0;
  const sync = await run(process.execPath, [CLI, "sync", "--json"], { env });
  const tools = await run(process.execPath, [CLI, "tools", "--json"], { env });
  const text = await run(process.execPath, [CLI, "tools", "--verbose"], { env });
  const mcp = await mcpSources();

  // The servers were read: references and warnings exist, without their secrets.
  const json = JSON.parse(tools.stdout);
  const refs = json.machine.flatMap((s: any) => s.references.map((r: any) => `${r.agent}|${r.server}|${r.name}@${r.version ?? "?"}`));
  assert.deepEqual(refs.sort(), ["Claude Code|leaky|leaky-mcp@1.0.0", "Claude Code|unpinned|lodash@?", "Cursor|leaky|leaky-mcp@1.0.0", "Cursor|unpinned|lodash@?"]);
  assert.equal(json.machine[0].skippedReferences, 4, "remote and git servers, in both files");
  assert.ok(json.machine[0].warnings.some((w: any) => w.message.includes("(mcp.example.com)")), "remote servers by host only");
  // Unpinned: checked by name; the fixed advisory applies only because the version last run is affected.
  const lodash = json.machine[0].findings.filter((f: any) => f.name === "lodash");
  assert.deepEqual(lodash.map((f: any) => [f.certainty, f.lastRun]), [["may-be-affected", "4.17.20"]]);
  assert.match(text.stdout, /last run 4\.17\.20 is affected/);
  assert.match(text.stdout, /Agent tools on this machine/);
  assert.match(mcp, /leaky-mcp/);

  const outputs = { sync: sync.stdout + sync.stderr, tools: tools.stdout + tools.stderr, text: text.stdout + text.stderr, mcp };
  for (const [name, out] of Object.entries(outputs)) assert.doesNotMatch(out, SECRET, name);
  const stored = allFiles(state);
  assert.ok(stored.some((f) => f.includes(`${join(state, "sources")}`)), "a source record was saved");
  for (const f of stored) assert.doesNotMatch(readFileSync(f, "utf8"), SECRET, f);
  assert.ok(osv.bodies.length > 0);
  const sent = JSON.stringify(osv.bodies);
  assert.doesNotMatch(sent, SECRET);
  assert.deepEqual(
    osv.bodies.flatMap((b) => b.queries.map((q: any) => `${q.package.name}@${q.version ?? "*"}`)).sort(),
    ["leaky-mcp@1.0.0", "lodash@*"],
    "only package names and versions are sent",
  );
});
