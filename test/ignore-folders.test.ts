// Ignore a whole folder from the Repos page (POST /api/folders/ignore) and include it again.
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { createServer, request, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { copyFixture } from "./helpers.ts";

const read = (req: IncomingMessage) => new Promise<string>((r) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => r(b)); });
const osv = createServer(async (req, res) => {
  res.setHeader("content-type", "application/json");
  if (req.url === "/v1/querybatch") {
    const body = JSON.parse(await read(req));
    res.end(JSON.stringify({ results: body.queries.map((q: any) => (q.package.name === "lodash" && q.version === "4.17.20" ? { vulns: [{ id: "GHSA-lodash", modified: "2026-01-01T00:00:00Z" }] } : {})) }));
    return;
  }
  if (req.url === "/v1/vulns/GHSA-lodash") {
    res.end(JSON.stringify({ id: "GHSA-lodash", modified: "2026-01-01T00:00:00Z", summary: "Prototype pollution", database_specific: { severity: "CRITICAL" },
      affected: [{ package: { ecosystem: "npm", name: "lodash" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }] }));
    return;
  }
  res.statusCode = 404;
  res.end("{}");
});

const TOKEN = "test-token-0123456789";
let server: Server;
let port: number;
let api: typeof import("../src/api.ts");
let code: string;
let remoteCode: string;

before(async () => {
  await new Promise<void>((r) => osv.listen(0, "127.0.0.1", r));
  process.env.SELFGUARD_OSV_API = `http://127.0.0.1:${(osv.address() as AddressInfo).port}/v1`;
  process.env.SELFGUARD_HOME = mkdtempSync(join(tmpdir(), "sg-ignore-"));
  process.env.HOME = realpathSync(mkdtempSync(join(tmpdir(), "sg-ignore-user-")));
  process.env.SELFGUARD_SSH = fileURLToPath(new URL("./bin/fake-ssh", import.meta.url));
  process.env.SG_FAKE_SSH_LOG = join(mkdtempSync(join(tmpdir(), "sg-ignore-ssh-")), "log");
  process.env.SELFGUARD_NO_NOTIFY = "1";
  process.env.SELFGUARD_NO_LAUNCHD = "1";
  api = await import("../src/api.ts");
  const { createUiServer } = await import("../src/ui/server.ts");
  server = createUiServer(TOKEN);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;

  // ~/code/old/{a,b} (ignorable folder), ~/code/keep and a project directly in the root.
  code = join(process.env.HOME, "code");
  for (const p of ["old/a", "old/b", "keep/c"]) copyFixture("v3", join(code, p));
  copyFixture("v3", join(code, "top"));
  api.addRoot(code, 4);
  await api.discoverNew();

  const remoteHome = realpathSync(mkdtempSync(join(tmpdir(), "sg-ignore-server-")));
  process.env.SG_FAKE_HOME = remoteHome;
  remoteCode = join(remoteHome, "code");
  for (const p of ["acme/api", "acme/web"]) {
    copyFixture("v3", join(remoteCode, p));
    mkdirSync(join(remoteCode, p, ".git"));
    writeFileSync(join(remoteCode, p, ".git", "HEAD"), "ref: refs/heads/main\n");
  }
});
after(() => {
  osv.close();
  server.close();
});

function post(path: string, body: unknown): Promise<{ status: number; json: any }> {
  return new Promise((resolve, reject) => {
    const req = request(
      { host: "127.0.0.1", port, path, method: "POST", headers: { host: `127.0.0.1:${port}`, "x-selfguard-token": TOKEN, "content-type": "application/json" } },
      (res) => {
        let b = "";
        res.on("data", (c) => (b += c));
        res.on("end", () => resolve({ status: res.statusCode!, json: JSON.parse(b || "{}") }));
      },
    );
    req.on("error", reject);
    req.end(JSON.stringify(body));
  });
}

const tracked = (machine?: string): number => api.getStatus().projects.filter((p) => (machine ? p.machine === machine : !p.machine)).length;
const menuBarTracked = (): number => JSON.parse(readFileSync(join(process.env.SELFGUARD_HOME!, "menubar.json"), "utf8")).trackedProjects;

test("local: only real folder buckets can be ignored, never roots or arbitrary paths", async () => {
  assert.equal(tracked(), 4);
  const rejected = [join(code, "old", "a"), code, join(code, "nope"), "/", join(code, "old") + "/"];
  for (const path of rejected) {
    const r = await post("/api/folders/ignore", { path });
    assert.ok(r.status === 400 || r.status === 404, `${path}: ${r.status}`);
  }
  assert.equal((await post("/api/folders/ignore", { path: join(code, "old"), machine: "nope" })).status, 404);
  assert.equal(tracked(), 4);
});

test("local: ignoring drops the projects, rewrites menubar.json, and include again brings them back", async () => {
  api.getStatus(); // warm
  const { writeMenuBar } = await import("../src/menubar.ts");
  writeMenuBar();
  assert.equal(menuBarTracked(), 4);

  const r = await post("/api/folders/ignore", { path: join(code, "old") });
  assert.equal(r.status, 200);
  assert.deepEqual(r.json, { path: join(code, "old"), machine: null, forgotten: 2 });
  assert.equal(tracked(), 2);
  assert.equal(menuBarTracked(), 2);
  assert.ok(api.listRoots().exclude.includes(join(code, "old")));

  // Excluded projects don't come back through sync, and don't alert.
  const events = () => (existsSync(join(process.env.SELFGUARD_HOME!, "events.jsonl")) ? readFileSync(join(process.env.SELFGUARD_HOME!, "events.jsonl"), "utf8").split("\n").length : 0);
  const before = events();
  copyFixture("v3", join(code, "old", "new-project")); // created later
  await api.sync({ notify: true });
  assert.equal(tracked(), 2);
  assert.equal(events(), before, "nothing announced for the ignored folder");
  assert.ok(!api.getAttention().some((a) => a.path.startsWith(join(code, "old"))));

  const back = await post("/api/unexclude", { path: join(code, "old") });
  assert.equal(back.status, 200);
  assert.equal(back.json.removed, true);
  assert.equal(back.json.restored, 3);
  assert.equal(tracked(), 5);
  assert.equal(menuBarTracked(), 5);
  assert.deepEqual(api.listRoots().exclude, []);
});

test("machine: ignore a remote folder and include it again", async () => {
  await api.addMachine("devbox", "devbox.tail1234.ts.net");
  api.addMachineRoot("devbox", "~/code", 3);
  await api.checkMachines();
  assert.equal(tracked("devbox"), 2);
  const folder = join(remoteCode, "acme");

  assert.equal((await post("/api/folders/ignore", { path: remoteCode, machine: "devbox" })).status, 400, "a watched folder");
  assert.equal((await post("/api/folders/ignore", { path: join(remoteCode, "zzz"), machine: "devbox" })).status, 404);
  assert.equal((await post("/api/folders/ignore", { path: folder })).status, 404, "a remote folder is not a local one");

  const r = await post("/api/folders/ignore", { path: folder, machine: "devbox" });
  assert.deepEqual(r.json, { path: folder, machine: "devbox", forgotten: 2 });
  assert.equal(tracked("devbox"), 0);
  assert.ok(api.listMachines().find((m) => m.name === "devbox")!.exclude.includes(folder));
  assert.equal(tracked(), 5, "local projects untouched");

  const back = await post("/api/machines/unexclude", { name: "devbox", path: folder });
  assert.equal(back.json.removed, true);
  assert.equal(back.json.restored, 2);
  assert.equal(tracked("devbox"), 2);
});
