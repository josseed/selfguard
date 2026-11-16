import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { request, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";

process.env.SELFGUARD_HOME = mkdtempSync(join(tmpdir(), "sg-menubar-"));
process.env.SELFGUARD_NO_NOTIFY = "1";
process.env.SELFGUARD_NO_LAUNCHD = "1";
process.env.SELFGUARD_NO_UPDATE_CHECK = "1";

const TOKEN = "test-token-0123456789";
let server: Server;
let port: number;

before(async () => {
  const { createUiServer } = await import("../src/ui/server.ts");
  server = createUiServer(TOKEN);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  port = (server.address() as AddressInfo).port;
});
after(() => server.close());

function get(path: string, headers: Record<string, string> = {}): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request({ host: "127.0.0.1", port, path, headers: { host: `127.0.0.1:${port}`, ...headers } }, (res) => {
      let body = "";
      res.on("data", (c) => (body += c));
      res.on("end", () => resolve({ status: res.statusCode!, body }));
    });
    req.on("error", reject);
    req.end();
  });
}

test("menu bar state: malicious, then serious findings, then a service down", async () => {
  const { menuBarState } = await import("../src/ui/menubar.ts");
  const zero = { malicious: 0, critical: 0, high: 0, moderate: 0, low: 0, unknown: 0 };
  const up = { sync: true, watcher: true };
  assert.equal(menuBarState({ ...zero, malicious: 1 }, 0, { sync: false, watcher: false }), "malicious");
  assert.equal(menuBarState({ ...zero, high: 2 }, 1, { sync: false, watcher: true }), "attention");
  assert.equal(menuBarState({ ...zero, moderate: 3 }, 0, { sync: true, watcher: false }), "degraded");
  assert.equal(menuBarState({ ...zero, low: 3 }, 0, up), "clean");
  assert.equal(menuBarState(zero, 0, null), "clean", "unknown services (not macOS) aren't a problem");
});

test("GET /api/menubar needs the token and returns the summary", async () => {
  assert.equal((await get("/api/menubar")).status, 401);
  const r = await get("/api/menubar", { "x-selfguard-token": TOKEN });
  assert.equal(r.status, 200);
  const m = JSON.parse(r.body);
  assert.equal(typeof m.version, "string");
  assert.equal(m.state, "clean");
  assert.deepEqual(m.repos, []);
  assert.equal(m.moreRepos, 0);
  assert.deepEqual(Object.keys(m.update).sort(), ["available", "latest"]);
});
