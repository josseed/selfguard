import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { request, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { agentPlist } from "../src/schedule.ts";

process.env.SELFGUARD_HOME = mkdtempSync(join(tmpdir(), "sg-ui-"));
process.env.SELFGUARD_NO_NOTIFY = "1";
process.env.SELFGUARD_NO_LAUNCHD = "1";

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

function call(
  path: string,
  opts: { method?: string; headers?: Record<string, string>; body?: string } = {},
): Promise<{ status: number; headers: Record<string, unknown>; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request(
      { host: "127.0.0.1", port, path, method: opts.method ?? "GET", headers: { host: `127.0.0.1:${port}`, ...opts.headers } },
      (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => resolve({ status: res.statusCode!, headers: res.headers, body }));
      },
    );
    req.on("error", reject);
    req.end(opts.body);
  });
}

const auth = () => ({ "x-selfguard-token": TOKEN });

test("serves the page with a strict CSP and no inline code", async () => {
  const r = await call("/");
  assert.equal(r.status, 200);
  assert.match(String(r.headers["content-security-policy"]), /default-src 'none'; script-src 'self'/);
  assert.equal(r.headers["x-frame-options"], "DENY");
  assert.equal(r.headers["x-content-type-options"], "nosniff");
  assert.doesNotMatch(r.body, /<script>|\sstyle="|\son[a-z]+="/, "no inline scripts, styles or handlers");
  assert.equal((await call("/app.js")).status, 200);
  assert.equal((await call("/../package.json")).status, 404);
  assert.equal((await call("/static/app.js")).status, 404);
});

test("rejects other Host headers (DNS rebinding)", async () => {
  const r = await call("/api/overview", { headers: { host: `evil.example:${port}`, ...auth() } });
  assert.equal(r.status, 421);
});

test("the API needs the session token", async () => {
  assert.equal((await call("/api/overview")).status, 401);
  assert.equal((await call("/api/overview", { headers: { "x-selfguard-token": "wrong" } })).status, 401);
  const ok = await call("/api/overview", { headers: auth() });
  assert.equal(ok.status, 200);
  const data = JSON.parse(ok.body);
  assert.deepEqual(data.repos, []);
  assert.equal(data.settings.remind, "daily");
});

test("POSTs must be same-origin JSON and only touch tracked projects", async () => {
  const json = { ...auth(), "content-type": "application/json" };
  const form = await call("/api/settings", { method: "POST", headers: { ...auth(), "content-type": "text/plain" }, body: "{}" });
  assert.equal(form.status, 403);
  const cross = await call("/api/settings", { method: "POST", headers: { ...json, origin: "https://evil.example" }, body: "{}" });
  assert.equal(cross.status, 403);
  const untracked = await call("/api/scan", { method: "POST", headers: json, body: JSON.stringify({ path: "/etc" }) });
  assert.equal(untracked.status, 404);
  assert.equal(JSON.parse(untracked.body).error.code, "not_tracked");
  const settings = await call("/api/settings", {
    method: "POST",
    headers: { ...json, origin: `http://127.0.0.1:${port}` },
    body: JSON.stringify({ remind: "weekly" }),
  });
  assert.equal(settings.status, 200);
  assert.equal(JSON.parse(settings.body).remind, "weekly");
  const bad = await call("/api/settings", { method: "POST", headers: json, body: JSON.stringify({ activeDays: -1 }) });
  assert.equal(bad.status, 400);
});

test("launchd plists escape paths and watch lockfiles", () => {
  const plist = agentPlist("dev.selfguard.watch", ["/bin/node", "/x/cli.js", "check"], { watch: ["/code/a&b", "/code/<x>/package-lock.json"] }, "/l.log");
  assert.match(plist, /<key>WatchPaths<\/key>\s*<array>\s*<string>\/code\/a&amp;b<\/string>\s*<string>\/code\/&lt;x&gt;\/package-lock.json<\/string>/);
  assert.match(plist, /<key>ThrottleInterval<\/key><integer>15<\/integer>/);
  assert.doesNotMatch(plist, /StartInterval/);
  assert.match(agentPlist("dev.selfguard.sync", ["n"], { interval: 3600 }, "/l"), /<key>StartInterval<\/key><integer>3600<\/integer>/);
});
