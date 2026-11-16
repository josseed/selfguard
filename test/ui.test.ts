import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
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

test("folders: browse, add, change depth, remove; unexclude only excluded paths", async () => {
  const json = { ...auth(), "content-type": "application/json" };
  const dir = mkdtempSync(join(tmpdir(), "sg-ui-code-"));
  mkdirSync(join(dir, "web"));
  writeFileSync(join(dir, "web", "package.json"), "{}");
  mkdirSync(join(dir, ".hidden"));
  mkdirSync(join(dir, "node_modules"));

  const fs = JSON.parse((await call(`/api/fs?path=${encodeURIComponent(dir)}`, { headers: auth() })).body);
  assert.deepEqual(fs.dirs.map((d: { name: string; isProject: boolean }) => [d.name, d.isProject]), [["web", true]]);
  assert.equal((await call(`/api/fs?path=${encodeURIComponent(join(dir, "nope"))}`, { headers: auth() })).status, 404);

  const added = await call("/api/folders/add", { method: "POST", headers: json, body: JSON.stringify({ path: dir, depth: 3 }) });
  assert.equal(added.status, 200);
  const folders = JSON.parse((await call("/api/folders", { headers: auth() })).body);
  assert.equal(folders.roots.length, 1);
  assert.equal(folders.roots[0].depth, 3);
  await call("/api/folders/add", { method: "POST", headers: json, body: JSON.stringify({ path: dir, depth: 7 }) });
  assert.equal(JSON.parse((await call("/api/folders", { headers: auth() })).body).roots[0].depth, 7);

  const notExcluded = await call("/api/unexclude", { method: "POST", headers: json, body: JSON.stringify({ path: dir }) });
  assert.equal(notExcluded.status, 404);
  const removed = await call("/api/folders/remove", { method: "POST", headers: json, body: JSON.stringify({ path: dir }) });
  assert.equal(JSON.parse(removed.body).removed, true);
  const bad = await call("/api/folders/add", { method: "POST", headers: json, body: JSON.stringify({ path: join(dir, "missing") }) });
  assert.equal(bad.status, 404);
});

test("repo markdown endpoint needs the token and a known repo", async () => {
  assert.equal((await call("/api/repo/markdown?key=nope")).status, 401);
  assert.equal((await call("/api/repo/markdown?key=nope", { headers: auth() })).status, 404);
});

test("machine endpoints: token, validation, only configured machines", async () => {
  const json = { ...auth(), "content-type": "application/json" };
  assert.equal((await call("/api/machines")).status, 401);
  assert.deepEqual(JSON.parse((await call("/api/machines", { headers: auth() })).body), { machines: [] });
  const bad = await call("/api/machines/add", { method: "POST", headers: json, body: JSON.stringify({ host: "-oProxyCommand=id" }) });
  assert.equal(bad.status, 400);
  const unknown = await call("/api/scan", { method: "POST", headers: json, body: JSON.stringify({ path: "/x", machine: "nope" }) });
  assert.equal(unknown.status, 404);
  assert.equal((await call("/api/machines/fs?name=nope", { headers: auth() })).status, 404);
});

test("update endpoints: status needs the token; restart only where supported", async () => {
  process.env.SELFGUARD_NO_UPDATE_CHECK = "1";
  const json = { ...auth(), "content-type": "application/json" };
  assert.equal((await call("/api/update")).status, 401);
  const st = JSON.parse((await call("/api/update", { headers: auth() })).body);
  assert.equal(st.restartNeeded, false);
  assert.equal(st.enabled, false);
  assert.equal((await call("/api/restart", { method: "POST", headers: json, body: "{}" })).status, 501);
  assert.equal((await call("/api/restart", { method: "POST", headers: { ...auth(), "content-type": "text/plain" }, body: "{}" })).status, 403);
});

test("tailnet endpoints: peers, sharing, pairing need the token and validate input", async () => {
  const json = { ...auth(), "content-type": "application/json" };
  process.env.SELFGUARD_TAILSCALE = "/nonexistent/tailscale";
  try {
    assert.equal((await call("/api/machines/peers")).status, 401);
    const peers = JSON.parse((await call("/api/machines/peers", { headers: auth() })).body);
    assert.equal(peers.tailscale.ok, false);
    assert.equal(peers.tailscale.reason, "not_installed");
    assert.deepEqual(peers.peers, []);
    const sh = JSON.parse((await call("/api/share", { headers: auth() })).body);
    assert.equal(sh.enabled, false);
    assert.deepEqual(sh.grants, []);
    const on = await call("/api/share", { method: "POST", headers: json, body: JSON.stringify({ enabled: true }) });
    assert.equal(JSON.parse(on.body).enabled, true);
    const off = await call("/api/share", { method: "POST", headers: json, body: JSON.stringify({ enabled: false }) });
    assert.equal(JSON.parse(off.body).enabled, false);
    assert.equal((await call("/api/share/approve", { method: "POST", headers: json, body: JSON.stringify({ id: "nope" }) })).status, 404);
    assert.equal(JSON.parse((await call("/api/share/revoke", { method: "POST", headers: json, body: JSON.stringify({ id: "nope" }) })).body).revoked, false);
    assert.equal((await call("/api/pair/status?job=nope", { headers: auth() })).status, 404);
    assert.equal((await call("/api/pair/start", { method: "POST", headers: json, body: JSON.stringify({ peer: "nobody" }) })).status, 404);
    assert.equal((await call("/api/share", { method: "POST", headers: { ...auth(), "content-type": "text/plain" }, body: "{}" })).status, 403);
  } finally {
    delete process.env.SELFGUARD_TAILSCALE;
  }
});

test("serves the page files of its own version, even if they change on disk (no mixed versions)", async () => {
  const { cpSync, appendFileSync } = await import("node:fs");
  const { fileURLToPath } = await import("node:url");
  const { createUiServer } = await import("../src/ui/server.ts");
  const dir = mkdtempSync(join(tmpdir(), "sg-static-"));
  cpSync(fileURLToPath(new URL("../src/ui/static/", import.meta.url)), dir, { recursive: true });
  const s = createUiServer(TOKEN, () => {}, { staticDir: dir });
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  const p = (s.address() as AddressInfo).port;
  try {
    const get = (): Promise<string> =>
      new Promise((resolve, reject) => {
        const req = request({ host: "127.0.0.1", port: p, path: "/app.js", headers: { host: `127.0.0.1:${p}` } }, (res) => {
          let b = "";
          res.on("data", (c) => (b += c));
          res.on("end", () => resolve(b));
        });
        req.on("error", reject);
        req.end();
      });
    const before = await get();
    appendFileSync(join(dir, "app.js"), "\n// a newer version installed over it\n");
    assert.equal(await get(), before);
  } finally {
    s.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("only a verified, older dashboard is replaced by selfguard ui", async () => {
  const { parsePing, shouldReplace } = await import("../src/ui/server.ts");
  assert.equal(parsePing(200, '{"ok":true,"version":"0.7.1"}'), "0.7.1");
  // Another server on the port, or anything that isn't a selfguard dashboard: not ours.
  assert.equal(parsePing(200, "<html>dev server</html>"), null);
  assert.equal(parsePing(200, '{"version":"0.7.1"}'), null);
  assert.equal(parsePing(200, '{"ok":true,"version":"; rm -rf /"}'), null);
  assert.equal(parsePing(401, '{"ok":true,"version":"0.7.1"}'), null);
  assert.equal(shouldReplace("0.7.1", "0.8.1"), true);
  assert.equal(shouldReplace("0.8.1", "0.8.1"), false);
  assert.equal(shouldReplace("0.9.0", "0.8.1"), false, "never downgrade a newer dashboard");
  assert.equal(shouldReplace("unknown", "0.8.1"), false);
});
