import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { FAKE_TAILSCALE, fakeTailnet, type FakeNode } from "./tailnet-helpers.ts";

const A: FakeNode = { id: "nodeA", name: "mac-a", ips: ["100.64.0.1"] };
const B: FakeNode = { id: "nodeB", name: "mac-b", ips: ["127.0.0.1"] };
const net = fakeTailnet(B, [A]);
const home = realpathSync(mkdtempSync(join(tmpdir(), "sg-share-home-")));
const code = join(home, "code");

let share: typeof import("../src/share.ts");
let remote: typeof import("../src/remote.ts");
let config: typeof import("../src/config.ts");
let server: Awaited<ReturnType<typeof import("../src/share.ts").startShareServer>>;
let port: number;

before(async () => {
  process.env.SELFGUARD_TAILSCALE = FAKE_TAILSCALE;
  process.env.SG_FAKE_TAILSCALE_DIR = net.dir;
  process.env.SELFGUARD_HOME = mkdtempSync(join(tmpdir(), "sg-share-state-"));
  process.env.SELFGUARD_NO_NOTIFY = "1";
  process.env.HOME = home;
  net.whois("127.0.0.1", A); // requests in these tests come from 127.0.0.1: "machine A"
  mkdirSync(join(code, "api", ".git"), { recursive: true });
  writeFileSync(join(code, "api", ".git", "HEAD"), "ref: refs/heads/main\n");
  writeFileSync(join(code, "api", "package.json"), "{}");
  writeFileSync(join(code, "api", "package-lock.json"), '{"lockfileVersion":3}');
  mkdirSync(join(code, "linked"));
  writeFileSync(join(code, "linked", "package.json"), "{}");
  symlinkSync("/etc/hosts", join(code, "linked", "package-lock.json"));
  mkdirSync(join(code, "huge"));
  writeFileSync(join(code, "huge", "package-lock.json"), "");
  truncateSync(join(code, "huge", "package-lock.json"), 51 * 1024 * 1024); // sparse: over the 50 MB cap
  mkdirSync(join(home, "secret"));
  writeFileSync(join(home, "secret", "package-lock.json"), '{"secret":true}');
  symlinkSync(join(home, "secret"), join(code, "escape"));
  share = await import("../src/share.ts");
  remote = await import("../src/remote.ts");
  config = await import("../src/config.ts");
  config.saveConfig({ ...config.loadConfig(), share: { enabled: true, port: 0, allowOtherUsers: false } });
  server = await share.startShareServer({ port: 0, whoisTtlMs: 0, pairRequestsPer10Min: 100 });
  port = server.addresses[0]!.port;
});
after(() => server.close());

const target = (credential: string) => ({ host: "127.0.0.1", port, transport: "share" as const, credential });

async function pair(scope = "~/code"): Promise<string> {
  const s = await share.requestPairing("127.0.0.1", port, "mac-a");
  const pending = share.listShareRequests();
  assert.equal(pending.find((p) => p.id === s.requestId)?.code, s.code, "both screens show the same code");
  await share.approveShareRequest(s.requestId, { scope });
  const r = await share.waitForPairing(s, { intervalMs: 20 });
  assert.equal(r.status, "approved");
  return r.status === "approved" ? r.payload.credential : "";
}

test("listens only on this machine's tailnet addresses", async () => {
  assert.deepEqual(server.addresses.map((a) => a.host), ["127.0.0.1"]);
  await assert.rejects(share.startShareServer({ hosts: ["0.0.0.0"], port: 0 }), /all interfaces/);
  const empty = fakeTailnet({ ...B, ips: [] });
  process.env.SG_FAKE_TAILSCALE_DIR = empty.dir;
  try {
    await assert.rejects(share.startShareServer({ port: 0 }), /no Tailscale address/);
  } finally {
    process.env.SG_FAKE_TAILSCALE_DIR = net.dir;
  }
  const hello = await share.probeShare("127.0.0.1", port);
  assert.equal(hello?.name, "mac-b");
  assert.equal(hello?.pairing, true);
});

test("pairing: same code on both sides, credential only after approval", async () => {
  const before = await remote.listMachine(target("x".repeat(43)), [{ path: "~/code", depth: 3 }]).catch((e) => e);
  assert.equal(before.code, "auth", "an unknown credential reads nothing");
  const cred = await pair();
  const grants = share.listGrants();
  assert.equal(grants.length, 1);
  assert.equal(grants[0]!.name, "mac-a");
  const stored = readFileSync(join(process.env.SELFGUARD_HOME!, "share", "grants.json"), "utf8");
  assert.ok(!stored.includes(cred), "only the hash is stored");
});

test("a paired machine reads lockfiles inside the scope, nothing else", async () => {
  const cred = await pair();
  const t = target(cred);
  const list = await remote.listMachine(t, [{ path: "~/code", depth: 3 }, { path: "~", depth: 2 }, { path: "/etc", depth: 1 }]);
  assert.equal(list.scope, code);
  // "linked" has only a symlinked lockfile and no .git: not a project (same as the sh reader).
  assert.deepEqual(list.projects.map((p) => p.root.slice(code.length + 1)).sort(), ["api", "huge"]);
  assert.deepEqual(list.roots.filter((r) => r.ok).map((r) => r.path), [code], "~ and /etc are outside the scope");
  const lock = join(code, "api", "package-lock.json");
  const files = await remote.fetchFiles(t, [lock, join(code, "linked", "package-lock.json"), join(code, "huge", "package-lock.json"), join(home, "secret", "package-lock.json"), join(code, "escape", "package-lock.json"), join(code, "api", ".git", "HEAD")]);
  assert.equal(files.get(lock)?.toString(), '{"lockfileVersion":3}');
  for (const f of ["linked", "huge", "secret", "escape"]) assert.equal([...files].find(([k]) => k.includes(`/${f}/`))?.[1] ?? null, null, f);
  assert.equal(files.get(join(code, "api", ".git", "HEAD")), null, "only lockfiles and package.json");
  await assert.rejects(remote.browseMachine(t, home), /outside the allowed folder/);
  assert.equal((await remote.browseMachine(t, "~/code")).parent, null);
});

test("rejected and expired requests read nothing", async () => {
  const s = await share.requestPairing("127.0.0.1", port, "mac-a");
  assert.equal(await share.rejectShareRequest(s.requestId), true);
  assert.equal((await share.pollPairing(s)).status, "rejected");
  const s2 = await share.requestPairing("127.0.0.1", port, "mac-a");
  const file = join(process.env.SELFGUARD_HOME!, "share", "pending.json");
  const pending = JSON.parse(readFileSync(file, "utf8"));
  for (const p of pending) p.expiresAt = new Date(Date.now() - 1000).toISOString();
  writeFileSync(file, JSON.stringify(pending));
  assert.equal((await share.pollPairing(s2)).status, "expired");
  assert.deepEqual(share.listShareRequests(), []);
  await assert.rejects(share.approveShareRequest(s2.requestId), /expired/);
});

test("only machines of the same Tailscale user can pair (unless allowed)", async () => {
  net.whois("127.0.0.1", { ...A, login: "someone@else.com" });
  try {
    await assert.rejects(share.requestPairing("127.0.0.1", port, "mac-a"), /own Tailscale user/);
    config.saveConfig({ ...config.loadConfig(), share: { enabled: true, port: 0, allowOtherUsers: true } });
    const s = await share.requestPairing("127.0.0.1", port, "mac-a");
    assert.equal(await share.rejectShareRequest(s.requestId), true);
  } finally {
    config.saveConfig({ ...config.loadConfig(), share: { enabled: true, port: 0, allowOtherUsers: false } });
    net.whois("127.0.0.1", A);
  }
  net.whois("127.0.0.1", null);
  try {
    await assert.rejects(share.requestPairing("127.0.0.1", port, "mac-a"), /this tailnet/);
  } finally {
    net.whois("127.0.0.1", A);
  }
});

test("a credential used from another machine is revoked", async () => {
  const cred = await pair();
  net.whois("127.0.0.1", { id: "nodeX", name: "intruder", ips: ["100.64.0.9"] });
  try {
    const e = await remote.listMachine(target(cred), [{ path: "~/code", depth: 1 }]).catch((x) => x);
    assert.equal(e.code, "auth");
  } finally {
    net.whois("127.0.0.1", A);
  }
  assert.deepEqual(share.listGrants(), [], "revoked");
  const again = await remote.listMachine(target(cred), [{ path: "~/code", depth: 1 }]).catch((x) => x);
  assert.equal(again.code, "auth", "even from the right machine now");
});

test("revoke and share off cut access at once", async () => {
  const cred = await pair();
  assert.ok((await remote.testHost(target(cred))).scope);
  assert.equal(await share.revokeGrant("mac-a"), true);
  assert.equal((await remote.testHost(target(cred)).catch((e) => e)).code, "auth");
  const cred2 = await pair();
  config.saveConfig({ ...config.loadConfig(), share: { enabled: false, port: 0, allowOtherUsers: false } });
  try {
    assert.equal(await share.probeShare("127.0.0.1", port), null);
    assert.equal((await remote.testHost(target(cred2)).catch((e) => e)).code, "unreachable");
  } finally {
    config.saveConfig({ ...config.loadConfig(), share: { enabled: true, port: 0, allowOtherUsers: false } });
  }
  assert.ok(readFileSync(share.accessLogFile(), "utf8").includes('"op":"list"'), "accesses are logged");
});

test("pairing requests are rate limited per address", async () => {
  const fresh = await share.startShareServer({ port: 0, whoisTtlMs: 0 });
  const p = fresh.addresses[0]!.port;
  try {
    const results: string[] = [];
    for (let i = 0; i < 6; i++) {
      results.push(await share.requestPairing("127.0.0.1", p, "mac-a").then(() => "ok", (e) => e.code));
    }
    assert.deepEqual(results.slice(-1), ["rate_limited"]);
  } finally {
    await fresh.close();
  }
});

test("the sealed credential only opens with the requester's key", () => {
  const a = share.newEphemeralKey();
  const b = share.newEphemeralKey();
  const sealed = share.seal({ credential: "c" }, b.privateRaw, a.publicRaw, b.publicRaw);
  assert.deepEqual(share.unseal(sealed, a.privateRaw, a.publicRaw, b.publicRaw), { credential: "c" });
  const other = share.newEphemeralKey();
  assert.throws(() => share.unseal(sealed, other.privateRaw, other.publicRaw, b.publicRaw));
  assert.equal(share.pairingCode(a.publicRaw, b.publicRaw).length, 6);
});

test("only our own address as Host, and JSON only (no DNS rebinding from a browser)", async () => {
  const { request } = await import("node:http");
  const raw = (path: string, headers: Record<string, string>, body = ""): Promise<number> =>
    new Promise((resolve, reject) => {
      const req = request({ host: "127.0.0.1", port, path, method: body ? "POST" : "GET", headers }, (res) => {
        res.resume();
        resolve(res.statusCode!);
      });
      req.on("error", reject);
      req.end(body || undefined);
    });
  assert.equal(await raw("/hello", { host: "evil.example" }), 421);
  assert.equal(await raw("/hello", { host: `evil.example:${port}` }), 421);
  assert.equal(await raw("/hello", { host: `127.0.0.1:${port}` }), 200);
  const key = share.newEphemeralKey().publicRaw.toString("base64url");
  const body = JSON.stringify({ name: "page", publicKey: key });
  assert.equal(await raw("/pair/request", { host: `127.0.0.1:${port}`, "content-type": "text/plain" }, body), 415);
  assert.equal(await raw("/pair/request", { host: `rebound.example:${port}`, "content-type": "application/json" }, body), 421);
});

test("git facts never come from outside the granted folder", async () => {
  // ~/code is a repo whose remote URL carries a token; the grant is only ~/code/app.
  mkdirSync(join(code, ".git"), { recursive: true });
  writeFileSync(join(code, ".git", "HEAD"), "ref: refs/heads/main\n");
  writeFileSync(join(code, ".git", "config"), '[remote "origin"]\n\turl = https://me:SECRET-TOKEN@github.com/me/code.git\n');
  mkdirSync(join(code, "app"), { recursive: true });
  writeFileSync(join(code, "app", "package-lock.json"), "{}");
  // and a worktree inside it whose git dir lives outside
  mkdirSync(join(code, "app", "wt"), { recursive: true });
  writeFileSync(join(code, "app", "wt", "package-lock.json"), "{}");
  writeFileSync(join(code, "app", "wt", ".git"), `gitdir: ${join(code, ".git")}\n`);
  const cred = await pair("~/code/app");
  const t = target(cred);
  const raw = (await remote.runRemote(t, "SGREQ1 list\n3\t~/code/app\n", { maxBytes: 1 << 20, timeoutMs: 10_000 })).toString();
  assert.ok(!raw.includes("SECRET-TOKEN"), "parent repo config not read");
  assert.ok(!/^G\t/m.test(raw), "no git facts from outside the scope");
  const list = await remote.listMachine(t, [{ path: "~/code/app", depth: 3 }]);
  assert.deepEqual(list.projects.map((p) => [p.root.slice(code.length + 1), p.git]), [["app", null], ["app/wt", null]]);
  rmSync(join(code, ".git"), { recursive: true });
});

test("a whois hiccup never revokes a grant nor ends a pairing", async () => {
  const cred = await pair();
  net.whois("127.0.0.1", "error");
  try {
    const e = await remote.listMachine(target(cred), [{ path: "~/code", depth: 1 }]).catch((x) => x);
    assert.equal(e.code, "unreachable", "retry later, not 'pair again'");
    assert.match(e.message, /couldn't check/);
  } finally {
    net.whois("127.0.0.1", A);
  }
  assert.equal(share.listGrants().length, 1, "grant kept");
  assert.ok((await remote.testHost(target(cred))).scope, "works again once Tailscale answers");

  // Approved while the requester's polls can't be identified: it keeps waiting, then gets it.
  const s = await share.requestPairing("127.0.0.1", port, "mac-a");
  net.whois("127.0.0.1", "error");
  const waiting = share.waitForPairing(s, { intervalMs: 30 });
  await share.approveShareRequest(s.requestId, { scope: "~/code" });
  await new Promise((r) => setTimeout(r, 150));
  net.whois("127.0.0.1", A);
  assert.equal((await waiting).status, "approved");
});

test("an address that can't be bound doesn't take the others down", async () => {
  // 192.0.2.1 (TEST-NET-1) isn't an address of this machine: binding it fails.
  const s = await share.startShareServer({ hosts: ["127.0.0.1", "192.0.2.1"], port: 0 });
  try {
    assert.deepEqual(s.addresses.map((a) => a.host), ["127.0.0.1"]);
    assert.deepEqual(s.failed.map((f) => f.host), ["192.0.2.1"]);
  } finally {
    await s.close();
  }
  await assert.rejects(share.startShareServer({ hosts: ["192.0.2.1"], port: 0 }), /couldn't listen/);
});
