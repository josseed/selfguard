import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { copyFixture } from "./helpers.ts";
import { FAKE_TAILSCALE, fakeTailnet } from "./tailnet-helpers.ts";

// Fake OSV: lodash@4.17.20 is vulnerable.
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

// One fake tailnet seen from this process: "mac-b" answers on 127.0.0.1 (where the share server
// listens) and requests to it come from 127.0.0.1, which whois says is "mac-a".
const MAC_A = { id: "nodeA", name: "mac-a", ips: ["127.0.0.1"] };
const net = fakeTailnet(MAC_A, [{ id: "nodeB", name: "mac-b", ips: ["127.0.0.1"] }]);
const remoteHome = realpathSync(mkdtempSync(join(tmpdir(), "sg-tm-home-")));

let api: typeof import("../src/api.ts");
let machines: typeof import("../src/machines.ts");
let share: typeof import("../src/share.ts");
let config: typeof import("../src/config.ts");
let server: Awaited<ReturnType<typeof import("../src/share.ts").startShareServer>>;
let port: number;

before(async () => {
  await new Promise<void>((r) => osv.listen(0, "127.0.0.1", r));
  process.env.SELFGUARD_OSV_API = `http://127.0.0.1:${(osv.address() as AddressInfo).port}/v1`;
  process.env.SELFGUARD_HOME = mkdtempSync(join(tmpdir(), "sg-tm-state-"));
  process.env.SELFGUARD_TAILSCALE = FAKE_TAILSCALE;
  process.env.SG_FAKE_TAILSCALE_DIR = net.dir;
  process.env.SELFGUARD_SSH = fileURLToPath(new URL("./bin/fake-ssh", import.meta.url));
  process.env.SG_FAKE_HOME = remoteHome; // the SSH side's home
  process.env.HOME = remoteHome; // the share side's home (same files)
  process.env.SELFGUARD_NO_NOTIFY = "1";
  process.env.SELFGUARD_NO_LAUNCHD = "1";
  net.whois("127.0.0.1", MAC_A);
  for (const name of ["api", "web"]) {
    const dir = join(remoteHome, "code", "acme", name);
    copyFixture("v3", dir);
    mkdirSync(join(dir, ".git"));
    writeFileSync(join(dir, ".git", "HEAD"), "ref: refs/heads/main\n");
    writeFileSync(join(dir, ".git", "config"), `[remote "origin"]\n\turl = git@github.com:acme/${name}.git\n`);
  }
  api = await import("../src/api.ts");
  machines = await import("../src/machines.ts");
  share = await import("../src/share.ts");
  config = await import("../src/config.ts");
  config.saveConfig({ ...config.loadConfig(), share: { enabled: true, port: 0, allowOtherUsers: false } });
  server = await share.startShareServer({ port: 0, whoisTtlMs: 0, pairRequestsPer10Min: 100 });
  port = server.addresses[0]!.port;
});
after(async () => {
  await server.close();
  osv.close();
});

/** Pair from "mac-a" with "mac-b", approving on mac-b with the given folders. */
async function pairWithB(opts: { replace?: string; name?: string } = {}): Promise<import("../src/machines.ts").MachineInfo> {
  const start = await machines.startPairing("mac-b", { port });
  const done = machines.finishPairing(start, { ...opts, intervalMs: 20 });
  const req = share.listShareRequests().find((r) => r.code === start.session.code)!;
  await share.approveShareRequest(req.id, { scope: "~/code", roots: [{ path: "~/code", depth: 3 }] });
  return done;
}

const snapshot = (machine: string) =>
  api.getStatus().projects
    .filter((p) => p.machine === machine)
    .map((p) => ({ path: p.path, lockType: p.lockType, packages: p.packages, worst: p.worstSeverity, vulnerable: p.vulnerablePackages, branch: p.repo?.branch, label: p.repo?.label, worktree: p.repo?.worktree }))
    .sort((a, b) => a.path.localeCompare(b.path));

test("configs written before 0.8 load as SSH machines", () => {
  config.saveConfig({ ...config.loadConfig(), machines: [] });
  const raw = { ...config.loadConfig(), machines: [{ name: "old", host: "old.example", roots: [], exclude: [] }] };
  writeFileSync(join(process.env.SELFGUARD_HOME!, "config.json"), JSON.stringify(raw));
  assert.equal(config.loadConfig().machines[0]!.transport, "ssh");
  config.saveConfig({ ...config.loadConfig(), machines: [] });
});

test("peers: the share-capable machine is offered a connection", async () => {
  const r = await machines.machinePeers({ sharePort: port });
  assert.equal(r.tailscale.ok, true);
  assert.equal(r.self?.name, "mac-a");
  const b = r.peers.find((p) => p.name === "mac-b")!;
  assert.equal(b.share?.pairing, true);
  assert.equal(b.action, "connect");
  assert.ok(!r.peers.some((p) => p.nodeId === "nodeA"), "this machine itself is not listed");
});

test("sync over share gives the same results as over SSH", async () => {
  await api.addMachine("via-ssh", "devbox", { mode: "ssh", roots: [{ path: "~/code", depth: 3 }] });
  const m = await pairWithB();
  assert.equal(m.name, "mac-b");
  assert.equal(m.transport, "share");
  assert.deepEqual(m.roots, [{ path: "~/code", depth: 3 }], "folders suggested by mac-b");
  const r = await api.checkMachines();
  assert.deepEqual(r.machines.map((x) => [x.name, x.ok, x.projects]).sort(), [["mac-b", true, 2], ["via-ssh", true, 2]]);
  const viaShare = snapshot("mac-b");
  assert.equal(viaShare.length, 2);
  assert.equal(viaShare[0]!.worst, "critical");
  assert.deepEqual(viaShare, snapshot("via-ssh"));
  assert.equal((await machines.machinePeers({ sharePort: port })).peers.find((p) => p.name === "mac-b")!.action, "added");
});

test("migrate an SSH machine to share, keeping its history", async () => {
  const before = snapshot("via-ssh");
  const m = await pairWithB({ replace: "via-ssh" });
  assert.equal(m.name, "via-ssh");
  assert.equal(m.transport, "share");
  assert.deepEqual(snapshot("via-ssh"), before, "records kept");
  const r = await api.checkMachines({ only: ["via-ssh"] });
  assert.equal(r.machines[0]!.ok, true);
});

test("pairing again replaces the old credential; removing revokes the grant over there", async () => {
  // via-ssh was paired with mac-b after the mac-b entry: one grant per machine, the old one is gone.
  const stale = await api.checkMachines({ only: ["mac-b"] });
  assert.equal(stale.machines[0]!.ok, false);
  assert.match(stale.machines[0]!.error ?? "", /pair again/);
  assert.equal(share.listGrants().length, 1);
  const r = await api.removeMachine("via-ssh");
  assert.equal(r.revoked, true);
  assert.equal(share.listGrants().length, 0);
});

test("a taken name is refused before asking; pairing again replaces the machine", async () => {
  await api.addMachine("devbox", "devbox", { mode: "ssh", roots: [{ path: "~/code", depth: 3 }] });
  await assert.rejects(machines.startPairing("mac-b", { port, name: "devbox" }), /already exists/);
  assert.equal(share.listShareRequests().length, 0, "nothing was asked");
  const m = await pairWithB({ name: "shared-b" });
  assert.equal(m.name, "shared-b");
  // Pair again (e.g. after a revoke): same entry, new credential.
  await share.revokeGrant("mac-a");
  const start = await machines.startRepairing("shared-b");
  const done = machines.finishPairing(start, { replace: "shared-b", intervalMs: 20 });
  const req = share.listShareRequests().find((r) => r.code === start.session.code)!;
  await share.approveShareRequest(req.id, { scope: "~/code" });
  await done;
  assert.equal(config.loadConfig().machines.filter((x) => x.name === "shared-b").length, 1);
  assert.equal((await api.checkMachines({ only: ["shared-b"] })).machines[0]!.ok, true);
});

test("moving a machine from sharing to SSH ends the sharing access", async () => {
  assert.equal(share.listGrants().length, 1);
  const r = await api.addMachine("shared-b", "devbox", { mode: "ssh" });
  assert.equal(r.installed, true);
  assert.equal(r.machine.transport, "ssh");
  assert.equal(share.listGrants().length, 0, "grant revoked over there");
  assert.equal(machines.loadShareCredential("shared-b"), null, "credential deleted here");
});
