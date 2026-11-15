import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { copyFixture } from "./helpers.ts";

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

const sshLog = join(mkdtempSync(join(tmpdir(), "sg-sshlog-")), "log");
let api: typeof import("../src/api.ts");
let machines: typeof import("../src/machines.ts");
let code: string;
let remoteHome: string;

before(async () => {
  await new Promise<void>((r) => osv.listen(0, "127.0.0.1", r));
  process.env.SELFGUARD_OSV_API = `http://127.0.0.1:${(osv.address() as AddressInfo).port}/v1`;
  process.env.SELFGUARD_HOME = mkdtempSync(join(tmpdir(), "sg-machines-"));
  process.env.SELFGUARD_SSH = fileURLToPath(new URL("./bin/fake-ssh", import.meta.url));
  process.env.SG_FAKE_SSH_LOG = sshLog;
  process.env.SELFGUARD_NO_NOTIFY = "1";
  process.env.SELFGUARD_NO_LAUNCHD = "1";
  api = await import("../src/api.ts");
  machines = await import("../src/machines.ts");
  // The "server": its home has ~/code/acme/api with lodash@4.17.20 in the lockfile.
  remoteHome = realpathSync(mkdtempSync(join(tmpdir(), "sg-server-home-")));
  process.env.SG_FAKE_HOME = remoteHome;
  code = join(remoteHome, "code");
  copyFixture("v3", join(code, "acme", "api"));
  mkdirSync(join(code, "acme", "api", ".git"));
  writeFileSync(join(code, "acme", "api", ".git", "HEAD"), "ref: refs/heads/main\n");
  writeFileSync(join(code, "acme", "api", ".git", "config"), '[remote "origin"]\n\turl = git@github.com:acme/api.git\n');
});
after(() => osv.close());

const sshCalls = (): number => (existsSync(sshLog) ? readFileSync(sshLog, "utf8").trim().split("\n").length : 0);

test("machine names and hosts are validated", async () => {
  await assert.rejects(api.addMachine("Dev Box", "devbox"), /name/);
  await assert.rejects(api.addMachine("devbox", "-oProxyCommand=id"), /invalid host/);
  assert.throws(() => api.addMachineRoot("nope", "~/code"), /unknown machine/);
});

test("add a machine (restricted key by default), sync it, find its vulnerable repo", async () => {
  const r0 = await api.addMachine("devbox", "devbox.tail1234.ts.net");
  assert.equal(r0.installed, true, r0.installError ?? "");
  assert.equal(r0.machine.mode, "restricted");
  assert.equal(r0.machine.status.home, remoteHome);
  const ak = readFileSync(join(remoteHome, ".ssh", "authorized_keys"), "utf8");
  assert.match(ak, /^restrict,command="\/bin\/sh \.selfguard-reader\/reader\.sh" ssh-ed25519 \S+ selfguard:devbox@/m);
  assert.ok(existsSync(join(process.env.SELFGUARD_HOME!, "ssh", "devbox_ed25519")));
  // From now on every call uses the dedicated key.
  api.addMachineRoot("devbox", "~/code", 3);
  const r = await api.checkMachines({ notify: true });
  assert.deepEqual(r.machines.map((x) => [x.name, x.ok, x.projects, x.rescanned]), [["devbox", true, 1, 1]]);

  const status = api.getStatus();
  const g = status.repos.find((x) => x.machine === "devbox")!;
  assert.equal(g.key, "devbox|github.com/acme/api");
  assert.equal(g.label, "acme/api");
  assert.equal(g.worstSeverity, "critical");
  assert.equal(g.folder?.label, "devbox › acme");
  assert.equal(g.checkouts[0]!.branch, "main");

  // First sync of a machine is its baseline: logged, not notified.
  const events = readFileSync(join(process.env.SELFGUARD_HOME!, "events.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(events.at(-1).machine, "devbox");
  assert.equal(events.at(-1).repo, "devbox · acme/api");

  const att = api.getAttention().find((a) => a.machine === "devbox")!;
  assert.equal(att.label, "devbox · acme/api");
  const md = api.getRepoMarkdown(g.key).markdown;
  assert.match(md, /- Machine: `devbox` \(ssh `devbox\.tail1234\.ts\.net`\)/);
  assert.match(md, /selfguard machines sync devbox/);
});

test("unchanged machine: one listing, no file transfer, no rescan", async () => {
  const before = sshCalls();
  const r = await api.checkMachines();
  assert.equal(r.machines[0]!.rescanned, 0);
  assert.equal(sshCalls() - before, 1);
});

test("a changed lockfile is fetched and re-scanned; a fix is noticed", async () => {
  const lock = join(code, "acme", "api", "package-lock.json");
  writeFileSync(lock, readFileSync(lock, "utf8").replaceAll("4.17.20", "4.17.21"));
  utimesSync(lock, new Date(), new Date(Date.now() + 5000));
  const r = await api.checkMachines();
  assert.equal(r.machines[0]!.rescanned, 1);
  const g = api.getStatus().repos.find((x) => x.machine === "devbox")!;
  assert.equal(g.worstSeverity, null);
  const events = readFileSync(join(process.env.SELFGUARD_HOME!, "events.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(events.at(-1).kind, "resolved");
});

test("full sync includes machines and keeps going when one is down", async () => {
  const st = await api.addMachine("staging", "staging", { mode: "ssh" });
  assert.equal(st.installed, true);
  assert.equal(st.setup, null);
  api.addMachineRoot("staging", "~/code");
  const dir = mkdtempSync(join(tmpdir(), "sg-down-"));
  const fake = process.env.SELFGUARD_SSH!;
  // staging is unreachable, devbox still answers
  writeFileSync(join(dir, "ssh"), `#!/bin/sh\ncase "$*" in *" staging "*) echo 'ssh: connect to host staging port 22: Connection refused' >&2; exit 255;; esac\nexec ${fake} "$@"\n`, { mode: 0o755 });
  process.env.SELFGUARD_SSH = join(dir, "ssh");
  try {
    const r = await api.sync();
    const byName = Object.fromEntries(r.machines.map((m) => [m.name, m]));
    assert.equal(byName.devbox?.ok, true);
    assert.equal(byName.staging?.ok, false);
    assert.match(byName.staging?.error ?? "", /Connection refused/);
    assert.match(api.listMachines().find((m) => m.name === "staging")!.status.error ?? "", /Connection refused/);
  } finally {
    process.env.SELFGUARD_SSH = fake;
  }
});

test("a project that disappears is forgotten; excluded ones stay out", async () => {
  copyFixture("v3", join(code, "acme", "web"));
  await api.checkMachines({ only: ["devbox"] });
  assert.equal(api.getStatus().projects.filter((p) => p.machine === "devbox").length, 2);
  rmSync(join(code, "acme", "web"), { recursive: true });
  await api.checkMachines({ only: ["devbox"] });
  assert.equal(api.getStatus().projects.filter((p) => p.machine === "devbox").length, 1);

  const path = join(code, "acme", "api");
  api.excludeOnMachine("devbox", path);
  await api.checkMachines({ only: ["devbox"] });
  assert.equal(api.getStatus().projects.filter((p) => p.machine === "devbox").length, 0);
  api.unexcludeOnMachine("devbox", path);
  await api.checkMachines({ only: ["devbox"] });
  assert.equal(api.getStatus().projects.filter((p) => p.machine === "devbox").length, 1);
});

test("a machine can be set up by hand, then verified", async () => {
  const r = await api.addMachine("manual", "manual", { install: false, scope: "~/code" });
  assert.equal(r.installed, false);
  assert.match(r.setup!.installScript, /reader\.sh/);
  assert.equal(api.listMachines().find((m) => m.name === "manual")!.status.errorCode, "not_installed");
  await assert.rejects(api.verifyMachine("manual"));
  const { runInstall } = await import("../src/remote.ts");
  await runInstall({ host: "manual" }, r.setup!.installScript); // what the user pastes on the machine
  const m = await api.verifyMachine("manual");
  assert.equal(m.status.error, null);
  const removed = await api.removeMachine("manual");
  assert.deepEqual([removed.removed, removed.revoked], [true, true]);
  assert.doesNotMatch(readFileSync(join(remoteHome, ".ssh", "authorized_keys"), "utf8"), /selfguard:manual@/);
});

test("removing a machine forgets its results, key and key line", async () => {
  const r = await api.removeMachine("devbox");
  assert.deepEqual([r.removed, r.revoked], [true, true]);
  assert.equal(existsSync(join(process.env.SELFGUARD_HOME!, "ssh", "devbox_ed25519")), false);
  assert.doesNotMatch(readFileSync(join(remoteHome, ".ssh", "authorized_keys"), "utf8"), /selfguard:devbox@/);
  assert.equal(api.getStatus().repos.some((g) => g.machine === "devbox"), false);
  assert.equal(existsSync(join(process.env.SELFGUARD_HOME!, "machines", "devbox")), false);
  assert.equal(machines.suggestName("me@Dev_Box.tail1.ts.net"), "dev-box");
});

test("projects without a lockfile are not re-scanned on every check", async () => {
  await api.addMachine("devbox2", "devbox2");
  const dir = join(code, "nolock");
  mkdirSync(join(dir, ".git"), { recursive: true });
  writeFileSync(join(dir, "package.json"), "{}");
  writeFileSync(join(dir, ".git", "HEAD"), "ref: refs/heads/main\n");
  api.addMachineRoot("devbox2", dir, 1);
  assert.equal((await api.checkMachines({ only: ["devbox2"] })).machines[0]!.rescanned, 1);
  assert.equal((await api.checkMachines({ only: ["devbox2"] })).machines[0]!.rescanned, 0);
});
