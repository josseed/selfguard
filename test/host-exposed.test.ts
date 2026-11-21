// Exposed local services: socket parsers, rules, and the snapshot path through the core.
import assert from "node:assert/strict";
import { mkdirSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import { before, test } from "node:test";
import { freshHome, put } from "./host-helpers.ts";

let sources: typeof import("../src/sources.ts");
let sockets: typeof import("../src/sources/host/sockets.ts");
let exposed: typeof import("../src/sources/host/exposed.ts");
let listening: typeof import("../src/sources/host/listening.ts");
let types: typeof import("../src/sources/types.ts");

before(async () => {
  freshHome();
  process.env.SELFGUARD_HOME = freshHome().home;
  sources = await import("../src/sources.ts");
  sockets = await import("../src/sources/host/sockets.ts");
  exposed = await import("../src/sources/host/exposed.ts");
  listening = await import("../src/sources/host/listening.ts");
  types = await import("../src/sources/types.ts");
  sources.resetSourceExtractors();
  sources.registerBuiltinExtractors();
});

const LSOF = [
  "p100", "claunchd", "f5", "n*:5000",
  "p200", "cnode", "f20", "n*:3000", "f21", "n[::]:3000", "f22", "n127.0.0.1:4000",
  "p300", "cGoogle\\x20Chrome", "f9", "n127.0.0.1:9222",
  "p400", "c/usr/local/bin/ollama", "f3", "n192.168.1.20:11434",
  "p500", "cnode", "f7", "n[::1]:9229", "f8", "n[fe80::1%en0]:9229", "f9", "nbroken", "f10", "n*:99999",
  "p600", "cpython3.12", "f4", "n100.101.102.103:8000",
  "p700", "crapportd", "f4", "n*:52434",
  "p800", "c\u001b[31mevil", "f4", "n*:8080",
  "",
].join("\n");

test("lsof -F output: ports, reach classes, process names; junk lines are skipped", () => {
  const l = sockets.parseLsof(LSOF);
  const show = l.map((s) => `${s.command ?? "?"}:${s.port}:${s.reach}`);
  assert.deepEqual(show, [
    "launchd:5000:wildcard",
    "node:3000:wildcard",
    "node:3000:wildcard",
    "node:4000:loopback",
    "Google Chrome:9222:loopback",
    "ollama:11434:lan",
    "node:9229:loopback",
    "node:9229:lan",
    "python3.12:8000:tailnet",
    "rapportd:52434:wildcard",
    "[31mevil:8080:wildcard",
  ]);
  assert.deepEqual(sockets.parseLsof(""), []);
  assert.doesNotThrow(() => sockets.parseLsof("n\nc\np\nn:::\nn[:1\n\u0000"));
  for (const [h, r] of [["*", "wildcard"], ["0.0.0.0", "wildcard"], ["127.5.5.5", "loopback"], ["[::1]", "loopback"], ["[::]", "wildcard"], ["[::ffff:127.0.0.1]", "loopback"], ["[::ffff:10.0.0.2]", "lan"], ["10.1.2.3", "lan"], ["100.64.0.1", "tailnet"], ["100.128.0.1", "lan"], ["[fd7a:115c:a1e0::1]", "tailnet"], ["[fe80::1%lo0]", "lan"], ["999.1.1.1", null], ["junk", null]] as const) {
    assert.equal(sockets.reachOfText(h), r, h);
  }
});

const TCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 11111 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 22222 1 0000000000000000 100 0 0 10 0
   2: 0501A8C0:2406 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 33333 1 0000000000000000 100 0 0 10 0
   3: 0501A8C0:2406 0100007F:9999 01 00000000:00000000 00:00000000 00000000  1000        0 44444 1 0000000000000000 100 0 0 10 0
   4: ZZZ:1 00000000:0000 0A 0 0 0 0 0 0 55555
`;
const TCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:2CAA 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 66666 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:1538 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 77777 1 0000000000000000 100 0 0 10 0
   2: 0000000000000000FFFF00000501A8C0:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 88888 1 0000000000000000 100 0 0 10 0
`;

test("/proc/net/tcp and tcp6: only LISTEN rows, little-endian addresses decoded to a class", () => {
  const four = sockets.parseProcNet(TCP).map((s) => `${s.port}:${s.reach}:${s.inode}`);
  assert.deepEqual(four, ["8080:wildcard:11111", "3000:loopback:22222", "9222:lan:33333"]);
  const six = sockets.parseProcNet(TCP6).map((s) => `${s.port}:${s.reach}:${s.inode}`);
  assert.deepEqual(six, ["11434:wildcard:66666", "5432:loopback:77777", "8080:lan:88888"]);
  assert.deepEqual(sockets.parseProcNet(""), []);
});

test("Linux reader: names the process owning each exposed socket from /proc/<pid>/fd", () => {
  const { system } = freshHome();
  put(system, "proc/net/tcp", TCP);
  put(system, "proc/net/tcp6", TCP6);
  put(system, "proc/4242/comm", "ollama\n");
  mkdirSync(join(system, "proc", "4242", "fd"), { recursive: true });
  symlinkSync("socket:[66666]", join(system, "proc", "4242", "fd", "7"));
  symlinkSync("/dev/null", join(system, "proc", "4242", "fd", "8"));
  put(system, "proc/self-not-a-pid/comm", "x");
  const l = listening.procListeners()!;
  assert.deepEqual(l.map((s) => `${s.command ?? "?"}:${s.port}:${s.reach}`), [
    "?:8080:wildcard", "?:3000:loopback", "?:9222:lan", "ollama:11434:wildcard", "?:5432:loopback", "?:8080:lan",
  ]);
  delete process.env.SELFGUARD_SYSTEM_ROOT;
});

test("rules: risky ports high+notify (takeover ones urgent), dev processes low, system daemons and loopback ignored", () => {
  const l = sockets.parseLsof(LSOF);
  const w = exposed.exposureWarnings(l);
  const show = w.map((x) => `${x.severity} ${x.rule} ${x.key}${x.urgent ? " U" : ""}${x.notify ? " N" : ""}`);
  assert.deepEqual(show, [
    "low exposed-local-service 3000/node",
    "high exposed-dev-service 11434/ollama N",
    "high exposed-dev-service 9229/node U N",
  ]);
  const msg = w.map((x) => x.message).join("\n");
  assert.match(msg, /node listens on all network interfaces, port 3000/);
  assert.match(msg, /OLLAMA_HOST=127\.0\.0\.1/);
  assert.match(msg, /--inspect=127\.0\.0\.1:9229/);
  assert.doesNotMatch(msg, /192\.168|fe80|rapportd|launchd/);

  const more = exposed.exposureWarnings([
    { port: 9222, reach: "wildcard", command: "launchd" }, // a system name can't hide an urgent port
    { port: 6379, reach: "wildcard" },
    { port: 5432, reach: "lan", command: "postgres" },
    { port: 8080, reach: "wildcard" }, // unknown process, ordinary port: nothing to say
    { port: 8081, reach: "wildcard", command: "Notion" },
    { port: 9222, reach: "tailnet", command: "chrome" },
    { port: 6277, reach: "loopback", command: "node" },
  ]).map((x) => `${x.severity} ${x.key}${x.urgent ? " U" : ""}`);
  assert.deepEqual(more, ["high 9222/launchd U", "high 6379/?", "high 5432/postgres"]);
});

test("process names are sanitized and cannot inject into the message", () => {
  const [w] = exposed.exposureWarnings([{ port: 9222, reach: "wildcard", command: sockets.commandName("../../evil\u001b]8;;x\u0007\nname")! }]);
  assert.ok(w);
  assert.doesNotMatch(w!.message, /[\u0000-\u001f]/);
});

const EMPTY = { refs: new Map(), vulns: new Map() };
const finish = (inv: ReturnType<typeof sources.prepareSources>["inventories"]) => sources.finishSources(inv, EMPTY);
const snap = (rec: { warnings: Array<{ file: string; key?: string }> }) => rec.warnings.filter((w) => w.file === types.SNAPSHOT_FILE).map((w) => w.key);

test("sync/scan take the snapshot, urgent exposure is news on the first scan, warnings are keyed by port and process", () => {
  process.env.SELFGUARD_HOME = freshHome().home;
  listening.setListeningReader(() => [
    { port: 9222, reach: "wildcard", command: "Google Chrome" },
    { port: 3000, reach: "wildcard", command: "node" },
  ]);
  try {
    // No files and no record yet: the input exists anyway, with the snapshot flag.
    const host = sources.sourceInputs([], { machine: true }).find((i) => i.kind === "host" && i.target.scope === "machine")!;
    assert.equal(host.snapshot, true);
    const [out] = finish(sources.prepareSources([host]).inventories);
    assert.deepEqual(snap(out!.record).sort(), ["3000/node", "9222/Google Chrome"]);
    assert.ok(out!.record.warnings.every((w) => w.file !== types.SNAPSHOT_FILE || w.line === 0));
    assert.deepEqual(out!.newWarnings.map((w) => w.key), ["9222/Google Chrome"]);
  } finally {
    listening.setListeningReader();
  }
});

test("check never takes a snapshot; it keeps the last one. A failing snapshot keeps it too; the next good one resolves it", () => {
  process.env.SELFGUARD_HOME = freshHome().home;
  const target = sources.machineTarget();
  let calls = 0;
  listening.setListeningReader(() => (calls++, [{ port: 9229, reach: "wildcard", command: "node" }]));
  try {
    const [first] = finish(sources.prepareSources([{ kind: "host", target, snapshot: true }]).inventories);
    assert.equal(calls, 1);
    sources.saveSource(first!.record);

    // check: changedSourceInputs asks for no snapshot, and without the flag the reader isn't called.
    assert.ok(sources.changedSourceInputs([], { machine: true }).every((i) => !i.snapshot));
    const viaCheck = sources.prepareSources([{ kind: "host", target }]).inventories[0]!.record;
    assert.equal(calls, 1);
    assert.deepEqual(snap(viaCheck), ["9229/node"]);

    listening.setListeningReader(() => null);
    const failed = sources.prepareSources([{ kind: "host", target, snapshot: true }]).inventories[0]!.record;
    assert.deepEqual(snap(failed), ["9229/node"]);

    listening.setListeningReader(() => []);
    const [gone] = finish(sources.prepareSources([{ kind: "host", target, snapshot: true }]).inventories);
    assert.deepEqual(gone!.resolvedWarnings.map((w) => w.key), ["9229/node"]);
    assert.deepEqual(snap(gone!.record), []);
  } finally {
    listening.setListeningReader();
  }
});

test("a repo target has no snapshot", () => {
  freshHome();
  listening.setListeningReader(() => {
    throw new Error("must not be called");
  });
  try {
    const rec = sources.prepareSources([{ kind: "host", target: sources.repoTarget("/nonexistent/repo"), snapshot: true }]).inventories[0]!.record;
    assert.deepEqual(rec.warnings, []);
  } finally {
    listening.setListeningReader();
  }
});

test("SELFGUARD_NO_SOCKETS=1 turns the check off", () => {
  process.env.SELFGUARD_NO_SOCKETS = "1";
  try {
    assert.equal(listening.listening(), null);
  } finally {
    delete process.env.SELFGUARD_NO_SOCKETS;
  }
});

test("darwin: a server on all interfaces is seen by the real lsof", { skip: process.platform !== "darwin" }, async () => {
  const net = await import("node:net");
  const server = net.createServer();
  await new Promise<void>((r) => server.listen(0, "0.0.0.0", r));
  const port = (server.address() as { port: number }).port;
  try {
    const mine = listening.listening()?.filter((s) => s.port === port) ?? [];
    assert.ok(mine.length >= 1, "listening socket found");
    assert.equal(mine[0]!.reach, "wildcard");
    assert.match(mine[0]!.command ?? "", /node/);
  } finally {
    server.close();
  }
});
