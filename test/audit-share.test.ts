/**
 * Regression tests for the share service and the two readers (sh and TypeScript): fetch
 * amplification, tagged Tailscale devices, symlinks inside git dirs, control characters in
 * folder names and the authorized_keys marker match. Each reader case runs on both readers
 * (every POSIX shell found here) and checks they still give the same answer.
 */
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { gunzipSync } from "node:zlib";
import { FAKE_TAILSCALE, fakeTailnet, type FakeNode } from "./tailnet-helpers.ts";

const tmp = (p: string): string => realpathSync(mkdtempSync(join(tmpdir(), p)));
const SHELLS = ["/bin/sh", ...["/bin/dash", "/usr/bin/dash", "/opt/homebrew/bin/dash", "/usr/local/bin/dash"].filter(existsSync).slice(0, 1)];

let answerReader: typeof import("../src/reader.ts").answerReader;
let remote: typeof import("../src/remote.ts");

before(async () => {
  process.env.SELFGUARD_HOME = tmp("sg-audit-state-");
  process.env.SELFGUARD_NO_NOTIFY = "1";
  ({ answerReader } = await import("../src/reader.ts"));
  remote = await import("../src/remote.ts");
});

/** The installed sh reader, run directly (what sshd's forced command does). */
function shReader(shell: string, scope: string, home: string, request: string): Buffer {
  const dir = tmp("sg-audit-reader-");
  writeFileSync(join(dir, "reader.sh"), remote.readerScript(scope, "selfguard:test@mac"));
  return execFileSync(shell, [join(dir, "reader.sh")], { input: request, cwd: home, env: { PATH: process.env.PATH!, HOME: home }, maxBuffer: 512 << 20 });
}

/** An answer with its fetch stream unzipped (gzip bytes differ between gzip and zlib). */
function plain(answer: Buffer): Buffer {
  const nl = answer.indexOf(0x0a);
  const rest = answer.subarray(nl + 1);
  if (rest[0] === 0x0a && rest[1] === 0x1f && rest[2] === 0x8b) return Buffer.concat([answer.subarray(0, nl + 2), gunzipSync(rest.subarray(1))]);
  return answer;
}

/** "size path" of every file in a fetch answer. */
function frames(answer: Buffer): string[] {
  const buf = plain(answer);
  let pos = buf.indexOf(0x0a) + 2;
  const out: string[] = [];
  while (pos < buf.length) {
    const nl = buf.indexOf(0x0a, pos);
    const [, size, path] = buf.subarray(pos, nl).toString("utf8").split("\t") as [string, string, string];
    out.push(`${size} ${path}`);
    pos = nl + 1 + Math.max(0, Number(size));
  }
  return out;
}

/** Both readers answer `request`: same bytes (fetch streams compared unzipped). Returns the TS answer. */
async function bothReaders(scope: string, home: string, request: string): Promise<Buffer> {
  const ts = await answerReader(request, { scope, home });
  const digest = (b: Buffer): string => createHash("sha256").update(plain(b)).digest("hex");
  for (const shell of SHELLS) {
    const sh = shReader(shell, scope, home, request);
    if (plain(ts).length < 1 << 20) assert.equal(plain(sh).toString("latin1"), plain(ts).toString("latin1"), `${shell} and reader.ts differ`);
    else {
      assert.deepEqual(frames(sh), frames(ts), `${shell} and reader.ts differ`);
      assert.equal(digest(sh), digest(ts), `${shell} and reader.ts differ`);
    }
  }
  return ts;
}

// ---------- 1. fetch amplification ----------

test("fetch: a file asked many times is answered once (both readers)", async () => {
  const home = tmp("sg-audit-dup-");
  mkdirSync(join(home, "p"));
  writeFileSync(join(home, "p", "package-lock.json"), '{"lockfileVersion":3}');
  writeFileSync(join(home, "p", "package.json"), "{}");
  const lock = join(home, "p", "package-lock.json");
  const req = `SGREQ1 fetch\n${Array(500).fill(lock).join("\n")}\n${join(home, "p", "package.json")}\n${lock}\n`;
  const out = await bothReaders(home, home, req);
  assert.deepEqual(frames(out), [`21 ${lock}`, `2 ${join(home, "p", "package.json")}`]);
});

test("fetch: at most 64 MB of file bodies per answer, the rest reported unreadable (both readers)", async () => {
  const home = tmp("sg-audit-cap-");
  const files = ["a", "b", "c"].map((d) => {
    mkdirSync(join(home, d));
    const f = join(home, d, "package-lock.json");
    writeFileSync(f, "");
    truncateSync(f, 30 * 1024 * 1024); // sparse
    return f;
  });
  mkdirSync(join(home, "d"));
  writeFileSync(join(home, "d", "package.json"), "{}");
  const small = join(home, "d", "package.json");
  const out = await bothReaders(home, home, `SGREQ1 fetch\n${[...files, small].join("\n")}\n`);
  const mb30 = String(30 * 1024 * 1024);
  // The third doesn't fit any more; a small one after it still does.
  assert.deepEqual(frames(out), [`${mb30} ${files[0]}`, `${mb30} ${files[1]}`, `-1 ${files[2]}`, `2 ${small}`]);
  // The client takes the over-the-cap file as unreadable, the others as usual.
  const got = remote.parseFetch(out, { host: "x", transport: "share" });
  assert.equal(got.get(files[2]!), null);
  assert.equal(got.get(small)?.toString(), "{}");
  assert.equal(got.get(files[0]!)?.length, 30 * 1024 * 1024);
});

test("list: the same folder asked twice is walked once, as deep as asked (both readers)", async () => {
  const home = tmp("sg-audit-roots-");
  mkdirSync(join(home, "code", "a", "b", "deep"), { recursive: true });
  writeFileSync(join(home, "code", "a", "b", "deep", "package-lock.json"), "{}");
  mkdirSync(join(home, "code", "top"));
  writeFileSync(join(home, "code", "top", "yarn.lock"), "");
  const code = join(home, "code");
  const out = (await bothReaders(home, home, `SGREQ1 list\n1\t${code}\n3\t~/code\n2\t${code}\n9\t/etc\n`)).toString();
  assert.deepEqual(out.split("\n").filter((l) => l.startsWith("R\t")), ["R\t0\t/etc", `R\t1\t${code}`]);
  assert.deepEqual(out.split("\n").filter((l) => l.startsWith("P\t")).map((l) => l.split("\t")[1]), [join(code, "a", "b", "deep"), join(code, "top")]);
});

// ---------- 3. symlinks inside a git dir ----------

test("git files that are symlinks are never read, so nothing leaks from outside the grant (both readers)", async () => {
  const root = tmp("sg-audit-git-");
  mkdirSync(join(root, ".git"));
  writeFileSync(join(root, ".git", "config"), '[remote "origin"]\n\turl = https://x:ghp_SECRET@github.com/o/r\n');
  writeFileSync(join(root, "secret.txt"), "TOP-SECRET-FIRST-LINE\n");
  const scope = join(root, "sub");
  // A real repo inside the grant, that symlinked pointers below could name.
  mkdirSync(join(scope, "real", ".git"), { recursive: true });
  writeFileSync(join(scope, "real", ".git", "HEAD"), "ref: refs/heads/main\n");
  writeFileSync(join(scope, "real", "package-lock.json"), "{}");
  writeFileSync(join(root, "pointer"), `gitdir: ${join(scope, "real", ".git")}\n`);
  writeFileSync(join(root, "commondir"), `${join(scope, "real", ".git")}\n`);
  // p: HEAD and config link outside.
  mkdirSync(join(scope, "p", ".git"), { recursive: true });
  writeFileSync(join(scope, "p", "package-lock.json"), "{}");
  symlinkSync(join(root, "secret.txt"), join(scope, "p", ".git", "HEAD"));
  symlinkSync(join(root, ".git", "config"), join(scope, "p", ".git", "config"));
  // q: the .git pointer file itself is a link to a file outside.
  mkdirSync(join(scope, "q"));
  writeFileSync(join(scope, "q", "package-lock.json"), "{}");
  symlinkSync(join(root, "pointer"), join(scope, "q", ".git"));
  // w: commondir links outside.
  mkdirSync(join(scope, "w", ".git"), { recursive: true });
  writeFileSync(join(scope, "w", ".git", "HEAD"), "ref: refs/heads/w\n");
  writeFileSync(join(scope, "w", "package-lock.json"), "{}");
  symlinkSync(join(root, "commondir"), join(scope, "w", ".git", "commondir"));

  const out = (await bothReaders(scope, root, `SGREQ1 list\n3\t${scope}\n`)).toString();
  assert.ok(!out.includes("SECRET"), out);
  const g = (dir: string): string[] | undefined => out.split("\n").find((l) => l.startsWith(`G\t${join(scope, dir)}\t`))?.split("\t");
  assert.equal(g("p")?.[6], "", "symlinked HEAD not read");
  assert.equal(g("q"), undefined, "symlinked .git pointer not followed");
  assert.equal(g("w")?.[5], join(scope, "w", ".git"), "symlinked commondir ignored");
  assert.equal(g("real")?.[6], "ref: refs/heads/main");
});

// ---------- 4. control characters in folder names ----------

test("folders whose names hold control characters are skipped; the sh reader stays in its folder (both readers)", async () => {
  const root = tmp("sg-audit-nl-");
  const outside = join(root, "o");
  mkdirSync(outside);
  writeFileSync(join(outside, "package-lock.json"), '{"outside":true}');
  const scope = join(root, "scope");
  mkdirSync(scope);
  // "x\n" + a copy of the outside path: `find | while read` splits it into a line naming the outside folder.
  const replica = join(scope, "x\n", outside);
  mkdirSync(replica, { recursive: true });
  writeFileSync(join(replica, "package-lock.json"), "{}");
  // A name that would add lines to the answer.
  mkdirSync(join(scope, "evil\nX\tinjected"));
  writeFileSync(join(scope, "evil\nX\tinjected", "package-lock.json"), "{}");
  mkdirSync(join(scope, "tab\there"));
  writeFileSync(join(scope, "tab\there", "package-lock.json"), "{}");
  mkdirSync(join(scope, "ok"));
  writeFileSync(join(scope, "ok", "package-lock.json"), "{}");
  symlinkSync(join(scope, "evil\nX\tinjected"), join(scope, "link"));

  const list = (await bothReaders(scope, root, `SGREQ1 list\n10\t${scope}\n`)).toString();
  assert.deepEqual(list.split("\n").filter((l) => l.startsWith("P\t")).map((l) => l.split("\t")[1]), [join(scope, "ok")]);
  assert.ok(!list.includes(outside + "\t"), "nothing listed outside the folder");
  assert.ok(!/^X\t/m.test(list), "no injected line");

  const browse = (await bothReaders(scope, root, `SGREQ1 browse\n${scope}\n`)).toString();
  assert.deepEqual(browse.split("\n").filter((l) => l.startsWith("S\t")), ["S\t0\tok"]);
  // A folder that resolves to such a name is refused like one outside the grant.
  const viaLink = (await bothReaders(scope, root, `SGREQ1 browse\n${join(scope, "link")}\n`)).toString();
  assert.match(viaLink, /\nX\toutside the allowed folder\n$/);
  assert.ok(!viaLink.includes("injected"));
});

// ---------- 5. authorized_keys marker ----------

test("removing or reinstalling one Mac's key never touches another Mac's line", () => {
  const home = tmp("sg-audit-ak-");
  mkdirSync(join(home, ".ssh"));
  const ak = join(home, ".ssh", "authorized_keys");
  const forced = 'restrict,command="/bin/sh .selfguard-reader/reader.sh"';
  const other = `${forced} ssh-ed25519 AAAAother selfguard:dev@mac-2`;
  const otherName = `${forced} ssh-ed25519 AAAAother2 selfguard:dev-2@mac`;
  const write = (): void =>
    writeFileSync(ak, ["ssh-ed25519 AAAAexisting you@laptop", other, `${forced} ssh-ed25519 AAAAold selfguard:dev@mac`, otherName, `${forced} ssh-ed25519 AAAAcrlf selfguard:dev@mac\r`, ""].join("\n"));
  for (const shell of SHELLS) {
    const run = (script: string): string => execFileSync(shell, ["-s"], { input: script, cwd: home, env: { PATH: process.env.PATH!, HOME: home } }).toString();
    write();
    assert.match(run(remote.revokeScript("selfguard:dev@mac")), /SGOK/);
    assert.deepEqual(readFileSync(ak, "utf8").split("\n"), ["ssh-ed25519 AAAAexisting you@laptop", other, otherName, ""], shell);
    write();
    const line = remote.authorizedLine("ssh-ed25519 AAAAnew", "selfguard:dev@mac");
    assert.match(run(remote.installScript(remote.readerScript("~", "selfguard:dev@mac"), line, "selfguard:dev@mac")), /SGOK/);
    assert.deepEqual(readFileSync(ak, "utf8").split("\n"), ["ssh-ed25519 AAAAexisting you@laptop", other, otherName, line, ""], shell);
  }
  for (const bad of ["selfguard:dev@mac.*", "selfguard:dev@mac$|", "x"]) {
    assert.throws(() => remote.revokeScript(bad), remote.RemoteError, bad);
    assert.throws(() => remote.installScript("", "", bad), remote.RemoteError, bad);
  }
});

// ---------- 2. tagged devices and the "same Tailscale user" check ----------

const A: FakeNode = { id: "nodeA", name: "mac-a", ips: ["100.64.0.1"] };
const servers: Array<{ close(): Promise<void> }> = [];
after(() => Promise.all(servers.map((s) => s.close())));

async function shareServer(self: FakeNode, caller: FakeNode, extra?: { selfTags?: string[]; callerTags?: string[] }) {
  const net = fakeTailnet(self, [A]);
  if (extra?.selfTags) {
    const st = JSON.parse(readFileSync(join(net.dir, "status.json"), "utf8"));
    st.Self.Tags = extra.selfTags;
    writeFileSync(join(net.dir, "status.json"), JSON.stringify(st));
  }
  net.whois("127.0.0.1", caller);
  if (extra?.callerTags) {
    const w = JSON.parse(readFileSync(join(net.dir, "whois-127.0.0.1.json"), "utf8"));
    w.Node.Tags = extra.callerTags;
    writeFileSync(join(net.dir, "whois-127.0.0.1.json"), JSON.stringify(w));
  }
  process.env.SELFGUARD_TAILSCALE = FAKE_TAILSCALE;
  process.env.SG_FAKE_TAILSCALE_DIR = net.dir;
  process.env.HOME = tmp("sg-audit-home-");
  const share = await import("../src/share.ts");
  const config = await import("../src/config.ts");
  const allow = (allowOtherUsers: boolean): void => config.saveConfig({ ...config.loadConfig(), share: { enabled: true, port: 0, allowOtherUsers } });
  allow(false);
  const server = await share.startShareServer({ port: 0, whoisTtlMs: 0, pairRequestsPer10Min: 100 });
  servers.push(server);
  return { share, allow, port: server.addresses[0]!.port };
}

test("two tagged devices don't count as the same Tailscale user", async () => {
  const tagged = { login: "tagged-devices" };
  const { share, allow, port } = await shareServer({ id: "nodeB", name: "server-b", ips: ["127.0.0.1"], ...tagged }, { ...A, ...tagged });
  const e = await share.requestPairing("127.0.0.1", port, "mac-a").catch((x) => x);
  assert.equal(e.code, "other_user");
  assert.match(e.message, /server-b is a tagged/);
  assert.match(e.message, /--allow-other-users/);
  allow(true);
  const s = await share.requestPairing("127.0.0.1", port, "mac-a");
  assert.equal(await share.rejectShareRequest(s.requestId), true);
});

test("a tagged caller (or a tagged self) never matches a user, even the same login", async () => {
  const caller = await shareServer({ id: "nodeB", name: "mac-b", ips: ["127.0.0.1"] }, A, { callerTags: ["tag:ci"] });
  const e1 = await caller.share.requestPairing("127.0.0.1", caller.port, "mac-a").catch((x) => x);
  assert.equal(e1.code, "other_user");
  assert.match(e1.message, /tagged/);
  assert.match(e1.message, /--allow-other-users/);
  const self = await shareServer({ id: "nodeB", name: "mac-b", ips: ["127.0.0.1"] }, A, { selfTags: ["tag:server"] });
  const e2 = await self.share.requestPairing("127.0.0.1", self.port, "mac-a").catch((x) => x);
  assert.equal(e2.code, "other_user");
  assert.match(e2.message, /mac-b is a tagged/);
  // Another user: still refused, and the message says how to allow it.
  const other = await shareServer({ id: "nodeB", name: "mac-b", ips: ["127.0.0.1"] }, { ...A, login: "someone@else.com" });
  const e3 = await other.share.requestPairing("127.0.0.1", other.port, "mac-a").catch((x) => x);
  assert.match(e3.message, /own Tailscale user/);
  assert.match(e3.message, /--allow-other-users/);
});

test("the share server streams fetch answers: duplicates answered once, client parses it", async () => {
  const { share, port } = await shareServer({ id: "nodeB", name: "mac-b", ips: ["127.0.0.1"] }, A);
  const home = process.env.HOME!;
  mkdirSync(join(home, "code", "api"), { recursive: true });
  const lock = join(home, "code", "api", "package-lock.json");
  writeFileSync(lock, Buffer.alloc(2 * 1024 * 1024, 0x61));
  const s = await share.requestPairing("127.0.0.1", port, "mac-a");
  await share.approveShareRequest(s.requestId, { scope: "~/code" });
  const r = await share.waitForPairing(s, { intervalMs: 20 });
  assert.equal(r.status, "approved");
  const t = { host: "127.0.0.1", port, transport: "share" as const, credential: r.status === "approved" ? r.payload.credential : "" };
  const raw = await remote.runRemote(t, `SGREQ1 fetch\n${Array(50).fill(lock).join("\n")}\n`, { maxBytes: 64 << 20, timeoutMs: 20_000 });
  assert.deepEqual(frames(raw), [`${2 * 1024 * 1024} ${lock}`]);
  assert.deepEqual(remote.parseFetch(raw, t).get(lock), readFileSync(lock));
  const files = await remote.fetchFiles(t, [lock, join(home, "code", "api", "package.json")]);
  assert.equal(files.get(lock)?.length, 2 * 1024 * 1024);
  assert.equal(files.get(join(home, "code", "api", "package.json")), null);
  // One answer stops at 64 MB: the client asks again for what didn't fit, not for what's missing.
  const big = ["b1", "b2", "b3"].map((d) => {
    mkdirSync(join(home, "code", d));
    const f = join(home, "code", d, "package-lock.json");
    writeFileSync(f, "");
    truncateSync(f, 30 * 1024 * 1024); // sparse
    return f;
  });
  const missing = join(home, "code", "nope", "package-lock.json");
  const all = await remote.fetchFiles(t, [...big, missing]);
  assert.deepEqual(big.map((f) => all.get(f)?.length), big.map(() => 30 * 1024 * 1024));
  assert.equal(all.get(missing), null);
  assert.ok(readFileSync(share.accessLogFile(), "utf8").includes('"op":"fetch"'), "fetches are logged");
});

test("a restricted reader installed before these fixes is reported outdated; a sharing peer isn't", () => {
  const old = "SG1\t/home/me\tLinux\treader r1\t/home/me";
  const keyed = { host: "x", key: "/k" };
  assert.throws(() => remote.parseHeader(old, keyed), (e: any) => e.code === "outdated" && /reinstall/.test(e.message));
  assert.throws(() => remote.parseHeader(`${old}\t1`, keyed), (e: any) => e.code === "outdated");
  assert.equal(remote.parseHeader(`${old}\t${remote.READER_REVISION}`, keyed).scope, "/home/me");
  // selfguard sharing: the other machine's own selfguard answers; an older one still works.
  assert.equal(remote.parseHeader(old, { host: "x", transport: "share" }).scope, "/home/me");
  // Both readers send the current revision.
  const home = tmp("sg-audit-rev-");
  for (const shell of SHELLS) assert.match(shReader(shell, home, home, "SGREQ1 ping\n").toString(), new RegExp(`^SG1\\t[^\\n]*\\treader r1\\t${home}\\t${remote.READER_REVISION}\\n`));
});
