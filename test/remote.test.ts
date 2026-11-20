import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";
import {
  authorizedLine,
  browseMachine,
  fetchFiles,
  installScript,
  listMachine,
  parseFetch,
  parseList,
  readerScript,
  RemoteError,
  revokeScript,
  runInstall,
  shq,
  sshArgs,
  testHost,
  type Target,
} from "../src/remote.ts";
import { identityFromFacts } from "../src/repoid.ts";

const FAKE_SSH = fileURLToPath(new URL("./bin/fake-ssh", import.meta.url));
process.env.SELFGUARD_SSH = FAKE_SSH;
const tmp = (p: string): string => realpathSync(mkdtempSync(join(tmpdir(), p)));
const OPEN: Target = { host: "devbox" };

test("ssh is called without prompts or forwarding, host after --", () => {
  const args = sshArgs({ host: "devbox.tail1234.ts.net" });
  for (const flag of ["-T", "-a", "-x", "BatchMode=yes", "ClearAllForwardings=yes"]) assert.ok(args.includes(flag), flag);
  assert.deepEqual(args.slice(-3), ["--", "devbox.tail1234.ts.net", "/bin/sh -s"]);
  assert.ok(!args.some((a) => /StrictHostKeyChecking/.test(a)), "host key checks are left alone");
  const keyed = sshArgs({ host: "devbox", port: 2222, key: "/k/devbox_ed25519" });
  for (const flag of ["IdentitiesOnly=yes", "IdentityAgent=none", "PasswordAuthentication=no"]) assert.ok(keyed.includes(flag), flag);
  assert.deepEqual(keyed.slice(keyed.indexOf("-i"), keyed.indexOf("-i") + 2), ["-i", "/k/devbox_ed25519"]);
  assert.deepEqual(keyed.slice(keyed.indexOf("-p"), keyed.indexOf("-p") + 2), ["-p", "2222"]);
  for (const bad of ["-oProxyCommand=touch /tmp/x", "host;id", "a b", "$(id)", "user@-x", ""]) {
    assert.throws(() => sshArgs({ host: bad }), RemoteError, bad);
  }
  assert.throws(() => sshArgs({ host: "devbox", port: 70000 }), RemoteError);
  assert.equal(shq("it's"), `'it'\\''s'`);
});

function tree(base = tmp("sg-remote-")): string {
  const code = join(base, "code with 'quote'");
  mkdirSync(join(code, "api", ".git", "logs"), { recursive: true });
  writeFileSync(join(code, "api", ".git", "HEAD"), "ref: refs/heads/main\n");
  writeFileSync(join(code, "api", ".git", "config"), '[core]\n\tbare = false\n[remote "origin"]\n\turl = https://user:secret@github.com/acme/api.git\n');
  writeFileSync(join(code, "api", "package.json"), '{"dependencies":{"lodash":"^4"}}');
  writeFileSync(join(code, "api", "package-lock.json"), '{"lockfileVersion":3,"packages":{}}');
  mkdirSync(join(code, "api", ".git", "worktrees", "feat"), { recursive: true });
  writeFileSync(join(code, "api", ".git", "worktrees", "feat", "HEAD"), "ref: refs/heads/feat/x\n");
  writeFileSync(join(code, "api", ".git", "worktrees", "feat", "commondir"), "../..\n");
  mkdirSync(join(code, "api-feat"));
  writeFileSync(join(code, "api-feat", ".git"), `gitdir: ${join(code, "api", ".git", "worktrees", "feat")}\n`);
  writeFileSync(join(code, "api-feat", "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
  mkdirSync(join(code, "old"));
  writeFileSync(join(code, "old", ".git"), "gitdir: /nonexistent/.git/worktrees/old\n");
  writeFileSync(join(code, "old", "yarn.lock"), "");
  mkdirSync(join(code, "api", "node_modules", "dep"), { recursive: true });
  writeFileSync(join(code, "api", "node_modules", "dep", "package-lock.json"), "{}");
  mkdirSync(join(code, ".cache", "x"), { recursive: true });
  writeFileSync(join(code, ".cache", "x", "package-lock.json"), "{}");
  mkdirSync(join(code, "a", "b", "c", "d"), { recursive: true });
  writeFileSync(join(code, "a", "b", "c", "d", "package-lock.json"), "{}");
  mkdirSync(join(code, "linked"));
  writeFileSync(join(code, "linked", "package.json"), "{}");
  symlinkSync("/etc/hosts", join(code, "linked", "package-lock.json"));
  return code;
}

test("ssh mode: projects, lockfile stats and git facts", async () => {
  const code = tree();
  const r = await listMachine(OPEN, [{ path: code, depth: 2 }, { path: "~/definitely-missing-sg", depth: 2 }]);
  assert.equal(r.home, process.env.HOME);
  assert.deepEqual(r.roots.map((x) => x.ok), [true, false]);
  const byName = new Map(r.projects.map((p) => [p.root.slice(code.length + 1), p]));
  assert.deepEqual([...byName.keys()].sort(), ["api", "api-feat", "old"]);
  const api = byName.get("api")!;
  assert.equal(api.lockType, "npm");
  assert.equal(api.size, 35);
  const id = identityFromFacts(api.git!, "devbox");
  assert.equal(id.key, "devbox|github.com/acme/api");
  assert.equal(id.branch, "main");
  assert.ok(!JSON.stringify(id).includes("secret"));
  const feat = identityFromFacts(byName.get("api-feat")!.git!, "devbox");
  assert.equal(feat.key, "devbox|github.com/acme/api", "worktree groups with its repo");
  assert.equal(feat.branch, "feat/x");
  assert.equal(identityFromFacts(byName.get("old")!.git!, "devbox").orphaned, true);
});

test("ssh mode: fetch exact bytes, only lockfiles/package.json, no symlinks", async () => {
  const code = tree();
  const lock = join(code, "api", "package-lock.json");
  const files = await fetchFiles(OPEN, [lock, join(code, "api", "package.json"), join(code, "linked", "package-lock.json"), "/etc/passwd", join(code, "nope", "package.json")]);
  assert.deepEqual(files.get(lock), readFileSync(lock));
  assert.equal(files.get(join(code, "linked", "package-lock.json")), null);
  assert.equal(files.get("/etc/passwd"), null);
  assert.equal(files.get(join(code, "nope", "package.json")), null);
  const b = await browseMachine(OPEN, code);
  assert.deepEqual(b.dirs.map((d) => [d.name, d.isProject]), [["a", false], ["api", true], ["api-feat", false], ["linked", true], ["old", false]]);
});

test("ssh mode: values reach the script as literals, never as shell code", async () => {
  const marker = join(tmp("sg-inject-"), "pwned");
  const evil = [`/tmp/x'; touch ${marker}; echo '`, `/tmp/$(touch ${marker})`, `/tmp/\`touch ${marker}\``];
  await listMachine(OPEN, evil.map((path) => ({ path, depth: 1 })));
  await fetchFiles(OPEN, evil.map((p) => `${p}/package-lock.json`));
  await browseMachine(OPEN, evil[0]!).catch(() => {});
  assert.equal(existsSync(marker), false);
});

// ---------- restricted mode ----------

function restrictedMachine(scopeRel = "code") {
  const home = tmp("sg-rhome-");
  process.env.SG_FAKE_HOME = home;
  mkdirSync(join(home, "code"));
  const code = tree(join(home, "code"));
  const keyDir = tmp("sg-key-");
  const key = join(keyDir, "devbox_ed25519");
  execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "selfguard:devbox@mac", "-f", key]);
  const marker = "selfguard:devbox@mac";
  const scope = `~/${scopeRel}`;
  const line = authorizedLine(readFileSync(`${key}.pub`, "utf8"), marker, ["100.101.102.103"]);
  const script = installScript(readerScript(scope, marker), line, marker);
  return { home, code, key, marker, line, script, keyed: { host: "devbox", key } as Target };
}

test("authorized_keys line: restrict + forced reader, pinned source, validated parts", () => {
  const pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOZfakefakefakefakefakefakefakefakefakefakefake selfguard:x@y";
  assert.equal(authorizedLine(pub, "selfguard:devbox@mac", ["100.1.2.3", "fd7a:115c:a1e0::1"]),
    'restrict,command="/bin/sh .selfguard-reader/reader.sh",from="100.1.2.3,fd7a:115c:a1e0::1" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOZfakefakefakefakefakefakefakefakefakefakefake selfguard:devbox@mac');
  assert.throws(() => authorizedLine("ssh-rsa AAAA x", "selfguard:d@m"), RemoteError);
  assert.throws(() => authorizedLine(pub, 'selfguard:d@m" evil'), RemoteError);
  assert.throws(() => authorizedLine(pub, "selfguard:d@m", ['1.2.3.4",command="sh']), RemoteError);
});

test("restricted mode: install once, then the key only reaches the reader", async () => {
  const m = restrictedMachine();
  // Without the line installed, the key is refused.
  await assert.rejects(testHost(m.keyed), (e: RemoteError) => e.code === "auth");
  writeFileSync(join(m.home, ".ssh_dummy"), "");
  mkdirSync(join(m.home, ".ssh"), { recursive: true });
  writeFileSync(join(m.home, ".ssh", "authorized_keys"), "ssh-ed25519 AAAAexisting you@laptop\n");
  await runInstall(OPEN, m.script);
  await runInstall(OPEN, m.script); // idempotent
  const ak = readFileSync(join(m.home, ".ssh", "authorized_keys"), "utf8").trim().split("\n");
  assert.deepEqual(ak, ["ssh-ed25519 AAAAexisting you@laptop", m.line]);

  const h = await testHost(m.keyed);
  assert.equal(h.scope, join(m.home, "code"));
  const r = await listMachine(m.keyed, [{ path: "~/code/code with 'quote'", depth: 2 }, { path: "/etc", depth: 2 }, { path: "~/code/../..", depth: 2 }]);
  assert.deepEqual(r.projects.map((p) => p.root.slice(m.code.length + 1)).sort(), ["api", "api-feat", "old"]);
  assert.ok(r.roots.some((x) => x.ok && x.path === m.code));
  assert.ok(r.roots.filter((x) => !x.ok).length === 2, "outside folders refused");
});

test("restricted mode: nothing outside the allowed folder, even via symlinks", async () => {
  const m = restrictedMachine("code");
  mkdirSync(join(m.home, ".ssh"), { recursive: true });
  await runInstall(OPEN, m.script);
  const outside = tmp("sg-outside-");
  writeFileSync(join(outside, "package-lock.json"), '{"secret":true}');
  symlinkSync(outside, join(m.code, "escape"));
  const inside = join(m.code, "api", "package-lock.json");
  const files = await fetchFiles(m.keyed, [inside, join(outside, "package-lock.json"), join(m.code, "escape", "package-lock.json"), `${m.code}/../../etc/package.json`]);
  assert.ok(files.get(inside));
  assert.equal(files.get(join(outside, "package-lock.json")), null);
  assert.equal(files.get(join(m.code, "escape", "package-lock.json")), null);
  await assert.rejects(browseMachine(m.keyed, outside), /outside the allowed folder/);
  await assert.rejects(browseMachine(m.keyed, join(m.code, "escape")), /outside the allowed folder/);
  const top = await browseMachine(m.keyed, "~/code");
  assert.equal(top.parent, null, "the picker stops at the allowed folder");
  const sub = await browseMachine(m.keyed, join(m.code, "api"));
  assert.equal(sub.parent, m.code);
});

test("restricted mode: requests are data, the requested command is ignored", async () => {
  const m = restrictedMachine();
  mkdirSync(join(m.home, ".ssh"), { recursive: true });
  await runInstall(OPEN, m.script);
  const marker = join(tmp("sg-inject-"), "pwned");
  await listMachine(m.keyed, [`~/code/x'; touch ${marker}; echo '`, `~/code/$(touch ${marker})`, `~/code/\`touch ${marker}\``].map((path) => ({ path, depth: 1 })));
  await fetchFiles(m.keyed, [`${m.code}/$(touch ${marker})/package.json`]);
  assert.equal(existsSync(marker), false);
  // A script sent over the restricted key is not run: the reader treats it as a bad request.
  const { runRemote } = await import("../src/remote.ts");
  const out = (await runRemote(m.keyed, `touch ${marker}\n`, { maxBytes: 65536, timeoutMs: 10_000 })).toString();
  assert.match(out, /^SG1\t.*\treader r1\t/);
  assert.match(out, /X\tbad request/);
  assert.equal(existsSync(marker), false);
});

test("restricted mode: revoke removes the line and the reader", async () => {
  const m = restrictedMachine();
  mkdirSync(join(m.home, ".ssh"), { recursive: true });
  writeFileSync(join(m.home, ".ssh", "authorized_keys"), "ssh-ed25519 AAAAexisting you@laptop\n");
  await runInstall(OPEN, m.script);
  await runInstall(OPEN, revokeScript(m.marker));
  assert.equal(readFileSync(join(m.home, ".ssh", "authorized_keys"), "utf8"), "ssh-ed25519 AAAAexisting you@laptop\n");
  assert.equal(existsSync(join(m.home, ".selfguard-reader")), false);
  await assert.rejects(testHost(m.keyed), (e: RemoteError) => e.code === "auth");
});

test("restricted target answered by a plain shell is refused", () => {
  const plain = Buffer.from("SG1\t/home/me\tLinux\tsh\t\n");
  assert.throws(() => parseList(plain, { host: "x", key: "/k" }), (e: RemoteError) => e.code === "not_installed");
  assert.throws(() => parseList(Buffer.from("SG1\t/home/me\tLinux\treader r0\t/home/me\n"), { host: "x", key: "/k" }), (e: RemoteError) => e.code === "outdated");
  assert.throws(() => parseList(Buffer.from("bash: selfguard-reader: command not found\n"), { host: "x", key: "/k" }), (e: RemoteError) => e.code === "not_installed");
});

test("answers are parsed strictly", () => {
  assert.throws(() => parseList(Buffer.from("hello\n")), /unexpected answer/);
  const list = parseList(Buffer.from("SG1\t/home/me\tLinux\tsh\t\nR\t1\t/home/me/code\nP\trelative\tpackage-lock.json\t1\t1\nP\t/home/me/code/x\tevil.sh\t1\t1\nP\t/home/me/code/../etc\tpackage-lock.json\t1\t1\nP\t/home/me/code/ok\tpackage-lock.json\t10\t20\ngarbage\n"));
  assert.deepEqual(list.projects.map((p) => p.root), ["/home/me/code/ok"]);
  assert.equal(list.projects[0]!.mtimeMs, 20_000);
  // a reader only reports projects inside its folder
  const scoped = parseList(Buffer.from("SG1\t/home/me\tLinux\treader r1\t/home/me/code\t2\nP\t/home/me/other\tpackage-lock.json\t1\t1\nP\t/home/me/code/a\tpackage-lock.json\t1\t1\n"), { host: "x", key: "/k" });
  assert.deepEqual(scoped.projects.map((p) => p.root), ["/home/me/code/a"]);
  const head = Buffer.from("SG1\t/home/me\tLinux\tsh\t\n\n");
  const files = parseFetch(Buffer.concat([head, gzipSync(Buffer.from("F\t3\t/home/me/a/package-lock.json\nabcF\t-1\t/home/me/b/yarn.lock\n"))]));
  assert.equal(files.get("/home/me/a/package-lock.json")?.toString(), "abc");
  assert.equal(files.get("/home/me/b/yarn.lock"), null);
  for (const bad of ["F\t3\t/home/me/a/.bashrc\nabc", "F\t3\t/home/me/../a/package-lock.json\nabc", "F\t10\t/home/me/a/package-lock.json\nabc", "X\t1\t/a/package.json\na"]) {
    assert.throws(() => parseFetch(Buffer.concat([head, Buffer.from(bad)])), RemoteError, bad);
  }
});

test("connection errors are reported, not thrown away", async () => {
  const dir = tmp("sg-ssh-");
  const down = join(dir, "ssh");
  writeFileSync(down, "#!/bin/sh\necho 'Permission denied (publickey).' >&2\nexit 255\n", { mode: 0o755 });
  process.env.SELFGUARD_SSH = down;
  try {
    await assert.rejects(listMachine(OPEN, [{ path: "~", depth: 1 }]), (e: RemoteError) => e.code === "auth" && /Permission denied/.test(e.message));
  } finally {
    process.env.SELFGUARD_SSH = FAKE_SSH;
  }
});
