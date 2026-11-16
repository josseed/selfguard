// Locks left by a process killed mid-run (e.g. by launchd's bootout) are reclaimed at once.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { before, test } from "node:test";

let fsutil: typeof import("../src/fsutil.ts");
let paths: typeof import("../src/paths.ts");

before(async () => {
  process.env.SELFGUARD_HOME = mkdtempSync(join(tmpdir(), "sg-locks-"));
  fsutil = await import("../src/fsutil.ts");
  paths = await import("../src/paths.ts");
});

const lockFile = (name: string): string => join(paths.locksDir(), `${fsutil.sha256(name).slice(0, 32)}.lock`);

/** A pid that no longer exists: a child that already exited. */
function deadPid(): number {
  const r = spawnSync(process.execPath, ["-e", "process.exit(0)"]);
  assert.ok(r.pid && !fsutil.pidAlive(r.pid));
  return r.pid;
}

test("a lock whose process is gone is reclaimed at once", () => {
  fsutil.ensureDir(paths.locksDir());
  writeFileSync(lockFile("dead"), String(deadPid()));
  const release = fsutil.tryLock("dead");
  assert.ok(release, "reclaimed");
  release();
  assert.equal(existsSync(lockFile("dead")), false);
});

test("a lock held by a live process is respected", () => {
  fsutil.ensureDir(paths.locksDir());
  writeFileSync(lockFile("live"), String(process.pid));
  assert.equal(fsutil.tryLock("live"), null);
  // Old enough, it is stale even with a live pid (pids get reused).
  const old = new Date(Date.now() - 10 * 60 * 1000);
  utimesSync(lockFile("live"), old, old);
  const release = fsutil.tryLock("live");
  assert.ok(release);
  release();
});

test("a lock still being written (no pid yet) falls back to its age", () => {
  fsutil.ensureDir(paths.locksDir());
  writeFileSync(lockFile("empty"), "");
  assert.equal(fsutil.tryLock("empty"), null);
});

test("taken twice in one process: the second waits; release frees it", () => {
  const release = fsutil.tryLock("twice")!;
  assert.equal(fsutil.tryLock("twice"), null);
  release();
  release(); // idempotent
  const again = fsutil.tryLock("twice");
  assert.ok(again);
  again();
});

test("SIGTERM releases the locks held, and the process still ends by the signal", async () => {
  const home = mkdtempSync(join(tmpdir(), "sg-locks-sig-"));
  const mod = fileURLToPath(new URL("../src/fsutil.ts", import.meta.url));
  const script = `const m = await import(${JSON.stringify(mod)}); m.tryLock("busy"); console.log("locked"); setInterval(() => {}, 1000);`;
  const child = spawn(process.execPath, ["--input-type=module", "-e", script], { env: { ...process.env, SELFGUARD_HOME: home } });
  await new Promise<void>((resolve) => child.stdout.once("data", () => resolve()));
  assert.equal(readdirSync(join(home, "locks")).length, 1);
  const ended = new Promise<NodeJS.Signals | null>((resolve) => child.on("exit", (_code, signal) => resolve(signal)));
  child.kill("SIGTERM");
  assert.equal(await ended, "SIGTERM");
  assert.deepEqual(readdirSync(join(home, "locks")), []);
});
