// Reloading a launchd agent while its job runs: bootout is asynchronous, so bootstrap is
// retried. A fake launchctl stands in for the real one (never called in tests).
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { before, test } from "node:test";

let launchd: typeof import("../src/schedule/launchd.ts");

before(async () => {
  process.env.HOME = realpathSync(mkdtempSync(join(tmpdir(), "sg-launchd-")));
  process.env.SELFGUARD_NO_LAUNCHD = "1";
  launchd = await import("../src/schedule/launchd.ts");
});

/** launchctl whose bootstrap fails `failures` times (the old job still exiting). */
function fake(failures: number, opts: { neverLoaded?: boolean } = {}) {
  const log: string[] = [];
  const sleeps: number[] = [];
  let loaded = true; // the old job
  let left = failures;
  const run = (args: string[]): void => {
    log.push(args[0]!);
    if (args[0] === "bootout") loaded = false;
    else if (args[0] === "bootstrap") {
      if (left-- > 0) throw new Error("Bootstrap failed: 5: Input/output error");
      loaded = !opts.neverLoaded;
    } else if (args[0] === "print" && !loaded) throw new Error("could not find service");
  };
  return { log, sleeps, deps: { run, sleep: (ms: number) => void sleeps.push(ms) } };
}

test("bootstrap succeeding at once: no wait, loaded is verified", () => {
  const f = fake(0);
  launchd.install("dev.selfguard.test", "<plist/>", f.deps);
  assert.deepEqual(f.log, ["bootout", "bootstrap", "print"]);
  assert.deepEqual(f.sleeps, []);
  assert.ok(existsSync(launchd.plistPath("dev.selfguard.test")));
});

test("bootstrap failing while the old job exits is retried with a growing backoff", () => {
  const f = fake(3);
  launchd.install("dev.selfguard.test", "<plist/>", f.deps);
  assert.deepEqual(f.log, ["bootout", "bootstrap", "bootstrap", "bootstrap", "bootstrap", "print"]);
  assert.deepEqual(f.sleeps, [100, 200, 300]);
});

test("still failing after every try: a clear error, after ~5 s of waiting at most", () => {
  const f = fake(Infinity);
  assert.throws(() => launchd.install("dev.selfguard.test", "<plist/>", f.deps), /could not load dev\.selfguard\.test with launchctl after 10 tries \(Bootstrap failed: 5/);
  assert.equal(f.log.filter((c) => c === "bootstrap").length, launchd.BOOTSTRAP_TRIES);
  const waited = f.sleeps.reduce((a, b) => a + b, 0);
  assert.ok(waited > 0 && waited <= 5000, `waited ${waited} ms`);
});

test("bootstrap that returns but leaves nothing loaded is not a success", () => {
  const f = fake(0, { neverLoaded: true });
  assert.throws(() => launchd.install("dev.selfguard.test", "<plist/>", f.deps), /not loaded after bootstrap/);
});

test("isLoaded and unload go through the runner", () => {
  const f = fake(0);
  assert.equal(launchd.isLoaded("x", f.deps), true);
  launchd.unload("x", f.deps);
  assert.equal(launchd.isLoaded("x", f.deps), false);
  // unload of something not loaded doesn't throw
  launchd.unload("x", { run: () => { throw new Error("no such service"); } });
});
