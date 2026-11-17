import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { DASHBOARD_PAGES, dashboardArgs } from "../src/app.ts";

test("the app is opened on a repo or a page with plain arguments", () => {
  assert.deepEqual(dashboardArgs(), ["--dashboard"]);
  assert.deepEqual(dashboardArgs({ repo: "github.com/acme/web", page: "repos" }), ["--dashboard", "--repo", "github.com/acme/web", "--page", "repos"]);
  assert.ok(DASHBOARD_PAGES.includes("settings") && DASHBOARD_PAGES.includes("overview"));
});

const cli = new URL("../src/cli.ts", import.meta.url).pathname;
const sandbox = () => {
  const home = realpathSync(mkdtempSync(join(tmpdir(), "sg-app-")));
  return { home, env: { ...process.env, HOME: home, SELFGUARD_HOME: join(home, ".sg"), SELFGUARD_NO_NOTIFY: "1" } };
};
const bundle = (home: string, id: string) => {
  const dir = join(home, "Applications", "selfguard.app", "Contents");
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "Info.plist"), `<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>${id}</string></dict></plist>\n`);
  return join(home, "Applications", "selfguard.app");
};

test("app uninstall removes only the old script launcher, never the real app", { skip: process.platform !== "darwin" }, () => {
  const { home, env } = sandbox();
  const real = bundle(home, "dev.selfguard.mac");
  const run = (...args: string[]) => JSON.parse(execFileSync(process.execPath, [cli, "app", ...args, "--json"], { env, encoding: "utf8" }));
  assert.equal(run("uninstall").removed, false);
  assert.ok(existsSync(real), "the Mac app stays");
  assert.equal(run("status").installed, true, "found (here or in /Applications)");
  const legacy = bundle(home, "dev.selfguard.app");
  assert.equal(run("status").legacyLauncher, true);
  assert.equal(run("uninstall").removed, true);
  assert.ok(!existsSync(legacy));
});

test("app install points to the download; ui validates --page", () => {
  const { env } = sandbox();
  const r = JSON.parse(execFileSync(process.execPath, [cli, "app", "install", "--json"], { env: { ...env, HOME: mkdtempSync(join(tmpdir(), "sg-app-")) }, encoding: "utf8" }));
  assert.match(r.download, /github\.com\/josseed\/selfguard\/releases\/latest/);
  assert.throws(() => execFileSync(process.execPath, [cli, "ui", "--page", "nope"], { env, stdio: "pipe" }), /--page must be one of/);
});
