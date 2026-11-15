import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, realpathSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { infoPlist, launcherScript, shQuote } from "../src/app.ts";

test("the launcher script quotes paths so they can't inject shell", () => {
  assert.equal(shQuote("/a b/it's"), `'/a b/it'\\''s'`);
  const script = launcherScript("/opt/node $(rm -rf ~)", "/x/it's/cli.js");
  assert.equal(script.split("\n")[2], `exec '/opt/node $(rm -rf ~)' '/x/it'\\''s/cli.js' ui`);
  // the shell really reads them back literally
  const out = execFileSync("/bin/sh", ["-c", `printf '%s|' ${shQuote("a'b $HOME")} ${shQuote("`x`")}`], { encoding: "utf8" });
  assert.equal(out, "a'b $HOME|`x`|");
});

test("Info.plist describes a background launcher with the selfguard icon", () => {
  const plist = infoPlist();
  assert.match(plist, /<key>CFBundleExecutable<\/key><string>selfguard<\/string>/);
  assert.match(plist, /<key>CFBundleIconFile<\/key><string>selfguard<\/string>/);
  assert.match(plist, /<key>LSUIElement<\/key><true\/>/);
});

test("app install creates a runnable bundle in ~/Applications", { skip: process.platform !== "darwin" }, () => {
  const home = realpathSync(mkdtempSync(join(tmpdir(), "sg-app-")));
  const cli = new URL("../src/cli.ts", import.meta.url).pathname;
  const env = { ...process.env, HOME: home, SELFGUARD_HOME: join(home, ".sg"), SELFGUARD_NO_NOTIFY: "1" };
  const res = JSON.parse(execFileSync(process.execPath, [cli, "app", "install", "--json"], { env, encoding: "utf8" }));
  assert.equal(res.installed, true);
  const app = join(home, "Applications", "selfguard.app", "Contents");
  assert.equal(statSync(join(app, "MacOS", "selfguard")).mode & 0o777, 0o755);
  assert.match(readFileSync(join(app, "MacOS", "selfguard"), "utf8"), / ui\n$/);
  assert.ok(statSync(join(app, "Resources", "selfguard.icns")).size > 1000);
  execFileSync("/usr/bin/plutil", ["-lint", join(app, "Info.plist")]);
  const off = JSON.parse(execFileSync(process.execPath, [cli, "app", "uninstall", "--json"], { env, encoding: "utf8" }));
  assert.equal(off.wasInstalled, true);
});
