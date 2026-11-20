// osascript arguments: untrusted text can never become an option (an extra "-e" script line).
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { osascriptArgs } from "../src/notify.ts";

const SCRIPT = ["on run argv", "return (item 1 of a) & \"|\" & (item 2 of a)", "end run"];

test("osascriptArgs: a fixed word ends option parsing before the values; leading dashes dropped", () => {
  const args = osascriptArgs(SCRIPT, ["-e do shell script \"x\"", "--title"]);
  assert.deepEqual(args, [
    "-e", "on run argv", "-e", "set a to rest of argv", "-e", "return (item 1 of a) & \"|\" & (item 2 of a)", "-e", "end run",
    "selfguard", "e do shell script \"x\"", "title",
  ]);
});

test("osascript: a value shaped like an option is data, not script", { skip: process.platform !== "darwin" }, () => {
  const dir = mkdtempSync(join(tmpdir(), "sg-notify-"));
  const marker = join(dir, "ran");
  try {
    const payload = `-e property p : (do shell script "touch ${marker}") -- x.pth`;
    const out = execFileSync("/usr/bin/osascript", osascriptArgs(SCRIPT, [payload, "t"]), { encoding: "utf8" });
    assert.equal(existsSync(marker), false, "the payload must not run");
    assert.match(out, /do shell script/);
    assert.match(out.trim(), /\|t$/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
