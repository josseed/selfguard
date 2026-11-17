import assert from "node:assert/strict";
import { test } from "node:test";
import { agentPlist } from "../src/schedule.ts";

test("launchd plists escape paths and watch lockfiles", () => {
  const plist = agentPlist("dev.selfguard.watch", ["/bin/node", "/x/cli.js", "check"], { watch: ["/code/a&b", "/code/<x>/package-lock.json"] }, "/l.log");
  assert.match(plist, /<key>WatchPaths<\/key>\s*<array>\s*<string>\/code\/a&amp;b<\/string>\s*<string>\/code\/&lt;x&gt;\/package-lock.json<\/string>/);
  assert.match(plist, /<key>ThrottleInterval<\/key><integer>15<\/integer>/);
  assert.doesNotMatch(plist, /StartInterval/);
  assert.match(agentPlist("dev.selfguard.sync", ["n"], { interval: 3600 }, "/l"), /<key>StartInterval<\/key><integer>3600<\/integer>/);
});

